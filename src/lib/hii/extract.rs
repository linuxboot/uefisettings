use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;

pub const OCP_HIIDB_PATH: &str =
    "/sys/firmware/efi/efivars/HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0";

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar {
    // hiitool calls this varlen but I think these are flags/attributes
    // first 4 bytes of the (efivarfs) output represent the UEFI variable attributes - from kernel.org
    flags: u32,

    length: u32,
    address: u32,
}

pub fn extract_db() -> Result<Vec<u8>> {
    // I haven't seen any documentation on extracting HiiDB anywhere on the internet
    // So this is directly based on what hiitool does.

    // try to read data from varstore
    let mut efivar_file =
        File::open(OCP_HIIDB_PATH).context(format!("Failed to open {OCP_HIIDB_PATH}"))?;

    let mut efivar_contents = Vec::new();
    efivar_file
        .read_to_end(&mut efivar_contents)
        .context(format!("Failed to read efivar file, {}", OCP_HIIDB_PATH))?;

    let mut efivar_cursor = Cursor::new(&efivar_contents);
    let db_info: HiiDBEFIVar = efivar_cursor.read_ne()?;

    // Now that we have offset and size from the HiiDB efivar, use it to read DB from memory.

    let mut mem_file = File::open("/dev/mem").context("Failed to open /dev/mem")?;
    mem_file.seek(SeekFrom::Start(db_info.address as u64))?;

    let mut buf = vec![0u8; db_info.length.try_into()?];
    mem_file
        .read_exact(&mut buf)
        .context("Failed to read bytes of specified length from /dev/mem")?;

    Ok(buf)
}
