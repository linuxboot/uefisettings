// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
