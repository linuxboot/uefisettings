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
use std::os::fd::AsRawFd;
use std::ptr;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;

pub const OCP_HIIDB_PATH: &str =
    "/sys/firmware/efi/efivars/HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0";

#[derive(Debug, PartialEq)]
struct HiiDBEFIVar {
    // hiitool calls this varlen but I think these are flags/attributes
    // first 4 bytes of the (efivarfs) output represent the UEFI variable attributes - from kernel.org
    flags: u32,

    length: u32,
    address: u64,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar32 {
    flags: u32,
    length: u32,
    address: u32,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar64 {
    flags: u32,
    length: u32,
    address: u64,
}

impl HiiDBEFIVar {
    fn parse(contents: &[u8]) -> Result<Self> {
        match contents.len() {
            12 => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar32 = cursor.read_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address.into(),
                })
            }
            16 => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar64 = cursor.read_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address,
                })
            }
            size => bail!("Unexpected HiiDB efivar size: {size} bytes"),
        }
    }
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

    let db_info = HiiDBEFIVar::parse(&efivar_contents)?;

    // Now that we have offset and size from the HiiDB efivar, use it to read DB from memory.
    read_physical_memory(db_info.address, db_info.length.try_into()?)
}

fn read_physical_memory(address: u64, length: usize) -> Result<Vec<u8>> {
    let mem_file = File::open("/dev/mem").context("Failed to open /dev/mem")?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        bail!("Failed to query system page size");
    }

    let page_size = page_size as usize;
    let page_mask = page_size as u64 - 1;
    let mut buf = Vec::with_capacity(length);
    let mut copied = 0usize;

    while copied < length {
        let phys = address + copied as u64;
        let map_base = phys & !page_mask;
        let map_offset = (phys - map_base) as usize;
        let chunk_len = std::cmp::min(page_size - map_offset, length - copied);

        let mapped = unsafe {
            libc::mmap(
                ptr::null_mut(),
                page_size,
                libc::PROT_READ,
                libc::MAP_SHARED,
                mem_file.as_raw_fd(),
                map_base as libc::off_t,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error()).context(format!(
                "Failed to mmap HII DB page from /dev/mem at 0x{map_base:x}"
            ));
        }

        // Some platforms expose the HII DB through memory that faults on
        // wider unaligned loads. Copy byte-by-byte so every access is a
        // naturally aligned u8 load from the mapped physical page.
        unsafe {
            let src = (mapped as *const u8).add(map_offset);
            for i in 0..chunk_len {
                buf.push(std::ptr::read_volatile(src.add(i)));
            }
            libc::munmap(mapped, page_size);
        }

        copied += chunk_len;
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_32_bit_hiidb_address() {
        let contents = [
            0x06, 0x00, 0x00, 0x00, // flags
            0x34, 0x12, 0x00, 0x00, // length
            0x78, 0x56, 0x34, 0x12, // address
        ];

        let var = HiiDBEFIVar::parse(&contents).unwrap();

        assert_eq!(var.flags, 0x6);
        assert_eq!(var.length, 0x1234);
        assert_eq!(var.address, 0x12345678);
    }

    #[test]
    fn parses_64_bit_hiidb_address() {
        let contents = [
            0x06, 0x00, 0x00, 0x00, // flags
            0x34, 0x12, 0x00, 0x00, // length
            0x00, 0xf0, 0xcc, 0xa4, 0x00, 0x02, 0x00, 0x00, // address
        ];

        let var = HiiDBEFIVar::parse(&contents).unwrap();

        assert_eq!(var.flags, 0x6);
        assert_eq!(var.length, 0x1234);
        assert_eq!(var.address, 0x200a4ccf000);
    }
}
