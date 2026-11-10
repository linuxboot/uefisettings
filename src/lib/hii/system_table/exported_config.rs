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

//! The configuration export that firmware advertises in the EFI Configuration Table under
//! EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID (UEFI 2.11 §33.2.11.1): the Results of ExportConfig()
//! (§35.4.3), a NUL-terminated EFI_STRING of CHAR16s (§34.1.2) in `<MultiConfigAltResp>` format
//! (§35.2.1.5). The configuration table gives only a pointer (§4.6.1), so the NUL gives the
//! string's extent, inside the runtime region that holds its start.

use std::path::Path;

use anyhow::bail;
use anyhow::Result;
use thiserror::Error;

use super::ConfigurationTables;
use super::PointerSpace;
use super::SystemTableFiles;
use super::SystemVendorTable;
use crate::hii::firmware_memory::runtime_memory::PhysicalMemory;
use crate::hii::package::Guid;

/// EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID (UEFI 2.11 §35.4.1).
const EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID: Guid = Guid {
    data1: 0x587e_72d7,
    data2: 0xcc50,
    data3: 0x4f79,
    data4: [0x82, 0x09, 0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0f],
};

/// The size of a CHAR16.
const CHAR16_SIZE: usize = 2;

/// The most bytes that one read takes: a page.
const CHUNK_SIZE: usize = 0x1000;

/// Why the configuration export holds no text that uefisettings reads. The messages spell
/// "section", as HiiExportError's do.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ExportedConfigError {
    /// No NUL CHAR16 ends the string before the end of the runtime region that holds its start.
    #[error(
        "the configuration export at {address:#x} has no NUL CHAR16 in the {room} bytes up to \
         the end of its runtime region (UEFI 2.11 section 35.4.3)"
    )]
    Unterminated { address: u64, room: u64 },
    /// A surrogate that no other completes, at byte `offset` of the string: no UTF-16 text.
    #[error(
        "the configuration export at {address:#x} holds the unpaired surrogate {unit:#06x} at \
         offset {offset:#x}: it is not UTF-16 text"
    )]
    UnpairedSurrogate {
        address: u64,
        offset: u64,
        unit: u16,
    },
}

/// The text of the configuration export that the System Table of `files` lists, in the physical
/// memory that `open_memory` opens, as read_hii_export reads its export; None where no entry
/// lists it, as firmware need not export it. Its address is taken as physical first, as
/// read_hii_export takes its own: UEFI 2.11 leaves its conversion to the specification of the
/// VendorGuid (§4.6.1), and §33.2.11.1 and §35.4 say none; edk2 publishes it as allocated
/// (edk2-stable202608 MdeModulePkg/Universal/HiiDatabaseDxe/Database.c:3551, :3566) and converts
/// no configuration table (MdeModulePkg/Core/RuntimeDxe/Runtime.c:358).
pub(in crate::hii) fn read_exported_config<M: PhysicalMemory>(
    files: &SystemTableFiles,
    open_memory: impl FnOnce(&Path, &Path) -> Result<M>,
) -> Result<Option<String>> {
    ConfigurationTables::read(files, open_memory)?
        .into_table(
            &EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID,
            PointerSpace::Physical,
        )?
        .map(|table| read_results(&table))
        .transpose()
}

/// The text before the first NUL CHAR16 of the string at `table`, read a page at a time up to
/// the page that holds that NUL, and at most up to the end of the runtime region that holds the
/// string's first CHAR16. edk2's buffer, zero-filled and a quarter larger than the string,
/// always holds the NUL (Database.c:3545, :3551, :3562-3565).
fn read_results<M: PhysicalMemory>(table: &SystemVendorTable<M>) -> Result<String> {
    let room = table.room(CHAR16_SIZE)?;
    // whole CHAR16s only
    let end = room - room % u64::try_from(CHAR16_SIZE)?;
    let chunk_size = u64::try_from(CHUNK_SIZE)?;
    let mut units = Vec::new();
    let mut offset = 0;
    while offset < end {
        let length = chunk_size.min(end - offset);
        let chunk = table.read_at(offset, usize::try_from(length)?)?;
        if u64::try_from(chunk.len())? != length {
            bail!(
                "read {} of {length} bytes of the configuration export",
                chunk.len()
            );
        }
        // `length` is even, so the chunk is whole CHAR16s
        let (char16s, _) = chunk.as_chunks::<CHAR16_SIZE>();
        for unit in char16s.iter().copied().map(u16::from_le_bytes) {
            if unit == 0 {
                return decode(table.address, &units);
            }
            units.push(unit);
        }
        offset += length;
    }
    Err(ExportedConfigError::Unterminated {
        address: table.address,
        room,
    }
    .into())
}

/// `units`, the string at `address` before its NUL, as text: UTF-16, as a surrogate that no
/// other completes is no character. UEFI 2.11 strings are UCS-2, without surrogates
/// (§33.2.6.2.2), which UTF-16 reads alike.
fn decode(address: u64, units: &[u16]) -> Result<String> {
    let mut text = String::with_capacity(units.len());
    let mut offset = 0;
    for decoded in char::decode_utf16(units.iter().copied()) {
        match decoded {
            Ok(character) => {
                text.push(character);
                offset += character.len_utf16() * CHAR16_SIZE;
            }
            Err(error) => {
                return Err(ExportedConfigError::UnpairedSurrogate {
                    address,
                    offset: u64::try_from(offset)?,
                    unit: error.unpaired_surrogate(),
                }
                .into())
            }
        }
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::firmware_width::FirmwareWidth;
    use crate::hii::firmware_memory::runtime_memory::fixture::UnreadMemory;
    use crate::hii::firmware_memory::runtime_memory::ReadToken;
    use crate::hii::lockdown::LockdownMode;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryAccessDenied;
    use crate::hii::memory_access_denied::MemoryDevice;
    use crate::hii::memory_access_denied::MemoryOperation;
    use crate::hii::system_table::fixture::arm64_files;
    use crate::hii::system_table::fixture::configuration_table;
    use crate::hii::system_table::fixture::valid_system_table;
    use crate::hii::system_table::fixture::x86_files;
    use crate::hii::system_table::fixture::SegmentMemory;
    use crate::hii::system_table::SystemTableError;
    use crate::hii::system_table::EFI_HII_DATABASE_PROTOCOL_GUID;
    use crate::memory_map::efi_memory_map::MemoryType;
    use crate::memory_map::efi_memory_map::RangeRefusal;
    use crate::memory_map::efi_memory_map::EFI_MEMORY_RUNTIME;

    /// The runtime data region of x86's tests, of REGION_PAGES pages at a physical and, after
    /// SetVirtualAddressMap(), a virtual address as OVMF's, and a runtime descriptor of
    /// memory-mapped I/O; boot services data at BOOT_SERVICES_AT is not runtime.
    const REGION_AT: u64 = 0x7f00_0000;
    const VIRTUAL_AT: u64 = 0xffff_fffe_ff00_0000;
    const REGION_PAGES: u64 = 16;
    const REGION_END: u64 = REGION_AT + REGION_PAGES * 0x1000;
    const MMIO_AT: u64 = 0xfeb0_0000;
    const BOOT_SERVICES_AT: u64 = 0x10_0000;
    const RUNTIME: [(MemoryType, u64, u64, u64); 2] = [
        (
            MemoryType::RUNTIME_SERVICES_DATA,
            REGION_AT,
            VIRTUAL_AT,
            REGION_PAGES,
        ),
        (
            MemoryType::MEMORY_MAPPED_IO,
            MMIO_AT,
            VIRTUAL_AT + 0x40_0000,
            1,
        ),
    ];
    /// Where the tests put the System Table, its entries and the Results string, unaligned.
    const SYSTEM_TABLE_AT: u64 = REGION_AT + 0x18;
    const ENTRIES_AT: u64 = REGION_AT + 0x201;
    const RESULTS_AT: u64 = REGION_AT + 0x1003;
    /// The bytes from RESULTS_AT to the region's end: an odd number.
    const ROOM: u64 = REGION_END - RESULTS_AT;
    /// A `<MultiConfigAltResp>` of one byte of one varstore (UEFI 2.11 section 35.2.1.5).
    const CONFIG: &str = "GUID=d7727e5850cc794f8209ca291fc1a10f&NAME=0043006f006e006600690067\
                          &PATH=7fff0400&OFFSET=0&WIDTH=1&VALUE=05";
    const ROUTING: Guid = EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID;

    /// The CHAR16s of `text`.
    fn char16s(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// The CHAR16s `units`.
    fn units(units: &[u16]) -> Vec<u8> {
        units.iter().copied().flat_map(u16::to_le_bytes).collect()
    }

    /// `bytes`, then `fill` up to the region's end, from RESULTS_AT.
    fn to_region_end(bytes: &[u8], fill: u8) -> Vec<u8> {
        let mut buffer = bytes.to_vec();
        buffer.resize(usize::try_from(ROOM).expect("a usize room"), fill);
        buffer
    }

    /// Physical memory that records the address and length of each read.
    struct Recorded {
        memory: SegmentMemory,
        reads: Rc<RefCell<Vec<(u64, usize)>>>,
    }

    impl PhysicalMemory for Recorded {
        fn read(&self, address: u64, length: usize, token: ReadToken) -> Result<Vec<u8>> {
            self.reads.borrow_mut().push((address, length));
            self.memory.read(address, length, token)
        }
    }

    /// Physical memory that holds, in the runtime data region, a System Table of `width` that
    /// lists `entries`, and `buffer` at RESULTS_AT.
    fn x86_memory(width: FirmwareWidth, entries: &[(Guid, u64)], buffer: Vec<u8>) -> SegmentMemory {
        let count = u64::try_from(entries.len()).expect("a u64 count");
        SegmentMemory(vec![
            (
                SYSTEM_TABLE_AT,
                valid_system_table(width, count, ENTRIES_AT),
            ),
            (ENTRIES_AT, configuration_table(width, entries)),
            (RESULTS_AT, buffer),
        ])
    }

    /// read_exported_config of x86's files, for a System Table of `width` that lists `entries`,
    /// with `buffer` at RESULTS_AT, and the reads that it makes past the System Table and its
    /// entries.
    fn read_x86(
        width: FirmwareWidth,
        entries: &[(Guid, u64)],
        buffer: Vec<u8>,
    ) -> (Result<Option<String>>, Vec<(u64, usize)>) {
        let dir = tempfile::tempdir().expect("create a directory");
        let files = x86_files(dir.path(), width, SYSTEM_TABLE_AT, ENTRIES_AT, &RUNTIME);
        let reads = Rc::default();
        let memory = Recorded {
            memory: x86_memory(width, entries, buffer),
            reads: Rc::clone(&reads),
        };

        let got = read_exported_config(&files, |_, _| Ok(memory));

        let reads = reads
            .borrow()
            .iter()
            .copied()
            .filter(|&(address, _)| address != SYSTEM_TABLE_AT && address != ENTRIES_AT)
            .collect();
        (got, reads)
    }

    /// The reads of `pages` whole pages from `address` on.
    fn pages_from(address: u64, pages: u64) -> Vec<(u64, usize)> {
        (0..pages)
            .map(|page| (address + page * 0x1000, 0x1000))
            .collect()
    }

    /// The text is what comes before the first NUL CHAR16, on firmware of either width: before
    /// zeros, as in edk2's zeroed buffer, a quarter larger than the string, or before more text.
    /// UTF-16 makes a surrogate pair one character; a NUL first is no text. It reads one page
    /// from the string's start, whose entry it finds among others.
    #[test]
    fn reads_the_text_before_the_first_nul() {
        let entries = [
            (EFI_HII_DATABASE_PROTOCOL_GUID, REGION_AT + 0x8000),
            (ROUTING, RESULTS_AT),
        ];
        for width in [FirmwareWidth::Bits64, FirmwareWidth::Bits32] {
            for (case, string, want) in [
                (
                    "zeros after",
                    [char16s(CONFIG), vec![0; 2]].concat(),
                    CONFIG,
                ),
                (
                    "text after",
                    [char16s(CONFIG), vec![0; 2], char16s("&OFFSET=1")].concat(),
                    CONFIG,
                ),
                (
                    "a character of the BMP and a surrogate pair",
                    [char16s("\u{e9}\u{1d11e}"), vec![0; 2]].concat(),
                    "\u{e9}\u{1d11e}",
                ),
                ("a NUL first", vec![0; 2], ""),
            ] {
                let (got, reads) = read_x86(width, &entries, to_region_end(&string, 0));

                assert_eq!(
                    got.unwrap_or_else(|error| panic!("{width:?}: {case}: {error:#}")),
                    Some(want.to_owned()),
                    "{width:?}: {case}"
                );
                assert_eq!(reads, [(RESULTS_AT, 0x1000)], "{width:?}: {case}: reads");
            }
        }
    }

    /// Text longer than a page is read a page at a time, up to the page that holds its NUL: one
    /// page where the NUL is the last CHAR16 of the first, two where it is the first of the
    /// second, three for two and a half pages of text.
    #[test]
    fn reads_text_longer_than_a_page_a_page_at_a_time() {
        for (case, length, pages) in [
            ("a NUL that ends the first page", 0x7ff, 1),
            ("a NUL that starts the second page", 0x800, 2),
            ("two and a half pages", 0x1400, 3),
        ] {
            let text: String = "0123456789abcdef&".chars().cycle().take(length).collect();
            let string = [char16s(&text), vec![0; 2]].concat();

            let (got, reads) = read_x86(
                FirmwareWidth::Bits64,
                &[(ROUTING, RESULTS_AT)],
                to_region_end(&string, 0),
            );

            assert_eq!(
                got.unwrap_or_else(|error| panic!("{case}: {error:#}")),
                Some(text),
                "{case}"
            );
            assert_eq!(reads, pages_from(RESULTS_AT, pages), "{case}: reads");
        }
    }

    /// Text up to the end of the runtime region that holds the string, without a NUL CHAR16, is
    /// refused with the string's address and its room, also where that room ends with a zero
    /// byte, half a CHAR16; the reads end at the region's last whole CHAR16, and a NUL there ends
    /// the text.
    #[test]
    fn refuses_text_without_a_nul_before_the_region_s_end() {
        // the whole CHAR16s from RESULTS_AT to the region's end, and the reads of them
        let whole = usize::try_from(ROOM / 2).expect("a usize count");
        let reads_to_end = |address: u64| {
            let mut reads = pages_from(address, 14);
            reads.push((address + 0xe000, 0xffc));
            reads
        };
        for (case, pointer, buffer, room) in [
            (
                "an odd room, ending with a zero byte",
                RESULTS_AT,
                [char16s(&"A".repeat(whole)), vec![0]].concat(),
                ROOM,
            ),
            (
                "an even room",
                RESULTS_AT + 1,
                [vec![0x41], char16s(&"A".repeat(whole))].concat(),
                ROOM - 1,
            ),
        ] {
            assert_eq!(buffer.len(), to_region_end(&[], 0).len(), "{case}: fixture");

            let (got, reads) = read_x86(FirmwareWidth::Bits64, &[(ROUTING, pointer)], buffer);

            let error = got.expect_err(case);
            assert_eq!(
                error.downcast_ref::<ExportedConfigError>(),
                Some(&ExportedConfigError::Unterminated {
                    address: pointer,
                    room
                }),
                "{case}: {error:#}"
            );
            assert_eq!(reads, reads_to_end(pointer), "{case}: reads");
        }

        let (got, _) = read_x86(
            FirmwareWidth::Bits64,
            &[(ROUTING, RESULTS_AT)],
            [char16s(&"A".repeat(whole)), vec![0]].concat(),
        );
        let error = got.expect_err("read a string without a NUL");
        assert_eq!(
            error.to_string(),
            "the configuration export at 0x7f001003 has no NUL CHAR16 in the 61437 bytes up to \
             the end of its runtime region (UEFI 2.11 section 35.4.3)"
        );

        let (got, reads) = read_x86(
            FirmwareWidth::Bits64,
            &[(ROUTING, RESULTS_AT)],
            [char16s(&"A".repeat(whole - 1)), vec![0; 2], vec![0x41]].concat(),
        );
        assert_eq!(
            got.expect("read a NUL in the region's last whole CHAR16"),
            Some("A".repeat(whole - 1)),
            "a NUL at the region's end"
        );
        assert_eq!(
            reads,
            reads_to_end(RESULTS_AT),
            "a NUL at the region's end: reads"
        );
    }

    /// A surrogate that no other completes is refused with the string's address, its offset and
    /// itself: a high one before a letter, before the NUL or before another high one, and a low
    /// one first.
    #[test]
    fn refuses_an_unpaired_surrogate() {
        for (case, string, offset, unit) in [
            (
                "a high surrogate before a letter",
                [char16s("AB"), units(&[0xd834]), char16s("C")].concat(),
                4,
                0xd834,
            ),
            (
                "a high surrogate before the NUL",
                [char16s("A"), units(&[0xd834])].concat(),
                2,
                0xd834,
            ),
            (
                "a high surrogate before a pair",
                [char16s("A"), units(&[0xd834, 0xd834, 0xdd1e])].concat(),
                2,
                0xd834,
            ),
            ("a low surrogate first", units(&[0xdd1e, 0x41]), 0, 0xdd1e),
        ] {
            let (got, _) = read_x86(
                FirmwareWidth::Bits64,
                &[(ROUTING, RESULTS_AT)],
                to_region_end(&[string, vec![0; 2]].concat(), 0),
            );

            let error = got.expect_err(case);
            assert_eq!(
                error.downcast_ref::<ExportedConfigError>(),
                Some(&ExportedConfigError::UnpairedSurrogate {
                    address: RESULTS_AT,
                    offset,
                    unit
                }),
                "{case}: {error:#}"
            );
        }

        let (got, _) = read_x86(
            FirmwareWidth::Bits64,
            &[(ROUTING, RESULTS_AT)],
            to_region_end(&[char16s("AB"), units(&[0xd834, 0x43, 0])].concat(), 0),
        );
        assert_eq!(
            got.expect_err("read an unpaired surrogate").to_string(),
            "the configuration export at 0x7f001003 holds the unpaired surrogate 0xd834 at \
             offset 0x4: it is not UTF-16 text"
        );
    }

    /// A string whose first CHAR16 lies outside runtime memory is refused unread: in boot services
    /// data, in memory-mapped I/O, or half past the region's end. One that the region's last
    /// CHAR16 holds is read.
    #[test]
    fn refuses_a_string_outside_runtime_memory() {
        for (case, pointer, want) in [
            (
                "boot services data",
                BOOT_SERVICES_AT,
                RangeRefusal::NotRuntime {
                    address: BOOT_SERVICES_AT,
                    length: 2,
                },
            ),
            (
                "memory-mapped I/O",
                MMIO_AT,
                RangeRefusal::MemoryMappedIo {
                    address: MMIO_AT,
                    length: 2,
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                },
            ),
            (
                "the region's last byte",
                REGION_END - 1,
                RangeRefusal::NotRuntime {
                    address: REGION_END - 1,
                    length: 2,
                },
            ),
        ] {
            let (got, reads) = read_x86(
                FirmwareWidth::Bits64,
                &[(ROUTING, pointer)],
                to_region_end(&[], 0),
            );

            let error = got.expect_err(case);
            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&want),
                "{case}: {error:#}"
            );
            assert_eq!(reads, [], "{case}: reads");
        }

        let (got, reads) = read_x86(
            FirmwareWidth::Bits64,
            &[(ROUTING, REGION_END - 2)],
            to_region_end(&[], 0),
        );
        assert_eq!(
            got.expect("read the region's last CHAR16"),
            Some(String::new()),
            "the region's last CHAR16"
        );
        assert_eq!(
            reads,
            [(REGION_END - 2, 2)],
            "the region's last CHAR16: reads"
        );
    }

    /// Physical memory that serves a CHAR16 less than each read at RESULTS_AT asks.
    struct Short(SegmentMemory);

    impl PhysicalMemory for Short {
        fn read(&self, address: u64, length: usize, token: ReadToken) -> Result<Vec<u8>> {
            let mut bytes = self.0.read(address, length, token)?;
            if address == RESULTS_AT {
                bytes.truncate(length - 2);
            }
            Ok(bytes)
        }
    }

    /// A read of the string that serves fewer bytes than it asks is refused, though the bytes
    /// that it serves hold the NUL.
    #[test]
    fn refuses_a_short_read() {
        let dir = tempfile::tempdir().expect("create a directory");
        let files = x86_files(
            dir.path(),
            FirmwareWidth::Bits64,
            SYSTEM_TABLE_AT,
            ENTRIES_AT,
            &RUNTIME,
        );
        let memory = Short(x86_memory(
            FirmwareWidth::Bits64,
            &[(ROUTING, RESULTS_AT)],
            to_region_end(&[char16s(CONFIG), vec![0; 2]].concat(), 0),
        ));

        let error =
            read_exported_config(&files, |_, _| Ok(memory)).expect_err("read 4094 of 4096 bytes");

        assert_eq!(
            error.to_string(),
            "read 4094 of 4096 bytes of the configuration export"
        );
    }

    /// An entry whose VendorTable is NULL is refused, naming its GUID, and nothing reads it.
    #[test]
    fn refuses_a_null_pointer() {
        let (got, reads) = read_x86(
            FirmwareWidth::Bits64,
            &[(EFI_HII_DATABASE_PROTOCOL_GUID, RESULTS_AT), (ROUTING, 0)],
            to_region_end(&[char16s(CONFIG), vec![0; 2]].concat(), 0),
        );

        let error = got.expect_err("read a NULL VendorTable");
        assert_eq!(
            error.downcast_ref::<SystemTableError>(),
            Some(&SystemTableError::NullVendorTable { guid: ROUTING }),
            "{error:#}"
        );
        assert_eq!(
            error.to_string(),
            "the EFI Configuration Table's entry of 587E72D7-CC50-4F79-8209-CA291FC1A10F has a \
             NULL VendorTable"
        );
        assert_eq!(reads, [], "reads");
    }

    /// Without an entry of EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID there is no text, also where
    /// entries of GUIDs a bit off it, at either end, or of the HII database export point at
    /// one, and nothing reads that.
    #[test]
    fn is_none_without_an_entry() {
        let others = [
            (EFI_HII_DATABASE_PROTOCOL_GUID, RESULTS_AT),
            (
                Guid {
                    data1: ROUTING.data1 ^ 1,
                    ..ROUTING
                },
                RESULTS_AT,
            ),
            (
                Guid {
                    data4: [0x82, 0x09, 0xca, 0x29, 0x1f, 0xc1, 0xa1, 0x0e],
                    ..ROUTING
                },
                RESULTS_AT,
            ),
        ];
        for (case, entries, want) in [
            ("no entries", Vec::new(), None),
            ("other GUIDs", others.to_vec(), None),
            (
                "other GUIDs and it",
                [&others[..], &[(ROUTING, RESULTS_AT)]].concat(),
                Some(CONFIG.to_owned()),
            ),
        ] {
            let (got, reads) = read_x86(
                FirmwareWidth::Bits64,
                &entries,
                to_region_end(&[char16s(CONFIG), vec![0; 2]].concat(), 0),
            );

            assert_eq!(
                got.unwrap_or_else(|error| panic!("{case}: {error:#}")),
                want,
                "{case}"
            );
            let want_reads = match want {
                Some(_) => vec![(RESULTS_AT, 0x1000)],
                None => Vec::new(),
            };
            assert_eq!(reads, want_reads, "{case}: reads");
        }
    }

    /// Through arm64's FDT, the VendorTable is taken as a physical address where a runtime region
    /// holds it physically, though it is also a virtual address of another region, and is
    /// translated through the memory map where no runtime region holds it physically, as firmware
    /// that converted it at SetVirtualAddressMap() would give it.
    #[test]
    fn takes_the_pointer_as_physical_first_then_as_virtual() {
        // Two runtime regions, each at the other's physical address after
        // SetVirtualAddressMap(), and a third at a virtual address that no region holds
        // physically.
        const A_AT: u64 = 0x8000_0000;
        const B_AT: u64 = 0x9000_0000;
        const C_AT: u64 = 0xa000_0000;
        const C_VIRTUAL_AT: u64 = 0x2000_0000;
        let width = FirmwareWidth::Bits64;
        let region = |physical, virtual_start| {
            (
                MemoryType::RUNTIME_SERVICES_DATA,
                physical,
                virtual_start,
                16,
                EFI_MEMORY_RUNTIME | 0xf,
            )
        };
        let string = |text: &str| [char16s(text), vec![0; 0x1000]].concat();
        for (case, pointer, want) in [
            (
                "physical, also another region's virtual address",
                A_AT + 0x1003,
                "in A",
            ),
            ("converted", C_VIRTUAL_AT + 0x1003, "in C"),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let files = arm64_files(
                dir.path(),
                "64\n",
                A_AT + 0x18,
                &[
                    region(A_AT, B_AT),
                    region(B_AT, A_AT),
                    region(C_AT, C_VIRTUAL_AT),
                ],
            );
            let memory = SegmentMemory(vec![
                (A_AT + 0x18, valid_system_table(width, 1, B_AT + 0x200)),
                (
                    A_AT + 0x200,
                    configuration_table(width, &[(ROUTING, pointer)]),
                ),
                (A_AT + 0x1003, string("in A")),
                (B_AT + 0x1003, string("in B")),
                (C_AT + 0x1003, string("in C")),
            ]);

            let got = read_exported_config(&files, |_, _| Ok(memory));

            assert_eq!(
                got.unwrap_or_else(|error| panic!("{case}: {error:#}")),
                Some(want.to_owned()),
                "{case}"
            );
        }
    }

    /// Kernel lockdown that refuses /dev/mem refuses the string before physical memory opens.
    #[test]
    fn lockdown_refuses_before_physical_memory_opens() {
        for mode in [LockdownMode::Integrity, LockdownMode::Confidentiality] {
            let dir = tempfile::tempdir().expect("create a directory");
            let mut files = x86_files(
                dir.path(),
                FirmwareWidth::Bits64,
                SYSTEM_TABLE_AT,
                ENTRIES_AT,
                &RUNTIME,
            );
            files.lockdown = lockdown_file(dir.path(), &mode.to_string());

            let error = read_exported_config(&files, |path, _| -> Result<UnreadMemory> {
                panic!("opened {}", path.display())
            })
            .expect_err("read under lockdown");

            assert_eq!(
                error.downcast_ref::<MemoryAccessDenied>(),
                Some(&MemoryAccessDenied {
                    device: MemoryDevice::DevMem,
                    operation: MemoryOperation::Open,
                    cause: DenialCause::Lockdown(mode),
                }),
                "{mode}: {error:#}"
            );
        }
    }

    /// The configuration table GUID of the string, as UEFI 2.11 section 35.4.1 spells it.
    #[test]
    fn config_routing_protocol_guid_is_the_specification_s() {
        assert_eq!(
            EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID.to_string(),
            "587E72D7-CC50-4F79-8209-CA291FC1A10F"
        );
    }
}
