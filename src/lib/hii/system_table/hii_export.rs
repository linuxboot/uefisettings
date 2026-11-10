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

//! The HII database export buffer that firmware advertises in the EFI Configuration Table under
//! EFI_HII_DATABASE_PROTOCOL_GUID (UEFI 2.11 §33.2.11.1, §4.6.5): what ExportPackageLists() writes
//! for every package list (§34.8.6), package lists back to back, each from its
//! EFI_HII_PACKAGE_LIST_HEADER, whose PackageLength includes it (§33.3.1.2). The configuration
//! table gives only a pointer (§4.6.1), so the package list headers give the export's extent.

use std::path::Path;

use anyhow::bail;
use anyhow::Result;
use thiserror::Error;

use super::ConfigurationTables;
use super::PointerSpace;
use super::SystemTableFiles;
use super::SystemVendorTable;
use crate::hii::firmware_memory::runtime_memory::PhysicalMemory;
use crate::hii::package::db_file::MAX_ALLOWED_FILESIZE;
use crate::hii::package::Guid;

/// EFI_HII_DATABASE_PROTOCOL_GUID (UEFI 2.11 §34.8.1).
pub(in crate::hii) const EFI_HII_DATABASE_PROTOCOL_GUID: Guid = Guid {
    data1: 0xef9f_c172,
    data2: 0xa1b2,
    data3: 0x4693,
    data4: [0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42],
};

/// The size of EFI_HII_PACKAGE_LIST_HEADER: PackageListGuid and PackageLength (UEFI 2.11
/// §33.3.1.2).
const PACKAGE_LIST_HEADER_SIZE: usize = 20;

/// The size of EFI_HII_PACKAGE_HEADER: Length:24 and Type:8 (UEFI 2.11 §33.3.1.1).
const PACKAGE_HEADER_SIZE: usize = 4;

/// EFI_HII_PACKAGE_END, the Type of the package that ends a package list (UEFI 2.11 §33.3.1.1).
const EFI_HII_PACKAGE_END: u8 = 0xdf;

/// Why the HII database export holds no HII database that uefisettings reads. The messages spell
/// "section", as PayloadError's do.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HiiExportError {
    /// The System Table lists no configuration table of EFI_HII_DATABASE_PROTOCOL_GUID: the
    /// firmware does not export its HII database this way.
    #[error(
        "the EFI System Table lists no configuration table of EFI_HII_DATABASE_PROTOCOL_GUID \
         {EFI_HII_DATABASE_PROTOCOL_GUID} (UEFI 2.11 section 33.2.11.1)"
    )]
    NotListed,
    /// Its first EFI_HII_PACKAGE_LIST_HEADER is zeros: it holds no package list.
    #[error("the HII database export holds no package list: its first header is zeros")]
    Empty,
    /// A PackageLength shorter than the header that it includes.
    #[error(
        "the package list at offset {offset:#x} of the HII database export has a PackageLength \
         of {length}, less than its {PACKAGE_LIST_HEADER_SIZE}-byte header (UEFI 2.11 section \
         33.3.1.2)"
    )]
    PackageLengthShort { offset: u64, length: u32 },
    /// A PackageLength that runs past the runtime region that holds the export.
    #[error(
        "the package list at offset {offset:#x} of the HII database export has a PackageLength \
         of {length}, past the end of its runtime region, {room} bytes on"
    )]
    PastRegion { offset: u64, length: u32, room: u64 },
    /// Packages that, walked by their EFI_HII_PACKAGE_HEADER.Length, do not end with an
    /// EFI_HII_PACKAGE_END package exactly at the PackageLength of their package list: the walk
    /// fails at offset `at` of the list.
    #[error(
        "the package list at offset {offset:#x} of the HII database export does not end with an \
         EFI_HII_PACKAGE_END package at its PackageLength of {length}: walked by their Length, \
         its packages fail at offset {at:#x} of it (UEFI 2.11 section 33.3.1.1)"
    )]
    Unterminated { offset: u64, length: u32, at: u64 },
    /// Package lists that reach past the largest HII database that uefisettings reads.
    #[error(
        "the package lists of the HII database export reach {length} bytes, more than the \
         {MAX_ALLOWED_FILESIZE} that uefisettings reads"
    )]
    TooLarge { length: u64 },
}

/// The memory of an HII database export, as a configuration table gives it.
pub(in crate::hii) trait ExportMemory {
    /// The bytes from the export's start to the end of the memory region that holds its first
    /// `length` bytes.
    fn room(&self, length: usize) -> Result<u64>;
    /// `length` bytes at `offset` of the export.
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>>;
}

impl<M: PhysicalMemory> ExportMemory for SystemVendorTable<M> {
    fn room(&self, length: usize) -> Result<u64> {
        SystemVendorTable::room(self, length)
    }

    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        SystemVendorTable::read_at(self, offset, length)
    }
}

/// The HII database export that the System Table of `files` lists, in the physical memory that
/// `open_memory` opens, read as read_export reads it. UEFI 2.11 leaves open whether its address
/// is virtual (§4.6.1, §33.2.11.1), and edk2 converts no configuration table, so it is taken as
/// physical first.
pub(in crate::hii) fn read_hii_export<M: PhysicalMemory>(
    files: &SystemTableFiles,
    open_memory: impl FnOnce(&Path, &Path) -> Result<M>,
) -> Result<Vec<u8>> {
    let table = ConfigurationTables::read(files, open_memory)?
        .into_table(&EFI_HII_DATABASE_PROTOCOL_GUID, PointerSpace::Physical)?
        .ok_or(HiiExportError::NotListed)?;
    read_export(&table)
}

/// The package lists of the HII database export in `memory`, exactly: each from its header, until
/// a header of zeros, which ends edk2's export in the buffer that it zero-fills and allocates a
/// quarter larger (edk2-stable202608 MdeModulePkg/Universal/HiiDatabaseDxe/Database.c:3600-3621),
/// or until its region leaves no room for another header. It reads each header, then the rest of
/// its package list, whose packages must end with an EFI_HII_PACKAGE_END package exactly at its
/// PackageLength (UEFI 2.11 §33.3.1.1), so that what it returns is what it checked. Where the
/// database has not grown, edk2 exports it again into the same buffer, zeroed (Database.c:3601,
/// :3622), which can leave fewer zero bytes than a header after the lists: this reads them and
/// the bytes after them as a header, and refuses the export unless they make a package list that
/// fits.
pub(in crate::hii) fn read_export(memory: &impl ExportMemory) -> Result<Vec<u8>> {
    let mut left = memory.room(PACKAGE_LIST_HEADER_SIZE)?;
    let header_size = u64::try_from(PACKAGE_LIST_HEADER_SIZE)?;
    let mut export = Vec::new();
    while left >= header_size {
        let offset = u64::try_from(export.len())?;
        let header = memory.read_at(offset, PACKAGE_LIST_HEADER_SIZE)?;
        let Ok(fields) = <[u8; PACKAGE_LIST_HEADER_SIZE]>::try_from(header.as_slice()) else {
            bail!("read {} bytes of a package list header", header.len());
        };
        if fields == [0; PACKAGE_LIST_HEADER_SIZE] {
            break;
        }
        // PackageListGuid, then PackageLength
        let [.., l0, l1, l2, l3] = fields;
        let length = u32::from_le_bytes([l0, l1, l2, l3]);
        let rest = u64::from(length)
            .checked_sub(header_size)
            .ok_or(HiiExportError::PackageLengthShort { offset, length })?;
        left = left
            .checked_sub(u64::from(length))
            .ok_or(HiiExportError::PastRegion {
                offset,
                length,
                room: left,
            })?;
        let end = offset.saturating_add(u64::from(length));
        if end > MAX_ALLOWED_FILESIZE {
            return Err(HiiExportError::TooLarge { length: end }.into());
        }
        export.extend(header);
        let packages = match rest {
            0 => Vec::new(),
            _ => memory.read_at(u64::try_from(export.len())?, usize::try_from(rest)?)?,
        };
        if let Err(at) = end_package_ends(&packages) {
            let at = u64::try_from(PACKAGE_LIST_HEADER_SIZE.saturating_add(at))?;
            return Err(HiiExportError::Unterminated { offset, length, at }.into());
        }
        export.extend(packages);
    }
    if export.is_empty() {
        return Err(HiiExportError::Empty.into());
    }
    Ok(export)
}

/// Checks that `packages`, a package list after its header, walked by each package's
/// EFI_HII_PACKAGE_HEADER.Length, end with an EFI_HII_PACKAGE_END package exactly at their end
/// (UEFI 2.11 §33.3.1.1). Else gives the offset in `packages` of the first package whose header
/// does not fit, whose Length is shorter than its header or runs past the end, or that is an END
/// package longer than its header or ending before it.
fn end_package_ends(packages: &[u8]) -> Result<(), usize> {
    let mut at = 0;
    while let Some((&[l0, l1, l2, package_type], _)) = packages
        .get(at..)
        .and_then(|rest| rest.split_first_chunk::<PACKAGE_HEADER_SIZE>())
    {
        // Length:24, then Type:8
        let length = usize::try_from(u32::from_le_bytes([l0, l1, l2, 0]))
            .ok()
            .filter(|&length| length >= PACKAGE_HEADER_SIZE)
            .ok_or(at)?;
        let end = at
            .checked_add(length)
            .filter(|&end| end <= packages.len())
            .ok_or(at)?;
        if package_type == EFI_HII_PACKAGE_END {
            // the End package is a header alone
            return match (length, end == packages.len()) {
                (PACKAGE_HEADER_SIZE, true) => Ok(()),
                _ => Err(at),
            };
        }
        at = end;
    }
    Err(at)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use anyhow::anyhow;

    use super::*;

    /// An export at the start of a memory region of `region`, which serves reads inside it only and
    /// records each read's offset and length.
    struct Region {
        region: Vec<u8>,
        reads: RefCell<Vec<(u64, usize)>>,
    }

    impl Region {
        fn new(region: Vec<u8>) -> Self {
            Self {
                region,
                reads: RefCell::default(),
            }
        }
    }

    impl ExportMemory for Region {
        fn room(&self, length: usize) -> Result<u64> {
            match self.region.len() >= length {
                true => Ok(u64::try_from(self.region.len())?),
                false => Err(anyhow!("{length} bytes run past the region")),
            }
        }

        fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
            self.reads.borrow_mut().push((offset, length));
            let start = usize::try_from(offset)?;
            Ok(self
                .region
                .get(start..start + length)
                .unwrap_or_else(|| panic!("read {length:#x} bytes at {offset:#x} past the region"))
                .to_vec())
        }
    }

    /// A package list of the GUID whose bytes are `id` repeated, with `body` after its header, its
    /// PackageLength `length`.
    fn package_list(id: u8, length: u32, body: &[u8]) -> Vec<u8> {
        [&[id; 16][..], &length.to_le_bytes(), body].concat()
    }

    /// A whole package list of the GUID whose bytes are `id`, with `body` after its header.
    fn whole_list(id: u8, body: &[u8]) -> Vec<u8> {
        let length = u32::try_from(PACKAGE_LIST_HEADER_SIZE + body.len()).expect("a u32 length");
        package_list(id, length, body)
    }

    /// The End package of a package list (UEFI 2.11 section 33.3.1.1).
    const END: [u8; 4] = [4, 0, 0, 0xdf];

    /// A package of `package_type` with `data` after its header.
    fn package(package_type: u8, data: &[u8]) -> Vec<u8> {
        let length = u32::try_from(PACKAGE_HEADER_SIZE + data.len()).expect("a u32 length");
        [&length.to_le_bytes()[..3], &[package_type], data].concat()
    }

    /// A GUID package (EFI_HII_PACKAGE_TYPE_GUID) of 9 bytes, then the End package.
    fn guid_package_and_end() -> Vec<u8> {
        [package(0x01, &[0x11; 5]), END.to_vec()].concat()
    }

    /// The export is the package lists up to the first header of zeros, edk2's slack, or up to the
    /// end of the region, also where fewer bytes than a header are left: exactly those bytes. It
    /// reads each header, then the rest of its list, and nothing past the export but the header
    /// of zeros.
    #[test]
    fn read_export_reads_the_package_lists_exactly() {
        let lists = [
            whole_list(1, &guid_package_and_end()),
            whole_list(2, &END),
            whole_list(3, &[package(0x04, &[]), END.to_vec()].concat()),
        ]
        .concat();
        let lists_reads = [(0, 20), (20, 13), (33, 20), (53, 4), (57, 20), (77, 8)];
        for (case, tail, zeros_read) in [
            ("zeros after", vec![0; 0x40], Some((85, 20))),
            ("the region's end", Vec::new(), None),
            ("19 bytes before the region's end", vec![0x5a; 19], None),
        ] {
            let region = Region::new([&lists[..], &tail].concat());

            let export = read_export(&region).unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(export, lists, "{case}");
            let reads: Vec<(u64, usize)> = lists_reads.into_iter().chain(zeros_read).collect();
            assert_eq!(*region.reads.borrow(), reads, "{case}: reads");
        }
    }

    /// A header whose PackageLength is shorter than the header, also one of a GUID of zeros, and
    /// one whose package list runs past the region, also one that ends the region, fail with what
    /// they hold, and so does an export whose first header is zeros.
    #[test]
    fn read_export_refuses_package_lists_that_do_not_fit() {
        let first = whole_list(1, &END);
        for (case, region, want) in [
            (
                "a PackageLength of 0",
                [&first[..], &package_list(2, 0, &[0; 8])].concat(),
                HiiExportError::PackageLengthShort {
                    offset: 24,
                    length: 0,
                },
            ),
            (
                "a PackageLength of 19 behind a GUID of zeros",
                [&first[..], &package_list(0, 19, &[0; 8])].concat(),
                HiiExportError::PackageLengthShort {
                    offset: 24,
                    length: 19,
                },
            ),
            (
                "a package list past the region",
                [&first[..], &package_list(2, 25, &[0; 4])].concat(),
                HiiExportError::PastRegion {
                    offset: 24,
                    length: 25,
                    room: 24,
                },
            ),
            (
                "a first header of zeros",
                vec![0; 64],
                HiiExportError::Empty,
            ),
            (
                "a header's room of other bytes at the region's end",
                [&first[..], &[0x5a; 20]].concat(),
                HiiExportError::PastRegion {
                    offset: 24,
                    length: 0x5a5a_5a5a,
                    room: 20,
                },
            ),
        ] {
            let error = read_export(&Region::new(region)).expect_err(case);

            assert_eq!(
                error.downcast_ref::<HiiExportError>(),
                Some(&want),
                "{case}"
            );
        }
    }

    /// Fewer zero bytes than a header after the lists, then other bytes of the region, as edk2's
    /// re-export into its zeroed buffer can leave, are read as a header: here one that runs past
    /// the region, so the export is refused.
    #[test]
    fn read_export_refuses_fewer_zeros_than_a_header_before_other_bytes() {
        let lists = whole_list(1, &END);
        for zeros in 1..PACKAGE_LIST_HEADER_SIZE {
            let header = [vec![0; zeros], vec![0xa5; PACKAGE_LIST_HEADER_SIZE - zeros]].concat();
            let length = u32::from_le_bytes(header[16..].try_into().expect("a PackageLength"));
            let region = [&lists[..], &header, &[0xa5; 0x40]].concat();

            let error = read_export(&Region::new(region)).expect_err(&format!("{zeros} zeros"));

            assert_eq!(
                error.downcast_ref::<HiiExportError>(),
                Some(&HiiExportError::PastRegion {
                    offset: 24,
                    length,
                    room: 0x54,
                }),
                "{zeros} zeros"
            );
        }
    }

    /// A package list is taken only where its End package, a header alone, ends exactly at its
    /// PackageLength, whatever the types of the packages before it: a byte more or less, an End
    /// package before another package or longer than its header, or none, refuse the export,
    /// naming where the walk of its packages by Length fails.
    #[test]
    fn read_export_takes_a_list_whose_end_package_ends_at_its_package_length() {
        let packages = guid_package_and_end();
        let exact = whole_list(1, &packages);
        let export = read_export(&Region::new([&exact[..], &[0; 20]].concat()))
            .expect("read a list whose End package ends at its PackageLength");
        assert_eq!(export, exact, "exactly");
        let system = whole_list(
            1,
            &[package(0xe0, &[1]), package(0xff, &[]), END.to_vec()].concat(),
        );
        let export = read_export(&Region::new([&system[..], &[0; 20]].concat()))
            .expect("read a list of packages of the platform firmware's types");
        assert_eq!(export, system, "packages of the platform firmware's types");

        // the GUID package at offset 20 of each list, the End package at 29
        for (case, list, length) in [
            (
                "a byte after the End package",
                whole_list(1, &[&packages[..], &[0]].concat()),
                34,
            ),
            (
                "the End package a byte past the PackageLength",
                whole_list(1, &packages[..12]),
                32,
            ),
            (
                "an End package before another package",
                whole_list(1, &[&packages[..], &END].concat()),
                37,
            ),
            ("no End package", whole_list(1, &packages[..9]), 29),
            (
                "an End package of Length 8",
                whole_list(1, &[&packages[..9], &[8, 0, 0, 0xdf, 0, 0, 0, 0]].concat()),
                37,
            ),
        ] {
            let error = read_export(&Region::new([&list[..], &[0; 20]].concat())).expect_err(case);

            assert_eq!(
                error.downcast_ref::<HiiExportError>(),
                Some(&HiiExportError::Unterminated {
                    offset: 0,
                    length,
                    at: 29
                }),
                "{case}"
            );
        }
    }

    /// A package shorter than its header or past its list's PackageLength refuses the export, and
    /// so does a list of no packages: here edk2's POOL_TAIL after the buffer's package lists
    /// (edk2-stable202608 MdeModulePkg/Core/Dxe/Mem/Pool.c:34-39), whose 16 bytes and a word of 20
    /// after them read as the header of a package list of 20 bytes.
    #[test]
    fn read_export_refuses_packages_that_do_not_walk_to_an_end_package() {
        // a list of a package with this header, then the End package, then a header of zeros
        let list_of =
            |header: [u8; 4]| [whole_list(1, &[header, END].concat()), vec![0; 20]].concat();
        // Signature, Reserved and Size, then the next pool's first word
        let pool_tail = [
            &b"ptal"[..],
            &[0; 4],
            &0x60u64.to_le_bytes(),
            &20u32.to_le_bytes(),
        ];
        for (case, region, want) in [
            (
                "a package of Length 3",
                list_of([3, 0, 0, 0x01]),
                HiiExportError::Unterminated {
                    offset: 0,
                    length: 28,
                    at: 20,
                },
            ),
            (
                "a package past the PackageLength",
                list_of([9, 0, 0, 0x01]),
                HiiExportError::Unterminated {
                    offset: 0,
                    length: 28,
                    at: 20,
                },
            ),
            (
                "edk2's POOL_TAIL after the package lists",
                [&whole_list(1, &END)[..], &pool_tail.concat(), &[0; 64]].concat(),
                HiiExportError::Unterminated {
                    offset: 24,
                    length: 20,
                    at: 20,
                },
            ),
        ] {
            let error = read_export(&Region::new(region)).expect_err(case);

            assert_eq!(
                error.downcast_ref::<HiiExportError>(),
                Some(&want),
                "{case}"
            );
        }
    }

    /// Package lists up to MAX_ALLOWED_FILESIZE bytes are read; one that reaches past it is
    /// refused before it is read.
    #[test]
    fn read_export_reads_no_more_than_the_maximum() {
        let max = usize::try_from(MAX_ALLOWED_FILESIZE).expect("a usize maximum");
        let last = whole_list(2, &END);
        let first_length = max - last.len();
        let data_length = first_length - PACKAGE_LIST_HEADER_SIZE - PACKAGE_HEADER_SIZE - END.len();
        let first = whole_list(
            1,
            &[package(0x01, &vec![0x11; data_length]), END.to_vec()].concat(),
        );
        let at_maximum = [&first[..], &last].concat();
        assert_eq!(at_maximum.len(), max, "the fixture");

        let export = read_export(&Region::new([&at_maximum[..], &[0; 20]].concat()))
            .expect("read an export of the maximum size");
        assert_eq!(export.len(), max, "at the maximum");

        let region = Region::new([&first[..], &whole_list(2, &[0; 5])].concat());
        let error = read_export(&region).expect_err("read past the maximum");
        assert_eq!(
            error.downcast_ref::<HiiExportError>(),
            Some(&HiiExportError::TooLarge {
                length: MAX_ALLOWED_FILESIZE + 1
            }),
            "past the maximum"
        );
        assert_eq!(
            region.reads.borrow().last(),
            Some(&(u64::try_from(first_length).expect("a u64 offset"), 20)),
            "the last read is the header past the maximum"
        );
    }

    /// An export whose region cannot hold its first header is refused with the region's error.
    #[test]
    fn read_export_refuses_a_region_without_a_header() {
        let error = read_export(&Region::new(vec![0x11; 19])).expect_err("read 19 bytes");
        assert_eq!(error.to_string(), "20 bytes run past the region");
    }

    /// read_hii_export reads the export that arm64's FDT locates, through the System Table's
    /// ConfigurationTable, which SetVirtualAddressMap() converted, at the physical address that
    /// the configuration table gives, though it is also a virtual address of another runtime
    /// region, which holds other package lists; it finds none that it does not list.
    #[test]
    fn read_hii_export_reads_the_export_that_the_fdt_locates() {
        use crate::firmware_width::FirmwareWidth;
        use crate::hii::system_table::fixture::arm64_files;
        use crate::hii::system_table::fixture::configuration_table;
        use crate::hii::system_table::fixture::valid_system_table;
        use crate::hii::system_table::fixture::SegmentMemory;
        use crate::memory_map::efi_memory_map::MemoryType;
        use crate::memory_map::efi_memory_map::EFI_MEMORY_RUNTIME;

        // Two runtime regions, each at the other's physical address after
        // SetVirtualAddressMap().
        const REGION_AT: u64 = 0x8000_0000;
        const OTHER_AT: u64 = 0x9000_0000;
        const SYSTEM_TABLE_AT: u64 = REGION_AT + 0x18;
        const ENTRIES_AT: u64 = REGION_AT + 0x200;
        const EXPORT_AT: u64 = REGION_AT + 0x1003;
        let width = FirmwareWidth::Bits64;
        let lists = [whole_list(1, &guid_package_and_end()), whole_list(2, &END)].concat();
        let others = whole_list(9, &[package(0x01, &[0x99; 3]), END.to_vec()].concat());
        for (case, guid, want) in [
            ("listed", EFI_HII_DATABASE_PROTOCOL_GUID, Ok(lists.clone())),
            (
                "unlisted",
                Guid::from([0x5a; 16]),
                Err(HiiExportError::NotListed),
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let region = |physical, virtual_start| {
                (
                    MemoryType::RUNTIME_SERVICES_DATA,
                    physical,
                    virtual_start,
                    16,
                    EFI_MEMORY_RUNTIME | 0xf,
                )
            };
            let files = arm64_files(
                dir.path(),
                "64\n",
                SYSTEM_TABLE_AT,
                &[region(REGION_AT, OTHER_AT), region(OTHER_AT, REGION_AT)],
            );
            let memory = SegmentMemory(vec![
                (
                    SYSTEM_TABLE_AT,
                    valid_system_table(width, 1, OTHER_AT + 0x200),
                ),
                (ENTRIES_AT, configuration_table(width, &[(guid, EXPORT_AT)])),
                (EXPORT_AT, [&lists[..], &[0; 0x40]].concat()),
                (OTHER_AT + 0x1003, [&others[..], &[0; 0x40]].concat()),
            ]);

            let got = read_hii_export(&files, |_, _| Ok(memory));

            match (got, want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{case}"),
                (Err(error), Err(want)) => assert_eq!(
                    error.downcast_ref::<HiiExportError>(),
                    Some(&want),
                    "{case}: {error:#}"
                ),
                (got, want) => panic!("{case}: {got:?}, not {want:?}"),
            }
        }
    }

    /// read_hii_export translates a VendorTable that no runtime region holds physically, as
    /// firmware that converted it at SetVirtualAddressMap() gives it, through the memory map.
    #[test]
    fn read_hii_export_translates_a_converted_vendor_table() {
        use crate::firmware_width::FirmwareWidth;
        use crate::hii::system_table::fixture::arm64_files;
        use crate::hii::system_table::fixture::configuration_table;
        use crate::hii::system_table::fixture::valid_system_table;
        use crate::hii::system_table::fixture::SegmentMemory;
        use crate::memory_map::efi_memory_map::MemoryType;
        use crate::memory_map::efi_memory_map::EFI_MEMORY_RUNTIME;

        const REGION_AT: u64 = 0x8000_0000;
        const VIRTUAL_AT: u64 = 0x2000_0000;
        let width = FirmwareWidth::Bits64;
        let lists = [whole_list(1, &guid_package_and_end()), whole_list(2, &END)].concat();
        let dir = tempfile::tempdir().expect("create a directory");
        let files = arm64_files(
            dir.path(),
            "64\n",
            REGION_AT + 0x18,
            &[(
                MemoryType::RUNTIME_SERVICES_DATA,
                REGION_AT,
                VIRTUAL_AT,
                16,
                EFI_MEMORY_RUNTIME | 0xf,
            )],
        );
        let entries = [(EFI_HII_DATABASE_PROTOCOL_GUID, VIRTUAL_AT + 0x1003)];
        let memory = SegmentMemory(vec![
            (
                REGION_AT + 0x18,
                valid_system_table(width, 1, VIRTUAL_AT + 0x200),
            ),
            (REGION_AT + 0x200, configuration_table(width, &entries)),
            (REGION_AT + 0x1003, [&lists[..], &[0; 0x40]].concat()),
        ]);

        let got = read_hii_export(&files, |_, _| Ok(memory)).expect("read the converted export");

        assert_eq!(got, lists);
    }

    /// The configuration table GUID of the export, as UEFI 2.11 section 34.8.1 spells it.
    #[test]
    fn hii_database_protocol_guid_is_the_specification_s() {
        assert_eq!(
            EFI_HII_DATABASE_PROTOCOL_GUID.to_string(),
            "EF9FC172-A1B2-4693-B327-6D32FC416042"
        );
    }
}
