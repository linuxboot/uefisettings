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

//! The reads of firmware memory that the efivar source makes: RuntimeMemory
//! checks each against the runtime descriptors of the EFI memory map, and ReservedMemory against
//! the firmware-reserved regions, before PhysicalMemory reads it.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

use super::firmware_reserved::FirmwareReservedMap;
use crate::hii::extract::read_physical_memory_at;
use crate::hii::memory_access_denied::mark_refused_open;
use crate::hii::memory_access_denied::MemoryDevice;
use crate::memory_map::efi_memory_map::EfiMemoryMap;

/// Physical memory, which only RuntimeMemory and ReservedMemory read: only this module makes the
/// ReadToken that read takes.
pub(in crate::hii) trait PhysicalMemory {
    /// `length` bytes at physical `address`.
    fn read(&self, address: u64, length: usize, token: ReadToken) -> Result<Vec<u8>>;
}

/// The proof that RuntimeMemory or ReservedMemory checked a read of PhysicalMemory.
pub(in crate::hii) struct ReadToken(());

/// /dev/mem, read as read_physical_memory_at reads it.
#[derive(Debug)]
pub(in crate::hii) struct DevMem(File);

impl DevMem {
    /// Opens /dev/mem at `path`: the only open of physical memory in the efivar source. A
    /// refusal is under MemoryAccessDenied (mark_refused_open, after the lockdown file
    /// `lockdown`).
    pub(in crate::hii) fn open(path: &Path, lockdown: &Path) -> Result<Self> {
        Self::open_with(path, lockdown, |path| File::open(path))
    }

    /// open, which opens the file with `open_file`.
    fn open_with(
        path: &Path,
        lockdown: &Path,
        open_file: impl FnOnce(&Path) -> io::Result<File>,
    ) -> Result<Self> {
        open_file(path)
            .map(Self)
            .with_context(|| format!("Failed to open {}", path.display()))
            .map_err(|error| mark_refused_open(error, MemoryDevice::DevMem, lockdown))
    }
}

impl PhysicalMemory for DevMem {
    #[expect(
        clippy::disallowed_methods,
        reason = "RuntimeMemory and ReservedMemory read DevMem only after their checks against a \
                  firmware memory map"
    )]
    fn read(&self, address: u64, length: usize, _: ReadToken) -> Result<Vec<u8>> {
        read_physical_memory_at(&self.0, address, length, FileExt::read_exact_at)
    }
}

/// The runtime regions of the EFI memory map `map` in `memory`: all that the efivar source
/// reads by default, so that no firmware pointer leads it elsewhere.
pub(in crate::hii) struct RuntimeMemory<M> {
    map: EfiMemoryMap,
    memory: M,
}

impl<M: PhysicalMemory> RuntimeMemory<M> {
    pub(in crate::hii) fn new(map: EfiMemoryMap, memory: M) -> Self {
        Self { map, memory }
    }

    /// `length` bytes at `address`, which one runtime region must hold.
    pub(in crate::hii) fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.region_end(address, length)?;
        self.memory.read(address, length, ReadToken(()))
    }

    /// The end of the runtime region that holds `length` bytes at `address`.
    pub(in crate::hii) fn region_end(&self, address: u64, length: usize) -> Result<u64> {
        self.map.runtime_range_end(address, u64::try_from(length)?)
    }
}

/// The firmware-reserved regions of `map` in `memory`: all that the efivar source reads with
/// EfivarMemory::FirmwareReserved.
pub(in crate::hii) struct ReservedMemory<M> {
    map: FirmwareReservedMap,
    memory: M,
}

impl<M: PhysicalMemory> ReservedMemory<M> {
    pub(in crate::hii) fn new(map: FirmwareReservedMap, memory: M) -> Self {
        Self { map, memory }
    }

    /// `length` bytes at `address`, which one firmware-reserved region must hold.
    pub(in crate::hii) fn read(&self, address: u64, length: usize) -> Result<Vec<u8>> {
        self.map
            .reserved_range_end(address, u64::try_from(length)?)?;
        self.memory.read(address, length, ReadToken(()))
    }
}

/// Physical memory for the tests of the efivar source.
#[cfg(test)]
pub(in crate::hii) mod fixture {
    use super::*;

    /// Physical memory in `file`, which panics at any read outside `start..end`.
    pub(in crate::hii) struct MemoryWithin {
        file: File,
        start: u64,
        end: u64,
    }

    impl MemoryWithin {
        /// The memory of the file at `path` within `start..end`.
        pub(in crate::hii) fn open(path: &Path, start: u64, end: u64) -> Result<Self> {
            let file =
                File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
            Ok(Self { file, start, end })
        }
    }

    impl PhysicalMemory for MemoryWithin {
        fn read(&self, address: u64, length: usize, _: ReadToken) -> Result<Vec<u8>> {
            let read_end = address + u64::try_from(length).expect("a u64 length");
            assert!(
                self.start <= address && read_end <= self.end,
                "read {address:#x}..{read_end:#x} outside {:#x}..{:#x}",
                self.start,
                self.end
            );
            let mut bytes = vec![0; length];
            self.file.read_exact_at(&mut bytes, address)?;
            Ok(bytes)
        }
    }

    /// Physical memory that must not be read.
    pub(in crate::hii) struct UnreadMemory;

    impl PhysicalMemory for UnreadMemory {
        fn read(&self, address: u64, length: usize, _: ReadToken) -> Result<Vec<u8>> {
            panic!("read {length:#x} bytes at {address:#x}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;
    use crate::hii::lockdown::LockdownMode;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::hii::memory_access_denied::fixture::refused_open;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryAccessDenied;
    use crate::hii::memory_access_denied::MemoryOperation;
    use crate::memory_map::efi_memory_map::fixture::runtime_map;
    use crate::memory_map::efi_memory_map::MemoryType;
    use crate::memory_map::efi_memory_map::RangeRefusal;
    use crate::memory_map::physical_range::PhysicalRange;

    const REGION: u64 = 0x20_0000;
    const PAGES: u64 = 2;
    const REGION_END: u64 = REGION + PAGES * 0x1000;

    /// A file whose bytes at REGION are `bytes`.
    fn memory_file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().expect("create the memory file");
        file.as_file()
            .write_all_at(bytes, REGION)
            .expect("write the memory");
        file
    }

    #[test]
    fn runtime_memory_reads_only_its_runtime_regions() {
        let bytes: Vec<u8> = (0..=255).collect();
        let file = memory_file(&bytes);
        let memory = RuntimeMemory::new(
            runtime_map(&[(REGION, 0, PAGES, MemoryType::RUNTIME_SERVICES_DATA)]),
            MemoryWithin::open(file.path(), REGION, REGION_END).expect("open the memory"),
        );

        let got = memory.read(REGION + 0x10, 0x20).expect("read the region");
        assert_eq!(got, bytes[0x10..0x30], "inside the region");
        for (address, length) in [(REGION_END, 8), (REGION_END - 4, 8), (REGION - 1, 2)] {
            let error = memory
                .read(address, length)
                .expect_err("read outside the runtime region");
            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&RangeRefusal::NotRuntime {
                    address,
                    length: u64::try_from(length).expect("a u64 length"),
                }),
                "{address:#x}+{length:#x}: {error:#}"
            );
        }
    }

    /// A runtime descriptor of memory-mapped I/O is refused before any read.
    #[test]
    fn runtime_memory_reads_no_memory_mapped_io() {
        for memory_type in [
            MemoryType::MEMORY_MAPPED_IO,
            MemoryType::MEMORY_MAPPED_IO_PORT_SPACE,
        ] {
            let memory = RuntimeMemory::new(
                runtime_map(&[(REGION, 0, PAGES, memory_type)]),
                UnreadMemory,
            );

            let error = memory.read(REGION, 8).expect_err("read memory-mapped I/O");

            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&RangeRefusal::MemoryMappedIo {
                    address: REGION,
                    length: 8,
                    memory_type,
                }),
                "{memory_type:?}: {error:#}"
            );
        }
    }

    /// A range that touches memory-mapped I/O is refused before any read, also where an
    /// earlier runtime descriptor that overlaps the device's holds it.
    #[test]
    fn runtime_memory_reads_no_memory_mapped_io_behind_an_overlapping_region() {
        let memory = RuntimeMemory::new(
            runtime_map(&[
                (REGION, 0, PAGES, MemoryType::RUNTIME_SERVICES_DATA),
                (REGION + 0x1000, 0, 1, MemoryType::MEMORY_MAPPED_IO),
            ]),
            UnreadMemory,
        );
        for (address, length) in [(REGION + 0x1000, 8), (REGION + 0xff8, 16)] {
            let error = memory
                .read(address, length)
                .expect_err("read memory-mapped I/O");

            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&RangeRefusal::MemoryMappedIo {
                    address,
                    length: u64::try_from(length).expect("a u64 length"),
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                }),
                "{address:#x}+{length:#x}: {error:#}"
            );
        }
    }

    /// ReservedMemory reads only inside its firmware-reserved regions, and no runtime
    /// memory-mapped I/O there.
    #[test]
    fn reserved_memory_reads_only_its_reserved_regions() {
        let bytes: Vec<u8> = (0..=255).collect();
        let file = memory_file(&bytes);
        let map = || {
            FirmwareReservedMap::new(
                vec![PhysicalRange::new(REGION, PAGES * 0x1000).expect("a range")],
                runtime_map(&[(REGION + 0x1000, 0, 1, MemoryType::MEMORY_MAPPED_IO)]),
            )
        };
        let memory = ReservedMemory::new(
            map(),
            MemoryWithin::open(file.path(), REGION, REGION + 0x100).expect("open the memory"),
        );

        let got = memory.read(REGION + 0x10, 0x20).expect("read the region");

        assert_eq!(got, bytes[0x10..0x30], "inside the region");
        let unread = ReservedMemory::new(map(), UnreadMemory);
        for (address, length, want) in [
            (
                REGION_END,
                8,
                RangeRefusal::NotFirmwareReserved {
                    address: REGION_END,
                    length: 8,
                },
            ),
            (
                REGION + 0xff8,
                16,
                RangeRefusal::MemoryMappedIo {
                    address: REGION + 0xff8,
                    length: 16,
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                },
            ),
        ] {
            let error = unread
                .read(address, length)
                .expect_err("read outside the reserved region");
            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&want),
                "{address:#x}+{length:#x}: {error:#}"
            );
        }
    }

    /// DevMem reads the file as read_physical_memory_at does: with pread() above 1 MiB.
    #[test]
    fn dev_mem_reads_its_file() {
        let bytes: Vec<u8> = (0..=255).rev().collect();
        let file = memory_file(&bytes);
        // read only for EPERM, which no open here gets
        let lockdown = file.path().with_extension("lockdown");
        let dev_mem = DevMem::open(file.path(), &lockdown).expect("open the fake /dev/mem");

        let got = dev_mem
            .read(REGION + 0x80, 0x10, ReadToken(()))
            .expect("read the fake /dev/mem");

        assert_eq!(got, bytes[0x80..0x90]);
        let missing = file.path().with_extension("missing");
        let error = DevMem::open(&missing, &lockdown).expect_err("open a missing /dev/mem");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "Failed to open {}: No such file or directory (os error 2)",
                missing.display()
            )
        );
    }

    /// A refused open of /dev/mem takes its cause from the lockdown file it was given.
    #[test]
    fn dev_mem_open_marks_a_refusal_after_its_lockdown_file() {
        let dir = tempfile::tempdir().expect("create a directory");
        for (mode, cause) in [
            ("integrity", DenialCause::Lockdown(LockdownMode::Integrity)),
            ("none", DenialCause::Capability),
        ] {
            let lockdown = lockdown_file(dir.path(), mode);

            let error = DevMem::open_with(&dir.path().join("mem"), &lockdown, refused_open)
                .expect_err("open a refusing /dev/mem");

            assert_eq!(
                error.downcast_ref::<MemoryAccessDenied>(),
                Some(&MemoryAccessDenied {
                    device: MemoryDevice::DevMem,
                    operation: MemoryOperation::Open,
                    cause,
                }),
                "{mode}: {error:#}"
            );
        }
    }
}
