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

//! The firmware-reserved regions of the full firmware memory map, which bound the efivar
//! source's reads of firmware memory with EfivarMemory::FirmwareReserved: wider than the EFI
//! runtime regions, for firmware that puts the HII database in memory that it reserves
//! without the RUNTIME attribute, but never runtime memory-mapped I/O. Firmware reports some
//! device memory as reserved, as OVMF reports PCIe ECAM (edk2-stable202211
//! OvmfPkg/Library/PlatformInitLib/Platform.c), which a range there may still reach.

use anyhow::Result;

#[cfg(any(target_arch = "aarch64", test))]
use anyhow::Context;

use super::efi_memory_map::EfiMemoryMap;
#[cfg(any(target_arch = "aarch64", test))]
use super::efi_memory_map::MemoryDescriptor;
use super::efi_memory_map::RangeRefusal;
use super::physical_range::PhysicalRange;

/// The firmware-reserved regions of a firmware memory map, and the runtime descriptors of the
/// EFI memory map, whose memory-mapped I/O stays refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::hii) struct FirmwareReservedMap {
    reserved: Vec<PhysicalRange>,
    runtime: EfiMemoryMap,
}

impl FirmwareReservedMap {
    /// The regions `reserved`, without the memory-mapped I/O of `runtime`: x86's, from the
    /// firmware memory map and the runtime-map.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
    pub(in crate::hii) fn new(reserved: Vec<PhysicalRange>, runtime: EfiMemoryMap) -> Self {
        Self { reserved, runtime }
    }

    /// The descriptors of `descriptors`, a whole EFI memory map, whose type firmware reserves
    /// (MemoryType::is_firmware_reserved), without its runtime memory-mapped I/O: arm64's.
    #[cfg(any(target_arch = "aarch64", test))]
    pub(in crate::hii) fn from_efi_descriptors(descriptors: Vec<MemoryDescriptor>) -> Result<Self> {
        let reserved = descriptors
            .iter()
            .filter(|descriptor| descriptor.memory_type.is_firmware_reserved())
            .map(|descriptor| {
                descriptor.physical_range().with_context(|| {
                    format!(
                        "the EFI memory descriptor at {:#x} overflows",
                        descriptor.physical_start
                    )
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            reserved,
            runtime: EfiMemoryMap::new(descriptors)?,
        })
    }

    /// The end of the firmware-reserved region that holds `length` bytes at `address`, which
    /// touch no runtime memory-mapped I/O.
    pub(in crate::hii) fn reserved_range_end(&self, address: u64, length: u64) -> Result<u64> {
        self.runtime.refuse_memory_mapped_io(address, length)?;
        Ok(self
            .reserved
            .iter()
            .find(|region| region.holds(address, length))
            .ok_or(RangeRefusal::NotFirmwareReserved { address, length })?
            .end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hii::firmware_memory::efi_memory_map::fixture::runtime_map;
    use crate::hii::firmware_memory::efi_memory_map::MemoryType;
    use crate::hii::firmware_memory::efi_memory_map::EFI_MEMORY_RUNTIME;

    /// The descriptor of `pages` pages of `memory_type` at `physical_start`, with `attribute`.
    fn descriptor(
        memory_type: MemoryType,
        physical_start: u64,
        pages: u64,
        attribute: u64,
    ) -> MemoryDescriptor {
        MemoryDescriptor {
            memory_type,
            physical_start,
            virtual_start: 0,
            pages,
            attribute,
        }
    }

    /// The end of the region that holds a range, or why none does.
    fn range_end(
        map: &FirmwareReservedMap,
        address: u64,
        length: u64,
    ) -> Result<u64, RangeRefusal> {
        map.reserved_range_end(address, length).map_err(|error| {
            *error
                .downcast_ref::<RangeRefusal>()
                .unwrap_or_else(|| panic!("{address:#x}+{length:#x}: {error:#}"))
        })
    }

    /// arm64's map: a range in one descriptor of a type that firmware reserves, up to its end,
    /// and in none of another type, nor across the end, nor into runtime memory-mapped I/O.
    #[test]
    fn from_efi_descriptors_holds_ranges_in_one_reserved_descriptor() {
        let map = FirmwareReservedMap::from_efi_descriptors(vec![
            descriptor(
                MemoryType::RUNTIME_SERVICES_DATA,
                0x10_0000,
                1,
                EFI_MEMORY_RUNTIME,
            ),
            descriptor(MemoryType::RESERVED, 0x20_0000, 2, 1),
            descriptor(
                MemoryType::MEMORY_MAPPED_IO,
                0x20_1000,
                1,
                EFI_MEMORY_RUNTIME,
            ),
            descriptor(MemoryType::ACPI_MEMORY_NVS, 0x30_0000, 1, 0xf),
            // EfiConventionalMemory and EfiMemoryMappedIO without the RUNTIME attribute
            descriptor(MemoryType(7), 0x40_0000, 1, 0xf),
            descriptor(MemoryType::MEMORY_MAPPED_IO, 0x50_0000, 1, 1),
        ])
        .expect("build the map");
        let not_reserved =
            |address, length| Err(RangeRefusal::NotFirmwareReserved { address, length });
        for (case, address, length, want) in [
            ("runtime data", 0x10_0010, 8, Ok(0x10_1000)),
            ("reserved, up to the device", 0x20_0ff8, 8, Ok(0x20_2000)),
            ("ACPI NVS, up to its end", 0x30_0ff8, 8, Ok(0x30_1000)),
            (
                "across the end of ACPI NVS",
                0x30_0ff8,
                9,
                not_reserved(0x30_0ff8, 9),
            ),
            (
                "conventional memory",
                0x40_0000,
                8,
                not_reserved(0x40_0000, 8),
            ),
            (
                "non-runtime memory-mapped I/O",
                0x50_0000,
                8,
                not_reserved(0x50_0000, 8),
            ),
            (
                "the last byte on runtime memory-mapped I/O",
                0x20_0ff8,
                9,
                Err(RangeRefusal::MemoryMappedIo {
                    address: 0x20_0ff8,
                    length: 9,
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                }),
            ),
            (
                "runtime memory-mapped I/O in reserved memory",
                0x20_0ff8,
                16,
                Err(RangeRefusal::MemoryMappedIo {
                    address: 0x20_0ff8,
                    length: 16,
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                }),
            ),
        ] {
            assert_eq!(range_end(&map, address, length), want, "{case}");
        }
    }

    /// arm64's map fails on a reserved descriptor whose end overflows, and without a runtime
    /// descriptor, as /proc/kcore's zeros are.
    #[test]
    fn from_efi_descriptors_refuses_a_map_that_is_not_one() {
        for (case, descriptors, want) in [
            (
                "an overflowing reserved descriptor",
                vec![
                    descriptor(
                        MemoryType::RUNTIME_SERVICES_DATA,
                        0x10_0000,
                        1,
                        EFI_MEMORY_RUNTIME,
                    ),
                    descriptor(MemoryType::RESERVED, u64::MAX - 0xfff, 2, 0),
                ],
                "the EFI memory descriptor at 0xfffffffffffff000 overflows",
            ),
            (
                "zeros",
                vec![descriptor(MemoryType::RESERVED, 0, 0, 0); 4],
                "the EFI memory map has no runtime descriptors",
            ),
        ] {
            let error = FirmwareReservedMap::from_efi_descriptors(descriptors).expect_err(case);
            assert_eq!(error.to_string(), want, "{case}");
        }
    }

    /// x86's map: the firmware memory map's reserved regions, without the runtime-map's
    /// memory-mapped I/O.
    #[test]
    fn new_holds_ranges_in_one_reserved_region() {
        let map = FirmwareReservedMap::new(
            vec![
                PhysicalRange::new(0x20_0000, 0x2000).expect("a range"),
                PhysicalRange::new(0x30_0000, 0x1000).expect("a range"),
            ],
            runtime_map(&[(0x20_1000, 0, 1, MemoryType::MEMORY_MAPPED_IO)]),
        );
        for (case, address, length, want) in [
            ("reserved", 0x30_0000, 0x1000, Ok(0x30_1000)),
            (
                "between the regions",
                0x20_2000,
                8,
                Err(RangeRefusal::NotFirmwareReserved {
                    address: 0x20_2000,
                    length: 8,
                }),
            ),
            (
                "memory-mapped I/O",
                0x20_1000,
                8,
                Err(RangeRefusal::MemoryMappedIo {
                    address: 0x20_1000,
                    length: 8,
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                }),
            ),
        ] {
            assert_eq!(range_end(&map, address, length), want, "{case}");
        }
    }
}
