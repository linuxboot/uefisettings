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

//! The runtime descriptors of the EFI memory map, which bound the efivar source's
//! reads of firmware memory. arm64 Linux gets the map from the EFI stub (fdt_params); x86 Linux
//! exports the descriptors that it maps for runtime services at /sys/firmware/efi/runtime-map:
//! RUNTIME descriptors, plus boot-services ones with efi=debug and RAM ones in mixed mode
//! (arch/x86/platform/efi/efi.c should_map_region(); otherwise quirks.c efi_free_boot_services()
//! drops boot services memory before runtime-map.c's initcall, Linux v6.11). EfiMemoryMap keeps
//! only RUNTIME. The UEFI Shell build bounds its reads of configuration tables with the memory
//! map of boot services the same way (uefi_config_table.rs).

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::physical_range::PhysicalRange;
#[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
use crate::hii::firmware_memory::array_at;
#[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
use crate::hii::firmware_memory::le_u64_at;

/// EFI_MEMORY_RUNTIME (include/linux/efi.h).
pub(crate) const EFI_MEMORY_RUNTIME: u64 = 1 << 63;
/// The size of an EFI page (include/linux/efi.h EFI_PAGE_SHIFT).
const EFI_PAGE_SIZE: u64 = 1 << 12;
/// EFI_MEMORY_DESCRIPTOR_VERSION (include/linux/efi.h), the layout of efi_memory_desc_t.
#[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
const MEMORY_DESCRIPTOR_VERSION: u32 = 1;
/// The bytes of efi_memory_desc_t (include/linux/efi.h) that a descriptor of the memory map
/// starts with: type, pad, phys_addr, virt_addr, num_pages, attribute.
#[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
const MEMORY_DESCRIPTOR_SIZE: usize = 40;

/// An EFI_MEMORY_TYPE (UEFI 2.11 §7.2.1), whose values firmware and OS loaders extend from
/// 0x70000000 on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryType(pub u32);

impl MemoryType {
    /// EfiReservedMemoryType (EFI_MEMORY_TYPE; include/linux/efi.h).
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) const RESERVED: Self = Self(0);
    /// EfiRuntimeServicesCode (EFI_MEMORY_TYPE; include/linux/efi.h).
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) const RUNTIME_SERVICES_CODE: Self = Self(5);
    /// EfiRuntimeServicesData (EFI_MEMORY_TYPE; include/linux/efi.h).
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) const RUNTIME_SERVICES_DATA: Self = Self(6);
    /// EfiACPIMemoryNVS (EFI_MEMORY_TYPE; include/linux/efi.h).
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) const ACPI_MEMORY_NVS: Self = Self(10);
    /// EfiMemoryMappedIO (UEFI 2.11 §7.2.1 EFI_MEMORY_TYPE).
    pub const MEMORY_MAPPED_IO: Self = Self(11);
    /// EfiMemoryMappedIOPortSpace (UEFI 2.11 §7.2.1 EFI_MEMORY_TYPE).
    pub const MEMORY_MAPPED_IO_PORT_SPACE: Self = Self(12);
    /// EfiPalCode (EFI_MEMORY_TYPE; include/linux/efi.h).
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) const PAL_CODE: Self = Self(13);

    /// Whether memory of this type is a device's, which firmware asks the OS to map for
    /// runtime services (UEFI 2.11 §7.2 Table 7.5).
    fn is_memory_mapped_io(self) -> bool {
        matches!(
            self,
            Self::MEMORY_MAPPED_IO | Self::MEMORY_MAPPED_IO_PORT_SPACE
        )
    }

    /// Whether firmware keeps memory of this type from the OS: EfiReservedMemoryType, runtime
    /// services code and data, EfiACPIMemoryNVS and EfiPalCode, which arm64 Linux does not take
    /// as System RAM (drivers/firmware/efi/efi-init.c is_usable_memory(); edk2
    /// MdePkg/Include/Uefi/UefiMultiPhase.h EFI_MEMORY_TYPE).
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) fn is_firmware_reserved(self) -> bool {
        matches!(
            self,
            Self::RESERVED
                | Self::RUNTIME_SERVICES_CODE
                | Self::RUNTIME_SERVICES_DATA
                | Self::ACPI_MEMORY_NVS
                | Self::PAL_CODE
        )
    }
}

/// The fields of an EFI memory descriptor (include/linux/efi.h efi_memory_desc_t) that
/// EfiMemoryMap keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemoryDescriptor {
    pub(crate) memory_type: MemoryType,
    pub(crate) physical_start: u64,
    pub(crate) virtual_start: u64,
    pub(crate) pages: u64,
    pub(crate) attribute: u64,
}

impl MemoryDescriptor {
    /// The descriptor that `bytes`, an efi_memory_desc_t, starts with.
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            memory_type: array_at(bytes, 0)
                .map(|memory_type| MemoryType(u32::from_le_bytes(memory_type)))
                .context("no type in an EFI memory descriptor")?,
            physical_start: le_u64_at(bytes, 8)?,
            virtual_start: le_u64_at(bytes, 16)?,
            pages: le_u64_at(bytes, 24)?,
            attribute: le_u64_at(bytes, 32)?,
        })
    }

    /// The pages of the descriptor, unless their end overflows.
    pub(crate) fn physical_range(&self) -> Option<PhysicalRange> {
        PhysicalRange::new(self.physical_start, self.pages.checked_mul(EFI_PAGE_SIZE)?)
    }

    /// The descriptors of the memory map `map` of `desc_size`-byte descriptors of version
    /// `desc_ver`, which must hold whole descriptors.
    #[cfg(any(all(firmware_memory_maps, target_arch = "aarch64"), test))]
    pub(crate) fn parse_map(map: &[u8], desc_size: usize, desc_ver: u32) -> Result<Vec<Self>> {
        if desc_ver != MEMORY_DESCRIPTOR_VERSION {
            bail!("EFI memory descriptor version {desc_ver} is not {MEMORY_DESCRIPTOR_VERSION}");
        }
        if desc_size < MEMORY_DESCRIPTOR_SIZE {
            bail!(
                "EFI memory descriptors of {desc_size} bytes are shorter than \
                 {MEMORY_DESCRIPTOR_SIZE}"
            );
        }
        if map.is_empty() || !map.len().is_multiple_of(desc_size) {
            bail!(
                "an EFI memory map of {} bytes holds no whole number of {desc_size}-byte \
                 descriptors",
                map.len()
            );
        }
        map.chunks_exact(desc_size).map(Self::parse).collect()
    }
}

/// Why a source reads no firmware memory at a range.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RangeRefusal {
    /// No EFI_MEMORY_RUNTIME descriptor holds the whole range.
    #[error("{address:#x}+{length:#x} lies in no EFI_MEMORY_RUNTIME region")]
    NotRuntime { address: u64, length: u64 },
    /// No single firmware-reserved region holds the whole range (EfivarMemory::FirmwareReserved).
    #[cfg(any(firmware_memory_maps, test))]
    #[error("{address:#x}+{length:#x} lies in no firmware-reserved region")]
    NotFirmwareReserved { address: u64, length: u64 },
    /// The range touches a runtime descriptor of memory-mapped I/O.
    #[error(
        "{address:#x}+{length:#x} lies in memory-mapped I/O, EFI memory type {}",
        .memory_type.0
    )]
    MemoryMappedIo {
        address: u64,
        length: u64,
        memory_type: MemoryType,
    },
}

/// An EFI_MEMORY_RUNTIME descriptor of the EFI memory map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeDescriptor {
    memory_type: MemoryType,
    range: PhysicalRange,
    /// The addresses from VirtualStart on that SetVirtualAddressMap() gave the range, unless they
    /// overflow, as from the U64_MAX with which arm64's EFI stub marks a failed call (Linux v6.11
    /// drivers/firmware/efi/libstub/fdt.c:310-322).
    #[cfg(any(firmware_memory_maps, test))]
    virtual_range: Option<PhysicalRange>,
}

/// The runtime descriptors of an EFI memory map, in the order given to new.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EfiMemoryMap {
    runtime: Vec<RuntimeDescriptor>,
}

impl EfiMemoryMap {
    /// The runtime descriptors of `descriptors`, in their order. At least one must be
    /// EFI_MEMORY_RUNTIME: a real map always has runtime code and data, and /proc/kcore reads a
    /// page that it cannot read as zeros.
    pub(crate) fn new(descriptors: impl IntoIterator<Item = MemoryDescriptor>) -> Result<Self> {
        let runtime = descriptors
            .into_iter()
            .filter(|descriptor| descriptor.attribute & EFI_MEMORY_RUNTIME != 0)
            .map(|descriptor| {
                let range = descriptor.physical_range().with_context(|| {
                    format!(
                        "the EFI runtime descriptor at {:#x} overflows",
                        descriptor.physical_start
                    )
                })?;
                Ok(RuntimeDescriptor {
                    memory_type: descriptor.memory_type,
                    range,
                    #[cfg(any(firmware_memory_maps, test))]
                    virtual_range: PhysicalRange::new(descriptor.virtual_start, range.size()),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if runtime.is_empty() {
            bail!("the EFI memory map has no runtime descriptors");
        }
        Ok(Self { runtime })
    }

    /// The end of the runtime descriptor whose physical range holds `length` bytes at
    /// `address`: the only memory that the efivar source reads by default
    /// (EfivarMemory::Runtime). Firmware pointers may be
    /// wrong, or virtual where the source takes them as physical, and point at a device, which
    /// a read may change: memory-mapped I/O that runtime services use is runtime too (UEFI 2.11
    /// §7.2 Table 7.5), so a range that touches any of its descriptors is refused.
    pub(crate) fn runtime_range_end(&self, address: u64, length: u64) -> Result<u64> {
        self.refuse_memory_mapped_io(address, length)?;
        Ok(self
            .runtime
            .iter()
            .find(|descriptor| descriptor.range.holds(address, length))
            .ok_or(RangeRefusal::NotRuntime { address, length })?
            .range
            .end())
    }

    /// Whether a runtime descriptor's physical range holds the byte at `address`.
    #[cfg(any(firmware_memory_maps, test))]
    pub(crate) fn holds(&self, address: u64) -> bool {
        self.runtime
            .iter()
            .any(|descriptor| descriptor.range.holds(address, 1))
    }

    /// The physical address of `address`, a virtual address of the map that the OS gave
    /// SetVirtualAddressMap() (UEFI 2.11 §8.4.1): the same offset in the first runtime descriptor
    /// whose virtual range holds it, if any. Linux gives each runtime descriptor virtual addresses
    /// of its own, and VirtualStart equal to PhysicalStart where its EFI stub calls no
    /// SetVirtualAddressMap() (Linux v6.11 drivers/firmware/efi/libstub/efi-stub.c:248-249).
    #[cfg(any(firmware_memory_maps, test))]
    pub(crate) fn physical_address(&self, address: u64) -> Option<u64> {
        self.runtime.iter().find_map(|descriptor| {
            let virtual_range = descriptor.virtual_range?;
            let offset = address.checked_sub(virtual_range.start())?;
            virtual_range
                .holds(address, 1)
                .then_some(offset)
                .and_then(|offset| descriptor.range.start().checked_add(offset))
        })
    }

    /// Refuses `length` bytes at `address` that touch a runtime descriptor of memory-mapped I/O.
    pub(crate) fn refuse_memory_mapped_io(
        &self,
        address: u64,
        length: u64,
    ) -> Result<(), RangeRefusal> {
        match self.runtime.iter().find(|descriptor| {
            descriptor.memory_type.is_memory_mapped_io()
                && descriptor.range.overlaps(address, length)
        }) {
            Some(device) => Err(RangeRefusal::MemoryMappedIo {
                address,
                length,
                memory_type: device.memory_type,
            }),
            None => Ok(()),
        }
    }
}

/// Memory maps for the tests of the efivar source.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    /// An EFI memory descriptor of `desc_size` bytes.
    pub(crate) fn descriptor(
        desc_size: usize,
        memory_type: MemoryType,
        physical: u64,
        virtual_start: u64,
        pages: u64,
        attribute: u64,
    ) -> Vec<u8> {
        let mut bytes = [
            memory_type.0.to_le_bytes().to_vec(),
            vec![0; 4],
            physical.to_le_bytes().to_vec(),
            virtual_start.to_le_bytes().to_vec(),
            pages.to_le_bytes().to_vec(),
            attribute.to_le_bytes().to_vec(),
        ]
        .concat();
        bytes.resize(desc_size, 0xa5);
        bytes
    }

    /// A memory map of the runtime regions `regions` of (physical start, virtual start, pages,
    /// type).
    pub(crate) fn runtime_map(regions: &[(u64, u64, u64, MemoryType)]) -> EfiMemoryMap {
        EfiMemoryMap::new(regions.iter().map(
            |&(physical_start, virtual_start, pages, memory_type)| MemoryDescriptor {
                memory_type,
                physical_start,
                virtual_start,
                pages,
                attribute: EFI_MEMORY_RUNTIME,
            },
        ))
        .expect("a runtime map")
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    /// EfiConventionalMemory, which is not runtime.
    const CONVENTIONAL_MEMORY: MemoryType = MemoryType(7);
    const RUNTIME_DATA: MemoryType = MemoryType::RUNTIME_SERVICES_DATA;

    fn memory_map(descriptors: &[Vec<u8>], desc_size: usize) -> EfiMemoryMap {
        MemoryDescriptor::parse_map(&descriptors.concat(), desc_size, 1)
            .and_then(EfiMemoryMap::new)
            .expect("parse the memory map")
    }

    /// As after SetVirtualAddressMap() on Ampere eMAG, whose stub maps from 512 MiB, behind a
    /// descriptor that is not runtime.
    fn svam_map() -> EfiMemoryMap {
        let desc_size = 48;
        memory_map(
            &[
                descriptor(desc_size, CONVENTIONAL_MEMORY, 0x4000_0000, 0, 0x1000, 0xf),
                descriptor(
                    desc_size,
                    MemoryType::RUNTIME_SERVICES_DATA,
                    0x7ffd_0000,
                    0x2058_0000,
                    0x10,
                    EFI_MEMORY_RUNTIME | 0xf,
                ),
                descriptor(
                    desc_size,
                    MemoryType::RUNTIME_SERVICES_DATA,
                    0x7c75_0000,
                    0x2050_0000,
                    0x2,
                    EFI_MEMORY_RUNTIME | 0xf,
                ),
            ],
            desc_size,
        )
    }

    #[test]
    fn runtime_range_end_holds_only_ranges_inside_a_runtime_descriptor() {
        let map = svam_map();
        for (address, length, want) in [
            (0x7ffd_fb18, 24, Some(0x7ffe_0000)),
            (0x7ffd_0000, 0x1_0000, Some(0x7ffe_0000)),
            (0x7c75_1ff0, 0x10, Some(0x7c75_2000)),
            // past a runtime descriptor's end, in a descriptor that is not runtime, in none,
            // an untranslated eMAG pointer, which pointed into a PCI window, and an overflow
            (0x7ffd_fff0, 0x11, None),
            (0x4000_1000, 1, None),
            (0x9000_0000, 1, None),
            (0x2058_fb18, 24, None),
            (u64::MAX, 2, None),
        ] {
            match (map.runtime_range_end(address, length), want) {
                (Ok(got), Some(want)) => assert_eq!(got, want, "{address:#x}+{length:#x}"),
                (Err(error), None) => assert_eq!(
                    error.downcast_ref::<RangeRefusal>(),
                    Some(&RangeRefusal::NotRuntime { address, length }),
                    "{address:#x}+{length:#x}: {error:#}"
                ),
                (got, want) => panic!("{address:#x}+{length:#x}: got {got:?}, want {want:?}"),
            }
        }
    }

    /// physical_address translates an address of a runtime descriptor's virtual range to the
    /// same offset of its physical range, as after SetVirtualAddressMap() on eMAG; addresses of no
    /// virtual range translate nothing, nor do those of a descriptor that is not runtime or whose
    /// virtual range overflows, as after a failed call. holds tells the physical ranges.
    #[test]
    fn physical_address_translates_through_the_virtual_ranges() {
        let map = svam_map();
        for (address, want) in [
            (0x2058_fb18, Some(0x7ffd_fb18)),
            (0x2058_0000, Some(0x7ffd_0000)),
            (0x2058_ffff, Some(0x7ffd_ffff)),
            (0x2050_1ff0, Some(0x7c75_1ff0)),
            // past a virtual range's end, before its start, a physical address, and the virtual
            // start of the descriptor that is not runtime
            (0x2059_0000, None),
            (0x204f_ffff, None),
            (0x7ffd_fb18, None),
            (0, None),
        ] {
            assert_eq!(map.physical_address(address), want, "{address:#x}");
        }
        for (address, want) in [
            (0x7ffd_fb18, true),
            (0x7c75_1fff, true),
            (0x7c75_2000, false),
            (0x4000_1000, false),
            (0x2058_fb18, false),
        ] {
            assert_eq!(map.holds(address), want, "holds {address:#x}");
        }

        let failed = runtime_map(&[(0x7ffd_0000, u64::MAX, 0x10, RUNTIME_DATA)]);
        assert_eq!(failed.physical_address(u64::MAX), None, "U64_MAX");
        let identity = runtime_map(&[(0x7ffd_0000, 0x7ffd_0000, 0x10, RUNTIME_DATA)]);
        assert_eq!(
            identity.physical_address(0x7ffd_fb18),
            Some(0x7ffd_fb18),
            "VirtualStart equal to PhysicalStart"
        );
    }

    /// Runtime descriptors of memory-mapped I/O, of either type, are refused, as the map that
    /// the stub passes lists them.
    #[test]
    fn runtime_range_end_refuses_memory_mapped_io() {
        let desc_size = 48;
        for memory_type in [
            MemoryType::MEMORY_MAPPED_IO,
            MemoryType::MEMORY_MAPPED_IO_PORT_SPACE,
        ] {
            let map = memory_map(
                &[
                    descriptor(
                        desc_size,
                        RUNTIME_DATA,
                        0x7ffd_0000,
                        0x2058_0000,
                        0x10,
                        EFI_MEMORY_RUNTIME,
                    ),
                    descriptor(
                        desc_size,
                        memory_type,
                        0x9000_0000,
                        0x2060_0000,
                        0x10,
                        EFI_MEMORY_RUNTIME,
                    ),
                ],
                desc_size,
            );

            let error = map
                .runtime_range_end(0x9000_0010, 8)
                .expect_err("hold memory-mapped I/O");

            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&RangeRefusal::MemoryMappedIo {
                    address: 0x9000_0010,
                    length: 8,
                    memory_type,
                }),
                "{memory_type:?}: {error:#}"
            );
            assert_eq!(
                map.runtime_range_end(0x7ffd_0010, 8)
                    .expect("hold runtime data"),
                0x7ffe_0000,
                "{memory_type:?}: runtime data"
            );
        }
    }

    /// A runtime descriptor of memory-mapped I/O refuses every range that touches it, also where
    /// an earlier runtime descriptor holds the range, as in a malformed map whose descriptors
    /// overlap.
    #[test]
    fn runtime_range_end_refuses_memory_mapped_io_behind_an_overlapping_region() {
        let map = runtime_map(&[
            (0x7ffd_0000, 0, 3, RUNTIME_DATA),
            (0x7ffd_1000, 0, 1, MemoryType::MEMORY_MAPPED_IO),
        ]);
        for (case, address, length, want) in [
            ("inside the device", 0x7ffd_1000, 8, None),
            ("across the device's start", 0x7ffd_0ff8, 16, None),
            ("across the device's end", 0x7ffd_1ff8, 16, None),
            (
                "up to the device's start",
                0x7ffd_0ff8,
                8,
                Some(0x7ffd_3000),
            ),
            ("from the device's end", 0x7ffd_2000, 8, Some(0x7ffd_3000)),
        ] {
            match (map.runtime_range_end(address, length), want) {
                (Ok(got), Some(want)) => assert_eq!(got, want, "{case}"),
                (Err(error), None) => assert_eq!(
                    error.downcast_ref::<RangeRefusal>(),
                    Some(&RangeRefusal::MemoryMappedIo {
                        address,
                        length,
                        memory_type: MemoryType::MEMORY_MAPPED_IO,
                    }),
                    "{case}: {error:#}"
                ),
                (got, want) => panic!("{case}: got {got:?}, want {want:?}"),
            }
        }
    }

    /// Firmware reserves EfiReservedMemoryType, runtime services code and data, EfiACPIMemoryNVS
    /// and EfiPalCode, and no other type.
    #[test]
    fn is_firmware_reserved_holds_for_the_types_that_firmware_keeps() {
        for value in (0..=16).chain([0x7000_0000, 0x8000_0000]) {
            let want = matches!(value, 0 | 5 | 6 | 10 | 13);
            assert_eq!(
                MemoryType(value).is_firmware_reserved(),
                want,
                "EFI memory type {value:#x}"
            );
        }
    }

    #[test]
    fn parse_refuses_a_map_that_is_not_one() {
        let runtime = descriptor(48, RUNTIME_DATA, 0x7ffd_0000, 0, 0x10, EFI_MEMORY_RUNTIME);
        for (case, map, desc_size, desc_ver, want) in [
            (
                "zeros",
                vec![0; 4 * 48],
                48,
                1,
                "the EFI memory map has no runtime descriptors",
            ),
            (
                "short descriptors",
                vec![0; 4 * 32],
                32,
                1,
                "EFI memory descriptors of 32 bytes are shorter than 40",
            ),
            (
                "another version",
                runtime.clone(),
                48,
                2,
                "EFI memory descriptor version 2 is not 1",
            ),
            (
                "a partial descriptor",
                [&runtime[..], &[0; 8]].concat(),
                48,
                1,
                "an EFI memory map of 56 bytes holds no whole number of 48-byte descriptors",
            ),
            (
                "no descriptors",
                Vec::new(),
                48,
                1,
                "an EFI memory map of 0 bytes holds no whole number of 48-byte descriptors",
            ),
            (
                "an overflowing descriptor",
                descriptor(48, RUNTIME_DATA, u64::MAX - 0xfff, 0, 2, EFI_MEMORY_RUNTIME),
                48,
                1,
                "the EFI runtime descriptor at 0xfffffffffffff000 overflows",
            ),
        ] {
            let error = MemoryDescriptor::parse_map(&map, desc_size, desc_ver)
                .and_then(EfiMemoryMap::new)
                .expect_err("parse a map that is not one");
            assert_eq!(error.to_string(), want, "{case}");
        }
    }
}
