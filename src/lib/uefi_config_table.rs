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

//! The configuration tables of the EFI System Table (UEFI 2.11 §4.6) of the firmware that the
//! UEFI Shell build runs on, read in place while boot services run and memory is identity-mapped.

use std::slice;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use uefi::boot;
use uefi::boot::MemoryType;
use uefi::mem::memory_map::MemoryMap;

use crate::efi_variables::VendorTable;
use crate::firmware_width::FirmwareWidth;
use crate::hii::package::Guid;
use crate::memory_map::efi_memory_map;
use crate::memory_map::efi_memory_map::EfiMemoryMap;
use crate::unaligned_array::read_unaligned_array;

/// A configuration table that the System Table lists: its VendorTable, and the runtime
/// descriptors of the memory map, which bound its reads as they bound the Linux build's
/// (EfiMemoryMap::runtime_range_end).
pub(crate) struct SystemConfigurationTable {
    start: *const u8,
    memory_map: EfiMemoryMap,
}

impl SystemConfigurationTable {
    /// The table of `guid` that the System Table lists, if any. It reads the entries one by one,
    /// at any alignment, as uefi::system::with_config_table panics on a misaligned
    /// ConfigurationTable (uefi 0.41.0 src/system.rs:99).
    pub(crate) fn find(guid: &Guid) -> Result<Option<Self>> {
        let system_table = uefi::table::system_table_raw().context("no system table")?;
        // SAFETY: the system table of the firmware, which the entry point set and boot services
        // keep
        let system_table = unsafe { system_table.as_ref() };
        let entries = system_table.configuration_table.cast_const();
        if entries.is_null() {
            return Ok(None);
        }
        // SAFETY: ConfigurationTable points at NumberOfTableEntries EFI_CONFIGURATION_TABLE
        // entries (UEFI 2.11 §4.3.1), at any alignment, which nothing changes before find returns
        let mut entries = unsafe {
            read_unaligned_array(entries, system_table.number_of_configuration_table_entries)
        };
        let Some(start) = entries
            .find(|entry| Guid::from(entry.vendor_guid) == *guid)
            .map(|entry| entry.vendor_table.cast_const().cast::<u8>())
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            start,
            memory_map: runtime_memory_map()?,
        }))
    }
}

impl VendorTable for SystemConfigurationTable {
    fn read(&self, len: usize) -> Result<Vec<u8>> {
        // The Linux build's bound, refusing in its words: only EFI_MEMORY_RUNTIME memory that is
        // no memory-mapped I/O. The JSON configuration tables lie in such memory: their
        // VendorTable "will be fixed up" at SetVirtualAddressMap() (UEFI 2.11 §4.6.1.2), whose
        // VirtualMap maps "all runtime ranges" (§8.4.1).
        self.memory_map
            .runtime_range_end(u64::try_from(self.start.addr())?, u64::try_from(len)?)?;
        if self.start.is_null() {
            bail!("the VendorTable is NULL");
        }
        // SAFETY: `len` bytes from `start`, which is not NULL, lie in one EFI_MEMORY_RUNTIME
        // region of the memory map that is no memory-mapped I/O, and u8 aligns anywhere. Boot
        // services run, when "any memory space defined by the UEFI memory map is identity mapped
        // (virtual address equals physical address)" (UEFI 2.11 §2.3.2 IA-32, if paging is
        // enabled, and §2.3.4 x64), as is "any RAM defined by the UEFI memory map" (§2.3.6
        // AArch64), so the region's physical addresses are those read
        let bytes = unsafe { slice::from_raw_parts(self.start, len) };
        Ok(bytes.to_vec())
    }

    fn firmware_width(&self) -> FirmwareWidth {
        FirmwareWidth::of_this_build()
    }
}

/// The EFI memory map of boot services, as EfiMemoryMap keeps it.
fn runtime_memory_map() -> Result<EfiMemoryMap> {
    let map = boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|error| anyhow!("GetMemoryMap(): {:?}", error.status()))?;
    EfiMemoryMap::new(
        map.entries()
            .map(|descriptor| efi_memory_map::MemoryDescriptor {
                memory_type: efi_memory_map::MemoryType(descriptor.ty.0),
                physical_start: descriptor.phys_start,
                virtual_start: descriptor.virt_start,
                pages: descriptor.page_count,
                attribute: descriptor.att.bits(),
            }),
    )
}
