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

//! The EFI System Table (UEFI 2.11 §4.3) of the firmware that Linux booted on, and the
//! configuration tables that it lists (§4.6), read from physical memory after ExitBootServices():
//! x86 Linux tells where the System Table is in boot_params and where its configuration table
//! entries are in /sys/firmware/efi/config_table, arm64 Linux in the FDT. Every read is
//! RuntimeMemory's, inside one EFI_MEMORY_RUNTIME region (§7.2.3) of the firmware's memory map:
//! firmware allocates the System Table and its entries as EfiRuntimeServicesData (§7.5.6
//! InstallConfigurationTable(); edk2-stable202608 MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c:301).

#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
pub(super) mod boot_params;
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "no caller reads the configuration export yet")
)]
mod exported_config;
mod hii_export;

#[cfg(any(target_arch = "aarch64", test))]
use std::fs;
#[cfg(any(target_arch = "aarch64", test))]
use std::io;
use std::path::Path;
use std::path::PathBuf;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use crate::efi_variables::VendorTable;
#[cfg(any(target_arch = "aarch64", test))]
use crate::firmware_width::read_fw_platform_size;
use crate::firmware_width::FirmwareWidth;
#[cfg(target_arch = "aarch64")]
use crate::firmware_width::FW_PLATFORM_SIZE_PATH;
#[cfg(any(target_arch = "aarch64", test))]
use crate::hii::firmware_memory::fdt_params::uefi_system_table;
#[cfg(any(target_arch = "aarch64", test))]
use crate::hii::firmware_memory::fdt_params::FdtSystemTable;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
use crate::hii::firmware_memory::read_sysfs_hex;
use crate::hii::firmware_memory::runtime_memory::DevMem;
use crate::hii::firmware_memory::runtime_memory::PhysicalMemory;
use crate::hii::firmware_memory::runtime_memory::RuntimeMemory;
use crate::hii::firmware_memory::MemoryMapFiles;
#[cfg(any(target_arch = "aarch64", test))]
use crate::hii::firmware_memory::MemoryMapUnavailable;
#[cfg(target_arch = "aarch64")]
use crate::hii::firmware_memory::FDT_PATH;
use crate::hii::lockdown::refuse_locked_down;
use crate::hii::lockdown::LOCKDOWN_PATH;
use crate::hii::memory_access_denied::MemoryDevice;
use crate::hii::package::Guid;
use crate::memory_map::efi_memory_map::EfiMemoryMap;
#[expect(
    unused_imports,
    reason = "no caller reads the configuration export yet"
)]
pub(in crate::hii) use exported_config::read_exported_config;
#[expect(
    unused_imports,
    reason = "no caller reads the configuration export yet"
)]
pub use exported_config::ExportedConfigError;
pub(in crate::hii) use hii_export::read_hii_export;
pub use hii_export::HiiExportError;
pub(in crate::hii) use hii_export::EFI_HII_DATABASE_PROTOCOL_GUID;

/// EFI_SYSTEM_TABLE_SIGNATURE (UEFI 2.11 §4.3.1).
const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249;
/// The size of EFI_TABLE_HEADER: Signature, Revision, HeaderSize, CRC32 and Reserved (UEFI 2.11
/// §4.2.1).
const TABLE_HEADER_SIZE: usize = 24;
/// The offset of HeaderSize in EFI_TABLE_HEADER.
const HEADER_SIZE_OFFSET: usize = 12;
/// The size of EFI_GUID, which starts an EFI_CONFIGURATION_TABLE (UEFI 2.11 §4.6.1).
const GUID_SIZE: usize = 16;
/// The most configuration tables that uefisettings reads, far above the two dozen kinds that
/// UEFI 2.11 §4.6 names, each listed at most once.
pub(in crate::hii) const MAX_TABLE_ENTRIES: u64 = 1024;
/// The physical address of the System Table's ConfigurationTable, which x86 Linux keeps from
/// before SetVirtualAddressMap() (Linux v6.11 Documentation/ABI/testing/sysfs-firmware-efi:15-20;
/// arch/x86/platform/efi/efi.c:414, 425, 930), also across kexec (efi.c:406).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const CONFIG_TABLE_PATH: &str = "/sys/firmware/efi/config_table";

/// Why uefisettings reads no EFI System Table, or no configuration table of it, on Linux. The
/// messages spell "section", as PayloadError's do.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SystemTableError {
    /// x86's boot_params ends before efi_info's efi_systab_hi.
    #[error("boot_params holds {length} bytes, which end before efi_info's efi_systab_hi")]
    BootParamsShort { length: usize },
    /// x86's efi_info has neither loader signature of EFI firmware: Linux was not booted through
    /// EFI.
    #[error(
        "efi_info's loader signature is \"{}\", neither \"EL64\" nor \"EL32\": Linux was not \
         booted through EFI",
        .signature.escape_ascii()
    )]
    NotBootedByEfi { signature: [u8; 4] },
    /// Linux gives the System Table's address as 0.
    #[error("Linux gives the EFI System Table's address as 0")]
    NoSystemTable,
    /// arm64's FDT has no linux,uefi-system-table in /chosen, and no /hypervisor/uefi that holds
    /// xen,uefi-system-table: Linux finds no UEFI (Linux v6.11
    /// drivers/firmware/efi/fdtparams.c:107-109, :118-122, :130-132).
    #[error(
        "the FDT has no linux,uefi-system-table in /chosen and no xen,uefi-system-table in \
         /hypervisor/uefi: Linux finds no UEFI"
    )]
    NoUefiInFdt,
    /// arm64's FDT has no linux,uefi-system-table in /chosen, and its /hypervisor/uefi holds
    /// Xen's xen,uefi-system-table (Linux v6.11 drivers/firmware/efi/fdtparams.c:38-41).
    #[error(
        "the FDT has no linux,uefi-system-table in /chosen, and its /hypervisor/uefi holds Xen's \
         xen,uefi-system-table, which uefisettings does not support"
    )]
    XenUefiInFdt,
    /// Hdr.Signature is not EFI_SYSTEM_TABLE_SIGNATURE.
    #[error(
        "the EFI System Table at {address:#x} has the signature {signature:#018x}, not \
         EFI_SYSTEM_TABLE_SIGNATURE {EFI_SYSTEM_TABLE_SIGNATURE:#018x} (UEFI 2.11 section 4.3.1)"
    )]
    Signature { address: u64, signature: u64 },
    /// Hdr.HeaderSize, the size of the whole table, ends before the fields that uefisettings
    /// reads.
    #[error(
        "the EFI System Table's HeaderSize {header_size} ends before the {needed} bytes up to its \
         ConfigurationTable (UEFI 2.11 sections 4.2.1, 4.3.1)"
    )]
    HeaderSize { header_size: u32, needed: usize },
    /// NumberOfTableEntries is implausible.
    #[error(
        "the EFI System Table lists {count} configuration tables, more than the \
         {MAX_TABLE_ENTRIES} that uefisettings reads"
    )]
    TooManyEntries { count: u64 },
    /// ConfigurationTable is NULL, but NumberOfTableEntries is not 0.
    #[error("the EFI System Table's ConfigurationTable is NULL, with {count} entries")]
    NullConfigurationTable { count: u64 },
    /// A VendorGuid that the configuration table lists more than once.
    #[error(
        "the EFI Configuration Table lists {guid} {count} times, but holds at most one table of \
         each GUID (UEFI 2.11 section 4.6)"
    )]
    DuplicateEntry { guid: Guid, count: usize },
    /// A VendorTable that is NULL.
    #[error("the EFI Configuration Table's entry of {guid} has a NULL VendorTable")]
    NullVendorTable { guid: Guid },
    /// A runtime region that holds a configuration table but ends before its address.
    #[error(
        "the runtime region that holds the configuration table at {address:#x} ends at {end:#x}, \
         before it"
    )]
    RegionEndsBefore { address: u64, end: u64 },
}

impl SystemTableError {
    /// Whether this says that Linux locates no System Table, so that the firmware publishes no
    /// configuration table that Linux gives.
    pub(in crate::hii) fn locates_no_system_table(&self) -> bool {
        match self {
            Self::NotBootedByEfi { .. } | Self::NoSystemTable | Self::NoUefiInFdt => true,
            Self::XenUefiInFdt
            | Self::BootParamsShort { .. }
            | Self::Signature { .. }
            | Self::HeaderSize { .. }
            | Self::TooManyEntries { .. }
            | Self::NullConfigurationTable { .. }
            | Self::DuplicateEntry { .. }
            | Self::NullVendorTable { .. }
            | Self::RegionEndsBefore { .. } => false,
        }
    }
}

/// Whether firmware converts a pointer to a virtual address at SetVirtualAddressMap() (UEFI 2.11
/// §8.4.1), which tells uefisettings the address space to try first: Linux leaves the
/// configuration tables as the firmware gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointerSpace {
    /// Converted: the System Table's ConfigurationTable (§8.4.1), and the VendorTable of the
    /// JSON configuration and capsule result tables (§4.6.1.2). Firmware that converts nothing,
    /// as where the OS calls no SetVirtualAddressMap(), leaves them physical.
    Virtual,
    /// Left physical, though converted where no runtime region holds it physically: the HII
    /// database export, which §33.2.11.1 leaves open and edk2 never converts ("UEFI don't
    /// require System Configuration Tables Conversion", edk2-stable202608
    /// MdeModulePkg/Core/RuntimeDxe/Runtime.c:358).
    Physical,
    /// Never converted: EFI_RT_PROPERTIES_TABLE, which "will not be fixed up" (§4.6.2), so a
    /// virtual range that holds its address leads to other memory.
    PhysicalOnly,
}

/// The physical address of the firmware pointer `pointer`, in `space` first, by the memory map
/// `map`: the reads check the address that it gives.
fn resolve(map: &EfiMemoryMap, pointer: u64, space: PointerSpace) -> u64 {
    match space {
        PointerSpace::PhysicalOnly => pointer,
        PointerSpace::Physical if map.holds(pointer) => pointer,
        PointerSpace::Physical | PointerSpace::Virtual => {
            map.physical_address(pointer).unwrap_or(pointer)
        }
    }
}

/// What Linux tells of the System Table: where its two sources of it are on this architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::hii) enum SystemTableLocator {
    /// x86's boot_params (boot_params::BOOT_PARAMS_PATH), whose efi_info gives the System
    /// Table's address and the firmware's width, and /sys/firmware/efi/config_table.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
    BootParams {
        boot_params: PathBuf,
        config_table: PathBuf,
    },
    /// arm64's FDT, whose /chosen gives the System Table's address, and fw_platform_size.
    #[cfg(any(target_arch = "aarch64", test))]
    Fdt {
        fdt: PathBuf,
        fw_platform_size: PathBuf,
    },
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Default for SystemTableLocator {
    fn default() -> Self {
        Self::BootParams {
            boot_params: PathBuf::from(boot_params::BOOT_PARAMS_PATH),
            config_table: PathBuf::from(CONFIG_TABLE_PATH),
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Default for SystemTableLocator {
    fn default() -> Self {
        Self::Fdt {
            fdt: PathBuf::from(FDT_PATH),
            fw_platform_size: PathBuf::from(FW_PLATFORM_SIZE_PATH),
        }
    }
}

/// The System Table that Linux locates.
struct LocatedSystemTable {
    /// Its physical address.
    address: u64,
    /// The firmware's width, which lays it out.
    width: FirmwareWidth,
    /// The physical address of its configuration table entries, where Linux tells it.
    configuration_table: Option<u64>,
}

impl SystemTableLocator {
    /// The System Table that these files locate, without reading physical memory.
    fn locate(&self) -> Result<LocatedSystemTable> {
        match self {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
            Self::BootParams {
                boot_params,
                config_table,
            } => {
                let info = boot_params::read_efi_info(boot_params)?;
                Ok(LocatedSystemTable {
                    address: info.system_table,
                    width: info.width,
                    configuration_table: Some(read_sysfs_hex(config_table)?),
                })
            }
            #[cfg(any(target_arch = "aarch64", test))]
            Self::Fdt {
                fdt,
                fw_platform_size,
            } => {
                let bytes = match fs::read(fdt) {
                    Ok(bytes) => bytes,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        return Err(MemoryMapUnavailable::NoFdt(fdt.to_owned()).into())
                    }
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("Failed to read {}", fdt.display()))
                    }
                };
                let located = uefi_system_table(&bytes)
                    .with_context(|| format!("Failed to parse {}", fdt.display()))?;
                let address = match located {
                    FdtSystemTable::At(address) => address,
                    FdtSystemTable::Absent => return Err(SystemTableError::NoUefiInFdt.into()),
                    FdtSystemTable::Xen => return Err(SystemTableError::XenUefiInFdt.into()),
                };
                if address == 0 {
                    return Err(SystemTableError::NoSystemTable.into());
                }
                Ok(LocatedSystemTable {
                    address,
                    width: read_fw_platform_size(fw_platform_size)?,
                    configuration_table: None,
                })
            }
        }
    }
}

/// The files from which uefisettings reads the configuration tables; Default is this machine's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::hii) struct SystemTableFiles {
    /// Where Linux tells where the System Table is.
    pub(in crate::hii) locator: SystemTableLocator,
    /// The firmware memory map that bounds the reads.
    pub(in crate::hii) maps: MemoryMapFiles,
    /// Physical memory.
    pub(in crate::hii) dev_mem: PathBuf,
    /// The kernel lockdown mode, which can refuse physical memory.
    pub(in crate::hii) lockdown: PathBuf,
}

impl Default for SystemTableFiles {
    fn default() -> Self {
        Self {
            locator: SystemTableLocator::default(),
            maps: MemoryMapFiles::default(),
            dev_mem: PathBuf::from(super::extract::DEV_MEM_PATH),
            lockdown: PathBuf::from(LOCKDOWN_PATH),
        }
    }
}

/// The offsets and sizes in an EFI_SYSTEM_TABLE of firmware of one width (UEFI 2.11 §4.3.1;
/// Linux v6.11 include/linux/efi.h:479-511): after Hdr come
/// FirmwareVendor, FirmwareRevision, padded to a pointer's alignment, three pairs of a handle and
/// a pointer, RuntimeServices, BootServices, then the UINTN NumberOfTableEntries and the pointer
/// ConfigurationTable.
struct SystemTableLayout {
    uintn: usize,
    entries: usize,
}

impl SystemTableLayout {
    fn of(width: FirmwareWidth) -> Self {
        match width {
            FirmwareWidth::Bits32 => Self {
                uintn: 4,
                entries: 64,
            },
            FirmwareWidth::Bits64 => Self {
                uintn: 8,
                entries: 104,
            },
        }
    }

    /// The offset of ConfigurationTable.
    fn configuration_table(&self) -> usize {
        self.entries + self.uintn
    }

    /// The size up to the end of ConfigurationTable.
    fn size(&self) -> usize {
        self.entries + 2 * self.uintn
    }
}

/// What uefisettings reads of the System Table: the fields of its configuration table, which
/// stay valid after ExitBootServices() (UEFI 2.11 §4.3).
struct SystemTableFields {
    /// NumberOfTableEntries.
    entries: u64,
    /// ConfigurationTable, a virtual address once SetVirtualAddressMap() converted it (§8.4.1).
    configuration_table: u64,
}

/// The System Table at `address` in `memory`, of firmware of `width`, once its header checks:
/// its Signature, and its HeaderSize, which must cover what this reads and lie in the runtime
/// region that holds it.
fn read_system_table<M: PhysicalMemory>(
    memory: &RuntimeMemory<M>,
    address: u64,
    width: FirmwareWidth,
) -> Result<SystemTableFields> {
    let header = memory
        .read(address, TABLE_HEADER_SIZE)
        .context("Failed to read the EFI System Table's header")?;
    let (Some(signature), Some(header_size)) = (
        header.first_chunk::<8>().copied().map(u64::from_le_bytes),
        header
            .get(HEADER_SIZE_OFFSET..)
            .and_then(<[u8]>::first_chunk::<4>)
            .copied()
            .map(u32::from_le_bytes),
    ) else {
        bail!(
            "read {} bytes of the EFI System Table's header",
            header.len()
        );
    };
    if signature != EFI_SYSTEM_TABLE_SIGNATURE {
        return Err(SystemTableError::Signature { address, signature }.into());
    }
    let layout = SystemTableLayout::of(width);
    let needed = layout.size();
    if usize::try_from(header_size).is_ok_and(|size| size < needed) {
        return Err(SystemTableError::HeaderSize {
            header_size,
            needed,
        }
        .into());
    }
    // "It is very important to always use the HeaderSize field" (UEFI 2.11 §4.2.1): the whole
    // table, which may have grown, must lie in the region.
    memory
        .region_end(address, usize::try_from(header_size)?)
        .context("the EFI System Table runs past its runtime region")?;
    let fields = memory
        .read(address, needed)
        .context("Failed to read the EFI System Table")?;
    let uintn_at = |offset: usize| {
        fields
            .get(offset..offset + layout.uintn)
            .and_then(|bytes| width.uintn(bytes))
            .with_context(|| format!("read {} bytes of the EFI System Table", fields.len()))
    };
    Ok(SystemTableFields {
        entries: uintn_at(layout.entries)?,
        configuration_table: uintn_at(layout.configuration_table())?,
    })
}

/// The `count` EFI_CONFIGURATION_TABLE entries of firmware of `width` at `address` in `memory`,
/// as their VendorGuid and VendorTable.
fn read_entries<M: PhysicalMemory>(
    memory: &RuntimeMemory<M>,
    address: u64,
    count: u64,
    width: FirmwareWidth,
) -> Result<Vec<(Guid, u64)>> {
    if count > MAX_TABLE_ENTRIES {
        return Err(SystemTableError::TooManyEntries { count }.into());
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if address == 0 {
        return Err(SystemTableError::NullConfigurationTable { count }.into());
    }
    let entry_size = GUID_SIZE + width.uintn_size();
    let size = usize::try_from(count)?
        .checked_mul(entry_size)
        .context("the EFI Configuration Table's size overflows")?;
    let bytes = memory
        .read(address, size)
        .context("Failed to read the EFI Configuration Table")?;
    bytes
        .chunks_exact(entry_size)
        .map(|entry| {
            entry
                .split_first_chunk::<GUID_SIZE>()
                .and_then(|(guid, table)| Some((Guid::from(*guid), width.uintn(table)?)))
                .context("an EFI Configuration Table entry is short")
        })
        .collect()
}

/// The configuration tables that the System Table lists, by VendorGuid and VendorTable, and the
/// physical memory that holds them.
pub(in crate::hii) struct ConfigurationTables<M> {
    entries: Vec<(Guid, u64)>,
    width: FirmwareWidth,
    memory: RuntimeMemory<M>,
}

impl ConfigurationTables<DevMem> {
    /// This machine's, read through /dev/mem.
    pub(in crate::hii) fn system() -> Result<Self> {
        Self::read(&SystemTableFiles::default(), DevMem::open)
    }
}

impl<M: PhysicalMemory> ConfigurationTables<M> {
    /// The configuration tables that `files` locate, in the physical memory that `open_memory`
    /// opens from files.dev_mem and files.lockdown: in that order, the System Table's address, the
    /// lockdown mode, the memory map that bounds the reads, physical memory, then the System
    /// Table and its entries.
    pub(in crate::hii) fn read(
        files: &SystemTableFiles,
        open_memory: impl FnOnce(&Path, &Path) -> Result<M>,
    ) -> Result<Self> {
        let located = files.locator.locate()?;
        // Integrity already refuses /dev/mem, and confidentiality /proc/kcore too, which arm64's
        // memory map comes from.
        refuse_locked_down(MemoryDevice::DevMem, &files.lockdown)?;
        let map = files.maps.runtime_bound(&files.lockdown)?;
        let memory = RuntimeMemory::new(map, open_memory(&files.dev_mem, &files.lockdown)?);
        let system_table = read_system_table(&memory, located.address, located.width)?;
        let address = located.configuration_table.unwrap_or_else(|| {
            resolve(
                memory.map(),
                system_table.configuration_table,
                PointerSpace::Virtual,
            )
        });
        let entries = read_entries(&memory, address, system_table.entries, located.width)?;
        Ok(Self {
            entries,
            width: located.width,
            memory,
        })
    }

    /// The table of `guid`, if the System Table lists it, whose VendorTable it takes in `space`
    /// first.
    pub(in crate::hii) fn into_table(
        self,
        guid: &Guid,
        space: PointerSpace,
    ) -> Result<Option<SystemVendorTable<M>>, SystemTableError> {
        let mut listed = self
            .entries
            .iter()
            .filter(|(entry, _)| entry == guid)
            .map(|&(_, table)| table);
        let Some(pointer) = listed.next() else {
            return Ok(None);
        };
        let more = listed.count();
        if more > 0 {
            return Err(SystemTableError::DuplicateEntry {
                guid: *guid,
                count: more + 1,
            });
        }
        if pointer == 0 {
            return Err(SystemTableError::NullVendorTable { guid: *guid });
        }
        Ok(Some(SystemVendorTable {
            address: resolve(self.memory.map(), pointer, space),
            width: self.width,
            memory: self.memory,
        }))
    }
}

/// A configuration table that the System Table lists: its VendorTable in physical memory.
pub(in crate::hii) struct SystemVendorTable<M> {
    address: u64,
    width: FirmwareWidth,
    memory: RuntimeMemory<M>,
}

impl<M: PhysicalMemory> SystemVendorTable<M> {
    /// `length` bytes at `offset` of the table, which one runtime region must hold.
    pub(in crate::hii) fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>> {
        let address = self
            .address
            .checked_add(offset)
            .with_context(|| format!("{:#x}+{offset:#x} overflows", self.address))?;
        self.memory.read(address, length)
    }

    /// The bytes from the table's start to the end of the runtime region that holds its first
    /// `length` bytes.
    pub(in crate::hii) fn room(&self, length: usize) -> Result<u64> {
        let end = self.memory.region_end(self.address, length)?;
        Ok(end
            .checked_sub(self.address)
            .ok_or(SystemTableError::RegionEndsBefore {
                address: self.address,
                end,
            })?)
    }
}

impl<M: PhysicalMemory> VendorTable for SystemVendorTable<M> {
    fn read(&self, len: usize) -> Result<Vec<u8>> {
        self.read_at(0, len)
    }

    fn firmware_width(&self) -> FirmwareWidth {
        self.width
    }
}

/// The configuration table of `guid` that this machine's System Table lists, if any, whose
/// VendorTable it takes in `space` first.
pub(crate) fn system_vendor_table(
    guid: &Guid,
    space: PointerSpace,
) -> Result<Option<impl VendorTable>> {
    Ok(ConfigurationTables::system()?.into_table(guid, space)?)
}

/// System Tables, configuration tables and the files that locate them, for the tests.
#[cfg(test)]
pub(in crate::hii) mod fixture {
    use std::path::Path;

    use anyhow::bail;

    use super::*;
    use crate::hii::firmware_memory::fdt_params::fixture::uefi_fdt_with_system_table;
    use crate::hii::firmware_memory::fdt_params::UefiFdtParams;
    use crate::hii::firmware_memory::fixture::write_runtime_map;
    use crate::hii::firmware_memory::kcore::fixture::kcore_fixture;
    use crate::hii::firmware_memory::runtime_memory::ReadToken;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::memory_map::efi_memory_map::fixture::descriptor;
    use crate::memory_map::efi_memory_map::MemoryType;
    use crate::memory_map::efi_memory_map::EFI_MEMORY_RUNTIME;

    /// The UINTN `value` of firmware of `width`.
    pub(in crate::hii) fn uintn(width: FirmwareWidth, value: u64) -> Vec<u8> {
        match width {
            FirmwareWidth::Bits32 => u32::try_from(value)
                .expect("a 32-bit value")
                .to_le_bytes()
                .to_vec(),
            FirmwareWidth::Bits64 => value.to_le_bytes().to_vec(),
        }
    }

    /// An EFI_SYSTEM_TABLE of firmware of `width` of `header_size` bytes, at least up to its
    /// ConfigurationTable, with `signature`, whose NumberOfTableEntries is `entries` and
    /// ConfigurationTable `table`, and 0xa5 in the fields that uefisettings does not read.
    pub(in crate::hii) fn system_table(
        width: FirmwareWidth,
        signature: u64,
        header_size: u32,
        entries: u64,
        table: u64,
    ) -> Vec<u8> {
        let layout = SystemTableLayout::of(width);
        let size = usize::try_from(header_size)
            .expect("a usize size")
            .max(layout.size());
        let mut bytes = vec![0xa5; size];
        bytes[..8].copy_from_slice(&signature.to_le_bytes());
        bytes[HEADER_SIZE_OFFSET..HEADER_SIZE_OFFSET + 4]
            .copy_from_slice(&header_size.to_le_bytes());
        for (offset, value) in [
            (layout.entries, entries),
            (layout.configuration_table(), table),
        ] {
            bytes[offset..offset + layout.uintn].copy_from_slice(&uintn(width, value));
        }
        bytes
    }

    /// The size of the EFI_SYSTEM_TABLE of UEFI 2.11 for firmware of `width`.
    pub(in crate::hii) fn system_table_size(width: FirmwareWidth) -> u32 {
        u32::try_from(SystemTableLayout::of(width).size()).expect("a u32 size")
    }

    /// A System Table of `width` and UEFI 2.11's size that lists `count` tables at `table`.
    pub(in crate::hii) fn valid_system_table(
        width: FirmwareWidth,
        count: u64,
        table: u64,
    ) -> Vec<u8> {
        system_table(
            width,
            EFI_SYSTEM_TABLE_SIGNATURE,
            system_table_size(width),
            count,
            table,
        )
    }

    /// The EFI_CONFIGURATION_TABLE entries `entries` of (VendorGuid, VendorTable) of firmware of
    /// `width`.
    pub(in crate::hii) fn configuration_table(
        width: FirmwareWidth,
        entries: &[(Guid, u64)],
    ) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|&(guid, table)| {
                [<[u8; 16]>::from(guid).to_vec(), uintn(width, table)].concat()
            })
            .collect()
    }

    /// Physical memory of `segments` of (address, bytes), which fails a read that no segment
    /// holds whole.
    pub(in crate::hii) struct SegmentMemory(pub(in crate::hii) Vec<(u64, Vec<u8>)>);

    impl PhysicalMemory for SegmentMemory {
        fn read(&self, address: u64, length: usize, _: ReadToken) -> Result<Vec<u8>> {
            for (start, bytes) in &self.0 {
                let Some(offset) = address.checked_sub(*start) else {
                    continue;
                };
                let offset = usize::try_from(offset)?;
                if let Some(read) = bytes.get(offset..offset + length) {
                    return Ok(read.to_vec());
                }
            }
            bail!("no segment holds {address:#x}+{length:#x}")
        }
    }

    /// x86's files in `dir` that locate the System Table at `system_table` of firmware of `width`
    /// and its entries at `config_table`, with a runtime-map of `runtime`, descriptors of (type,
    /// physical start, virtual start, pages), and the lockdown mode none.
    pub(in crate::hii) fn x86_files(
        dir: &Path,
        width: FirmwareWidth,
        system_table: u64,
        config_table: u64,
        runtime: &[(MemoryType, u64, u64, u64)],
    ) -> SystemTableFiles {
        let signature = match width {
            FirmwareWidth::Bits32 => *b"EL32",
            FirmwareWidth::Bits64 => *b"EL64",
        };
        let boot_params = dir.join("boot_params");
        fs::write(
            &boot_params,
            super::boot_params::fixture::boot_params(signature, system_table),
        )
        .expect("write boot_params");
        let config_table_path = dir.join("config_table");
        fs::write(&config_table_path, format!("{config_table:#x}\n")).expect("write config_table");
        let runtime: Vec<[String; 5]> = runtime
            .iter()
            .map(|&(memory_type, physical, virtual_start, pages)| {
                [
                    format!("{:#x}\n", memory_type.0),
                    format!("{physical:#x}\n"),
                    format!("{virtual_start:#x}\n"),
                    format!("{pages:#x}\n"),
                    format!("{:#x}\n", EFI_MEMORY_RUNTIME | 0xf),
                ]
            })
            .collect();
        let runtime: Vec<[&str; 5]> = runtime
            .iter()
            .map(|entry| entry.each_ref().map(String::as_str))
            .collect();
        let runtime_map = dir.join("runtime-map");
        write_runtime_map(&runtime_map, &runtime);
        SystemTableFiles {
            locator: SystemTableLocator::BootParams {
                boot_params,
                config_table: config_table_path,
            },
            maps: MemoryMapFiles::Sysfs {
                runtime_map,
                firmware_memmap: dir.join("memmap"),
            },
            dev_mem: dir.join("mem"),
            lockdown: lockdown_file(dir, "none"),
        }
    }

    /// Where arm64's files put the EFI memory map in physical memory, which /proc/kcore serves.
    const MMAP_AT: u64 = 0x4000_0000;

    /// arm64's files in `dir` that locate the System Table at `system_table` of firmware of the
    /// width that `fw_platform_size` names, with an EFI memory map of `descriptors`, of (type,
    /// physical start, virtual start, pages, attribute), and the lockdown mode none.
    pub(in crate::hii) fn arm64_files(
        dir: &Path,
        fw_platform_size: &str,
        system_table: u64,
        descriptors: &[(MemoryType, u64, u64, u64, u64)],
    ) -> SystemTableFiles {
        let desc_size = 48;
        let map: Vec<u8> = descriptors
            .iter()
            .flat_map(
                |&(memory_type, physical, virtual_start, pages, attribute)| {
                    descriptor(
                        desc_size,
                        memory_type,
                        physical,
                        virtual_start,
                        pages,
                        attribute,
                    )
                },
            )
            .collect();
        let params = UefiFdtParams {
            mmap_start: MMAP_AT,
            mmap_size: map.len(),
            mmap_desc_size: desc_size,
            mmap_desc_ver: 1,
        };
        let (fdt, kcore) = (dir.join("fdt"), dir.join("kcore"));
        fs::write(
            &fdt,
            uefi_fdt_with_system_table(&params, &system_table.to_be_bytes()),
        )
        .expect("write the FDT");
        kcore_fixture(&kcore, &[(MMAP_AT, &map)]);
        let width = dir.join("fw_platform_size");
        fs::write(&width, fw_platform_size).expect("write fw_platform_size");
        SystemTableFiles {
            locator: SystemTableLocator::Fdt {
                fdt: fdt.clone(),
                fw_platform_size: width,
            },
            maps: MemoryMapFiles::Fdt { fdt, kcore },
            dev_mem: dir.join("mem"),
            lockdown: lockdown_file(dir, "none"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;
    use crate::hii::firmware_memory::runtime_memory::fixture::UnreadMemory;
    use crate::hii::lockdown::LockdownMode;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryAccessDenied;
    use crate::hii::memory_access_denied::MemoryOperation;
    use crate::memory_map::efi_memory_map::fixture::runtime_map;
    use crate::memory_map::efi_memory_map::MemoryType;
    use crate::memory_map::efi_memory_map::RangeRefusal;
    use crate::memory_map::efi_memory_map::EFI_MEMORY_RUNTIME;

    /// The runtime data region of the tests, of REGION_PAGES pages at a physical and, after
    /// SetVirtualAddressMap() on x86_64, a virtual address as OVMF's; boot services data, which
    /// is not runtime; and a runtime descriptor of memory-mapped I/O.
    const RUNTIME_DATA_AT: u64 = 0x7f00_0000;
    const X86_VIRTUAL_AT: u64 = 0xffff_fffe_ff00_0000;
    const REGION_PAGES: u64 = 16;
    const REGION_END: u64 = RUNTIME_DATA_AT + REGION_PAGES * 0x1000;
    const BOOT_SERVICES_AT: u64 = 0x10_0000;
    const MMIO_AT: u64 = 0xfeb0_0000;
    /// Where the tests put the System Table, its entries and a table, unaligned.
    const SYSTEM_TABLE_AT: u64 = RUNTIME_DATA_AT + 0x18;
    const ENTRIES_AT: u64 = RUNTIME_DATA_AT + 0x201;
    const TABLE_AT: u64 = RUNTIME_DATA_AT + 0x8003;
    /// A table's bytes.
    const TABLE: &[u8] = b"a configuration table";
    /// The GUIDs of the tests' tables.
    const LISTED: Guid = Guid {
        data1: 0x8c78_a505,
        data2: 0xbaa0,
        data3: 0x4c4a,
        data4: [0x86, 0x9f, 0, 0, 0, 0, 0x17, 0x01],
    };
    const OTHER: Guid = Guid {
        data1: 0x8c78_a505,
        data2: 0xbaa0,
        data3: 0x4c4a,
        data4: [0x86, 0x9f, 0, 0, 0, 0, 0x17, 0x02],
    };
    const UNLISTED: Guid = Guid {
        data1: 0x8c78_a505,
        data2: 0xbaa0,
        data3: 0x4c4a,
        data4: [0x86, 0x9f, 0, 0, 0, 0, 0x17, 0x03],
    };

    /// The runtime-map of x86's tests: runtime data, memory-mapped I/O, and boot services data
    /// that efi=debug lists, which is not runtime but read_runtime_map drops.
    const X86_RUNTIME: [(MemoryType, u64, u64, u64); 2] = [
        (
            MemoryType::RUNTIME_SERVICES_DATA,
            RUNTIME_DATA_AT,
            X86_VIRTUAL_AT,
            REGION_PAGES,
        ),
        (
            MemoryType::MEMORY_MAPPED_IO,
            MMIO_AT,
            X86_VIRTUAL_AT + 0x40_0000,
            1,
        ),
    ];

    /// Physical memory that holds, in runtime data, the System Table `system_table` and the
    /// entries `entries`, and TABLE at TABLE_AT.
    fn memory(system_table: Vec<u8>, entries: Vec<u8>) -> SegmentMemory {
        SegmentMemory(vec![
            (SYSTEM_TABLE_AT, system_table),
            (ENTRIES_AT, entries),
            (TABLE_AT, TABLE.to_vec()),
        ])
    }

    /// The configuration tables of x86's files in `dir` for a System Table of `width` that lists
    /// `entries` at ENTRIES_AT, in `memory`.
    fn read_x86(
        dir: &Path,
        width: FirmwareWidth,
        system_table: Vec<u8>,
        entries: Vec<u8>,
    ) -> Result<ConfigurationTables<SegmentMemory>> {
        let files = x86_files(dir, width, SYSTEM_TABLE_AT, ENTRIES_AT, &X86_RUNTIME);
        ConfigurationTables::read(&files, |_, _| Ok(memory(system_table, entries)))
    }

    /// On x86, of either width, boot_params locates the System Table and config_table its entries,
    /// whose ConfigurationTable is virtual after SetVirtualAddressMap(); a listed table reads
    /// from its VendorTable, and an unlisted one is absent.
    #[test]
    fn x86_reads_the_configuration_tables_that_boot_params_locates() {
        // ConfigurationTable, converted: by x86_64 Linux, and by 32-bit Linux as __va() does
        for (width, converted) in [
            (FirmwareWidth::Bits64, X86_VIRTUAL_AT + 0x201),
            (FirmwareWidth::Bits32, 0xff00_0201),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let entries = [(OTHER, RUNTIME_DATA_AT), (LISTED, TABLE_AT)];
            let read = || {
                read_x86(
                    dir.path(),
                    width,
                    valid_system_table(width, 2, converted),
                    configuration_table(width, &entries),
                )
                .unwrap_or_else(|error| panic!("{width:?}: {error:#}"))
            };

            let table = read()
                .into_table(&LISTED, PointerSpace::PhysicalOnly)
                .expect("find the listed table")
                .expect("a listed table");

            assert_eq!(
                table.read(TABLE.len()).expect("read the table"),
                TABLE,
                "{width:?}"
            );
            assert_eq!(table.firmware_width(), width, "{width:?}");
            assert!(
                read()
                    .into_table(&UNLISTED, PointerSpace::PhysicalOnly)
                    .expect("look for an unlisted table")
                    .is_none(),
                "{width:?}: unlisted"
            );
        }
    }

    /// On arm64, the FDT locates the System Table, whose ConfigurationTable is virtual where
    /// Linux calls SetVirtualAddressMap(), as with vamap, equal to the physical address where it
    /// does not, and physical where the call failed and the stub set VirtualStart to U64_MAX; it
    /// reads with the width of fw_platform_size.
    #[test]
    fn arm64_reads_the_configuration_tables_that_the_fdt_locates() {
        const VAMAP_AT: u64 = 0x2000_0000;
        for (case, virtual_start, width, size) in [
            ("vamap", VAMAP_AT, FirmwareWidth::Bits64, "64\n"),
            ("vamap, 32-bit", VAMAP_AT, FirmwareWidth::Bits32, "32\n"),
            ("novamap", RUNTIME_DATA_AT, FirmwareWidth::Bits64, "64\n"),
            ("failed", u64::MAX, FirmwareWidth::Bits64, "64\n"),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let files = arm64_files(
                dir.path(),
                size,
                SYSTEM_TABLE_AT,
                &[
                    (MemoryType(7), 0x4000_0000, 0, 0x100, 0xf),
                    (
                        MemoryType::RUNTIME_SERVICES_DATA,
                        RUNTIME_DATA_AT,
                        virtual_start,
                        REGION_PAGES,
                        EFI_MEMORY_RUNTIME | 0xf,
                    ),
                ],
            );
            let converted = match virtual_start {
                u64::MAX => ENTRIES_AT,
                start => start + (ENTRIES_AT - RUNTIME_DATA_AT),
            };
            let entries = configuration_table(width, &[(LISTED, TABLE_AT)]);

            let table = ConfigurationTables::read(&files, |_, _| {
                Ok(memory(valid_system_table(width, 1, converted), entries))
            })
            .unwrap_or_else(|error| panic!("{case}: {error:#}"))
            .into_table(&LISTED, PointerSpace::PhysicalOnly)
            .expect("find the listed table")
            .expect("a listed table");

            assert_eq!(
                table.read(TABLE.len()).expect("read the table"),
                TABLE,
                "{case}"
            );
        }
    }

    /// The EFI_SYSTEM_TABLE of UEFI 2.11 §4.2.1 and §4.3.1, written byte by byte from the
    /// specification's offsets, not from SystemTableLayout, HEADER_SIZE_OFFSET or
    /// EFI_SYSTEM_TABLE_SIGNATURE: Signature "IBI SYST" at 0, Revision at 8, HeaderSize at 12,
    /// NumberOfTableEntries at 104 and ConfigurationTable at 112 of 120 bytes for 64-bit
    /// firmware, at 64 and 68 of 72 bytes for 32-bit firmware, and 0xa5 elsewhere. x86 reads
    /// NumberOfTableEntries and takes the entries from config_table; arm64 reads
    /// ConfigurationTable too. Each finds the second of the two tables listed.
    #[test]
    fn the_layouts_are_uefi_2_11_s() {
        for (width, size, entries_offset, table_offset, uintn, fw_platform_size) in [
            (FirmwareWidth::Bits64, 120, 104, 112, 8, "64\n"),
            (FirmwareWidth::Bits32, 72, 64, 68, 4, "32\n"),
        ] {
            let mut bytes = vec![0xa5; size];
            bytes[..8].copy_from_slice(b"IBI SYST");
            bytes[8..12].copy_from_slice(&0x0002_0046_u32.to_le_bytes());
            bytes[12..16].copy_from_slice(&u32::try_from(size).expect("a u32 size").to_le_bytes());
            bytes[entries_offset..entries_offset + uintn]
                .copy_from_slice(&2_u64.to_le_bytes()[..uintn]);
            bytes[table_offset..table_offset + uintn]
                .copy_from_slice(&ENTRIES_AT.to_le_bytes()[..uintn]);
            let entries =
                configuration_table(width, &[(OTHER, RUNTIME_DATA_AT), (LISTED, TABLE_AT)]);

            let dir = tempfile::tempdir().expect("create a directory");
            let x86 = read_x86(dir.path(), width, bytes.clone(), entries.clone())
                .unwrap_or_else(|error| panic!("{width:?}: x86: {error:#}"));
            let dir = tempfile::tempdir().expect("create a directory");
            let files = arm64_files(
                dir.path(),
                fw_platform_size,
                SYSTEM_TABLE_AT,
                &[(
                    MemoryType::RUNTIME_SERVICES_DATA,
                    RUNTIME_DATA_AT,
                    RUNTIME_DATA_AT,
                    REGION_PAGES,
                    EFI_MEMORY_RUNTIME | 0xf,
                )],
            );
            let arm64 = ConfigurationTables::read(&files, |_, _| Ok(memory(bytes, entries)))
                .unwrap_or_else(|error| panic!("{width:?}: arm64: {error:#}"));

            for (case, tables) in [("x86", x86), ("arm64", arm64)] {
                let table = tables
                    .into_table(&LISTED, PointerSpace::PhysicalOnly)
                    .unwrap_or_else(|error| panic!("{width:?}: {case}: {error:#}"))
                    .unwrap_or_else(|| panic!("{width:?}: {case}: the second table"));
                assert_eq!(
                    table.read(TABLE.len()).expect("read the table"),
                    TABLE,
                    "{width:?}: {case}"
                );
            }
        }
    }

    /// A System Table that is not one, or whose HeaderSize leaves out what is read, is refused;
    /// so are one in memory that is not runtime, one in memory-mapped I/O, and one whose
    /// HeaderSize runs past its region.
    #[test]
    fn x86_refuses_a_system_table_that_does_not_check() {
        let width = FirmwareWidth::Bits64;
        let size = system_table_size(width);
        let entries = configuration_table(width, &[(LISTED, TABLE_AT)]);
        for (case, signature, header_size, want) in [
            (
                "another signature",
                EFI_SYSTEM_TABLE_SIGNATURE ^ 1,
                size,
                SystemTableError::Signature {
                    address: SYSTEM_TABLE_AT,
                    signature: EFI_SYSTEM_TABLE_SIGNATURE ^ 1,
                },
            ),
            (
                "a HeaderSize short of ConfigurationTable",
                EFI_SYSTEM_TABLE_SIGNATURE,
                size - 1,
                SystemTableError::HeaderSize {
                    header_size: size - 1,
                    needed: 120,
                },
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let table = system_table(width, signature, header_size, 1, ENTRIES_AT);

            let error = read_x86(dir.path(), width, table, entries.clone())
                .err()
                .unwrap_or_else(|| panic!("{case}: read"));

            assert_eq!(
                error.downcast_ref::<SystemTableError>(),
                Some(&want),
                "{case}: {error:#}"
            );
        }

        // the table's HeaderSize, which may grow, past its region
        let dir = tempfile::tempdir().expect("create a directory");
        let past = u32::try_from(REGION_END - SYSTEM_TABLE_AT + 1).expect("a u32 size");
        let error = read_x86(
            dir.path(),
            width,
            system_table(width, EFI_SYSTEM_TABLE_SIGNATURE, past, 1, ENTRIES_AT),
            entries.clone(),
        )
        .err()
        .expect("read a table past its region");
        assert_eq!(
            error.downcast_ref::<RangeRefusal>(),
            Some(&RangeRefusal::NotRuntime {
                address: SYSTEM_TABLE_AT,
                length: u64::from(past),
            }),
            "past the region: {error:#}"
        );
        let whole = u32::try_from(REGION_END - SYSTEM_TABLE_AT).expect("a u32 size");
        read_x86(
            dir.path(),
            width,
            system_table(width, EFI_SYSTEM_TABLE_SIGNATURE, whole, 1, ENTRIES_AT),
            entries,
        )
        .expect("read a table up to its region's end");

        for (case, address, want) in [
            (
                "boot services data",
                BOOT_SERVICES_AT,
                RangeRefusal::NotRuntime {
                    address: BOOT_SERVICES_AT,
                    length: 24,
                },
            ),
            (
                "memory-mapped I/O",
                MMIO_AT,
                RangeRefusal::MemoryMappedIo {
                    address: MMIO_AT,
                    length: 24,
                    memory_type: MemoryType::MEMORY_MAPPED_IO,
                },
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let files = x86_files(dir.path(), width, address, ENTRIES_AT, &X86_RUNTIME);

            let error = ConfigurationTables::read(&files, |_, _| Ok(UnreadMemory))
                .err()
                .unwrap_or_else(|| panic!("{case}: read"));

            assert_eq!(
                error.downcast_ref::<RangeRefusal>(),
                Some(&want),
                "{case}: {error:#}"
            );
        }
    }

    /// NumberOfTableEntries up to MAX_TABLE_ENTRIES reads, one more is refused unread, and
    /// entries that run past their region, or a NULL ConfigurationTable with entries, are
    /// refused; no entries list no table, and read nothing.
    #[test]
    fn x86_reads_only_plausible_entries() {
        let width = FirmwareWidth::Bits64;
        let dir = tempfile::tempdir().expect("create a directory");
        let mut many = vec![(OTHER, RUNTIME_DATA_AT); 1023];
        many.push((LISTED, TABLE_AT));
        let tables = read_x86(
            dir.path(),
            width,
            valid_system_table(width, MAX_TABLE_ENTRIES, ENTRIES_AT),
            configuration_table(width, &many),
        )
        .expect("read MAX_TABLE_ENTRIES entries");
        assert!(
            tables
                .into_table(&LISTED, PointerSpace::PhysicalOnly)
                .expect("find the last table")
                .is_some(),
            "the last of MAX_TABLE_ENTRIES"
        );

        for (case, count, config_table, want) in [
            (
                "one entry more",
                MAX_TABLE_ENTRIES + 1,
                ENTRIES_AT,
                SystemTableError::TooManyEntries {
                    count: MAX_TABLE_ENTRIES + 1,
                },
            ),
            (
                "a NULL ConfigurationTable",
                1,
                0,
                SystemTableError::NullConfigurationTable { count: 1 },
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let files = x86_files(
                dir.path(),
                width,
                SYSTEM_TABLE_AT,
                config_table,
                &X86_RUNTIME,
            );
            let table = valid_system_table(width, count, config_table);

            let error = ConfigurationTables::read(&files, |_, _| {
                Ok(SegmentMemory(vec![(SYSTEM_TABLE_AT, table)]))
            })
            .err()
            .unwrap_or_else(|| panic!("{case}: read"));

            assert_eq!(
                error.downcast_ref::<SystemTableError>(),
                Some(&want),
                "{case}: {error:#}"
            );
        }

        let dir = tempfile::tempdir().expect("create a directory");
        let near_end = REGION_END - 23;
        let files = x86_files(dir.path(), width, SYSTEM_TABLE_AT, near_end, &X86_RUNTIME);
        let error = ConfigurationTables::read(&files, |_, _| {
            Ok(SegmentMemory(vec![(
                SYSTEM_TABLE_AT,
                valid_system_table(width, 1, near_end),
            )]))
        })
        .err()
        .expect("read entries past their region");
        assert_eq!(
            error.downcast_ref::<RangeRefusal>(),
            Some(&RangeRefusal::NotRuntime {
                address: near_end,
                length: 24,
            }),
            "past the region: {error:#}"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let files = x86_files(dir.path(), width, SYSTEM_TABLE_AT, 0, &X86_RUNTIME);
        let tables = ConfigurationTables::read(&files, |_, _| {
            Ok(SegmentMemory(vec![(
                SYSTEM_TABLE_AT,
                valid_system_table(width, 0, 0),
            )]))
        })
        .expect("read no entries");
        assert!(
            tables
                .into_table(&LISTED, PointerSpace::PhysicalOnly)
                .expect("look for a table")
                .is_none(),
            "no entries"
        );
    }

    /// A GUID listed twice, against UEFI 2.11 section 4.6, and a NULL VendorTable are refused
    /// for that GUID only.
    #[test]
    fn into_table_refuses_a_duplicate_or_null_entry() {
        let width = FirmwareWidth::Bits64;
        let dir = tempfile::tempdir().expect("create a directory");
        let entries = [
            (LISTED, TABLE_AT),
            (OTHER, 0),
            (LISTED, TABLE_AT),
            (UNLISTED, TABLE_AT),
        ];
        let read = || {
            read_x86(
                dir.path(),
                width,
                valid_system_table(width, 4, ENTRIES_AT),
                configuration_table(width, &entries),
            )
            .expect("read the entries")
        };
        for (guid, want) in [
            (
                LISTED,
                Some(SystemTableError::DuplicateEntry {
                    guid: LISTED,
                    count: 2,
                }),
            ),
            (
                OTHER,
                Some(SystemTableError::NullVendorTable { guid: OTHER }),
            ),
            (UNLISTED, None),
        ] {
            assert_eq!(
                read().into_table(&guid, PointerSpace::PhysicalOnly).err(),
                want,
                "{guid}"
            );
        }
    }

    /// x86 Linux not booted through EFI locates no System Table, so nothing opens physical
    /// memory; and a missing config_table fails.
    #[test]
    fn x86_refuses_what_locates_no_system_table() {
        let width = FirmwareWidth::Bits64;
        let dir = tempfile::tempdir().expect("create a directory");
        let files = x86_files(dir.path(), width, SYSTEM_TABLE_AT, ENTRIES_AT, &X86_RUNTIME);
        let SystemTableLocator::BootParams {
            boot_params,
            config_table,
        } = &files.locator
        else {
            panic!("no boot_params");
        };
        fs::write(
            boot_params,
            super::boot_params::fixture::boot_params([0; 4], SYSTEM_TABLE_AT),
        )
        .expect("write a BIOS boot's boot_params");
        let error = ConfigurationTables::read(&files, |path, _| -> Result<UnreadMemory> {
            panic!("opened {}", path.display())
        })
        .err()
        .expect("read a BIOS boot's configuration tables");
        assert_eq!(
            error.downcast_ref::<SystemTableError>(),
            Some(&SystemTableError::NotBootedByEfi { signature: [0; 4] }),
            "BIOS: {error:#}"
        );

        let files = x86_files(dir.path(), width, SYSTEM_TABLE_AT, ENTRIES_AT, &X86_RUNTIME);
        fs::remove_file(config_table).expect("remove config_table");
        let error = ConfigurationTables::read(&files, |path, _| -> Result<UnreadMemory> {
            panic!("opened {}", path.display())
        })
        .err()
        .expect("read without config_table");
        assert!(
            format!("{error:#}")
                .starts_with(&format!("Failed to read {}: ", config_table.display())),
            "no config_table: {error:#}"
        );
    }

    /// arm64 Linux without an FDT locates no System Table, nor without the property, nor where
    /// it gives the address 0, and the System Table that xen,uefi-system-table in /hypervisor/uefi
    /// gives is refused; nothing opens physical memory.
    #[test]
    fn arm64_refuses_what_locates_no_system_table() {
        let runtime = [(
            MemoryType::RUNTIME_SERVICES_DATA,
            RUNTIME_DATA_AT,
            RUNTIME_DATA_AT,
            REGION_PAGES,
            EFI_MEMORY_RUNTIME | 0xf,
        )];
        let unopened =
            |path: &Path, _: &Path| -> Result<UnreadMemory> { panic!("opened {}", path.display()) };

        let dir = tempfile::tempdir().expect("create a directory");
        let files = arm64_files(dir.path(), "64\n", 0, &runtime);
        let error = ConfigurationTables::read(&files, unopened)
            .err()
            .expect("read an address of 0");
        assert_eq!(
            error.downcast_ref::<SystemTableError>(),
            Some(&SystemTableError::NoSystemTable),
            "0: {error:#}"
        );

        let SystemTableLocator::Fdt { fdt, .. } = &files.locator else {
            panic!("no FDT");
        };
        for (case, bytes, want) in [
            (
                "no property",
                crate::hii::firmware_memory::fdt_params::fixture::uefi_fdt(
                    &crate::hii::firmware_memory::fdt_params::UefiFdtParams {
                        mmap_start: 0x4000_0000,
                        mmap_size: 48,
                        mmap_desc_size: 48,
                        mmap_desc_ver: 1,
                    },
                ),
                SystemTableError::NoUefiInFdt,
            ),
            (
                "Xen",
                crate::hii::firmware_memory::fdt_params::fixture::xen_uefi_fdt(),
                SystemTableError::XenUefiInFdt,
            ),
        ] {
            fs::write(fdt, bytes).expect("write an FDT without the System Table");
            let error = ConfigurationTables::read(&files, unopened)
                .err()
                .expect("read an FDT without the System Table");
            assert_eq!(
                error.downcast_ref::<SystemTableError>(),
                Some(&want),
                "{case}: {error:#}"
            );
        }

        fs::remove_file(fdt).expect("remove the FDT");
        let error = ConfigurationTables::read(&files, unopened)
            .err()
            .expect("read without an FDT");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            Some(&MemoryMapUnavailable::NoFdt(fdt.clone())),
            "no FDT: {error:#}"
        );
    }

    /// Kernel lockdown that refuses /dev/mem refuses the configuration tables before anything
    /// reads the memory map or opens physical memory, and names lockdown: integrity and
    /// confidentiality on x86, also without a runtime-map, and on arm64 also without
    /// /proc/kcore.
    #[test]
    fn lockdown_refuses_before_the_memory_map() {
        for mode in [LockdownMode::Integrity, LockdownMode::Confidentiality] {
            let dir = tempfile::tempdir().expect("create a directory");
            let mut x86 = x86_files(
                dir.path(),
                FirmwareWidth::Bits64,
                SYSTEM_TABLE_AT,
                ENTRIES_AT,
                &X86_RUNTIME,
            );
            x86.maps = MemoryMapFiles::Sysfs {
                runtime_map: dir.path().join("missing"),
                firmware_memmap: dir.path().join("missing"),
            };
            x86.lockdown = lockdown_file(dir.path(), &mode.to_string());
            let arm64_dir = tempfile::tempdir().expect("create a directory");
            let mut arm64 = arm64_files(arm64_dir.path(), "64\n", SYSTEM_TABLE_AT, &[]);
            if let MemoryMapFiles::Fdt { kcore, .. } = &arm64.maps {
                fs::remove_file(kcore).expect("remove /proc/kcore");
            }
            arm64.lockdown = lockdown_file(arm64_dir.path(), &mode.to_string());
            for (case, files) in [("x86", x86), ("arm64", arm64)] {
                let error = ConfigurationTables::read(&files, |path, _| -> Result<UnreadMemory> {
                    panic!("opened {}", path.display())
                })
                .err()
                .unwrap_or_else(|| panic!("{case} {mode}: read"));

                assert_eq!(
                    error.downcast_ref::<MemoryAccessDenied>(),
                    Some(&MemoryAccessDenied {
                        device: MemoryDevice::DevMem,
                        operation: MemoryOperation::Open,
                        cause: DenialCause::Lockdown(mode),
                    }),
                    "{case} {mode}: {error:#}"
                );
            }
        }
    }

    /// Without x86's runtime-map or arm64's /proc/kcore, no memory map bounds the reads, so none
    /// is made.
    #[test]
    fn a_missing_memory_map_refuses_the_reads() {
        let dir = tempfile::tempdir().expect("create a directory");
        let mut files = x86_files(
            dir.path(),
            FirmwareWidth::Bits64,
            SYSTEM_TABLE_AT,
            ENTRIES_AT,
            &X86_RUNTIME,
        );
        let missing = dir.path().join("missing");
        files.maps = MemoryMapFiles::Sysfs {
            runtime_map: missing.clone(),
            firmware_memmap: missing.clone(),
        };
        let error = ConfigurationTables::read(&files, |path, _| -> Result<UnreadMemory> {
            panic!("opened {}", path.display())
        })
        .err()
        .expect("read without a runtime-map");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            Some(&MemoryMapUnavailable::NoRuntimeMap(missing)),
            "x86: {error:#}"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let files = arm64_files(dir.path(), "64\n", SYSTEM_TABLE_AT, &[]);
        let MemoryMapFiles::Fdt { kcore, .. } = &files.maps else {
            panic!("no FDT map");
        };
        fs::remove_file(kcore).expect("remove /proc/kcore");
        let error = ConfigurationTables::read(&files, |path, _| -> Result<UnreadMemory> {
            panic!("opened {}", path.display())
        })
        .err()
        .expect("read without /proc/kcore");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            Some(&MemoryMapUnavailable::NoKcore(kcore.clone())),
            "arm64: {error:#}"
        );
    }

    /// resolve leaves a pointer of PointerSpace::PhysicalOnly as it is, though a virtual range
    /// holds it, takes one of PointerSpace::Physical as it is where a runtime region holds it
    /// physically, else translates it through the virtual ranges, and one of
    /// PointerSpace::Virtual through them first; it leaves a pointer that no range holds as it
    /// is, for the read to refuse.
    #[test]
    fn resolve_tries_the_pointer_s_space_first() {
        // the virtual range of the first region is the physical range of the second
        let map = runtime_map(&[
            (
                0x7f00_0000,
                0x7e00_0000,
                0x10,
                MemoryType::RUNTIME_SERVICES_DATA,
            ),
            (
                0x7e00_0000,
                0x2000_0000,
                0x10,
                MemoryType::RUNTIME_SERVICES_DATA,
            ),
        ]);
        for (pointer, space, want) in [
            (0x7e00_0010, PointerSpace::PhysicalOnly, 0x7e00_0010),
            (0x7e00_0010, PointerSpace::Physical, 0x7e00_0010),
            (0x7e00_0010, PointerSpace::Virtual, 0x7f00_0010),
            (0x2000_0010, PointerSpace::PhysicalOnly, 0x2000_0010),
            (0x2000_0010, PointerSpace::Physical, 0x7e00_0010),
            (0x2000_0010, PointerSpace::Virtual, 0x7e00_0010),
            (0x7f00_0010, PointerSpace::Virtual, 0x7f00_0010),
            (0x9000_0000, PointerSpace::PhysicalOnly, 0x9000_0000),
            (0x9000_0000, PointerSpace::Physical, 0x9000_0000),
            (0x9000_0000, PointerSpace::Virtual, 0x9000_0000),
        ] {
            assert_eq!(
                resolve(&map, pointer, space),
                want,
                "{pointer:#x} {space:?}"
            );
        }
    }
}
