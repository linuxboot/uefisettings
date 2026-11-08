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

mod source;

use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;
#[cfg(any(firmware_memory_maps, test))]
use std::os::fd::AsRawFd;
use std::path::Path;
use std::path::PathBuf;
#[cfg(any(firmware_memory_maps, test))]
use std::ptr;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use log::debug;
use thiserror::Error;

#[cfg(firmware_memory_maps)]
use crate::hii::config_snapshot::ExportedConfig;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::runtime_memory::DevMem;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::runtime_memory::PhysicalMemory;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::runtime_memory::ReservedMemory;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::runtime_memory::RuntimeMemory;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::MemoryMapFiles;
use crate::hii::firmware_memory::MemoryMapUnavailable;
use crate::hii::lockdown::refuse_locked_down;
use crate::hii::lockdown::LOCKDOWN_PATH;
#[cfg(any(firmware_memory_maps, test))]
use crate::hii::memory_access_denied::mark_refused_access;
#[cfg(any(firmware_memory_maps, test))]
use crate::hii::memory_access_denied::MemoryAccess;
use crate::hii::memory_access_denied::MemoryDevice;
use crate::hii::package;
use crate::hii::package::db_file::read_db_bytes;
use crate::hii::package::db_file::DbFileTooBig;
use crate::hii::package::db_file::MAX_ALLOWED_FILESIZE;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::read_exported_config;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::read_hii_export;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::ConfigurationTables;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::HiiExportError;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::PointerSpace;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::SystemTableError;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::SystemTableFiles;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::SystemTableLocator;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::EFI_HII_DATABASE_PROTOCOL_GUID;
use crate::parse_error::ReadParsed;
pub use source::HiiMethod;
pub use source::HiiMethodError;
pub use source::HiiSource;
pub use source::HiiSourceOptions;
pub use source::NoHiiDatabase;

// TODO: build this path from EFIVARS_MOUNT_POINT and EfivarFileName and open it with
// open_efivar, so efivarfs paths and missing-variable errors have one source.
pub const OCP_HIIDB_PATH: &str =
    "/sys/firmware/efi/efivars/HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0";

// Vendor ACPI table ("QHII" or "HIID"), with no public spec. Per the patch author, its
// body (after the 36-byte ACPI header) is a copy of the HII database itself, so
// it is read straight from sysfs with no /dev/mem, which lockdown refuses (Linux
// v6.11 drivers/char/mem.c:612, open_port()) and STRICT_DEVMEM refuses for System
// RAM.
const HIIDB_ACPI_DIR: &str = "/sys/firmware/acpi/tables";

/// Signatures of the vendor ACPI tables, the first field of their headers; each table is the
/// file of HIIDB_ACPI_DIR named exactly after it. The tables are equal: the acpi source tries
/// them in this order only so that its result is deterministic. Only a single instance of each
/// is read: Linux names the files of a signature with two or more instances `<SIG>1`, `<SIG>2`,
/// …, with no file `<SIG>` (Linux v6.11 drivers/acpi/sysfs.c:364-372).
const HIIDB_ACPI_SIGNATURES: [[u8; 4]; 2] = [*b"QHII", *b"HIID"];

// Size of the standard ACPI table header (EFI_ACPI_DESCRIPTION_HEADER) that
// prefixes the HII database bytes in the QHII or HIID table.
const ACPI_HEADER_LEN: usize = 36;

pub(super) const DEV_MEM_PATH: &str = "/dev/mem";

/// Below this address (1 MiB), x86 read() of /dev/mem may return zeros.
#[cfg(any(firmware_memory_maps, test))]
const X86_ZERO_FILL_END: u64 = 0x10_0000;

/// The firmware memory that the efivar source reads, where the OCP HiiDB efivar's pointer may
/// lead; the kernel's checks of /dev/mem apply either way.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EfivarMemory {
    /// One EFI_MEMORY_RUNTIME region of the EFI memory map that is not memory-mapped I/O: from
    /// x86's /sys/firmware/efi/runtime-map, or arm64's map from the FDT and /proc/kcore.
    #[default]
    Runtime,
    /// One firmware-reserved region of the full firmware memory map: an entry of type
    /// Reserved or ACPI Non-volatile Storage of x86's /sys/firmware/memmap, or an arm64 EFI
    /// memory descriptor of type EfiReservedMemoryType, EfiRuntimeServicesCode or Data,
    /// EfiACPIMemoryNVS or EfiPalCode; never one that touches runtime memory-mapped I/O. It
    /// may still read device memory that firmware reports as reserved, as OVMF reports PCIe
    /// ECAM.
    FirmwareReserved,
}

/// Where extract_db reads the vendor ACPI tables, the OCP HiiDB efivar and the files that locate
/// the EFI System Table, and the lockdown mode for physical memory; Default is this machine's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HiiSourcePaths {
    /// The OCP HiiDB efivar.
    ocp_hiidb: PathBuf,
    /// The directory of the vendor ACPI tables.
    acpi_tables: PathBuf,
    /// Physical memory, which the OCP HiiDB efivar points into.
    dev_mem: PathBuf,
    /// The kernel lockdown mode, which can refuse physical memory to the efivar source.
    lockdown: PathBuf,
    /// The firmware memory maps that bound the efivar source's read of physical memory.
    #[cfg(firmware_memory_maps)]
    maps: MemoryMapFiles,
    /// Where Linux tells where the EFI System Table is, for HiiMethod::Systab.
    #[cfg(firmware_memory_maps)]
    system_table: SystemTableLocator,
}

impl Default for HiiSourcePaths {
    fn default() -> Self {
        Self {
            ocp_hiidb: PathBuf::from(OCP_HIIDB_PATH),
            acpi_tables: PathBuf::from(HIIDB_ACPI_DIR),
            dev_mem: PathBuf::from(DEV_MEM_PATH),
            lockdown: PathBuf::from(LOCKDOWN_PATH),
            #[cfg(firmware_memory_maps)]
            maps: MemoryMapFiles::default(),
            #[cfg(firmware_memory_maps)]
            system_table: SystemTableLocator::default(),
        }
    }
}

impl HiiSourcePaths {
    /// The files from which HiiMethod::Systab reads, with the memory maps, physical memory and
    /// lockdown mode of the efivar source.
    #[cfg(firmware_memory_maps)]
    fn system_table_files(&self) -> SystemTableFiles {
        SystemTableFiles {
            locator: self.system_table.clone(),
            maps: self.maps.clone(),
            dev_mem: self.dev_mem.clone(),
            lockdown: self.lockdown.clone(),
        }
    }
}

/// Whether the firmware publishes its HII database through one of the methods of `options`, in
/// their order: a vendor ACPI table or the OCP variable exists, or the EFI System Table lists the
/// HII database export, which only this reads from /dev/mem.
pub fn hii_db_published_using(options: &HiiSourceOptions) -> Result<bool> {
    hii_db_published_using_at(&HiiSourcePaths::default(), options)
}

/// hii_db_published_using, with the files at `paths`.
fn hii_db_published_using_at(paths: &HiiSourcePaths, options: &HiiSourceOptions) -> Result<bool> {
    for method in options.source.methods() {
        let published = match method {
            HiiMethod::Acpi => acpi_table_exists(&paths.acpi_tables)?,
            HiiMethod::Efivar => paths.ocp_hiidb.try_exists()?,
            HiiMethod::Systab => systab_probe_answer(systab_lists_hii_export(paths))?,
        };
        if published {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a vendor ACPI table exists in `dir`.
fn acpi_table_exists(dir: &Path) -> io::Result<bool> {
    for (_, path) in hiidb_acpi_tables(dir) {
        if path.try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The configuration table's answer from `listed`, whether the System Table lists the HII
/// database export: false where the method finds its source absent, or where this build reads no
/// firmware memory map, so that the method reads nothing; the error where its source is refused
/// or fails.
fn systab_probe_answer(listed: Result<bool>) -> Result<bool> {
    let error = match listed {
        Ok(listed) => return Ok(listed),
        Err(error) => error,
    };
    if matches!(
        error.downcast_ref::<MemoryMapUnavailable>(),
        Some(MemoryMapUnavailable::NoMapReader)
    ) {
        return Ok(false);
    }
    match classify_systab(error) {
        HiiMethodError::Absent(_) => Ok(false),
        HiiMethodError::Refused(error) | HiiMethodError::Failed(error) => Err(error),
    }
}

/// Whether the System Table that the files at `paths` locate lists the HII database export.
#[cfg(firmware_memory_maps)]
fn systab_lists_hii_export(paths: &HiiSourcePaths) -> Result<bool> {
    Ok(
        ConfigurationTables::read(&paths.system_table_files(), DevMem::open)?
            .into_table(&EFI_HII_DATABASE_PROTOCOL_GUID, PointerSpace::Physical)?
            .is_some(),
    )
}

/// Fails: no firmware memory map bounds the read of the System Table.
#[cfg(not(firmware_memory_maps))]
fn systab_lists_hii_export(_: &HiiSourcePaths) -> Result<bool> {
    Err(MemoryMapUnavailable::NoMapReader.into())
}

/// The raw HII database bytes, read as `options` say.
pub fn extract_db_from(options: &HiiSourceOptions) -> Result<Vec<u8>, NoHiiDatabase> {
    extract_db_from_at(&HiiSourcePaths::default(), options)
}

/// extract_db_from, with the files at `paths`.
fn extract_db_from_at(
    paths: &HiiSourcePaths,
    options: &HiiSourceOptions,
) -> Result<Vec<u8>, NoHiiDatabase> {
    source::read_through(&options.source, |method| {
        read_by(paths, method, options.efivar_memory)
    })
}

/// The HII database that `method` reads with the files at `paths`, or why not: each method finds
/// its source absent only where the firmware does not publish it that way, which leaves the files
/// that the method reads first missing, Linux locating no System Table, or the configuration
/// table without its entry.
fn read_by(
    paths: &HiiSourcePaths,
    method: HiiMethod,
    efivar_memory: EfivarMemory,
) -> Result<Vec<u8>, HiiMethodError> {
    match method {
        HiiMethod::Acpi => extract_db_acpi(&paths.acpi_tables).map_err(|error| {
            match error.downcast_ref::<AcpiTablesInvalid>() {
                Some(AcpiTablesInvalid(tried)) if tried.iter().all(is_missing_file) => {
                    HiiMethodError::Absent(error)
                }
                _ => HiiMethodError::of_present(error),
            }
        }),
        HiiMethod::Efivar => extract_db_efivar(paths, efivar_memory).map_err(|error| {
            match error.is::<HiiDbVariableAbsent>() {
                true => HiiMethodError::Absent(error),
                false => HiiMethodError::of_present(error),
            }
        }),
        HiiMethod::Systab => extract_db_systab(paths).map_err(classify_systab),
    }
}

/// The error of HiiMethod::Systab: absent where Linux locates no System Table, as on a BIOS
/// boot or an arm64 boot without UEFI, or the System Table lists no HII database export.
#[cfg(firmware_memory_maps)]
fn classify_systab(error: anyhow::Error) -> HiiMethodError {
    match error.downcast_ref::<HiiExportError>() {
        Some(HiiExportError::NotListed) => HiiMethodError::Absent(error),
        Some(
            HiiExportError::Empty
            | HiiExportError::PackageLengthShort { .. }
            | HiiExportError::PastRegion { .. }
            | HiiExportError::Unterminated { .. }
            | HiiExportError::TooLarge { .. },
        ) => HiiMethodError::of_present(error),
        None => match error
            .downcast_ref::<SystemTableError>()
            .is_some_and(SystemTableError::locates_no_system_table)
        {
            true => HiiMethodError::Absent(error),
            false => HiiMethodError::of_present(error),
        },
    }
}

/// The error of HiiMethod::Systab, which reads no System Table on this architecture.
#[cfg(not(firmware_memory_maps))]
fn classify_systab(error: anyhow::Error) -> HiiMethodError {
    HiiMethodError::of_present(error)
}

/// The HII database export that the System Table that the files at `paths` locate lists, read
/// from paths.dev_mem.
#[cfg(firmware_memory_maps)]
fn extract_db_systab(paths: &HiiSourcePaths) -> Result<Vec<u8>> {
    read_hii_export(&paths.system_table_files(), DevMem::open)
}

/// Fails: no firmware memory map bounds the read of the System Table.
#[cfg(not(firmware_memory_maps))]
fn extract_db_systab(_: &HiiSourcePaths) -> Result<Vec<u8>> {
    Err(MemoryMapUnavailable::NoMapReader.into())
}

/// ExportConfig()'s results that the configuration table of this machine's System Table lists
/// (UEFI 2.11 §33.2.11.1), read from /dev/mem; None where it lists none.
#[cfg(firmware_memory_maps)]
pub(crate) fn exported_config() -> Result<Option<ExportedConfig>> {
    let paths = HiiSourcePaths::default();
    Ok(read_exported_config(&paths.system_table_files(), DevMem::open)?.map(ExportedConfig::new))
}

/// Whether `error` says only that a file does not exist.
fn is_missing_file(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

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

impl HiiDBEFIVar32 {
    /// The size of this layout of the HiiDB efivar.
    const SIZE: usize = 12;
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar64 {
    flags: u32,
    length: u32,
    address: u64,
}

impl HiiDBEFIVar64 {
    /// The size of this layout of the HiiDB efivar, the longer one.
    const SIZE: usize = 16;
}

impl HiiDBEFIVar {
    fn parse(contents: &[u8]) -> Result<Self> {
        match contents.len() {
            HiiDBEFIVar32::SIZE => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar32 = cursor.parse_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address.into(),
                })
            }
            HiiDBEFIVar64::SIZE => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar64 = cursor.parse_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address,
                })
            }
            size => Err(HiiDbEfivarSizeInvalid::Exactly(size).into()),
        }
    }

    /// The length of the HII database that the efivar locates: 1 to MAX_ALLOWED_FILESIZE bytes.
    fn checked_length(&self) -> Result<usize, HiiDbLengthInvalid> {
        if !(1..=MAX_ALLOWED_FILESIZE).contains(&u64::from(self.length)) {
            return Err(HiiDbLengthInvalid(self.length));
        }
        usize::try_from(self.length).map_err(|_| HiiDbLengthInvalid(self.length))
    }
}

/// The OCP HiiDB efivar has the size of neither layout, so it locates no HII database.
#[derive(Debug, Error, PartialEq, Eq)]
enum HiiDbEfivarSizeInvalid {
    /// It has this many bytes.
    #[error("Unexpected HiiDB efivar size: {0} bytes")]
    Exactly(usize),
    /// It is longer than HiiDBEFIVar64::SIZE, so it is not read whole.
    #[error(
        "HiiDB efivar is longer than its maximum of {} bytes",
        HiiDBEFIVar64::SIZE
    )]
    OverMaximum,
}

/// The OCP HiiDB efivar gives a length that no HII database has, so it locates none: a
/// variable of that name and GUID that holds only an 8-byte pointer, as one firmware's does,
/// parses as the 32-bit layout, with the pointer's low half as the length and its high half,
/// 0 below 4 GiB, as the address.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the HiiDB efivar gives a length of {0} bytes, not 1 to {MAX_ALLOWED_FILESIZE}")]
struct HiiDbLengthInvalid(u32);

/// The OCP HiiDB efivar does not exist: the firmware does not publish its HII database this way.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("the HiiDB variable {} does not exist", .0.display())]
pub struct HiiDbVariableAbsent(pub PathBuf);

/// The physical address and length of the HII database that the OCP HiiDB efivar at
/// paths.ocp_hiidb locates, once the kernel lockdown mode in paths.lockdown allows /dev/mem.
fn locate_efivar_database(paths: &HiiSourcePaths) -> Result<(u64, usize)> {
    // I haven't seen any documentation on extracting HiiDB anywhere on the internet
    // So this is directly based on what hiitool does.

    // try to read data from varstore
    let efivar_file = match File::open(&paths.ocp_hiidb) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(HiiDbVariableAbsent(paths.ocp_hiidb.clone()).into());
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to open {}", paths.ocp_hiidb.display()));
        }
    };

    let efivar_contents = read_hiidb_efivar(efivar_file)
        .with_context(|| format!("Failed to read efivar file, {}", paths.ocp_hiidb.display()))?;

    let db_info = HiiDBEFIVar::parse(&efivar_contents)?;
    let length = db_info.checked_length()?;
    refuse_locked_down(MemoryDevice::DevMem, &paths.lockdown)?;
    Ok((db_info.address, length))
}

/// The HiiDB that the OCP HiiDB efivar at paths.ocp_hiidb points to in paths.dev_mem, read only
/// inside `efivar_memory`, under the kernel lockdown mode in paths.lockdown.
#[cfg(firmware_memory_maps)]
fn extract_db_efivar(paths: &HiiSourcePaths, efivar_memory: EfivarMemory) -> Result<Vec<u8>> {
    extract_db_with(paths, efivar_memory, DevMem::open)
}

/// extract_db_efivar on an architecture whose firmware memory maps uefisettings does not read,
/// which refuses the read that nothing bounds.
#[cfg(not(firmware_memory_maps))]
fn extract_db_efivar(paths: &HiiSourcePaths, _: EfivarMemory) -> Result<Vec<u8>> {
    locate_efivar_database(paths)?;
    Err(MemoryMapUnavailable::NoMapReader.into())
}

/// extract_db_efivar, reading physical memory that `open_memory` opens from paths.dev_mem and
/// paths.lockdown: in that order, the efivar, its length, the lockdown mode, the memory map that
/// bounds the read, /dev/mem, then the read that the map admits.
#[cfg(firmware_memory_maps)]
fn extract_db_with<M: PhysicalMemory>(
    paths: &HiiSourcePaths,
    efivar_memory: EfivarMemory,
    open_memory: impl FnOnce(&Path, &Path) -> Result<M>,
) -> Result<Vec<u8>> {
    let (address, length) = locate_efivar_database(paths)?;

    // Now that we have offset and size from the HiiDB efivar, use it to read DB from memory.
    match efivar_memory {
        EfivarMemory::Runtime => {
            let map = paths.maps.runtime_bound(&paths.lockdown)?;
            RuntimeMemory::new(map, open_memory(&paths.dev_mem, &paths.lockdown)?)
                .read(address, length)
        }
        EfivarMemory::FirmwareReserved => {
            let map = paths.maps.firmware_reserved_bound(&paths.lockdown)?;
            ReservedMemory::new(map, open_memory(&paths.dev_mem, &paths.lockdown)?)
                .read(address, length)
        }
    }
}

/// The bytes of the HiiDB efivar `file`; one longer than HiiDBEFIVar64::SIZE, which
/// HiiDBEFIVar::parse would refuse, is refused without being read whole.
fn read_hiidb_efivar(file: impl Read) -> Result<Vec<u8>> {
    // one byte past the maximum, so that a longer file shows
    let mut file = file.take(u64::try_from(HiiDBEFIVar64::SIZE)? + 1);
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    if file.limit() == 0 {
        return Err(HiiDbEfivarSizeInvalid::OverMaximum.into());
    }
    Ok(contents)
}

/// Returns `length` bytes at `address` of `mem_file`, physical memory, which only DevMem reads
/// (clippy.toml); tests pass a fake `pread`.
///
/// It reads /dev/mem with one pread(), so the kernel copies the whole range and
/// the copy costs the same in unoptimized builds, unlike read_mapped()'s
/// userspace loop. Linux v7.2 fails that read with EFAULT when
/// valid_phys_addr_range() rejects the range (drivers/char/mem.c read_mem()).
/// mmap() of /dev/mem still maps those ranges, so only
/// EFAULT falls back to read_mapped(); every other error is returned, e.g.
/// EPERM from CONFIG_STRICT_DEVMEM, which mmap() enforces too. A refusal is under
/// MemoryAccessDenied (mark_refused_access).
///
/// Ranges for which pread_may_zero_fill() holds go straight to read_mapped().
#[cfg(any(firmware_memory_maps, test))]
pub(super) fn read_physical_memory_at(
    mem_file: &File,
    address: u64,
    length: usize,
    pread: impl Fn(&File, &mut [u8], u64) -> std::io::Result<()>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; length];

    if pread_may_zero_fill(address) {
        debug!("{DEV_MEM_PATH} at 0x{address:x} may read as zeros; using mmap()");
        read_mapped(mem_file, address, &mut buf)
            .with_context(|| {
                format!("Failed to map 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x}")
            })
            .map_err(|error| mark_refused_access(error, MemoryAccess::DevMemMap))?;
        return Ok(buf);
    }

    match pread(mem_file, &mut buf, address) {
        Ok(()) => Ok(buf),
        Err(e) if e.raw_os_error() == Some(libc::EFAULT) => {
            debug!("pread() of {DEV_MEM_PATH} at 0x{address:x} returned EFAULT; using mmap()");
            read_mapped(mem_file, address, &mut buf)
                .with_context(|| {
                    format!(
                        "pread() of 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x} \
                         returned EFAULT and the mmap() fallback failed"
                    )
                })
                .map_err(|error| mark_refused_access(error, MemoryAccess::DevMemMap))?;
            Ok(buf)
        }
        Err(e) => Err(e)
            .with_context(|| {
                format!("Failed to read 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x}")
            })
            .map_err(|error| mark_refused_access(error, MemoryAccess::DevMemRead)),
    }
}

/// Reports whether read() of /dev/mem may return zeros for a range starting at
/// `address` while mmap() maps the real bytes.
///
/// With CONFIG_STRICT_DEVMEM, Linux v7.2 x86 does so for System RAM below
/// 1 MiB (devmem_is_allowed(), arch/x86/mm/init.c); other architectures never
/// do. A range touching the first 1 MiB starts in it, so `address` suffices.
#[cfg(any(firmware_memory_maps, test))]
fn pread_may_zero_fill(address: u64) -> bool {
    cfg!(any(target_arch = "x86", target_arch = "x86_64")) && address < X86_ZERO_FILL_END
}

/// Fills `dst` from byte `offset` of `file`, mapping one page at a
/// time: Linux v7.2 picks one memory type per /dev/mem mapping
/// (mmap_mem_prepare(), drivers/char/mem.c). `file` must back the
/// whole range: a load from a page past the end of a regular file raises
/// SIGBUS (mmap(2)).
#[cfg(any(firmware_memory_maps, test))]
fn read_mapped(file: &File, offset: u64, dst: &mut [u8]) -> Result<()> {
    let length = dst.len();
    // Reject a range whose end overflows u64 before deriving the mapping from
    // it, so the error names the requested range instead of a derived value.
    offset
        .checked_add(u64::try_from(length)?)
        .with_context(|| format!("Range 0x{offset:x}+0x{length:x} overflows u64"))?;

    let mut done = 0;
    while done < length {
        // Cannot overflow: offset + length was checked above.
        done += copy_mapped_page(file, offset + u64::try_from(done)?, &mut dst[done..])?;
    }

    Ok(())
}

/// Copies bytes from `offset` to the end of its page, at most `dst.len()`,
/// through a one-page mapping; returns the count. `file` must back the copied
/// range. Loads go through copy_from_mapping: the page may be Device memory.
#[cfg(any(firmware_memory_maps, test))]
fn copy_mapped_page(file: &File, offset: u64, dst: &mut [u8]) -> Result<usize> {
    let page_size = page_size()?;
    let page_base = offset - offset % u64::try_from(page_size)?;
    let offset_in_page = usize::try_from(offset - page_base)?;
    let len = (page_size - offset_in_page).min(dst.len());
    // mmap64(), as off_t is signed and has 32 bits on most 32-bit glibc targets.
    let map_base = libc::off64_t::try_from(page_base)
        .with_context(|| format!("Mapping offset 0x{page_base:x} does not fit off64_t"))?;

    // SAFETY: addr = NULL lets the kernel pick an unused address range, so the
    // new PROT_READ mapping cannot alias any Rust allocation (including dst).
    let mapped = unsafe {
        libc::mmap64(
            ptr::null_mut(),
            page_size,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            map_base,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("Failed to mmap 0x{page_size:x} bytes at offset 0x{map_base:x}")
        });
    }

    // SAFETY: mmap succeeded, so [mapped, mapped + page_size) is mapped
    // PROT_READ, file backs the whole range, as the doc comment requires, and
    // offset_in_page + len <= page_size keeps the source in bounds. The mapping is
    // new, so it does not overlap dst.
    unsafe { copy_from_mapping(mapped.cast::<u8>().add(offset_in_page), &mut dst[..len]) };

    // SAFETY: mapped/page_size are exactly the region returned by mmap above and
    // no pointer into it is used after this call.
    if unsafe { libc::munmap(mapped, page_size) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to munmap 0x{page_size:x} bytes"));
    }

    Ok(len)
}

/// Returns the kernel page size, the granularity of mmap offsets.
#[cfg(any(firmware_memory_maps, test))]
fn page_size() -> Result<usize> {
    // SAFETY: sysconf has no memory-safety preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(size).context("Failed to query system page size")?;
    if !size.is_power_of_two() {
        bail!("System page size {size} is not a power of two");
    }
    Ok(size)
}

/// The widest load copy_from_mapping issues.
#[cfg(any(firmware_memory_maps, test))]
type MappedWord = u64;

/// Fills `dst` from `src` using only volatile loads from
/// addresses that are multiples of the load size: single bytes up to the first
/// MappedWord boundary, MappedWord loads, then the trailing bytes.
///
/// Wider unaligned loads fault on memory with strict access requirements
/// (<https://github.com/linuxboot/uefisettings/pull/12>); MappedWord loads cut
/// the load count ~8x. Linux v7.2 memcpy_fromio() (lib/iomem_copy.c) does the same.
///
/// # Safety
///
/// `src` must be valid for volatile reads of `dst.len()` bytes and must not
/// overlap `dst`.
#[cfg(any(firmware_memory_maps, test))]
unsafe fn copy_from_mapping(src: *const u8, dst: &mut [u8]) {
    const WORD: usize = std::mem::size_of::<MappedWord>();
    let len = dst.len();
    let dst = dst.as_mut_ptr();
    // SAFETY (every pointer access below): byte accesses use i < len and word
    // accesses use i + WORD <= len, so all stay inside src (caller contract) and
    // dst (length len). Word reads start only once src + i is a multiple of
    // WORD (a power of two, so the mask test is exact), which is a multiple of
    // align_of::<MappedWord>(), and i then advances by WORD, which keeps it so.
    let mut i = 0;
    while i < len && (src.add(i) as usize) & (WORD - 1) != 0 {
        *dst.add(i) = ptr::read_volatile(src.add(i));
        i += 1;
    }
    while len - i >= WORD {
        let word = ptr::read_volatile(src.add(i).cast::<MappedWord>());
        dst.add(i).cast::<MappedWord>().write_unaligned(word);
        i += WORD;
    }
    while i < len {
        *dst.add(i) = ptr::read_volatile(src.add(i));
        i += 1;
    }
}

/// The vendor ACPI tables in `dir` (HIIDB_ACPI_DIR), as their signatures and paths, in the
/// order of HIIDB_ACPI_SIGNATURES.
fn hiidb_acpi_tables(dir: &Path) -> [([u8; 4], PathBuf); HIIDB_ACPI_SIGNATURES.len()] {
    HIIDB_ACPI_SIGNATURES.map(|signature| {
        let path = dir.join(String::from_utf8_lossy(&signature).as_ref());
        (signature, path)
    })
}

/// The HII database of the first vendor ACPI table in `dir` that extract_db_acpi_table reads,
/// in the order of HIIDB_ACPI_SIGNATURES. It moves on only while a table is absent or fails
/// its checks (AcpiTableInvalid); any other error stops it. With no table read, it fails with
/// AcpiTablesInvalid.
fn extract_db_acpi(dir: &Path) -> Result<Vec<u8>> {
    let mut tried = Vec::new();
    for (signature, path) in hiidb_acpi_tables(dir) {
        let error = match extract_db_acpi_table(&path, signature) {
            Ok(db) => {
                debug!("HII database ACPI table: {}", path.display());
                return Ok(db);
            }
            Err(error) => error,
        };
        if !(is_missing_file(&error) || error.is::<AcpiTableInvalid>()) {
            return Err(error);
        }
        let name = String::from_utf8_lossy(&signature);
        debug!("ACPI table {name} unavailable: {error:#}");
        tried.push(error);
    }
    Err(AcpiTablesInvalid(tried).into())
}

/// No vendor ACPI table gave the HII database: each table's error, in the order of
/// HIIDB_ACPI_SIGNATURES.
#[derive(Debug)]
struct AcpiTablesInvalid(Vec<anyhow::Error>);

impl fmt::Display for AcpiTablesInvalid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("no vendor ACPI table holds an HII database (")?;
        for (i, error) in self.0.iter().enumerate() {
            if i > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{error:#}")?;
        }
        formatter.write_str(")")
    }
}

impl std::error::Error for AcpiTablesInvalid {}

/// Reads the HII database from the vendor ACPI table at `path`, of `signature`, whose
/// body IS the database content. The sysfs file is a 36-byte ACPI header
/// (EFI_ACPI_DESCRIPTION_HEADER) followed by the database bytes, so we drop the
/// header and return the rest, once validate_acpi_table accepts the table. No
/// /dev/mem — works where lockdown or STRICT_DEVMEM refuses /dev/mem; read_db_bytes caps it
/// at MAX_ALLOWED_FILESIZE.
fn extract_db_acpi_table(path: &Path, signature: [u8; 4]) -> Result<Vec<u8>> {
    let mut acpi_file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;

    let contents = match read_db_bytes(&mut acpi_file) {
        Ok(contents) => contents,
        Err(error) if error.is::<DbFileTooBig>() => {
            return Err(AcpiTableInvalid::TooLong)
                .with_context(|| format!("{} holds no HII database", path.display()));
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("Failed to read ACPI table file, {}", path.display()));
        }
    };

    validate_acpi_table(&contents, signature)
        .map(<[u8]>::to_vec)
        .with_context(|| format!("{} holds no HII database", path.display()))
}

/// Why the bytes of a vendor ACPI table hold no HII database: the table is not one
/// that publishes it, so the next table is tried.
#[derive(Debug, Error)]
enum AcpiTableInvalid {
    #[error("the table has {0} bytes, no more than its {ACPI_HEADER_LEN}-byte header")]
    TooShort(usize),
    #[error("the table is longer than {MAX_ALLOWED_FILESIZE} bytes")]
    TooLong,
    #[error(
        "the table's signature is {:?}, not {:?}",
        String::from_utf8_lossy(.found),
        String::from_utf8_lossy(.expected)
    )]
    Signature { found: [u8; 4], expected: [u8; 4] },
    #[error("the table's header gives a length of {header} bytes, but it has {actual}")]
    Length { header: u32, actual: usize },
    #[error("the table fails its checksum: its bytes sum to {0:#04x}, not 0")]
    Checksum(u8),
    #[error("the table's body is not a series of HII package lists")]
    Database(#[source] anyhow::Error),
}

/// The HII database in the vendor ACPI table `bytes` of `signature`: its body, after the
/// header, once the table checks and the body splits into HII package lists.
///
/// The packages inside are left to the parser, so that a database it cannot parse
/// fails with the parse error instead of a fallback to the next source, and
/// `hii extract-db` still copies it for a bug report.
///
/// For HIIDB_ACPI_DIR, sysfs guarantees Signature and Length: the file is named
/// after the signature and holds Length bytes (Linux v6.11 drivers/acpi/sysfs.c
/// acpi_table_attr_init, acpi_table_show). extract_db_acpi_table reads any path, so
/// they are checked too.
fn validate_acpi_table(bytes: &[u8], signature: [u8; 4]) -> Result<&[u8], AcpiTableInvalid> {
    let (header, body) = bytes
        .split_first_chunk::<ACPI_HEADER_LEN>()
        .filter(|(_, body)| !body.is_empty())
        .ok_or(AcpiTableInvalid::TooShort(bytes.len()))?;

    let [s0, s1, s2, s3, l0, l1, l2, l3, ..] = *header;
    let found = [s0, s1, s2, s3];
    if found != signature {
        return Err(AcpiTableInvalid::Signature {
            found,
            expected: signature,
        });
    }
    let length = u32::from_le_bytes([l0, l1, l2, l3]);
    if u32::try_from(bytes.len()).ok() != Some(length) {
        return Err(AcpiTableInvalid::Length {
            header: length,
            actual: bytes.len(),
        });
    }
    // The checksum makes all bytes of the table sum to 0 (Linux v6.11
    // include/acpi/actbl.h struct acpi_table_header).
    let sum = bytes.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
    if sum != 0 {
        return Err(AcpiTableInvalid::Checksum(sum));
    }

    package::get_package_lists(body).map_err(AcpiTableInvalid::Database)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::FileExt;

    use super::*;
    #[cfg(firmware_memory_maps)]
    use crate::hii::firmware_memory::fixture::write_firmware_memmap;
    #[cfg(firmware_memory_maps)]
    use crate::hii::firmware_memory::fixture::write_runtime_map;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryAccessDenied;
    use crate::hii::memory_access_denied::MemoryOperation;
    use crate::hii::package::hiidb_fixtures::en_strings_list;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    #[cfg(firmware_memory_maps)]
    use crate::hii::system_table::boot_params::fixture::boot_params;
    #[cfg(firmware_memory_maps)]
    use crate::memory_map::efi_memory_map::MemoryType;
    #[cfg(firmware_memory_maps)]
    use crate::memory_map::efi_memory_map::EFI_MEMORY_RUNTIME;

    /// Offset of Checksum in an ACPI table header, after Signature, Length and Revision.
    const ACPI_CHECKSUM_OFFSET: usize = 9;

    /// The lockdown mode none.
    const NO_LOCKDOWN: &str = "[none] integrity confidentiality\n";

    /// HiiSourcePaths of files in `dir`, each missing until the test writes it, with x86's
    /// memory maps.
    fn paths_in(dir: &Path) -> HiiSourcePaths {
        HiiSourcePaths {
            ocp_hiidb: dir.join("HiiDB"),
            acpi_tables: dir.to_owned(),
            dev_mem: dir.join("mem"),
            // the test's own lockdown file, never this machine's
            lockdown: dir.join("lockdown"),
            #[cfg(firmware_memory_maps)]
            maps: MemoryMapFiles::Sysfs {
                runtime_map: dir.join("runtime-map"),
                firmware_memmap: dir.join("memmap"),
            },
            #[cfg(firmware_memory_maps)]
            system_table: SystemTableLocator::BootParams {
                boot_params: dir.join("boot_params"),
                config_table: dir.join("config_table"),
            },
        }
    }

    /// Writes at `path` an OCP HiiDB efivar, in the 64-bit layout, that locates `length` bytes
    /// at `address`.
    fn write_efivar(path: &Path, address: u64, length: u32) {
        let efivar = [
            &7u32.to_le_bytes()[..],
            &length.to_le_bytes(),
            &address.to_le_bytes(),
        ];
        std::fs::write(path, efivar.concat()).expect("write the HiiDB efivar");
    }

    /// Writes x86's memory maps into `dir`, at paths_in's paths: a runtime-map of the
    /// descriptors `runtime` of (type, physical start, pages, attribute), and a firmware memory
    /// map of the entries `memmap` of (start, inclusive end, type).
    #[cfg(firmware_memory_maps)]
    fn write_sysfs_maps(
        dir: &Path,
        runtime: &[(MemoryType, u64, u64, u64)],
        memmap: &[(u64, u64, &str)],
    ) {
        let runtime: Vec<[String; 5]> = runtime
            .iter()
            .map(|&(memory_type, start, pages, attribute)| {
                [
                    format!("{:#x}\n", memory_type.0),
                    format!("{start:#x}\n"),
                    format!("{start:#x}\n"),
                    format!("{pages:#x}\n"),
                    format!("{attribute:#x}\n"),
                ]
            })
            .collect();
        let runtime: Vec<[&str; 5]> = runtime
            .iter()
            .map(|entry| entry.each_ref().map(String::as_str))
            .collect();
        write_runtime_map(&dir.join("runtime-map"), &runtime);
        let memmap: Vec<[String; 3]> = memmap
            .iter()
            .map(|&(start, end, memory_type)| {
                [
                    format!("{start:#x}\n"),
                    format!("{end:#x}\n"),
                    format!("{memory_type}\n"),
                ]
            })
            .collect();
        let memmap: Vec<[&str; 3]> = memmap
            .iter()
            .map(|entry| entry.each_ref().map(String::as_str))
            .collect();
        write_firmware_memmap(&dir.join("memmap"), &memmap);
    }

    /// The efivar source's bound and the order of its checks, where it reads memory maps.
    #[cfg(firmware_memory_maps)]
    mod efivar_bound {
        use super::*;
        use crate::hii::firmware_memory::fdt_params::fixture::uefi_fdt;
        use crate::hii::firmware_memory::fdt_params::UefiFdtParams;
        use crate::hii::firmware_memory::kcore::fixture::kcore_fixture;
        use crate::hii::firmware_memory::runtime_memory::fixture::MemoryWithin;
        use crate::hii::firmware_memory::runtime_memory::fixture::UnreadMemory;
        use crate::hii::firmware_memory::MemoryMapUnavailable;
        use crate::memory_map::efi_memory_map::fixture::descriptor;
        use crate::memory_map::efi_memory_map::RangeRefusal;

        /// The regions of the bound tests' memory maps: runtime data, reserved memory and ACPI NVS
        /// without the RUNTIME attribute, System RAM, ACPI tables, and a runtime descriptor of
        /// memory-mapped I/O inside the reserved memory, each of 4 pages but RAM.
        const RUNTIME_DATA_AT: u64 = 0x20_0000;
        const RESERVED_AT: u64 = 0x30_0000;
        const MMIO_AT: u64 = 0x30_2000;
        const NVS_AT: u64 = 0x40_0000;
        const RAM_AT: u64 = 0x50_0000;
        const ACPI_TABLES_AT: u64 = 0x60_0000;
        /// The size of each region but RAM.
        const REGION_SIZE: u64 = 0x4000;
        /// Where the database starts in its region: unaligned.
        const DB_OFFSET: u64 = 0x101;
        /// The database that the bound tests' efivar locates.
        const BOUNDED_DB: &[u8] = b"the bounded HiiDB";

        /// Writes into `dir` x86's maps of the bound tests' regions, as the x86 EFI stub and Linux
        /// export them: E820 reserved for runtime data, reserved memory and memory-mapped I/O.
        fn write_bound_sysfs_maps(dir: &Path) -> MemoryMapFiles {
            write_sysfs_maps(
                dir,
                &[
                    (
                        MemoryType::RUNTIME_SERVICES_DATA,
                        RUNTIME_DATA_AT,
                        4,
                        EFI_MEMORY_RUNTIME | 0xf,
                    ),
                    (
                        MemoryType::MEMORY_MAPPED_IO,
                        MMIO_AT,
                        1,
                        EFI_MEMORY_RUNTIME | 1,
                    ),
                ],
                &[
                    (
                        RUNTIME_DATA_AT,
                        RUNTIME_DATA_AT + REGION_SIZE - 1,
                        "Reserved",
                    ),
                    (RESERVED_AT, RESERVED_AT + REGION_SIZE - 1, "Reserved"),
                    (
                        NVS_AT,
                        NVS_AT + REGION_SIZE - 1,
                        "ACPI Non-volatile Storage",
                    ),
                    (RAM_AT, RAM_AT + 0xf_ffff, "System RAM"),
                    (
                        ACPI_TABLES_AT,
                        ACPI_TABLES_AT + REGION_SIZE - 1,
                        "ACPI Tables",
                    ),
                ],
            );
            paths_in(dir).maps
        }

        /// Writes into `dir` arm64's maps of the bound tests' regions: an FDT whose EFI memory map
        /// /proc/kcore serves.
        fn write_bound_fdt_maps(dir: &Path) -> MemoryMapFiles {
            const MMAP_AT: u64 = 0x4000_0000;
            let desc_size = 48;
            let pages = REGION_SIZE / 0x1000;
            let map = [
                descriptor(
                    desc_size,
                    MemoryType::RUNTIME_SERVICES_DATA,
                    RUNTIME_DATA_AT,
                    0,
                    pages,
                    EFI_MEMORY_RUNTIME | 0xf,
                ),
                descriptor(desc_size, MemoryType::RESERVED, RESERVED_AT, 0, pages, 1),
                descriptor(
                    desc_size,
                    MemoryType::MEMORY_MAPPED_IO,
                    MMIO_AT,
                    0,
                    1,
                    EFI_MEMORY_RUNTIME | 1,
                ),
                descriptor(
                    desc_size,
                    MemoryType::ACPI_MEMORY_NVS,
                    NVS_AT,
                    0,
                    pages,
                    0xf,
                ),
                // EfiLoaderData and EfiACPIReclaimMemory
                descriptor(desc_size, MemoryType(2), RAM_AT, 0, 0x100, 0xf),
                descriptor(desc_size, MemoryType(9), ACPI_TABLES_AT, 0, pages, 0xf),
            ]
            .concat();
            let (fdt, kcore) = (dir.join("fdt"), dir.join("kcore"));
            let params = UefiFdtParams {
                mmap_start: MMAP_AT,
                mmap_size: map.len(),
                mmap_desc_size: desc_size,
                mmap_desc_ver: 1,
            };
            std::fs::write(&fdt, uefi_fdt(&params)).expect("write the FDT");
            kcore_fixture(&kcore, &[(MMAP_AT, &map)]);
            MemoryMapFiles::Fdt { fdt, kcore }
        }

        /// The length of BOUNDED_DB.
        fn bounded_length() -> u32 {
            u32::try_from(BOUNDED_DB.len()).expect("a u32 length")
        }

        /// HiiSourcePaths in `dir` with the memory maps `maps`, without lockdown, and an efivar
        /// that locates BOUNDED_DB at `address`, where a fake /dev/mem holds it.
        fn bounded_paths(dir: &Path, maps: MemoryMapFiles, address: u64) -> HiiSourcePaths {
            let paths = HiiSourcePaths {
                maps,
                ..paths_in(dir)
            };
            std::fs::write(&paths.lockdown, NO_LOCKDOWN).expect("write lockdown");
            write_efivar(&paths.ocp_hiidb, address, bounded_length());
            let mem = File::create(&paths.dev_mem).expect("create the fake /dev/mem");
            mem.write_all_at(BOUNDED_DB, address)
                .expect("write the database");
            paths
        }

        /// Opens no physical memory.
        fn unopened(path: &Path, _lockdown: &Path) -> Result<UnreadMemory> {
            panic!("opened {}", path.display())
        }

        /// The efivar source reads only inside the memory that EfivarMemory names, by x86's and
        /// by arm64's maps: by default runtime data, and with FirmwareReserved also reserved
        /// memory and ACPI NVS, never System RAM, ACPI tables or runtime memory-mapped I/O. A
        /// refused range is read nowhere.
        #[test]
        fn efivar_reads_only_the_memory_that_efivar_memory_names() {
            use EfivarMemory::FirmwareReserved;
            use EfivarMemory::Runtime;

            let length = u64::try_from(BOUNDED_DB.len()).expect("a u64 length");
            let not_runtime = |address| RangeRefusal::NotRuntime { address, length };
            let not_reserved = |address| RangeRefusal::NotFirmwareReserved { address, length };
            let mmio = |address| RangeRefusal::MemoryMappedIo {
                address,
                length,
                memory_type: MemoryType::MEMORY_MAPPED_IO,
            };
            let reserved_end = RESERVED_AT + REGION_SIZE - 8;
            for (case, memory, address, refusal) in [
                ("runtime data", Runtime, RUNTIME_DATA_AT + DB_OFFSET, None),
                (
                    "reserved memory",
                    Runtime,
                    RESERVED_AT + DB_OFFSET,
                    Some(not_runtime(RESERVED_AT + DB_OFFSET)),
                ),
                (
                    "ACPI NVS",
                    Runtime,
                    NVS_AT + DB_OFFSET,
                    Some(not_runtime(NVS_AT + DB_OFFSET)),
                ),
                (
                    "System RAM",
                    Runtime,
                    RAM_AT + DB_OFFSET,
                    Some(not_runtime(RAM_AT + DB_OFFSET)),
                ),
                (
                    "memory-mapped I/O",
                    Runtime,
                    MMIO_AT + DB_OFFSET,
                    Some(mmio(MMIO_AT + DB_OFFSET)),
                ),
                (
                    "runtime data",
                    FirmwareReserved,
                    RUNTIME_DATA_AT + DB_OFFSET,
                    None,
                ),
                (
                    "reserved memory",
                    FirmwareReserved,
                    RESERVED_AT + DB_OFFSET,
                    None,
                ),
                ("ACPI NVS", FirmwareReserved, NVS_AT + DB_OFFSET, None),
                (
                    "System RAM",
                    FirmwareReserved,
                    RAM_AT + DB_OFFSET,
                    Some(not_reserved(RAM_AT + DB_OFFSET)),
                ),
                (
                    "ACPI tables",
                    FirmwareReserved,
                    ACPI_TABLES_AT + DB_OFFSET,
                    Some(not_reserved(ACPI_TABLES_AT + DB_OFFSET)),
                ),
                (
                    "past the end of reserved memory",
                    FirmwareReserved,
                    reserved_end,
                    Some(not_reserved(reserved_end)),
                ),
                (
                    "memory-mapped I/O in reserved memory",
                    FirmwareReserved,
                    MMIO_AT + DB_OFFSET,
                    Some(mmio(MMIO_AT + DB_OFFSET)),
                ),
            ] {
                for (family, write_maps) in [
                    ("x86", write_bound_sysfs_maps as fn(&Path) -> MemoryMapFiles),
                    ("arm64", write_bound_fdt_maps),
                ] {
                    let dir = tempfile::tempdir().expect("create a directory");
                    let paths = bounded_paths(dir.path(), write_maps(dir.path()), address);
                    // a refused range is read nowhere, and only the database otherwise
                    let readable = match refusal {
                        Some(_) => 0..0,
                        None => address..address + length,
                    };

                    let got = extract_db_with(&paths, memory, |path, _| {
                        MemoryWithin::open(path, readable.start, readable.end)
                    });

                    match (got, refusal) {
                        (Ok(db), None) => {
                            assert_eq!(db, BOUNDED_DB, "{family}, {memory:?}: {case}")
                        }
                        (Err(error), Some(refusal)) => assert_eq!(
                            error.downcast_ref::<RangeRefusal>(),
                            Some(&refusal),
                            "{family}, {memory:?}: {case}: {error:#}"
                        ),
                        (got, _) => panic!("{family}, {memory:?}: {case}: got {got:?}"),
                    }
                }
            }
        }

        /// Without the FDT or /proc/kcore, which give arm64's map, the efivar source refuses
        /// before it opens /dev/mem, by either bound.
        #[test]
        fn efivar_refuses_without_arm64_map_files() {
            for memory in [EfivarMemory::Runtime, EfivarMemory::FirmwareReserved] {
                for (missing, unavailable) in [
                    (
                        "fdt",
                        MemoryMapUnavailable::NoFdt as fn(PathBuf) -> MemoryMapUnavailable,
                    ),
                    ("kcore", MemoryMapUnavailable::NoKcore),
                ] {
                    let dir = tempfile::tempdir().expect("create a directory");
                    let paths = bounded_paths(
                        dir.path(),
                        write_bound_fdt_maps(dir.path()),
                        RUNTIME_DATA_AT + DB_OFFSET,
                    );
                    let path = dir.path().join(missing);
                    std::fs::remove_file(&path).expect("remove a map file");

                    let error = extract_db_with(&paths, memory, unopened).expect_err(missing);

                    assert_eq!(
                        error.downcast_ref::<MemoryMapUnavailable>(),
                        Some(&unavailable(path)),
                        "{memory:?}, no {missing}: {error:#}"
                    );
                }
            }
        }
    }

    /// Callers that name no bound get the runtime regions.
    #[test]
    fn efivar_memory_defaults_to_runtime() {
        assert_eq!(
            EfivarMemory::default(),
            EfivarMemory::Runtime,
            "the efivar source's default bound"
        );
    }

    /// hii_db_published_using fails, rather than answers false, when it cannot check a file: a
    /// vendor ACPI table or the OCP HiiDB efivar.
    #[test]
    fn hii_db_published_fails_when_a_file_cannot_be_checked() {
        let dir = tempfile::tempdir().expect("create a directory");
        let file = dir.path().join("file");
        std::fs::write(&file, b"").expect("create the file");
        // stat() of a path through a regular file fails with ENOTDIR, not ENOENT
        for (case, paths, method) in [
            (
                "the ACPI tables",
                HiiSourcePaths {
                    acpi_tables: file.clone(),
                    ..paths_in(dir.path())
                },
                HiiMethod::Acpi,
            ),
            (
                "the HiiDB efivar",
                HiiSourcePaths {
                    ocp_hiidb: file.join("HiiDB"),
                    ..paths_in(dir.path())
                },
                HiiMethod::Efivar,
            ),
        ] {
            let options = HiiSourceOptions {
                source: HiiSource::Method(method),
                ..HiiSourceOptions::default()
            };

            let error = hii_db_published_using_at(&paths, &options).expect_err(case);

            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(std::io::ErrorKind::NotADirectory),
                "{case}: not ENOTDIR: {error}"
            );
        }
    }

    /// hii_db_published_using holds for the acpi method once a vendor ACPI table exists, not
    /// another ACPI table, and for the efivar method once the OCP HiiDB efivar does; the
    /// automatic order holds once either does, on a BIOS boot, where Linux locates no System
    /// Table, and answers false without either.
    #[test]
    fn hii_db_published_once_any_file_exists() {
        let each_table = HIIDB_ACPI_SIGNATURES.map(|signature| {
            let name = String::from_utf8_lossy(&signature).into_owned();
            (
                format!("the {name} table only"),
                false,
                Some(name),
                [true, false],
            )
        });
        for (case, ocp_file, acpi_table, [want_acpi, want_efivar]) in [
            ("no file".to_owned(), false, None, [false, false]),
            (
                "another ACPI table only".to_owned(),
                false,
                Some("XSDT".to_owned()),
                [false, false],
            ),
            (
                "the HiiDB efivar only".to_owned(),
                true,
                None,
                [false, true],
            ),
            (
                "the HiiDB efivar and HIID".to_owned(),
                true,
                Some("HIID".to_owned()),
                [true, true],
            ),
        ]
        .into_iter()
        .chain(each_table)
        {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = paths_in(dir.path());
            #[cfg(firmware_memory_maps)]
            std::fs::write(dir.path().join("boot_params"), boot_params([0; 4], 0))
                .expect("write a BIOS boot's boot_params");
            let acpi_path = acpi_table.map(|name| paths.acpi_tables.join(name));
            let ocp_path = ocp_file.then_some(&paths.ocp_hiidb);
            for path in [ocp_path, acpi_path.as_ref()].into_iter().flatten() {
                std::fs::write(path, b"").expect("create the file");
            }

            for (source, want) in [
                (HiiSource::Method(HiiMethod::Acpi), want_acpi),
                (HiiSource::Method(HiiMethod::Efivar), want_efivar),
            ] {
                let options = HiiSourceOptions {
                    source,
                    ..HiiSourceOptions::default()
                };
                let got = hii_db_published_using_at(&paths, &options)
                    .unwrap_or_else(|error| panic!("{case}: {source:?}: {error:#}"));
                assert_eq!(got, want, "{case}: {source:?}");
            }
            let got = hii_db_published_using_at(&paths, &HiiSourceOptions::default())
                .unwrap_or_else(|error| panic!("{case}: auto: {error:#}"));
            assert_eq!(got, want_acpi || want_efivar, "{case}: auto");
        }
    }

    /// The configuration-table probe answers what the System Table lists, and false where this
    /// build reads no firmware memory map; it fails where its source is refused or fails.
    #[test]
    fn systab_probe_answers_false_only_without_its_source() {
        for (case, listed, want) in [
            ("listed", Ok(true), Some(true)),
            ("not listed", Ok(false), Some(false)),
            (
                "no memory map reader",
                Err(MemoryMapUnavailable::NoMapReader.into()),
                Some(false),
            ),
            (
                "refused",
                Err(io::Error::from(io::ErrorKind::PermissionDenied).into()),
                None,
            ),
            ("failed", Err(anyhow::anyhow!("the read failed")), None),
        ] {
            assert_eq!(systab_probe_answer(listed).ok(), want, "{case}");
        }
    }

    /// An ACPI table of `signature` and Length `length`, then `body`, whose checksum holds.
    fn acpi_table(signature: [u8; 4], length: u32, body: &[u8]) -> Vec<u8> {
        let mut table = [&signature[..], &length.to_le_bytes()].concat();
        table.resize(ACPI_HEADER_LEN, 0);
        table.extend_from_slice(body);
        let sum = table.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
        table[ACPI_CHECKSUM_OFFSET] = sum.wrapping_neg();
        table
    }

    /// An ACPI table of `signature` and `body`, whose header and checksum hold.
    fn signed_table(signature: [u8; 4], body: &[u8]) -> Vec<u8> {
        let length = u32::try_from(ACPI_HEADER_LEN + body.len()).expect("a u32 table length");
        acpi_table(signature, length, body)
    }

    /// The body of a vendor ACPI table is the HiiDB only if the table is no longer than
    /// MAX_ALLOWED_FILESIZE, its header, of the table's own signature, and its checksum hold, and
    /// the body parses, for each of HIIDB_ACPI_SIGNATURES. A table of other content, one longer
    /// than MAX_ALLOWED_FILESIZE included, fails with AcpiTableInvalid, so that the next table is
    /// tried.
    #[test]
    fn extract_db_acpi_table_returns_only_a_checked_database() {
        /// What extract_db_acpi_table returns for a case.
        enum Want {
            Database(Vec<u8>),
            /// AcpiTableInvalid, as Display gives it
            Invalid(String),
        }

        let database = en_strings_list([0x11; 16], b'A');
        // a form package of an IFR End op without its length byte
        let unparsable = package_list_with_guid([0x33; 16], &[0x05, 0x00, 0x00, 0x02, 0x29]);
        assert!(
            package::read_db(&unparsable).is_err(),
            "read_db parsed the unparsable package list"
        );
        let length = u32::try_from(ACPI_HEADER_LEN + database.len()).expect("a u32 table length");
        let over_cap = usize::try_from(MAX_ALLOWED_FILESIZE + 1).expect("a usize size");
        for signature in HIIDB_ACPI_SIGNATURES {
            let name = String::from_utf8_lossy(&signature);
            let mut bad_checksum = signed_table(signature, &database);
            bad_checksum[ACPI_CHECKSUM_OFFSET] = bad_checksum[ACPI_CHECKSUM_OFFSET].wrapping_add(1);
            let [s0, s1, s2, _] = signature;
            let last_byte_differs = [s0, s1, s2, b'X'];
            for (case, table, want) in [
                (
                    "a database",
                    signed_table(signature, &database),
                    Want::Database(database.clone()),
                ),
                (
                    "a bad checksum",
                    bad_checksum,
                    Want::Invalid(
                        "the table fails its checksum: its bytes sum to 0x01, not 0".into(),
                    ),
                ),
                (
                    "a body that is no database",
                    signed_table(signature, &[0x5a; 64]),
                    Want::Invalid("the table's body is not a series of HII package lists".into()),
                ),
                (
                    "package lists that the parser refuses",
                    signed_table(signature, &unparsable),
                    Want::Database(unparsable.clone()),
                ),
                (
                    "a header only",
                    signed_table(signature, &[]),
                    Want::Invalid("the table has 36 bytes, no more than its 36-byte header".into()),
                ),
                (
                    "shorter than a header",
                    vec![0x5a; 4],
                    Want::Invalid("the table has 4 bytes, no more than its 36-byte header".into()),
                ),
                (
                    "another signature",
                    acpi_table(*b"XSDT", length, &database),
                    Want::Invalid(format!(r#"the table's signature is "XSDT", not "{name}""#)),
                ),
                (
                    "a signature that differs in its last byte",
                    acpi_table(last_byte_differs, length, &database),
                    Want::Invalid(format!(
                        r#"the table's signature is "{}", not "{name}""#,
                        String::from_utf8_lossy(&last_byte_differs)
                    )),
                ),
                (
                    "a Length past the end",
                    acpi_table(signature, length + 1, &database),
                    Want::Invalid(format!(
                        "the table's header gives a length of {} bytes, but it has {length}",
                        length + 1
                    )),
                ),
                (
                    "a Length short of the end",
                    acpi_table(signature, length - 1, &database),
                    Want::Invalid(format!(
                        "the table's header gives a length of {} bytes, but it has {length}",
                        length - 1
                    )),
                ),
                (
                    "longer than MAX_ALLOWED_FILESIZE",
                    vec![0; over_cap],
                    Want::Invalid(format!(
                        "the table is longer than {MAX_ALLOWED_FILESIZE} bytes"
                    )),
                ),
            ] {
                let dir = tempfile::tempdir().expect("create a directory");
                let path = dir.path().join(name.as_ref());
                std::fs::write(&path, &table).expect("write the table");

                match (extract_db_acpi_table(&path, signature), want) {
                    (Ok(db), Want::Database(want)) => assert_eq!(db, want, "{case} ({name})"),
                    (Err(error), Want::Invalid(message)) => assert_eq!(
                        error
                            .downcast_ref::<AcpiTableInvalid>()
                            .map(ToString::to_string),
                        Some(message),
                        "{case} ({name}): {error:#}"
                    ),
                    (got, _) => panic!("{case} ({name}): got {got:?}"),
                }
            }
        }
    }

    /// A HiiDB efivar of HiiDBEFIVar64::SIZE bytes reads whole; one byte longer, it is
    /// refused.
    #[test]
    fn hiidb_efivar_longer_than_its_maximum_is_refused() {
        let size = u64::try_from(HiiDBEFIVar64::SIZE).expect("a u64 size");
        for (case, length, fits) in [
            ("the 64-bit layout's size", size, true),
            ("one byte longer", size + 1, false),
        ] {
            let read = read_hiidb_efivar(std::io::repeat(0).take(length));

            match (read, fits) {
                (Ok(contents), true) => {
                    assert_eq!(contents, [0; HiiDBEFIVar64::SIZE], "{case}: contents")
                }
                (Err(error), false) => {
                    assert_eq!(
                        error.to_string(),
                        "HiiDB efivar is longer than its maximum of 16 bytes",
                        "{case}"
                    );
                    assert_eq!(
                        error.downcast_ref::<HiiDbEfivarSizeInvalid>(),
                        Some(&HiiDbEfivarSizeInvalid::OverMaximum),
                        "{case}"
                    );
                }
                (read, _) => panic!("{case}: read {read:?}"),
            }
        }
    }

    /// An HiiDB efivar whose length no HII database has is refused before anything else: before
    /// the kernel lockdown, in integrity mode here, and /dev/mem, missing here. One firmware's
    /// variable holds only a pointer below 4 GiB, whose low half is the length.
    #[test]
    fn hiidb_efivar_with_an_implausible_length_is_refused_first() {
        let max = u32::try_from(MAX_ALLOWED_FILESIZE).expect("a u32 maximum");
        let pointer = [&6u32.to_le_bytes()[..], &0x7a5b_3000u64.to_le_bytes()].concat();
        for (case, efivar, length) in [
            (
                "length 0",
                [
                    &7u32.to_le_bytes()[..],
                    &0u32.to_le_bytes(),
                    &0x7f00_1000u64.to_le_bytes(),
                ]
                .concat(),
                0,
            ),
            (
                "length MAX_ALLOWED_FILESIZE + 1",
                [
                    &7u32.to_le_bytes()[..],
                    &(max + 1).to_le_bytes(),
                    &0x7f00_1000u64.to_le_bytes(),
                ]
                .concat(),
                max + 1,
            ),
            ("an 8-byte pointer", pointer, 0x7a5b_3000),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = HiiSourcePaths {
                lockdown: lockdown_file(dir.path(), "integrity"),
                ..paths_in(dir.path())
            };
            std::fs::write(&paths.ocp_hiidb, efivar).expect("write the HiiDB efivar");

            let error = extract_db_efivar(&paths, EfivarMemory::Runtime)
                .expect_err("read an implausible length");

            assert_eq!(
                error.downcast_ref::<HiiDbLengthInvalid>(),
                Some(&HiiDbLengthInvalid(length)),
                "{case}: {error:#}"
            );
            assert_eq!(
                error.to_string(),
                format!("the HiiDB efivar gives a length of {length} bytes, not 1 to 16777216"),
                "{case}"
            );
        }
    }

    /// The shortest and the longest HII database that an HiiDB efivar may give are read.
    #[test]
    #[cfg(firmware_memory_maps)]
    fn hiidb_efivar_reads_lengths_of_1_to_max_hiidb_size() {
        let max = usize::try_from(MAX_ALLOWED_FILESIZE).expect("a usize maximum");
        for (case, ocp) in [
            ("1 byte", vec![0xa5]),
            ("MAX_ALLOWED_FILESIZE", vec![0x5a; max]),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = paths_in(dir.path());
            std::fs::write(&paths.lockdown, NO_LOCKDOWN).expect("write lockdown");
            // runtime data as long as the longest database, from where pread() reads
            write_sysfs_maps(
                dir.path(),
                &[(
                    MemoryType::RUNTIME_SERVICES_DATA,
                    X86_ZERO_FILL_END,
                    MAX_ALLOWED_FILESIZE / 0x1000,
                    EFI_MEMORY_RUNTIME,
                )],
                &[],
            );
            let length = u32::try_from(ocp.len()).expect("a u32 length");
            write_efivar(&paths.ocp_hiidb, X86_ZERO_FILL_END, length);
            File::create(&paths.dev_mem)
                .expect("create the fake /dev/mem")
                .write_all_at(&ocp, X86_ZERO_FILL_END)
                .expect("write the database");

            let got = extract_db_efivar(&paths, EfivarMemory::Runtime)
                .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert!(got == ocp, "{case}: read {} bytes", got.len());
        }
    }

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

    /// Returns a temp file of `len` bytes and those bytes. The pattern's period,
    /// 251, is prime, so reads shifted by a word or a page mismatch.
    fn mapped_fixture(len: usize) -> (File, Vec<u8>) {
        use std::io::Write;
        let data: Vec<u8> = (0..len).map(|i| ((i * 131 + 7) % 251) as u8).collect();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&data).unwrap();
        (file, data)
    }

    #[test]
    fn read_mapped_matches_file_bytes_at_every_alignment() {
        let page = page_size().unwrap();
        let (file, data) = mapped_fixture(3 * page + 64);
        for offset in (0..=8).chain([page - 1, page, page + 3]) {
            for length in [1, 7, 8, 9, 15, 16, 17, page, page + 13, 2 * page + 5] {
                // 0xff is not in the fixture, so unwritten bytes fail.
                let mut got = vec![0xff; length];
                read_mapped(&file, offset as u64, &mut got).unwrap();
                assert_eq!(
                    got,
                    data[offset..offset + length],
                    "offset {offset} length {length}"
                );
            }
        }
    }

    #[test]
    fn read_mapped_zero_length_is_empty() {
        let (file, _) = mapped_fixture(16);
        for offset in [0, 3] {
            read_mapped(&file, offset, &mut [])
                .unwrap_or_else(|err| panic!("offset {offset}: {err:#}"));
        }
    }

    /// The offset also fails the off64_t check; the overflow error must win.
    #[test]
    fn read_mapped_rejects_overflowing_range() {
        let (file, _) = mapped_fixture(16);
        let err = read_mapped(&file, u64::MAX - 2, &mut [0; 8]).unwrap_err();
        assert!(
            format!("{err:#}").contains("overflows u64"),
            "unexpected error: {err:#}"
        );
    }

    /// Catches off_t truncation to 32 bits.
    #[test]
    fn read_mapped_reads_above_4gib() {
        let offset: u64 = 0x1_0000_0123;
        let file = tempfile::tempfile().unwrap();
        let data: Vec<u8> = (0..100u8).collect();
        file.write_all_at(&data, offset).unwrap();
        let mut got = vec![0xff; data.len()];
        read_mapped(&file, offset, &mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn copy_mapped_page_stops_at_page_end() {
        let page = page_size().unwrap();
        let (file, data) = mapped_fixture(2 * page);
        for (offset, dst_len, want) in [(page - 3, 8, 3), (page, page + 5, page), (page + 1, 4, 4)]
        {
            // 0xff is not in the fixture, so bytes written past `want` fail.
            let mut got = vec![0xff; dst_len];
            let copied = copy_mapped_page(&file, offset as u64, &mut got).unwrap();
            assert_eq!(copied, want, "offset {offset}");
            assert_eq!(got[..want], data[offset..offset + want], "offset {offset}");
            assert!(got[want..].iter().all(|&b| b == 0xff), "offset {offset}");
        }
    }

    #[test]
    fn parse_rejects_unexpected_hiidb_efivar_size() {
        for size in [0, 4, 8, 11, 13, 15, 17, 20, 24] {
            let err = HiiDBEFIVar::parse(&vec![0x5a; size]).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("Unexpected HiiDB efivar size: {size} bytes")
            );
            assert_eq!(
                err.downcast_ref::<HiiDbEfivarSizeInvalid>(),
                Some(&HiiDbEfivarSizeInvalid::Exactly(size)),
                "{size} bytes"
            );
        }
    }

    #[test]
    fn pread_may_zero_fill_only_below_1_mib_on_x86() {
        let x86 = cfg!(any(target_arch = "x86", target_arch = "x86_64"));
        for (address, want) in [
            (0, x86),
            (0x9f000, x86),
            (0xf_ffff, x86),
            (0x10_0000, false),
            (0x6bb3_9000, false),
            (u64::MAX, false),
        ] {
            assert_eq!(pread_may_zero_fill(address), want, "address 0x{address:x}");
        }
    }

    fn failing_pread(errno: i32) -> impl Fn(&File, &mut [u8], u64) -> std::io::Result<()> {
        move |_, _, _| Err(std::io::Error::from_raw_os_error(errno))
    }

    fn offset_stamp(offset: u64) -> u8 {
        offset as u8 ^ 0xa5
    }

    /// Fakes a successful pread whose bytes encode their offset.
    fn offset_stamping_pread(_: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = offset_stamp(offset + i as u64);
        }
        Ok(())
    }

    fn root_errno(err: &anyhow::Error) -> Option<i32> {
        err.root_cause()
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "tests read_physical_memory_at itself"
    )]
    fn read_physical_memory_at_routes_by_pread_may_zero_fill() {
        let x86 = cfg!(any(target_arch = "x86", target_arch = "x86_64"));
        let (file, data) = mapped_fixture(X86_ZERO_FILL_END as usize + 16);
        for (address, mapped) in [
            (0, x86),
            (0x9f000, x86),
            (0xf_fff8, x86),
            (0x10_0000, false),
            (0x6bb3_9000, false),
        ] {
            let start = address as usize;
            let stamps: Vec<u8> = (address..address + 16).map(offset_stamp).collect();
            // File bytes differ from stamps, so each result's source is clear.
            assert_ne!(
                data.get(start..start + 16),
                Some(&stamps[..]),
                "address 0x{address:x}"
            );

            let failed = read_physical_memory_at(&file, address, 16, failing_pread(libc::EIO));
            // Below 1 MiB, x86 read() succeeds even when it returns zeros, so a
            // successful `pread` must be skipped too.
            let stamped = read_physical_memory_at(&file, address, 16, offset_stamping_pread)
                .unwrap_or_else(|err| panic!("stamping pread, address 0x{address:x}: {err:#}"));
            if mapped {
                let want = &data[start..start + 16];
                let failed = failed
                    .unwrap_or_else(|err| panic!("EIO pread, address 0x{address:x}: {err:#}"));
                assert_eq!(failed, want, "EIO pread, address 0x{address:x}");
                assert_eq!(stamped, want, "stamping pread, address 0x{address:x}");
            } else {
                let err = failed.unwrap_err();
                assert_eq!(
                    root_errno(&err),
                    Some(libc::EIO),
                    "EIO pread, address 0x{address:x}: {err:#}"
                );
                assert_eq!(stamped, stamps, "stamping pread, address 0x{address:x}");
            }
        }
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "tests read_physical_memory_at itself"
    )]
    fn read_physical_memory_at_returns_pread_bytes() {
        let address = X86_ZERO_FILL_END + 5;
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&[1; 100], address).unwrap();
        let want: Vec<u8> = (address..address + 100).map(offset_stamp).collect();
        // Neither zeros nor the file's bytes (1) can match `want`.
        assert!(want.iter().all(|&b| b != 0 && b != 1), "{want:?}");

        let got = read_physical_memory_at(&file, address, want.len(), offset_stamping_pread);

        assert_eq!(got.unwrap(), want);
    }

    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "tests read_physical_memory_at itself"
    )]
    fn read_physical_memory_at_maps_on_efault() {
        let address = X86_ZERO_FILL_END + 5;
        let file = tempfile::tempfile().unwrap();
        let data: Vec<u8> = (1..=100u8).collect();
        file.write_all_at(&data, address).unwrap();
        let got = read_physical_memory_at(&file, address, data.len(), failing_pread(libc::EFAULT))
            .unwrap();
        assert_eq!(got, data);
    }

    /// A pread() error other than EFAULT is returned, with no mmap() fallback; EPERM and EACCES
    /// are refusals.
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "tests read_physical_memory_at itself"
    )]
    fn read_physical_memory_at_returns_other_pread_errors() {
        let address = X86_ZERO_FILL_END + 5;
        let file = tempfile::tempfile().unwrap();
        // mmap() would succeed here, so a fallback would hide the error.
        file.write_all_at(&[1; 100], address).unwrap();
        for (errno, cause) in [
            (libc::EPERM, Some(DenialCause::StrictDevmem)),
            (libc::EACCES, Some(DenialCause::Permission)),
            (libc::EIO, None),
            (libc::EINVAL, None),
        ] {
            let err =
                read_physical_memory_at(&file, address, 100, failing_pread(errno)).unwrap_err();
            assert_eq!(root_errno(&err), Some(errno), "{err:#}");
            let want = cause.map(|cause| MemoryAccessDenied {
                device: MemoryDevice::DevMem,
                operation: MemoryOperation::Read,
                cause,
            });
            assert_eq!(
                err.downcast_ref::<MemoryAccessDenied>(),
                want.as_ref(),
                "errno {errno}: {err:#}"
            );
        }
    }

    /// A refused mmap() is a refusal, both below 1 MiB on x86 and on the EFAULT fallback:
    /// mmap() of a file open only for writing fails with EACCES (mmap(2)).
    #[test]
    #[expect(
        clippy::disallowed_methods,
        reason = "tests read_physical_memory_at itself"
    )]
    fn read_physical_memory_at_marks_a_refused_mmap() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("mem");
        let file = File::options()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create the fake /dev/mem for writing only");
        let want = MemoryAccessDenied {
            device: MemoryDevice::DevMem,
            operation: MemoryOperation::Map,
            cause: DenialCause::Permission,
        };
        for address in [0x1000, X86_ZERO_FILL_END + 5] {
            let err = read_physical_memory_at(&file, address, 16, failing_pread(libc::EFAULT))
                .expect_err("read a file open only for writing");

            assert_eq!(
                root_errno(&err),
                Some(libc::EACCES),
                "0x{address:x}: {err:#}"
            );
            assert_eq!(
                err.downcast_ref::<MemoryAccessDenied>(),
                Some(&want),
                "0x{address:x}: {err:#}"
            );
        }
    }

    /// The order in which the vendor ACPI table method tries the tables, as the starting tree
    /// implements it.
    mod acpi_order {
        use super::*;
        use crate::hii::memory_access_denied::fixture::unreadable_file;

        /// The database of each table: a package list of the table's own GUID.
        fn database(signature: [u8; 4]) -> Vec<u8> {
            let guid = [signature, signature, signature, signature].concat();
            en_strings_list(guid.try_into().expect("16 bytes"), signature[0])
        }

        /// Writes into `dir` the table of `signature` that holds database(signature).
        fn write_valid(dir: &Path, signature: [u8; 4]) {
            let name = String::from_utf8_lossy(&signature).into_owned();
            std::fs::write(
                dir.join(name),
                signed_table(signature, &database(signature)),
            )
            .expect("write the table");
        }

        /// Writes into `dir` a table of `signature` whose checksum fails.
        fn write_invalid(dir: &Path, signature: [u8; 4]) {
            let name = String::from_utf8_lossy(&signature).into_owned();
            let mut table = signed_table(signature, &database(signature));
            table[ACPI_CHECKSUM_OFFSET] = table[ACPI_CHECKSUM_OFFSET].wrapping_add(1);
            std::fs::write(dir.join(name), table).expect("write the table");
        }

        /// It tries QHII first, then HIID: with both valid it reads QHII, with QHII absent or
        /// invalid HIID.
        #[test]
        fn tries_qhii_then_hiid_past_absent_or_invalid_tables() {
            for (case, qhii, want) in [
                ("both valid", Some(true), *b"QHII"),
                ("QHII absent", None, *b"HIID"),
                ("QHII invalid", Some(false), *b"HIID"),
            ] {
                let dir = tempfile::tempdir().expect("create a directory");
                match qhii {
                    Some(true) => write_valid(dir.path(), *b"QHII"),
                    Some(false) => write_invalid(dir.path(), *b"QHII"),
                    None => {}
                }
                write_valid(dir.path(), *b"HIID");

                let db =
                    extract_db_acpi(dir.path()).unwrap_or_else(|error| panic!("{case}: {error:#}"));

                assert_eq!(db, database(want), "{case}");
            }
        }

        /// It stops at a table that it may not read, or cannot read as a file, and fails with that
        /// table's error, though HIID holds the database.
        #[test]
        fn stops_at_a_table_that_it_may_not_read() {
            let dir = tempfile::tempdir().expect("create a directory");
            write_valid(dir.path(), *b"HIID");
            std::fs::create_dir(dir.path().join("QHII")).expect("create the directory QHII");

            let error = extract_db_acpi(dir.path()).expect_err("read the directory QHII");
            assert!(
                format!("{error:#}").starts_with(&format!(
                    "Failed to read ACPI table file, {}",
                    dir.path().join("QHII").display()
                )),
                "a directory: {error:#}"
            );

            let dir = tempfile::tempdir().expect("create a directory");
            write_valid(dir.path(), *b"HIID");
            if !unreadable_file(&dir.path().join("QHII")) {
                // CAP_DAC_OVERRIDE reads it anyway
                return;
            }
            let error = extract_db_acpi(dir.path()).expect_err("read the unreadable QHII");
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .map(std::io::Error::kind),
                Some(std::io::ErrorKind::PermissionDenied),
                "an unreadable file: {error:#}"
            );
        }

        /// With no table that gives the database, the error names each table's error, QHII's
        /// first.
        #[test]
        fn names_each_table_s_error_in_order() {
            let dir = tempfile::tempdir().expect("create a directory");
            write_invalid(dir.path(), *b"QHII");

            let error = extract_db_acpi(dir.path()).expect_err("read no table");

            let qhii = dir.path().join("QHII");
            let hiid = dir.path().join("HIID");
            assert_eq!(
                format!("{error:#}"),
                format!(
                    "no vendor ACPI table holds an HII database ({} holds no HII database: the \
                     table fails its checksum: its bytes sum to 0x01, not 0; Failed to open {}: \
                     No such file or directory (os error 2))",
                    qhii.display(),
                    hiid.display()
                )
            );
        }
    }

    /// Which methods read the HII database, and how each reports its source absent, refused or
    /// failing otherwise.
    mod sources {
        use super::*;
        use crate::hii::lockdown::LockdownMode;
        use crate::hii::memory_access_denied::fixture::unreadable_file;
        use crate::hii::memory_access_denied::MemoryDevice;

        /// The lockdown mode integrity, which refuses /dev/mem.
        const INTEGRITY: &str = "none [integrity] confidentiality\n";

        /// The options of `source`, with the default memory for the efivar method.
        fn options(source: HiiSource) -> HiiSourceOptions {
            HiiSourceOptions {
                source,
                ..HiiSourceOptions::default()
            }
        }

        /// The method's error of each method that extract_db_from_at tried with `paths` and
        /// `source`, which reads no database.
        fn tried(paths: &HiiSourcePaths, source: HiiSource) -> NoHiiDatabase {
            extract_db_from_at(paths, &options(source)).expect_err("read no database")
        }

        /// Whether `error` is the lockdown mode integrity's refusal of /dev/mem.
        fn refused_by_integrity(error: &HiiMethodError) -> bool {
            matches!(error, HiiMethodError::Refused(_)) && denied_by_integrity(error.error())
        }

        /// Whether `error` is the lockdown mode integrity's MemoryAccessDenied of /dev/mem.
        fn denied_by_integrity(error: &anyhow::Error) -> bool {
            error.downcast_ref::<MemoryAccessDenied>()
                == Some(&MemoryAccessDenied {
                    device: MemoryDevice::DevMem,
                    operation: MemoryOperation::Open,
                    cause: DenialCause::Lockdown(LockdownMode::Integrity),
                })
        }

        /// Without a vendor ACPI table or the HiiDB variable, the acpi and efivar methods find
        /// their sources absent, the efivar method naming the variable.
        #[test]
        fn acpi_and_efivar_find_their_sources_absent_without_their_files() {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = paths_in(dir.path());

            for method in [HiiMethod::Acpi, HiiMethod::Efivar] {
                let error = tried(&paths, HiiSource::Method(method));

                let [(got, HiiMethodError::Absent(_))] = error.tried.as_slice() else {
                    panic!("{method}: {error}");
                };
                assert_eq!(*got, method);
            }
            let error = tried(&paths, HiiSource::Method(HiiMethod::Efivar));
            assert_eq!(
                error.to_string(),
                format!(
                    "no HII database: efivar: absent: the HiiDB variable {} does not exist",
                    paths.ocp_hiidb.display()
                )
            );
        }

        /// A vendor ACPI table that fails its checks, and a HiiDB variable of an implausible
        /// length, are no absent sources.
        #[test]
        fn invalid_sources_fail_without_being_absent() {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = paths_in(dir.path());
            std::fs::write(paths.acpi_tables.join("QHII"), b"no ACPI table").expect("write QHII");
            write_efivar(&paths.ocp_hiidb, 0x7e00_0000, 0);

            for method in [HiiMethod::Acpi, HiiMethod::Efivar] {
                let error = tried(&paths, HiiSource::Method(method));

                let [(_, HiiMethodError::Failed(_))] = error.tried.as_slice() else {
                    panic!("{method}: {error}");
                };
            }
        }

        /// The efivar method is refused before /dev/mem under lockdown, and the acpi method by a
        /// table that this user may not read; the automatic order stops at either.
        #[test]
        fn refused_methods_stop_the_automatic_order() {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = paths_in(dir.path());
            std::fs::write(&paths.lockdown, INTEGRITY).expect("write lockdown");
            write_efivar(&paths.ocp_hiidb, 0x7e00_0000, 16);

            let error = tried(&paths, HiiSource::Auto);
            let [(HiiMethod::Acpi, HiiMethodError::Absent(_)), (HiiMethod::Efivar, efivar)] =
                error.tried.as_slice()
            else {
                panic!("{error}");
            };
            assert!(refused_by_integrity(efivar), "{error}");

            if !unreadable_file(&paths.acpi_tables.join("QHII")) {
                // CAP_DAC_OVERRIDE reads it anyway
                return;
            }
            let error = tried(&paths, HiiSource::Auto);
            let [(HiiMethod::Acpi, HiiMethodError::Refused(_))] = error.tried.as_slice() else {
                panic!("{error}");
            };
        }

        /// The configuration-table method, through x86's files.
        #[cfg(firmware_memory_maps)]
        mod systab {
            use super::*;
            use crate::firmware_width::FirmwareWidth;
            use crate::hii::firmware_memory::fdt_params::fixture::no_uefi_fdt;
            use crate::hii::firmware_memory::fdt_params::fixture::xen_uefi_fdt;
            use crate::hii::package::Guid;
            use crate::hii::system_table::fixture::configuration_table;
            use crate::hii::system_table::fixture::valid_system_table;
            use crate::hii::system_table::fixture::x86_files;

            /// The runtime data region of the tests, where the System Table, its entries and
            /// the export are, unaligned.
            const REGION_AT: u64 = 0x7e00_0000;
            const SYSTEM_TABLE_AT: u64 = REGION_AT + 0x18;
            const ENTRIES_AT: u64 = REGION_AT + 0x200;
            const EXPORT_AT: u64 = REGION_AT + 0x1003;
            /// A configuration table that is not the export.
            const OTHER: Guid = Guid {
                data1: 0x8c78_a505,
                data2: 0xbaa0,
                data3: 0x4c4a,
                data4: [0x86, 0x9f, 0, 0, 0, 0, 0x17, 0x02],
            };

            /// The database that the tests export: two package lists.
            fn database() -> Vec<u8> {
                [
                    en_strings_list([1; 16], b'a'),
                    en_strings_list([2; 16], b'b'),
                ]
                .concat()
            }

            /// paths_in `dir`, with x86's files of firmware of `width` whose System Table lists
            /// `entries`, and a fake /dev/mem that holds database() and zeros at EXPORT_AT,
            /// under the lockdown mode `lockdown`.
            fn systab_paths(
                dir: &Path,
                width: FirmwareWidth,
                entries: &[(Guid, u64)],
                lockdown: &str,
            ) -> HiiSourcePaths {
                let paths = paths_in(dir);
                x86_files(
                    dir,
                    width,
                    SYSTEM_TABLE_AT,
                    ENTRIES_AT,
                    &[(
                        MemoryType::RUNTIME_SERVICES_DATA,
                        REGION_AT,
                        REGION_AT + 0x1000_0000,
                        16,
                    )],
                );
                std::fs::write(&paths.lockdown, lockdown).expect("write lockdown");
                let count = u64::try_from(entries.len()).expect("a u64 count");
                let mem = File::create(&paths.dev_mem).expect("create the fake /dev/mem");
                for (address, bytes) in [
                    (
                        SYSTEM_TABLE_AT,
                        valid_system_table(width, count, ENTRIES_AT),
                    ),
                    (ENTRIES_AT, configuration_table(width, entries)),
                    (EXPORT_AT, [database(), vec![0; 0x40]].concat()),
                ] {
                    mem.write_all_at(&bytes, address)
                        .expect("write physical memory");
                }
                paths
            }

            /// The configuration-table method reads exactly the export that the System Table
            /// lists, of firmware of either width, named and in the automatic order, where the
            /// other methods find their sources absent; identify finds it too.
            #[test]
            fn reads_the_export_that_the_system_table_lists() {
                for width in [FirmwareWidth::Bits32, FirmwareWidth::Bits64] {
                    let dir = tempfile::tempdir().expect("create a directory");
                    let entries = [
                        (OTHER, ENTRIES_AT),
                        (EFI_HII_DATABASE_PROTOCOL_GUID, EXPORT_AT),
                    ];
                    let paths = systab_paths(dir.path(), width, &entries, NO_LOCKDOWN);

                    for source in [HiiSource::Method(HiiMethod::Systab), HiiSource::Auto] {
                        let db = extract_db_from_at(&paths, &options(source))
                            .unwrap_or_else(|error| panic!("{width:?}: {source:?}: {error}"));
                        assert_eq!(db, database(), "{width:?}: {source:?}");

                        let published = hii_db_published_using_at(&paths, &options(source))
                            .unwrap_or_else(|error| panic!("{width:?}: {source:?}: {error:#}"));
                        assert!(published, "{width:?}: {source:?}: published");
                    }
                }
            }

            /// A System Table that does not list the export leaves the configuration-table
            /// method's source absent, so that no method finds the database, and identify finds
            /// none.
            #[test]
            fn finds_its_source_absent_where_the_system_table_does_not_list_it() {
                let dir = tempfile::tempdir().expect("create a directory");
                let paths = systab_paths(
                    dir.path(),
                    FirmwareWidth::Bits64,
                    &[(OTHER, EXPORT_AT)],
                    NO_LOCKDOWN,
                );

                let error = tried(&paths, HiiSource::Method(HiiMethod::Systab));
                let [(HiiMethod::Systab, systab @ HiiMethodError::Absent(_))] =
                    error.tried.as_slice()
                else {
                    panic!("{error}");
                };
                assert_eq!(
                    systab.error().downcast_ref::<HiiExportError>(),
                    Some(&HiiExportError::NotListed),
                    "{error}"
                );

                let error = tried(&paths, HiiSource::Auto);
                let methods: Vec<HiiMethod> = error
                    .tried
                    .iter()
                    .filter(|(_, error)| matches!(error, HiiMethodError::Absent(_)))
                    .map(|&(method, _)| method)
                    .collect();
                assert_eq!(methods, HiiMethod::AUTOMATIC_ORDER, "{error}");

                let published = hii_db_published_using_at(&paths, &HiiSourceOptions::default())
                    .expect("look for the database");
                assert!(!published, "published");
            }

            /// Where Linux locates no System Table, on a BIOS boot or where it gives the address
            /// 0, the configuration-table method finds its source absent without physical
            /// memory, as the other methods find theirs without their files, and identify finds
            /// no database.
            #[test]
            fn finds_its_source_absent_where_linux_locates_no_system_table() {
                for (case, signature, address, want) in [
                    (
                        "BIOS",
                        [0; 4],
                        SYSTEM_TABLE_AT,
                        SystemTableError::NotBootedByEfi { signature: [0; 4] },
                    ),
                    ("address 0", *b"EL64", 0, SystemTableError::NoSystemTable),
                ] {
                    let dir = tempfile::tempdir().expect("create a directory");
                    let paths = paths_in(dir.path());
                    std::fs::write(
                        dir.path().join("boot_params"),
                        boot_params(signature, address),
                    )
                    .expect("write boot_params");

                    let error = tried(&paths, HiiSource::Method(HiiMethod::Systab));
                    let [(HiiMethod::Systab, systab @ HiiMethodError::Absent(_))] =
                        error.tried.as_slice()
                    else {
                        panic!("{case}: {error}");
                    };
                    assert_eq!(
                        systab.error().downcast_ref::<SystemTableError>(),
                        Some(&want),
                        "{case}: {error}"
                    );

                    let error = tried(&paths, HiiSource::Auto);
                    let methods: Vec<HiiMethod> = error
                        .tried
                        .iter()
                        .filter(|(_, error)| matches!(error, HiiMethodError::Absent(_)))
                        .map(|&(method, _)| method)
                        .collect();
                    assert_eq!(methods, HiiMethod::AUTOMATIC_ORDER, "{case}: {error}");

                    for source in [HiiSource::Method(HiiMethod::Systab), HiiSource::Auto] {
                        let published = hii_db_published_using_at(&paths, &options(source))
                            .unwrap_or_else(|error| panic!("{case}: {source:?}: {error:#}"));
                        assert!(!published, "{case}: {source:?}: published");
                    }
                }
            }

            /// Where arm64's FDT has no linux,uefi-system-table in /chosen and no /hypervisor/uefi
            /// that holds xen,uefi-system-table, the configuration-table method finds its source
            /// absent, as Linux finds no UEFI, and identify finds no database; where its
            /// /hypervisor/uefi holds Xen's xen,uefi-system-table, which uefisettings does not
            /// support, it fails, and identify cannot tell.
            #[test]
            fn finds_its_source_absent_where_the_fdt_gives_no_uefi() {
                for (case, fdt, want) in [
                    ("no UEFI", no_uefi_fdt(), SystemTableError::NoUefiInFdt),
                    ("Xen", xen_uefi_fdt(), SystemTableError::XenUefiInFdt),
                ] {
                    let dir = tempfile::tempdir().expect("create a directory");
                    let fdt_path = dir.path().join("fdt");
                    std::fs::write(&fdt_path, fdt).expect("write the FDT");
                    let paths = HiiSourcePaths {
                        system_table: SystemTableLocator::Fdt {
                            fdt: fdt_path,
                            fw_platform_size: dir.path().join("fw_platform_size"),
                        },
                        ..paths_in(dir.path())
                    };
                    let absent = want == SystemTableError::NoUefiInFdt;

                    let error = tried(&paths, HiiSource::Method(HiiMethod::Systab));
                    let [(HiiMethod::Systab, systab)] = error.tried.as_slice() else {
                        panic!("{case}: {error}");
                    };
                    match absent {
                        true => assert!(matches!(systab, HiiMethodError::Absent(_)), "{error}"),
                        false => assert!(matches!(systab, HiiMethodError::Failed(_)), "{error}"),
                    }
                    assert_eq!(
                        systab.error().downcast_ref::<SystemTableError>(),
                        Some(&want),
                        "{case}: {error}"
                    );

                    let published = hii_db_published_using_at(
                        &paths,
                        &options(HiiSource::Method(HiiMethod::Systab)),
                    );
                    assert_eq!(published.ok(), absent.then_some(false), "{case}: published");
                }
            }

            /// Under lockdown, the configuration-table method is refused before /dev/mem, and
            /// identify cannot tell whether the firmware publishes the export.
            #[test]
            fn is_refused_under_lockdown() {
                let dir = tempfile::tempdir().expect("create a directory");
                let entries = [(EFI_HII_DATABASE_PROTOCOL_GUID, EXPORT_AT)];
                let paths = systab_paths(dir.path(), FirmwareWidth::Bits64, &entries, INTEGRITY);

                let error = tried(&paths, HiiSource::Method(HiiMethod::Systab));

                let [(HiiMethod::Systab, systab)] = error.tried.as_slice() else {
                    panic!("{error}");
                };
                assert!(refused_by_integrity(systab), "{error}");

                for source in [HiiSource::Method(HiiMethod::Systab), HiiSource::Auto] {
                    let error = hii_db_published_using_at(&paths, &options(source))
                        .expect_err("look for the export under lockdown");
                    assert!(denied_by_integrity(&error), "{source:?}: {error:#}");
                }
            }

            /// The probe answers false where the configuration-table method finds its source
            /// absent, and fails with the method's error where its source exists but holds no
            /// export that it reads.
            #[test]
            fn probe_answers_false_where_the_source_is_absent() {
                for (case, error, want) in [
                    (
                        "not listed",
                        anyhow::Error::new(HiiExportError::NotListed),
                        Some(false),
                    ),
                    (
                        "BIOS",
                        SystemTableError::NotBootedByEfi { signature: [0; 4] }.into(),
                        Some(false),
                    ),
                    (
                        "address 0",
                        SystemTableError::NoSystemTable.into(),
                        Some(false),
                    ),
                    (
                        "no UEFI in the FDT",
                        SystemTableError::NoUefiInFdt.into(),
                        Some(false),
                    ),
                    ("Xen", SystemTableError::XenUefiInFdt.into(), None),
                    ("empty", HiiExportError::Empty.into(), None),
                    (
                        "a short PackageLength",
                        HiiExportError::PackageLengthShort {
                            offset: 0,
                            length: 19,
                        }
                        .into(),
                        None,
                    ),
                    (
                        "past the region",
                        HiiExportError::PastRegion {
                            offset: 0,
                            length: 25,
                            room: 24,
                        }
                        .into(),
                        None,
                    ),
                    (
                        "unterminated",
                        HiiExportError::Unterminated {
                            offset: 0,
                            length: 28,
                            at: 20,
                        }
                        .into(),
                        None,
                    ),
                    (
                        "too large",
                        HiiExportError::TooLarge {
                            length: MAX_ALLOWED_FILESIZE + 1,
                        }
                        .into(),
                        None,
                    ),
                    (
                        "another signature",
                        SystemTableError::Signature {
                            address: SYSTEM_TABLE_AT,
                            signature: 0,
                        }
                        .into(),
                        None,
                    ),
                ] {
                    assert_eq!(systab_probe_answer(Err(error)).ok(), want, "{case}");
                }
            }

            /// The automatic order moves past a vendor ACPI table that fails its checks and a
            /// HiiDB variable of an implausible length to the configuration table.
            #[test]
            fn auto_moves_past_invalid_sources() {
                let dir = tempfile::tempdir().expect("create a directory");
                let entries = [(EFI_HII_DATABASE_PROTOCOL_GUID, EXPORT_AT)];
                let paths = systab_paths(dir.path(), FirmwareWidth::Bits64, &entries, NO_LOCKDOWN);
                std::fs::write(paths.acpi_tables.join("QHII"), b"no ACPI table")
                    .expect("write QHII");
                write_efivar(&paths.ocp_hiidb, EXPORT_AT, 0);

                let db = extract_db_from_at(&paths, &HiiSourceOptions::default())
                    .unwrap_or_else(|error| panic!("{error}"));

                assert_eq!(db, database());
            }
        }
    }
}
