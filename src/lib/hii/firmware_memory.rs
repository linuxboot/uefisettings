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

//! The firmware memory maps that bound the efivar source's reads of physical
//! memory, from what Linux exports on x86 and arm64, and the reads that they bound
//! (runtime_memory). On other architectures, MemoryMapUnavailable::NoMapReader refuses them.

#[cfg(any(firmware_memory_maps, test))]
use std::fs;
#[cfg(any(target_arch = "aarch64", test))]
use std::fs::File;
#[cfg(any(firmware_memory_maps, test))]
use std::path::Path;
use std::path::PathBuf;

#[cfg(any(target_arch = "aarch64", test))]
use anyhow::bail;
#[cfg(any(firmware_memory_maps, test))]
use anyhow::Context;
#[cfg(any(firmware_memory_maps, test))]
use anyhow::Result;
use thiserror::Error;

#[cfg(any(firmware_memory_maps, test))]
use efi_memory_map::EfiMemoryMap;
#[cfg(any(firmware_memory_maps, test))]
use efi_memory_map::MemoryDescriptor;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
use efi_memory_map::MemoryType;
#[cfg(any(target_arch = "aarch64", test))]
use fdt_params::UefiFdtParams;
#[cfg(firmware_memory_maps)]
use firmware_reserved::FirmwareReservedMap;
#[cfg(any(target_arch = "aarch64", test))]
use kcore::read_kcore;
#[cfg(target_arch = "aarch64")]
use kcore::KCORE_PATH;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
use physical_range::PhysicalRange;

#[cfg(any(firmware_memory_maps, test))]
pub(super) mod efi_memory_map;
#[cfg(any(target_arch = "aarch64", test))]
pub(super) mod fdt_params;
#[cfg(any(firmware_memory_maps, test))]
pub(super) mod firmware_reserved;
#[cfg(any(target_arch = "aarch64", test))]
pub(super) mod kcore;
#[cfg(any(firmware_memory_maps, test))]
mod physical_range;
#[cfg(any(firmware_memory_maps, test))]
pub(super) mod runtime_memory;

/// The upper bound of the memory map that the arm64 source reads.
#[cfg(any(target_arch = "aarch64", test))]
pub(in crate::hii) const MAX_MEMORY_MAP_SIZE: usize = 1 << 20;

/// The descriptors of the EFI memory map that x86 Linux maps for runtime services, a directory
/// each, with CONFIG_EFI_RUNTIME_MAP only (arch/x86/platform/efi/runtime-map.c).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const RUNTIME_MAP_PATH: &str = "/sys/firmware/efi/runtime-map";

/// The firmware memory map that x86 Linux exports, a directory per entry, with
/// CONFIG_FIRMWARE_MEMMAP only (drivers/firmware/memmap.c): the E820 table of the firmware, or
/// of the EFI stub, which converts the EFI memory map (drivers/firmware/efi/libstub/x86-stub.c
/// setup_e820()), before the kernel changes its own copy.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const FIRMWARE_MEMMAP_PATH: &str = "/sys/firmware/memmap";

/// The types of the firmware memmap entries that firmware reserves (arch/x86/kernel/e820.c
/// e820_type_to_string()): E820 reserved, which the x86 EFI stub gives EfiReservedMemoryType,
/// runtime services code and data, memory-mapped I/O and PAL code, and ACPI NVS.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
const FIRMWARE_RESERVED_E820_TYPES: [&str; 2] = ["Reserved", "ACPI Non-volatile Storage"];

/// The FDT that the kernel got from arm64's EFI stub (drivers/of/fdt.c of_fdt_raw_init()).
#[cfg(target_arch = "aarch64")]
pub(in crate::hii) const FDT_PATH: &str = "/sys/firmware/fdt";

/// The `N` bytes at `offset` of `bytes`, if it holds them.
#[cfg(any(target_arch = "aarch64", test))]
pub(in crate::hii) fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..)?.first_chunk().copied()
}

/// The little-endian u64 at `offset` of `bytes`.
#[cfg(any(target_arch = "aarch64", test))]
pub(in crate::hii) fn le_u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    array_at(bytes, offset)
        .map(u64::from_le_bytes)
        .with_context(|| format!("no 8 bytes at offset {offset} of {} bytes", bytes.len()))
}

/// Why a source reads no physical memory at all, besides a kernel lockdown (MemoryAccessDenied)
/// or an unknown lockdown mode (LockdownUnknown): no firmware memory map bounds its reads.
#[derive(Debug, Error, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MemoryMapUnavailable {
    /// x86 has no runtime-map, which lists the EFI runtime regions.
    #[error(
        "{} does not exist, so no EFI runtime region bounds the reads of firmware memory",
        .0.display()
    )]
    NoRuntimeMap(PathBuf),
    /// x86 has no firmware memory map, which lists the firmware-reserved regions.
    #[error(
        "{} does not exist, so no firmware-reserved region bounds the reads of firmware memory",
        .0.display()
    )]
    NoFirmwareMemmap(PathBuf),
    /// arm64 has no FDT from the EFI stub, which locates the EFI memory map.
    #[error(
        "{} does not exist, so no EFI memory map bounds the reads of firmware memory",
        .0.display()
    )]
    NoFdt(PathBuf),
    /// arm64 has no /proc/kcore (CONFIG_PROC_KCORE), which serves the EFI memory map.
    #[error(
        "{} does not exist, so no EFI memory map bounds the reads of firmware memory",
        .0.display()
    )]
    NoKcore(PathBuf),
    /// uefisettings reads no firmware memory map on this architecture.
    #[error(
        "uefisettings reads no firmware memory map on {}, so nothing bounds the reads of firmware \
         memory",
        std::env::consts::ARCH
    )]
    NoMapReader,
}

/// The number in the sysfs attribute `path`, which the kernel prints as "0x%lx\n" or
/// "0x%llx\n".
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
pub(in crate::hii) fn read_sysfs_hex(path: &Path) -> Result<u64> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let digits = contents
        .strip_prefix("0x")
        .and_then(|number| number.strip_suffix('\n'))
        .with_context(|| {
            format!(
                "{} holds {contents:?}, not 0x, a number and a newline",
                path.display()
            )
        })?;
    // from_str_radix takes a leading '+', which the kernel never prints.
    let hex = Some(digits)
        .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .with_context(|| format!("{} holds {contents:?}, not a hex number", path.display()))?;
    u64::from_str_radix(hex, 16)
        .with_context(|| format!("{} holds {contents:?}, not a hex number", path.display()))
}

/// The runtime descriptors of the EFI memory map that x86 Linux exports at `dir`
/// (RUNTIME_MAP_PATH), in directory order. Without
/// `dir`, a refusal: nothing else bounds the reads of firmware memory.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
pub(in crate::hii) fn read_runtime_map(dir: &Path) -> Result<EfiMemoryMap> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(MemoryMapUnavailable::NoRuntimeMap(dir.to_owned()).into())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to read {}", dir.display()))
        }
    };
    let descriptors = entries
        .map(|entry| {
            let entry = entry
                .with_context(|| format!("Failed to read {}", dir.display()))?
                .path();
            Ok(MemoryDescriptor {
                memory_type: MemoryType(u32::try_from(read_sysfs_hex(&entry.join("type"))?)?),
                physical_start: read_sysfs_hex(&entry.join("phys_addr"))?,
                virtual_start: read_sysfs_hex(&entry.join("virt_addr"))?,
                pages: read_sysfs_hex(&entry.join("num_pages"))?,
                attribute: read_sysfs_hex(&entry.join("attribute"))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    EfiMemoryMap::new(descriptors).with_context(|| format!("Failed to read {}", dir.display()))
}

/// The firmware-reserved regions of the firmware memory map that x86 Linux exports at `dir`
/// (FIRMWARE_MEMMAP_PATH): its entries of FIRMWARE_RESERVED_E820_TYPES, whose end the kernel
/// prints inclusive (drivers/firmware/memmap.c firmware_map_add_entry()). Without `dir`, a
/// refusal.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
fn read_firmware_memmap(dir: &Path) -> Result<Vec<PhysicalRange>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(MemoryMapUnavailable::NoFirmwareMemmap(dir.to_owned()).into())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to read {}", dir.display()))
        }
    };
    let mut reserved = Vec::new();
    for entry in entries {
        let entry = entry
            .with_context(|| format!("Failed to read {}", dir.display()))?
            .path();
        let type_path = entry.join("type");
        let contents = fs::read_to_string(&type_path)
            .with_context(|| format!("Failed to read {}", type_path.display()))?;
        let memory_type = contents.strip_suffix('\n').with_context(|| {
            format!(
                "{} holds {contents:?}, not a type and a newline",
                type_path.display()
            )
        })?;
        if !FIRMWARE_RESERVED_E820_TYPES.contains(&memory_type) {
            continue;
        }
        let start = read_sysfs_hex(&entry.join("start"))?;
        let end = read_sysfs_hex(&entry.join("end"))?;
        reserved.push(PhysicalRange::from_inclusive(start, end).with_context(|| {
            format!(
                "{} ends at {end:#x}, before its start {start:#x} or at the end of memory",
                entry.display()
            )
        })?);
    }
    Ok(reserved)
}

/// The files of this machine's firmware memory maps, as its architecture's Linux exports them;
/// Default is this machine's.
#[cfg(firmware_memory_maps)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::hii) enum MemoryMapFiles {
    /// x86's runtime-map (read_runtime_map) and firmware memory map (read_firmware_memmap).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
    Sysfs {
        runtime_map: PathBuf,
        firmware_memmap: PathBuf,
    },
    /// arm64's FDT, whose EFI memory map /proc/kcore serves (read_fdt_memory_map).
    #[cfg(any(target_arch = "aarch64", test))]
    Fdt { fdt: PathBuf, kcore: PathBuf },
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Default for MemoryMapFiles {
    fn default() -> Self {
        Self::Sysfs {
            runtime_map: PathBuf::from(RUNTIME_MAP_PATH),
            firmware_memmap: PathBuf::from(FIRMWARE_MEMMAP_PATH),
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Default for MemoryMapFiles {
    fn default() -> Self {
        Self::Fdt {
            fdt: PathBuf::from(FDT_PATH),
            kcore: PathBuf::from(KCORE_PATH),
        }
    }
}

#[cfg(firmware_memory_maps)]
impl MemoryMapFiles {
    /// The runtime descriptors of the EFI memory map, which bound EfivarMemory::Runtime, read
    /// with the lockdown file `lockdown` after the caller's refuse_locked_down.
    pub(in crate::hii) fn runtime_bound(
        &self,
        #[cfg_attr(
            not(any(target_arch = "aarch64", test)),
            allow(unused_variables, reason = "only arm64's /proc/kcore takes it")
        )]
        lockdown: &Path,
    ) -> Result<EfiMemoryMap> {
        match self {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
            Self::Sysfs { runtime_map, .. } => read_runtime_map(runtime_map),
            #[cfg(any(target_arch = "aarch64", test))]
            Self::Fdt { fdt, kcore } => {
                EfiMemoryMap::new(read_fdt_memory_map(fdt, kcore, lockdown)?.descriptors)
                    .context("Failed to parse the EFI memory map")
            }
        }
    }

    /// The firmware-reserved regions of the firmware memory map, which bound
    /// EfivarMemory::FirmwareReserved, read as runtime_bound reads.
    pub(in crate::hii) fn firmware_reserved_bound(
        &self,
        #[cfg_attr(
            not(any(target_arch = "aarch64", test)),
            allow(unused_variables, reason = "only arm64's /proc/kcore takes it")
        )]
        lockdown: &Path,
    ) -> Result<FirmwareReservedMap> {
        match self {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
            Self::Sysfs {
                runtime_map,
                firmware_memmap,
            } => Ok(FirmwareReservedMap::new(
                read_firmware_memmap(firmware_memmap)?,
                read_runtime_map(runtime_map)?,
            )),
            #[cfg(any(target_arch = "aarch64", test))]
            Self::Fdt { fdt, kcore } => FirmwareReservedMap::from_efi_descriptors(
                read_fdt_memory_map(fdt, kcore, lockdown)?.descriptors,
            )
            .context("Failed to parse the EFI memory map"),
        }
    }
}

/// The EFI memory map that arm64's EFI stub passes in the FDT.
#[cfg(any(target_arch = "aarch64", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::hii) struct FdtMemoryMap {
    /// The descriptors of the EFI memory map
    pub(in crate::hii) descriptors: Vec<MemoryDescriptor>,
}

/// The EFI memory map whose address the FDT at `fdt` gives (fdt_params), read from /proc/kcore at
/// `kcore`, with the lockdown file `lockdown` (read_kcore), after the caller's
/// refuse_locked_down. A missing FDT or /proc/kcore is MemoryMapUnavailable.
#[cfg(any(target_arch = "aarch64", test))]
pub(in crate::hii) fn read_fdt_memory_map(
    fdt: &Path,
    kcore: &Path,
    lockdown: &Path,
) -> Result<FdtMemoryMap> {
    let fdt_bytes = match fs::read(fdt) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(MemoryMapUnavailable::NoFdt(fdt.to_owned()).into())
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to read {}", fdt.display()))
        }
    };
    let params = UefiFdtParams::parse(&fdt_bytes)
        .with_context(|| format!("Failed to parse {}", fdt.display()))?;
    if params.mmap_size > MAX_MEMORY_MAP_SIZE {
        bail!(
            "Implausible EFI memory map size {} in {}",
            params.mmap_size,
            fdt.display()
        );
    }
    let descriptors = MemoryDescriptor::parse_map(
        &read_kcore(
            kcore,
            lockdown,
            |path| File::open(path),
            params.mmap_start,
            params.mmap_size,
        )?,
        params.mmap_desc_size,
        params.mmap_desc_ver,
    )
    .context("Failed to parse the EFI memory map")?;
    Ok(FdtMemoryMap { descriptors })
}

/// Firmware memory map files for the tests.
#[cfg(test)]
pub(in crate::hii) mod fixture {
    use std::fs;
    use std::path::Path;

    /// A firmware memory map at `dir` with an entry of each start, end and type of `entries`,
    /// as drivers/firmware/memmap.c prints them.
    pub(in crate::hii) fn write_firmware_memmap(dir: &Path, entries: &[[&str; 3]]) {
        for (index, attributes) in entries.iter().enumerate() {
            let entry_dir = dir.join(index.to_string());
            fs::create_dir_all(&entry_dir).expect("create a firmware memmap entry");
            for (name, contents) in ["start", "end", "type"].iter().zip(attributes) {
                fs::write(entry_dir.join(name), contents)
                    .expect("write a firmware memmap attribute");
            }
        }
    }

    /// A runtime-map at `dir` with an entry of each type, phys_addr, virt_addr, num_pages and
    /// attribute of `entries`, as arch/x86/platform/efi/runtime-map.c prints them.
    pub(in crate::hii) fn write_runtime_map(dir: &Path, entries: &[[&str; 5]]) {
        for (index, attributes) in entries.iter().enumerate() {
            let entry_dir = dir.join(index.to_string());
            fs::create_dir_all(&entry_dir).expect("create a runtime-map entry");
            for (name, contents) in ["type", "phys_addr", "virt_addr", "num_pages", "attribute"]
                .iter()
                .zip(attributes)
            {
                fs::write(entry_dir.join(name), contents).expect("write a runtime-map attribute");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::efi_memory_map::fixture::descriptor;
    use super::fdt_params::fixture::uefi_fdt;
    use super::fixture::write_firmware_memmap;
    use super::fixture::write_runtime_map;
    use super::kcore::fixture::kcore_fixture;
    use super::runtime_memory::DevMem;
    use super::*;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::hii::memory_access_denied::fixture::unreadable_file;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryAccessDenied;
    use crate::hii::memory_access_denied::MemoryDevice;
    use crate::hii::memory_access_denied::MemoryOperation;
    use efi_memory_map::RangeRefusal;

    #[test]
    fn array_at_and_le_u64_at_read_only_what_bytes_hold() {
        let bytes: Vec<u8> = (1..=10).collect();
        assert_eq!(array_at::<2>(&bytes, 8), Some([9, 10]), "the last 2 bytes");
        assert_eq!(array_at::<2>(&bytes, 9), None, "1 byte left");
        assert_eq!(array_at::<1>(&bytes, 11), None, "past the end");
        assert_eq!(
            le_u64_at(&bytes, 2).expect("read 8 bytes"),
            0x0a09_0807_0605_0403,
            "8 bytes at 2"
        );
        let error = le_u64_at(&bytes, 3).expect_err("read past the end");
        assert_eq!(error.to_string(), "no 8 bytes at offset 3 of 10 bytes");
    }

    /// A refused open of /proc/kcore or of /dev/mem is a refusal: EACCES from a file without
    /// read permission, unless this process overrides the permission.
    #[test]
    fn a_refused_open_is_a_refusal() {
        let dir = tempfile::tempdir().expect("create a directory");
        let Some(unreadable) = unreadable_file(dir.path()) else {
            return;
        };
        // read only for EPERM
        let lockdown = dir.path().join("lockdown");
        let want = |device| MemoryAccessDenied {
            device,
            operation: MemoryOperation::Open,
            cause: DenialCause::Permission,
        };

        let error = read_kcore(&unreadable, &lockdown, |path| File::open(path), 0, 1)
            .expect_err("open /proc/kcore");
        assert_eq!(
            error.downcast_ref::<MemoryAccessDenied>(),
            Some(&want(MemoryDevice::Kcore)),
            "/proc/kcore: {error:#}"
        );

        let error = DevMem::open(&unreadable, &lockdown).expect_err("open /dev/mem");
        assert_eq!(
            error.downcast_ref::<MemoryAccessDenied>(),
            Some(&want(MemoryDevice::DevMem)),
            "/dev/mem: {error:#}"
        );
    }

    /// arm64's map is MemoryMapUnavailable only where its FDT or /proc/kcore is missing; an FDT
    /// that cannot be read otherwise stays an error.
    #[test]
    fn read_fdt_memory_map_refuses_a_missing_fdt_or_kcore_as_no_map() {
        const MMAP_AT: u64 = 0x4000_0000;
        let dir = tempfile::tempdir().expect("create a directory");
        let lockdown = lockdown_file(dir.path(), "none");
        let (fdt, kcore) = (dir.path().join("fdt"), dir.path().join("kcore"));
        let map = descriptor(48, MemoryType(7), 0x4000_0000, 0, 0x100, 0xf);
        let params = UefiFdtParams {
            mmap_start: MMAP_AT,
            mmap_size: map.len(),
            mmap_desc_size: 48,
            mmap_desc_ver: 1,
        };

        let error = read_fdt_memory_map(&fdt, &kcore, &lockdown).expect_err("read no FDT");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            Some(&MemoryMapUnavailable::NoFdt(fdt.clone())),
            "no FDT: {error:#}"
        );

        // read() of a directory fails with EISDIR
        fs::create_dir(&fdt).expect("create a directory as the FDT");
        let error = read_fdt_memory_map(&fdt, &kcore, &lockdown).expect_err("read a directory");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            None,
            "an unreadable FDT: {error:#}"
        );
        assert!(
            format!("{error:#}").starts_with(&format!("Failed to read {}: ", fdt.display())),
            "an unreadable FDT: {error:#}"
        );
        fs::remove_dir(&fdt).expect("remove the directory");

        fs::write(&fdt, uefi_fdt(&params)).expect("write the FDT");
        let error = read_fdt_memory_map(&fdt, &kcore, &lockdown).expect_err("read no kcore");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            Some(&MemoryMapUnavailable::NoKcore(kcore.clone())),
            "no /proc/kcore: {error:#}"
        );

        kcore_fixture(&kcore, &[(MMAP_AT, &map)]);
        let got = read_fdt_memory_map(&fdt, &kcore, &lockdown).expect("read the map");
        assert_eq!(got.descriptors.len(), 1, "both files");
    }

    /// An address that x86 Linux prints in a runtime-map entry's phys_addr, such as 0x7f9e_8018,
    /// but not "7f9e8018", "0x7f9e8018" without a newline, a sign, or no hex number.
    #[test]
    fn read_sysfs_hex_reads_what_the_kernel_prints() {
        let dir = tempfile::tempdir().expect("create a sysfs directory");
        let path = dir.path().join("phys_addr");
        for (contents, want) in [
            ("0x7f9e8018\n", Some(0x7f9e_8018)),
            ("0x0\n", Some(0)),
            ("7f9e8018\n", None),
            ("0x7f9e8018", None),
            ("0x+7f\n", None),
            ("0xzz\n", None),
            ("0x\n", None),
        ] {
            fs::write(&path, contents).expect("write phys_addr");
            match (read_sysfs_hex(&path), want) {
                (Ok(value), Some(want)) => assert_eq!(value, want, "{contents:?}"),
                (Err(error), None) => assert!(
                    format!("{error:#}").contains("phys_addr holds"),
                    "{contents:?}: {error:#}"
                ),
                (got, want) => panic!("{contents:?}: got {got:?}, want {want:?}"),
            }
        }
        fs::remove_file(&path).expect("remove phys_addr");
        let error = read_sysfs_hex(&path).expect_err("read a missing phys_addr");
        assert!(
            format!("{error:#}").starts_with("Failed to read"),
            "no file: {error:#}"
        );
    }

    /// read_sysfs_hex gives from_str_radix's error as the cause of no number or one past u64.
    #[test]
    fn read_sysfs_hex_keeps_the_cause_of_a_number_that_does_not_parse() {
        use std::num::IntErrorKind;
        use std::num::ParseIntError;

        let dir = tempfile::tempdir().expect("create a sysfs directory");
        let path = dir.path().join("phys_addr");
        for (contents, want) in [
            ("0x\n", IntErrorKind::Empty),
            ("0x10000000000000000\n", IntErrorKind::PosOverflow),
        ] {
            fs::write(&path, contents).expect("write phys_addr");
            let error = read_sysfs_hex(&path).expect_err(contents);
            assert_eq!(
                error
                    .root_cause()
                    .downcast_ref::<ParseIntError>()
                    .map(ParseIntError::kind),
                Some(&want),
                "{contents:?}: {error:#}"
            );
        }
    }

    /// As on OVMF: runtime data that holds the database, and boot services data that the
    /// kernel maps too, but that is not runtime.
    const RUNTIME_DATA: [&str; 5] = [
        "0x6\n",
        "0x7f000000\n",
        "0xfffffffeff000000\n",
        "0x2\n",
        "0x800000000000000f\n",
    ];
    const BOOT_SERVICES_DATA: [&str; 5] = ["0x4\n", "0x100000\n", "0x100000\n", "0x10\n", "0xf\n"];
    /// A runtime descriptor of memory-mapped I/O.
    const RUNTIME_MMIO: [&str; 5] = [
        "0xb\n",
        "0xfeb00000\n",
        "0xfffffffeff400000\n",
        "0x1\n",
        "0x8000000000000001\n",
    ];

    #[test]
    fn read_runtime_map_reads_the_runtime_descriptors() {
        let dir = tempfile::tempdir().expect("create a sysfs directory");
        write_runtime_map(
            dir.path(),
            &[BOOT_SERVICES_DATA, RUNTIME_DATA, RUNTIME_MMIO],
        );

        let map = read_runtime_map(dir.path()).expect("read the runtime map");

        assert_eq!(
            map.runtime_range_end(0x7f00_1000, 20)
                .expect("runtime data"),
            0x7f00_2000
        );
        let error = map
            .runtime_range_end(0x10_0000, 20)
            .expect_err("hold boot services data");
        assert_eq!(
            error.downcast_ref::<RangeRefusal>(),
            Some(&RangeRefusal::NotRuntime {
                address: 0x10_0000,
                length: 20,
            }),
            "boot services data: {error:#}"
        );
        let error = map
            .runtime_range_end(0xfeb0_0010, 20)
            .expect_err("hold memory-mapped I/O");
        assert_eq!(
            error.downcast_ref::<RangeRefusal>(),
            Some(&RangeRefusal::MemoryMappedIo {
                address: 0xfeb0_0010,
                length: 20,
                memory_type: MemoryType::MEMORY_MAPPED_IO,
            }),
            "memory-mapped I/O: {error:#}"
        );
    }

    /// Without CONFIG_EFI_RUNTIME_MAP, nothing would bound the reads, so the source refuses.
    #[test]
    fn read_runtime_map_refuses_a_missing_map() {
        let dir = tempfile::tempdir().expect("create a sysfs directory");
        let missing = dir.path().join("runtime-map");

        let error = read_runtime_map(&missing).expect_err("read a missing runtime map");

        assert!(
            matches!(
                error.downcast_ref::<MemoryMapUnavailable>(),
                Some(MemoryMapUnavailable::NoRuntimeMap(got)) if *got == missing
            ),
            "{error:#}"
        );
    }

    /// A firmware memory map or runtime-map that exists but cannot be read stays an error, not
    /// MemoryMapUnavailable.
    #[test]
    fn unreadable_maps_are_not_missing_maps() {
        let dir = tempfile::tempdir().expect("create a directory");
        // read_dir() of a regular file fails with ENOTDIR
        let file = dir.path().join("file");
        fs::write(&file, b"").expect("create a file");
        for (case, error) in [
            (
                "memmap",
                read_firmware_memmap(&file).expect_err("read a file as the memmap"),
            ),
            (
                "runtime-map",
                read_runtime_map(&file).expect_err("read a file as the runtime-map"),
            ),
        ] {
            assert_eq!(
                error.downcast_ref::<MemoryMapUnavailable>(),
                None,
                "{case}: {error:#}"
            );
            assert!(
                format!("{error:#}").starts_with(&format!("Failed to read {}: ", file.display())),
                "{case}: {error:#}"
            );
        }
    }

    /// An entry that does not parse fails the map even next to good ones, as does a map with
    /// no runtime descriptors.
    #[test]
    fn read_runtime_map_fails_on_a_bad_map() {
        let bad_num_pages = [
            RUNTIME_DATA[0],
            RUNTIME_DATA[1],
            RUNTIME_DATA[2],
            "0x2z\n",
            RUNTIME_DATA[4],
        ];
        let wide_type = [
            "0x100000000\n",
            RUNTIME_DATA[1],
            RUNTIME_DATA[2],
            RUNTIME_DATA[3],
            RUNTIME_DATA[4],
        ];
        for (case, entries, message) in [
            (
                "bad num_pages",
                vec![RUNTIME_DATA, bad_num_pages],
                "num_pages holds \"0x2z\\n\", not a hex number",
            ),
            (
                "a type wider than 32 bits",
                vec![RUNTIME_DATA, wide_type],
                "out of range integral type conversion attempted",
            ),
            (
                "no runtime descriptors",
                vec![BOOT_SERVICES_DATA],
                "the EFI memory map has no runtime descriptors",
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a sysfs directory");
            write_runtime_map(dir.path(), &entries);

            let error = read_runtime_map(dir.path()).expect_err("read a bad runtime map");

            assert!(format!("{error:#}").contains(message), "{case}: {error:#}");
        }
    }

    /// Only the entries of type Reserved and ACPI Non-volatile Storage are firmware-reserved,
    /// each with its inclusive end, as drivers/firmware/memmap.c prints them.
    #[test]
    fn read_firmware_memmap_reads_the_reserved_entries() {
        let dir = tempfile::tempdir().expect("create a sysfs directory");
        write_firmware_memmap(
            dir.path(),
            &[
                ["0x0\n", "0x9fbff\n", "System RAM\n"],
                ["0x9fc00\n", "0x9ffff\n", "Reserved\n"],
                ["0x7f000000\n", "0x7f001fff\n", "ACPI Tables\n"],
                [
                    "0x7f002000\n",
                    "0x7f005fff\n",
                    "ACPI Non-volatile Storage\n",
                ],
                ["0x7f006000\n", "0x7f006fff\n", "Unusable memory\n"],
                ["0x7f007000\n", "0x7f007fff\n", "Soft Reserved\n"],
            ],
        );

        let mut got: Vec<(u64, u64)> = read_firmware_memmap(dir.path())
            .expect("read the firmware memory map")
            .into_iter()
            .map(|range| (range.start(), range.end()))
            .collect();

        got.sort_unstable();
        assert_eq!(got, [(0x9_fc00, 0xa_0000), (0x7f00_2000, 0x7f00_6000)]);
    }

    /// Without CONFIG_FIRMWARE_MEMMAP, no firmware-reserved region is known, so the source
    /// refuses; an entry that does not parse fails the map.
    #[test]
    fn read_firmware_memmap_refuses_a_missing_or_bad_map() {
        let dir = tempfile::tempdir().expect("create a sysfs directory");
        let missing = dir.path().join("memmap");
        let error = read_firmware_memmap(&missing).expect_err("read a missing map");
        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            Some(&MemoryMapUnavailable::NoFirmwareMemmap(missing)),
            "{error:#}"
        );

        for (case, entry, want) in [
            (
                "a type without a newline",
                ["0x1000\n", "0x1fff\n", "Reserved"],
                "type holds \"Reserved\", not a type and a newline",
            ),
            (
                "a bad start",
                ["0x1000z\n", "0x1fff\n", "Reserved\n"],
                "start holds \"0x1000z\\n\", not a hex number",
            ),
            (
                "a bad end",
                ["0x1000\n", "0x1fffz\n", "Reserved\n"],
                "end holds \"0x1fffz\\n\", not a hex number",
            ),
            (
                "an end before the start",
                ["0x2000\n", "0x1fff\n", "Reserved\n"],
                "ends at 0x1fff, before its start 0x2000 or at the end of memory",
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a sysfs directory");
            write_firmware_memmap(dir.path(), &[["0x0\n", "0xfff\n", "Reserved\n"], entry]);

            let error = read_firmware_memmap(dir.path()).expect_err(case);

            assert!(format!("{error:#}").contains(want), "{case}: {error:#}");
        }
    }

    /// The refusal of an architecture without a map reader names the architecture.
    #[test]
    fn no_map_reader_names_the_architecture() {
        assert_eq!(
            MemoryMapUnavailable::NoMapReader.to_string(),
            format!(
                "uefisettings reads no firmware memory map on {}, so nothing bounds the reads of \
                 firmware memory",
                std::env::consts::ARCH
            )
        );
    }
}
