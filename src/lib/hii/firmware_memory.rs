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
#[cfg(any(target_arch = "aarch64", test))]
use kcore::read_kcore;
#[cfg(target_arch = "aarch64")]
use kcore::KCORE_PATH;

#[cfg(any(firmware_memory_maps, test))]
pub(super) mod efi_memory_map;
#[cfg(any(target_arch = "aarch64", test))]
pub(super) mod fdt_params;
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

/// The files of this machine's firmware memory maps, as its architecture's Linux exports them;
/// Default is this machine's.
#[cfg(firmware_memory_maps)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::hii) enum MemoryMapFiles {
    /// x86's runtime-map (read_runtime_map).
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", test))]
    Sysfs { runtime_map: PathBuf },
    /// arm64's FDT, whose EFI memory map /proc/kcore serves (read_fdt_memory_map).
    #[cfg(any(target_arch = "aarch64", test))]
    Fdt { fdt: PathBuf, kcore: PathBuf },
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
impl Default for MemoryMapFiles {
    fn default() -> Self {
        Self::Sysfs {
            runtime_map: PathBuf::from(RUNTIME_MAP_PATH),
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
    /// The runtime descriptors of the EFI memory map, which bound the efivar source, read with
    /// the lockdown file `lockdown` after the caller's refuse_locked_down.
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
            Self::Sysfs { runtime_map } => read_runtime_map(runtime_map),
            #[cfg(any(target_arch = "aarch64", test))]
            Self::Fdt { fdt, kcore } => {
                EfiMemoryMap::new(read_fdt_memory_map(fdt, kcore, lockdown)?.descriptors)
                    .context("Failed to parse the EFI memory map")
            }
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
/// refuse_locked_down.
#[cfg(any(target_arch = "aarch64", test))]
pub(in crate::hii) fn read_fdt_memory_map(
    fdt: &Path,
    kcore: &Path,
    lockdown: &Path,
) -> Result<FdtMemoryMap> {
    let fdt_bytes = fs::read(fdt).with_context(|| format!("Failed to read {}", fdt.display()))?;
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
    use super::fixture::write_runtime_map;
    use super::runtime_memory::DevMem;
    use super::*;
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

    /// A runtime-map that exists but cannot be read stays an error, not MemoryMapUnavailable.
    #[test]
    fn unreadable_maps_are_not_missing_maps() {
        let dir = tempfile::tempdir().expect("create a directory");
        // read_dir() of a regular file fails with ENOTDIR
        let file = dir.path().join("file");
        fs::write(&file, b"").expect("create a file");

        let error = read_runtime_map(&file).expect_err("read a file as the runtime-map");

        assert_eq!(
            error.downcast_ref::<MemoryMapUnavailable>(),
            None,
            "{error:#}"
        );
        assert!(
            format!("{error:#}").starts_with(&format!("Failed to read {}: ", file.display())),
            "{error:#}"
        );
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
