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

//! x86 Linux's copy of the boot protocol's struct boot_params, whose efi_info locates the EFI
//! System Table and names the firmware's width, as the EFI stub fills it in (Linux v6.11
//! drivers/firmware/efi/libstub/x86-stub.c:775-780) and the kernel reads it (arch/x86/kernel/
//! setup.c:809-817, arch/x86/platform/efi/efi.c:480-481).

use std::fs;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

use super::SystemTableError;
use crate::firmware_width::FirmwareWidth;

/// "the binary representation of struct boot_params" (Linux v6.11
/// Documentation/ABI/testing/sysfs-kernel-boot_params:12), which every user may read
/// (arch/x86/kernel/ksysfs.c:38-45).
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(in crate::hii) const BOOT_PARAMS_PATH: &str = "/sys/kernel/boot_params/data";

/// The offset of efi_info in struct boot_params (Linux v6.11
/// Documentation/arch/x86/zero-page.rst:33).
const EFI_INFO_OFFSET: usize = 0x1c0;
/// efi_info's __u32 fields up to efi_systab_hi: efi_loader_signature, efi_systab,
/// efi_memdesc_size, efi_memdesc_version, efi_memmap, efi_memmap_size, efi_systab_hi
/// (arch/x86/include/uapi/asm/bootparam.h:93-102).
const EFI_INFO_READ: usize = 7 * 4;
/// The loader signatures of 32-bit and 64-bit firmware (arch/x86/include/asm/efi.h:29-30).
const EFI32_LOADER_SIGNATURE: [u8; 4] = *b"EL32";
const EFI64_LOADER_SIGNATURE: [u8; 4] = *b"EL64";

/// The EFI System Table that efi_info locates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::hii) struct EfiInfo {
    /// Its physical address: efi_systab, and efi_systab_hi above bit 31.
    pub(in crate::hii) system_table: u64,
    /// The width of the firmware, which the loader signature names.
    pub(in crate::hii) width: FirmwareWidth,
}

/// The efi_info of `boot_params`, the bytes of struct boot_params, of a Linux booted through EFI.
pub(in crate::hii) fn parse_efi_info(boot_params: &[u8]) -> Result<EfiInfo, SystemTableError> {
    let fields = boot_params
        .get(EFI_INFO_OFFSET..)
        .and_then(<[u8]>::first_chunk::<EFI_INFO_READ>)
        .ok_or(SystemTableError::BootParamsShort {
            length: boot_params.len(),
        })?;
    let [s0, s1, s2, s3, a0, a1, a2, a3, .., h0, h1, h2, h3] = *fields;
    let width = match [s0, s1, s2, s3] {
        EFI64_LOADER_SIGNATURE => FirmwareWidth::Bits64,
        EFI32_LOADER_SIGNATURE => FirmwareWidth::Bits32,
        signature => return Err(SystemTableError::NotBootedByEfi { signature }),
    };
    let system_table = u64::from(u32::from_le_bytes([a0, a1, a2, a3]))
        | u64::from(u32::from_le_bytes([h0, h1, h2, h3])) << 32;
    if system_table == 0 {
        return Err(SystemTableError::NoSystemTable);
    }
    Ok(EfiInfo {
        system_table,
        width,
    })
}

/// The efi_info of the boot_params file at `path` (BOOT_PARAMS_PATH).
pub(in crate::hii) fn read_efi_info(path: &Path) -> Result<EfiInfo> {
    let boot_params =
        fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    parse_efi_info(&boot_params)
        .with_context(|| format!("{} locates no EFI System Table", path.display()))
}

/// struct boot_params for the tests.
#[cfg(test)]
pub(in crate::hii) mod fixture {
    use super::*;

    /// The size of struct boot_params, a page (arch/x86/include/uapi/asm/bootparam.h:116-163).
    const BOOT_PARAMS_SIZE: usize = 4096;

    /// The bytes of a struct boot_params whose efi_info has `signature` and the System Table
    /// address `system_table`, and 0xa5 elsewhere.
    pub(in crate::hii) fn boot_params(signature: [u8; 4], system_table: u64) -> Vec<u8> {
        let mut bytes = vec![0xa5; BOOT_PARAMS_SIZE];
        let [l0, l1, l2, l3, h0, h1, h2, h3] = system_table.to_le_bytes();
        for (offset, field) in [
            (0, signature),
            (4, [l0, l1, l2, l3]),
            (24, [h0, h1, h2, h3]),
        ] {
            let at = EFI_INFO_OFFSET + offset;
            bytes[at..at + 4].copy_from_slice(&field);
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::boot_params;
    use super::*;

    /// "EL64" and "EL32" name 64-bit and 32-bit firmware, and the address joins efi_systab and
    /// efi_systab_hi.
    #[test]
    fn parse_efi_info_reads_the_address_and_the_width() {
        for (signature, system_table, width) in [
            (*b"EL64", 0x7f9e_8018, FirmwareWidth::Bits64),
            (*b"EL64", 0x1_7f9e_8018, FirmwareWidth::Bits64),
            (*b"EL32", 0x3f9e_8018, FirmwareWidth::Bits32),
        ] {
            assert_eq!(
                parse_efi_info(&boot_params(signature, system_table)),
                Ok(EfiInfo {
                    system_table,
                    width
                }),
                "{signature:?} {system_table:#x}"
            );
        }
    }

    /// A Linux not booted through EFI has no loader signature; its boot_params locates no
    /// System Table, and neither does one whose address is 0 or that ends before efi_info.
    #[test]
    fn parse_efi_info_refuses_what_locates_no_system_table() {
        let full = boot_params(*b"EL64", 0x7f9e_8018);
        for (case, bytes, want) in [
            (
                "no signature",
                boot_params([0; 4], 0x7f9e_8018),
                SystemTableError::NotBootedByEfi { signature: [0; 4] },
            ),
            (
                "another signature",
                boot_params(*b"EL16", 0x7f9e_8018),
                SystemTableError::NotBootedByEfi {
                    signature: *b"EL16",
                },
            ),
            (
                "address 0",
                boot_params(*b"EL32", 0),
                SystemTableError::NoSystemTable,
            ),
            (
                "short of efi_systab_hi",
                full[..EFI_INFO_OFFSET + EFI_INFO_READ - 1].to_vec(),
                SystemTableError::BootParamsShort {
                    length: EFI_INFO_OFFSET + EFI_INFO_READ - 1,
                },
            ),
        ] {
            assert_eq!(parse_efi_info(&bytes), Err(want), "{case}");
        }
        assert_eq!(
            parse_efi_info(&full[..EFI_INFO_OFFSET + EFI_INFO_READ]).map(|info| info.system_table),
            Ok(0x7f9e_8018),
            "up to efi_systab_hi"
        );
    }

    /// efi_info is at 0x1c0 of the page of struct boot_params (Linux v6.11
    /// Documentation/arch/x86/zero-page.rst:33), with efi_loader_signature at 0x1c0, efi_systab
    /// at 0x1c4 and efi_systab_hi at 0x1d8 (arch/x86/include/uapi/asm/bootparam.h:93-102),
    /// written from these offsets, not from EFI_INFO_OFFSET.
    #[test]
    fn efi_info_is_at_0x1c0() {
        let mut bytes = vec![0xa5; 4096];
        bytes[0x1c0..0x1c4].copy_from_slice(b"EL64");
        bytes[0x1c4..0x1c8].copy_from_slice(&0x7f9e_8018_u32.to_le_bytes());
        bytes[0x1d8..0x1dc].copy_from_slice(&1_u32.to_le_bytes());

        assert_eq!(
            parse_efi_info(&bytes),
            Ok(EfiInfo {
                system_table: 0x1_7f9e_8018,
                width: FirmwareWidth::Bits64
            })
        );
    }

    /// read_efi_info names the file that it cannot read, and the one that locates nothing.
    #[test]
    fn read_efi_info_names_the_file() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("data");
        let error = read_efi_info(&path).expect_err("read a missing file");
        assert!(
            format!("{error:#}").starts_with(&format!("Failed to read {}: ", path.display())),
            "missing: {error:#}"
        );

        fs::write(&path, boot_params([0; 4], 1)).expect("write boot_params");
        let error = read_efi_info(&path).expect_err("read a BIOS boot's boot_params");
        assert_eq!(
            error.downcast_ref::<SystemTableError>(),
            Some(&SystemTableError::NotBootedByEfi { signature: [0; 4] }),
            "BIOS: {error:#}"
        );
        assert!(
            format!("{error:#}")
                .starts_with(&format!("{} locates no EFI System Table: ", path.display())),
            "BIOS: {error:#}"
        );
    }
}
