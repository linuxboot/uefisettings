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

//! The width of the firmware's UINTN and pointers, which lays out its System Table, its
//! configuration table and an EFI_STATUS (edk2-stable202508 MdePkg/Include/Base.h: RETURN_STATUS
//! is a UINTN), and how a build learns it: Linux tells it in fw_platform_size, the UEFI Shell
//! build runs on firmware of its own pointer width, and the Windows build takes its own too.

#[cfg(any(target_os = "linux", test))]
use std::fs;
#[cfg(any(target_os = "linux", test))]
use std::path::Path;

#[cfg(any(target_os = "linux", test))]
use anyhow::anyhow;
#[cfg(any(target_os = "linux", test))]
use anyhow::Context;
#[cfg(any(target_os = "linux", test))]
use anyhow::Result;

/// The width of the firmware that Linux booted on, "64" or "32" and a newline (Linux v6.11
/// drivers/firmware/efi/efi.c fw_platform_size_show(), since v4.0), which every user may read. On
/// x86 the kernel takes it from the loader signature of boot_params' efi_info
/// (arch/x86/kernel/setup.c), and other architectures run firmware of their own width
/// (drivers/firmware/efi/efi-init.c efi_init()).
#[cfg(target_os = "linux")]
pub(crate) const FW_PLATFORM_SIZE_PATH: &str = "/sys/firmware/efi/fw_platform_size";

/// The width of the firmware's UINTN and pointers: 32-bit firmware's EFI_SYSTEM_TABLE and
/// EFI_CONFIGURATION_TABLE are Linux v6.7's efi_system_table_32_t and efi_config_table_32_t
/// (include/linux/efi.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    any(target_os = "uefi", target_os = "windows"),
    allow(
        dead_code,
        reason = "these builds make only the width of their own pointers"
    )
)]
pub(crate) enum FirmwareWidth {
    Bits32,
    Bits64,
}

impl FirmwareWidth {
    /// The width of this build's pointers: that of the firmware that runs the UEFI Shell build,
    /// as a UEFI image runs natively, with the firmware's calling convention (UEFI 2.11 §2.3),
    /// and that which the Windows build assumes (exports/windows.rs). A build of another pointer
    /// width has none, so it does not compile.
    #[cfg(all(
        any(target_os = "uefi", target_os = "windows"),
        target_pointer_width = "32"
    ))]
    pub(crate) const fn of_this_build() -> Self {
        Self::Bits32
    }

    /// of_this_build of a 64-bit build.
    #[cfg(all(
        any(target_os = "uefi", target_os = "windows"),
        target_pointer_width = "64"
    ))]
    pub(crate) const fn of_this_build() -> Self {
        Self::Bits64
    }

    /// The size of UINTN and of a pointer.
    pub(crate) const fn uintn_size(self) -> usize {
        match self {
            Self::Bits32 => 4,
            Self::Bits64 => 8,
        }
    }

    /// The UINTN `bytes`, little-endian, of uintn_size bytes.
    pub(crate) fn uintn(self, bytes: &[u8]) -> Option<u64> {
        match self {
            Self::Bits32 => <[u8; 4]>::try_from(bytes)
                .ok()
                .map(|bytes| u32::from_le_bytes(bytes).into()),
            Self::Bits64 => <[u8; 8]>::try_from(bytes).ok().map(u64::from_le_bytes),
        }
    }

    /// The width in bits, as fw_platform_size names it.
    pub(crate) const fn bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

/// The width that the fw_platform_size file at `path` names.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn read_fw_platform_size(path: &Path) -> Result<FirmwareWidth> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "Failed to read {}: is this Linux booted by EFI?",
            path.display()
        )
    })?;
    match text.as_str() {
        "64\n" => Ok(FirmwareWidth::Bits64),
        "32\n" => Ok(FirmwareWidth::Bits32),
        _ => Err(anyhow!(
            "{} holds {text:?}, not the 64 or 32 of a firmware width and a newline",
            path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// read_fw_platform_size takes "64" and "32", each with Linux's newline, and refuses any
    /// other text, naming the file and what it holds, and a missing file.
    #[test]
    fn read_fw_platform_size_takes_64_and_32_only() {
        let dir = tempfile::tempdir().expect("make a directory");
        let path = dir.path().join("fw_platform_size");
        for (text, want) in [
            ("64\n", Ok(FirmwareWidth::Bits64)),
            ("32\n", Ok(FirmwareWidth::Bits32)),
            ("16\n", Err("16\n")),
            ("64", Err("64")),
            ("", Err("")),
        ] {
            fs::write(&path, text).expect("write fw_platform_size");

            let got = read_fw_platform_size(&path).map_err(|error| error.to_string());

            assert_eq!(
                got,
                want.map_err(|text| format!(
                    "{} holds {text:?}, not the 64 or 32 of a firmware width and a newline",
                    path.display()
                )),
                "{text:?}"
            );
        }

        let missing = dir.path().join("missing");
        let error = read_fw_platform_size(&missing).expect_err("read a missing file");
        assert_eq!(
            error.to_string(),
            format!(
                "Failed to read {}: is this Linux booted by EFI?",
                missing.display()
            ),
            "missing"
        );
    }

    /// uintn reads uintn_size bytes little-endian and refuses any other count.
    #[test]
    fn uintn_reads_the_bytes_of_its_width() {
        let bytes = [1, 2, 3, 4, 5, 6, 7, 0x88];
        for (width, input, want) in [
            (FirmwareWidth::Bits32, &bytes[..4], Some(0x0403_0201)),
            (
                FirmwareWidth::Bits64,
                &bytes[..],
                Some(0x8807_0605_0403_0201),
            ),
            (FirmwareWidth::Bits32, &bytes[..], None),
            (FirmwareWidth::Bits64, &bytes[..4], None),
        ] {
            assert_eq!(width.uintn(input), want, "{width:?} {input:?}");
        }
    }
}
