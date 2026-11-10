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

//! The scenario hii-acpi-nvs, on x86_64 and i686, where a test checks the kernel's refusal of the
//! copy itself, through read() and mmap() of `/dev/mem`: `publish-hiidb.efi acpi-nvs` copies the
//! HII database into ACPI NVS memory, which firmware reserves without the RUNTIME attribute and
//! x86 Linux marks busy, so that `/dev/mem` refuses it under CONFIG_IO_STRICT_DEVMEM, and points
//! the `HiiDB` variable at the copy. With `--efivar-memory firmware-reserved`, which admits ACPI
//! NVS, the `HiiDB` variable method reads `/dev/mem` and reports the kernel's refusal, not an
//! absent database, and the automatic order stops there.

use uefisettings_qemu_guest::extract_db_error;
use uefisettings_qemu_guest::map_dev_mem_byte;
use uefisettings_qemu_guest::published_database;
use uefisettings_qemu_guest::read_dev_mem_byte;
use uefisettings_qemu_guest::EFAULT;
use uefisettings_qemu_guest::EPERM;

/// What the kernel's refusal of the read looks like (`src/lib/hii/memory_access_denied.rs`
/// DenialCause::StrictDevmem).
const STRICT_DEVMEM: &str = "CONFIG_STRICT_DEVMEM or a security module refuses the range";

/// This kernel refuses to map the copy from `/dev/mem` and to read it: read() fails with EPERM
/// on x86_64, and with EFAULT on i686, whose Linux reads `/dev/mem` only up to the end of its low
/// memory (Linux v6.11 drivers/char/mem.c:112-113, arch/x86/mm/mmap.c:218-221), before the check
/// of the range that mmap() fails with EPERM (drivers/char/mem.c:362-363).
#[test]
fn the_kernel_refuses_the_copy() {
    let address = published_database().address;
    let error = read_dev_mem_byte(address).expect_err("read the copy from /dev/mem");
    let read_errno = match cfg!(target_arch = "x86") {
        true => EFAULT,
        false => EPERM,
    };
    assert_eq!(
        error.raw_os_error(),
        Some(read_errno),
        "{address:#x}: {error}"
    );

    let error = map_dev_mem_byte(address).expect_err("map the copy from /dev/mem");
    assert!(
        error.contains("Operation not permitted"),
        "{address:#x}: {error}"
    );
}

/// The `HiiDB` variable method reports the kernel's refusal as a refusal, named and in the
/// automatic order, which stops there, before the configuration-table method.
#[test]
fn efivar_reports_the_kernel_s_refusal() {
    for (index, flags) in [
        &[
            "--hii-source",
            "efivar",
            "--efivar-memory",
            "firmware-reserved",
        ][..],
        &["--efivar-memory", "firmware-reserved"],
    ]
    .into_iter()
    .enumerate()
    {
        let error = extract_db_error(flags, &format!("/tmp/hiidb-acpi-nvs-{index}.bin"));
        let efivar = error
            .error_message
            .split_once("efivar: ")
            .map(|(_, efivar)| efivar)
            .unwrap_or_else(|| panic!("{flags:?}: no efivar method: {error:?}"));
        assert!(
            efivar.starts_with("refused: ") && efivar.contains(STRICT_DEVMEM),
            "{flags:?}: {error:?}"
        );
        assert!(
            !efivar.contains("systab"),
            "{flags:?}: tried the configuration table after the refusal: {error:?}"
        );
    }
}
