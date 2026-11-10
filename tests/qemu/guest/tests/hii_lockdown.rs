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

//! The scenarios hii-lockdown-acpi and hii-lockdown-efivar boot Linux with lockdown=integrity,
//! which refuses to open `/dev/mem`. The tests of each are in the module named after the method,
//! which its scenario's libtest filter selects: `acpi::` for `publish-hiidb.efi acpi-table`,
//! which installs the HII database as the body of a QHII ACPI table, and `efivar::` for
//! `publish-hiidb.efi rt-data`, which points the `HiiDB` variable at a copy in runtime data.

use std::fs;

use uefisettings_qemu_guest::read_dev_mem_byte;
use uefisettings_qemu_guest::EPERM;

/// The kernel lockdown mode file of securityfs.
const LOCKDOWN: &str = "/sys/kernel/security/lockdown";

/// Panics unless the kernel runs under lockdown=integrity and refuses to open `/dev/mem`.
#[track_caller]
fn assert_dev_mem_refused() {
    let mode = fs::read_to_string(LOCKDOWN).unwrap_or_else(|error| panic!("{LOCKDOWN}: {error}"));
    assert!(mode.contains("[integrity]"), "{LOCKDOWN}: {mode:?}");
    let error = read_dev_mem_byte(0).expect_err("read /dev/mem under lockdown");
    assert_eq!(error.raw_os_error(), Some(EPERM), "{error}");
}

mod acpi {
    use uefisettings_qemu_guest::extract_db_matches;

    /// The vendor ACPI table method reads the database from QHII, which needs no `/dev/mem`:
    /// named and in the automatic order, where it comes first.
    #[test]
    fn reads_the_database_without_dev_mem() {
        super::assert_dev_mem_refused();
        for (index, flags) in [&["--hii-source", "acpi"][..], &[]].into_iter().enumerate() {
            extract_db_matches(flags, &format!("/tmp/hiidb-lockdown-{index}.bin"), None);
        }
    }
}

mod efivar {
    use uefisettings_qemu_guest::extract_db_error;

    /// What the `HiiDB` variable method fails with, before it opens `/dev/mem`
    /// (`src/lib/hii/lockdown.rs` refuse_locked_down).
    const REFUSED: &str =
        "efivar: refused: the kernel refuses to open /dev/mem (kernel lockdown is integrity)";

    /// The `HiiDB` variable method refuses before it opens `/dev/mem`, naming lockdown, rather
    /// than meeting the kernel's refusal of the open; the automatic order stops there, before the
    /// configuration-table method.
    #[test]
    fn refuses_before_opening_dev_mem() {
        super::assert_dev_mem_refused();
        for (index, flags) in [&["--hii-source", "efivar"][..], &[]]
            .into_iter()
            .enumerate()
        {
            let error = extract_db_error(flags, &format!("/tmp/hiidb-lockdown-{index}.bin"));
            assert!(
                error.error_message.ends_with(REFUSED),
                "{flags:?}: {error:?}"
            );
            assert!(
                !error.error_message.contains("systab"),
                "{flags:?}: tried the configuration table after the refusal: {error:?}"
            );
        }
    }
}
