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

//! The scenarios `json-config-data*`: `capsule config-data` prints the configuration data of the
//! table of EFI_JSON_CONFIG_DATA_TABLE_GUID (UEFI 2.11 §4.6.1.2) that `publish-hiidb.efi
//! json-config-data` installs, from physical memory, and refuses the tables of
//! `json-config-data-past-region`, `-boot-services` and `-mmio` before it reads anything past
//! their Version and TotalLength: one whose TotalLength runs past its runtime region, one in boot
//! services data and one in runtime memory-mapped I/O. Each scenario names its test as the
//! libtest filter. The scenarios `shell-json-config-data*` check what `uefisettings.efi` prints in
//! the UEFI Shell.

use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;

/// `capsule config-data`.
const CONFIG_DATA: [&str; 2] = ["capsule", "config-data"];

#[test]
fn prints_the_table() {
    let report: serde_json::Value = json(&CONFIG_DATA);

    assert_eq!(
        report,
        serde_json::json!({
            "items": [
                { "text": "{\"uefisettings\":\"json-config-data\"}" },
                { "hex": "ff00807f" },
            ],
        })
    );
}

/// Panics unless `message` is the refusal of `length` bytes at an address, after `read`, for
/// `reason`.
#[track_caller]
fn assert_refusal(message: &str, read: &str, length: &str, reason: &str) {
    let rest = message
        .strip_prefix(&format!(
            "read the {read} of the JSON configuration table: 0x"
        ))
        .unwrap_or_else(|| panic!("{message:?} reads no {read:?}"));
    let (address, rest) = rest
        .split_once('+')
        .unwrap_or_else(|| panic!("{message:?} names no range"));
    assert!(
        !address.is_empty() && address.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{message:?}: address {address:?}"
    );
    assert_eq!(rest, format!("{length} {reason}"), "{message:?}");
}

#[test]
fn refuses_a_table_past_its_region() {
    let error = json_error(&CONFIG_DATA);
    assert_refusal(
        &error.error_message,
        "TotalLength 16777216 bytes",
        "0x1000000",
        "lies in no EFI_MEMORY_RUNTIME region",
    );
}

#[test]
fn refuses_a_table_in_boot_services_data() {
    let error = json_error(&CONFIG_DATA);
    assert_refusal(
        &error.error_message,
        "Version and TotalLength",
        "0x8",
        "lies in no EFI_MEMORY_RUNTIME region",
    );
}

#[test]
fn refuses_a_table_in_memory_mapped_io() {
    let error = json_error(&CONFIG_DATA);
    assert_refusal(
        &error.error_message,
        "Version and TotalLength",
        "0x8",
        "lies in memory-mapped I/O, EFI memory type 11",
    );
}
