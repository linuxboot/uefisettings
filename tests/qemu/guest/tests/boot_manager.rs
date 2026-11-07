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

//! The variables of the boot manager (src/lib/efi_variables/boot_manager.rs) in the scenario
//! boot-manager, whose variable store tests/qemu/vars/boot-manager.json seeds with Boot0099, of
//! a file that no ESP holds, with an undefined attribute bit and OptionalData, and Key0099,
//! CTRL-q to Boot0099: `before_shell` checks that `variable get` shows them as their bytes tell,
//! and so does the UEFI Shell boot after it, shell/boot-manager.nsh, whose checks compare what
//! uefisettings.efi prints with the lines "uefisettings-qemu-test: TAG JSON" of this test log.

use std::io;
use std::io::Write;

use serde_json::json;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::EFI_GLOBAL_VARIABLE;

/// What `variable get` prints of `name`, which the test log records as
/// "uefisettings-qemu-test: TAG JSON", written to stderr itself, which libtest does not capture,
/// on a line of its own after libtest's "test ... ".
#[track_caller]
fn get(tag: &str, name: &str) -> serde_json::Value {
    let output = uefisettings_qemu_guest::uefisettings(&["variable", "get", name]);
    writeln!(
        io::stderr(),
        "\nuefisettings-qemu-test: {tag} {}",
        output.stdout.trim_end()
    )
    .expect("cannot write to stderr");
    output.json(0)
}

/// The global variable `name` of `value`, with NV+BS+RT, as get prints it.
fn global(name: &str, value: serde_json::Value) -> serde_json::Value {
    json!({
        "variable": format!("{name}-{EFI_GLOBAL_VARIABLE}"),
        "attributes": 7,
        "value": value,
    })
}

/// Boot0099 as tests/qemu/vars/boot-manager.json seeds it, with `attributes`.
fn seeded_boot0099(attributes: serde_json::Value) -> serde_json::Value {
    global(
        "Boot0099",
        json!({
            "attributes": attributes,
            "category": "boot",
            "description": "file missing-99.efi",
            "device_paths": ["\\missing-99.efi"],
            "optional_data": "7565666973657474696e6773",
        }),
    )
}

/// Key0099 as tests/qemu/vars/boot-manager.json seeds it, whose BootOptionCrc is that of the
/// seeded Boot0099.
fn seeded_key0099(crc_matches: bool) -> serde_json::Value {
    global(
        "Key0099",
        json!({
            "revision": 0,
            "modifiers": ["control"],
            "keys": ["q"],
            "boot_option": "Boot0099",
            "crc_matches": crc_matches,
        }),
    )
}

#[test]
fn before_shell() {
    require_test_vm();

    assert_eq!(
        get("seeded-boot0099", "Boot0099"),
        seeded_boot0099(json!(["active", "0x40000000"])),
        "Boot0099"
    );
    assert_eq!(
        get("seeded-key0099", "Key0099"),
        seeded_key0099(true),
        "Key0099"
    );
}
