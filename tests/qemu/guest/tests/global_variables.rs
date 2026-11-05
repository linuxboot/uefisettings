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

//! `variable get` of the global variables (src/lib/efi_variables/globals.rs), which reads them
//! through efivarfs: `get_default_firmware` in variable-get, on the default firmware, whose
//! variable store holds no Secure Boot variables, and `get_secboot_setup` and `get_secboot_user`
//! in variable-get-secboot-setup and variable-get-secboot-user, on the secboot firmware in Setup
//! Mode and, with run.sh's PK, KEK and db enrolled, in User Mode. Each test records what get
//! prints of each variable, for the Shell boots of the shell- scenarios to compare.

use std::io;
use std::io::Write;

use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use uefisettings_qemu_guest::assert_absent;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::variable_bytes;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::EFIVARS;

/// EFI_GLOBAL_VARIABLE, as efivarfs names the files of its variables.
const EFI_GLOBAL_VARIABLE: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor GUID of db.
const EFI_IMAGE_SECURITY_DATABASE: &str = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";
/// NV+BS+RT, the attributes of Timeout and BootOrder in UEFI 2.11 Table 3.1.
const NV_BS_RT: u32 = 0x07;
/// BS+RT, the attributes of SetupMode and SecureBoot in UEFI 2.11 Table 3.1.
const BS_RT: u32 = 0x06;
/// NV+BS+RT+AT, the attributes of PK and KEK in UEFI 2.11 Table 3.1, and of db.
const NV_BS_RT_AT: u32 = 0x27;
/// EFI_CERT_X509_GUID (UEFI 2.11 §32.4.1), the SignatureType of the lists that run.sh enrolls.
const EFI_CERT_X509: &str = "A5C059A1-94E4-4AA7-87B5-AB155C2BF072";
/// The SignatureOwner of the certificates that run.sh enrolls (secboot_owner).
const SECBOOT_OWNER: &str = "DE145B29-C3CD-455F-91DE-A76237B67C52";
/// The Timeout that the firmware writes at every boot without `-boot menu=on`:
/// PcdPlatformBootTimeOut, 0 in OvmfPkg's PcdsDynamicDefault, 5 in ArmVirtQemu's PcdsDynamicHii,
/// which reads Timeout itself (edk2-stable202508 OvmfPkg/OvmfPkgX64.dsc:716,
/// OvmfPkg/OvmfPkgIa32.dsc:609, ArmVirtPkg/ArmVirtQemu.dsc:329;
/// OvmfPkg/Library/PlatformBootManagerLib/BdsPlatform.c:300-313,
/// OvmfPkg/Library/PlatformBootManagerLibLight/PlatformBm.c:857-870).
const FIRMWARE_TIMEOUT: u16 = if cfg!(target_arch = "aarch64") { 5 } else { 0 };
/// The Secure Boot variables of UEFI 2.11 §3.3 that edk2 implements without AuditMode and
/// DeployedMode: AuthVariableLibNull leaves them uncreated.
const SECURE_BOOT_MODES: [&str; 4] = ["SecureBoot", "SetupMode", "AuditMode", "DeployedMode"];

/// What `variable get` prints.
#[derive(Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Global {
    variable: String,
    attributes: Option<u32>,
    value: Option<serde_json::Value>,
    #[serde(default)]
    absent: bool,
}

/// What `variable get` prints of `name`, which the test log records as
/// "uefisettings-qemu-test: get NAME JSON", written to stderr itself, which libtest does not
/// capture.
#[track_caller]
fn get(name: &str) -> Global {
    let output = uefisettings_qemu_guest::uefisettings(&["variable", "get", name]);
    writeln!(
        io::stderr(),
        "uefisettings-qemu-test: get {name} {}",
        output.stdout.trim_end()
    )
    .expect("cannot write to stderr");
    output.json(0)
}

/// The efivar file of the variable `name` of `vendor`.
fn path(name: &str, vendor: &str) -> String {
    format!("{EFIVARS}/{name}-{vendor}")
}

/// The attributes and data of the variable `name` of `vendor`, as efivarfs holds them.
#[track_caller]
fn efivar(name: &str, vendor: &str) -> (u32, Vec<u8>) {
    let path = path(name, vendor);
    let bytes = variable_bytes(&path).unwrap_or_else(|| panic!("{path} is missing"));
    let (attributes, data) = bytes
        .split_first_chunk::<EFIVARFS_HEADER_SIZE>()
        .unwrap_or_else(|| panic!("{path} has no attributes: {bytes:02X?}"));
    (u32::from_ne_bytes(*attributes), data.to_vec())
}

/// get shows the global variable `name`, whose attributes are `attributes`, as the value that
/// `decode` makes of its data in efivarfs, which it returns.
#[track_caller]
fn assert_global(
    name: &str,
    attributes: u32,
    decode: impl Fn(&[u8]) -> serde_json::Value,
) -> serde_json::Value {
    let (held, data) = efivar(name, EFI_GLOBAL_VARIABLE);
    let value = decode(&data);
    assert_eq!(held, attributes, "{name}: attributes in efivarfs");
    assert_eq!(
        get(name),
        Global {
            variable: format!("{name}-{EFI_GLOBAL_VARIABLE}"),
            attributes: Some(attributes),
            value: Some(value.clone()),
            absent: false,
        },
        "{name}"
    );
    value
}

/// get shows the variable `name` as absent, and efivarfs holds no file of it.
#[track_caller]
fn assert_absent_global(name: &str, vendor: &str) {
    assert_absent(&path(name, vendor));
    assert_eq!(
        get(name),
        Global {
            variable: format!("{name}-{vendor}"),
            attributes: None,
            value: None,
            absent: true,
        },
        "{name}"
    );
}

/// The UINT16 of `data`, little-endian.
#[track_caller]
fn uint16(data: &[u8]) -> u16 {
    u16::from_le_bytes(data.try_into().expect("a UINT16"))
}

/// Timeout and BootOrder: a UINT16 of seconds, FIRMWARE_TIMEOUT, and the Boot#### of each UINT16.
#[track_caller]
fn assert_timeout_and_boot_order() {
    let timeout = assert_global("Timeout", NV_BS_RT, |data| serde_json::json!(uint16(data)));
    assert_eq!(timeout, serde_json::json!(FIRMWARE_TIMEOUT), "Timeout");
    let boot_order = assert_global("BootOrder", NV_BS_RT, |data| {
        data.chunks(2)
            .map(|number| format!("Boot{:04X}", uint16(number)))
            .collect()
    });
    assert_ne!(boot_order, serde_json::json!([]), "BootOrder");
}

/// get shows the global variable `name` as `value`, with BS+RT.
#[track_caller]
fn assert_mode(name: &str, value: u8) {
    assert_global(name, BS_RT, |data| {
        assert_eq!(data, [value], "{name} in efivarfs");
        serde_json::json!(value)
    });
}

/// get shows the signature database `name` of `vendor` as the one EFI_SIGNATURE_LIST of an X.509
/// certificate that run.sh enrolled, with its SHA-256.
#[track_caller]
fn assert_enrolled(name: &str, vendor: &str) {
    let (attributes, data) = efivar(name, vendor);
    // SignatureType, SignatureListSize, SignatureHeaderSize 0, SignatureSize, then one
    // EFI_SIGNATURE_DATA: SignatureOwner and the certificate (UEFI 2.11 §32.4.1)
    let certificate = data.get(28 + 16..).expect("an EFI_SIGNATURE_LIST");
    let sha256: String = Sha256::digest(certificate)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(
        get(name),
        Global {
            variable: format!("{name}-{vendor}"),
            attributes: Some(attributes),
            value: Some(serde_json::json!([{
                "type": EFI_CERT_X509,
                "signatures": [{ "owner": SECBOOT_OWNER, "sha256": sha256 }],
            }])),
            absent: false,
        },
        "{name}"
    );
    assert_eq!(attributes, NV_BS_RT_AT, "{name}: attributes in efivarfs");
}

#[test]
fn get_default_firmware() {
    require_test_vm();
    assert_timeout_and_boot_order();
    for name in SECURE_BOOT_MODES.into_iter().chain(["PK", "KEK"]) {
        assert_absent_global(name, EFI_GLOBAL_VARIABLE);
    }
    assert_absent_global("db", EFI_IMAGE_SECURITY_DATABASE);

    let error = json_error(&["variable", "get", "Boot0000"]);

    assert!(
        error.error_message.contains("variable info Boot0000 GUID"),
        "Boot0000: {error:?}"
    );
}

#[test]
fn get_secboot_setup() {
    require_test_vm();
    assert_timeout_and_boot_order();
    assert_mode("SetupMode", 1);
    assert_mode("SecureBoot", 0);
    for name in ["AuditMode", "DeployedMode", "PK", "KEK"] {
        assert_absent_global(name, EFI_GLOBAL_VARIABLE);
    }
}

#[test]
fn get_secboot_user() {
    require_test_vm();
    assert_timeout_and_boot_order();
    assert_mode("SetupMode", 0);
    assert_mode("SecureBoot", 0);
    for name in ["AuditMode", "DeployedMode"] {
        assert_absent_global(name, EFI_GLOBAL_VARIABLE);
    }
    assert_enrolled("PK", EFI_GLOBAL_VARIABLE);
    assert_enrolled("KEK", EFI_GLOBAL_VARIABLE);
    assert_enrolled("db", EFI_IMAGE_SECURITY_DATABASE);
}
