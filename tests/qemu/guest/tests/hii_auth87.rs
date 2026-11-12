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

//! A guest whose firmware publishes, after its own package lists, the one that publish-hiidb's
//! `enhanced_auth_forms` registers: a question on each of EnhancedAuthData and
//! EnhancedAuthRefused, which tests/qemu/vars/enhanced-auth-87.json creates with the attributes
//! 0x87, among them EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, their values behind
//! EFI_VARIABLE_AUTHENTICATION_3 metadata (UEFI 2.11 §8.2.1). `get` reads the variables whole
//! from efivarfs, decodes the value behind the metadata of EnhancedAuthData and names the check
//! that refuses that of EnhancedAuthRefused, as shell/auth87.tsv checks in the UEFI Shell; `set`
//! refuses both and changes neither variable. `variable info` shows the metadata of
//! EnhancedAuthData, and that of EnhancedAuthRefused as the check that refuses it.

use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_bytes;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::PREFIXES;

/// The vendor GUID of both variables, as efivarfs names their files.
const VENDOR: &str = "8c78a505-baa0-4c4a-869f-000000000301";
/// The variable whose metadata uefisettings accepts.
const ACCEPTED: &str = "EnhancedAuthData";
/// The variable whose EFI_VARIABLE_AUTHENTICATION_3 has Version 2.
const REFUSED: &str = "EnhancedAuthRefused";
/// NV+BS+RT and EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, the attributes of both variables.
const ATTRIBUTES: u32 = 0x87;
/// The data size of both variables: the 68 bytes of EFI_VARIABLE_AUTHENTICATION_3, EFI_TIME and
/// EFI_VARIABLE_AUTHENTICATION_3_CERT_ID, then the 4 of the VarStore.
const SIZE: usize = 72;

/// Each variable, the question on it and the answer of that question.
fn questions() -> [(&'static str, &'static str, String); 2] {
    [
        (ACCEPTED, "Value behind accepted metadata", "18".to_owned()),
        (
            REFUSED,
            "Value behind refused metadata",
            format!(
                "<ValueUnavailable: EFI variable {REFUSED}-{VENDOR} has enhanced authenticated \
                 access (attributes 0x87), whose metadata uefisettings refuses: \
                 EFI_VARIABLE_AUTHENTICATION_3 Version 2, not 1>"
            ),
        ),
    ]
}

/// The attributes and data of `variable`, checked to have ATTRIBUTES and SIZE.
#[track_caller]
fn seeded(variable: &str) -> Vec<u8> {
    let path = format!("{EFIVARS}/{variable}-{VENDOR}");
    let bytes = variable_bytes(&path).unwrap_or_else(|| panic!("{path} is missing"));
    assert_eq!(
        (&bytes[..EFIVARFS_HEADER_SIZE], bytes.len()),
        (&ATTRIBUTES.to_ne_bytes()[..], EFIVARFS_HEADER_SIZE + SIZE),
        "the attributes and size of {variable}"
    );
    bytes
}

#[test]
fn get_reads_behind_enhanced_authenticated_metadata() {
    for (variable, question, answer) in questions() {
        seeded(variable);

        for prefix in PREFIXES {
            let (got, _) = single_response(
                &[prefix, &["get", question, "--json"]].concat(),
                BACKEND_HII,
            );

            assert_eq!(got.answer, answer, "{prefix:?} get {question:?}");
        }
    }
}

#[test]
fn set_refuses_enhanced_authenticated_variables() {
    for (variable, question, _) in questions() {
        let before = seeded(variable);

        for prefix in PREFIXES {
            let error = json_error(&[prefix, &["set", question, "44", "--json"]].concat());

            assert_eq!(
                error.error_message,
                format!(
                    "EFI variable {variable}-{VENDOR} has authenticated access (attributes 0x87), \
                     which uefisettings does not write"
                ),
                "{prefix:?} set {question:?}"
            );
            assert_eq!(seeded(variable), before, "{variable} after {prefix:?} set");
        }
    }
}

#[test]
fn variable_info_shows_the_metadata() {
    let cert_id: String = (0..32u8).map(|byte| format!("{byte:02x}")).collect();
    for (variable, metadata) in [
        (
            ACCEPTED,
            serde_json::json!({
                "version": 1,
                "type": 1,
                "metadata_size": 68,
                "flags": 0,
                "time_stamp": "2026-11-06T12:00:00Z",
                "cert_id": {"type": 1, "id": {"hex": cert_id}},
            }),
        ),
        (
            REFUSED,
            serde_json::json!({"refused": "EFI_VARIABLE_AUTHENTICATION_3 Version 2, not 1"}),
        ),
    ] {
        seeded(variable);

        let info: serde_json::Value = json(&["variable", "info", variable, VENDOR]);

        assert_eq!(
            info,
            serde_json::json!({
                "variable": format!("{variable}-{VENDOR}"),
                "attributes": ATTRIBUTES,
                "size": SIZE,
                "metadata": metadata,
            }),
            "{variable}"
        );
    }
}
