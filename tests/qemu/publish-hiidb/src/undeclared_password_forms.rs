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

//! The HII package lists that `undeclared-password-forms`, `rt-data-undeclared-password-forms`
//! and `export-config-undeclared-password` register in the HII database for a handle with the
//! device path [`DRIVER_PATH`], for the UEFI Shell scenario `shell-undeclared-password` and the
//! Linux scenarios `hii-undeclared-password` and `hii-undeclared-password-snapshot` of
//! `tests/qemu/scenarios.tsv`. The first list's form set declares the buffer VARSTORE UdBacking,
//! VarStoreId 1, with a UINT32 NUMERIC over its bytes 0..4, of the x-UEFI-ns keyword
//! UndeclaredSetting, and a PASSWORD of VarStoreId 9, which no VarStore of its form package
//! declares, so it names no VarStore: UEFI 2.11 §33.3.8.2.2 asks for "a previously declared
//! variable store"; the second list's form set has a UINT16 NUMERIC over the buffer VARSTORE
//! Other. Its driver, which may serve several package lists, keeps that password where it
//! chooses, so in any variable: `tests/qemu/vars/undeclared-password.json` creates UdBacking
//! holding [`PIN`] where the NUMERIC reads, and Other. The PASSWORD's prompt has no x-UEFI-ns
//! keyword, so no keyword request selects it, and UdBacking is a buffer VARSTORE, not a
//! VARSTORE_EFI, so edk2 resolves the PASSWORD's storage neither when it registers the forms nor
//! when it exports their configuration.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi::guid;
use uefi::Guid;

use crate::hii_package::end;
use crate::hii_package::form_set_op;
use crate::hii_package::language_strings_package;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::question_header;
use crate::hii_package::strings_package;
use crate::hii_package::uint16_numeric;
use crate::hii_package::uint32_numeric;
use crate::hii_package::var_store;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::vendor_device_path;

/// The GUID of the first package list and of its form set.
const UNDECLARED_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002300");
/// The vendor GUID of UdBacking.
const UD_BACKING_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002301");
/// The GUID of the second package list and of its form set.
const OTHER_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002302");
/// The vendor GUID of Other.
const OTHER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002303");
/// The Vendor_GUID of the Vendor Device Path node of [`DRIVER_PATH`].
const DRIVER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002304");
/// The device path of the handle that registers both package lists.
pub(crate) static DRIVER_PATH: [u8; 24] = vendor_device_path(DRIVER_VENDOR);
/// The value that `tests/qemu/vars/undeclared-password.json` puts in UdBacking's bytes 0..4,
/// little-endian, standing for a password that the PASSWORD's driver keeps there, and that the
/// `<ConfigResp>` of [`backing_resp`] holds.
const PIN: u32 = 0x7A4C_19E3;

// The strings of the first package list, from string ID 2, after the language name.
const BACKING_SETTING: u16 = 2;
const TITLE: u16 = 3;
const HELP: u16 = 4;
const PASSWORD_PROMPT: u16 = 5;
const STRINGS: [&str; 5] = [
    "English",
    "Undeclared backing setting",
    "uefisettings QEMU undeclared password forms",
    "A password question of a VarStoreId that no VarStore declares",
    "Undeclared password",
];
/// The language and the strings, from string ID 1, of the first package list's x-UEFI-ns
/// strings package: the keyword of "Undeclared backing setting" (UEFI 2.11 §35.2.1.6).
const KEYWORD_LANGUAGE: &[u8] = b"x-UEFI-ns\0";
const KEYWORD_STRINGS: [&str; 2] = ["UefiNameSpace", "UndeclaredSetting"];

// The strings of the second package list, likewise.
const OTHER_SETTING: u16 = 2;
const OTHER_TITLE: u16 = 3;
const OTHER_HELP: u16 = 4;
const OTHER_STRINGS: [&str; 4] = [
    "English",
    "Undeclared other setting",
    "uefisettings QEMU undeclared password other forms",
    "A question of another package list of the driver of the undeclared password",
];

/// The VarStoreIds of UdBacking and of Other, and the one of the PASSWORD, which no VarStore of
/// its form package declares.
const UD_BACKING_ID: u16 = 1;
const OTHER_ID: u16 = 2;
const UNDECLARED_ID: u16 = 9;
/// The name and the size of UdBacking, and the size of Other.
const UD_BACKING_NAME: &str = "UdBacking";
const UD_BACKING_SIZE: u16 = 4;
const OTHER_SIZE: u16 = 2;
/// The MinSize and MaxSize of the PASSWORD, in characters.
const PASSWORD_MIN_SIZE: u16 = 4;
const PASSWORD_MAX_SIZE: u16 = 8;

/// The package lists, as NewPackageList() takes them.
pub(crate) fn package_lists() -> [Vec<u8>; 2] {
    let keywords = language_strings_package(KEYWORD_LANGUAGE, KEYWORD_STRINGS);
    [
        package_list(
            UNDECLARED_FORM_SET,
            &[strings_package(STRINGS), keywords, undeclared_forms()],
        ),
        package_list(
            OTHER_FORM_SET,
            &[strings_package(OTHER_STRINGS), other_forms()],
        ),
    ]
}

/// The `<ConfigResp>` of UdBacking that the driver at [`DRIVER_PATH`] would export, as edk2's
/// HiiConstructConfigHdr and BlockToConfig write one: its NAME in hex CHAR16s and its bytes
/// holding [`PIN`], VALUE's digits most significant first (UEFI 2.11 §35.4.6).
pub(crate) fn backing_resp() -> String {
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    let name: String = UD_BACKING_NAME
        .encode_utf16()
        .map(|unit| format!("{unit:04x}"))
        .collect();
    format!(
        "GUID={}&NAME={name}&PATH={}&OFFSET=0&WIDTH={UD_BACKING_SIZE:x}&VALUE={PIN:08x}",
        hex(&UD_BACKING_VENDOR.to_bytes()),
        hex(&DRIVER_PATH),
    )
}

/// The first list's form package: its form set, UdBacking and one form that holds the UINT32
/// NUMERIC over UdBacking and the PASSWORD of VarStoreId 9.
fn undeclared_forms() -> Vec<u8> {
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let password = [
        question_header(PASSWORD_PROMPT, HELP, 2, UNDECLARED_ID, 0),
        [
            PASSWORD_MIN_SIZE.to_le_bytes(),
            PASSWORD_MAX_SIZE.to_le_bytes(),
        ]
        .concat(),
    ]
    .concat();
    let body = [
        form_set_op(UNDECLARED_FORM_SET, TITLE, HELP),
        var_store(
            UD_BACKING_ID,
            UD_BACKING_VENDOR,
            UD_BACKING_SIZE,
            &[UD_BACKING_NAME.as_bytes(), &[0]].concat(),
        ),
        op(EFI_IFR_FORM_OP, true, &form),
        uint32_numeric(question_header(BACKING_SETTING, HELP, 1, UD_BACKING_ID, 0)),
        op(EFI_IFR_PASSWORD_OP, false, &password),
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The second list's form package: its form set, Other and one form that holds the UINT16
/// NUMERIC over Other.
fn other_forms() -> Vec<u8> {
    let form = [1u16.to_le_bytes(), OTHER_TITLE.to_le_bytes()].concat();
    let body = [
        form_set_op(OTHER_FORM_SET, OTHER_TITLE, OTHER_HELP),
        var_store(OTHER_ID, OTHER_VENDOR, OTHER_SIZE, b"Other\0"),
        op(EFI_IFR_FORM_OP, true, &form),
        uint16_numeric(question_header(OTHER_SETTING, OTHER_HELP, 1, OTHER_ID, 0)),
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}
