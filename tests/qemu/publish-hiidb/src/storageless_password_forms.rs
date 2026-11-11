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

//! The HII package lists that `storageless-password-forms`, `rt-data-storageless-password-forms`
//! and `export-config-storageless-password` register in the HII database for a handle with the
//! device path [`DRIVER_PATH`], for the UEFI Shell scenario `shell-storageless-password` and the
//! Linux scenarios `hii-storageless-password` and `hii-storageless-password-snapshot` of
//! `tests/qemu/scenarios.tsv`. The first list's form set declares the buffer VARSTORE SlBacking,
//! VarStoreId 1, with a UINT32 NUMERIC over its bytes 0..4, of the x-UEFI-ns keyword
//! StoragelessSetting, and two PASSWORDs of VarStoreId 0, which names no VarStore (UEFI 2.11
//! §33.3.8.2.2), one with EFI_IFR_FLAG_CALLBACK and one without; the second list's form set has a
//! UINT16 NUMERIC over the buffer VARSTORE Other. A question without a VarStore keeps its value
//! through its callbacks or READ and WRITE ops (§33.2.5.6), where its driver, which may serve
//! several package lists, chooses, so the passwords may be in any variable:
//! `tests/qemu/vars/storageless-password.json` creates SlBacking holding [`PIN`] where the
//! NUMERIC reads, and Other.

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
use crate::hii_package::question_header_with;
use crate::hii_package::strings_package;
use crate::hii_package::uint16_numeric;
use crate::hii_package::uint32_numeric;
use crate::hii_package::var_store;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::vendor_device_path;

/// The GUID of the first package list and of its form set.
const STORAGELESS_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002100");
/// The vendor GUID of SlBacking.
const SL_BACKING_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002101");
/// The GUID of the second package list and of its form set.
const OTHER_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002102");
/// The vendor GUID of Other.
const OTHER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002103");
/// The Vendor_GUID of the Vendor Device Path node of [`DRIVER_PATH`].
const DRIVER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002104");
/// The device path of the handle that registers both package lists.
pub(crate) static DRIVER_PATH: [u8; 24] = vendor_device_path(DRIVER_VENDOR);
/// The value that `tests/qemu/vars/storageless-password.json` puts in SlBacking's bytes 0..4,
/// little-endian, standing for a password that a PASSWORD's callbacks keep there, and that the
/// `<ConfigResp>` of [`backing_resp`] holds.
const PIN: u32 = 0x3E17_A95C;

// The strings of the first package list, from string ID 2, after the language name.
const BACKING_SETTING: u16 = 2;
const TITLE: u16 = 3;
const HELP: u16 = 4;
const CALLBACK_PASSWORD: u16 = 5;
const PLAIN_PASSWORD: u16 = 6;
const STRINGS: [&str; 6] = [
    "English",
    "Storageless backing setting",
    "uefisettings QEMU storageless password forms",
    "A password question of VarStoreId 0, which names no VarStore",
    "Storageless callback password",
    "Storageless plain password",
];
/// The language and the strings, from string ID 1, of the first package list's x-UEFI-ns
/// strings package: the keyword of "Storageless backing setting" (UEFI 2.11 §35.2.1.6).
const KEYWORD_LANGUAGE: &[u8] = b"x-UEFI-ns\0";
const KEYWORD_STRINGS: [&str; 2] = ["UefiNameSpace", "StoragelessSetting"];

// The strings of the second package list, likewise.
const OTHER_SETTING: u16 = 2;
const OTHER_TITLE: u16 = 3;
const OTHER_HELP: u16 = 4;
const OTHER_STRINGS: [&str; 4] = [
    "English",
    "Storageless other setting",
    "uefisettings QEMU storageless password other forms",
    "A question of another package list of the driver of the storageless passwords",
];

/// The VarStoreIds of SlBacking and of Other; 0 names no VarStore.
const SL_BACKING_ID: u16 = 1;
const OTHER_ID: u16 = 2;
const NO_VAR_STORE: u16 = 0;
/// The name and the size of SlBacking, and the size of Other.
const SL_BACKING_NAME: &str = "SlBacking";
const SL_BACKING_SIZE: u16 = 4;
const OTHER_SIZE: u16 = 2;
/// The MinSize and MaxSize of the PASSWORDs, in characters.
const PASSWORD_MIN_SIZE: u16 = 4;
const PASSWORD_MAX_SIZE: u16 = 8;
/// EFI_IFR_FLAG_CALLBACK (UEFI 2.11 §33.3.8.2.2).
const EFI_IFR_FLAG_CALLBACK: u8 = 0x04;

/// The package lists, as NewPackageList() takes them.
pub(crate) fn package_lists() -> [Vec<u8>; 2] {
    let keywords = language_strings_package(KEYWORD_LANGUAGE, KEYWORD_STRINGS);
    [
        package_list(
            STORAGELESS_FORM_SET,
            &[strings_package(STRINGS), keywords, storageless_forms()],
        ),
        package_list(
            OTHER_FORM_SET,
            &[strings_package(OTHER_STRINGS), other_forms()],
        ),
    ]
}

/// The `<ConfigResp>` of SlBacking that the driver at [`DRIVER_PATH`] would export, as edk2's
/// HiiConstructConfigHdr and BlockToConfig write one: its NAME in hex CHAR16s and its bytes
/// holding [`PIN`], VALUE's digits most significant first (UEFI 2.11 §35.4.6).
pub(crate) fn backing_resp() -> String {
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    let name: String = SL_BACKING_NAME
        .encode_utf16()
        .map(|unit| format!("{unit:04x}"))
        .collect();
    format!(
        "GUID={}&NAME={name}&PATH={}&OFFSET=0&WIDTH={SL_BACKING_SIZE:x}&VALUE={PIN:08x}",
        hex(&SL_BACKING_VENDOR.to_bytes()),
        hex(&DRIVER_PATH),
    )
}

/// A PASSWORD of VarStoreId 0, prompted `prompt`, of QuestionId `id` and the question Flags
/// `flags`.
fn storageless_password(prompt: u16, id: u16, flags: u8) -> Vec<u8> {
    op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header_with(prompt, HELP, id, NO_VAR_STORE, 0, flags),
            [
                PASSWORD_MIN_SIZE.to_le_bytes(),
                PASSWORD_MAX_SIZE.to_le_bytes(),
            ]
            .concat(),
        ]
        .concat(),
    )
}

/// The first list's form package: its form set, SlBacking and one form that holds the UINT32
/// NUMERIC over SlBacking, the PASSWORD with EFI_IFR_FLAG_CALLBACK and the one without.
fn storageless_forms() -> Vec<u8> {
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        form_set_op(STORAGELESS_FORM_SET, TITLE, HELP),
        var_store(
            SL_BACKING_ID,
            SL_BACKING_VENDOR,
            SL_BACKING_SIZE,
            &[SL_BACKING_NAME.as_bytes(), &[0]].concat(),
        ),
        op(EFI_IFR_FORM_OP, true, &form),
        uint32_numeric(question_header(BACKING_SETTING, HELP, 1, SL_BACKING_ID, 0)),
        storageless_password(CALLBACK_PASSWORD, 2, EFI_IFR_FLAG_CALLBACK),
        storageless_password(PLAIN_PASSWORD, 3, 0),
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
