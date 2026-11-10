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

//! The HII package lists that `name-value-password-forms`, `rt-data-name-value-password-forms`
//! and `export-config-name-value-password` register in the HII database for a handle with the
//! device path [`DRIVER_PATH`], for the UEFI Shell scenario `shell-name-value-password` and the
//! Linux scenarios `hii-name-value-password` and `hii-name-value-password-snapshot` of
//! `tests/qemu/scenarios.tsv`. The first list's form set declares the buffer VARSTORE NvBacking,
//! VarStoreId 1, with a UINT32 NUMERIC over its bytes 0..4, and the VARSTORE_NAME_VALUE of
//! VarStoreId 3, with a UINT32 NUMERIC and a PASSWORD on its name "Pin"; the second list's form
//! set has a UINT16 NUMERIC over the buffer VARSTORE Other. A VARSTORE_NAME_VALUE is one whose
//! values its driver exposes, as UEFI 2.11 §33.2.5.6 says, through EFI_HII_CONFIG_ACCESS_PROTOCOL,
//! in storage of its own choosing, and one driver may serve several package lists
//! (edk2-stable202608 DriverSample.c installs one EFI_HII_CONFIG_ACCESS_PROTOCOL for two, on two
//! handles, :1870-1918), so the password may be in any variable:
//! `tests/qemu/vars/name-value-password.json` creates NvBacking holding [`PIN`] where the
//! NUMERIC reads, and Other.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi::guid;
use uefi::Guid;

use crate::hii_package::end;
use crate::hii_package::language_strings_package;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::question_header;
use crate::hii_package::strings_package;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_VARSTORE_NAME_VALUE_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;
use crate::vendor_device_path;

/// The GUID of the first package list and of its form set.
const NAME_VALUE_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001f00");
/// The GUID of the VARSTORE_NAME_VALUE.
const NAME_VALUE_GUID: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001f01");
/// The vendor GUID of NvBacking.
const NV_BACKING_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001f02");
/// The GUID of the second package list and of its form set.
const OTHER_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001f03");
/// The vendor GUID of Other.
const OTHER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001f04");
/// The Vendor_GUID of the Vendor Device Path node of [`DRIVER_PATH`].
const DRIVER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001f05");
/// The device path of the handle that registers both package lists.
pub(crate) static DRIVER_PATH: [u8; 24] = vendor_device_path(DRIVER_VENDOR);
/// The value of [`PIN_LABEL`], which the `<ConfigResp>` of [`pin_resp`] holds, and which
/// `tests/qemu/vars/name-value-password.json` puts in NvBacking's bytes 0..4, little-endian.
const PIN: u32 = 0x7A5B_C3E1;

// The strings of the first package list, from string ID 2, after the language name.
const BACKING_SETTING: u16 = 2;
const TITLE: u16 = 3;
const HELP: u16 = 4;
const PIN_NAME: u16 = 5;
const PASSWORD: u16 = 6;
const PIN_NUMBER: u16 = 7;
/// The name of the VARSTORE_NAME_VALUE's value that the NUMERIC and the PASSWORD are on.
const PIN_LABEL: &str = "Pin";
const STRINGS: [&str; 7] = [
    "English",
    "Backing setting",
    "uefisettings QEMU name value password forms",
    "A password question that edk2 may route to a VARSTORE_NAME_VALUE",
    PIN_LABEL,
    "Name value password",
    "Name value pin as a number",
];
/// The language and the strings, from string ID 1, of the first package list's x-UEFI-ns
/// strings package: the keyword of "Backing setting" (UEFI 2.11 §35.2.1.6).
const KEYWORD_LANGUAGE: &[u8] = b"x-UEFI-ns\0";
const KEYWORD_STRINGS: [&str; 2] = ["UefiNameSpace", "BackingSetting"];

// The strings of the second package list, likewise.
const OTHER_SETTING: u16 = 2;
const OTHER_TITLE: u16 = 3;
const OTHER_HELP: u16 = 4;
const OTHER_STRINGS: [&str; 4] = [
    "English",
    "Other setting",
    "uefisettings QEMU name value password other forms",
    "A question of another package list of the driver of a VARSTORE_NAME_VALUE",
];

/// The VarStoreIds of NvBacking, of the VARSTORE_NAME_VALUE and of Other.
const NV_BACKING_ID: u16 = 1;
const NAME_VALUE_ID: u16 = 3;
const OTHER_ID: u16 = 2;
/// The sizes of NvBacking and Other.
const NV_BACKING_SIZE: u16 = 4;
const OTHER_SIZE: u16 = 2;
/// The MinSize and MaxSize of the PASSWORD, in characters.
const PASSWORD_MIN_SIZE: u16 = 4;
const PASSWORD_MAX_SIZE: u16 = 8;
/// EFI_IFR_NUMERIC_SIZE_2 | EFI_IFR_DISPLAY_UINT_DEC and EFI_IFR_NUMERIC_SIZE_4 |
/// EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT16_DECIMAL: u8 = 0x11;
const UINT32_DECIMAL: u8 = 0x12;

/// The package lists, as NewPackageList() takes them.
pub(crate) fn package_lists() -> [Vec<u8>; 2] {
    let keywords = language_strings_package(KEYWORD_LANGUAGE, KEYWORD_STRINGS);
    [
        package_list(
            NAME_VALUE_FORM_SET,
            &[strings_package(STRINGS), keywords, name_value_forms()],
        ),
        package_list(
            OTHER_FORM_SET,
            &[strings_package(OTHER_STRINGS), other_forms()],
        ),
    ]
}

/// The `<ConfigResp>` that the driver at [`DRIVER_PATH`] would export for the
/// VARSTORE_NAME_VALUE, whose `<ConfigHdr>` (UEFI 2.11 §35.2.1.3) has an empty NAME, as the
/// VarStore names no variable: [`PIN_LABEL`] holds [`PIN`], its digits most significant first.
pub(crate) fn pin_resp() -> String {
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    format!(
        "GUID={}&NAME=&PATH={}&{PIN_LABEL}={PIN:08x}",
        hex(&NAME_VALUE_GUID.to_bytes()),
        hex(&DRIVER_PATH),
    )
}

/// The FORM_SET op of the form set `guid`, titled `title` and helped `help`, which opens its
/// scope.
fn form_set_op(guid: Guid, title: u16, help: u16) -> Vec<u8> {
    let form_set = [
        &guid.to_bytes()[..],
        &title.to_le_bytes(),
        &help.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    op(EFI_IFR_FORM_SET_OP, true, &form_set)
}

/// The VARSTORE of `id` of the variable `name`, `vendor`, of `size` bytes.
fn var_store(id: u16, vendor: Guid, size: u16, name: &[u8]) -> Vec<u8> {
    op(
        EFI_IFR_VARSTORE_OP,
        false,
        &[
            &vendor.to_bytes()[..],
            &id.to_le_bytes(),
            &size.to_le_bytes(),
            name,
        ]
        .concat(),
    )
}

/// A NUMERIC of `flags` and the MinValue, MaxValue and Step `range`, whose question header is
/// `header`, with its scope's End.
fn numeric(header: Vec<u8>, flags: u8, range: &[u8]) -> Vec<u8> {
    [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[&header[..], &[flags], range].concat(),
        ),
        end(),
    ]
    .concat()
}

/// A decimal UINT32 NUMERIC of the whole range whose question header is `header`.
fn uint32_numeric(header: Vec<u8>) -> Vec<u8> {
    numeric(
        header,
        UINT32_DECIMAL,
        &[0, u32::MAX, 1].map(u32::to_le_bytes).concat(),
    )
}

/// A decimal UINT16 NUMERIC of the whole range whose question header is `header`.
fn uint16_numeric(header: Vec<u8>) -> Vec<u8> {
    numeric(
        header,
        UINT16_DECIMAL,
        &[0, u16::MAX, 1].map(u16::to_le_bytes).concat(),
    )
}

/// The first list's form package: its form set, NvBacking, the VARSTORE_NAME_VALUE and one form
/// that holds the NUMERIC over NvBacking, the NUMERIC on "Pin" and the PASSWORD on "Pin".
fn name_value_forms() -> Vec<u8> {
    let password = op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header(PASSWORD, HELP, 3, NAME_VALUE_ID, PIN_NAME),
            [
                PASSWORD_MIN_SIZE.to_le_bytes(),
                PASSWORD_MAX_SIZE.to_le_bytes(),
            ]
            .concat(),
        ]
        .concat(),
    );
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        form_set_op(NAME_VALUE_FORM_SET, TITLE, HELP),
        var_store(
            NV_BACKING_ID,
            NV_BACKING_VENDOR,
            NV_BACKING_SIZE,
            b"NvBacking\0",
        ),
        op(
            EFI_IFR_VARSTORE_NAME_VALUE_OP,
            false,
            &[
                &NAME_VALUE_ID.to_le_bytes()[..],
                &NAME_VALUE_GUID.to_bytes(),
            ]
            .concat(),
        ),
        op(EFI_IFR_FORM_OP, true, &form),
        uint32_numeric(question_header(BACKING_SETTING, HELP, 1, NV_BACKING_ID, 0)),
        uint32_numeric(question_header(
            PIN_NUMBER,
            HELP,
            2,
            NAME_VALUE_ID,
            PIN_NAME,
        )),
        password,
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The second list's form package: its form set, Other and one form that holds the NUMERIC over
/// Other.
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
