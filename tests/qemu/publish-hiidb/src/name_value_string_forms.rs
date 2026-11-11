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

//! The HII package list that `rt-data-name-value-string-forms` and
//! `export-config-name-value-string` register in the HII database for a handle with the device
//! path [`DRIVER_PATH`], for the Linux scenarios `hii-name-value-string` and
//! `hii-name-value-string-snapshot` of `tests/qemu/scenarios.tsv`. Its form set declares a
//! VARSTORE_NAME_VALUE, whose values its driver exposes, as UEFI 2.11 §33.2.5.6 says, through
//! EFI_HII_CONFIG_ACCESS_PROTOCOL, and no PASSWORD; on each name of [`STRING_SETTINGS`] a STRING
//! of MaxSize [`STRING_MAX_SIZE`], and on [`FLAG_SETTING`]'s a CHECKBOX, each prompted by its
//! name. [`settings_resp`] is the `<ConfigResp>` that `export-config-name-value-string` appends
//! to ExportConfig()'s results: as a STRING reads them, 4 hex digits per `<Char>` (UEFI 2.11
//! §35.2.1.2), Text holds "AB", Nul "AB" and a NULL, Full "ABCD", Padded "ABCD" and a NULL,
//! Long 5 characters, Odd one and 2 digits, and Empty none.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use uefi::guid;
use uefi::Guid;

use crate::hii_package::end;
use crate::hii_package::form_set_op;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::question_header;
use crate::hii_package::string_op;
use crate::hii_package::strings_package;
use crate::hii_package::var_store_name_value_op;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_CHECKBOX_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::vendor_device_path;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002200");
/// The GUID of the VARSTORE_NAME_VALUE.
const NAME_VALUE_GUID: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002201");
/// The Vendor_GUID of the Vendor Device Path node of [`DRIVER_PATH`].
const DRIVER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002202");
/// The device path of the handle that registers the package list.
pub(crate) static DRIVER_PATH: [u8; 24] = vendor_device_path(DRIVER_VENDOR);

/// The names of the VARSTORE_NAME_VALUE's values that the STRINGs are on, with the digits that
/// [`settings_resp`] gives each.
const STRING_SETTINGS: [(&str, &str); 7] = [
    ("Text", "00410042"),
    ("Nul", "004100420000"),
    ("Full", "0041004200430044"),
    ("Padded", "00410042004300440000"),
    ("Long", "00410042004300440045"),
    ("Odd", "004100"),
    ("Empty", ""),
];
/// The name of the VARSTORE_NAME_VALUE's value that the CHECKBOX is on, with its digits: 1.
const FLAG_SETTING: (&str, &str) = ("Flag", "01");

// The strings, from string ID 2, after the language name: TITLE, HELP, then the names of
// STRING_SETTINGS and FLAG_SETTING's, from FIRST_NAME on.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const FIRST_NAME: u16 = 4;
const LANGUAGE_AND_TEXTS: [&str; 3] = [
    "English",
    "uefisettings QEMU name value string forms",
    "A question of a VARSTORE_NAME_VALUE",
];

/// The VarStoreId of the VARSTORE_NAME_VALUE.
const NAME_VALUE_ID: u16 = 1;
/// The MaxSize of each STRING, in characters.
const STRING_MAX_SIZE: u8 = 4;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    let names = STRING_SETTINGS
        .into_iter()
        .chain([FLAG_SETTING])
        .map(|(name, _)| name);
    package_list(
        FORM_SET,
        &[
            strings_package(LANGUAGE_AND_TEXTS.into_iter().chain(names)),
            forms(),
        ],
    )
}

/// The `<ConfigResp>` that the driver at [`DRIVER_PATH`] would export for the
/// VARSTORE_NAME_VALUE, whose `<ConfigHdr>` (UEFI 2.11 §35.2.1.3) has an empty NAME, as the
/// VarStore names no variable: an `<NvConfig>` (§35.2.1.4) of each name of [`STRING_SETTINGS`]
/// and of [`FLAG_SETTING`]'s, in that order.
pub(crate) fn settings_resp() -> String {
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    let settings: String = STRING_SETTINGS
        .into_iter()
        .chain([FLAG_SETTING])
        .map(|(name, digits)| format!("&{name}={digits}"))
        .collect();
    format!(
        "GUID={}&NAME=&PATH={}{settings}",
        hex(&NAME_VALUE_GUID.to_bytes()),
        hex(&DRIVER_PATH),
    )
}

/// The form package: the form set, the VARSTORE_NAME_VALUE and one form that holds a STRING on
/// each name of [`STRING_SETTINGS`], then the CHECKBOX on [`FLAG_SETTING`]'s, each of the
/// QuestionId after the one before it, from 1, and prompted by its name.
fn forms() -> Vec<u8> {
    let question =
        |name: u16| question_header(name, HELP, name - FIRST_NAME + 1, NAME_VALUE_ID, name);
    let mut names = FIRST_NAME..;
    let strings: Vec<Vec<u8>> = STRING_SETTINGS
        .iter()
        .zip(names.by_ref())
        .map(|(_, name)| string_op(question(name), 0, STRING_MAX_SIZE))
        .collect();
    let flag = names
        .next()
        .expect("a string ID after the names of the STRINGs");
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        vec![
            form_set_op(FORM_SET, TITLE, HELP),
            var_store_name_value_op(NAME_VALUE_ID, NAME_VALUE_GUID),
            op(EFI_IFR_FORM_OP, true, &form),
        ],
        strings,
        vec![
            op(
                EFI_IFR_CHECKBOX_OP,
                false,
                &[&question(flag)[..], &[0]].concat(),
            ),
            end(), // of the form
            end(), // of the form set
        ],
    ]
    .concat()
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}
