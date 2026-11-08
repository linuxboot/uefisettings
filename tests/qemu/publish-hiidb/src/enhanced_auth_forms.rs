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

//! The HII package list that `enhanced-auth-forms` registers in the HII database, for the UEFI
//! Shell scenario `shell-auth87` and the Linux scenario `hii-auth87`, where `rt-data` then
//! publishes it, of `tests/qemu/scenarios.tsv`: a form set with a UINT8 NUMERIC
//! at byte 1 of each of two 4-byte VARSTORE_EFIs, EnhancedAuthData and EnhancedAuthRefused,
//! whose variables tests/qemu/vars/enhanced-auth-87.json creates with
//! EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: their data holds the value behind
//! EFI_VARIABLE_AUTHENTICATION_3 metadata (UEFI 2.11 §8.2.1), which uefisettings accepts for
//! EnhancedAuthData and refuses for EnhancedAuthRefused. No firmware driver reads these
//! variables, so they stay as seeded. DriverSample's variable would not do: its GetVariable()
//! finds the metadata too long for its buffer, and its rewrite fails on the attributes, so it
//! unloads and registers no forms (edk2-stable202608 DriverSample.c DriverSampleInit()).

use alloc::vec::Vec;

use uefi::guid;
use uefi::Guid;

use crate::hii_package::end;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::question_header;
use crate::hii_package::strings_package;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000300");
/// The vendor GUID of both variables, which tests/qemu/vars/enhanced-auth-87.json creates.
const VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000301");
/// The Attributes of each VARSTORE_EFI: non-volatile, boot service and runtime access, and
/// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, as the variables have.
const NV_BS_RT_ENHANCED_AUTHENTICATED: u32 = 0x87;
/// The Size of each VARSTORE_EFI.
const VAR_STORE_SIZE: u16 = 4;

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const ACCEPTED_VALUE: u16 = 4;
const REFUSED_VALUE: u16 = 5;
const STRINGS: [&str; 5] = [
    "English",
    "uefisettings QEMU enhanced authenticated forms",
    "Values behind EFI_VARIABLE_AUTHENTICATION_3 metadata",
    "Value behind accepted metadata",
    "Value behind refused metadata",
];

// The VarStores
const ENHANCED_AUTH_DATA: u16 = 1;
const ENHANCED_AUTH_REFUSED: u16 = 2;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FORM_SET, &[strings_package(STRINGS), form_package()])
}

/// The form package: the form set, its VarStores, and one form that holds the questions.
fn form_package() -> Vec<u8> {
    let form_set = [
        &FORM_SET.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        var_store(ENHANCED_AUTH_DATA, b"EnhancedAuthData\0"),
        var_store(ENHANCED_AUTH_REFUSED, b"EnhancedAuthRefused\0"),
        op(EFI_IFR_FORM_OP, true, &form),
        numeric(1, ACCEPTED_VALUE, ENHANCED_AUTH_DATA),
        numeric(2, REFUSED_VALUE, ENHANCED_AUTH_REFUSED),
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The VARSTORE_EFI `id` of the variable `name` (NUL-terminated ASCII) of VENDOR.
fn var_store(id: u16, name: &[u8]) -> Vec<u8> {
    let data = [
        &id.to_le_bytes()[..],
        &VENDOR.to_bytes(),
        &NV_BS_RT_ENHANCED_AUTHENTICATED.to_le_bytes(),
        &VAR_STORE_SIZE.to_le_bytes(),
        name,
    ]
    .concat();
    op(EFI_IFR_VARSTORE_EFI_OP, false, &data)
}

/// The UINT8 NUMERIC question `id`, of prompt `prompt`, at byte 1 of the VarStore `var_store`.
fn numeric(id: u16, prompt: u16, var_store: u16) -> Vec<u8> {
    let data = [
        question_header(prompt, HELP, id, var_store, 1),
        // Flags, MinValue, MaxValue, Step
        [UINT8_DECIMAL, 0, 255, 1].to_vec(),
    ]
    .concat();
    [op(EFI_IFR_NUMERIC_OP, true, &data), end()].concat()
}
