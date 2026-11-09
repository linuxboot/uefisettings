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

//! The HII package list that `outside-form-set-password-forms` and
//! `rt-data-outside-form-set-password-forms` register in the HII database, for the UEFI Shell
//! scenario `shell-outside-form-set-password` and the Linux scenario
//! `hii-outside-form-set-password` of `tests/qemu/scenarios.tsv`: a PASSWORD question outside
//! any form set, which no Forms Browser shows but edk2-stable202608 ConfigKeywordHandler.c finds
//! (FindQuestionFromStringId walks the whole form package), on VarStoreId 1; then a form set
//! whose VARSTORE_EFI of VarStoreId 1, OutsidePassword, the variable that the driver creates
//! when it is missing, holds that password in bytes 0..16, which FindStorageFromVarId takes,
//! with a UINT64 NUMERIC over bytes 0..8 of the password and a UINT8 NUMERIC beside it, at byte
//! 16. UEFI 2.11 §33.2.5.1 declares variable stores within a form set, and edk2's VfrCompiler
//! emits no op outside one.

use alloc::vec::Vec;

use uefi::cstr16;
use uefi::guid;
use uefi::runtime::VariableAttributes;
use uefi::CStr16;
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
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001b00");
/// The vendor GUID of OutsidePassword.
pub(crate) const STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001b01");
/// The name of the variable of the VARSTORE_EFI.
pub(crate) const STORE_NAME: &CStr16 = cstr16!("OutsidePassword");
/// The attributes of that variable and of its VARSTORE_EFI.
pub(crate) const STORE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// The bytes that the driver creates OutsidePassword with: the password "Outside" in UCS-2,
/// NUL-padded to its MaxSize of 8 characters, as a string question keeps it (UEFI 2.11
/// §33.2.5.4.9), then 5, which "Setting beside the outside password" holds.
pub(crate) const STORE_DATA: [u8; 17] = [
    b'O', 0, b'u', 0, b't', 0, b's', 0, b'i', 0, b'd', 0, b'e', 0, 0, 0, 5,
];

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const OUTSIDE_PASSWORD: u16 = 4;
const PASSWORD_PREFIX: u16 = 5;
const BESIDE_PASSWORD: u16 = 6;
const STRINGS: [&str; 6] = [
    "English",
    "uefisettings QEMU outside form set password forms",
    "A password question outside any form set, and questions over and beside its bytes",
    "Outside password",
    "Outside password prefix as a number",
    "Setting beside the outside password",
];

/// The VarStoreId of OutsidePassword.
const OUTSIDE_PASSWORD_STORE: u16 = 1;
/// The MinSize and MaxSize of the PASSWORD, in characters: its UCS-2 string takes 16 bytes.
const PASSWORD_MIN_SIZE: u16 = 4;
const PASSWORD_MAX_SIZE: u16 = 8;
/// EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT64_DECIMAL: u8 = 0x13;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FORM_SET, &[strings_package(STRINGS), form_package()])
}

/// The form package: the PASSWORD, then the form set, its VarStore, and one form that holds the
/// questions over and beside the password's bytes.
fn form_package() -> Vec<u8> {
    let password = op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header(OUTSIDE_PASSWORD, HELP, 1, OUTSIDE_PASSWORD_STORE, 0),
            [
                PASSWORD_MIN_SIZE.to_le_bytes(),
                PASSWORD_MAX_SIZE.to_le_bytes(),
            ]
            .concat(),
        ]
        .concat(),
    );
    let form_set = [
        &FORM_SET.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    let store = op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &OUTSIDE_PASSWORD_STORE.to_le_bytes()[..],
            &STORE_VENDOR.to_bytes(),
            &STORE_ATTRIBUTES.bits().to_le_bytes(),
            &u16::try_from(STORE_DATA.len())
                .expect("OutsidePassword fits a VARSTORE_EFI")
                .to_le_bytes(),
            b"OutsidePassword\0",
        ]
        .concat(),
    );
    let password_prefix = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(PASSWORD_PREFIX, HELP, 2, OUTSIDE_PASSWORD_STORE, 0),
                // Flags, MinValue, MaxValue, Step
                [UINT64_DECIMAL].to_vec(),
                0u64.to_le_bytes().to_vec(),
                u64::MAX.to_le_bytes().to_vec(),
                1u64.to_le_bytes().to_vec(),
            ]
            .concat(),
        ),
        end(),
    ]
    .concat();
    let beside_password = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(BESIDE_PASSWORD, HELP, 3, OUTSIDE_PASSWORD_STORE, 16),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 255, 1].to_vec(),
            ]
            .concat(),
        ),
        end(),
    ]
    .concat();
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        password,
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        store,
        op(EFI_IFR_FORM_OP, true, &form),
        password_prefix,
        beside_password,
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}
