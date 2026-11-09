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

//! The HII package list that `nested-password-forms` and `rt-data-nested-password-forms` register
//! in the HII database, for `tests/qemu/guest/tests/hii_nested_password.rs` and the UEFI Shell
//! scenario `shell-nested-password` of `tests/qemu/scenarios.tsv`: a form set that declares its
//! VarStores in the scopes of FormSet-level conditions, which UEFI 2.11 §33.2.5.1 admits.
//! NestedPassword, under a SUPPRESS_IF, keeps a plaintext password in bytes 0..16, which a
//! PASSWORD question names, with a UINT64 NUMERIC over bytes 0..8 of it and a CHECKBOX beside it,
//! at byte 16. VarStore 2 is declared twice: NestedChoiceDecoy under a DISABLE_IF whose condition
//! is TRUE, which edk2 never creates, then NestedChoice under one whose condition is FALSE, which
//! a second CHECKBOX names. A second form set declares NestedPassword directly, with a UINT64
//! NUMERIC over bytes 0..8 of the password: where the PASSWORD's VarStore is unknown, it would show
//! them. The driver creates NestedPassword and NestedChoice when they are missing, never
//! NestedChoiceDecoy.

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
use crate::hii_package::EFI_IFR_CHECKBOX_OP;
use crate::hii_package::EFI_IFR_DISABLE_IF_OP;
use crate::hii_package::EFI_IFR_FALSE_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_SUPPRESS_IF_OP;
use crate::hii_package::EFI_IFR_TRUE_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001c00");
/// The GUID of the form set that declares NestedPassword directly.
const READER_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001c02");
/// The vendor GUID of the variables of the VARSTORE_EFIs.
pub(crate) const VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001c01");
/// The attributes of those variables and of their VARSTORE_EFIs.
pub(crate) const ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// The variable of the VARSTORE_EFI under the SUPPRESS_IF.
pub(crate) const PASSWORD_STORE_NAME: &CStr16 = cstr16!("NestedPassword");
/// The bytes that the driver creates NestedPassword with: the password "Kumquat" in UCS-2,
/// NUL-padded to its MaxSize of 8 characters, as a string question keeps it (UEFI 2.11
/// §33.2.5.4.9), then 1, which the CHECKBOX beside it holds.
pub(crate) const PASSWORD_STORE_DATA: [u8; 17] = [
    b'K', 0, b'u', 0, b'm', 0, b'q', 0, b'u', 0, b'a', 0, b't', 0, 0, 0, 1,
];
/// The variable of the VARSTORE_EFI under the DISABLE_IF whose condition is FALSE.
pub(crate) const CHOICE_STORE_NAME: &CStr16 = cstr16!("NestedChoice");
/// The byte that the driver creates NestedChoice with.
pub(crate) const CHOICE_STORE_DATA: [u8; 1] = [0];

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const NESTED_PASSWORD: u16 = 4;
const PASSWORD_PREFIX: u16 = 5;
const BESIDE_PASSWORD: u16 = 6;
const CHOICE: u16 = 7;
const READER_PASSWORD_PREFIX: u16 = 8;
const STRINGS: [&str; 8] = [
    "English",
    "uefisettings QEMU nested password forms",
    "VarStores declared in the scopes of FormSet-level conditions",
    "Nested password",
    "Nested password prefix as a number",
    "Nested setting beside the password",
    "Nested choice",
    "Nested password prefix from another form set",
];

/// The VarStoreId of NestedPassword.
const PASSWORD_STORE: u16 = 1;
/// The VarStoreId of NestedChoiceDecoy and NestedChoice.
const CHOICE_STORE: u16 = 2;
/// The MinSize and MaxSize of the PASSWORD, in characters: its UCS-2 string takes 16 bytes.
const PASSWORD_MIN_SIZE: u16 = 4;
const PASSWORD_MAX_SIZE: u16 = 8;
/// EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT64_DECIMAL: u8 = 0x13;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FORM_SET, &[strings_package(STRINGS), form_package()])
}

/// The form package: the form set whose VarStores sit in the scopes of FormSet-level conditions,
/// with one form that holds its questions, then the one that declares NestedPassword directly.
fn form_package() -> Vec<u8> {
    let password_store = var_store_efi(PASSWORD_STORE, &PASSWORD_STORE_DATA, b"NestedPassword\0");
    let decoy_store = var_store_efi(CHOICE_STORE, &CHOICE_STORE_DATA, b"NestedChoiceDecoy\0");
    let choice_store = var_store_efi(CHOICE_STORE, &CHOICE_STORE_DATA, b"NestedChoice\0");
    let password = op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header(NESTED_PASSWORD, HELP, 1, PASSWORD_STORE, 0),
            [
                PASSWORD_MIN_SIZE.to_le_bytes(),
                PASSWORD_MAX_SIZE.to_le_bytes(),
            ]
            .concat(),
        ]
        .concat(),
    );
    let body = [
        form_set(
            FORM_SET,
            &[
                in_condition(EFI_IFR_SUPPRESS_IF_OP, EFI_IFR_TRUE_OP, &password_store),
                in_condition(EFI_IFR_DISABLE_IF_OP, EFI_IFR_TRUE_OP, &decoy_store),
                in_condition(EFI_IFR_DISABLE_IF_OP, EFI_IFR_FALSE_OP, &choice_store),
            ],
            &[
                password,
                password_prefix(PASSWORD_PREFIX),
                checkbox(BESIDE_PASSWORD, 3, PASSWORD_STORE, 16),
                checkbox(CHOICE, 4, CHOICE_STORE, 0),
            ],
        ),
        form_set(
            READER_FORM_SET,
            core::slice::from_ref(&password_store),
            &[password_prefix(READER_PASSWORD_PREFIX)],
        ),
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// A form set of `guid` whose ops `declarations` come before one form that holds `questions`.
fn form_set(guid: Guid, declarations: &[Vec<u8>], questions: &[Vec<u8>]) -> Vec<u8> {
    let form_set = [
        &guid.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        declarations.concat(),
        op(EFI_IFR_FORM_OP, true, &form),
        questions.concat(),
        end(), // of the form
        end(), // of the form set
    ]
    .concat()
}

/// A UINT64 NUMERIC prompted by `prompt` over bytes 0..8 of NestedPassword.
fn password_prefix(prompt: u16) -> Vec<u8> {
    [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(prompt, HELP, 2, PASSWORD_STORE, 0),
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
    .concat()
}

/// A VARSTORE_EFI of `id` on the variable `name`, NUL-terminated, of VENDOR, sized for `data`.
fn var_store_efi(id: u16, data: &[u8], name: &[u8]) -> Vec<u8> {
    op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &id.to_le_bytes()[..],
            &VENDOR.to_bytes(),
            &ATTRIBUTES.bits().to_le_bytes(),
            &u16::try_from(data.len())
                .expect("the variable fits a VARSTORE_EFI")
                .to_le_bytes(),
            name,
        ]
        .concat(),
    )
}

/// `body` in the scope of the SUPPRESS_IF or DISABLE_IF `condition_op` on the constant
/// `constant_op`.
fn in_condition(condition_op: u8, constant_op: u8, body: &[u8]) -> Vec<u8> {
    [
        op(condition_op, true, &[]),
        op(constant_op, false, &[]),
        body.to_vec(),
        end(),
    ]
    .concat()
}

/// A CHECKBOX prompted by `prompt`, of question `id`, over the byte at `offset` of VarStore
/// `var_store`.
fn checkbox(prompt: u16, id: u16, var_store: u16, offset: u16) -> Vec<u8> {
    [
        op(
            EFI_IFR_CHECKBOX_OP,
            true,
            &[
                question_header(prompt, HELP, id, var_store, offset),
                [0].to_vec(),
            ]
            .concat(), // Flags
        ),
        end(),
    ]
    .concat()
}
