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

//! The HII package list that `first-store-password-forms` and
//! `rt-data-first-store-password-forms` register in the HII database, for the UEFI Shell
//! scenario `shell-first-store-password` and the Linux scenario `hii-first-store-password` of
//! `tests/qemu/scenarios.tsv`: a first form set whose VARSTORE_EFI of VarStoreId 1, FirstStore,
//! is the first VarStore of that id in the form package, with a UINT64 NUMERIC over bytes 0..8
//! and a UINT8 NUMERIC at byte 16; then a second form set whose VARSTORE_EFI of VarStoreId 1,
//! PasswordStore, holds the 16 bytes of its PASSWORD from VarOffset 0. edk2-stable202608
//! ConfigKeywordHandler.c FindStorageFromVarId (:1520) takes the first VarStore of a question's
//! VarStoreId in the form package, so a keyword request of that PASSWORD reads and writes
//! FirstStore's bytes 0..16: the driver creates FirstStore with the password "First" there,
//! and PasswordStore with "Second", when they are missing.

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

/// The GUID of the package list and of its second form set, which holds the PASSWORD.
const PASSWORD_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001d00");
/// The vendor GUID of FirstStore.
pub(crate) const FIRST_STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001d01");
/// The GUID of the first form set.
const FIRST_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001d02");
/// The vendor GUID of PasswordStore.
pub(crate) const PASSWORD_STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001d03");
/// The names of the variables of the VARSTORE_EFIs.
pub(crate) const FIRST_STORE_NAME: &CStr16 = cstr16!("FirstStore");
pub(crate) const PASSWORD_STORE_NAME: &CStr16 = cstr16!("PasswordStore");
/// The attributes of those variables and of their VARSTORE_EFIs.
pub(crate) const STORE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// The bytes that the driver creates FirstStore with: the password "First" in UCS-2, NUL-padded
/// to its MaxSize of 8 characters, as a string question keeps it (UEFI 2.11 §33.2.5.4.9), then
/// 5, which "Setting beside the first store password" holds.
pub(crate) const FIRST_STORE_DATA: [u8; 17] = [
    b'F', 0, b'i', 0, b'r', 0, b's', 0, b't', 0, 0, 0, 0, 0, 0, 0, 5,
];
/// The bytes that the driver creates PasswordStore with: the password "Second", likewise.
pub(crate) const PASSWORD_STORE_DATA: [u8; 16] = [
    b'S', 0, b'e', 0, b'c', 0, b'o', 0, b'n', 0, b'd', 0, 0, 0, 0, 0,
];

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const PASSWORD: u16 = 4;
const PASSWORD_PREFIX: u16 = 5;
const BESIDE_PASSWORD: u16 = 6;
const STRINGS: [&str; 6] = [
    "English",
    "uefisettings QEMU first store password forms",
    "A password question whose VarStoreId an earlier form set declares first",
    "First store password",
    "First store password prefix as a number",
    "Setting beside the first store password",
];

/// The VarStoreId of FirstStore in the first form set and of PasswordStore in the second.
const VAR_STORE_ID: u16 = 1;
/// The MinSize and MaxSize of the PASSWORD, in characters: its UCS-2 string takes 16 bytes.
const PASSWORD_MIN_SIZE: u16 = 4;
const PASSWORD_MAX_SIZE: u16 = 8;
/// EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT64_DECIMAL: u8 = 0x13;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(
        PASSWORD_FORM_SET,
        &[strings_package(STRINGS), form_package()],
    )
}

/// The FORM_SET op of the form set `guid`, which opens its scope.
fn form_set_op(guid: Guid) -> Vec<u8> {
    let form_set = [
        &guid.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    op(EFI_IFR_FORM_SET_OP, true, &form_set)
}

/// The VARSTORE_EFI of VAR_STORE_ID of the variable `name`, `vendor`, of `size` bytes.
fn var_store_efi(vendor: Guid, size: usize, name: &[u8]) -> Vec<u8> {
    op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &VAR_STORE_ID.to_le_bytes()[..],
            &vendor.to_bytes(),
            &STORE_ATTRIBUTES.bits().to_le_bytes(),
            &u16::try_from(size)
                .expect("the variable fits a VARSTORE_EFI")
                .to_le_bytes(),
            name,
        ]
        .concat(),
    )
}

/// The form package: the first form set, its VarStore and one form that holds the questions over
/// and beside the password's bytes there, then the second form set, its VarStore and one form
/// that holds the PASSWORD.
fn form_package() -> Vec<u8> {
    let password_prefix = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(PASSWORD_PREFIX, HELP, 2, VAR_STORE_ID, 0),
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
                question_header(BESIDE_PASSWORD, HELP, 3, VAR_STORE_ID, 16),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 255, 1].to_vec(),
            ]
            .concat(),
        ),
        end(),
    ]
    .concat();
    let password = op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header(PASSWORD, HELP, 1, VAR_STORE_ID, 0),
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
        form_set_op(FIRST_FORM_SET),
        var_store_efi(FIRST_STORE_VENDOR, FIRST_STORE_DATA.len(), b"FirstStore\0"),
        op(EFI_IFR_FORM_OP, true, &form),
        password_prefix,
        beside_password,
        end(), // of the form
        end(), // of the first form set
        form_set_op(PASSWORD_FORM_SET),
        var_store_efi(
            PASSWORD_STORE_VENDOR,
            PASSWORD_STORE_DATA.len(),
            b"PasswordStore\0",
        ),
        op(EFI_IFR_FORM_OP, true, &form),
        password,
        end(), // of the form
        end(), // of the second form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}
