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

//! The HII package list that `dropped-password-forms` registers in the HII database, for the
//! UEFI Shell scenario `shell-dropped-password` of `tests/qemu/scenarios.tsv`: a form package of
//! two form sets on one EFI variable. The first keeps a UINT8 NUMERIC at byte 20 of it; the
//! second a PASSWORD at bytes 0 to 19, then, outside its form, a VARSTORE op shorter than its
//! minimum, which UEFI 2.11 §33.2.5.10.1 calls malformed, so that `uefisettings` ignores that
//! form set.

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
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the package list and of its first form set.
const FIRST_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000f00");
/// The GUID of the second form set.
const SECOND_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000f01");
/// The vendor GUID of the variable, which tests/qemu/vars/dropped-password.json creates.
const VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000f02");
/// The name of the variable, NUL-terminated.
const NAME: &[u8] = b"UefisettingsDropped\0";
/// The Attributes of the VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;
/// The Size of the VARSTORE_EFI: the password, then the setting.
const SIZE: u16 = 21;

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const SHARED_SETTING: u16 = 4;
const PASSWORD: u16 = 5;
const STRINGS: [&str; 5] = [
    "English",
    "uefisettings QEMU dropped password forms",
    "A password in a form set that uefisettings ignores",
    "Shared setting",
    "Password",
];

/// The VarStoreId of the variable in each form set.
const VAR_STORE: u16 = 1;

/// The MaxSize of the PASSWORD, in characters: its UCS-2 string takes bytes 0 to 19.
const PASSWORD_MAX_SIZE: u16 = 10;
/// The Data of a VARSTORE op that ends after 4 of the 20 bytes before its Name.
const SHORT_VAR_STORE: [u8; 4] = [0; 4];

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FIRST_FORM_SET, &[strings_package(STRINGS), form_package()])
}

/// The form package: the two form sets.
fn form_package() -> Vec<u8> {
    let shared_setting = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(SHARED_SETTING, HELP, 1, VAR_STORE, 20),
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
            question_header(PASSWORD, HELP, 2, VAR_STORE, 0),
            [1u16.to_le_bytes(), PASSWORD_MAX_SIZE.to_le_bytes()].concat(), // MinSize, MaxSize
        ]
        .concat(),
    );
    let body = [
        form_set(FIRST_FORM_SET, &shared_setting, &[]),
        form_set(
            SECOND_FORM_SET,
            &password,
            &op(EFI_IFR_VARSTORE_OP, false, &SHORT_VAR_STORE),
        ),
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// A form set of `guid` that declares the variable and holds a form of `question`, then the ops
/// `after`, outside the form.
fn form_set(guid: Guid, question: &[u8], after: &[u8]) -> Vec<u8> {
    let form_set = [
        &guid.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    let var_store = op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &VAR_STORE.to_le_bytes()[..],
            &VENDOR.to_bytes(),
            &NV_BS_RT.to_le_bytes(),
            &SIZE.to_le_bytes(),
            NAME,
        ]
        .concat(),
    );
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        var_store,
        op(EFI_IFR_FORM_OP, true, &form),
        question.to_vec(),
        end(), // of the form
        after.to_vec(),
        end(), // of the form set
    ]
    .concat()
}
