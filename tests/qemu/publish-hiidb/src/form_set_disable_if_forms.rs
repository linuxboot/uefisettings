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

//! The HII package list that `form-set-disable-if-forms` registers in the HII database, for the
//! scenarios `hii-form-set-disable-if` and `shell-form-set-disable-if` of
//! `tests/qemu/scenarios.tsv`: a form set on the VARSTORE_EFI UefisettingsFormSetDisableIf, which
//! `tests/qemu/vars/form-set-disable-if.json` creates, whose forms but the first are in DISABLE_IFs
//! outside forms, which UEFI 2.11 §33.3.8.3.14 has rely on constants only. The first form holds
//! Gate, Shown, in a SUPPRESS_IF on Hidden holding 1, and O, over the bytes of the PASSWORD; a
//! true DISABLE_IF holds the form of Hidden and of that PASSWORD; a DISABLE_IF on Gate holds the
//! form of After; and a false DISABLE_IF holds a true SUPPRESS_IF, then the form of Later. Each
//! question but the PASSWORD is a UINT8 NUMERIC. The x-UEFI-ns keywords HiddenKeyword and
//! ShownKeyword name Hidden and Shown.

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
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_DISABLE_IF_OP;
use crate::hii_package::EFI_IFR_EQ_ID_VAL_OP;
use crate::hii_package::EFI_IFR_FALSE_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_SUPPRESS_IF_OP;
use crate::hii_package::EFI_IFR_TRUE_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002400");
/// The vendor GUID of UefisettingsFormSetDisableIf.
const STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002401");
/// The Name of UefisettingsFormSetDisableIf, NUL-terminated.
const STORE_NAME: &[u8] = b"UefisettingsFormSetDisableIf\0";
/// The size of UefisettingsFormSetDisableIf: Gate, Hidden, Shown, After and Later, 3 bytes that
/// no question holds, then the password.
const STORE_SIZE: u16 = 24;
/// The VarStoreId of UefisettingsFormSetDisableIf.
const VAR_STORE: u16 = 1;
/// The Attributes of the VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;

// The strings, from string ID 2, after the language name: the prompts of Hidden and Shown first,
// so that the x-UEFI-ns strings name them. Each question's QuestionId is its prompt's.
const HIDDEN: u16 = 2;
const SHOWN: u16 = 3;
const GATE: u16 = 4;
const AFTER: u16 = 5;
const LATER: u16 = 6;
const O: u16 = 7;
const PASSWORD: u16 = 8;
const TITLE: u16 = 9;
const HELP: u16 = 10;
const STRINGS: [&str; 10] = [
    "English",
    "Hidden",
    "Shown",
    "Gate",
    "After",
    "Later",
    "O",
    "Password",
    "uefisettings QEMU form set DISABLE_IF forms",
    "Forms in DISABLE_IFs outside forms",
];
/// The language and the strings, from string ID 1, of the x-UEFI-ns strings package: the
/// keywords of Hidden and Shown (UEFI 2.11 §35.2.1.6).
const KEYWORD_LANGUAGE: &[u8] = b"x-UEFI-ns\0";
const KEYWORDS: [&str; 3] = ["UefiNameSpace", "HiddenKeyword", "ShownKeyword"];

/// The byte of each UINT8 NUMERIC, and the first of the PASSWORD's, which O's overlaps.
const GATE_OFFSET: u16 = 0;
const HIDDEN_OFFSET: u16 = 1;
const SHOWN_OFFSET: u16 = 2;
const AFTER_OFFSET: u16 = 3;
const LATER_OFFSET: u16 = 4;
const PASSWORD_OFFSET: u16 = 8;
/// The MinSize and MaxSize of the PASSWORD, in characters: its UCS-2 string takes bytes 8 to 23.
const PASSWORD_MIN_SIZE: u16 = 1;
const PASSWORD_MAX_SIZE: u16 = 8;
/// What Gate and Hidden hold where the DISABLE_IF on Gate disables, and where the SUPPRESS_IF on
/// Hidden suppresses.
const TRUE_VALUE: u16 = 1;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(
        FORM_SET,
        &[
            strings_package(STRINGS),
            language_strings_package(KEYWORD_LANGUAGE, KEYWORDS),
            form_package(),
        ],
    )
}

/// The form package: the form set, which declares UefisettingsFormSetDisableIf first, then holds
/// the forms in the order of the module's documentation.
fn form_package() -> Vec<u8> {
    let var_store = op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &VAR_STORE.to_le_bytes()[..],
            &STORE_VENDOR.to_bytes(),
            &NV_BS_RT.to_le_bytes(),
            &STORE_SIZE.to_le_bytes(),
            STORE_NAME,
        ]
        .concat(),
    );
    let first = form(
        1,
        &[
            uint8_numeric(GATE, GATE_OFFSET),
            conditional(
                EFI_IFR_SUPPRESS_IF_OP,
                &eq_id_val(HIDDEN),
                &uint8_numeric(SHOWN, SHOWN_OFFSET),
            ),
            uint8_numeric(O, PASSWORD_OFFSET),
        ]
        .concat(),
    );
    let hidden = form(
        2,
        &[uint8_numeric(HIDDEN, HIDDEN_OFFSET), password()].concat(),
    );
    let after = form(3, &uint8_numeric(AFTER, AFTER_OFFSET));
    let later = [
        conditional(EFI_IFR_SUPPRESS_IF_OP, &constant(EFI_IFR_TRUE_OP), &[]),
        form(4, &uint8_numeric(LATER, LATER_OFFSET)),
    ]
    .concat();
    let body = [
        form_set_op(FORM_SET, TITLE, HELP),
        var_store,
        first,
        conditional(EFI_IFR_DISABLE_IF_OP, &constant(EFI_IFR_TRUE_OP), &hidden),
        conditional(EFI_IFR_DISABLE_IF_OP, &eq_id_val(GATE), &after),
        conditional(EFI_IFR_DISABLE_IF_OP, &constant(EFI_IFR_FALSE_OP), &later),
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The conditional op `op_code`, whose scope holds the expression `condition`, then `ops`.
fn conditional(op_code: u8, condition: &[u8], ops: &[u8]) -> Vec<u8> {
    [
        op(op_code, true, &[]),
        condition.to_vec(),
        ops.to_vec(),
        end(),
    ]
    .concat()
}

/// The expression of the constant op `op_code`, EFI_IFR_TRUE or EFI_IFR_FALSE.
fn constant(op_code: u8) -> Vec<u8> {
    op(op_code, false, &[])
}

/// An EFI_IFR_EQ_ID_VAL: whether the question of QuestionId `question_id` holds TRUE_VALUE.
fn eq_id_val(question_id: u16) -> Vec<u8> {
    op(
        EFI_IFR_EQ_ID_VAL_OP,
        false,
        &[question_id.to_le_bytes(), TRUE_VALUE.to_le_bytes()].concat(),
    )
}

/// A form of FormId `id` that holds `questions`.
fn form(id: u16, questions: &[u8]) -> Vec<u8> {
    let form = [id.to_le_bytes(), TITLE.to_le_bytes()].concat();
    [op(EFI_IFR_FORM_OP, true, &form), questions.to_vec(), end()].concat()
}

/// A UINT8 NUMERIC prompted, and of QuestionId, `prompt` at byte `offset` of the variable.
fn uint8_numeric(prompt: u16, offset: u16) -> Vec<u8> {
    [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(prompt, HELP, prompt, VAR_STORE, offset),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 255, 1].to_vec(),
            ]
            .concat(),
        ),
        end(),
    ]
    .concat()
}

/// The PASSWORD at bytes PASSWORD_OFFSET to PASSWORD_OFFSET + 2 * PASSWORD_MAX_SIZE - 1 of the
/// variable.
fn password() -> Vec<u8> {
    op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header(PASSWORD, HELP, PASSWORD, VAR_STORE, PASSWORD_OFFSET),
            [
                PASSWORD_MIN_SIZE.to_le_bytes(),
                PASSWORD_MAX_SIZE.to_le_bytes(),
            ]
            .concat(),
        ]
        .concat(),
    )
}
