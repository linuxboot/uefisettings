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

//! The HII package list that `rt-data-readwrite-forms` registers in the HII database before it
//! publishes the database, for `tests/qemu/guest/tests/hii_readwrite.rs` and the UEFI Shell
//! scenario `shell-readwrite` of `tests/qemu/scenarios.tsv`: a form set whose questions take
//! their values through READ and WRITE expressions (UEFI 2.11 §33.2.5.4.1), over the
//! VARSTORE_EFI ReadWriteData, which the driver creates when it is missing, and questions without
//! a VarStore that get and set refuse, each for its own reason. One more question over
//! ReadWriteData takes its value from an EFI_IFR_VALUE expression instead, which makes it
//! read-only (UEFI 2.11 §33.3.8.3.88). The VARSTORE AbsentBuffer has no variable.

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
use crate::hii_package::strings_package;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_ADD_OP;
use crate::hii_package::EFI_IFR_AND_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_GET_OP;
use crate::hii_package::EFI_IFR_MAP_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OPTION_OP;
use crate::hii_package::EFI_IFR_QUESTION_REF1_OP;
use crate::hii_package::EFI_IFR_READ_OP;
use crate::hii_package::EFI_IFR_SET_OP;
use crate::hii_package::EFI_IFR_THIS_OP;
use crate::hii_package::EFI_IFR_TO_UINT_OP;
use crate::hii_package::EFI_IFR_UINT16_OP;
use crate::hii_package::EFI_IFR_UINT8_OP;
use crate::hii_package::EFI_IFR_VALUE_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;
use crate::hii_package::EFI_IFR_WRITE_OP;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000200");
/// The vendor GUID of ReadWriteData and AbsentBuffer.
pub(crate) const STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000201");
/// The name of the variable of the VARSTORE_EFI.
pub(crate) const STORE_NAME: &CStr16 = cstr16!("ReadWriteData");
/// The attributes of that variable and of its VARSTORE_EFI.
pub(crate) const STORE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// The bytes that the driver creates ReadWriteData with: byte 0, which "Mapped choice" keeps,
/// holds no option; "Linked value" holds 4 at byte 1, which its WRITE copies to byte 2 and, plus
/// 0x100, to bytes 4 and 5; "Absent target" holds 0 at byte 3; byte 6 is what "Write only" sets,
/// "Read transformed" holds 0xEE at byte 7, which its READ shows plus 1, and "Computed value"
/// holds 0x11 at byte 8, which its VALUE hides.
pub(crate) const STORE_DATA: [u8; 9] = [0x00, 0x04, 0x04, 0x00, 0x04, 0x01, 0x00, 0xEE, 0x11];

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const MAPPED_CHOICE: u16 = 4;
const LINKED_VALUE: u16 = 5;
const ABSENT_TARGET: u16 = 6;
const DRIVER_HELD: u16 = 7;
const NO_VALUE_SOURCE: u16 = 8;
const WRITE_ONLY: u16 = 9;
const READ_ONLY: u16 = 10;
const UNEVALUATED_READ: u16 = 11;
const FIRST: u16 = 12;
const SECOND: u16 = 13;
const THIRD: u16 = 14;
const READ_TRANSFORMED: u16 = 15;
const COMPUTED_VALUE: u16 = 16;
const STRINGS: [&str; 16] = [
    "English",
    "uefisettings QEMU read/write forms",
    "Questions that READ and WRITE expressions give and keep the values of",
    "Mapped choice",
    "Linked value",
    "Absent target",
    "Driver held",
    "No value source",
    "Write only",
    "Read only",
    "Unevaluated read",
    "First",
    "Second",
    "Third",
    "Read transformed",
    "Computed value",
];

// The VarStores
const STORE: u16 = 1;
const ABSENT_BUFFER: u16 = 2;
/// VarStoreId 0: no VarStore (UEFI 2.11 §33.3.8.2.2).
const NO_VAR_STORE: u16 = 0;

/// The QuestionId of "Linked value", whose value the VALUE of "Computed value" takes.
const LINKED_VALUE_QUESTION: u16 = 2;

/// EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT8_DECIMAL: u8 = 0x10;
/// EFI_IFR_TYPE_NUM_SIZE_8 and _16, the types of UINT8 and UINT16 values.
const NUM_SIZE_8: u8 = 0x00;
const NUM_SIZE_16: u8 = 0x01;
/// The question flag that has a browser call the driver's CallBack() (UEFI 2.11 §33.3.8.2.2).
const EFI_IFR_FLAG_CALLBACK: u8 = 0x04;

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
    let store = op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &STORE.to_le_bytes()[..],
            &STORE_VENDOR.to_bytes(),
            &STORE_ATTRIBUTES.bits().to_le_bytes(),
            &u16::try_from(STORE_DATA.len())
                .expect("ReadWriteData fits a VarStore")
                .to_le_bytes(),
            b"ReadWriteData\0",
        ]
        .concat(),
    );
    let absent_buffer = op(
        EFI_IFR_VARSTORE_OP,
        false,
        &[
            &STORE_VENDOR.to_bytes()[..],
            &ABSENT_BUFFER.to_le_bytes(),
            &1u16.to_le_bytes(), // Size
            b"AbsentBuffer\0",
        ]
        .concat(),
    );
    let this = || op(EFI_IFR_THIS_OP, false, &[]);
    let questions = [
        // READ maps byte 0 to an option, which WRITE sets there
        one_of(
            1,
            MAPPED_CHOICE,
            0,
            &[
                read(&[
                    store_op(EFI_IFR_GET_OP, STORE, 0, NUM_SIZE_8),
                    map(&[(1, 1), (2, 2), (3, 3)]),
                ]),
                write(&[this(), store_op(EFI_IFR_SET_OP, STORE, 0, NUM_SIZE_8)]),
            ],
        ),
        numeric(
            LINKED_VALUE_QUESTION,
            LINKED_VALUE,
            (STORE, 1),
            0,
            &[write(&[
                this(),
                store_op(EFI_IFR_SET_OP, STORE, 2, NUM_SIZE_8),
                this(),
                op(EFI_IFR_UINT16_OP, false, &0x100u16.to_le_bytes()),
                op(EFI_IFR_ADD_OP, false, &[]),
                store_op(EFI_IFR_SET_OP, STORE, 4, NUM_SIZE_16),
                op(EFI_IFR_AND_OP, false, &[]),
            ])],
        ),
        numeric(
            3,
            ABSENT_TARGET,
            (STORE, 3),
            0,
            &[write(&[
                this(),
                store_op(EFI_IFR_SET_OP, ABSENT_BUFFER, 0, NUM_SIZE_8),
            ])],
        ),
        one_of(4, DRIVER_HELD, EFI_IFR_FLAG_CALLBACK, &[]),
        numeric(5, NO_VALUE_SOURCE, (NO_VAR_STORE, 0), 0, &[]),
        numeric(
            6,
            WRITE_ONLY,
            (NO_VAR_STORE, 0),
            0,
            &[write(&[
                this(),
                store_op(EFI_IFR_SET_OP, STORE, 6, NUM_SIZE_8),
            ])],
        ),
        numeric(
            7,
            READ_ONLY,
            (NO_VAR_STORE, 0),
            0,
            &[read(&[store_op(EFI_IFR_GET_OP, STORE, 1, NUM_SIZE_8)])],
        ),
        numeric(
            8,
            UNEVALUATED_READ,
            (NO_VAR_STORE, 0),
            0,
            &[read(&[uint8(3), op(EFI_IFR_TO_UINT_OP, false, &[])])],
        ),
        // READ gives the stored byte plus 1, which replaces the stored value
        numeric(
            9,
            READ_TRANSFORMED,
            (STORE, 7),
            0,
            &[read(&[this(), uint8(1), op(EFI_IFR_ADD_OP, false, &[])])],
        ),
        // VALUE gives "Linked value" plus 0x10, never byte 8, and makes the question read-only
        numeric(
            10,
            COMPUTED_VALUE,
            (STORE, 8),
            0,
            &[value(&[
                op(
                    EFI_IFR_QUESTION_REF1_OP,
                    false,
                    &LINKED_VALUE_QUESTION.to_le_bytes(),
                ),
                uint8(0x10),
                op(EFI_IFR_ADD_OP, false, &[]),
            ])],
        ),
    ];
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        store,
        absent_buffer,
        op(EFI_IFR_FORM_OP, true, &form),
        questions.concat(),
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// EFI_IFR_QUESTION_HEADER: Prompt, Help, QuestionId, VarStoreId, VarOffset and Flags.
fn question_header(id: u16, prompt: u16, (var_store, offset): (u16, u16), flags: u8) -> Vec<u8> {
    [
        &prompt.to_le_bytes()[..],
        &HELP.to_le_bytes(),
        &id.to_le_bytes(),
        &var_store.to_le_bytes(),
        &offset.to_le_bytes(),
        &[flags],
    ]
    .concat()
}

/// A ONE_OF without a VarStore of question `id`, with `flags`, the options First (1), Second
/// (2) and Third (3), then `children`.
fn one_of(id: u16, prompt: u16, flags: u8, children: &[Vec<u8>]) -> Vec<u8> {
    let data = [
        question_header(id, prompt, (NO_VAR_STORE, 0), flags),
        // Flags, MinValue, MaxValue, Step
        [UINT8_DECIMAL, 1, 3, 0].to_vec(),
    ]
    .concat();
    let options = [(FIRST, 1), (SECOND, 2), (THIRD, 3)].map(|(text, value)| {
        op(
            EFI_IFR_ONE_OF_OPTION_OP,
            false,
            &[&text.to_le_bytes()[..], &[0, NUM_SIZE_8, value]].concat(),
        )
    });
    [
        op(EFI_IFR_ONE_OF_OP, true, &data),
        options.concat(),
        children.concat(),
        end(),
    ]
    .concat()
}

/// A UINT8 NUMERIC from 0 to 255 of question `id` at `var_store`, `(VarStoreId, VarOffset)`,
/// with `flags`, holding `children`.
fn numeric(
    id: u16,
    prompt: u16,
    var_store: (u16, u16),
    flags: u8,
    children: &[Vec<u8>],
) -> Vec<u8> {
    let data = [
        question_header(id, prompt, var_store, flags),
        // Flags, MinValue, MaxValue, Step
        [UINT8_DECIMAL, 0, 255, 1].to_vec(),
    ]
    .concat();
    [
        op(EFI_IFR_NUMERIC_OP, true, &data),
        children.concat(),
        end(),
    ]
    .concat()
}

/// A READ, then the expression of `ops` (UEFI 2.11 §33.3.8.3.58).
fn read(ops: &[Vec<u8>]) -> Vec<u8> {
    [op(EFI_IFR_READ_OP, false, &[]), expression(ops)].concat()
}

/// A WRITE, then the expression of `ops` (UEFI 2.11 §33.3.8.3.94).
fn write(ops: &[Vec<u8>]) -> Vec<u8> {
    [op(EFI_IFR_WRITE_OP, false, &[]), expression(ops)].concat()
}

/// An EFI_IFR_VALUE whose scope holds the ops of its expression (UEFI 2.11 §33.3.8.3.88), as
/// edk2's VfrCompile emits `value = <expression>;` (VfrSyntax.g vfrStatementValue).
fn value(ops: &[Vec<u8>]) -> Vec<u8> {
    [op(EFI_IFR_VALUE_OP, true, &[]), expression(ops), end()].concat()
}

/// The expression of `ops`: of more than one, the first opens a scope that an End closes, as
/// edk2's VfrCompile emits it.
fn expression(ops: &[Vec<u8>]) -> Vec<u8> {
    match ops {
        [] | [_] => ops.concat(),
        [first, rest @ ..] => {
            let mut first = first.clone();
            // the Scope bit of EFI_IFR_OP_HEADER (UEFI 2.11 §33.3.8.2.1)
            first[1] |= 0x80;
            [first, rest.concat(), end()].concat()
        }
    }
}

/// A GET or SET of the `value_type` value at VarOffset `offset` of VarStore `var_store`
/// (UEFI 2.11 §33.3.8.3.27, §33.3.8.3.66).
fn store_op(op_code: u8, var_store: u16, offset: u16, value_type: u8) -> Vec<u8> {
    let data = [
        &var_store.to_le_bytes()[..],
        &offset.to_le_bytes(),
        &[value_type],
    ]
    .concat();
    op(op_code, false, &data)
}

/// A MAP of UINT8 `(match, return)` pairs (UEFI 2.11 §33.3.8.3.38).
fn map(pairs: &[(u8, u8)]) -> Vec<u8> {
    let pairs: Vec<u8> = pairs
        .iter()
        .flat_map(|&(matched, returned)| [uint8(matched), uint8(returned)])
        .flatten()
        .collect();
    [op(EFI_IFR_MAP_OP, true, &[]), pairs, end()].concat()
}

/// The UINT8 `value` (UEFI 2.11 §33.3.8.3.86).
fn uint8(value: u8) -> Vec<u8> {
    op(EFI_IFR_UINT8_OP, false, &[value])
}
