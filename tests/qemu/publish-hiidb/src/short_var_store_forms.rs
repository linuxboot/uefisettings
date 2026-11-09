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

//! The HII package list that `short-var-store-forms` registers in the HII database, and that
//! `rt-data-short-var-store-forms` registers before it publishes the database, for
//! `tests/qemu/guest/tests/hii_short_var_store.rs` and the UEFI Shell scenario
//! `shell-short-var-store` of `tests/qemu/scenarios.tsv`: a form set whose VARSTORE_EFI has the
//! form before UEFI 2.3.1, which ends at Attributes, so that each question keeps its value alone
//! in the EFI variable that its VarName names, of the store's Guid (edk2-stable202608
//! SetupBrowserDxe/IfrParse.c CreateQuestion, Setup.c GetQuestionValue), and so do the GET and
//! SET of its expressions. `tests/qemu/vars/short-var-store.json` creates the variables, but
//! not ShortVarD, which set creates.
//!
//! edk2-stable202608 IfrParse.c CreateStorage reads the Size and the Name of the 2.3.1 form past
//! the 24 bytes of the short op, in the op after it. That op is the FORM of FormId [`FORM_ID`],
//! below 256: its OpCode and Length make the Size, and its FormId the Name, which the FormId's
//! high byte, 0x00, ends.

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
use crate::hii_package::EFI_IFR_CHECKBOX_OP;
use crate::hii_package::EFI_IFR_EQUAL_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_GET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OPTION_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_SET_OP;
use crate::hii_package::EFI_IFR_SUPPRESS_IF_OP;
use crate::hii_package::EFI_IFR_THIS_OP;
use crate::hii_package::EFI_IFR_UINT8_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_WRITE_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000b00");
/// The Guid of the VARSTORE_EFI, the vendor GUID of each variable of a VarName.
const STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000b01");
/// The Attributes of the VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const SHORT_NUMERIC: u16 = 4;
const SHORT_ONE_OF: u16 = 5;
const SHORT_CHECKBOX: u16 = 6;
const SHORT_PASSWORD: u16 = 7;
const DISABLED: u16 = 8;
const ENABLED: u16 = 9;
// The VarNames, whose strings name the variables
const SHORT_VAR_A: u16 = 10;
const SHORT_VAR_B: u16 = 11;
const SHORT_VAR_C: u16 = 12;
const SHORT_VAR_PW: u16 = 13;
const SHORT_CREATED: u16 = 14;
const SHORT_VAR_D: u16 = 15;
const STRINGS: [&str; 15] = [
    "English",
    "uefisettings QEMU short VARSTORE_EFI forms",
    "Questions on a VARSTORE_EFI of the form before UEFI 2.3.1",
    "Short numeric",
    "Short one-of",
    "Short checkbox",
    "Short password",
    "Disabled",
    "Enabled",
    "ShortVarA",
    "ShortVarB",
    "ShortVarC",
    "ShortVarPw",
    "Short created",
    "ShortVarD",
];

/// The VarStoreId of the VARSTORE_EFI.
const VAR_STORE: u16 = 1;
/// The FormId of the form, which follows the VARSTORE_EFI.
const FORM_ID: u16 = 1;
const _: () = assert!(
    FORM_ID < 0x100,
    "the FormId's high byte ends the Name that edk2 reads"
);

/// The MaxSize of the PASSWORD, in characters: its UCS-2 string takes all 20 bytes of ShortVarPw.
const PASSWORD_MAX_SIZE: u16 = 10;
/// EFI_IFR_TYPE_NUM_SIZE_8, the type of a UINT8 value.
const NUM_SIZE_8: u8 = 0x00;
/// EFI_IFR_NUMERIC_SIZE_2 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT16_DECIMAL: u8 = 0x11;
/// The ShortVarA value that the SUPPRESS_IF hides "Short checkbox" for.
const SUPPRESSING_VALUE: u8 = 5;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FORM_SET, &[strings_package(STRINGS), form_package()])
}

/// The form package: the form set, its VARSTORE_EFI of the form before UEFI 2.3.1, then the form
/// that holds the questions.
fn form_package() -> Vec<u8> {
    let form_set = [
        &FORM_SET.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    // VarStoreId, Guid and Attributes, without the Size and Name of UEFI 2.3.1
    let store = op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &VAR_STORE.to_le_bytes()[..],
            &STORE_VENDOR.to_bytes(),
            &NV_BS_RT.to_le_bytes(),
        ]
        .concat(),
    );
    let numeric = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(SHORT_NUMERIC, HELP, 1, VAR_STORE, SHORT_VAR_A),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 255, 1].to_vec(),
            ]
            .concat(),
        ),
        end(),
    ]
    .concat();
    let options = [(DISABLED, 0), (ENABLED, 1)].map(|(text, value)| {
        op(
            EFI_IFR_ONE_OF_OPTION_OP,
            false,
            &[&text.to_le_bytes()[..], &[0, NUM_SIZE_8, value]].concat(),
        )
    });
    let one_of = [
        op(
            EFI_IFR_ONE_OF_OP,
            true,
            &[
                question_header(SHORT_ONE_OF, HELP, 2, VAR_STORE, SHORT_VAR_B),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 1, 0].to_vec(),
            ]
            .concat(),
        ),
        options.concat(),
        end(),
    ]
    .concat();
    // hidden while the UINT8 of ShortVarA is SUPPRESSING_VALUE; its WRITE sets ShortVarB to its
    // value
    let checkbox = [
        op(EFI_IFR_SUPPRESS_IF_OP, true, &[]),
        op(EFI_IFR_GET_OP, true, &store_operand(SHORT_VAR_A)),
        op(EFI_IFR_UINT8_OP, false, &[SUPPRESSING_VALUE]),
        op(EFI_IFR_EQUAL_OP, false, &[]),
        end(), // of the expression
        op(
            EFI_IFR_CHECKBOX_OP,
            true,
            &[
                question_header(SHORT_CHECKBOX, HELP, 3, VAR_STORE, SHORT_VAR_C),
                [0].to_vec(), // Flags
            ]
            .concat(),
        ),
        op(EFI_IFR_WRITE_OP, false, &[]),
        op(EFI_IFR_THIS_OP, true, &[]),
        op(EFI_IFR_SET_OP, false, &store_operand(SHORT_VAR_B)),
        end(), // of the expression
        end(), // of the CHECKBOX
        end(), // of the SUPPRESS_IF
    ]
    .concat();
    // on ShortVarD, which no variable holds until set creates it
    let created = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(SHORT_CREATED, HELP, 5, VAR_STORE, SHORT_VAR_D),
                // Flags, then MinValue, MaxValue and Step
                [UINT16_DECIMAL].to_vec(),
                [0u16, u16::MAX, 1].map(u16::to_le_bytes).concat(),
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
            question_header(SHORT_PASSWORD, HELP, 4, VAR_STORE, SHORT_VAR_PW),
            [1u16.to_le_bytes(), PASSWORD_MAX_SIZE.to_le_bytes()].concat(), // MinSize, MaxSize
        ]
        .concat(),
    );
    let form = [FORM_ID.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        store,
        op(EFI_IFR_FORM_OP, true, &form),
        numeric,
        one_of,
        checkbox,
        created,
        password,
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The operand of a GET or SET of the UINT8 in the variable of VarName `var_name` (UEFI 2.11
/// §33.3.8.3.27, §33.3.8.3.66): VarStoreId, VarStoreInfo and VarStoreType.
fn store_operand(var_name: u16) -> Vec<u8> {
    [
        &VAR_STORE.to_le_bytes()[..],
        &var_name.to_le_bytes(),
        &[NUM_SIZE_8],
    ]
    .concat()
}
