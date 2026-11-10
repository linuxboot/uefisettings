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

//! The package list that `publish-hiidb.efi keyword-kinds-forms` registers for a handle of
//! [`DRIVER_PATH`], for the UEFI Shell scenario `shell-keyword-kinds` of
//! `tests/qemu/scenarios.tsv`: a form set with a DATE that suppresses its year, a TIME that
//! suppresses its second, an ORDERED_LIST of at most 3 UINT8 options under EFI_IFR_UNIQUE_SET and
//! a REF5, each with an x-UEFI-ns keyword, on the VARSTORE_EFI KindStore, which the driver creates
//! with the VarStore's Attributes and Size when it is missing. The Keyword Handler finds the
//! questions by the device path package that the HII database adds for that handle, and writes
//! KindStore through SetVariable() with the VarStore's Attributes (edk2-stable202608
//! ConfigRouting.c RouteConfigRespForEfiVarStore :4837), which needs no ConfigAccess protocol.

use alloc::vec::Vec;

use uefi::cstr16;
use uefi::guid;
use uefi::runtime::VariableAttributes;
use uefi::CStr16;
use uefi::Guid;

use crate::hii_package::end;
use crate::hii_package::language_strings_package;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::question_header;
use crate::hii_package::strings_package;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_DATE_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OPTION_OP;
use crate::hii_package::EFI_IFR_ORDERED_LIST_OP;
use crate::hii_package::EFI_IFR_REF_OP;
use crate::hii_package::EFI_IFR_TIME_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::vendor_device_path;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001e00");
/// The vendor GUID of KindStore.
pub(crate) const STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001e01");
/// The name of the variable of the VARSTORE_EFI.
pub(crate) const STORE_NAME: &CStr16 = cstr16!("KindStore");
/// The attributes of that variable and of its VARSTORE_EFI: SetVariable() refuses to rewrite a
/// variable with other attributes (UEFI 2.11 §8.2.3).
pub(crate) const STORE_ATTRIBUTES: VariableAttributes =
    VariableAttributes::NON_VOLATILE.union(VariableAttributes::BOOTSERVICE_ACCESS);
/// The Vendor_GUID of the Vendor Device Path node of [`DRIVER_PATH`].
const DRIVER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001e02");
/// The device path of the handle that registers the package list, whose hex digits are the PATH of
/// its keywords.
pub(crate) static DRIVER_PATH: [u8; 24] = vendor_device_path(DRIVER_VENDOR);

// The strings, from string ID 2, after the language name: the prompts first, so that the x-UEFI-ns
// keywords take the same string IDs
const KIND_DATE: u16 = 2;
const KIND_TIME: u16 = 3;
const KIND_LIST: u16 = 4;
const KIND_REF: u16 = 5;
const TITLE: u16 = 6;
const HELP: u16 = 7;
const FIRST: u16 = 8;
const SECOND: u16 = 9;
const THIRD: u16 = 10;
const STRINGS: [&str; 10] = [
    "English",
    "Kind date",
    "Kind time",
    "Kind list",
    "Kind ref",
    "uefisettings QEMU keyword kinds forms",
    "A DATE, a TIME, an ORDERED_LIST and a REF5 with x-UEFI-ns keywords",
    "First",
    "Second",
    "Third",
];
/// The x-UEFI-ns strings: the language name, as edk2's DriverSample names it, then the keywords
/// of the prompts.
const KEYWORDS: [&str; 5] = [
    "UefiNameSpace",
    "KindDate",
    "KindTime",
    "KindList",
    "KindRef",
];

// The VarStore and the questions' VarOffsets
const STORE: u16 = 1;
const DATE_OFFSET: u16 = 0;
const TIME_OFFSET: u16 = 4;
const LIST_OFFSET: u16 = 8;
const REF_OFFSET: u16 = 12;

/// EFI_QF_DATE_YEAR_SUPPRESS (UEFI 2.11 §33.3.8.3.11).
const YEAR_SUPPRESS: u8 = 0x01;
/// QF_TIME_SECOND_SUPPRESS (UEFI 2.11 §33.3.8.3.78).
const SECOND_SUPPRESS: u8 = 0x04;
/// EFI_IFR_UNIQUE_SET (UEFI 2.11 §33.3.8.3.53).
const UNIQUE_SET: u8 = 0x01;
/// The MaxContainers of the ORDERED_LIST.
const MAX_CONTAINERS: u8 = 3;
/// EFI_IFR_TYPE_NUM_SIZE_8 (UEFI 2.11 §33.3.8.3.51).
const UINT8_TYPE: u8 = 0x00;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(
        FORM_SET,
        &[
            strings_package(STRINGS),
            language_strings_package(b"x-UEFI-ns\0", KEYWORDS),
            form_package(),
        ],
    )
}

/// The bytes that the driver creates KindStore with, as many as its VarStore's Size: the
/// EFI_HII_DATE 2024-03-31 at [`DATE_OFFSET`], the EFI_HII_TIME 12:34:56 at [`TIME_OFFSET`], the
/// items 1, 2 and 3 at [`LIST_OFFSET`], and at [`REF_OFFSET`] the EFI_HII_REF of the REF5 itself
/// (QuestionId 4, FormId 1, FormSetGuid [`FORM_SET`], DevicePath 0), its last 22 bytes, as edk2's
/// HiiConfigToBlock refuses a block past the variable's end (ConfigRouting.c :6383-6386); 0 in
/// bytes 7 and 11, which are in no question.
pub(crate) fn store_data() -> Vec<u8> {
    [
        &[0xE8, 0x07, 3, 31][..],
        &[12, 34, 56],
        &[0],
        &[1, 2, 3],
        &[0],
        &4u16.to_le_bytes(),
        &1u16.to_le_bytes(),
        &FORM_SET.to_bytes(),
        &0u16.to_le_bytes(),
    ]
    .concat()
}

/// The form package: the form set, its VarStore, and one form that holds the questions.
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
            &u16::try_from(store_data().len())
                .expect("KindStore fits a VarStore")
                .to_le_bytes(),
            b"KindStore\0",
        ]
        .concat(),
    );
    let options: Vec<u8> = [(FIRST, 1), (SECOND, 2), (THIRD, 3)]
        .into_iter()
        .flat_map(|(text, value)| {
            op(
                EFI_IFR_ONE_OF_OPTION_OP,
                false,
                &[&text.to_le_bytes()[..], &[0, UINT8_TYPE, value]].concat(),
            )
        })
        .collect();
    let list = [
        &question_header(KIND_LIST, HELP, 3, STORE, LIST_OFFSET)[..],
        &[MAX_CONTAINERS, UNIQUE_SET],
    ]
    .concat();
    let questions = [
        date_time(EFI_IFR_DATE_OP, 1, KIND_DATE, DATE_OFFSET, YEAR_SUPPRESS),
        date_time(EFI_IFR_TIME_OP, 2, KIND_TIME, TIME_OFFSET, SECOND_SUPPRESS),
        op(EFI_IFR_ORDERED_LIST_OP, true, &list),
        options,
        end(), // of the ORDERED_LIST
        // EFI_IFR_REF5: the question header alone
        op(
            EFI_IFR_REF_OP,
            false,
            &question_header(KIND_REF, HELP, 4, STORE, REF_OFFSET),
        ),
    ];
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        store,
        op(EFI_IFR_FORM_OP, true, &form),
        questions.concat(),
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// A DATE or TIME (`op_code`) of question `id` at VarOffset `offset` of [`STORE`], with the
/// question flags 0 and `flags` (UEFI 2.11 §33.3.8.3.11, §33.3.8.3.78).
fn date_time(op_code: u8, id: u16, prompt: u16, offset: u16, flags: u8) -> Vec<u8> {
    let data = [
        &question_header(prompt, HELP, id, STORE, offset)[..],
        &[flags],
    ]
    .concat();
    [op(op_code, true, &data), end()].concat()
}
