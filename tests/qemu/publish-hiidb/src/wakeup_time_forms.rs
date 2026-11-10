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

//! The HII package list that `wakeup-time-forms` registers in the HII database before it
//! publishes the database, for `tests/qemu/guest/tests/hii_time_storage.rs` and the UEFI Shell
//! scenario `shell-time-storage` of `tests/qemu/scenarios.tsv`: a form set with a DATE and a
//! TIME, which suppresses its second, on the VARSTORE_EFI DateTimeData, which the driver creates
//! when it is missing, and a DATE and a TIME of the wake-up time, EFI Date/Time Storage without
//! a VarStore (UEFI 2.11 §33.2.5.6), each with its own prompt. The stored DATE holds an
//! EFI_IFR_ONE_OF_OPTION of Type DATE flagged DEFAULT_MFG, and the stored TIME one of Type TIME
//! flagged DEFAULT.

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
use crate::hii_package::EFI_IFR_DATE_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OPTION_OP;
use crate::hii_package::EFI_IFR_TIME_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000500");
/// The vendor GUID of DateTimeData.
pub(crate) const STORE_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000501");
/// The name of the variable of the VARSTORE_EFI.
pub(crate) const STORE_NAME: &CStr16 = cstr16!("DateTimeData");
/// The attributes of that variable and of its VARSTORE_EFI.
pub(crate) const STORE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// The bytes that the driver creates DateTimeData with: the EFI_HII_DATE 2024-02-29 of "Stored
/// date" at byte 0, the EFI_HII_TIME 12:34:56 of "Stored time" at byte 4, and byte 7, which is
/// in no question.
pub(crate) const STORE_DATA: [u8; 8] = [0xE8, 0x07, 0x02, 0x1D, 12, 34, 56, 0xEE];

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const STORED_DATE: u16 = 4;
const STORED_TIME: u16 = 5;
const WAKEUP_DATE: u16 = 6;
const WAKEUP_TIME: u16 = 7;
const DATE_OPTION: u16 = 8;
const TIME_OPTION: u16 = 9;
const STRINGS: [&str; 9] = [
    "English",
    "uefisettings QEMU date and time forms",
    "Dates and times on a VarStore and of the wake-up time",
    "Stored date",
    "Stored time",
    "Wake-up date",
    "Wake-up time",
    "Manufacturing date",
    "Standard time",
];

// The VarStores
const STORE: u16 = 1;
/// VarStoreId 0: no VarStore (UEFI 2.11 §33.3.8.2.2).
const NO_VAR_STORE: u16 = 0;

/// QF_TIME_SECOND_SUPPRESS (UEFI 2.11 §33.3.8.3.78).
const SECOND_SUPPRESS: u8 = 0x04;
/// QF_DATE_STORAGE_WAKEUP and QF_TIME_STORAGE_WAKEUP (UEFI 2.11 §33.3.8.3.11, §33.3.8.3.78).
const STORAGE_WAKEUP: u8 = 0x20;
/// EFI_IFR_OPTION_DEFAULT and EFI_IFR_OPTION_DEFAULT_MFG (UEFI 2.11 §33.3.8.3.51).
const OPTION_DEFAULT: u8 = 0x10;
const OPTION_DEFAULT_MFG: u8 = 0x20;
/// EFI_IFR_TYPE_TIME and EFI_IFR_TYPE_DATE, the Types of EFI_IFR_ONE_OF_OPTIONs (UEFI 2.11
/// §33.3.8.3.51).
const TYPE_TIME: u8 = 0x05;
const TYPE_DATE: u8 = 0x06;

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FORM_SET, &[strings_package(STRINGS), form_package()])
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
            &u16::try_from(STORE_DATA.len())
                .expect("DateTimeData fits a VarStore")
                .to_le_bytes(),
            b"DateTimeData\0",
        ]
        .concat(),
    );
    let questions = [
        date_time(
            EFI_IFR_DATE_OP,
            1,
            STORED_DATE,
            (STORE, 0),
            0,
            // 2004-01-02
            &[option(
                DATE_OPTION,
                OPTION_DEFAULT_MFG,
                TYPE_DATE,
                &[0xD4, 0x07, 1, 2],
            )],
        ),
        date_time(
            EFI_IFR_TIME_OP,
            2,
            STORED_TIME,
            (STORE, 4),
            SECOND_SUPPRESS,
            // 15:33:33
            &[option(
                TIME_OPTION,
                OPTION_DEFAULT,
                TYPE_TIME,
                &[15, 33, 33],
            )],
        ),
        date_time(
            EFI_IFR_DATE_OP,
            3,
            WAKEUP_DATE,
            (NO_VAR_STORE, 0),
            STORAGE_WAKEUP,
            &[],
        ),
        date_time(
            EFI_IFR_TIME_OP,
            4,
            WAKEUP_TIME,
            (NO_VAR_STORE, 0),
            STORAGE_WAKEUP,
            &[],
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

/// A DATE or TIME (`op_code`) of question `id` at `var_store`, `(VarStoreId, VarOffset)`, with
/// the question flags 0 and `flags` (UEFI 2.11 §33.3.8.3.11, §33.3.8.3.78), holding `children`.
fn date_time(
    op_code: u8,
    id: u16,
    prompt: u16,
    (var_store, offset): (u16, u16),
    flags: u8,
    children: &[Vec<u8>],
) -> Vec<u8> {
    let data = [
        &prompt.to_le_bytes()[..],
        &HELP.to_le_bytes(),
        &id.to_le_bytes(),
        &var_store.to_le_bytes(),
        &offset.to_le_bytes(),
        &[0, flags],
    ]
    .concat();
    [op(op_code, true, &data), children.concat(), end()].concat()
}

/// An EFI_IFR_ONE_OF_OPTION of `text` with `flags` whose Value of Type `value_type` is `value`
/// (UEFI 2.11 §33.3.8.3.51).
fn option(text: u16, flags: u8, value_type: u8, value: &[u8]) -> Vec<u8> {
    let data = [&text.to_le_bytes()[..], &[flags, value_type], value].concat();
    op(EFI_IFR_ONE_OF_OPTION_OP, false, &data)
}
