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

//! The HII package list that `password-forms` registers in the HII database, for the UEFI
//! Shell scenario `shell-password` of `tests/qemu/scenarios.tsv`: a form set with the layout
//! of AMI firmware's setup passwords, whose PASSWORD questions keep the Administrator and the
//! User password at bytes 0 and 40 of the buffer VarStore AMITSESetup and a ONE_OF keeps a
//! setting at byte 80, and with a UINT8 NUMERIC on the EFI global variable ConOutDev, which
//! EDK2's firmware keeps volatile, under a VarStore that declares it non-volatile.

use alloc::vec::Vec;

use uefi::guid;
use uefi::runtime::VariableVendor;
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
use crate::hii_package::EFI_IFR_ONE_OF_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OPTION_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000100");
/// The vendor GUID of AMITSESetup, which tests/qemu/vars/amitse-setup.json creates.
const AMITSE_SETUP_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000000101");
/// The Attributes of the VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const ADMINISTRATOR_PASSWORD: u16 = 4;
const USER_PASSWORD: u16 = 5;
const QUIET_BOOT: u16 = 6;
const DISABLED: u16 = 7;
const ENABLED: u16 = 8;
const VOLATILE_SETTING: u16 = 9;
const STRINGS: [&str; 9] = [
    "English",
    "uefisettings QEMU password forms",
    "AMI's setup password layout and a volatile variable",
    "Administrator Password",
    "User Password",
    "Quiet Boot",
    "Disabled",
    "Enabled",
    "Volatile setting",
];

// The VarStores
const AMITSE_SETUP: u16 = 1;
const CON_OUT_DEV: u16 = 2;

/// EFI_IFR_TYPE_NUM_SIZE_8, the Type of a UINT8 EFI_IFR_ONE_OF_OPTION.
const NUM_SIZE_8: u8 = 0x00;
/// The MaxSize of each PASSWORD, in characters: its UCS-2 string takes 40 bytes.
const PASSWORD_MAX_SIZE: u16 = 20;

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
    let amitse_setup = op(
        EFI_IFR_VARSTORE_OP,
        false,
        &[
            &AMITSE_SETUP_VENDOR.to_bytes()[..],
            &AMITSE_SETUP.to_le_bytes(),
            &81u16.to_le_bytes(), // Size
            b"AMITSESetup\0",
        ]
        .concat(),
    );
    let con_out_dev = op(
        EFI_IFR_VARSTORE_EFI_OP,
        false,
        &[
            &CON_OUT_DEV.to_le_bytes()[..],
            &VariableVendor::GLOBAL_VARIABLE.0.to_bytes(),
            &NV_BS_RT.to_le_bytes(),
            &1u16.to_le_bytes(), // Size
            b"ConOutDev\0",
        ]
        .concat(),
    );
    let quiet_boot = [
        op(
            EFI_IFR_ONE_OF_OP,
            true,
            &[
                question_header(QUIET_BOOT, HELP, 3, AMITSE_SETUP, 80),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 1, 0].to_vec(),
            ]
            .concat(),
        ),
        option(DISABLED, 0),
        option(ENABLED, 1),
        end(),
    ]
    .concat();
    let volatile_setting = [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(VOLATILE_SETTING, HELP, 4, CON_OUT_DEV, 0),
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
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        amitse_setup,
        con_out_dev,
        op(EFI_IFR_FORM_OP, true, &form),
        password(1, ADMINISTRATOR_PASSWORD, 0),
        password(2, USER_PASSWORD, 40),
        quiet_boot,
        volatile_setting,
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The PASSWORD op of question `id` at byte `offset` of AMITSESetup (UEFI 2.10
/// §33.3.8.3.54), out of scope.
fn password(id: u16, prompt: u16, offset: u16) -> Vec<u8> {
    let data = [
        question_header(prompt, HELP, id, AMITSE_SETUP, offset),
        [1u16.to_le_bytes(), PASSWORD_MAX_SIZE.to_le_bytes()].concat(), // MinSize, MaxSize
    ]
    .concat();
    op(EFI_IFR_PASSWORD_OP, false, &data)
}

/// A UINT8 EFI_IFR_ONE_OF_OPTION of `text` and `value`.
fn option(text: u16, value: u8) -> Vec<u8> {
    let data = [&text.to_le_bytes()[..], &[0, NUM_SIZE_8, value]].concat();
    op(EFI_IFR_ONE_OF_OPTION_OP, false, &data)
}
