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

//! The HII package lists that `formset-skip-forms` registers in the HII database, for the
//! scenarios `hii-formset-skip` and `shell-formset-skip` of `tests/qemu/scenarios.tsv`, each
//! holding a form set that `uefisettings` ignores: one with a PASSWORD at bytes 0 to 19 of the
//! variable that it declares, then, outside its form, a VARSTORE op shorter than its minimum,
//! which UEFI 2.11 §33.2.5.10.1 calls malformed. In the first list, four form sets: the second is
//! the ignored one, on a variable of its own, and the others are on one variable: the first keeps
//! a UINT8 NUMERIC at byte 20 of it, the third keeps a UINT8 NUMERIC at byte 21, which
//! `uefisettings` reads past the second, and has a second form, with a PASSWORD at bytes 22 to 41
//! and a UINT8 NUMERIC at byte 42, that a CHECKBOX op shorter than its minimum disables
//! (§33.2.5.10.1), and the fourth keeps a UINT8 NUMERIC at byte 22, over that PASSWORD. In the
//! second list, two form sets on another variable: the ignored one first, then one that keeps a
//! UINT8 NUMERIC at byte 20, which `uefisettings` withholds with every byte of that variable, as
//! the ignored form set declares it.
//! The package list that `disabled-form-forms` registers, for the scenario `shell-disabled-form`,
//! holds one form set on a third variable, whose first form keeps a UINT8 NUMERIC at byte 20 and
//! one at byte 0, over the PASSWORD at bytes 0 to 19 of its second form, a form with a UINT8
//! NUMERIC at byte 21 that a CHECKBOX op shorter than its minimum disables.

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
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;
use crate::hii_package::UINT8_DECIMAL;

/// The GUID of the first package list and of its first form set.
const FIRST_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001200");
/// The GUID of the second form set of the first list, which `uefisettings` ignores.
const IGNORED_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001201");
/// The GUID of the third form set of the first list.
const THIRD_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001202");
/// The GUID of the fourth form set of the first list.
const FOURTH_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001204");
/// The variable of the first list, which tests/qemu/vars/formset-skip.json creates: 20 bytes
/// that no question holds, the first and third settings, then the password and the setting of
/// the disabled form.
const STORE: VarStoreEfi = VarStoreEfi {
    vendor: guid!("8c78a505-baa0-4c4a-869f-000000001203"),
    name: b"UefisettingsFormSetSkip\0",
    size: 43,
};
/// The variable of the second form set of the first list, which `uefisettings` ignores, and of
/// its PASSWORD alone; its Name is as long as that of STORE, so the ops after it keep their
/// offsets.
const IGNORED_STORE: VarStoreEfi = VarStoreEfi {
    vendor: guid!("8c78a505-baa0-4c4a-869f-000000001205"),
    name: b"UefisettingsSkippedForm\0",
    size: 20,
};
/// The GUID of the second package list.
const SECOND_LIST: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001210");
/// The GUID of the first form set of the second list, which `uefisettings` ignores.
const IGNORED_FIRST_FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001211");
/// The GUID of the second form set of the second list.
const AFTER_IGNORED_FIRST: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001212");
/// The variable of the second list, which tests/qemu/vars/formset-skip.json creates: the
/// password, then the setting.
const SECOND_STORE: VarStoreEfi = VarStoreEfi {
    vendor: guid!("8c78a505-baa0-4c4a-869f-000000001213"),
    name: b"UefisettingsFirstFormSetSkip\0",
    size: 21,
};
/// The Attributes of each VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;

// The strings of each list, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const FIRST_SETTING: u16 = 4;
const PASSWORD: u16 = 5;
const THIRD_SETTING: u16 = 6;
const OVER_PASSWORD: u16 = 7;
const DISABLED_SETTING: u16 = 8;
const STRINGS: [&str; 8] = [
    "English",
    "uefisettings QEMU formset skip forms",
    "Form sets around one that uefisettings ignores",
    "First setting",
    "Password",
    "Third setting",
    "Over password",
    "Disabled setting",
];
const FOURTH_SETTING: u16 = 4;
const SECOND_STRINGS: [&str; 5] = [
    "English",
    "uefisettings QEMU formset skip forms, first ignored",
    "A form set after a first one that uefisettings ignores",
    "Fourth setting",
    "Password",
];

/// The GUID of the package list of `disabled-form-forms` and of its form set.
const DISABLED_FORM_LIST: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001230");
/// The variable of that list, which tests/qemu/vars/disabled-form.json creates: the password,
/// then the live and the disabled settings.
const DISABLED_FORM_STORE: VarStoreEfi = VarStoreEfi {
    vendor: guid!("8c78a505-baa0-4c4a-869f-000000001231"),
    name: b"UefisettingsDisabledForm\0",
    size: 22,
};
// The strings of that list, from string ID 4, after its title and help.
const LIVE_SETTING: u16 = 4;
const ALONE_OVER_PASSWORD: u16 = 6;
const ALONE_DISABLED_SETTING: u16 = 7;
const DISABLED_FORM_STRINGS: [&str; 7] = [
    "English",
    "uefisettings QEMU disabled form",
    "A form that uefisettings disables beside one that it reads",
    "Live setting",
    "Password",
    "Over password",
    "Disabled setting",
];

/// The VarStoreId of the variable in each form set.
const VAR_STORE: u16 = 1;

/// The MaxSize of the PASSWORD, in characters: its UCS-2 string takes bytes 0 to 19.
const PASSWORD_MAX_SIZE: u16 = 10;
/// The Data of a VARSTORE op that ends after 4 of the 20 bytes before its Name.
const SHORT_VAR_STORE: [u8; 4] = [0; 4];
/// The Data of a CHECKBOX op that ends after 1 of the 12 bytes of its data.
const SHORT_CHECKBOX: [u8; 1] = [0];

/// The variable of a VARSTORE_EFI of VarStoreId VAR_STORE.
struct VarStoreEfi {
    vendor: Guid,
    /// NUL-terminated
    name: &'static [u8],
    size: u16,
}

/// The package lists, as NewPackageList() takes them, in the order to register them.
pub(crate) fn package_lists() -> [Vec<u8>; 2] {
    [
        package_list(
            FIRST_FORM_SET,
            &[
                strings_package(STRINGS),
                package(
                    EFI_HII_PACKAGE_FORMS,
                    &[
                        form_set(FIRST_FORM_SET, &STORE, &uint8_numeric(FIRST_SETTING, 1, 20)),
                        ignored_form_set(IGNORED_FORM_SET, &IGNORED_STORE),
                        form_set_with(
                            THIRD_FORM_SET,
                            &STORE,
                            &[
                                form(1, &uint8_numeric(THIRD_SETTING, 3, 21)),
                                disabled_form(DISABLED_SETTING, 42, 22),
                            ]
                            .concat(),
                            &[],
                        ),
                        form_set(
                            FOURTH_FORM_SET,
                            &STORE,
                            &uint8_numeric(OVER_PASSWORD, 6, 22),
                        ),
                    ]
                    .concat(),
                ),
            ],
        ),
        package_list(
            SECOND_LIST,
            &[
                strings_package(SECOND_STRINGS),
                package(
                    EFI_HII_PACKAGE_FORMS,
                    &[
                        ignored_form_set(IGNORED_FIRST_FORM_SET, &SECOND_STORE),
                        form_set(
                            AFTER_IGNORED_FIRST,
                            &SECOND_STORE,
                            &uint8_numeric(FOURTH_SETTING, 1, 20),
                        ),
                    ]
                    .concat(),
                ),
            ],
        ),
    ]
}

/// The package list of `disabled-form-forms`, as NewPackageList() takes it.
pub(crate) fn disabled_form_package_list() -> Vec<u8> {
    package_list(
        DISABLED_FORM_LIST,
        &[
            strings_package(DISABLED_FORM_STRINGS),
            package(
                EFI_HII_PACKAGE_FORMS,
                &form_set_with(
                    DISABLED_FORM_LIST,
                    &DISABLED_FORM_STORE,
                    &[
                        form(
                            1,
                            &[
                                uint8_numeric(LIVE_SETTING, 1, 20),
                                uint8_numeric(ALONE_OVER_PASSWORD, 3, 0),
                            ]
                            .concat(),
                        ),
                        disabled_form(ALONE_DISABLED_SETTING, 21, 0),
                    ]
                    .concat(),
                    &[],
                ),
            ),
        ],
    )
}

/// A form set of `guid` on `store` whose form holds a PASSWORD at bytes 0 to 19, followed,
/// outside the form, by a VARSTORE op shorter than its minimum.
fn ignored_form_set(guid: Guid, store: &VarStoreEfi) -> Vec<u8> {
    form_set_with(
        guid,
        store,
        &form(1, &password(2, 0)),
        &op(EFI_IFR_VARSTORE_OP, false, &SHORT_VAR_STORE),
    )
}

/// The form of FormId 2 of a UINT8 NUMERIC of prompt `prompt` at byte `setting` and a PASSWORD at
/// bytes `password_offset` to `password_offset` + 19, then a CHECKBOX op shorter than its minimum,
/// which UEFI 2.11 §33.2.5.10.1 calls malformed, so that `uefisettings` disables the form.
fn disabled_form(prompt: u16, setting: u16, password_offset: u16) -> Vec<u8> {
    form(
        2,
        &[
            uint8_numeric(prompt, 4, setting),
            password(5, password_offset),
            op(EFI_IFR_CHECKBOX_OP, false, &SHORT_CHECKBOX),
        ]
        .concat(),
    )
}

/// A PASSWORD of QuestionId `question_id` at bytes `offset` to `offset` + 19 of the variable.
fn password(question_id: u16, offset: u16) -> Vec<u8> {
    op(
        EFI_IFR_PASSWORD_OP,
        false,
        &[
            question_header(PASSWORD, HELP, question_id, VAR_STORE, offset),
            [1u16.to_le_bytes(), PASSWORD_MAX_SIZE.to_le_bytes()].concat(), // MinSize, MaxSize
        ]
        .concat(),
    )
}

/// A UINT8 NUMERIC of prompt `prompt` and QuestionId `question_id` at byte `offset` of the
/// variable.
fn uint8_numeric(prompt: u16, question_id: u16, offset: u16) -> Vec<u8> {
    [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(prompt, HELP, question_id, VAR_STORE, offset),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 255, 1].to_vec(),
            ]
            .concat(),
        ),
        end(),
    ]
    .concat()
}

/// A form set of `guid` that declares `store` and holds a form of `question`.
fn form_set(guid: Guid, store: &VarStoreEfi, question: &[u8]) -> Vec<u8> {
    form_set_with(guid, store, &form(1, question), &[])
}

/// A form of FormId `id` that holds `questions`.
fn form(id: u16, questions: &[u8]) -> Vec<u8> {
    let form = [id.to_le_bytes(), TITLE.to_le_bytes()].concat();
    [op(EFI_IFR_FORM_OP, true, &form), questions.to_vec(), end()].concat()
}

/// A form set of `guid` that declares `store` and holds `forms`, then the ops `after`, outside
/// them.
fn form_set_with(guid: Guid, store: &VarStoreEfi, forms: &[u8], after: &[u8]) -> Vec<u8> {
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
            &store.vendor.to_bytes(),
            &NV_BS_RT.to_le_bytes(),
            &store.size.to_le_bytes(),
            store.name,
        ]
        .concat(),
    );
    [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        var_store,
        forms.to_vec(),
        after.to_vec(),
        end(), // of the form set
    ]
    .concat()
}
