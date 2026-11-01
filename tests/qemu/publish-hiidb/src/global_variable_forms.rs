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

//! The HII package lists that `rt-data-global-variable-forms` appends to the published
//! database, for `tests/qemu/guest/tests/hii_global_variables.rs`: each holds a strings
//! package, a form package and the End package (UEFI 2.10 §33.3.1).
//! Every question is a UINT8 NUMERIC at VarOffset 0 of an EFI global variable that EDK2's
//! firmware creates, under a VarStore that declares it non-volatile: the firmware keeps
//! ConOutDev, LangCodes and PlatformLangCodes volatile and Timeout non-volatile, so only
//! the attribute word of each efivar file tells `uefisettings set` which it can write.

use alloc::vec::Vec;

use uefi::guid;
use uefi::runtime::VariableVendor;
use uefi::Guid;

use crate::hii_package::end;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::strings_package;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;

/// The Attributes of every VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;

/// The string ID of the form set's title.
const TITLE: u16 = 2;
/// The string ID of the help of the form set and of each question; the prompts follow it.
const HELP: u16 = 3;

/// EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.10 §33.3.8.3.47).
const UINT8_DECIMAL: u8 = 0x10;

/// The package lists, in the order of the database: a question in several lists has one
/// copy in each.
const PACKAGE_LISTS: &[PackageList] = &[
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000001"),
        questions: &[
            Question {
                prompt: "Volatile EFI variable",
                var_store: VarStore::efi("ConOutDev", 1),
                maximum: 255,
            },
            Question {
                prompt: "Buffer on a volatile EFI variable",
                var_store: VarStore::buffer("LangCodes", 1),
                maximum: 255,
            },
            Question {
                prompt: "Volatile EFI variable under a larger VarStore",
                var_store: VarStore::efi("PlatformLangCodes", 255),
                maximum: 255,
            },
            Question {
                prompt: "Non-volatile EFI variable",
                var_store: VarStore::efi("Timeout", 2),
                maximum: 255,
            },
        ],
    },
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000002"),
        questions: &[Question {
            prompt: "Volatile copy among several",
            var_store: VarStore::efi("Timeout", 2),
            maximum: 255,
        }],
    },
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000003"),
        questions: &[Question {
            prompt: "Volatile copy among several",
            var_store: VarStore::efi("ConOutDev", 1),
            maximum: 255,
        }],
    },
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000004"),
        questions: &[Question {
            prompt: "Unreadable copy among several",
            var_store: VarStore::efi("Timeout", 2),
            maximum: 255,
        }],
    },
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000005"),
        questions: &[Question {
            prompt: "Unreadable copy among several",
            var_store: VarStore::efi("Timeout", 64),
            maximum: 255,
        }],
    },
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000006"),
        questions: &[Question {
            prompt: "Copies with different maxima",
            var_store: VarStore::efi("Timeout", 2),
            maximum: 200,
        }],
    },
    PackageList {
        guid: guid!("8c78a505-baa0-4c4a-869f-000000000007"),
        questions: &[Question {
            prompt: "Copies with different maxima",
            var_store: VarStore::efi("Timeout", 2),
            maximum: 100,
        }],
    },
];

/// A package list whose form set, of the same GUID, has one form with `questions`, each on
/// its own VarStore.
struct PackageList {
    guid: Guid,
    questions: &'static [Question],
}

/// A UINT8 NUMERIC from 0 to `maximum` at VarOffset 0 of `var_store`.
struct Question {
    prompt: &'static str,
    var_store: VarStore,
    maximum: u8,
}

/// A VarStore on the EFI global variable `name`, which it declares `size` bytes long.
struct VarStore {
    kind: VarStoreKind,
    name: &'static str,
    size: u16,
}

/// The op that declares a VarStore.
enum VarStoreKind {
    /// EFI_IFR_VARSTORE_EFI, with the Attributes [`NV_BS_RT`].
    Efi,
    /// EFI_IFR_VARSTORE, a buffer VarStore.
    Buffer,
}

impl VarStore {
    const fn efi(name: &'static str, size: u16) -> Self {
        Self {
            kind: VarStoreKind::Efi,
            name,
            size,
        }
    }

    const fn buffer(name: &'static str, size: u16) -> Self {
        Self {
            kind: VarStoreKind::Buffer,
            name,
            size,
        }
    }

    /// The op that declares this VarStore as `id`.
    fn op(&self, id: u16) -> Vec<u8> {
        let guid = VariableVendor::GLOBAL_VARIABLE.0.to_bytes();
        let name = [self.name.as_bytes(), &[0]].concat();
        match self.kind {
            VarStoreKind::Efi => op(
                EFI_IFR_VARSTORE_EFI_OP,
                false,
                &[
                    &id.to_le_bytes()[..],
                    &guid,
                    &NV_BS_RT.to_le_bytes(),
                    &self.size.to_le_bytes(),
                    &name,
                ]
                .concat(),
            ),
            VarStoreKind::Buffer => op(
                EFI_IFR_VARSTORE_OP,
                false,
                &[
                    &guid[..],
                    &id.to_le_bytes(),
                    &self.size.to_le_bytes(),
                    &name,
                ]
                .concat(),
            ),
        }
    }
}

/// [`PACKAGE_LISTS`], as the HII database exports package lists.
pub(crate) fn package_lists() -> Vec<u8> {
    PACKAGE_LISTS.iter().flat_map(PackageList::bytes).collect()
}

impl PackageList {
    /// The package list of the strings and form packages.
    fn bytes(&self) -> Vec<u8> {
        package_list(self.guid, &[self.strings_package(), self.form_package()])
    }

    /// The strings package: the language name, the title, the help, then each prompt, from
    /// string ID 1.
    fn strings_package(&self) -> Vec<u8> {
        let strings = [
            "English",
            "uefisettings QEMU test forms",
            "On EFI global variables",
        ]
        .into_iter()
        .chain(self.questions.iter().map(|question| question.prompt));
        strings_package(strings)
    }

    /// A form package: a form set of the package list's GUID that declares one VarStore per
    /// question, with one form that holds the questions.
    fn form_package(&self) -> Vec<u8> {
        let form_set = [
            &self.guid.to_bytes()[..],
            &TITLE.to_le_bytes(),
            &HELP.to_le_bytes(),
            &[1],        // Flags: one ClassGuid
            &[0x22; 16], // ClassGuid
        ]
        .concat();
        let var_stores: Vec<u8> = (1..)
            .zip(self.questions)
            .flat_map(|(id, question)| question.var_store.op(id))
            .collect();
        let questions: Vec<u8> = (1..)
            .zip(self.questions)
            .flat_map(|(id, question)| question.op(id))
            .collect();
        let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
        let body = [
            op(EFI_IFR_FORM_SET_OP, true, &form_set),
            var_stores,
            op(EFI_IFR_FORM_OP, true, &form),
            questions,
            end(), // of the form
            end(), // of the form set
        ]
        .concat();
        package(EFI_HII_PACKAGE_FORMS, &body)
    }
}

impl Question {
    /// The NUMERIC op, in its own scope, of question `id` on VarStore `id`, whose prompt is
    /// the string after the help.
    fn op(&self, id: u16) -> Vec<u8> {
        let prompt = HELP + id;
        let data = [
            // EFI_IFR_QUESTION_HEADER: Prompt, Help, QuestionId, VarStoreId, VarOffset, Flags
            &prompt.to_le_bytes()[..],
            &HELP.to_le_bytes(),
            &id.to_le_bytes(),
            &id.to_le_bytes(),
            &0u16.to_le_bytes(),
            &[0],
            // Flags, MinValue, MaxValue, Step
            &[UINT8_DECIMAL, 0, self.maximum, 1],
        ]
        .concat();
        [op(EFI_IFR_NUMERIC_OP, true, &data), end()].concat()
    }
}
