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

//! The HII package list that `control-text-forms` registers in the HII database, for the
//! scenarios `hii-control-text` and `shell-control-text` of `tests/qemu/scenarios.tsv`: a form
//! package of a form set whose CHECKBOXes, on no variable, have prompts and a help that a
//! terminal would take as commands, as a reordering of the text or as line breaks, and prompts
//! that hold U+010D and U+200D, characters whose low byte is CR, which edk2-stable202608
//! TerminalDxe writes in place of a character that its PC-ANSI and VT100 types lack
//! (TerminalConOut.c:237-241).

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

/// The GUID of the package list and of its form set.
const FORM_SET: Guid = guid!("8c78a505-baa0-4c4a-869f-000000002000");

// The strings, from string ID 2, after the language name.
const TITLE: u16 = 2;
const HELP: u16 = 3;
/// The help of the CHECKBOX prompted P05: a line break, then a line that show-ifr would show as
/// that CHECKBOX's answer.
const FORGING_HELP: u16 = 13;
/// The CHECKBOXes: their prompts and helps.
const CHECK_BOXES: [(u16, u16); 9] = [
    (4, HELP),
    (5, HELP),
    (6, HELP),
    (7, HELP),
    (8, HELP),
    (9, FORGING_HELP),
    (10, HELP),
    (11, HELP),
    (12, HELP),
];
const STRINGS: [&str; 13] = [
    "English",
    "uefisettings QEMU control text forms",
    "H",
    // a control sequence that clears the screen
    "P00<\u{1b}[2J>Q",
    "P01<\r>Q",
    // CONTROL SEQUENCE INTRODUCER
    "P02<\u{9b}>Q",
    // RIGHT-TO-LEFT OVERRIDE, a Bidi_Control character
    "P03<\u{202e}>Q",
    // a text that spells an escape, with no control character
    "P04<\\u{1b}>Q",
    "P05",
    // LINE SEPARATOR
    "P06<\u{2028}>Q",
    "P07<\u{10d}>Q",
    // ZERO WIDTH JOINER
    "P08<\u{200d}>Q",
    "H05\n    -Answer: forged",
];

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(FORM_SET, &[strings_package(STRINGS), form_package()])
}

/// The form package: the form set, whose form holds the CHECKBOXes of CHECK_BOXES, on no
/// VarStore.
fn form_package() -> Vec<u8> {
    let form_set = [
        &FORM_SET.to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let check_boxes: Vec<u8> = CHECK_BOXES
        .iter()
        .flat_map(|&(prompt, help)| {
            // the question header of QuestionId `prompt`, VarStoreId 0, then CheckBox Flags 0
            let data = [question_header(prompt, help, prompt, 0, 0), [0].to_vec()].concat();
            op(EFI_IFR_CHECKBOX_OP, false, &data)
        })
        .collect();
    let body = [
        op(EFI_IFR_FORM_SET_OP, true, &form_set),
        op(EFI_IFR_FORM_OP, true, &form),
        check_boxes,
        end(), // of the form
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}
