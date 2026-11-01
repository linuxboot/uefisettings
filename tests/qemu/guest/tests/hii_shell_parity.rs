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

//! The first boot of the UEFI Shell scenario shell-parity: prints the questions that
//! `hii list-questions --json` lists here, for `tests/qemu/check-shell-log.sh` to compare with
//! those that `uefisettings.efi` lists in the UEFI Shell, the next boot, on the same variables.
//! Both list them in every state, as the shell can evaluate conditions that Linux cannot.

use std::io::Write;

use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::Question;

/// What the line that holds the questions starts with, which check-shell-log.sh looks for.
const QUESTIONS_LINE: &str = "uefisettings-qemu-test: list-questions ";
/// The flags of shell/list-questions.nsh, which list every question.
const EVERY_STATE: [&str; 2] = ["--include", "grayed-out,suppressed,disabled"];

#[test]
fn list_questions_for_the_shell() {
    let output = uefisettings(&[&["hii", "list-questions", "--json"][..], &EVERY_STATE].concat());
    let questions: Vec<Question> = output.json(0);
    assert!(!questions.is_empty(), "no questions: {output:#?}");

    // to the test log, past libtest's capture, which takes print! but not writes to stdout,
    // on a line of its own after libtest's "test ... "
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{QUESTIONS_LINE}{}", output.stdout.trim_end())
        .and_then(|()| stdout.flush())
        .expect("write the questions");
}
