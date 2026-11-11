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

//! The boot of the scenario hii-control-text: publish-hiidb's `control-text-forms` registers the
//! forms of `publish-hiidb/src/control_text_forms.rs`, whose CHECKBOXes have prompts and a help
//! that a terminal would take as commands, as a reordering of the text or as line breaks, and
//! `rt-data` publishes the HII database after it. show-ifr shows each such character escaped,
//! the help's line break inside its line, and list-questions --json keeps every prompt exact,
//! with none of them raw in what it prints.

use serde::Deserialize;
use uefisettings_qemu_guest::uefisettings;

/// The prompts and the help of the form set, as the HII database holds them.
const PROMPTS: [&str; 9] = [
    "P00<\u{1b}[2J>Q",
    "P01<\r>Q",
    "P02<\u{9b}>Q",
    "P03<\u{202e}>Q",
    "P04<\\u{1b}>Q",
    "P05",
    "P06<\u{2028}>Q",
    "P07<\u{10d}>Q",
    "P08<\u{200d}>Q",
];
const FORGING_HELP: &str = "H05\n    -Answer: forged";
/// The prompts that show-ifr shows escaped, as it shows them.
const SHOWN: [&str; 6] = [
    "P00<\\u{1b}[2J>Q",
    "P01<\\r>Q",
    "P02<\\u{9b}>Q",
    "P03<\\u{202e}>Q",
    "P04<\\\\u{1b}>Q",
    "P06<\\u{2028}>Q",
];
/// The line that FORGING_HELP forges, as show-ifr would show the answer of a question.
const FORGED: &str = "-Answer: forged";

/// A question as list-questions --json prints it, with the texts that this boot checks.
#[derive(Debug, Deserialize)]
struct Texts {
    name: String,
    help: String,
}

/// Whether a terminal takes `character` as a command, as a reordering of the text after it or
/// as a line break: a control character, a Bidi_Control character (Unicode 17.0 PropList.txt),
/// U+2028 or U+2029.
fn rewrites_the_terminal(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{61c}' | '\u{200e}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
        || matches!(character, '\u{2028}' | '\u{2029}')
}

/// show-ifr shows each control character, Bidi_Control character and U+2028 of the prompts
/// escaped, P04's backslash doubled and the help's line break inside its line, which then forges
/// no line; it prints no such character raw but its line breaks.
#[test]
fn show_ifr_escapes_what_would_rewrite_the_terminal() {
    let output = uefisettings(&["hii", "show-ifr"]);
    assert_eq!(output.code, Some(0), "show-ifr: {output:#?}");

    let lines: Vec<&str> = output.stdout.lines().collect();
    for shown in SHOWN {
        assert!(
            lines.iter().any(|line| line.contains(shown)),
            "show-ifr shows {shown:?}: {}",
            output.stdout
        );
    }
    let help = format!("Help: - H05\\n    {FORGED}");
    assert!(
        lines.iter().any(|line| line.ends_with(&help)),
        "show-ifr shows {help:?}: {}",
        output.stdout
    );
    assert!(
        !lines
            .iter()
            .any(|line| line.trim_start().starts_with(FORGED)),
        "show-ifr shows the line {FORGED:?}: {}",
        output.stdout
    );
    let raw: Vec<char> = output
        .stdout
        .chars()
        .filter(|&character| character != '\n' && rewrites_the_terminal(character))
        .collect();
    assert_eq!(raw, [], "show-ifr prints raw: {}", output.stdout);
}

/// list-questions --json keeps each prompt and the forging help exact, and its JSON holds no
/// character that rewrites the terminal raw, as serde_json carries U+007F-U+009F, Bidi_Control
/// characters, U+2028 and U+2029 raw.
#[test]
fn list_questions_keeps_each_text_and_escapes_what_would_rewrite_the_terminal() {
    let output = uefisettings(&["hii", "list-questions", "--json"]);
    let listed: Vec<Texts> = output.json(0);

    for prompt in PROMPTS {
        assert!(
            listed.iter().any(|question| question.name == prompt),
            "list-questions lists {prompt:?}: {listed:#?}"
        );
    }
    assert!(
        listed
            .iter()
            .any(|question| question.name == "P05" && question.help == FORGING_HELP),
        "list-questions gives P05 the help {FORGING_HELP:?}: {listed:#?}"
    );
    let raw: Vec<char> = output
        .stdout
        .chars()
        .filter(|&character| character != '\n' && rewrites_the_terminal(character))
        .collect();
    assert_eq!(raw, [], "list-questions prints raw: {}", output.stdout);
}
