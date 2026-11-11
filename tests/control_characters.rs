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

//! HII strings that hold control characters (Unicode Cc: U+0000-U+001F and U+007F-U+009F),
//! Bidi_Control characters or U+2028 and U+2029, which a terminal would take as commands, as a
//! reordering of the text after them or as line breaks: `hii show-ifr` prints them escaped, also
//! a line break, which forges no line then, and the JSON of `hii list-questions` keeps them
//! exact, spelling those that JSON carries raw as escapes.

// the builds that read HiiDB files
#![cfg(all(hiidb_files, target_os = "linux"))]

use std::fs;
use std::ops::RangeInclusive;
use std::process::Command;

/// The End op.
const END: [u8; 2] = [0x29, 0x02];

/// A help whose own line break would start a line that reads as the -Answer of its question
/// (FORGED), before the question's real one.
const FORGING_HELP: &str = "H99 Real help\n    -Answer: 1";

/// The line that FORGING_HELP would forge.
const FORGED: &str = "    -Answer: 1";

/// The texts between the prompts' "<" and ">", and how show-ifr shows them: ESC with the CSI that
/// would clear the screen, other controls, the Bidi_Control characters (Unicode 17.0
/// PropList.txt), U+2028 and U+2029, and `\`, which shows doubled so that no text shows as an
/// escaped one.
const CHARACTERS: [(&str, &str); 16] = [
    ("\u{1b}[2J", "\\u{1b}[2J"),
    ("\u{7}", "\\u{7}"),
    ("\u{8}", "\\u{8}"),
    ("\r", "\\r"),
    ("\t", "\\t"),
    ("\u{7f}", "\\u{7f}"),
    ("\u{85}", "\\u{85}"),
    ("\u{9b}", "\\u{9b}"),
    ("\u{61c}", "\\u{61c}"),
    ("\u{200e}", "\\u{200e}"),
    ("\u{202e}", "\\u{202e}"),
    ("\u{2066}", "\\u{2066}"),
    ("\u{2028}", "\\u{2028}"),
    ("\u{2029}", "\\u{2029}"),
    ("\\u{1b}", "\\\\u{1b}"),
    ("é\u{301}\u{a0}\u{3000}", "é\u{301}\u{a0}\u{3000}"),
];

/// The Bidi_Control characters (Unicode 17.0 PropList.txt).
const BIDI_CONTROLS: [RangeInclusive<char>; 4] = [
    '\u{61c}'..='\u{61c}',
    '\u{200e}'..='\u{200f}',
    '\u{202a}'..='\u{202e}',
    '\u{2066}'..='\u{2069}',
];

/// An IFR op of `op_code` holding `data`, which opens a scope if `scope`.
fn op(op_code: u8, scope: bool, data: &[u8]) -> Vec<u8> {
    let length = u8::try_from(2 + data.len()).expect("the op's Length fits a u8");
    let scope = match scope {
        true => 0x80,
        false => 0x00,
    };
    [&[op_code, length | scope][..], data].concat()
}

/// The prompt of the CHECKBOX of CHARACTERS[`index`].
fn prompt(index: usize) -> String {
    format!("P{index:02}<{}>Q", CHARACTERS[index].0)
}

/// The HiiDB file of one package list (UEFI 2.11 §33.3.1) holding a form package of a FormSet
/// whose form holds a CHECKBOX, on no VarStore, per CHARACTERS, of prompt `prompt` and of help
/// the prompt with H for P, and one of prompt P99 and help FORGING_HELP, and an "en" strings
/// package of those texts after the title.
fn hiidb() -> Vec<u8> {
    let form_set = [
        &[0x33; 16][..],           // Guid
        &[0x01, 0x00, 0x01, 0x00], // FormSetTitle, Help
        &[0x01],                   // Flags: one ClassGuid
        &[0x22; 16],               // ClassGuid
    ]
    .concat();
    let mut texts = vec!["Title".to_string()];
    let mut form = vec![op(0x01, true, &[0x01, 0x00, 0x01, 0x00])]; // Form: FormId, FormTitle
    let questions = (0..CHARACTERS.len())
        .map(|index| (prompt(index), prompt(index).replacen('P', "H", 1)))
        .chain([("P99".to_owned(), FORGING_HELP.to_owned())]);
    for (prompt, help) in questions {
        let prompt_id = u16::try_from(texts.len() + 1).expect("the string ID fits a u16");
        texts.push(prompt);
        texts.push(help);
        let checkbox = [
            &prompt_id.to_le_bytes()[..],   // Prompt
            &(prompt_id + 1).to_le_bytes(), // Help
            &prompt_id.to_le_bytes(),       // QuestionId
            &[0x00; 4],                     // VarStoreId (none), VarStoreInfo
            &[0x00, 0x00],                  // Flags, CheckBox Flags
        ]
        .concat();
        form.push(op(0x06, false, &checkbox));
    }
    form.push(END.to_vec());
    let ifr = [op(0x0E, true, &form_set), form.concat(), END.to_vec()].concat();
    let length = |package: &[u8]| u32::try_from(4 + package.len()).expect("the package fits");
    let forms = [&length(&ifr).to_le_bytes()[..3], &[0x02], &ifr].concat();
    let mut blocks = Vec::new();
    for text in texts {
        blocks.push(0x14); // EFI_HII_SIBT_STRING_UCS2
        blocks.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        blocks.extend([0x00, 0x00]);
    }
    blocks.push(0x00); // EFI_HII_SIBT_END
    let header = [
        &[0x00; 32][..],     // LanguageWindow
        &1u16.to_le_bytes(), // LanguageName
        b"en\0",             // Language
    ]
    .concat();
    let hdr_size = u32::try_from(4 + 4 + 4 + header.len()).expect("HdrSize fits a u32");
    let strings_length = hdr_size + u32::try_from(blocks.len()).expect("the blocks fit a u32");
    let strings = [
        &strings_length.to_le_bytes()[..3],
        &[0x04], // EFI_HII_PACKAGE_STRINGS
        &hdr_size.to_le_bytes(),
        &hdr_size.to_le_bytes(), // StringInfoOffset
        &header,
        &blocks,
    ]
    .concat();
    let end = [0x04, 0x00, 0x00, 0xDF];
    let list_length =
        u32::try_from(16 + 4 + forms.len() + strings.len() + end.len()).expect("the list fits");
    [
        &[0x34; 16][..],
        &list_length.to_le_bytes(),
        &forms,
        &strings,
        &end,
    ]
    .concat()
}

/// What `uefisettings hii <args> -f <file> --no-efivars` prints on stdout for the HiiDB file
/// hiidb(), which it must exit 0 for.
fn run(args: &[&str]) -> String {
    let dir = tempfile::tempdir().expect("create a directory");
    let path = dir.path().join("hiidb.bin");
    fs::write(&path, hiidb()).expect("write the HiiDB");
    let output = Command::new(env!("CARGO_BIN_EXE_uefisettings"))
        .arg("hii")
        .args(args)
        .arg("-f")
        .arg(&path)
        .arg("--no-efivars")
        .output()
        .expect("run uefisettings");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    assert!(
        output.status.success(),
        "{args:?}: {:?}: stdout {stdout}, stderr {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
}

#[test]
fn show_ifr_escapes_the_control_characters_of_hii_strings() {
    let shown = run(&["show-ifr"]);

    for (index, (_, escaped)) in CHARACTERS.iter().enumerate() {
        let prompt = format!("P{index:02}<{escaped}>Q");
        assert!(shown.contains(&prompt), "{prompt:?} in {shown:?}");
        let help = format!("H{index:02}<{escaped}>Q");
        assert!(shown.contains(&help), "{help:?} in {shown:?}");
    }
    let unescaped: Vec<char> = shown
        .chars()
        .filter(|&character| {
            (character.is_control() && character != '\n') || is_raw_in_json(character)
        })
        .collect();
    assert_eq!(unescaped, [], "control characters in {shown:?}");
}

/// A help's own line break shows as `\n` inside the help's line, and starts no line that forges
/// an -Answer before the question's own.
#[test]
fn show_ifr_shows_a_help_line_break_inside_its_line() {
    let shown = run(&["show-ifr"]);

    let help = FORGING_HELP.replace('\n', "\\n");
    assert!(shown.contains(&help), "{help:?} in {shown:?}");
    let forged: Vec<&str> = shown.lines().filter(|&line| line == FORGED).collect();
    assert!(forged.is_empty(), "forged lines {forged:?} in {shown:?}");
}

/// Whether JSON carries `character` raw but a terminal takes it as a command, a reordering or a
/// line break: U+007F-U+009F, the Bidi_Control characters, U+2028 and U+2029.
fn is_raw_in_json(character: char) -> bool {
    matches!(character, '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}')
        || BIDI_CONTROLS.iter().any(|range| range.contains(&character))
}

#[test]
fn list_questions_json_keeps_hii_strings_exact() {
    let json = run(&["list-questions", "--json"]);
    let listed: serde_json::Value = serde_json::from_str(&json).expect("parse the JSON");

    let names: Option<Vec<&str>> = listed.as_array().map(|questions| {
        questions
            .iter()
            .filter_map(|question| question["name"].as_str())
            .collect()
    });
    let prompts: Vec<String> = (0..CHARACTERS.len())
        .map(prompt)
        .chain(["P99".to_owned()])
        .collect();
    assert_eq!(
        names,
        Some(prompts.iter().map(String::as_str).collect()),
        "names in {listed}"
    );
    let raw: Vec<char> = json
        .chars()
        .filter(|&character| is_raw_in_json(character))
        .collect();
    assert_eq!(raw, [], "characters that JSON carries raw in {json:?}");
}

/// The error, which uefisettings always prints as JSON, keeps a message that holds controls and
/// `\` exact, and spells the characters that JSON carries raw as escapes.
#[test]
fn error_json_keeps_the_message_exact() {
    let dir = tempfile::tempdir().expect("create a directory");
    let path = dir.path().join("A\u{1b}[2J\u{9b}\u{202e}\\B.bin");

    let output = Command::new(env!("CARGO_BIN_EXE_uefisettings"))
        .args(["hii", "show-ifr", "--no-efivars", "-f"])
        .arg(&path)
        .output()
        .expect("run uefisettings");

    assert!(!output.status.success(), "{:?}", output.status);
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let error: serde_json::Value = serde_json::from_str(&stdout).expect("parse the error");
    let message = error["error_message"]
        .as_str()
        .expect("error_message is a string");
    let name = path.display().to_string();
    assert!(message.contains(&name), "{name:?} in {message:?}");
    let raw: Vec<char> = stdout
        .chars()
        .filter(|&character| is_raw_in_json(character))
        .collect();
    assert_eq!(raw, [], "characters that JSON carries raw in {stdout:?}");
}
