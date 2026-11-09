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

//! `uefisettings hii list-questions --json` keeps printing a JSON array of questions for a HiiDB
//! with IFR that uefisettings ignores, and names that IFR on stderr, as questions may be in it;
//! `hii get --json` lists it in the ignored_ifr of its answer.

// the builds that read HiiDB files
#![cfg(all(hiidb_files, target_os = "linux"))]

use std::fs;
use std::process::Command;

/// The GUID 8C78A505-BAA0-4C4A-869F-0000000012xx of `last` byte xx, as stored: its first three
/// fields little-endian.
const fn fixture_guid(last: u8) -> [u8; 16] {
    [
        0x05, 0xA5, 0x78, 0x8C, 0xA0, 0xBA, 0x4A, 0x4C, 0x86, 0x9F, 0, 0, 0, 0, 0x12, last,
    ]
}

/// The GUID of the package list.
const LIST: [u8; 16] = fixture_guid(0x20);
/// LIST as uefisettings prints it.
const LIST_TEXT: &str = "8C78A505-BAA0-4C4A-869F-000000001220";
/// The GUID of the FormSet that uefisettings ignores, as uefisettings prints it.
const IGNORED_TEXT: &str = "8C78A505-BAA0-4C4A-869F-000000001222";
/// The End op.
const END: [u8; 2] = [0x29, 0x02];

/// An IFR op of `op_code` holding `data`, which opens a scope if `scope`.
fn op(op_code: u8, scope: bool, data: &[u8]) -> Vec<u8> {
    let length = u8::try_from(2 + data.len()).expect("the op's Length fits a u8");
    let scope = match scope {
        true => 0x80,
        false => 0x00,
    };
    [&[op_code, length | scope][..], data].concat()
}

/// A FormSet of GUID fixture_guid(`guid`), titled by string ID 1, holding a form with the
/// CHECKBOX of prompt string `prompt`, on no VarStore, then `after`, outside the form.
fn form_set(guid: u8, prompt: u16, after: &[u8]) -> Vec<u8> {
    let form_set = [
        &fixture_guid(guid)[..],
        &[0x01, 0x00, 0x01, 0x00], // FormSetTitle, Help
        &[0x01],                   // Flags: one ClassGuid
        &[0x22; 16],               // ClassGuid
    ]
    .concat();
    let checkbox = [
        &prompt.to_le_bytes()[..], // Prompt
        &[0x01, 0x00],             // Help
        &prompt.to_le_bytes(),     // QuestionId
        &[0x00; 4],                // VarStoreId (none), VarStoreInfo
        &[0x00, 0x00],             // Flags, CheckBox Flags
    ]
    .concat();
    [
        op(0x0E, true, &form_set),
        op(0x01, true, &[0x01, 0x00, 0x01, 0x00]), // Form: FormId, FormTitle
        op(0x06, false, &checkbox),
        END.to_vec(),
        after.to_vec(),
        END.to_vec(),
    ]
    .concat()
}

/// The HiiDB file of one package list (UEFI 2.11 §33.3.1) holding a form package of three
/// FormSets, the second of them with a VARSTORE op that ends after 4 of its data bytes, which
/// uefisettings ignores (UEFI 2.11 §33.2.5.10.1), and an "en" strings package of the title and
/// the prompts Q1, Q2 and Q3, one per FormSet; and the offset of that FormSet in the form package.
fn hiidb() -> (Vec<u8>, usize) {
    let first = form_set(0x21, 2, &[]);
    let ifr = [
        first.clone(),
        form_set(0x22, 3, &op(0x24, false, &[0x00; 4])),
        form_set(0x23, 4, &[]),
    ]
    .concat();
    let length = |package: &[u8]| u32::try_from(4 + package.len()).expect("the package fits");
    let forms = [&length(&ifr).to_le_bytes()[..3], &[0x02], &ifr].concat();
    let mut blocks = Vec::new();
    for string in ["Title", "Q1", "Q2", "Q3"] {
        blocks.push(0x14); // EFI_HII_SIBT_STRING_UCS2
        blocks.extend(string.encode_utf16().flat_map(u16::to_le_bytes));
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
    let hiidb = [
        &LIST[..],
        &list_length.to_le_bytes(),
        &forms,
        &strings,
        &end,
    ]
    .concat();
    (hiidb, first.len())
}

/// What `uefisettings hii <args> -f <file> --no-efivars` prints on stdout and stderr for the
/// HiiDB file `hiidb`, which it must exit 0 for.
fn run(args: &[&str], hiidb: &[u8]) -> (String, String) {
    let dir = tempfile::tempdir().expect("create a directory");
    let path = dir.path().join("hiidb.bin");
    fs::write(&path, hiidb).expect("write the HiiDB");
    let output = Command::new(env!("CARGO_BIN_EXE_uefisettings"))
        .arg("hii")
        .args(args)
        .arg("-f")
        .arg(&path)
        .arg("--no-efivars")
        .output()
        .expect("run uefisettings");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "{args:?}: {:?}: stdout {stdout}, stderr {stderr}",
        output.status
    );
    (stdout, stderr)
}

/// The record of the ignored FormSet, from its offset on.
fn record(offset: usize) -> String {
    format!(
        "the IFR that uefisettings ignores at offset {offset} of a form package of package list \
         {LIST_TEXT}: the FormSet {IGNORED_TEXT}, which does not parse; uefisettings ignores it, \
         where UEFI 2.11 §33.2.5.10.1 disables only the form of a malformed op and ignores only a \
         malformed forms set: "
    )
}

#[test]
fn list_questions_names_the_ignored_ifr_on_stderr() {
    let (hiidb, offset) = hiidb();
    let (stdout, stderr) = run(&["list-questions", "--json"], &hiidb);

    let listed: serde_json::Value = serde_json::from_str(&stdout).expect("parse stdout");
    let names: Option<Vec<&str>> = listed.as_array().map(|questions| {
        questions
            .iter()
            .filter_map(|question| question["name"].as_str())
            .collect()
    });
    assert_eq!(names, Some(vec!["Q1", "Q3"]), "stdout: {stdout}");
    let warning = format!("warning: questions may be in {}", record(offset));
    assert_eq!(
        stderr
            .lines()
            .filter(|line| line.starts_with(&warning))
            .count(),
        1,
        "stderr: {stderr}"
    );
}

#[test]
fn get_lists_the_ignored_ifr_in_its_answer() {
    let (hiidb, offset) = hiidb();
    let (stdout, _) = run(&["get", "Q2", "--json"], &hiidb);

    let answer: serde_json::Value = serde_json::from_str(&stdout).expect("parse stdout");
    assert_eq!(
        answer["responses"].as_array().map(Vec::len),
        Some(0),
        "{stdout}"
    );
    let records = answer["ignored_ifr"].as_array();
    let reason = format!(
        "the FormSet {IGNORED_TEXT}, which does not parse; uefisettings ignores it, where UEFI \
         2.11 §33.2.5.10.1"
    );
    // each record's package list, offset and whether its reason is that of the FormSet
    type Record<'a> = (Option<&'a str>, Option<u64>, bool);
    let got: Option<Vec<Record<'_>>> = records.map(|records| {
        records
            .iter()
            .map(|record| {
                (
                    record["package_list"].as_str(),
                    record["offset"].as_u64(),
                    record["reason"]
                        .as_str()
                        .is_some_and(|got| got.starts_with(&reason)),
                )
            })
            .collect()
    });
    assert_eq!(
        got,
        Some(vec![(Some(LIST_TEXT), u64::try_from(offset).ok(), true)]),
        "{stdout}"
    );
}
