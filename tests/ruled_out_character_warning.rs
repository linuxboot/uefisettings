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

//! The warning that uefisettings logs for a string that holds a character that UEFI 2.11 rules
//! out of strings, which reads as U+FFFD: one per string, naming the first such character, while
//! list-strings still writes valid JSON. A string that holds only common control codes
//! (§33.2.6.2.4) gets none.

// the builds that read HiiDB files and log as RUST_LOG says
#![cfg(all(hiidb_files, target_os = "linux"))]

use std::fs;
use std::process::Command;

/// The HiiDB file of one package list of a strings package and the End package (UEFI 2.11
/// §33.3.1, §33.3.6): its header holds Language "en", and its string blocks are an
/// EFI_HII_SIBT_STRING_UCS2 of the CHAR16s of each of `strings`, then EFI_HII_SIBT_END.
fn hiidb(strings: &[&[u16]]) -> Vec<u8> {
    let header = [
        &[0u8; 32][..],      // LanguageWindow
        &1u16.to_le_bytes(), // LanguageName
        b"en\0",             // Language
    ]
    .concat();
    let mut blocks = Vec::new();
    for units in strings {
        blocks.push(0x14);
        blocks.extend(units.iter().chain(&[0]).flat_map(|unit| unit.to_le_bytes()));
    }
    blocks.push(0x00);
    let hdr_size = u32::try_from(4 + 4 + 4 + header.len()).expect("HdrSize fits a u32");
    let length = hdr_size + u32::try_from(blocks.len()).expect("the blocks fit a u32");
    let strings = [
        &length.to_le_bytes()[..3],
        &[0x04], // EFI_HII_PACKAGE_STRINGS
        &hdr_size.to_le_bytes(),
        &hdr_size.to_le_bytes(), // StringInfoOffset
        &header,
        &blocks,
    ]
    .concat();
    let end = [0x04, 0x00, 0x00, 0xDF];
    let list_length = u32::try_from(16 + 4 + strings.len() + end.len()).expect("the list fits");
    [&[0x11; 16][..], &list_length.to_le_bytes(), &strings, &end].concat()
}

/// What `uefisettings hii list-strings --json -f <file>` prints on stdout, parsed as JSON, and on
/// stderr, with RUST_LOG=warn, for the HiiDB file `hiidb`.
fn list_strings(hiidb: &[u8]) -> (serde_json::Value, String) {
    let dir = tempfile::tempdir().expect("create a directory");
    let path = dir.path().join("hiidb.bin");
    fs::write(&path, hiidb).expect("write the HiiDB");
    let output = Command::new(env!("CARGO_BIN_EXE_uefisettings"))
        .args(["hii", "list-strings", "--json", "-f"])
        .arg(&path)
        .env("RUST_LOG", "warn")
        .output()
        .expect("run uefisettings");
    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "{:?}: stdout {stdout}, stderr {stderr}",
        output.status
    );
    let json = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("parse stdout {stdout} as JSON: {err}"));
    (json, stderr)
}

/// Whether `json` holds the string `text`.
fn lists(json: &serde_json::Value, text: &str) -> bool {
    json.to_string()
        .contains(&serde_json::Value::from(text).to_string())
}

/// What every warning of a ruled-out character ends with.
const READS_AS_U_FFFD: &str = "it reads as U+FFFD";

#[test]
fn list_strings_warns_once_per_string_of_its_first_ruled_out_character() {
    let cases: [(&str, &[u16], &str, &str); 3] = [
        (
            "private use",
            &[0x41, 0xE000, 0xE001, 0x42],
            "A\u{FFFD}\u{FFFD}B",
            "string 1 of the \"en\" strings package holds U+E000, which is in the private use \
             area (UEFI 2.11 §33.2.6.2.1): it reads as U+FFFD",
        ),
        (
            "a surrogate pair",
            &[0xD83D, 0xDE00],
            "\u{FFFD}\u{FFFD}",
            "string 1 of the \"en\" strings package holds U+D83D, which is a surrogate (UEFI \
             2.11 §33.2.6.2.2): it reads as U+FFFD",
        ),
        (
            "U+FC00",
            &[0xFC00],
            "\u{FFFD}",
            "string 1 of the \"en\" strings package holds U+FC00, which is between 0xF000 and \
             0xFCFF (UEFI 2.11 §33.3.6.3.1, §33.3.6.3.2): it reads as U+FFFD",
        ),
    ];
    // string 2 holds a ruled-out character too, so that its warning is its own
    let string_2 = "string 2 of the \"en\" strings package holds U+F000, which is in the private \
                    use area (UEFI 2.11 §33.2.6.2.1): it reads as U+FFFD";
    for (case, units, string, warning) in cases {
        let (json, stderr) = list_strings(&hiidb(&[units, &[0xF000, 0x5A]]));

        assert!(lists(&json, string), "{case}: {string:?} is listed: {json}");
        assert!(
            lists(&json, "\u{FFFD}Z"),
            "{case}: string 2 is listed: {json}"
        );
        assert_eq!(
            (
                stderr.matches(warning).count(),
                stderr.matches(string_2).count(),
                stderr.matches(READS_AS_U_FFFD).count()
            ),
            (1, 1, 2),
            "{case}: one warning per string: {stderr}"
        );
    }
}

#[test]
fn list_strings_keeps_control_codes_without_a_warning() {
    let (json, stderr) = list_strings(&hiidb(&[&[0xF620, 0x51, 0xF621, 0xF7AB, 0xF8FF]]));

    assert!(
        lists(&json, "\u{F620}Q\u{F621}\u{F7AB}\u{F8FF}"),
        "the control codes are listed: {json}"
    );
    assert!(!stderr.contains(READS_AS_U_FFFD), "stderr: {stderr}");
}
