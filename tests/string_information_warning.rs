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

//! The warning that uefisettings logs for a strings package whose StringInfoOffset points past
//! its HdrSize: it reads the strings at StringInfoOffset (UEFI 2.11 §33.3.6.1), while edk2's
//! HiiDatabase reads them at HdrSize, so the firmware may show other strings.

// the builds that read HiiDB files and log as RUST_LOG says
#![cfg(all(hiidb_files, target_os = "linux"))]

use std::fs;
use std::process::Command;

/// The HiiDB file of one package list of a strings package and the End package (UEFI 2.11
/// §33.3.1, §33.3.6): its header holds Language "en" and `padding` bytes of 0xAA, and its string
/// ID 1, "A", follows `gap` bytes of 0xAA after the header, at StringInfoOffset.
fn hiidb(padding: usize, gap: usize) -> Vec<u8> {
    let header = [
        &[0x00; 32][..],     // LanguageWindow
        &1u16.to_le_bytes(), // LanguageName
        b"en\0",             // Language
        &vec![0xAA; padding],
    ]
    .concat();
    // EFI_HII_SIBT_STRING_UCS2 "A", then EFI_HII_SIBT_END
    let blocks = [0x14, b'A', 0x00, 0x00, 0x00, 0x00];
    let hdr_size = u32::try_from(4 + 4 + 4 + header.len()).expect("HdrSize fits a u32");
    let string_info_offset = hdr_size + u32::try_from(gap).expect("the gap fits a u32");
    let length = string_info_offset + u32::try_from(blocks.len()).expect("the blocks fit a u32");
    let strings = [
        &length.to_le_bytes()[..3],
        &[0x04], // EFI_HII_PACKAGE_STRINGS
        &hdr_size.to_le_bytes(),
        &string_info_offset.to_le_bytes(),
        &header,
        &vec![0xAA; gap],
        &blocks,
    ]
    .concat();
    let end = [0x04, 0x00, 0x00, 0xDF];
    let list_length = u32::try_from(16 + 4 + strings.len() + end.len()).expect("the list fits");
    [&[0x11; 16][..], &list_length.to_le_bytes(), &strings, &end].concat()
}

/// What `uefisettings hii list-strings --json -f <file>` prints on stdout and stderr, with
/// RUST_LOG=warn, for the HiiDB file `hiidb`.
fn list_strings(hiidb: &[u8]) -> (String, String) {
    let dir = tempfile::tempdir().expect("create a directory");
    let path = dir.path().join("hiidb.bin");
    fs::write(&path, hiidb).expect("write the HiiDB");
    let output = Command::new(env!("CARGO_BIN_EXE_uefisettings"))
        .args(["hii", "list-strings", "--json", "-f"])
        .arg(&path)
        .env("RUST_LOG", "warn")
        .output()
        .expect("run uefisettings");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "{:?}: stdout {stdout}, stderr {stderr}",
        output.status
    );
    (stdout, stderr)
}

#[test]
fn list_strings_warns_of_string_information_past_hdr_size() {
    let (stdout, stderr) = list_strings(&hiidb(3, 4));

    assert!(stdout.contains(r#""A""#), "the string is listed: {stdout}");
    assert!(
        stderr.contains(
            "StringInfoOffset 56 is past HdrSize 52: the strings are read from StringInfoOffset \
             (UEFI 2.11 §33.3.6.1), while edk2's HiiDatabase reads them from HdrSize, so the \
             firmware may show other strings"
        ),
        "stderr: {stderr}"
    );
}

#[test]
fn list_strings_does_not_warn_of_string_information_at_hdr_size() {
    let (stdout, stderr) = list_strings(&hiidb(3, 0));

    assert!(stdout.contains(r#""A""#), "the string is listed: {stdout}");
    assert!(!stderr.contains("StringInfoOffset"), "stderr: {stderr}");
}

/// The warning's line keeps env_logger's default header, whatever uefisettings escapes in its
/// message: a timestamp in seconds, the level padded to 5 columns and the target.
#[test]
fn list_strings_warning_keeps_the_default_log_header() {
    let (_, stderr) = list_strings(&hiidb(3, 4));

    let header = stderr
        .lines()
        .find(|line| line.contains("StringInfoOffset 56"))
        .and_then(|line| line.strip_prefix('['))
        .and_then(|line| line.split_once("] "))
        .map(|(header, _)| header)
        .unwrap_or_else(|| panic!("no warning line with a header: {stderr}"));
    let (timestamp, rest) = header
        .split_once(' ')
        .unwrap_or_else(|| panic!("no timestamp in {header:?}"));
    let in_seconds = timestamp.len() == 20
        && timestamp
            .char_indices()
            .all(|(index, character)| match index {
                4 | 7 => character == '-',
                10 => character == 'T',
                13 | 16 => character == ':',
                19 => character == 'Z',
                _ => character.is_ascii_digit(),
            });
    assert!(in_seconds, "timestamp {timestamp:?} of {header:?}");
    assert_eq!(
        rest, "WARN  uefisettings::hii::strings",
        "header {header:?}"
    );
}
