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

//! The warning that uefisettings logs for an SCSU string whose text does not end at its first
//! 0x00 byte: it reads the string up to its first decoded U+0000 (UEFI 2.11 §33.3.6.2), while
//! edk2's HiiDatabase ends it at the first 0x00 byte (AsciiStrSize), so the firmware may show
//! other strings.

// the builds that read HiiDB files and log as RUST_LOG says
#![cfg(all(hiidb_files, target_os = "linux"))]

use std::fs;
use std::process::Command;

/// edk2's mLanguageWindow (edk2-stable202608 MdeModulePkg/Universal/HiiDatabaseDxe/String.c).
const EDK2_LANGUAGE_WINDOW: [u16; 16] = [
    0x0000, 0x0080, 0x0100, 0x0300, 0x2000, 0x2080, 0x2100, 0x3000, //
    0x0080, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00,
];

/// The HiiDB file of one package list of a strings package and the End package (UEFI 2.11
/// §33.3.1, §33.3.6): its header holds `language_window` and Language "en", and its string
/// blocks are EFI_HII_SIBT_STRING_SCSU of `text`, then EFI_HII_SIBT_STRING_UCS2 "Z" and
/// EFI_HII_SIBT_END.
fn hiidb(language_window: &[u16; 16], text: &[u8]) -> Vec<u8> {
    let language_window: Vec<u8> = language_window
        .iter()
        .flat_map(|window| window.to_le_bytes())
        .collect();
    let header = [
        &language_window[..],
        &1u16.to_le_bytes(), // LanguageName
        b"en\0",             // Language
    ]
    .concat();
    let blocks = [&[0x10][..], text, &[0x14, b'Z', 0x00, 0x00, 0x00, 0x00]].concat();
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

/// The warning for string 1.
const WARNING: &str = "string 1's SCSU text does not end at its first 0x00 byte, where edk2's \
                       HiiDatabase ends it (AsciiStrSize), so the firmware may show other strings";

#[test]
fn list_strings_warns_of_scsu_strings_that_edk2_ends_elsewhere() {
    let cases: [(&str, &[u16; 16], &[u8], &str); 4] = [
        // "A", Font Family 0x01, "B"
        (
            "an inner 0x00",
            &EDK2_LANGUAGE_WINDOW,
            &[0x41, 0x7F, 0x00, 0x01, 0x42, 0x00],
            "\"A\u{F701}B\"",
        ),
        (
            "a terminator in Unicode mode",
            &EDK2_LANGUAGE_WINDOW,
            &[0x0F, 0x41, 0x42, 0x00, 0x00],
            "\"\u{4142}\"",
        ),
        (
            "an SQU terminator",
            &EDK2_LANGUAGE_WINDOW,
            &[0x41, 0x0E, 0x00, 0x00],
            r#""A""#,
        ),
        // dynamic window 0 at 0x0000: 0x80 is U+0000
        ("a zero LanguageWindow", &[0; 16], &[0x41, 0x80], r#""A""#),
    ];
    for (case, language_window, text, string) in cases {
        let (stdout, stderr) = list_strings(&hiidb(language_window, text));

        assert!(
            stdout.contains(string),
            "{case}: {string} is listed: {stdout}"
        );
        assert!(stdout.contains(r#""Z""#), "{case}: Z is listed: {stdout}");
        assert!(stderr.contains(WARNING), "{case}: stderr: {stderr}");
    }
}

#[test]
fn list_strings_does_not_warn_of_scsu_strings_that_edk2_ends_alike() {
    let cases: [(&str, &[u8], &str); 2] = [
        ("a 0x00 terminator", &[0x41, 0x00], r#""A""#),
        ("an SQ0 0x00 terminator", &[0x41, 0x01, 0x00], r#""A""#),
    ];
    for (case, text, string) in cases {
        let (stdout, stderr) = list_strings(&hiidb(&EDK2_LANGUAGE_WINDOW, text));

        assert!(
            stdout.contains(string),
            "{case}: {string} is listed: {stdout}"
        );
        assert!(stdout.contains(r#""Z""#), "{case}: Z is listed: {stdout}");
        assert!(!stderr.contains("SCSU"), "{case}: stderr: {stderr}");
    }
}
