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

//! The output of hii commands that read a saved HiiDB and efivars dump and nothing of the machine:
//! byte for byte the same on every build that reads them, Linux's and macOS's.
//! tests/fixtures/offline holds the dump, which the unit test offline_fixtures_are_current
//! writes, and the outputs; UEFISETTINGS_BLESS=1 rewrites both.

// the builds that read efivars dumps
#![cfg(efivar_dumps)]

use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Command;

/// The dump, in dump/, and the outputs.
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/offline");
/// The variable that makes offline_output_is_golden rewrite the outputs.
const BLESS: &str = "UEFISETTINGS_BLESS";

/// Each output in FIXTURES, and the arguments that print it, run in FIXTURES.
const CASES: [(&str, &[&str]); 5] = [
    (
        "list-questions.json",
        &["hii", "list-questions", "--json", "--efivars", "dump"],
    ),
    (
        "get.json",
        &["hii", "get", "Fast Boot", "--json", "--efivars", "dump"],
    ),
    (
        "list-questions-no-efivars.json",
        &[
            "hii",
            "list-questions",
            "--json",
            "-f",
            "dump/hiidb.bin",
            "--no-efivars",
        ],
    ),
    ("show-ifr.txt", &["hii", "show-ifr", "--efivars", "dump"]),
    (
        "list-strings.json",
        &["hii", "list-strings", "--json", "-f", "dump/hiidb.bin"],
    ),
];

/// Whether `value`, that of BLESS, asks for a rewrite: only "1" does.
fn blesses(value: Option<&OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
}

#[test]
fn only_bless_1_rewrites_the_outputs() {
    for (value, want) in [
        (None, false),
        (Some(""), false),
        (Some("0"), false),
        (Some("1"), true),
    ] {
        assert_eq!(blesses(value.map(OsStr::new)), want, "{BLESS}={value:?}");
    }
}

#[test]
fn offline_output_is_golden() {
    for (name, args) in CASES {
        let output = Command::new(env!("CARGO_BIN_EXE_uefisettings"))
            .args(args)
            .current_dir(FIXTURES)
            .output()
            .expect("run uefisettings");
        assert!(output.status.success(), "{name}: {output:?}");
        let path = Path::new(FIXTURES).join(name);

        if blesses(std::env::var_os(BLESS).as_deref()) {
            fs::write(&path, &output.stdout)
                .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
            continue;
        }
        let golden =
            fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            std::str::from_utf8(&output.stdout).expect("UTF-8 output"),
            std::str::from_utf8(&golden).expect("UTF-8 golden output"),
            "{name}; {BLESS}=1 rewrites it"
        );
    }
}
