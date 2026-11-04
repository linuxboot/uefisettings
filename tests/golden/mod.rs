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

//! Golden files, which tests compare output with byte for byte; UEFISETTINGS_BLESS=1 makes them
//! rewrite the files instead.

use std::ffi::OsStr;
use std::fs;
use std::path::Path;

/// The variable that makes assert_golden rewrite the golden files.
const BLESS: &str = "UEFISETTINGS_BLESS";

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

/// Asserts that `output` equals the file `name` in `dir`, or writes it there when BLESS asks for
/// a rewrite.
pub fn assert_golden(dir: &str, name: &str, output: &[u8]) {
    let path = Path::new(dir).join(name);
    if blesses(std::env::var_os(BLESS).as_deref()) {
        fs::write(&path, output)
            .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
        return;
    }
    let golden = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    assert_eq!(
        std::str::from_utf8(output).expect("UTF-8 output"),
        std::str::from_utf8(&golden).expect("UTF-8 golden output"),
        "{name}; {BLESS}=1 rewrites it"
    );
}
