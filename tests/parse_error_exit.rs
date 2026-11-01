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

//! The exit status of uefisettings when it cannot print clap's message: clap's own, 0 for help
//! and 2 for a usage error, as clap's Error::exit, which ignores the failed print, gives it.

use std::fs::File;
use std::process::Command;
use std::process::Stdio;

/// The exit code of uefisettings with `args`, its stdout and stderr on /dev/full, where every
/// write fails.
fn exit_code_on_a_full_device(args: &[&str]) -> Option<i32> {
    let full = || {
        File::options()
            .write(true)
            .open("/dev/full")
            .expect("open /dev/full")
    };
    Command::new(env!("CARGO_BIN_EXE_uefisettings"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(full())
        .stderr(full())
        .status()
        .expect("run uefisettings")
        .code()
}

#[test]
fn parse_errors_exit_as_clap_exits_when_nothing_prints() {
    let cases: [(&[&str], i32); 4] = [
        (&["--help"], 0),
        (&["hii", "--help"], 0),
        (&["bogus"], 2),
        (&["hii", "get"], 2),
    ];
    for (args, want) in cases {
        assert_eq!(exit_code_on_a_full_device(args), Some(want), "{args:?}");
    }
}
