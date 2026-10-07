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

//! Helpers of the tests that run inside the QEMU test guests.
//!
//! `tests/qemu/run.sh` builds this crate's test binaries for musl and boots each scenario
//! under OVMF, with the binaries and a static `uefisettings` in the initramfs.
//! `tests/qemu/init` runs the test binary that the boot's kernel command line names, then
//! checks the kernel's health. The tests assert inside the guest; libtest reports their
//! outcomes on the second serial port.
//!
//! Every helper and test that reads the machine's files or runs `uefisettings` calls
//! [`require_test_vm`] first, so on any other machine the tests fail before they touch
//! its firmware settings.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fs;
use std::process::Command;
use std::process::Stdio;

use serde::de::DeserializeOwned;
use serde::Deserialize;

/// The kernel command line parameter that names a boot's test binary; `run.sh` passes it
/// to every test guest and to no other machine.
pub const TEST_PARAMETER: &str = "uefisettings.test=";

/// Path of the static `uefisettings` in the guest.
pub const UEFISETTINGS: &str = "/bin/uefisettings";

/// The efivarfs mount point.
pub const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// The variable through which the firmware of OCP machines publishes the HII database
/// (`src/lib/hii/extract.rs`).
pub const HIIDB_VARIABLE: &str =
    "/sys/firmware/efi/efivars/HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0";

/// `Backend::Unknown` in `thrift/uefisettings_backend.thrift`.
pub const BACKEND_UNKNOWN: i32 = 0;

/// Panics unless this process runs in a QEMU test guest, whose kernel command line has
/// [`TEST_PARAMETER`].
#[track_caller]
pub fn require_test_vm() {
    let cmdline = fs::read_to_string("/proc/cmdline").expect("cannot read /proc/cmdline");
    assert!(
        cmdline
            .split_whitespace()
            .any(|parameter| parameter.starts_with(TEST_PARAMETER)),
        "not a QEMU test guest: the kernel command line {cmdline:?} lacks {TEST_PARAMETER}; \
         run these tests through tests/qemu/run.sh"
    );
}

/// How a `uefisettings` run exited, and what it printed.
#[derive(Debug)]
pub struct Output {
    /// The exit code, or `None` if a signal killed it.
    pub code: Option<i32>,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

impl Output {
    /// Parses standard output as one JSON value; panics unless the run exited with `code`
    /// and printed exactly that.
    #[track_caller]
    pub fn json<T: DeserializeOwned>(&self, code: i32) -> T {
        assert_eq!(self.code, Some(code), "unexpected exit: {self:#?}");
        serde_json::from_str(&self.stdout).unwrap_or_else(|error| {
            panic!(
                "cannot parse the output as {}: {error}: {self:#?}",
                std::any::type_name::<T>()
            )
        })
    }
}

/// Runs `uefisettings` with `args` and empty standard input.
#[track_caller]
pub fn uefisettings(args: &[&str]) -> Output {
    require_test_vm();
    let output = Command::new(UEFISETTINGS)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("cannot run {UEFISETTINGS} {args:?}: {error}"));
    Output {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Runs `uefisettings` with `args`; panics unless it exits with 0 and prints one JSON value
/// of type `T`.
#[track_caller]
pub fn json<T: DeserializeOwned>(args: &[&str]) -> T {
    uefisettings(args).json(0)
}

/// Runs `uefisettings` with `args`; panics unless it fails the way `src/main.rs` reports
/// every error: it exits with 1 and prints one JSON error object, and nothing else. A panic
/// exits with 101, and output printed before the error object fails the parse. The message
/// is for people, so only its presence is checked.
#[track_caller]
pub fn json_error(args: &[&str]) -> ErrorObject {
    let error: ErrorObject = uefisettings(args).json(1);
    assert!(
        !error.error_message.is_empty(),
        "{args:?}: the error object has an empty error_message"
    );
    error
}

/// Output of `identify --json` (`MachineInfo`). The output types read only the fields the
/// tests use, so additions to the output do not break them.
#[derive(Debug, Deserialize)]
pub struct MachineInfo {
    /// The detected backends.
    pub backend: Vec<i32>,
}

/// What a failing command prints (`Error`).
#[derive(Debug, Deserialize)]
pub struct ErrorObject {
    /// The error chain.
    pub error_message: String,
}
