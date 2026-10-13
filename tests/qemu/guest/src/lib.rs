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
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
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

/// `Backend::Hii` in `thrift/uefisettings_backend.thrift`.
pub const BACKEND_HII: i32 = 1;

/// The variable that holds the answers of the main form of EDK2's DriverSample, which the
/// HII scenarios load: `MyIfrNVData`, with the formset GUID as its vendor.
pub const DRIVER_SAMPLE_VARIABLE: &str =
    "/sys/firmware/efi/efivars/MyIfrNVData-a04a27f4-df00-4d42-b552-39511302113d";

/// Size of the attributes that efivarfs puts before the data of a variable.
pub const EFIVARFS_HEADER_SIZE: usize = 4;

/// The prefix of the answer of a question whose value the HII backend cannot read
/// (`src/lib/hii/forms.rs`).
pub const UNAVAILABLE: &str = "<ValueUnavailable";

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

/// Questions of the main form of EDK2's DriverSample that the HII tests use, and the
/// offsets of their answers in the data of [`DRIVER_SAMPLE_VARIABLE`].
pub mod driver_sample {
    /// A one-of question whose options "My one-of text #1", "#2" and "#3" store 0, 1 and 3.
    pub const ONE_OF: &str = "My Keyword Namespace Test";
    /// Offset of the 8-bit answer of [`ONE_OF`].
    pub const ONE_OF_OFFSET: usize = 91;
    /// A check box, which the form shows twice, both times on one field.
    pub const CHECK_BOX: &str = "Activate this check box";
    /// Offset of the 8-bit answer of [`CHECK_BOX`].
    pub const CHECK_BOX_OFFSET: usize = 92;
    /// A numeric question from 0 to 243 in steps of 1.
    pub const NUMERIC: &str = "How old are you? (Step)";
    /// Offset of the 8-bit answer of [`NUMERIC`].
    pub const NUMERIC_OFFSET: usize = 85;
    /// A one-of question whose options "3F8", "2F8", "3E8" and "2E8" store those numbers.
    pub const SERIAL_PORT: &str = "Serial port IO address";
    /// Offset of the 16-bit little-endian answer of [`SERIAL_PORT`].
    pub const SERIAL_PORT_OFFSET: usize = 194;
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

/// A question as `hii list-questions --json` prints it, and as `get` and `set` print it in
/// their responses (`Question`).
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct Question {
    /// The prompt.
    pub name: String,
    /// The current answer.
    pub answer: String,
    /// The answers that a one-of question accepts.
    pub options: Vec<String>,
}

/// Output of `get --json` and `set --json` (`GetResponseList` and `SetResponseList`).
#[derive(Debug, Deserialize)]
pub struct Responses {
    /// One response per matching question.
    pub responses: Vec<Response>,
}

/// One response of `get --json` or `set --json` (`GetResponse` or `SetResponse`).
#[derive(Debug, Deserialize)]
pub struct Response {
    /// The backend that answered.
    pub backend: i32,
    /// The question, with its answer after the command.
    pub question: Question,
    /// Whether a `set` changed the answer; `get` does not print it.
    #[serde(default)]
    pub modified: bool,
}

/// Runs `uefisettings` with `args`, a `get` or `set` command; panics unless it exits with 0
/// and prints exactly one response, from `backend`. Returns the question of the response,
/// and whether it was modified.
#[track_caller]
pub fn single_response(args: &[&str], backend: i32) -> (Question, bool) {
    let Responses { responses } = json(args);
    let [response] = <[Response; 1]>::try_from(responses)
        .unwrap_or_else(|responses| panic!("{args:?}: expected one response: {responses:#?}"));
    assert_eq!(response.backend, backend, "{args:?}: {response:#?}");
    (response.question, response.modified)
}

/// The data of an efivarfs variable, without the attributes, or `None` if it does not
/// exist.
#[track_caller]
pub fn variable_data(path: &str) -> Option<Vec<u8>> {
    require_test_vm();
    match fs::read(path) {
        Ok(bytes) => {
            assert!(bytes.len() >= EFIVARFS_HEADER_SIZE, "{path}: {bytes:02x?}");
            Some(bytes[EFIVARFS_HEADER_SIZE..].to_vec())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read {path}: {error}"),
    }
}

/// Reads the HII database where the `HiiDB` variable points, through `/dev/mem`, as
/// `uefisettings` does. Panics if the variable does not exist.
#[track_caller]
pub fn read_published_database() -> io::Result<Vec<u8>> {
    let hiidb = variable_data(HIIDB_VARIABLE).expect("the HiiDB variable does not exist");
    let (length, address) = hiidb.split_at(size_of::<u32>());
    let length = u32::from_le_bytes(length.try_into().expect("HiiDB holds no length"));
    let address = u64::from_le_bytes(address.try_into().expect("HiiDB holds no 64-bit address"));
    let mut database = vec![0; length.try_into().expect("the length exceeds usize")];
    let mut mem = File::open("/dev/mem")?;
    mem.seek(SeekFrom::Start(address))?;
    mem.read_exact(&mut database)?;
    Ok(database)
}

/// The bytes that differ between `before` and `after`, which have the same length, as
/// (offset, new value) pairs.
pub fn changed_bytes(before: &[u8], after: &[u8]) -> Vec<(usize, u8)> {
    assert_eq!(before.len(), after.len(), "the variable changed its size");
    before
        .iter()
        .zip(after)
        .enumerate()
        .filter(|(_, (old, new))| old != new)
        .map(|(offset, (_, &new))| (offset, new))
        .collect()
}
