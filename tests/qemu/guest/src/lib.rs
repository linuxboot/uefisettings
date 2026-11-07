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
//! under EDK2's firmware, with the binaries and a static `uefisettings` in the initramfs.
//! `tests/qemu/init` runs the test binary that the boot's kernel command line names, then
//! checks the kernel's health. The tests assert inside the guest; libtest reports their
//! outcomes on the test terminal.
//!
//! Every helper and test that reads the machine's files or runs `uefisettings` calls
//! [`require_test_vm`] first, so on any other machine the tests fail before they touch
//! its firmware settings.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::ops::RangeInclusive;
use std::os::unix::fs::FileExt;
use std::process::Command;
use std::process::Stdio;
use std::slice;

use rustix::fs::IFlags;
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

/// What the Linux build says to `capsule config-data` and `capsule result-table`, as it does not
/// read their configuration tables yet (`src/capsule_command.rs`).
pub const NO_CONFIGURATION_TABLES_ON_LINUX: &str =
    "reading this configuration table is not supported on Linux yet; run uefisettings.efi in \
     the UEFI Shell";

/// The variable in which publish-hiidb puts the CRC-32 of the HII database that
/// [`HIIDB_VARIABLE`] points at.
pub const HIIDB_CRC32_VARIABLE: &str =
    "/sys/firmware/efi/efivars/HiiDBCrc32-de145b29-c3cd-455f-91de-a76237b67c52";

/// `Backend::Unknown` in `thrift/uefisettings_backend.thrift`.
pub const BACKEND_UNKNOWN: i32 = 0;

/// `Backend::Hii` in `thrift/uefisettings_backend.thrift`.
pub const BACKEND_HII: i32 = 1;

/// What comes before `get` or `set`: `["hii"]` for the HII commands, `[]` for the generic ones.
pub const PREFIXES: [&[&str]; 2] = [&["hii"], &[]];

/// The variable that holds the answers of the main form of EDK2's DriverSample, which the
/// HII scenarios load: `MyIfrNVData`, with the formset GUID as its vendor.
pub const DRIVER_SAMPLE_VARIABLE: &str =
    "/sys/firmware/efi/efivars/MyIfrNVData-a04a27f4-df00-4d42-b552-39511302113d";

/// DriverSample's EFI variable `MyEfiVar`, which its `Vfr.vfr` declares without
/// EFI_VARIABLE_RUNTIME_ACCESS: the scenario `hii` creates it with runtime access first
/// (`tests/qemu/vars/my-ifr-nv-data-runtime-my-efi-var.json`), as some vendors' firmware does.
pub const MY_EFI_VAR: &str =
    "/sys/firmware/efi/efivars/MyEfiVar-a04a27f4-df00-4d42-b552-39511302113d";

/// A numeric question of DriverSample's main form, from 0 to 250, on the first byte of the data
/// of [`MY_EFI_VAR`]; `Vfr.vfr` has it displayed in hex.
pub const MY_EFI_VAR_QUESTION: &str = "How tall are you? (Hex)";

/// Size of the attributes that efivarfs puts before the data of a variable.
pub const EFIVARFS_HEADER_SIZE: usize = 4;

/// Linux's EFAULT (`include/uapi/asm-generic/errno-base.h`), with which `/dev/mem`'s read()
/// refuses memory that the kernel does not map.
pub const EFAULT: i32 = 14;

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
    /// The flag that makes `get`, `set` and `hii list-questions` select questions that a
    /// SUPPRESS_IF hides too: [`SERIAL_PORT`], which the form grays out and suppresses while
    /// the serial port is off, and the second [`CHECK_BOX`], whose form is suppressed while
    /// BootOrderLarge is 0.
    pub const INCLUDE_SUPPRESSED: [&str; 2] = ["--include", "suppressed"];
    /// A numeric question from 0 to 243 in a `grayoutif match2 (...)`, which the library does
    /// not evaluate: it may be grayed out.
    pub const MATCH2: &str = "Match2 Test";
    /// Offset of the 8-bit answer of [`MATCH2`].
    pub const MATCH2_OFFSET: usize = 203;
    /// Why the condition of [`MATCH2`] is not evaluated: its first op is a stringref, which the
    /// library does not evaluate.
    pub const MATCH2_REASON: &str = "EFI_IFR_STRING_REF1 not evaluated";
    /// The flag that makes `get` and `set` select questions that a GRAY_OUT_IF may gray out
    /// too, such as [`MATCH2`], and those that an EFI_IFR_LOCKED grays out, such as [`LOCKED`].
    pub const INCLUDE_GRAYED_OUT: [&str; 2] = ["--include", "grayed-out"];
    /// A numeric question on DriverSample's name/value store whose scope holds an
    /// EFI_IFR_LOCKED (`locked` in Vfr.vfr, edk2-stable202608), which grays it out.
    pub const LOCKED: &str = "NameValueVar0";
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
    uefisettings_with_env(args, &[])
}

/// Runs `uefisettings` with `args`, the environment variables `env` added, and empty standard
/// input.
#[track_caller]
pub fn uefisettings_with_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    require_test_vm();
    let output = Command::new(UEFISETTINGS)
        .args(args)
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("cannot run {UEFISETTINGS} {args:?}: {error}"));
    Output {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Writes the output of `output` to the test log, on the line "uefisettings-qemu-test: TAG
/// OUTPUT", which check-shell-log.sh looks for, past libtest's capture, which takes print! but
/// not writes to stdout, on a line of its own after libtest's "test ... ".
#[track_caller]
pub fn write_for_the_shell(tag: &str, output: &Output) {
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "\nuefisettings-qemu-test: {tag} {}",
        output.stdout.trim_end()
    )
    .and_then(|()| stdout.flush())
    .unwrap_or_else(|error| panic!("write the line {tag}: {error}"));
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
    /// The package list that answered, for the HII backend.
    pub selector: String,
    /// The backend that answered.
    pub backend: i32,
    /// The question, with its answer after the command.
    pub question: Question,
    /// Whether a `set` changed the answer; `get` does not print it.
    #[serde(default)]
    pub modified: bool,
}

/// One strings package of `hii list-strings --json` (`HiiStringsPackage`).
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct StringPackage {
    /// The strings, by string ID.
    pub string_package: BTreeMap<String, String>,
    /// The Language of the package's header; optional, so that a build without the field fails
    /// an assertion, not the parse.
    pub language: Option<String>,
}

/// A variable as `variable list` prints it.
#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Variable {
    /// The name.
    pub name: String,
    /// The vendor GUID, in upper case.
    pub guid: String,
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

/// The attributes and data of an efivarfs variable, or `None` if it does not exist.
#[track_caller]
pub fn variable_bytes(path: &str) -> Option<Vec<u8>> {
    require_test_vm();
    match fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => panic!("cannot read {path}: {error}"),
    }
}

/// The data of an efivarfs variable, without the attributes, or `None` if it does not
/// exist.
#[track_caller]
pub fn variable_data(path: &str) -> Option<Vec<u8>> {
    let bytes = variable_bytes(path)?;
    assert!(bytes.len() >= EFIVARFS_HEADER_SIZE, "{path}: {bytes:02x?}");
    Some(bytes[EFIVARFS_HEADER_SIZE..].to_vec())
}

/// Clears the immutable flag of the efivarfs variable at `path`, which efivarfs sets on every
/// variable that it does not know to be removable, such as db (Linux v6.1
/// fs/efivarfs/inode.c efivarfs_get_inode()), so that a test can write it. The guest's
/// busybox has no chattr. Panics if the flags cannot be read or set.
#[track_caller]
pub fn clear_immutable(path: &str) {
    require_test_vm();
    let file = File::open(path).unwrap_or_else(|error| panic!("cannot open {path}: {error}"));
    let flags = rustix::fs::ioctl_getflags(&file)
        .unwrap_or_else(|error| panic!("FS_IOC_GETFLAGS on {path}: {error}"));
    rustix::fs::ioctl_setflags(&file, flags.difference(IFlags::IMMUTABLE))
        .unwrap_or_else(|error| panic!("FS_IOC_SETFLAGS on {path}: {error}"));
}

/// Whether efivarfs holds the variable at `path` immutable, as it holds every variable that it
/// does not know to be removable (Linux v6.1 fs/efivarfs/inode.c efivarfs_get_inode()). Panics
/// if the flags cannot be read.
#[track_caller]
pub fn is_immutable(path: &str) -> bool {
    require_test_vm();
    let file = File::open(path).unwrap_or_else(|error| panic!("cannot open {path}: {error}"));
    rustix::fs::ioctl_getflags(&file)
        .unwrap_or_else(|error| panic!("FS_IOC_GETFLAGS on {path}: {error}"))
        .contains(IFlags::IMMUTABLE)
}

/// EFI_GLOBAL_VARIABLE, the vendor GUID of SetupMode, SecureBoot, AuditMode and DeployedMode.
pub const EFI_GLOBAL_VARIABLE: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
/// EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor GUID of db.
pub const EFI_IMAGE_SECURITY_DATABASE: &str = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";
/// The KEK-signed db append that run.sh puts in the initramfs.
pub const DB_APPEND: &str = "/auth/db-append.auth";
/// Its copy with a data byte flipped.
pub const DB_TAMPERED: &str = "/auth/db-tampered.auth";
/// The same append signed with db's key, which KEK lacks.
pub const DB_UNAUTHORIZED: &str = "/auth/db-unauthorized.auth";
/// The same append signed with a key that no variable holds.
pub const DB_FOREIGN: &str = "/auth/db-foreign.auth";
/// The size of EFI_TIME, which starts an AUTH_2 descriptor, before WIN_CERTIFICATE.
const EFI_TIME_SIZE: usize = 16;
/// The release of the guest's kernel.
const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
/// Linux's EACCES.
pub const EACCES: i32 = 13;
/// Linux's EINVAL.
pub const EINVAL: i32 = 22;
/// The errno of EFI_SECURITY_VIOLATION from each pinned guest kernel (guest-packages-*), by
/// release. Linux's efi_status_to_err() makes it EACCES (v6.1 drivers/firmware/efi/efi.c).
/// Fedora's kernel replaces that switch with a bsearch() whose size and count arguments are
/// swapped (patch-6.17-redhat.patch:1359-1360 of kernel-6.17.1-300.fc43.src.rpm; the kernel's
/// bsearch() takes the count first), so the lookup misses and falls back to EINVAL.
const SECURITY_VIOLATION_ERRNO: [(&str, i32); 3] = [
    ("6.1.0-50-686-pae", EACCES),
    ("6.17.1-300.fc43.x86_64", EINVAL),
    ("6.17.1-300.fc43.aarch64", EINVAL),
];

/// The data of the variable `name` of [`EFI_GLOBAL_VARIABLE`], or `None` if it does not exist.
#[track_caller]
pub fn global_variable(name: &str) -> Option<Vec<u8>> {
    variable_data(&format!("{EFIVARS}/{name}-{EFI_GLOBAL_VARIABLE}"))
}

/// The efivarfs path of db.
pub fn db_path() -> String {
    format!("{EFIVARS}/db-{EFI_IMAGE_SECURITY_DATABASE}")
}

/// The errno of EFI_SECURITY_VIOLATION from the guest's kernel.
#[track_caller]
pub fn security_violation_errno() -> i32 {
    require_test_vm();
    let release = fs::read_to_string(OSRELEASE).expect("cannot read the kernel release");
    let release = release.trim_end();
    SECURITY_VIOLATION_ERRNO
        .iter()
        .find_map(|&(pinned, errno)| (pinned == release).then_some(errno))
        .unwrap_or_else(|| panic!("no errno of EFI_SECURITY_VIOLATION for kernel {release}"))
}

/// The variable data of an AUTH_2 payload: what follows EFI_TIME and WIN_CERTIFICATE, whose
/// first field, dwLength, is its size.
#[track_caller]
pub fn auth2_data(payload: &[u8]) -> &[u8] {
    let length = payload
        .get(EFI_TIME_SIZE..EFI_TIME_SIZE + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .expect("an AUTH_2 payload without WIN_CERTIFICATE");
    let start = EFI_TIME_SIZE + usize::try_from(length).expect("dwLength fits usize");
    payload
        .get(start..)
        .expect("an AUTH_2 payload shorter than its dwLength")
}

/// Panics unless `path` does not exist.
#[track_caller]
pub fn assert_absent(path: &str) {
    require_test_vm();
    match fs::metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        got => panic!("{path} exists or cannot be checked: {got:?}"),
    }
}

/// The path of the vendor ACPI table of `signature`.
pub fn acpi_table_path(signature: &str) -> String {
    format!("/sys/firmware/acpi/tables/{signature}")
}

/// The HII database that publish-hiidb published.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PublishedDatabase {
    /// Its length, from [`HIIDB_VARIABLE`].
    pub length: u32,
    /// Its physical address, from [`HIIDB_VARIABLE`].
    pub address: u64,
    /// Its CRC-32, from [`HIIDB_CRC32_VARIABLE`], for the tests to compare: read() of
    /// `/dev/mem` serves the database only on x86 below the end of Linux's low memory, and
    /// mmap() needs unsafe code, which this crate forbids.
    pub crc32: u32,
}

/// The HII database that [`HIIDB_VARIABLE`] and [`HIIDB_CRC32_VARIABLE`] describe. Panics
/// if either variable does not exist or has the wrong size.
#[track_caller]
pub fn published_database() -> PublishedDatabase {
    let hiidb = variable_data(HIIDB_VARIABLE).expect("the HiiDB variable does not exist");
    let (length, address) = hiidb.split_at(size_of::<u32>());
    PublishedDatabase {
        length: u32::from_le_bytes(length.try_into().expect("HiiDB holds no length")),
        address: u64::from_le_bytes(address.try_into().expect("HiiDB holds no 64-bit address")),
        crc32: published_crc32(),
    }
}

/// The CRC-32 of the HII database that publish-hiidb published, from
/// [`HIIDB_CRC32_VARIABLE`]. Panics if the variable does not exist or has the wrong size.
#[track_caller]
pub fn published_crc32() -> u32 {
    let crc32 =
        variable_data(HIIDB_CRC32_VARIABLE).expect("the HiiDBCrc32 variable does not exist");
    u32::from_le_bytes(crc32.try_into().expect("HiiDBCrc32 holds no CRC-32"))
}

impl PublishedDatabase {
    /// The efivar source's refusal of this database, which no `region`, `EFI_MEMORY_RUNTIME` or
    /// `firmware-reserved`, holds (`src/lib/memory_map/efi_memory_map.rs`
    /// `RangeRefusal`).
    pub fn refusal(&self, region: &str) -> String {
        format!(
            "{:#x}+{:#x} lies in no {region} region",
            self.address, self.length
        )
    }
}

/// Reads the byte at physical `address` with read() of `/dev/mem`, which `uefisettings` tries
/// before mmap().
#[track_caller]
pub fn read_dev_mem_byte(address: u64) -> io::Result<u8> {
    require_test_vm();
    let mut byte = 0;
    File::open("/dev/mem")?.read_exact_at(slice::from_mut(&mut byte), address)?;
    Ok(byte)
}

/// Whether `address` is in a System RAM range of `/proc/iomem`, which `/dev/mem` refuses to
/// read and map under `CONFIG_STRICT_DEVMEM` (`devmem_is_allowed()`), except in x86's first
/// MiB.
#[track_caller]
pub fn is_system_ram(address: u64) -> bool {
    require_test_vm();
    let iomem = fs::read_to_string("/proc/iomem").expect("cannot read /proc/iomem");
    iomem
        .lines()
        .filter_map(|line| line.trim_start().strip_suffix(" : System RAM"))
        .map(parse_iomem_range)
        .any(|range| range.contains(&address))
}

/// Parses a range of `/proc/iomem`, `<start>-<end>` in hexadecimal.
fn parse_iomem_range(range: &str) -> RangeInclusive<u64> {
    let bounds = range
        .split_once('-')
        .map(|(start, end)| (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16)));
    let Some((Ok(start), Ok(end))) = bounds else {
        panic!("/proc/iomem: cannot parse the range {range:?}");
    };
    start..=end
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
