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

//! `set` on Linux without upstream 0e8d2444168d (v5.8 to v6.7 before stable 5.10.209, 5.15.148,
//! 6.1.75, 6.6.14 and 6.7.2), which crashes on an efivarfs write when the firmware's
//! EFI_RT_PROPERTIES_TABLE leaves out SetVariable(), and on Linux with it. The scenarios
//! crash-guard-* install that table with publish-hiidb, or none, mount efivarfs as init's
//! uefisettings.efivarfs= asks, and name the outcome that `set` must have as the libtest
//! filter: each test sets DriverSample's one-of question, checks that the kernel neither
//! oopsed nor tainted, and that `set` refused, with the variable and the mount unchanged, or
//! wrote. The checks of the kernel come first: an oops leaves efivars_lock held, so a read of
//! efivarfs would hang.

use std::fs;

use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::driver_sample::ONE_OF_OFFSET;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::EFIVARS;

/// The answer that the tests set, which DriverSample stores as 3.
const ANSWER: &str = "My one-of text #3";
const STORED: u8 = 3;

/// What the kernel logs when it oopses: on x86, "BUG: kernel NULL pointer dereference"; on
/// arm64, "Unable to handle kernel NULL pointer dereference" and "Internal error: Oops".
const OOPS_LINES: [&str; 3] = ["BUG:", "Oops", "Unable to handle kernel"];

/// The refusal where the kernel's efivar_operations lacks SetVariable(), as Linux leaves it
/// when the RT properties table does (src/lib/hii/efivarfs.rs CrashingWrite).
const NO_SET_VARIABLE: &str =
    "Linux has no runtime SetVariable() and, without efivarfs_reconfigure() (upstream \
     0e8d2444168d, Linux v6.8), crashes on an efivarfs write; run uefisettings.efi in the UEFI \
     Shell";

/// The refusal where uefisettings cannot tell (src/lib/hii/efivarfs.rs CrashingWrite).
const UNKNOWN: &str =
    "Linux without efivarfs_reconfigure() (upstream 0e8d2444168d, Linux v6.8) crashes on an \
     efivarfs write without a runtime SetVariable(), as on firmware whose \
     EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out, and uefisettings cannot tell \
     whether this one does; run uefisettings.efi in the UEFI Shell";

/// What uefisettings says when a Linux with efivarfs_reconfigure() refuses the read-write
/// remount (src/lib/hii/efivarfs.rs NoRuntimeSetVariable).
const NO_RUNTIME_SET_VARIABLE: &str =
    "Linux refuses a read-write efivarfs without a runtime SetVariable(), as on firmware whose \
     EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out; run uefisettings.efi in the UEFI \
     Shell";

/// What `set` must do.
enum Outcome {
    /// Refuse with this text.
    Refuse(&'static str),
    /// Write.
    Write,
}

/// The kernel's taint flags.
fn taint() -> String {
    fs::read_to_string("/proc/sys/kernel/tainted").expect("cannot read the taint flags")
}

/// The kernel log, through busybox dmesg, which reads it through syslog(2) as printk.devkmsg=off
/// allows.
fn kernel_log() -> String {
    let output = std::process::Command::new("dmesg")
        .output()
        .expect("cannot run dmesg");
    assert!(output.status.success(), "dmesg: {output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The options of the efivarfs mount.
fn efivarfs_options() -> String {
    let mounts = fs::read_to_string("/proc/mounts").expect("cannot read /proc/mounts");
    mounts
        .lines()
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            (fields.get(1) == Some(&EFIVARS))
                .then(|| fields.get(3).copied().unwrap_or_default().to_owned())
        })
        .unwrap_or_else(|| panic!("no mount of {EFIVARS} in {mounts}"))
}

/// The stored answer of the one-of question.
fn one_of_byte() -> u8 {
    let data = variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist");
    *data.get(ONE_OF_OFFSET).expect("the variable is short")
}

/// Sets the one-of question and checks that `set` has `outcome`, and that the kernel neither
/// oopsed nor tainted.
fn set_one_of(outcome: Outcome) {
    require_test_vm();
    let before = one_of_byte();
    let mount = efivarfs_options();
    let taint_before = taint();
    assert_ne!(before, STORED, "the answer is already stored");

    let output: Output = uefisettings(&["hii", "set", ONE_OF, ANSWER, "--json"]);

    let log = kernel_log();
    for oops in OOPS_LINES {
        assert!(
            !log.contains(oops),
            "the kernel logged {oops:?}: {log}\n{output:#?}"
        );
    }
    assert_eq!(taint(), taint_before, "taint: {output:#?}");
    match outcome {
        Outcome::Refuse(text) => {
            let error: ErrorObject = output.json(1);
            assert!(
                error.error_message.contains(text),
                "{:?} lacks {text:?}",
                error.error_message
            );
            assert_eq!(one_of_byte(), before, "the stored answer after the refusal");
        }
        Outcome::Write => {
            assert_eq!(output.code, Some(0), "{output:#?}");
            assert_eq!(one_of_byte(), STORED, "the stored answer after the write");
        }
    }
    assert_eq!(efivarfs_options(), mount, "the efivarfs mount afterwards");
}

/// Linux without the fix applied the RT properties table, which leaves SetVariable() out, and
/// its generic_ops shows it.
#[test]
fn set_refuses_a_kernel_without_set_variable() {
    set_one_of(Outcome::Refuse(NO_SET_VARIABLE));
}

/// Linux without the fix applied an RT properties table that uefisettings does not read on
/// Linux, or cannot.
#[test]
fn set_refuses_what_it_cannot_tell() {
    set_one_of(Outcome::Refuse(UNKNOWN));
}

/// Linux keeps SetVariable(), so the write is safe.
#[test]
fn set_writes() {
    set_one_of(Outcome::Write);
}

/// Linux with the fix refuses the read-write remount itself.
#[test]
fn set_meets_the_remount_refusal() {
    set_one_of(Outcome::Refuse(NO_RUNTIME_SET_VARIABLE));
}
