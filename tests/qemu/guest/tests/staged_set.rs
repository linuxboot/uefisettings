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

//! A set staged for the next boot (src/lib/staged_set.rs), in staged-set: Linux stages
//! questions of publish-hiidb's callback-forms, whose driver holds their value, on the EFI
//! system partition of the writable GPT disk of devices=esp-disk (run.sh), /dev/vdb, whose ESP is
//! GPT entry 2 but the first partition on the disk. Before the UEFI Shell of each
//! rebooting-shell: boot in between, the firmware starts the staged set's Boot#### from BootNext,
//! which shell/staged-set-*.tsv check.
//! - `stage_two_sets` formats that ESP, then two sets stage a question each in one staged set.
//! - `after_the_applied_boot` reads what that set's boot applied, then stages another set and
//!   deletes its image from the ESP.
//! - `after_the_boot_without_its_image` reads that that set's boot never started
//!   uefisettings.efi, then stages a set whose question's Callback(CHANGED) resets the platform.
//! - `after_the_interrupted_boot` reads that that set's boot stopped while it applied it, then
//!   stages another set.
//!
//! A set after a staged set's boot first settles that set: records its outcome and deletes its
//! Boot#### and image.

use std::fs;
use std::process::Command;

use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use uefisettings_qemu_guest::global_variable;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::EFI_GLOBAL_VARIABLE;

/// The disk of devices=esp-disk, its size in 512-byte sectors, and its EFI system partition:
/// that of tests/qemu/esp-disk.sfdisk.
const DISK: &str = "/sys/block/vdb";
const DISK_SECTORS: u64 = 131_072;
const ESP: &str = "/dev/vdb2";
const ESP_PARTITION_NUMBER: u32 = 2;
const ESP_START: u64 = 2048;
const ESP_SIZE: u64 = 81_920;
/// The ESP's UniquePartitionGUID, as a GPT entry and a Hard Drive node hold it: the first three
/// fields little-endian.
const ESP_SIGNATURE: [u8; 16] = [
    0x05, 0xA5, 0x78, 0x8C, 0xA0, 0xBA, 0x4A, 0x4C, 0x86, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x10,
];
/// Where the tests mount the ESP.
const MOUNT_POINT: &str = "/esp";
/// The uefisettings.efi that run.sh puts in the initramfs, which set stages.
const IMAGE: &str = "/uefisettings.efi";
/// Where set stages it, under the mount point.
const STAGED_IMAGE: &str = "/esp/EFI/uefisettings/uefisettings.efi";
/// Questions of callback-forms without a VarStore: one whose Callback(CHANGED) keeps its value
/// in a variable of its own, one whose Callback(CHANGING) refuses every value, and one whose
/// Callback(CHANGED) keeps its value, then resets the platform.
const BESIDE_STORES: &str = "Callback value beside stores";
const REFUSED: &str = "Callback value refused in CHANGING";
const RESETTING: &str = "Callback value resetting the platform";
/// The variables in which callback-forms keeps those questions' values, of the tests' vendor
/// GUID.
const BESIDE_STORES_VALUE: &str = "CallbackValue0201";
const REFUSED_VALUE: &str = "CallbackValue0204";
const RESETTING_VALUE: &str = "CallbackValue0102";
const TESTS_VENDOR: &str = "de145b29-c3cd-455f-91de-a76237b67c52";
/// uefisettings' vendor GUID, and its records of the staged set and of the last staged set's
/// outcome.
const UEFISETTINGS_VENDOR: &str = "dd16f539-09ed-41b9-8b64-d85d6cd93a8e";
const STAGED_SET: &str = "UefisettingsStagedSet";
const STAGED_OUTCOME: &str = "UefisettingsStagedOutcome";

/// Runs busybox's `applet` with `args`; panics unless it succeeds.
#[track_caller]
fn busybox(applet: &str, args: &[&str]) {
    require_test_vm();
    let status = Command::new("/bin/busybox")
        .arg(applet)
        .args(args)
        .status()
        .unwrap_or_else(|error| panic!("cannot run busybox {applet} {args:?}: {error}"));
    assert!(status.success(), "busybox {applet} {args:?}: {status}");
}

/// A number that a sysfs file of the disk holds.
#[track_caller]
fn disk_number(file: &str) -> u64 {
    require_test_vm();
    let path = format!("{DISK}/{file}");
    let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    text.trim_end()
        .parse()
        .unwrap_or_else(|error| panic!("{path}: {text:?}: {error}"))
}

fn mount_esp() {
    fs::create_dir_all(MOUNT_POINT).expect("create the mount point");
    busybox("mount", &["-t", "vfat", ESP, MOUNT_POINT]);
}

fn unmount_esp() {
    busybox("umount", &[MOUNT_POINT]);
}

/// The JSON of uefisettings' record `name`, or None if there is none.
#[track_caller]
fn record(name: &str) -> Option<Value> {
    let data = variable_data(&format!("{EFIVARS}/{name}-{UEFISETTINGS_VENDOR}"))?;
    Some(
        serde_json::from_slice(&data).unwrap_or_else(|error| {
            panic!("{name}: {error}: {:?}", String::from_utf8_lossy(&data))
        }),
    )
}

/// The record of the staged set; panics if there is none.
#[track_caller]
fn staged_set() -> Value {
    record(STAGED_SET).expect("a staged set's record")
}

/// The data of callback-forms' variable `name`.
#[track_caller]
fn question_variable(name: &str) -> Option<Vec<u8>> {
    variable_data(&format!("{EFIVARS}/{name}-{TESTS_VENDOR}"))
}

/// The number of the Boot#### that BootNext names; panics if there is no BootNext.
#[track_caller]
fn boot_next() -> u16 {
    let data = global_variable("BootNext").expect("BootNext");
    let bytes: [u8; 2] = data.try_into().expect("BootNext is a UINT16");
    u16::from_le_bytes(bytes)
}

/// The data of Boot`number`, or None if there is none.
#[track_caller]
fn boot_option(number: u16) -> Option<Vec<u8>> {
    global_variable(&format!("Boot{number:04X}"))
}

/// The Boot#### number of a staged set's record.
#[track_caller]
fn boot_option_number(set: &Value) -> u16 {
    set["boot_option"]
        .as_u64()
        .and_then(|number| u16::try_from(number).ok())
        .unwrap_or_else(|| panic!("no Boot#### number: {set}"))
}

/// The Hard Drive node (UEFI 2.11 §10.3.5.1) of the ESP: Type, SubType and Length, then the
/// partition number, start, size, signature, MBR or GPT, and signature type, GUID.
fn esp_hard_drive_node() -> Vec<u8> {
    [
        &[0x04, 0x01, 42, 0][..],
        &ESP_PARTITION_NUMBER.to_le_bytes(),
        &ESP_START.to_le_bytes(),
        &ESP_SIZE.to_le_bytes(),
        &ESP_SIGNATURE,
        &[0x02, 0x02],
    ]
    .concat()
}

/// `text` in CHAR16s, as a load option's OptionalData holds a command line.
fn char16s(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The numbers of the Boot#### whose data holds the command line of a staged set, in order.
#[track_caller]
fn staged_boot_options() -> Vec<u16> {
    require_test_vm();
    let suffix = format!("-{EFI_GLOBAL_VARIABLE}");
    let command = char16s("uefisettings.efi apply-staged ");
    let mut numbers: Vec<u16> = fs::read_dir(EFIVARS)
        .expect("list efivarfs")
        .map(|entry| entry.expect("an efivarfs entry").file_name())
        .filter_map(|name| {
            let digits = name.to_str()?.strip_suffix(&suffix)?.strip_prefix("Boot")?;
            match digits.len() {
                4 => u16::from_str_radix(digits, 16).ok(),
                _ => None,
            }
        })
        .filter(|&number| {
            boot_option(number)
                .is_some_and(|data| data.windows(command.len()).any(|window| window == command))
        })
        .collect();
    numbers.sort_unstable();
    numbers
}

/// Panics unless Boot`number` starts the image on the ESP by its Hard Drive node, with the
/// command line of the staged set of `nonce`, then a Null character.
#[track_caller]
fn assert_starts_staged_set(number: u16, nonce: &str) {
    let option = boot_option(number).unwrap_or_else(|| panic!("no Boot{number:04X}"));
    let node = esp_hard_drive_node();
    assert!(
        option.windows(node.len()).any(|window| window == node),
        "Boot{number:04X} names no Hard Drive node {node:02x?} of the ESP: {option:02x?}"
    );
    let command = char16s(&format!("uefisettings.efi apply-staged {nonce}\0"));
    assert!(
        option.ends_with(&command),
        "Boot{number:04X} has not the command line of {nonce}: {option:02x?}"
    );
}

/// The nonce of a record.
#[track_caller]
fn nonce(record: &Value) -> String {
    record["nonce"]
        .as_str()
        .unwrap_or_else(|| panic!("no nonce: {record}"))
        .to_owned()
}

/// What set answers of a request of an outcome's results.
#[track_caller]
fn result(outcome: &Value) -> String {
    outcome["result"]
        .as_str()
        .unwrap_or_else(|| panic!("no result: {outcome}"))
        .to_owned()
}

/// The answer that `hii get` gives of `question`.
#[track_caller]
fn get(question: &str) -> String {
    single_response(&["hii", "get", "--json", question], BACKEND_HII)
        .0
        .answer
}

/// Runs `hii set` of `question` to `value` with `more` arguments; panics unless it stages it in
/// the set whose Boot#### BootNext names, which it returns.
#[track_caller]
fn stage(question: &str, value: &str, more: &[&str]) -> u16 {
    let args = [&["hii", "set", "--json", question, value][..], more].concat();
    let (answer, _) = single_response(&args, BACKEND_HII);
    let number = boot_next();
    let staged = format!(" <staged for the next boot, as Boot{number:04X}: restart to apply>");
    assert!(
        answer.answer.ends_with(&staged),
        "{args:?}: {answer:#?} does not end with {staged:?}"
    );
    number
}

/// Panics unless `get` of `question` shows its refusal with the note `note`.
#[track_caller]
fn assert_note(question: &str, note: &str) {
    let answer = get(question);
    let suffix = format!(" <{note}>");
    assert!(
        answer.starts_with("<ValueUnavailable") && answer.ends_with(&suffix),
        "get {question:?}: {answer:?} does not end with {suffix:?}"
    );
}

/// The SHA-256 of the file at `path`, as a staged set's record writes it.
#[track_caller]
fn sha256(path: &str) -> String {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {path}: {error}"));
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn stage_two_sets() {
    require_test_vm();
    // the disk that run.sh made, partitioned as esp-disk.sfdisk, before formatting anything
    assert_eq!(disk_number("ro"), 0, "{DISK} is read-only");
    assert_eq!(
        disk_number("size"),
        DISK_SECTORS,
        "{DISK} is not the ESP disk"
    );
    assert_eq!(
        disk_number("vdb2/start"),
        ESP_START,
        "{ESP} does not start the disk"
    );
    assert_eq!(disk_number("vdb2/size"), ESP_SIZE, "{ESP} is not the ESP");
    busybox("mkdosfs", &[ESP]);
    mount_esp();

    let number = stage(BESIDE_STORES, "On", &["--image", IMAGE]);
    // the second set appends to the pending set, which keeps its image and Boot####; its flag
    // lifts nothing here, and its request records it
    assert_eq!(
        stage(REFUSED, "On", &["--i-am-fine-to-brick-this-system"]),
        number,
        "the second set's Boot####"
    );

    let set = staged_set();
    assert_eq!(boot_option_number(&set), number, "{set}");
    let requests: Vec<(&str, &str)> = set["requests"]
        .as_array()
        .unwrap_or_else(|| panic!("no requests: {set}"))
        .iter()
        .map(|request| {
            (
                request["question"].as_str().expect("a question"),
                request["unsafe_operations"].as_str().expect("a grant"),
            )
        })
        .collect();
    assert_eq!(
        requests,
        [(BESIDE_STORES, "refuse"), (REFUSED, "allow")],
        "{set}"
    );
    assert_eq!(
        set["image"]["sha256"].as_str(),
        Some(sha256(IMAGE).as_str()),
        "{set}"
    );
    assert_eq!(sha256(STAGED_IMAGE), sha256(IMAGE), "the staged image");
    assert_starts_staged_set(number, &nonce(&set));
    assert_eq!(
        staged_boot_options(),
        [number],
        "the Boot#### of staged sets"
    );
    assert_eq!(
        record(STAGED_OUTCOME),
        None,
        "an outcome before any staged boot"
    );

    let pending = format!("On is staged for the next boot, as Boot{number:04X}: restart to apply");
    assert_note(BESIDE_STORES, &pending);
    assert_note(REFUSED, &pending);
    unmount_esp();
}

#[test]
fn after_the_applied_boot() {
    require_test_vm();
    mount_esp();
    // uefisettings.efi deleted the set's Boot####, after the boot manager deleted BootNext; the
    // firmware's boot after the reset would have taken its number too, as
    // after_the_interrupted_boot tells
    let set = staged_set();
    assert_eq!(global_variable("BootNext"), None, "BootNext");
    assert_eq!(
        staged_boot_options(),
        Vec::<u16>::new(),
        "the Boot#### of staged sets"
    );

    let outcome = record(STAGED_OUTCOME).expect("the outcome of the staged boot");
    assert_eq!(outcome["state"], "finished", "{outcome}");
    assert_eq!(nonce(&outcome), nonce(&set), "{outcome}");
    let results = outcome["results"]
        .as_array()
        .unwrap_or_else(|| panic!("no results: {outcome}"));
    let [applied, refused] = results.as_slice() else {
        panic!("not two results: {outcome}");
    };
    assert_eq!(applied["request"]["question"], BESIDE_STORES, "{outcome}");
    assert_eq!(applied["applied"], true, "{outcome}");
    assert_eq!(refused["request"]["question"], REFUSED, "{outcome}");
    assert_eq!(refused["applied"], false, "{outcome}");
    assert!(result(refused).contains("EFI_ACCESS_DENIED"), "{outcome}");
    // neither lifted an unsafe operation
    for outcome_of in [applied, refused] {
        assert_eq!(
            outcome_of["warnings"].as_array().map(Vec::len),
            Some(0),
            "{outcome}"
        );
    }
    assert_note(
        BESIDE_STORES,
        &format!("the last staged boot applied On: {}", result(applied)),
    );
    assert_note(
        REFUSED,
        &format!("the last staged boot did not apply On: {}", result(refused)),
    );
    // what the driver keeps
    assert_eq!(question_variable(BESIDE_STORES_VALUE), Some(vec![1]));
    assert_eq!(question_variable(REFUSED_VALUE), None);

    // settles the applied set, then stages a set whose image the firmware will not find
    let next = stage(BESIDE_STORES, "Off", &["--image", IMAGE]);
    let staged = staged_set();
    assert_ne!(nonce(&staged), nonce(&set), "a new set's nonce");
    assert_starts_staged_set(next, &nonce(&staged));
    assert_eq!(staged_boot_options(), [next], "the Boot#### of staged sets");
    fs::remove_file(STAGED_IMAGE).expect("delete the staged image");
    unmount_esp();
}

#[test]
fn after_the_boot_without_its_image() {
    require_test_vm();
    mount_esp();
    // nothing ran to delete the set's Boot####
    let set = staged_set();
    let number = boot_option_number(&set);
    assert_eq!(global_variable("BootNext"), None, "BootNext");
    assert_starts_staged_set(number, &nonce(&set));
    assert_eq!(
        staged_boot_options(),
        [number],
        "the Boot#### of staged sets"
    );
    assert_note(
        BESIDE_STORES,
        "the last staged boot did not start uefisettings.efi, so Off is not applied",
    );
    assert_eq!(question_variable(BESIDE_STORES_VALUE), Some(vec![1]));

    // settles the set, recording that its boot never started it, then stages the question whose
    // Callback(CHANGED) resets the platform
    let next = stage(RESETTING, "On", &["--image", IMAGE]);
    let outcome = record(STAGED_OUTCOME).expect("the settled outcome");
    assert_eq!(outcome["state"], "not-started", "{outcome}");
    assert_eq!(nonce(&outcome), nonce(&set), "{outcome}");
    let staged = staged_set();
    assert_ne!(nonce(&staged), nonce(&set), "a new set's nonce");
    // the new set's Boot#### alone, which may have the old one's number
    assert_starts_staged_set(next, &nonce(&staged));
    assert_eq!(staged_boot_options(), [next], "the Boot#### of staged sets");
    unmount_esp();
}

#[test]
fn after_the_interrupted_boot() {
    require_test_vm();
    mount_esp();
    // uefisettings.efi recorded its start, then the reset came before any result or cleanup
    let set = staged_set();
    let outcome = record(STAGED_OUTCOME).expect("the recorded start");
    assert_eq!(outcome["state"], "started", "{outcome}");
    assert_eq!(nonce(&outcome), nonce(&set), "{outcome}");
    assert_eq!(global_variable("BootNext"), None, "BootNext");
    assert_note(
        RESETTING,
        "the last staged boot stopped while it applied On, which may be partly applied",
    );
    // the driver kept the value before it reset the platform
    assert_eq!(question_variable(RESETTING_VALUE), Some(vec![1]));
    // Once the boot manager deleted BootNext, nothing referenced the set's Boot####, which the
    // firmware may then remove (UEFI 2.11 §3.1.1). The boot after the reset wrote the guest
    // OVMF's Grub option at its number, the lowest that neither BootOrder nor BootNext holds,
    // then removed that option, as no firmware volume holds its file (edk2-stable202402
    // MdeModulePkg/Library/UefiBootManagerLib/BmLoadOption.c BmGetFreeOptionNumber,
    // OvmfPkg/Library/PlatformBootManagerLib/BdsPlatform.c PlatformBootManagerAfterConsole).
    // AAVMF keeps the set's Boot####, OVMF removes it.
    let left = staged_boot_options();
    assert!(
        left.is_empty() || left == [boot_option_number(&set)],
        "the Boot#### of staged sets: {left:?}"
    );

    // settles the set, recording that its boot was interrupted
    let next = stage(BESIDE_STORES, "Twice", &["--image", IMAGE]);
    let outcome = record(STAGED_OUTCOME).expect("the settled outcome");
    assert_eq!(outcome["state"], "interrupted", "{outcome}");
    assert_eq!(nonce(&outcome), nonce(&set), "{outcome}");
    assert_eq!(outcome["requests"][0]["question"], RESETTING, "{outcome}");
    assert_eq!(staged_boot_options(), [next], "the Boot#### of staged sets");
    unmount_esp();
}
