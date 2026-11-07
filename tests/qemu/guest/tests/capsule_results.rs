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

//! `capsule results`, which prints the results of capsule processing that the variables of
//! `tests/qemu/vars/capsule-results-64.json` or `-32.json` hold (UEFI 2.11 §8.5.6): Capsule0000,
//! a JSON capsule's, Capsule0001, that of another CapsuleGuid, Capsule0003, 3 bytes, which do not
//! decode, and CapsuleMax and CapsuleLast.
//! Their EFI_CAPSULE_RESULT_VARIABLE_HEADER is that of the firmware's width: 48 bytes on x86_64 and
//! aarch64, 44 on i686, whose guest is 32-bit as its firmware is. `capsule results` writes what
//! it printed to the test log, for `tests/qemu/check-shell-log.sh` to compare with what
//! `uefisettings.efi` prints in the UEFI Shell, the next boot of the scenario. And
//! `capsule result-table`, which the Linux build refuses, though `publish-hiidb.efi
//! json-capsule-result` installs the JSON capsule result table (§23.5.3).

use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::write_for_the_shell;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::NO_CONFIGURATION_TABLES_ON_LINUX;

/// The size of the EFI_CAPSULE_RESULT_VARIABLE_HEADER of the firmware, of this guest's width.
const HEADER_SIZE: u64 = 40 + usize::BITS as u64 / 8;
/// EFI_INVALID_PARAMETER, whose high bit is that of a UINTN of the firmware's width
/// (edk2-stable202508 MdePkg/Include/Base.h ENCODE_ERROR).
const INVALID_PARAMETER: u64 = 1 << (usize::BITS - 1) | 2;

/// `status` as the capsule commands print an EFI_STATUS: in hex.
fn status(status: u64) -> String {
    format!("{status:#x}")
}

#[test]
fn results_prints_the_result_variables() {
    let output = uefisettings(&["capsule", "results"]);
    let report: serde_json::Value = output.json(0);

    let processed = serde_json::json!({
        "year": 2026,
        "month": 11,
        "day": 7,
        "hour": 12,
        "minute": 34,
        "second": 56,
        "nanosecond": 0,
        "time_zone": 2047,
        "daylight": 0,
    });
    assert_eq!(
        report,
        serde_json::json!({
            "capsule_max": "Capsule0003",
            "capsule_last": "Capsule0001",
            "results": [
                {
                    "name": "Capsule0000",
                    "result": {
                        "variable_total_size": HEADER_SIZE + 12 + 34,
                        "capsule_guid": "67D6F4CD-D6B8-4573-BF4A-DE5E252D61AE",
                        "capsule_processed": processed,
                        "capsule_status": status(INVALID_PARAMETER),
                        "json": {
                            "capsule_id": 7,
                            "resp": { "text": "{\"uefisettings\":\"capsule-results\"}" },
                        },
                    },
                },
                {
                    "name": "Capsule0001",
                    "result": {
                        "variable_total_size": HEADER_SIZE + 4,
                        "capsule_guid": "8C78A505-BAA0-4C4A-869F-000000001300",
                        "capsule_processed": processed,
                        "capsule_status": "0x0",
                        "data": { "hex": "ff00807f" },
                    },
                },
                {
                    "name": "Capsule0003",
                    "error": format!(
                        "the capsule result holds 3 bytes, fewer than the {HEADER_SIZE} of the \
                         EFI_CAPSULE_RESULT_VARIABLE_HEADER of {}-bit firmware (UEFI 2.11 \
                         section 8.5.6.1.1)",
                        usize::BITS
                    ),
                    "data": { "hex": "010203" },
                },
            ],
        }),
        "the variables of tests/qemu/vars/capsule-results-{}.json: {output:#?}",
        usize::BITS
    );

    write_for_the_shell("results", &output);
}

#[test]
fn result_table_refuses_on_linux() {
    let output = uefisettings(&["capsule", "result-table"]);
    let error: ErrorObject = output.json(1);

    assert_eq!(
        error.error_message, NO_CONFIGURATION_TABLES_ON_LINUX,
        "{output:#?}"
    );
}
