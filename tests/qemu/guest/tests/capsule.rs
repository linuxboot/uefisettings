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

//! The scenarios `capsule` and `capsule-payload`: `capsule deliver` passes a JSON payload to
//! Linux's capsule loader, /dev/efi_capsule_loader, which the Linux 6.17 of the x86_64 and
//! aarch64 guests lacks, as Fedora builds it without CONFIG_EFI_CAPSULE_LOADER
//! (`tests/qemu/guest-packages-x86_64`, `-aarch64`), so `uefisettings` names its absence. The
//! i686 guests' Linux 6.1 has the loader, which logs the firmware's refusal at KERN_ERR, which
//! `init` fails as an error of the test, so i686 boots only `capsule-payload`: a payload that is
//! empty or missing, which is refused before the loader is opened.

use std::fs;
use std::path::Path;

use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;

/// The loader that `capsule deliver` writes to.
const CAPSULE_LOADER: &str = "/dev/efi_capsule_loader";

/// Writes `payload` to the file `path` for `capsule deliver`.
fn write_payload(path: &str, payload: &[u8]) {
    require_test_vm();
    fs::write(path, payload).unwrap_or_else(|error| panic!("write {path}: {error}"));
}

/// `capsule deliver` names the missing loader, and makes no file there.
#[test]
fn deliver_names_the_missing_capsule_loader() {
    let payload = "/tmp/capsule-payload.json";
    write_payload(payload, b"{\"uefisettings\":\"capsule\"}");

    let error = json_error(&["capsule", "deliver", payload, "--capsule-id", "1"]);

    assert_eq!(
        error.error_message,
        "/dev/efi_capsule_loader does not exist: Linux has no EFI capsule loader without \
         CONFIG_EFI_CAPSULE_LOADER, while its module capsule-loader is not loaded, or without \
         EFI runtime services",
        "Linux 6.17 without CONFIG_EFI_CAPSULE_LOADER"
    );
    assert!(!Path::new(CAPSULE_LOADER).exists(), "{CAPSULE_LOADER} made");
}

/// `capsule deliver` refuses an empty payload and names a missing one, before it looks for the
/// loader.
#[test]
fn deliver_refuses_an_empty_or_missing_payload() {
    let empty = "/tmp/capsule-empty.json";
    write_payload(empty, b"");
    let missing = "/tmp/capsule-missing.json";
    assert!(!Path::new(missing).exists(), "{missing} exists");

    for (payload, want) in [
        (
            empty,
            "the JSON payload is empty: \"A capsule in which PayloadLength is zero will not be \
             processed.\" (UEFI 2.11 section 23.5.3)",
        ),
        (
            missing,
            "read the payload /tmp/capsule-missing.json: No such file or directory (os error 2)",
        ),
    ] {
        let error = json_error(&["capsule", "deliver", payload, "--capsule-id", "1"]);

        assert_eq!(error.error_message, want, "{payload}");
    }
}
