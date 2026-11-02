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

//! The UEFI Shell build's binary enters through uefi_std_entry (src/lib/uefi_entry.rs), which
//! initializes the uefi crate before std's efi_main runs.
//!
//! Each of CAPABILITIES is a cfg for what some builds lack, for shared modules to test instead of
//! OS names.

use std::env;
use std::env::VarError;

/// A cfg that builds for `target_oses` set, as they have what it names.
struct Capability {
    cfg: &'static str,
    target_oses: &'static [&'static str],
}

const CAPABILITIES: [Capability; 3] = [
    // HiiBackend::system_hiidb: this machine's HiiDB
    Capability {
        cfg: "system_hiidb",
        target_oses: &["linux", "uefi"],
    },
    // HiiBackend::system_variables and EfivarSource::System: this machine's EFI variables, the
    // only ones that set writes
    Capability {
        cfg: "system_variables",
        target_oses: &["linux", "uefi"],
    },
    // db_file: HiiDB files, which -f names
    Capability {
        cfg: "hiidb_files",
        target_oses: &["linux", "macos"],
    },
];

fn main() -> Result<(), VarError> {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    if target_os == "uefi" {
        println!("cargo:rustc-link-arg-bins=/entry:uefi_std_entry");
    }
    for capability in CAPABILITIES {
        println!("cargo:rustc-check-cfg=cfg({})", capability.cfg);
        if capability.target_oses.contains(&target_os.as_str()) {
            println!("cargo:rustc-cfg={}", capability.cfg);
        }
    }
    Ok(())
}
