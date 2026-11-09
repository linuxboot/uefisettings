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

// Only the binary prints; the library logs.
#![deny(clippy::print_stdout, clippy::print_stderr)]

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "uefi",
    target_os = "windows"
)))]
compile_error!("uefisettings builds for Linux, macOS, the UEFI Shell and Windows only");

#[cfg(target_os = "linux")]
mod capsule_loader;
#[cfg(target_os = "uefi")]
mod capsule_services;
#[cfg(target_os = "linux")]
mod chattr;
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
mod efi_status;
mod efi_variables;
#[cfg(any(target_os = "linux", target_os = "windows"))]
#[cfg_attr(
    target_os = "windows",
    allow(dead_code, reason = "the Windows build locates no ESP yet")
)]
mod esp;
mod exit_status;
pub mod exports;
#[cfg(target_os = "linux")]
mod file_lock;
#[cfg(variable_data)]
mod firmware_width;
mod hex_digits;
mod hii;
#[cfg(target_os = "linux")]
mod ilorest;
#[cfg(any(
    firmware_memory_maps,
    target_os = "uefi",
    all(target_os = "linux", test)
))]
mod memory_map;
pub mod parse_error;
#[cfg(target_os = "uefi")]
mod runtime_time_services;
pub mod secret_file;
#[cfg(variable_data)]
#[cfg_attr(
    not(any(target_os = "linux", test)),
    allow(
        dead_code,
        reason = "only the Linux build stages a set for the next boot yet"
    )
)]
mod staged_set;
pub mod terminal_text;
mod translation;
#[cfg(target_os = "uefi")]
mod uefi_config_table;
#[cfg(target_os = "uefi")]
mod uefi_entry;
#[cfg(any(target_os = "uefi", test))]
mod unaligned_array;
mod unsafe_operations;
