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

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "no Config Routing or Keyword Handler caller builds or parses these strings yet"
    )
)]
mod config_string;
#[cfg(target_os = "uefi")]
mod database_protocol;
#[cfg(efivar_dumps)]
mod efivar_dump;
#[cfg(target_os = "linux")]
mod efivarfs;
#[cfg(efivar_dumps)]
mod efivarfs_format;
#[cfg(target_os = "linux")]
pub mod extract;
// The Windows backends, firmware_environment and hiidb_driver, and their Win32 conventions,
// win32: the tests of every host build their logic.
#[cfg(any(target_os = "windows", test))]
mod firmware_environment;
// The firmware memory maps of the efivar source.
#[cfg(target_os = "linux")]
mod firmware_memory;
pub mod forms;
#[cfg(any(target_os = "windows", test))]
mod hiidb_driver;
#[cfg(target_os = "linux")]
mod lockdown;
#[cfg(target_os = "linux")]
mod memory_access_denied;
pub mod package;
mod strings;
#[cfg(target_os = "uefi")]
mod variable_services;
mod variables;
#[cfg(any(target_os = "windows", test))]
mod win32;
// UEFI HII Library

// Implements (partial) decoding of the Form and Strings packages.
// See UEFI 2.10 §33 "Human Interface Infrastructure Overview":
// https://uefi.org/specifications

#[cfg(target_os = "uefi")]
pub(crate) use database_protocol::export_package_lists;
#[cfg(target_os = "linux")]
pub(crate) use efivar_dump::dump_efivars;
#[cfg(target_os = "linux")]
pub use efivar_dump::EfivarDump;
#[cfg(target_os = "linux")]
pub use efivar_dump::EfivarRedaction;
#[cfg(efivar_dumps)]
pub(crate) use efivar_dump::SavedDump;
#[cfg(target_os = "linux")]
pub(crate) use efivarfs::EfivarFiles;
#[cfg(target_os = "windows")]
pub(crate) use firmware_environment::FirmwareEnvironment;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use firmware_memory::efi_memory_map::MemoryType;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use firmware_memory::efi_memory_map::RangeRefusal;
#[cfg(target_os = "linux")]
pub use firmware_memory::MemoryMapUnavailable;
#[cfg(target_os = "windows")]
pub(crate) use hiidb_driver::read_hiidb;
#[cfg(target_os = "linux")]
pub use lockdown::LockdownMode;
#[cfg(target_os = "linux")]
pub use lockdown::LockdownUnknown;
#[cfg(target_os = "linux")]
pub use memory_access_denied::DenialCause;
#[cfg(target_os = "linux")]
pub use memory_access_denied::MemoryAccessDenied;
#[cfg(target_os = "linux")]
pub use memory_access_denied::MemoryDevice;
#[cfg(target_os = "linux")]
pub use memory_access_denied::MemoryOperation;
#[cfg(target_os = "uefi")]
pub(crate) use variable_services::variable_info;
#[cfg(target_os = "uefi")]
pub use variable_services::VariableInfo;
#[cfg(target_os = "uefi")]
pub(crate) use variable_services::VariableServices;
pub(crate) use variables::EfivarReader;
pub use variables::EfivarSource;
pub(crate) use variables::FirmwareVariables;
#[cfg(variable_names)]
pub use variables::VariableKey;
