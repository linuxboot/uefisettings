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

// Linux's boot log, which tells whether Linux applied an EFI_RT_PROPERTIES_TABLE.
#[cfg(target_os = "linux")]
mod boot_log;
pub(crate) mod config_snapshot;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the UEFI Shell build routes <ConfigRequest>s and calls the Keyword Handler \
                  with these strings"
    )
)]
mod config_string;
// EFI_HII_CONFIG_ACCESS_PROTOCOL of a package list's driver, whose Callback() question_callbacks
// runs.
#[cfg(target_os = "uefi")]
pub(crate) mod config_access;
// The Buffer and Name/Value stores of a FormSet, which only the UEFI Shell build reaches; the
// tests run on every host with variables.
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
pub(crate) mod config_routing;
#[cfg(target_os = "uefi")]
pub(crate) mod database_protocol;
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
// The firmware memory maps of the efivar source, and the byte readers that crate::memory_map
// parses arm64's EFI memory map with.
#[cfg(target_os = "linux")]
pub(crate) mod firmware_memory;
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
pub(crate) mod form_set_stores;
pub mod forms;
#[cfg(any(target_os = "windows", test))]
mod hiidb_driver;
// Linux's symbol table, which tells whether Linux keeps a read-only efivarfs read-only.
#[cfg(target_os = "linux")]
mod kallsyms;
// Get and set by keyword, of the UEFI Shell build; the tests of every host build its logic.
#[cfg(any(target_os = "uefi", test))]
mod keyword_access;
#[cfg(target_os = "uefi")]
mod keyword_handler;
#[cfg(target_os = "linux")]
mod lockdown;
#[cfg(target_os = "linux")]
mod memory_access_denied;
pub mod package;
// Callback() of the driver of a question without a VarStore, which only the UEFI Shell build
// calls; the tests run on every host that lists variables.
#[cfg(all(variable_data, variable_names, any(target_os = "uefi", test)))]
pub(crate) mod question_callbacks;
mod scsu;
mod strings;
pub(crate) mod time_services;
// The EFI System Table and its configuration tables, which the Linux build reads from physical
// memory where a firmware memory map bounds the reads.
#[cfg(firmware_memory_maps)]
mod system_table;
#[cfg(all(variable_data, variable_names, any(target_os = "uefi", test)))]
mod variable_changes;
#[cfg(target_os = "uefi")]
mod variable_services;
mod variables;
#[cfg(any(target_os = "windows", test))]
pub(crate) mod win32;
// UEFI HII Library

// Implements (partial) decoding of the Form and Strings packages.
// See UEFI 2.10 §33 "Human Interface Infrastructure Overview":
// https://uefi.org/specifications

/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::memory_map::efi_memory_map::MemoryType;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::memory_map::efi_memory_map::RangeRefusal;
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
#[cfg(target_os = "linux")]
pub(crate) use efivarfs_format::EFIVARFS_REACH;
#[cfg(firmware_memory_maps)]
pub(crate) use extract::exported_config;
#[cfg(target_os = "windows")]
pub(crate) use firmware_environment::FirmwareEnvironment;
#[cfg(target_os = "windows")]
pub(crate) use firmware_environment::RealFirmwareEnvironmentCalls;
#[cfg(target_os = "linux")]
pub use firmware_memory::MemoryMapUnavailable;
#[cfg(target_os = "windows")]
pub(crate) use hiidb_driver::read_hiidb;
#[cfg(target_os = "uefi")]
pub(crate) use keyword_access::get_keywords_witnessed;
#[cfg(target_os = "uefi")]
pub(crate) use keyword_access::set_keywords_witnessed;
#[cfg(target_os = "uefi")]
pub use keyword_access::KeywordFilterBy;
#[cfg(target_os = "uefi")]
pub use keyword_access::KeywordGetOptions;
#[cfg(target_os = "uefi")]
pub use keyword_access::KeywordInfoSource;
#[cfg(target_os = "uefi")]
pub use keyword_access::KeywordValues;
#[cfg(target_os = "uefi")]
pub(crate) use keyword_handler::FirmwareKeywordHandler;
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
pub(crate) use strings::MatchTier;
pub(crate) use strings::PRIVATE_USE_AREA;
#[cfg(firmware_memory_maps)]
pub(crate) use system_table::system_vendor_table;
#[cfg(firmware_memory_maps)]
pub use system_table::ExportedConfigError;
#[cfg(firmware_memory_maps)]
pub use system_table::HiiExportError;
#[cfg(firmware_memory_maps)]
pub(crate) use system_table::PointerSpace;
#[cfg(firmware_memory_maps)]
pub use system_table::SystemTableError;
#[cfg(target_os = "uefi")]
pub(crate) use variable_services::VariableServices;
pub(crate) use variables::EfivarReader;
pub use variables::EfivarSource;
pub(crate) use variables::FirmwareVariables;
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
pub(crate) use variables::PasswordBytesRefusal;
pub use variables::VariableAttributes;
#[cfg(variable_data)]
pub(crate) use variables::VariableInterface;
#[cfg(any(variable_names, variable_info, variable_data))]
pub use variables::VariableKey;
#[cfg(all(variable_data, test))]
pub(crate) use variables::VariableNotFound;
pub(crate) use variables::VariableReach;
pub use variables::VolatileWrites;
pub(crate) use variables::WithholdingVariables;
pub(crate) use variables::VOLATILE_ANNOTATION;
