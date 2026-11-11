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

//! `export-config`: the current configuration that edk2's HiiDatabaseDxe exports for the OS when
//! PcdHiiOsRuntimeSupport is TRUE (UEFI 2.11 §33.2.11.1), which OVMF builds without:
//! ExportConfig()'s results (§35.4.3), in a runtime-data pool zeroed a quarter past their NUL,
//! as the configuration table of the HII Configuration Routing Protocol's GUID. First it
//! registers the package list of [`password_forms`] for a handle with the device path
//! [`DRIVER_PATH`], as a driver does, then appends to the results a `<ConfigResp>` that fills
//! the bytes of that list's PASSWORD questions in its VarStore AMITSESetup with [`MARKER`], and
//! sets the ONE_OF after them to [`QUIET_BOOT_ENABLED`], as that driver's ExtractConfig() would
//! export it: `uefisettings` shows the ONE_OF's value, and no byte of the passwords.
//! `export-config-name-value-password` does the same with the package lists of
//! [`name_value_password_forms`] and the `<ConfigResp>` of their VARSTORE_NAME_VALUE, which holds
//! the value of the name that their PASSWORD is on. `export-config-storageless-password` does it
//! with those of [`storageless_password_forms`] and the `<ConfigResp>` of their VARSTORE
//! SlBacking, whose bytes stand for a password that their PASSWORDs of VarStoreId 0 keep there,
//! and `export-config-undeclared-password` with those of [`undeclared_password_forms`] and the
//! `<ConfigResp>` of their VARSTORE UdBacking, whose bytes stand for a password that the driver of
//! their PASSWORD of an undeclared VarStoreId keeps there.
//! `export-config-name-value-string` does the same with the package list of
//! [`name_value_string_forms`] and the `<ConfigResp>` of its VARSTORE_NAME_VALUE, which holds the
//! settings of its STRINGs and its CHECKBOX.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use core::ptr::NonNull;

use uefi::boot;
use uefi::boot::MemoryType;
use uefi::guid;
use uefi::println;
use uefi::proto::unsafe_protocol;
use uefi::CStr16;
use uefi::Guid;
use uefi::Status;
use uefi::StatusExt;
use uefi_raw::protocol::hii::config::HiiConfigRoutingProtocol;

use crate::install_device_path;
use crate::name_value_password_forms;
use crate::name_value_string_forms;
use crate::password_forms;
use crate::register_name_value_password_forms;
use crate::register_name_value_string_forms;
use crate::register_package_list_for;
use crate::register_storageless_password_forms;
use crate::register_undeclared_password_forms;
use crate::storageless_password_forms;
use crate::undeclared_password_forms;
use crate::vendor_device_path;
use crate::Failure;

/// The configuration table GUID of ExportConfig()'s results (UEFI 2.11 §33.2.11.1).
static HII_CONFIG_ROUTING_GUID: Guid = HiiConfigRoutingProtocol::GUID;
/// The Vendor_GUID of the Vendor Device Path node of [`DRIVER_PATH`].
const DRIVER_VENDOR: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001400");
/// The device path of the handle that registers the password forms.
static DRIVER_PATH: [u8; 24] = vendor_device_path(DRIVER_VENDOR);
/// The byte that the appended `<ConfigResp>` sets each password byte of AMITSESetup to.
const MARKER: u8 = 0xA5;
/// The value that the appended `<ConfigResp>` gives the ONE_OF of AMITSESetup: Enabled.
const QUIET_BOOT_ENABLED: u8 = 1;

/// EFI_HII_CONFIG_ROUTING_PROTOCOL, of which the uefi crate wraps no function.
#[repr(transparent)]
#[unsafe_protocol(HiiConfigRoutingProtocol::GUID)]
struct RawConfigRouting(HiiConfigRoutingProtocol);

/// Registers the password forms for a handle of [`DRIVER_PATH`], then installs ExportConfig()'s
/// results with the `<ConfigResp>` of AMITSESetup after them, and logs where.
pub(crate) fn export_config() -> Result<(), Failure> {
    let driver = install_device_path(&DRIVER_PATH)?;
    register_package_list_for(
        &password_forms::package_list_bytes(),
        Some(driver),
        "registering the password forms for a handle with a device path",
    )?;
    export_config_with(&marker_resp(), "AMITSESetup")
}

/// Registers the package lists of [`name_value_password_forms`] for a handle of their device
/// path, then installs ExportConfig()'s results with the `<ConfigResp>` of their
/// VARSTORE_NAME_VALUE after them, and logs where.
pub(crate) fn export_name_value_config() -> Result<(), Failure> {
    register_name_value_password_forms()?;
    export_config_with(
        &name_value_password_forms::pin_resp(),
        "the VARSTORE_NAME_VALUE",
    )
}

/// Registers the package lists of [`storageless_password_forms`] for a handle of their device
/// path, then installs ExportConfig()'s results with the `<ConfigResp>` of their VARSTORE
/// SlBacking after them, and logs where.
pub(crate) fn export_storageless_config() -> Result<(), Failure> {
    register_storageless_password_forms()?;
    export_config_with(&storageless_password_forms::backing_resp(), "SlBacking")
}

/// Registers the package lists of [`undeclared_password_forms`] for a handle of their device
/// path, then installs ExportConfig()'s results with the `<ConfigResp>` of their VARSTORE
/// UdBacking after them, and logs where.
pub(crate) fn export_undeclared_config() -> Result<(), Failure> {
    register_undeclared_password_forms()?;
    export_config_with(&undeclared_password_forms::backing_resp(), "UdBacking")
}

/// Registers the package list of [`name_value_string_forms`] for a handle of its device path,
/// then installs ExportConfig()'s results with the `<ConfigResp>` of its VARSTORE_NAME_VALUE
/// after them, and logs where.
pub(crate) fn export_name_value_string_config() -> Result<(), Failure> {
    register_name_value_string_forms()?;
    export_config_with(
        &name_value_string_forms::settings_resp(),
        "the VARSTORE_NAME_VALUE of the STRINGs",
    )
}

/// Installs ExportConfig()'s results with `resp`, the `<ConfigResp>` of `storage`, after them,
/// and logs where.
fn export_config_with(resp: &str, storage: &str) -> Result<(), Failure> {
    let mut text = exported_config()?;
    let exported = text.len();
    // a <MultiConfigAltResp> joins its <ConfigAltResp>s with '&'
    if !text.is_empty() {
        text.push(u16::from(b'&'));
    }
    text.extend(resp.encode_utf16());
    let address = install_config_table(&text)?;
    println!(
        "publish-hiidb: config table {HII_CONFIG_ROUTING_GUID} at {address:#x}: {exported} \
         CHAR16s of ExportConfig(), then a <ConfigResp> of {storage}"
    );
    Ok(())
}

/// The CHAR16s of ExportConfig()'s results, without their NUL.
fn exported_config() -> Result<Vec<u16>, Failure> {
    let routing = boot::get_handle_for_protocol::<RawConfigRouting>()
        .and_then(boot::open_protocol_exclusive::<RawConfigRouting>)
        .map_err(|error| {
            (
                "opening the HII Configuration Routing Protocol",
                error.status(),
            )
        })?;
    let mut results = ptr::null_mut();
    #[expect(
        unsafe_code,
        reason = "the uefi crate does not wrap ExportConfig(), a function of the protocol"
    )]
    // SAFETY: `routing` is the protocol that the firmware installed, which stays open while the
    // call runs, and `results` is a valid place for the pointer to the string that it allocates.
    let status = unsafe { (routing.0.export_config)(&routing.0, &mut results) };
    status
        .to_result()
        .map_err(|error| ("calling ExportConfig()", error.status()))?;
    let results = NonNull::new(results).ok_or(("calling ExportConfig()", Status::NOT_FOUND))?;
    #[expect(
        unsafe_code,
        reason = "ExportConfig()'s results are only reachable through a raw pointer"
    )]
    // SAFETY: ExportConfig() succeeded, so `results` points to its NUL-terminated string, which
    // stays allocated until free_pool below.
    let text = unsafe { CStr16::from_ptr(results.as_ptr().cast()) }
        .to_u16_slice()
        .to_vec();
    #[expect(unsafe_code, reason = "the uefi crate's FreePool() wrapper is unsafe")]
    // SAFETY: ExportConfig() allocated the string from pool (edk2-stable202608 ConfigRouting.c
    // HiiConfigRoutingExportConfig(), AllocateZeroPool()), which `text` copies: nothing refers
    // to it any more.
    unsafe { boot::free_pool(results.cast()) }
        .map_err(|error| ("freeing ExportConfig()'s results", error.status()))?;
    Ok(text)
}

/// The `<ConfigResp>` that AMITSESetup's driver at [`DRIVER_PATH`] would export, as edk2's
/// HiiConstructConfigHdr and BlockToConfig write one: every byte [`MARKER`] but the ONE_OF's
/// [`QUIET_BOOT_ENABLED`], and VALUE's digits most significant first (UEFI 2.11 §35.4.6).
fn marker_resp() -> String {
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() };
    let name: String = password_forms::AMITSE_SETUP_NAME
        .encode_utf16()
        .map(|unit| format!("{unit:04x}"))
        .collect();
    let size = password_forms::AMITSE_SETUP_SIZE;
    let value: Vec<u8> = (0..size)
        .rev()
        .map(|offset| match offset == password_forms::QUIET_BOOT_OFFSET {
            true => QUIET_BOOT_ENABLED,
            false => MARKER,
        })
        .collect();
    format!(
        "GUID={}&NAME={name}&PATH={}&OFFSET=0&WIDTH={size:x}&VALUE={}",
        hex(&password_forms::AMITSE_SETUP_VENDOR.to_bytes()),
        hex(&DRIVER_PATH),
        hex(&value),
    )
}

/// Installs `text` and a NUL as the configuration table of [`HII_CONFIG_ROUTING_GUID`], in a
/// runtime-data pool zeroed a quarter past them, as edk2's HiiGetConfigRespInfo() does
/// (MdeModulePkg/Universal/HiiDatabaseDxe/Database.c). Returns the table's address.
fn install_config_table(text: &[u16]) -> Result<u64, Failure> {
    let too_large = (
        "the ExportConfig snapshot's size overflows",
        Status::BAD_BUFFER_SIZE,
    );
    let length = text
        .len()
        .checked_add(1)
        .and_then(|units| units.checked_mul(size_of::<u16>()))
        .ok_or(too_large)?;
    let size = length.checked_add(length / 4).ok_or(too_large)?;
    let bytes: Vec<u8> = text.iter().copied().flat_map(u16::to_le_bytes).collect();
    let pool = boot::allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, size)
        .map_err(|error| ("allocating the runtime pool", error.status()))?;
    #[expect(
        unsafe_code,
        reason = "the pool from allocate_pool() is only reachable through a raw pointer"
    )]
    // SAFETY: allocate_pool returned `size` bytes, more than `bytes` and the NUL, that nothing
    // else references, at an identity-mapped address, and `bytes` does not overlap them.
    unsafe {
        ptr::write_bytes(pool.as_ptr(), 0, size);
        ptr::copy_nonoverlapping(bytes.as_ptr(), pool.as_ptr(), bytes.len());
    }
    #[expect(
        unsafe_code,
        reason = "InstallConfigurationTable() takes a raw pointer that must stay valid"
    )]
    // SAFETY: the table is a runtime-data pool allocation, as the function requires, that is
    // never freed or written again.
    unsafe { boot::install_configuration_table(&HII_CONFIG_ROUTING_GUID, pool.as_ptr().cast()) }
        .map_err(|error| ("installing the configuration table", error.status()))?;
    // `usize` has at most 64 bits on the UEFI targets.
    Ok(pool.as_ptr().addr() as u64)
}
