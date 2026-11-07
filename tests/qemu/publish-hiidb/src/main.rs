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

//! UEFI driver for the QEMU tests of the `uefisettings` HII backend, which a
//! `Driver####` load option runs as
//! `publish-hiidb.efi [rt-data|reserved|acpi-nvs|loader-data|rt-data-global-variable-forms|rt-data-readwrite-forms|password-forms|enhanced-auth-forms|dropped-password-forms|padded-strings|acpi-table|acpi-table-hiid|acpi-table-junk-qhii|install-config-tables|rt-properties-no-set-variable|rt-properties-all|rt-properties-version-2|rt-properties-version-2-all|json-config-data|json-config-data-past-region|json-config-data-boot-services|json-config-data-mmio|set-auth-variables=PATH[,PATH]...]`:
//! it copies the HII database into pages of that memory type, one byte in, and points
//! the volatile `HiiDB` variable at the copy as `{ u32 length; u64 address }`, the way
//! OCP firmware does for `src/lib/hii/extract.rs`. The x86 EFI stub reports
//! `rt-data` (the default) and `reserved` as E820 reserved ranges, which
//! `/dev/mem` serves under `CONFIG_STRICT_DEVMEM`; `loader-data` becomes System
//! RAM, which it refuses.
//! arm64 Linux maps neither `rt-data` nor `reserved`, so `/dev/mem` serves them only
//! to mmap(), as 32-bit x86 Linux does above its low memory.
//! `acpi-nvs` puts the copy in ACPI NVS memory, which firmware reserves without the RUNTIME
//! attribute: x86 Linux marks it busy, which `/dev/mem` refuses under
//! `CONFIG_IO_STRICT_DEVMEM`, while arm64 Linux serves it.
//! The driver also puts the CRC-32 of the database in the volatile `HiiDBCrc32`
//! variable, for the tests to check what `uefisettings` extracts.
//! `rt-data-global-variable-forms` is `rt-data`, with the package lists of
//! [`global_variable_forms`] after those that the firmware exports.
//! `rt-data-readwrite-forms` is `rt-data`, after it creates the variable of
//! [`readwrite_forms`] if it is missing and registers its package list in the HII database, so
//! that both Linux and `uefisettings.efi` in the UEFI Shell find it.
//! `password-forms` publishes nothing: it registers the package list of [`password_forms`]
//! in the HII database, for `uefisettings.efi` in the UEFI Shell, which exports the database.
//! `enhanced-auth-forms` does the same with the package list of [`enhanced_auth_forms`].
//! `dropped-password-forms` does the same with the package list of [`dropped_password_forms`].
//! `padded-strings` publishes nothing either: it registers the package list of
//! [`padded_strings`], which a later `publish-hiidb.efi` exports with the database.
//! `acpi-table` sets no `HiiDB`: it installs the database as the body of a `QHII` ACPI table,
//! where `src/lib/hii/extract.rs` also looks, and puts its CRC-32 in `HiiDBCrc32`.
//! `acpi-table-hiid` does the same with an `HIID` table, the other vendor ACPI table that
//! `src/lib/hii/extract.rs` reads. `acpi-table-junk-qhii` installs a `QHII` table whose body
//! holds no HII package list, a table that fails the checks of `src/lib/hii/extract.rs`.
//! `install-config-tables` sets no `HiiDB`: it installs a runtime-data copy of the database,
//! with edk2's zeroed slack, as the configuration table of the HII database protocol's GUID, as
//! edk2's HiiDatabaseDxe does when PcdHiiOsRuntimeSupport is TRUE (UEFI 2.11 §33.2.11.1), and
//! puts its length and address in the volatile `HiiDBConfigTable` variable, in `HiiDB`'s
//! layout, for the tests.
//! `rt-properties-no-set-variable` publishes nothing: it installs an EFI_RT_PROPERTIES_TABLE
//! (UEFI 2.11 §4.6.2) whose RuntimeServicesSupported lists every runtime service but
//! SetVariable(), as firmware that cannot write variables at runtime publishes, and
//! `rt-properties-all` one that lists every runtime service.
//! `rt-properties-version-2` and `rt-properties-version-2-all` install the same tables with
//! Version 2, which no UEFI version defines.
//! `json-config-data` publishes nothing: it installs an EFI_JSON_CAPSULE_CONFIG_DATA (UEFI 2.11
//! §23.5.2) of [`JSON_CONFIG_DATA_ITEMS`] as the configuration table of
//! EFI_JSON_CONFIG_DATA_TABLE_GUID (§4.6.1.2). It never converts the table's address, which
//! SetVirtualAddressMap() asks for after ExitBootServices() (§8.4.1), when no boot service driver
//! runs. `json-config-data-past-region` installs the same table with a TotalLength of
//! [`PAST_REGION_TOTAL_LENGTH`], and `json-config-data-boot-services` in boot services data,
//! while `json-config-data-mmio` points the configuration table at the start of the first runtime
//! memory-mapped I/O of the memory map, where it writes nothing.
//! `set-auth-variables=PATH[,PATH]...` publishes nothing: it runs the authenticated writes of
//! [`auth_variables`] for the Secure Boot scenarios.

#![cfg_attr(target_os = "uefi", no_std, no_main)]
#![deny(unsafe_code)]

extern crate alloc;

mod auth_variables;
mod dropped_password_forms;
mod enhanced_auth_forms;
mod global_variable_forms;
mod hii_package;
mod padded_strings;
mod password_forms;
mod readwrite_forms;

use alloc::vec::Vec;
use core::ptr;

use uefi::boot;
use uefi::boot::AllocateType;
use uefi::boot::MemoryAttribute;
use uefi::boot::MemoryType;
use uefi::boot::PAGE_SIZE;
use uefi::cstr16;
use uefi::entry;
use uefi::guid;
use uefi::mem::memory_map::MemoryMap;
use uefi::println;
use uefi::proto::acpi::AcpiTable;
use uefi::proto::hii::database::HiiDatabase;
use uefi::proto::loaded_image::LoadOptionsError;
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::unsafe_protocol;
use uefi::runtime;
use uefi::runtime::VariableAttributes;
use uefi::runtime::VariableVendor;
use uefi::CStr16;
use uefi::Guid;
use uefi::Status;
use uefi::StatusExt;
use uefi_raw::protocol::hii::database::HiiDatabaseProtocol;

/// Name of the variable that `uefisettings` looks for.
const HIIDB_NAME: &CStr16 = cstr16!("HiiDB");
/// Vendor GUID of that variable.
const HIIDB_VENDOR: Guid = guid!("1b838190-4625-4ead-abc9-cd5e6af18fe0");
/// Attributes of that variable: volatile and readable at runtime.
const HIIDB_ATTRIBUTES: VariableAttributes =
    VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);
/// Name of the variable that holds the CRC-32 of the database, for the tests
/// only, with the attributes of `HiiDB`.
const HIIDB_CRC32_NAME: &CStr16 = cstr16!("HiiDBCrc32");
/// Vendor GUID of that variable, which the tests own.
const HIIDB_CRC32_VENDOR: Guid = guid!("de145b29-c3cd-455f-91de-a76237b67c52");
/// Name of the variable that holds the length and address of the configuration table copy, in
/// `HiiDB`'s layout, for the tests only, with the vendor and attributes of `HiiDBCrc32`.
const HIIDB_CONFIG_TABLE_NAME: &CStr16 = cstr16!("HiiDBConfigTable");
/// The configuration table GUID of the database copy (UEFI 2.11 §33.2.11.1).
static HII_DATABASE_GUID: Guid = HiiDatabaseProtocol::GUID;

/// Where the copy starts in its pages: an unaligned start makes `uefisettings`
/// read the first page from an unaligned address, which arm64 Device memory
/// faults for wide loads (<https://github.com/linuxboot/uefisettings/pull/12>).
const COPY_OFFSET: usize = 1;

/// Signature of the ACPI table that `acpi-table` installs.
const QHII_SIGNATURE: [u8; 4] = *b"QHII";
/// Signature of the ACPI table that `acpi-table-hiid` installs.
const HIID_SIGNATURE: [u8; 4] = *b"HIID";
/// The body of the table that `acpi-table-junk-qhii` installs: no HII package list.
const JUNK_TABLE_BODY: [u8; 64] = [0x5a; 64];
/// Size of the header of an ACPI table, EFI_ACPI_DESCRIPTION_HEADER (edk2
/// MdePkg/Include/IndustryStandard/Acpi10.h), which the database follows.
const ACPI_HEADER_SIZE: usize = 36;
/// Revision of the `QHII` and `HIID` tables, which uefisettings does not read.
const ACPI_TABLE_REVISION: u8 = 1;

/// The configuration table GUID of EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2).
static RT_PROPERTIES_TABLE_GUID: Guid = guid!("eb66918a-7eef-402a-842e-931d21c38ae9");
/// EFI_RT_PROPERTIES_TABLE_VERSION.
const RT_PROPERTIES_TABLE_VERSION: u16 = 1;
/// The size of EFI_RT_PROPERTIES_TABLE: Version, Length, then RuntimeServicesSupported.
const RT_PROPERTIES_TABLE_LEN: u16 = 8;
/// RuntimeServicesSupported with every EFI_RT_SUPPORTED_* bit of UEFI 2.11 §4.6.2.
const RT_SUPPORTED_ALL: u32 = 0x3fff;
/// EFI_RT_SUPPORTED_SET_VARIABLE.
const RT_SUPPORTED_SET_VARIABLE: u32 = 0x0040;
/// A Version of EFI_RT_PROPERTIES_TABLE that no UEFI version defines.
const RT_PROPERTIES_TABLE_VERSION_UNDEFINED: u16 = 2;

/// EFI_JSON_CONFIG_DATA_TABLE_GUID (UEFI 2.11 §4.6.1.2).
static JSON_CONFIG_DATA_TABLE_GUID: Guid = guid!("87367f87-1119-41ce-aaec-8be0111f558a");
/// EFI_JSON_CAPSULE_CONFIG_DATA's Version, "initially 0x00000001" (UEFI 2.11 §23.5.2).
const JSON_CONFIG_DATA_VERSION: u32 = 1;
/// The ConfigData of the items of the table that `json-config-data` installs: JSON text, then
/// bytes that are no UTF-8.
const JSON_CONFIG_DATA_ITEMS: [&[u8]; 2] = [
    br#"{"uefisettings":"json-config-data"}"#,
    &[0xff, 0x00, 0x80, 0x7f],
];
/// The TotalLength of the table of `json-config-data-past-region`, 16 MiB, which runs past the
/// end of the runtime-data region that holds the table.
const PAST_REGION_TOTAL_LENGTH: u32 = 0x0100_0000;

/// A failed step and the firmware's status.
type Failure = (&'static str, Status);

/// Lets `cargo build --workspace` build the host target too; only the UEFI
/// build is a driver.
#[cfg(not(target_os = "uefi"))]
fn main() {
    panic!("publish-hiidb is a UEFI driver: build it for a UEFI target");
}

#[entry]
fn efi_main() -> Status {
    let result = match load_option() {
        Some(Task::Publish(memory_type, database)) => {
            publish(memory_type, database).map(|(address, length)| {
                println!("publish-hiidb: {length} bytes at {address:#x}, type {memory_type:?}");
            })
        }
        Some(Task::RegisterPasswordForms) => register_package_list(
            &password_forms::package_list_bytes(),
            "registering the password forms",
        )
        .map(|()| println!("publish-hiidb: registered the password forms")),
        Some(Task::RegisterEnhancedAuthForms) => register_package_list(
            &enhanced_auth_forms::package_list_bytes(),
            "registering the enhanced authenticated forms",
        )
        .map(|()| println!("publish-hiidb: registered the enhanced authenticated forms")),
        Some(Task::RegisterDroppedPasswordForms) => register_package_list(
            &dropped_password_forms::package_list_bytes(),
            "registering the dropped password forms",
        )
        .map(|()| println!("publish-hiidb: registered the dropped password forms")),
        Some(Task::RegisterPaddedStrings) => register_package_list(
            &padded_strings::package_list_bytes(),
            "registering the padded strings",
        )
        .map(|()| println!("publish-hiidb: registered the padded strings")),
        Some(Task::PublishReadWriteForms) => publish_readwrite_forms().map(|(address, length)| {
            println!("publish-hiidb: read/write forms registered; {length} bytes at {address:#x}");
        }),
        Some(Task::PublishAcpiTable(signature)) => publish_acpi_table(signature).map(|length| {
            let signature = signature.escape_ascii();
            println!("publish-hiidb: {length} bytes in the {signature} ACPI table");
        }),
        Some(Task::PublishJunkAcpiTable(signature)) => {
            install_acpi_table(signature, &JUNK_TABLE_BODY).map(|length| {
                let signature = signature.escape_ascii();
                println!("publish-hiidb: {length} junk bytes in the {signature} ACPI table");
            })
        }
        Some(Task::InstallConfigTables) => install_config_tables(),
        Some(Task::InstallRtProperties(version, supported)) => {
            install_rt_properties(version, supported)
        }
        Some(Task::InstallJsonConfigData(table)) => install_json_config_data(table),
        Some(Task::SetAuthVariables(payloads)) => auth_variables::set_auth_variables(&payloads)
            .map(|log| println!("publish-hiidb: AuthProbeLog {log}")),
        None => {
            println!(
                "usage: publish-hiidb \
                 [rt-data|reserved|acpi-nvs|loader-data|rt-data-global-variable-forms\
                 |rt-data-readwrite-forms|password-forms|enhanced-auth-forms\
                 |dropped-password-forms|padded-strings\
                 |acpi-table|acpi-table-hiid|acpi-table-junk-qhii\
                 |install-config-tables|rt-properties-no-set-variable|rt-properties-all\
                 |rt-properties-version-2|rt-properties-version-2-all|json-config-data\
                 |json-config-data-past-region|json-config-data-boot-services\
                 |json-config-data-mmio|set-auth-variables=PATH[,PATH]...]"
            );
            return Status::INVALID_PARAMETER;
        }
    };
    match result {
        Ok(()) => Status::SUCCESS,
        Err((step, status)) => {
            println!("publish-hiidb: ERROR: {step}: {status:?}");
            status
        }
    }
}

/// What the load option asks for.
#[derive(Clone, Debug)]
enum Task {
    /// Publish the database in pages of the memory type.
    Publish(MemoryType, Database),
    /// Register the package list of [`password_forms`] in the HII database.
    RegisterPasswordForms,
    /// Register the package list of [`enhanced_auth_forms`] in the HII database.
    RegisterEnhancedAuthForms,
    /// Register the package list of [`dropped_password_forms`] in the HII database.
    RegisterDroppedPasswordForms,
    /// Register the package list of [`padded_strings`] in the HII database.
    RegisterPaddedStrings,
    /// Create the variable of [`readwrite_forms`] if missing, register its package list in the
    /// HII database, then publish the database in runtime-data pages.
    PublishReadWriteForms,
    /// Publish the database in an ACPI table of the signature.
    PublishAcpiTable([u8; 4]),
    /// Install an ACPI table of the signature whose body is JUNK_TABLE_BODY.
    PublishJunkAcpiTable([u8; 4]),
    /// Install a copy of the database as the HII database protocol's configuration table.
    InstallConfigTables,
    /// Install an EFI_RT_PROPERTIES_TABLE of this Version and RuntimeServicesSupported.
    InstallRtProperties(u16, u32),
    /// Install this JSON configuration table.
    InstallJsonConfigData(JsonConfigTable),
    /// Run the authenticated writes of [`auth_variables`] with the payloads.
    SetAuthVariables(Vec<auth_variables::Payload>),
}

/// The task that the optional data of the load option, a NUL-terminated UCS-2 string,
/// names: `rt-data` if there is none, or `None` if it is invalid.
fn load_option() -> Option<Task> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok()?;
    let rt_data = MemoryType::RUNTIME_SERVICES_DATA;
    match image.load_options_as_cstr16() {
        Err(LoadOptionsError::NotSet) => Some(Task::Publish(rt_data, Database::Exported)),
        Ok(option) if option == cstr16!("rt-data") => {
            Some(Task::Publish(rt_data, Database::Exported))
        }
        Ok(option) if option == cstr16!("reserved") => {
            Some(Task::Publish(MemoryType::RESERVED, Database::Exported))
        }
        Ok(option) if option == cstr16!("acpi-nvs") => Some(Task::Publish(
            MemoryType::ACPI_NON_VOLATILE,
            Database::Exported,
        )),
        Ok(option) if option == cstr16!("loader-data") => {
            Some(Task::Publish(MemoryType::LOADER_DATA, Database::Exported))
        }
        Ok(option) if option == cstr16!("rt-data-global-variable-forms") => {
            Some(Task::Publish(rt_data, Database::WithGlobalVariableForms))
        }
        Ok(option) if option == cstr16!("rt-data-readwrite-forms") => {
            Some(Task::PublishReadWriteForms)
        }
        Ok(option) if option == cstr16!("password-forms") => Some(Task::RegisterPasswordForms),
        Ok(option) if option == cstr16!("enhanced-auth-forms") => {
            Some(Task::RegisterEnhancedAuthForms)
        }
        Ok(option) if option == cstr16!("dropped-password-forms") => {
            Some(Task::RegisterDroppedPasswordForms)
        }
        Ok(option) if option == cstr16!("padded-strings") => Some(Task::RegisterPaddedStrings),
        Ok(option) if option == cstr16!("acpi-table") => {
            Some(Task::PublishAcpiTable(QHII_SIGNATURE))
        }
        Ok(option) if option == cstr16!("acpi-table-hiid") => {
            Some(Task::PublishAcpiTable(HIID_SIGNATURE))
        }
        Ok(option) if option == cstr16!("acpi-table-junk-qhii") => {
            Some(Task::PublishJunkAcpiTable(QHII_SIGNATURE))
        }
        Ok(option) if option == cstr16!("install-config-tables") => Some(Task::InstallConfigTables),
        Ok(option) if option == cstr16!("rt-properties-no-set-variable") => {
            Some(Task::InstallRtProperties(
                RT_PROPERTIES_TABLE_VERSION,
                RT_SUPPORTED_ALL & !RT_SUPPORTED_SET_VARIABLE,
            ))
        }
        Ok(option) if option == cstr16!("rt-properties-all") => Some(Task::InstallRtProperties(
            RT_PROPERTIES_TABLE_VERSION,
            RT_SUPPORTED_ALL,
        )),
        Ok(option) if option == cstr16!("rt-properties-version-2") => {
            Some(Task::InstallRtProperties(
                RT_PROPERTIES_TABLE_VERSION_UNDEFINED,
                RT_SUPPORTED_ALL & !RT_SUPPORTED_SET_VARIABLE,
            ))
        }
        Ok(option) if option == cstr16!("rt-properties-version-2-all") => Some(
            Task::InstallRtProperties(RT_PROPERTIES_TABLE_VERSION_UNDEFINED, RT_SUPPORTED_ALL),
        ),
        Ok(option) if option == cstr16!("json-config-data") => {
            Some(Task::InstallJsonConfigData(JsonConfigTable::Runtime))
        }
        Ok(option) if option == cstr16!("json-config-data-past-region") => {
            Some(Task::InstallJsonConfigData(JsonConfigTable::PastRegion))
        }
        Ok(option) if option == cstr16!("json-config-data-boot-services") => {
            Some(Task::InstallJsonConfigData(JsonConfigTable::BootServices))
        }
        Ok(option) if option == cstr16!("json-config-data-mmio") => {
            Some(Task::InstallJsonConfigData(JsonConfigTable::MemoryMappedIo))
        }
        Ok(option) => auth_variables::payloads(option).map(Task::SetAuthVariables),
        _ => None,
    }
}

/// EFI_HII_DATABASE_PROTOCOL with its functions, of which the uefi crate's HiiDatabase wraps
/// only ExportPackageLists().
#[repr(transparent)]
#[unsafe_protocol(HiiDatabaseProtocol::GUID)]
struct RawHiiDatabase(HiiDatabaseProtocol);

/// Registers the package list `list` in the HII database, for no driver, until the reset: the
/// UEFI Shell or a later publish-hiidb exports the database. A failure names `step`.
fn register_package_list(list: &[u8], step: &'static str) -> Result<(), Failure> {
    let database = boot::get_handle_for_protocol::<RawHiiDatabase>()
        .and_then(boot::open_protocol_exclusive::<RawHiiDatabase>)
        .map_err(|error| ("opening the HII database", error.status()))?;
    let mut handle = ptr::null_mut();
    #[expect(
        unsafe_code,
        reason = "the uefi crate does not wrap NewPackageList(), a function of the protocol"
    )]
    // SAFETY: `database` is the protocol that the firmware installed, which stays open while
    // the call runs; `list` is a whole package list whose header gives its length, whose
    // packages the database adds (UEFI 2.10 §34.8.2) as copies (edk2-stable202508
    // HiiDatabaseDxe/Database.c HiiNewPackageList); DriverHandle is optional, and `handle` is a
    // valid place for the new HII handle.
    let status = unsafe {
        (database.0.new_package_list)(
            &database.0,
            list.as_ptr().cast(),
            ptr::null_mut(),
            &mut handle,
        )
    };
    status.to_result().map_err(|error| (step, error.status()))
}

/// Creates the variable of [`readwrite_forms`] unless it exists, as a driver creates its
/// storage, registers the package list of [`readwrite_forms`], then publishes the database in
/// runtime-data pages. Returns the address and length of the copy.
fn publish_readwrite_forms() -> Result<(u64, u32), Failure> {
    let vendor = VariableVendor(readwrite_forms::STORE_VENDOR);
    match runtime::get_variable(readwrite_forms::STORE_NAME, &vendor, &mut []) {
        Err(error) if error.status() == Status::NOT_FOUND => runtime::set_variable(
            readwrite_forms::STORE_NAME,
            &vendor,
            readwrite_forms::STORE_ATTRIBUTES,
            &readwrite_forms::STORE_DATA,
        )
        .map_err(|error| ("creating the ReadWriteData variable", error.status()))?,
        // it exists, with data
        Err(error) if error.status() == Status::BUFFER_TOO_SMALL => {}
        Err(error) => return Err(("reading the ReadWriteData variable", error.status())),
        Ok(_) => {
            return Err((
                "reading the ReadWriteData variable",
                Status::BAD_BUFFER_SIZE,
            ))
        }
    }
    register_package_list(
        &readwrite_forms::package_list_bytes(),
        "registering the read/write forms",
    )?;
    publish(MemoryType::RUNTIME_SERVICES_DATA, Database::Exported)
}

/// The HII database that publish-hiidb copies.
#[derive(Clone, Copy, Debug)]
enum Database {
    /// The one that the firmware exports.
    Exported,
    /// That one, then the package lists of [`global_variable_forms`].
    WithGlobalVariableForms,
}

/// Returns `database` after putting its CRC-32 in `HiiDBCrc32`, so that no source
/// publishes it without its CRC-32.
fn export_with_crc32(database: Database) -> Result<Vec<u8>, Failure> {
    let mut export = boot::get_handle_for_protocol::<HiiDatabase>()
        .and_then(boot::open_protocol_exclusive::<HiiDatabase>)
        .and_then(|database| database.export_all_raw())
        .map_err(|error| ("exporting the HII database", error.status()))?
        .into_vec();
    match database {
        Database::Exported => {}
        Database::WithGlobalVariableForms => {
            export.extend(global_variable_forms::package_lists());
        }
    }

    let crc32 = boot::calculate_crc32(&export)
        .map_err(|error| ("computing the CRC-32 of the HII database", error.status()))?;
    runtime::set_variable(
        HIIDB_CRC32_NAME,
        &VariableVendor(HIIDB_CRC32_VENDOR),
        HIIDB_ATTRIBUTES,
        &crc32.to_le_bytes(),
    )
    .map_err(|error| ("setting the HiiDBCrc32 variable", error.status()))?;
    Ok(export)
}

/// Copies `database` into pages of `memory_type` at `COPY_OFFSET` and points `HiiDB` at
/// the copy. Returns the address and length of the copy.
///
/// The pages are never freed: the OS reads them after boot.
fn publish(memory_type: MemoryType, database: Database) -> Result<(u64, u32), Failure> {
    let export = export_with_crc32(database)?;
    let length = u32::try_from(export.len())
        .map_err(|_| ("the HII database exceeds 4 GiB", Status::BAD_BUFFER_SIZE))?;

    let pages = (COPY_OFFSET + export.len()).div_ceil(PAGE_SIZE);
    let base = boot::allocate_pages(AllocateType::AnyPages, memory_type, pages)
        .map_err(|error| ("allocating pages", error.status()))?;
    let copy = base.as_ptr().wrapping_add(COPY_OFFSET);
    #[expect(
        unsafe_code,
        reason = "the pages from allocate_pages() are only reachable through a raw pointer"
    )]
    // SAFETY: `allocate_pages` returned `pages * PAGE_SIZE` bytes that nothing
    // else references, and UEFI identity-maps memory, so the address is a
    // valid pointer. `export` fits in them after `COPY_OFFSET` and does not
    // overlap them.
    unsafe {
        ptr::write_bytes(base.as_ptr(), 0, pages * PAGE_SIZE);
        ptr::copy_nonoverlapping(export.as_ptr(), copy, export.len());
    }
    // `usize` has at most 64 bits on the UEFI targets.
    let address = copy.addr() as u64;

    let mut data = [0; size_of::<u32>() + size_of::<u64>()];
    data[..4].copy_from_slice(&length.to_le_bytes());
    data[4..].copy_from_slice(&address.to_le_bytes());
    runtime::set_variable(
        HIIDB_NAME,
        &VariableVendor(HIIDB_VENDOR),
        HIIDB_ATTRIBUTES,
        &data,
    )
    .map_err(|error| ("setting the HiiDB variable", error.status()))?;
    Ok((address, length))
}

/// Installs the database that the firmware exports as the body of an ACPI table of
/// `signature`, after its header. Returns the length of the database.
fn publish_acpi_table(signature: [u8; 4]) -> Result<usize, Failure> {
    let export = export_with_crc32(Database::Exported)?;
    install_acpi_table(signature, &export)
}

/// Installs an ACPI table of `signature` whose body, after its header, is `body`. Returns the
/// length of the body.
fn install_acpi_table(signature: [u8; 4], body: &[u8]) -> Result<usize, Failure> {
    let table_length = ACPI_HEADER_SIZE
        .checked_add(body.len())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(("the ACPI table exceeds 4 GiB", Status::BAD_BUFFER_SIZE))?;

    // Signature, Length and Revision. The rest of the header is zeros: Checksum, which
    // InstallAcpiTable() corrects in its copy (UEFI 2.11 §20.2), then the OEM and creator fields,
    // which uefisettings does not read.
    let mut table = [
        &signature[..],
        &table_length.to_le_bytes(),
        &[ACPI_TABLE_REVISION],
    ]
    .concat();
    table.resize(ACPI_HEADER_SIZE, 0);
    table.extend_from_slice(body);

    let acpi = boot::get_handle_for_protocol::<AcpiTable>()
        .and_then(boot::open_protocol_exclusive::<AcpiTable>)
        .map_err(|error| ("opening the ACPI table protocol", error.status()))?;
    #[expect(
        unsafe_code,
        reason = "the uefi crate's InstallAcpiTable() wrapper is unsafe"
    )]
    // SAFETY: `table` is a whole table whose Length is its size. InstallAcpiTable() links a copy
    // of it (UEFI 2.11 §20.2): edk2-stable202608 AcpiTableProtocol.c InstallAcpiTable() copies it
    // with AllocateCopyPool() and passes the copy to AddTableToList() with Checksum TRUE. So it
    // needs `table` only during the call, not in memory of a type that the OS keeps, which the
    // wrapper's documentation asks for.
    unsafe { acpi.install_acpi_table(table.as_ptr().cast(), table.len()) }
        .map_err(|error| ("installing the ACPI table", error.status()))?;
    Ok(body.len())
}

/// Installs a runtime-data pool copy of the exported database as the configuration table of
/// [`HII_DATABASE_GUID`], as edk2's HiiGetDatabaseInfo() does
/// (MdeModulePkg/Universal/HiiDatabaseDxe/Database.c): in a zeroed pool a quarter larger than
/// the database, so that the OS finds its end at a zero header. Puts its CRC-32 in
/// `HiiDBCrc32` and its length and address in `HiiDBConfigTable`, and logs the latter two.
fn install_config_tables() -> Result<(), Failure> {
    let export = export_with_crc32(Database::Exported)?;
    let length = u32::try_from(export.len())
        .map_err(|_| ("the HII database exceeds 4 GiB", Status::BAD_BUFFER_SIZE))?;

    let size = export.len().checked_add(export.len() / 4).ok_or((
        "the HII database's pool size overflows",
        Status::BAD_BUFFER_SIZE,
    ))?;
    let copy = boot::allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, size)
        .map_err(|error| ("allocating the runtime pool", error.status()))?;
    #[expect(
        unsafe_code,
        reason = "the pool from allocate_pool() is only reachable through a raw pointer"
    )]
    // SAFETY: allocate_pool returned `size` bytes, at least `export.len()`, that nothing else
    // references, at an identity-mapped address, and `export` does not overlap them.
    unsafe {
        ptr::write_bytes(copy.as_ptr(), 0, size);
        ptr::copy_nonoverlapping(export.as_ptr(), copy.as_ptr(), export.len());
    }
    #[expect(
        unsafe_code,
        reason = "InstallConfigurationTable() takes a raw pointer that must stay valid"
    )]
    // SAFETY: the table is a runtime-data pool allocation, as the function requires, that is
    // never freed or written again.
    unsafe { boot::install_configuration_table(&HII_DATABASE_GUID, copy.as_ptr().cast()) }
        .map_err(|error| ("installing the configuration table", error.status()))?;
    // `usize` has at most 64 bits on the UEFI targets.
    let address = copy.as_ptr().addr() as u64;

    let mut data = [0; size_of::<u32>() + size_of::<u64>()];
    data[..4].copy_from_slice(&length.to_le_bytes());
    data[4..].copy_from_slice(&address.to_le_bytes());
    runtime::set_variable(
        HIIDB_CONFIG_TABLE_NAME,
        &VariableVendor(HIIDB_CRC32_VENDOR),
        HIIDB_ATTRIBUTES,
        &data,
    )
    .map_err(|error| ("setting the HiiDBConfigTable variable", error.status()))?;

    println!("publish-hiidb: config table {HII_DATABASE_GUID} at {address:#x}, {length} bytes");
    Ok(())
}

/// Installs an EFI_RT_PROPERTIES_TABLE of Version `version` whose RuntimeServicesSupported is
/// `supported`, in a runtime-data pool, and logs its address.
fn install_rt_properties(version: u16, supported: u32) -> Result<(), Failure> {
    let mut table = [0; RT_PROPERTIES_TABLE_LEN as usize];
    table[..2].copy_from_slice(&version.to_le_bytes());
    table[2..4].copy_from_slice(&RT_PROPERTIES_TABLE_LEN.to_le_bytes());
    table[4..].copy_from_slice(&supported.to_le_bytes());

    let pool = boot::allocate_pool(MemoryType::RUNTIME_SERVICES_DATA, table.len())
        .map_err(|error| ("allocating the runtime pool", error.status()))?;
    #[expect(
        unsafe_code,
        reason = "the pool from allocate_pool() is only reachable through a raw pointer"
    )]
    // SAFETY: allocate_pool returned `table.len()` bytes that nothing else references, at an
    // identity-mapped address, and `table` does not overlap them.
    unsafe {
        ptr::copy_nonoverlapping(table.as_ptr(), pool.as_ptr(), table.len());
    }
    #[expect(
        unsafe_code,
        reason = "InstallConfigurationTable() takes a raw pointer that must stay valid"
    )]
    // SAFETY: the table is a runtime-data pool allocation, as the function requires, that is
    // never freed or written again.
    unsafe { boot::install_configuration_table(&RT_PROPERTIES_TABLE_GUID, pool.as_ptr().cast()) }
        .map_err(|error| ("installing the RT properties table", error.status()))?;

    let address = pool.as_ptr().addr();
    println!(
        "publish-hiidb: RT properties table at {address:#x}, Version {version}, \
         RuntimeServicesSupported {supported:#06x}"
    );
    Ok(())
}

/// The JSON configuration table that install_json_config_data installs.
#[derive(Clone, Copy, Debug)]
enum JsonConfigTable {
    /// An EFI_JSON_CAPSULE_CONFIG_DATA of [`JSON_CONFIG_DATA_ITEMS`], in runtime services data.
    Runtime,
    /// That table with a TotalLength of [`PAST_REGION_TOTAL_LENGTH`].
    PastRegion,
    /// That table in boot services data, which the OS may take after ExitBootServices().
    BootServices,
    /// The start of the first EFI_MEMORY_RUNTIME descriptor of memory-mapped I/O.
    MemoryMappedIo,
}

/// Installs `table` as the configuration table of EFI_JSON_CONFIG_DATA_TABLE_GUID, and logs its
/// address.
fn install_json_config_data(table: JsonConfigTable) -> Result<(), Failure> {
    let address = match table {
        JsonConfigTable::Runtime => {
            copy_json_config_data(MemoryType::RUNTIME_SERVICES_DATA, TotalLength::OfItems)?
        }
        JsonConfigTable::PastRegion => {
            copy_json_config_data(MemoryType::RUNTIME_SERVICES_DATA, TotalLength::PastRegion)?
        }
        JsonConfigTable::BootServices => {
            copy_json_config_data(MemoryType::BOOT_SERVICES_DATA, TotalLength::OfItems)?
        }
        JsonConfigTable::MemoryMappedIo => runtime_memory_mapped_io()?,
    };
    #[expect(
        unsafe_code,
        reason = "InstallConfigurationTable() takes a raw pointer that must stay valid"
    )]
    // SAFETY: the table is in a pool allocation that is never freed or written again, or is
    // memory-mapped I/O that the firmware keeps for runtime services: both stay valid as long as
    // the firmware runs. The OS may take boot services data, which is what that table tests.
    unsafe {
        boot::install_configuration_table(
            &JSON_CONFIG_DATA_TABLE_GUID,
            ptr::with_exposed_provenance(address),
        )
    }
    .map_err(|error| ("installing the JSON configuration table", error.status()))?;

    println!("publish-hiidb: JSON configuration table at {address:#x}, {table:?}");
    Ok(())
}

/// The TotalLength of the table that copy_json_config_data copies.
#[derive(Clone, Copy, Debug)]
enum TotalLength {
    /// That of the table's Version, TotalLength and items.
    OfItems,
    /// [`PAST_REGION_TOTAL_LENGTH`].
    PastRegion,
}

/// Copies an EFI_JSON_CAPSULE_CONFIG_DATA of [`JSON_CONFIG_DATA_ITEMS`], their
/// EFI_JSON_CONFIG_DATA_ITEMs back to back after its Version and TotalLength (UEFI 2.11
/// §23.5.2), with the TotalLength that `total_length` says, to `COPY_OFFSET` of a pool of
/// `memory_type`. Returns the copy's address.
fn copy_json_config_data(
    memory_type: MemoryType,
    total_length: TotalLength,
) -> Result<usize, Failure> {
    let too_large = (
        "the JSON configuration data exceeds 4 GiB",
        Status::BAD_BUFFER_SIZE,
    );
    let items: Vec<u8> = JSON_CONFIG_DATA_ITEMS
        .iter()
        .map(|data| {
            let length = u32::try_from(data.len()).map_err(|_| too_large)?;
            Ok([&length.to_le_bytes()[..], data].concat())
        })
        .collect::<Result<Vec<_>, Failure>>()?
        .concat();
    let total_length = match total_length {
        TotalLength::OfItems => items
            .len()
            .checked_add(2 * size_of::<u32>())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(too_large)?,
        TotalLength::PastRegion => PAST_REGION_TOTAL_LENGTH,
    };
    let table = [
        &JSON_CONFIG_DATA_VERSION.to_le_bytes()[..],
        &total_length.to_le_bytes(),
        &items,
    ]
    .concat();

    let pool = boot::allocate_pool(memory_type, COPY_OFFSET + table.len())
        .map_err(|error| ("allocating the pool", error.status()))?;
    let copy = pool.as_ptr().wrapping_add(COPY_OFFSET);
    #[expect(
        unsafe_code,
        reason = "the pool from allocate_pool() is only reachable through a raw pointer"
    )]
    // SAFETY: allocate_pool returned `COPY_OFFSET + table.len()` bytes that nothing else
    // references, at an identity-mapped address, and `table` fits after `COPY_OFFSET` without
    // overlapping them.
    unsafe {
        ptr::copy_nonoverlapping(table.as_ptr(), copy, table.len());
    }
    Ok(copy.addr())
}

/// The start of the first EFI_MEMORY_RUNTIME descriptor of memory-mapped I/O of the memory map.
fn runtime_memory_mapped_io() -> Result<usize, Failure> {
    let map = boot::memory_map(MemoryType::LOADER_DATA)
        .map_err(|error| ("reading the memory map", error.status()))?;
    let start = map
        .entries()
        .find(|descriptor| {
            descriptor.ty == MemoryType::MMIO && descriptor.att.contains(MemoryAttribute::RUNTIME)
        })
        .ok_or((
            "finding runtime memory-mapped I/O in the memory map",
            Status::NOT_FOUND,
        ))?
        .phys_start;
    usize::try_from(start)
        .map_err(|_| ("the memory-mapped I/O lies past usize", Status::UNSUPPORTED))
}
