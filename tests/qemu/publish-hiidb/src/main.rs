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
//! `publish-hiidb.efi [rt-data|reserved|acpi-nvs|loader-data|rt-data-global-variable-forms|password-forms|acpi-table|acpi-table-hiid|acpi-table-junk-qhii|install-config-tables]`:
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
//! `password-forms` publishes nothing: it registers the package list of [`password_forms`]
//! in the HII database, for `uefisettings.efi` in the UEFI Shell, which exports the database.
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

#![cfg_attr(target_os = "uefi", no_std, no_main)]
#![deny(unsafe_code)]

extern crate alloc;

mod global_variable_forms;
mod hii_package;
mod password_forms;

use alloc::vec::Vec;
use core::ptr;

use uefi::boot;
use uefi::boot::AllocateType;
use uefi::boot::MemoryType;
use uefi::boot::PAGE_SIZE;
use uefi::cstr16;
use uefi::entry;
use uefi::guid;
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
        Some(Task::RegisterPasswordForms) => register_password_forms()
            .map(|()| println!("publish-hiidb: registered the password forms")),
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
        None => {
            println!(
                "usage: publish-hiidb \
                 [rt-data|reserved|acpi-nvs|loader-data|rt-data-global-variable-forms\
                 |password-forms|acpi-table|acpi-table-hiid|acpi-table-junk-qhii\
                 |install-config-tables]"
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
#[derive(Clone, Copy, Debug)]
enum Task {
    /// Publish the database in pages of the memory type.
    Publish(MemoryType, Database),
    /// Register the package list of [`password_forms`] in the HII database.
    RegisterPasswordForms,
    /// Publish the database in an ACPI table of the signature.
    PublishAcpiTable([u8; 4]),
    /// Install an ACPI table of the signature whose body is JUNK_TABLE_BODY.
    PublishJunkAcpiTable([u8; 4]),
    /// Install a copy of the database as the HII database protocol's configuration table.
    InstallConfigTables,
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
        Ok(option) if option == cstr16!("password-forms") => Some(Task::RegisterPasswordForms),
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
        _ => None,
    }
}

/// EFI_HII_DATABASE_PROTOCOL with its functions, of which the uefi crate's HiiDatabase wraps
/// only ExportPackageLists().
#[repr(transparent)]
#[unsafe_protocol(HiiDatabaseProtocol::GUID)]
struct RawHiiDatabase(HiiDatabaseProtocol);

/// Registers the package list of [`password_forms`] in the HII database, for no driver, until
/// the reset: the UEFI Shell exports the database later.
fn register_password_forms() -> Result<(), Failure> {
    let database = boot::get_handle_for_protocol::<RawHiiDatabase>()
        .and_then(boot::open_protocol_exclusive::<RawHiiDatabase>)
        .map_err(|error| ("opening the HII database", error.status()))?;
    let list = password_forms::package_list_bytes();
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
    status
        .to_result()
        .map_err(|error| ("registering the password forms", error.status()))
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
