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
//! `Driver####` load option runs as `publish-hiidb.efi [rt-data|reserved|loader-data]`:
//! it copies the HII database into pages of that memory type and points the
//! volatile `HiiDB` variable at them as `{ u32 length; u64 address }`, the way
//! OCP firmware does for `src/lib/hii/extract.rs`. The x86 EFI stub reports
//! `rt-data` (the default) and `reserved` as E820 reserved ranges, which
//! `/dev/mem` serves under `CONFIG_STRICT_DEVMEM`; `loader-data` becomes System
//! RAM, which it refuses.

#![cfg_attr(target_os = "uefi", no_std, no_main)]
#![deny(unsafe_code)]

extern crate alloc;

use core::ptr;

use uefi::boot;
use uefi::boot::AllocateType;
use uefi::boot::MemoryType;
use uefi::boot::PAGE_SIZE;
use uefi::cstr16;
use uefi::entry;
use uefi::guid;
use uefi::println;
use uefi::proto::hii::database::HiiDatabase;
use uefi::proto::loaded_image::LoadOptionsError;
use uefi::proto::loaded_image::LoadedImage;
use uefi::runtime;
use uefi::runtime::VariableAttributes;
use uefi::runtime::VariableVendor;
use uefi::CStr16;
use uefi::Guid;
use uefi::Status;

/// Name of the variable that `uefisettings` looks for.
const HIIDB_NAME: &CStr16 = cstr16!("HiiDB");
/// Vendor GUID of that variable.
const HIIDB_VENDOR: Guid = guid!("1b838190-4625-4ead-abc9-cd5e6af18fe0");
/// Attributes of that variable: volatile and readable at runtime.
const HIIDB_ATTRIBUTES: VariableAttributes =
    VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);

/// A failed step and the firmware's status.
type Failure = (&'static str, Status);

/// Lets `cargo build --workspace` build the host target too; only the UEFI
/// build is a driver.
#[cfg(not(target_os = "uefi"))]
fn main() {
    panic!("publish-hiidb is a UEFI driver: build it for x86_64-unknown-uefi");
}

#[entry]
fn efi_main() -> Status {
    let Some(memory_type) = memory_type() else {
        println!("usage: publish-hiidb [rt-data|reserved|loader-data]");
        return Status::INVALID_PARAMETER;
    };
    match publish(memory_type) {
        Ok((address, length)) => {
            println!("publish-hiidb: {length} bytes at {address:#x}, type {memory_type:?}");
            Status::SUCCESS
        }
        Err((step, status)) => {
            println!("publish-hiidb: ERROR: {step}: {status:?}");
            status
        }
    }
}

/// The memory type that the optional data of the load option, a NUL-terminated
/// UCS-2 string, names: `rt-data` if there is none, or `None` if it is invalid.
fn memory_type() -> Option<MemoryType> {
    let image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle()).ok()?;
    match image.load_options_as_cstr16() {
        Err(LoadOptionsError::NotSet) => Some(MemoryType::RUNTIME_SERVICES_DATA),
        Ok(option) if option == cstr16!("rt-data") => Some(MemoryType::RUNTIME_SERVICES_DATA),
        Ok(option) if option == cstr16!("reserved") => Some(MemoryType::RESERVED),
        Ok(option) if option == cstr16!("loader-data") => Some(MemoryType::LOADER_DATA),
        _ => None,
    }
}

/// Copies the exported HII database into pages of `memory_type` and points
/// `HiiDB` at them. Returns the address and length of the copy.
///
/// The pages are never freed: the OS reads them after boot.
fn publish(memory_type: MemoryType) -> Result<(u64, u32), Failure> {
    let export = boot::get_handle_for_protocol::<HiiDatabase>()
        .and_then(boot::open_protocol_exclusive::<HiiDatabase>)
        .and_then(|database| database.export_all_raw())
        .map_err(|error| ("exporting the HII database", error.status()))?;
    let length = u32::try_from(export.len())
        .map_err(|_| ("the HII database exceeds 4 GiB", Status::BAD_BUFFER_SIZE))?;
    let pages = export.len().div_ceil(PAGE_SIZE);
    let base = boot::allocate_pages(AllocateType::AnyPages, memory_type, pages)
        .map_err(|error| ("allocating pages", error.status()))?;
    #[expect(
        unsafe_code,
        reason = "the pages from allocate_pages() are only reachable through a raw pointer"
    )]
    // SAFETY: `allocate_pages` returned `pages * PAGE_SIZE` bytes that nothing
    // else references, and UEFI identity-maps memory, so the address is a
    // valid pointer. `export` fits in them and does not overlap them.
    unsafe {
        ptr::write_bytes(base.as_ptr(), 0, pages * PAGE_SIZE);
        ptr::copy_nonoverlapping(export.as_ptr(), base.as_ptr(), export.len());
    }
    // `usize` is 64 bits wide on x86_64-unknown-uefi.
    let address = base.as_ptr().addr() as u64;

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
