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

//! The HII database of the UEFI Shell build, from EFI_HII_DATABASE_PROTOCOL through the uefi
//! crate, which the image's entry point initializes.

use std::ptr;

use anyhow::anyhow;
use anyhow::Result;
use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::boot::ScopedProtocol;
use uefi::proto::unsafe_protocol;
use uefi::Handle;
use uefi::Status;
use uefi_raw::protocol::hii::database::HiiDatabaseProtocol;
use uefi_raw::protocol::hii::HiiHandle;

/// EFI_HII_PACKAGE_TYPE_ALL (UEFI 2.11 §33.3.1.1): ListPackageLists() lists every package list.
const EFI_HII_PACKAGE_TYPE_ALL: u8 = 0x00;

/// EFI_HII_DATABASE_PROTOCOL, whose ListPackageLists(), ExportPackageLists() of one handle and
/// GetPackageListHandle() uefi's HiiDatabase does not wrap.
#[repr(transparent)]
// SAFETY: uefi-raw's GUID of the struct this wraps with repr(transparent)
#[unsafe_protocol(HiiDatabaseProtocol::GUID)]
struct HiiDatabaseFunctions(HiiDatabaseProtocol);

/// The package lists of the HII database, each exported by itself, in ListPackageLists() order,
/// with its EFI_HII_HANDLE: the i-th package list of their HiiDB is that of the i-th handle.
pub(crate) struct PackageLists {
    lists: Vec<(HiiHandle, Vec<u8>)>,
}

impl PackageLists {
    /// ListPackageLists() of every type, then ExportPackageLists() of each handle (UEFI 2.11
    /// §34.8.5, §34.8.6).
    pub(crate) fn export() -> Result<Self> {
        let database = open_database()?;
        let functions = database
            .get()
            .map(|database| &database.0)
            .ok_or_else(|| anyhow!("EFI_HII_DATABASE_PROTOCOL has no interface"))?;
        let lists = list_handles(functions)?
            .into_iter()
            .map(|handle| Ok((handle, export_list(functions, handle)?)))
            .collect::<Result<_>>()?;
        Ok(Self { lists })
    }

    /// The HiiDB of the package lists, in the format of the Linux build: each list whole, one
    /// after the other.
    pub(crate) fn hiidb(&self) -> Vec<u8> {
        self.lists
            .iter()
            .flat_map(|(_, list)| list)
            .copied()
            .collect()
    }

    /// The EFI_HII_HANDLE of the `index`-th package list.
    #[expect(dead_code, reason = "no caller reaches a package list's driver yet")]
    pub(crate) fn handle(&self, index: usize) -> Option<HiiHandle> {
        self.lists.get(index).map(|(handle, _)| *handle)
    }
}

/// The driver handle that registered the package list of `handle`: GetPackageListHandle()
/// (UEFI 2.11 §34.8.12), None if it names none.
#[expect(dead_code, reason = "no caller reaches a package list's driver yet")]
pub(crate) fn driver_handle(handle: HiiHandle) -> Result<Option<Handle>> {
    let database = open_database()?;
    let functions = database
        .get()
        .map(|database| &database.0)
        .ok_or_else(|| anyhow!("EFI_HII_DATABASE_PROTOCOL has no interface"))?;
    let mut driver: uefi_raw::Handle = ptr::null_mut();
    // SAFETY: GetPackageListHandle() of a handle that ListPackageLists() gave, which stores a
    // handle in `driver`
    let status = unsafe { (functions.get_package_list_handle)(functions, handle, &mut driver) };
    if status.is_error() {
        return Err(anyhow!("GetPackageListHandle(): {status:?}"));
    }
    // SAFETY: the handle that the HII database returned, or NULL
    Ok(unsafe { Handle::from_ptr(driver) })
}

/// Every package list of the HII database, as ExportPackageLists() with a NULL Handle gives
/// them (UEFI 2.10 §34.8.6), in the HiiDB format of the Linux build.
/// Each list is exported by its own handle, so that the i-th list is that of the i-th handle of
/// ListPackageLists().
pub(crate) fn export_package_lists() -> Result<Vec<u8>> {
    Ok(PackageLists::export()?.hiidb())
}

/// EFI_HII_DATABASE_PROTOCOL, opened GetProtocol for as long as the result lives.
fn open_database() -> Result<ScopedProtocol<HiiDatabaseFunctions>> {
    let handle = boot::get_handle_for_protocol::<HiiDatabaseFunctions>()
        .map_err(|error| anyhow!("EFI_HII_DATABASE_PROTOCOL: {:?}", error.status()))?;
    let params = OpenProtocolParams {
        handle,
        agent: boot::image_handle(),
        controller: None,
    };
    // GetProtocol, as Exclusive would disconnect the drivers that opened the protocol BY_DRIVER.
    // SAFETY: the protocol stays installed while the ScopedProtocol lives: edk2's HiiDatabaseDxe
    // (edk2-stable202508 HiiDatabaseEntry.c) installs it and uninstalls it nowhere.
    unsafe {
        boot::open_protocol::<HiiDatabaseFunctions>(params, OpenProtocolAttributes::GetProtocol)
    }
    .map_err(|error| {
        anyhow!(
            "OpenProtocol() of EFI_HII_DATABASE_PROTOCOL: {:?}",
            error.status()
        )
    })
}

/// ListPackageLists() of every type: a size probe, then the handles.
fn list_handles(functions: &HiiDatabaseProtocol) -> Result<Vec<HiiHandle>> {
    let mut size = 0;
    // SAFETY: ListPackageLists() with a HandleBufferLength of 0 and no buffer, which stores the
    // size it needs
    let status = unsafe {
        (functions.list_package_lists)(
            functions,
            EFI_HII_PACKAGE_TYPE_ALL,
            ptr::null(),
            &mut size,
            ptr::null_mut(),
        )
    };
    match status {
        Status::BUFFER_TOO_SMALL => {}
        // "No matching handles were found" (UEFI 2.11 §34.8.5)
        Status::NOT_FOUND => return Ok(Vec::new()),
        status => return Err(anyhow!("ListPackageLists(): {status:?}")),
    }
    let mut handles: Vec<HiiHandle> = vec![ptr::null_mut(); size.div_ceil(size_of::<HiiHandle>())];
    let mut size = handles.len() * size_of::<HiiHandle>();
    // SAFETY: ListPackageLists() into a buffer of `size` bytes of handles
    let status = unsafe {
        (functions.list_package_lists)(
            functions,
            EFI_HII_PACKAGE_TYPE_ALL,
            ptr::null(),
            &mut size,
            handles.as_mut_ptr(),
        )
    };
    if status.is_error() {
        return Err(anyhow!("ListPackageLists(): {status:?}"));
    }
    handles.truncate(size / size_of::<HiiHandle>());
    Ok(handles)
}

/// ExportPackageLists() of the package list of `handle`: a size probe, then the list.
fn export_list(functions: &HiiDatabaseProtocol, handle: HiiHandle) -> Result<Vec<u8>> {
    let mut size = 0;
    // SAFETY: ExportPackageLists() with a BufferSize of 0 and no buffer, which stores the size
    // it needs
    let status =
        unsafe { (functions.export_package_lists)(functions, handle, &mut size, ptr::null_mut()) };
    match status {
        Status::BUFFER_TOO_SMALL => {}
        status => return Err(anyhow!("ExportPackageLists() size: {status:?}")),
    }
    let mut list = vec![0u8; size];
    // SAFETY: ExportPackageLists() into a buffer of `size` bytes
    let status = unsafe {
        (functions.export_package_lists)(functions, handle, &mut size, list.as_mut_ptr().cast())
    };
    if status.is_error() {
        return Err(anyhow!("ExportPackageLists(): {status:?}"));
    }
    // the firmware may write less than it announced, as uefi's export_all_raw keeps
    list.truncate(size);
    Ok(list)
}
