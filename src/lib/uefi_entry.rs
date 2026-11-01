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

//! The entry point of the UEFI Shell build, which the linker takes from build.rs: it hands the
//! image handle and system table to the uefi crate, as its documentation asks of an image
//! without uefi::entry, then runs the efi_main that rustc generates for std's main.
//! It exists because std::os::uefi::env, which would give main both, is unstable
//! (<https://github.com/rust-lang/rust/issues/100499>). Once that is stable, main can initialize
//! the uefi crate, and this entry point stays only while std returns ExitCode::FAILURE as the
//! warning 1 (Rust 1.93.1 library/std/src/sys/process/uefi.rs). Its efi_main declaration mirrors
//! the entry point that rustc generates.

use core::ffi::c_void;

use uefi::Status;

use crate::exit_status::efi_status;

extern "efiapi" {
    /// std's entry point, which runs main and returns its exit code: 0 or, for
    /// ExitCode::FAILURE, 1.
    fn efi_main(image_handle: *mut c_void, system_table: *mut c_void) -> usize;
}

/// Runs main and returns the efi_status of its exit code.
///
/// # Safety
/// Only the firmware calls it, as the image's entry point, with the image's handle and the
/// system table.
#[no_mangle]
unsafe extern "efiapi" fn uefi_std_entry(
    image_handle: *mut c_void,
    system_table: *mut c_void,
) -> Status {
    // SAFETY: the firmware's system table, set before any other call into the uefi crate, as
    // uefi::table::set_system_table asks of an image without uefi::entry
    unsafe { uefi::table::set_system_table(system_table.cast()) };
    // SAFETY: the firmware's image handle, as the caller guarantees
    let Some(handle) = (unsafe { uefi::Handle::from_ptr(image_handle) }) else {
        return Status::INVALID_PARAMETER;
    };
    // SAFETY: the image's handle, set before any boot services call, as
    // uefi::boot::set_image_handle asks
    unsafe { uefi::boot::set_image_handle(handle) };
    // SAFETY: the firmware's arguments, passed on unchanged
    Status(efi_status(unsafe { efi_main(image_handle, system_table) }))
}
