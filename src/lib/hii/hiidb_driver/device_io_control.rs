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

//! The HiiDB driver's device, through CreateFileW and DeviceIoControl.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::HandleOrInvalid;
use std::os::windows::io::OwnedHandle;
use std::ptr;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::System::IO::DeviceIoControl;

use super::open_error;
use super::DriverTransport;
use super::DEVICE_PATH;
use crate::hii::win32::nul_terminated_utf16;
use crate::hii::win32::Win32Error;

/// The HiiDB driver, opened once, through CreateFileW and DeviceIoControl.
pub(super) struct DeviceIoControlTransport {
    device: OwnedHandle,
}

impl DeviceIoControlTransport {
    /// Opens the HiiDB driver device.
    pub(super) fn open() -> Result<Self> {
        let path = nul_terminated_utf16(DEVICE_PATH)
            .context("the HiiDB driver device path holds a NUL")?;
        // SAFETY: CreateFileW with a NUL-terminated device path, read-only access, as
        // this consumer only reads the HiiDB, shared reads and writes, no security
        // attributes, OPEN_EXISTING, no flags, and no template file.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        // SAFETY: CreateFileW returns INVALID_HANDLE_VALUE or a handle that it opened for
        // this call, which nothing else owns or closes.
        let handle = unsafe { HandleOrInvalid::from_raw_handle(handle) };
        // The conversion makes no Win32 call, so the last error is still CreateFileW's.
        let device = OwnedHandle::try_from(handle).map_err(|_| open_error(Win32Error::last()))?;
        Ok(Self { device })
    }
}

impl DriverTransport for DeviceIoControlTransport {
    fn control(&mut self, ioctl: u32, buffer: &mut [u8]) -> Result<u32> {
        let out_size = u32::try_from(buffer.len()).context("HiiDB buffer size fits in u32")?;
        // A null output pointer with an out size of 0 for an empty buffer: an empty
        // slice's pointer may dangle, so it must never be handed to the driver.
        let out_buffer = if buffer.is_empty() {
            ptr::null_mut()
        } else {
            buffer.as_mut_ptr().cast::<c_void>()
        };
        let mut bytes_returned = 0u32;
        // SAFETY: DeviceIoControl with a handle that CreateFileW returned for the HiiDB
        // device, `ioctl`, which read_hiidb_from passes as one of the contract's two
        // IOCTLs, no input buffer, an output buffer of `out_size` bytes that `buffer` owns
        // for the call, or a null output pointer when `out_size` is 0, a place for the bytes
        // returned, and no OVERLAPPED, so the call runs synchronously. Both IOCTLs are
        // METHOD_OUT_DIRECT, so the driver writes into `buffer` itself, through an MDL of its
        // `out_size` bytes, and the contract keeps those writes within it; that bound rests on
        // the driver. The I/O manager copies nothing back for direct I/O ("Using Direct I/O",
        // Microsoft Learn), so an IoStatus.Information over `out_size` reaches only
        // `bytes_returned`, which read_hiidb_from checks against the buffer.
        let succeeded = unsafe {
            DeviceIoControl(
                self.device.as_raw_handle(),
                ioctl,
                ptr::null(),
                0,
                out_buffer,
                out_size,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if succeeded == 0 {
            return Err(anyhow!(
                "DeviceIoControl of IOCTL {ioctl:#010x} on the HiiDB driver failed with {}",
                Win32Error::last()
            ));
        }
        Ok(bytes_returned)
    }
}
