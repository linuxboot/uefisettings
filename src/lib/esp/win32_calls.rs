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

//! The Win32 calls that find the EFI system partition. A volume or disk opens as Microsoft Learn's
//! CreateFileW page, "Physical Disks and Volumes", tells: OPEN_EXISTING, FILE_SHARE_WRITE, by
//! Administrators.

use std::mem::offset_of;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::ptr;

use log::warn;
use windows_sys::Win32::Foundation::ERROR_INVALID_NAME;
use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
use windows_sys::Win32::Foundation::MAX_PATH;
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::Storage::FileSystem::FindFirstVolumeW;
use windows_sys::Win32::Storage::FileSystem::FindNextVolumeW;
use windows_sys::Win32::Storage::FileSystem::FindVolumeClose;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_WRITE;
use windows_sys::Win32::Storage::FileSystem::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS;
use windows_sys::Win32::Storage::FileSystem::OPEN_EXISTING;
use windows_sys::Win32::System::Ioctl::DISK_EXTENT;
use windows_sys::Win32::System::Ioctl::DISK_GEOMETRY;
use windows_sys::Win32::System::Ioctl::IOCTL_DISK_GET_DRIVE_GEOMETRY;
use windows_sys::Win32::System::Ioctl::VOLUME_DISK_EXTENTS;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::IO::OVERLAPPED;

use super::windows::CallFailed;
use super::windows::DiskExtent;
use super::windows::EspCalls;
use crate::hii::win32::nul_terminated_utf16;
use crate::hii::win32::Win32Error;

/// The calls that name failures
const EXTENTS_CALL: &str = "DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS)";
const GEOMETRY_CALL: &str = "DeviceIoControl(IOCTL_DISK_GET_DRIVE_GEOMETRY)";
/// The failure of the extents' call whose count no buffer that it takes can hold
const EXTENTS_UNHELD: CallFailed = CallFailed {
    call: EXTENTS_CALL,
    code: Win32Error::INSUFFICIENT_BUFFER,
};
/// The CHAR16s of a buffer for a volume GUID path, \\?\Volume{GUID}\ and a NUL, with room
const VOLUME_NAME_CAPACITY: u32 = MAX_PATH;

/// The Win32 calls themselves.
#[derive(Debug)]
pub(crate) struct RealEspCalls;

/// A volume search of FindFirstVolumeW, which FindVolumeClose ends when it drops.
pub(crate) struct VolumeSearch(HANDLE);

impl Drop for VolumeSearch {
    fn drop(&mut self) {
        // SAFETY: FindFirstVolumeW opened the search handle, which only this value holds and
        // nothing closed yet.
        if unsafe { FindVolumeClose(self.0) } == 0 {
            warn!("FindVolumeClose failed: {}", Win32Error::last());
        }
    }
}

impl EspCalls for RealEspCalls {
    type Search = VolumeSearch;
    type Disk = OwnedHandle;

    fn find_first_volume(&self) -> Result<(VolumeSearch, String), CallFailed> {
        let mut name = [0u16; VOLUME_NAME_CAPACITY as usize];
        // SAFETY: FindFirstVolumeW with a buffer of VOLUME_NAME_CAPACITY CHAR16s and that count,
        // which it writes at most.
        let search = unsafe { FindFirstVolumeW(name.as_mut_ptr(), VOLUME_NAME_CAPACITY) };
        if search == INVALID_HANDLE_VALUE {
            return Err(failed("FindFirstVolumeW"));
        }
        Ok((VolumeSearch(search), up_to_nul(&name)))
    }

    fn find_next_volume(&self, search: &mut VolumeSearch) -> Result<String, CallFailed> {
        let mut name = [0u16; VOLUME_NAME_CAPACITY as usize];
        // SAFETY: FindNextVolumeW with the open search handle and a buffer of
        // VOLUME_NAME_CAPACITY CHAR16s and that count, which it writes at most.
        let found = unsafe { FindNextVolumeW(search.0, name.as_mut_ptr(), VOLUME_NAME_CAPACITY) };
        if found == 0 {
            return Err(failed("FindNextVolumeW"));
        }
        Ok(up_to_nul(&name))
    }

    fn volume_disk_extents(&self, device: &str) -> Result<Vec<DiskExtent>, CallFailed> {
        let volume = open(device, 0)?;
        let mut capacity = 1;
        loop {
            let mut buffer = vec![0u8; extents_size(capacity).ok_or(EXTENTS_UNHELD)?];
            let size = u32::try_from(buffer.len()).map_err(|_| EXTENTS_UNHELD)?;
            let mut returned = 0u32;
            // SAFETY: DeviceIoControl on the open volume handle with no input, an output buffer
            // of `size` writable bytes, a place for the bytes returned, and no OVERLAPPED, as
            // the handle is synchronous.
            let done = unsafe {
                DeviceIoControl(
                    volume.as_raw_handle(),
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    ptr::null(),
                    0,
                    buffer.as_mut_ptr().cast(),
                    size,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            let code = match done {
                0 => Win32Error::last(),
                _ => Win32Error::SUCCESS,
            };
            let count = field::<4>(
                &buffer,
                offset_of!(VOLUME_DISK_EXTENTS, NumberOfDiskExtents),
            )
            .map(u32::from_ne_bytes)
            .and_then(|count| usize::try_from(count).ok())
            .ok_or(EXTENTS_UNHELD)?;
            if code == Win32Error::SUCCESS {
                let extents = buffer
                    .get(offset_of!(VOLUME_DISK_EXTENTS, Extents)..)
                    .unwrap_or_default()
                    .chunks_exact(size_of::<DISK_EXTENT>())
                    .take(count)
                    .map(disk_extent)
                    .collect::<Option<Vec<_>>>()
                    .ok_or(EXTENTS_UNHELD)?;
                return match extents.len() == count {
                    true => Ok(extents),
                    false => Err(EXTENTS_UNHELD),
                };
            }
            // NumberOfDiskExtents tells the room that a volume of more extents needs (Microsoft
            // Learn, VOLUME_DISK_EXTENTS)
            if code.0 != ERROR_MORE_DATA || count <= capacity {
                return Err(CallFailed {
                    call: EXTENTS_CALL,
                    code,
                });
            }
            capacity = count;
        }
    }

    fn open_disk(&self, number: u32) -> Result<OwnedHandle, CallFailed> {
        open(&format!(r"\\.\PhysicalDrive{number}"), GENERIC_READ)
    }

    fn disk_block_size(&self, disk: &OwnedHandle) -> Result<u32, CallFailed> {
        let mut geometry = DISK_GEOMETRY::default();
        let mut returned = 0u32;
        let size = u32::try_from(size_of::<DISK_GEOMETRY>()).map_err(|_| CallFailed {
            call: GEOMETRY_CALL,
            code: Win32Error::INSUFFICIENT_BUFFER,
        })?;
        // SAFETY: DeviceIoControl on the open disk handle with no input, a DISK_GEOMETRY of
        // `size` bytes as its output, a place for the bytes returned, and no OVERLAPPED, as the
        // handle is synchronous.
        let done = unsafe {
            DeviceIoControl(
                disk.as_raw_handle(),
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                ptr::null(),
                0,
                ptr::from_mut(&mut geometry).cast(),
                size,
                &mut returned,
                ptr::null_mut(),
            )
        };
        match done {
            0 => Err(failed(GEOMETRY_CALL)),
            _ => Ok(geometry.BytesPerSector),
        }
    }

    fn read_disk(
        &self,
        disk: &OwnedHandle,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, CallFailed> {
        let size = u32::try_from(buffer.len()).map_err(|_| CallFailed {
            call: "ReadFile",
            code: Win32Error::INSUFFICIENT_BUFFER,
        })?;
        // On a synchronous handle, ReadFile reads at the offset of the OVERLAPPED (Microsoft
        // Learn, ReadFile, "Synchronization and File Position").
        let mut at = OVERLAPPED::default();
        let [b0, b1, b2, b3, b4, b5, b6, b7] = offset.to_le_bytes();
        at.Anonymous.Anonymous.Offset = u32::from_le_bytes([b0, b1, b2, b3]);
        at.Anonymous.Anonymous.OffsetHigh = u32::from_le_bytes([b4, b5, b6, b7]);
        let mut read = 0u32;
        // SAFETY: ReadFile on the open disk handle into `size` writable bytes of `buffer`, with
        // a place for the bytes read and an OVERLAPPED that holds the offset and lives through
        // the call, which returns when the read is done.
        let done = unsafe {
            ReadFile(
                disk.as_raw_handle(),
                buffer.as_mut_ptr(),
                size,
                &mut read,
                &mut at,
            )
        };
        match done {
            0 => Err(failed("ReadFile")),
            _ => usize::try_from(read).map_err(|_| CallFailed {
                call: "ReadFile",
                code: Win32Error::INSUFFICIENT_BUFFER,
            }),
        }
    }
}

/// Opens the volume or disk `device` with `access`: CreateFileW.
fn open(device: &str, access: u32) -> Result<OwnedHandle, CallFailed> {
    // what CreateFileW gives for a name that it cannot take
    let name = nul_terminated_utf16(device).ok_or(CallFailed {
        call: "CreateFileW",
        code: Win32Error(ERROR_INVALID_NAME),
    })?;
    // SAFETY: CreateFileW with a NUL-terminated name, the access, both shares that a volume or
    // disk needs, no security attributes, OPEN_EXISTING, no flags and no template.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(failed("CreateFileW"));
    }
    // SAFETY: CreateFileW succeeded, so `handle` is a handle that it opened for this call, which
    // nothing else owns or closes.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// The failure of `call`, with the calling thread's last error.
fn failed(call: &'static str) -> CallFailed {
    CallFailed {
        call,
        code: Win32Error::last(),
    }
}

/// The CHAR16s of `buffer` before the first NUL, as text. Volume GUID paths hold ASCII alone
/// (Microsoft Learn, Naming a Volume); any other CHAR16 shows as U+FFFD, and the call that takes
/// that text fails on it.
fn up_to_nul(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(buffer.get(..end).unwrap_or_default())
}

/// The bytes of a VOLUME_DISK_EXTENTS of `count` extents, None past usize.
fn extents_size(count: usize) -> Option<usize> {
    size_of::<DISK_EXTENT>()
        .checked_mul(count)?
        .checked_add(offset_of!(VOLUME_DISK_EXTENTS, Extents))
}

/// The DISK_EXTENT that `bytes` hold, None if they end before it.
fn disk_extent(bytes: &[u8]) -> Option<DiskExtent> {
    Some(DiskExtent {
        disk_number: u32::from_ne_bytes(field(bytes, offset_of!(DISK_EXTENT, DiskNumber))?),
        starting_offset: i64::from_ne_bytes(field(bytes, offset_of!(DISK_EXTENT, StartingOffset))?),
        extent_length: i64::from_ne_bytes(field(bytes, offset_of!(DISK_EXTENT, ExtentLength))?),
    })
}

/// The `N` bytes at byte `at` of `buffer`, None if `buffer` ends before them.
fn field<const N: usize>(buffer: &[u8], at: usize) -> Option<[u8; N]> {
    buffer.get(at..at.checked_add(N)?)?.try_into().ok()
}
