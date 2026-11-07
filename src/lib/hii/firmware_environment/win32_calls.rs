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

//! The Win32 calls that FirmwareEnvironment makes on Windows, and the variables of each
//! EfivarSource there.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::os::windows::io::OwnedHandle;
use std::ptr;

use anyhow::Result;
use windows_sys::Win32::Foundation::SetLastError;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::LUID;
use windows_sys::Win32::Security::AdjustTokenPrivileges;
use windows_sys::Win32::Security::LookupPrivilegeValueW;
use windows_sys::Win32::Security::LUID_AND_ATTRIBUTES;
use windows_sys::Win32::Security::SE_PRIVILEGE_ENABLED;
use windows_sys::Win32::Security::SE_SYSTEM_ENVIRONMENT_NAME;
use windows_sys::Win32::Security::TOKEN_ADJUST_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_PRIVILEGES;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Threading::OpenProcessToken;
use windows_sys::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableExW;
use windows_sys::Win32::System::WindowsProgramming::SetFirmwareEnvironmentVariableExW;

use super::FirmwareEnvironment;
use super::FirmwareEnvironmentCalls;
use super::GotVariable;
use crate::efi_variables::globals::platform_lang;
use crate::hii::variables::EfivarSource;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::UnreadVariables;
use crate::hii::win32::Win32Error;

impl EfivarSource {
    /// The firmware variables that questions read from this source, which validate accepts.
    pub(crate) fn into_variables(self) -> Result<Box<dyn FirmwareVariables>> {
        self.validate()?;
        Ok(match self {
            Self::System => Box::new(FirmwareEnvironment::new()?),
            Self::Disabled => Box::new(UnreadVariables {
                reach: FirmwareEnvironment::<RealFirmwareEnvironmentCalls>::REACH,
                interface: FirmwareEnvironment::<RealFirmwareEnvironmentCalls>::INTERFACE,
            }),
        })
    }

    /// The platform language, PlatformLang, that this source holds (globals::platform_lang); none
    /// for Disabled.
    pub(crate) fn platform_lang(&self) -> Result<Option<String>> {
        match self {
            Self::System => platform_lang(&FirmwareEnvironment::new()?),
            Self::Disabled => Ok(None),
        }
    }
}

impl FirmwareEnvironment<RealFirmwareEnvironmentCalls> {
    /// This machine's firmware environment variables, through the Win32 calls.
    pub(crate) fn new() -> Result<Self> {
        Self::with_calls(RealFirmwareEnvironmentCalls)
    }
}

/// The Win32 calls themselves.
#[derive(Debug)]
pub(crate) struct RealFirmwareEnvironmentCalls;

impl FirmwareEnvironmentCalls for RealFirmwareEnvironmentCalls {
    fn enable_system_environment_privilege(&self) -> std::result::Result<(), Win32Error> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: GetCurrentProcess takes no arguments and returns the pseudo-handle of
        // this process, which OpenProcessToken accepts and which need not be closed:
        // CloseHandle on it has no effect.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: OpenProcessToken with the pseudo-handle of this process, the access to
        // adjust and query its token, and a place for the token handle, which it fills on
        // success.
        let opened =
            unsafe { OpenProcessToken(process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(Win32Error::last());
        }
        // SAFETY: OpenProcessToken succeeded, so `token` is a handle that it opened for this
        // call, which nothing else owns or closes.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut luid = LUID::default();
        // SAFETY: LookupPrivilegeValueW with a null system name, for the local machine,
        // the name of the system-environment privilege, and a place for its LUID.
        let found =
            unsafe { LookupPrivilegeValueW(ptr::null(), SE_SYSTEM_ENVIRONMENT_NAME, &mut luid) };
        if found == 0 {
            return Err(Win32Error::last());
        }
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        // SAFETY: AdjustTokenPrivileges with the token handle, FALSE so it adjusts only
        // the named privilege, a TOKEN_PRIVILEGES holding one enabled privilege, and no
        // previous state.
        let adjusted = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                FALSE,
                &privileges,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if adjusted == 0 {
            return Err(Win32Error::last());
        }
        // AdjustTokenPrivileges succeeds even when it assigned no privilege, reporting
        // that through the last error instead.
        let code = Win32Error::last();
        if code == Win32Error::NOT_ALL_ASSIGNED {
            return Err(code);
        }
        Ok(())
    }

    fn get_variable(
        &self,
        name: &[u16],
        guid: &[u16],
        buffer: &mut [u8],
    ) -> std::result::Result<GotVariable, Win32Error> {
        let mut attributes = 0u32;
        let size = u32::try_from(buffer.len()).map_err(|_| Win32Error::INSUFFICIENT_BUFFER)?;
        let data = buffer.as_mut_ptr().cast::<c_void>();
        // SetLastError(0) before the call, so that a return of 0 with no error left by
        // it means an empty variable, not a stale error from an earlier call.
        // SAFETY: SetLastError takes only the error value to store for this thread.
        unsafe { SetLastError(Win32Error::SUCCESS.0) };
        // SAFETY: GetFirmwareEnvironmentVariableExW with NUL-terminated UTF-16 name and
        // GUID strings, a buffer of `size` writable bytes, and a place for the variable's
        // attributes; it writes at most `size` bytes.
        let written = unsafe {
            GetFirmwareEnvironmentVariableExW(
                name.as_ptr(),
                guid.as_ptr(),
                data,
                size,
                &mut attributes,
            )
        };
        if written == 0 {
            match Win32Error::last() {
                Win32Error::SUCCESS => Ok(GotVariable {
                    attributes,
                    written,
                }),
                code => Err(code),
            }
        } else {
            Ok(GotVariable {
                attributes,
                written,
            })
        }
    }

    fn set_variable(
        &self,
        name: &[u16],
        guid: &[u16],
        data: &[u8],
        attributes: u32,
    ) -> std::result::Result<(), Win32Error> {
        let size = u32::try_from(data.len()).map_err(|_| Win32Error::INSUFFICIENT_BUFFER)?;
        let value: *const u8 = if data.is_empty() {
            ptr::null()
        } else {
            data.as_ptr()
        };
        // SAFETY: SetFirmwareEnvironmentVariableExW with NUL-terminated UTF-16 name and
        // GUID strings, `size` readable bytes at `value`, or a null value with a size of
        // 0, and the variable's attributes.
        let succeeded = unsafe {
            SetFirmwareEnvironmentVariableExW(
                name.as_ptr(),
                guid.as_ptr(),
                value.cast::<c_void>(),
                size,
                attributes,
            )
        };
        if succeeded == 0 {
            Err(Win32Error::last())
        } else {
            Ok(())
        }
    }
}
