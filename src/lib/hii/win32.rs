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

//! The Win32 conventions of the Windows backends, hiidb_driver.rs and firmware_environment.rs:
//! error codes, and the NUL-terminated UTF-16 strings that the calls take.

use thiserror::Error;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::Foundation::ERROR_ENVVAR_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Foundation::ERROR_INVALID_FUNCTION;
use windows_sys::Win32::Foundation::ERROR_NOT_ALL_ASSIGNED;
#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::ERROR_SUCCESS;

/// A Win32 error code, as GetLastError returns it. The codes form an open set: one without a
/// constant here keeps its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("Win32 error {0}")]
pub(crate) struct Win32Error(pub(crate) u32);

// SUCCESS builds for Windows alone: only the Win32 calls themselves, which build there alone,
// compare it.
impl Win32Error {
    #[cfg(target_os = "windows")]
    pub(crate) const SUCCESS: Self = Self(ERROR_SUCCESS);
    pub(crate) const INVALID_FUNCTION: Self = Self(ERROR_INVALID_FUNCTION);
    pub(crate) const FILE_NOT_FOUND: Self = Self(ERROR_FILE_NOT_FOUND);
    pub(crate) const ACCESS_DENIED: Self = Self(ERROR_ACCESS_DENIED);
    pub(crate) const INSUFFICIENT_BUFFER: Self = Self(ERROR_INSUFFICIENT_BUFFER);
    pub(crate) const ENVVAR_NOT_FOUND: Self = Self(ERROR_ENVVAR_NOT_FOUND);
    pub(crate) const NOT_ALL_ASSIGNED: Self = Self(ERROR_NOT_ALL_ASSIGNED);

    /// The calling thread's last Win32 error.
    #[cfg(target_os = "windows")]
    pub(crate) fn last() -> Self {
        // SAFETY: GetLastError takes no arguments and only reads the calling thread's
        // last-error value.
        Self(unsafe { GetLastError() })
    }
}

/// `text` as the NUL-terminated UTF-16 string that the Win32 calls take, or None if it holds a
/// NUL, at which they would end it.
pub(crate) fn nul_terminated_utf16(text: &str) -> Option<Vec<u16>> {
    if text.contains('\0') {
        return None;
    }
    Some(text.encode_utf16().chain([0]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A string without a NUL ends with one; one with a NUL is None.
    #[test]
    fn nul_terminated_utf16_refuses_an_interior_nul() {
        assert_eq!(
            nul_terminated_utf16("Aé"),
            Some(vec![0x41, 0xE9, 0]),
            "no NUL"
        );
        assert_eq!(nul_terminated_utf16(""), Some(vec![0]), "empty");
        assert_eq!(nul_terminated_utf16("A\0B"), None, "interior NUL");
    }

    /// A Win32Error displays its code.
    #[test]
    fn win32_error_displays_its_code() {
        assert_eq!(Win32Error(5).to_string(), "Win32 error 5", "code 5");
    }
}
