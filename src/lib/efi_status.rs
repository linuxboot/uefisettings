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

//! EFI_STATUS (UEFI 2.11 Appendix D) as the code that drives protocol calls handles it on every
//! host: the firmware's calls run only in the UEFI Shell build, their logic everywhere.

use std::fmt;

/// An EFI_STATUS: a UINTN whose top bit marks an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct EfiStatus(pub(crate) usize);

impl EfiStatus {
    const ERROR_BIT: usize = 1 << (usize::BITS - 1);

    pub(crate) const SUCCESS: Self = Self(0);
    pub(crate) const INVALID_PARAMETER: Self = Self(Self::ERROR_BIT | 2);
    pub(crate) const UNSUPPORTED: Self = Self(Self::ERROR_BIT | 3);
    pub(crate) const BUFFER_TOO_SMALL: Self = Self(Self::ERROR_BIT | 5);
    pub(crate) const DEVICE_ERROR: Self = Self(Self::ERROR_BIT | 7);
    pub(crate) const WRITE_PROTECTED: Self = Self(Self::ERROR_BIT | 8);
    pub(crate) const OUT_OF_RESOURCES: Self = Self(Self::ERROR_BIT | 9);
    pub(crate) const NOT_FOUND: Self = Self(Self::ERROR_BIT | 14);
    pub(crate) const ACCESS_DENIED: Self = Self(Self::ERROR_BIT | 15);
    pub(crate) const ABORTED: Self = Self(Self::ERROR_BIT | 21);
    pub(crate) const SECURITY_VIOLATION: Self = Self(Self::ERROR_BIT | 26);

    /// The names of the statuses above, which Display writes.
    const NAMES: [(Self, &'static str); 11] = [
        (Self::SUCCESS, "EFI_SUCCESS"),
        (Self::INVALID_PARAMETER, "EFI_INVALID_PARAMETER"),
        (Self::UNSUPPORTED, "EFI_UNSUPPORTED"),
        (Self::BUFFER_TOO_SMALL, "EFI_BUFFER_TOO_SMALL"),
        (Self::DEVICE_ERROR, "EFI_DEVICE_ERROR"),
        (Self::WRITE_PROTECTED, "EFI_WRITE_PROTECTED"),
        (Self::OUT_OF_RESOURCES, "EFI_OUT_OF_RESOURCES"),
        (Self::NOT_FOUND, "EFI_NOT_FOUND"),
        (Self::ACCESS_DENIED, "EFI_ACCESS_DENIED"),
        (Self::ABORTED, "EFI_ABORTED"),
        (Self::SECURITY_VIOLATION, "EFI_SECURITY_VIOLATION"),
    ];
}

/// The status's name for those that NAMES lists, else its value in hex, as EFI_STATUS names a
/// status by its value.
impl fmt::Display for EfiStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Self::NAMES.iter().find(|(status, _)| status == self) {
            Some((_, name)) => f.write_str(name),
            None => write!(f, "EFI_STATUS {:#x}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_known_statuses_and_shows_others_in_hex() {
        let error_bit = 1usize << (usize::BITS - 1);
        let cases = [
            (EfiStatus(0), "EFI_SUCCESS".to_string()),
            (EfiStatus(error_bit | 3), "EFI_UNSUPPORTED".to_string()),
            (EfiStatus(error_bit | 14), "EFI_NOT_FOUND".to_string()),
            (EfiStatus(error_bit | 21), "EFI_ABORTED".to_string()),
            (
                EfiStatus(error_bit | 30),
                format!("EFI_STATUS {:#x}", error_bit | 30),
            ),
            (EfiStatus(7), "EFI_STATUS 0x7".to_string()),
        ];
        for (status, want) in cases {
            assert_eq!(status.to_string(), want, "status {:#x}", status.0);
        }
    }
}
