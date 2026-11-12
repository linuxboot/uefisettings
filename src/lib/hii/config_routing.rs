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

//! The settings of Buffer and Name/Value storage, which only their driver holds: read by
//! EFI_HII_CONFIG_ROUTING_PROTOCOL.ExtractConfig() of a `<ConfigRequest>` and written by its
//! RouteConfig() of a `<ConfigResp>` (UEFI 2.11 §35.4.2, §35.4.4), which route each string to
//! the driver whose device path its `<ConfigHdr>` names. The strings are those of
//! config_string.rs.

use thiserror::Error;

use crate::efi_status::EfiStatus;
use crate::hii::config_string::ConfigRequest;
use crate::hii::config_string::ConfigResp;
use crate::hii::config_string::ConfigStringError;
use crate::hii::config_string::MultiConfigAltResp;

/// ExtractConfig() and RouteConfig() of EFI_HII_CONFIG_ROUTING_PROTOCOL.
pub(crate) trait ConfigRouting {
    /// The `<MultiConfigAltResp>` that ExtractConfig() returns for `request`.
    fn extract_config(
        &self,
        request: &ConfigRequest,
    ) -> Result<MultiConfigAltResp, ConfigRoutingError>;

    /// Has RouteConfig() write the settings of `resp`.
    fn route_config(&self, resp: &ConfigResp) -> Result<(), ConfigRoutingError>;
}

/// Why ExtractConfig() or RouteConfig() gave no settings or wrote none.
#[derive(Debug, Error)]
#[cfg_attr(
    not(target_os = "uefi"),
    allow(dead_code, reason = "only the UEFI Shell build's protocol makes some")
)]
pub(crate) enum ConfigRoutingError {
    /// The firmware has no EFI_HII_CONFIG_ROUTING_PROTOCOL, or OpenProtocol() of it failed
    #[error("EFI_HII_CONFIG_ROUTING_PROTOCOL: {0}")]
    Protocol(EfiStatus),
    /// The call returned an error; Progress pointed `progress` CHAR16 into its string
    #[error("{function}() returned {status} at CHAR16 {progress} of its string")]
    Status {
        function: &'static str,
        status: EfiStatus,
        progress: usize,
    },
    /// ExtractConfig() succeeded without a Results string
    #[error("ExtractConfig() returned {0} without Results")]
    NoResults(EfiStatus),
    /// ExtractConfig()'s Results are no UTF-16
    #[error("ExtractConfig() returned Results that are not UTF-16: {0}")]
    NotUtf16(std::string::FromUtf16Error),
    /// ExtractConfig()'s Results are no `<MultiConfigAltResp>`
    #[error("ExtractConfig() returned Results that are not a <MultiConfigAltResp>: {0}")]
    Results(ConfigStringError),
}

#[cfg(target_os = "uefi")]
pub(crate) use uefi_protocol::RoutingProtocol;

/// The firmware's EFI_HII_CONFIG_ROUTING_PROTOCOL, through the uefi crate.
#[cfg(target_os = "uefi")]
mod uefi_protocol {
    use std::ptr;
    use std::ptr::NonNull;

    use uefi::boot;
    use uefi::boot::OpenProtocolAttributes;
    use uefi::boot::OpenProtocolParams;
    use uefi::boot::ScopedProtocol;
    use uefi::proto::unsafe_protocol;
    use uefi_raw::protocol::hii::config::HiiConfigRoutingProtocol;
    use uefi_raw::Char16;
    use uefi_raw::Status;
    use zeroize::Zeroize;
    use zeroize::Zeroizing;

    use super::ConfigRouting;
    use super::ConfigRoutingError;
    use crate::efi_status::EfiStatus;
    use crate::hii::config_string::ConfigRequest;
    use crate::hii::config_string::ConfigResp;
    use crate::hii::config_string::MultiConfigAltResp;

    /// EFI_HII_CONFIG_ROUTING_PROTOCOL, whose functions uefi's HiiConfigRouting keeps private.
    #[repr(transparent)]
    // SAFETY: uefi-raw's GUID of the struct this wraps with repr(transparent)
    #[unsafe_protocol(HiiConfigRoutingProtocol::GUID)]
    struct ConfigRoutingFunctions(HiiConfigRoutingProtocol);

    /// The protocol, opened GetProtocol for as long as this lives, or why it could not be: each
    /// call fails with that status then.
    pub(crate) struct RoutingProtocol(Result<ScopedProtocol<ConfigRoutingFunctions>, EfiStatus>);

    impl RoutingProtocol {
        pub(crate) fn open() -> Self {
            Self(open_protocol())
        }

        fn functions(&self) -> Result<&HiiConfigRoutingProtocol, ConfigRoutingError> {
            let protocol = self
                .0
                .as_ref()
                .map_err(|&status| ConfigRoutingError::Protocol(status))?;
            protocol
                .get()
                .map(|functions| &functions.0)
                .ok_or(ConfigRoutingError::Protocol(EfiStatus::NOT_FOUND))
        }
    }

    /// OpenProtocol() of the firmware's EFI_HII_CONFIG_ROUTING_PROTOCOL.
    fn open_protocol() -> Result<ScopedProtocol<ConfigRoutingFunctions>, EfiStatus> {
        let handle = boot::get_handle_for_protocol::<ConfigRoutingFunctions>()
            .map_err(|error| EfiStatus(error.status().0))?;
        let params = OpenProtocolParams {
            handle,
            agent: boot::image_handle(),
            controller: None,
        };
        // GetProtocol, as Exclusive would disconnect the drivers that opened it BY_DRIVER.
        // SAFETY: the protocol stays installed while the ScopedProtocol lives: edk2's
        // HiiDatabaseDxe (edk2-stable202608 HiiDatabaseEntry.c) installs it and uninstalls it
        // nowhere
        unsafe {
            boot::open_protocol::<ConfigRoutingFunctions>(
                params,
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map_err(|error| EfiStatus(error.status().0))
    }

    impl ConfigRouting for RoutingProtocol {
        fn extract_config(
            &self,
            request: &ConfigRequest,
        ) -> Result<MultiConfigAltResp, ConfigRoutingError> {
            let functions = self.functions()?;
            let text = ucs2(&request.to_string());
            let mut progress: *const Char16 = ptr::null();
            let mut results: *mut Char16 = ptr::null_mut();
            // SAFETY: ExtractConfig() of a NUL-terminated request, which stores a pointer into
            // it in Progress and a pool allocation, or NULL, in Results
            let status = unsafe {
                (functions.extract_config)(
                    functions,
                    text.as_ptr().cast(),
                    &mut progress,
                    &mut results,
                )
            };
            // Results is the caller's to free, also with an error
            let results = PoolString::new(results);
            if status.is_error() {
                return Err(ConfigRoutingError::Status {
                    function: "ExtractConfig",
                    status: EfiStatus(status.0),
                    progress: offset_in(&text, progress),
                });
            }
            let results = results
                .ok_or(ConfigRoutingError::NoResults(EfiStatus(status.0)))?
                .read()?;
            results
                .parse::<MultiConfigAltResp>()
                .map_err(ConfigRoutingError::Results)
        }

        fn route_config(&self, resp: &ConfigResp) -> Result<(), ConfigRoutingError> {
            let functions = self.functions()?;
            let text = ucs2(&resp.to_string());
            let mut progress: *const Char16 = ptr::null();
            // SAFETY: RouteConfig() of a NUL-terminated configuration, which stores a pointer
            // into it in Progress
            let status =
                unsafe { (functions.route_config)(functions, text.as_ptr().cast(), &mut progress) };
            match status {
                Status::SUCCESS => Ok(()),
                status => Err(ConfigRoutingError::Status {
                    function: "RouteConfig",
                    status: EfiStatus(status.0),
                    progress: offset_in(&text, progress),
                }),
            }
        }
    }

    /// `text` as a NUL-terminated UCS-2 string; config strings are ASCII (UEFI 2.11 §35.2.1).
    fn ucs2(text: &str) -> Vec<u16> {
        text.encode_utf16().chain([0]).collect()
    }

    /// How many CHAR16 of `text` lie before `progress`, or its length if `progress` points
    /// elsewhere.
    fn offset_in(text: &[u16], progress: *const Char16) -> usize {
        let start = text.as_ptr().addr();
        let unit = size_of::<u16>();
        progress
            .addr()
            .checked_sub(start)
            .map(|bytes| bytes / unit)
            .filter(|&units| units < text.len())
            .unwrap_or(text.len())
    }

    /// A NUL-terminated string in pool memory that the firmware allocated for the caller, which
    /// drop zeroes and frees.
    struct PoolString(NonNull<u16>);

    impl PoolString {
        fn new(pointer: *mut Char16) -> Option<Self> {
            NonNull::new(pointer.cast()).map(Self)
        }

        /// The string, as many CHAR16 as precede its NUL.
        fn units(&self) -> &[u16] {
            let mut len = 0;
            // SAFETY: the firmware's NUL-terminated string, read up to its NUL
            while unsafe { self.0.add(len).read() } != 0 {
                len += 1;
            }
            // SAFETY: the `len` CHAR16 before the NUL, which live as long as `self`
            unsafe { std::slice::from_raw_parts(self.0.as_ptr(), len) }
        }

        /// The string up to its NUL.
        fn read(&self) -> Result<Zeroizing<String>, ConfigRoutingError> {
            String::from_utf16(self.units())
                .map(Zeroizing::new)
                .map_err(ConfigRoutingError::NotUtf16)
        }
    }

    impl Drop for PoolString {
        fn drop(&mut self) {
            let len = self.units().len();
            // SAFETY: the string's CHAR16 before its NUL, which nothing else references now
            unsafe { std::slice::from_raw_parts_mut(self.0.as_ptr(), len) }.zeroize();
            // SAFETY: a pool allocation of the firmware that nothing else frees
            if let Err(error) = unsafe { boot::free_pool(self.0.cast()) } {
                log::warn!(
                    "FreePool() of ExtractConfig()'s Results: {:?}",
                    error.status()
                );
            }
        }
    }
}
