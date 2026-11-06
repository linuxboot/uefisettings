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

//! The EFI_HII_CONFIG_ACCESS_PROTOCOL of the driver that registered a package list (UEFI 2.11
//! §35.5): its Callback(), called as the protocol defines it, through the uefi crate, which the
//! image's entry point initializes. Nothing here replaces or hooks a protocol: a Callback() that
//! needs a forms browser's session finds none.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::boot::ScopedProtocol;
use uefi::proto::unsafe_protocol;
use uefi_raw::protocol::hii::config::BrowserAction as RawBrowserAction;
use uefi_raw::protocol::hii::config::HiiConfigAccessProtocol;
use uefi_raw::protocol::hii::form_browser::BrowserActionRequest;
use uefi_raw::protocol::hii::HiiHandle;

use crate::efi_status::EfiStatus;
use crate::hii::database_protocol::driver_handle;
use crate::hii::forms::StoragelessRefusal;
use crate::hii::question_callbacks::ActionRequest;
use crate::hii::question_callbacks::BrowserAction;
use crate::hii::question_callbacks::CallbackReturn;
use crate::hii::question_callbacks::DriverCallback;
use crate::hii::question_callbacks::IfrValue;

/// EFI_HII_CONFIG_ACCESS_PROTOCOL, whose functions uefi's HiiConfigAccess keeps private.
#[repr(transparent)]
// SAFETY: uefi-raw's GUID of the struct this wraps with repr(transparent)
#[unsafe_protocol(HiiConfigAccessProtocol::GUID)]
struct ConfigAccessFunctions(HiiConfigAccessProtocol);

/// The driver of a package list: the EFI_HII_CONFIG_ACCESS_PROTOCOL on its handle, opened
/// GetProtocol for as long as this lives.
pub(crate) struct ConfigAccessDriver {
    protocol: ScopedProtocol<ConfigAccessFunctions>,
}

impl ConfigAccessDriver {
    /// The driver that registered the package list of `hii_handle`, as GetPackageListHandle()
    /// names it (UEFI 2.11 §34.8.12), as a forms browser finds it (edk2-stable202608
    /// SetupBrowserDxe Setup.c:6187-6204).
    pub(crate) fn of_package_list(hii_handle: HiiHandle) -> Result<Self> {
        let handle = driver_handle(hii_handle)?
            .ok_or_else(|| anyhow!("GetPackageListHandle() names no driver handle"))
            .context(StoragelessRefusal::NoConfigAccess)?;
        let params = OpenProtocolParams {
            handle,
            agent: boot::image_handle(),
            controller: None,
        };
        // GetProtocol, as a forms browser takes it (HandleProtocol), and as Exclusive would stop
        // the driver
        // SAFETY: the protocol stays installed while the ScopedProtocol lives: only Callback()s of
        // the one question run meanwhile, and a driver installs its EFI_HII_CONFIG_ACCESS_PROTOCOL
        // with its package list
        let protocol = unsafe {
            boot::open_protocol::<ConfigAccessFunctions>(
                params,
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map_err(|error| anyhow!("OpenProtocol() returned {:?}", error.status()))
        .context(StoragelessRefusal::NoConfigAccess)?;
        Ok(Self { protocol })
    }
}

impl DriverCallback for ConfigAccessDriver {
    fn callback(
        &self,
        action: BrowserAction,
        question_id: u16,
        value: &mut IfrValue,
    ) -> CallbackReturn {
        let Some(functions) = self.protocol.get().map(|protocol| &protocol.0) else {
            return CallbackReturn {
                status: EfiStatus::NOT_FOUND,
                request: ActionRequest::NONE,
            };
        };
        let mut union = value.to_union();
        let mut request = BrowserActionRequest::NONE;
        // SAFETY: Callback() of the protocol's own instance with a Value of the union's size and
        // alignment, which it may change, and an ActionRequest that it may set
        let status = unsafe {
            (functions.callback)(
                functions,
                RawBrowserAction(action as usize),
                question_id,
                value.value_type as u8,
                union.as_mut_ptr().cast(),
                &mut request,
            )
        };
        *value = IfrValue::from_union(value.value_type, &union);
        CallbackReturn {
            status: EfiStatus(status.0),
            request: ActionRequest(request.0),
        }
    }
}
