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

//! EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL (UEFI 2.11 §35.3.1) of the firmware that the UEFI Shell
//! build runs on, through the uefi crate, which the image's entry point initializes.

use std::ptr;
use std::ptr::NonNull;

use anyhow::anyhow;
use anyhow::Result;
use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::boot::ScopedProtocol;
use uefi::proto::unsafe_protocol;
use uefi::CStr16;
use uefi::CString16;
use uefi::Status;
use uefi_raw::protocol::hii::config::ConfigKeywordHandlerProtocol;

use super::keyword_access::call_error;
use super::keyword_access::progress_char;
use super::keyword_access::GetDataError;
use super::keyword_access::KeywordData;

/// EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL, whose functions uefi's ConfigKeywordHandler keeps private.
#[repr(transparent)]
// SAFETY: uefi-raw's GUID of the struct this wraps with repr(transparent)
#[unsafe_protocol(ConfigKeywordHandlerProtocol::GUID)]
struct KeywordHandler(ConfigKeywordHandlerProtocol);

/// This firmware's EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL, opened for each call.
pub(crate) struct FirmwareKeywordHandler;

impl KeywordData for FirmwareKeywordHandler {
    fn get_data(&self, namespace_id: &str, keyword_string: &str) -> Result<String, GetDataError> {
        let namespace_id = CString16::try_from(namespace_id).map_err(anyhow::Error::from)?;
        let keyword_string = CString16::try_from(keyword_string).map_err(anyhow::Error::from)?;
        let protocol = open()?;
        let handler = protocol
            .get()
            .ok_or_else(|| anyhow!("EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL has no interface"))?;
        let mut progress = ptr::null();
        let mut progress_err = 0;
        let mut results = ptr::null_mut();
        // SAFETY: GetData() of NUL-terminated UCS-2 strings that outlive the call; it stores a
        // pointer into `keyword_string` in `progress` and a pool string or nothing in `results`
        let status = unsafe {
            (handler.0.get_data)(
                &handler.0,
                namespace_id.as_ptr().cast(),
                keyword_string.as_ptr().cast(),
                &mut progress,
                &mut progress_err,
                &mut results,
            )
        };
        let results = NonNull::new(results).map(|results| {
            // SAFETY: GetData() returned a NUL-terminated UCS-2 string in pool memory
            let text = unsafe { CStr16::from_ptr(results.as_ptr().cast()) }.to_string();
            // SAFETY: that pool memory, which the caller frees (UEFI 2.11 §35.3.3), freed once,
            // after its last use
            let freed = unsafe { boot::free_pool(results.cast()) }.map_err(|error| {
                anyhow!("FreePool() of GetData()'s Results: {:?}", error.status())
            });
            (text, freed)
        });
        // on a failure, Results holds the values of the keywords before the failing one
        // (UEFI 2.11 §35.3.3)
        match (
            check_status("GetData()", status, progress, &keyword_string, progress_err),
            results,
        ) {
            (Ok(()), Some((text, freed))) => freed.map(|()| text).map_err(GetDataError::from),
            (Ok(()), None) => Err(anyhow!("GetData() succeeded without Results").into()),
            (Err(error), None) => Err(error.into()),
            (Err(error), Some((text, Ok(())))) => Err(GetDataError {
                results: Some(text),
                error,
            }),
            (Err(error), Some((text, Err(freed)))) => Err(GetDataError {
                results: Some(text),
                error: error.context(freed),
            }),
        }
    }

    fn set_data(&self, keyword_string: &str) -> Result<()> {
        let keyword_string = CString16::try_from(keyword_string)?;
        let mut protocol = open()?;
        let handler = protocol
            .get_mut()
            .ok_or_else(|| anyhow!("EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL has no interface"))?;
        let mut progress = ptr::null();
        let mut progress_err = 0;
        // SAFETY: SetData() of a NUL-terminated UCS-2 string that outlives the call; it stores a
        // pointer into it in `progress`
        let status = unsafe {
            (handler.0.set_data)(
                &mut handler.0,
                keyword_string.as_ptr().cast(),
                &mut progress,
                &mut progress_err,
            )
        };
        check_status("SetData()", status, progress, &keyword_string, progress_err)
    }
}

/// EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL, for this image.
fn open() -> Result<ScopedProtocol<KeywordHandler>> {
    let handle = boot::get_handle_for_protocol::<KeywordHandler>()
        .map_err(|error| anyhow!("EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL: {:?}", error.status()))?;
    // GetProtocol, as Exclusive would disconnect the drivers that opened the protocol BY_DRIVER.
    // SAFETY: the protocol stays installed while the ScopedProtocol lives: it lives through one
    // GetData() or SetData() of this image, which runs alone and uninstalls no protocol.
    // edk2-stable202608 HiiDatabaseDxe also installs it in its entry point
    // (HiiDatabaseEntry.c:217) and uninstalls it nowhere.
    unsafe {
        boot::open_protocol::<KeywordHandler>(
            OpenProtocolParams {
                handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|error| {
        anyhow!(
            "OpenProtocol() of EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL: {:?}",
            error.status()
        )
    })
}

/// Fails unless `status` of `function` is a success, naming where Progress points in
/// `keyword_string` and the bits of ProgressErr.
fn check_status(
    function: &str,
    status: Status,
    progress: *const u16,
    keyword_string: &CStr16,
    progress_err: u32,
) -> Result<()> {
    if !status.is_error() {
        return Ok(());
    }
    let at = progress_char(
        progress.addr(),
        keyword_string.as_ptr().addr(),
        keyword_string.num_chars(),
    );
    Err(call_error(
        function,
        &format!("{status:?}"),
        at,
        progress_err,
    ))
}
