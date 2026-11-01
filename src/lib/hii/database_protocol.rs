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

use anyhow::anyhow;
use anyhow::Result;
use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::proto::hii::database::HiiDatabase;

/// Every package list of the HII database, as ExportPackageLists() with a NULL Handle gives
/// them (UEFI 2.10 §34.8.6), in the HiiDB format of the Linux build.
pub(crate) fn export_package_lists() -> Result<Vec<u8>> {
    let handle = boot::get_handle_for_protocol::<HiiDatabase>()
        .map_err(|error| anyhow!("EFI_HII_DATABASE_PROTOCOL: {:?}", error.status()))?;
    let params = OpenProtocolParams {
        handle,
        agent: boot::image_handle(),
        controller: None,
    };
    // GetProtocol, as Exclusive would disconnect the drivers that opened the protocol BY_DRIVER.
    // SAFETY: the protocol stays installed while the ScopedProtocol, which ends in this
    // function, lives: only ExportPackageLists() runs meanwhile, and nothing here uninstalls
    // protocols. edk2's HiiDatabaseDxe (edk2-stable202508 HiiDatabaseEntry.c) also installs it and
    // uninstalls it nowhere.
    let database =
        unsafe { boot::open_protocol::<HiiDatabase>(params, OpenProtocolAttributes::GetProtocol) }
            .map_err(|error| {
                anyhow!(
                    "OpenProtocol() of EFI_HII_DATABASE_PROTOCOL: {:?}",
                    error.status()
                )
            })?;
    let lists = database
        .export_all_raw()
        .map_err(|error| anyhow!("ExportPackageLists(): {:?}", error.status()))?;
    Ok(lists.into_vec())
}
