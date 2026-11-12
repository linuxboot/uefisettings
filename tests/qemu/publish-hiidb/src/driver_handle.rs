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

//! The handles that register the package lists of publish-hiidb's forms with a driver: each has
//! a vendor device path, which the HII database keeps as the list's device path package and
//! EFI_HII_CONFIG_ROUTING_PROTOCOL routes a `<ConfigHdr>` by (edk2-stable202608 HiiDatabaseDxe
//! Database.c HiiNewPackageList, ConfigRouting.c HiiConfigRoutingExtractConfig), and an
//! EFI_HII_CONFIG_ACCESS_PROTOCOL.

use core::ptr;

use uefi::boot;
use uefi::Guid;
use uefi::Handle;
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::protocol::hii::config::HiiConfigAccessProtocol;

use crate::Failure;

/// A device path of one vendor-defined hardware node of `guid` (UEFI 2.11 §10.3.2.4), then the
/// End node.
pub(crate) const fn vendor_device_path(guid: Guid) -> [u8; 24] {
    let mut path = [0; 24];
    // Type, SubType and Length of the vendor node
    path[0] = 0x01;
    path[1] = 0x04;
    path[2] = 20;
    let bytes = guid.to_bytes();
    let mut i = 0;
    while i < 16 {
        path[4 + i] = bytes[i];
        i += 1;
    }
    // End of Hardware Device Path, End Entire Device Path
    path[20] = 0x7F;
    path[21] = 0xFF;
    path[22] = 4;
    path
}

/// A new handle with the device path `path` and the EFI_HII_CONFIG_ACCESS_PROTOCOL `access`,
/// both statics of this resident driver.
pub(crate) fn install(
    path: &'static [u8],
    access: &'static HiiConfigAccessProtocol,
) -> Result<Handle, Failure> {
    #[expect(
        unsafe_code,
        reason = "installs a protocol whose interface is a static of this driver"
    )]
    // SAFETY: the device path is a static of this resident boot service driver, which nothing
    // writes
    let handle = unsafe {
        boot::install_protocol_interface(None, &DevicePathProtocol::GUID, path.as_ptr().cast())
    }
    .map_err(|error| ("installing a device path", error.status()))?;
    #[expect(
        unsafe_code,
        reason = "installs a protocol whose interface is a static of this driver"
    )]
    // SAFETY: the protocol is a static of this resident boot service driver
    unsafe {
        boot::install_protocol_interface(
            Some(handle),
            &HiiConfigAccessProtocol::GUID,
            ptr::from_ref(access).cast(),
        )
    }
    .map_err(|error| ("installing EFI_HII_CONFIG_ACCESS_PROTOCOL", error.status()))?;
    Ok(handle)
}
