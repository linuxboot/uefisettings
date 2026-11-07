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

//! The Vendor nodes of the Hardware, Messaging and Media Types (UEFI 2.11 §10.3.2.4, §10.3.4.16,
//! §10.3.5.3), and the Messaging Vendor nodes that UEFI 2.11 Table 10.67 names by their GUID.

use super::guid;
use super::parameters::upper_hex;
use super::parameters::Parameters;
use super::serial;
use super::storage;
use super::DevicePathTextError;
use crate::hii::package::Guid;

/// The Sub-Type of a Messaging Vendor node (UEFI 2.11 §10.3.4.16)
pub(super) const MESSAGING_VENDOR: u8 = 0x0A;
/// DEVICE_PATH_MESSAGING_UART_FLOW_CONTROL (UEFI 2.11 §10.3.4.17)
const UART_FLOW_CONTROL: Guid = guid(
    0x37499A9D,
    0x542F,
    0x4C89,
    [0xA0, 0x26, 0x35, 0xDA, 0x14, 0x20, 0x94, 0xE4],
);
/// The Vendor GUID of the Serial Attached SCSI (SAS) Device Path (UEFI 2.11 §10.3.4.18, Table 10.35),
/// edk2-stable202608 DEVICE_PATH_MESSAGING_SAS (MdePkg/Include/Protocol/DevicePath.h:773)
const SAS: Guid = guid(
    0xD487DDB4,
    0x008B,
    0x11D9,
    [0xAF, 0xDC, 0x00, 0x10, 0x83, 0xFF, 0xCA, 0x4D],
);
/// The Messaging Vendor nodes without data that UEFI 2.11 Table 10.67 names, by their GUID
pub(super) const NAMES: [(Guid, &str); 5] = [
    (
        guid(
            0xE0C14753,
            0xF9BE,
            0x11D2,
            [0x9A, 0x0C, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
        ),
        "VenPcAnsi",
    ),
    (
        guid(
            0xDFA66065,
            0xB419,
            0x11D3,
            [0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
        ),
        "VenVt100",
    ),
    (
        guid(
            0x7BAEC70B,
            0x57E0,
            0x4C76,
            [0x8E, 0x87, 0x2F, 0x9E, 0x28, 0x08, 0x83, 0x43],
        ),
        "VenVt100Plus",
    ),
    (
        guid(
            0xAD15A0D6,
            0x8BEC,
            0x4ACF,
            [0xA0, 0x73, 0xD0, 0x1D, 0xE7, 0x7E, 0x2D, 0x88],
        ),
        "VenUtf8",
    ),
    // EFI_DEBUGPORT_PROTOCOL_GUID, edk2-stable202608 MdePkg.dec gEfiDebugPortProtocolGuid
    (
        guid(
            0xEBA4E8D2,
            0x3858,
            0x41EC,
            [0xA2, 0x81, 0x26, 0x47, 0xBA, 0x96, 0x60, 0xD0],
        ),
        "DebugPort",
    ),
];

/// VenHw, VenMsg or VenMedia: the GUID, then any data as a Hex Dump.
pub(super) fn text(kind: &str, data: &[u8]) -> Option<String> {
    let (guid, rest) = data.split_first_chunk::<16>()?;
    let guid = Guid::from(*guid);
    Some(match rest.is_empty() {
        true => format!("Ven{kind}({guid})"),
        false => format!("Ven{kind}({guid},{})", upper_hex(rest)),
    })
}

/// A Vendor node's data: its GUID, then a Hex Dump, none if omitted.
pub(super) fn vendor(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok([&p.guid()?[..], &p.hex()?].concat())
}

/// The form that edk2 writes a Messaging Vendor node in: the name of its GUID, whatever the data,
/// UartFlowCtrl or SAS for theirs, else VenMsg.
pub(super) fn messaging_text(data: &[u8]) -> Option<String> {
    let (guid, rest) = data.split_first_chunk::<16>()?;
    let guid = Guid::from(*guid);
    match NAMES.iter().find(|(named, _)| *named == guid) {
        Some((_, name)) => Some(format!("{name}()")),
        None if guid == UART_FLOW_CONTROL => serial::flow_control_text(rest),
        None if guid == SAS => storage::sas_text(rest),
        None => text("Msg", data),
    }
}

/// UartFlowCtrl(Value): the node of DEVICE_PATH_MESSAGING_UART_FLOW_CONTROL.
pub(super) fn flow_control(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok([
        &<[u8; 16]>::from(UART_FLOW_CONTROL)[..],
        &serial::flow_control(p)?,
    ]
    .concat())
}

/// SAS(Address,LUN,RTP,SASSATA,Location,Connect,DriveBay,Reserved): the node of
/// DEVICE_PATH_MESSAGING_SAS.
pub(super) fn sas(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok([&<[u8; 16]>::from(SAS)[..], &storage::sas(p)?].concat())
}
