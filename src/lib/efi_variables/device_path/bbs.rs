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

//! The BIOS Boot Specification Device Path node (UEFI 2.11 §10.3.6), BBS of Table 10.67.

use super::parameters::ascii_text;
use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;

/// The Sub-Type of a BBS 1.01 node
pub(super) const BBS_101: u8 = 0x01;
/// The Device Type keywords of UEFI 2.11 Table 10.67
const DEVICE_TYPES: [(&str, u16); 6] = [
    ("Floppy", 0x01),
    ("HD", 0x02),
    ("CDROM", 0x03),
    ("PCMCIA", 0x04),
    ("USB", 0x05),
    ("Network", 0x06),
];

/// BBS(Type,Id,Flags), of Device Type, Status Flag and the Description String, ASCII ended by
/// Null.
pub(super) fn bbs_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (device_type, flags) = (fields.u16()?, fields.u16()?);
    let id = ascii_text(fields.0.strip_suffix(&[0])?)?;
    let device_type = match DEVICE_TYPES.iter().find(|(_, value)| *value == device_type) {
        Some((name, _)) => (*name).to_owned(),
        None => format!("0x{device_type:X}"),
    };
    Some(format!("BBS({device_type},{id},0x{flags:X})"))
}

/// BBS(Type,Id,Flags), Flags 0 if omitted.
pub(super) fn bbs(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let device_type = p.keyword_or_integer(&DEVICE_TYPES)?;
    let id = p.ascii()?;
    let flags: u16 = p.integer_or(0)?;
    let data = [
        &device_type.to_le_bytes()[..],
        &flags.to_le_bytes(),
        id.as_bytes(),
        &[0],
    ];
    Ok(data.concat())
}
