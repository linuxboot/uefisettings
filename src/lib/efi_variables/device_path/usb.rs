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

//! The USB nodes (UEFI 2.11 §10.3.4.5, §10.3.4.7) of named forms in Table 10.67: USB, USB Class
//! with the shortcuts of the classes it names, and USB WWID.

use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;

/// The Sub-Types of UEFI 2.11 §10.3.4
pub(super) const USB: u8 = 0x05;
pub(super) const USB_CLASS: u8 = 0x0F;
pub(super) const USB_WWID: u8 = 0x10;

/// The USB classes that UEFI 2.11 Table 10.67 names a form of, by their class code
pub(super) const CLASS_NAMES: [(u8, &str); 12] = [
    (1, "UsbAudio"),
    (2, "UsbCDCControl"),
    (3, "UsbHID"),
    (6, "UsbImage"),
    (7, "UsbPrinter"),
    (8, "UsbMassStorage"),
    (9, "UsbHub"),
    (10, "UsbCDCData"),
    (11, "UsbSmartCard"),
    (14, "UsbVideo"),
    (220, "UsbDiagnostic"),
    (224, "UsbWireless"),
];
/// The class of the application-specific subclasses that UEFI 2.11 Table 10.67 names a form of,
/// by their subclass code
const APPLICATION_SPECIFIC: u8 = 254;
pub(super) const SUBCLASS_NAMES: [(u8, &str); 3] = [
    (1, "UsbDeviceFirmwareUpdate"),
    (2, "UsbIrdaBridge"),
    (3, "UsbTestAndMeasurement"),
];
/// What an omitted VID, PID, class, subclass or protocol of a USB Class form reads as: any
const ANY_ID: u16 = 0xFFFF;
const ANY_CODE: u8 = 0xFF;

/// USB(Port,Interface).
pub(super) fn usb_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (port, interface) = (fields.u8()?, fields.u8()?);
    Some(format!("USB(0x{port:X},0x{interface:X})"))
}

pub(super) fn usb(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(vec![p.integer()?, p.integer()?])
}

/// The form of the node's class or subclass that UEFI 2.11 Table 10.67 names, as edk2's
/// DevPathToTextUsbClass() picks it, else UsbClass(VID,PID,Class,SubClass,Protocol).
pub(super) fn class_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (vendor, product) = (fields.u16()?, fields.u16()?);
    let (class, subclass, protocol) = (fields.u8()?, fields.u8()?, fields.u8()?);
    let class_name = CLASS_NAMES.iter().find(|(code, _)| *code == class);
    let subclass_name = SUBCLASS_NAMES
        .iter()
        .find(|(code, _)| class == APPLICATION_SPECIFIC && *code == subclass);
    Some(match (class_name, subclass_name) {
        (Some((_, name)), _) => {
            format!("{name}(0x{vendor:X},0x{product:X},0x{subclass:X},0x{protocol:X})")
        }
        (None, Some((_, name))) => format!("{name}(0x{vendor:X},0x{product:X},0x{protocol:X})"),
        (None, None) => format!(
            "UsbClass(0x{vendor:X},0x{product:X},0x{class:X},0x{subclass:X},0x{protocol:X})"
        ),
    })
}

/// UsbClass(VID,PID,Class,SubClass,Protocol), each any if omitted.
pub(super) fn class(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (vendor, product) = (p.integer_or(ANY_ID)?, p.integer_or(ANY_ID)?);
    let class = p.integer_or(ANY_CODE)?;
    let (subclass, protocol) = (p.integer_or(ANY_CODE)?, p.integer_or(ANY_CODE)?);
    Ok(class_data(vendor, product, [class, subclass, protocol]))
}

/// The form of CLASS_NAMES of `class`: `Usb<Class>(VID,PID,SubClass,Protocol)`, each any if
/// omitted.
pub(super) fn named_class(
    p: &mut Parameters<'_>,
    class: u8,
) -> Result<Vec<u8>, DevicePathTextError> {
    let (vendor, product) = (p.integer_or(ANY_ID)?, p.integer_or(ANY_ID)?);
    let (subclass, protocol) = (p.integer_or(ANY_CODE)?, p.integer_or(ANY_CODE)?);
    Ok(class_data(vendor, product, [class, subclass, protocol]))
}

/// The form of SUBCLASS_NAMES of `subclass`: `Usb<Subclass>(VID,PID,Protocol)`, each any if
/// omitted.
pub(super) fn named_subclass(
    p: &mut Parameters<'_>,
    subclass: u8,
) -> Result<Vec<u8>, DevicePathTextError> {
    let (vendor, product) = (p.integer_or(ANY_ID)?, p.integer_or(ANY_ID)?);
    let protocol = p.integer_or(ANY_CODE)?;
    Ok(class_data(
        vendor,
        product,
        [APPLICATION_SPECIFIC, subclass, protocol],
    ))
}

fn class_data(vendor: u16, product: u16, codes: [u8; 3]) -> Vec<u8> {
    [&vendor.to_le_bytes()[..], &product.to_le_bytes(), &codes].concat()
}

/// UsbWwid(VID,PID,InterfaceNumber,"WWID"), of InterfaceNumber, VID and PID, then the serial
/// number, CHAR16s without Null, as edk2 writes and reads them.
pub(super) fn wwid_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (interface, vendor, product) = (fields.u16()?, fields.u16()?, fields.u16()?);
    let (units, []) = fields.0.as_chunks::<2>() else {
        return None;
    };
    let units: Vec<u16> = units.iter().map(|unit| u16::from_le_bytes(*unit)).collect();
    let serial = String::from_utf16(&units)
        .ok()
        .filter(|serial| !serial.contains('\0'))?;
    Some(format!(
        "UsbWwid(0x{vendor:X},0x{product:X},0x{interface:X},\"{serial}\")"
    ))
}

/// UsbWwid(VID,PID,InterfaceNumber,"WWID"): the WWID without its quotes, if quoted, as edk2's
/// DevPathFromTextUsbWwid() takes it, of UCS-2 but Null.
pub(super) fn wwid(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (vendor, product, interface): (u16, u16, u16) = (p.integer()?, p.integer()?, p.integer()?);
    let text = p.next();
    let serial = match text
        .strip_prefix('"')
        .and_then(|text| text.strip_suffix('"'))
    {
        Some(quoted) => quoted,
        None if !text.is_empty() => text,
        None => return Err(DevicePathTextError::Value(text.to_owned())),
    };
    if serial.chars().any(|c| c == '\0' || c.len_utf16() != 1) {
        return Err(DevicePathTextError::NotUcs2(serial.to_owned()));
    }
    let serial: Vec<u8> = serial.encode_utf16().flat_map(u16::to_le_bytes).collect();
    Ok([interface, vendor, product]
        .map(u16::to_le_bytes)
        .concat()
        .into_iter()
        .chain(serial)
        .collect())
}
