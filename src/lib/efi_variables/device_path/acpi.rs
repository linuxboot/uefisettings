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

//! The ACPI Device Path nodes (UEFI 2.11 §10.3.3) of named forms in Table 10.67.

use super::parameters::ascii_text;
use super::parameters::eisa_id;
use super::parameters::eisa_id_text;
use super::parameters::integer;
use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;

/// The Sub-Types of UEFI 2.11 §10.3.3
pub(super) const HID: u8 = 0x01;
pub(super) const EXTENDED: u8 = 0x02;
pub(super) const ADR: u8 = 0x03;
pub(super) const NVDIMM: u8 = 0x04;
/// "PNP" compressed as an EISA ID, the low 16 bits of a PNP device's _HID (edk2
/// PNP_EISA_ID_CONST)
const PNP_EISA_ID: u32 = 0x41D0;

/// The PNP devices whose ACPI nodes UEFI 2.11 Table 10.67 names, by the device number of their
/// _HID
pub(super) const PNP_NAMES: [(u32, &str); 6] = [
    (0x0A03, "PciRoot"),
    (0x0A08, "PcieRoot"),
    (0x0604, "Floppy"),
    (0x0301, "Keyboard"),
    (0x0501, "Serial"),
    (0x0401, "ParallelPort"),
];

/// The name that UEFI 2.11 Table 10.67 gives the PNP device, else Acpi(HID,UID). edk2 writes a
/// _HID other than a PNP one as Acpi(0x%08x,…), which its EisaIdFromText() does not read; this
/// writes its EISA ID as edk2 writes those of AcpiEx.
pub(super) fn hid_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (hid, uid) = (fields.u32()?, fields.u32()?);
    let name = (hid & 0xFFFF == PNP_EISA_ID)
        .then(|| PNP_NAMES.iter().find(|(number, _)| *number == hid >> 16))
        .flatten();
    match name {
        Some((_, name)) => Some(format!("{name}(0x{uid:X})")),
        None => Some(format!("Acpi({},0x{uid:X})", eisa_id_text(hid)?)),
    }
}

/// Acpi(HID,UID).
pub(super) fn hid(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let hid = eisa_id(p.next())?;
    Ok([hid, p.integer_or(0)?].map(u32::to_le_bytes).concat())
}

/// A name of PNP_NAMES, as `Acpi(PNP<number>,UID)`.
pub(super) fn pnp(p: &mut Parameters<'_>, number: u32) -> Result<Vec<u8>, DevicePathTextError> {
    let hid = PNP_EISA_ID | number << 16;
    Ok([hid, p.integer_or(0)?].map(u32::to_le_bytes).concat())
}

/// An ACPI Expanded node: HID, UID, CID, then HIDSTR, UIDSTR and CIDSTR, each ended by Null.
struct Expanded<'a> {
    hid: u32,
    uid: u32,
    cid: u32,
    hid_str: &'a str,
    uid_str: &'a str,
    cid_str: &'a str,
}

impl<'a> Expanded<'a> {
    /// None unless `data` holds exactly the fields and three strings of ASCII, as edk2's
    /// DevPathFromTextAcpiEx() writes them.
    fn read(data: &'a [u8]) -> Option<Self> {
        let mut fields = Fields(data);
        let (hid, uid, cid) = (fields.u32()?, fields.u32()?, fields.u32()?);
        let strings: Option<Vec<&str>> = fields
            .0
            .strip_suffix(&[0])?
            .split(|byte| *byte == 0)
            .map(ascii_text)
            .collect();
        let [hid_str, uid_str, cid_str] = strings?[..] else {
            return None;
        };
        Some(Self {
            hid,
            uid,
            cid,
            hid_str,
            uid_str,
            cid_str,
        })
    }

    /// AcpiEx(HID,CID,UID,HIDSTR,CIDSTR,UIDSTR).
    fn full_text(&self) -> Option<String> {
        Some(format!(
            "AcpiEx({},{},0x{:X},{},{},{})",
            eisa_id_text(self.hid)?,
            eisa_id_text(self.cid)?,
            self.uid,
            self.hid_str,
            self.cid_str,
            self.uid_str
        ))
    }

    fn data(&self) -> Vec<u8> {
        let ids = [self.hid, self.uid, self.cid].map(u32::to_le_bytes);
        let strings =
            [self.hid_str, self.uid_str, self.cid_str].map(|text| [text.as_bytes(), &[0]].concat());
        [ids.concat(), strings.concat()].concat()
    }
}

/// AcpiExp(HID,CID,UIDSTR) where only UIDSTR is set, else AcpiEx(HID,CID,UID,HIDSTR,CIDSTR,
/// UIDSTR), as edk2 chooses.
pub(super) fn extended_text(data: &[u8]) -> Option<String> {
    let node = Expanded::read(data)?;
    match (node.hid_str, node.cid_str, node.uid_str) {
        ("", "", uid_str) if !uid_str.is_empty() => {
            let cid = match node.cid {
                0 => "0".to_owned(),
                cid => eisa_id_text(cid)?,
            };
            Some(format!(
                "AcpiExp({},{cid},{uid_str})",
                eisa_id_text(node.hid)?
            ))
        }
        _ => node.full_text(),
    }
}

/// AcpiEx(HID,CID,UID,HIDSTR,CIDSTR,UIDSTR), which a node whose AcpiExp would drop its UID takes:
/// edk2 writes AcpiExp whatever the UID.
pub(super) fn extended_full_text(data: &[u8]) -> Option<String> {
    Expanded::read(data)?.full_text()
}

/// AcpiEx(HID,CID,UID,HIDSTR,CIDSTR,UIDSTR), each 0 or empty if omitted, as Table 10.67 gives
/// them: edk2's EisaIdFromText() reads an omitted HID or CID from the characters after it.
pub(super) fn extended(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (hid, cid) = (p.eisa_id_or(0)?, p.eisa_id_or(0)?);
    let uid = p.integer_or(0)?;
    let (hid_str, cid_str, uid_str) = (p.ascii()?, p.ascii()?, p.ascii()?);
    Ok(Expanded {
        hid,
        uid,
        cid,
        hid_str,
        uid_str,
        cid_str,
    }
    .data())
}

/// AcpiExp(HID,CID,UIDSTR): UID 0, HIDSTR and CIDSTR empty, CID 0 if omitted.
pub(super) fn expanded(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let hid = eisa_id(p.next())?;
    let cid = p.eisa_id_or(0)?;
    let uid_str = p.ascii()?;
    Ok(Expanded {
        hid,
        uid: 0,
        cid,
        hid_str: "",
        uid_str,
        cid_str: "",
    }
    .data())
}

/// AcpiAdr(ADR,…), each _ADR of the node.
pub(super) fn adr_text(data: &[u8]) -> Option<String> {
    let (adrs, []) = data.as_chunks::<4>() else {
        return None;
    };
    let adrs: Vec<String> = adrs
        .iter()
        .map(|adr| format!("0x{:X}", u32::from_le_bytes(*adr)))
        .collect();
    (!adrs.is_empty()).then(|| format!("AcpiAdr({})", adrs.join(",")))
}

/// AcpiAdr(DisplayDevice,…), one or more.
pub(super) fn adr(p: &mut Parameters<'_>, text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let adrs = p
        .rest()
        .map(|adr| integer::<u32>(adr).map(u32::to_le_bytes))
        .collect::<Result<Vec<_>, _>>()?;
    match adrs.is_empty() {
        true => Err(DevicePathTextError::EmptyList(text.to_owned())),
        false => Ok(adrs.concat()),
    }
}

/// NvdimmAcpiAdr(NFIT Device Handle), as Table 10.67 gives it: edk2 has no form for it. The
/// handle, an _ADR, is hexadecimal as AcpiAdr's.
pub(super) fn nvdimm_text(data: &[u8]) -> Option<String> {
    Some(format!("NvdimmAcpiAdr(0x{:X})", Fields(data).u32()?))
}

pub(super) fn nvdimm(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.integer::<u32>()?.to_le_bytes().to_vec())
}
