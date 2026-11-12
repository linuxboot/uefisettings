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

//! The UART node (UEFI 2.11 §10.3.4.15) and the flow control of a UART Flow Control node
//! (§10.3.4.17).

use super::parameters::integer;
use super::parameters::keyword_or_integer;
use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;

/// The Sub-Type of a UART node
pub(super) const UART: u8 = 0x0E;
/// What edk2 writes for a UART's BaudRate or DataBits of 0, and reads back as 115200 or 8
pub(super) const UART_DEFAULT: &str = "DEFAULT";
/// The UART Parity and Stop Bits keywords, by value (UEFI 2.11 Table 10.67)
const PARITY_NAMES: [&str; 6] = ["D", "N", "E", "O", "M", "S"];
const STOP_BITS_NAMES: [&str; 4] = ["D", "1", "1.5", "2"];
/// The FlowControlMap values that UartFlowCtrl names (UEFI 2.11 Table 10.67)
const FLOW_CONTROLS: [(&str, u32); 3] = [("None", 0), ("Hardware", 1), ("XonXoff", 2)];
/// The bits of FlowControlMap that edk2's DevPathToTextVendor() names
const FLOW_CONTROL_MASK: u32 = 0x3;

/// Uart(BaudRate,DataBits,Parity,StopBits): Parity and StopBits both keywords, or both integers,
/// as "Mixing formats is prohibited" (UEFI 2.11 Table 10.67). edk2 writes a BaudRate or DataBits
/// of 0 as DEFAULT, which it reads back as 115200 or 8; this writes 0.
pub(super) fn uart_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let _reserved = fields.u32()?;
    let (baud, data_bits) = (fields.u64()?, fields.u8()?);
    let (parity, stop_bits) = (fields.u8()?, fields.u8()?);
    let keywords = PARITY_NAMES
        .get(usize::from(parity))
        .zip(STOP_BITS_NAMES.get(usize::from(stop_bits)));
    Some(match keywords {
        Some((parity, stop_bits)) => format!("Uart({baud},{data_bits},{parity},{stop_bits})"),
        None => format!("Uart({baud},{data_bits},{parity},{stop_bits})"),
    })
}

/// Uart(BaudRate,DataBits,Parity,StopBits), 115200, 8, D and D if omitted; refuses DEFAULT,
/// which to_text never writes, and a keyword next to an integer, which edk2 reads all the same.
pub(super) fn uart(p: &mut Parameters<'_>, text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let baud: u64 = uart_integer_or(p, 115_200)?;
    let data_bits: u8 = uart_integer_or(p, 8)?;
    let parity = UartField::read(p.next(), &PARITY_NAMES)?;
    let stop_bits = UartField::read(p.next(), &STOP_BITS_NAMES)?;
    if let (UartFormat::Keyword, UartFormat::Integer) | (UartFormat::Integer, UartFormat::Keyword) =
        (parity.format, stop_bits.format)
    {
        return Err(DevicePathTextError::UartMixedFormats(text.to_owned()));
    }
    let data = [
        &0_u32.to_le_bytes()[..],
        &baud.to_le_bytes(),
        &[data_bits, parity.value, stop_bits.value],
    ];
    Ok(data.concat())
}

/// A UART's BaudRate or DataBits: an Integer, `default` if omitted, but never UART_DEFAULT.
fn uart_integer_or<T: TryFrom<u64>>(
    p: &mut Parameters<'_>,
    default: T,
) -> Result<T, DevicePathTextError> {
    match p.next() {
        "" => Ok(default),
        UART_DEFAULT => Err(DevicePathTextError::UartDefault),
        text => integer(text),
    }
}

/// How a UART's Parity or StopBits is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UartFormat {
    Keyword,
    Integer,
    /// Omitted, or "1" of StopBits, which is both a keyword and the integer of its value
    Either,
}

/// A UART's Parity or StopBits: its value and how it is written.
struct UartField {
    value: u8,
    format: UartFormat,
}

impl UartField {
    /// A keyword of `names`, as its index, or an Integer; 0 if omitted.
    fn read(text: &str, names: &[&str]) -> Result<Self, DevicePathTextError> {
        let keyword = names
            .iter()
            .position(|name| *name == text)
            .map(u8::try_from)
            .transpose()
            .map_err(|_| DevicePathTextError::Value(text.to_owned()))?;
        let number = integer::<u8>(text).ok();
        let (value, format) = match (text, keyword, number) {
            ("", _, _) => (0, UartFormat::Either),
            (_, Some(keyword), Some(number)) if keyword == number => (keyword, UartFormat::Either),
            (_, Some(keyword), _) => (keyword, UartFormat::Keyword),
            (_, None, Some(number)) => (number, UartFormat::Integer),
            (_, None, None) => return Err(DevicePathTextError::Value(text.to_owned())),
        };
        Ok(Self { value, format })
    }
}

/// UartFlowCtrl(Value), of the FlowControlMap that follows the GUID, by the bits that edk2
/// names.
pub(super) fn flow_control_text(data: &[u8]) -> Option<String> {
    let map = Fields(data).u32()? & FLOW_CONTROL_MASK;
    let (name, _) = FLOW_CONTROLS.iter().find(|(_, value)| *value == map)?;
    Some(format!("UartFlowCtrl({name})"))
}

/// The FlowControlMap of UartFlowCtrl(Value): a keyword, or the integer 0, 1 or 2 that Table
/// 10.67 allows and edk2's DevPathFromTextUartFlowCtrl() reads as 0.
pub(super) fn flow_control(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let text = p.next();
    let map: u32 = keyword_or_integer(text, &FLOW_CONTROLS)?;
    match FLOW_CONTROLS.iter().any(|(_, value)| *value == map) {
        true => Ok(map.to_le_bytes().to_vec()),
        false => Err(DevicePathTextError::Value(text.to_owned())),
    }
}
