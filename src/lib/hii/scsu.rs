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

//! SCSU, the Standard Compression Scheme for Unicode (Unicode Technical Standard #6, revision 4),
//! as UEFI 2.11 §33.3.6.3.1 extends it for the text of the SCSU string blocks (§33.3.6.2): the
//! windows start from the strings package's LanguageWindow (§33.3.6.1) instead of UTS #6's fixed
//! values, 0x7F introduces a control code of §33.2.6.2.4, and every character fits UCS-2.

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;

/// The first byte of a UEFI control code in single-byte mode (UEFI 2.11 §33.3.6.3.1).
const CONTROL_CODE: u8 = 0x7F;

/// Decodes the SCSU string at the start of `bytes` up to its null terminator, the first decoded
/// U+0000 (UEFI 2.11 §33.3.6.2 "null-terminated encoded string"), from `language_window`:
/// static windows 0-7, then dynamic windows 0-7, the order of edk2's mLanguageWindow
/// (edk2-stable202608 MdeModulePkg/Universal/HiiDatabaseDxe/String.c). Returns the string and
/// the bytes after its terminator. A control code becomes its 0xFxyy form, as in UCS-2 strings
/// (§33.2.6.2.4).
///
/// Example: under edk2's LanguageWindow, `41 7F 00 01 42 00 43` is ("A\u{F701}B", `43`): Font
/// Family 0x01 between "A" and "B", whose 0x00 byte is no terminator.
pub(super) fn decode<'a>(
    bytes: &'a [u8],
    language_window: &[u16; 16],
) -> Result<(String, &'a [u8])> {
    let mut decoder = Decoder::new(bytes, language_window);
    let mut string = String::new();
    loop {
        let decoded = match decoder.mode {
            Mode::SingleByte => decoder.single_byte()?,
            Mode::Unicode => decoder.unicode()?,
        };
        match decoded {
            Decoded::State => {}
            Decoded::ControlCode(code) => string.push(code),
            // the null terminator
            Decoded::Character(0) => return Ok((string, decoder.bytes.as_slice())),
            Decoded::Character(code_point) => string.push(ucs2_character(code_point)?),
        }
    }
}

/// UTS #6 §5's two modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Bytes are characters or tags (Table 6).
    SingleByte,
    /// Pairs of bytes are big-endian UTF-16 units, or a byte is a tag (Table 7).
    Unicode,
}

/// What one step of decoding gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Decoded {
    /// A tag that changed the mode or the windows.
    State,
    /// A UEFI control code, as its 0xFxyy form.
    ControlCode(char),
    /// A character's code point, which may lie outside UCS-2.
    Character(u32),
}

/// One of 8 static or 8 dynamic windows: a tag of 8 consecutive values names one by its low 3
/// bits (UTS #6 Tables 6 and 7), and SDX or UDX by the top 3 bits of its next byte (§6.1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Window {
    W0,
    W1,
    W2,
    W3,
    W4,
    W5,
    W6,
    W7,
}

impl Window {
    /// The window of the low 3 bits of `bits`.
    fn of(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::W0,
            1 => Self::W1,
            2 => Self::W2,
            3 => Self::W3,
            4 => Self::W4,
            5 => Self::W5,
            6 => Self::W6,
            // 7: `bits & 0x07` is below 8
            _ => Self::W7,
        }
    }
}

/// The offsets of 8 windows, static or dynamic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Windows([u32; 8]);

impl Windows {
    /// The offset of `window`.
    fn get(&self, window: Window) -> u32 {
        let Self([w0, w1, w2, w3, w4, w5, w6, w7]) = *self;
        match window {
            Window::W0 => w0,
            Window::W1 => w1,
            Window::W2 => w2,
            Window::W3 => w3,
            Window::W4 => w4,
            Window::W5 => w5,
            Window::W6 => w6,
            Window::W7 => w7,
        }
    }

    /// The offset of `window`, to change.
    fn get_mut(&mut self, window: Window) -> &mut u32 {
        let Self([w0, w1, w2, w3, w4, w5, w6, w7]) = self;
        match window {
            Window::W0 => w0,
            Window::W1 => w1,
            Window::W2 => w2,
            Window::W3 => w3,
            Window::W4 => w4,
            Window::W5 => w5,
            Window::W6 => w6,
            Window::W7 => w7,
        }
    }
}

/// The state of UTS #6's decoder, which each string starts afresh (§7.1).
struct Decoder<'a> {
    bytes: std::slice::Iter<'a, u8>,
    mode: Mode,
    static_windows: Windows,
    dynamic_windows: Windows,
    /// The dynamically positioned window of bytes 80-FF in single-byte mode.
    active_window: Window,
}

impl<'a> Decoder<'a> {
    /// UTS #6 §7.1's initial state: single-byte mode, window 0 active, the windows where
    /// `language_window` puts them.
    fn new(bytes: &'a [u8], language_window: &[u16; 16]) -> Self {
        let windows = language_window.map(u32::from);
        let [static_windows @ .., _, _, _, _, _, _, _, _] = windows;
        let [_, _, _, _, _, _, _, _, dynamic_windows @ ..] = windows;
        Self {
            bytes: bytes.iter(),
            mode: Mode::SingleByte,
            static_windows: Windows(static_windows),
            dynamic_windows: Windows(dynamic_windows),
            active_window: Window::W0,
        }
    }

    /// The next byte of the string.
    fn next(&mut self) -> Result<u8> {
        self.bytes
            .next()
            .copied()
            .ok_or_else(|| anyhow!("the SCSU string has no null terminator"))
    }

    /// The UTF-16 unit of the next two bytes, big-endian.
    fn next_unit(&mut self, high: u8) -> Result<u32> {
        Ok(u32::from(u16::from_be_bytes([high, self.next()?])))
    }

    /// Decodes a tag or character of single-byte mode (UTS #6 Table 6).
    fn single_byte(&mut self) -> Result<Decoded> {
        let byte = self.next()?;
        Ok(match byte {
            // UTS #6 Table 6 "pass": 0x00 is the terminator, whatever static window 0 holds
            0x00 => Decoded::Character(0),
            0x09 | 0x0A | 0x0D | 0x20..=0x7E => {
                self.check_static_window_0()?;
                Decoded::Character(u32::from(byte))
            }
            CONTROL_CODE => self.control_code()?,
            // SQn
            0x01..=0x08 => {
                let window = Window::of(byte - 0x01);
                match self.next()? {
                    quoted @ 0x00..=0x7F => {
                        if window == Window::W0 {
                            self.check_static_window_0()?;
                        }
                        Decoded::Character(self.static_windows.get(window) + u32::from(quoted))
                    }
                    quoted @ 0x80..=0xFF => Decoded::Character(
                        self.dynamic_windows.get(window) + u32::from(quoted - 0x80),
                    ),
                }
            }
            // SDX
            0x0B => self.define_extended_window()?,
            0x0C => bail!("reserved SCSU tag {byte:#04x}"),
            // SQU
            0x0E => {
                let high = self.next()?;
                Decoded::Character(self.next_unit(high)?)
            }
            // SCU
            0x0F => {
                self.mode = Mode::Unicode;
                Decoded::State
            }
            // SCn
            0x10..=0x17 => {
                self.active_window = Window::of(byte);
                Decoded::State
            }
            // SDn
            0x18..=0x1F => self.define_window(Window::of(byte))?,
            0x80..=0xFF => Decoded::Character(
                self.dynamic_windows.get(self.active_window) + u32::from(byte - 0x80),
            ),
        })
    }

    /// Decodes a tag or character of Unicode mode (UTS #6 Table 7).
    fn unicode(&mut self) -> Result<Decoded> {
        let byte = self.next()?;
        Ok(match byte {
            // UCn
            0xE0..=0xE7 => {
                self.active_window = Window::of(byte);
                self.mode = Mode::SingleByte;
                Decoded::State
            }
            // UDn
            0xE8..=0xEF => {
                self.mode = Mode::SingleByte;
                self.define_window(Window::of(byte))?
            }
            // UQU
            0xF0 => {
                let high = self.next()?;
                Decoded::Character(self.next_unit(high)?)
            }
            // UDX
            0xF1 => {
                self.mode = Mode::SingleByte;
                self.define_extended_window()?
            }
            0xF2 => bail!("reserved SCSU tag {byte:#04x}"),
            0x00..=0xDF | 0xF3..=0xFF => Decoded::Character(self.next_unit(byte)?),
        })
    }

    /// A UEFI control code after its 0x7F (UEFI 2.11 Table 33.3): Font Family Select and Font
    /// Size Select take one more byte.
    fn control_code(&mut self) -> Result<Decoded> {
        let code = match self.next()? {
            0x00 => 0xF700 | u16::from(self.next()?),
            0x01 => 0xF800 | u16::from(self.next()?),
            style @ 0x20..=0x2B => 0xF600 | u16::from(style),
            code => bail!("unknown control code 0x7F {code:#04x} (UEFI 2.11 Table 33.3)"),
        };
        // 0xF6xx-0xF8xx are no surrogates
        let code = char::from_u32(u32::from(code)).ok_or_else(|| surrogate(code.into()))?;
        Ok(Decoded::ControlCode(code))
    }

    /// SDn or UDn: positions dynamic window `window` by the next byte (UTS #6 Table 3) and
    /// makes it the active one.
    fn define_window(&mut self, window: Window) -> Result<Decoded> {
        *self.dynamic_windows.get_mut(window) = window_offset(self.next()?)?;
        self.active_window = window;
        Ok(Decoded::State)
    }

    /// SDX or UDX: positions a dynamic window in the supplementary code space by the next two
    /// bytes (UTS #6 §6.1.3) and makes it the active one. Its characters do not fit UCS-2, so
    /// the first one is refused.
    fn define_extended_window(&mut self) -> Result<Decoded> {
        let high = self.next()?;
        let low = self.next()?;
        let window = Window::of(high >> 5);
        *self.dynamic_windows.get_mut(window) =
            0x1_0000 + 0x80 * ((u32::from(high & 0x1F) << 8) | u32::from(low));
        self.active_window = window;
        Ok(Decoded::State)
    }

    /// UTS #6 reads bytes 09/0A/0D/20-7F, and SQ0 00-7F, through static window 0 (Table 1
    /// "Use static window 0 for all following bytes that are in the range 20 to 7F, or CR, LF,
    /// HT") and also as Basic Latin (§6.1.1 "always represent the corresponding character from
    /// the Basic Latin block"). The two agree only while static window 0 is at 0, UTS #6's fixed
    /// value, which LanguageWindow may change (UEFI 2.11 §33.3.6.3.1).
    fn check_static_window_0(&self) -> Result<()> {
        let window_0 = self.static_windows.get(Window::W0);
        ensure!(
            window_0 == 0,
            "static window 0 is {window_0:#06x}; UTS #6 reads bytes 20-7F both through it and as \
             Basic Latin (UEFI 2.11 §33.3.6.3.1)"
        );
        Ok(())
    }
}

/// The offset of the dynamically positioned window that an SDn or UDn tag's `index` names (UTS
/// #6 Table 3).
fn window_offset(index: u8) -> Result<u32> {
    Ok(match index {
        // half-blocks from U+0080 to U+3380
        0x01..=0x67 => u32::from(index) * 0x80,
        // half-blocks from U+E000 to U+FF80
        0x68..=0xA7 => u32::from(index) * 0x80 + 0xAC00,
        // Latin-1 letters and half of Latin Extended-A
        0xF9 => 0x00C0,
        // IPA Extensions
        0xFA => 0x0250,
        // Greek
        0xFB => 0x0370,
        // Armenian
        0xFC => 0x0530,
        // Hiragana
        0xFD => 0x3040,
        // Katakana
        0xFE => 0x30A0,
        // Halfwidth Katakana
        0xFF => 0xFF60,
        0x00 | 0xA8..=0xF8 => bail!("reserved SCSU window offset {index:#04x}"),
    })
}

/// The character of `code_point`, which must fit UCS-2 (UEFI 2.11 §33.2.6.2.2) and lie outside
/// 0xF000-0xFCFF (§33.3.6.3.1).
fn ucs2_character(code_point: u32) -> Result<char> {
    match code_point {
        0xF000..=0xFCFF => bail!(
            "SCSU character U+{code_point:04X} is between 0xF000 and 0xFCFF (UEFI 2.11 \
             §33.3.6.3.1)"
        ),
        0x1_0000.. => {
            bail!("SCSU character U+{code_point:04X} is outside UCS-2 (UEFI 2.11 §33.2.6.2.2)")
        }
        // char::from_u32 refuses exactly the surrogates of the BMP
        _ => char::from_u32(code_point).ok_or_else(|| surrogate(code_point)),
    }
}

/// The refusal of the surrogate `code_point` (UEFI 2.11 §33.2.6.2.2 "UEFI does not support
/// surrogate characters").
fn surrogate(code_point: u32) -> anyhow::Error {
    anyhow!("SCSU character U+{code_point:04X} is a surrogate (UEFI 2.11 §33.2.6.2.2)")
}

#[cfg(test)]
pub(crate) mod tests {
    use super::decode;

    /// edk2's mLanguageWindow (edk2-stable202608 MdeModulePkg/Universal/HiiDatabaseDxe/String.c):
    /// UTS #6's static windows (Table 4), then its dynamic windows (Table 5).
    pub(crate) const EDK2_LANGUAGE_WINDOW: [u16; 16] = [
        0x0000, 0x0080, 0x0100, 0x0300, 0x2000, 0x2080, 0x2100, 0x3000, //
        0x0080, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00,
    ];

    /// A LanguageWindow of zeros, as every strings package of edk2's StrGather holds.
    const ZERO_LANGUAGE_WINDOW: [u16; 16] = [0; 16];

    /// EDK2_LANGUAGE_WINDOW with static window 0 at 0x0100.
    const STATIC_WINDOW_0_AT_0100: [u16; 16] = [
        0x0100, 0x0080, 0x0100, 0x0300, 0x2000, 0x2080, 0x2100, 0x3000, //
        0x0080, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00,
    ];

    /// EDK2_LANGUAGE_WINDOW with static window 7 at Greek, 0x0370, and dynamic window 0 at
    /// Cyrillic, 0x0400.
    const GREEK_AND_CYRILLIC: [u16; 16] = [
        0x0000, 0x0080, 0x0100, 0x0300, 0x2000, 0x2080, 0x2100, 0x0370, //
        0x0400, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00,
    ];

    /// EDK2_LANGUAGE_WINDOW with static window 1 at 0xD800, static window 2 at 0xFFF0 and
    /// dynamic window 0 at 0xFFC0.
    const WINDOWS_PAST_UCS2: [u16; 16] = [
        0x0000, 0xD800, 0xFFF0, 0x0300, 0x2000, 0x2080, 0x2100, 0x3000, //
        0xFFC0, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00,
    ];

    // UTS #6 revision 4 §9.1-§9.4: each example's code points, then its compressed bytes
    const DE_CODE_POINTS: [u32; 9] = [
        0x00D6, 0x006C, 0x0020, 0x0066, 0x006C, 0x0069, 0x0065, 0x00DF, 0x0074,
    ];
    const DE_SCSU: [u8; 9] = [0xD6, 0x6C, 0x20, 0x66, 0x6C, 0x69, 0x65, 0xDF, 0x74];
    const RU_CODE_POINTS: [u32; 6] = [0x041C, 0x043E, 0x0441, 0x043A, 0x0432, 0x0430];
    const RU_SCSU: [u8; 7] = [0x12, 0x9C, 0xBE, 0xC1, 0xBA, 0xB2, 0xB0];
    const JA_CODE_POINTS: [u32; 116] = [
        0x3000, 0x266A, 0x30EA, 0x30F3, 0x30B4, 0x53EF, 0x611B, 0x3044, 0x3084, 0x53EF, 0x611B,
        0x3044, 0x3084, 0x30EA, 0x30F3, 0x30B4, 0x3002, 0x534A, 0x4E16, 0x7D00, 0x3082, 0x524D,
        0x306B, 0x6D41, 0x884C, 0x3057, 0x305F, 0x300C, 0x30EA, 0x30F3, 0x30B4, 0x306E, 0x6B4C,
        0x300D, 0x304C, 0x3074, 0x3063, 0x305F, 0x308A, 0x3059, 0x308B, 0x304B, 0x3082, 0x3057,
        0x308C, 0x306A, 0x3044, 0x3002, 0x7C73, 0x30A2, 0x30C3, 0x30D7, 0x30EB, 0x30B3, 0x30F3,
        0x30D4, 0x30E5, 0x30FC, 0x30BF, 0x793E, 0x306E, 0x30D1, 0x30BD, 0x30B3, 0x30F3, 0x300C,
        0x30DE, 0x30C3, 0x30AF, 0xFF08, 0x30DE, 0x30C3, 0x30AD, 0x30F3, 0x30C8, 0x30C3, 0x30B7,
        0x30E5, 0xFF09, 0x300D, 0x3092, 0x3001, 0x3053, 0x3088, 0x306A, 0x304F, 0x611B, 0x3059,
        0x308B, 0x4EBA, 0x305F, 0x3061, 0x306E, 0x3053, 0x3068, 0x3060, 0x3002, 0x300C, 0x30A2,
        0x30C3, 0x30D7, 0x30EB, 0x4FE1, 0x8005, 0x300D, 0x306A, 0x3093, 0x3066, 0x8A00, 0x3044,
        0x65B9, 0x307E, 0x3067, 0x3042, 0x308B, 0x3002,
    ];
    const JA_SCSU: [u8; 178] = [
        0x08, 0x00, 0x1B, 0x4C, 0xEA, 0x16, 0xCA, 0xD3, 0x94, 0x0F, 0x53, 0xEF, 0x61, 0x1B, 0xE5,
        0x84, 0xC4, 0x0F, 0x53, 0xEF, 0x61, 0x1B, 0xE5, 0x84, 0xC4, 0x16, 0xCA, 0xD3, 0x94, 0x08,
        0x02, 0x0F, 0x53, 0x4A, 0x4E, 0x16, 0x7D, 0x00, 0x30, 0x82, 0x52, 0x4D, 0x30, 0x6B, 0x6D,
        0x41, 0x88, 0x4C, 0xE5, 0x97, 0x9F, 0x08, 0x0C, 0x16, 0xCA, 0xD3, 0x94, 0x15, 0xAE, 0x0E,
        0x6B, 0x4C, 0x08, 0x0D, 0x8C, 0xB4, 0xA3, 0x9F, 0xCA, 0x99, 0xCB, 0x8B, 0xC2, 0x97, 0xCC,
        0xAA, 0x84, 0x08, 0x02, 0x0E, 0x7C, 0x73, 0xE2, 0x16, 0xA3, 0xB7, 0xCB, 0x93, 0xD3, 0xB4,
        0xC5, 0xDC, 0x9F, 0x0E, 0x79, 0x3E, 0x06, 0xAE, 0xB1, 0x9D, 0x93, 0xD3, 0x08, 0x0C, 0xBE,
        0xA3, 0x8F, 0x08, 0x88, 0xBE, 0xA3, 0x8D, 0xD3, 0xA8, 0xA3, 0x97, 0xC5, 0x17, 0x89, 0x08,
        0x0D, 0x15, 0xD2, 0x08, 0x01, 0x93, 0xC8, 0xAA, 0x8F, 0x0E, 0x61, 0x1B, 0x99, 0xCB, 0x0E,
        0x4E, 0xBA, 0x9F, 0xA1, 0xAE, 0x93, 0xA8, 0xA0, 0x08, 0x02, 0x08, 0x0C, 0xE2, 0x16, 0xA3,
        0xB7, 0xCB, 0x0F, 0x4F, 0xE1, 0x80, 0x05, 0xEC, 0x60, 0x8D, 0xEA, 0x06, 0xD3, 0xE6, 0x0F,
        0x8A, 0x00, 0x30, 0x44, 0x65, 0xB9, 0xE4, 0xFE, 0xE7, 0xC2, 0x06, 0xCB, 0x82,
    ];
    const ALL_CODE_POINTS: [u32; 18] = [
        0x0041, 0x00DF, 0x0401, 0x015F, 0x00DF, 0x01DF, 0xF000, 0x10FFFF, 0x000D, 0x000A, 0x0041,
        0x00DF, 0x0401, 0x015F, 0x00DF, 0x01DF, 0xF000, 0x10FFFF,
    ];
    const ALL_SCSU: [u8; 35] = [
        0x41, 0xDF, 0x12, 0x81, 0x03, 0x5F, 0x10, 0xDF, 0x1B, 0x03, 0xDF, 0x1C, 0x88, 0x80, 0x0B,
        0xBF, 0xFF, 0xFF, 0x0D, 0x0A, 0x41, 0x10, 0xDF, 0x12, 0x81, 0x03, 0x5F, 0x10, 0xDF, 0x13,
        0xDF, 0x14, 0x80, 0x15, 0xFF,
    ];

    /// The string of `code_points`.
    fn text(code_points: &[u32]) -> String {
        code_points
            .iter()
            .map(|&code_point| char::from_u32(code_point).expect("a code point of UTS #6"))
            .collect()
    }

    /// decode's result for `bytes` under `language_window`, with the size of the string in bytes
    /// in place of the bytes after it, and its error as it renders.
    fn decoded(bytes: &[u8], language_window: &[u16; 16]) -> Result<(String, usize), String> {
        decode(bytes, language_window)
            .map(|(string, rest)| (string, bytes.len() - rest.len()))
            .map_err(|err| format!("{err:#}"))
    }

    /// decode reads UTS #6's examples of German, Russian and Japanese, given a null terminator,
    /// under edk2's LanguageWindow; §9.3 holds 0x00 bytes as tag arguments and in Unicode mode.
    #[test]
    fn decode_reads_the_uts_6_examples() {
        let examples: [(&str, &[u32], &[u8]); 3] = [
            ("9.1", &DE_CODE_POINTS, &DE_SCSU),
            ("9.2", &RU_CODE_POINTS, &RU_SCSU),
            ("9.3", &JA_CODE_POINTS, &JA_SCSU),
        ];
        for (example, code_points, scsu) in examples {
            let bytes = [scsu, &[0x00]].concat();

            assert_eq!(
                decoded(&bytes, &EDK2_LANGUAGE_WINDOW),
                Ok((text(code_points), bytes.len())),
                "UTS #6 §{example}"
            );
        }
    }

    /// decode reads UTS #6 §9.4 up to its seventh code point, U+F000, which it refuses (UEFI
    /// 2.11 §33.3.6.3.1).
    #[test]
    fn decode_refuses_the_uts_6_example_of_all_features_at_u_f000() {
        // SD4 0x88: window 4 at 0x88 * 0x80 + 0xAC00 = 0xF000, then its first character
        let before_f000 = [&ALL_SCSU[..11], &[0x00]].concat();
        let all = [&ALL_SCSU[..], &[0x00]].concat();

        assert_eq!(
            decoded(&before_f000, &EDK2_LANGUAGE_WINDOW),
            Ok((text(&ALL_CODE_POINTS[..6]), before_f000.len())),
            "the code points before U+F000"
        );
        assert_eq!(
            ALL_CODE_POINTS[6], 0xF000,
            "UTS #6 §9.4's seventh code point"
        );
        assert_eq!(
            decoded(&all, &EDK2_LANGUAGE_WINDOW),
            Err(
                "SCSU character U+F000 is between 0xF000 and 0xFCFF (UEFI 2.11 §33.3.6.3.1)"
                    .to_string()
            ),
            "UTS #6 §9.4"
        );
    }

    /// decode reads each tag of UTS #6 Tables 6 and 7 and each control code of UEFI 2.11 Table
    /// 33.3, up to the first decoded U+0000, whatever bytes follow.
    #[test]
    fn decode_reads_every_tag() {
        let e = &EDK2_LANGUAGE_WINDOW;
        // the case, its LanguageWindow and bytes, then the string and its size in bytes
        type Case = (
            &'static str,
            &'static [u16; 16],
            &'static [u8],
            &'static str,
            usize,
        );
        let cases: &[Case] = &[
            (
                "pass bytes",
                e,
                &[0x09, 0x0A, 0x0D, 0x20, 0x7E, 0x00],
                "\t\n\r ~",
                6,
            ),
            ("SQ0 00-7F", e, &[0x01, 0x41, 0x00], "A", 3),
            (
                "SQ0 7F, the character 0x7F",
                e,
                &[0x01, 0x7F, 0x00],
                "\u{7F}",
                3,
            ),
            ("SQ1 00-7F", e, &[0x02, 0x41, 0x00], "\u{C1}", 3),
            ("SQ7 00-7F", e, &[0x08, 0x01, 0x00], "\u{3001}", 3),
            ("SQ0 80-FF", e, &[0x01, 0x81, 0x00], "\u{81}", 3),
            ("SQ2 80-FF", e, &[0x03, 0x81, 0x00], "\u{401}", 3),
            ("SQ7 80-FF", e, &[0x08, 0x88, 0x00], "\u{FF08}", 3),
            (
                "dynamic window 0",
                e,
                &[0x80, 0xFF, 0x00],
                "\u{80}\u{FF}",
                3,
            ),
            (
                "SC1-SC7, then SC0",
                e,
                &[
                    0x11, 0x80, 0x12, 0x80, 0x13, 0x80, 0x14, 0x80, 0x15, 0x80, 0x16, 0x80, 0x17,
                    0x80, 0x10, 0x80, 0x00,
                ],
                "\u{C0}\u{400}\u{600}\u{900}\u{3040}\u{30A0}\u{FF00}\u{80}",
                17,
            ),
            ("SD0 01", e, &[0x18, 0x01, 0x80, 0x00], "\u{80}", 4),
            ("SD1 67", e, &[0x19, 0x67, 0xFF, 0x00], "\u{33FF}", 4),
            ("SD2 68", e, &[0x1A, 0x68, 0x80, 0x00], "\u{E000}", 4),
            ("SD3 A7", e, &[0x1B, 0xA7, 0x80, 0x00], "\u{FF80}", 4),
            ("SD4 F9", e, &[0x1C, 0xF9, 0x80, 0x00], "\u{C0}", 4),
            ("SD5 FA", e, &[0x1D, 0xFA, 0x80, 0x00], "\u{250}", 4),
            ("SD6 FB", e, &[0x1E, 0xFB, 0x80, 0x00], "\u{370}", 4),
            ("SD7 FC", e, &[0x1F, 0xFC, 0x80, 0x00], "\u{530}", 4),
            (
                "SD1 FB, then SC0",
                e,
                &[0x19, 0xFB, 0x10, 0x81, 0x00],
                "\u{81}",
                5,
            ),
            ("SD0 FD", e, &[0x18, 0xFD, 0x80, 0x00], "\u{3040}", 4),
            ("SD1 FE", e, &[0x19, 0xFE, 0x80, 0x00], "\u{30A0}", 4),
            ("SD2 FF", e, &[0x1A, 0xFF, 0x80, 0x00], "\u{FF60}", 4),
            ("SQU", e, &[0x0E, 0x4E, 0x2D, 0x00], "\u{4E2D}", 4),
            ("SQU EFFF", e, &[0x0E, 0xEF, 0xFF, 0x00], "\u{EFFF}", 4),
            ("SQU FD00", e, &[0x0E, 0xFD, 0x00, 0x00], "\u{FD00}", 4),
            (
                "SCU, UC0",
                e,
                &[0x0F, 0x4E, 0x2D, 0xE0, 0x41, 0x00],
                "\u{4E2D}A",
                6,
            ),
            ("SCU, UC5", e, &[0x0F, 0xE5, 0x82, 0x00], "\u{3042}", 4),
            (
                "SCU, UD1 FB",
                e,
                &[0x0F, 0xE9, 0xFB, 0x81, 0x00],
                "\u{371}",
                5,
            ),
            (
                "SCU, UD1 FB, then SC0",
                e,
                &[0x0F, 0xE9, 0xFB, 0x10, 0x81, 0x00],
                "\u{81}",
                6,
            ),
            (
                "SCU, UQU",
                e,
                &[0x0F, 0xF0, 0xE1, 0x23, 0x00, 0x00],
                "\u{E123}",
                6,
            ),
            (
                "SCU, FF 21",
                e,
                &[0x0F, 0xFF, 0x21, 0x00, 0x00],
                "\u{FF21}",
                5,
            ),
            (
                "SDX, then Basic Latin",
                e,
                &[0x0B, 0xBF, 0xFF, 0x41, 0x00],
                "A",
                5,
            ),
            (
                "SCU, UDX, then Basic Latin",
                e,
                &[0x0F, 0xF1, 0xBF, 0xFF, 0x41, 0x00],
                "A",
                6,
            ),
            (
                "control codes",
                e,
                &[
                    0x7F, 0x00, 0x05, 0x7F, 0x01, 0x18, 0x7F, 0x20, 0x7F, 0x2B, 0x00,
                ],
                "\u{F705}\u{F818}\u{F620}\u{F62B}",
                11,
            ),
            (
                "Font Family 7F 00 zz",
                e,
                &[0x41, 0x7F, 0x00, 0x01, 0x42, 0x00],
                "A\u{F701}B",
                6,
            ),
            (
                "Unicode mode 4E 00",
                e,
                &[0x0F, 0x4E, 0x00, 0x00, 0x00],
                "\u{4E00}",
                5,
            ),
            ("SQ7 00", e, &[0x08, 0x00, 0x00], "\u{3000}", 3),
            ("SQ0 00 ends it", e, &[0x41, 0x01, 0x00, 0x42], "A", 3),
            (
                "Unicode mode 00 00 ends it",
                e,
                &[0x0F, 0x41, 0x42, 0x00, 0x00, 0x43],
                "\u{4142}",
                5,
            ),
            (
                "SQU 00 00 ends it",
                e,
                &[0x41, 0x0E, 0x00, 0x00, 0x42],
                "A",
                4,
            ),
            (
                "a zero dynamic window 0 ends it at 80",
                &ZERO_LANGUAGE_WINDOW,
                &[0x41, 0x80, 0x42],
                "A",
                2,
            ),
            (
                "a zero dynamic window 0 maps 81 to U+0001",
                &ZERO_LANGUAGE_WINDOW,
                &[0x81, 0x00],
                "\u{1}",
                2,
            ),
            (
                "static window 7 at 0x0370",
                &GREEK_AND_CYRILLIC,
                &[0x08, 0x31, 0x00],
                "\u{3A1}",
                3,
            ),
            (
                "dynamic window 0 at 0x0400",
                &GREEK_AND_CYRILLIC,
                &[0x9F, 0x00],
                "\u{41F}",
                2,
            ),
            (
                "static window 0 moved: SC2 81",
                &STATIC_WINDOW_0_AT_0100,
                &[0x12, 0x81, 0x00],
                "\u{401}",
                3,
            ),
            (
                "static window 0 moved: SQ0 81",
                &STATIC_WINDOW_0_AT_0100,
                &[0x01, 0x81, 0x00],
                "\u{81}",
                3,
            ),
            (
                "static window 0 moved: SQ1 41",
                &STATIC_WINDOW_0_AT_0100,
                &[0x02, 0x41, 0x00],
                "\u{C1}",
                3,
            ),
            (
                "static window 0 moved: Unicode mode",
                &STATIC_WINDOW_0_AT_0100,
                &[0x0F, 0x00, 0x41, 0x00, 0x00],
                "A",
                5,
            ),
            (
                "static window 0 moved: control code",
                &STATIC_WINDOW_0_AT_0100,
                &[0x7F, 0x20, 0x00],
                "\u{F620}",
                3,
            ),
            ("an empty string", e, &[0x00], "", 1),
        ];
        for &(case, language_window, bytes, string, size) in cases {
            assert_eq!(
                decoded(bytes, language_window),
                Ok((string.to_string(), size)),
                "{case}: {bytes:02x?}"
            );
        }
    }

    /// decode refuses a string whose bytes end first, a byte that static window 0 would read
    /// otherwise than UTS #6's Basic Latin, an undefined control code, a reserved tag or window
    /// offset, and a character outside UCS-2, a surrogate or one between 0xF000 and 0xFCFF.
    #[test]
    fn decode_refuses_every_bad_string() {
        let e = &EDK2_LANGUAGE_WINDOW;
        let moved = &STATIC_WINDOW_0_AT_0100;
        let no_terminator = "the SCSU string has no null terminator";
        let static_window_0 = "static window 0 is 0x0100; UTS #6 reads bytes 20-7F both through \
                               it and as Basic Latin (UEFI 2.11 §33.3.6.3.1)";
        let cases: &[(&str, &[u16; 16], &[u8], &str)] = &[
            ("no bytes", e, &[], no_terminator),
            ("no terminator", e, &[0x41], no_terminator),
            ("SQ1 without its byte", e, &[0x02], no_terminator),
            (
                "SQU without its second byte",
                e,
                &[0x0E, 0x4E],
                no_terminator,
            ),
            ("SDn without its index", e, &[0x18], no_terminator),
            (
                "SDX without its second byte",
                e,
                &[0x0B, 0xBF],
                no_terminator,
            ),
            ("0x7F without its code", e, &[0x7F], no_terminator),
            ("7F 00 without its font", e, &[0x7F, 0x00], no_terminator),
            ("7F 01 without its size", e, &[0x7F, 0x01], no_terminator),
            (
                "a Unicode-mode character cut",
                e,
                &[0x0F, 0x4E],
                no_terminator,
            ),
            ("UDn without its index", e, &[0x0F, 0xE8], no_terminator),
            (
                "UQU without its second byte",
                e,
                &[0x0F, 0xF0, 0x12],
                no_terminator,
            ),
            (
                "UDX without its second byte",
                e,
                &[0x0F, 0xF1, 0x00],
                no_terminator,
            ),
            (
                "static window 0 moved: 41",
                moved,
                &[0x41, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: 09",
                moved,
                &[0x09, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: 0A",
                moved,
                &[0x0A, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: 0D",
                moved,
                &[0x0D, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: 20",
                moved,
                &[0x20, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: 7E",
                moved,
                &[0x7E, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: SQ0 00",
                moved,
                &[0x01, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved: SQ0 7F",
                moved,
                &[0x01, 0x7F, 0x00],
                static_window_0,
            ),
            (
                "static window 0 moved, after UC0",
                moved,
                &[0x0F, 0xE0, 0x41, 0x00],
                static_window_0,
            ),
            (
                "control code 0x7F 0x2C",
                e,
                &[0x7F, 0x2C, 0x00],
                "unknown control code 0x7F 0x2c (UEFI 2.11 Table 33.3)",
            ),
            (
                "control code 0x7F 0x1F",
                e,
                &[0x7F, 0x1F, 0x00],
                "unknown control code 0x7F 0x1f (UEFI 2.11 Table 33.3)",
            ),
            (
                "control code 0x7F 0x02",
                e,
                &[0x7F, 0x02, 0x00],
                "unknown control code 0x7F 0x02 (UEFI 2.11 Table 33.3)",
            ),
            ("tag 0C", e, &[0x0C, 0x00], "reserved SCSU tag 0x0c"),
            (
                "tag F2",
                e,
                &[0x0F, 0xF2, 0x00, 0x00],
                "reserved SCSU tag 0xf2",
            ),
            (
                "SD0 00",
                e,
                &[0x18, 0x00, 0x00],
                "reserved SCSU window offset 0x00",
            ),
            (
                "SD0 A8",
                e,
                &[0x18, 0xA8, 0x00],
                "reserved SCSU window offset 0xa8",
            ),
            (
                "SD0 F8",
                e,
                &[0x18, 0xF8, 0x00],
                "reserved SCSU window offset 0xf8",
            ),
            (
                "UD0 00",
                e,
                &[0x0F, 0xE8, 0x00, 0x00],
                "reserved SCSU window offset 0x00",
            ),
            (
                "SQU D800",
                e,
                &[0x0E, 0xD8, 0x00, 0x00],
                "SCSU character U+D800 is a surrogate (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "Unicode mode DFFF",
                e,
                &[0x0F, 0xDF, 0xFF, 0x00, 0x00],
                "SCSU character U+DFFF is a surrogate (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "SQ1 00 in static window 1 at 0xD800",
                &WINDOWS_PAST_UCS2,
                &[0x02, 0x00, 0x00],
                "SCSU character U+D800 is a surrogate (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "SQU F000",
                e,
                &[0x0E, 0xF0, 0x00, 0x00],
                "SCSU character U+F000 is between 0xF000 and 0xFCFF (UEFI 2.11 §33.3.6.3.1)",
            ),
            (
                "SQU FCFF",
                e,
                &[0x0E, 0xFC, 0xFF, 0x00],
                "SCSU character U+FCFF is between 0xF000 and 0xFCFF (UEFI 2.11 §33.3.6.3.1)",
            ),
            (
                "Unicode mode F620",
                e,
                &[0x0F, 0xF6, 0x20, 0x00, 0x00],
                "SCSU character U+F620 is between 0xF000 and 0xFCFF (UEFI 2.11 §33.3.6.3.1)",
            ),
            (
                "SDX of window 0 at 0x10000, then 80",
                e,
                &[0x0B, 0x00, 0x00, 0x80, 0x00],
                "SCSU character U+10000 is outside UCS-2 (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "SDX of window 5 at 0x10FF80, then SQ5 FF",
                e,
                &[0x0B, 0xBF, 0xFF, 0x06, 0xFF, 0x00],
                "SCSU character U+10FFFF is outside UCS-2 (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "UDX of window 0 at 0x10000, then 80",
                e,
                &[0x0F, 0xF1, 0x00, 0x00, 0x80, 0x00],
                "SCSU character U+10000 is outside UCS-2 (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "SQ2 7F in static window 2 at 0xFFF0",
                &WINDOWS_PAST_UCS2,
                &[0x03, 0x7F, 0x00],
                "SCSU character U+1006F is outside UCS-2 (UEFI 2.11 §33.2.6.2.2)",
            ),
            (
                "FF in dynamic window 0 at 0xFFC0",
                &WINDOWS_PAST_UCS2,
                &[0xFF, 0x00],
                "SCSU character U+1003F is outside UCS-2 (UEFI 2.11 §33.2.6.2.2)",
            ),
        ];
        for &(case, language_window, bytes, refusal) in cases {
            assert_eq!(
                decoded(bytes, language_window),
                Err(refusal.to_string()),
                "{case}: {bytes:02x?}"
            );
        }
    }
}
