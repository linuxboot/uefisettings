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

//! EFI_KEY_OPTION (UEFI 2.11 §3.1.6), what a Key#### variable holds: a hot key that starts a
//! Boot#### load option, which the boot manager takes only while its BootOptionCrc is the CRC-32
//! of that Boot#### variable.

use std::fmt;

use serde::Serialize;
use serde::Serializer;
use thiserror::Error;

/// KeyData, BootOptionCrc and BootOption, before the keys
const KEY_OPTION_HEADER_SIZE: usize = 10;
/// Where BootOptionCrc starts, after KeyData, and where BootOption starts, after BootOptionCrc
const BOOT_OPTION_CRC_OFFSET: usize = 4;
const BOOT_OPTION_OFFSET: usize = 8;
/// ScanCode and UnicodeChar, the fields of an EFI_INPUT_KEY
const INPUT_KEY_SIZE: usize = 4;
/// The shift states and Reserved bits of KeyData, between Revision, its low byte, and
/// InputKeyCount, its top 2 bits
const MODIFIERS_MASK: u32 = 0x3FFF_FF00;
/// InputKeyCount, the top 2 bits of KeyData
const INPUT_KEY_COUNT_SHIFT: u32 = 30;

/// The scan codes of EFI_INPUT_KEY by their names after SCAN_, as edk2-stable202608
/// MdePkg/Include/Protocol/SimpleTextIn.h and SimpleTextInEx.h define them
const SCAN_CODES: [(u16, &str); 46] = [
    (0x0001, "UP"),
    (0x0002, "DOWN"),
    (0x0003, "RIGHT"),
    (0x0004, "LEFT"),
    (0x0005, "HOME"),
    (0x0006, "END"),
    (0x0007, "INSERT"),
    (0x0008, "DELETE"),
    (0x0009, "PAGE_UP"),
    (0x000A, "PAGE_DOWN"),
    (0x000B, "F1"),
    (0x000C, "F2"),
    (0x000D, "F3"),
    (0x000E, "F4"),
    (0x000F, "F5"),
    (0x0010, "F6"),
    (0x0011, "F7"),
    (0x0012, "F8"),
    (0x0013, "F9"),
    (0x0014, "F10"),
    (0x0015, "F11"),
    (0x0016, "F12"),
    (0x0017, "ESC"),
    (0x0048, "PAUSE"),
    (0x0068, "F13"),
    (0x0069, "F14"),
    (0x006A, "F15"),
    (0x006B, "F16"),
    (0x006C, "F17"),
    (0x006D, "F18"),
    (0x006E, "F19"),
    (0x006F, "F20"),
    (0x0070, "F21"),
    (0x0071, "F22"),
    (0x0072, "F23"),
    (0x0073, "F24"),
    (0x007F, "MUTE"),
    (0x0080, "VOLUME_UP"),
    (0x0081, "VOLUME_DOWN"),
    (0x0100, "BRIGHTNESS_UP"),
    (0x0101, "BRIGHTNESS_DOWN"),
    (0x0102, "SUSPEND"),
    (0x0103, "HIBERNATE"),
    (0x0104, "TOGGLE_DISPLAY"),
    (0x0105, "RECOVERY"),
    (0x0106, "EJECT"),
];

bitflags::bitflags! {
    /// The shift states of EFI_BOOT_KEY_DATA, each of which "must be pressed (1) or must not be
    /// pressed (0)" (UEFI 2.11 §3.1.6), and its Reserved bits, kept as read.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct KeyModifiers: u32 {
        const SHIFT = 1 << 8;
        const CONTROL = 1 << 9;
        const ALT = 1 << 10;
        const LOGO = 1 << 11;
        const MENU = 1 << 12;
        const SYS_REQ = 1 << 13;
    }
}

/// The shift states of EFI_BOOT_KEY_DATA, these names and Pressed (UEFI 2.11 §3.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KeyModifier {
    Shift,
    Control,
    Alt,
    Logo,
    Menu,
    SysReq,
}

impl KeyModifier {
    pub(crate) const ALL: [Self; 6] = [
        Self::Shift,
        Self::Control,
        Self::Alt,
        Self::Logo,
        Self::Menu,
        Self::SysReq,
    ];

    /// The name that variable get prints.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Shift => "shift",
            Self::Control => "control",
            Self::Alt => "alt",
            Self::Logo => "logo",
            Self::Menu => "menu",
            Self::SysReq => "sys-req",
        }
    }

    pub(crate) fn modifiers(self) -> KeyModifiers {
        match self {
            Self::Shift => KeyModifiers::SHIFT,
            Self::Control => KeyModifiers::CONTROL,
            Self::Alt => KeyModifiers::ALT,
            Self::Logo => KeyModifiers::LOGO,
            Self::Menu => KeyModifiers::MENU,
            Self::SysReq => KeyModifiers::SYS_REQ,
        }
    }
}

/// EFI_INPUT_KEY: a scan code, or a character with scan code 0 (edk2-stable202608
/// MdePkg/Include/Protocol/SimpleTextIn.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InputKey {
    pub scan_code: u16,
    pub unicode_char: u16,
}

/// The name of its scan code after SCAN_, such as F2, or its character; else
/// ScanCode=0x####,UnicodeChar=0x####.
impl fmt::Display for InputKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = SCAN_CODES
            .iter()
            .find(|(scan_code, _)| *scan_code == self.scan_code)
            .map(|(_, name)| *name);
        let character = char::from_u32(u32::from(self.unicode_char)).filter(|c| *c != '\0');
        match (self.scan_code, self.unicode_char, name, character) {
            (_, 0, Some(name), _) => f.write_str(name),
            (0, _, _, Some(character)) => write!(f, "{character}"),
            _ => write!(
                f,
                "ScanCode=0x{:04X},UnicodeChar=0x{:04X}",
                self.scan_code, self.unicode_char
            ),
        }
    }
}

/// As Display writes it.
impl Serialize for InputKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// An EFI_KEY_OPTION, what a Key#### variable holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyOption {
    /// KeyData.PackedValue, as read: Revision, the shift states, Reserved, InputKeyCount
    pub(crate) key_data: u32,
    /// The CRC-32 of the whole Boot#### variable that the key starts
    pub(crate) boot_option_crc: u32,
    /// The #### of the Boot#### that the key starts
    pub(crate) boot_option: u16,
    pub(crate) keys: Vec<InputKey>,
}

impl KeyOption {
    /// The EFI_KEY_OPTION that `bytes` hold: exactly InputKeyCount keys after its header, as
    /// edk2-stable202608 BmIsKeyOptionValid() (BmHotkey.c) requires.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, KeyOptionError> {
        let (header, keys) =
            bytes
                .split_first_chunk::<KEY_OPTION_HEADER_SIZE>()
                .ok_or(KeyOptionError::Length {
                    length: bytes.len(),
                    want: KEY_OPTION_HEADER_SIZE,
                })?;
        let [a, b, c, d, e, f, g, h, i, j] = *header;
        let key_data = u32::from_le_bytes([a, b, c, d]);
        let [count, ..] = (key_data >> INPUT_KEY_COUNT_SHIFT).to_le_bytes();
        let count = usize::from(count);
        match keys.as_chunks::<INPUT_KEY_SIZE>() {
            (keys, []) if keys.len() == count => Ok(Self {
                key_data,
                boot_option_crc: u32::from_le_bytes([e, f, g, h]),
                boot_option: u16::from_le_bytes([i, j]),
                keys: keys
                    .iter()
                    .map(|&[a, b, c, d]| InputKey {
                        scan_code: u16::from_le_bytes([a, b]),
                        unicode_char: u16::from_le_bytes([c, d]),
                    })
                    .collect(),
            }),
            _ => Err(KeyOptionError::Length {
                length: bytes.len(),
                want: KEY_OPTION_HEADER_SIZE + INPUT_KEY_SIZE * count,
            }),
        }
    }

    /// KeyData's Revision, which "should be 0" (UEFI 2.11 §3.1.6).
    pub(crate) fn revision(&self) -> u8 {
        let [revision, ..] = self.key_data.to_le_bytes();
        revision
    }

    /// KeyData's shift states and Reserved bits.
    pub(crate) fn modifiers(&self) -> KeyModifiers {
        KeyModifiers::from_bits_retain(self.key_data & MODIFIERS_MASK)
    }

    /// Whether the boot manager takes the key for the Boot#### that holds `boot_option_bytes`:
    /// "If the CRC-32s do not match this value, then this key option is ignored."
    pub(crate) fn matches(&self, boot_option_bytes: &[u8]) -> bool {
        self.boot_option_crc == boot_option_crc(boot_option_bytes)
    }
}

/// `bytes`, an EFI_KEY_OPTION, with BootOptionCrc `crc` and every other byte as read.
pub(crate) fn with_boot_option_crc(bytes: &[u8], crc: u32) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    if let Some(field) = changed.get_mut(BOOT_OPTION_CRC_OFFSET..BOOT_OPTION_OFFSET) {
        field.copy_from_slice(&crc.to_le_bytes());
    }
    changed
}

/// BootOptionCrc: "the CRC-32 of the entire EFI_LOAD_OPTION", the Boot#### variable's value,
/// after any EFI_VARIABLE_AUTHENTICATION_3 metadata (UEFI 2.11 §8.2.1), which edk2-stable202608
/// BmIsKeyOptionValid() hands to CalculateCrc32(): the CRC-32 of polynomial 0xEDB88320,
/// reflected, as crc32fast computes it.
pub(crate) fn boot_option_crc(boot_option_bytes: &[u8]) -> u32 {
    crc32fast::hash(boot_option_bytes)
}

/// Why bytes are no EFI_KEY_OPTION.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum KeyOptionError {
    #[error("an EFI_KEY_OPTION of {length} bytes is not the {want} that InputKeyCount gives")]
    Length { length: usize, want: usize },
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::efi_variables::device_path::tests::bytes;
    use crate::efi_variables::device_path::tests::AA64_BOOT0000;
    use crate::efi_variables::device_path::tests::X64_BOOT0000;

    /// The Key0000 that OVMF's boot manager wrote, F2 to Boot0000, read from the vars.fd of QEMU
    /// runs of Ubuntu's edk2 2024.02 builds (i686 equals x86_64)
    pub(crate) const X64_KEY0000: &str = "0000004051d7979f00000c000000";
    const AA64_KEY0000: &str = "000000405d4d80dd00000c000000";
    /// SCAN_F2 (edk2-stable202608 MdePkg/Include/Protocol/SimpleTextIn.h)
    const SCAN_F2: u16 = 0x000C;

    #[test]
    fn ovmf_hot_keys_carry_the_crc_32_of_their_whole_boot_option() {
        for (name, key, boot0000, other) in [
            ("x86_64", X64_KEY0000, X64_BOOT0000, AA64_BOOT0000),
            ("aarch64", AA64_KEY0000, AA64_BOOT0000, X64_BOOT0000),
        ] {
            let key = KeyOption::decode(&bytes(key)).expect("an OVMF Key0000");
            assert_eq!(key.key_data, 0x4000_0000, "{name}: one key, no shift state");
            assert_eq!(
                (key.revision(), key.modifiers()),
                (0, KeyModifiers::empty()),
                "{name}: revision and shift states"
            );
            assert_eq!(key.boot_option, 0, "{name}: Boot0000");
            assert_eq!(
                key.keys,
                [InputKey {
                    scan_code: SCAN_F2,
                    unicode_char: 0
                }],
                "{name}: F2"
            );
            assert!(
                key.matches(&bytes(boot0000)),
                "{name}: BootOptionCrc of its Boot0000"
            );
            assert!(
                !key.matches(&bytes(other)),
                "{name}: not of the other Boot0000"
            );
        }
    }

    /// KeyData's Revision, shift states, Reserved bits and InputKeyCount each land where
    /// EFI_BOOT_KEY_DATA puts them, as UEFI 2.11 §3.1.6 Example #2, CTRL-ALT-P-R, packs them.
    #[test]
    fn key_data_splits_into_its_fields() {
        let mut key = bytes(X64_KEY0000);
        key[..4].copy_from_slice(&0x8000_0600_u32.to_le_bytes());
        key.extend([0, 0, 0x72, 0]);
        key.splice(10..14, [0, 0, 0x70, 0]);
        let key = KeyOption::decode(&key).expect("CTRL-ALT-P-R");
        assert_eq!(
            (key.revision(), key.modifiers()),
            (0, KeyModifiers::CONTROL | KeyModifiers::ALT),
            "CTRL-ALT"
        );
        assert_eq!(
            key.keys.iter().map(ToString::to_string).collect::<Vec<_>>(),
            ["p", "r"],
            "P-R"
        );

        let mut odd = bytes(X64_KEY0000);
        odd[..4].copy_from_slice(&0x3FFF_C001_u32.to_le_bytes());
        odd.truncate(10);
        let odd = KeyOption::decode(&odd).expect("no key, every Reserved bit, revision 1");
        assert_eq!(odd.revision(), 1, "revision");
        assert_eq!(
            odd.modifiers().bits(),
            0x3FFF_C000,
            "the Reserved bits, outside the shift states"
        );
    }

    #[test]
    fn input_keys_read_as_their_scan_code_name_or_character() {
        for (scan_code, unicode_char, want) in [
            (0x000C, 0, "F2"),
            (0x0017, 0, "ESC"),
            (0x0105, 0, "RECOVERY"),
            (0x0106, 0, "EJECT"),
            (0, 0x0070, "p"),
            (0, 0x00E9, "\u{E9}"),
            (0x0099, 0, "ScanCode=0x0099,UnicodeChar=0x0000"),
            (0x000C, 0x0070, "ScanCode=0x000C,UnicodeChar=0x0070"),
            (0, 0xD800, "ScanCode=0x0000,UnicodeChar=0xD800"),
            (0, 0, "ScanCode=0x0000,UnicodeChar=0x0000"),
        ] {
            let key = InputKey {
                scan_code,
                unicode_char,
            };
            assert_eq!(key.to_string(), want, "{key:?}");
        }
    }

    #[test]
    fn key_options_refuse_a_length_other_than_input_key_count_gives() {
        let key = bytes(X64_KEY0000);
        for (name, bytes, want) in [
            ("a key more", [&key[..], &[0; 4]].concat(), 14),
            ("a key less", key[..10].to_vec(), 14),
            ("half a key more", [&key[..], &[0; 2]].concat(), 14),
            ("no header", key[..9].to_vec(), 10),
        ] {
            assert_eq!(
                KeyOption::decode(&bytes),
                Err(KeyOptionError::Length {
                    length: bytes.len(),
                    want
                }),
                "{name}"
            );
        }
    }

    #[test]
    fn boot_option_crc_is_the_crc_32_of_the_variable_as_read() {
        assert_eq!(
            boot_option_crc(b"123456789"),
            0xCBF4_3926,
            "the CRC-32 check value"
        );
        assert_eq!(
            boot_option_crc(&bytes(X64_BOOT0000)),
            0x9F97_D751,
            "the BootOptionCrc of OVMF's x86_64 Key0000"
        );
    }
}
