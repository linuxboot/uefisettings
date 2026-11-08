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

//! Bytes written as hex digits, two per byte, as config strings (hii/config_string.rs) and the
//! nonces of EFI_VARIABLE_AUTHENTICATION_3 writes (efi_variables/enhanced_authenticated.rs) take
//! them.

/// The bytes of `digits`, two hex digits per byte in order, as `<Guid>` and `<PathHdr>` list them.
pub(crate) fn hex_bytes<B: FromIterator<u8>>(digits: &str) -> Option<B> {
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => hex_byte(*high, *low),
            _ => None,
        })
        .collect()
}

pub(crate) fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some((hex_digit(high)? << 4) | hex_digit(low)?)
}

/// The value of a hex digit of either case: `<HexCh>` is lowercase, but EDK2's StrHexToUint64
/// reads both and §35.4.6's example has "AA55".
pub(crate) fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// hex_bytes takes two hex digits of either case per byte, in order, and no odd count or
    /// other character.
    #[test]
    fn hex_bytes_takes_two_digits_per_byte() {
        let cases: [(&str, Option<Vec<u8>>); 6] = [
            ("", Some(vec![])),
            ("00ff", Some(vec![0x00, 0xFF])),
            ("aA5a", Some(vec![0xAA, 0x5A])),
            ("a", None),
            ("abc", None),
            ("0g", None),
        ];
        for (digits, want) in cases {
            assert_eq!(hex_bytes::<Vec<u8>>(digits), want, "{digits:?}");
        }
    }
}
