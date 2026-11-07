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

//! The Capsule Services of the UEFI Shell build: QueryCapsuleCapabilities() and UpdateCapsule()

//! Bytes in JSON: as {"text": ...} if they are UTF-8, as JSON text exchanged between systems is
//! (RFC 8259 §8.1), else as {"hex": ...}, lowercase.

use serde::ser::SerializeMap;
use serde::Serialize;
use serde::Serializer;

/// Bytes that serialize as {"hex": ...}, lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hex<'a>(pub &'a [u8]);

impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let hex: String = self.0.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("hex", &hex)?;
        map.end()
    }
}

/// Bytes that serialize as {"text": ...} if they are UTF-8, else as Hex does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextOrHex<'a>(pub &'a [u8]);

impl Serialize for TextOrHex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Ok(text) = std::str::from_utf8(self.0) else {
            return Hex(self.0).serialize(serializer);
        };
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("text", text)?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TextOrHex gives UTF-8 as text, empty or not, and the rest as lowercase hex; Hex gives
    /// lowercase hex, UTF-8 or not.
    #[test]
    fn bytes_serialize_as_text_or_hex() {
        for (bytes, text_or_hex, hex) in [
            (
                br#"{"a":"\u00e9"}"#.to_vec(),
                serde_json::json!({ "text": "{\"a\":\"\\u00e9\"}" }),
                "7b2261223a225c7530306539227d",
            ),
            (
                "é".as_bytes().to_vec(),
                serde_json::json!({ "text": "é" }),
                "c3a9",
            ),
            (Vec::new(), serde_json::json!({ "text": "" }), ""),
            (
                vec![0xff, 0x00, 0xab],
                serde_json::json!({ "hex": "ff00ab" }),
                "ff00ab",
            ),
            (vec![0xc3], serde_json::json!({ "hex": "c3" }), "c3"),
        ] {
            assert_eq!(
                serde_json::to_value(TextOrHex(&bytes)).expect("serialize TextOrHex"),
                text_or_hex,
                "TextOrHex {bytes:?}"
            );
            assert_eq!(
                serde_json::to_value(Hex(&bytes)).expect("serialize Hex"),
                serde_json::json!({ "hex": hex }),
                "Hex {bytes:?}"
            );
        }
    }
}
