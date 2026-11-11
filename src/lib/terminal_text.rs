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

//! Text that a HiiDB or an EFI variable holds, as uefisettings prints it on a terminal.

use std::fmt;
use std::fmt::Write;
use std::ops::RangeInclusive;

/// The Bidi_Control characters (Unicode 17.0 PropList.txt), which reorder the text after them.
const BIDI_CONTROLS: [RangeInclusive<char>; 4] = [
    '\u{61c}'..='\u{61c}',
    '\u{200e}'..='\u{200f}',
    '\u{202a}'..='\u{202e}',
    '\u{2066}'..='\u{2069}',
];

/// A text as uefisettings shows it to people: each control character (Unicode Cc: U+0000-U+001F
/// and U+007F-U+009F), each Bidi_Control character, U+2028 and U+2029 and `\` escaped as
/// `char::escape_debug` spells them, such as `\u{1b}`, `\r`, `\u{2028}` and `\\`. A terminal
/// would take the controls as commands, the Bidi_Control characters as a reordering of the text
/// after them and the separators as line breaks (UEFI 2.11 §33.2.6.2.5 Table 33.4), which would
/// rewrite what people read; the doubled `\` keeps every other text from showing as an escaped
/// one, though a console that shows a character as another, such as edk2-stable202608's VT100
/// terminal showing U+2510 as `\` (TerminalConOut.c:24, :260-261), can still make a text look
/// like an escape. JSON (JsonText) and thrift carry texts unchanged, and no input is unescaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TerminalText<'a>(pub &'a str);

impl fmt::Display for TerminalText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .chars()
            .try_for_each(|character| match is_escaped(character) {
                true => write!(f, "{}", character.escape_debug()),
                false => f.write_char(character),
            })
    }
}

/// Whether TerminalText escapes `character`.
fn is_escaped(character: char) -> bool {
    character == '\\'
        || character.is_control()
        || BIDI_CONTROLS.iter().any(|range| range.contains(&character))
        || matches!(character, '\u{2028}' | '\u{2029}')
}

/// A text in lines, each without its line break, so that a line may show a text that holds a
/// line break itself: TerminalText escapes that one, where it would start a line that the text
/// forges. Display ends each line with `\n`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct TextLines(pub Vec<String>);

impl TextLines {
    /// The lines, each without its line break.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(String::as_str)
    }
}

impl fmt::Display for TextLines {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.lines().try_for_each(|line| writeln!(f, "{line}"))
    }
}

/// A JSON text as uefisettings prints it: each character that TerminalText escapes and JSON
/// carries raw, U+007F-U+009F, Bidi_Control, U+2028 and U+2029, spelled as `\uXXXX`. A JSON text
/// holds them only inside strings, whose values stay the same: serde_json decodes the escape
/// (1.0.110 read.rs:863).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JsonText<'a>(pub &'a str);

impl fmt::Display for JsonText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .chars()
            .try_for_each(|character| match is_escaped_in_json(character) {
                true => write_json_escape(f, character),
                false => f.write_char(character),
            })
    }
}

/// Whether JsonText escapes `character`: whatever TerminalText escapes but `\` and U+0000-U+001F,
/// which serde_json escapes itself (1.0.110 ser.rs:2109-2127).
fn is_escaped_in_json(character: char) -> bool {
    is_escaped(character) && !matches!(character, '\\' | '\0'..='\u{1f}')
}

/// Writes `character` to `output` as a JSON string escapes it: `\u010d`, or the UTF-16 surrogate
/// pair of a character outside the BMP, `\ud83d\ude0a`.
fn write_json_escape(output: &mut impl Write, character: char) -> fmt::Result {
    character
        .encode_utf16(&mut [0; 2])
        .iter()
        .try_for_each(|unit| write!(output, "\\u{unit:04x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What TerminalText escapes, by code point: `\`, the control characters (Unicode 17.0
    /// UnicodeData.txt, category Cc), the Bidi_Control characters (PropList.txt) and U+2028 and
    /// U+2029.
    const ESCAPED: [RangeInclusive<char>; 8] = [
        '\\'..='\\',
        '\u{0}'..='\u{1f}',
        '\u{7f}'..='\u{9f}',
        '\u{61c}'..='\u{61c}',
        '\u{200e}'..='\u{200f}',
        '\u{202a}'..='\u{202e}',
        '\u{2066}'..='\u{2069}',
        '\u{2028}'..='\u{2029}',
    ];

    #[test]
    fn spells_escapes_as_escape_debug_does() {
        let cases = [
            ("A\u{1b}[2JB", "A\\u{1b}[2JB"),
            ("A\rB\nC\tD\0", "A\\rB\\nC\\tD\\0"),
            ("A\u{7}\u{8}\u{7f}B", "A\\u{7}\\u{8}\\u{7f}B"),
            ("A\u{85}\u{9b}B", "A\\u{85}\\u{9b}B"),
            ("A\u{61c}\u{200e}\u{200f}B", "A\\u{61c}\\u{200e}\\u{200f}B"),
            (
                "A\u{202a}\u{202e}\u{2066}\u{2069}B",
                "A\\u{202a}\\u{202e}\\u{2066}\\u{2069}B",
            ),
            ("A\u{2028}B\u{2029}C", "A\\u{2028}B\\u{2029}C"),
            ("C:\\EFI", "C:\\\\EFI"),
        ];
        for (text, want) in cases {
            assert_eq!(TerminalText(text).to_string(), want, "{text:?}");
        }
    }

    /// Every character outside ESCAPED shows as itself, such as quotes, combining marks, the
    /// spaces that are not Cc, the format characters that are not Bidi_Control and the font
    /// display codes of UEFI 2.11 §33.2.6.2.4.
    #[test]
    fn escapes_exactly_the_backslash_controls_bidi_controls_and_separators() {
        for character in '\u{0}'..=char::MAX {
            let text = character.to_string();
            let escaped = ESCAPED.iter().any(|range| range.contains(&character));
            assert_eq!(
                TerminalText(&text).to_string() != text,
                escaped,
                "U+{:04X}",
                u32::from(character)
            );
        }
    }

    /// A text that holds the escape of another shows apart from it.
    #[test]
    fn shows_texts_apart() {
        let texts = ["A\u{1b}B", "A\\u{1b}B", "A\\\\u{1b}B", "A\nB", "A\\nB"];

        let shown: Vec<String> = texts
            .iter()
            .map(|text| TerminalText(text).to_string())
            .collect();

        for (index, text) in shown.iter().enumerate() {
            assert_eq!(
                shown.iter().filter(|other| *other == text).count(),
                1,
                "{:?} shows as {text:?}",
                texts[index]
            );
        }
    }

    /// The JSON of a string of each character, through JsonText: the same string, and no
    /// character of ESCAPED but those that JSON itself escapes, `\` and U+0000-U+001F.
    #[test]
    fn json_text_keeps_every_string_and_escapes_what_json_carries_raw() {
        for character in '\u{0}'..=char::MAX {
            let json = serde_json::to_string(&character.to_string()).expect("serialize");

            let shown = JsonText(&json).to_string();

            let case = format!("U+{:04X}: {shown:?}", u32::from(character));
            let parsed: String = serde_json::from_str(&shown).expect(&case);
            assert_eq!(parsed, character.to_string(), "{case}");
            let raw = shown.chars().any(|shown| {
                ESCAPED.iter().any(|range| range.contains(&shown))
                    && !matches!(shown, '\\' | '\0'..='\u{1f}')
            });
            assert!(!raw, "{case}");
        }
    }

    #[test]
    fn json_text_spells_escapes_as_json_does() {
        let cases = [
            ("{\"a\":\"K\u{202e}K\"}", r#"{"a":"K\u202eK"}"#),
            (
                "[\"\u{7f}\u{85}\u{9b}\u{2028}\"]",
                r#"["\u007f\u0085\u009b\u2028"]"#,
            ),
            (r#"{"a":"\u001b\\\""}"#, r#"{"a":"\u001b\\\""}"#),
            (
                "{\"a\":\"\u{10d}\u{1f60a}\"}",
                "{\"a\":\"\u{10d}\u{1f60a}\"}",
            ),
        ];
        for (json, want) in cases {
            assert_eq!(JsonText(json).to_string(), want, "{json:?}");
        }
    }
}
