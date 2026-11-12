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

//! String questions (UEFI 2.11 §33.2.5.4.9, §33.3.8.3.70): the NULL-terminated UCS-2 string that
//! one on a VarStore holds, which get shows and set writes.

use std::cell::RefCell;
use std::num::NonZeroU8;
use std::rc::Rc;

use binrw::BinRead;
use thiserror::Error;

use super::conditions::ExpressionInputs;
use super::conditions::QuestionValues;
use super::conditions::StateEvaluation;
use super::defaults::buffer_defaults;
use super::defaults::push_default;
use super::defaults::DefaultError;
use super::set::ChangeValueError;
use super::storage::read_buffer;
use super::storage::BufferExpression;
use super::storage::BufferQuestion;
use super::storage::ValueLocation;
use super::storage::ValueSource;
use super::storage::ValueUnavailable;
use super::storage::VariableStore;
use super::FormSetWalk;
use super::IFROperation;
use super::Question;
use super::QuestionDescriptor;
use super::QuestionFlags;
use super::QuestionHeader;
use super::QuestionIdentity;
use super::TextInput;
use crate::hii::strings::is_control_character;
use crate::hii::strings::PRIVATE_USE_AREA;
use crate::hii::variables::VariableLayout;

/// The bytes of a CHAR16, a character of a string (UEFI 2.11 §33.2.6).
const CHAR16_SIZE: u16 = 2;

/// The Flags bit EFI_IFR_STRING_MULTI_LINE, without which "multi-line editing should not be
/// allowed" (UEFI 2.11 §33.3.8.3.70).
const EFI_IFR_STRING_MULTI_LINE: u8 = 0x01;

/// The Mandatory Breaks of UEFI 2.11 §33.2.6.2.5 Table 33.4, which force a line break.
const MANDATORY_BREAKS: [char; 5] = ['\u{A}', '\u{C}', '\u{D}', '\u{2028}', '\u{2029}'];

/// An EFI_IFR_STRING (UEFI 2.11 §33.3.8.3.70).
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(layout: VariableLayout))]
pub struct StringQuestion {
    pub question_header: QuestionHeader,
    pub min_size: u8,
    pub max_size: u8,
    pub flags: u8,
    #[br(calc = layout)]
    pub(super) layout: VariableLayout,
}

impl Question for StringQuestion {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

impl StringQuestion {
    /// The bytes of its value, MaxSize CHAR16s: the StorageWidth of edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c:2225.
    pub(super) fn storage_width(&self) -> u16 {
        u16::from(self.max_size) * CHAR16_SIZE
    }

    /// Where one on a VarStore keeps its value: storage_width bytes from VarOffset, or from byte 0
    /// of the variable of its VarName.
    pub(super) fn location(&self) -> ValueLocation {
        ValueLocation::Bytes {
            offset: self.layout.offset(self.question_header.var_store_info),
            size: self.storage_width(),
        }
    }

    /// `bytes`, the CHAR16s of a default's string, cut to storage_width, as edk2-stable202608
    /// SetupBrowserDxe/Setup.c:4507-4511 GetQuestionDefault copies at most StorageWidth bytes of
    /// it.
    pub(super) fn default_bytes<'b>(&self, bytes: &'b [u8]) -> &'b [u8] {
        bytes
            .get(..usize::from(self.storage_width()))
            .unwrap_or(bytes)
    }

    /// The text of `bytes`, a default's CHAR16s, cut by default_bytes.
    fn default_text(&self, bytes: &[u8]) -> Result<String, DefaultError> {
        stored_text(self.default_bytes(bytes)).map_err(DefaultError::StringText)
    }
}

/// A CHAR16 of a STRING that is a UTF-16 surrogate, no UCS-2 character.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "its character {index} is CHAR16 {unit:#06x}, a UTF-16 surrogate, which UCS-2 has no \
     character for (UEFI 2.11 §33.2.6.2.2)"
)]
pub(super) struct NotUcs2 {
    index: usize,
    unit: u16,
}

/// The CHAR16s of `bytes`, little-endian, up to the first NULL, or all of them without one, as
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c:2229 keeps one more CHAR16, zero, after them.
fn stored_units(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    let (units, _) = bytes.as_chunks::<2>();
    units
        .iter()
        .map(|&unit| u16::from_le_bytes(unit))
        .take_while(|&unit| unit != 0)
}

/// The text of `bytes`, the CHAR16s of a STRING that stored_units takes.
pub(super) fn stored_text(bytes: &[u8]) -> Result<String, NotUcs2> {
    stored_units(bytes)
        .enumerate()
        .map(|(index, unit)| char::from_u32(u32::from(unit)).ok_or(NotUcs2 { index, unit }))
        .collect()
}

/// Why set refuses to give a STRING a value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum StringRefusal {
    #[error(
        "the STRING takes at most {most} characters, its last CHAR16 of MaxSize {max_size} \
         holding the NULL (UEFI 2.11 §33.2.5.4.9), not {given}",
        most = .max_size.get() - 1
    )]
    TooLong { max_size: NonZeroU8, given: usize },
    #[error("the STRING takes at least {min} characters (MinSize), not {given}")]
    TooShort { min: u8, given: usize },
    #[error(
        "the STRING of MaxSize 0 has no CHAR16 for the NULL that ends it (UEFI 2.11 \
         §33.2.5.4.9), so it takes no VALUE"
    )]
    NoNull,
    #[error(
        "the STRING takes at least {min_size} characters (MinSize) and at most {most}, its last \
         CHAR16 of MaxSize {max_size} holding the NULL (UEFI 2.11 §33.2.5.4.9), so it takes no \
         VALUE",
        most = .max_size.get() - 1
    )]
    NoLength { min_size: u8, max_size: NonZeroU8 },
    #[error(
        "{0:?} (U+{code:04X}) has no UCS-2 character, which the STRING stores (UEFI 2.11 \
         §33.2.6.2.2)",
        code = u32::from(*.0)
    )]
    NotUcs2(char),
    #[error(
        "{0:?} (U+{code:04X}) lies in the Private Use Area, U+E000..U+F8FF, which UEFI 2.11 \
         §33.2.6.2.1 prohibits",
        code = u32::from(*.0)
    )]
    PrivateUse(char),
    #[error(
        "the STRING is single-line (no EFI_IFR_STRING_MULTI_LINE, UEFI 2.11 §33.3.8.3.70), so it \
         takes no line break"
    )]
    LineBreak,
    #[error("a NULL character ends a STRING, which takes none within (UEFI 2.11 §33.2.5.4.9)")]
    Null,
    #[error("{0}")]
    Expression(BufferExpression),
    #[error("the STRING holds characters, not a number")]
    NotNumber,
}

impl StringRefusal {
    /// set's error for `question` that it refuses so.
    pub(super) fn of(self, question: &QuestionDescriptor) -> ChangeValueError {
        ChangeValueError::String {
            question: question.question.clone(),
            refusal: self,
        }
    }
}

/// The bytes that set writes to the CHAR16s of a STRING, at VarOffset `offset`.
pub(super) struct StringWrite {
    pub(super) offset: u16,
    pub(super) bytes: Vec<u8>,
}

/// Whether a STRING takes line breaks: with EFI_IFR_STRING_MULTI_LINE in its Flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lines {
    Single,
    Multi,
}

impl Lines {
    /// The Lines of a STRING of `flags`.
    fn of(flags: u8) -> Self {
        match flags & EFI_IFR_STRING_MULTI_LINE {
            0 => Self::Single,
            _ => Self::Multi,
        }
    }
}

/// How set takes the text of a STRING: where its CHAR16s are, its MinSize and MaxSize, and
/// whether it takes line breaks.
pub(super) struct StringInput {
    offset: u16,
    min_size: u8,
    max_size: u8,
    lines: Lines,
}

impl StringInput {
    /// The write that gives the STRING `text`: its UCS-2 CHAR16s, NULL-padded to MaxSize. It
    /// takes at most MaxSize − 1 characters, so that a NULL ends them within the field (UEFI 2.11
    /// §33.2.5.4.9: "the buffer size must exceed the size of the NULL-terminated string"), where
    /// edk2-stable202608 DisplayEngineDxe/InputHandler.c:260 takes MaxSize: then
    /// Library/UefiHiiLib/HiiLib.c:1833 StrLen reads past the field, DriverSampleDxe/
    /// DriverSample.c:2012-2022 unloads the driver whose settings fail that check, and MdePkg
    /// BaseLib/SafeString.c:256-259 StrCpyS fails on the field. A STRING whose MaxSize leaves no
    /// length from MinSize takes nothing. It refuses a NULL, a character that UCS-2 has none for
    /// or that lies in the Private Use Area outside the Common Control Codes, a Mandatory Break
    /// where single-line, and fewer characters than MinSize, as InputHandler.c:209 does.
    pub(super) fn write(&self, text: &str) -> Result<StringWrite, StringRefusal> {
        let max_size = NonZeroU8::new(self.max_size).ok_or(StringRefusal::NoNull)?;
        let most = max_size.get() - 1;
        if self.min_size > most {
            return Err(StringRefusal::NoLength {
                min_size: self.min_size,
                max_size,
            });
        }
        let units = text
            .chars()
            .map(|character| self.unit(character))
            .collect::<Result<Vec<u16>, StringRefusal>>()?;
        let given = units.len();
        if given > usize::from(most) {
            return Err(StringRefusal::TooLong { max_size, given });
        }
        if given < usize::from(self.min_size) {
            return Err(StringRefusal::TooShort {
                min: self.min_size,
                given,
            });
        }
        let mut bytes = vec![0; usize::from(self.max_size) * usize::from(CHAR16_SIZE)];
        bytes
            .iter_mut()
            .zip(units.iter().flat_map(|unit| unit.to_le_bytes()))
            .for_each(|(byte, unit)| *byte = unit);
        Ok(StringWrite {
            offset: self.offset,
            bytes,
        })
    }

    /// The CHAR16 of `character`, which ends a STRING if NULL, breaks its line if a Mandatory
    /// Break of UEFI 2.11 §33.2.6.2.5 Table 33.4, is of the Private Use Area only as a Common
    /// Control Code of §33.2.6.2.4 Table 33.3, which strings may hold, and is no UCS-2 character
    /// beyond U+FFFF. edk2-stable202608 DisplayEngineDxe/InputHandler.c ignores
    /// EFI_IFR_STRING_MULTI_LINE, ends input at CR (:208) and stores any other typed character,
    /// LF and the Private Use Area too (:256-262).
    fn unit(&self, character: char) -> Result<u16, StringRefusal> {
        match character {
            '\0' => Err(StringRefusal::Null),
            character if self.lines == Lines::Single && MANDATORY_BREAKS.contains(&character) => {
                Err(StringRefusal::LineBreak)
            }
            character
                if PRIVATE_USE_AREA.contains(&u32::from(character))
                    && !is_control_character(character) =>
            {
                Err(StringRefusal::PrivateUse(character))
            }
            character => {
                u16::try_from(u32::from(character)).map_err(|_| StringRefusal::NotUcs2(character))
            }
        }
    }
}

/// The answer that show-ifr shows for the STRING `question` of the op `node` on `varstore`: its
/// text as get shows it, or why it has none.
pub(super) fn display_string_answer(
    node: &Rc<RefCell<IFROperation>>,
    varstore: &anyhow::Result<Box<dyn VariableStore>>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> String {
    match read_text(node, varstore, inputs) {
        Ok((text, source)) => text + source.annotation(),
        Err(reason) => reason.to_answer(),
    }
}

/// The text of the STRING of the op `node` on `varstore` and where it comes from, or why it has
/// none.
fn read_text(
    node: &Rc<RefCell<IFROperation>>,
    varstore: &anyhow::Result<Box<dyn VariableStore>>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Result<(String, ValueSource), ValueUnavailable> {
    let (bytes, source) = read_buffer(node, BufferQuestion::String, varstore, inputs.reader)?;
    let text = stored_text(&bytes).map_err(ValueUnavailable::StoredString)?;
    Ok((text, source))
}

/// The QuestionDescriptor of the STRING `question`: its text, else why it has none and its
/// default.
pub(super) fn handle_string(
    varstore: anyhow::Result<Box<dyn VariableStore>>,
    question: &StringQuestion,
    prompt: &str,
    flags: QuestionFlags,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let texts = walk.texts;
    let stored = read_text(node, &varstore, &mut walk.inputs);
    let stores = walk.default_stores.of(current_node, &mut walk.inputs);
    let defaults = buffer_defaults(
        current_node,
        BufferQuestion::String,
        stores,
        texts,
        &mut walk.inputs,
        |bytes| question.default_text(bytes),
    );
    let (answer, value_source) = match stored {
        Ok(stored) => stored,
        Err(reason) => {
            let mut answer = reason.to_answer();
            push_default(&mut answer, &defaults, stores);
            (answer, ValueSource::Current)
        }
    };
    let header = question.question_header();
    QuestionDescriptor {
        question: prompt.trim().to_string(),
        value: answer,
        help: texts.display(header.help_string_id).to_string(),
        possible_options: Vec::new(),
        // StoragelessQuestion::refusal refuses one that its driver holds
        driver_held: None,
        varstore,
        location: question.location(),
        input: TextInput::String(StringInput {
            offset: question.layout.offset(header.var_store_info),
            min_size: question.min_size,
            max_size: question.max_size,
            lines: Lines::of(question.flags),
        }),
        opcode: current_node.op_code,
        flags,
        defaults,
        identity: QuestionIdentity::of(current_node, &header, texts),
        value_state: StateEvaluation::selectable(),
        value_source,
        node: Rc::clone(node),
    }
}

#[cfg(test)]
mod tests {
    use super::stored_text;
    use super::stored_units;
    use super::Lines;
    use super::NotUcs2;
    use super::StringInput;
    use super::StringRefusal;
    use std::num::NonZeroU8;

    /// The little-endian CHAR16s of `units`.
    fn bytes_of(units: &[u16]) -> Vec<u8> {
        units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
    }

    /// A StringInput at VarOffset 6 of MinSize `min_size`, MaxSize `max_size` and `lines`.
    fn input(min_size: u8, max_size: u8, lines: Lines) -> StringInput {
        StringInput {
            offset: 6,
            min_size,
            max_size,
            lines,
        }
    }

    /// The NonZeroU8 `value`.
    fn non_zero(value: u8) -> NonZeroU8 {
        NonZeroU8::new(value).expect("a MaxSize above 0")
    }

    /// stored_units takes the CHAR16s up to the first NULL, all of them without one, and
    /// stored_text refuses a surrogate before that NULL only.
    #[test]
    fn stored_text_ends_at_the_first_null() {
        let cases: [(&str, Vec<u16>, Result<&str, NotUcs2>); 6] = [
            ("empty", vec![], Ok("")),
            ("null first", vec![0, 0x41], Ok("")),
            ("null-terminated", vec![0x41, 0x42, 0, 0x43], Ok("AB")),
            ("no null", vec![0x41, 0xFFFD, 0x20AC], Ok("A\u{FFFD}€")),
            (
                "surrogate",
                vec![0x41, 0xDFFF],
                Err(NotUcs2 {
                    index: 1,
                    unit: 0xDFFF,
                }),
            ),
            ("surrogate after the null", vec![0x41, 0, 0xD800], Ok("A")),
        ];
        for (case, units, want) in cases {
            assert_eq!(
                stored_text(&bytes_of(&units)),
                want.map(str::to_owned),
                "{case}"
            );
        }
        assert_eq!(
            stored_units(&bytes_of(&[0x41, 0xD800, 0, 0x42])).collect::<Vec<u16>>(),
            [0x41, 0xD800],
            "units up to the NULL, a surrogate among them"
        );
    }

    /// write NULL-pads the CHAR16s of at most MaxSize − 1 characters to MaxSize, at the STRING's
    /// offset, takes Mandatory Breaks with EFI_IFR_STRING_MULTI_LINE, and the Common Control
    /// Codes.
    #[test]
    fn write_null_pads_the_text_to_max_size() {
        let cases: [(StringInput, &str, Vec<u16>); 8] = [
            (input(1, 3, Lines::Single), "A", vec![0x41, 0, 0]),
            (
                input(1, 3, Lines::Single),
                "\u{FFFF}b",
                vec![0xFFFF, 0x62, 0],
            ),
            (input(1, 3, Lines::Single), "ab", vec![0x61, 0x62, 0]),
            (input(0, 1, Lines::Single), "", vec![0]),
            (input(2, 3, Lines::Multi), "\r\n", vec![0x0D, 0x0A, 0]),
            (input(0, 3, Lines::Single), "\u{F900}", vec![0xF900, 0, 0]),
            (
                input(0, 3, Lines::Multi),
                "\u{C}\u{2028}",
                vec![0x0C, 0x2028, 0],
            ),
            (
                input(0, 3, Lines::Single),
                "\u{F620}\u{F8FF}",
                vec![0xF620, 0xF8FF, 0],
            ),
        ];
        for (input, text, units) in cases {
            let write = input.write(text).expect("write the text");
            assert_eq!(
                (write.offset, write.bytes),
                (6, bytes_of(&units)),
                "{text:?}"
            );
        }
    }

    /// write refuses every text of a STRING whose MaxSize leaves no length from MinSize, then a
    /// NULL, a character beyond UCS-2, one of the Private Use Area outside the Common Control
    /// Codes or a Mandatory Break of a single-line STRING wherever it is, before it counts
    /// characters against MinSize and MaxSize − 1.
    #[test]
    fn write_refuses_what_the_string_cannot_hold() {
        let cases = [
            (
                input(2, 4, Lines::Single),
                "abcd",
                StringRefusal::TooLong {
                    max_size: non_zero(4),
                    given: 4,
                },
            ),
            (
                input(2, 4, Lines::Single),
                "a",
                StringRefusal::TooShort { min: 2, given: 1 },
            ),
            (
                input(2, 4, Lines::Single),
                "",
                StringRefusal::TooShort { min: 2, given: 0 },
            ),
            (input(2, 4, Lines::Single), "ab\0", StringRefusal::Null),
            (input(2, 4, Lines::Multi), "\0", StringRefusal::Null),
            (
                input(2, 4, Lines::Single),
                "abcd\u{10000}",
                StringRefusal::NotUcs2('\u{10000}'),
            ),
            (
                input(2, 4, Lines::Single),
                "a\u{E000}",
                StringRefusal::PrivateUse('\u{E000}'),
            ),
            (
                input(2, 4, Lines::Multi),
                "\u{F6FF}b",
                StringRefusal::PrivateUse('\u{F6FF}'),
            ),
            (input(2, 4, Lines::Single), "a\nb", StringRefusal::LineBreak),
            (input(2, 4, Lines::Single), "a\rb", StringRefusal::LineBreak),
            (
                input(2, 4, Lines::Single),
                "a\u{C}b",
                StringRefusal::LineBreak,
            ),
            (
                input(2, 4, Lines::Single),
                "a\u{2028}b",
                StringRefusal::LineBreak,
            ),
            (
                input(2, 4, Lines::Single),
                "a\u{2029}b",
                StringRefusal::LineBreak,
            ),
            (
                input(2, 4, Lines::Single),
                "a\u{F61F}",
                StringRefusal::PrivateUse('\u{F61F}'),
            ),
            (
                input(2, 4, Lines::Single),
                "a\u{F62C}",
                StringRefusal::PrivateUse('\u{F62C}'),
            ),
            (input(0, 0, Lines::Single), "", StringRefusal::NoNull),
            (input(0, 0, Lines::Single), "a", StringRefusal::NoNull),
            (
                input(4, 4, Lines::Single),
                "abcd",
                StringRefusal::NoLength {
                    min_size: 4,
                    max_size: non_zero(4),
                },
            ),
            (
                input(5, 4, Lines::Single),
                "abc",
                StringRefusal::NoLength {
                    min_size: 5,
                    max_size: non_zero(4),
                },
            ),
        ];
        for (input, text, want) in cases {
            assert_eq!(
                input.write(text).map(|write| write.bytes),
                Err(want),
                "{text:?}"
            );
        }
    }

    /// Lines takes EFI_IFR_STRING_MULTI_LINE alone from the Flags.
    #[test]
    fn lines_follow_the_multi_line_flag() {
        for (flags, want) in [
            (0x00, Lines::Single),
            (0x01, Lines::Multi),
            (0xFE, Lines::Single),
            (0xFF, Lines::Multi),
        ] {
            assert_eq!(Lines::of(flags), want, "Flags {flags:#04x}");
        }
    }
}
