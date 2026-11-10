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

//! DATE and TIME questions (UEFI 2.11 §33.2.5.4.6, §33.2.5.4.11): their ops, where they keep
//! their values, and the text that get shows and set takes for them.

use std::fmt;
use std::ops::RangeInclusive;

use binrw::BinRead;
use thiserror::Error;

use super::storage::ValueLocation;
use super::time_storage::TimeStorage;
use super::Date;
use super::Question;
use super::QuestionHeader;
use super::Time;
use super::TypeValue;
use super::ValueEncoding;
use crate::hii::variables::VariableLayout;

/// The Flags bits of an EFI_IFR_DATE or EFI_IFR_TIME that suppress its fields, in text order:
/// EFI_QF_DATE_YEAR_SUPPRESS, _MONTH_ and _DAY_, or QF_TIME_HOUR_SUPPRESS, _MINUTE_ and _SECOND_
/// (UEFI 2.11 §33.3.8.3.11, §33.3.8.3.78).
const SUPPRESS: [u8; 3] = [0x01, 0x02, 0x04];
/// EFI_QF_DATE_STORAGE and QF_TIME_STORAGE, and their three valid values.
const STORAGE: u8 = 0x30;
const STORAGE_NORMAL: u8 = 0x00;
const STORAGE_TIME: u8 = 0x10;
const STORAGE_WAKEUP: u8 = 0x20;

/// The UINT64 that edk2-stable202608 SetupBrowserDxe/Expression.c HiiValueToUINT64 widens an
/// EFI_HII_DATE to, in arithmetic and bitwise ops: its bytes, little-endian.
pub(super) fn widened_date(bytes: [u8; 4]) -> u64 {
    u64::from(u32::from_le_bytes(bytes))
}

/// The UINT64 that HiiValueToUINT64 widens an EFI_HII_TIME to: its 3 bytes, little-endian.
pub(super) fn widened_time([hour, minute, second]: [u8; 3]) -> u64 {
    u64::from(u32::from_le_bytes([hour, minute, second, 0]))
}

/// Whether an op is an EFI_IFR_DATE or an EFI_IFR_TIME.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DateTimeKind {
    Date,
    Time,
}

impl DateTimeKind {
    /// The bytes of its value: an EFI_HII_DATE or an EFI_HII_TIME.
    pub(super) fn size(self) -> u8 {
        match self {
            Self::Date => 4,
            Self::Time => 3,
        }
    }

    /// The fields of its value, in text order.
    pub(super) fn fields(self) -> [Field; 3] {
        match self {
            Self::Date => [Field::Year, Field::Month, Field::Day],
            Self::Time => [Field::Hour, Field::Minute, Field::Second],
        }
    }

    fn separator(self) -> char {
        match self {
            Self::Date => '-',
            Self::Time => ':',
        }
    }

    /// The section of UEFI 2.11 that describes its question.
    fn section(self) -> &'static str {
        match self {
            Self::Date => "§33.2.5.4.6",
            Self::Time => "§33.2.5.4.11",
        }
    }

    /// Its text, as get shows it and set takes it.
    fn pattern(self) -> &'static str {
        match self {
            Self::Date => "YYYY-MM-DD",
            Self::Time => "HH:MM:SS",
        }
    }
}

impl fmt::Display for DateTimeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Date => "DATE",
            Self::Time => "TIME",
        })
    }
}

/// A field of an EFI_HII_DATE or an EFI_HII_TIME.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Field {
    Year,
    Month,
    Day,
    Hour,
    Minute,
    Second,
}

impl Field {
    /// Where it is in the bytes of its value, little-endian.
    pub(super) fn bytes(self) -> std::ops::Range<usize> {
        match self {
            Self::Year => 0..2,
            Self::Month => 2..3,
            Self::Day => 3..4,
            Self::Hour => 0..1,
            Self::Minute => 1..2,
            Self::Second => 2..3,
        }
    }

    /// The digits that get shows: of a year at least, of the others exactly.
    fn digits(self) -> usize {
        match self {
            Self::Year => 4,
            Self::Month | Self::Day | Self::Hour | Self::Minute | Self::Second => 2,
        }
    }

    /// Its value in `bytes`, the bytes of a value of its kind, an EFI_HII_TIME's then a 0.
    pub(super) fn value(self, &[first, second, third, fourth]: &[u8; 4]) -> u16 {
        match self {
            Self::Year => u16::from_le_bytes([first, second]),
            Self::Month | Self::Second => third.into(),
            Self::Day => fourth.into(),
            Self::Hour => first.into(),
            Self::Minute => second.into(),
        }
    }

    /// Puts `value` into `bytes`, the bytes of a value of its kind: a field of a byte takes its
    /// low byte.
    pub(super) fn put(self, [first, second, third, fourth]: &mut [u8; 4], value: u16) {
        let [low, high] = value.to_le_bytes();
        match self {
            Self::Year => (*first, *second) = (low, high),
            Self::Month | Self::Second => *third = low,
            Self::Day => *fourth = low,
            Self::Hour => *first = low,
            Self::Minute => *second = low,
        }
    }

    /// The exception to "which keep it" in Suppressed's text: a day that the new month or year
    /// lacks becomes adjusted_day's.
    fn kept_except(self) -> &'static str {
        match self {
            Self::Day => {
                ", except a day that the new month or year lacks, which becomes the month's last \
                 day after a month change, else 1"
            }
            Self::Year | Self::Month | Self::Hour | Self::Minute | Self::Second => "",
        }
    }

    /// The values that edk2-stable202608 DisplayEngineDxe/InputHandler.c lets a browser enter in
    /// it, where `bytes` hold the other fields: the days of the month and year of `bytes`.
    fn range(self, bytes: &[u8; 4]) -> RangeInclusive<u16> {
        match self {
            Self::Year => 1..=u16::MAX,
            Self::Month => 1..=12,
            Self::Day => {
                let year = Self::Year.value(bytes);
                let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
                match (Self::Month.value(bytes), leap) {
                    (2, true) => 1..=29,
                    (2, false) => 1..=28,
                    (4 | 6 | 9 | 11, _) => 1..=30,
                    _ => 1..=31,
                }
            }
            Self::Hour => 0..=23,
            Self::Minute | Self::Second => 0..=59,
        }
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Year => "year",
            Self::Month => "month",
            Self::Day => "day",
            Self::Hour => "hour",
            Self::Minute => "minute",
            Self::Second => "second",
        })
    }
}

/// The UEFI Storage of a DATE or TIME, which its Flags give.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DateTimeStorage {
    /// The question's Value Storage only
    Normal,
    /// EFI Date/Time Storage, in addition to any Value Storage
    Efi(TimeStorage),
    /// 0x30, none of the three valid values
    Reserved,
}

/// An EFI_IFR_DATE (UEFI 2.11 §33.3.8.3.11) or EFI_IFR_TIME (§33.3.8.3.78), which have the same
/// fields.
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(kind: DateTimeKind, layout: VariableLayout))]
pub struct DateTimeQuestion {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(calc = kind)]
    pub kind: DateTimeKind,
    #[br(calc = layout)]
    layout: VariableLayout,
}

impl Question for DateTimeQuestion {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

impl DateTimeQuestion {
    pub(crate) fn storage(&self) -> DateTimeStorage {
        match self.flags & STORAGE {
            STORAGE_NORMAL => DateTimeStorage::Normal,
            STORAGE_TIME => DateTimeStorage::Efi(TimeStorage::SystemTime),
            STORAGE_WAKEUP => DateTimeStorage::Efi(TimeStorage::WakeupTime),
            _ => DateTimeStorage::Reserved,
        }
    }

    /// Its EFI Date/Time Storage, if any.
    pub(crate) fn time_storage(&self) -> Option<TimeStorage> {
        match self.storage() {
            DateTimeStorage::Efi(storage) => Some(storage),
            DateTimeStorage::Normal | DateTimeStorage::Reserved => None,
        }
    }

    /// Where it keeps its value on its VarStore: its EFI_HII_DATE or EFI_HII_TIME at VarOffset, or
    /// at byte 0 of the variable of its VarName.
    pub(super) fn location(&self) -> ValueLocation {
        ValueLocation::Bytes {
            offset: self.layout.offset(self.question_header.var_store_info),
            size: self.kind.size().into(),
        }
    }

    /// How it stores its value; never in a bit field, which edk2-stable202608 IfrParse.c reads
    /// only of a ONE_OF or NUMERIC (:2061) or a CHECKBOX (:2192).
    pub(super) fn encoding(&self) -> ValueEncoding {
        match self.layout {
            VariableLayout::Offsets => ValueEncoding::NumericSize,
            VariableLayout::OneValue => ValueEncoding::VarName,
        }
    }

    pub(super) fn format(&self) -> DateTimeFormat {
        DateTimeFormat {
            kind: self.kind,
            flags: self.flags,
        }
    }
}

/// How get shows and set reads the value of a DATE or TIME: its kind and the fields that its
/// Flags suppress, which a browser neither displays nor updates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DateTimeFormat {
    kind: DateTimeKind,
    flags: u8,
}

impl DateTimeFormat {
    /// The fields of the value, each with whether the question suppresses it.
    fn fields(self) -> impl Iterator<Item = (Field, bool)> {
        self.kind
            .fields()
            .into_iter()
            .zip(SUPPRESS)
            .map(move |(field, bit)| (field, self.flags & bit != 0))
    }

    /// get's text of `value`, the bytes of the value little-endian: YYYY-MM-DD or HH:MM:SS, with
    /// dashes in each field that the question suppresses.
    pub(super) fn text(self, value: u64) -> String {
        let bytes = value_bytes(value);
        let fields: Vec<String> = self
            .fields()
            .map(|(field, suppressed)| match suppressed {
                true => "-".repeat(field.digits()),
                false => format!("{:0width$}", field.value(&bytes), width = field.digits()),
            })
            .collect();
        fields.join(&self.kind.separator().to_string())
    }

    /// set's value for `text`, as get shows a value: digits in each field that the question does
    /// not suppress, within edk2's ranges, and dashes in each that it does, which keep that field
    /// of `stored`, the value as get reads it, or why it cannot be read. A kept day that the new
    /// month or year lacks becomes adjusted_day's.
    pub(super) fn value(
        self,
        text: &str,
        stored: Result<u64, &str>,
    ) -> Result<TypeValue, DateTimeTextError> {
        let bytes = self.given_bytes(self.parse(text)?, stored)?;
        Ok(self.typed(bytes))
    }

    /// set's value for `number`, a keyword VALUE: every field of the value, little-endian, which
    /// SetData() writes as given. A field that the question does not suppress is taken as value
    /// takes its digits; one that it suppresses must be what set writes there, as value keeps it
    /// from `stored`, for a VALUE has no dashes.
    pub(super) fn number_value(
        self,
        number: u64,
        stored: Result<u64, &str>,
    ) -> Result<TypeValue, DateTimeTextError> {
        let value = value_bytes(number);
        let mut fields = [None; 3];
        for ((field, suppressed), slot) in self.fields().zip(&mut fields) {
            *slot = (!suppressed).then(|| u32::from(field.value(&value)));
        }
        let bytes = self.given_bytes(fields, stored)?;
        for (field, suppressed) in self.fields() {
            let (given, written) = (field.value(&value), field.value(&bytes));
            if suppressed && given != written {
                return Err(DateTimeTextError::SuppressedChanged {
                    kind: self.kind,
                    field,
                    given,
                    written,
                });
            }
        }
        Ok(self.typed(bytes))
    }

    /// The bytes of set's value with `given`, the number in each field in text order, None for
    /// each that the question suppresses (value).
    fn given_bytes(
        self,
        given: [Option<u32>; 3],
        stored: Result<u64, &str>,
    ) -> Result<[u8; 4], DateTimeTextError> {
        let mut bytes = [0; 4];
        if self.fields().any(|(_, suppressed)| suppressed) {
            let stored = stored.map_err(|reason| DateTimeTextError::StoredUnreadable {
                kind: self.kind,
                reason: reason.to_owned(),
            })?;
            bytes = value_bytes(stored);
        }
        let kept = bytes;
        for ((field, suppressed), value) in self.fields().zip(given) {
            match (suppressed, value) {
                (true, None) => {}
                (true, Some(_)) => {
                    return Err(DateTimeTextError::Suppressed {
                        kind: self.kind,
                        field,
                    })
                }
                (false, None) => {
                    return Err(DateTimeTextError::NotSuppressed {
                        kind: self.kind,
                        field,
                    })
                }
                (false, Some(value)) => {
                    let value =
                        u16::try_from(value).map_err(|_| DateTimeTextError::OutOfRange {
                            field,
                            value,
                            range: field.range(&bytes),
                        })?;
                    field.put(&mut bytes, value);
                }
            }
        }
        if self.fields().any(|field| field == (Field::Day, true)) {
            let day = adjusted_day(&kept, &bytes);
            Field::Day.put(&mut bytes, day);
        }
        // after every field: the days of a month depend on the year and month
        for ((field, suppressed), value) in self.fields().zip(given) {
            let range = field.range(&bytes);
            match (suppressed, value) {
                (false, Some(value)) if !range.contains(&field.value(&bytes)) => {
                    return Err(DateTimeTextError::OutOfRange {
                        field,
                        value,
                        range,
                    });
                }
                (false | true, _) => {}
            }
        }
        Ok(bytes)
    }

    /// The value of `bytes`, the fields of a value of its kind.
    fn typed(self, [first, second, third, fourth]: [u8; 4]) -> TypeValue {
        match self.kind {
            DateTimeKind::Date => TypeValue::Date(Date::from_bytes([first, second, third, fourth])),
            DateTimeKind::Time => TypeValue::Time(Time::from_bytes([first, second, third])),
        }
    }

    /// The number in each field of `text`, in text order; None for dashes.
    fn parse(self, text: &str) -> Result<[Option<u32>; 3], DateTimeTextError> {
        let malformed = || DateTimeTextError::Malformed {
            kind: self.kind,
            text: text.to_owned(),
        };
        let parts = match self.kind {
            // the year takes any number of digits, the other fields two, from the end: dashes
            // separate fields and fill suppressed ones
            DateTimeKind::Date => {
                let (year, rest) = text
                    .len()
                    .checked_sub(6)
                    .and_then(|at| text.split_at_checked(at))
                    .ok_or_else(malformed)?;
                match (rest.as_bytes(), rest.get(1..3), rest.get(4..6)) {
                    ([b'-', _, _, b'-', _, _], Some(first), Some(second)) => [year, first, second],
                    _ => return Err(malformed()),
                }
            }
            DateTimeKind::Time => {
                let parts: Vec<&str> = text.split(':').collect();
                <[&str; 3]>::try_from(parts).map_err(|_| malformed())?
            }
        };
        let mut numbers = [None; 3];
        for ((field, part), number) in self.kind.fields().into_iter().zip(parts).zip(&mut numbers) {
            *number = match (field, part.len()) {
                _ if part == "-".repeat(field.digits()) => None,
                (Field::Year, 1..=5) | (_, 2) if part.bytes().all(|byte| byte.is_ascii_digit()) => {
                    Some(part.parse().map_err(|_| malformed())?)
                }
                _ => return Err(malformed()),
            };
        }
        Ok(numbers)
    }
}

/// The bytes of the fields of `value`, the bytes of an EFI_HII_DATE, or of an EFI_HII_TIME then a
/// 0, little-endian.
fn value_bytes(value: u64) -> [u8; 4] {
    let [first, second, third, fourth, ..] = value.to_le_bytes();
    [first, second, third, fourth]
}

/// The day of `bytes`, a date whose day set keeps from `kept`, the stored date, as a browser
/// adjusts it after an edit of the month or year (edk2-stable202608
/// DisplayEngineDxe/InputHandler.c AdjustQuestionValue): a day past the end of the month becomes
/// its last day after a month edit (:361-363), and 1 after a year edit (:370-372). Of the two
/// orders in which a browser can edit the year and month, this gives the larger day for a valid
/// stored date: the month's rule with the new year, the year's rule only where the month stays.
fn adjusted_day(kept: &[u8; 4], bytes: &[u8; 4]) -> u16 {
    let changed = |field: Field| field.value(kept) != field.value(bytes);
    let day = Field::Day.value(bytes);
    let maximum = *Field::Day.range(bytes).end();
    match (changed(Field::Month), changed(Field::Year)) {
        (true, _) => day.min(maximum),
        (false, true) if day > maximum => 1,
        (false, _) => day,
    }
}

/// What set needs to take the text of a DATE or TIME: how it reads it, and the value stored, whose
/// suppressed fields it keeps, or why it cannot be read.
#[derive(Debug)]
pub(super) struct DateTimeInput {
    pub(super) format: DateTimeFormat,
    pub(super) stored: Result<u64, String>,
}

impl DateTimeInput {
    /// The value that `text` sets.
    pub(super) fn value(&self, text: &str) -> Result<TypeValue, DateTimeTextError> {
        self.format
            .value(text, self.stored.as_ref().copied().map_err(String::as_str))
    }

    /// The value that `number`, a keyword VALUE, sets (DateTimeFormat::number_value).
    pub(super) fn number_value(&self, number: u64) -> Result<TypeValue, DateTimeTextError> {
        self.format.number_value(
            number,
            self.stored.as_ref().copied().map_err(String::as_str),
        )
    }
}

/// Why set does not take the text of a DATE or TIME.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum DateTimeTextError {
    #[error(
        "{kind} value {text:?} is not {}, with dashes in each field that the question suppresses",
        .kind.pattern()
    )]
    Malformed { kind: DateTimeKind, text: String },
    #[error(
        "the {field} of this {kind} is suppressed (UEFI 2.11 {}): give dashes there, which keep \
         it{}",
        .kind.section(),
        .field.kept_except()
    )]
    Suppressed { kind: DateTimeKind, field: Field },
    #[error("the {field} of this {kind} is not suppressed: give its digits, not dashes")]
    NotSuppressed { kind: DateTimeKind, field: Field },
    /// A keyword VALUE whose suppressed field differs from what set writes there
    #[error(
        "the {field} of this {kind} is suppressed (UEFI 2.11 {}), and set writes it as \
         {written}, not {given}",
        .kind.section()
    )]
    SuppressedChanged {
        kind: DateTimeKind,
        field: Field,
        given: u16,
        written: u16,
    },
    #[error("{field} {value} is outside {} to {}", .range.start(), .range.end())]
    OutOfRange {
        field: Field,
        value: u32,
        range: RangeInclusive<u16>,
    },
    #[error(
        "cannot keep the suppressed fields of this {kind}: its stored value cannot be read: \
         {reason}"
    )]
    StoredUnreadable { kind: DateTimeKind, reason: String },
}
