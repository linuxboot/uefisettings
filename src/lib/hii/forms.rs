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

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::Infallible;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::rc::Weak;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;
use binrw::BinResult;
use log::debug;
use thiserror::Error;

use crate::chattr::EfivarsImmutabilityGuard;
use crate::file_lock::FileLock;
use crate::hii::efivarfs::open_efivar;
use crate::hii::efivarfs::EfivarFileName;
use crate::hii::efivarfs::EfivarNotFound;
use crate::hii::efivarfs::EfivarRange;
use crate::hii::efivarfs::EfivarReader;
use crate::hii::efivarfs::EfivarsMountGuard;
use crate::hii::efivarfs::EfivarsNotRead;
use crate::hii::efivarfs::EFIVARFS_HEADER_SIZE;
use crate::hii::efivarfs::EFIVARS_MOUNT_POINT;
use crate::hii::package::Guid;
use conditions::option_state;
use conditions::question_state;
use conditions::select;
use conditions::skips_scope;
use conditions::ExpressionInputs;
use conditions::QuestionValues;
use conditions::StateEvaluation;
use conditions::VarStoreValues;
use defaults::option_text;
use defaults::push_default;
use defaults::question_scope;
use defaults::DefaultId;
use defaults::FormSetDefaultIds;

pub use conditions::IncludedStates;
pub use conditions::QuestionState;
pub use conditions::SelectionError;

pub(crate) use conditions::Choice;
pub(crate) use conditions::Selection;

mod conditions;
mod defaults;
#[cfg(test)]
pub(crate) mod ifr_fixtures;

const DUMMY_OPCODE: u8 = 0xFFu8; // doesn't correspond to any known IFROpCode
const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x00000004;
// UEFI 2.10 §33.3.8.3.47
const EFI_IFR_NUMERIC_SIZE: u8 = 0x03;
const EFI_IFR_NUMERIC_SIZE_1: u8 = 0x00;
const EFI_IFR_NUMERIC_SIZE_2: u8 = 0x01;
const EFI_IFR_NUMERIC_SIZE_4: u8 = 0x02;
const EFI_IFR_DISPLAY: u8 = 0x30;
const EFI_IFR_DISPLAY_INT_DEC: u8 = 0x00;
// UEFI 2.10 §33.3.8.3.51
const EFI_IFR_TYPE_NUM_SIZE_8: u8 = 0x00;
const EFI_IFR_TYPE_NUM_SIZE_16: u8 = 0x01;
const EFI_IFR_TYPE_NUM_SIZE_32: u8 = 0x02;
const EFI_IFR_TYPE_NUM_SIZE_64: u8 = 0x03;
const EFI_IFR_TYPE_BOOLEAN: u8 = 0x04;
const EFI_IFR_TYPE_OTHER: u8 = 0x08;
// edk2-stable202608 MdeModulePkg/Include/Guid/MdeModuleHii.h; the GUID is
// 82DDD68B-9163-4187-9B27-20A8FD60A71D, here in its EFI_GUID byte order
const EDKII_IFR_BIT_VARSTORE_GUID: [u8; 16] = [
    0x8B, 0xD6, 0xDD, 0x82, 0x63, 0x91, 0x87, 0x41, 0x9B, 0x27, 0x20, 0xA8, 0xFD, 0x60, 0xA7, 0x1D,
];
const EDKII_IFR_DISPLAY_BIT: u8 = 0xC0;
const EDKII_IFR_DISPLAY_INT_DEC_BIT: u8 = 0x00;
const EDKII_IFR_NUMERIC_SIZE_BIT: u8 = 0x3F;
// edk2-stable202608 BaseTools VfrCompile stores bit-field values as UINT32 (VfrSyntax.g) and
// caps their width at MAX_BIT_WIDTH 32 (VfrUtilityLib.h)
const EDKII_BIT_FIELD_VALUE_BITS: u32 = 32;

/// IFR_OPERATION_HEADER_SIZE is the size of EFI_IFR_OP_HEADER, which starts
/// every IFR operation (IFROperation): OpCode (8 bits), Length (7 bits) and
/// Scope (1 bit). UEFI Spec v2.10 §33.3.8.2.1 defines Length as "the number of
/// bytes in the opcode, including this header"; §33.3.8.1 gives it as 2-127
/// bytes, so "opcode" is the whole operation, not the OpCode byte (IFROpCode).
///
/// Example: Length includes the header, so an operation carries
/// `length - IFR_OPERATION_HEADER_SIZE` bytes of data.
const IFR_OPERATION_HEADER_SIZE: u8 = 2;

fn update_efivarfs_bytes(
    bytes: &mut [u8],
    payload_size: u16,
    offset: u16,
    data: TypeValue,
) -> Result<()> {
    let encoded = match data {
        TypeValue::NumSize8(value) => value.to_le_bytes().to_vec(),
        TypeValue::NumSize16(value) => value.to_le_bytes().to_vec(),
        TypeValue::NumSize32(value) => value.to_le_bytes().to_vec(),
        TypeValue::NumSize64(value) => value.to_le_bytes().to_vec(),
        _ => return Err(anyhow!("unsupported value type for efivarfs write")),
    };
    let payload = bytes
        .get_mut(EFIVARFS_HEADER_SIZE..)
        .context("efivarfs file is missing its attributes header")?;
    if payload.len() < usize::from(payload_size) {
        return Err(anyhow!(
            "efivarfs payload is shorter than the declared varstore: {} < {} bytes",
            payload.len(),
            payload_size
        ));
    }

    let start = usize::from(offset);
    let end = start + encoded.len();
    if end > usize::from(payload_size) {
        return Err(anyhow!(
            "write at offset {} with width {} exceeds varstore size {}",
            offset,
            encoded.len(),
            payload_size
        ));
    }
    payload[start..end].copy_from_slice(&encoded);
    Ok(())
}

// UEFI Spec v2.9 Page 1844
#[derive(BinRead, Debug, PartialEq, Copy, Clone)]
// binrw tries the variants in order; by default it collects every miss's
// error in a Vec that grows up to 100 entries and is dropped per opcode
#[br(little, return_unexpected_error)]
pub enum IFROpCode {
    #[br(magic = 0x01u8)]
    Form,
    #[br(magic = 0x02u8)]
    Subtitle,
    #[br(magic = 0x03u8)]
    Text,
    #[br(magic = 0x04u8)]
    Image,
    #[br(magic = 0x05u8)]
    OneOf,
    #[br(magic = 0x06u8)]
    CheckBox,
    #[br(magic = 0x07u8)]
    Numeric,
    #[br(magic = 0x08u8)]
    Password,
    #[br(magic = 0x09u8)]
    OneOfOption,
    #[br(magic = 0x0Au8)]
    SuppressIf,
    #[br(magic = 0x0Bu8)]
    Locked,
    #[br(magic = 0x0Cu8)]
    Action,
    #[br(magic = 0x0Du8)]
    ResetButton,
    #[br(magic = 0x0Eu8)]
    FormSet,
    #[br(magic = 0x0Fu8)]
    Ref,
    #[br(magic = 0x10u8)]
    NoSubmitIf,
    #[br(magic = 0x11u8)]
    InconsistentIf,
    #[br(magic = 0x12u8)]
    EqIdVal,
    #[br(magic = 0x13u8)]
    EqIdId,
    #[br(magic = 0x14u8)]
    EqIdValList,
    #[br(magic = 0x15u8)]
    And,
    #[br(magic = 0x16u8)]
    Or,
    #[br(magic = 0x17u8)]
    Not,
    #[br(magic = 0x18u8)]
    Rule,
    #[br(magic = 0x19u8)]
    GrayOutIf,
    #[br(magic = 0x1Au8)]
    Date,
    #[br(magic = 0x1Bu8)]
    Time,
    #[br(magic = 0x1Cu8)]
    String,
    #[br(magic = 0x1Du8)]
    Refresh,
    #[br(magic = 0x1Eu8)]
    DisableIf,
    #[br(magic = 0x1Fu8)]
    Animation,
    #[br(magic = 0x20u8)]
    ToLower,
    #[br(magic = 0x21u8)]
    ToUpper,
    #[br(magic = 0x22u8)]
    Map,
    #[br(magic = 0x23u8)]
    OrderedList,
    #[br(magic = 0x24u8)]
    VarStore,
    #[br(magic = 0x25u8)]
    VarStoreNameValue,
    #[br(magic = 0x26u8)]
    VarStoreEfi,
    #[br(magic = 0x27u8)]
    VarStoreDevice,
    #[br(magic = 0x28u8)]
    Version,
    #[br(magic = 0x29u8)]
    End,
    #[br(magic = 0x2Au8)]
    Match,
    #[br(magic = 0x2Bu8)]
    Get,
    #[br(magic = 0x2Cu8)]
    Set,
    #[br(magic = 0x2Du8)]
    Read,
    #[br(magic = 0x2Eu8)]
    Write,
    #[br(magic = 0x2Fu8)]
    Equal,
    #[br(magic = 0x30u8)]
    NotEqual,
    #[br(magic = 0x31u8)]
    GreaterThan,
    #[br(magic = 0x32u8)]
    GreaterEqual,
    #[br(magic = 0x33u8)]
    LessThan,
    #[br(magic = 0x34u8)]
    LessEqual,
    #[br(magic = 0x35u8)]
    BitwiseAnd,
    #[br(magic = 0x36u8)]
    BitwiseOr,
    #[br(magic = 0x37u8)]
    BitwiseNot,
    #[br(magic = 0x38u8)]
    ShiftLeft,
    #[br(magic = 0x39u8)]
    ShiftRight,
    #[br(magic = 0x3Au8)]
    Add,
    #[br(magic = 0x3Bu8)]
    Subtract,
    #[br(magic = 0x3Cu8)]
    Multiply,
    #[br(magic = 0x3Du8)]
    Divide,
    #[br(magic = 0x3Eu8)]
    Modulo,
    #[br(magic = 0x3Fu8)]
    RuleRef,
    #[br(magic = 0x40u8)]
    QuestionRef1,
    #[br(magic = 0x41u8)]
    QuestionRef2,
    #[br(magic = 0x42u8)]
    Uint8,
    #[br(magic = 0x43u8)]
    Uint16,
    #[br(magic = 0x44u8)]
    Uint32,
    #[br(magic = 0x45u8)]
    Uint64,
    #[br(magic = 0x46u8)]
    True,
    #[br(magic = 0x47u8)]
    False,
    #[br(magic = 0x48u8)]
    ToUint,
    #[br(magic = 0x49u8)]
    ToString,
    #[br(magic = 0x4Au8)]
    ToBoolean,
    #[br(magic = 0x4Bu8)]
    Mid,
    #[br(magic = 0x4Cu8)]
    Find,
    #[br(magic = 0x4Du8)]
    Token,
    #[br(magic = 0x4Eu8)]
    StringRef1,
    #[br(magic = 0x4Fu8)]
    StringRef2,
    #[br(magic = 0x50u8)]
    Conditional,
    #[br(magic = 0x51u8)]
    QuestionRef3,
    #[br(magic = 0x52u8)]
    Zero,
    #[br(magic = 0x53u8)]
    One,
    #[br(magic = 0x54u8)]
    Ones,
    #[br(magic = 0x55u8)]
    Undefined,
    #[br(magic = 0x56u8)]
    Length,
    #[br(magic = 0x57u8)]
    Dup,
    #[br(magic = 0x58u8)]
    This,
    #[br(magic = 0x59u8)]
    Span,
    #[br(magic = 0x5Au8)]
    Value,
    #[br(magic = 0x5Bu8)]
    Default,
    #[br(magic = 0x5Cu8)]
    DefaultStore,
    #[br(magic = 0x5Du8)]
    FormMap,
    #[br(magic = 0x5Eu8)]
    Catenate,
    #[br(magic = 0x5Fu8)]
    Guid,
    #[br(magic = 0x60u8)]
    Security,
    #[br(magic = 0x61u8)]
    ModalTag,
    #[br(magic = 0x62u8)]
    RefreshId,
    #[br(magic = 0x63u8)]
    WarningIf,
    #[br(magic = 0x64u8)]
    Match2,
    Unknown(u8),
}

/// IFROperation is a node for a tree data structure.
/// In HiiDB the opcodes + data are in a series/list.
/// However, here we will use the open_scope boolean field + the end opcode (which marks end of scope)
/// to generate an HTML like DOM tree.
#[derive(BinRead)]
#[br(little)]
pub struct IFROperation {
    pub op_code: IFROpCode,
    #[br(restore_position, map = |x: u8| x  & 0x7F)]
    // only store the first 7 bits and then move the cursor back to position before this field
    //
    // the assert below rejects a length below the header size, because binrw
    // computes `count` further down without a bounds check (debug builds panic
    // on underflow, release builds wrap); no upper bound is needed, as a 7-bit
    // length reserves at most 125 bytes
    #[br(assert(
        length >= IFR_OPERATION_HEADER_SIZE,
        "invalid IFR operation length {}",
        length
    ))]
    length: u8, // size of the entire operation, including the header
    #[br(map = |x: u8| x & 0x80 != 0)]
    // read 8 bits, discard all of them except the last one
    pub open_scope: bool,
    #[br(count = usize::from(length - IFR_OPERATION_HEADER_SIZE))]
    data: Vec<u8>,

    // the following fields will not be parsed by binrw and when an instance of this struct is created
    // they'll get the default values until we change them
    #[br(default)]
    pub parent: Option<Weak<RefCell<IFROperation>>>,
    #[br(default)]
    pub children: Vec<Rc<RefCell<IFROperation>>>,
    #[br(default)]
    pub parsed_data: ParsedOperation,
}

// Debug is implemented manually because if we derived Debug instead then we'd
// get a stack overflow caused by parent printing child which will try to print it's parent....
impl fmt::Debug for IFROperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IFROperation")
            .field("op_code", &self.op_code)
            .field("open_scope", &self.open_scope)
            .field("length", &self.length)
            .field("children", &self.children)
            .finish()
    }
}

#[derive(Debug, Default)]
pub enum ParsedOperation {
    FormSet(FormSet),
    OneOf(OneOf),
    CheckBox(CheckBox),
    OneOfOption(OneOfOption),
    VarStore(VarStore),
    VarStoreNameValue(VarStoreNameValue),
    VarStoreEfi(VarStoreEfi),
    DefaultStore(DefaultStore),
    IFRDefault(IFRDefault),
    #[expect(dead_code, reason = "decoded IFR payload; nothing reads it yet")]
    Form(Form),
    #[expect(dead_code, reason = "decoded IFR payload; nothing reads it yet")]
    Text(Text),
    Subtitle(Subtitle),
    Numeric(Numeric),
    QuestionRef1(QuestionRef1),
    EqIdVal(EqIdVal),
    EqIdId(EqIdId),
    EqIdValList(EqIdValList),
    #[default]
    Placeholder,
}

// Documentation for subsequent structs at:
// UEFI Spec v2.9 Pages 1840 - 1916

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct FormSet {
    pub guid: Guid,
    pub title_string_id: u16,
    pub help_string_id: u16,
    pub flags: u8,
    pub class_guid: Guid,
}

pub trait Question {
    fn question_header(&self) -> QuestionHeader;
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
// In the UEFI spec question header's first field is statement header
// however instead of having a separate nested struct I've combined it together
pub struct QuestionHeader {
    // start of statement header
    pub prompt_string_id: u16,
    pub help_string_id: u16,
    // rest of the question header
    pub question_id: u16,
    pub var_store_id: u16,
    pub var_store_info: u16, // an offset except in case of VarStoreNameValue where it'll be a string_id
    pub question_flags: u8,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: RangeEncoding))]
pub struct OneOf {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags, encoding))]
    pub data: Range,
}

impl Question for OneOf {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: RangeEncoding))]
pub struct Numeric {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags, encoding))]
    pub data: Range,
}

impl Question for Numeric {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

// Note: there is nothing called Range in the spec.
// It has weird conditions to parse the data field in Numeric and OneOfOption.

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range8 {
    min_value: u8,
    max_value: u8,
    step: u8,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range16 {
    min_value: u16,
    max_value: u16,
    step: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range32 {
    min_value: u32,
    max_value: u32,
    step: u32,
}
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range64 {
    min_value: u64,
    max_value: u64,
    step: u64,
}

pub enum RangeType {
    NumSize8(u8),
    NumSize16(u16),
    NumSize32(u32),
    NumSize64(u64),
}

#[derive(Debug, PartialEq)]
pub enum Range {
    Range8(Range8),
    Range16(Range16),
    Range32(Range32),
    Range64(Range64),
}

impl Range {
    /// The size in bytes of the value, and of each of MinValue, MaxValue and Step.
    fn size(&self) -> u8 {
        match self {
            Range::Range8(_) => 1,
            Range::Range16(_) => 2,
            Range::Range32(_) => 4,
            Range::Range64(_) => 8,
        }
    }
}

struct NumericRange {
    minimum: i128,
    maximum: i128,
    bits: u32,
}

impl NumericRange {
    fn from_ifr(range: &Range, flags: u8) -> Self {
        let (minimum, maximum) = match range {
            Range::Range8(range) => (u64::from(range.min_value), u64::from(range.max_value)),
            Range::Range16(range) => (u64::from(range.min_value), u64::from(range.max_value)),
            Range::Range32(range) => (u64::from(range.min_value), u64::from(range.max_value)),
            Range::Range64(range) => (range.min_value, range.max_value),
        };
        let format = NumericFormat::from_ifr(range, flags);
        Self {
            minimum: format.decode(minimum),
            maximum: format.decode(maximum),
            bits: format.bits,
        }
    }

    fn parse_value(&self, value: &str) -> Result<TypeValue, ChangeValueError> {
        if self.minimum > self.maximum {
            return Err(ChangeValueError::InvalidNumericRange);
        }
        let value = value
            .parse::<i128>()
            .context("value should be a decimal integer")?;
        if value < self.minimum {
            return Err(ChangeValueError::BelowMinValue);
        }
        if value > self.maximum {
            return Err(ChangeValueError::ExceededMaxValue);
        }
        match self.bits {
            8 => Ok(TypeValue::NumSize8(value as u8)),
            16 => Ok(TypeValue::NumSize16(value as u16)),
            32 => Ok(TypeValue::NumSize32(value as u32)),
            64 => Ok(TypeValue::NumSize64(value as u64)),
            _ => Err(ChangeValueError::InvalidNumericRange),
        }
    }
}

/// The stored width in bits, 1 to 64, of a NUMERIC or ONE_OF value, and, if
/// EFI_IFR_DISPLAY_INT_DEC signs it, the width of its type.
#[derive(Clone, Copy)]
struct NumericFormat {
    bits: u32,
    signed_type_bits: Option<u32>,
}

/// Why the Flags of a NUMERIC or ONE_OF give no value format.
#[derive(Debug, Error)]
enum NumericFormatError {
    #[error("EDKII bit-field width {0}, not 1 to 32")]
    BitFieldWidth(u8),
}

impl NumericFormat {
    /// Returns the format that the Range and EFI_IFR_DISPLAY give (UEFI 2.10 §33.3.8.3.47).
    fn from_ifr(range: &Range, flags: u8) -> Self {
        let bits = u32::from(range.size()) * u8::BITS;
        Self {
            bits,
            signed_type_bits: (flags & EFI_IFR_DISPLAY == EFI_IFR_DISPLAY_INT_DEC).then_some(bits),
        }
    }

    /// Returns the format of an EDKII bit varstore field's IFR default, from its Flags.
    fn from_bit_field_flags(flags: u8) -> Result<Self, NumericFormatError> {
        let width = flags & EDKII_IFR_NUMERIC_SIZE_BIT;
        let bits = u32::from(width);
        if !(1..=EDKII_BIT_FIELD_VALUE_BITS).contains(&bits) {
            return Err(NumericFormatError::BitFieldWidth(width));
        }
        // edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionDefault copies the EFI_IFR_DEFAULT,
        // Type UINT32 here, and DisplayEngineDxe/ProcessOptions.c PrintFormattedNumber signs by
        // that Type; IfrParse.c types the question by the bytes it spans and GetBitsQuestionValue
        // copies no Type, so a byte-aligned 8-bit INT_DEC 0xFF shows 255 as a default and -1 when
        // read after a parse
        let signed = flags & EDKII_IFR_DISPLAY_BIT == EDKII_IFR_DISPLAY_INT_DEC_BIT;
        Ok(Self {
            bits,
            signed_type_bits: signed.then_some(EDKII_BIT_FIELD_VALUE_BITS),
        })
    }

    /// Returns `value` cut to `bits` bits.
    fn cut(self, value: u64) -> u64 {
        let unused = 64 - self.bits;
        value << unused >> unused
    }

    /// Returns `value` cut to `bits` bits and, if signed, sign-extended from its type width.
    fn decode(self, value: u64) -> i128 {
        let value = self.cut(value);
        match self.signed_type_bits {
            Some(type_bits) => {
                let unused = 64 - type_bits;
                i128::from((value << unused).cast_signed() >> unused)
            }
            None => i128::from(value),
        }
    }
}

/// Returns the format of the question's IFR default, from EDKII bit-field Flags if it has them.
fn numeric_format(
    question: &IFROperation,
    flags: u8,
    range: &Range,
) -> Result<NumericFormat, NumericFormatError> {
    if refers_to_bit_field(question) {
        NumericFormat::from_bit_field_flags(flags)
    } else {
        Ok(NumericFormat::from_ifr(range, flags))
    }
}

/// Whether the question is wrapped in the GUID op that marks an EDKII bit varstore field;
/// edk2-stable202608 BaseTools VfrSyntax.g wraps each such question in its own.
fn refers_to_bit_field(question: &IFROperation) -> bool {
    question
        .parent
        .as_ref()
        .and_then(Weak::upgrade)
        .is_some_and(|parent| {
            let parent = parent.borrow();
            parent.op_code == IFROpCode::Guid
                && parent.data.starts_with(&EDKII_IFR_BIT_VARSTORE_GUID)
        })
}

/// How a NUMERIC or ONE_OF stores its MinValue, MaxValue and Step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RangeEncoding {
    /// In the size of EFI_IFR_NUMERIC_SIZE in its Flags.
    NumericSize,
    /// As UINT32, as edk2-stable202608 VfrSyntax.g stores them for an EDKII bit varstore field,
    /// whose Flags hold its width in bits.
    EdkiiBitField,
}

impl RangeEncoding {
    fn from_question(question: &IFROperation) -> Self {
        if refers_to_bit_field(question) {
            Self::EdkiiBitField
        } else {
            Self::NumericSize
        }
    }
}

fn range_parser<R: Read + Seek>(
    reader: &mut R,
    _endian: binrw::Endian,
    (flags, encoding): (u8, RangeEncoding),
) -> BinResult<Range> {
    match encoding {
        RangeEncoding::EdkiiBitField => Ok(Range::Range32(reader.read_ne()?)),
        RangeEncoding::NumericSize => match flags & EFI_IFR_NUMERIC_SIZE {
            EFI_IFR_NUMERIC_SIZE_1 => Ok(Range::Range8(reader.read_ne()?)),
            EFI_IFR_NUMERIC_SIZE_2 => Ok(Range::Range16(reader.read_ne()?)),
            EFI_IFR_NUMERIC_SIZE_4 => Ok(Range::Range32(reader.read_ne()?)),
            // EFI_IFR_NUMERIC_SIZE_8, the only value left
            _ => Ok(Range::Range64(reader.read_ne()?)),
        },
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct CheckBox {
    pub question_header: QuestionHeader,
    pub flags: u8,
}

impl Question for CheckBox {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

/// A question whose value get reads and set writes.
#[derive(Clone, Copy)]
enum ValueQuestion<'a> {
    OneOf(&'a OneOf),
    Numeric(&'a Numeric),
    CheckBox(&'a CheckBox),
}

impl ValueQuestion<'_> {
    fn header(self) -> QuestionHeader {
        match self {
            ValueQuestion::OneOf(question) => question.question_header(),
            ValueQuestion::Numeric(question) => question.question_header(),
            ValueQuestion::CheckBox(question) => question.question_header(),
        }
    }
}

/// Returns `op` as a ONE_OF, NUMERIC or CHECKBOX.
fn value_question(op: &IFROperation) -> Option<ValueQuestion<'_>> {
    match &op.parsed_data {
        ParsedOperation::OneOf(question) => Some(ValueQuestion::OneOf(question)),
        ParsedOperation::Numeric(question) => Some(ValueQuestion::Numeric(question)),
        ParsedOperation::CheckBox(question) => Some(ValueQuestion::CheckBox(question)),
        ParsedOperation::FormSet(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::VarStore(_)
        | ParsedOperation::VarStoreNameValue(_)
        | ParsedOperation::VarStoreEfi(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Placeholder => None,
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct OneOfOption {
    pub option_string_id: u16,
    pub flags: u8,
    value_type: u8,
    #[br(parse_with = type_value_parser, args(value_type))]
    pub value: TypeValue,
}

trait VariableStore {
    fn name(&self) -> String;
    fn guid(&self) -> Guid;
    fn size(&self) -> u16;
    fn kind(&self) -> VariableStoreKind;
    fn is_runtime_accessible(&self) -> bool;

    fn efivar_file_name(&self) -> EfivarFileName {
        EfivarFileName::new(&self.name(), self.guid())
    }

    /// Refuses an EFI variable without EFI_VARIABLE_RUNTIME_ACCESS, which efivarfs neither
    /// lists nor writes (UEFI 2.10 §8.2.2, §8.2.3).
    fn check_runtime_access(&self) -> std::result::Result<(), BootServiceOnlyVariable> {
        if self.kind() == VariableStoreKind::EfiVariable && !self.is_runtime_accessible() {
            return Err(BootServiceOnlyVariable(self.efivar_file_name()));
        }
        Ok(())
    }

    fn write_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
        self.check_runtime_access()?;
        self.write_efivarfs_at_offset(offset, data)
    }

    fn write_efivarfs_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
        // Steps:
        // * Read bytes
        // * Seek to 4 + offset
        // * If checks pass, write your answer

        // We have three layers of checks so as to not accidentally corrupt EFI vars.

        // The /run/lock/efibootmgr-remount lock will release automatically on drop.
        // If something errors out, doesn't matter since we are using the flock syscall to lock it.
        // Linux will then release it automatically after the program ends.

        const LOCK_FILE_PATH: &str = "/run/lock/efibootmgr-remount";
        let mut lock = FileLock::new(LOCK_FILE_PATH);
        lock.lock()?;

        let efivars = Path::new(EFIVARS_MOUNT_POINT);
        let file_name = self.efivar_file_name();
        let path = efivars.join(&file_name);

        let mut file_ro = open_efivar(efivars, &file_name).map_err(VariableNotExported::explain)?;

        let mut file_contents = Vec::new();
        file_ro
            .read_to_end(&mut file_contents)
            .context(format!("Failed to read efivarfs file '{}'", path.display()))?;

        update_efivarfs_bytes(&mut file_contents, self.size(), offset, data)?;

        let _efifs = EfivarsMountGuard::new().context("Failed to create efivars fs mount guard")?;

        // Needed on kernel 4.6+ to make EFI vars the kernel doesn't know how to
        // validate temporarily writable.
        let _immutability_attribute_guard = EfivarsImmutabilityGuard::new(&path)
            .context("failed to create immutability attribute guard")?;

        // All checks passed, now we can try to write.
        debug!("Writing value to {}", path.display());
        File::create(&path)
            .context("Failed to open efivarfs file for writing")?
            .write_all(&file_contents)
            .context("Failed to write to efivarfs file")?;

        Ok(())
    }
}

/// set's error for a missing efivar file: firmware that keeps the variable from the OS, e.g.
/// boot-service-only, leaves no file to rewrite.
#[derive(Error, Debug)]
#[error(
    "{0}: the firmware has not created it or does not expose it to the OS, so its questions \
     cannot be set from Linux; change them in the firmware setup, or ask the board vendor for \
     firmware that exposes it; see https://github.com/linuxboot/uefisettings/issues/2"
)]
struct VariableNotExported(EfivarNotFound);

impl VariableNotExported {
    /// Turns open_efivar's EfivarNotFound into VariableNotExported; other errors pass through
    /// unchanged.
    fn explain(error: anyhow::Error) -> anyhow::Error {
        match error.downcast::<EfivarNotFound>() {
            Ok(not_found) => Self(not_found).into(),
            Err(error) => error,
        }
    }
}

/// An EFI variable without EFI_VARIABLE_RUNTIME_ACCESS, which set refuses and get shows as
/// unavailable.
#[derive(Error, Debug)]
#[error("EFI variable {0} is boot-service-only and cannot be written through efivarfs")]
struct BootServiceOnlyVariable(EfivarFileName);

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum VariableStoreKind {
    Buffer,
    EfiVariable,
}

#[cfg(test)]
mod non_efi_varstore_tests {
    use super::ifr_fixtures::*;
    use super::*;
    use crate::hii::efivarfs::tests::EFI_GLOBAL_VARIABLE;

    struct TestVariableStore {
        kind: VariableStoreKind,
    }

    impl VariableStore for TestVariableStore {
        fn name(&self) -> String {
            "TestVarStore".to_string()
        }

        fn guid(&self) -> Guid {
            NIL_GUID
        }

        fn size(&self) -> u16 {
            1
        }

        fn kind(&self) -> VariableStoreKind {
            self.kind
        }

        fn is_runtime_accessible(&self) -> bool {
            self.kind == VariableStoreKind::EfiVariable
        }

        fn write_efivarfs_at_offset(&self, _offset: u16, _data: TypeValue) -> Result<()> {
            Ok(())
        }
    }

    fn efi_varstore(attributes: u32) -> VarStoreEfi {
        VarStoreEfi {
            var_store_id: 1,
            guid: Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            attributes,
            size: 1,
            name: "TestVarStore".into(),
        }
    }

    /// read_current_value_bytes of `store` with a fresh EfivarReader of `efivars`.
    fn read(
        store: impl VariableStore + 'static,
        efivars: &Efivars,
    ) -> std::result::Result<Vec<u8>, String> {
        read_current_value_bytes(&Ok(Box::new(store)), &mut efivars.reader())
            .map(<[u8]>::to_vec)
            .map_err(Cow::into_owned)
    }

    #[test]
    fn boot_service_only_varstore_is_reported_as_unavailable() {
        for attributes in [0x2, 0x3] {
            assert_eq!(
                read(efi_varstore(attributes), &Efivars::new()),
                Err("<ValueUnavailable: EFI variable \
                     TestVarStore-00000000-0000-0000-0000-000000000000 is boot-service-only \
                     (no EFI_VARIABLE_RUNTIME_ACCESS)>"
                    .to_string()),
                "attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn boot_service_only_varstore_write_is_rejected() {
        for attributes in [0x2, 0x3] {
            assert_eq!(
                efi_varstore(attributes)
                    .write_at_offset(0, TypeValue::NumSize8(1))
                    .unwrap_err()
                    .to_string(),
                "EFI variable TestVarStore-00000000-0000-0000-0000-000000000000 is \
                 boot-service-only and cannot be written through efivarfs",
                "attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn efi_varstore_runtime_access_does_not_require_nonvolatile_storage() {
        for attributes in [0x6, 0x7] {
            let varstore = efi_varstore(attributes);

            assert_eq!(varstore.kind(), VariableStoreKind::EfiVariable);
            assert!(varstore.is_runtime_accessible());
        }
    }

    #[test]
    fn short_efivar_file_is_a_read_error() {
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Short", 2), &[1]);
        let want = format!(
            "<VStoreError: failed to read efivar file '{}'>",
            efivars
                .path()
                .join("Short-00000000-0000-0000-0000-000000000000")
                .display()
        );

        for store in [efi_variable("Short", 2), buffer("Short", 2)] {
            let kind = store.kind;
            assert_eq!(read(store, &efivars), Err(want.clone()), "{kind:?}");
        }
    }

    #[test]
    fn efi_varstore_without_efivar_file_is_unavailable() {
        let store = VarStoreEfi {
            var_store_id: 1,
            guid: EFI_GLOBAL_VARIABLE,
            attributes: 0x7,
            size: 1,
            name: "Missing".into(),
        };

        assert_eq!(
            read(store, &Efivars::new()),
            Err(
                "<ValueUnavailable: no EFI variable Missing-8be4df61-93ca-11d2-aa0d-00e098032b8c>"
                    .to_string()
            ),
            "runtime EFI variable without an efivar file"
        );
    }

    #[test]
    fn not_found_read_error_is_not_a_missing_variable() {
        let error = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("failed to read bytes");

        assert_eq!(
            read_failure_reason(VariableStoreKind::Buffer, &error),
            "<VStoreError: failed to read bytes>",
            "a NotFound io::Error under a context"
        );
    }

    #[test]
    fn buffer_varstore_with_efivarfs_backing_is_read() {
        let efivars = Efivars::new();
        let store = buffer("Buffer", 1);
        efivars.write(&store, &[1]);

        assert_eq!(
            read(store, &efivars),
            Ok(efivarfs_bytes(&[1])),
            "buffer VarStore with an efivar file"
        );
    }

    #[test]
    fn buffer_varstore_without_efivarfs_backing_names_the_missing_variable() {
        assert_eq!(
            read(buffer("Buffer", 1), &Efivars::new()),
            Err("<ValueUnavailable: no EFI variable \
                 Buffer-00000000-0000-0000-0000-000000000000; \
                 HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>"
                .to_string()),
            "buffer VarStore without an efivar file"
        );
    }

    #[test]
    fn crafted_varstore_name_stays_in_efivarfs() {
        for name in ["../T/ou", "/etc/passwd", "a/b", ".."] {
            let var_store = VarStore {
                guid: NIL_GUID,
                var_store_id: 1,
                size: 1,
                name: name.into(),
            };
            let var_store_efi = VarStoreEfi {
                var_store_id: 1,
                guid: NIL_GUID,
                attributes: 0x7,
                size: 1,
                name: name.into(),
            };
            for file_name in [
                var_store.efivar_file_name(),
                var_store_efi.efivar_file_name(),
            ] {
                let path = Path::new(EFIVARS_MOUNT_POINT).join(file_name);
                assert_eq!(
                    path.parent(),
                    Some(Path::new(EFIVARS_MOUNT_POINT)),
                    "VarStore name {name:?}"
                );
            }
        }
    }

    #[test]
    fn question_without_varstore_is_reported_as_unavailable() {
        let node = Rc::new(RefCell::new(IFROperation {
            op_code: IFROpCode::Unknown(DUMMY_OPCODE),
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Placeholder,
        }));

        let error = find_corresponding_varstore(node, 0).err().unwrap();
        assert_eq!(
            error.to_string(),
            "question is callback-driven or temporary and has no varstore"
        );
    }

    #[test]
    fn change_value_allows_buffer_varstore_with_efivarfs_backing() {
        let question = QuestionDescriptor {
            question: "SHA-1 PCR Bank".to_string(),
            help: String::new(),
            value: "Disabled".to_string(),
            max_value: RangeType::NumSize8(1),
            numeric_range: None,
            opcode: IFROpCode::OneOf,
            possible_options: vec![AnswerOption {
                value: "Enabled".to_string(),
                raw_value: TypeValue::NumSize8(1),
                state: StateEvaluation::selectable(),
            }],
            header: QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 0,
                var_store_id: 1,
                var_store_info: 0,
                question_flags: 0,
            },
            varstore: Some(Box::new(TestVariableStore {
                kind: VariableStoreKind::Buffer,
            })),
            refers_to_bit_field: false,
            value_state: StateEvaluation::selectable(),
        };

        assert!(change_value(&question, "Enabled").unwrap());
    }
}

impl EfivarRange {
    /// The efivar bytes that hold the value of `store`.
    fn of(store: &dyn VariableStore) -> Self {
        Self {
            name: store.efivar_file_name(),
            size: store.size(),
        }
    }
}

impl EfivarReader {
    /// Why the efivar of `store` is missing, if a read of it found it so.
    fn missing(&self, store: &dyn VariableStore) -> Option<&EfivarNotFound> {
        self.outcomes
            .get(&EfivarRange::of(store))?
            .as_ref()
            .err()?
            .downcast_ref()
    }
}

/// Returns the bytes of `varstore`'s efivar file, or why a question on it has no value.
fn read_current_value_bytes<'a>(
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &'a mut EfivarReader,
) -> std::result::Result<&'a [u8], Cow<'static, str>> {
    let store = match varstore {
        Ok(store) => store,
        Err(error) => return Err(Cow::Owned(format!("<ValueUnavailable: {}>", error))),
    };
    if let Err(BootServiceOnlyVariable(name)) = store.check_runtime_access() {
        return Err(Cow::Owned(format!(
            "<ValueUnavailable: EFI variable {name} is boot-service-only \
             (no EFI_VARIABLE_RUNTIME_ACCESS)>"
        )));
    }

    reader
        .read(EfivarRange::of(store.as_ref()))
        .map_err(|error| Cow::Owned(read_failure_reason(store.kind(), error)))
}

/// Why a question on a VarStore of `kind` has no value, its efivar file having failed with
/// `error`.
fn read_failure_reason(kind: VariableStoreKind, error: &anyhow::Error) -> String {
    if error.downcast_ref::<EfivarsNotRead>().is_some() {
        return format!("<ValueUnavailable: {error}>");
    }
    let Some(missing) = error.downcast_ref::<EfivarNotFound>() else {
        return format!("<VStoreError: {error}>");
    };
    match kind {
        VariableStoreKind::Buffer => format!(
            "<ValueUnavailable: {missing}; HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>"
        ),
        VariableStoreKind::EfiVariable => format!("<ValueUnavailable: {missing}>"),
    }
}

/// The payload bytes that hold the value of `question`, if it is a ONE_OF, NUMERIC or CHECKBOX,
/// where edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes places it: an EDKII bit
/// varstore field, whose VarOffset and width count bits, spans the bytes of its bits.
fn value_bytes(question: &IFROperation) -> Option<std::ops::Range<usize>> {
    let value_question = value_question(question)?;
    let (size, bits) = match value_question {
        ValueQuestion::OneOf(OneOf { flags, data, .. })
        | ValueQuestion::Numeric(Numeric { flags, data, .. }) => {
            (usize::from(data.size()), flags & EDKII_IFR_NUMERIC_SIZE_BIT)
        }
        ValueQuestion::CheckBox(_) => (std::mem::size_of::<u8>(), 1),
    };
    let offset = usize::from(value_question.header().var_store_info);
    if refers_to_bit_field(question) {
        Some(offset / 8..(offset + usize::from(bits)).div_ceil(8))
    } else {
        Some(offset..offset + size)
    }
}

/// Returns the value_bytes of the question, or why its value cannot be read.
fn read_question_bytes<'a>(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &'a mut EfivarReader,
) -> std::result::Result<&'a [u8], Cow<'static, str>> {
    let Some(value) = value_bytes(question) else {
        return Err(Cow::Owned(format!(
            "<ValueUnavailable: {:?} value not decoded>",
            question.op_code
        )));
    };
    let bytes = read_current_value_bytes(varstore, reader)?;
    // edk2-stable202608 SetupBrowserDxe/IfrParse.c reads the VarOffset of such a question in bits
    // TODO: decode bit fields by the width in their Flags, not their Range32 (UINT32 storage)
    if refers_to_bit_field(question) {
        return Err(Cow::Borrowed(
            "<ValueUnavailable: EDKII bit-field value not decoded>",
        ));
    }
    let offset = value.start;
    bytes
        .get(EFIVARFS_HEADER_SIZE..)
        .and_then(|payload| payload.get(value))
        .ok_or_else(|| {
            Cow::Owned(format!(
                "<ExtractEFIDataError: failed to fill whole buffer (offset: {offset}; buflen: {})>",
                bytes.len()
            ))
        })
}

/// The little-endian integer that `bytes`, the value_bytes of a question that is not a bit
/// field, store.
fn stored_value(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

#[cfg(test)]
mod efivar_reader_tests {
    use super::ifr_fixtures::*;
    use super::*;

    const MISSING_BUFFER: &str = "<ValueUnavailable: no EFI variable \
        Missing-00000000-0000-0000-0000-000000000000; \
        HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>";
    const BOOT_SERVICE_ONLY: &str = "<ValueUnavailable: EFI variable \
         Setup-00000000-0000-0000-0000-000000000000 is boot-service-only \
         (no EFI_VARIABLE_RUNTIME_ACCESS)>";
    const NOT_READ: &str = "<ValueUnavailable: EFI variables not read>";

    /// read_question_bytes of `store`, owned.
    fn question_bytes(
        question: &IFROperation,
        store: DeclaredVarStore,
        reader: &mut EfivarReader,
    ) -> std::result::Result<Vec<u8>, String> {
        read_question_bytes(question, &Ok(Box::new(store)), reader)
            .map(<[u8]>::to_vec)
            .map_err(Cow::into_owned)
    }

    #[test]
    fn variable_read_through_two_stores_is_read_once() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 1), &[42]);
        let mut reader = efivars.reader();

        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut reader),
            Ok(vec![42]),
            "read_question_bytes"
        );
        efivars.write(&efi_variable("Setup", 1), &[43]);
        let answer = display_answer(
            &question,
            &Ok(Box::new(efi_variable("Setup", 1))),
            &mut reader,
        );

        assert_eq!(answer, "42", "display_answer after the file changed");
    }

    #[test]
    fn stores_of_one_file_and_size_share_one_read() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        let mut reader = efivars.reader();

        efivars.write(&efi_variable("Setup", 1), &[0]);
        assert_eq!(
            question_bytes(
                &question,
                DeclaredVarStore {
                    runtime_accessible: false,
                    ..efi_variable("Setup", 1)
                },
                &mut reader
            ),
            Err(BOOT_SERVICE_ONLY.to_string()),
            "boot-service-only"
        );
        efivars.write(&efi_variable("Setup", 1), &[1]);
        assert_eq!(
            question_bytes(&question, buffer("Setup", 1), &mut reader),
            Ok(vec![1]),
            "buffer after a boot-service-only store"
        );
        efivars.write(&efi_variable("Setup", 1), &[2]);
        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut reader),
            Ok(vec![1]),
            "runtime EFI variable after the buffer"
        );
    }

    #[test]
    fn other_files_sizes_and_fresh_reads_read_again() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 2), &[1, 2]);
        efivars.write(&efi_variable("Other", 1), &[3]);
        let mut reader = efivars.reader();

        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut reader),
            Ok(vec![1]),
            "first"
        );
        efivars.write(&efi_variable("Setup", 2), &[4, 5]);
        let cases: [(&str, DeclaredVarStore, &[u8]); 3] = [
            ("other name", efi_variable("Other", 1), &[3]),
            ("other size", efi_variable("Setup", 2), &[4]),
            ("first again", efi_variable("Setup", 1), &[1]),
        ];
        for (case, store, want) in cases {
            assert_eq!(
                question_bytes(&question, store, &mut reader),
                Ok(want.to_vec()),
                "{case}"
            );
        }

        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut efivars.reader()),
            Ok(vec![4]),
            "fresh EfivarReader"
        );
    }

    #[test]
    fn missing_buffer_variable_is_read_once() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let missing = || buffer("Missing", 1);
        let efivars = Efivars::new();
        let mut reader = efivars.reader();

        assert_eq!(
            question_bytes(&question, missing(), &mut reader),
            Err(MISSING_BUFFER.to_string()),
            "first call"
        );
        efivars.write(&missing(), &[0]);
        assert_eq!(
            question_bytes(&question, missing(), &mut reader),
            Err(MISSING_BUFFER.to_string()),
            "call after the file appeared"
        );
        assert_eq!(
            question_bytes(&question, missing(), &mut efivars.reader()),
            Ok(vec![0]),
            "fresh EfivarReader"
        );
    }

    #[test]
    fn missing_file_reason_follows_each_store_kind() {
        const MISSING_EFI_VARIABLE: &str =
            "<ValueUnavailable: no EFI variable Missing-00000000-0000-0000-0000-000000000000>";
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        let mut reader = efivars.reader();
        let cases = [
            (
                "EFI variable",
                efi_variable("Missing", 1),
                MISSING_EFI_VARIABLE,
            ),
            ("buffer after it", buffer("Missing", 1), MISSING_BUFFER),
            (
                "EFI variable after the buffer",
                efi_variable("Missing", 1),
                MISSING_EFI_VARIABLE,
            ),
        ];

        for (case, store, want) in cases {
            assert_eq!(
                question_bytes(&question, store, &mut reader),
                Err(want.to_string()),
                "{case}"
            );
        }
        assert_eq!(reader.outcomes.len(), 1, "cached outcomes");
    }

    #[test]
    fn disabled_source_leaves_every_value_unread() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let mut reader = disabled_reader();
        let cases = [
            ("EFI variable", efi_variable("Setup", 1), NOT_READ),
            ("buffer", buffer("Setup", 1), NOT_READ),
            (
                "boot-service-only EFI variable",
                DeclaredVarStore {
                    runtime_accessible: false,
                    ..efi_variable("Setup", 1)
                },
                BOOT_SERVICE_ONLY,
            ),
        ];

        for (case, store, want) in cases {
            assert_eq!(
                question_bytes(&question, store, &mut reader),
                Err(want.to_string()),
                "{case}"
            );
        }
    }

    #[test]
    fn disabled_source_shows_the_ifr_default() {
        let (root, _node) = parse_question(
            &[var_store_efi(1, "Setup", NV_BS_RT, 1)],
            CHECKBOX,
            &checkbox(0, 0x01),
            &[],
        );

        let listed: Vec<String> = list_questions(
            root,
            &strings(),
            IncludedStates::empty(),
            &mut disabled_reader(),
        )
        .into_iter()
        .map(|(question, _)| question.value)
        .collect();

        assert_eq!(
            listed,
            [format!("{NOT_READ} <IFR default: 1>")],
            "list_questions without efivars"
        );
    }

    /// The state annotations that list_questions gives, with every state included, to question
    /// 2, to question 1 under a SUPPRESS_IF on question 2 being 1, and to question 3 under a
    /// SUPPRESS_IF TRUE, all on the 2-byte efivar Setup, read through `reader`.
    fn suppressed_states(reader: &mut EfivarReader) -> Vec<String> {
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 2),
            form(
                1,
                &[
                    checkbox_on(2, 5, 1),
                    conditional(SUPPRESS_IF, eq_id_val_of(2, 1), &[checkbox_op(1, 1)]),
                    conditional(SUPPRESS_IF, ifr_true(), &[checkbox_op(3, 1)]),
                ],
            ),
        ]);
        list_questions(root, &strings(), IncludedStates::all(), reader)
            .into_iter()
            .map(|(_, state)| state.annotation())
            .collect()
    }

    #[test]
    fn disabled_source_leaves_value_conditions_undetermined() {
        let efivars = Efivars::new();
        let undetermined = " <selectable or suppressed: EqIdVal of question 0x0002: \
            <ValueUnavailable: EFI variables not read>>";

        efivars.write(&efi_variable("Setup", 2), &[1, 0]);
        assert_eq!(
            suppressed_states(&mut efivars.reader()),
            ["", " <suppressed>", " <suppressed>"],
            "question 2 is 1"
        );
        efivars.write(&efi_variable("Setup", 2), &[0, 0]);
        assert_eq!(
            suppressed_states(&mut efivars.reader()),
            ["", "", " <suppressed>"],
            "question 2 is 0"
        );
        assert_eq!(
            suppressed_states(&mut disabled_reader()),
            ["", undetermined, " <suppressed>"],
            "Disabled"
        );
    }

    #[test]
    fn list_questions_and_display_share_one_read() {
        let first = operation(CHECKBOX, false, &checkbox(0, 0x00));
        let (root, _second) = parse_question(
            &[var_store_efi(1, "Setup", NV_BS_RT, 2), first],
            CHECKBOX,
            &checkbox(1, 0x00),
            &[],
        );
        let show = |reader: &mut EfivarReader| {
            display(Rc::clone(&root), 0, &strings(), reader).expect("display the form package")
        };
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 2), &[1, 0]);
        let mut reader = efivars.reader();
        let shown_before = show(&mut efivars.reader());

        let listed: Vec<String> = list_questions(
            Rc::clone(&root),
            &strings(),
            IncludedStates::empty(),
            &mut reader,
        )
        .into_iter()
        .map(|(question, _)| question.value)
        .collect();
        efivars.write(&efi_variable("Setup", 2), &[0, 1]);
        let shown = show(&mut reader);

        assert_eq!(listed, ["1", "0"], "list_questions");
        assert_eq!(reader.outcomes.len(), 1, "files read by two questions");
        assert_eq!(shown, shown_before, "display after list_questions");
        assert_ne!(
            show(&mut efivars.reader()),
            shown_before,
            "display of the changed file"
        );
    }

    /// A NUMERIC or ONE_OF at VarOffset `offset` whose MinValue, MaxValue and Step take `size`
    /// bytes, as `flags` says.
    fn sized_question(offset: u16, flags: u8, size: usize) -> Vec<u8> {
        [question_header(offset), vec![flags], vec![0; 3 * size]].concat()
    }

    /// Where setup_question puts its question.
    #[derive(Clone, Copy)]
    enum Placement {
        /// In the FormSet, so that its VarOffset counts bytes
        FormSet,
        /// In an EDKII bit varstore GUID op, so that its VarOffset and width count bits
        BitVarStoreGuid,
    }

    /// Parses a FormSet holding the 16-byte VARSTORE_EFI "Setup" and then one question, put
    /// where `placement` says; returns the root and the question.
    fn setup_question(placement: Placement, op_code: u8, data: &[u8]) -> RootAndQuestion {
        let var_store = var_store_efi(1, "Setup", NV_BS_RT, 16);
        match placement {
            Placement::FormSet => parse_question(&[var_store], op_code, data, &[]),
            Placement::BitVarStoreGuid => {
                let bytes = form_set(&[
                    var_store,
                    operation(GUID, true, &BIT_VARSTORE_GUID),
                    operation(op_code, false, data),
                    END.to_vec(), // End of the GUID
                ]);
                let root =
                    handle_form_package(&mut Cursor::new(&bytes)).expect("parse the form package");
                let guid = Rc::clone(&root.borrow().children[0].borrow().children[1]);
                let question = Rc::clone(&guid.borrow().children[0]);
                (root, question)
            }
        }
    }

    /// The questions that value_bytes_are_where_the_value_is_stored and
    /// questions_decode_only_their_value_bytes check: name, parsed question, value_bytes.
    fn value_questions() -> Vec<(&'static str, RootAndQuestion, std::ops::Range<usize>)> {
        let in_form_set = |op_code, data: &[u8]| setup_question(Placement::FormSet, op_code, data);
        let bit_field =
            |op_code, data: &[u8]| setup_question(Placement::BitVarStoreGuid, op_code, data);
        vec![
            (
                "CHECKBOX at 3",
                in_form_set(CHECKBOX, &checkbox(3, 0x00)),
                3..4,
            ),
            (
                "UINT8 ONE_OF at 0",
                in_form_set(ONE_OF, &one_of_data()),
                0..1,
            ),
            (
                "UINT16 NUMERIC at 6",
                in_form_set(NUMERIC, &sized_question(6, EFI_IFR_NUMERIC_SIZE_2, 2)),
                6..8,
            ),
            (
                "UINT32 ONE_OF at 5",
                in_form_set(ONE_OF, &uint32_range_question(5, EFI_IFR_NUMERIC_SIZE_4)),
                5..9,
            ),
            (
                "UINT64 NUMERIC at 1",
                // EFI_IFR_NUMERIC_SIZE_8
                in_form_set(NUMERIC, &sized_question(1, 0x03, 8)),
                1..9,
            ),
            (
                "5-bit NUMERIC at bit 13",
                bit_field(NUMERIC, &uint32_range_question(13, 5)),
                1..3,
            ),
            (
                "3-bit ONE_OF at bit 16",
                bit_field(ONE_OF, &uint32_range_question(16, 3)),
                2..3,
            ),
            (
                "bit-field CHECKBOX at bit 15",
                bit_field(CHECKBOX, &checkbox(15, 0x00)),
                1..2,
            ),
            (
                "bit-field CHECKBOX at bit 16",
                bit_field(CHECKBOX, &checkbox(16, 0x00)),
                2..3,
            ),
        ]
    }

    #[test]
    fn value_bytes_are_where_the_value_is_stored() {
        for (case, (_root, question), expected) in value_questions() {
            assert_eq!(value_bytes(&question.borrow()), Some(expected), "{case}");
        }
        let (root, _question) = parse_question(&[], CHECKBOX, &checkbox(3, 0x00), &[]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        assert_eq!(value_bytes(&form_set.borrow()), None, "FORM_SET");
    }

    #[test]
    fn ops_without_value_bytes_are_not_decoded() {
        let (root, _question) = parse_question(&[], CHECKBOX, &checkbox(3, 0x00), &[]);
        let form_set = Rc::clone(&root.borrow().children[0]);

        assert_eq!(
            question_bytes(
                &form_set.borrow(),
                efi_variable("FormSet", 4),
                &mut disabled_reader()
            ),
            Err("<ValueUnavailable: FormSet value not decoded>".to_string()),
            "FORM_SET"
        );
    }

    #[test]
    fn questions_decode_only_their_value_bytes() {
        for (case, (root, question), value) in value_questions() {
            let show = |outside: u8, inside: u8| {
                let payload: Vec<u8> = (0..16)
                    .map(|offset| match value.contains(&offset) {
                        true => inside,
                        false => outside,
                    })
                    .collect();
                let efivars = Efivars::new();
                efivars.write(&efi_variable("Setup", 16), &payload);
                let mut reader = efivars.reader();
                let root = Rc::clone(&root);
                let listed: Vec<String> = list_questions(
                    Rc::clone(&root),
                    &strings(),
                    IncludedStates::empty(),
                    &mut reader,
                )
                .into_iter()
                .map(|(question, _)| question.value)
                .collect();
                let shown = display(root, 0, &strings(), &mut reader).expect("display");
                (listed, shown)
            };

            assert_eq!(show(0x00, 0x01), show(0xFF, 0x01), "{case}: other bytes");
            // read_question_bytes refuses bit fields
            if !refers_to_bit_field(&question.borrow()) {
                assert_ne!(
                    show(0x00, 0x01).1,
                    show(0x00, 0x00).1,
                    "{case}: value bytes"
                );
            }
        }
    }
}

#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct VarStore {
    pub guid: Guid,
    pub var_store_id: u16,
    pub size: u16,
    pub name: binrw::NullString,
}

#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct VarStoreNameValue {
    pub var_store_id: u16,
    pub guid: Guid,
}

impl VariableStore for VarStore {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn guid(&self) -> Guid {
        self.guid
    }
    fn size(&self) -> u16 {
        self.size
    }
    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::Buffer
    }
    fn is_runtime_accessible(&self) -> bool {
        false
    }
}

#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct VarStoreEfi {
    pub var_store_id: u16,
    pub guid: Guid,
    pub attributes: u32,
    pub size: u16,
    pub name: binrw::NullString,
}
impl VariableStore for VarStoreEfi {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn guid(&self) -> Guid {
        self.guid
    }
    fn size(&self) -> u16 {
        self.size
    }
    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::EfiVariable
    }
    fn is_runtime_accessible(&self) -> bool {
        (self.attributes & EFI_VARIABLE_RUNTIME_ACCESS) != 0
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct DefaultStore {
    pub name_string_id: u16,
    pub default_id: DefaultId,
}

// IFRDefault is called IFRDefault instead of Default like the opcode because we don't want
// rust to confuse it with std:default:Default trait
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct IFRDefault {
    pub default_id: DefaultId,
    value_type: u8,
    #[br(parse_with = default_value_parser, args(value_type))]
    value: IfrDefaultValue,
}

/// The Value of an EFI_IFR_DEFAULT.
#[derive(Debug, PartialEq, Clone, Copy)]
enum IfrDefaultValue {
    Decoded(TypeValue),
    /// Absent from EFI_IFR_DEFAULT_2 (Type EFI_IFR_TYPE_OTHER), whose value is a nested
    /// EFI_IFR_VALUE.
    InValueOp,
    /// Of a Type other than numeric, boolean and EFI_IFR_TYPE_OTHER.
    NotDecoded,
    /// Length leaves no room for a value of Type.
    Missing,
}

fn default_value_parser<R: Read + Seek>(
    reader: &mut R,
    endian: binrw::Endian,
    args: (u8,),
) -> BinResult<IfrDefaultValue> {
    match args.0 {
        EFI_IFR_TYPE_NUM_SIZE_8
        | EFI_IFR_TYPE_NUM_SIZE_16
        | EFI_IFR_TYPE_NUM_SIZE_32
        | EFI_IFR_TYPE_NUM_SIZE_64
        | EFI_IFR_TYPE_BOOLEAN => match type_value_parser(reader, endian, args) {
            Ok(value) => Ok(IfrDefaultValue::Decoded(value)),
            Err(error) if error.is_eof() => Ok(IfrDefaultValue::Missing),
            Err(error) => Err(error),
        },
        EFI_IFR_TYPE_OTHER => Ok(IfrDefaultValue::InValueOp),
        _ => Ok(IfrDefaultValue::NotDecoded),
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Form {
    pub form_id: u16,
    pub title_string_id: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Text {
    pub prompt_string_id: u16,
    pub help_string_id: u16,
    pub text_id: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Subtitle {
    pub prompt_string_id: u16,
    pub help_string_id: u16,
    pub flags: u8,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct QuestionRef1 {
    pub question_id: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct EqIdVal {
    pub question_id: u16,
    pub value: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct EqIdId {
    pub question_id_1: u16,
    pub question_id_2: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct EqIdValList {
    pub question_id: u16,
    pub list_length: u16,
    #[br(count = usize::from(list_length))]
    pub value_list: Vec<u16>,
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Time {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Ref {
    pub question_id: u16,
    pub form_id: u16,
    pub form_set_guid: Guid,
    pub device_path_string_id: u16,
}

#[derive(Debug, PartialEq, Clone, Copy)]
/// Any structs having TypeValue as a field can have value of one of these types
/// depending on the value of the value_type
pub enum TypeValue {
    NumSize8(u8),
    NumSize16(u16),
    NumSize32(u32),
    NumSize64(u64),
    Boolean(bool),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Time(Time),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Date(Date),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    StringID(u16),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Other,
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Undefined,
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Action(u16),
    // Buffer(Vec<u8>),  - spec unclear ; FIXME
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Ref(Ref),
    Unknown(u8),
}

impl TypeValue {
    /// Returns a numeric or boolean value as an unsigned integer.
    fn as_u64(self) -> Option<u64> {
        match self {
            TypeValue::NumSize8(v) => Some(v.into()),
            TypeValue::NumSize16(v) => Some(v.into()),
            TypeValue::NumSize32(v) => Some(v.into()),
            TypeValue::NumSize64(v) => Some(v),
            TypeValue::Boolean(v) => Some(v.into()),
            TypeValue::Time(_)
            | TypeValue::Date(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => None,
        }
    }
}

fn type_value_parser<R: Read + Seek>(
    reader: &mut R,
    _endian: binrw::Endian,
    args: (u8,),
) -> BinResult<TypeValue> {
    match args.0 {
        0x00u8 => {
            let r: u8 = reader.read_ne()?;
            Ok(TypeValue::NumSize8(r))
        }
        0x01u8 => {
            let r: u16 = reader.read_ne()?;
            Ok(TypeValue::NumSize16(r))
        }
        0x02u8 => {
            let r: u32 = reader.read_ne()?;
            Ok(TypeValue::NumSize32(r))
        }
        0x03u8 => {
            let r: u64 = reader.read_ne()?;
            Ok(TypeValue::NumSize64(r))
        }
        0x04u8 => {
            let r: u8 = reader.read_ne()?;
            if r != 0 {
                return Ok(TypeValue::Boolean(true));
            }
            Ok(TypeValue::Boolean(false))
        }
        // TODO: handle other types like Date, Time & Ref. We have already made structs for them.
        _ => {
            let r: u8 = reader.read_ne()?;
            Ok(TypeValue::Unknown(r))
        }
    }
}

pub fn handle_form_package(
    package_cursor: &mut Cursor<&Vec<u8>>,
) -> Result<Rc<RefCell<IFROperation>>> {
    // this is the root element so all the values like op_code, length, etc are dummy
    debug!("new forms package");
    let root = Rc::new(RefCell::new(IFROperation {
        op_code: IFROpCode::Unknown(DUMMY_OPCODE),
        length: 0,
        open_scope: false,
        data: Vec::new(),
        parent: None,
        children: Vec::new(),
        parsed_data: ParsedOperation::Placeholder,
    }));

    let mut current_scope = Rc::clone(&root);

    // this loop will terminate when it sees the IFR:End opcode as a child of FormSet
    // if input data is malformed then it will exit on erroring out cause none of the magic bytes match
    loop {
        let node: IFROperation = package_cursor
            .read_ne()
            .context("Failed to parse IFR operation")?;

        let current_node = Rc::new(RefCell::new(node));

        debug!("OpCode is {:?}", current_node.borrow().op_code);

        // end of current scope
        if current_node.borrow().op_code == IFROpCode::End {
            let current_scope_clone = Rc::clone(&current_scope);
            match current_scope_clone.borrow().parent.as_ref() {
                Some(parent_ref) => {
                    if let Some(parent_ref_rc) = parent_ref.upgrade() {
                        // current_scope = current_scope 's parent
                        current_scope = Rc::clone(&parent_ref_rc);
                    }

                    debug!(
                        "Inside the IFR:End case. Op Code: {:?}",
                        current_scope.borrow().op_code
                    );
                }
                None => debug!("IFR:End when parent_ref is none"),
            };

            // if its our own dummy opcode we've reached the top again and this form package has been parsed
            if current_scope.borrow().op_code == IFROpCode::Unknown(DUMMY_OPCODE) {
                debug!("Reached root element. Current scope: {:?}", current_scope);
                // NOTE: I'm 99.99 % sure there is only one top level FormSet in a package.
                // Just in case there isn't there could be a chance we're skipping any subsequent FormSets
                // by breaking here.
                // If anyone finds an exception in the future (next to zero chance I know) you will have to
                // remove the break here and find another way of checking bounds to prevent a "trying to read out of bounds" error
                break;
            }
            continue;
        }

        // set current_node's parent
        // before handle_opcode: RangeEncoding::from_question reads it
        current_node.borrow_mut().parent = Some(Rc::downgrade(&current_scope));

        handle_opcode(Rc::clone(&current_node)).context(format!(
            "Failed to parse op_code {:?} properly",
            &current_node.borrow().op_code,
        ))?;

        // add current_node to current_scope's children
        current_scope
            .borrow_mut()
            .children
            .push(Rc::clone(&current_node));

        if current_node.borrow().open_scope {
            current_scope = Rc::clone(&current_node);
        }
    }

    Ok(root)
}

fn handle_opcode(node: Rc<RefCell<IFROperation>>) -> Result<()> {
    let mut node = node.borrow_mut();
    let mut data_cursor = Cursor::new(&node.data);

    // debug!("Handling OpCode {:?}", current_node.borrow().op_code);

    match node.op_code {
        IFROpCode::FormSet => {
            let parsed: FormSet = data_cursor
                .read_ne()
                .context("Failed to parse FormSet's data")?;
            debug!("FormSet is {:?}", parsed);
            node.parsed_data = ParsedOperation::FormSet(parsed);
        }

        IFROpCode::OneOf => {
            let parsed: OneOf = data_cursor
                .read_ne_args((RangeEncoding::from_question(&node),))
                .context("Failed to parse OneOf's data")?;
            debug!("OneOf is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOf(parsed);
        }
        IFROpCode::CheckBox => {
            let parsed: CheckBox = data_cursor
                .read_ne()
                .context("Failed to parse CheckBox's data")?;
            debug!("CheckBox is {:?}", parsed);
            node.parsed_data = ParsedOperation::CheckBox(parsed);
        }
        IFROpCode::OneOfOption => {
            let parsed: OneOfOption = data_cursor
                .read_ne()
                .context("Failed to parse OneOfOption's data")?;
            debug!("OneOfOption is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOfOption(parsed);
        }
        IFROpCode::VarStore => {
            let parsed: VarStore = data_cursor
                .read_ne()
                .context("Failed to parse VarStore's data")?;

            debug!("VarStore is {:?}", &parsed);

            node.parsed_data = ParsedOperation::VarStore(parsed);
        }
        IFROpCode::VarStoreNameValue => {
            let parsed: VarStoreNameValue = data_cursor
                .read_ne()
                .context("Failed to parse VarStoreNameValue's data")?;
            debug!("VarStoreNameValue is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreNameValue(parsed);
        }
        IFROpCode::VarStoreEfi => {
            // this is implemented in hiilib and the docs for this are relatively clear
            // so I implemented this but I haven't seen it being used anywhere in the dbdumps I have
            let parsed: VarStoreEfi = data_cursor
                .read_ne()
                .context("Failed to parse VarStoreEfi's data")?;
            debug!("VarStoreEfi is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreEfi(parsed);
        }
        IFROpCode::DefaultStore => {
            let parsed: DefaultStore = data_cursor
                .read_ne()
                .context("Failed to parse DefaultStore's data")?;
            debug!("DefaultStore is {:?}", parsed);
            node.parsed_data = ParsedOperation::DefaultStore(parsed);
        }
        IFROpCode::Default => {
            let parsed: IFRDefault = data_cursor
                .read_ne()
                .context("Failed to parse Default's data")?;
            debug!("Default is {:?}", parsed);
            node.parsed_data = ParsedOperation::IFRDefault(parsed);
        }
        IFROpCode::Form => {
            let parsed: Form = data_cursor
                .read_ne()
                .context("Failed to parse Form's data")?;
            debug!("Form is {:?}", parsed);
            node.parsed_data = ParsedOperation::Form(parsed);
        }
        IFROpCode::Text => {
            let parsed: Text = data_cursor
                .read_ne()
                .context("Failed to parse Text's data")?;
            debug!("Text is {:?}", parsed);
            node.parsed_data = ParsedOperation::Text(parsed);
        }
        IFROpCode::Subtitle => {
            let parsed: Subtitle = data_cursor
                .read_ne()
                .context("Failed to parse Subtitle's data")?;
            debug!("Subtitle is {:?}", parsed);
            node.parsed_data = ParsedOperation::Subtitle(parsed);
        }
        IFROpCode::Numeric => {
            let parsed: Numeric = data_cursor
                .read_ne_args((RangeEncoding::from_question(&node),))
                .context("Failed to parse Numeric's data")?;
            debug!("Numeric is {:?}", parsed);
            node.parsed_data = ParsedOperation::Numeric(parsed);
        }
        IFROpCode::QuestionRef1 => {
            let parsed: QuestionRef1 = data_cursor
                .read_ne()
                .context("Failed to parse QuestionRef1's data")?;
            debug!("QuestionRef1 is {:?}", parsed);
            node.parsed_data = ParsedOperation::QuestionRef1(parsed);
        }
        IFROpCode::EqIdVal => {
            let parsed: EqIdVal = data_cursor
                .read_ne()
                .context("Failed to parse EqIdVal's data")?;
            debug!("EqIdVal is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdVal(parsed);
        }
        IFROpCode::EqIdId => {
            let parsed: EqIdId = data_cursor
                .read_ne()
                .context("failed to parse EqIdId's data")?;
            debug!("EqIdId is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdId(parsed);
        }
        IFROpCode::EqIdValList => {
            let parsed: EqIdValList = data_cursor
                .read_ne()
                .context("Failed to parse EqIdValList's data")?;
            debug!("EqIdValList is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdValList(parsed);
        }
        _ => (),
    }

    Ok(())
}

pub struct QuestionDescriptor {
    pub question: String,
    pub help: String,
    pub value: String,
    max_value: RangeType,
    numeric_range: Option<NumericRange>,
    opcode: IFROpCode,
    pub possible_options: Vec<AnswerOption>,
    header: QuestionHeader,
    varstore: Option<Box<dyn VariableStore>>,
    /// Whether the question is an EDKII bit varstore field, whose VarOffset edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c reads in bits
    refers_to_bit_field: bool,
    /// The state of the option that `value` names: selectable if none does
    pub(crate) value_state: StateEvaluation,
}
impl fmt::Debug for QuestionDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuestionObject")
            .field("question", &self.question)
            .field("value", &self.value)
            .field("help", &self.help)
            .field("possible_options", &self.possible_options)
            .finish()
    }
}

#[derive(Debug)]
pub struct AnswerOption {
    pub value: String,
    raw_value: TypeValue,
    pub(crate) state: StateEvaluation,
}

impl QuestionDescriptor {
    /// The texts of the options that `include` certainly allows: those that get lists and set
    /// takes.
    pub(crate) fn listed_options(&self, include: IncludedStates) -> Vec<String> {
        self.possible_options
            .iter()
            .filter(|option| option.state.is_allowed(include))
            .map(|option| option.value.clone())
            .collect()
    }

    /// Returns the option whose text is one of `texts`, ignoring ASCII case, that select()
    /// picks with `include`, or None if no option has such a text.
    pub(crate) fn select_option(
        &self,
        texts: &HashSet<String>,
        include: IncludedStates,
    ) -> std::result::Result<Option<&AnswerOption>, SelectionError> {
        let matches: Vec<(&AnswerOption, StateEvaluation)> = self
            .possible_options
            .iter()
            .filter(|option| {
                texts
                    .iter()
                    .any(|text| text.eq_ignore_ascii_case(&option.value))
            })
            .map(|option| (option, option.state.clone()))
            .collect();
        let Some(&(first, _)) = matches.first() else {
            return Ok(None);
        };
        let question = self.question.clone();
        match select(matches, include) {
            Selection::Picked(option, _) => Ok(Some(option)),
            Selection::Undetermined {
                likely: (option, _),
                reasons,
                states,
            } => Err(SelectionError::OptionUndetermined {
                question,
                option: option.value.clone(),
                states,
                reasons,
            }),
            Selection::Excluded(states) => Err(SelectionError::OptionExcluded {
                question,
                option: first.value.clone(),
                states,
            }),
            Selection::NotFound => Ok(None),
        }
    }
}

// list_questions returns a list of QuestionDescriptors in a form package
// with their states, of the questions in a state that `include` may allow
// node should be the form_package node
pub fn list_questions(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &[HashMap<i32, String>],
    include: IncludedStates,
    reader: &mut EfivarReader,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let values = VarStoreValues::new(&node);
    list_questions_in(
        &node,
        &mut FormPackageWalk::new(string_packages, reader, &values, include),
    )
}

/// What walking the ops of a form package takes besides them.
struct FormPackageWalk<'a, V> {
    /// The string packages of the form package's package list
    string_packages: &'a [HashMap<i32, String>],
    default_ids: FormSetDefaultIds,
    inputs: ExpressionInputs<'a, V>,
    include: IncludedStates,
}

impl<'a, V> FormPackageWalk<'a, V> {
    fn new(
        string_packages: &'a [HashMap<i32, String>],
        reader: &'a mut EfivarReader,
        values: &'a V,
        include: IncludedStates,
    ) -> Self {
        Self {
            string_packages,
            default_ids: FormSetDefaultIds::default(),
            inputs: ExpressionInputs { reader, values },
            include,
        }
    }
}

/// Lists questions as list_questions does, with `walk`.
fn list_questions_in(
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let mut res: Vec<_> = listed_question(node, walk).into_iter().collect();

    // Now look inside current node's children for more questions
    // TODO: skip the scopes that skips_scope names, as questions_named does.
    for child in &node.borrow().children {
        res.extend(list_questions_in(child, walk));
    }

    res
}

/// Returns the QuestionDescriptor and states of a ONE_OF, NUMERIC or CHECKBOX in a state that
/// `walk.include` may allow.
fn listed_question(
    question: &Rc<RefCell<IFROperation>>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> Option<(QuestionDescriptor, StateEvaluation)> {
    let op = question.borrow();
    let value_question = value_question(&op)?;
    let state = question_state(&op, &mut walk.inputs);
    if !state.may_be_allowed(walk.include) {
        return None;
    }
    let descriptor = describe_question(question, &op, value_question, walk);
    Some((descriptor, state))
}

/// find_question accepts the root node, string_packages and possible_question_phrases.
/// possible_question_phrases is a vector of strings which represent variations of the
/// same question. So if a single phrase matches then we assume that we have the answer.
/// Of the matching questions, it selects one as select does.
pub fn find_question<T>(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &[HashMap<i32, String>],
    possible_question_phrases: &HashSet<T>,
    include: IncludedStates,
    reader: &mut EfivarReader,
) -> Selection<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let values = VarStoreValues::new(&node);
    find_question_in(
        &node,
        possible_question_phrases,
        &mut FormPackageWalk::new(string_packages, reader, &values, include),
    )
}

/// Finds a question as find_question does, with `walk`.
fn find_question_in<T>(
    node: &Rc<RefCell<IFROperation>>,
    possible_question_phrases: &HashSet<T>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> Selection<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let questions = questions_named(node, walk.string_packages, possible_question_phrases);
    let ops: Vec<std::cell::Ref<IFROperation>> =
        questions.iter().map(|question| question.borrow()).collect();
    let matches = questions
        .iter()
        .zip(&ops)
        .filter_map(|(question, op)| {
            let value_question = value_question(op)?;
            let state = question_state(op, &mut walk.inputs);
            Some(((question, op, value_question), state))
        })
        .collect();
    select(matches, walk.include)
        .map(|(question, op, value_question)| describe_question(question, op, value_question, walk))
}

/// set's choice of the selection of a form package: that of Selection::for_set, unless the
/// efivar of the match that set would write, or of the likely match, is missing or
/// boot-service-only, which --include cannot make writable: then VariableNotExported, as
/// `reader` found it, or BootServiceOnlyVariable.
pub(crate) fn choice_for_set(
    selection: Selection<QuestionDescriptor>,
    question: &str,
    reader: &EfivarReader,
) -> Result<Choice<QuestionDescriptor>> {
    let store = match &selection {
        Selection::Picked(descriptor, _)
        | Selection::Undetermined {
            likely: (descriptor, _),
            ..
        } => descriptor.varstore.as_deref(),
        Selection::Excluded(_) | Selection::NotFound => None,
    };
    if let Some(store) = store {
        store.check_runtime_access()?;
        if let Some(missing) = reader.missing(store) {
            return Err(VariableNotExported(missing.clone()).into());
        }
    }
    Ok(selection.for_set(question)?)
}

#[cfg(test)]
mod choice_for_set_tests {
    use super::ifr_fixtures::*;
    use super::*;

    /// The text of write_at_offset's refusal of the boot-service-only efivar Present.
    const PRESENT_BOOT_SERVICE_ONLY: &str = "EFI variable \
        Present-00000000-0000-0000-0000-000000000000 is boot-service-only and cannot be written \
        through efivarfs";
    /// The EfivarNotFound of the efivar Missing.
    const MISSING_NOT_FOUND: &str = "no EFI variable Missing-00000000-0000-0000-0000-000000000000";
    /// Why the EQ_ID_VAL on question 2, on the efivar Missing, is not evaluated.
    const MISSING_INPUT: &str = "EqIdVal of question 0x0002: <ValueUnavailable: no EFI variable \
        Missing-00000000-0000-0000-0000-000000000000>";

    /// set's choice for PROMPT in the form package `root`, where only the efivar Present, of
    /// 1 byte, exists.
    fn choice_in(root: &Rc<RefCell<IFROperation>>) -> Result<Choice<QuestionDescriptor>> {
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Present", 1), &[0]);
        let mut reader = efivars.reader();
        let values = VarStoreValues::new(root);
        let selection = find_question_in(
            root,
            &HashSet::from([PROMPT]),
            &mut FormPackageWalk::new(&strings(), &mut reader, &values, IncludedStates::empty()),
        );
        choice_for_set(selection, PROMPT, &reader)
    }

    /// set's choice for PROMPT, prompting question 1 on VarStore `own` under a SUPPRESS_IF on
    /// question 2, which is on VarStore 2; VarStore 3 is VarStore 1 without runtime access,
    /// and only their efivar exists.
    fn choice(own: u16) -> Result<Choice<QuestionDescriptor>> {
        choice_in(&parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store_efi(2, "Missing", NV_BS_RT, 1),
            var_store_efi(3, "Present", NV_BS, 1),
            form(
                1,
                &[
                    checkbox_on(2, 5, 2),
                    conditional(SUPPRESS_IF, eq_id_val_of(2, 1), &[checkbox_on(1, 3, own)]),
                ],
            ),
        ]))
    }

    /// set's choice for PROMPT, prompting a selectable ONE_OF on VarStore 1, after the
    /// VarStores `var_stores`, whose option Enabled is under a SUPPRESS_IF on question 2 of
    /// VarStore `input`.
    fn picked_choice(var_stores: &[Vec<u8>], input: u16) -> Result<Choice<QuestionDescriptor>> {
        let (root, _question) = parse_question(
            &[var_stores, &[checkbox_on(2, 5, input)]].concat(),
            ONE_OF,
            &one_of_data(),
            &[
                flagged_option(5, 0x00, 0),
                conditional(
                    SUPPRESS_IF,
                    eq_id_val_of(2, 1),
                    &[flagged_option(6, 0x00, 1)],
                ),
            ],
        );
        choice_in(&root)
    }

    #[test]
    fn undetermined_match_on_a_missing_efivar_is_not_exported() {
        let error = choice(2).expect_err("set refuses question 1");
        assert_eq!(
            error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.0.to_string())
                .as_deref(),
            Some(MISSING_NOT_FOUND),
            "question 1 on the missing VarStore: {error:#}"
        );
    }

    #[test]
    fn undetermined_match_on_a_present_efivar_is_undetermined() {
        let error = choice(1).expect_err("set refuses question 1");
        assert_eq!(
            error.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Undetermined {
                question: PROMPT.to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![MISSING_INPUT.to_string()],
            }),
            "question 1 on the present VarStore"
        );
    }

    #[test]
    fn picked_match_on_a_missing_efivar_is_not_exported() {
        let error = picked_choice(&[var_store_efi(1, "Missing", NV_BS_RT, 1)], 1)
            .expect_err("set refuses the ONE_OF");
        assert_eq!(
            error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.0.to_string())
                .as_deref(),
            Some(MISSING_NOT_FOUND),
            "the ONE_OF on the missing VarStore: {error:#}"
        );
    }

    #[test]
    fn picked_match_on_a_present_efivar_is_chosen() {
        let choice = picked_choice(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        assert!(
            matches!(choice, Ok(Choice::Chosen(..))),
            "the ONE_OF on the present VarStore: {choice:?}"
        );
    }

    #[test]
    fn picked_match_with_a_missing_condition_input_is_chosen() {
        let choice = picked_choice(
            &[
                var_store_efi(1, "Present", NV_BS_RT, 1),
                var_store_efi(2, "Missing", NV_BS_RT, 1),
            ],
            2,
        );
        let Ok(Choice::Chosen(descriptor, _)) = choice else {
            panic!("the ONE_OF on the present VarStore: {choice:?}");
        };
        let enabled = HashSet::from(["Enabled".to_string()]);
        let selected = |include| {
            descriptor
                .select_option(&enabled, include)
                .map(|option| option.map(|option| option.value.as_str()))
        };

        assert_eq!(
            selected(IncludedStates::empty()),
            Err(SelectionError::OptionUndetermined {
                question: PROMPT.to_string(),
                option: "Enabled".to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![MISSING_INPUT.to_string()],
            }),
            "Enabled without --include"
        );
        assert_eq!(
            selected(IncludedStates::SUPPRESSED),
            Ok(Some("Enabled")),
            "Enabled with --include suppressed"
        );
    }

    #[test]
    fn match_on_a_boot_service_only_store_is_refused() {
        let cases = [
            ("undetermined", choice(3)),
            (
                "picked",
                picked_choice(&[var_store_efi(1, "Present", NV_BS, 1)], 1),
            ),
        ];
        for (case, choice) in cases {
            assert_eq!(
                choice.map_err(|error| error.to_string()).err().as_deref(),
                Some(PRESENT_BOOT_SERVICE_ONLY),
                "{case}"
            );
        }
    }
}

/// Returns the ONE_OF, NUMERIC and CHECKBOX questions under `node`, in IFR order, whose
/// prompt is one of `phrases`, ignoring ASCII case and surrounding whitespace.
fn questions_named<T>(
    node: &Rc<RefCell<IFROperation>>,
    string_packages: &[HashMap<i32, String>],
    phrases: &HashSet<T>,
) -> Vec<Rc<RefCell<IFROperation>>>
where
    T: AsRef<str>,
{
    fn walk<T: AsRef<str>>(
        node: &Rc<RefCell<IFROperation>>,
        string_packages: &[HashMap<i32, String>],
        phrases: &HashSet<T>,
        found: &mut Vec<Rc<RefCell<IFROperation>>>,
    ) {
        let op = node.borrow();
        if skips_scope(&op) {
            return;
        }
        let prompt = prompt(&op, string_packages).trim();
        // Only Numeric, OneOf and CheckBox are questions.
        if value_question(&op).is_some()
            && phrases
                .iter()
                .any(|phrase| phrase.as_ref().eq_ignore_ascii_case(prompt))
        {
            found.push(Rc::clone(node));
        }
        for child in &op.children {
            walk(child, string_packages, phrases, found);
        }
    }
    let mut found = Vec::new();
    walk(node, string_packages, phrases, &mut found);
    found
}

/// Returns the prompt of a ONE_OF, NUMERIC or CHECKBOX, empty for other ops.
fn prompt<'a>(op: &IFROperation, string_packages: &'a [HashMap<i32, String>]) -> &'a str {
    value_question(op).map_or("", |question| {
        find_corresponding_string(question.header().prompt_string_id, string_packages)
    })
}

/// Returns the QuestionDescriptor of `question`, whose op `op` is `value_question`.
fn describe_question(
    question: &Rc<RefCell<IFROperation>>,
    op: &std::cell::Ref<IFROperation>,
    value_question: ValueQuestion<'_>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let header = value_question.header();
    let prompt = find_corresponding_string(header.prompt_string_id, walk.string_packages);
    let varstore = find_corresponding_varstore(Rc::clone(question), header.var_store_id);
    match value_question {
        ValueQuestion::OneOf(parsed) => handle_oneof(varstore, parsed, prompt, op, walk),
        ValueQuestion::Numeric(parsed) => handle_numeric(varstore, parsed, prompt, op, walk),
        ValueQuestion::CheckBox(parsed) => handle_checkbox(varstore, parsed, prompt, op, walk),
    }
}

fn handle_checkbox(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &CheckBox,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let mut answer = String::new();
    let available = match read_question_bytes(current_node, &varstore, walk.inputs.reader) {
        Err(reason) => {
            answer.push_str(&reason);
            false
        }
        Ok(bytes) => {
            answer.push_str(&stored_value(bytes).to_string());
            true
        }
    };
    if !available {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        push_default(
            &mut answer,
            current_node,
            default_ids,
            &mut walk.inputs,
            // FALSE or TRUE (UEFI 2.10 §33.3.8.3.9)
            |v, _| Ok::<_, Infallible>(u8::from(v != 0).to_string()),
        );
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options: Vec::new(),
        header: parsed.question_header(),
        varstore: varstore.ok(),
        refers_to_bit_field: refers_to_bit_field(current_node),
        max_value: RangeType::NumSize8(1),
        numeric_range: None,
        opcode: current_node.op_code,
        value_state: StateEvaluation::selectable(),
    };
    res
}

fn handle_oneof(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &OneOf,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let mut answer = String::new();
    // None, with the reason in `answer`, when the current value cannot be read: any u64,
    // all ones too, can be stored.
    let chosen_value = match read_question_bytes(current_node, &varstore, walk.inputs.reader) {
        Err(reason) => {
            answer.push_str(&reason);
            None
        }
        Ok(bytes) => Some(stored_value(bytes)),
    };

    if chosen_value.is_none() {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        match numeric_format(current_node, parsed.flags, &parsed.data) {
            Ok(format) => push_default(
                &mut answer,
                current_node,
                default_ids,
                &mut walk.inputs,
                |v, inputs| {
                    option_text(current_node, format.cut(v), walk.string_packages, inputs).map(
                        |option| {
                            option.unwrap_or_else(|| {
                                format!("{} (no matching option)", format.decode(v))
                            })
                        },
                    )
                },
            ),
            Err(error) => push_default(
                &mut answer,
                current_node,
                default_ids,
                &mut walk.inputs,
                |_, _| Err::<String, _>(error),
            ),
        }
    }

    let mut possible_options = Vec::new();
    // Some of OneOf's children are OneOfOptions

    for op in question_scope(current_node) {
        let op = op.borrow();
        if let ParsedOperation::OneOfOption(o) = &op.parsed_data {
            possible_options.push(AnswerOption {
                raw_value: o.value,
                value: find_corresponding_string(o.option_string_id, walk.string_packages)
                    .to_string(),
                state: option_state(&op, &mut walk.inputs),
            });
        }
    }
    let chosen: Vec<&AnswerOption> = possible_options
        .iter()
        .filter(
            |opt| matches!((chosen_value, opt.raw_value.as_u64()), (Some(a), Some(b)) if a == b),
        )
        .collect();
    // the first that may be shown, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption
    // finds it, else the first, which a SUPPRESS_IF hides
    let value_state = match chosen
        .iter()
        .find(|opt| opt.state.may_be_allowed(IncludedStates::empty()))
        .or(chosen.first())
    {
        Some(opt) => {
            answer.push_str(opt.value.trim());
            opt.state.clone()
        }
        None => StateEvaluation::selectable(),
    };
    if answer.is_empty() {
        answer.push_str("Unknown");
    }

    let res = QuestionDescriptor {
        question: question.trim().to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options,
        header: parsed.question_header(),
        varstore: varstore.ok(),
        refers_to_bit_field: refers_to_bit_field(current_node),
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        numeric_range: None,
        opcode: current_node.op_code,
        value_state,
    };
    res
}

fn handle_numeric(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &Numeric,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
    walk: &mut FormPackageWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let mut answer = String::new();

    let available = match read_question_bytes(current_node, &varstore, walk.inputs.reader) {
        Err(reason) => {
            answer.push_str(&reason);
            false
        }
        // read_question_bytes refuses bit-field questions, so the Range gives the width
        Ok(bytes) => {
            let format = NumericFormat::from_ifr(&parsed.data, parsed.flags);
            answer.push_str(&format.decode(stored_value(bytes)).to_string());
            true
        }
    };
    if !available {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        push_default(
            &mut answer,
            current_node,
            default_ids,
            &mut walk.inputs,
            |v, _| {
                numeric_format(current_node, parsed.flags, &parsed.data)
                    .map(|format| format.decode(v).to_string())
            },
        );
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options: Vec::new(),
        header: parsed.question_header(),
        varstore: varstore.ok(),
        refers_to_bit_field: refers_to_bit_field(current_node),
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        // TODO: None for bit fields: from_ifr reads EFI_IFR_DISPLAY from EDKII bit-field Flags
        numeric_range: Some(NumericRange::from_ifr(&parsed.data, parsed.flags)),
        opcode: current_node.op_code,
        value_state: StateEvaluation::selectable(),
    };
    res
}

#[cfg(test)]
mod question_value_tests {
    use std::io::SeekFrom;

    use super::ifr_fixtures::*;
    use super::*;

    const BIT_FIELD_NOT_DECODED: &str = "<ValueUnavailable: EDKII bit-field value not decoded>";

    #[test]
    fn readable_checkbox_shows_no_default() {
        assert_eq!(
            answer(&[], CHECKBOX, &checkbox(0, 0x01), &[], var_store_of(&[0])),
            "0",
            "readable CHECKBOX"
        );
    }

    #[test]
    fn checkbox_past_var_store_shows_bracketed_error_and_default() {
        assert_eq!(
            answer(&[], CHECKBOX, &checkbox(1, 0x01), &[], var_store_of(&[0])),
            "<ExtractEFIDataError: failed to fill whole buffer (offset: 1; buflen: 5)> \
             <IFR default: 1>",
            "CHECKBOX past its VarStore"
        );
    }

    fn one_of_value(data: &[u8], children: &[Vec<u8>], var_store: VarStoreFixture) -> String {
        answer(&[], ONE_OF, data, children, var_store)
    }

    /// A UINT8 ONE_OF of options Disabled (0) and Enabled (1) whose
    /// manufacturing EFI_IFR_DEFAULT (DefaultId 1) has Value 0.
    fn uint8_one_of(offset: u16) -> (Vec<u8>, Vec<Vec<u8>>) {
        let data = [&question_header(offset)[..], &[0x00, 0x00, 0x01, 0x01]].concat();
        let children = vec![
            one_of_option(5, 0x00, &[0]),
            one_of_option(6, 0x00, &[1]),
            ifr_default(0x0001, 0),
        ];
        (data, children)
    }

    #[test]
    fn one_of_storing_all_ones_shows_that_option() {
        let data = [
            &question_header(0)[..],
            &[0x03],                 // Flags: UINT64
            &0u64.to_le_bytes(),     // MinValue
            &u64::MAX.to_le_bytes(), // MaxValue
            &1u64.to_le_bytes(),     // Step
        ]
        .concat();
        let children = [
            one_of_option(5, 0x03, &0u64.to_le_bytes()),
            one_of_option(7, 0x03, &u64::MAX.to_le_bytes()),
            ifr_default(0x0000, 0),
        ];

        let got = one_of_value(&data, &children, var_store_of(&u64::MAX.to_le_bytes()));

        assert_eq!(got, "AllOnes", "ONE_OF storing all ones");
    }

    /// The DefaultId (1 = Enabled) is not a value, and nothing is shown as
    /// the current value when it cannot be read.
    #[test]
    fn one_of_past_var_store_shows_extraction_error() {
        let (data, children) = uint8_one_of(8);
        let declarations = [default_store(0x0000), default_store(0x0001)];
        let var_store = var_store_of(&[1; 8]);

        let got = answer(&declarations, ONE_OF, &data, &children, var_store);

        assert_eq!(
            got,
            "<ExtractEFIDataError: failed to fill whole buffer (offset: 8; buflen: 12)> \
             <IFR default (DefaultId 0x0001): Disabled>",
            "ONE_OF past its VarStore"
        );
    }

    #[test]
    fn one_of_without_var_store_shows_only_the_reason() {
        let (data, children) = uint8_one_of(0);

        let got = one_of_value(&data, &children, unavailable());

        assert_eq!(got, UNAVAILABLE, "ONE_OF without VarStore");
    }

    #[test]
    fn one_of_shows_stored_option() {
        let (data, children) = uint8_one_of(7);

        let got = one_of_value(&data, &children, var_store_of(&[0, 0, 0, 0, 0, 0, 0, 1]));

        assert_eq!(got, "Enabled", "ONE_OF storing option 1");
    }

    /// A ONE_OF answers the option whose value, decoded as defaults are, is the
    /// stored one: a BOOLEAN option TRUE is 1, and an option of another Type
    /// matches nothing, not even an unreadable value.
    #[test]
    fn one_of_matches_options_by_their_decoded_value() {
        let cases = [
            (
                "BOOLEAN options",
                vec![one_of_option(5, 0x04, &[0]), one_of_option(6, 0x04, &[1])],
                var_store_of(&[1]),
                "Enabled",
            ),
            (
                "DATE option before a UINT8 option of 0",
                vec![one_of_option(5, 0x06, &[0]), one_of_option(6, 0x00, &[0])],
                var_store_of(&[0]),
                "Enabled",
            ),
            (
                "DATE option without a current value",
                vec![one_of_option(5, 0x06, &[0])],
                unavailable(),
                UNAVAILABLE,
            ),
        ];
        for (name, children, var_store, want) in cases {
            assert_eq!(
                answer(&[], ONE_OF, &one_of_data(), &children, var_store),
                want,
                "{name}"
            );
        }
    }

    #[test]
    fn one_of_shows_default_only_without_current_value() {
        let children = [
            one_of_option(5, 0x00, &[0]),
            one_of_option(6, 0x00, &[1]),
            ifr_default(0x0000, 1),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "unreadable ONE_OF"
        );
        assert_eq!(
            answer(&[], ONE_OF, &one_of_data(), &children, var_store_of(&[0])),
            "Disabled",
            "readable ONE_OF"
        );
    }

    #[test]
    fn one_of_default_without_option_shows_its_value() {
        let children = [one_of_option(5, 0x00, &[0]), ifr_default(0x0000, 7)];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: 7 (no matching option)>"),
            "ONE_OF default without option"
        );
    }

    /// A ONE_OF default is cut to the ONE_OF's width before it is matched to an
    /// option, and a CHECKBOX has only FALSE and TRUE (UEFI 2.10 §33.3.8.3.9).
    #[test]
    fn one_of_and_checkbox_defaults_are_cut_to_question_values() {
        // Type UINT16, Value 0x0101 and 0x0107
        let uint16_default = |value: u16| {
            let data = [&[0x00, 0x00, 0x01][..], &value.to_le_bytes()].concat();
            operation(DEFAULT, false, &data)
        };
        let options = || vec![one_of_option(5, 0x00, &[0]), one_of_option(6, 0x00, &[1])];
        let cases = [
            (
                "UINT16 default of a UINT8 ONE_OF",
                ONE_OF,
                one_of_data(),
                [options(), vec![uint16_default(0x0101)]].concat(),
                " <IFR default: Enabled>",
            ),
            (
                "UINT16 default of a UINT8 ONE_OF without its option",
                ONE_OF,
                one_of_data(),
                [options(), vec![uint16_default(0x0107)]].concat(),
                " <IFR default: 7 (no matching option)>",
            ),
            (
                "ONES default of a UINT8 ONE_OF",
                ONE_OF,
                one_of_data(),
                vec![
                    one_of_option(5, 0x00, &[0]),
                    one_of_option(7, 0x00, &[0xFF]),
                    ifr_default_2(0x0000, ifr_ones()),
                ],
                " <IFR default: AllOnes>",
            ),
            (
                "ONES default of a CHECKBOX",
                CHECKBOX,
                checkbox(0, 0x00),
                vec![ifr_default_2(0x0000, ifr_ones())],
                " <IFR default: 1>",
            ),
            (
                "UINT8 2 default of a CHECKBOX",
                CHECKBOX,
                checkbox(0, 0x00),
                vec![ifr_default(0x0000, 2)],
                " <IFR default: 1>",
            ),
        ];
        for (name, op_code, data, children, suffix) in cases {
            assert_eq!(
                answer(&[], op_code, &data, &children, unavailable()),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// Fails every read with an error other than a short read.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated read failure"))
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn default_value_read_failure_other_than_short_read_is_an_error() {
        let short = default_value_parser(
            &mut Cursor::new(&[0x00][..]),
            binrw::Endian::Little,
            (0x01,),
        );
        let failed = default_value_parser(&mut FailingReader, binrw::Endian::Little, (0x00,));

        assert!(
            matches!(short, Ok(IfrDefaultValue::Missing)),
            "short read: {short:?}"
        );
        assert!(
            matches!(
                &failed,
                Err(binrw::Error::Io(error)) if error.kind() == std::io::ErrorKind::Other
            ),
            "failed read: {failed:?}"
        );
    }

    #[test]
    fn numeric_shows_default_only_without_current_value() {
        let data = uint8_numeric(0x10, 0, 10);
        let children = [ifr_default(0x0000, 5)];

        assert_eq!(
            answer(&[], NUMERIC, &data, &children, unavailable()),
            format!("{UNAVAILABLE} <IFR default: 5>"),
            "unreadable NUMERIC"
        );
        assert_eq!(
            answer(&[], NUMERIC, &data, &children, var_store_of(&[7])),
            "7",
            "readable NUMERIC"
        );
    }

    #[test]
    fn signed_numeric_default_is_signed() {
        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x00, 0xFB, 5),
            &[ifr_default(0x0000, 0xFF)],
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: -1>"),
            "signed UINT8 NUMERIC"
        );
    }

    #[test]
    fn signed_uint16_numeric_default_is_signed() {
        let data = [
            &question_header(0)[..],
            &[0x01],                 // Flags: UINT16, EFI_IFR_DISPLAY_INT_DEC
            &(-10i16).to_le_bytes(), // MinValue
            &10i16.to_le_bytes(),    // MaxValue
            &1u16.to_le_bytes(),     // Step
        ]
        .concat();
        // Type UINT16, Value 0xFFFE
        let default = operation(DEFAULT, false, &[0x00, 0x00, 0x01, 0xFE, 0xFF]);

        let got = answer(&[], NUMERIC, &data, &[default], unavailable());

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: -2>"),
            "signed UINT16 NUMERIC"
        );
    }

    #[test]
    fn unsigned_numeric_default_is_cut_to_question_size() {
        // Type UINT16, Value 0x01FF
        let default = operation(DEFAULT, false, &[0x00, 0x00, 0x01, 0xFF, 0x01]);

        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[default],
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: 255>"),
            "UINT16 default of a UINT8 NUMERIC"
        );
    }

    /// The answer of a NUMERIC with `flags`, Range UINT32 0..=300 and a UINT32
    /// standard default of `default`, in the scope of an EFI_IFR_GUID of `guid`.
    fn numeric_in_guid_answer(guid: [u8; 16], flags: u8, default: u32) -> String {
        answer_in_guid(
            guid,
            NUMERIC,
            &uint32_range_question(0, flags),
            &[uint32_default(0x0000, default)],
            unavailable(),
        )
    }

    /// A bit-field default is cut to the width in EDKII_IFR_NUMERIC_SIZE_BIT, 1 to 32, and
    /// EDKII_IFR_DISPLAY_INT_DEC_BIT signs it as a UINT32.
    #[test]
    fn bit_field_numeric_default_has_edkii_width_and_display() {
        let cases = [
            (
                "12-bit UINT_DEC",
                BIT_VARSTORE_GUID,
                0x4C,
                200,
                " <IFR default: 200>",
            ),
            (
                "8-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x08,
                0xFF,
                " <IFR default: 255>",
            ),
            (
                "12-bit UINT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x4C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit UINT_HEX all ones",
                BIT_VARSTORE_GUID,
                0x8C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x0C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit INT_DEC over 2047",
                BIT_VARSTORE_GUID,
                0x0C,
                3000,
                " <IFR default: 3000>",
            ),
            (
                "32-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x20,
                u32::MAX,
                " <IFR default: -1>",
            ),
            (
                "zero width",
                BIT_VARSTORE_GUID,
                0x40,
                1,
                " <IFR default: unknown (EDKII bit-field width 0, not 1 to 32)>",
            ),
            (
                "33-bit width",
                BIT_VARSTORE_GUID,
                0x61,
                1,
                " <IFR default: unknown (EDKII bit-field width 33, not 1 to 32)>",
            ),
            // Flags 0x00: UINT8 INT_DEC
            ("other GUID", OTHER_GUID, 0x00, 0xC8, " <IFR default: -56>"),
        ];
        for (name, guid, flags, default, suffix) in cases {
            assert_eq!(
                numeric_in_guid_answer(guid, flags, default),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// show-ifr does not decode a readable EDKII bit varstore field either.
    #[test]
    fn show_ifr_answer_of_bit_field_is_not_decoded() {
        for (guid, want) in [
            (BIT_VARSTORE_GUID, BIT_FIELD_NOT_DECODED),
            (OTHER_GUID, "1"),
        ] {
            let (_root, node) = parse_question_in_guid(guid, CHECKBOX, &checkbox(3, 0x00), &[]);
            let question = node.borrow();

            let VarStoreFixture { store, efivars } = var_store_of(&[0x00, 0x00, 0x00, 0x01]);

            let got = display_answer(&question, &store, &mut efivars.reader());

            assert_eq!(got, want, "GUID {guid:02X?}");
        }
    }

    /// An unmatched ONE_OF default is the number that its Flags, those of a NUMERIC (UEFI
    /// 2.10 §33.3.8.3.50), display, as for a NUMERIC default.
    #[test]
    fn unmatched_one_of_default_is_displayed_as_its_flags_say() {
        let cases = [
            (
                "12-bit INT_DEC over 2047",
                BIT_VARSTORE_GUID,
                0x0C,
                3000,
                "3000",
            ),
            (
                "12-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x0C,
                u32::MAX,
                "4095",
            ),
            (
                "32-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x20,
                u32::MAX,
                "-1",
            ),
            (
                "32-bit UINT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x60,
                u32::MAX,
                "4294967295",
            ),
            // Flags 0x02: UINT32 INT_DEC; 0x12: UINT32 UINT_DEC
            ("UINT32 INT_DEC all ones", OTHER_GUID, 0x02, u32::MAX, "-1"),
            (
                "UINT32 UINT_DEC all ones",
                OTHER_GUID,
                0x12,
                u32::MAX,
                "4294967295",
            ),
        ];
        for (name, guid, flags, default, number) in cases {
            let children = [
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                uint32_default(0x0000, default),
            ];
            assert_eq!(
                answer_in_guid(
                    guid,
                    ONE_OF,
                    &uint32_range_question(0, flags),
                    &children,
                    unavailable()
                ),
                format!("{UNAVAILABLE} <IFR default: {number} (no matching option)>"),
                "{name}"
            );
        }
    }

    /// A readable EDKII bit varstore field's stored value is not decoded, and its
    /// default is shown, as for any value that cannot be read.
    #[test]
    fn readable_bit_field_question_shows_its_default() {
        let store = || var_store_of(&[0x00, 0xC8, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let one_of_children = || {
            vec![
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                one_of_option(6, 0x02, &1u32.to_le_bytes()),
            ]
        };
        let cases = [
            (
                "12-bit UINT_DEC NUMERIC",
                NUMERIC,
                uint32_range_question(4, 0x4C),
                vec![uint32_default(0x0000, 200)],
                " <IFR default: 200>",
            ),
            (
                "CHECKBOX",
                CHECKBOX,
                checkbox(4, 0x01),
                vec![],
                " <IFR default: 1>",
            ),
            (
                "2-bit UINT_DEC ONE_OF",
                ONE_OF,
                uint32_range_question(4, 0x42),
                [one_of_children(), vec![uint32_default(0x0000, 1)]].concat(),
                " <IFR default: Enabled>",
            ),
            (
                "2-bit ONE_OF default cut to its width",
                ONE_OF,
                uint32_range_question(4, 0x42),
                [one_of_children(), vec![uint32_default(0x0000, 0b101)]].concat(),
                " <IFR default: Enabled>",
            ),
        ];
        for (name, op_code, data, children, suffix) in cases {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children, store()),
                format!("{BIT_FIELD_NOT_DECODED}{suffix}"),
                "{name}"
            );
        }
    }

    /// A ONE_OF bit field of width 33 shows its default as unknown for its width, unless the
    /// default itself is unknown, whose reason shows instead.
    #[test]
    fn one_of_bit_field_width_33_default_is_unknown() {
        let reason = "EDKII bit-field width 33, not 1 to 32";
        let cases = [
            (
                "constant DEFAULT",
                uint32_default(0x0000, 1),
                format!("{UNAVAILABLE} <IFR default: unknown ({reason})>"),
            ),
            (
                "non-constant DEFAULT_2",
                ifr_default_2(0x0000, eq_id_val()),
                format!(
                    "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_VALUE expression not \
                     evaluated: EqIdVal of question 0x0001: <ValueUnavailable: no supported \
                     varstore with matching id 0x0001 found>)>"
                ),
            ),
        ];
        for (name, default, want) in cases {
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    ONE_OF,
                    // Flags: EDKII_IFR_DISPLAY_UINT_DEC_BIT, width 33
                    &uint32_range_question(0, 0x61),
                    &[default],
                    unavailable()
                ),
                want,
                "{name}"
            );
        }
    }

    /// The Range of the NUMERIC or ONE_OF `question`.
    fn question_range(question: &IFROperation) -> &Range {
        match &question.parsed_data {
            ParsedOperation::Numeric(parsed) => &parsed.data,
            ParsedOperation::OneOf(parsed) => &parsed.data,
            other => panic!("not a NUMERIC or ONE_OF: {other:?}"),
        }
    }

    /// A NUMERIC or ONE_OF at VarOffset 0 with `flags` and the MinValue, MaxValue and Step of
    /// `range`, in its size.
    fn range_question(flags: u8, range: &Range) -> Vec<u8> {
        let values = match range {
            Range::Range8(r) => [r.min_value, r.max_value, r.step]
                .map(u8::to_le_bytes)
                .concat(),
            Range::Range16(r) => [r.min_value, r.max_value, r.step]
                .map(u16::to_le_bytes)
                .concat(),
            Range::Range32(r) => [r.min_value, r.max_value, r.step]
                .map(u32::to_le_bytes)
                .concat(),
            Range::Range64(r) => [r.min_value, r.max_value, r.step]
                .map(u64::to_le_bytes)
                .concat(),
        };
        [question_header(0), vec![flags], values].concat()
    }

    /// An EDKII bit varstore field's Range is UINT32, whatever its width in Flags.
    #[test]
    fn bit_field_range_is_uint32() {
        let want = Range::Range32(Range32 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let cases = [
            ("3-bit UINT_DEC", 0x43),
            ("19-bit UINT_HEX", 0x93),
            ("19-bit INT_DEC", 0x13),
            ("1-bit UINT_DEC", 0x41),
            ("17-bit UINT_DEC", 0x51),
            ("12-bit UINT_DEC", 0x4C),
            ("zero width", 0x40),
            ("33-bit width", 0x61),
        ];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, flags) in cases {
                let data = range_question(flags, &want);
                let (_root, question) =
                    try_parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &[])
                        .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    &want,
                    "{name}, op {op_code:#04x}"
                );
            }
        }
    }

    /// A question outside an EDKII bit varstore field's GUID has the Range size of
    /// EFI_IFR_NUMERIC_SIZE, also right after such a field and in another GUID.
    #[test]
    fn non_bit_field_range_has_efi_ifr_numeric_size() {
        let want = Range::Range64(Range64 {
            min_value: 0,
            max_value: 1 << 40,
            step: 1,
        });
        let data = range_question(0x13, &want); // UINT64 UINT_DEC
        let bit_field = [
            operation(GUID, true, &BIT_VARSTORE_GUID),
            operation(NUMERIC, true, &uint32_range_question(0, 0x42)),
            END.to_vec(), // End of the NUMERIC
            END.to_vec(), // End of the GUID
        ]
        .concat();
        let cases = [("alone", vec![]), ("after a bit field", vec![bit_field])];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, declarations) in &cases {
                let (_root, question) = try_parse_question(declarations, op_code, &data, &[])
                    .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    &want,
                    "{name}, op {op_code:#04x}"
                );
            }

            let (_root, question) = try_parse_question_in_guid(OTHER_GUID, op_code, &data, &[])
                .unwrap_or_else(|e| panic!("parse other GUID, op {op_code:#04x}: {e:#}"));

            assert_eq!(
                question_range(&question.borrow()),
                &want,
                "other GUID, op {op_code:#04x}"
            );
        }
    }

    /// Reserved Flags bits 2-3 do not change the Range size that EFI_IFR_NUMERIC_SIZE gives.
    #[test]
    fn reserved_flags_bits_do_not_change_range_size() {
        let uint8 = Range::Range8(Range8 {
            min_value: 0,
            max_value: 10,
            step: 1,
        });
        let uint16 = Range::Range16(Range16 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let uint32 = Range::Range32(Range32 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let uint64 = Range::Range64(Range64 {
            min_value: 0,
            max_value: 1 << 40,
            step: 1,
        });
        let cases = [
            ("UINT8", 0x00, &uint8),
            ("UINT8 with reserved bit 2", 0x04, &uint8),
            ("UINT16", 0x01, &uint16),
            ("UINT16 with reserved bit 2", 0x05, &uint16),
            ("UINT32", 0x02, &uint32),
            ("UINT32 with reserved bits 2-3", 0x0E, &uint32),
            ("UINT64", 0x03, &uint64),
            ("UINT64 with reserved bit 2", 0x07, &uint64),
            ("UINT64 with reserved bits 2-3", 0x0F, &uint64),
        ];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, flags, want) in cases {
                let data = range_question(flags, want);
                let (_root, question) = try_parse_question(&[], op_code, &data, &[])
                    .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    want,
                    "{name}, op {op_code:#04x}"
                );
            }
        }
    }
}

// display returns a String which is our tree like representation of a Forms package
// TODO: show the default of an unreadable OneOf, Numeric or CheckBox, as list_questions does.
// TODO: show the state that the conditions give each question and option, as list-questions
// does.
pub fn display(
    node: Rc<RefCell<IFROperation>>,
    level: usize,
    string_packages: &[HashMap<i32, String>],
    reader: &mut EfivarReader,
) -> Result<String> {
    let mut result = String::new();
    let extra_spaces = "    ".repeat(level);

    let current_node = node.borrow();

    match &current_node.parsed_data {
        ParsedOperation::Placeholder => {
            if current_node.op_code == IFROpCode::Unknown(DUMMY_OPCODE) {
                result.push_str(format!("{extra_spaces}OpCode: ROOT\n").as_str())
            }
        }
        ParsedOperation::Subtitle(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - S: {}\n",
                current_node.op_code,
                find_corresponding_string(parsed.prompt_string_id, string_packages),
            )
            .as_str(),
        ),
        ParsedOperation::FormSet(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - {} - GUID {} - ClassGUID {}\n",
                current_node.op_code,
                find_corresponding_string(parsed.title_string_id, string_packages),
                parsed.guid,
                parsed.class_guid,
            )
            .as_str(),
        ),
        ParsedOperation::VarStore(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - Name: {}\n",
                current_node.op_code,
                parsed.name,
            )
            .as_str(),
        ),
        ParsedOperation::VarStoreNameValue(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - Id: {} - Guid: {}\n",
                current_node.op_code, parsed.var_store_id, parsed.guid,
            )
            .as_str(),
        ),
        ParsedOperation::OneOfOption(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - S: {}\n{extra_spaces}-ValueType:{}\n{extra_spaces}-Value:{:?}\n",
                current_node.op_code,
                find_corresponding_string(parsed.option_string_id, string_packages),
                parsed.value_type,
                parsed.value
            )
            .as_str(),
        ),

        ParsedOperation::OneOf(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(&node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(&current_node, &varstore, reader);

            result.push_str(
                format!(
                    "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}\n{extra_spaces}-{:?}\n{extra_spaces}-Answer: {answer_disp}\n",
                    current_node.op_code,
                    find_corresponding_string(
                        parsed.question_header().prompt_string_id,
                        string_packages
                    ),
                    find_corresponding_string(
                        parsed.question_header().help_string_id,
                        string_packages
                    ),
                    parsed.data
                )
                .as_str(),
            );
        }
        ParsedOperation::Numeric(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(&node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(&current_node, &varstore, reader);

            result.push_str(
                format!(
                    "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}\n{extra_spaces}-{:?}\n{extra_spaces}-Answer: {answer_disp}\n",
                    current_node.op_code,
                    find_corresponding_string(
                        parsed.question_header().prompt_string_id,
                        string_packages
                    ),
                    find_corresponding_string(
                        parsed.question_header().help_string_id,
                        string_packages
                    ),
                    parsed.data
                )
                .as_str(),
            );
        }
        ParsedOperation::CheckBox(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(&node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(&current_node, &varstore, reader);

            result.push_str(
                format!(
                    "{extra_spaces}OpCode: {:?} - Q: - {} - Help: - {}\n{extra_spaces}-Answer: {answer_disp}\n",
                    current_node.op_code,
                    find_corresponding_string(
                        parsed.question_header().prompt_string_id,
                        string_packages
                    ),
                    find_corresponding_string(
                        parsed.question_header().help_string_id,
                        string_packages
                    ),
                )
                .as_str(),
            );
        }

        // TODO: we have already made structs for the most popular opcodes so we should finish the display function for them
        // however display is only for debugging and a visual representation of the forms for humans
        _ => result
            .push_str(format!("{extra_spaces}OpCode: {:?}\n",  current_node.op_code).as_str()),
    }

    for child in &node.borrow().children {
        result.push_str(display(Rc::clone(child), level + 1, string_packages, reader)?.as_str());
    }

    Ok(result)
}

/// Returns the answer that show-ifr shows: the question's value, or why it cannot be read.
fn display_answer(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> String {
    match read_question_bytes(question, varstore, reader) {
        Err(reason) => reason.into_owned(),
        Ok(bytes) => stored_value(bytes).to_string(),
    }
}

#[derive(Error, Debug)]
pub enum ChangeValueError {
    #[error("provided value did not match any possible option")]
    InvalidOption,
    #[error("provided value exceeded max possible value")]
    ExceededMaxValue,
    #[error("provided value is below the minimum possible value")]
    BelowMinValue,
    #[error("numeric question has an invalid range")]
    InvalidNumericRange,
    #[error("setting EDKII bit-field values is not supported")]
    UnsupportedBitField,
    #[error(transparent)]
    Selection(#[from] SelectionError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub fn change_value(
    question: &QuestionDescriptor,
    new_value: &str,
) -> Result<bool, ChangeValueError> {
    // writes take VarOffset in bytes
    if question.refers_to_bit_field {
        return Err(ChangeValueError::UnsupportedBitField);
    }
    let mut changed = false;
    if let Some(varstore) = &question.varstore {
        if question.opcode == IFROpCode::OneOf {
            let option = question
                .select_option(
                    &HashSet::from([new_value.to_owned()]),
                    IncludedStates::empty(),
                )?
                .ok_or(ChangeValueError::InvalidOption)?;
            return change_option(question, option);
        } else if let Some(range) = &question.numeric_range {
            let data = range.parse_value(new_value)?;
            varstore.write_at_offset(question.header.var_store_info, data)?;
            changed = true;
        } else {
            match question.max_value {
                RangeType::NumSize8(m) => {
                    let data_to_write = new_value
                        .parse::<u8>()
                        .context("value should fit in a u8")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize8(data_to_write),
                    )?;
                    changed = true;
                }
                RangeType::NumSize16(m) => {
                    let data_to_write = new_value
                        .parse::<u16>()
                        .context("value should fit in a u16")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize16(data_to_write),
                    )?;
                    changed = true;
                }
                RangeType::NumSize32(m) => {
                    let data_to_write = new_value
                        .parse::<u32>()
                        .context("value should fit in a u32")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize32(data_to_write),
                    )?;
                    changed = true;
                }
                RangeType::NumSize64(m) => {
                    let data_to_write = new_value
                        .parse::<u64>()
                        .context("value should fit in a u64")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize64(data_to_write),
                    )?;
                    changed = true;
                }
            }
        }
    }

    Ok(changed)
}

/// Writes `option`, one of the possible_options of the ONE_OF `question`; Ok(false) without a
/// VarStore.
pub fn change_option(
    question: &QuestionDescriptor,
    option: &AnswerOption,
) -> Result<bool, ChangeValueError> {
    // writes take VarOffset in bytes
    if question.refers_to_bit_field {
        return Err(ChangeValueError::UnsupportedBitField);
    }
    let Some(varstore) = &question.varstore else {
        return Ok(false);
    };
    varstore.write_at_offset(question.header.var_store_info, option.raw_value)?;
    Ok(true)
}

fn find_corresponding_string(string_id: u16, string_packages: &[HashMap<i32, String>]) -> &str {
    // TODO: accept language pack parameter later
    // it defaults to the first language pack it can find and the first one is en-US

    for package in string_packages {
        if let Some(s) = package.get(&(string_id as i32)) {
            return s;
        }
    }

    // in lots of language packs most strings are simply not present
    // in some cases strings aren't there at all in any language

    // cannot return an error here because its the firmware not following the spec

    debug!("string id: {string_id} not found");

    ""
}

/// find_corresponding_varstore bubble's up from current node till we find a FormSet.
/// then it looks for varstores which will be FormSet's children
fn find_corresponding_varstore(
    node: Rc<RefCell<IFROperation>>,
    var_store_id: u16,
) -> Result<Box<dyn VariableStore>> {
    if var_store_id == 0 {
        return Err(anyhow!(
            "question is callback-driven or temporary and has no varstore"
        ));
    }

    let current_node = node.borrow();

    if current_node.op_code == IFROpCode::FormSet {
        // look at its children

        for child in &current_node.children {
            match &child.borrow().parsed_data {
                ParsedOperation::VarStore(v) => {
                    if v.var_store_id == var_store_id {
                        return Ok(Box::new(v.clone()));
                    }
                }
                ParsedOperation::VarStoreEfi(v) => {
                    if v.var_store_id == var_store_id {
                        return Ok(Box::new(v.clone()));
                    }
                }
                ParsedOperation::VarStoreNameValue(v) => {
                    if v.var_store_id == var_store_id {
                        return Err(anyhow!(
                            "HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL"
                        ));
                    }
                }
                _ => {}
            }
        }
        return Err(anyhow!(
            "no supported varstore with matching id {:#06x} found",
            var_store_id
        ));
    }

    match current_node.parent.as_ref() {
        Some(parent_ref) => match parent_ref.upgrade() {
            Some(parent_ref_rc) => {
                find_corresponding_varstore(Rc::clone(&parent_ref_rc), var_store_id)
            }
            None => Err(anyhow!("could not upgrade parent_ref Weak<> to get Rc<>")),
        },
        None => Err(anyhow!("varstore not found because we reached root")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hii::efivarfs::read_efivarfs_bytes;

    fn variable_bytes(payload_size: usize) -> Vec<u8> {
        let mut bytes = 7u32.to_le_bytes().to_vec();
        bytes.extend(vec![0xa5; payload_size]);
        bytes
    }

    #[test]
    fn writes_each_integer_width_at_end_of_varstore() {
        for (data, encoded) in [
            (TypeValue::NumSize8(95), 95u8.to_le_bytes().to_vec()),
            (TypeValue::NumSize16(259), 259u16.to_le_bytes().to_vec()),
            (
                TypeValue::NumSize32(123456),
                123456u32.to_le_bytes().to_vec(),
            ),
            (
                TypeValue::NumSize64(u64::MAX),
                u64::MAX.to_le_bytes().to_vec(),
            ),
        ] {
            let mut bytes = variable_bytes(42);
            let mut expected = bytes.clone();
            let offset = 42 - encoded.len();
            expected[EFIVARFS_HEADER_SIZE + offset..].copy_from_slice(&encoded);
            update_efivarfs_bytes(&mut bytes, 42, offset as u16, data).unwrap();
            assert_eq!(bytes, expected);
        }
    }

    #[test]
    fn trailing_thermal_fields_do_not_overlap() {
        let mut bytes = variable_bytes(42);
        update_efivarfs_bytes(&mut bytes, 42, 38, TypeValue::NumSize16(95)).unwrap();
        update_efivarfs_bytes(&mut bytes, 42, 40, TypeValue::NumSize16(90)).unwrap();
        assert_eq!(stored_value(&bytes[EFIVARFS_HEADER_SIZE + 38..][..2]), 95);
        assert_eq!(stored_value(&bytes[EFIVARFS_HEADER_SIZE + 40..][..2]), 90);
        assert_eq!(&bytes[..4], &7u32.to_le_bytes());
    }

    #[test]
    fn rejects_writes_past_declared_size_without_changing_bytes() {
        for (size, offset, data) in [
            (42, 42, TypeValue::NumSize8(1)),
            (42, 41, TypeValue::NumSize16(1)),
            (42, 39, TypeValue::NumSize32(1)),
            (42, 35, TypeValue::NumSize64(1)),
            (0, 0, TypeValue::NumSize8(1)),
            (42, u16::MAX, TypeValue::NumSize64(1)),
        ] {
            let mut bytes = variable_bytes(64);
            let original = bytes.clone();
            assert!(update_efivarfs_bytes(&mut bytes, size, offset, data).is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn rejects_short_payload_even_when_requested_field_fits() {
        for offset in [0, 40] {
            let mut bytes = variable_bytes(39);
            let original = bytes.clone();
            assert!(
                update_efivarfs_bytes(&mut bytes, 42, offset, TypeValue::NumSize16(1)).is_err()
            );
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn rejects_incomplete_attributes_header() {
        for length in 0..EFIVARFS_HEADER_SIZE {
            let mut bytes = vec![0xa5; length];
            let original = bytes.clone();
            assert!(update_efivarfs_bytes(&mut bytes, 1, 0, TypeValue::NumSize8(1)).is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn preserves_bytes_beyond_declared_varstore() {
        let mut bytes = variable_bytes(50);
        let original = bytes.clone();
        update_efivarfs_bytes(&mut bytes, 42, 40, TypeValue::NumSize16(95)).unwrap();
        assert_eq!(&bytes[46..], &original[46..]);
        assert_eq!(&bytes[..44], &original[..44]);
        assert_eq!(bytes.len(), original.len());
    }

    #[test]
    fn writes_small_and_maximum_sized_varstores() {
        for size in [1, 2, u16::MAX] {
            let mut bytes = variable_bytes(usize::from(size));
            update_efivarfs_bytes(&mut bytes, size, size - 1, TypeValue::NumSize8(95)).unwrap();
            assert_eq!(bytes.len(), EFIVARFS_HEADER_SIZE + usize::from(size));
            assert_eq!(bytes.last(), Some(&95));
        }
    }

    #[test]
    fn rejects_unsupported_value_instead_of_silent_noop() {
        let mut bytes = variable_bytes(42);
        let original = bytes.clone();
        assert!(update_efivarfs_bytes(&mut bytes, 42, 0, TypeValue::Boolean(true)).is_err());
        assert_eq!(bytes, original);
    }

    #[test]
    fn read_efivarfs_bytes_includes_attributes_and_complete_payload() {
        let payload = 95u16.to_le_bytes();
        let mut efivarfs_data = 7u32.to_le_bytes().to_vec();
        efivarfs_data.extend_from_slice(&payload);

        let mut reader = Cursor::new(&efivarfs_data);
        let bytes = read_efivarfs_bytes(&mut reader, payload.len()).unwrap();

        assert_eq!(bytes, efivarfs_data);
        assert_eq!(stored_value(&bytes[EFIVARFS_HEADER_SIZE..]), 95);
    }

    #[test]
    fn missing_efivar_is_explained_as_not_exported() {
        let name = EfivarFileName::new(
            "Setup",
            Guid {
                data1: 0xec87d643,
                data2: 0xeba4,
                data3: 0x4bb5,
                data4: [0xa1, 0xe5, 0x3f, 0x3e, 0x36, 0xb2, 0x0d, 0xa9],
            },
        );

        let error = VariableNotExported::explain(EfivarNotFound { name }.into());

        assert!(
            error.downcast_ref::<VariableNotExported>().is_some(),
            "{error:#} is not VariableNotExported"
        );
        assert_eq!(
            format!("{error:#}"),
            "no EFI variable Setup-ec87d643-eba4-4bb5-a1e5-3f3e36b20da9: the firmware has not \
             created it or does not expose it to the OS, so its questions cannot be set from \
             Linux; change them in the firmware setup, or ask the board vendor for firmware that \
             exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            "message of the missing variable"
        );
    }

    #[test]
    fn other_efivar_open_failure_is_not_explained_as_not_exported() {
        // ENOTDIR: the directory is a regular file
        let not_a_dir = tempfile::NamedTempFile::new().expect("create a file");
        let name = EfivarFileName::new("Setup", ifr_fixtures::NIL_GUID);

        let open_error = open_efivar(not_a_dir.path(), &name).expect_err("open below a file");
        let expected = format!("{open_error:#}");

        let error = VariableNotExported::explain(open_error);

        assert!(
            error.downcast_ref::<VariableNotExported>().is_none(),
            "{error:#} is VariableNotExported"
        );
        assert_eq!(
            format!("{error:#}"),
            expected,
            "message of the open failure below a file"
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotADirectory),
            "root cause of the open failure below a file"
        );
    }

    /// An IFR operation Length below the header size is rejected as an
    /// invalid length before binrw computes the size of the operation's data
    /// from it.
    #[test]
    fn operation_length_below_header_size_is_an_error() {
        for length in [0, IFR_OPERATION_HEADER_SIZE - 1] {
            let data = vec![0x0E, length]; // FormSet
            let mut cursor = Cursor::new(&data);

            let err = format!("{:#}", handle_form_package(&mut cursor).unwrap_err());

            let want = format!("invalid IFR operation length {} at 0x", length);
            assert!(err.contains(&want), "length {}: {}", length, err);
        }
    }

    /// An IFR operation of Length 0 is an error even when 254 bytes (what a
    /// wrapped `length - IFR_OPERATION_HEADER_SIZE` would read) and an End
    /// operation follow it.
    #[test]
    fn operation_length_zero_before_254_bytes_and_end_is_an_error() {
        let wrapped_count = 0u8.wrapping_sub(IFR_OPERATION_HEADER_SIZE);
        let data = [
            &[0x0E, 0x00][..],                       // FormSet: Length 0
            &vec![0x00; usize::from(wrapped_count)], // 254 bytes
            &[0x29, IFR_OPERATION_HEADER_SIZE],      // End
        ]
        .concat();
        let mut cursor = Cursor::new(&data);

        let err = format!("{:#}", handle_form_package(&mut cursor).unwrap_err());

        let want = "invalid IFR operation length 0 at 0x";
        assert!(err.contains(want), "{}", err);
    }

    /// An IFR operation of exactly the header size, like End, is parsed.
    #[test]
    fn operation_of_header_size_is_parsed() {
        let form_set_data = [
            &[0x11; 16][..],           // Guid
            &[0x01, 0x00, 0x02, 0x00], // FormSetTitle, Help
            &[0x01],                   // Flags: one ClassGuid
            &[0x22; 16],               // ClassGuid
        ]
        .concat();
        let form_set_length =
            IFR_OPERATION_HEADER_SIZE + u8::try_from(form_set_data.len()).unwrap();
        let data = [
            &[0x0E, 0x80 | form_set_length][..], // FormSet: Length, Scope
            &form_set_data,
            &[0x29, IFR_OPERATION_HEADER_SIZE], // End
        ]
        .concat();
        let mut cursor = Cursor::new(&data);

        let root = handle_form_package(&mut cursor).unwrap();

        let root = root.borrow();
        assert_eq!(root.children.len(), 1);
        let form_set = root.children[0].borrow();
        assert_eq!(form_set.op_code, IFROpCode::FormSet);
        assert!(form_set.children.is_empty());
    }
}

#[cfg(test)]
mod write_validation_tests {
    use super::ifr_fixtures::*;
    use super::*;

    struct RecordingVarStore {
        writes: RecordedWrites,
    }

    impl VariableStore for RecordingVarStore {
        fn name(&self) -> String {
            "NumericTest".to_string()
        }

        fn guid(&self) -> Guid {
            NIL_GUID
        }

        fn size(&self) -> u16 {
            42
        }

        fn kind(&self) -> VariableStoreKind {
            VariableStoreKind::Buffer
        }

        fn is_runtime_accessible(&self) -> bool {
            false
        }

        fn write_efivarfs_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
            self.writes.borrow_mut().push((offset, data));
            Ok(())
        }
    }

    fn recording_store() -> (VarStoreFixture, RecordedWrites) {
        let writes = RecordedWrites::default();
        let store = RecordingVarStore {
            writes: Rc::clone(&writes),
        };
        let efivars = Efivars::new();
        efivars.write(&store, &[0; 42]);
        let fixture = VarStoreFixture {
            store: Ok(Box::new(store)),
            efivars,
        };
        (fixture, writes)
    }

    fn numeric_question(
        bits: u32,
        minimum: u64,
        maximum: u64,
        step: u64,
        display: u8,
        initial: u64,
    ) -> (QuestionDescriptor, RecordedWrites) {
        let (width_code, range) = match bits {
            8 => (
                0,
                Range::Range8(Range8 {
                    min_value: minimum as u8,
                    max_value: maximum as u8,
                    step: step as u8,
                }),
            ),
            16 => (
                1,
                Range::Range16(Range16 {
                    min_value: minimum as u16,
                    max_value: maximum as u16,
                    step: step as u16,
                }),
            ),
            32 => (
                2,
                Range::Range32(Range32 {
                    min_value: minimum as u32,
                    max_value: maximum as u32,
                    step: step as u32,
                }),
            ),
            64 => (
                3,
                Range::Range64(Range64 {
                    min_value: minimum,
                    max_value: maximum,
                    step,
                }),
            ),
            _ => panic!("invalid test width"),
        };
        let parsed = Numeric {
            question_header: QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 1,
                var_store_id: 1,
                var_store_info: 2,
                question_flags: 0,
            },
            flags: width_code | display,
            data: range,
        };
        let node = RefCell::new(IFROperation {
            op_code: IFROpCode::Numeric,
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Numeric(parsed),
        });
        let mut payload = vec![0; 42];
        let width = (bits / 8) as usize;
        payload[2..2 + width].copy_from_slice(&initial.to_le_bytes()[..width]);
        let writes = Rc::new(RefCell::new(Vec::new()));
        let store = RecordingVarStore {
            writes: Rc::clone(&writes),
        };
        let efivars = Efivars::new();
        efivars.write(&store, &payload);
        let current = node.borrow();
        let ParsedOperation::Numeric(parsed) = &current.parsed_data else {
            panic!("not a NUMERIC: {:?}", current.parsed_data);
        };
        let question = handle_numeric(
            Ok(Box::new(store)),
            parsed,
            "Numeric test",
            &current,
            &mut FormPackageWalk::new(
                &[],
                &mut efivars.reader(),
                &MapValues(HashMap::new()),
                IncludedStates::empty(),
            ),
        );
        (question, writes)
    }

    fn encoded_value(bits: u32, value: i128) -> TypeValue {
        match bits {
            8 => TypeValue::NumSize8(value as u8),
            16 => TypeValue::NumSize16(value as u16),
            32 => TypeValue::NumSize32(value as u32),
            64 => TypeValue::NumSize64(value as u64),
            _ => panic!("invalid test width"),
        }
    }

    #[test]
    fn rejects_unsigned_out_of_range_values_before_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, writes) = numeric_question(bits, 10, 20, 2, 0x10, 10);
            assert!(matches!(
                change_value(&question, "9"),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "21"),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            for value in [
                "-1",
                "not-a-number",
                "340282366920938463463374607431768211455",
            ] {
                assert!(change_value(&question, value).is_err());
            }
            assert!(writes.borrow().is_empty());
        }
    }

    #[test]
    fn accepts_unsigned_boundaries_and_does_not_treat_step_as_a_constraint() {
        for bits in [8, 16, 32, 64] {
            for step in [0, 2] {
                for display in [0x10, 0x20] {
                    let (question, writes) = numeric_question(bits, 10, 20, step, display, 10);
                    for value in [10, 11, 20] {
                        assert!(change_value(&question, &value.to_string()).unwrap());
                    }
                    assert_eq!(
                        *writes.borrow(),
                        vec![
                            (2, encoded_value(bits, 10)),
                            (2, encoded_value(bits, 11)),
                            (2, encoded_value(bits, 20)),
                        ]
                    );
                }
            }
        }
    }

    #[test]
    fn validates_signed_bounds_and_encodes_negative_values() {
        for bits in [8, 16, 32, 64] {
            let (question, writes) =
                numeric_question(bits, (-10i64) as u64, 10, 1, 0, (-3i64) as u64);
            assert_eq!(question.value, "-3");
            assert!(matches!(
                change_value(&question, "-11"),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "11"),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            assert!(writes.borrow().is_empty());
            for value in [-10, 0, 10] {
                assert!(change_value(&question, &value.to_string()).unwrap());
            }
            assert_eq!(
                *writes.borrow(),
                vec![
                    (2, encoded_value(bits, -10)),
                    (2, encoded_value(bits, 0)),
                    (2, encoded_value(bits, 10)),
                ]
            );
        }
    }

    #[test]
    fn supports_full_signed_range_at_each_width() {
        for bits in [8, 16, 32, 64] {
            let minimum = -(1i128 << (bits - 1));
            let maximum = (1i128 << (bits - 1)) - 1;
            let (question, writes) =
                numeric_question(bits, minimum as u64, maximum as u64, 1, 0, 0);
            assert!(change_value(&question, &minimum.to_string()).unwrap());
            assert!(change_value(&question, &maximum.to_string()).unwrap());
            assert!(change_value(&question, &(minimum - 1).to_string()).is_err());
            assert!(change_value(&question, &(maximum + 1).to_string()).is_err());
            assert_eq!(writes.borrow().len(), 2);
        }
    }

    #[test]
    fn supports_unsigned_64_bit_values_above_signed_maximum() {
        let (question, writes) = numeric_question(64, u64::MAX - 2, u64::MAX, 1, 0x10, u64::MAX);
        assert_eq!(question.value, u64::MAX.to_string());
        assert!(change_value(&question, &u64::MAX.to_string()).unwrap());
        assert_eq!(*writes.borrow(), vec![(2, TypeValue::NumSize64(u64::MAX))]);
        assert!(change_value(&question, "18446744073709551616").is_err());
        assert_eq!(writes.borrow().len(), 1);
    }

    #[test]
    fn rejects_invalid_numeric_ranges_without_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, writes) = numeric_question(bits, 20, 10, 1, 0x10, 0);
            assert!(matches!(
                change_value(&question, "15"),
                Err(ChangeValueError::InvalidNumericRange)
            ));
            assert!(writes.borrow().is_empty());
        }
    }

    /// set refuses an EDKII bit varstore field, with or without a VarStore, and writes nothing.
    #[test]
    fn bit_field_question_is_not_set() {
        let one_of_children = vec![
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            one_of_option(6, 0x02, &1u32.to_le_bytes()),
        ];
        let cases = [
            (
                "18-bit NUMERIC",
                NUMERIC,
                uint32_range_question(12, 0x52),
                vec![],
                "5",
                (12, TypeValue::NumSize32(5)),
            ),
            (
                "CHECKBOX",
                CHECKBOX,
                checkbox(3, 0x00),
                vec![],
                "1",
                (3, TypeValue::NumSize8(1)),
            ),
            (
                "2-bit ONE_OF",
                ONE_OF,
                uint32_range_question(8, 0x42),
                one_of_children,
                "Enabled",
                (8, TypeValue::NumSize32(1)),
            ),
        ];
        for (name, op_code, data, children, value, write) in cases {
            let set = |guid, var_store| {
                let (_root, node) = parse_question_in_guid(guid, op_code, &data, &children);
                change_value(&question_descriptor(&node, var_store), value)
            };

            let (store, writes) = recording_store();
            let changed = set(BIT_VARSTORE_GUID, store);
            assert!(
                matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?}: {changed:?}"
            );
            assert!(
                writes.borrow().is_empty(),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?}"
            );

            let changed = set(BIT_VARSTORE_GUID, unavailable());
            assert!(
                matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?} without VarStore: {changed:?}"
            );

            // set writes a ONE_OF's option as change_option does, not as change_value does
            let (_root, node) =
                parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children);
            let (store, writes) = recording_store();
            let question = question_descriptor(&node, store);
            for option in &question.possible_options {
                let changed = change_option(&question, option);
                assert!(
                    matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                    "{name}: change_option {:?}: {changed:?}",
                    option.value
                );
            }
            assert!(writes.borrow().is_empty(), "{name}: change_option");

            let question = question_descriptor(&node, unavailable());
            for option in &question.possible_options {
                let changed = change_option(&question, option);
                assert!(
                    matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                    "{name}: change_option {:?} without VarStore: {changed:?}",
                    option.value
                );
            }

            let other_guid = OTHER_GUID;
            let (store, writes) = recording_store();
            let changed = set(other_guid, store);
            assert!(
                matches!(changed, Ok(true)),
                "{name}, GUID {other_guid:02X?}: {changed:?}"
            );
            assert_eq!(*writes.borrow(), [write], "{name}, GUID {other_guid:02X?}");
        }
    }
}
