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

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt;
use std::io::Read;
use std::io::Seek;
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
use log::warn;
use thiserror::Error;

use crate::hii::package::Guid;
use crate::hii::variables::check_non_volatile;
use crate::hii::variables::check_runtime_writable;
use crate::hii::variables::check_unauthenticated;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use conditions::question_state;
use conditions::question_value_expression;
use conditions::retrieve_question_value;
use conditions::select;
use conditions::skips_scope;
use conditions::ExpressionInputs;
use conditions::QuestionExpression;
use conditions::QuestionValues;
use conditions::VarStoreValues;
use defaults::FormSetDefaultIds;
use question_values::describe_question;
use question_values::questions_named;
use question_values::value_question;
use set::ChangeValueError;
use storage::storage_width;
use storage::ReadableLocation;
use storage::ValueLocation;
use storage::VarStore;
use storage::VarStoreEfi;
use storage::VarStoreNameValue;
use storage::VariableNotExported;
use storage::VariableStore;
use storageless::NoVarStore;
use storageless::StoragelessQuestion;
use storageless::StoragelessRefusal;
use storageless::StoragelessRoute;

pub use ami_access_level::AccessLevel;
pub use conditions::IncludedStates;
pub use conditions::QuestionState;
pub use conditions::SelectionError;
pub use setup_password::SetupPasswordPolicy;

pub(crate) use ami_access_level::check_access_level;
pub(crate) use conditions::Choice;
pub(crate) use conditions::Selection;
pub(crate) use conditions::StateEvaluation;
pub(crate) use defaults::DefaultId;
pub(crate) use set::set_questions;
pub(crate) use setup_password::PasswordQuestions;

mod ami_access_level;
mod conditions;
mod defaults;
#[cfg(test)]
pub(crate) mod ifr_fixtures;
mod question_values;
mod set;
mod setup_password;
mod storage;
mod storageless;
mod write_plan;

const DUMMY_OPCODE: u8 = 0xFFu8; // doesn't correspond to any known IFROpCode
/// How DeclaredBootServiceOnly names a form's declaration without EFI_VARIABLE_RUNTIME_ACCESS.
const DECLARED_BOOT_SERVICE_ONLY: &str = "boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
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
const EFI_IFR_TYPE_TIME: u8 = 0x05;
const EFI_IFR_TYPE_DATE: u8 = 0x06;
const EFI_IFR_TYPE_STRING: u8 = 0x07;
const EFI_IFR_TYPE_OTHER: u8 = 0x08;
const EFI_IFR_TYPE_REF: u8 = 0x0C;
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

// UEFI 2.10 §33.3.8.3, Table 33.11 IFR Opcodes
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

impl IFROpCode {
    /// The name of the opcode in UEFI 2.11 Table 33.11, as edk2-stable202608
    /// MdePkg/Include/Uefi/UefiInternalFormRepresentation.h defines it, without _OP.
    pub(crate) fn spec_name(self) -> &'static str {
        match self {
            Self::Form => "EFI_IFR_FORM",
            Self::Subtitle => "EFI_IFR_SUBTITLE",
            Self::Text => "EFI_IFR_TEXT",
            Self::Image => "EFI_IFR_IMAGE",
            Self::OneOf => "EFI_IFR_ONE_OF",
            Self::CheckBox => "EFI_IFR_CHECKBOX",
            Self::Numeric => "EFI_IFR_NUMERIC",
            Self::Password => "EFI_IFR_PASSWORD",
            Self::OneOfOption => "EFI_IFR_ONE_OF_OPTION",
            Self::SuppressIf => "EFI_IFR_SUPPRESS_IF",
            Self::Locked => "EFI_IFR_LOCKED",
            Self::Action => "EFI_IFR_ACTION",
            Self::ResetButton => "EFI_IFR_RESET_BUTTON",
            Self::FormSet => "EFI_IFR_FORM_SET",
            Self::Ref => "EFI_IFR_REF",
            Self::NoSubmitIf => "EFI_IFR_NO_SUBMIT_IF",
            Self::InconsistentIf => "EFI_IFR_INCONSISTENT_IF",
            Self::EqIdVal => "EFI_IFR_EQ_ID_VAL",
            Self::EqIdId => "EFI_IFR_EQ_ID_ID",
            Self::EqIdValList => "EFI_IFR_EQ_ID_VAL_LIST",
            Self::And => "EFI_IFR_AND",
            Self::Or => "EFI_IFR_OR",
            Self::Not => "EFI_IFR_NOT",
            Self::Rule => "EFI_IFR_RULE",
            Self::GrayOutIf => "EFI_IFR_GRAY_OUT_IF",
            Self::Date => "EFI_IFR_DATE",
            Self::Time => "EFI_IFR_TIME",
            Self::String => "EFI_IFR_STRING",
            Self::Refresh => "EFI_IFR_REFRESH",
            Self::DisableIf => "EFI_IFR_DISABLE_IF",
            Self::Animation => "EFI_IFR_ANIMATION",
            Self::ToLower => "EFI_IFR_TO_LOWER",
            Self::ToUpper => "EFI_IFR_TO_UPPER",
            Self::Map => "EFI_IFR_MAP",
            Self::OrderedList => "EFI_IFR_ORDERED_LIST",
            Self::VarStore => "EFI_IFR_VARSTORE",
            Self::VarStoreNameValue => "EFI_IFR_VARSTORE_NAME_VALUE",
            Self::VarStoreEfi => "EFI_IFR_VARSTORE_EFI",
            Self::VarStoreDevice => "EFI_IFR_VARSTORE_DEVICE",
            Self::Version => "EFI_IFR_VERSION",
            Self::End => "EFI_IFR_END",
            Self::Match => "EFI_IFR_MATCH",
            Self::Get => "EFI_IFR_GET",
            Self::Set => "EFI_IFR_SET",
            Self::Read => "EFI_IFR_READ",
            Self::Write => "EFI_IFR_WRITE",
            Self::Equal => "EFI_IFR_EQUAL",
            Self::NotEqual => "EFI_IFR_NOT_EQUAL",
            Self::GreaterThan => "EFI_IFR_GREATER_THAN",
            Self::GreaterEqual => "EFI_IFR_GREATER_EQUAL",
            Self::LessThan => "EFI_IFR_LESS_THAN",
            Self::LessEqual => "EFI_IFR_LESS_EQUAL",
            Self::BitwiseAnd => "EFI_IFR_BITWISE_AND",
            Self::BitwiseOr => "EFI_IFR_BITWISE_OR",
            Self::BitwiseNot => "EFI_IFR_BITWISE_NOT",
            Self::ShiftLeft => "EFI_IFR_SHIFT_LEFT",
            Self::ShiftRight => "EFI_IFR_SHIFT_RIGHT",
            Self::Add => "EFI_IFR_ADD",
            Self::Subtract => "EFI_IFR_SUBTRACT",
            Self::Multiply => "EFI_IFR_MULTIPLY",
            Self::Divide => "EFI_IFR_DIVIDE",
            Self::Modulo => "EFI_IFR_MODULO",
            Self::RuleRef => "EFI_IFR_RULE_REF",
            Self::QuestionRef1 => "EFI_IFR_QUESTION_REF1",
            Self::QuestionRef2 => "EFI_IFR_QUESTION_REF2",
            Self::Uint8 => "EFI_IFR_UINT8",
            Self::Uint16 => "EFI_IFR_UINT16",
            Self::Uint32 => "EFI_IFR_UINT32",
            Self::Uint64 => "EFI_IFR_UINT64",
            Self::True => "EFI_IFR_TRUE",
            Self::False => "EFI_IFR_FALSE",
            Self::ToUint => "EFI_IFR_TO_UINT",
            Self::ToString => "EFI_IFR_TO_STRING",
            Self::ToBoolean => "EFI_IFR_TO_BOOLEAN",
            Self::Mid => "EFI_IFR_MID",
            Self::Find => "EFI_IFR_FIND",
            Self::Token => "EFI_IFR_TOKEN",
            Self::StringRef1 => "EFI_IFR_STRING_REF1",
            Self::StringRef2 => "EFI_IFR_STRING_REF2",
            Self::Conditional => "EFI_IFR_CONDITIONAL",
            Self::QuestionRef3 => "EFI_IFR_QUESTION_REF3",
            Self::Zero => "EFI_IFR_ZERO",
            Self::One => "EFI_IFR_ONE",
            Self::Ones => "EFI_IFR_ONES",
            Self::Undefined => "EFI_IFR_UNDEFINED",
            Self::Length => "EFI_IFR_LENGTH",
            Self::Dup => "EFI_IFR_DUP",
            Self::This => "EFI_IFR_THIS",
            Self::Span => "EFI_IFR_SPAN",
            Self::Value => "EFI_IFR_VALUE",
            Self::Default => "EFI_IFR_DEFAULT",
            Self::DefaultStore => "EFI_IFR_DEFAULTSTORE",
            Self::FormMap => "EFI_IFR_FORM_MAP",
            Self::Catenate => "EFI_IFR_CATENATE",
            Self::Guid => "EFI_IFR_GUID",
            Self::Security => "EFI_IFR_SECURITY",
            Self::ModalTag => "EFI_IFR_MODAL_TAG",
            Self::RefreshId => "EFI_IFR_REFRESH_ID",
            Self::WarningIf => "EFI_IFR_WARNING_IF",
            Self::Match2 => "EFI_IFR_MATCH2",
            Self::Unknown(_) => "an unknown IFR opcode",
        }
    }
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
// It prints what Debug derived for op_code, open_scope, length and children prints, from a stack
// on the heap, as walk_scopes walks.
impl fmt::Debug for IFROperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// What is left to print after the fields of an op `depth` scopes down.
        enum Pending {
            /// An op of its scope, as RefCell prints it; `first` in the scope or not
            Entry {
                op: Rc<RefCell<IFROperation>>,
                depth: usize,
                first: bool,
            },
            /// The end of the RefCell of an op of its scope
            EntryEnd { depth: usize },
            /// The end of its scope and of the op
            End { depth: usize, empty: bool },
        }

        /// Pushes what is left of `op`, `depth` scopes down, after its fields.
        fn push_scope(pending: &mut Vec<Pending>, op: &IFROperation, depth: usize) {
            pending.push(Pending::End {
                depth,
                empty: op.children.is_empty(),
            });
            pending.extend(op.children.iter().enumerate().rev().map(|(index, child)| {
                Pending::Entry {
                    op: Rc::clone(child),
                    depth,
                    first: index == 0,
                }
            }));
        }

        let mut printer = DebugPrinter {
            pretty: f.alternate(),
            f,
        };
        printer.fields(self, 0)?;
        let mut pending = Vec::new();
        push_scope(&mut pending, self, 0);
        while let Some(next) = pending.pop() {
            match next {
                Pending::Entry { op, depth, first } => {
                    printer.entry(depth, first)?;
                    match op.try_borrow() {
                        Ok(op) => {
                            printer.fields(&op, depth + 1)?;
                            pending.push(Pending::EntryEnd { depth });
                            push_scope(&mut pending, &op, depth + 1);
                        }
                        Err(_) => {
                            printer.f.write_str("<borrowed>")?;
                            printer.entry_end(depth)?;
                        }
                    }
                }
                Pending::EntryEnd { depth } => printer.entry_end(depth)?,
                Pending::End { depth, empty } => printer.end(depth, empty)?,
            }
        }
        Ok(())
    }
}

/// Prints ops as Debug derived for IFROperation's op_code, open_scope, length and children would.
struct DebugPrinter<'a, 'b> {
    f: &'a mut fmt::Formatter<'b>,
    pretty: bool,
}

impl DebugPrinter<'_, '_> {
    /// The indentation of `{:#?}` for an op `depth` scopes down: each scope nests a list, a
    /// RefCell and an op, which indent what they hold by 4 spaces each
    fn indent(depth: usize) -> usize {
        12 * depth
    }

    /// Prints `op` up to its children's opening bracket.
    fn fields(&mut self, op: &IFROperation, depth: usize) -> fmt::Result {
        if !self.pretty {
            return write!(
                self.f,
                "IFROperation {{ op_code: {:?}, open_scope: {:?}, length: {:?}, children: [",
                op.op_code, op.open_scope, op.length
            );
        }
        let indent = Self::indent(depth) + 4;
        self.f.write_str("IFROperation {\n")?;
        let fields: [(&str, &dyn fmt::Debug); 3] = [
            ("op_code", &op.op_code),
            ("open_scope", &op.open_scope),
            ("length", &op.length),
        ];
        for (name, value) in fields {
            write!(self.f, "{:indent$}{name}: ", "")?;
            let value = format!("{value:#?}");
            for (index, line) in value.split('\n').enumerate() {
                if index > 0 {
                    write!(self.f, "\n{:indent$}", "")?;
                }
                self.f.write_str(line)?;
            }
            self.f.write_str(",\n")?;
        }
        write!(self.f, "{:indent$}children: [", "")?;
        if !op.children.is_empty() {
            self.f.write_str("\n")?;
        }
        Ok(())
    }

    /// Prints the start of a RefCell of an op in the scope of an op `depth` scopes down.
    fn entry(&mut self, depth: usize, first: bool) -> fmt::Result {
        match (self.pretty, first) {
            (false, true) => self.f.write_str("RefCell { value: "),
            (false, false) => self.f.write_str(", RefCell { value: "),
            (true, _) => {
                let indent = Self::indent(depth) + 8;
                write!(
                    self.f,
                    "{:indent$}RefCell {{\n{:value_indent$}value: ",
                    "",
                    "",
                    value_indent = indent + 4
                )
            }
        }
    }

    /// Prints the end of a RefCell of an op in the scope of an op `depth` scopes down.
    fn entry_end(&mut self, depth: usize) -> fmt::Result {
        match self.pretty {
            false => self.f.write_str(" }"),
            true => {
                let indent = Self::indent(depth) + 8;
                write!(self.f, ",\n{:indent$}}},\n", "")
            }
        }
    }

    /// Prints the end of the children and of an op `depth` scopes down, `empty` if it has no
    /// children.
    fn end(&mut self, depth: usize, empty: bool) -> fmt::Result {
        let indent = Self::indent(depth);
        match (self.pretty, empty) {
            (false, _) => self.f.write_str("] }"),
            (true, true) => write!(self.f, "],\n{:indent$}}}", ""),
            (true, false) => write!(
                self.f,
                "{:field_indent$}],\n{:indent$}}}",
                "",
                "",
                field_indent = indent + 4
            ),
        }
    }
}

// The ops in its scope are dropped from a stack on the heap, as walk_scopes walks, not by the
// recursive drop glue.
impl Drop for IFROperation {
    fn drop(&mut self) {
        let mut ops = std::mem::take(&mut self.children);
        while let Some(op) = ops.pop() {
            // otherwise the op's last Rc drops its scope
            if let Ok(op) = Rc::try_unwrap(op) {
                ops.append(&mut op.into_inner().children);
            }
        }
    }
}

/// What walk_scopes does after it visits an op.
enum Walk<C> {
    /// Visit the ops in the op's scope, each with this context
    Enter(C),
    /// Leave the ops in the op's scope unvisited
    Skip,
}

/// Visits `ops`, each with `context`, then the ops in the scope of each that `visit` enters, in
/// IFR order. The ops left to visit wait on a stack on the heap, not in recursive calls, so that
/// the thread's stack, e.g. the 128 KiB of UEFI DXE (edk2-stable202608
/// MdeModulePkg/Core/DxeIplPeim/DxeIpl.h STACK_SIZE), does not bound how deep scopes nest.
fn try_walk_scopes<C: Clone, E>(
    ops: &[Rc<RefCell<IFROperation>>],
    context: C,
    mut visit: impl FnMut(&Rc<RefCell<IFROperation>>, &C) -> Result<Walk<C>, E>,
) -> Result<(), E> {
    let mut pending: Vec<_> = ops
        .iter()
        .rev()
        .map(|op| (Rc::clone(op), context.clone()))
        .collect();
    while let Some((op, context)) = pending.pop() {
        match visit(&op, &context)? {
            Walk::Enter(inner) => pending.extend(
                op.borrow()
                    .children
                    .iter()
                    .rev()
                    .map(|child| (Rc::clone(child), inner.clone())),
            ),
            Walk::Skip => {}
        }
    }
    Ok(())
}

/// try_walk_scopes with a `visit` that cannot fail.
fn walk_scopes<C: Clone>(
    ops: &[Rc<RefCell<IFROperation>>],
    context: C,
    mut visit: impl FnMut(&Rc<RefCell<IFROperation>>, &C) -> Walk<C>,
) {
    let Ok(()) = try_walk_scopes(ops, context, |op, context| {
        Ok::<_, Infallible>(visit(op, context))
    });
}

/// The most IFR scopes open at once in a FormSet, its own counted. UEFI 2.11 §33.3.8.2.1 sets no
/// limit and edk2-stable202608 SetupBrowserDxe parses any depth, but its count of the scopes in an
/// unknown op (SetupBrowserDxe/IfrParse.c ParseOpCodes UnknownDepth) and HiiDatabaseDxe's of
/// those in a question (HiiDatabaseDxe/HiiDatabase.h IFR_BLOCK_DATA Scope) are UINT8s, which wrap
/// past 255; show-ifr indents each op by its depth.
pub(crate) const MAX_SCOPE_NESTING: usize = 255;

/// A FormSet whose IFR scopes nest deeper than `limit`, from the op at `offset` of its form
/// package on.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("IFR scopes nest deeper than {limit} at offset {offset} of a form package")]
pub(crate) struct ScopesTooDeep {
    pub(crate) offset: u64,
    pub(crate) limit: usize,
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
    Get(VarStoreOperand),
    Set(VarStoreOperand),
    FormMap(FormMap),
    #[default]
    Placeholder,
}

// Documentation for subsequent structs at:
// UEFI 2.10 §33.3.8

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
// In UEFI 2.10 §33.3.8.2.2 question header's first field is statement header
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

bitflags::bitflags! {
    /// The Flags of an EFI_IFR_QUESTION_HEADER (UEFI 2.11 §33.3.8.2.2), named as there.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct QuestionFlags: u8 {
        const READ_ONLY = 0x01;
        const CALLBACK = 0x04;
        const RESET_REQUIRED = 0x10;
        const REST_STYLE = 0x20;
        const RECONNECT_REQUIRED = 0x40;
        const OPTIONS_ONLY = 0x80;
    }
}

impl QuestionHeader {
    /// The question Flags without the reserved bits, which "the Forms Processor should ignore"
    /// (UEFI 2.11 §33.2.5.10.1).
    pub fn flags(&self) -> QuestionFlags {
        QuestionFlags::from_bits_truncate(self.question_flags)
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: ValueEncoding))]
pub struct OneOf {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags, encoding))]
    pub data: Range,
    #[br(calc = encoding.numeric_location(question_header.var_store_info, flags, &data))]
    location: ValueLocation,
}

impl Question for OneOf {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: ValueEncoding))]
pub struct Numeric {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags, encoding))]
    pub data: Range,
    #[br(calc = encoding.numeric_location(question_header.var_store_info, flags, &data))]
    location: ValueLocation,
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
    format: NumericFormat,
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
            format,
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
        let stored = self
            .format
            .encode(value)
            .ok_or(ChangeValueError::InvalidNumericRange)?;
        match self.format.bits {
            8 => Ok(TypeValue::NumSize8(
                u8::try_from(stored).map_err(|_| ChangeValueError::InvalidNumericRange)?,
            )),
            16 => Ok(TypeValue::NumSize16(
                u16::try_from(stored).map_err(|_| ChangeValueError::InvalidNumericRange)?,
            )),
            32 => Ok(TypeValue::NumSize32(
                u32::try_from(stored).map_err(|_| ChangeValueError::InvalidNumericRange)?,
            )),
            64 => Ok(TypeValue::NumSize64(stored)),
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

/// Why the Flags and VarOffset of a NUMERIC or ONE_OF give no value format.
#[derive(Debug, Error)]
enum NumericFormatError {
    #[error("EDKII bit-field width {0}, not 1 to 32")]
    BitFieldWidth(u8),
    #[error("EDKII bit field of width {width} at bit {offset} spans more than 4 bytes")]
    BitFieldSpan { offset: u16, width: u8 },
}

/// Returns `width`, an EDKII bit varstore field's width, in bits if it is 1 to 32.
fn bit_field_bits(width: u8) -> Result<u32, NumericFormatError> {
    let bits = u32::from(width);
    if !(1..=EDKII_BIT_FIELD_VALUE_BITS).contains(&bits) {
        return Err(NumericFormatError::BitFieldWidth(width));
    }
    Ok(bits)
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

    /// Returns the format of the value at `location` of a NUMERIC or ONE_OF with `flags` and
    /// `range`. edk2-stable202608 IfrParse.c types an EDKII bit varstore field's value by its
    /// StorageWidth, the bytes its bits span: UINT8, UINT16, or UINT32 for 3 or 4;
    /// ProcessOptions.c signs an INT_DEC value from that type. So an 8-bit field holding 0xFF
    /// shows -1 at bit 0, in UINT8, and 255 at bit 4, in UINT16.
    fn from_location(location: ReadableLocation, flags: u8, range: &Range) -> Self {
        match location.0 {
            ValueLocation::Bytes { .. } => Self::from_ifr(range, flags),
            ValueLocation::Bits { offset, width } => {
                let storage_bits = u32::from(storage_width(offset, width)) * u8::BITS;
                let signed = flags & EDKII_IFR_DISPLAY_BIT == EDKII_IFR_DISPLAY_INT_DEC_BIT;
                Self {
                    bits: u32::from(width),
                    signed_type_bits: signed.then_some(storage_bits.next_power_of_two()),
                }
            }
        }
    }

    /// Returns the format of the IFR default of an EDKII bit varstore field of `width` bits,
    /// from its Flags.
    fn from_bit_field(width: u8, flags: u8) -> Result<Self, NumericFormatError> {
        let bits = bit_field_bits(width)?;
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

    /// Returns the stored bits that decode to `value`, or None if no stored bits do.
    fn encode(self, value: i128) -> Option<u64> {
        let stored = match self.signed_type_bits {
            Some(_) => i64::try_from(value).ok()?.cast_unsigned(),
            None => u64::try_from(value).ok()?,
        };
        let stored = self.cut(stored);
        (self.decode(stored) == value).then_some(stored)
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
    location: ValueLocation,
    flags: u8,
    range: &Range,
) -> Result<NumericFormat, NumericFormatError> {
    match location {
        ValueLocation::Bits { width, .. } => NumericFormat::from_bit_field(width, flags),
        ValueLocation::Bytes { .. } => Ok(NumericFormat::from_ifr(range, flags)),
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

/// How a ONE_OF, NUMERIC or CHECKBOX stores its value, and a NUMERIC or ONE_OF its MinValue,
/// MaxValue and Step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueEncoding {
    /// In the size of EFI_IFR_NUMERIC_SIZE in its Flags, a CHECKBOX value in a byte.
    NumericSize,
    /// As UINT32, as edk2-stable202608 VfrSyntax.g stores them for an EDKII bit varstore field,
    /// whose Flags hold its width in bits; the value in that width, a CHECKBOX value in 1 bit.
    EdkiiBitField,
}

impl ValueEncoding {
    fn from_question(question: &IFROperation) -> Self {
        if refers_to_bit_field(question) {
            Self::EdkiiBitField
        } else {
            Self::NumericSize
        }
    }

    /// Where a ONE_OF or NUMERIC with `flags` and `range` keeps its value, VarOffset `offset`.
    fn numeric_location(self, offset: u16, flags: u8, range: &Range) -> ValueLocation {
        match self {
            Self::NumericSize => ValueLocation::Bytes {
                offset,
                size: range.size(),
            },
            Self::EdkiiBitField => ValueLocation::Bits {
                offset,
                width: flags & EDKII_IFR_NUMERIC_SIZE_BIT,
            },
        }
    }

    /// Where a CHECKBOX keeps its value, VarOffset `offset`: in a byte, or in the 1 bit that
    /// edk2-stable202608 IfrParse.c gives a bit-field CHECKBOX.
    fn checkbox_location(self, offset: u16) -> ValueLocation {
        match self {
            Self::NumericSize => ValueLocation::Bytes { offset, size: 1 },
            Self::EdkiiBitField => ValueLocation::Bits { offset, width: 1 },
        }
    }
}

fn range_parser<R: Read + Seek>(
    reader: &mut R,
    _endian: binrw::Endian,
    (flags, encoding): (u8, ValueEncoding),
) -> BinResult<Range> {
    match encoding {
        ValueEncoding::EdkiiBitField => Ok(Range::Range32(reader.read_ne()?)),
        ValueEncoding::NumericSize => match flags & EFI_IFR_NUMERIC_SIZE {
            EFI_IFR_NUMERIC_SIZE_1 => Ok(Range::Range8(reader.read_ne()?)),
            EFI_IFR_NUMERIC_SIZE_2 => Ok(Range::Range16(reader.read_ne()?)),
            EFI_IFR_NUMERIC_SIZE_4 => Ok(Range::Range32(reader.read_ne()?)),
            // EFI_IFR_NUMERIC_SIZE_8, the only value left
            _ => Ok(Range::Range64(reader.read_ne()?)),
        },
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: ValueEncoding))]
pub struct CheckBox {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(calc = encoding.checkbox_location(question_header.var_store_info))]
    location: ValueLocation,
}

impl Question for CheckBox {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
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

/// The stored value that an EFI_IFR_GET reads or an EFI_IFR_SET writes (UEFI 2.11 §33.3.8.3.27,
/// §33.3.8.3.66).
#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct VarStoreOperand {
    pub var_store_id: u16,
    /// VarOffset in a VARSTORE or VARSTORE_EFI, VarName in a VARSTORE_NAME_VALUE
    pub var_store_info: u16,
    /// An EFI_IFR_TYPE_x
    pub var_store_type: u8,
}

/// EFI_HII_STANDARD_FORM_GUID, the method of a standard map form (UEFI 2.11 §33.3.8.3.25).
const EFI_HII_STANDARD_FORM_GUID: Guid = Guid {
    data1: 0x3BD2_F4EC,
    data2: 0xE524,
    data3: 0x46E4,
    data4: [0xA9, 0xD8, 0x51, 0x01, 0x17, 0x42, 0x55, 0x62],
};

/// The bytes of an EFI_IFR_FORM_MAP_METHOD: MethodTitle and MethodIdentifier.
const EFI_IFR_FORM_MAP_METHOD_SIZE: usize = 18;

/// An EFI_IFR_FORM_MAP_METHOD.
#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct FormMapMethod {
    pub method_title: u16,
    pub method_identifier: Guid,
}

/// An EFI_IFR_FORM_MAP.
#[derive(Debug, PartialEq)]
pub struct FormMap {
    pub form_id: u16,
    pub methods: Vec<FormMapMethod>,
}

impl FormMap {
    /// Decodes the FormId and the methods that fit in `data`, or None without room for the
    /// FormId. edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes fails the FormSet of a
    /// FORM_MAP without a method; here its questions stay, as in other forms.
    fn decode(data: &[u8]) -> Option<Self> {
        let (form_id, methods) = data.split_first_chunk::<2>()?;
        let methods = methods
            .chunks_exact(EFI_IFR_FORM_MAP_METHOD_SIZE)
            .map(|method| Cursor::new(method).read_le())
            .collect::<BinResult<Vec<FormMapMethod>>>()
            .ok()?;
        Some(Self {
            form_id: u16::from_le_bytes(*form_id),
            methods,
        })
    }

    /// Whether this is a standard map form, whose questions edk2-stable202608
    /// SetupBrowserDxe/Setup.c GetQuestionValue and SetQuestionValue take through their READ and
    /// WRITE expressions, as they take those of every FORM.
    pub fn has_standard_method(&self) -> bool {
        self.methods
            .iter()
            .any(|method| method.method_identifier == EFI_HII_STANDARD_FORM_GUID)
    }
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
        EFI_IFR_TYPE_NUM_SIZE_8 => {
            let r: u8 = reader.read_ne()?;
            Ok(TypeValue::NumSize8(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_16 => {
            let r: u16 = reader.read_ne()?;
            Ok(TypeValue::NumSize16(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_32 => {
            let r: u32 = reader.read_ne()?;
            Ok(TypeValue::NumSize32(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_64 => {
            let r: u64 = reader.read_ne()?;
            Ok(TypeValue::NumSize64(r))
        }
        EFI_IFR_TYPE_BOOLEAN => {
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

/// Parses a form package into one root per FORM_SET op, outside another FormSet, that
/// edk2-stable202608 SetupBrowserDxe/Setup.c GetIfrBinaryData reaches when it looks for a FormSet
/// by GUID, walking the package op by op, scopes unread, e.g. into an unknown op's scope; each as
/// handle_form_set parses it, the walk going on after its End. A package without one has no root.
/// That walk ends at an op whose Length runs past the package; here it also ends at one below the
/// header size, which that walk loops on (Length 0) or steps into (Length 1), and at a later
/// FormSet whose bytes do not parse. A later FormSet whose scopes nest deeper than
/// MAX_SCOPE_NESTING is skipped to its End, as that walk steps over it.
/// None of them fails the package after the first FormSet: edk2 reads past it only for such a
/// walk. Before it, they fail the package as they fail the first FormSet.
pub(super) fn parse_form_sets(
    package_cursor: &mut Cursor<&Vec<u8>>,
    package_list_guid: Guid,
) -> Result<Vec<Rc<RefCell<IFROperation>>>> {
    let mut roots = Vec::new();
    let package_length = u64::try_from(package_cursor.get_ref().len())
        .context("failed to convert form package length into u64")?;
    while package_cursor.position() < package_length {
        let offset = package_cursor.position();
        let op: IFROperation = match package_cursor.read_ne() {
            Ok(op) => op,
            Err(error) if roots.is_empty() => {
                return Err(error).context("failed to parse IFR operation")
            }
            Err(error)
                if error.is_eof()
                    || matches!(error.root_cause(), binrw::Error::AssertFail { .. }) =>
            {
                debug!("ending the FormSet walk at offset {offset}: {error}");
                break;
            }
            Err(error) => return Err(error).context("failed to parse IFR operation"),
        };
        if op.op_code != IFROpCode::FormSet {
            debug!(
                "skipping {:?} outside a FormSet at offset {offset}",
                op.op_code
            );
            continue;
        }
        package_cursor.set_position(offset);
        match handle_form_set(package_cursor) {
            Ok(root) => roots.push(root),
            Err(error)
                if !roots.is_empty() && error.chain().any(|cause| cause.is::<ScopesTooDeep>()) =>
            {
                warn!(
                    "package list {package_list_guid}: ignoring the FormSet at offset {offset} of \
                     a form package: {error:#}"
                );
                package_cursor.set_position(offset);
                if let Err(error) = skip_scope(package_cursor) {
                    debug!("ending the FormSet walk in the FormSet at offset {offset}: {error}");
                    break;
                }
            }
            Err(error)
                if !roots.is_empty() && error.chain().any(|cause| cause.is::<binrw::Error>()) =>
            {
                warn!(
                    "package list {package_list_guid}: ignoring the FormSet at offset {offset} of \
                     a form package and the ops after it: {error:#}"
                );
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(roots)
}

/// Moves `package_cursor` from the op at its position past the End that closes that op's scope,
/// reading the ops in between undecoded, as GetIfrBinaryData's walk steps over them.
fn skip_scope(package_cursor: &mut Cursor<&Vec<u8>>) -> binrw::BinResult<()> {
    let mut depth: usize = 0;
    loop {
        let op: IFROperation = package_cursor.read_ne()?;
        match (&op.op_code, op.open_scope) {
            (IFROpCode::End, _) => depth = depth.saturating_sub(1),
            (_, true) => depth = depth.saturating_add(1),
            (_, false) => {}
        }
        if depth == 0 {
            return Ok(());
        }
    }
}

pub fn handle_form_set(package_cursor: &mut Cursor<&Vec<u8>>) -> Result<Rc<RefCell<IFROperation>>> {
    handle_form_set_within(package_cursor, MAX_SCOPE_NESTING)
}

/// handle_form_set, failing with ScopesTooDeep at an op that opens more than `limit` scopes at
/// once.
fn handle_form_set_within(
    package_cursor: &mut Cursor<&Vec<u8>>,
    limit: usize,
) -> Result<Rc<RefCell<IFROperation>>> {
    // this is the root element so all the values like op_code, length, etc are dummy
    debug!("new FormSet");
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
    // The scopes open inside an op that skips_scope names, its own scope counted: their ops are not
    // decoded, as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips them unread
    // (InUnknownScope, UnknownDepth).
    let mut skipped_depth: usize = 0;
    // The scopes open, the FormSet's own and skipped ones counted
    let mut depth: usize = 0;

    // this loop will terminate when it sees the IFR:End opcode as a child of FormSet
    // if input data is malformed then it will exit on erroring out cause none of the magic bytes match
    loop {
        let offset = package_cursor.position();
        let node: IFROperation = package_cursor
            .read_ne()
            .context("failed to parse IFR operation")?;

        let current_node = Rc::new(RefCell::new(node));

        debug!("OpCode is {:?}", current_node.borrow().op_code);

        // end of current scope
        if current_node.borrow().op_code == IFROpCode::End {
            skipped_depth = skipped_depth.saturating_sub(1);
            depth = depth.saturating_sub(1);
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

            // back at the root: this FormSet has been parsed. The root is found by
            // identity: an IFR op may have opcode 0xFF, the root's DUMMY_OPCODE, and a scope.
            if Rc::ptr_eq(&current_scope, &root) {
                debug!("Reached root element. Current scope: {:?}", current_scope);
                // parse_form_sets reads the FormSets after this one
                break;
            }
            continue;
        }

        if current_node.borrow().open_scope {
            if depth >= limit {
                return Err(ScopesTooDeep { offset, limit }.into());
            }
            depth += 1;
        }

        // set current_node's parent
        // before handle_opcode: ValueEncoding::from_question reads it
        current_node.borrow_mut().parent = Some(Rc::downgrade(&current_scope));

        if skipped_depth == 0 {
            handle_opcode(Rc::clone(&current_node)).context(format!(
                "failed to parse op_code {:?} properly",
                &current_node.borrow().op_code,
            ))?;
        }

        // add current_node to current_scope's children
        current_scope
            .borrow_mut()
            .children
            .push(Rc::clone(&current_node));

        if current_node.borrow().open_scope {
            if skipped_depth > 0 || skips_scope(&current_node.borrow()) {
                skipped_depth += 1;
            }
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
                .context("failed to parse FormSet's data")?;
            debug!("FormSet is {:?}", parsed);
            node.parsed_data = ParsedOperation::FormSet(parsed);
        }

        IFROpCode::OneOf => {
            let parsed: OneOf = data_cursor
                .read_ne_args((ValueEncoding::from_question(&node),))
                .context("failed to parse OneOf's data")?;
            debug!("OneOf is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOf(parsed);
        }
        IFROpCode::CheckBox => {
            let parsed: CheckBox = data_cursor
                .read_ne_args((ValueEncoding::from_question(&node),))
                .context("failed to parse CheckBox's data")?;
            debug!("CheckBox is {:?}", parsed);
            node.parsed_data = ParsedOperation::CheckBox(parsed);
        }
        IFROpCode::OneOfOption => {
            let parsed: OneOfOption = data_cursor
                .read_ne()
                .context("failed to parse OneOfOption's data")?;
            debug!("OneOfOption is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOfOption(parsed);
        }
        IFROpCode::VarStore => {
            let parsed: VarStore = data_cursor
                .read_ne()
                .context("failed to parse VarStore's data")?;

            debug!("VarStore is {:?}", &parsed);

            node.parsed_data = ParsedOperation::VarStore(parsed);
        }
        IFROpCode::VarStoreNameValue => {
            let parsed: VarStoreNameValue = data_cursor
                .read_ne()
                .context("failed to parse VarStoreNameValue's data")?;
            debug!("VarStoreNameValue is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreNameValue(parsed);
        }
        IFROpCode::VarStoreEfi => {
            // this is implemented in hiilib and the docs for this are relatively clear
            // so I implemented this but I haven't seen it being used anywhere in the dbdumps I have
            let parsed: VarStoreEfi = data_cursor
                .read_ne()
                .context("failed to parse VarStoreEfi's data")?;
            debug!("VarStoreEfi is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreEfi(parsed);
        }
        IFROpCode::DefaultStore => {
            let parsed: DefaultStore = data_cursor
                .read_ne()
                .context("failed to parse DefaultStore's data")?;
            debug!("DefaultStore is {:?}", parsed);
            node.parsed_data = ParsedOperation::DefaultStore(parsed);
        }
        IFROpCode::Default => {
            let parsed: IFRDefault = data_cursor
                .read_ne()
                .context("failed to parse Default's data")?;
            debug!("Default is {:?}", parsed);
            node.parsed_data = ParsedOperation::IFRDefault(parsed);
        }
        IFROpCode::Form => {
            let parsed: Form = data_cursor
                .read_ne()
                .context("failed to parse Form's data")?;
            debug!("Form is {:?}", parsed);
            node.parsed_data = ParsedOperation::Form(parsed);
        }
        IFROpCode::Text => {
            let parsed: Text = data_cursor
                .read_ne()
                .context("failed to parse Text's data")?;
            debug!("Text is {:?}", parsed);
            node.parsed_data = ParsedOperation::Text(parsed);
        }
        IFROpCode::Subtitle => {
            let parsed: Subtitle = data_cursor
                .read_ne()
                .context("failed to parse Subtitle's data")?;
            debug!("Subtitle is {:?}", parsed);
            node.parsed_data = ParsedOperation::Subtitle(parsed);
        }
        IFROpCode::Numeric => {
            let parsed: Numeric = data_cursor
                .read_ne_args((ValueEncoding::from_question(&node),))
                .context("failed to parse Numeric's data")?;
            debug!("Numeric is {:?}", parsed);
            node.parsed_data = ParsedOperation::Numeric(parsed);
        }
        IFROpCode::QuestionRef1 => {
            let parsed: QuestionRef1 = data_cursor
                .read_ne()
                .context("failed to parse QuestionRef1's data")?;
            debug!("QuestionRef1 is {:?}", parsed);
            node.parsed_data = ParsedOperation::QuestionRef1(parsed);
        }
        IFROpCode::EqIdVal => {
            let parsed: EqIdVal = data_cursor
                .read_ne()
                .context("failed to parse EqIdVal's data")?;
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
                .context("failed to parse EqIdValList's data")?;
            debug!("EqIdValList is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdValList(parsed);
        }
        // An undecoded GET, SET or FORM_MAP keeps the FormSet, whose other questions get and set
        // still reach: an evaluation refuses an undecoded GET or SET, and an undecoded FORM_MAP is
        // no standard map form.
        IFROpCode::Get => match data_cursor.read_ne() {
            Ok(parsed) => node.parsed_data = ParsedOperation::Get(parsed),
            Err(error) => debug!("leaving a Get undecoded: {error}"),
        },
        IFROpCode::Set => match data_cursor.read_ne() {
            Ok(parsed) => node.parsed_data = ParsedOperation::Set(parsed),
            Err(error) => debug!("leaving a Set undecoded: {error}"),
        },
        IFROpCode::FormMap => match FormMap::decode(&node.data) {
            Some(parsed) => node.parsed_data = ParsedOperation::FormMap(parsed),
            None => debug!("leaving a FormMap without a FormId undecoded"),
        },
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
    /// The Flags of its question header
    pub flags: QuestionFlags,
    pub possible_options: Vec<AnswerOption>,
    /// The VarStore of the question, or why set cannot write it
    varstore: Result<Box<dyn VariableStore>>,
    /// Where the question keeps its value
    location: ValueLocation,
    /// The state of the option that `value` names: selectable if none does
    pub(crate) value_state: StateEvaluation,
    /// The question's op, whose WRITE expression set evaluates
    node: Rc<RefCell<IFROperation>>,
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
    /// The VarStore of the question, or None for a question without one whose WRITE expression
    /// alone takes the value, or why set, through variables of `reach`, cannot write it, as for a
    /// question that an EFI_IFR_VALUE makes read-only.
    fn store(
        &self,
        reach: VariableReach,
    ) -> std::result::Result<Option<&dyn VariableStore>, ChangeValueError> {
        if question_value_expression(&self.node).is_some() {
            return Err(ChangeValueError::ReadOnly {
                question: self.question.clone(),
            });
        }
        let reason = match &self.varstore {
            Ok(store) => return Ok(Some(store.as_ref())),
            Err(reason) => reason,
        };
        match reason.downcast_ref::<NoVarStore>() {
            Some(NoVarStore(storageless)) => {
                match storageless.refusal(QuestionExpression::Write, reach) {
                    None => Ok(None),
                    Some(refusal) => Err(ChangeValueError::Storageless {
                        question: self.question.clone(),
                        refusal,
                    }),
                }
            }
            None => Err(ChangeValueError::NoVarStore {
                question: self.question.clone(),
                reason: format!("{reason:#}"),
            }),
        }
    }

    /// How get (`Read`) or set (`Write`) reaches the value of a question without a VarStore;
    /// None for one with a VarStore.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
        )
    )]
    pub(crate) fn storageless_route(
        &self,
        expression: QuestionExpression,
    ) -> Option<std::result::Result<StoragelessRoute, StoragelessRefusal>> {
        let NoVarStore(storageless) = self.varstore.as_ref().err()?.downcast_ref::<NoVarStore>()?;
        Some(storageless.route(expression))
    }

    /// The option that set writes for one of `texts`.
    pub(crate) fn chosen_option(
        &self,
        texts: &BTreeSet<String>,
        include: IncludedStates,
    ) -> Result<&AnswerOption> {
        // if not a single option matched then error out
        self.select_option(texts, include)?
            .ok_or_else(|| ChangeValueError::InvalidOption.into())
    }

    /// The texts of the options that `include` certainly allows: those that get lists and set
    /// takes.
    pub(crate) fn listed_options(&self, include: IncludedStates) -> Vec<String> {
        self.possible_options
            .iter()
            .filter(|option| option.state.is_allowed(include))
            .map(|option| option.value.clone())
            .collect()
    }

    /// Returns the option that select() picks with `include` among those whose text is one of
    /// `texts` ignoring ASCII case, or, if there are none, among those whose text is one of
    /// `texts` ignoring surrounding whitespace too (get shows the text trimmed), or None if there
    /// are none either. So a text as stored never picks an option that differs from it only by
    /// such whitespace.
    pub(crate) fn select_option(
        &self,
        texts: &BTreeSet<String>,
        include: IncludedStates,
    ) -> std::result::Result<Option<&AnswerOption>, SelectionError> {
        let stored: Vec<&AnswerOption> = self
            .possible_options
            .iter()
            .filter(|option| {
                texts
                    .iter()
                    .any(|text| text.eq_ignore_ascii_case(&option.value))
            })
            .collect();
        let candidates = if stored.is_empty() {
            self.possible_options
                .iter()
                .filter(|option| {
                    texts
                        .iter()
                        .any(|text| text.trim().eq_ignore_ascii_case(option.value.trim()))
                })
                .collect()
        } else {
            stored
        };
        let matches: Vec<(&AnswerOption, StateEvaluation)> = candidates
            .into_iter()
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

// list_questions returns a list of QuestionDescriptors in a FormSet
// with their states, of the questions in a state that `include` may allow
// node should be the root of a FormSet
// conditions read `access_level`, if stated, for AMI_ACCESS_LEVEL instead of its value
pub fn list_questions(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &[BTreeMap<i32, String>],
    include: IncludedStates,
    access_level: Option<AccessLevel>,
    reader: &mut EfivarReader,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let values = VarStoreValues::new(&node, access_level);
    list_questions_in(
        &node,
        &mut FormSetWalk::new(string_packages, reader, &values, include),
    )
}

/// What walking the ops of a FormSet takes besides them.
struct FormSetWalk<'a, V> {
    /// The string packages of the FormSet's package list
    string_packages: &'a [BTreeMap<i32, String>],
    default_ids: FormSetDefaultIds,
    inputs: ExpressionInputs<'a, V>,
    include: IncludedStates,
}

impl<'a, V> FormSetWalk<'a, V> {
    fn new(
        string_packages: &'a [BTreeMap<i32, String>],
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
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let mut res = Vec::new();
    walk_scopes(std::slice::from_ref(node), (), |node, ()| {
        if skips_scope(&node.borrow()) {
            return Walk::Skip;
        }
        res.extend(listed_question(node, walk));
        Walk::Enter(())
    });
    res
}

/// Returns the QuestionDescriptor and states of a ONE_OF, NUMERIC or CHECKBOX in a state that
/// `walk.include` may allow.
fn listed_question(
    question: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Option<(QuestionDescriptor, StateEvaluation)> {
    let op = question.borrow();
    let value_question = value_question(&op)?;
    let state = question_state(&op, &mut walk.inputs);
    if !state.may_be_allowed(walk.include) {
        return None;
    }
    let descriptor = describe_question(question, value_question, walk);
    Some((descriptor, state))
}

/// find_question accepts the root node, string_packages and possible_question_phrases.
/// possible_question_phrases is a vector of strings which represent variations of the
/// same question. So if a single phrase matches then we assume that we have the answer.
/// Of the matching questions, it selects one as select does, with conditions reading
/// `access_level`, if stated, for AMI_ACCESS_LEVEL instead of its value.
pub fn find_question<T>(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &[BTreeMap<i32, String>],
    possible_question_phrases: &BTreeSet<T>,
    include: IncludedStates,
    access_level: Option<AccessLevel>,
    reader: &mut EfivarReader,
) -> Selection<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let values = VarStoreValues::new(&node, access_level);
    find_question_in(
        &node,
        possible_question_phrases,
        &mut FormSetWalk::new(string_packages, reader, &values, include),
    )
}

/// Finds a question as find_question does, with `walk`.
fn find_question_in<T>(
    node: &Rc<RefCell<IFROperation>>,
    possible_question_phrases: &BTreeSet<T>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
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
            Some(((question, value_question), state))
        })
        .collect();
    select(matches, walk.include)
        .map(|(question, value_question)| describe_question(question, value_question, walk))
}

/// set's choice of the selection of a FormSet: that of Selection::for_set, unless the
/// match that set would write, or the likely match, has no VarStore, or its efivar is missing,
/// unreadable, e.g. withheld, boot-service-only, volatile or authenticated, which --include
/// cannot make writable: then ChangeValueError::NoVarStore, DeclaredBootServiceOnly,
/// VariableNotExported or the read's error, as `reader` found it, BootServiceOnlyVariable,
/// VolatileVariable or AuthenticatedVariable.
pub(crate) fn choice_for_set(
    selection: Selection<QuestionDescriptor>,
    question: &str,
    reader: &EfivarReader,
) -> Result<Choice<QuestionDescriptor>> {
    let descriptor = match &selection {
        Selection::Picked(descriptor, _)
        | Selection::Undetermined {
            likely: (descriptor, _),
            ..
        } => descriptor,
        Selection::Excluded(_) | Selection::NotFound => return Ok(selection.for_set(question)?),
    };
    // the WRITE expression of a question without a VarStore names the stores that set writes
    if let Some(store) = descriptor.store(reader.reach())? {
        check_writable(store, reader)?;
    }
    Ok(selection.for_set(question)?)
}

/// Refuses `store` unless set may write its variable, which `reader` has read: one that the read
/// failed for, or whose attributes set does not write, a volatile, authenticated, or, at OS
/// runtime, boot-service-only variable.
fn check_writable(store: &dyn VariableStore, reader: &EfivarReader) -> Result<()> {
    let reach = reader.reach();
    let interface = reader.interface();
    if let Some(error) = reader.read_error(store) {
        return Err(unwritable(store, error, reach, interface));
    }
    if let Some(attributes) = reader.attributes(store) {
        let key = store.variable_key();
        check_non_volatile(&key, interface, attributes)?;
        check_unauthenticated(&key, attributes)?;
        check_runtime_writable(&key, reach, attributes)?;
    }
    Ok(())
}

/// Why set does not write the variable of `store`, whose read through variables of `reach` and
/// `interface` failed with `error`.
fn unwritable(
    store: &dyn VariableStore,
    error: &anyhow::Error,
    reach: VariableReach,
    interface: VariableInterface,
) -> anyhow::Error {
    if let Some(declared) = store.explain_unread(reach, interface, error) {
        return declared.into();
    }
    match error.downcast_ref::<VariableNotFound>() {
        Some(missing) => VariableNotExported {
            missing: missing.clone(),
            interface,
        }
        .into(),
        None => anyhow!("{error:#}"),
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod choice_for_set_tests {
    use super::ifr_fixtures::*;
    use super::storage::read_current_value_bytes;
    use super::*;

    /// The refusal of the efivar Present with the attributes NV_BS through variables that reach
    /// Runtime.
    const PRESENT_BOOT_SERVICE_ONLY: &str = "EFI variable \
        Present-00000000-0000-0000-0000-000000000000 has no EFI_VARIABLE_RUNTIME_ACCESS \
        (attributes 0x3), so the firmware refuses to write it at OS runtime";
    /// The refusal of the efivar Missing, which variables that reach Runtime lack, where its
    /// form declares it boot-service-only.
    const MISSING_NOT_PRESENT: &str = "EFI variable Missing-00000000-0000-0000-0000-000000000000 \
        is not present at OS runtime: efivarfs does not list it, and its form declares it \
        boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
    /// MISSING_NOT_PRESENT for variables through the firmware environment calls.
    const WINDOWS_MISSING_NOT_PRESENT: &str = "EFI variable \
        Missing-00000000-0000-0000-0000-000000000000 is not present at OS runtime: \
        GetFirmwareEnvironmentVariableExW does not find it, and its form declares it \
        boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
    /// The VariableNotFound of the efivar Missing.
    const MISSING_NOT_FOUND: &str = "no EFI variable Missing-00000000-0000-0000-0000-000000000000";
    /// Why the EQ_ID_VAL on question 2, on the efivar Missing, is not evaluated.
    const MISSING_INPUT: &str = "EFI_IFR_EQ_ID_VAL of question 0x0002: <ValueUnavailable: no EFI \
        variable Missing-00000000-0000-0000-0000-000000000000>";
    /// Why the EQ_ID_VAL on question 2, on AMI firmware's buffer VarStore SystemAccess without
    /// an efivar, is not evaluated.
    const SYSTEM_ACCESS_INPUT: &str = "EFI_IFR_EQ_ID_VAL of question 0x0002: <ValueUnavailable: \
        no EFI variable SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac; HII buffer varstore \
        requires EFI_HII_CONFIG_ACCESS_PROTOCOL; the AMI setup browser keeps its access level \
        there (0 Administrator, 1 User); --access-level administrator|user states one>";

    /// set's choice for PROMPT in the FormSet `root`, where only the efivar Present, of
    /// 1 byte, exists.
    fn choice_in(root: &Rc<RefCell<IFROperation>>) -> Result<Choice<QuestionDescriptor>> {
        choice_attributed(root, NV_BS_RT)
    }

    /// choice_in, with the attribute word `attributes` in the efivar file of Present.
    fn choice_attributed(
        root: &Rc<RefCell<IFROperation>>,
        attributes: u32,
    ) -> Result<Choice<QuestionDescriptor>> {
        let efivars = Efivars::new();
        efivars.write_attributed(&efi_variable("Present", 1), attributes, &[0]);
        choice_with(root, &efivars)
    }

    /// set's choice for PROMPT in the FormSet `root`, with the efivar files `efivars`.
    fn choice_with(
        root: &Rc<RefCell<IFROperation>>,
        efivars: &Efivars,
    ) -> Result<Choice<QuestionDescriptor>> {
        choice_reading(root, efivars, None)
    }

    /// choice_with, with conditions reading `access_level`, if stated, for SystemAccess instead of
    /// its value.
    fn choice_reading(
        root: &Rc<RefCell<IFROperation>>,
        efivars: &Efivars,
        access_level: Option<AccessLevel>,
    ) -> Result<Choice<QuestionDescriptor>> {
        choice_by(root, efivars.reader(), access_level)
    }

    /// choice_reading, with `reader` instead of a reader of efivar files.
    fn choice_by(
        root: &Rc<RefCell<IFROperation>>,
        mut reader: EfivarReader,
        access_level: Option<AccessLevel>,
    ) -> Result<Choice<QuestionDescriptor>> {
        let values = VarStoreValues::new(root, access_level);
        let selection = find_question_in(
            root,
            &BTreeSet::from([PROMPT]),
            &mut FormSetWalk::new(&strings(), &mut reader, &values, IncludedStates::empty()),
        );
        choice_for_set(selection, PROMPT, &reader)
    }

    /// set's choice for PROMPT in the FormSet of `undetermined_on(own)`.
    fn choice(own: u16) -> Result<Choice<QuestionDescriptor>> {
        choice_in(&undetermined_on(own))
    }

    /// The FormSet of PROMPT, question 1 on VarStore `own` under a SUPPRESS_IF on question 2,
    /// which is on VarStore 2; VarStore 3 is VarStore 1 without runtime access, and only their
    /// efivar exists.
    fn undetermined_on(own: u16) -> Rc<RefCell<IFROperation>> {
        parse_form_set(&[
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
        ])
    }

    /// set's choice for PROMPT, prompting a selectable ONE_OF on VarStore 1, after the
    /// VarStores `var_stores`, whose option Enabled is under a SUPPRESS_IF on question 2 of
    /// VarStore `input`.
    fn picked_choice(var_stores: &[Vec<u8>], input: u16) -> Result<Choice<QuestionDescriptor>> {
        choice_in(&picked_one_of(var_stores, input))
    }

    /// The FormSet of picked_choice.
    fn picked_one_of(var_stores: &[Vec<u8>], input: u16) -> Rc<RefCell<IFROperation>> {
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
        root
    }

    #[test]
    fn undetermined_match_on_a_missing_efivar_is_not_exported() {
        let error = choice(2).expect_err("set refuses question 1");
        assert_eq!(
            error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.missing.to_string())
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

    /// The FormSet of PROMPT, question 1 on VarStore 1, which AMI firmware grays out for a
    /// User session: SystemAccess, question 2, being 1.
    fn grayed_out_for_users() -> Rc<RefCell<IFROperation>> {
        parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
            form(
                1,
                &[
                    checkbox_on(2, 5, 2),
                    conditional(GRAY_OUT_IF, eq_id_val_of(2, 1), &[checkbox_on(1, 3, 1)]),
                ],
            ),
        ])
    }

    /// set's refusal of a question that AMI firmware grays out for a User session names where
    /// the access level is kept.
    #[test]
    fn undetermined_match_on_the_ami_access_level_names_it() {
        let error = choice_in(&grayed_out_for_users()).expect_err("set refuses question 1");
        assert_eq!(
            error.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Undetermined {
                question: PROMPT.to_string(),
                states: IncludedStates::GRAYED_OUT,
                reasons: vec![SYSTEM_ACCESS_INPUT.to_string()],
            }),
            "question 1 under a GRAY_OUT_IF on the access level: {error:#}"
        );
    }

    /// set chooses a question that AMI firmware grays out for a User session at a stated
    /// Administrator level, and skips it as grayed out at a stated User level.
    #[test]
    fn stated_access_level_decides_the_choice() {
        let root = grayed_out_for_users();
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Present", 1), &[0]);

        let administrator = choice_reading(&root, &efivars, Some(AccessLevel::Administrator));
        assert!(
            matches!(administrator, Ok(Choice::Chosen(..))),
            "Administrator: {administrator:?}"
        );
        let user = choice_reading(&root, &efivars, Some(AccessLevel::User));
        assert!(
            matches!(user, Ok(Choice::Skipped(states)) if states == IncludedStates::GRAYED_OUT),
            "User: {user:?}"
        );
    }

    #[test]
    fn picked_match_on_a_missing_efivar_is_not_exported() {
        let error = picked_choice(&[var_store_efi(1, "Missing", NV_BS_RT, 1)], 1)
            .expect_err("set refuses the ONE_OF");
        assert_eq!(
            error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.missing.to_string())
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
        let enabled = BTreeSet::from(["Enabled".to_string()]);
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
    fn match_without_a_varstore_is_refused() {
        let choice = choice_in(&parse_form_set(&[form(1, &[checkbox_on(1, 3, 0)])]));
        assert_eq!(
            choice.map_err(|error| error.to_string()).err().as_deref(),
            Some(
                "cannot set question \"Prompt\": question has no VarStore, READ or WRITE \
                 expression, or EFI_IFR_FLAG_CALLBACK, one of which UEFI 2.11 §33.2.5.6 requires"
            ),
            "question 1 on VarStoreId 0"
        );
    }

    #[test]
    fn match_on_an_unreadable_efivar_is_refused_with_the_read_error() {
        // VARSTORE_EFI's Size is 2
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 2)], 1);
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Present", 1), &[0]);

        let error = choice_with(&root, &efivars).expect_err("set refuses the ONE_OF");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "failed to read efivar file '{}': failed to fill whole buffer",
                efivars
                    .path()
                    .join("Present-00000000-0000-0000-0000-000000000000")
                    .display()
            ),
            "efivar file of 1 payload byte"
        );
        efivars.write(&efi_variable("Present", 2), &[0, 0]);
        let choice = choice_with(&root, &efivars);
        assert!(
            matches!(choice, Ok(Choice::Chosen(..))),
            "efivar file of 2 payload bytes: {choice:?}"
        );
    }

    #[test]
    fn match_on_a_volatile_efivar_is_refused() {
        // VARSTORE_EFI's Attributes say NV: the efivar file's attribute word decides
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);

        let volatile = choice_attributed(&root, BS_RT);
        assert_eq!(
            volatile.map_err(|error| error.to_string()).err().as_deref(),
            Some(
                "EFI variable Present-00000000-0000-0000-0000-000000000000 is volatile \
                 (no EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs"
            ),
            "efivar file with attributes BS_RT"
        );
        let non_volatile = choice_attributed(&root, NV_BS_RT);
        assert!(
            matches!(non_volatile, Ok(Choice::Chosen(..))),
            "efivar file with attributes NV_BS_RT: {non_volatile:?}"
        );
    }

    /// set chooses a question on an NV|BS variable from variables that reach BootServices, and
    /// refuses it, having read it, from variables that reach Runtime, through efivarfs or the
    /// firmware environment calls.
    #[test]
    fn match_on_a_boot_service_only_efivar_is_refused_only_for_runtime_variables() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS, 1)], 1);
        let choose = |reach, interface| {
            let variables = Rc::new(MemoryVariables::new(reach, interface));
            variables.insert(variable_key("Present"), NV_BS, &[0]);
            let reader = EfivarReader::with_variables(Box::new(Rc::clone(&variables)));
            (choice_by(&root, reader, None), variables.reads())
        };

        let (choice, reads) = choose(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        assert!(
            matches!(choice, Ok(Choice::Chosen(..))),
            "BootServices: {choice:?}"
        );
        assert_eq!(reads, [(variable_key("Present"), 1)], "BootServices: reads");
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::FirmwareEnvironment,
        ] {
            let (choice, reads) = choose(VariableReach::Runtime, interface);
            assert_eq!(
                choice.map_err(|error| error.to_string()).err().as_deref(),
                Some(PRESENT_BOOT_SERVICE_ONLY),
                "{interface:?}"
            );
            assert_eq!(
                reads,
                [(variable_key("Present"), 1)],
                "{interface:?}: reads"
            );
        }
    }

    /// set refuses a match whose variable lacks EFI_VARIABLE_RUNTIME_ACCESS and chooses one whose
    /// variable has it, whatever runtime access its VARSTORE_EFI declares, from efivarfs and from
    /// the firmware environment calls; the refusal comes before set tells whether the match is
    /// selectable.
    #[test]
    fn match_is_decided_by_the_runtime_access_of_its_efivar() {
        let firmware_environment = |root: &Rc<RefCell<IFROperation>>, attributes| {
            let variables = MemoryVariables::new(
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            );
            variables.insert(variable_key("Present"), attributes, &[0]);
            choice_by(
                root,
                EfivarReader::with_variables(Box::new(variables)),
                None,
            )
        };
        let refusal = |choice: Result<Choice<QuestionDescriptor>>| {
            choice.map_err(|error| error.to_string()).err()
        };

        for declared in [NV_BS, NV_BS_RT] {
            let root = picked_one_of(&[var_store_efi(1, "Present", declared, 1)], 1);
            let cases = [
                (
                    "efivarfs",
                    choice_attributed(&root, NV_BS),
                    choice_attributed(&root, NV_BS_RT),
                ),
                (
                    "Windows",
                    firmware_environment(&root, NV_BS),
                    firmware_environment(&root, NV_BS_RT),
                ),
            ];

            for (variables, boot_service_only, runtime) in cases {
                assert_eq!(
                    refusal(boot_service_only).as_deref(),
                    Some(PRESENT_BOOT_SERVICE_ONLY),
                    "{variables}, VarStore attributes {declared:#x}, efivar attributes 0x3"
                );
                assert!(
                    matches!(runtime, Ok(Choice::Chosen(..))),
                    "{variables}, VarStore attributes {declared:#x}, efivar attributes 0x7: \
                     {runtime:?}"
                );
            }
        }
        for (variables, undetermined) in [
            ("efivarfs", choice_attributed(&undetermined_on(3), NV_BS)),
            ("Windows", firmware_environment(&undetermined_on(3), NV_BS)),
        ] {
            assert_eq!(
                refusal(undetermined).as_deref(),
                Some(PRESENT_BOOT_SERVICE_ONLY),
                "{variables}, undetermined match on VarStore 3, efivar attributes 0x3"
            );
        }
    }

    /// set refuses a match whose variable is missing by its VARSTORE_EFI's boot-service-only
    /// declaration for variables that reach Runtime, in the words of their interface, with the
    /// text that get shows for it, and as VariableNotExported otherwise.
    #[test]
    fn match_on_a_missing_efivar_of_a_boot_service_only_store_is_not_present() {
        let efivarfs = (VariableReach::Runtime, VariableInterface::Efivarfs);
        let firmware_environment = (
            VariableReach::Runtime,
            VariableInterface::FirmwareEnvironment,
        );
        let variable_services = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let cases = [
            (NV_BS, efivarfs, Some(MISSING_NOT_PRESENT)),
            (
                NV_BS,
                firmware_environment,
                Some(WINDOWS_MISSING_NOT_PRESENT),
            ),
            (NV_BS, variable_services, None),
            (NV_BS_RT, efivarfs, None),
            (NV_BS_RT, firmware_environment, None),
        ];

        for (declared, (reach, interface), not_present) in cases {
            let root = picked_one_of(&[var_store_efi(1, "Missing", declared, 1)], 1);
            let store = VarStoreEfi {
                var_store_id: 1,
                guid: NIL_GUID,
                attributes: declared,
                size: 1,
                name: "Missing".into(),
            };
            let mut reader =
                EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)));
            let case = format!("VarStore attributes {declared:#x}, {reach:?}, {interface:?}");

            let read = read_current_value_bytes(&Ok(Box::new(store)), 0..1, &mut reader)
                .map(<[u8]>::to_vec)
                .map_err(|reason| reason.to_answer());
            let error = choice_by(&root, reader, None).expect_err("set refuses the ONE_OF");

            let not_exported = error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.missing.to_string());
            match not_present {
                Some(text) => {
                    assert_eq!(
                        read,
                        Err(format!("<ValueUnavailable: {error}>")),
                        "{case}: get"
                    );
                    assert_eq!(error.to_string(), text, "{case}");
                    assert_eq!(not_exported, None, "{case}: VariableNotExported");
                }
                None => assert_eq!(
                    not_exported.as_deref(),
                    Some(MISSING_NOT_FOUND),
                    "{case}: {error:#}"
                ),
            }
        }
    }

    /// set's refusal of a match whose variable is missing follows the interface of the variables
    /// that it reads.
    #[test]
    fn match_on_a_missing_variable_is_explained_by_its_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Missing", NV_BS_RT, 1)], 1);
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "does not expose it to the OS",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                "cannot be set from Windows",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                ": the firmware has not created it, and set never creates variables",
            ),
        ];

        for (reach, interface, refusal) in cases {
            let reader =
                EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)));
            let error = choice_by(&root, reader, None).expect_err("set refuses the ONE_OF");

            let text = error.to_string();
            assert!(
                text.starts_with(MISSING_NOT_FOUND) && text.contains(refusal),
                "{interface:?}: {text}"
            );
        }
    }

    /// set decides the runtime access of a match by the reach of its variables, whatever their
    /// interface: it chooses a question on an NV|BS variable from variables that reach
    /// BootServices and refuses it from those that reach Runtime.
    #[test]
    fn runtime_access_is_decided_by_reach_whatever_the_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS, 1)], 1);
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::VariableServices,
            VariableInterface::FirmwareEnvironment,
        ] {
            for (reach, refusal) in [
                (VariableReach::BootServices, None),
                (VariableReach::Runtime, Some(PRESENT_BOOT_SERVICE_ONLY)),
            ] {
                let variables = MemoryVariables::new(reach, interface);
                variables.insert(variable_key("Present"), NV_BS, &[0]);

                let choice = choice_by(
                    &root,
                    EfivarReader::with_variables(Box::new(variables)),
                    None,
                );

                let chosen = matches!(choice, Ok(Choice::Chosen(..)));
                assert_eq!(
                    (chosen, choice.err().map(|error| error.to_string())),
                    (refusal.is_none(), refusal.map(str::to_string)),
                    "{reach:?}, {interface:?}"
                );
            }
        }
    }

    /// get and set explain a missing variable of a boot-service-only VARSTORE_EFI by the reach of
    /// their variables, whatever their interface, in the words of that interface: by the form's
    /// declaration for variables that reach Runtime, and otherwise as VariableNotExported.
    #[test]
    fn missing_variable_is_explained_by_reach_in_the_words_of_its_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Missing", NV_BS, 1)], 1);
        let cases = [
            (
                VariableInterface::Efivarfs,
                "efivarfs does not list it",
                "cannot be set from Linux",
            ),
            (
                VariableInterface::VariableServices,
                "GetVariable() does not find it",
                "set never creates variables",
            ),
            (
                VariableInterface::FirmwareEnvironment,
                "GetFirmwareEnvironmentVariableExW does not find it",
                "cannot be set from Windows",
            ),
        ];

        let crossed = cases.into_iter().flat_map(|case| {
            [VariableReach::Runtime, VariableReach::BootServices].map(|reach| (case, reach))
        });
        for ((interface, absence, not_found_refusal), reach) in crossed {
            let store = VarStoreEfi {
                var_store_id: 1,
                guid: NIL_GUID,
                attributes: NV_BS,
                size: 1,
                name: "Missing".into(),
            };
            let mut reader =
                EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)));
            let case = format!("{reach:?}, {interface:?}");

            let read = read_current_value_bytes(&Ok(Box::new(store)), 0..1, &mut reader)
                .map(<[u8]>::to_vec)
                .map_err(|reason| reason.to_answer());
            let error = choice_by(&root, reader, None).expect_err("set refuses the ONE_OF");

            match reach {
                VariableReach::Runtime => {
                    let not_present = format!(
                        "EFI variable Missing-00000000-0000-0000-0000-000000000000 is not \
                         present at OS runtime: {absence}, and its form declares it \
                         boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)"
                    );
                    assert_eq!(
                        read,
                        Err(format!("<ValueUnavailable: {not_present}>")),
                        "{case}: get"
                    );
                    assert_eq!(error.to_string(), not_present, "{case}: set");
                }
                VariableReach::BootServices => {
                    assert_eq!(
                        read,
                        Err(format!("<ValueUnavailable: {MISSING_NOT_FOUND}>")),
                        "{case}: get"
                    );
                    let text = error.to_string();
                    assert!(
                        error.is::<VariableNotExported>()
                            && text.starts_with(MISSING_NOT_FOUND)
                            && text.contains(not_found_refusal),
                        "{case}: set: {text}"
                    );
                }
            }
        }
    }

    /// set refuses a match on a volatile efivar in the words of the interface of its variables,
    /// whatever their reach.
    #[test]
    fn match_on_a_volatile_efivar_is_refused_in_the_words_of_its_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        for (interface, refusal) in [
            (
                VariableInterface::Efivarfs,
                " and cannot be written through efivarfs",
            ),
            (
                VariableInterface::VariableServices,
                ", so a write would not outlast a power cycle",
            ),
            (
                VariableInterface::FirmwareEnvironment,
                ", so a write would not outlast a power cycle",
            ),
        ] {
            for reach in [VariableReach::Runtime, VariableReach::BootServices] {
                let variables = MemoryVariables::new(reach, interface);
                variables.insert(variable_key("Present"), BS_RT, &[0]);
                let reader = EfivarReader::with_variables(Box::new(variables));

                let error =
                    choice_by(&root, reader, None).expect_err("set refuses a volatile efivar");

                assert_eq!(
                    error.to_string(),
                    format!(
                        "EFI variable Present-00000000-0000-0000-0000-000000000000 is volatile \
                         (no EFI_VARIABLE_NON_VOLATILE){refusal}"
                    ),
                    "{reach:?}, {interface:?}"
                );
            }
        }
    }

    /// set refuses a match on a variable with any authenticated access before any write: every
    /// write of it needs a signed descriptor (UEFI 2.10 §8.2.3).
    #[test]
    fn match_on_an_authenticated_efivar_is_refused() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        for attributes in [NV_BS_RT | 0x10, NV_BS_RT | 0x20, NV_BS_RT | 0x80] {
            let signed = choice_attributed(&root, attributes);

            assert_eq!(
                signed.map_err(|error| error.to_string()).err(),
                Some(format!(
                    "EFI variable Present-00000000-0000-0000-0000-000000000000 has authenticated \
                     access (attributes {attributes:#x}), which uefisettings does not write"
                )),
                "efivar file with attributes {attributes:#x}"
            );
        }
    }

    /// set decides on a match on an NV|BS VARSTORE_EFI whose variable has
    /// EFI_VARIABLE_RUNTIME_ACCESS as on one on a VARSTORE_EFI that declares it.
    #[test]
    fn match_on_a_boot_service_only_store_of_a_runtime_efivar_is_decided_by_its_conditions() {
        let undetermined = choice(3).expect_err("set refuses question 1");
        assert_eq!(
            undetermined.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Undetermined {
                question: PROMPT.to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![MISSING_INPUT.to_string()],
            }),
            "undetermined: {undetermined:#}"
        );
        let picked = picked_choice(&[var_store_efi(1, "Present", NV_BS, 1)], 1);
        assert!(
            matches!(picked, Ok(Choice::Chosen(..))),
            "picked: {picked:?}"
        );
    }
}

// display returns a String which is our tree like representation of a FormSet
// TODO: show the default of an unreadable OneOf, Numeric or CheckBox, as list_questions does.
// TODO: show the state that the conditions give each question and option, as list-questions
// does.
pub fn display(
    node: Rc<RefCell<IFROperation>>,
    level: usize,
    string_packages: &[BTreeMap<i32, String>],
    reader: &mut EfivarReader,
) -> Result<String> {
    let mut result = String::new();
    let values = VarStoreValues::new(&node, None);
    let mut inputs = ExpressionInputs {
        reader,
        values: &values,
    };
    walk_scopes(std::slice::from_ref(&node), level, |node, &level| {
        display_op(node, level, string_packages, &mut inputs, &mut result)
    });
    Ok(result)
}

/// Appends the line of `node` that display shows `level` scopes down to `result`, and enters its
/// scope unless edk2 skips it.
fn display_op(
    node: &Rc<RefCell<IFROperation>>,
    level: usize,
    string_packages: &[BTreeMap<i32, String>],
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    result: &mut String,
) -> Walk<usize> {
    let extra_spaces = "    ".repeat(level);

    let current_node = node.borrow();
    if let IFROpCode::Unknown(code) = current_node.op_code {
        if skips_scope(&current_node) {
            result.push_str(&format!(
                "{extra_spaces}OpCode: Unknown({code:#04x}) - skipped, as edk2 does\n"
            ));
            return Walk::Skip;
        }
    }

    match &current_node.parsed_data {
        ParsedOperation::Placeholder => {
            // every op that handle_form_set parses has a parent; the root has none
            if current_node.parent.is_none() {
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
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

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
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

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
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

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

    Walk::Enter(level + 1)
}

/// Returns the answer that show-ifr shows: the question's value, or why it cannot be read.
fn display_answer(
    question: &Rc<RefCell<IFROperation>>,
    varstore: &Result<Box<dyn VariableStore>>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> String {
    match retrieve_question_value(question, varstore, inputs) {
        Err(reason) => reason.to_answer(),
        Ok((_, value)) => value.to_string(),
    }
}

fn find_corresponding_string(string_id: u16, string_packages: &[BTreeMap<i32, String>]) -> &str {
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
        return Err(match StoragelessQuestion::of(&node) {
            Some(question) => NoVarStore(question).into(),
            None => anyhow!(
                "{} has VarStoreId 0 and no value that uefisettings decodes",
                node.borrow().op_code.spec_name()
            ),
        });
    }

    let mut node = node;
    loop {
        let parent = {
            let current_node = node.borrow();
            if current_node.op_code == IFROpCode::FormSet {
                return form_set_varstore(&current_node, var_store_id);
            }
            match current_node.parent.as_ref() {
                Some(parent_ref) => match parent_ref.upgrade() {
                    Some(parent_ref_rc) => parent_ref_rc,
                    None => return Err(anyhow!("could not upgrade parent_ref Weak<> to get Rc<>")),
                },
                None => return Err(anyhow!("varstore not found because we reached root")),
            }
        };
        node = parent;
    }
}

/// Returns the varstore of `var_store_id` among the children of `form_set`.
fn form_set_varstore(form_set: &IFROperation, var_store_id: u16) -> Result<Box<dyn VariableStore>> {
    match declared_var_store(form_set, var_store_id) {
        Some(DeclaredStore::Variable(store)) => Ok(store),
        Some(DeclaredStore::NameValue) => Err(anyhow!(
            "HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL"
        )),
        None => Err(anyhow!(
            "no supported varstore with matching id {:#06x} found",
            var_store_id
        )),
    }
}

/// A VarStore that a FormSet declares.
enum DeclaredStore {
    /// A VARSTORE or VARSTORE_EFI, which an EFI variable of its Name and Guid holds; UEFI 2.11
    /// §33.2.5.6 makes the EFI variable a specialized form of Buffer Storage
    Variable(Box<dyn VariableStore>),
    /// A VARSTORE_NAME_VALUE, whose values only the driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches
    NameValue,
}

/// Returns the VarStore of `var_store_id` that `form_set` declares, if any: the first among its
/// children.
fn declared_var_store(form_set: &IFROperation, var_store_id: u16) -> Option<DeclaredStore> {
    form_set
        .children
        .iter()
        .find_map(|child| match &child.borrow().parsed_data {
            ParsedOperation::VarStore(store) if store.var_store_id == var_store_id => {
                Some(DeclaredStore::Variable(Box::new(store.clone())))
            }
            ParsedOperation::VarStoreEfi(store) if store.var_store_id == var_store_id => {
                Some(DeclaredStore::Variable(Box::new(store.clone())))
            }
            ParsedOperation::VarStoreNameValue(store) if store.var_store_id == var_store_id => {
                Some(DeclaredStore::NameValue)
            }
            _ => None,
        })
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use super::ifr_fixtures::*;
    use super::set::VarStoreWrite;
    use super::storage::stored_value;
    use super::*;
    use crate::hii::efivarfs_format::open_efivar;
    use crate::hii::efivarfs_format::read_efivarfs_bytes;
    use crate::hii::efivarfs_format::EfivarFileName;
    use crate::hii::variables::FirmwareVariables;
    use crate::hii::variables::EFIVARFS_HEADER_SIZE;

    /// Each bit of the question Flags names its flag, and a reserved bit none.
    #[test]
    fn each_question_flag_bit_names_its_flag() {
        let cases: [(u8, &[&str]); 9] = [
            (0x01, &["READ_ONLY"]),
            (0x02, &[]),
            (0x04, &["CALLBACK"]),
            (0x08, &[]),
            (0x10, &["RESET_REQUIRED"]),
            (0x20, &["REST_STYLE"]),
            (0x40, &["RECONNECT_REQUIRED"]),
            (0x80, &["OPTIONS_ONLY"]),
            (0x00, &[]),
        ];
        for (question_flags, want) in cases {
            let header = QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 0,
                var_store_id: 0,
                var_store_info: 0,
                question_flags,
            };
            let names: Vec<&str> = header.flags().iter_names().map(|(name, _)| name).collect();
            assert_eq!(names, want, "Flags {question_flags:#04x}");
        }
    }

    /// find_question_in finds a question by the name that list_questions prints, whose leading
    /// and trailing whitespace the prompt string keeps, and by that name with other surrounding
    /// whitespace or ASCII case.
    #[test]
    fn questions_are_found_by_their_listed_name() {
        let root = parse_form_set(&[form(1, &[checkbox_op(1, 0)])]);
        let values = VarStoreValues::new(&root, None);
        let prompted = |prompt: &str| vec![BTreeMap::from([(3, prompt.to_string())])];
        let find = |prompt: &str, phrase: &str| {
            find_question_in(
                &root,
                &BTreeSet::from([phrase]),
                &mut FormSetWalk::new(
                    &prompted(prompt),
                    &mut Efivars::new().reader(),
                    &values,
                    IncludedStates::empty(),
                ),
            )
            .map(|_| ())
        };
        let listed = list_questions(
            Rc::clone(&root),
            &prompted("  Prompt "),
            IncludedStates::empty(),
            None,
            &mut Efivars::new().reader(),
        );
        let name = &listed[0].0.question;
        assert_eq!(name, "  Prompt ", "listed name");

        let cases = [
            ("  Prompt ", name.as_str()),
            ("  Prompt ", "Prompt"),
            ("  Prompt ", " PROMPT"),
            (" ", ""),
            (" ", " "),
        ];
        for (prompt, phrase) in cases {
            assert_eq!(
                find(prompt, phrase),
                Selection::Picked((), StateEvaluation::selectable()),
                "prompt {prompt:?}, phrase {phrase:?}"
            );
        }
        assert_eq!(
            find("  Prompt ", "Prompt 2"),
            Selection::NotFound,
            "another name"
        );
    }

    /// select_option takes an option by the text that get shows, which is the option's string
    /// trimmed, by that string as stored, and by either with other surrounding whitespace or
    /// ASCII case. When some option's string is the text as stored, ignoring ASCII case, it
    /// takes only such an option.
    #[test]
    fn options_are_selected_by_the_text_that_get_shows() {
        let options = [
            flagged_option(5, 0x00, 0),
            flagged_option(PADDED_ENABLED, 0x00, 1),
        ];
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &options);
        let shown = question_descriptor(&question, var_store_of(&[1]));
        assert_eq!(shown.value, "Enabled", "the text get shows");
        assert_eq!(
            shown.listed_options(IncludedStates::empty()),
            ["Disabled", "Enabled "],
            "listed options"
        );
        let select = |question: &QuestionDescriptor, text: &str| {
            question
                .select_option(&BTreeSet::from([text.to_string()]), IncludedStates::empty())
                .unwrap_or_else(|error| panic!("select {text:?}: {error}"))
                .map(|option| option.value.clone())
        };

        for text in [shown.value.as_str(), "Enabled ", " enabled"] {
            assert_eq!(
                select(&shown, text).as_deref(),
                Some("Enabled "),
                "{text:?}"
            );
        }
        assert_eq!(select(&shown, "Enable"), None, "another text");

        let enabled = flagged_option(6, 0x00, 2);
        let padded = flagged_option(PADDED_ENABLED, 0x00, 1);
        let orders = [
            ("padded first", [padded.clone(), enabled.clone()]),
            ("padded last", [enabled, padded]),
        ];
        for (order, options) in orders {
            let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &options);
            let twins = question_descriptor(&question, var_store_of(&[1]));
            for (text, want) in [
                ("Enabled", "Enabled"),
                ("Enabled ", "Enabled "),
                ("enabled", "Enabled"),
            ] {
                assert_eq!(
                    select(&twins, text).as_deref(),
                    Some(want),
                    "{order}: {text:?}"
                );
            }
        }
    }

    /// set writes each integer width at the end of its VarStore, through FirmwareVariables, which
    /// keep the attributes word and the other bytes.
    #[test]
    fn writes_each_integer_width_at_end_of_varstore() {
        let store = efi_variable("Test", 42);
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
            let variables = MemoryVariables::default();
            variables.insert(store.variable_key(), NV_BS_RT, &[0xa5; 42]);
            let mut expected = variables
                .bytes(&store.variable_key())
                .expect("the bytes of Test");
            let offset = 42 - encoded.len();
            expected[EFIVARFS_HEADER_SIZE + offset..].copy_from_slice(&encoded);
            let write = VarStoreWrite::new(
                &store,
                u16::try_from(offset).expect("offset fits u16"),
                data,
                variables.interface(),
            )
            .unwrap_or_else(|error| panic!("write {data:?} at offset {offset}: {error}"));
            assert_eq!(
                write.patches,
                [(
                    u16::try_from(offset).expect("offset fits u16"),
                    encoded.clone()
                )],
                "{data:?}"
            );

            write
                .write(&variables)
                .unwrap_or_else(|error| panic!("write {data:?} at offset {offset}: {error:#}"));

            assert_eq!(
                variables.bytes(&store.variable_key()),
                Some(expected),
                "{data:?}"
            );
        }
    }

    /// set refuses a VarStore whose variable is shorter than its Size, also where the value
    /// fits, and writes nothing.
    #[test]
    fn write_of_a_variable_shorter_than_its_var_store_is_refused() {
        let store = efi_variable("Short", 4);
        let variables = MemoryVariables::default();
        variables.insert(store.variable_key(), NV_BS_RT, &[0; 2]);
        let write = VarStoreWrite::new(&store, 0, TypeValue::NumSize8(1), variables.interface())
            .expect("write 1");

        let error = write
            .write(&variables)
            .expect_err("write a variable shorter than its VarStore");

        assert_eq!(
            error.to_string(),
            "efivarfs payload is shorter than the declared varstore: 2 < 4 bytes",
            "refusal"
        );
        assert_eq!(variables.writes_to(&store.variable_key()), [], "writes");
    }

    /// set of a VarStore whose variable is missing explains why it cannot write it.
    #[test]
    fn write_of_a_missing_variable_is_explained_as_not_exported() {
        let store = efi_variable("Setup", 1);
        let write = VarStoreWrite::new(
            &store,
            0,
            TypeValue::NumSize8(1),
            VariableInterface::Efivarfs,
        )
        .expect("write 1");

        let error = write
            .write(&MemoryVariables::default())
            .expect_err("write a missing variable");

        assert!(
            error.downcast_ref::<VariableNotExported>().is_some(),
            "{error:#} is not VariableNotExported"
        );
    }

    #[test]
    fn rejects_writes_past_declared_size() {
        for (size, offset, data, width) in [
            (42, 42, TypeValue::NumSize8(1), 1),
            (42, 41, TypeValue::NumSize16(1), 2),
            (42, 39, TypeValue::NumSize32(1), 4),
            (42, 35, TypeValue::NumSize64(1), 8),
            (0, 0, TypeValue::NumSize8(1), 1),
            (42, u16::MAX, TypeValue::NumSize64(1), 8),
        ] {
            let store = efi_variable("Test", size);
            assert_eq!(
                VarStoreWrite::new(&store, offset, data, VariableInterface::Efivarfs)
                    .map(drop)
                    .map_err(|error| error.to_string()),
                Err(format!(
                    "write at offset {offset} with width {width} exceeds varstore size {size}"
                )),
                "{data:?} at offset {offset} of {size} bytes"
            );
        }
    }

    #[test]
    fn rejects_unsupported_value_instead_of_silent_noop() {
        assert_eq!(
            VarStoreWrite::new(
                &efi_variable("Test", 42),
                0,
                TypeValue::Boolean(true),
                VariableInterface::Efivarfs
            )
            .map(drop)
            .map_err(|error| error.to_string()),
            Err("unsupported value type for efivarfs write".to_string()),
            "BOOLEAN"
        );
    }

    /// set's error for a missing variable follows the interface of its variables: efivarfs as on
    /// Linux, the firmware environment calls as on Windows, GetVariable() as in the UEFI Shell,
    /// whose variables would find any variable the firmware has created.
    #[test]
    fn variable_not_exported_follows_its_interface() {
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000: the firmware has not \
                 created it or does not expose it to the OS, so its questions cannot be set from \
                 Linux; change them in the firmware setup, or ask the board vendor for firmware \
                 that exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000: the firmware has not \
                 created it or does not expose it to the OS, so its questions cannot be set from \
                 Windows; change them in the firmware setup, or ask the board vendor for firmware \
                 that exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000: the firmware has \
                 not created it, and set never creates variables",
            ),
        ];
        for (reach, interface, want) in cases {
            let variables = MemoryVariables::new(reach, interface);
            let store = efi_variable("Setup", 1);
            let write =
                VarStoreWrite::new(&store, 0, TypeValue::NumSize8(1), interface).expect("write 1");

            let error = write
                .write(&variables)
                .expect_err("write a missing variable");

            assert_eq!(error.to_string(), want, "{interface:?}");
        }
    }

    /// A write of an unsupported value names the write of its variables: efivarfs, or
    /// SetVariable() in the UEFI Shell.
    #[test]
    fn unsupported_value_names_the_write_of_its_interface() {
        for (interface, want) in [
            (
                VariableInterface::Efivarfs,
                "unsupported value type for efivarfs write",
            ),
            (
                VariableInterface::VariableServices,
                "unsupported value type for SetVariable() write",
            ),
        ] {
            assert_eq!(
                VarStoreWrite::new(
                    &efi_variable("Test", 42),
                    0,
                    TypeValue::Boolean(true),
                    interface
                )
                .map(drop)
                .map_err(|error| error.to_string()),
                Err(want.to_string()),
                "{interface:?}"
            );
        }
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
        let key = VariableKey {
            name: "Setup".to_string(),
            guid: Guid {
                data1: 0xec87d643,
                data2: 0xeba4,
                data3: 0x4bb5,
                data4: [0xa1, 0xe5, 0x3f, 0x3e, 0x36, 0xb2, 0x0d, 0xa9],
            },
        };

        let error = VariableNotExported::explain(
            VariableNotFound(key).into(),
            &efi_variable("Setup", 1),
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

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

    /// The missing variable of a form that declares it boot-service-only is explained by that
    /// declaration, not as not exported.
    #[test]
    fn missing_efivar_of_a_boot_service_only_form_is_explained_by_its_declaration() {
        let store = DeclaredVarStore {
            runtime_accessible: false,
            ..efi_variable("Setup", 1)
        };

        let error = VariableNotExported::explain(
            VariableNotFound(store.variable_key()).into(),
            &store,
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

        assert!(
            error.downcast_ref::<VariableNotExported>().is_none(),
            "{error:#} is VariableNotExported"
        );
        assert_eq!(
            format!("{error:#}"),
            "EFI variable Setup-00000000-0000-0000-0000-000000000000 is not present at OS \
             runtime: efivarfs does not list it, and its form declares it boot-service-only \
             (no EFI_VARIABLE_RUNTIME_ACCESS)",
            "message of the missing variable"
        );
    }

    #[test]
    fn other_efivar_open_failure_is_not_explained_as_not_exported() {
        // ENOTDIR: the directory is a regular file
        let not_a_dir = tempfile::NamedTempFile::new().expect("create a file");
        let name = EfivarFileName::new("Setup", NIL_GUID);

        let open_error = open_efivar(not_a_dir.path(), &name).expect_err("open below a file");
        let expected = format!("{open_error:#}");

        let error = VariableNotExported::explain(
            open_error,
            &efi_variable("Setup", 1),
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

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

            let err = format!("{:#}", handle_form_set(&mut cursor).unwrap_err());

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

        let err = format!("{:#}", handle_form_set(&mut cursor).unwrap_err());

        let want = "invalid IFR operation length 0 at 0x";
        assert!(err.contains(want), "{}", err);
    }

    /// An End that returns to an IFR op with opcode 0xFF, which is also the root's
    /// DUMMY_OPCODE, does not end the FormSet: the ops after that op's scope are parsed.
    #[test]
    fn end_back_in_an_opcode_0xff_scope_does_not_end_the_form_set() {
        let data = form_set(&[form(
            1,
            &[
                operation(DUMMY_OPCODE, true, &[]),
                form(2, &[]), // its End returns to the opcode 0xFF op
                END.to_vec(), // End of the opcode 0xFF op
                checkbox_op(1, 0),
            ],
        )]);
        let mut cursor = Cursor::new(&data);

        let root = handle_form_set(&mut cursor).expect("parse the FormSet");

        let root = root.borrow();
        assert_eq!(root.children.len(), 1, "FormSets");
        let form_set = root.children[0].borrow();
        assert_eq!(form_set.children.len(), 1, "Forms");
        let form = form_set.children[0].borrow();
        let op_codes: Vec<IFROpCode> = form.children.iter().map(|op| op.borrow().op_code).collect();
        assert_eq!(
            op_codes,
            [IFROpCode::Unknown(DUMMY_OPCODE), IFROpCode::CheckBox],
            "ops of the Form"
        );
        assert_eq!(
            cursor.position(),
            u64::try_from(data.len()).expect("length"),
            "bytes read"
        );
    }

    /// display shows the root as ROOT, and not an IFR op with opcode 0xFF, the root's
    /// DUMMY_OPCODE.
    #[test]
    fn display_shows_only_the_root_as_root() {
        let root = parse_form_set(&[form(1, &[operation(DUMMY_OPCODE, false, &[])])]);

        let shown = display(root, 0, &strings(), &mut disabled_reader()).expect("display");

        let roots: Vec<&str> = shown
            .lines()
            .filter(|line| line.trim() == "OpCode: ROOT")
            .collect();
        assert_eq!(roots, ["OpCode: ROOT"], "ROOT lines of {shown:?}");
    }

    /// display shows an op whose scope edk2 skips on one line, and nothing in that scope.
    #[test]
    fn display_skips_an_unknown_opcode_scope() {
        let skipped_scope = [operation(0x70, true, &[]), checkbox_op(2, 1), END.to_vec()].concat();
        let root = parse_form_set(&[form(1, &[checkbox_op(1, 0), skipped_scope])]);

        let shown = display(root, 0, &strings(), &mut disabled_reader()).expect("display");

        let check_boxes = shown
            .lines()
            .filter(|line| line.trim().starts_with("OpCode: CheckBox "))
            .count();
        assert_eq!(check_boxes, 1, "CheckBox lines of {shown:?}");
        let unknown: Vec<&str> = shown
            .lines()
            .filter(|line| line.trim().starts_with("OpCode: Unknown"))
            .collect();
        assert_eq!(
            unknown,
            ["            OpCode: Unknown(0x70) - skipped, as edk2 does"],
            "Unknown lines of {shown:?}"
        );
    }

    /// The ops in the scope of an opcode above EFI_IFR_MATCH2_OP, nested ones too, are not
    /// decoded, so a malformed one does not fail the FormSet; in a known opcode's scope
    /// it still does.
    #[test]
    fn ops_in_an_unknown_opcode_scope_are_not_decoded() {
        let in_scope = |op_code: u8| {
            let short_checkbox = operation(CHECKBOX, false, &[0x00]); // 1 of its data bytes
            let scope = [
                operation(op_code, true, &[0x00; 16]),
                operation(0x02, true, &[0x05, 0x00, 0x06, 0x00, 0x00]), // Subtitle
                short_checkbox.clone(),
                END.to_vec(), // End of Subtitle
                short_checkbox,
                END.to_vec(), // End of op_code
            ];
            form_set(&[form(
                1,
                &[
                    scope.concat(),
                    operation(op_code, false, &[]),
                    checkbox_op(1, 0),
                ],
            )])
        };

        for op_code in [0x65, 0x70, 0xFF] {
            let data = in_scope(op_code);
            let root = handle_form_set(&mut Cursor::new(&data)).unwrap_or_else(|error| {
                panic!("parse the scope of opcode {op_code:#x}: {error:#}")
            });

            let root = root.borrow();
            let form = Rc::clone(&root.children[0].borrow().children[0]);
            let scope = Rc::clone(&form.borrow().children[0]);
            let subtitle = Rc::clone(&scope.borrow().children[0]);
            let undecoded = [
                ("in the Subtitle", Rc::clone(&subtitle.borrow().children[0])),
                ("after the Subtitle", Rc::clone(&scope.borrow().children[1])),
            ];
            for (place, checkbox) in undecoded {
                assert!(
                    matches!(checkbox.borrow().parsed_data, ParsedOperation::Placeholder),
                    "opcode {op_code:#x}: the CheckBox {place} is not decoded"
                );
            }
            let after = Rc::clone(&form.borrow().children[2]);
            assert!(
                matches!(after.borrow().parsed_data, ParsedOperation::CheckBox(_)),
                "opcode {op_code:#x}: the CheckBox after the scope is decoded"
            );
        }

        let data = in_scope(GUID);
        let error = handle_form_set(&mut Cursor::new(&data)).expect_err("GUID scope");
        assert!(
            format!("{error:#}").contains("failed to parse CheckBox's data"),
            "GUID scope: {error:#}"
        );
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

        let root = handle_form_set(&mut cursor).unwrap();

        let root = root.borrow();
        assert_eq!(root.children.len(), 1);
        let form_set = root.children[0].borrow();
        assert_eq!(form_set.op_code, IFROpCode::FormSet);
        assert!(form_set.children.is_empty());
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod nesting_tests {
    use super::conditions::evaluate_condition;
    use super::conditions::Truth;
    use super::defaults::question_scope;
    use super::ifr_fixtures::*;
    use super::*;

    /// IFR scopes nested in the trees that the walks below run on: a frame per scope would take
    /// far more than SMALL_STACK
    const DEEP: usize = 20_000;
    /// IFR scopes nested in the tree that display runs on: its text grows with the square of the
    /// depth, to 8 MB here, but a frame per scope would still take far more than SMALL_STACK
    const DISPLAY_DEEP: usize = 2_000;

    /// The strings of deep_form_set.
    fn deep_strings() -> Vec<BTreeMap<i32, String>> {
        vec![BTreeMap::from([
            (3, "Deep".to_string()),
            (4, "Help".to_string()),
            (5, "Hidden".to_string()),
        ])]
    }

    /// `op` opening a scope that holds `body`, with its End.
    fn with_scope(mut op: Vec<u8>, body: &[Vec<u8>]) -> Vec<u8> {
        op[1] |= 0x80;
        [op, body.concat(), END.to_vec()].concat()
    }

    /// The CHECKBOX "Deep" on VarStore 1.
    fn deep_checkbox() -> Vec<u8> {
        checkbox_on(1, 3, 1)
    }

    /// The CHECKBOX "Hidden" without a VarStore.
    fn hidden_checkbox() -> Vec<u8> {
        checkbox_on(2, 5, 0)
    }

    /// A FormSet of the VarStore 1 whose Form nests `depth` Subtitle scopes around: deep_checkbox
    /// holding `depth` nested LOCKED scopes; hidden_checkbox in a SUPPRESS_IF of TRUE holding
    /// `nots` nested NOTs; and, if `password`, a PASSWORD on VarStore 1.
    fn deep_form_set(depth: usize, nots: usize, password: bool) -> Vec<u8> {
        let not = operation(NOT, true, &[]);
        let condition = with_scope(operation(TRUE, false, &[]), &[nested(&not, nots, &[])]);
        let mut body = vec![
            with_scope(deep_checkbox(), &[nested(&locked_scope(), depth, &[])]),
            conditional(SUPPRESS_IF, condition, &[hidden_checkbox()]),
        ];
        if password {
            body.push(password_on(3, 3, 1, 0));
        }
        form_set(&[
            var_store(1, [0x22; 16], "Deep", 1),
            form(1, &[nested(&subtitle_scope(3), depth, &body)]),
        ])
    }

    /// The root of deep_form_set, parsed past MAX_SCOPE_NESTING.
    fn parse_deep(depth: usize, nots: usize, password: bool) -> Rc<RefCell<IFROperation>> {
        let ifr = deep_form_set(depth, nots, password);
        handle_form_set_within(&mut Cursor::new(&ifr), usize::MAX).expect("parse the FormSet")
    }

    /// The op of the tree of `root` whose data is that of the op `op`.
    fn op_like(root: &Rc<RefCell<IFROperation>>, op: &[u8]) -> Rc<RefCell<IFROperation>> {
        let data = op.get(2..).expect("an op past its header");
        find_op(root, data).expect("find the op")
    }

    /// The limit counts the scopes open at once, not every scope of a FormSet: MAX_SCOPE_NESTING
    /// + 1 sibling Subtitle scopes, each closed before the next, parse.
    #[test]
    fn scopes_that_close_do_not_count_toward_the_limit() {
        let siblings: Vec<Vec<u8>> = (0..=MAX_SCOPE_NESTING)
            .map(|_| nested(&subtitle_scope(3), 1, &[]))
            .collect();
        let root = handle_form_set(&mut Cursor::new(&form_set(&siblings)))
            .unwrap_or_else(|error| panic!("{} sibling scopes: {error:#}", siblings.len()));
        let form_set = Rc::clone(&root.borrow().children[0]);
        assert_eq!(
            form_set.borrow().children.len(),
            siblings.len(),
            "the sibling Subtitles"
        );
    }

    /// A FormSet nests up to MAX_SCOPE_NESTING scopes at once, its own and unknown ones counted;
    /// handle_form_set fails with ScopesTooDeep at the op that opens one more.
    #[test]
    fn scopes_nest_up_to_the_limit() {
        let unknown = operation(0x70, true, &[]);
        let form_set_op = form_set(&[]).len() - END.len();
        let subtitle_op = subtitle_scope(3).len();
        for in_unknown_scope in [false, true] {
            let outer = 1 + usize::from(in_unknown_scope);
            let ifr = |subtitles: usize| {
                let nested = nested(&subtitle_scope(3), subtitles, &[checkbox_op(1, 0)]);
                let body = match in_unknown_scope {
                    true => [unknown.clone(), nested, END.to_vec()].concat(),
                    false => nested,
                };
                form_set(&[body])
            };
            let case = format!("in an unknown scope: {in_unknown_scope}");

            let root = handle_form_set(&mut Cursor::new(&ifr(MAX_SCOPE_NESTING - outer)))
                .unwrap_or_else(|error| panic!("at the limit, {case}: {error:#}"));
            assert_eq!(
                op_like(&root, &checkbox_op(1, 0)).borrow().op_code,
                IFROpCode::CheckBox,
                "the op in the innermost scope at the limit, {case}"
            );

            let error = handle_form_set(&mut Cursor::new(&ifr(MAX_SCOPE_NESTING - outer + 1)))
                .expect_err("scopes past the limit");
            let past_limit = form_set_op
                + usize::from(in_unknown_scope) * unknown.len()
                + (MAX_SCOPE_NESTING - outer) * subtitle_op;
            assert_eq!(
                error.downcast_ref::<ScopesTooDeep>(),
                Some(&ScopesTooDeep {
                    offset: u64::try_from(past_limit).expect("a u64 offset"),
                    limit: MAX_SCOPE_NESTING,
                }),
                "past the limit, {case}: {error:#}"
            );
        }
    }

    /// The parser, every walk of the tree, Debug and Drop take the same stack however deep IFR
    /// scopes nest: on SMALL_STACK, through DEEP nested scopes (display DISPLAY_DEEP), each finds
    /// what lies at the bottom and nothing that does not.
    #[test]
    fn walks_take_a_stack_that_nesting_does_not_grow() {
        on_small_stack("handle_form_set", || {
            let root = parse_deep(DEEP, DEEP, true);
            let deep = op_like(&root, &deep_checkbox());
            assert_eq!(
                deep.borrow().children.len(),
                1,
                "the Deep CheckBox's LOCKED"
            );
        });

        on_small_stack("PasswordQuestions::of", || {
            for password in [true, false] {
                let declared = PasswordQuestions::of([&parse_deep(DEEP, DEEP, password)])
                    .check_set(VariableReach::BootServices, SetupPasswordPolicy::Refuse)
                    .is_err();
                assert_eq!(declared, password, "declares the PASSWORD at the bottom");
            }
        });

        on_small_stack("VarStoreValues::new", || {
            let root = parse_deep(DEEP, DEEP, false);
            let deep = op_like(&root, &deep_checkbox());
            let values = VarStoreValues::new(&root, None);
            let mut reader = disabled_reader();
            for (id, indexed) in [(1, true), (9, false)] {
                assert_eq!(
                    values.value(&deep.borrow(), id, &mut reader).is_some(),
                    indexed,
                    "question {id} indexed"
                );
            }
        });

        on_small_stack("list_questions", || {
            for (include, want) in [
                (IncludedStates::all(), &["Deep", "Hidden"][..]),
                (IncludedStates::empty(), &["Deep"][..]),
            ] {
                let listed = list_questions(
                    parse_deep(DEEP, DEEP, false),
                    &deep_strings(),
                    include,
                    None,
                    &mut disabled_reader(),
                );
                let names: Vec<String> = listed
                    .into_iter()
                    .map(|(question, _)| question.question)
                    .collect();
                assert_eq!(names, want, "questions listed of {include:?}");
            }
        });

        on_small_stack("find_question", || {
            for (name, want) in [("Deep", true), ("Hidden", false)] {
                let selection = find_question(
                    parse_deep(DEEP, DEEP, false),
                    &deep_strings(),
                    &BTreeSet::from([name]),
                    IncludedStates::empty(),
                    None,
                    &mut disabled_reader(),
                );
                assert_eq!(
                    matches!(selection, Selection::Picked(..)),
                    want,
                    "{name} picked: {selection:?}"
                );
            }
        });

        on_small_stack("question_scope", || {
            let root = parse_deep(DEEP, DEEP, false);
            let deep = op_like(&root, &deep_checkbox());
            let scope = question_scope(&deep.borrow());
            assert_eq!(
                scope.len(),
                DEEP,
                "the LOCKED ops in the Deep CheckBox's scope"
            );
        });

        on_small_stack("find_corresponding_varstore", || {
            let root = parse_deep(DEEP, DEEP, false);
            let deep = op_like(&root, &deep_checkbox());
            assert!(
                find_corresponding_varstore(Rc::clone(&deep), 1).is_ok(),
                "VarStore 1 found from the bottom"
            );
            let missing = find_corresponding_varstore(deep, 2)
                .err()
                .map(|error| error.to_string());
            assert_eq!(
                missing.as_deref(),
                Some("no supported varstore with matching id 0x0002 found"),
                "VarStore 2"
            );
        });

        on_small_stack("evaluate_condition", || {
            for (nots, want) in [(DEEP, true), (DEEP + 1, false)] {
                let root = parse_deep(1, nots, false);
                let hidden = op_like(&root, &hidden_checkbox());
                let suppress_if = hidden
                    .borrow()
                    .parent
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .expect("the SUPPRESS_IF");
                let values = VarStoreValues::new(&root, None);
                let mut reader = disabled_reader();
                let mut inputs = ExpressionInputs {
                    reader: &mut reader,
                    values: &values,
                };
                assert_eq!(
                    evaluate_condition(&suppress_if.borrow(), &mut inputs),
                    Truth::Known(want),
                    "TRUE, then {nots} NOTs"
                );
            }
        });

        on_small_stack("Debug", || {
            let root = parse_deep(DEEP, DEEP, true);
            let printed = format!("{:?}", root.borrow());
            // the root, the FormSet, its VarStore and Form, the Subtitles, the Deep CheckBox and
            // its LOCKEDs, the SUPPRESS_IF, its TRUE and NOTs, Hidden and the PASSWORD
            assert_eq!(
                printed.matches("IFROperation {").count(),
                3 * DEEP + 9,
                "ops printed"
            );
            assert!(
                printed.starts_with(
                    "IFROperation { op_code: Unknown(255), open_scope: false, length: 0, children: \
                     [RefCell { value: IFROperation { op_code: FormSet, open_scope: true"
                ),
                "printed from the root: {}",
                printed.get(..200).unwrap_or(&printed)
            );
        });

        on_small_stack("Drop", || {
            let root = parse_deep(DEEP, DEEP, true);
            let deep = op_like(&root, &deep_checkbox());
            drop(root);
            let deep = deep.borrow();
            assert!(
                deep.parent.as_ref().and_then(Weak::upgrade).is_none(),
                "the Deep CheckBox's ancestors dropped"
            );
            assert_eq!(deep.children.len(), 1, "the Deep CheckBox's LOCKED kept");
        });

        on_small_stack("display", || {
            let root = parse_deep(DISPLAY_DEEP, 1, false);
            let shown = display(root, 0, &deep_strings(), &mut disabled_reader()).expect("display");
            // the root, the FormSet, the Form, then the Subtitles
            let want = format!(
                "{}OpCode: CheckBox - Q: - Deep - Help: - Help",
                "    ".repeat(DISPLAY_DEEP + 3)
            );
            assert!(
                shown.lines().any(|line| line == want),
                "the Deep CheckBox shown"
            );
            let subtitles = shown
                .lines()
                .filter(|line| line.trim_start() == "OpCode: Subtitle - S: Deep")
                .count();
            assert_eq!(subtitles, DISPLAY_DEEP, "the Subtitles shown");
        });
    }

    /// Debug prints what Debug derived for op_code, open_scope, length and children prints, as
    /// `{:?}` and as `{:#?}`, also for an op whose RefCell is borrowed mutably.
    #[test]
    fn debug_prints_as_derived_debug() {
        mod derived {
            use super::*;

            /// IFROperation's printed fields, with Debug derived
            #[derive(Debug)]
            #[expect(dead_code, reason = "Debug, which the test compares, reads them")]
            pub(super) struct IFROperation {
                op_code: IFROpCode,
                open_scope: bool,
                length: u8,
                pub(super) children: Vec<Rc<RefCell<IFROperation>>>,
            }

            /// `op`'s tree, recursively: its ops are few.
            pub(super) fn of(op: &super::IFROperation) -> IFROperation {
                IFROperation {
                    op_code: op.op_code,
                    open_scope: op.open_scope,
                    length: op.length,
                    children: op
                        .children
                        .iter()
                        .map(|child| Rc::new(RefCell::new(of(&child.borrow()))))
                        .collect(),
                }
            }
        }

        let root = parse_form_set(&[
            var_store(1, [0x22; 16], "Deep", 1),
            form(
                1,
                &[
                    nested(&subtitle_scope(3), 2, &[deep_checkbox()]),
                    [operation(0x70, true, &[]), END.to_vec()].concat(),
                ],
            ),
        ]);
        let want = derived::of(&root.borrow());
        assert_eq!(
            format!("{:?}", root.borrow()),
            format!("{want:?}"),
            "{{:?}}"
        );
        assert_eq!(
            format!("{:#?}", root.borrow()),
            format!("{want:#?}"),
            "{{:#?}}"
        );

        let form_set = Rc::clone(&root.borrow().children[0]);
        let form = Rc::clone(&form_set.borrow().children[1]);
        let want_form = Rc::clone(&want.children[0].borrow().children[1]);
        let _mutable = form.borrow_mut();
        let _want_mutable = want_form.borrow_mut();
        assert_eq!(
            format!("{:?}", root.borrow()),
            format!("{want:?}"),
            "{{:?}}, borrowed"
        );
        assert_eq!(
            format!("{:#?}", root.borrow()),
            format!("{want:#?}"),
            "{{:#?}}, borrowed"
        );
    }
}

#[cfg(test)]
mod expression_operand_tests {
    use super::ifr_fixtures::*;
    use super::*;

    /// The ops of the FORM of a FormSet that holds `body` in it.
    fn parsed_form(body: &[Vec<u8>]) -> Vec<Rc<RefCell<IFROperation>>> {
        let root = parse_form_set(&[form(1, body)]);
        let root = root.borrow();
        let form_set = root.children[0].borrow();
        let form = form_set.children[0].borrow();
        form.children.clone()
    }

    /// The first op of a FormSet that holds `ops` outside forms.
    fn parsed_first(ops: &[Vec<u8>]) -> Rc<RefCell<IFROperation>> {
        let root = parse_form_set(ops);
        let root = root.borrow();
        let form_set = root.children[0].borrow();
        Rc::clone(&form_set.children[0])
    }

    /// GET and SET name a VarStore, a VarOffset or VarName, and the type of the value
    /// (UEFI 2.11 §33.3.8.3.27, §33.3.8.3.66).
    #[test]
    fn get_and_set_decode_their_var_store_operand() {
        let ops = parsed_form(&[
            operation(0x2B, false, &[0x34, 0x12, 0xC1, 0x00, EFI_IFR_TYPE_BOOLEAN]),
            operation(
                0x2C,
                false,
                &[0x01, 0x00, 0x02, 0x01, EFI_IFR_TYPE_NUM_SIZE_16],
            ),
        ]);

        let get = ops[0].borrow();
        let ParsedOperation::Get(get) = &get.parsed_data else {
            panic!("GET not decoded: {:?}", get.parsed_data);
        };
        assert_eq!(
            *get,
            VarStoreOperand {
                var_store_id: 0x1234,
                var_store_info: 0xC1,
                var_store_type: EFI_IFR_TYPE_BOOLEAN,
            },
            "GET"
        );
        let set = ops[1].borrow();
        let ParsedOperation::Set(set) = &set.parsed_data else {
            panic!("SET not decoded: {:?}", set.parsed_data);
        };
        assert_eq!(
            *set,
            VarStoreOperand {
                var_store_id: 1,
                var_store_info: 0x102,
                var_store_type: EFI_IFR_TYPE_NUM_SIZE_16,
            },
            "SET"
        );
    }

    /// A GET or SET too short for its operand is left undecoded, for the evaluation to refuse,
    /// and does not fail the FormSet, whose other questions get and set still reach.
    #[test]
    fn short_get_and_set_are_not_decoded_and_keep_the_form_set() {
        for op_code in [0x2B, 0x2C] {
            let ops = parsed_form(&[operation(op_code, false, &[0x34, 0x12, 0xC1, 0x00])]);

            assert!(
                matches!(ops[0].borrow().parsed_data, ParsedOperation::Placeholder),
                "opcode {op_code:#x}: {:?}",
                ops[0].borrow().parsed_data
            );
        }
    }

    /// A FORM_MAP decodes its methods; it is a standard map form if one of them is
    /// EFI_HII_STANDARD_FORM_GUID (UEFI 2.11 §33.3.8.3.25), the forms whose READ and WRITE
    /// expressions edk2-stable202608 SetupBrowserDxe evaluates (IfrParse.c ParseOpCodes).
    #[test]
    fn form_map_decodes_its_methods() {
        let cases = [
            (
                "standard second",
                vec![(5, OTHER_GUID), (6, STANDARD_FORM_GUID)],
                true,
            ),
            ("standard only", vec![(6, STANDARD_FORM_GUID)], true),
            ("no standard", vec![(5, OTHER_GUID)], false),
        ];
        for (name, methods, standard) in cases {
            let op = parsed_first(&[form_map(&methods, &[])]);

            let op = op.borrow();
            let ParsedOperation::FormMap(form_map) = &op.parsed_data else {
                panic!("{name}: FORM_MAP not decoded: {:?}", op.parsed_data);
            };
            assert_eq!(form_map.form_id, 4, "{name}: FormId");
            let titles: Vec<u16> = form_map
                .methods
                .iter()
                .map(|method| method.method_title)
                .collect();
            let want: Vec<u16> = methods.iter().map(|&(title, _)| title).collect();
            assert_eq!(titles, want, "{name}: MethodTitles");
            assert_eq!(form_map.has_standard_method(), standard, "{name}");
        }
    }

    /// A FORM_MAP keeps the methods that fit in its Length; one without room for its FormId is
    /// left undecoded, and neither fails the FormSet.
    #[test]
    fn short_form_map_keeps_the_methods_that_fit() {
        let truncated = [
            operation(
                FORM_MAP,
                true,
                &[
                    &4u16.to_le_bytes()[..],
                    &[0x06, 0x00],
                    &STANDARD_FORM_GUID[..8],
                ]
                .concat(),
            ),
            END.to_vec(),
        ]
        .concat();
        let op = parsed_first(&[truncated]);
        let op = op.borrow();
        let ParsedOperation::FormMap(form_map) = &op.parsed_data else {
            panic!("FORM_MAP not decoded: {:?}", op.parsed_data);
        };
        assert!(form_map.methods.is_empty(), "{:?}", form_map.methods);
        assert!(!form_map.has_standard_method(), "a cut-off method");

        let op = parsed_first(&[[operation(FORM_MAP, true, &[0x04]), END.to_vec()].concat()]);
        assert!(
            matches!(op.borrow().parsed_data, ParsedOperation::Placeholder),
            "{:?}",
            op.borrow().parsed_data
        );
    }
}
