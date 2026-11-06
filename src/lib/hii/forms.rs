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
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinResult;
use log::debug;
use thiserror::Error;

use crate::exports::SetOptions;
use crate::hii::package::is_padding;
use crate::hii::package::Guid;
use crate::hii::strings::Language;
use crate::hii::strings::ListTexts;
use crate::hii::strings::StringPackage;
use crate::hii::variables::check_runtime_writable;
use crate::hii::variables::check_unauthenticated;
use crate::hii::variables::check_volatile_write;
use crate::hii::variables::efivar_attributes;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::EnhancedAuthenticatedVariable;
use crate::hii::variables::VariableGuids;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableLayout;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VolatileWrites;
use crate::parse_error::ParseError;
use crate::parse_error::ReadParsed;
use crate::terminal_text::TextLines;
use crate::unsafe_operations::PendingOperations;
use crate::unsafe_operations::UnsafeOperation;
use crate::unsafe_operations::UnsafeOperations;
use conditions::constant_condition;
use conditions::enclosing_form_set;
use conditions::parse_question_header;
use conditions::question_state;
use conditions::retrieve_question_value;
use conditions::select;
use conditions::skips_scope;
use conditions::ExpressionInputs;
use conditions::QuestionValues;
use conditions::Truth;
use conditions::VarStoreValues;
use cross_reference::display_ref_answer;
use cross_reference::CrossReference;
use date_time::widened_date;
use date_time::widened_time;
use date_time::DateTimeInput;
use date_time::DateTimeKind;
use date_time::DateTimeQuestion;
use defaults::FormSetDefaultStores;
use defaults::OptionValueError;
use keywords::KeywordStatement;
use ordered_list::display_list_answer;
use ordered_list::ListInput;
use ordered_list::OrderedList;
use ordered_list::OrderedListQuestion;
use question_values::describe_question;
use question_values::form_set_guid;
use question_values::questions_addressed;
use question_values::questions_matching;
use question_values::questions_named;
use question_values::share_a_language;
use question_values::value_question;
pub(crate) use question_values::Keyword;
pub use question_values::KeywordError;
pub use question_values::KeywordName;
pub use question_values::KeywordNamespace;
use question_values::ListedQuestion;
pub use question_values::OptionMatch;
pub use question_values::PromptMatch;
pub use question_values::QuestionAddress;
pub use question_values::QuestionAddressError;
pub(crate) use question_values::QuestionIdentity;
pub(crate) use question_values::QuestionMatch;
pub use question_values::QuestionSelector;
use question_values::ValueQuestion;
use set::ChangeValueError;
use storage::created_attributes;
use storage::storage_width;
use storage::var_name_variables;
use storage::NameValueStore;
use storage::ReadableLocation;
use storage::ShortEfiReason;
use storage::ShortEfiRefusal;
use storage::ShortEfiVariable;
use storage::ShortVarStoreEfi;
use storage::UnresolvedVarName;
use storage::ValueLocation;
use storage::ValueSource;
use storage::VarNames;
use storage::VarStore;
use storage::VarStoreEfi;
use storage::VarStoreNameValue;
use storage::VariableNotExported;
use storage::VariableStore;
use storageless::NoVarStore;
use storageless::StoragelessQuestion;
use string_question::display_string_answer;
use string_question::StringInput;
use string_question::StringQuestion;
use time_storage::TimeStorage;
use time_storage::TimeStorageOnly;

pub use ami_access_level::AccessLevel;
pub use conditions::IncludedStates;
pub use conditions::QuestionState;
pub use conditions::SelectionError;

pub(crate) use ami_access_level::check_access_level;
pub(crate) use conditions::Choice;
pub(crate) use conditions::Exclusion;
pub(crate) use conditions::QuestionExpression;
pub(crate) use conditions::RankedBefore;
pub(crate) use conditions::ReadOnlyCause;
pub(crate) use conditions::Selection;
pub(crate) use conditions::StateEvaluation;
pub(crate) use defaults::DeclaredDefault;
pub(crate) use defaults::DefaultId;
pub(crate) use driver_held::DriverHeldQuestion;
pub(crate) use driver_held::ExpressionBesideCallback;
#[cfg(variable_data)]
pub(crate) use driver_held::IfrValueType;
pub(crate) use set::check_one_kind;
pub(crate) use set::set_questions;
pub(crate) use set::DriverStore;
pub(crate) use set::NewAnswer;
pub(crate) use setup_password::PasswordQuestions;
pub(crate) use setup_password::UnresolvedPassword;
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
pub(crate) use storage::DeclaredKind;
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
pub(crate) use storage::StoreDeclaration;
pub(crate) use storageless::StoragelessRefusal;

mod ami_access_level;
mod conditions;
mod cross_reference;
mod date_time;
mod defaults;
mod driver_held;
#[cfg(test)]
pub(crate) mod ifr_fixtures;
#[cfg_attr(
    not(any(target_os = "uefi", test)),
    expect(
        dead_code,
        reason = "only the UEFI Shell build's Keyword Handler resolves keywords for GetData() and \
                  SetData() and checks them; get, set and list-questions take resolve_offline \
                  and keyword_of on every build"
    )
)]
pub(crate) mod keywords;
mod ordered_list;
mod question_values;
mod set;
mod setup_password;
mod storage;
mod storageless;
mod string_question;
mod time_storage;
mod write_plan;

const DUMMY_OPCODE: u8 = 0xFFu8; // doesn't correspond to any known IFROpCode
/// How DeclaredBootServiceOnly names a form's declaration without EFI_VARIABLE_RUNTIME_ACCESS.
const DECLARED_BOOT_SERVICE_ONLY: &str = "boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
// UEFI 2.11 §33.3.8.3.26: "Bits 0:1 = number of members in ClassGuid"
const EFI_IFR_FORM_SET_CLASS_GUID_COUNT: u8 = 0x03;
// UEFI 2.11 §35.6.2
const EFI_HII_REST_STYLE_FORMSET_GUID: Guid = Guid {
    data1: 0x7902_17BD,
    data2: 0xBECF,
    data3: 0x485B,
    data4: [0x91, 0x70, 0x5F, 0xF7, 0x11, 0x31, 0x8B, 0x27],
};
// UEFI 2.10 §33.3.8.3.47
const EFI_IFR_NUMERIC_SIZE: u8 = 0x03;
const EFI_IFR_NUMERIC_SIZE_1: u8 = 0x00;
const EFI_IFR_NUMERIC_SIZE_2: u8 = 0x01;
const EFI_IFR_NUMERIC_SIZE_4: u8 = 0x02;
const EFI_IFR_NUMERIC_SIZE_8: u8 = 0x03;
const EFI_IFR_DISPLAY: u8 = 0x30;
const EFI_IFR_DISPLAY_INT_DEC: u8 = 0x00;
/// The prefixes of a NUMERIC value in hexadecimal, which set takes whatever EFI_IFR_DISPLAY
/// shows: "Input is still allowed in any form" (UEFI 2.11 §33.3.8.3.47)
const HEX_PREFIXES: [&str; 2] = ["0x", "0X"];
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
// UEFI 2.11 §33.3.8.3.51
const EFI_IFR_TYPE_ACTION: u8 = 0x0A;
const EFI_IFR_TYPE_BUFFER: u8 = 0x0B;
const EFI_IFR_TYPE_REF: u8 = 0x0C;
/// The bytes of an EFI_HII_TIME, EFI_HII_DATE and EFI_HII_REF, packed
/// (edk2-stable202608 MdePkg/Include/Uefi/UefiInternalFormRepresentation.h:659-676): Hour, Minute
/// and Second; a UINT16 Year, Month and Day; QuestionId, FormId, FormSetGuid and DevicePath.
const EFI_HII_TIME_SIZE: usize = 3;
const EFI_HII_DATE_SIZE: usize = 4;
const EFI_HII_REF_SIZE: usize = 22;
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
/// sizeof (EFI_IFR_VARSTORE_EFI) under #pragma pack(1), with a Name of one byte
/// (edk2-stable202608 MdePkg/Include/Uefi/UefiInternalFormRepresentation.h): edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes takes a shorter VARSTORE_EFI for the form before UEFI
/// 2.3.1.
const VAR_STORE_EFI_SIZE: u8 = 27;
/// The offset of the Guid of an EFI_IFR_VARSTORE from the start of its op, after its op header
/// (edk2-stable202608 MdePkg/Include/Uefi/UefiInternalFormRepresentation.h).
const VAR_STORE_GUID_OFFSET: u64 = 2;
/// The offset of the Guid of an EFI_IFR_VARSTORE_EFI from the start of its op, after its op
/// header and VarStoreId (UefiInternalFormRepresentation.h).
const VAR_STORE_EFI_GUID_OFFSET: u64 = 4;
/// sizeof (EFI_IFR_QUESTION_HEADER) under #pragma pack(1) (UefiInternalFormRepresentation.h): its
/// EFI_IFR_STATEMENT_HEADER, QuestionId, VarStoreId, VarStoreInfo and Flags (QuestionHeader).
const QUESTION_HEADER_SIZE: usize = 11;

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

    /// The Length below which an op of the opcode is malformed (UEFI 2.11 §33.2.5.10.1): that of
    /// its shortest encoding in UEFI 2.11 §33.3.8.3, its structure as edk2-stable202608
    /// MdePkg/Include/Uefi/UefiInternalFormRepresentation.h packs it with the fewest entries that
    /// the section allows in each array, those it leaves out of the structure too; of the
    /// shortest form of the opcode where it has several. An unknown opcode has no structure past
    /// its header.
    fn minimum_length(self) -> u8 {
        match self {
            Self::SuppressIf
            | Self::Locked
            | Self::And
            | Self::Or
            | Self::Not
            | Self::GrayOutIf
            | Self::DisableIf
            | Self::ToLower
            | Self::ToUpper
            | Self::Map
            | Self::Version
            | Self::End
            | Self::Match
            | Self::Read
            | Self::Write
            | Self::Equal
            | Self::NotEqual
            | Self::GreaterThan
            | Self::GreaterEqual
            | Self::LessThan
            | Self::LessEqual
            | Self::BitwiseAnd
            | Self::BitwiseOr
            | Self::BitwiseNot
            | Self::ShiftLeft
            | Self::ShiftRight
            | Self::Add
            | Self::Subtract
            | Self::Multiply
            | Self::Divide
            | Self::Modulo
            | Self::QuestionRef2
            | Self::True
            | Self::False
            | Self::ToUint
            | Self::ToBoolean
            | Self::Mid
            | Self::Token
            | Self::StringRef2
            | Self::Conditional
            | Self::Zero
            | Self::One
            | Self::Ones
            | Self::Undefined
            | Self::Length
            | Self::Dup
            | Self::This
            | Self::Value
            | Self::Catenate
            | Self::ModalTag
            | Self::Unknown(_) => IFR_OPERATION_HEADER_SIZE,
            // EFI_IFR_QUESTION_REF3, without the DevicePath of _2 and the Guid of _3
            Self::QuestionRef3 => IFR_OPERATION_HEADER_SIZE,
            Self::Rule
            | Self::Refresh
            | Self::RuleRef
            | Self::Uint8
            | Self::ToString
            | Self::Find
            | Self::Span => 3,
            Self::Image
            | Self::NoSubmitIf
            | Self::InconsistentIf
            | Self::Animation
            | Self::VarStoreDevice
            | Self::QuestionRef1
            | Self::Uint16
            | Self::StringRef1 => 4,
            Self::WarningIf => 5,
            // EFI_IFR_DEFAULT_2, whose value a nested EFI_IFR_VALUE gives
            Self::Default => 5,
            Self::Form | Self::EqIdVal | Self::EqIdId | Self::DefaultStore | Self::Uint32 => 6,
            // no ValueList entry, which UEFI 2.11 §33.3.8.3.20 allows
            Self::EqIdValList => 6,
            // EFI_IFR_TYPE_OTHER, whose value a nested EFI_IFR_VALUE gives
            Self::OneOfOption => 6,
            Self::Subtitle | Self::Get | Self::Set => 7,
            Self::Text | Self::ResetButton => 8,
            Self::Uint64 => 10,
            // EFI_IFR_ACTION_1 without QuestionConfig, and EFI_IFR_REF5 with no target
            Self::Action | Self::Ref => 13,
            Self::CheckBox | Self::Date | Self::Time => 14,
            Self::OrderedList => 15,
            Self::String => 16,
            // EFI_IFR_NUMERIC_SIZE_1: a MinValue, a MaxValue and a Step of one byte each
            Self::OneOf | Self::Numeric => 17,
            Self::Password => 17,
            Self::Guid | Self::Security | Self::RefreshId | Self::Match2 => 18,
            Self::VarStoreNameValue => 20,
            // one Method, of the one or more that UEFI 2.11 §33.3.8.3.25 requires
            Self::FormMap => 22,
            // an empty Name, its NUL counted in Length (UEFI 2.11 §33.3.8.3.89)
            Self::VarStore => 23,
            // no ClassGuid (UEFI 2.11 §33.3.8.3.26)
            Self::FormSet => 23,
            // up to Attributes: the form before UEFI 2.3.1, without Size, that edk2-stable202608
            // SetupBrowserDxe/IfrParse.c ParseOpCodes takes
            Self::VarStoreEfi => 24,
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
    /// Of a PASSWORD op that ends before its question header, the bytes of its form package after
    /// it up to the end of that header (keep_header_past_length)
    #[br(default)]
    header_past_length: Vec<u8>,
}

impl IFROperation {
    /// The FormId that a FORM or FORM_MAP op starts its data with (UEFI 2.11 §33.3.8.3.24,
    /// §33.3.8.3.25), decoded or not; None for other ops and one whose Length leaves none.
    pub(crate) fn form_id(&self) -> Option<u16> {
        self.data
            .first_chunk()
            .filter(|_| matches!(self.op_code, IFROpCode::Form | IFROpCode::FormMap))
            .map(|form_id| u16::from_le_bytes(*form_id))
    }

    /// Keeps, of a PASSWORD op at `offset` of the form package `package` that ends before its
    /// question header, the bytes of `package` after it up to the end of that header, those that
    /// it holds: edk2-stable202608 SetupBrowserDxe/IfrParse.c CreateQuestion (:119-124) reads the
    /// header there whatever the op's Length.
    fn keep_header_past_length(&mut self, package: &[u8], offset: u64) {
        if self.op_code != IFROpCode::Password {
            return;
        }
        let missing = QUESTION_HEADER_SIZE.saturating_sub(self.data.len());
        let after = usize::try_from(offset)
            .ok()
            .and_then(|offset| offset.checked_add(usize::from(self.length)));
        self.header_past_length = after
            .and_then(|after| package.get(after..))
            .map(|rest| rest.iter().take(missing).copied().collect())
            .unwrap_or_default();
    }
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
    ShortVarStoreEfi(ShortVarStoreEfi),
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
    Date(DateTimeQuestion),
    Time(DateTimeQuestion),
    OrderedList(OrderedList),
    Ref(CrossReference),
    String(StringQuestion),
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
    /// As many as bits 0:1 of Flags count; bits 2:7 are reserved (UEFI 2.11 §33.3.8.3.26)
    #[br(count = usize::from(flags & EFI_IFR_FORM_SET_CLASS_GUID_COUNT))]
    pub class_guids: Vec<Guid>,
    /// The VarStoreIds of the VarStore ops in the scopes of its FORMs and FORM_MAPs, which
    /// handle_form_set records as it parses them, so that declared_var_store walks those forms only
    /// for such an id
    #[br(default)]
    pub(super) var_stores_in_forms: BTreeSet<u16>,
    /// Those of the forms that handle_form_set disables, which leave the tree, so that
    /// declared_var_store refuses a lookup of such an id
    #[br(default)]
    pub(super) var_stores_in_disabled_forms: BTreeSet<u16>,
}

impl FormSet {
    /// The question Flags that the FormSet's class gives each of its questions: REST_STYLE,
    /// which "can be omitted if the formset class guid already contains
    /// EFI_HII_REST_STYLE_FORMSET_GUID" (UEFI 2.11 §33.3.8.2.2).
    fn class_question_flags(&self) -> QuestionFlags {
        if self.class_guids.contains(&EFI_HII_REST_STYLE_FORMSET_GUID) {
            QuestionFlags::REST_STYLE
        } else {
            QuestionFlags::empty()
        }
    }
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
    #[br(calc = encoding)]
    encoding: ValueEncoding,
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
    #[br(calc = encoding)]
    encoding: ValueEncoding,
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
        let value = self.number(value)?;
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

    /// The number that `text` names: after 0x or 0X, the stored bits in hexadecimal, decoded as
    /// get shows them; otherwise a decimal integer.
    fn number(&self, text: &str) -> Result<i128, ChangeValueError> {
        let unsigned = text.strip_prefix(['+', '-']).unwrap_or(text);
        let Some(digits) = HEX_PREFIXES
            .iter()
            .find_map(|prefix| unsigned.strip_prefix(prefix))
        else {
            return Ok(text
                .parse::<i128>()
                .context("value should be a decimal integer, or hexadecimal after 0x")?);
        };
        if unsigned.len() != text.len() {
            return Err(ChangeValueError::SignedHex(text.to_owned()));
        }
        // from_str_radix takes a sign too
        if !digits.bytes().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(anyhow!(
                "hexadecimal value {text:?} has a character after its prefix that is no \
                 hexadecimal digit"
            )
            .into());
        }
        let bits = u64::from_str_radix(digits, 16)
            .with_context(|| format!("failed to parse hexadecimal value {text:?}"))?;
        if self.format.cut(bits) != bits {
            return Err(ChangeValueError::HexTooWide {
                value: text.to_owned(),
                bits: self.format.bits,
            });
        }
        Ok(self.format.decode(bits))
    }
}

/// The stored width in bits, 1 to 64, of a NUMERIC or ONE_OF value, and, if
/// EFI_IFR_DISPLAY_INT_DEC signs it, the width of its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NumericFormat {
    bits: u32,
    signed_type_bits: Option<u32>,
}

/// Why the Flags and VarOffset of a NUMERIC or ONE_OF give no value format.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
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
        .is_some_and(|parent| is_bit_varstore_guid(&parent.borrow()))
}

/// Whether `op` is the GUID op that marks an EDKII bit varstore field.
fn is_bit_varstore_guid(op: &IFROperation) -> bool {
    op.op_code == IFROpCode::Guid && op.data.starts_with(&EDKII_IFR_BIT_VARSTORE_GUID)
}

/// Whether VarStore `var_store_id` of `op` is a VARSTORE_EFI of the form before UEFI 2.3.1 that
/// its FormSet declares: before `op`, while the FormSet is parsed.
fn names_short_var_store(op: &IFROperation, var_store_id: u16) -> bool {
    short_var_store_of(op, var_store_id).is_some()
}

/// VarStore `var_store_id` of `op`, if its FormSet declares it as a VARSTORE_EFI of the form
/// before UEFI 2.3.1.
fn short_var_store_of(op: &IFROperation, var_store_id: u16) -> Option<ShortVarStoreEfi> {
    match declared_var_store(&enclosing_form_set(op)?.borrow(), var_store_id) {
        Ok(Some(DeclaredStore::ShortEfi(store))) => Some(store),
        // a lookup that fails refuses the question as form_set_varstore reads it
        Ok(Some(DeclaredStore::Variable(_) | DeclaredStore::NameValue(_)) | None) | Err(_) => None,
    }
}

/// The layout of the variable that `question` names, while the FormSet is parsed: OneValue on a
/// VARSTORE_EFI before UEFI 2.3.1 declared before it.
fn parsed_layout(question: &IFROperation) -> VariableLayout {
    if parse_question_header(question)
        .is_some_and(|header| names_short_var_store(question, header.var_store_id))
    {
        VariableLayout::OneValue
    } else {
        VariableLayout::Offsets
    }
}

/// How a ONE_OF, NUMERIC, CHECKBOX, DATE or TIME stores its value, and a NUMERIC or ONE_OF its
/// MinValue, MaxValue and Step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueEncoding {
    /// In the size of EFI_IFR_NUMERIC_SIZE in its Flags, a CHECKBOX value in a byte, a DATE or
    /// TIME value in its EFI_HII_DATE or EFI_HII_TIME.
    NumericSize,
    /// As UINT32, as edk2-stable202608 VfrSyntax.g stores them for an EDKII bit varstore field,
    /// whose Flags hold its width in bits; the value in that width, a CHECKBOX value in 1 bit.
    EdkiiBitField,
    /// As NumericSize, from byte 0 of the EFI variable that its VarName names, on a VARSTORE_EFI
    /// of the form before UEFI 2.3.1.
    VarName,
}

impl ValueEncoding {
    fn from_question(question: &IFROperation) -> Self {
        match (refers_to_bit_field(question), parsed_layout(question)) {
            (true, _) => Self::EdkiiBitField,
            (false, VariableLayout::OneValue) => Self::VarName,
            (false, VariableLayout::Offsets) => Self::NumericSize,
        }
    }

    /// Where a ONE_OF or NUMERIC with `flags` and `range` keeps its value, VarStoreInfo
    /// `var_store_info`.
    fn numeric_location(self, var_store_info: u16, flags: u8, range: &Range) -> ValueLocation {
        match self {
            Self::NumericSize => ValueLocation::Bytes {
                offset: var_store_info,
                size: range.size().into(),
            },
            Self::EdkiiBitField => ValueLocation::Bits {
                offset: var_store_info,
                width: flags & EDKII_IFR_NUMERIC_SIZE_BIT,
            },
            Self::VarName => ValueLocation::Bytes {
                offset: VariableLayout::OneValue.offset(var_store_info),
                size: range.size().into(),
            },
        }
    }

    /// Where a CHECKBOX keeps its value, VarStoreInfo `var_store_info`: in a byte, or in the 1 bit
    /// that edk2-stable202608 IfrParse.c gives a bit-field CHECKBOX.
    fn checkbox_location(self, var_store_info: u16) -> ValueLocation {
        match self {
            Self::NumericSize => ValueLocation::Bytes {
                offset: var_store_info,
                size: 1,
            },
            Self::EdkiiBitField => ValueLocation::Bits {
                offset: var_store_info,
                width: 1,
            },
            Self::VarName => ValueLocation::Bytes {
                offset: VariableLayout::OneValue.offset(var_store_info),
                size: 1,
            },
        }
    }
}

/// The MinValue, MaxValue and Step of a NUMERIC or ONE_OF of `flags` in `encoding`.
fn range_parser<R: Read + Seek>(
    reader: &mut R,
    endian: binrw::Endian,
    (flags, encoding): (u8, ValueEncoding),
) -> BinResult<Range> {
    match encoding {
        ValueEncoding::EdkiiBitField => {
            BinRead::read_options(reader, endian, ()).map(Range::Range32)
        }
        ValueEncoding::NumericSize | ValueEncoding::VarName => match flags & EFI_IFR_NUMERIC_SIZE {
            EFI_IFR_NUMERIC_SIZE_1 => BinRead::read_options(reader, endian, ()).map(Range::Range8),
            EFI_IFR_NUMERIC_SIZE_2 => BinRead::read_options(reader, endian, ()).map(Range::Range16),
            EFI_IFR_NUMERIC_SIZE_4 => BinRead::read_options(reader, endian, ()).map(Range::Range32),
            // EFI_IFR_NUMERIC_SIZE_8, the only value left
            EFI_IFR_NUMERIC_SIZE_8.. => {
                BinRead::read_options(reader, endian, ()).map(Range::Range64)
            }
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
    #[br(calc = encoding)]
    encoding: ValueEncoding,
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
#[derive(Debug, PartialEq, Clone)]
enum IfrDefaultValue {
    Decoded(TypeValue),
    /// Of Type EFI_IFR_TYPE_STRING: the string's identifier
    String(u16),
    /// Of Type EFI_IFR_TYPE_BUFFER: every byte after Type, as edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c:2335-2337 copies them
    Buffer(Vec<u8>),
    /// Of Type EFI_IFR_TYPE_REF: every byte after Type, an EFI_HII_REF
    Ref(Vec<u8>),
    /// Absent from EFI_IFR_DEFAULT_2 (Type EFI_IFR_TYPE_OTHER), whose value is a nested
    /// EFI_IFR_VALUE.
    InValueOp,
    /// Of a Type other than numeric, boolean, date, time, string, buffer, EFI_IFR_TYPE_REF and
    /// EFI_IFR_TYPE_OTHER.
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
        | EFI_IFR_TYPE_BOOLEAN
        | EFI_IFR_TYPE_TIME
        | EFI_IFR_TYPE_DATE => match type_value_parser(reader, endian, args) {
            Ok(value) => Ok(IfrDefaultValue::Decoded(value)),
            Err(error) if error.is_eof() => Ok(IfrDefaultValue::Missing),
            Err(error) => Err(error),
        },
        EFI_IFR_TYPE_STRING => match u16::read_options(reader, endian, ()) {
            Ok(id) => Ok(IfrDefaultValue::String(id)),
            Err(error) if error.is_eof() => Ok(IfrDefaultValue::Missing),
            Err(error) => Err(error),
        },
        EFI_IFR_TYPE_BUFFER | EFI_IFR_TYPE_REF => {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            Ok(match (bytes.is_empty(), args.0) {
                (true, _) => IfrDefaultValue::Missing,
                (false, EFI_IFR_TYPE_REF) => IfrDefaultValue::Ref(bytes),
                (false, _) => IfrDefaultValue::Buffer(bytes),
            })
        }
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
    /// FORM_MAP without a method; here minimum_length disables its form.
    fn decode(data: &[u8]) -> Option<Self> {
        let (form_id, methods) = data.split_first_chunk::<2>()?;
        let methods = methods
            .chunks_exact(EFI_IFR_FORM_MAP_METHOD_SIZE)
            .map(|method| Cursor::new(method).parse_le())
            .collect::<Result<Vec<FormMapMethod>, ParseError>>()
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

/// An EFI_HII_TIME.
#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Time {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl Time {
    pub(crate) fn from_bytes([hour, minute, second]: [u8; 3]) -> Self {
        Self {
            hour,
            minute,
            second,
        }
    }

    /// Its bytes, as stored.
    pub(crate) fn to_bytes(self) -> [u8; 3] {
        [self.hour, self.minute, self.second]
    }
}

/// An EFI_HII_DATE.
#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl Date {
    pub(crate) fn from_bytes([low, high, month, day]: [u8; 4]) -> Self {
        Self {
            year: u16::from_le_bytes([low, high]),
            month,
            day,
        }
    }

    /// Its bytes, as stored.
    pub(crate) fn to_bytes(self) -> [u8; 4] {
        let [low, high] = self.year.to_le_bytes();
        [low, high, self.month, self.day]
    }
}

/// An EFI_HII_REF (UEFI 2.11 §33.3.8.3.51).
#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Ref {
    pub question_id: u16,
    pub form_id: u16,
    pub form_set_guid: Guid,
    pub device_path_string_id: u16,
}

impl Ref {
    /// The bytes of one, as stored.
    pub(crate) const SIZE: u16 = 22;

    pub(crate) fn from_bytes(bytes: [u8; Self::SIZE as usize]) -> Self {
        let [question_low, question_high, form_low, form_high, guid @ .., path_low, path_high] =
            bytes;
        Self {
            question_id: u16::from_le_bytes([question_low, question_high]),
            form_id: u16::from_le_bytes([form_low, form_high]),
            form_set_guid: Guid::from(guid),
            device_path_string_id: u16::from_le_bytes([path_low, path_high]),
        }
    }
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
    Time(Time),
    Date(Date),
    StringID(u16),
    /// EFI_IFR_TYPE_OTHER, of no bytes: a nested EFI_IFR_VALUE gives the value
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

    /// Returns the value as edk2-stable202608 SetupBrowserDxe/Expression.c HiiValueToUINT64
    /// widens it: a number or BOOLEAN as as_u64 does, an EFI_HII_DATE or EFI_HII_TIME as its
    /// bytes, little-endian.
    fn widened(self) -> Option<u64> {
        match self {
            TypeValue::Date(date) => Some(widened_date(date.to_bytes())),
            TypeValue::Time(time) => Some(widened_time(time.to_bytes())),
            TypeValue::NumSize8(_)
            | TypeValue::NumSize16(_)
            | TypeValue::NumSize32(_)
            | TypeValue::NumSize64(_)
            | TypeValue::Boolean(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => self.as_u64(),
        }
    }
}

/// A value of the type `args.0`, read in the endian that its derive passes; an EFI_HII_DATE or
/// EFI_HII_TIME little-endian, which its #[br(little)] struct always takes.
fn type_value_parser<R: Read + Seek>(
    reader: &mut R,
    endian: binrw::Endian,
    args: (u8,),
) -> BinResult<TypeValue> {
    match args.0 {
        EFI_IFR_TYPE_NUM_SIZE_8 => {
            let r: u8 = BinRead::read_options(reader, endian, ())?;
            Ok(TypeValue::NumSize8(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_16 => {
            let r: u16 = BinRead::read_options(reader, endian, ())?;
            Ok(TypeValue::NumSize16(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_32 => {
            let r: u32 = BinRead::read_options(reader, endian, ())?;
            Ok(TypeValue::NumSize32(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_64 => {
            let r: u64 = BinRead::read_options(reader, endian, ())?;
            Ok(TypeValue::NumSize64(r))
        }
        EFI_IFR_TYPE_BOOLEAN => {
            let r: u8 = BinRead::read_options(reader, endian, ())?;
            if r != 0 {
                return Ok(TypeValue::Boolean(true));
            }
            Ok(TypeValue::Boolean(false))
        }
        EFI_IFR_TYPE_STRING => {
            let r: u16 = BinRead::read_options(reader, endian, ())?;
            Ok(TypeValue::StringID(r))
        }
        EFI_IFR_TYPE_OTHER => Ok(TypeValue::Other),
        EFI_IFR_TYPE_TIME => Ok(TypeValue::Time(BinRead::read_options(reader, endian, ())?)),
        EFI_IFR_TYPE_DATE => Ok(TypeValue::Date(BinRead::read_options(reader, endian, ())?)),
        // TODO: handle other types like Ref. We have already made structs for them.
        _ => {
            let r: u8 = BinRead::read_options(reader, endian, ())?;
            Ok(TypeValue::Unknown(r))
        }
    }
}

/// Parses a form package into one root per FORM_SET op, outside another FormSet, that
/// edk2-stable202608 SetupBrowserDxe/Setup.c GetIfrBinaryData reaches when it looks for a FormSet
/// by GUID, walking the package op by op, scopes unread, e.g. into an unknown op's scope; each as
/// handle_form_set_within parses it, the walk going on after its End. A package without one has
/// no root.
/// That walk ends at an op whose Length runs past the package; here it also ends at one below the
/// header size, which that walk loops on (Length 0) or steps into (Length 1), before the first
/// FORM_SET op too, without failing the package. A FormSet whose bytes do not parse, which holds,
/// outside its forms, an op that is malformed or that uefisettings does not decode, or whose
/// scopes nest deeper than MAX_SCOPE_NESTING, the first one too, is ignored, as UEFI 2.11
/// §33.2.5.10.1 ignores a malformed forms set wherever it is, and the walk
/// goes on from the op after its FORM_SET op, as that walk does, so a FORM_SET op in it becomes a
/// root, as that walk finds it, though that section ignores the entire forms set. A FORM_SET op
/// without Scope that a failed parse reads outside every scope that it opened is ignored with that
/// parse's failure, unparsed: the parse from it reads the same ops and fails at the same one. So
/// each op is parsed at most twice per scope open around it, which a parse that reaches it opens
/// no more than MAX_SCOPE_NESTING of: from the FORM_SET op that opens that scope and from one
/// without Scope directly in it; then once from one without Scope outside them, and once by the
/// walk.
/// The forms that handle_form_set_within disables in the FormSets that it parses are returned too.
/// The IFR that the walk leaves unread is returned too, as PASSWORD questions in it are unknown:
/// such a FormSet, and the bytes after an op where the walk ends, unless they are padding.
/// So is each FormSet, first or later, whose FORM_SET op opens no scope and that parses: edk2
/// parses its ops on to the end of the package, past the End where handle_form_set_within ends
/// it. Their records, and those of the FormSets that the walk ignores, hold the variables that
/// IgnoredPasswords::Declared names.
/// The VarStores and statements that the walk steps over outside a FormSet are returned as well:
/// UEFI 2.11 §33.2.5.1 declares variable stores within a form set, and SetupBrowserDxe parses
/// none outside one, but edk2-stable202608 ConfigKeywordHandler.c FindQuestionFromStringId and
/// FindStorageFromVarId walk the whole form package. Statements, PASSWORDs among them, are
/// returned undecoded, as FindQuestionFromStringId reads only their Prompt; a VarStore that does
/// not parse, which hides only its VarStoreId, is returned apart. In the IFR that those records
/// cover (declared_ifr), which already counts the PASSWORDs and malformed ops there, only the
/// VarStores that parse and the PASSWORDs are, marked so (OutsideOp::in_ignored_ifr). So are the
/// VarStores in the scope of an unknown opcode in a FormSet that parses: SetupBrowserDxe/IfrParse.c
/// ParseOpCodes skips that scope (:1358-1381), and FindStorageFromVarId reads them as any
/// (OutsidePlace::UnknownScope).
pub(super) fn parse_form_sets(
    package_cursor: &mut Cursor<&Vec<u8>>,
    package_list_guid: Guid,
) -> Result<FormSets> {
    let mut roots = Vec::new();
    // the VarStore ops of the roots, disabled forms' among them, with their offsets, in IFR order
    let mut var_stores = Vec::new();
    let mut ignored = Vec::new();
    let mut disabled_forms = Vec::new();
    // the records of the FormSets that the walk ignores and of those whose FORM_SET ops open no
    // scope, by index in `ignored`
    let mut declaring = Vec::new();
    // the offsets of the FORM_SET ops of the FormSets that the walk ignores
    let mut ignored_form_sets = Vec::new();
    // the spans from the FORM_SET op without Scope of each FormSet that parses to the next FORM_SET
    // op that the walk meets or the end of the package, and the start of the last one while open
    let mut past_end: Vec<std::ops::Range<u64>> = Vec::new();
    let mut open_past_end = None;
    // FORM_SET ops without Scope, by offset, that a failed parse read outside every scope that it
    // opened, with its failure, which the parse from each gives too
    let mut failing_alike: BTreeMap<u64, Rc<FormSetFailure>> = BTreeMap::new();
    // the ops outside a FormSet that the walk steps over, and the VarStores in the scope of an
    // unknown opcode in a FormSet that parses, by offset
    let mut walked = Vec::new();
    let package_length = u64::try_from(package_cursor.get_ref().len())
        .context("failed to convert form package length into u64")?;
    while package_cursor.position() < package_length {
        let offset = package_cursor.position();
        let op: IFROperation = match package_cursor.parse_ne() {
            Ok(op) => op,
            Err(error)
                if error.is_eof()
                    || matches!(error.root_cause(), binrw::Error::AssertFail { .. }) =>
            {
                debug!("ending the FormSet walk at offset {offset}: {error}");
                let unread = usize::try_from(offset)
                    .ok()
                    .and_then(|offset| package_cursor.get_ref().get(offset..));
                if !unread.is_some_and(is_padding) {
                    ignored.push(IgnoredIfr {
                        package_list: package_list_guid,
                        offset,
                        reason: format!(
                            "an op that does not fit the form package, and the bytes after it: \
                             {error}"
                        ),
                        passwords: IgnoredPasswords::AnyVariable,
                    });
                }
                break;
            }
            Err(error) => return Err(error).context("failed to parse IFR operation"),
        };
        // where GetIfrBinaryData's walk goes on past a FormSet that this one ignores
        let after_op = package_cursor.position();
        if op.op_code != IFROpCode::FormSet {
            debug!(
                "skipping {:?} outside a FormSet at offset {offset}",
                op.op_code
            );
            walked.push((offset, op, OutsidePlace::NoFormSet));
            continue;
        }
        if let Some(start) = open_past_end.take() {
            past_end.push(start..offset);
        }
        let failure = match failing_alike.remove(&offset) {
            Some(failure) => failure,
            None => {
                package_cursor.set_position(offset);
                let mut alike = Vec::new();
                match handle_form_set_within(package_cursor, MAX_SCOPE_NESTING, &mut alike) {
                    Ok(parsed) => {
                        if !op.open_scope {
                            declaring.push(ignored.len());
                            ignored.push(opens_no_scope(&op, package_list_guid, offset));
                            open_past_end = Some(offset);
                        }
                        var_stores.extend(parsed.var_stores);
                        let roots_before = roots.len();
                        roots.push(parsed.root);
                        disabled_forms.extend(
                            parsed
                                .disabled_forms
                                .into_iter()
                                .map(|disabled| disabled.after_roots(roots_before)),
                        );
                        for store in parsed.unknown_scope_stores {
                            let op = op_at(package_cursor.get_ref(), store)?;
                            walked.push((store, op, OutsidePlace::UnknownScope));
                        }
                        continue;
                    }
                    Err(error) => {
                        let failure = Rc::new(FormSetFailure::of(error)?);
                        failing_alike.extend(alike.into_iter().map(|at| (at, Rc::clone(&failure))));
                        failure
                    }
                }
            }
        };
        debug!(
            "package list {package_list_guid}: ignoring the FormSet at offset {offset} of a form \
             package: {}",
            failure.error
        );
        declaring.push(ignored.len());
        ignored_form_sets.push(offset);
        ignored.push(IgnoredIfr {
            package_list: package_list_guid,
            offset,
            reason: failure.reason(&form_set_name(&op)),
            passwords: IgnoredPasswords::Declared(Arc::default()),
        });
        package_cursor.set_position(after_op);
    }
    if let Some(start) = open_past_end {
        past_end.push(start..package_length);
    }
    let package = package_cursor.get_ref();
    let DeclaredIfr { spans, storage } = match declaring.is_empty() {
        true => DeclaredIfr::default(),
        false => declared_ifr(package, &ignored_form_sets, &past_end),
    };
    let declared = Arc::new(storage);
    for index in declaring {
        if let Some(record) = ignored.get_mut(index) {
            record.passwords = IgnoredPasswords::Declared(Arc::clone(&declared));
        }
    }
    let mut outside = Vec::new();
    let mut malformed_stores = Vec::new();
    for (offset, op, place) in walked {
        let in_ignored_ifr = spans
            .get(spans.partition_point(|span| span.end <= offset))
            .is_some_and(|span| span.contains(&offset));
        let at = OutsideAt {
            offset,
            place,
            in_ignored_ifr,
        };
        record_outside_op(
            op,
            at,
            package,
            package_list_guid,
            &mut outside,
            &mut malformed_stores,
        );
    }
    let (first_var_stores, name_value_first, declared) = first_var_stores(&var_stores, &outside);
    Ok(FormSets {
        roots,
        ignored,
        disabled_forms,
        outside,
        malformed_stores,
        first_var_stores,
        name_value_first,
        declared,
    })
}

/// The first VarStore of each VarStoreId of a form package where a FormSet declares it, with the
/// FORM_SET op nearest around it, and the VarStoreIds whose first VarStore is a
/// VARSTORE_NAME_VALUE, in a FormSet or not: of `var_stores`, those in the FormSets that
/// parse_form_sets parses, disabled forms' among them, and `outside`, those outside them or in the
/// scope of an unknown opcode in them, each in IFR order with its offset. edk2-stable202608
/// ConfigKeywordHandler.c FindStorageFromVarId takes that VarStore for every question of the id in
/// the package, as it walks the package op by op (:1520-1567), FORM_SET ops or not, so a FormSet
/// nested in another is another FormSet, and steps into the scope of an unknown opcode as into any
/// (:1566). An id whose first VarStore is outside any FormSet or in such a scope has no FormSet's:
/// PasswordQuestions withholds those as VarStores outside any FormSet. Every id of those
/// VarStores comes third: for a question of the package of an id of none, the Forms Browser and
/// FindStorageFromVarId find none but a VarStore op that does not decode, which each reads
/// whatever the op's Length: the Forms Browser one of the question's FormSet outside an unknown
/// opcode's scope (SetupBrowserDxe/IfrParse.c ParseOpCodes, :1873-1918), FindStorageFromVarId the
/// first in the package (:1538-1555).
fn first_var_stores(
    var_stores: &[(u64, Rc<RefCell<IFROperation>>)],
    outside: &[OutsideOp],
) -> (BTreeMap<u16, FirstVarStore>, BTreeSet<u16>, BTreeSet<u16>) {
    let in_form_sets = var_stores.iter().filter_map(|(offset, store)| {
        let (var_store_id, declared) = declared_store(&store.borrow().parsed_data)?;
        Some((*offset, var_store_id, declared, Some(store)))
    });
    let outside = outside.iter().filter_map(|op| {
        let (var_store_id, declared) = declared_store(&op.op.parsed_data)?;
        Some((op.offset, var_store_id, declared, None))
    });
    let mut stores: Vec<_> = in_form_sets.chain(outside).collect();
    stores.sort_by_key(|&(offset, ..)| offset);
    let mut first = BTreeMap::new();
    let mut name_value_first = BTreeSet::new();
    for (_, var_store_id, declared, store) in stores {
        if first.contains_key(&var_store_id) {
            continue;
        }
        if let DeclaredStore::NameValue(_) = declared {
            name_value_first.insert(var_store_id);
        }
        let declared_by = store.and_then(|store| {
            let form_set = enclosing_form_set(&store.borrow())?;
            Some(FirstVarStore {
                form_set,
                store: Rc::clone(store),
            })
        });
        first.insert(var_store_id, declared_by);
    }
    let declared = first.keys().copied().collect();
    let first = first
        .into_iter()
        .filter_map(|(var_store_id, first)| Some((var_store_id, first?)))
        .collect();
    (first, name_value_first, declared)
}

/// Where an op that parse_form_sets records outside the FormSets that it parses sits.
#[derive(Clone, Copy)]
struct OutsideAt {
    offset: u64,
    place: OutsidePlace,
    /// Whether it is in the IFR that IgnoredPasswords::Declared covers
    in_ignored_ifr: bool,
}

impl OutsideAt {
    /// The record of `op`, which sits here.
    fn record(self, op: IFROperation) -> OutsideOp {
        OutsideOp {
            offset: self.offset,
            op,
            place: self.place,
            in_ignored_ifr: self.in_ignored_ifr,
        }
    }
}

/// Records the op `op`, `at` an offset of the form package `package` of the package list
/// `package_list`, in `outside` if it is a VarStore that parses, a PASSWORD, or, unless it is in
/// ignored IFR, another statement, and in `malformed_stores` if it is a VarStore that does not
/// parse, with the storage that it may declare (DeclaredStorage::declare). A PASSWORD keeps the
/// bytes after it that its question header may take (IFROperation::keep_header_past_length).
fn record_outside_op(
    mut op: IFROperation,
    at: OutsideAt,
    package: &[u8],
    package_list: Guid,
    outside: &mut Vec<OutsideOp>,
    malformed_stores: &mut Vec<IgnoredIfr>,
) {
    let OutsideAt {
        offset,
        place,
        in_ignored_ifr,
    } = at;
    op.keep_header_past_length(package, offset);
    match op.op_code {
        IFROpCode::VarStore | IFROpCode::VarStoreEfi | IFROpCode::VarStoreNameValue => {
            match handle_opcode(&mut op) {
                Ok(()) => outside.push(at.record(op)),
                Err(error) if in_ignored_ifr => debug!(
                    "a malformed {} {place}, in ignored IFR: {error:#}",
                    op.op_code.spec_name()
                ),
                Err(error) => {
                    let mut storage = DeclaredStorage::default();
                    storage.declare(&op, package, offset);
                    malformed_stores.push(IgnoredIfr {
                        package_list,
                        offset,
                        reason: format!(
                            "a malformed {} {place}: {error:#}",
                            op.op_code.spec_name()
                        ),
                        passwords: IgnoredPasswords::Declared(Arc::new(storage)),
                    })
                }
            }
        }
        // a statement that does not parse counts for the Keyword Handler, which reads its Prompt
        // alone; PasswordQuestions decodes a PASSWORD's question header
        op_code if defaults::is_statement(op_code) && !in_ignored_ifr => {
            outside.push(at.record(op))
        }
        // in ignored IFR too, as FindQuestionFromStringId finds it there and FindStorageFromVarId
        // takes the first VarStore of its VarStoreId in the form package
        IFROpCode::Password => outside.push(at.record(op)),
        _ => {}
    }
}

/// The op at `offset` of the form package `package`.
fn op_at(package: &[u8], offset: u64) -> Result<IFROperation> {
    let mut cursor = Cursor::new(package);
    cursor.set_position(offset);
    cursor
        .parse_ne()
        .with_context(|| format!("failed to parse the IFR operation at offset {offset}"))
}

/// The IFR of a form package that IgnoredPasswords::Declared covers: its spans of offsets,
/// ascending, and the storage that its ops declare.
#[derive(Default)]
struct DeclaredIfr {
    spans: Vec<std::ops::Range<u64>>,
    storage: DeclaredStorage,
}

/// The IFR of the FormSets of the form package `package` whose FORM_SET ops sit at `form_sets`,
/// ascending, and that at offsets in the spans `past_end`, ascending, with the storage that its
/// VARSTORE and VARSTORE_EFI ops declare (DeclaredStorage::declare). A FormSet's ops run from its
/// FORM_SET op to the End of its scope, or, where that op opens none, to the end of the package,
/// as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes parses them. The walk goes op by
/// op from the start of the package, as parse_form_sets' does, so it ends where that walk ends, at
/// an op that does not fit the package, which parse_form_sets records as
/// IgnoredPasswords::AnyVariable.
fn declared_ifr(
    package: &[u8],
    form_sets: &[u64],
    past_end: &[std::ops::Range<u64>],
) -> DeclaredIfr {
    let mut cursor = Cursor::new(package);
    let mut form_sets = form_sets.iter().peekable();
    let mut past_end = past_end.iter().peekable();
    let mut depth: usize = 0;
    // while a FormSet of `form_sets` is open: the depth that the End of the outermost one's scope
    // returns to, or None for one whose FORM_SET op opens no scope, which runs to the end
    let mut open: Option<Option<usize>> = None;
    // the start of the span that the ops up to here are in, if they are
    let mut span_start = None;
    let mut declared = DeclaredIfr::default();
    loop {
        let offset = cursor.position();
        // parse_form_sets' walk ends at the same op
        let Ok(op) = cursor.parse_ne::<IFROperation>() else {
            break;
        };
        while form_sets.next_if(|&&form_set| form_set < offset).is_some() {}
        let starts = form_sets.next_if_eq(&&offset).is_some();
        match (open, starts, op.open_scope) {
            (None, true, true) => open = Some(Some(depth)),
            (None | Some(Some(_)), true, false) => open = Some(None),
            (_, false, _) | (Some(Some(_)), true, true) | (Some(None), true, _) => {}
        }
        while past_end.next_if(|span| span.end <= offset).is_some() {}
        let declaring =
            open.is_some() || past_end.peek().is_some_and(|span| span.contains(&offset));
        match (declaring, span_start) {
            (true, None) => span_start = Some(offset),
            (false, Some(start)) => {
                declared.spans.push(start..offset);
                span_start = None;
            }
            (true, Some(_)) | (false, None) => {}
        }
        if declaring {
            declared.storage.declare(&op, package, offset);
        }
        match (op.op_code, op.open_scope) {
            (IFROpCode::End, _) => {
                depth = depth.saturating_sub(1);
                if open == Some(Some(depth)) {
                    open = None;
                }
            }
            (_, true) => depth += 1,
            (_, false) => {}
        }
    }
    // up to the end of the walk
    if let Some(start) = span_start {
        declared.spans.push(start..u64::MAX);
    }
    declared
}

/// The storage that VARSTORE and VARSTORE_EFI ops of IFR that read_db ignores, or such an op outside
/// any FormSet that does not parse, declare.
#[derive(Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct DeclaredStorage {
    /// The variables that they name
    pub(crate) variables: BTreeSet<VariableKey>,
    /// The vendor GUIDs of those whose variables' names are unknown, every variable of which
    /// may be theirs
    pub(crate) guids: VariableGuids,
    /// Whether a VARSTORE_NAME_VALUE op is among the ops, decoded or not: edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c creates its storage whatever its Length (:1885-1895), as
    /// ConfigKeywordHandler.c FindStorageFromVarId takes it by its VarStoreId (:1547-1550), and
    /// it is one whose values its driver exposes, as UEFI 2.11 §33.2.5.6 says, through
    /// EFI_HII_CONFIG_ACCESS_PROTOCOL, in storage of its own choosing
    pub(crate) name_value: bool,
}

impl DeclaredStorage {
    /// Adds what the op `op`, at `offset` of the form package `package`, declares if it is a
    /// VARSTORE or VARSTORE_EFI: its variable, decoded from its op alone, else its GUID, every
    /// variable of which may be its, read where edk2-stable202608 SetupBrowserDxe/IfrParse.c
    /// CreateStorage reads it whatever the op's Length (:440, :446), and unknown past the package.
    /// The GUID is taken for a VARSTORE_EFI of the form before UEFI 2.3.1 too, which names a
    /// variable for each question on it by the string of the question's VarName (CreateQuestion
    /// :156, Setup.c GetToken :1069-1072, GetQuestionValue :1772-1774), any string for a question
    /// that is not read. A VARSTORE_NAME_VALUE declares no variable: it sets name_value.
    fn declare(&mut self, op: &IFROperation, package: &[u8], offset: u64) {
        self.declare_with(op, |guid_offset| guid_at(package, offset, guid_offset));
    }

    /// Adds what the op `op` of the tree of a FormSet declares, as declare does, from its op
    /// alone: its GUID is unknown where it runs past its Length, as the bytes after the op are
    /// not in the tree.
    pub(crate) fn declare_in_tree(&mut self, op: &IFROperation) {
        self.declare_with(op, |guid_offset| {
            let start = guid_offset.checked_sub(u64::from(IFR_OPERATION_HEADER_SIZE))?;
            let start = usize::try_from(start).ok()?;
            let bytes: [u8; 16] = op
                .data
                .get(start..start.checked_add(16)?)?
                .try_into()
                .ok()?;
            Some(Guid::from(bytes))
        });
    }

    /// declare, with the GUID at each offset from the start of `op` from `guid_at_offset`.
    fn declare_with(
        &mut self,
        op: &IFROperation,
        guid_at_offset: impl FnOnce(u64) -> Option<Guid>,
    ) {
        let mut data = Cursor::new(&op.data);
        let (variable, guid_offset) = match op.op_code {
            IFROpCode::VarStore => (
                data.parse_ne::<VarStore>()
                    .ok()
                    .map(|store| store.variable_key()),
                VAR_STORE_GUID_OFFSET,
            ),
            IFROpCode::VarStoreEfi if op.length >= VAR_STORE_EFI_SIZE => (
                data.parse_ne::<VarStoreEfi>()
                    .ok()
                    .map(|store| store.variable_key()),
                VAR_STORE_EFI_GUID_OFFSET,
            ),
            IFROpCode::VarStoreEfi => (None, VAR_STORE_EFI_GUID_OFFSET),
            IFROpCode::VarStoreNameValue => {
                self.name_value = true;
                return;
            }
            _ => return,
        };
        match variable {
            Some(variable) => {
                self.variables.insert(variable);
            }
            None => self.guids.insert(guid_at_offset(guid_offset)),
        }
    }

    /// Adds those of `other`.
    pub(crate) fn extend(&mut self, other: &Self) {
        self.variables.extend(other.variables.iter().cloned());
        self.guids.extend(&other.guids);
        self.name_value |= other.name_value;
    }
}

/// The GUID at `guid_offset` of the op at `offset` of the form package `package`, if the package
/// holds it.
fn guid_at(package: &[u8], offset: u64, guid_offset: u64) -> Option<Guid> {
    let start = usize::try_from(offset.checked_add(guid_offset)?).ok()?;
    let bytes: [u8; 16] = package
        .get(start..start.checked_add(16)?)?
        .try_into()
        .ok()?;
    Some(Guid::from(bytes))
}

/// The record of the FormSet that parses from the FORM_SET op `op` without Scope, at offset
/// `offset` of a form package of the package list `package_list`.
fn opens_no_scope(op: &IFROperation, package_list: Guid, offset: u64) -> IgnoredIfr {
    let reason = format!(
        "{} opens no scope, so edk2 parses its ops on to the end of the form package, past the End \
         where uefisettings ends it (edk2-stable202211 SetupBrowserDxe IfrParse.c ParseOpCodes \
         pushes a scope only for Scope != 0, and ends a FormSet only at the End of a FORM_SET \
         scope)",
        form_set_name(op)
    );
    debug!("package list {package_list}: at offset {offset} of a form package, {reason}");
    IgnoredIfr {
        package_list,
        offset,
        reason,
        passwords: IgnoredPasswords::Declared(Arc::default()),
    }
}

/// The records that an error names before it counts the rest.
const NAMED_RECORDS: usize = 16;

/// `records` joined by "; ": the first NAMED_RECORDS of them, then the count of the rest.
pub(crate) fn named_records(records: &[impl fmt::Display]) -> String {
    let mut named: Vec<String> = records
        .iter()
        .take(NAMED_RECORDS)
        .map(ToString::to_string)
        .collect();
    let rest = records.len().saturating_sub(NAMED_RECORDS);
    if rest > 0 {
        named.push(format!("and {rest} more"));
    }
    named.join("; ")
}

/// Why a FormSet that parse_form_sets ignores does not parse: the error of its parse, and what
/// fails.
struct FormSetFailure {
    kind: FormSetFailureKind,
    error: String,
}

/// What fails in a FormSet that parse_form_sets ignores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormSetFailureKind {
    /// Its scopes nest deeper than MAX_SCOPE_NESTING
    TooDeep,
    /// An op runs past the package or below the header size
    Malformed,
    /// An op outside its forms is shorter than the Length that it needs (ShortOp)
    Short,
    /// An op outside its forms that uefisettings does not decode
    Undecoded,
    /// A VarStore op in a form that a malformed op disables (VarStoreInDisabledForm)
    VarStoreInDisabledForm,
}

impl FormSetFailure {
    /// That of the error `error` of handle_form_set_within, which ignores the FormSet if it nests
    /// too deep, does not parse or holds an op that uefisettings does not decode outside its
    /// forms; `error` for any other.
    fn of(error: anyhow::Error) -> Result<Self> {
        let too_deep = error.chain().any(|cause| cause.is::<ScopesTooDeep>());
        let var_store = error
            .chain()
            .any(|cause| cause.is::<VarStoreInDisabledForm>());
        let undecoded = error.chain().any(|cause| cause.is::<UndecodedOp>());
        let short = error.chain().any(|cause| cause.is::<ShortOp>());
        let malformed = error.chain().any(|cause| cause.is::<ParseError>());
        let kind = match (too_deep, var_store, undecoded, short, malformed) {
            (true, _, _, _, _) => FormSetFailureKind::TooDeep,
            (false, true, _, _, _) => FormSetFailureKind::VarStoreInDisabledForm,
            (false, false, true, _, _) => FormSetFailureKind::Undecoded,
            (false, false, false, true, _) => FormSetFailureKind::Short,
            (false, false, false, false, true) => FormSetFailureKind::Malformed,
            (false, false, false, false, false) => return Err(error),
        };
        Ok(Self {
            kind,
            error: format!("{error:#}"),
        })
    }

    /// The reason of the record of the FormSet `name` that fails so.
    fn reason(&self, name: &str) -> String {
        let error = &self.error;
        match self.kind {
            FormSetFailureKind::TooDeep => format!("{name}, which nests too deep: {error}"),
            FormSetFailureKind::Malformed => format!(
                "{name}, which does not parse; uefisettings ignores it, where UEFI 2.11 \
                 §33.2.5.10.1 disables only the form of a malformed op and ignores only a \
                 malformed forms set: {error}"
            ),
            FormSetFailureKind::Short => format!(
                "{name}, which holds, outside its forms, an op shorter than its minimum, which \
                 UEFI 2.11 §33.2.5.10.1 calls malformed, in no form for that section to disable: \
                 {error}"
            ),
            FormSetFailureKind::Undecoded => format!(
                "{name}, which holds, outside its forms, an op that uefisettings does not \
                 decode: {error}"
            ),
            FormSetFailureKind::VarStoreInDisabledForm => format!(
                "{name}, which holds a VarStore op in a form that a malformed op disables, whose \
                 VarStoreId edk2's Config Keyword Handler reads all the same: {error}"
            ),
        }
    }
}

/// The FormSet that the FORM_SET op `op` opens, named by its GUID, or "a FormSet" if its data is
/// too short for one.
fn form_set_name(op: &IFROperation) -> String {
    match op.data.first_chunk() {
        Some(&guid) => format!("the FormSet {}", Guid::from(guid)),
        None => "a FormSet".to_string(),
    }
}

/// The FormSets of a form package: a root for each that parse_form_sets parses, the IFR that it
/// ignores, the forms that it drops from those roots, the VarStores and statements outside the
/// FormSets that it parses, with the VarStores in the scope of an unknown opcode in those,
/// malformed VarStores apart, the first VarStore of each VarStoreId that a FormSet declares, the
/// VarStoreIds whose first VarStore is a VARSTORE_NAME_VALUE, and every VarStoreId that a VarStore
/// that decodes declares (first_var_stores).
pub(super) struct FormSets {
    pub(super) roots: Vec<Rc<RefCell<IFROperation>>>,
    pub(super) ignored: Vec<IgnoredIfr>,
    pub(super) disabled_forms: Vec<DisabledForm>,
    pub(super) outside: Vec<OutsideOp>,
    pub(super) malformed_stores: Vec<IgnoredIfr>,
    pub(super) first_var_stores: BTreeMap<u16, FirstVarStore>,
    pub(super) name_value_first: BTreeSet<u16>,
    pub(super) declared: BTreeSet<u16>,
}

/// The FormSets of a form package of a package list, by index in its forms, which the forms that
/// read_db disables in them name too (DisabledForm::root_index), its ops outside them, by index in
/// the list's outside_ifr, and the first VarStore of each VarStoreId of the package where a
/// FormSet declares it, by that id: the VarStore that edk2-stable202608 ConfigKeywordHandler.c
/// FindStorageFromVarId (:1520) takes for every question of the id in the package
/// (first_var_stores).
#[derive(Debug, Clone)]
pub(crate) struct FirstVarStores {
    pub(crate) form_sets: std::ops::Range<usize>,
    pub(crate) outside: std::ops::Range<usize>,
    pub(crate) declared_by: BTreeMap<u16, FirstVarStore>,
    /// The VarStoreIds whose first VarStore in the package, in a FormSet or not, is a
    /// VARSTORE_NAME_VALUE
    pub(crate) name_value_first: BTreeSet<u16>,
    /// Every VarStoreId that a VarStore of the package that decodes declares, in a FormSet or not
    pub(crate) declared: BTreeSet<u16>,
}

/// The first VarStore op of a VarStoreId of a form package, `store`, and the FORM_SET op nearest
/// around it, `form_set`, which declares it.
#[derive(Debug, Clone)]
pub(crate) struct FirstVarStore {
    pub(crate) form_set: Rc<RefCell<IFROperation>>,
    pub(crate) store: Rc<RefCell<IFROperation>>,
}

/// A VarStore or statement op of a form package outside the FormSets that parse_form_sets
/// parses, or a VarStore in the scope of an unknown opcode in one, at `offset`, and whether it is
/// in the IFR that IgnoredPasswords::Declared covers.
#[derive(Debug)]
pub struct OutsideOp {
    pub offset: u64,
    pub op: IFROperation,
    pub place: OutsidePlace,
    pub in_ignored_ifr: bool,
}

/// Where an op sits that edk2-stable202608 SetupBrowserDxe parses into no FormSet but
/// ConfigKeywordHandler.c finds, as FindQuestionFromStringId (:1478) and FindStorageFromVarId
/// (:1520) walk the whole form package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutsidePlace {
    /// Outside any FormSet (UEFI 2.11 §33.2.5.1 declares variable stores within a form set)
    NoFormSet,
    /// In the scope of an unknown opcode in a FormSet, which SetupBrowserDxe/IfrParse.c
    /// ParseOpCodes skips (:1358-1381)
    UnknownScope,
}

impl fmt::Display for OutsidePlace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoFormSet => "outside a FormSet",
            Self::UnknownScope => "in the scope of an unknown opcode",
        })
    }
}

/// A form that parse_form_sets drops from the tree of its FormSet, as UEFI 2.11 §33.2.5.10.1
/// disables the form of a malformed op, or as uefisettings does not decode an op in it, so that no
/// question of it is read or set; its PASSWORD questions are withheld as those of the forms that
/// it keeps.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DisabledForm {
    /// The offset of its FORM or FORM_MAP op in its form package
    pub offset: u64,
    /// What it is and what disables it
    pub reason: String,
    /// Its FORM or FORM_MAP op, with its parent in the tree, holding its ops, undecoded from the
    /// op that disables it on
    pub form: Rc<RefCell<IFROperation>>,
    /// The index of the root of its FormSet among the roots that its parse returns: in the forms
    /// of its package list (ParsedPackageList::forms) for read_db
    pub root_index: usize,
    /// The name of its first PASSWORD or VarStore op, which record_disabled_var_stores finds
    /// (DriverHeldQuestion::check_disabled_forms)
    pub(crate) store_op: Option<&'static str>,
}

impl DisabledForm {
    /// Itself in a parse that returns `roots_before` roots before those of the parse that
    /// returned it, as parse_form_sets and read_package_list collect the roots in order.
    pub(super) fn after_roots(self, roots_before: usize) -> Self {
        #[cfg(test)]
        ROOT_INDICES_SHIFTED.with(|shifted| shifted.set(shifted.get() + 1));
        Self {
            root_index: self.root_index + roots_before,
            ..self
        }
    }

    /// Its record, as a form of a form package of the package list `package_list`.
    pub fn record(&self, package_list: Guid) -> IgnoredIfr {
        IgnoredIfr {
            package_list,
            offset: self.offset,
            reason: self.reason.clone(),
            passwords: IgnoredPasswords::Found,
        }
    }
}

/// IFR of a form package of the package list `package_list` that parse_form_sets ignores, from
/// `offset` on, and what it is. Only parse_form_sets makes one:
///
/// ```compile_fail
/// use uefisettings::exports::IgnoredIfr;
///
/// fn at_offset_0(ignored: &IgnoredIfr) -> IgnoredIfr {
///     IgnoredIfr {
///         offset: 0,
///         ..ignored.clone()
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct IgnoredIfr {
    pub package_list: Guid,
    pub offset: u64,
    pub reason: String,
    /// Where a PASSWORD in it, or of a VarStoreId that it may declare, may keep its password
    pub(crate) passwords: IgnoredPasswords,
}

/// Where a PASSWORD in IFR that parse_form_sets ignores may keep its password, which
/// PasswordQuestions::of_lists withholds.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum IgnoredPasswords {
    /// In any variable: the IFR past an op where the walk for FormSets ends has no op boundary
    AnyVariable,
    /// In this storage: that which the VARSTORE and VARSTORE_EFI ops of the FormSets that the walk
    /// ignores in the form package declare, and those of the ops from the FORM_SET op without
    /// Scope of a FormSet that parses up to the next FORM_SET op that the walk meets, which edk2
    /// parses into that FormSet past its End (declared_ifr), as find_corresponding_varstore
    /// takes a PASSWORD's VarStore from its own FormSet; or that which a VarStore outside any
    /// FormSet that does not parse may declare, as a PASSWORD of any VarStoreId may name it. A
    /// PASSWORD there whose question header parses is withheld in each VarStore of its VarStoreId
    /// too, as one outside any FormSet is (OutsideOp)
    Declared(Arc<DeclaredStorage>),
    /// Where PasswordQuestions finds it: a disabled form keeps its PASSWORD ops
    Found,
}

impl fmt::Display for IgnoredIfr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the IFR that uefisettings ignores at offset {} of a form package of package list {}: \
             {}",
            self.offset, self.package_list, self.reason
        )
    }
}

#[cfg(test)]
thread_local! {
    /// The ops that handle_form_set_within has parsed on this thread, which tests of the bound on
    /// parse_form_sets' parses count.
    pub(crate) static OPS_PARSED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    /// The calls of DisabledForm::after_roots on this thread, which shifts the root index of a
    /// disabled form as each parse collects it, which tests of the bound on grouping disabled
    /// forms by FormSet count.
    pub(crate) static ROOT_INDICES_SHIFTED: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// The root of handle_form_set_within, for the tests, at MAX_SCOPE_NESTING
#[cfg(test)]
pub(crate) fn handle_form_set(
    package_cursor: &mut Cursor<&Vec<u8>>,
) -> Result<Rc<RefCell<IFROperation>>> {
    handle_form_set_within(package_cursor, MAX_SCOPE_NESTING, &mut Vec::new())
        .map(|parsed| parsed.root)
}

/// A FormSet that handle_form_set_within parses: the root of its tree, the forms that it drops
/// from it, and the VarStore ops that it puts in the tree, those of the forms that it drops among
/// them, each with its offset, in IFR order.
struct ParsedFormSet {
    root: Rc<RefCell<IFROperation>>,
    disabled_forms: Vec<DisabledForm>,
    /// The offsets of the VarStore ops in the scopes of unknown opcodes, which are not decoded
    unknown_scope_stores: Vec<u64>,
    var_stores: Vec<(u64, Rc<RefCell<IFROperation>>)>,
}

/// Parses the FormSet at `package_cursor`, failing with ScopesTooDeep at an op that opens more
/// than `limit` scopes at once, adding to `alike` the offset of each FORM_SET op without Scope
/// after its first op that it reads outside every scope that it opened: the parse from such an op
/// reads the ops after it as this one does, so it fails where this one fails.
/// An op outside the scope of an op that skips_scope names that is shorter than the
/// minimum_length of its opcode, or that uefisettings does not decode, disables its form: the
/// innermost FORM or FORM_MAP op whose scope is open, or the op itself if it is one. The form's
/// ops up to its End are read undecoded, and the form leaves the tree as a DisabledForm. Such an
/// op outside every form fails the FormSet with ShortOp or UndecodedOp, and a VarStore op that
/// would disable its form, or that a disabled form holds after the op that disables it, with
/// VarStoreInDisabledForm.
fn handle_form_set_within(
    package_cursor: &mut Cursor<&Vec<u8>>,
    limit: usize,
    alike: &mut Vec<u64>,
) -> Result<ParsedFormSet> {
    let start = package_cursor.position();
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
        header_past_length: Vec::new(),
    }));

    let mut current_scope = Rc::clone(&root);
    // The scopes open inside an op that skips_scope names, its own scope counted: their ops are not
    // decoded, as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips them unread
    // (InUnknownScope, UnknownDepth).
    let mut skipped_depth: usize = 0;
    // The scopes open, the FormSet's own and skipped ones counted
    let mut depth: usize = 0;
    // The FORM and FORM_MAP ops whose scopes are open outside skipped ones, innermost last, with
    // their offsets
    let mut open_forms: Vec<(Rc<RefCell<IFROperation>>, u64)> = Vec::new();
    // The form whose ops up to its End are read undecoded
    let mut disabling: Option<DisabledForm> = None;
    let mut disabled_forms = Vec::new();
    let mut unknown_scope_stores = Vec::new();
    let mut var_stores = Vec::new();

    // this loop will terminate when it sees the IFR:End opcode as a child of FormSet
    // if input data is malformed then it will exit on erroring out cause none of the magic bytes match
    loop {
        let offset = package_cursor.position();
        let mut node: IFROperation = package_cursor
            .parse_ne()
            .context("failed to parse IFR operation")?;
        node.keep_header_past_length(package_cursor.get_ref(), offset);
        #[cfg(test)]
        OPS_PARSED.with(|parsed| parsed.set(parsed.get() + 1));
        if depth == 0 && offset != start && node.op_code == IFROpCode::FormSet && !node.open_scope {
            alike.push(offset);
        }

        let current_node = Rc::new(RefCell::new(node));

        debug!("OpCode is {:?}", current_node.borrow().op_code);

        // end of current scope
        if current_node.borrow().op_code == IFROpCode::End {
            skipped_depth = skipped_depth.saturating_sub(1);
            depth = depth.saturating_sub(1);
            let current_scope_clone = Rc::clone(&current_scope);
            if open_forms
                .last()
                .is_some_and(|(form, _)| Rc::ptr_eq(form, &current_scope_clone))
            {
                open_forms.pop();
            }
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
            if let Some(mut disabled) =
                disabling.take_if(|disabled| Rc::ptr_eq(&disabled.form, &current_scope_clone))
            {
                // every op after the form went into its scope, so it is its parent's last child
                let mut parent = current_scope.borrow_mut();
                match parent.children.last() {
                    Some(last) if Rc::ptr_eq(last, &disabled.form) => {
                        parent.children.pop();
                    }
                    _ => {
                        return Err(anyhow!(
                            "the form disabled at offset {} of a form package is not the last op \
                             of its parent",
                            disabled.offset
                        ))
                    }
                }
                drop(parent);
                disabled.store_op = record_disabled_var_stores(&disabled.form);
                disabled_forms.push(disabled);
            }

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

        let (op_code, is_form, open_scope) = {
            let node = current_node.borrow();
            (
                node.op_code,
                matches!(node.op_code, IFROpCode::Form | IFROpCode::FormMap),
                node.open_scope,
            )
        };
        let var_store = VarStoreInDisabledForm {
            op: op_code.spec_name(),
            offset,
        };
        let is_var_store = matches!(
            op_code,
            IFROpCode::VarStore | IFROpCode::VarStoreEfi | IFROpCode::VarStoreNameValue
        );
        if is_var_store && disabling.is_some() {
            return Err(var_store.into());
        }
        if is_var_store && skipped_depth > 0 {
            unknown_scope_stores.push(offset);
        }
        if skipped_depth == 0 && disabling.is_none() {
            if let Err(failure) = decode_op(&current_node, offset) {
                let (form, form_offset) = match (is_form, open_forms.last(), is_var_store) {
                    (true, _, _) => (Rc::clone(&current_node), offset),
                    (false, Some(_), true) => return Err(var_store.into()),
                    (false, Some((form, form_offset)), false) => (Rc::clone(form), *form_offset),
                    (false, None, _) => return Err(failure.into()),
                };
                let form_set = root
                    .borrow()
                    .children
                    .first()
                    .map_or_else(|| "a FormSet".to_string(), |op| form_set_name(&op.borrow()));
                let reason = failure.disabled_form_reason(&form_name(&form.borrow()), &form_set);
                let disabled = DisabledForm {
                    offset: form_offset,
                    reason,
                    form,
                    // the one root that this parse returns
                    root_index: 0,
                    // record_disabled_var_stores finds it once the form's End is read
                    store_op: None,
                };
                debug!(
                    "disabling, at offset {}, {}",
                    disabled.offset, disabled.reason
                );
                if !open_scope && Rc::ptr_eq(&disabled.form, &current_node) {
                    disabled_forms.push(disabled);
                    continue;
                }
                disabling = Some(disabled);
            }
        }

        // add current_node to current_scope's children
        current_scope
            .borrow_mut()
            .children
            .push(Rc::clone(&current_node));
        if is_var_store {
            var_stores.push((offset, Rc::clone(&current_node)));
        }
        if skipped_depth == 0 {
            record_var_store_in_form(&current_node.borrow());
        }

        if open_scope {
            match (
                skipped_depth > 0 || skips_scope(&current_node.borrow()),
                is_form,
            ) {
                (true, _) => skipped_depth += 1,
                (false, true) => open_forms.push((Rc::clone(&current_node), offset)),
                (false, false) => {}
            }
            current_scope = Rc::clone(&current_node);
        }
    }

    Ok(ParsedFormSet {
        root,
        disabled_forms,
        unknown_scope_stores,
        var_stores,
    })
}

/// Decodes the op at `node`, at offset `offset` of its form package, unless it is shorter than the
/// minimum_length of its opcode or the required_length that its fields give it.
fn decode_op(node: &Rc<RefCell<IFROperation>>, offset: u64) -> Result<(), OpFailure> {
    let (op_code, short) = {
        let op = node.borrow();
        let minimum = Minimum {
            bytes: usize::from(op.op_code.minimum_length()),
            of: MinimumOf::Opcode,
        };
        let short = [Some(minimum), required_length(&op)]
            .into_iter()
            .flatten()
            .find(|minimum| usize::from(op.length) < minimum.bytes)
            .map(|minimum| ShortOp {
                op: op.op_code.spec_name(),
                offset,
                length: op.length,
                minimum,
            });
        (op.op_code, short)
    };
    if let Some(short) = short {
        return Err(OpFailure::Short(short));
    }
    let decoded = handle_opcode(&mut node.borrow_mut());
    decoded
        .context(format!("failed to parse op_code {op_code:?} properly"))
        .map_err(|error| {
            OpFailure::Undecoded(UndecodedOp {
                op: op_code.spec_name(),
                offset,
                detail: format!("{error:#}"),
            })
        })
}

/// The form that the FORM or FORM_MAP op `form` opens, named by its form_id, or "a form" if its
/// Length leaves none.
fn form_name(form: &IFROperation) -> String {
    match form.form_id() {
        Some(form_id) => format!("the form {form_id}"),
        None => "a form".to_string(),
    }
}

/// Why an op of a FormSet disables its form, or, outside every form, fails the FormSet.
enum OpFailure {
    /// Malformed, as UEFI 2.11 §33.2.5.10.1 calls it
    Short(ShortOp),
    Undecoded(UndecodedOp),
}

impl OpFailure {
    /// The reason of the record of the form `form` of the FormSet `form_set` that it disables.
    fn disabled_form_reason(&self, form: &str, form_set: &str) -> String {
        match self {
            Self::Short(short) => format!(
                "{form} of {form_set}, whose {} op is malformed; UEFI 2.11 §33.2.5.10.1 disables \
                 the form of a malformed op: {short}",
                short.op
            ),
            Self::Undecoded(undecoded) => format!(
                "{form} of {form_set}, whose {} op uefisettings does not decode: {undecoded}",
                undecoded.op
            ),
        }
    }
}

impl From<OpFailure> for anyhow::Error {
    fn from(failure: OpFailure) -> Self {
        match failure {
            OpFailure::Short(short) => short.into(),
            OpFailure::Undecoded(undecoded) => undecoded.into(),
        }
    }
}

/// An op shorter than the minimum_length of its opcode or the required_length of its fields, which
/// UEFI 2.11 §33.2.5.10.1 calls malformed.
#[derive(Debug, Error, PartialEq, Eq)]
#[error(
    "the {op} op at offset {offset} of a form package is {length} bytes long, shorter than \
     {minimum}"
)]
struct ShortOp {
    op: &'static str,
    offset: u64,
    length: u8,
    minimum: Minimum,
}

/// The Length below which an op is malformed, and what sets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Minimum {
    bytes: usize,
    of: MinimumOf,
}

/// What sets a Minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MinimumOf {
    /// The opcode: minimum_length
    Opcode,
    /// The field that it names: required_length
    Field(&'static str),
}

impl fmt::Display for Minimum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.of {
            MinimumOf::Opcode => write!(f, "its minimum of {}", self.bytes),
            MinimumOf::Field(field) => write!(f, "the {} bytes required by {field}", self.bytes),
        }?;
        f.write_str(" (UEFI 2.11 §33.3.8.3)")
    }
}

/// The fields of a NUMERIC or ONE_OF before its MinValue (UEFI 2.11 §33.3.8.3.47, §33.3.8.3.50).
#[derive(BinRead)]
#[br(little)]
struct NumericFlagsOp {
    _question: QuestionHeader,
    flags: u8,
}

/// The fields of a ONE_OF_OPTION before its Value (UEFI 2.11 §33.3.8.3.51).
#[derive(BinRead)]
#[br(little)]
struct OptionTypeOp {
    _option: u16,
    _flags: u8,
    option_type: u8,
}

/// The fields of a DEFAULT before its Value (UEFI 2.11 §33.3.8.3.12).
#[derive(BinRead)]
#[br(little)]
struct DefaultTypeOp {
    _default_id: u16,
    default_type: u8,
}

/// The fields of a FORM_SET before its ClassGuid (UEFI 2.11 §33.3.8.3.26).
#[derive(BinRead)]
#[br(little)]
struct FormSetFlagsOp {
    _guid: Guid,
    _title: u16,
    _help: u16,
    flags: u8,
}

/// The fields of an EQ_ID_VAL_LIST before its ValueList (UEFI 2.11 §33.3.8.3.20).
#[derive(BinRead)]
#[br(little)]
struct ListLengthOp {
    _question_id: u16,
    list_length: u16,
}

/// The Length that a field of `op` gives it where that field fixes the size of the fields after
/// it (UEFI 2.11 §33.3.8.3): of a NUMERIC or ONE_OF, the size of MinValue, MaxValue and Step that
/// its Flags give (§33.3.8.3.47, §33.3.8.3.50), or UINT32 for an EDKII bit field; of a
/// ONE_OF_OPTION or DEFAULT, that of the Value of its Type (type_value_size; §33.3.8.3.51,
/// §33.3.8.3.12); of a FORM_SET, the ClassGuids that its Flags count (§33.3.8.3.26); of an
/// EQ_ID_VAL_LIST, the ValueList entries of its ListLength (§33.3.8.3.20). None for other ops,
/// Types of no fixed size, and an op too short for that field, which minimum_length refuses.
fn required_length(op: &IFROperation) -> Option<Minimum> {
    let header = usize::from(IFR_OPERATION_HEADER_SIZE);
    let mut data = Cursor::new(&op.data);
    let (bytes, field) = match op.op_code {
        IFROpCode::Numeric | IFROpCode::OneOf => {
            let NumericFlagsOp { flags, .. } = data.parse_le().ok()?;
            let (size, field) = match ValueEncoding::from_question(op) {
                ValueEncoding::NumericSize | ValueEncoding::VarName => {
                    (numeric_size(flags), "its Flags")
                }
                ValueEncoding::EdkiiBitField => (std::mem::size_of::<u32>(), "its EDKII bit field"),
            };
            (usize::try_from(data.position()).ok()? + 3 * size, field)
        }
        IFROpCode::OneOfOption => {
            let option: OptionTypeOp = data.parse_le().ok()?;
            (
                usize::try_from(data.position()).ok()? + type_value_size(option.option_type)?,
                "its Type",
            )
        }
        IFROpCode::Default => {
            let default: DefaultTypeOp = data.parse_le().ok()?;
            (
                usize::try_from(data.position()).ok()? + type_value_size(default.default_type)?,
                "its Type",
            )
        }
        IFROpCode::FormSet => {
            let form_set: FormSetFlagsOp = data.parse_le().ok()?;
            let class_guids = usize::from(form_set.flags & EFI_IFR_FORM_SET_CLASS_GUID_COUNT);
            (
                usize::try_from(data.position()).ok()? + class_guids * std::mem::size_of::<Guid>(),
                "the ClassGuid count of its Flags",
            )
        }
        IFROpCode::EqIdValList => {
            let list: ListLengthOp = data.parse_le().ok()?;
            (
                usize::try_from(data.position()).ok()?
                    + usize::from(list.list_length) * std::mem::size_of::<u16>(),
                "its ListLength",
            )
        }
        _ => return None,
    };
    Some(Minimum {
        bytes: header + bytes,
        of: MinimumOf::Field(field),
    })
}

/// The bytes of each of the MinValue, MaxValue and Step that the Flags `flags` of a NUMERIC or
/// ONE_OF give them (UEFI 2.11 §33.3.8.3.47, §33.3.8.3.50).
fn numeric_size(flags: u8) -> usize {
    match flags & EFI_IFR_NUMERIC_SIZE {
        EFI_IFR_NUMERIC_SIZE_1 => 1,
        EFI_IFR_NUMERIC_SIZE_2 => 2,
        EFI_IFR_NUMERIC_SIZE_4 => 4,
        // EFI_IFR_NUMERIC_SIZE_8, the only value left
        EFI_IFR_NUMERIC_SIZE_8.. => 8,
    }
}

/// The bytes of the Value of Type `value_type` in an EFI_IFR_TYPE_VALUE (UEFI 2.11 §33.3.8.3.51),
/// none for EFI_IFR_TYPE_OTHER, whose value a nested EFI_IFR_VALUE gives; None for
/// EFI_IFR_TYPE_UNDEFINED and EFI_IFR_TYPE_BUFFER, whose size it does not fix, and unknown Types.
fn type_value_size(value_type: u8) -> Option<usize> {
    match value_type {
        EFI_IFR_TYPE_NUM_SIZE_8 | EFI_IFR_TYPE_BOOLEAN => Some(1),
        EFI_IFR_TYPE_NUM_SIZE_16 | EFI_IFR_TYPE_STRING | EFI_IFR_TYPE_ACTION => Some(2),
        EFI_IFR_TYPE_NUM_SIZE_32 => Some(4),
        EFI_IFR_TYPE_NUM_SIZE_64 => Some(8),
        EFI_IFR_TYPE_TIME => Some(EFI_HII_TIME_SIZE),
        EFI_IFR_TYPE_DATE => Some(EFI_HII_DATE_SIZE),
        EFI_IFR_TYPE_REF => Some(EFI_HII_REF_SIZE),
        EFI_IFR_TYPE_OTHER => Some(0),
        _ => None,
    }
}

/// A VarStore op in a form that a malformed op disables, that op or one after it: edk2-stable202608
/// ConfigKeywordHandler.c FindStorageFromVarId takes a VarStore op of a question's VarStoreId
/// wherever it is in the form package, whatever its Length, so it ignores its FormSet, whose
/// storage IgnoredPasswords::Declared withholds whole.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the {op} op at offset {offset} of a form package, in a form that uefisettings disables")]
struct VarStoreInDisabledForm {
    op: &'static str,
    offset: u64,
}

/// An op that uefisettings does not decode, though it is no shorter than the minimum_length of its
/// opcode.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("the {op} op at offset {offset} of a form package: {detail}")]
struct UndecodedOp {
    op: &'static str,
    offset: u64,
    detail: String,
}

/// Records the VarStoreId of `op`, if it is a VarStore op in the scope of a FORM or FORM_MAP, in
/// the FormSet that holds that FORM (FormSet::var_stores_in_forms).
fn record_var_store_in_form(op: &IFROperation) {
    if !matches!(
        op.op_code,
        IFROpCode::VarStore | IFROpCode::VarStoreEfi | IFROpCode::VarStoreNameValue
    ) {
        return;
    }
    let (Some((var_store_id, _)), Some(form_set)) =
        (declared_store(&op.parsed_data), form_set_of_form(op))
    else {
        return;
    };
    let mut form_set = form_set.borrow_mut();
    if let ParsedOperation::FormSet(form_set) = &mut form_set.parsed_data {
        form_set.var_stores_in_forms.insert(var_store_id);
    }
}

/// Records the VarStoreId of each VarStore op of the disabled form `form` in the FormSet that
/// holds it (FormSet::var_stores_in_disabled_forms); returns the name of its first PASSWORD or
/// VarStore op (DisabledForm::store_op).
fn record_disabled_var_stores(form: &Rc<RefCell<IFROperation>>) -> Option<&'static str> {
    let mut store_op = None;
    walk_scopes(std::slice::from_ref(form), (), |node, ()| {
        let op = node.borrow();
        if store_op.is_none()
            && matches!(
                op.op_code,
                IFROpCode::Password
                    | IFROpCode::VarStore
                    | IFROpCode::VarStoreNameValue
                    | IFROpCode::VarStoreEfi
            )
        {
            store_op = Some(op.op_code.spec_name());
        }
        if let (Some((var_store_id, _)), Some(form_set)) =
            (declared_store(&op.parsed_data), form_set_of_form(&op))
        {
            if let ParsedOperation::FormSet(form_set) = &mut form_set.borrow_mut().parsed_data {
                form_set.var_stores_in_disabled_forms.insert(var_store_id);
            }
        }
        Walk::Enter(())
    });
    store_op
}

/// The FormSet that holds `op` if a FORM or FORM_MAP of that FormSet holds `op`.
fn form_set_of_form(op: &IFROperation) -> Option<Rc<RefCell<IFROperation>>> {
    let mut in_form = false;
    let mut parent = op.parent.as_ref().and_then(Weak::upgrade);
    while let Some(node) = parent {
        let op_code = node.borrow().op_code;
        match op_code {
            IFROpCode::Form | IFROpCode::FormMap => in_form = true,
            IFROpCode::FormSet => return in_form.then_some(node),
            _ => {}
        }
        parent = node.borrow().parent.as_ref().and_then(Weak::upgrade);
    }
    None
}

fn handle_opcode(node: &mut IFROperation) -> Result<()> {
    let mut data_cursor = Cursor::new(&node.data);

    // debug!("Handling OpCode {:?}", current_node.borrow().op_code);

    match node.op_code {
        IFROpCode::FormSet => {
            let parsed: FormSet = data_cursor
                .parse_ne()
                .context("failed to parse FormSet's data")?;
            debug!("FormSet is {:?}", parsed);
            node.parsed_data = ParsedOperation::FormSet(parsed);
        }

        IFROpCode::OneOf => {
            let parsed: OneOf = data_cursor
                .parse_ne_args((ValueEncoding::from_question(node),))
                .context("failed to parse OneOf's data")?;
            debug!("OneOf is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOf(parsed);
        }
        IFROpCode::CheckBox => {
            let parsed: CheckBox = data_cursor
                .parse_ne_args((ValueEncoding::from_question(node),))
                .context("failed to parse CheckBox's data")?;
            debug!("CheckBox is {:?}", parsed);
            node.parsed_data = ParsedOperation::CheckBox(parsed);
        }
        IFROpCode::OneOfOption => {
            let parsed: OneOfOption = data_cursor
                .parse_ne()
                .context("failed to parse OneOfOption's data")?;
            debug!("OneOfOption is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOfOption(parsed);
        }
        IFROpCode::VarStore | IFROpCode::VarStoreNameValue | IFROpCode::VarStoreEfi => {
            if let Some(parsed) = decode_var_store(node)? {
                debug!("VarStore op is {:?}", parsed);
                node.parsed_data = parsed;
            }
        }
        IFROpCode::DefaultStore => {
            let parsed: DefaultStore = data_cursor
                .parse_ne()
                .context("failed to parse DefaultStore's data")?;
            debug!("DefaultStore is {:?}", parsed);
            node.parsed_data = ParsedOperation::DefaultStore(parsed);
        }
        IFROpCode::Default => {
            let parsed: IFRDefault = data_cursor
                .parse_ne()
                .context("failed to parse Default's data")?;
            debug!("Default is {:?}", parsed);
            node.parsed_data = ParsedOperation::IFRDefault(parsed);
        }
        IFROpCode::Form => {
            let parsed: Form = data_cursor
                .parse_ne()
                .context("failed to parse Form's data")?;
            debug!("Form is {:?}", parsed);
            node.parsed_data = ParsedOperation::Form(parsed);
        }
        IFROpCode::Text => {
            let parsed: Text = data_cursor
                .parse_ne()
                .context("failed to parse Text's data")?;
            debug!("Text is {:?}", parsed);
            node.parsed_data = ParsedOperation::Text(parsed);
        }
        IFROpCode::Subtitle => {
            let parsed: Subtitle = data_cursor
                .parse_ne()
                .context("failed to parse Subtitle's data")?;
            debug!("Subtitle is {:?}", parsed);
            node.parsed_data = ParsedOperation::Subtitle(parsed);
        }
        IFROpCode::Numeric => {
            let parsed: Numeric = data_cursor
                .parse_ne_args((ValueEncoding::from_question(node),))
                .context("failed to parse Numeric's data")?;
            debug!("Numeric is {:?}", parsed);
            node.parsed_data = ParsedOperation::Numeric(parsed);
        }
        IFROpCode::QuestionRef1 => {
            let parsed: QuestionRef1 = data_cursor
                .parse_ne()
                .context("failed to parse QuestionRef1's data")?;
            debug!("QuestionRef1 is {:?}", parsed);
            node.parsed_data = ParsedOperation::QuestionRef1(parsed);
        }
        IFROpCode::EqIdVal => {
            let parsed: EqIdVal = data_cursor
                .parse_ne()
                .context("failed to parse EqIdVal's data")?;
            debug!("EqIdVal is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdVal(parsed);
        }
        IFROpCode::EqIdId => {
            let parsed: EqIdId = data_cursor
                .parse_ne()
                .context("failed to parse EqIdId's data")?;
            debug!("EqIdId is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdId(parsed);
        }
        IFROpCode::EqIdValList => {
            let parsed: EqIdValList = data_cursor
                .parse_ne()
                .context("failed to parse EqIdValList's data")?;
            debug!("EqIdValList is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdValList(parsed);
        }
        // An undecoded GET, SET or FORM_MAP keeps the FormSet, whose other questions get and set
        // still reach: an evaluation refuses an undecoded GET or SET, and an undecoded FORM_MAP is
        // no standard map form.
        IFROpCode::Get => match data_cursor.parse_ne() {
            Ok(parsed) => node.parsed_data = ParsedOperation::Get(parsed),
            Err(error) => debug!("leaving a Get undecoded: {error}"),
        },
        IFROpCode::Set => match data_cursor.parse_ne() {
            Ok(parsed) => node.parsed_data = ParsedOperation::Set(parsed),
            Err(error) => debug!("leaving a Set undecoded: {error}"),
        },
        IFROpCode::FormMap => match FormMap::decode(&node.data) {
            Some(parsed) => node.parsed_data = ParsedOperation::FormMap(parsed),
            None => debug!("leaving a FormMap without a FormId undecoded"),
        },
        // A DATE or TIME too short for its fields is left undecoded, as uefisettings left every
        // DATE and TIME before it decoded them, and keeps the FormSet.
        IFROpCode::Date => {
            match data_cursor.parse_ne_args((DateTimeKind::Date, parsed_layout(node))) {
                Ok(parsed) => node.parsed_data = ParsedOperation::Date(parsed),
                Err(error) => debug!("leaving a Date undecoded: {error}"),
            }
        }
        IFROpCode::Time => {
            match data_cursor.parse_ne_args((DateTimeKind::Time, parsed_layout(node))) {
                Ok(parsed) => node.parsed_data = ParsedOperation::Time(parsed),
                Err(error) => debug!("leaving a Time undecoded: {error}"),
            }
        }
        // likewise an ORDERED_LIST, which uefisettings did not decode before either
        IFROpCode::OrderedList => match data_cursor.parse_ne_args((parsed_layout(node),)) {
            Ok(parsed) => node.parsed_data = ParsedOperation::OrderedList(parsed),
            Err(error) => debug!("leaving an OrderedList undecoded: {error}"),
        },
        // and a REF
        IFROpCode::Ref => match data_cursor.parse_ne_args((parsed_layout(node),)) {
            Ok(parsed) => node.parsed_data = ParsedOperation::Ref(parsed),
            Err(error) => debug!("leaving a Ref undecoded: {error}"),
        },
        // and a STRING
        IFROpCode::String => match data_cursor.parse_ne_args((parsed_layout(node),)) {
            Ok(parsed) => node.parsed_data = ParsedOperation::String(parsed),
            Err(error) => debug!("leaving a String undecoded: {error}"),
        },
        _ => (),
    }

    Ok(())
}

pub struct QuestionDescriptor {
    pub question: String,
    pub help: String,
    pub value: String,
    /// How set takes the text of a new value, unless it picks an option
    input: TextInput,
    opcode: IFROpCode,
    /// The Flags of its question header
    pub flags: QuestionFlags,
    /// The defaults that its IFR declares, by DefaultId ascending
    pub(crate) defaults: Vec<DeclaredDefault>,
    /// Its QuestionId, FormSet GUID and keywords
    pub(crate) identity: QuestionIdentity,
    pub possible_options: Vec<AnswerOption>,
    /// The VarStore of the question, or why set cannot write it
    varstore: Result<Box<dyn VariableStore>>,
    /// Where the question keeps its value
    location: ValueLocation,
    /// The state of the option that `value` names: selectable if none does
    pub(crate) value_state: StateEvaluation,
    /// Where `value` comes from
    pub(crate) value_source: ValueSource,
    /// The question's op, whose WRITE expression set evaluates
    node: Rc<RefCell<IFROperation>>,
    /// What get and set need if no VarStore but the question's driver holds its value
    driver_held: Option<DriverHeldQuestion>,
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

/// How set takes the text of a question's new value, unless it picks an option.
enum TextInput {
    /// A NUMERIC on bytes: a number within its range
    Range(NumericRange),
    /// A CHECKBOX, or a ONE_OF or NUMERIC on bits: a decimal number up to this maximum
    Maximum(RangeType),
    /// A DATE or TIME
    DateTime(DateTimeInput),
    /// An ORDERED_LIST, which takes options as items instead
    OrderedList(ListInput),
    /// A REF on a VarStore, whose EFI_HII_REF set does not write
    CrossReference,
    /// A STRING, which takes characters
    String(StringInput),
}

impl TextInput {
    /// Its variant, which an internal inconsistency names.
    fn kind(&self) -> TextInputKind {
        match self {
            Self::Range(_) => TextInputKind::Range,
            Self::Maximum(_) => TextInputKind::Maximum,
            Self::DateTime(_) => TextInputKind::DateTime,
            Self::OrderedList(_) => TextInputKind::OrderedList,
            Self::CrossReference => TextInputKind::CrossReference,
            Self::String(_) => TextInputKind::String,
        }
    }
}

/// The variant of a TextInput.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextInputKind {
    Range,
    Maximum,
    DateTime,
    OrderedList,
    CrossReference,
    String,
}

impl fmt::Display for TextInputKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Range => "Range",
            Self::Maximum => "Maximum",
            Self::DateTime => "DateTime",
            Self::OrderedList => "OrderedList",
            Self::CrossReference => "CrossReference",
            Self::String => "String",
        };
        write!(f, "TextInput::{name}")
    }
}

#[derive(Debug)]
pub struct AnswerOption {
    /// The option's text, as get shows it
    pub value: String,
    /// The option's text in each strings package of no configuration language that holds it,
    /// with its language: those that VALUE matches
    texts: Vec<(Language, String)>,
    /// The option's EFI_IFR_ONE_OF_OPTION Type
    value_type: u8,
    /// The option's value, or why it is not known
    raw_value: Result<TypeValue, OptionValueError>,
    /// Snapshot if the EFI_IFR_VALUE of an option of Type OTHER took a value from there
    source: ValueSource,
    pub(crate) state: StateEvaluation,
}

impl AnswerOption {
    /// The option's value as an unsigned integer; None if it is not known or not a number.
    fn as_u64(&self) -> Option<u64> {
        self.raw_value
            .as_ref()
            .ok()
            .copied()
            .and_then(TypeValue::as_u64)
    }
}

impl QuestionDescriptor {
    /// The EFI Date/Time Storage of a DATE or TIME of such storage.
    fn time_storage(&self) -> Option<TimeStorage> {
        value_question(&self.node.borrow())
            .and_then(|question| question.time_storage())
            .map(|(_, storage)| storage)
    }

    /// The VarStore of the question, or None for a question without one whose WRITE expression
    /// alone takes the value, or why set, through variables of `reach`, cannot write it.
    fn store(
        &self,
        reach: VariableReach,
    ) -> std::result::Result<Option<&dyn VariableStore>, ChangeValueError> {
        let reason = match &self.varstore {
            Ok(store) => return Ok(Some(store.as_ref())),
            Err(reason) => reason,
        };
        // its value goes to its EFI Date/Time Storage only
        if reason.downcast_ref::<TimeStorageOnly>().is_some() {
            return Ok(None);
        }
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

    /// The texts of the options of the stored items of an ORDERED_LIST, in order, as get shows
    /// them without their states; None for another question, or one whose items cannot be read.
    pub(crate) fn items(&self) -> Option<Vec<String>> {
        match &self.input {
            TextInput::OrderedList(input) => input.items(&self.possible_options),
            TextInput::Range(_)
            | TextInput::Maximum(_)
            | TextInput::DateTime(_)
            | TextInput::CrossReference
            | TextInput::String(_) => None,
        }
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

    /// The options of a text in a language of no configuration language that `names` takes,
    /// each with those languages.
    fn options_named(&self, names: impl Fn(&str) -> bool) -> Vec<(&AnswerOption, OptionMatch)> {
        self.possible_options
            .iter()
            .filter_map(|option| {
                let languages: Vec<String> = option
                    .texts
                    .iter()
                    .filter(|(_, text)| names(text))
                    .map(|(language, _)| language.to_string())
                    .collect();
                let named = OptionMatch {
                    option: option.value.clone(),
                    languages,
                };
                (!named.languages.is_empty()).then_some((option, named))
            })
            .collect()
    }

    /// The texts of the options that `include` certainly allows: those that get lists and set
    /// takes, each whose value is not known with why.
    pub(crate) fn listed_options(&self, include: IncludedStates) -> Vec<String> {
        self.possible_options
            .iter()
            .filter(|option| option.state.is_allowed(include))
            .map(|option| match &option.raw_value {
                Ok(_) => option.value.clone(),
                Err(reason) => format!("{} <ValueUnavailable: {reason}>", option.value),
            })
            .collect()
    }

    /// Returns the option that select() picks with `include` among those whose text in a
    /// language of no configuration language is one of `texts` ignoring ASCII case, or, if there
    /// are none, among those whose text is one of `texts` ignoring surrounding whitespace too
    /// (get shows the text trimmed), or None if there are none either. So a text as stored never
    /// picks an option that differs from it only by such whitespace. Refuses with
    /// SelectionError::AmbiguousOption options that no one language names all.
    pub(crate) fn select_option(
        &self,
        texts: &BTreeSet<String>,
        include: IncludedStates,
    ) -> std::result::Result<Option<&AnswerOption>, SelectionError> {
        let stored =
            self.options_named(|text| texts.iter().any(|named| named.eq_ignore_ascii_case(text)));
        let candidates = if stored.is_empty() {
            self.options_named(|text| {
                texts
                    .iter()
                    .any(|named| named.trim().eq_ignore_ascii_case(text.trim()))
            })
        } else {
            stored
        };
        let language_sets: Vec<&[String]> = candidates
            .iter()
            .map(|(_, named)| named.languages.as_slice())
            .collect();
        if !share_a_language(&language_sets) {
            return Err(SelectionError::AmbiguousOption {
                question: self.question.clone(),
                matches: candidates.into_iter().map(|(_, named)| named).collect(),
            });
        }
        self.pick_option(
            candidates.into_iter().map(|(option, _)| option).collect(),
            include,
        )
    }

    /// Returns the option of `candidates`, in IFR order, that select() picks with `include`, or
    /// None if there are none.
    fn pick_option<'a>(
        &self,
        candidates: Vec<&'a AnswerOption>,
        include: IncludedStates,
    ) -> std::result::Result<Option<&'a AnswerOption>, SelectionError> {
        let matches: Vec<(&AnswerOption, StateEvaluation)> = candidates
            .into_iter()
            .map(|option| (option, option.state.clone()))
            .collect();
        let Some(&(first, _)) = matches.first() else {
            return Ok(None);
        };
        let question = self.question.clone();
        match select(matches, include) {
            Selection::Picked {
                picked: (option, _),
                ..
            } => Ok(Some(option)),
            Selection::Undetermined {
                likely: (option, _),
                reasons,
                states,
                ..
            } => Err(SelectionError::OptionUndetermined {
                question,
                option: option.value.clone(),
                states,
                reasons,
            }),
            Selection::Excluded(exclusion) => {
                Err(exclusion.option_error(question, first.value.clone()))
            }
            Selection::NotFound => Ok(None),
        }
    }
}

// list_questions returns a list of QuestionDescriptors in a FormSet
// with their states, of the questions in a state that `include` may allow
// node should be the root of a FormSet
// conditions read `access_level`, if stated, for AMI_ACCESS_LEVEL instead of its value
pub(crate) fn list_questions(
    node: Rc<RefCell<IFROperation>>,
    texts: &ListTexts<'_>,
    include: IncludedStates,
    access_level: Option<AccessLevel>,
    reader: &mut EfivarReader,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let values = VarStoreValues::new(&node, access_level);
    list_questions_in(
        &node,
        &mut FormSetWalk::new(texts, reader, &values, include),
    )
}

/// What walking the ops of a FormSet takes besides them.
struct FormSetWalk<'a, V> {
    /// The texts of the FormSet's package list, which no expression reads
    texts: &'a ListTexts<'a>,
    default_stores: FormSetDefaultStores,
    inputs: ExpressionInputs<'a, V>,
    include: IncludedStates,
}

impl<'a, V> FormSetWalk<'a, V> {
    fn new(
        texts: &'a ListTexts<'a>,
        reader: &'a mut EfivarReader,
        values: &'a V,
        include: IncludedStates,
    ) -> Self {
        Self {
            texts,
            default_stores: FormSetDefaultStores::default(),
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

/// Returns the QuestionDescriptor and states of a ListedQuestion, in a state that `walk.include`
/// may allow.
fn listed_question(
    question: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Option<(QuestionDescriptor, StateEvaluation)> {
    let op = question.borrow();
    let listed = ListedQuestion::of(&op)?;
    let state = question_state(&op, &mut walk.inputs);
    if !state.may_be_allowed(walk.include) {
        return None;
    }
    let descriptor = describe_question(question, listed, walk);
    Some((descriptor, state))
}

/// find_question accepts the root node, texts and what to match questions by: by prompt, a set
/// of strings which represent variations of the same question, so if a single phrase matches
/// then we assume that we have the answer; or by QuestionId or keyword (QuestionMatch).
/// Of the matching questions, it selects one as select does, with conditions reading
/// `access_level`, if stated, for AMI_ACCESS_LEVEL instead of its value.
pub(crate) fn find_question<T>(
    node: Rc<RefCell<IFROperation>>,
    texts: &ListTexts<'_>,
    matching: &QuestionMatch<'_, T>,
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
        matching,
        &mut FormSetWalk::new(texts, reader, &values, include),
    )
}

/// Finds a question as find_question does, with `walk`.
fn find_question_in<T>(
    node: &Rc<RefCell<IFROperation>>,
    matching: &QuestionMatch<'_, T>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Selection<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let questions = questions_matching(node, walk.texts, matching);
    let ops: Vec<std::cell::Ref<IFROperation>> =
        questions.iter().map(|question| question.borrow()).collect();
    let matches = questions
        .iter()
        .zip(&ops)
        .filter_map(|(question, op)| {
            let listed = ListedQuestion::of(op)?;
            let state = question_state(op, &mut walk.inputs);
            Some(((question, listed), state))
        })
        .collect();
    select(matches, walk.include)
        .map(|(question, listed)| describe_question(question, listed, walk))
}

/// The questions under the root `node` of a FormSet whose prompt is one of
/// `possible_question_phrases` in a language of `texts`, as find_question finds them, for
/// check_prompt_language.
pub(crate) fn prompt_matches<T>(
    node: &Rc<RefCell<IFROperation>>,
    texts: &ListTexts<'_>,
    possible_question_phrases: &BTreeSet<T>,
) -> Vec<PromptMatch>
where
    T: AsRef<str>,
{
    questions_named(node, texts, possible_question_phrases)
        .into_iter()
        .map(|named| named.prompt)
        .collect()
}

/// Refuses with SelectionError::Ambiguous the `statements` of the keyword `question` whose
/// ListedQuestions are of more than one NAMESPACE, naming each: a
/// NAMESPACE "is equivalent to the platform configuration language being used for the keyword
/// definition" (UEFI 2.11 §35.2.1.6), so they would be settings of different definitions.
pub(crate) fn check_keyword_namespace(
    question: &str,
    statements: &[KeywordStatement<'_>],
) -> std::result::Result<(), SelectionError> {
    let matches: Vec<PromptMatch> = statements
        .iter()
        .filter_map(|statement| {
            let op = statement.op().borrow();
            let header = ListedQuestion::of(&op)?.header();
            Some(PromptMatch {
                question_id: header.question_id,
                form_set: form_set_guid(&op),
                languages: vec![statement.namespace().to_string()],
            })
        })
        .collect();
    let first = matches.first().map(|named| &named.languages);
    match matches.iter().all(|named| Some(&named.languages) == first) {
        true => Ok(()),
        false => Err(SelectionError::Ambiguous {
            question: question.to_owned(),
            matches,
        }),
    }
}

/// Refuses `address` with SelectionError::SharedQuestionId if two or more questions under the
/// root `node` of a FormSet hold it, naming them by their prompts in `texts`: find_question
/// would select one of them.
pub(crate) fn check_address_unique(
    node: &Rc<RefCell<IFROperation>>,
    texts: &ListTexts<'_>,
    address: &QuestionAddress,
) -> std::result::Result<(), SelectionError> {
    let questions = questions_addressed(node, address);
    if questions.len() < 2 {
        return Ok(());
    }
    Err(SelectionError::SharedQuestionId {
        question: QuestionSelector::Address(*address).to_string(),
        prompts: questions
            .iter()
            .filter_map(|question| {
                let op = question.borrow();
                ListedQuestion::of(&op)
                    .map(|question| texts.display(question.header().prompt_string_id))
            })
            .map(str::to_owned)
            .collect(),
    })
}

/// Refuses `question` with SelectionError::Ambiguous unless one language holds it as the prompt
/// of each of `matches`, the questions that it names in every FormSet: a QUESTION in the
/// language of one question could otherwise select another, whose prompt in another language
/// it is.
pub(crate) fn check_prompt_language(
    question: &str,
    matches: Vec<PromptMatch>,
) -> std::result::Result<(), SelectionError> {
    let language_sets: Vec<&[String]> = matches
        .iter()
        .map(|named| named.languages.as_slice())
        .collect();
    match share_a_language(&language_sets) {
        true => Ok(()),
        false => Err(SelectionError::Ambiguous {
            question: question.to_owned(),
            matches,
        }),
    }
}

/// Who writes a question that EFI_IFR_FLAG_READ_ONLY makes read-only.
pub(crate) enum ReadOnlyWriter<'a> {
    /// set, which takes the write in as an unsafe operation, done only with
    /// UnsafeOperations::Allow
    Set(&'a mut PendingOperations),
    /// The Keyword Handler, which refuses it: "trying to write a read-only element" is "a
    /// violation of system policy", for which SetData() sets KEYWORD_HANDLER_ACCESS_NOT_PERMITTED
    /// (UEFI 2.11 §35.3.2), as edk2-stable202608 EfiConfigKeywordHandlerSetData does
    /// (ConfigKeywordHandler.c:3033-3047)
    KeywordHandler,
}

impl ReadOnlyWriter<'_> {
    /// Takes in the write of `question`, which EFI_IFR_FLAG_READ_ONLY makes read-only, or refuses
    /// it; including the states `ranked_before` selects a writable match instead.
    fn write_read_only(
        self,
        question: String,
        ranked_before: IncludedStates,
    ) -> std::result::Result<(), ChangeValueError> {
        match self {
            Self::Set(pending) => {
                pending.add(UnsafeOperation::ReadOnlyQuestion {
                    question,
                    writable: ranked_before,
                });
                Ok(())
            }
            Self::KeywordHandler => Err(ChangeValueError::ReadOnly {
                question,
                cause: ReadOnlyCause::Flag,
                ranked_before,
            }),
        }
    }

    /// The states of `ranked_before` that select a match that this writes: a writable one, or
    /// also one that EFI_IFR_FLAG_READ_ONLY makes read-only where it writes those.
    fn selecting_written(&self, ranked_before: RankedBefore) -> IncludedStates {
        match self {
            Self::Set(pending) if pending.grant() == UnsafeOperations::Allow => {
                ranked_before.writable | ranked_before.flag_read_only
            }
            Self::Set(_) | Self::KeywordHandler => ranked_before.writable,
        }
    }
}

/// set's choice of the selection of a FormSet: that of Selection::for_set, unless the match that
/// set would write, or the likely match, has no VarStore, or its efivar is missing, unreadable,
/// e.g. withheld, boot-service-only, volatile or authenticated, which --include cannot make
/// writable: then ChangeValueError::NoVarStore, DeclaredBootServiceOnly, VariableNotExported or
/// the read's error, as `reader` found it, BootServiceOnlyVariable, VolatileVariable or
/// AuthenticatedVariable; or is read-only by an EFI_IFR_VALUE, which nothing makes writable:
/// then ChangeValueError::ReadOnly. A chosen match that EFI_IFR_FLAG_READ_ONLY makes read-only
/// goes to `writer` after these refusals and those of Selection::for_set.
pub(crate) fn choice_for_set(
    selection: Selection<QuestionDescriptor>,
    question: &str,
    options: &SetOptions,
    writer: ReadOnlyWriter<'_>,
    reader: &EfivarReader,
) -> Result<Choice<QuestionDescriptor>> {
    // the WRITE expression of a question without a VarStore names the stores that set writes
    if let Some(((descriptor, _), _)) = selection.written_or_likely() {
        if let Some(store) = descriptor.store(reader.reach())? {
            check_writable(store, reader, options.volatile)?;
        }
    }
    read_only_choice(selection, question, writer)
}

/// The choice of Selection::for_set, unless the match that set would write, or the likely match,
/// is read-only by an EFI_IFR_VALUE, which nothing makes writable: then
/// ChangeValueError::ReadOnly. A chosen match that EFI_IFR_FLAG_READ_ONLY makes read-only goes to
/// `writer` after these refusals and those of Selection::for_set. choice_for_set checks the
/// efivar of the match first; set takes this choice alone for a question whose driver holds its
/// value, which has none.
pub(crate) fn read_only_choice(
    selection: Selection<QuestionDescriptor>,
    question: &str,
    writer: ReadOnlyWriter<'_>,
) -> Result<Choice<QuestionDescriptor>> {
    let Some(((descriptor, evaluation), ranked_before)) = selection.written_or_likely() else {
        return Ok(selection.for_set(question)?);
    };
    let name = descriptor.question.clone();
    match evaluation.read_only() {
        Some(cause @ ReadOnlyCause::ValueExpression) => Err(ChangeValueError::ReadOnly {
            question: name,
            cause,
            ranked_before: writer.selecting_written(ranked_before),
        }
        .into()),
        Some(ReadOnlyCause::Flag) => {
            let choice = selection.for_set(question)?;
            writer.write_read_only(name, ranked_before.writable)?;
            Ok(choice)
        }
        None => Ok(selection.for_set(question)?),
    }
}

/// Refuses `store` unless set may write its variable, which `reader` has read (check_read).
fn check_writable(
    store: &dyn VariableStore,
    reader: &EfivarReader,
    volatile: VolatileWrites,
) -> Result<()> {
    match reader.outcome(store) {
        Some(read) => check_read(store, read, (reader.reach(), reader.interface()), volatile),
        None => Ok(()),
    }
}

/// Refuses `store` unless set may write its variable, whose read through variables of `reach`
/// and `interface` gave `read`: one that the read failed for, unless it is missing and set
/// creates it (created_attributes), or whose attributes, or those that set creates it with, set
/// does not write, a volatile one unless `volatile` allows it (check_volatile_write), an
/// authenticated, or, at OS runtime, boot-service-only variable.
fn check_read(
    store: &dyn VariableStore,
    read: std::result::Result<&[u8], &anyhow::Error>,
    (reach, interface): (VariableReach, VariableInterface),
    volatile: VolatileWrites,
) -> Result<()> {
    let attributes = match read {
        Ok(bytes) => efivar_attributes(bytes),
        Err(error) => match (
            error.is::<VariableNotFound>(),
            created_attributes(store, reach, interface),
        ) {
            (true, Some(attributes)) => Some(attributes),
            (true, None) | (false, _) => return Err(unwritable(store, error, reach, interface)),
        },
    };
    if let Some(attributes) = attributes {
        let key = store.variable_key();
        check_volatile_write(&key, interface, reach, volatile, attributes)?;
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
    // set writes no authenticated variable, whether or not get decodes it
    if let Some(refused) = error.downcast_ref::<EnhancedAuthenticatedVariable>() {
        if let Err(authenticated) = check_unauthenticated(&store.variable_key(), refused.attributes)
        {
            return authenticated.into();
        }
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
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::unsafe_operations::UnsafeOperations;

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
            &QuestionMatch::Prompt(&BTreeSet::from([PROMPT])),
            &mut FormSetWalk::new(
                &ListTexts::new(&strings(), &[]),
                &mut reader,
                &values,
                IncludedStates::empty(),
            ),
        );
        choice_for_set(
            selection,
            PROMPT,
            &SetOptions::default(),
            ReadOnlyWriter::Set(&mut PendingOperations::new(UnsafeOperations::Refuse)),
            &reader,
        )
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
            matches!(
                user,
                Ok(Choice::Skipped(exclusion)) if exclusion.states == IncludedStates::GRAYED_OUT
            ),
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

    /// set refuses a question on a VARSTORE_EFI of the form before UEFI 2.3.1 whose VarName no
    /// string holds, with why.
    #[test]
    fn match_on_a_var_store_efi_before_uefi_2_3_1_is_refused() {
        let choice = choice_in(&parse_form_set(&[
            short_var_store_efi(7),
            form(1, &[checkbox_on(1, 3, 7)]),
        ]));
        assert_eq!(
            choice.map_err(|error| error.to_string()).err().as_deref(),
            Some(
                "cannot set question \"Prompt\": VarStore 0x0007 (EFI_IFR_VARSTORE_EFI before \
                 UEFI 2.3.1): no string 0x0000 holds its VarName"
            ),
            "question 1 on VarStore 7"
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
                ": the firmware has not created it, and set creates only the per-question \
                 variables of an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1",
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
                "set creates only the per-question variables",
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
                ", so a write would not outlast a power cycle; pass --allow-volatile to write it \
                 anyway",
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
    /// write of it needs a signed descriptor (UEFI 2.10 §8.2.3). With
    /// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, it does so whether or not get accepts its
    /// metadata.
    #[test]
    fn match_on_an_authenticated_efivar_is_refused() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        let refusal = |attributes: u32| {
            format!(
                "EFI variable Present-00000000-0000-0000-0000-000000000000 has authenticated \
                 access (attributes {attributes:#x}), which uefisettings does not write"
            )
        };
        for attributes in [NV_BS_RT | 0x10, NV_BS_RT | 0x20, NV_BS_RT | 0x80] {
            let signed = choice_attributed(&root, attributes);

            assert_eq!(
                signed.map_err(|error| error.to_string()).err(),
                Some(refusal(attributes)),
                "efivar file with attributes {attributes:#x}"
            );
        }
        let efivars = Efivars::new();
        efivars.write_attributed(
            &efi_variable("Present", 1),
            NV_BS_RT | 0x80,
            &[&timestamp_metadata()[..], &[0]].concat(),
        );

        assert_eq!(
            choice_with(&root, &efivars)
                .map_err(|error| error.to_string())
                .err(),
            Some(refusal(NV_BS_RT | 0x80)),
            "efivar file with attributes 0x87 and metadata"
        );
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

// display returns the lines of our tree like representation of a FormSet
// TODO: show the default of an unreadable OneOf, Numeric or CheckBox, as list_questions does.
// TODO: show the state that the conditions give each question and option, as list-questions
// does.
pub(crate) fn display(
    node: Rc<RefCell<IFROperation>>,
    level: usize,
    texts: &ListTexts<'_>,
    reader: &mut EfivarReader,
) -> Result<TextLines> {
    let mut lines = Vec::new();
    let values = VarStoreValues::new(&node, None);
    let mut inputs = ExpressionInputs {
        reader,
        values: &values,
    };
    walk_scopes(std::slice::from_ref(&node), level, |node, &level| {
        display_op(node, level, texts, &mut inputs, &mut lines)
    });
    Ok(TextLines(lines))
}

/// Appends the lines of `node` that display shows `level` scopes down to `lines`, each on its
/// own, so that a line break in a text that a line shows stays in that line; and enters its
/// scope unless edk2 skips it.
fn display_op(
    node: &Rc<RefCell<IFROperation>>,
    level: usize,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    lines: &mut Vec<String>,
) -> Walk<usize> {
    let extra_spaces = "    ".repeat(level);

    let current_node = node.borrow();
    if let IFROpCode::Unknown(code) = current_node.op_code {
        if skips_scope(&current_node) {
            lines.push(format!(
                "{extra_spaces}OpCode: Unknown({code:#04x}) - skipped, as edk2 does"
            ));
            return Walk::Skip;
        }
    }

    match &current_node.parsed_data {
        // every op that handle_form_set parses has a parent; the root has none
        ParsedOperation::Placeholder if current_node.parent.is_none() => {
            lines.push(format!("{extra_spaces}OpCode: ROOT"))
        }
        ParsedOperation::Subtitle(parsed) => lines.push(format!(
            "{extra_spaces}OpCode: {:?} - S: {}",
            current_node.op_code,
            texts.display(parsed.prompt_string_id),
        )),
        ParsedOperation::FormSet(parsed) => lines.push(format!(
            "{extra_spaces}OpCode: {:?} - {} - GUID {}{}",
            current_node.op_code,
            texts.display(parsed.title_string_id),
            parsed.guid,
            parsed
                .class_guids
                .iter()
                .map(|class_guid| format!(" - ClassGUID {class_guid}"))
                .collect::<String>(),
        )),
        ParsedOperation::VarStore(parsed) => lines.push(format!(
            "{extra_spaces}OpCode: {:?} - Name: {}",
            current_node.op_code, parsed.name,
        )),
        ParsedOperation::VarStoreNameValue(parsed) => lines.push(format!(
            "{extra_spaces}OpCode: {:?} - Id: {} - Guid: {}",
            current_node.op_code, parsed.var_store_id, parsed.guid,
        )),
        ParsedOperation::OneOfOption(parsed) => {
            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - S: {}",
                current_node.op_code,
                texts.display(parsed.option_string_id),
            ));
            lines.push(format!("{extra_spaces}-ValueType:{}", parsed.value_type));
            lines.push(format!("{extra_spaces}-Value:{:?}", parsed.value));
        }

        ParsedOperation::OneOf(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}",
                current_node.op_code,
                texts.display(parsed.question_header().prompt_string_id),
                texts.display(parsed.question_header().help_string_id),
            ));
            lines.push(format!("{extra_spaces}-{:?}", parsed.data));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }
        ParsedOperation::Numeric(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}",
                current_node.op_code,
                texts.display(parsed.question_header().prompt_string_id),
                texts.display(parsed.question_header().help_string_id),
            ));
            lines.push(format!("{extra_spaces}-{:?}", parsed.data));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }
        ParsedOperation::CheckBox(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: - {} - Help: - {}",
                current_node.op_code,
                texts.display(parsed.question_header().prompt_string_id),
                texts.display(parsed.question_header().help_string_id),
            ));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }

        ParsedOperation::Date(parsed) | ParsedOperation::Time(parsed) => {
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(node, &varstore, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}",
                current_node.op_code,
                texts.display(parsed.question_header().prompt_string_id),
                texts.display(parsed.question_header().help_string_id),
            ));
            lines.push(format!("{extra_spaces}-Flags: {:#04x}", parsed.flags));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }

        ParsedOperation::OrderedList(parsed) => {
            let header = parsed.question_header();
            let varstore = find_corresponding_varstore(Rc::clone(node), header.var_store_id);
            let question = OrderedListQuestion::of(&current_node, parsed);
            let answer_disp = display_list_answer(node, question, &varstore, texts, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}",
                current_node.op_code,
                texts.display(header.prompt_string_id),
                texts.display(header.help_string_id),
            ));
            lines.push(format!(
                "{extra_spaces}-MaxContainers: {} - Flags: {:#04x}",
                parsed.max_containers, parsed.flags
            ));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }

        ParsedOperation::Ref(parsed) if parsed.question_header.var_store_id != 0 => {
            let header = parsed.question_header();
            let varstore = find_corresponding_varstore(Rc::clone(node), header.var_store_id);
            let answer_disp = display_ref_answer(node, &varstore, texts, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}",
                current_node.op_code,
                texts.display(header.prompt_string_id),
                texts.display(header.help_string_id),
            ));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }

        ParsedOperation::String(parsed) => {
            let header = parsed.question_header();
            let varstore = find_corresponding_varstore(Rc::clone(node), header.var_store_id);
            let answer_disp = display_string_answer(node, &varstore, inputs);

            lines.push(format!(
                "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}",
                current_node.op_code,
                texts.display(header.prompt_string_id),
                texts.display(header.help_string_id),
            ));
            lines.push(format!(
                "{extra_spaces}-MinSize: {} - MaxSize: {} - Flags: {:#04x}",
                parsed.min_size, parsed.max_size, parsed.flags
            ));
            lines.push(format!("{extra_spaces}-Answer: {answer_disp}"));
        }

        // TODO: we have already made structs for the most popular opcodes so we should finish the display function for them
        // however display is only for debugging and a visual representation of the forms for humans
        _ => lines.push(format!("{extra_spaces}OpCode: {:?}", current_node.op_code)),
    }

    Walk::Enter(level + 1)
}

/// Returns the answer that show-ifr shows: the question's value, tagged with where it comes
/// from, or why it cannot be read.
fn display_answer(
    question: &Rc<RefCell<IFROperation>>,
    varstore: &Result<Box<dyn VariableStore>>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> String {
    match retrieve_question_value(question, varstore, inputs) {
        Err(reason) => reason.to_answer(),
        Ok(retrieved) => {
            let value = match value_question(&question.borrow()) {
                Some(ValueQuestion::DateTime(parsed)) => parsed.format().text(retrieved.value),
                Some(
                    ValueQuestion::OneOf(_)
                    | ValueQuestion::Numeric(_)
                    | ValueQuestion::CheckBox(_),
                )
                | None => retrieved.value.to_string(),
            };
            format!("{value}{}", retrieved.source.annotation())
        }
    }
}

/// find_corresponding_varstore bubble's up from current node till we find a FormSet.
/// then it looks for varstores that the FormSet declares (form_set_varstore)
fn find_corresponding_varstore(
    node: Rc<RefCell<IFROperation>>,
    var_store_id: u16,
) -> Result<Box<dyn VariableStore>> {
    if var_store_id == 0 {
        let storage = value_question(&node.borrow()).and_then(|question| question.time_storage());
        if let Some((_, storage)) = storage {
            return Err(TimeStorageOnly(storage).into());
        }
        return Err(match StoragelessQuestion::of(&node) {
            Some(question) => NoVarStore(question).into(),
            None => anyhow!(
                "{} has VarStoreId 0 and no value that uefisettings decodes",
                node.borrow().op_code.spec_name()
            ),
        });
    }

    let question = Rc::clone(&node);
    let mut node = node;
    loop {
        let parent = {
            let current_node = node.borrow();
            if current_node.op_code == IFROpCode::FormSet {
                return form_set_varstore(&current_node, var_store_id, &question.borrow());
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

/// Returns the varstore of `var_store_id` that `form_set` declares (declared_var_store), as
/// `question` reads it: of a VARSTORE_EFI before UEFI 2.3.1, the EFI variable of its VarName.
fn form_set_varstore(
    form_set: &IFROperation,
    var_store_id: u16,
    question: &IFROperation,
) -> Result<Box<dyn VariableStore>> {
    match declared_var_store(form_set, var_store_id)? {
        Some(DeclaredStore::Variable(store)) => Ok(store),
        Some(DeclaredStore::NameValue(guid)) => Err(NameValueStore { guid }.into()),
        Some(DeclaredStore::ShortEfi(store)) => Ok(Box::new(short_efi_variable(&store, question)?)),
        None => Err(undeclared_var_store(var_store_id)),
    }
}

/// Why a question of `var_store_id` has no store.
fn undeclared_var_store(var_store_id: u16) -> anyhow::Error {
    anyhow!("no supported varstore with matching id {var_store_id:#06x} found")
}

/// The EFI variable of `question` on the VARSTORE_EFI before UEFI 2.3.1 `store`: of a ONE_OF,
/// NUMERIC, CHECKBOX, DATE or TIME, whose value ValueEncoding::VarName places at byte 0, as wide
/// as the value; of a STRING, ORDERED_LIST or REF, as wide as its StorageWidth (buffer_var_name).
/// That of a PASSWORD has no width (short_password_variable).
fn short_efi_variable(
    store: &ShortVarStoreEfi,
    question: &IFROperation,
) -> Result<ShortEfiVariable, ShortEfiRefusal> {
    let id = store.var_store_id;
    let (var_name, size) = match value_question(question) {
        Some(value_question) => match (value_question.encoding(), value_question.location()) {
            (ValueEncoding::VarName, ValueLocation::Bytes { size, .. }) => {
                (value_question.header().var_store_info, size)
            }
            (ValueEncoding::EdkiiBitField, _)
            | (ValueEncoding::VarName, ValueLocation::Bits { .. }) => {
                return Err(ShortEfiRefusal::new(id, ShortEfiReason::BitField))
            }
            // the store was not declared yet when the question was parsed
            (ValueEncoding::NumericSize, _) => {
                return Err(ShortEfiRefusal::new(id, ShortEfiReason::DeclaredAfter))
            }
        },
        None => buffer_var_name(question).map_err(|reason| ShortEfiRefusal::new(id, reason))?,
    };
    store
        .variable(var_name, size)
        .map_err(|unresolved| ShortEfiRefusal::new(id, unresolved.into()))
}

/// The VarName of the STRING, ORDERED_LIST or REF `question` on a VARSTORE_EFI before UEFI 2.3.1,
/// and the StorageWidth of edk2-stable202608 SetupBrowserDxe/IfrParse.c that its variable holds
/// whole, as Setup.c GetQuestionValue and SetQuestionValue read and write it (:1764-1782,
/// :2061-2077): the bytes of the location of an ORDERED_LIST, MaxContainers containers (:2492),
/// or of a REF, an EFI_HII_REF (:2041); of a STRING, MaxSize CHAR16s (:2225). An ORDERED_LIST
/// without options has none. An ORDERED_LIST, REF or STRING parsed before the store took its
/// VarStoreInfo for a VarOffset.
fn buffer_var_name(question: &IFROperation) -> Result<(u16, u16), ShortEfiReason> {
    let (header, layout, location) = match &question.parsed_data {
        ParsedOperation::OrderedList(list) => {
            let ordered_list = OrderedListQuestion::of(question, list);
            if !ordered_list.has_options() {
                return Err(ShortEfiReason::NoOptions);
            }
            (list.question_header, list.layout, ordered_list.location())
        }
        ParsedOperation::Ref(reference) => (
            reference.question_header,
            reference.layout,
            reference.location(),
        ),
        ParsedOperation::String(string) => {
            (string.question_header, string.layout, string.location())
        }
        ParsedOperation::Placeholder
        | ParsedOperation::FormSet(_)
        | ParsedOperation::OneOf(_)
        | ParsedOperation::CheckBox(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::VarStore(_)
        | ParsedOperation::VarStoreNameValue(_)
        | ParsedOperation::VarStoreEfi(_)
        | ParsedOperation::ShortVarStoreEfi(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::Numeric(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Get(_)
        | ParsedOperation::Set(_)
        | ParsedOperation::FormMap(_)
        | ParsedOperation::Date(_)
        | ParsedOperation::Time(_) => return Err(not_read(question)),
    };
    let size = match location {
        ValueLocation::Bytes { size, .. } => size,
        // no ORDERED_LIST, REF or STRING is an EDKII bit varstore field
        ValueLocation::Bits { .. } => return Err(not_read(question)),
    };
    match layout {
        VariableLayout::OneValue => Ok((header.var_store_info, size)),
        // the store was not declared yet when the question was parsed
        VariableLayout::Offsets => Err(ShortEfiReason::DeclaredAfter),
    }
}

/// Why get and set read no value of `question` on a VARSTORE_EFI before UEFI 2.3.1.
fn not_read(question: &IFROperation) -> ShortEfiReason {
    ShortEfiReason::NotRead(question.op_code.spec_name())
}

/// A VarStore that a FormSet, or an op outside any, declares.
enum DeclaredStore {
    /// A VARSTORE or VARSTORE_EFI, which an EFI variable of its Name and Guid holds; UEFI 2.11
    /// §33.2.5.6 makes the EFI variable a specialized form of Buffer Storage
    Variable(Box<dyn VariableStore>),
    /// A VARSTORE_NAME_VALUE of the Guid, whose values only the driver's
    /// EFI_HII_CONFIG_ACCESS_PROTOCOL reaches
    NameValue(Guid),
    /// A VARSTORE_EFI of the form before UEFI 2.3.1, whose ops each name an EFI variable by their
    /// VarName
    ShortEfi(ShortVarStoreEfi),
}

/// Returns the VarStore of `var_store_id` that `form_set` declares where edk2 creates it, if any:
/// the first of the id that form_set_list_var_stores meets. Why not, if that one may not be
/// created, or if a VarStore op of the id in a FORM or FORM_MAP of the FormSet comes before it,
/// or is in a form that handle_form_set disables, whose place it does not keep:
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes creates that one too (:1873-1884,
/// :477), and CreateQuestion binds a question to the first of the id (:136-145).
fn declared_var_store(form_set: &IFROperation, var_store_id: u16) -> Result<Option<DeclaredStore>> {
    let found = form_set_list_var_stores(form_set, |op, creation, forms_before| {
        let (id, store) = declared_store(&op.parsed_data)?;
        (id == var_store_id).then(|| (creation.clone(), store, forms_before.to_vec()))
    });
    let Some((creation, store, forms_before)) = found else {
        return Ok(None);
    };
    let form_first = match &form_set.parsed_data {
        ParsedOperation::FormSet(form_set)
            if !form_set.var_stores_in_forms.contains(&var_store_id) =>
        {
            None
        }
        _ => forms_before
            .iter()
            .find_map(|form| declares_in_scope(form, var_store_id)),
    };
    if let Some(form) = form_first {
        return Err(anyhow!(
            "VarStore {var_store_id:#06x} is declared in an {form} of its FormSet before the one \
             of its form-set-list: edk2 creates both and binds a question to the first \
             (SetupBrowserDxe/IfrParse.c:1873-1884, :136-145)"
        ));
    }
    if let ParsedOperation::FormSet(form_set) = &form_set.parsed_data {
        if form_set
            .var_stores_in_disabled_forms
            .contains(&var_store_id)
        {
            return Err(anyhow!(
                "VarStore {var_store_id:#06x} is declared in a form of its FormSet that \
                 uefisettings disables, before or after the one of its form-set-list: edk2 creates \
                 both and binds a question to the first (SetupBrowserDxe/IfrParse.c:1873-1884, \
                 :136-145)"
            ));
        }
    }
    match creation {
        Creation::Created => Ok(Some(store)),
        Creation::Undetermined(Undetermined::DisableIf(reason)) => Err(anyhow!(
            "VarStore {var_store_id:#06x} is declared in the scope of a DISABLE_IF of its FormSet \
             whose condition is not known: {reason}"
        )),
        Creation::Undetermined(Undetermined::Hiding(hiding)) => Err(anyhow!(
            "VarStore {var_store_id:#06x} follows an {} in the scope of a DISABLE_IF of its \
             FormSet, whose condition is {}: edk2-stable202608 SetupBrowserDxe/IfrParse.c takes \
             that condition for the DISABLE_IF's, which may skip the rest of its scope \
             (:1690-1704, :3045-3059), where UEFI 2.11 §33.3.8.3.75 has it only hide",
            hiding.op,
            hiding.condition()
        )),
    }
}

/// The spec name of the FORM or FORM_MAP `form` if a VarStore op of `var_store_id` is in its
/// scope, which edk2 parses whatever the ops around it there, but those of unknown ops.
fn declares_in_scope(form: &Rc<RefCell<IFROperation>>, var_store_id: u16) -> Option<&'static str> {
    let declared = try_walk_scopes(&form.borrow().children, (), |node, ()| {
        let op = node.borrow();
        if skips_scope(&op) {
            return Ok(Walk::Skip);
        }
        match declared_store(&op.parsed_data) {
            Some((id, _)) if id == var_store_id => Err(()),
            Some(_) | None => Ok(Walk::Enter(())),
        }
    });
    declared.is_err().then(|| form.borrow().op_code.spec_name())
}

#[cfg(test)]
thread_local! {
    /// The calls of declared_store on this thread, which tests of the bound on PasswordQuestions'
    /// reads of VarStores count.
    pub(crate) static DECLARATIONS_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The VarStoreId that the op of `parsed` declares and its VarStore, if it declares one.
fn declared_store(parsed: &ParsedOperation) -> Option<(u16, DeclaredStore)> {
    #[cfg(test)]
    DECLARATIONS_READ.with(|read| read.set(read.get() + 1));
    match parsed {
        ParsedOperation::VarStore(store) => Some((
            store.var_store_id,
            DeclaredStore::Variable(Box::new(store.clone())),
        )),
        ParsedOperation::VarStoreEfi(store) => Some((
            store.var_store_id,
            DeclaredStore::Variable(Box::new(store.clone())),
        )),
        ParsedOperation::VarStoreNameValue(store) => {
            Some((store.var_store_id, DeclaredStore::NameValue(store.guid)))
        }
        ParsedOperation::ShortVarStoreEfi(store) => {
            Some((store.var_store_id, DeclaredStore::ShortEfi(store.clone())))
        }
        ParsedOperation::FormSet(_)
        | ParsedOperation::OneOf(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::Numeric(_)
        | ParsedOperation::CheckBox(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Get(_)
        | ParsedOperation::Set(_)
        | ParsedOperation::FormMap(_)
        | ParsedOperation::Date(_)
        | ParsedOperation::Time(_)
        | ParsedOperation::OrderedList(_)
        | ParsedOperation::Ref(_)
        | ParsedOperation::String(_)
        | ParsedOperation::Placeholder => None,
    }
}

/// The VARSTORE, VARSTORE_NAME_VALUE or VARSTORE_EFI `op`, decoded from its data; None for another
/// op.
fn decode_var_store(op: &IFROperation) -> Result<Option<ParsedOperation>> {
    let mut data_cursor = Cursor::new(&op.data);
    let parsed = match op.op_code {
        IFROpCode::VarStore => ParsedOperation::VarStore(
            data_cursor
                .parse_ne()
                .context("failed to parse VarStore's data")?,
        ),
        IFROpCode::VarStoreNameValue => ParsedOperation::VarStoreNameValue(
            data_cursor
                .parse_ne()
                .context("failed to parse VarStoreNameValue's data")?,
        ),
        IFROpCode::VarStoreEfi if op.length < VAR_STORE_EFI_SIZE => {
            ParsedOperation::ShortVarStoreEfi(
                data_cursor
                    .parse_ne()
                    .context("failed to parse VarStoreEfi's data")?,
            )
        }
        // this is implemented in hiilib and the docs for this are relatively clear
        // so I implemented this but I haven't seen it being used anywhere in the dbdumps I have
        IFROpCode::VarStoreEfi => ParsedOperation::VarStoreEfi(
            data_cursor
                .parse_ne()
                .context("failed to parse VarStoreEfi's data")?,
        ),
        _ => return Ok(None),
    };
    Ok(Some(parsed))
}

/// declared_store of `op`, decoded from its data where handle_form_set leaves it undecoded, in the
/// scope of an unknown op.
fn decoded_store(op: &IFROperation) -> Result<Option<(u16, DeclaredStore)>> {
    if !matches!(op.parsed_data, ParsedOperation::Placeholder) {
        return Ok(declared_store(&op.parsed_data));
    }
    Ok(decode_var_store(op)?.and_then(|parsed| declared_store(&parsed)))
}

/// Whether edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes creates the store of a
/// VarStore op of a form-set-list (CreateStorage, :1873-1913); form_set_list_var_stores never meets
/// one that it skips.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Creation {
    Created,
    Undetermined(Undetermined),
}

/// Why ParseOpCodes may skip a VarStore op of a form-set-list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Undetermined {
    /// In the scope of a DISABLE_IF whose condition is not known: why
    DisableIf(Rc<str>),
    /// After a SUPPRESS_IF or GRAY_OUT_IF in the scope of a DISABLE_IF, whose condition is TRUE or
    /// not known
    Hiding(Hiding),
}

/// A SUPPRESS_IF or GRAY_OUT_IF of a form-set-list in the scope of a DISABLE_IF, whose condition
/// ParseOpCodes takes for the DISABLE_IF's (:1690-1704, :3045-3059): TRUE skips the rest of that
/// DISABLE_IF's scope (:1390-1413).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Hiding {
    /// Its spec name
    op: &'static str,
    /// Why its condition is not known; None if it is TRUE
    unknown: Option<Rc<str>>,
}

impl Hiding {
    /// Its condition, as text.
    fn condition(&self) -> String {
        match &self.unknown {
            Some(reason) => format!("not known: {reason}"),
            None => "TRUE".to_owned(),
        }
    }
}

/// The scopes around an op of a form-set-list, as form_set_list_var_stores walks them.
#[derive(Clone, Default)]
struct ListScopes {
    /// Why the first DISABLE_IF around, outermost first, whose condition is not known, may skip it
    unknown_disable_if: Option<Rc<str>>,
    /// In the scope of a DISABLE_IF: the first SUPPRESS_IF or GRAY_OUT_IF met so far in the scope
    /// of the outermost one whose condition is TRUE or not known, shared by every op in that scope
    hiding: Option<Rc<RefCell<Option<Hiding>>>>,
}

impl ListScopes {
    /// Whether ParseOpCodes creates the store of a VarStore op in these scopes: the DISABLE_IFs
    /// first, then the SUPPRESS_IFs and GRAY_OUT_IFs.
    fn creation(&self) -> Creation {
        let hiding = self
            .hiding
            .as_ref()
            .and_then(|hiding| hiding.borrow().clone());
        match (&self.unknown_disable_if, hiding) {
            (Some(reason), _) => Creation::Undetermined(Undetermined::DisableIf(Rc::clone(reason))),
            (None, Some(hiding)) => Creation::Undetermined(Undetermined::Hiding(hiding)),
            (None, None) => Creation::Created,
        }
    }
}

/// Visits the VarStore ops in the form-set-list of `form_set` (UEFI 2.11 §33.2.5.1), where
/// VfrCompile declares VarStores, in IFR order, each with whether edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes creates its store and the FORMs and FORM_MAPs before
/// it, until `visit` gives Some. It meets none in the scope of a FORM or FORM_MAP, outside the
/// form-set-list, nor of an unknown op (IsUnKnownOpCode), nor of a DISABLE_IF whose condition is
/// TRUE, which ParseOpCodes skips whatever DISABLE_IFs it nests (:1390-1413). It evaluates each
/// DISABLE_IF, SUPPRESS_IF and GRAY_OUT_IF of the form-set-list once, the latter only in the scope
/// of a DISABLE_IF.
fn form_set_list_var_stores<T>(
    form_set: &IFROperation,
    mut visit: impl FnMut(&IFROperation, &Creation, &[Rc<RefCell<IFROperation>>]) -> Option<T>,
) -> Option<T> {
    let mut forms = Vec::new();
    let walked = try_walk_scopes(&form_set.children, ListScopes::default(), |node, scopes| {
        let op = node.borrow();
        if skips_scope(&op) {
            return Ok(Walk::Skip);
        }
        match op.op_code {
            IFROpCode::VarStore | IFROpCode::VarStoreEfi | IFROpCode::VarStoreNameValue => {
                match visit(&op, &scopes.creation(), &forms) {
                    Some(found) => Err(found),
                    None => Ok(Walk::Enter(scopes.clone())),
                }
            }
            IFROpCode::Form | IFROpCode::FormMap => {
                forms.push(Rc::clone(node));
                Ok(Walk::Skip)
            }
            IFROpCode::DisableIf => {
                let mut inner = scopes.clone();
                inner.hiding.get_or_insert_with(Rc::default);
                match constant_condition(&op) {
                    Truth::Known(true) => return Ok(Walk::Skip),
                    Truth::Known(false) => {}
                    Truth::Unknown(reason) => {
                        inner.unknown_disable_if.get_or_insert(reason.into());
                    }
                }
                Ok(Walk::Enter(inner))
            }
            IFROpCode::SuppressIf | IFROpCode::GrayOutIf => {
                if let Some(hiding) = &scopes.hiding {
                    let unknown = match constant_condition(&op) {
                        Truth::Known(true) => Some(None),
                        Truth::Known(false) => None,
                        Truth::Unknown(reason) => Some(Some(reason.into())),
                    };
                    if let Some(unknown) = unknown {
                        hiding.borrow_mut().get_or_insert(Hiding {
                            op: op.op_code.spec_name(),
                            unknown,
                        });
                    }
                }
                Ok(Walk::Enter(scopes.clone()))
            }
            _ => Ok(Walk::Enter(scopes.clone())),
        }
    });
    walked.err()
}

/// Fills the VarName strings of the VARSTORE_EFIs before UEFI 2.3.1 of the FormSets of `roots`,
/// one package list's, from `string_packages`, its strings packages, as edk2-stable202608
/// SetupBrowserDxe/IfrParse.c takes the string of each VarName (GetToken): for each op with a
/// question header, GET and SET of the VarStoreId of such a store, in any scope, the string that
/// every strings package holding its VarName gives, or the strings that they differ on. The
/// strings are the list's, so every such store shares one map of them, filled after the walk,
/// which borrows the ops that it visits.
/// `roots` may hold the forms that their parse disables too, whose ops name VarNames as well.
pub(super) fn resolve_short_var_names(
    roots: &[Rc<RefCell<IFROperation>>],
    string_packages: &[StringPackage],
) {
    let mut stores = Vec::new();
    let mut short_ids = BTreeSet::new();
    walk_scopes(roots, (), |node, ()| {
        if let ParsedOperation::ShortVarStoreEfi(store) = &node.borrow().parsed_data {
            short_ids.insert(store.var_store_id);
            stores.push(Rc::clone(node));
        }
        Walk::Enter(())
    });
    let mut names = VarNames::new();
    walk_scopes(roots, (), |node, ()| {
        let op = node.borrow();
        let var_name = var_store_reference(&op)
            .filter(|(var_store_id, _)| short_ids.contains(var_store_id))
            .map(|(_, var_name)| var_name);
        let string = var_name
            .and_then(|var_name| Some((var_name, var_name_string(var_name, string_packages)?)));
        if let Some((var_name, string)) = string {
            names.insert(var_name, string);
        }
        Walk::Enter(())
    });
    let names = Rc::new(names);
    for store in stores {
        if let ParsedOperation::ShortVarStoreEfi(store) = &mut store.borrow_mut().parsed_data {
            store.var_names = Rc::clone(&names);
        }
    }
}

/// Returns the VarStoreId and VarStoreInfo that `op` names: those of its question header, or of
/// its operand, of a GET or SET.
fn var_store_reference(op: &IFROperation) -> Option<(u16, u16)> {
    if let ParsedOperation::Get(operand) | ParsedOperation::Set(operand) = &op.parsed_data {
        return Some((operand.var_store_id, operand.var_store_info));
    }
    parse_question_header(op).map(|header| (header.var_store_id, header.var_store_info))
}

/// The EFI variables of Guid `guid` that VarName `var_name` may name on a VARSTORE_EFI before UEFI
/// 2.3.1, by the strings of `string_packages` (var_name_string, var_name_variables).
fn var_name_candidates(
    guid: Guid,
    var_name: u16,
    string_packages: &[StringPackage],
) -> Vec<VariableKey> {
    var_name_variables(guid, var_name_string(var_name, string_packages).as_ref())
}

/// Returns the string of VarName `var_name` in the `string_packages` that hold it, or, where they
/// differ, each with its language; None if none holds it.
fn var_name_string(
    var_name: u16,
    string_packages: &[StringPackage],
) -> Option<std::result::Result<Rc<str>, UnresolvedVarName>> {
    let held: Vec<(&Language, &Rc<str>)> = string_packages
        .iter()
        .filter_map(|package| Some((&package.language, package.strings.get(&var_name)?)))
        .collect();
    let &(_, first) = held.first()?;
    if held.iter().all(|&(_, string)| string == first) {
        return Some(Ok(Rc::clone(first)));
    }
    Some(Err(UnresolvedVarName::Disagreeing {
        var_name,
        strings: held
            .into_iter()
            .map(|(language, string)| (language.0.escape_ascii().to_string(), string.to_string()))
            .collect(),
    }))
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
    use crate::hii::variables::EfivarFileName;
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

    /// A question lists REST_STYLE when its FormSet's ClassGuids hold
    /// EFI_HII_REST_STYLE_FORMSET_GUID, wherever among them, as its Flags can then omit it
    /// (UEFI 2.11 §33.3.8.2.2); other classes add no flag.
    #[test]
    fn question_lists_rest_style_of_its_form_set_class() {
        // EFI_HII_REST_STYLE_FORMSET_GUID (UEFI 2.11 §35.6.2) as stored
        let rest_style = [
            0xBD, 0x17, 0x02, 0x79, 0xCF, 0xBE, 0x5B, 0x48, 0x91, 0x70, 0x5F, 0xF7, 0x11, 0x31,
            0x8B, 0x27,
        ];
        let classes = [[0x22; 16], [0x33; 16], rest_style];
        let cases = [
            (&classes[2..], 0x00, &["REST_STYLE"][..]),
            (&classes[..], 0x10, &["RESET_REQUIRED", "REST_STYLE"][..]),
            (&classes[2..], 0x20, &["REST_STYLE"][..]),
            (&classes[..2], 0x00, &[][..]),
            (&classes[..2], 0x20, &["REST_STYLE"][..]),
            (&classes[..0], 0x00, &[][..]),
        ];
        for (class_guids, question_flags, want) in cases {
            let count = u8::try_from(class_guids.len()).expect("a ClassGuid count");
            let question = [question_header_with(1, 3, 1, 0, question_flags), vec![0x00]].concat();
            let data = form_set_with_class_guids(
                count,
                class_guids,
                &[form(1, &[operation(CHECKBOX, false, &question)])],
            );
            let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the FormSet");

            let listed = list_questions(
                root,
                &ListTexts::new(&[], &[]),
                IncludedStates::empty(),
                None,
                &mut Efivars::new().reader(),
            );

            let names: Vec<Vec<&str>> = listed
                .iter()
                .map(|(question, _)| question.flags.iter_names().map(|(name, _)| name).collect())
                .collect();
            assert_eq!(
                names,
                [want],
                "ClassGuids {class_guids:02x?}, Flags {question_flags:#04x}"
            );
        }
    }

    /// find_question_in finds a question by the name that list_questions prints, whose leading
    /// and trailing whitespace the prompt string keeps, and by that name with other surrounding
    /// whitespace or ASCII case.
    #[test]
    fn questions_are_found_by_their_listed_name() {
        let root = parse_form_set(&[form(1, &[checkbox_op(1, 0)])]);
        let values = VarStoreValues::new(&root, None);
        let prompted = |prompt: &str| vec![en_us_package(StringMap::from([(3, prompt.into())]))];
        let find = |prompt: &str, phrase: &str| {
            find_question_in(
                &root,
                &QuestionMatch::Prompt(&BTreeSet::from([phrase])),
                &mut FormSetWalk::new(
                    &ListTexts::new(&prompted(prompt), &[]),
                    &mut Efivars::new().reader(),
                    &values,
                    IncludedStates::empty(),
                ),
            )
            .map(|_| ())
        };
        let listed = list_questions(
            Rc::clone(&root),
            &ListTexts::new(&prompted("  Prompt "), &[]),
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
                Selection::Picked {
                    picked: ((), StateEvaluation::selectable()),
                    ranked_before: RankedBefore::default(),
                },
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
                u16::try_from(encoded.len()).expect("width fits u16"),
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
        let write = VarStoreWrite::new(&store, 0, 1, TypeValue::NumSize8(1), variables.interface())
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
            1,
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
            (42, 41, TypeValue::NumSize8(1), 2),
            (0, 0, TypeValue::NumSize8(1), 1),
            (42, u16::MAX, TypeValue::NumSize64(1), 8),
        ] {
            let store = efi_variable("Test", size);
            assert_eq!(
                VarStoreWrite::new(&store, offset, width, data, VariableInterface::Efivarfs)
                    .map(drop)
                    .map_err(|error| error.to_string()),
                Err(format!(
                    "write at offset {offset} with width {width} exceeds varstore size {size}"
                )),
                "{data:?} at offset {offset} of {size} bytes"
            );
        }
    }

    /// VarStoreWrite::new refuses a question's storage of no byte, whose write would change
    /// nothing, or of more bytes than a UINT64, and takes the widths between, such as a TIME's 3.
    #[test]
    fn refuses_storage_widths_outside_1_to_8() {
        let write = |width| {
            VarStoreWrite::new(
                &efi_variable("Test", 42),
                0,
                width,
                TypeValue::NumSize8(0),
                VariableInterface::Efivarfs,
            )
            .map(drop)
            .map_err(|error| error.to_string())
        };
        for width in [0, 9] {
            assert_eq!(
                write(width),
                Err(format!("a question's storage of {width} bytes, not 1 to 8")),
                "{width} bytes"
            );
        }
        for width in 1..=8 {
            assert_eq!(write(width), Ok(()), "{width} bytes");
        }
    }

    /// VarStoreWrite::new writes a date or time as its EFI_HII_DATE or EFI_HII_TIME, which fills
    /// the 4 bytes of a DATE's storage or the 3 of a TIME's, and refuses a storage of another width.
    #[test]
    fn dates_and_times_fill_their_storage_with_their_bytes() {
        let date = TypeValue::Date(Date::from_bytes([0xE8, 0x07, 0x02, 0x1D]));
        let time = TypeValue::Time(Time::from_bytes([23, 59, 58]));
        let write = |value, width| {
            VarStoreWrite::new(
                &efi_variable("Test", 42),
                1,
                width,
                value,
                VariableInterface::Efivarfs,
            )
            .map(|write| write.patches)
            .map_err(|error| error.to_string())
        };
        assert_eq!(
            write(date, 4),
            Ok(vec![(1, vec![0xE8, 0x07, 0x02, 0x1D])]),
            "DATE"
        );
        assert_eq!(write(time, 3), Ok(vec![(1, vec![23, 59, 58])]), "TIME");
        for (value, width, size) in [(date, 3, 4), (date, 8, 4), (time, 4, 3), (time, 1, 3)] {
            assert_eq!(
                write(value, width),
                Err(format!(
                    "a question's storage of {width} bytes, not the {size} of its value"
                )),
                "{value:?} in {width} bytes"
            );
        }
    }

    #[test]
    fn rejects_unsupported_value_instead_of_silent_noop() {
        assert_eq!(
            VarStoreWrite::new(
                &efi_variable("Test", 42),
                0,
                1,
                TypeValue::Unknown(0),
                VariableInterface::Efivarfs
            )
            .map(drop)
            .map_err(|error| error.to_string()),
            Err("unsupported value type for efivarfs write".to_string()),
            "a value of an unknown type"
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
                 not created it, and set creates only the per-question variables of an \
                 EFI_IFR_VARSTORE_EFI before UEFI 2.3.1",
            ),
        ];
        for (reach, interface, want) in cases {
            let variables = MemoryVariables::new(reach, interface);
            let store = efi_variable("Setup", 1);
            let write = VarStoreWrite::new(&store, 0, 1, TypeValue::NumSize8(1), interface)
                .expect("write 1");

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
                    1,
                    TypeValue::Unknown(0),
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

    /// type_value_parser reads a value in the endian that its derive passes, as a parse_with
    /// function takes it.
    #[test]
    fn type_value_parser_reads_in_the_endian_it_is_given() {
        for (endian, want) in [
            (binrw::Endian::Little, 0x0201),
            (binrw::Endian::Big, 0x0102),
        ] {
            let got = type_value_parser(
                &mut Cursor::new([0x01, 0x02]),
                endian,
                (EFI_IFR_TYPE_NUM_SIZE_16,),
            )
            .unwrap_or_else(|error| panic!("{endian:?}: {error}"));
            assert_eq!(got, TypeValue::NumSize16(want), "{endian:?}");
        }
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

        let shown = display(
            root,
            0,
            &ListTexts::new(&strings(), &[]),
            &mut disabled_reader(),
        )
        .expect("display");

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

        let shown = display(
            root,
            0,
            &ListTexts::new(&strings(), &[]),
            &mut disabled_reader(),
        )
        .expect("display");

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
    /// decoded, so a malformed one does not disable its form; in a known opcode's scope it still
    /// does.
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
        let parsed =
            handle_form_set_within(&mut Cursor::new(&data), MAX_SCOPE_NESTING, &mut Vec::new())
                .expect("parse the GUID scope");
        let forms = parsed.root.borrow().children[0].borrow().children.len();
        let reasons: Vec<&str> = parsed
            .disabled_forms
            .iter()
            .map(|disabled| disabled.reason.as_str())
            .collect();
        assert!(
            forms == 0
                && matches!(reasons.as_slice(), [reason] if reason.contains("whose EFI_IFR_CHECKBOX op is malformed")),
            "GUID scope: {forms} forms, disabled: {reasons:?}"
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

    /// A FORM_SET holds as many ClassGuids as bits 0:1 of its Flags count, whatever its
    /// reserved bits 2:7 hold (UEFI 2.11 §33.3.8.3.26), and show-ifr shows each.
    #[test]
    fn form_set_holds_the_class_guids_that_its_flags_count() {
        let guids = [[0x22; 16], [0x33; 16], [0x44; 16]];
        let three = [
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "44444444-4444-4444-4444-444444444444",
        ];
        let cases = [
            (0x00, &guids[..0], &three[..0]),
            (0x01, &guids[..1], &three[..1]),
            (0x03, &guids[..], &three[..]),
            (0x07, &guids[..], &three[..]),
        ];
        for (flags, class_guids, shown) in cases {
            let data = form_set_with_class_guids(flags, class_guids, &[]);
            let root = handle_form_set(&mut Cursor::new(&data))
                .unwrap_or_else(|error| panic!("parse Flags {flags:#04x}: {error:#}"));

            let display = display(
                root,
                0,
                &ListTexts::new(&strings(), &[]),
                &mut disabled_reader(),
            )
            .expect("display");

            let line = display
                .lines()
                .find(|line| line.trim_start().starts_with("OpCode: FormSet "))
                .unwrap_or_else(|| panic!("Flags {flags:#04x}: no FormSet line in {display:?}"));
            let class_guids: Vec<&str> = line.split(" - ClassGUID ").skip(1).collect();
            assert_eq!(class_guids, shown, "Flags {flags:#04x}: {line:?}");
        }
    }

    /// A FORM_SET that holds fewer ClassGuids than its Flags count is malformed (UEFI 2.11
    /// §33.2.5.10.1), shorter than the Length that they require.
    #[test]
    fn form_set_short_of_its_class_guid_count_does_not_parse() {
        let data = form_set_with_class_guids(0x03, &[[0x22; 16]], &[]);

        let error = handle_form_set(&mut Cursor::new(&data)).expect_err("3 counted, 1 held");

        assert_eq!(
            format!("{error:#}"),
            "the EFI_IFR_FORM_SET op at offset 0 of a form package is 39 bytes long, shorter than \
             the 71 bytes required by the ClassGuid count of its Flags (UEFI 2.11 §33.3.8.3)",
            "3 counted, 1 held"
        );
    }

    /// A VARSTORE_EFI of Length 24 to 26 is the form before UEFI 2.3.1, which ends at
    /// Attributes, as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes takes one
    /// shorter than sizeof (EFI_IFR_VARSTORE_EFI): its FormSet parses, and a question on it lists
    /// without a value. One of Length 27 is the later form; one of 23 ends inside Attributes and
    /// does not parse (UEFI 2.11 §33.2.5.10.1).
    #[test]
    fn var_store_efi_of_24_to_26_bytes_is_the_form_before_uefi_2_3_1() {
        let short = short_var_store_efi(7);
        let fields = short.get(2..).expect("the fields past the header");
        let parse = |store: Vec<u8>| {
            let data = form_set(&[store, form(1, &[checkbox_on(1, 3, 7)])]);
            handle_form_set(&mut Cursor::new(&data))
        };
        let unread = "<ValueUnavailable: VarStore 0x0007 (EFI_IFR_VARSTORE_EFI before UEFI \
                      2.3.1): no string 0x0000 holds its VarName> <IFR default: 0>";

        for tail in [&[][..], &[0x05], &[0x05, 0x00]] {
            let data = [fields, tail].concat();
            let length = data.len() + 2;
            let root = parse(operation(VAR_STORE_EFI, false, &data))
                .unwrap_or_else(|error| panic!("parse Length {length}: {error:#}"));

            let listed = list_questions(
                root,
                &ListTexts::new(&strings(), &[]),
                IncludedStates::empty(),
                None,
                &mut disabled_reader(),
            );

            let values: Vec<&str> = listed
                .iter()
                .map(|(question, _)| question.value.as_str())
                .collect();
            assert_eq!(values, [unread], "Length {length}");
        }

        let root = parse(var_store_efi(7, "", NV_BS_RT, 5)).expect("parse Length 27");
        let store = Rc::clone(&root.borrow().children[0].borrow().children[0]);
        let parsed = format!("{:?}", store.borrow().parsed_data);
        assert!(
            parsed.starts_with("VarStoreEfi(VarStoreEfi { var_store_id: 7,")
                && parsed.contains("size: 5,"),
            "Length 27: {parsed}"
        );

        let error = parse(operation(VAR_STORE_EFI, false, &fields[..21]))
            .expect_err("Length 23 ends inside Attributes");
        assert!(
            format!("{error:#}").contains("is 23 bytes long, shorter than its minimum of 24"),
            "Length 23: {error:#}"
        );
    }

    /// A STRING on a VARSTORE_EFI before UEFI 2.3.1 has the EFI variable of its VarName, as wide
    /// as its StorageWidth, MaxSize CHAR16s (edk2-stable202608 SetupBrowserDxe/IfrParse.c:2225).
    #[test]
    fn a_string_on_a_short_var_store_has_a_variable_of_max_size_char16s() {
        // QuestionId 1, prompt 3, VarStoreId 7, VarName 5; MinSize 1, MaxSize 4, Flags 0
        let data = [question_header_with(1, 3, 7, 5, 0x00), vec![1, 4, 0x00]].concat();
        let root = parse_form_set(&[
            short_var_store_efi(7),
            form(1, &[operation(STRING, false, &data)]),
        ]);
        resolve_short_var_names(
            &[Rc::clone(&root)],
            &[en_us_package(StringMap::from([(5, "ShortVarS".into())]))],
        );
        let string = find_op(&root, &data).expect("the STRING");

        let store = find_corresponding_varstore(string, 7).expect("the variable of VarName 5");

        let key = VariableKey {
            name: "ShortVarS".to_string(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        };
        assert_eq!(
            (store.variable_key(), store.size(), store.layout()),
            (key, 8, VariableLayout::OneValue),
            "STRING of MinSize 1 and MaxSize 4"
        );
    }

    /// show-ifr shows each op of which it decodes nothing, but the root, by its OpCode, one scope
    /// down from its parent: here the condition and string ops of a SUPPRESS_IF.
    #[test]
    fn show_ifr_shows_ops_without_decoded_data_by_their_opcode() {
        let string_ref1 = operation(STRING_REF1, false, &5u16.to_le_bytes());
        let condition = [
            string_ref1.clone(),
            string_ref1,
            operation(EQUAL, false, &[]),
        ]
        .concat();
        let root = parse_form_set(&[form(
            1,
            &[conditional(SUPPRESS_IF, condition, &[checkbox_op(1, 0)])],
        )]);

        let display = display(
            root,
            0,
            &ListTexts::new(&strings(), &[]),
            &mut disabled_reader(),
        )
        .expect("display");

        let ops: Vec<&str> = display
            .lines()
            .filter(|line| !line.trim_start().starts_with('-'))
            .map(|line| line.split(" - ").next().unwrap_or(line))
            .collect();
        assert_eq!(
            ops,
            [
                "OpCode: ROOT",
                "    OpCode: FormSet",
                "        OpCode: Form",
                "            OpCode: SuppressIf",
                "                OpCode: StringRef1",
                "                OpCode: StringRef1",
                "                OpCode: Equal",
                "                OpCode: CheckBox",
            ],
            "{display}"
        );
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
    fn deep_strings() -> Vec<StringPackage> {
        vec![en_us_package(StringMap::from([
            (3, "Deep".into()),
            (4, "Help".into()),
            (5, "Hidden".into()),
        ]))]
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
        handle_form_set_within(&mut Cursor::new(&ifr), usize::MAX, &mut Vec::new())
            .expect("parse the FormSet")
            .root
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
                    .setup_password_bypass(VariableReach::BootServices)
                    .is_some();
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
            // the LOCKED ops gray out Deep
            for (include, want) in [
                (IncludedStates::CONDITIONS, &["Deep", "Hidden"][..]),
                (IncludedStates::GRAYED_OUT, &["Deep"][..]),
                (IncludedStates::empty(), &[][..]),
            ] {
                let listed = list_questions(
                    parse_deep(DEEP, DEEP, false),
                    &ListTexts::new(&deep_strings(), &[]),
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
                    &ListTexts::new(&deep_strings(), &[]),
                    &QuestionMatch::Prompt(&BTreeSet::from([name])),
                    IncludedStates::GRAYED_OUT,
                    None,
                    &mut disabled_reader(),
                );
                assert_eq!(
                    matches!(selection, Selection::Picked { .. }),
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
            let shown = display(
                root,
                0,
                &ListTexts::new(&deep_strings(), &[]),
                &mut disabled_reader(),
            )
            .expect("display");
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

    /// A GET or SET too short for its operand is malformed, so it disables its form (UEFI 2.11
    /// §33.2.5.10.1).
    #[test]
    fn short_get_and_set_disable_their_form() {
        for op_code in [0x2B, 0x2C] {
            let short = operation(op_code, false, &[0x34, 0x12, 0xC1, 0x00]);
            let (root, disabled) = parse_form_set_dropping(&[form(1, &[short])]);

            let forms = root.borrow().children[0].borrow().children.len();
            let reasons: Vec<&str> = disabled
                .iter()
                .map(|disabled| disabled.reason.as_str())
                .collect();
            assert!(
                forms == 0
                    && matches!(reasons.as_slice(), [reason] if reason.starts_with("the form 1 of")
                        && reason.contains("op is malformed")),
                "opcode {op_code:#x}: {forms} forms, disabled: {reasons:?}"
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

    /// A FORM_MAP keeps the methods that fit in its Length; one without room for a method is
    /// malformed (UEFI 2.11 §33.3.8.3.25 requires one), so its form is disabled (§33.2.5.10.1).
    #[test]
    fn short_form_map_keeps_the_methods_that_fit() {
        let truncated = |methods: &[&[u8]]| {
            let data = [&[&4u16.to_le_bytes()[..]], methods].concat().concat();
            [operation(FORM_MAP, true, &data), END.to_vec()].concat()
        };
        let cut_off: &[u8] = &[&[0x06, 0x00][..], &STANDARD_FORM_GUID[..8]].concat();
        let other: &[u8] = &[&[0x05, 0x00][..], &OTHER_GUID].concat();

        let op = parsed_first(&[truncated(&[other, cut_off])]);
        let op = op.borrow();
        let ParsedOperation::FormMap(form_map) = &op.parsed_data else {
            panic!("FORM_MAP not decoded: {:?}", op.parsed_data);
        };
        let titles: Vec<u16> = form_map
            .methods
            .iter()
            .map(|method| method.method_title)
            .collect();
        assert_eq!(titles, [5], "the whole method");
        assert!(!form_map.has_standard_method(), "a cut-off method");

        for (name, methods) in [("a cut-off method", &[cut_off][..]), ("no method", &[])] {
            let (root, disabled) = parse_form_set_dropping(&[truncated(methods)]);

            let forms = root.borrow().children[0].borrow().children.len();
            let reasons: Vec<&str> = disabled
                .iter()
                .map(|disabled| disabled.reason.as_str())
                .collect();
            assert!(
                forms == 0
                    && matches!(reasons.as_slice(), [reason] if reason.starts_with("the form 4 of")
                        && reason.contains("whose EFI_IFR_FORM_MAP op is malformed")),
                "{name}: {forms} forms, disabled: {reasons:?}"
            );
        }
    }

    /// An op shorter than the Length that its Flags, Type or ListLength require is malformed, so
    /// it disables its form (UEFI 2.11 §33.2.5.10.1); one of that Length decodes.
    #[test]
    fn ops_shorter_than_their_fields_require_disable_their_form() {
        const EQ_ID_VAL_LIST: u8 = 0x14;
        let numeric = |op_code: u8, flags: u8, values: usize| {
            let data = [question_header(0), vec![flags], vec![0; values]].concat();
            operation(op_code, false, &data)
        };
        let bit_field =
            |op: Vec<u8>| [operation(GUID, true, &BIT_VARSTORE_GUID), op, END.to_vec()].concat();
        let cases = [
            (
                "UINT16 NUMERIC",
                numeric(NUMERIC, 0x01, 3),
                numeric(NUMERIC, 0x01, 6),
                "EFI_IFR_NUMERIC op at offset",
                "17 bytes long, shorter than the 20 bytes required by its Flags",
            ),
            (
                "UINT32 ONE_OF",
                numeric(ONE_OF, 0x02, 3),
                numeric(ONE_OF, 0x02, 12),
                "EFI_IFR_ONE_OF op at offset",
                "17 bytes long, shorter than the 26 bytes required by its Flags",
            ),
            (
                "bit-field NUMERIC",
                bit_field(numeric(NUMERIC, 0x08, 3)),
                bit_field(numeric(NUMERIC, 0x08, 12)),
                "EFI_IFR_NUMERIC op at offset",
                "17 bytes long, shorter than the 26 bytes required by its EDKII bit field",
            ),
            (
                "UINT32 ONE_OF_OPTION",
                one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_32, &[0]),
                one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_32, &[0; 4]),
                "EFI_IFR_ONE_OF_OPTION op at offset",
                "7 bytes long, shorter than the 10 bytes required by its Type",
            ),
            (
                "UINT16 DEFAULT",
                operation(DEFAULT, false, &[0, 0, EFI_IFR_TYPE_NUM_SIZE_16, 0]),
                operation(DEFAULT, false, &[0, 0, EFI_IFR_TYPE_NUM_SIZE_16, 0, 0]),
                "EFI_IFR_DEFAULT op at offset",
                "6 bytes long, shorter than the 7 bytes required by its Type",
            ),
            (
                "EQ_ID_VAL_LIST of 2",
                operation(EQ_ID_VAL_LIST, false, &[1, 0, 2, 0, 0, 0]),
                operation(EQ_ID_VAL_LIST, false, &[1, 0, 2, 0, 0, 0, 0, 0]),
                "EFI_IFR_EQ_ID_VAL_LIST op at offset",
                "8 bytes long, shorter than the 10 bytes required by its ListLength",
            ),
        ];
        for (name, short, whole, op, length) in cases {
            let (root, disabled) = parse_form_set_dropping(&[form(1, &[short])]);

            let forms = root.borrow().children[0].borrow().children.len();
            let reasons: Vec<&str> = disabled
                .iter()
                .map(|disabled| disabled.reason.as_str())
                .collect();
            assert!(
                forms == 0
                    && matches!(reasons.as_slice(), [reason] if reason.starts_with("the form 1 of")
                        && reason.contains(op)
                        && reason.ends_with(&format!("{length} (UEFI 2.11 §33.3.8.3)"))),
                "{name}: {forms} forms, disabled: {reasons:?}"
            );

            let (root, disabled) = parse_form_set_dropping(&[form(1, &[whole])]);
            let forms = root.borrow().children[0].borrow().children.len();
            assert!(
                forms == 1 && disabled.is_empty(),
                "{name} of its Length: {forms} forms, disabled: {disabled:?}"
            );
        }
    }

    /// A FormSet of live forms between disabled ones keeps every live form in order and records
    /// every disabled one (UEFI 2.11 §33.2.5.10.1).
    #[test]
    fn interleaved_disabled_forms_leave_the_live_ones_in_order() {
        let short_checkbox = operation(CHECKBOX, false, &[0x00]);
        let forms: Vec<Vec<u8>> = [(1, true), (2, false), (3, false), (4, true), (5, false)]
            .into_iter()
            .map(|(form_id, live)| match live {
                true => form(form_id, &[]),
                false => form(form_id, std::slice::from_ref(&short_checkbox)),
            })
            .collect();

        let (root, disabled) = parse_form_set_dropping(&forms);

        let form_set = Rc::clone(&root.borrow().children[0]);
        let live: Vec<u16> = form_set
            .borrow()
            .children
            .iter()
            .filter_map(|form| form.borrow().form_id())
            .collect();
        assert_eq!(live, [1, 4], "the live forms");
        let reasons: Vec<&str> = disabled
            .iter()
            .map(|disabled| disabled.reason.as_str())
            .collect();
        assert!(
            matches!(reasons.as_slice(), [two, three, five]
                if two.starts_with("the form 2 of")
                    && three.starts_with("the form 3 of")
                    && five.starts_with("the form 5 of")),
            "disabled: {reasons:?}"
        );
    }
}

#[cfg(test)]
mod option_value_tests {
    use super::ifr_fixtures::*;
    use super::*;

    /// An EFI_IFR_ONE_OF_OPTION of Type DATE or TIME holds the EFI_HII_DATE or EFI_HII_TIME of its
    /// first bytes. One shorter than its Type is malformed: it disables its form, whose reason
    /// tells how short it is, and the FormSet stays (UEFI 2.11 §33.2.5.10.1).
    #[test]
    fn date_and_time_option_values_decode_and_short_ones_disable_their_form() {
        let date = TypeValue::Date(Date::from_bytes([0xD4, 0x07, 1, 2]));
        let decoded = [
            ("DATE", EFI_IFR_TYPE_DATE, &[0xD4, 0x07, 1, 2][..], date),
            (
                "DATE of 5 bytes",
                EFI_IFR_TYPE_DATE,
                &[0xD4, 0x07, 1, 2, 0xEE],
                date,
            ),
            (
                "TIME",
                EFI_IFR_TYPE_TIME,
                &[15, 33, 34],
                TypeValue::Time(Time::from_bytes([15, 33, 34])),
            ),
            (
                "UINT8",
                EFI_IFR_TYPE_NUM_SIZE_8,
                &[7],
                TypeValue::NumSize8(7),
            ),
        ];
        for (name, value_type, value, want) in decoded {
            let root = parse_form_set(&[form(1, &[one_of_option(5, value_type, value)])]);
            let root = root.borrow();
            let form_set = root.children[0].borrow();
            let form = form_set.children[0].borrow();
            let op = form.children[0].borrow();
            let ParsedOperation::OneOfOption(option) = &op.parsed_data else {
                panic!("{name}: option not decoded: {:?}", op.parsed_data);
            };
            assert_eq!(option.value, want, "{name}");
        }

        let short = [
            (
                "DATE of 3 bytes",
                EFI_IFR_TYPE_DATE,
                &[0xD4, 0x07, 1][..],
                "9 bytes long, shorter than the 10",
            ),
            (
                "DATE without bytes",
                EFI_IFR_TYPE_DATE,
                &[],
                "6 bytes long, shorter than the 10",
            ),
            (
                "TIME of 2 bytes",
                EFI_IFR_TYPE_TIME,
                &[15, 33],
                "8 bytes long, shorter than the 9",
            ),
        ];
        for (name, value_type, value, length) in short {
            let (root, disabled) =
                parse_form_set_dropping(&[form(1, &[one_of_option(5, value_type, value)])]);

            let forms = root.borrow().children[0].borrow().children.len();
            let reasons: Vec<&str> = disabled
                .iter()
                .map(|disabled| disabled.reason.as_str())
                .collect();
            assert!(
                forms == 0
                    && matches!(reasons.as_slice(), [reason] if reason.starts_with("the form 1 of")
                    && reason.contains("EFI_IFR_ONE_OF_OPTION op at offset")
                    && reason.ends_with(&format!(
                        "{length} bytes required by its Type (UEFI 2.11 §33.3.8.3)"
                    ))),
                "{name}: {forms} forms, disabled: {reasons:?}"
            );
        }
    }
}
