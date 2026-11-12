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
use std::fmt;
use std::rc::Rc;

use binrw::BinRead;
use thiserror::Error;

use super::conditions::enclosing_form_set;
use super::conditions::evaluate_condition;
use super::conditions::evaluate_value;
use super::conditions::option_state;
use super::conditions::skips_scope;
use super::conditions::ExpressionInputs;
use super::conditions::QuestionValues;
use super::conditions::Truth;
use super::is_bit_varstore_guid;
use super::question_values::QuestionKind;
use super::storage::BufferQuestion;
use super::storage::ValueLocation;
use super::string_question::NotUcs2;
use super::walk_scopes;
use super::IFRDefault;
use super::IFROpCode;
use super::IFROperation;
use super::IfrDefaultValue;
use super::IncludedStates;
use super::NumericFormatError;
use super::OneOf;
use super::OneOfOption;
use super::ParsedOperation;
use super::Range;
use super::TypeValue;
use super::Walk;
use crate::hii::strings::ListTexts;
use crate::hii::strings::ScsuRuledOut;

// UEFI 2.10 §33.3.8.3.9, §33.3.8.3.51
const EFI_IFR_CHECKBOX_DEFAULT: u8 = 0x01;
const EFI_IFR_CHECKBOX_DEFAULT_MFG: u8 = 0x02;
const EFI_IFR_OPTION_DEFAULT: u8 = 0x10;
const EFI_IFR_OPTION_DEFAULT_MFG: u8 = 0x20;
/// The offset of Value in an EFI_IFR_ONE_OF_OPTION's data, after Option, Flags and Type (UEFI
/// 2.11 §33.3.8.3.51).
const ONE_OF_OPTION_VALUE_OFFSET: usize = 4;

/// The DEFAULTSTOREs of a question outside every FormSet.
static NO_DEFAULT_STORES: DefaultStores = DefaultStores(BTreeMap::new());

/// The identifier of a default store, from an open set (UEFI 2.10 §33.2.5.8).
#[derive(BinRead, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[br(little)]
pub struct DefaultId(pub u16);

impl DefaultId {
    // EFI_HII_DEFAULT_CLASS_STANDARD, EFI_HII_DEFAULT_CLASS_MANUFACTURING and
    // EFI_HII_DEFAULT_CLASS_SAFE (UEFI 2.11 §33.2.5.8)
    pub(super) const STANDARD: Self = Self(0x0000);
    pub(super) const MANUFACTURING: Self = Self(0x0001);
    pub(super) const SAFE: Self = Self(0x0002);
}

impl fmt::Display for DefaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

/// A default that the IFR declares for a question (UEFI 2.11 §33.2.5.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeclaredDefault {
    pub(crate) default_id: DefaultId,
    /// The DefaultName of the DEFAULTSTORE of `default_id`, if the FormSet declares one
    pub(crate) store_name: Option<String>,
    pub(crate) value: DefaultValue,
}

/// The value of a declared default, as the answer shows a current value, or why it is unknown;
/// it shows as answers and `defaults` show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DefaultValue(Result<String, DefaultError>);

impl fmt::Display for DefaultValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(value) => f.write_str(value),
            Err(reason) => write!(f, "unknown ({reason})"),
        }
    }
}

/// The DEFAULTSTOREs of a FormSet by DefaultId, each with the string id of the DefaultName of
/// its first DEFAULTSTORE.
#[derive(Default)]
pub(super) struct DefaultStores(BTreeMap<DefaultId, u16>);

impl DefaultStores {
    /// Whether a DEFAULTSTORE declares `default_id`.
    fn is_declared(&self, default_id: DefaultId) -> bool {
        self.0.contains_key(&default_id)
    }
}

/// A question's default, as the IFR declares it (default_for_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TypedDefault {
    /// Of a numeric, BOOLEAN, DATE or TIME Type (an EFI_HII_DATE or EFI_HII_TIME as
    /// TypeValue::widened takes it), an EFI_IFR_VALUE, a flagged option of a ONE_OF, or a
    /// CHECKBOX's flags
    Number(u64),
    /// Of Type EFI_IFR_TYPE_STRING: the identifier of the string
    String(u16),
    /// Of Type EFI_IFR_TYPE_BUFFER, or the Value of a flagged option of an ORDERED_LIST, which
    /// UEFI 2.11 §33.2.5.4.8 makes "the default value for all Containers"
    Buffer(Vec<u8>),
    /// Of Type EFI_IFR_TYPE_REF: an EFI_HII_REF (UEFI 2.11 §33.2.5.4.10)
    Ref(Vec<u8>),
}

impl TypedDefault {
    /// The number, refused for a string or a buffer, which no numeric question stores.
    fn number(self) -> Result<u64, DefaultError> {
        match self {
            Self::Number(number) => Ok(number),
            Self::String(_) => Err(DefaultError::NotNumber("EFI_IFR_TYPE_STRING")),
            Self::Buffer(_) => Err(DefaultError::NotNumber("EFI_IFR_TYPE_BUFFER")),
            Self::Ref(_) => Err(DefaultError::NotNumber("EFI_IFR_TYPE_REF")),
        }
    }

    /// The buffer, refused for a number or a string, which no ORDERED_LIST stores.
    fn buffer(self) -> Result<Vec<u8>, DefaultError> {
        match self {
            Self::Buffer(bytes) => Ok(bytes),
            Self::Number(_) => Err(DefaultError::NotBuffer("a number")),
            Self::String(_) => Err(DefaultError::NotBuffer("EFI_IFR_TYPE_STRING")),
            Self::Ref(_) => Err(DefaultError::NotBuffer("EFI_IFR_TYPE_REF")),
        }
    }

    /// The string id, refused for a number, a buffer or an EFI_HII_REF, which no STRING
    /// stores.
    fn string_id(self) -> Result<u16, DefaultError> {
        match self {
            Self::String(id) => Ok(id),
            Self::Number(_) => Err(DefaultError::NotString("a number")),
            Self::Buffer(_) => Err(DefaultError::NotString("EFI_IFR_TYPE_BUFFER")),
            Self::Ref(_) => Err(DefaultError::NotString("EFI_IFR_TYPE_REF")),
        }
    }

    /// The EFI_HII_REF, refused for a number, a string or a buffer, which no REF stores.
    fn hii_ref(self) -> Result<Vec<u8>, DefaultError> {
        match self {
            Self::Ref(bytes) => Ok(bytes),
            Self::Number(_) => Err(DefaultError::NotRef("a number")),
            Self::String(_) => Err(DefaultError::NotRef("EFI_IFR_TYPE_STRING")),
            Self::Buffer(_) => Err(DefaultError::NotRef("EFI_IFR_TYPE_BUFFER")),
        }
    }
}

/// Why a question's default is not known.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(super) enum DefaultError {
    #[error("EFI_IFR_DEFAULT Type {0:#04x} value not decoded")]
    DefaultType(u8),
    #[error("a default of {0} where the question stores a number")]
    NotNumber(&'static str),
    #[error("a default of {0} where the question stores a buffer")]
    NotBuffer(&'static str),
    #[error("a default of {0} where the question stores an EFI_HII_REF")]
    NotRef(&'static str),
    #[error("a default of {0} where the question stores a string")]
    NotString(&'static str),
    #[error("EFI_IFR_TYPE_STRING default: string {0:#06x} not found")]
    StringNotFound(u16),
    #[error(
        "EFI_IFR_TYPE_STRING default: string {id:#06x} is SCSU text with a character that UEFI \
         rules out of strings, which holds no CHAR16s to copy"
    )]
    StringRuledOut { id: u16 },
    #[error("EFI_IFR_TYPE_STRING default: {0}")]
    StringText(NotUcs2),
    #[error("EFI_IFR_DEFAULT value missing")]
    DefaultValueMissing,
    #[error("EFI_IFR_DEFAULT_2 without EFI_IFR_VALUE")]
    ValueOpMissing,
    #[error("EFI_IFR_VALUE expression not evaluated: {0}")]
    ValueExpression(String),
    #[error("EFI_IFR_SUPPRESS_IF condition not evaluated: {0}")]
    SuppressIfCondition(String),
    #[error("EFI_IFR_ONE_OF_OPTION Type {0:#04x} value not decoded")]
    OptionType(u8),
    #[error(transparent)]
    NumericFormat(#[from] NumericFormatError),
    #[error("EFI_IFR_ONE_OF_OPTION value not known: {0}")]
    OptionValue(OptionValueError),
}

/// Why the value of an EFI_IFR_ONE_OF_OPTION of Type EFI_IFR_TYPE_OTHER is not known.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum OptionValueError {
    #[error("EFI_IFR_TYPE_OTHER without a nested EFI_IFR_VALUE")]
    ValueOpMissing,
    #[error("its EFI_IFR_VALUE expression not evaluated: {0}")]
    ValueExpression(String),
    #[error(
        "its EFI_IFR_VALUE gives {value:#x}, which does not fit in the {bits} bits of the ONE_OF"
    )]
    TooWide { value: u64, bits: u32 },
    #[error("EFI_IFR_TYPE_OTHER outside a ONE_OF")]
    OutsideOneOf,
}

/// What question_scope takes from the scope of an op nested in a question.
enum NestedScope {
    /// Nothing: the ops belong to the nested op (a statement, a question, a DEFAULT's value,
    /// vendor data)
    Own,
    /// The question's ops
    Question,
}

impl NestedScope {
    /// Classifies an op as edk2-stable202608 SetupBrowserDxe/IfrParse.c attaches the ops in its
    /// scope.
    fn of(op: &IFROperation) -> Self {
        match (op.op_code, is_parent_statement(op)) {
            (IFROpCode::Default, _) | (_, true) => Self::Own,
            (_, false) => Self::Question,
        }
    }
}

/// Whether the ops in the scope of `op` are its own: edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes makes a statement with a scope their ParentStatement,
/// but clears the Scope of the GUID op of an EDKII bit varstore field, so that the ops in it stay
/// the enclosing statement's.
pub(super) fn is_parent_statement(op: &IFROperation) -> bool {
    is_statement(op.op_code) && !is_bit_varstore_guid(op)
}

/// Whether `op_code` is a statement's, as edk2-stable202608 SetupBrowserDxe/IfrParse.c
/// IsStatementOpCode tells, and HiiDatabaseDxe/ConfigKeywordHandler.c's of the same opcodes.
pub(super) fn is_statement(op_code: IFROpCode) -> bool {
    match op_code {
        IFROpCode::Subtitle
        | IFROpCode::Text
        | IFROpCode::ResetButton
        | IFROpCode::Ref
        | IFROpCode::Action
        | IFROpCode::Numeric
        | IFROpCode::OrderedList
        | IFROpCode::CheckBox
        | IFROpCode::String
        | IFROpCode::Password
        | IFROpCode::Date
        | IFROpCode::Time
        | IFROpCode::Guid
        | IFROpCode::OneOf => true,
        IFROpCode::Default
        | IFROpCode::Form
        | IFROpCode::Image
        | IFROpCode::OneOfOption
        | IFROpCode::SuppressIf
        | IFROpCode::Locked
        | IFROpCode::FormSet
        | IFROpCode::NoSubmitIf
        | IFROpCode::InconsistentIf
        | IFROpCode::EqIdVal
        | IFROpCode::EqIdId
        | IFROpCode::EqIdValList
        | IFROpCode::And
        | IFROpCode::Or
        | IFROpCode::Not
        | IFROpCode::Rule
        | IFROpCode::GrayOutIf
        | IFROpCode::Refresh
        | IFROpCode::DisableIf
        | IFROpCode::Animation
        | IFROpCode::ToLower
        | IFROpCode::ToUpper
        | IFROpCode::Map
        | IFROpCode::VarStore
        | IFROpCode::VarStoreNameValue
        | IFROpCode::VarStoreEfi
        | IFROpCode::VarStoreDevice
        | IFROpCode::Version
        | IFROpCode::End
        | IFROpCode::Match
        | IFROpCode::Get
        | IFROpCode::Set
        | IFROpCode::Read
        | IFROpCode::Write
        | IFROpCode::Equal
        | IFROpCode::NotEqual
        | IFROpCode::GreaterThan
        | IFROpCode::GreaterEqual
        | IFROpCode::LessThan
        | IFROpCode::LessEqual
        | IFROpCode::BitwiseAnd
        | IFROpCode::BitwiseOr
        | IFROpCode::BitwiseNot
        | IFROpCode::ShiftLeft
        | IFROpCode::ShiftRight
        | IFROpCode::Add
        | IFROpCode::Subtract
        | IFROpCode::Multiply
        | IFROpCode::Divide
        | IFROpCode::Modulo
        | IFROpCode::RuleRef
        | IFROpCode::QuestionRef1
        | IFROpCode::QuestionRef2
        | IFROpCode::Uint8
        | IFROpCode::Uint16
        | IFROpCode::Uint32
        | IFROpCode::Uint64
        | IFROpCode::True
        | IFROpCode::False
        | IFROpCode::ToUint
        | IFROpCode::ToString
        | IFROpCode::ToBoolean
        | IFROpCode::Mid
        | IFROpCode::Find
        | IFROpCode::Token
        | IFROpCode::StringRef1
        | IFROpCode::StringRef2
        | IFROpCode::Conditional
        | IFROpCode::QuestionRef3
        | IFROpCode::Zero
        | IFROpCode::One
        | IFROpCode::Ones
        | IFROpCode::Undefined
        | IFROpCode::Length
        | IFROpCode::Dup
        | IFROpCode::This
        | IFROpCode::Span
        | IFROpCode::Value
        | IFROpCode::DefaultStore
        | IFROpCode::FormMap
        | IFROpCode::Catenate
        | IFROpCode::Security
        | IFROpCode::ModalTag
        | IFROpCode::RefreshId
        | IFROpCode::WarningIf
        | IFROpCode::Match2
        | IFROpCode::Unknown(_) => false,
    }
}

/// Returns the ops in the question's scope in IFR order.
// TODO: drop options and expressions (e.g. EFI_IFR_DEFAULT_2's EFI_IFR_VALUE) under a true
// DISABLE_IF, as UEFI 2.10 §33.3.8.3.14 says, for firmware that does; edk2-stable202608
// IfrParse.c keeps them inside a question, as this does.
pub(super) fn question_scope(question: &IFROperation) -> Vec<Rc<RefCell<IFROperation>>> {
    let mut scope = Vec::new();
    walk_scopes(&question.children, (), |child, ()| {
        if skips_scope(&child.borrow()) {
            return Walk::Skip;
        }
        scope.push(Rc::clone(child));
        match NestedScope::of(&child.borrow()) {
            NestedScope::Own => Walk::Skip,
            NestedScope::Question => Walk::Enter(()),
        }
    });
    scope
}

/// Whether edk2-stable202608 SetupBrowserDxe shows an option.
pub(super) enum OptionVisibility {
    Shown,
    /// A SUPPRESS_IF hides it
    Suppressed,
    /// Why it is not known
    Unknown(String),
}

/// Returns whether edk2-stable202608 SetupBrowserDxe shows the option `op`.
pub(super) fn option_visibility(
    op: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> OptionVisibility {
    let state = option_state(op, inputs);
    let shown = IncludedStates::empty();
    match (state.is_allowed(shown), state.may_be_allowed(shown)) {
        (true, _) => OptionVisibility::Shown,
        (false, true) => {
            let reasons: Vec<&str> = state.reasons().collect();
            OptionVisibility::Unknown(reasons.join("; "))
        }
        (false, false) => OptionVisibility::Suppressed,
    }
}

/// form_set_default_stores of the FormSet of the last question asked about: questions come
/// FormSet by FormSet, so that a FormSet is walked once per run of its questions.
#[derive(Default)]
pub(super) struct FormSetDefaultStores(Option<(Rc<RefCell<IFROperation>>, DefaultStores)>);

impl FormSetDefaultStores {
    /// Returns form_set_default_stores of the question's FormSet, or none outside FormSets.
    pub(super) fn of(
        &mut self,
        question: &IFROperation,
        inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    ) -> &DefaultStores {
        let Some(form_set) = enclosing_form_set(question) else {
            return &NO_DEFAULT_STORES;
        };
        let entry = match self.0.take() {
            Some((known, stores)) if Rc::ptr_eq(&known, &form_set) => (known, stores),
            _ => {
                let stores = form_set_default_stores(&form_set.borrow(), inputs);
                (form_set, stores)
            }
        };
        &self.0.insert(entry).1
    }
}

/// Returns the DEFAULTSTOREs in `form_set`.
fn form_set_default_stores(
    form_set: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> DefaultStores {
    // Nested ones too (UEFI 2.10 §33.2.5.1), except under a true DISABLE_IF
    // outside forms (§33.3.8.3.14), the only one edk2-stable202608
    // SetupBrowserDxe/IfrParse.c evaluates while parsing.
    let mut stores = BTreeMap::new();
    walk_scopes(&form_set.children, false, |child, &in_form| {
        let child = child.borrow();
        if skips_scope(&child) {
            return Walk::Skip;
        }
        if let ParsedOperation::DefaultStore(store) = &child.parsed_data {
            stores
                .entry(store.default_id)
                .or_insert(store.name_string_id);
        }
        if !in_form
            && child.op_code == IFROpCode::DisableIf
            && evaluate_condition(&child, inputs) == Truth::Known(true)
        {
            return Walk::Skip;
        }
        Walk::Enter(in_form || matches!(child.op_code, IFROpCode::Form | IFROpCode::FormMap))
    });
    DefaultStores(stores)
}

/// Returns the value of the EFI_IFR_DEFAULT `op`.
fn ifr_default_value(
    op: &IFROperation,
    default: &IFRDefault,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Result<TypedDefault, DefaultError> {
    let value = op
        .children
        .iter()
        .find(|child| child.borrow().op_code == IFROpCode::Value);
    let Some(value) = value else {
        return match &default.value {
            IfrDefaultValue::Decoded(value) => value
                .widened()
                .map(TypedDefault::Number)
                .ok_or(DefaultError::DefaultType(default.value_type)),
            IfrDefaultValue::String(id) => Ok(TypedDefault::String(*id)),
            IfrDefaultValue::Buffer(bytes) => Ok(TypedDefault::Buffer(bytes.clone())),
            IfrDefaultValue::Ref(bytes) => Ok(TypedDefault::Ref(bytes.clone())),
            IfrDefaultValue::InValueOp => Err(DefaultError::ValueOpMissing),
            IfrDefaultValue::NotDecoded => Err(DefaultError::DefaultType(default.value_type)),
            IfrDefaultValue::Missing => Err(DefaultError::DefaultValueMissing),
        };
    };
    let value = value.borrow();
    evaluate_value(&value, inputs)
        .map(TypedDefault::Number)
        .map_err(DefaultError::ValueExpression)
}

/// Returns the value of the EFI_IFR_ONE_OF_OPTION `op`, `option`, in the scope of `question`: its
/// Value, or, of Type EFI_IFR_TYPE_OTHER, that of its nested EFI_IFR_VALUE (UEFI 2.11
/// §33.3.8.3.51) in the width of the ONE_OF `question`. edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes instead copies no Value and makes that EFI_IFR_VALUE
/// the question's, which makes the question read-only.
pub(super) fn option_value(
    question: &IFROperation,
    op: &IFROperation,
    option: &OneOfOption,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Result<TypeValue, OptionValueError> {
    let TypeValue::Other = option.value else {
        return Ok(option.value);
    };
    let ParsedOperation::OneOf(one_of) = &question.parsed_data else {
        return Err(OptionValueError::OutsideOneOf);
    };
    let value = op
        .children
        .iter()
        .find(|child| child.borrow().op_code == IFROpCode::Value)
        .ok_or(OptionValueError::ValueOpMissing)?;
    let value =
        evaluate_value(&value.borrow(), inputs).map_err(OptionValueError::ValueExpression)?;
    one_of_value(one_of, value)
}

/// Returns `value` as a value of `one_of`: of the size of its Range, and within the width of an
/// EDKII bit varstore field.
fn one_of_value(one_of: &OneOf, value: u64) -> Result<TypeValue, OptionValueError> {
    let bits = match one_of.location {
        ValueLocation::Bytes { size, .. } => u32::from(size) * u8::BITS,
        ValueLocation::Bits { width, .. } => u32::from(width),
    };
    let fits = bits >= u64::BITS || value >> bits == 0;
    let sized = match one_of.data {
        Range::Range8(_) => u8::try_from(value).ok().map(TypeValue::NumSize8),
        Range::Range16(_) => u16::try_from(value).ok().map(TypeValue::NumSize16),
        Range::Range32(_) => u32::try_from(value).ok().map(TypeValue::NumSize32),
        Range::Range64(_) => Some(TypeValue::NumSize64(value)),
    };
    sized
        .filter(|_| fits)
        .ok_or(OptionValueError::TooWide { value, bits })
}

/// Returns every default that the IFR declares for the question, by DefaultId ascending, each
/// valued by `text`: of STANDARD; of MANUFACTURING, if `stores` declares it or the question or one
/// of its options has a *_DEFAULT_MFG flag; of every DEFAULTSTORE of `stores`; and of every
/// EFI_IFR_DEFAULT in its scope, also of a DefaultId that no DEFAULTSTORE declares, though UEFI
/// 2.11 §33.3.8.3.12 requires one. edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionDefault
/// falls back to another default store and then to a value by type; these are not shown.
pub(super) fn question_defaults<V: QuestionValues>(
    question: &IFROperation,
    stores: &DefaultStores,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, V>,
    mut text: impl FnMut(u64, &mut ExpressionInputs<'_, V>) -> Result<String, DefaultError>,
) -> Vec<DeclaredDefault> {
    question_default_values(question, stores, inputs)
        .into_iter()
        .map(|(default_id, value)| {
            let value = value
                .and_then(TypedDefault::number)
                .and_then(|value| text(value, inputs));
            declared_default(default_id, value, stores, texts)
        })
        .collect()
}

/// The defaults of question_defaults, each as the IFR declares it or why it is unknown.
pub(super) fn question_default_values(
    question: &IFROperation,
    stores: &DefaultStores,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Vec<(DefaultId, Result<TypedDefault, DefaultError>)> {
    let scope = question_scope(question);
    declared_default_ids(question, &scope, stores)
        .into_iter()
        .filter_map(|default_id| {
            let value = default_for_id(question, &scope, default_id, inputs)?;
            Some((default_id, value))
        })
        .collect()
}

/// The DefaultIds of the defaults that question_defaults lists for `question`, whose scope is
/// `scope`.
fn declared_default_ids(
    question: &IFROperation,
    scope: &[Rc<RefCell<IFROperation>>],
    stores: &DefaultStores,
) -> BTreeSet<DefaultId> {
    let mut default_ids: BTreeSet<DefaultId> = stores.0.keys().copied().collect();
    default_ids.insert(DefaultId::STANDARD);
    if has_manufacturing_flag(question, scope) {
        default_ids.insert(DefaultId::MANUFACTURING);
    }
    default_ids.extend(
        scope
            .iter()
            .filter_map(|op| match &op.borrow().parsed_data {
                ParsedOperation::IFRDefault(default) => Some(default.default_id),
                _ => None,
            }),
    );
    default_ids
}

/// The default of `default_id` with `value`, with the DefaultName of its DEFAULTSTORE in
/// `stores`, if any.
fn declared_default(
    default_id: DefaultId,
    value: Result<String, DefaultError>,
    stores: &DefaultStores,
    texts: &ListTexts<'_>,
) -> DeclaredDefault {
    DeclaredDefault {
        default_id,
        store_name: stores
            .0
            .get(&default_id)
            .map(|&name| texts.display(name).to_string()),
        value: DefaultValue(value),
    }
}

/// Whether `option`, in the scope of `question`, is a flagged option of an ORDERED_LIST, which
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c:2369-2402 makes a buffer default and no option.
pub(super) fn is_ordered_list_default(question: &IFROperation, option: &OneOfOption) -> bool {
    question.op_code == IFROpCode::OrderedList
        && option.flags & (EFI_IFR_OPTION_DEFAULT | EFI_IFR_OPTION_DEFAULT_MFG) != 0
}

/// Whether the question, if a CHECKBOX, or one of its options has a manufacturing default flag
/// (UEFI 2.11 §33.3.8.3.9, §33.3.8.3.51), which needs no DEFAULTSTORE.
fn has_manufacturing_flag(question: &IFROperation, scope: &[Rc<RefCell<IFROperation>>]) -> bool {
    let checkbox = matches!(
        &question.parsed_data,
        ParsedOperation::CheckBox(checkbox) if checkbox.flags & EFI_IFR_CHECKBOX_DEFAULT_MFG != 0
    );
    checkbox
        || scope.iter().any(|op| {
            matches!(
                &op.borrow().parsed_data,
                ParsedOperation::OneOfOption(option)
                    if option.flags & EFI_IFR_OPTION_DEFAULT_MFG != 0
            )
        })
}

/// Whether flagged EFI_IFR_ONE_OF_OPTIONs give a question of `op_code` a default: every question
/// whose grammar nests `option` (question-option-list, UEFI 2.11 §33.2.5.4), as §33.2.5.8 lists
/// them for any question and §33.2.5.5 makes a DEFAULT-flagged option "the option selected when
/// the user asks for the defaults"; an ORDERED_LIST as "the default value for all Containers"
/// (§33.2.5.4.8, is_ordered_list_default).
fn takes_option_defaults(op_code: IFROpCode) -> bool {
    match QuestionKind::of(op_code) {
        Some(
            QuestionKind::Value
            | QuestionKind::Date
            | QuestionKind::Time
            | QuestionKind::String
            | QuestionKind::OrderedList,
        ) => true,
        // its grammar nests options (§33.2.5.4.9), but edk2-stable202608
        // HiiDatabaseDxe/ConfigRouting.c ParseIfrData gives it no default: "No default value for
        // string." (:3135-3137)
        Some(QuestionKind::Password) => false,
        // their grammar nests no option (§33.2.5.4.10, §33.2.5.4.4)
        Some(QuestionKind::Ref | QuestionKind::Action) | None => false,
    }
}

/// Returns the question's standard default, which a forms browser gives a question without
/// storage before it reads it (edk2-stable202608 SetupBrowserDxe Setup.c:5956).
pub(super) fn standard_default(
    question: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Option<Result<u64, DefaultError>> {
    default_for_id(
        question,
        &question_scope(question),
        DefaultId::STANDARD,
        inputs,
    )
    .map(|value| value.and_then(TypedDefault::number))
}

/// Returns the question's default for `default_id`: EFI_IFR_DEFAULT, then a flagged
/// EFI_IFR_ONE_OF_OPTION, then CHECKBOX Flags (UEFI 2.10 §33.3.8.3.9, §33.3.8.3.47). A flagged
/// option of an ORDERED_LIST gives its Value's bytes, whatever SUPPRESS_IF is around it, as
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c:2369-2402 makes it a buffer default and no option.
/// An EFI_IFR_DEFAULT still comes first for an ORDERED_LIST, by UEFI 2.11 §33.2.5.8, where
/// edk2-stable202608 Setup.c GetQuestionDefault takes whichever of the two comes first in IFR
/// order. A flagged option of Type EFI_IFR_TYPE_STRING gives a STRING the string of its Value, as
/// EFI_IFR_STRING (UEFI 2.11 §33.3.8.3.70) takes defaults from "one or more nested
/// EFI_IFR_ONE_OF_OPTION (lowest priority)", and any other question a default that it refuses for
/// its Type.
fn default_for_id(
    question: &IFROperation,
    scope: &[Rc<RefCell<IFROperation>>],
    default_id: DefaultId,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Option<Result<TypedDefault, DefaultError>> {
    // EFI_IFR_DEFAULT, wherever it is in the question's scope
    let ifr_default = scope.iter().find_map(|op| {
        let op = op.borrow();
        match &op.parsed_data {
            ParsedOperation::IFRDefault(default) if default.default_id == default_id => {
                Some(ifr_default_value(&op, default, inputs))
            }
            _ => None,
        }
    });
    if ifr_default.is_some() {
        return ifr_default;
    }

    let (option_flag, checkbox_flag) = match default_id {
        DefaultId::STANDARD => (EFI_IFR_OPTION_DEFAULT, EFI_IFR_CHECKBOX_DEFAULT),
        DefaultId::MANUFACTURING => (EFI_IFR_OPTION_DEFAULT_MFG, EFI_IFR_CHECKBOX_DEFAULT_MFG),
        _ => return None,
    };
    // As in edk2-stable202608: SetupBrowserDxe/Setup.c GetQuestionDefault takes the ALTCFG default
    // first (:4449-4450) for storage other than EFI_HII_VARSTORE_EFI_VARIABLE (:4140), which
    // HiiDatabaseDxe/ConfigRouting.c ParseIfrData builds from the flagged options of a DATE, TIME,
    // NUMERIC, CHECKBOX, STRING or ONE_OF (:2929-3017, :3218-3235); only its fallback takes the
    // options of a ONE_OF alone (:4525).
    let option_scope = match takes_option_defaults(question.op_code) {
        true => scope,
        false => &[],
    };
    let option_default = option_scope.iter().find_map(|op| {
        let op = op.borrow();
        let ParsedOperation::OneOfOption(option) = &op.parsed_data else {
            return None;
        };
        if option.flags & option_flag == 0 {
            return None;
        }
        if is_ordered_list_default(question, option) {
            // IfrParse.c:2383-2387 makes an option of both flags a standard default alone
            if default_id == DefaultId::MANUFACTURING && option.flags & EFI_IFR_OPTION_DEFAULT != 0
            {
                return None;
            }
            return Some(
                op.data
                    .get(ONE_OF_OPTION_VALUE_OFFSET..)
                    .filter(|value| !value.is_empty())
                    .map(|value| TypedDefault::Buffer(value.to_vec()))
                    .ok_or(DefaultError::OptionType(option.value_type)),
            );
        }
        match option_visibility(&op, inputs) {
            OptionVisibility::Shown => Some(
                option_value(question, &op, option, inputs)
                    .map_err(DefaultError::OptionValue)
                    .and_then(|value| {
                        // the string of an option of Type EFI_IFR_TYPE_STRING, which a question
                        // that stores no string refuses for its Type
                        if let TypeValue::StringID(id) = value {
                            return Ok(TypedDefault::String(id));
                        }
                        // a DATE or TIME option's bytes, as an EFI_IFR_DEFAULT's
                        value
                            .widened()
                            .map(TypedDefault::Number)
                            .ok_or(DefaultError::OptionType(option.value_type))
                    }),
            ),
            OptionVisibility::Suppressed => None,
            OptionVisibility::Unknown(reason) => {
                Some(Err(DefaultError::SuppressIfCondition(reason)))
            }
        }
    });
    if option_default.is_some() {
        return option_default;
    }

    // The flags end the search, as in edk2-stable202608 SetupBrowserDxe/Setup.c
    // GetQuestionDefault, and a clear one is FALSE, as in its HiiDatabaseDxe/ConfigRouting.c:
    // with only the MFG flag set, the standard default is 0, though ConfigRouting.c copies the
    // MFG TRUE to every DefaultId.
    let ParsedOperation::CheckBox(checkbox) = &question.parsed_data else {
        return None;
    };
    Some(Ok(TypedDefault::Number(u64::from(
        checkbox.flags & checkbox_flag != 0,
    ))))
}

/// Appends the question's default among `defaults`, those of question_defaults, to the reason
/// its current value is unavailable: that of STANDARD, else of the first DEFAULTSTORE of
/// `stores` that holds one, ascending, as edk2-stable202608 SetupBrowserDxe/Setup.c
/// GetQuestionDefault tries them.
pub(super) fn push_default(
    answer: &mut String,
    defaults: &[DeclaredDefault],
    stores: &DefaultStores,
) {
    let Some(DeclaredDefault {
        default_id, value, ..
    }) = defaults.iter().find(|default| {
        default.default_id == DefaultId::STANDARD || stores.is_declared(default.default_id)
    })
    else {
        return;
    };
    match *default_id {
        DefaultId::STANDARD => answer.push_str(&format!(" <IFR default: {value}>")),
        _ => answer.push_str(&format!(" <IFR default (DefaultId {default_id}): {value}>")),
    }
}

/// Returns every default that the IFR declares for `question`, a question of `buffer`, as
/// question_default_values finds them, each the buffer of an ORDERED_LIST, the EFI_HII_REF
/// of a REF or the CHAR16s of the string of a STRING that `text` shows, or why it cannot.
pub(super) fn buffer_defaults(
    question: &IFROperation,
    buffer: BufferQuestion,
    stores: &DefaultStores,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    mut text: impl FnMut(&[u8]) -> Result<String, DefaultError>,
) -> Vec<DeclaredDefault> {
    question_default_values(question, stores, inputs)
        .into_iter()
        .map(|(default_id, value)| {
            let value = value
                .and_then(|value| match buffer {
                    BufferQuestion::OrderedList => value.buffer(),
                    BufferQuestion::CrossReference => value.hii_ref(),
                    BufferQuestion::String => {
                        value.string_id().and_then(|id| string_bytes(texts, id))
                    }
                })
                .and_then(|bytes| text(&bytes));
            declared_default(default_id, value, stores, texts)
        })
        .collect()
}

/// The little-endian CHAR16s of the string `id` that `texts` show, as the firmware holds them
/// (ListTexts::shown_units), as edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionDefault
/// copies a default of Type STRING from HiiGetString in the platform language; refused for an
/// SCSU string with a character that UEFI rules out of strings, which holds none.
pub(super) fn string_bytes(texts: &ListTexts<'_>, id: u16) -> Result<Vec<u8>, DefaultError> {
    let units = texts
        .shown_units(id)
        .ok_or(DefaultError::StringNotFound(id))?
        .map_err(|ScsuRuledOut| DefaultError::StringRuledOut { id })?;
    Ok(units.into_iter().flat_map(u16::to_le_bytes).collect())
}

/// Returns the text of the first option in the question's scope with `value` that no
/// SUPPRESS_IF hides, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption finds it.
pub(super) fn option_text(
    question: &IFROperation,
    value: u64,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Result<Option<String>, DefaultError> {
    question_scope(question)
        .iter()
        .find_map(|op| {
            let op = op.borrow();
            let ParsedOperation::OneOfOption(option) = &op.parsed_data else {
                return None;
            };
            // an option whose value is not known matches no value
            match option_value(question, &op, option, inputs) {
                Ok(option_value) if option_value.as_u64() == Some(value) => {}
                Ok(_) | Err(_) => return None,
            }
            match option_visibility(&op, inputs) {
                OptionVisibility::Shown => Some(Ok(texts
                    .display(option.option_string_id)
                    .trim()
                    .to_string())),
                OptionVisibility::Suppressed => None,
                OptionVisibility::Unknown(reason) => {
                    Some(Err(DefaultError::SuppressIfCondition(reason)))
                }
            }
        })
        .transpose()
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;
    use std::rc::Rc;

    use binrw::io::Cursor;

    use super::super::conditions::QuestionValue;
    use super::super::conditions::ValueKind;
    use super::super::find_question;
    use super::super::handle_form_set;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::CheckedVarStores;
    use super::super::IncludedStates;
    use super::super::QuestionMatch;
    use super::super::Selection;
    use super::string_bytes;
    use super::DeclaredDefault;
    use super::DefaultError;
    use super::DefaultId;
    use super::DefaultValue;
    use super::OptionValueError;
    use crate::hii::package::hiidb_fixtures::en_strings_package_with_blocks;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::read_db;
    use crate::hii::strings::MatchTier;

    /// The MethodIdentifier of the test EFI_IFR_FORM_MAP method.
    const METHOD_IDENTIFIER: [u8; 16] = [0x33; 16];

    /// Why a condition on question 1, the question of `parse_question()`, is not evaluated.
    const QUESTION_1_UNAVAILABLE: &str = "EFI_IFR_EQ_ID_VAL of question 0x0001: \
                                          <ValueUnavailable: no supported varstore with matching \
                                          id 0x0001 found>";

    #[test]
    fn checkbox_default_comes_from_default_then_flags() {
        let stores = [default_store(0), default_store(1)];
        let cases: [(&str, u8, Vec<Vec<u8>>, &str); 5] = [
            ("standard flag", 0x01, vec![], " <IFR default: 1>"),
            ("clear flags", 0x00, vec![], " <IFR default: 0>"),
            (
                "DEFAULT beats the flag",
                0x01,
                vec![ifr_default(0, 0)],
                " <IFR default: 0>",
            ),
            (
                "constant DEFAULT_2",
                0x00,
                vec![ifr_default_2(0, uint8(1))],
                " <IFR default: 1>",
            ),
            (
                "manufacturing DEFAULT does not hide the standard flag",
                0x01,
                vec![ifr_default(1, 0)],
                " <IFR default: 1>",
            ),
        ];
        for (name, flags, children, suffix) in cases {
            assert_eq!(
                answer(
                    &stores,
                    CHECKBOX,
                    &checkbox(0, flags),
                    &children,
                    unavailable()
                ),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// A DEFAULT in an EDKII bit-varstore GUID in the question's scope is the question's, as
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes, which clears that GUID's Scope,
    /// attaches it; one in another GUID statement is that statement's.
    #[test]
    fn default_in_a_bit_varstore_guid_in_scope_is_the_questions() {
        for (name, guid, suffix) in [
            ("bit-varstore GUID", BIT_VARSTORE_GUID, " <IFR default: 5>"),
            ("other GUID", OTHER_GUID, ""),
        ] {
            let in_guid = [
                operation(GUID, true, &guid),
                ifr_default(0, 5),
                END.to_vec(),
            ]
            .concat();
            assert_eq!(
                answer(
                    &[],
                    NUMERIC,
                    &uint8_numeric(0x10, 0, 255),
                    &[in_guid],
                    unavailable()
                ),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// question_defaults shows a default that it cannot evaluate as unknown, with why, and lists
    /// no default for a flagged option that a SUPPRESS_IF hides.
    #[test]
    fn declared_defaults_tell_why_a_value_is_unknown() {
        let (_root, node) = parse_question(
            &[],
            ONE_OF,
            &one_of_data(),
            &[
                conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(5, 0x20, 0)]),
                conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(6, 0x10, 1)]),
                ifr_default_2(0x4000, eq_id_val()),
            ],
        );
        let unknown = |default_id, error: DefaultError| DeclaredDefault {
            default_id: DefaultId(default_id),
            store_name: None,
            value: DefaultValue(Err(error)),
        };

        assert_eq!(
            question_descriptor(&node, unavailable()).defaults,
            [
                unknown(
                    0x0000,
                    DefaultError::SuppressIfCondition(QUESTION_1_UNAVAILABLE.to_string())
                ),
                unknown(
                    0x4000,
                    DefaultError::ValueExpression(QUESTION_1_UNAVAILABLE.to_string())
                ),
            ],
            "defaults"
        );
    }

    /// A DEFAULT-flagged EFI_IFR_TYPE_OTHER option outside a ONE_OF, which gives it no width,
    /// gives a default unknown with why.
    #[test]
    fn default_flag_of_an_option_of_type_other_outside_a_one_of_tells_why() {
        let (_root, node) = parse_question(
            &[],
            NUMERIC,
            &uint8_numeric(0x00, 0, 10),
            &[other_option(6, 0x10, &[uint8(1)])],
        );

        assert_eq!(
            question_descriptor(&node, unavailable()).defaults,
            [DeclaredDefault {
                default_id: DefaultId::STANDARD,
                store_name: None,
                value: DefaultValue(Err(DefaultError::OptionValue(
                    OptionValueError::OutsideOneOf
                ))),
            }],
            "defaults"
        );
    }

    #[test]
    fn one_of_option_flag_gives_standard_default() {
        let children = [flagged_option(5, 0x20, 0), flagged_option(6, 0x10, 1)];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "standard option flag"
        );
    }

    #[test]
    fn ifr_default_overrides_option_flag() {
        let children = [
            flagged_option(5, 0x00, 0),
            flagged_option(6, 0x10, 1),
            ifr_default(0x0000, 0),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Disabled>"),
            "DEFAULT and option flag"
        );
    }

    #[test]
    fn manufacturing_default_needs_declared_default_store() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];

        assert_eq!(
            one_of_default(&[], &children),
            UNAVAILABLE,
            "no DEFAULTSTORE"
        );
        assert_eq!(
            one_of_default(&[default_store(0x0000), default_store(0x0001)], &children),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>"),
            "STANDARD and manufacturing DEFAULTSTOREs"
        );
    }

    #[test]
    fn default_store_under_form_set_suppress_if_is_declared() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];
        let suppressed_store = |default_id| {
            [conditional(
                SUPPRESS_IF,
                ifr_true(),
                &[default_store(default_id)],
            )]
        };

        assert_eq!(
            one_of_default(&suppressed_store(0x0001), &children),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>"),
            "DEFAULTSTORE 0x0001 under SUPPRESS_IF"
        );
        assert_eq!(
            one_of_default(&suppressed_store(0x0002), &children),
            UNAVAILABLE,
            "DEFAULTSTORE 0x0002 under SUPPRESS_IF"
        );
    }

    #[test]
    fn default_store_under_true_form_set_disable_if_is_ignored() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];
        let disabled_store =
            |condition| conditional(DISABLE_IF, condition, &[default_store(0x0001)]);
        let in_form = |op_code, data: &[u8]| {
            [
                operation(op_code, true, data),
                disabled_store(ifr_true()),
                END.to_vec(),
            ]
            .concat()
        };
        // FormId 1, FormTitle 1
        let form = in_form(FORM, &[0x01, 0x00, 0x01, 0x00]);
        // FormId 2, one method: MethodTitle 1, METHOD_IDENTIFIER
        let form_map = in_form(
            FORM_MAP,
            &[&[0x02, 0x00, 0x01, 0x00][..], &METHOD_IDENTIFIER].concat(),
        );
        let mfg_default = format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>");

        assert_eq!(
            one_of_default(&[disabled_store(ifr_true())], &children),
            UNAVAILABLE,
            "DISABLE_IF TRUE"
        );
        assert_eq!(
            one_of_default(&[disabled_store(ifr_false())], &children),
            mfg_default,
            "DISABLE_IF FALSE"
        );
        assert_eq!(
            one_of_default(&[disabled_store(eq_id_val())], &children),
            mfg_default,
            "unevaluated DISABLE_IF"
        );
        assert_eq!(
            one_of_default(&[form], &children),
            mfg_default,
            "DISABLE_IF TRUE in a FORM"
        );
        assert_eq!(
            one_of_default(&[form_map], &children),
            mfg_default,
            "DISABLE_IF TRUE in a FORM_MAP"
        );
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes declares no DEFAULTSTORE in the
    /// scope of an opcode above EFI_IFR_MATCH2_OP.
    #[test]
    fn default_store_in_an_unknown_opcode_scope_is_not_declared() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];
        let in_scope = |op_code: u8| {
            [
                operation(op_code, true, &[]),
                default_store(0x0001),
                END.to_vec(),
            ]
            .concat()
        };
        let mfg_default = format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>");
        let cases = [
            ("opcode 0x00", in_scope(0x00), mfg_default.as_str()),
            ("opcode 0x65", in_scope(0x65), UNAVAILABLE),
            ("opcode 0x70", in_scope(0x70), UNAVAILABLE),
        ];
        for (name, scope, want) in cases {
            assert_eq!(one_of_default(&[scope], &children), want, "{name}");
        }
    }

    #[test]
    fn declared_default_stores_are_tried_in_ascending_order() {
        let data = uint8_numeric(0x10, 0, 10);
        let children = [ifr_default(0x4000, 3), ifr_default(0x0002, 4)];
        let numeric = |declarations: &[Vec<u8>]| {
            answer(declarations, NUMERIC, &data, &children, unavailable())
        };

        assert_eq!(numeric(&[]), UNAVAILABLE, "no DEFAULTSTORE");
        assert_eq!(
            numeric(&[default_store(0x4000), default_store(0x0002)]),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x0002): 4>"),
            "DEFAULTSTOREs 0x4000 and 0x0002"
        );
        assert_eq!(
            numeric(&[default_store(0x4000)]),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x4000): 3>"),
            "DEFAULTSTORE 0x4000"
        );
    }

    /// list_questions and find_question try the DEFAULTSTOREs of the FormSet they walk into.
    #[test]
    fn list_and_find_question_try_the_form_set_default_stores() {
        let (root, _question) = parse_question(
            &[default_store(0x0000), default_store(0x0001)],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[ifr_default(0x0001, 4)],
        );
        let want = "<ValueUnavailable: no supported varstore with matching id 0x0001 found> \
                    <IFR default (DefaultId 0x0001): 4>";

        let efivars = Efivars::new();
        let listed = list_questions(
            Rc::clone(&root),
            &ListTexts::new(&strings(), &[]),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut efivars.reader(),
        );
        let Selection::Picked {
            picked: (found, _), ..
        } = find_question(
            root,
            &ListTexts::new(&strings(), &[]),
            &QuestionMatch::Prompt(&BTreeSet::from([PROMPT]), MatchTier::Stored),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut efivars.reader(),
        )
        else {
            panic!("find the question by its prompt");
        };

        let answers: Vec<&str> = listed
            .iter()
            .map(|(question, _)| question.value.as_str())
            .collect();
        assert_eq!(answers, [want], "list_questions");
        assert_eq!(found.value, want, "find_question");
    }

    /// A question outside every FormSet tries the standard default store.
    #[test]
    fn question_outside_form_sets_tries_the_standard_default_store() {
        let data = [
            operation(NUMERIC, true, &uint8_numeric(0x10, 0, 10)),
            ifr_default(0x0000, 4),
            END.to_vec(),
        ]
        .concat();
        let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the Numeric");
        let unavailable = "<ValueUnavailable: varstore not found because we reached root>";

        let listed = list_questions(
            root,
            &ListTexts::new(&strings(), &[]),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut Efivars::new().reader(),
        );

        let answers: Vec<&str> = listed.iter().map(|(q, _)| q.value.as_str()).collect();
        assert_eq!(
            answers,
            [format!("{unavailable} <IFR default: 4>")],
            "answer of a question outside FormSets"
        );
    }

    /// The questions of a FormSet in a FormSet try the DEFAULTSTOREs of the inner FormSet, and
    /// those after it the DEFAULTSTOREs of the outer one again.
    #[test]
    fn questions_try_the_default_stores_of_their_form_set() {
        let numeric = |default: u8| {
            [
                operation(NUMERIC, true, &uint8_numeric(0x10, 0, 10)),
                ifr_default(0x0001, default),
                END.to_vec(),
            ]
            .concat()
        };
        let data = form_set(&[
            default_store(0x0001),
            // in a FORM, FormId 1, FormTitle 1, so the FormSet is not its parent
            [
                operation(FORM, true, &[0x01, 0x00, 0x01, 0x00]),
                numeric(4),
                END.to_vec(),
            ]
            .concat(),
            form_set(&[numeric(5)]),
            numeric(6),
        ]);
        let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the FormSet");
        let unavailable = "<ValueUnavailable: no supported varstore with matching id 0x0001 found>";

        let listed = list_questions(
            root,
            &ListTexts::new(&strings(), &[]),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut Efivars::new().reader(),
        );

        let answers: Vec<&str> = listed
            .iter()
            .map(|(question, _)| question.value.as_str())
            .collect();
        assert_eq!(
            answers,
            [
                format!("{unavailable} <IFR default (DefaultId 0x0001): 4>"),
                unavailable.to_string(),
                format!("{unavailable} <IFR default (DefaultId 0x0001): 6>"),
            ],
            "answers before, in and after the inner FormSet"
        );
    }

    /// A question outside every FormSet, after a question in one, tries the standard default store
    /// and not the DEFAULTSTOREs of that FormSet.
    #[test]
    fn question_outside_form_sets_after_a_form_set_tries_the_standard_default_store() {
        let numeric = |default: u8| {
            [
                operation(NUMERIC, true, &uint8_numeric(0x10, 0, 10)),
                ifr_default(0x0001, default),
                END.to_vec(),
            ]
            .concat()
        };
        // a scope that is no FormSet holds both
        let data = conditional(
            SUPPRESS_IF,
            ifr_false(),
            &[form_set(&[default_store(0x0001), numeric(4)]), numeric(5)],
        );
        let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the SUPPRESS_IF");

        let listed = list_questions(
            root,
            &ListTexts::new(&strings(), &[]),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut Efivars::new().reader(),
        );

        let answers: Vec<&str> = listed.iter().map(|(q, _)| q.value.as_str()).collect();
        assert_eq!(
            answers,
            [
                "<ValueUnavailable: no supported varstore with matching id 0x0001 found> \
                 <IFR default (DefaultId 0x0001): 4>",
                "<ValueUnavailable: varstore not found because we reached root>",
            ],
            "answers in the FormSet and after it"
        );
    }

    #[test]
    fn suppressed_option_flag_is_skipped() {
        let with_condition = |condition| {
            one_of_default(
                &[],
                &[
                    conditional(SUPPRESS_IF, condition, &[flagged_option(6, 0x10, 1)]),
                    flagged_option(5, 0x10, 0),
                ],
            )
        };

        let in_true_suppress_if = |inner| {
            one_of_default(
                &[],
                &[
                    conditional(SUPPRESS_IF, ifr_true(), &[inner]),
                    flagged_option(5, 0x10, 0),
                ],
            )
        };

        let disabled = format!("{UNAVAILABLE} <IFR default: Disabled>");
        assert_eq!(with_condition(ifr_true()), disabled, "SUPPRESS_IF TRUE");
        assert_eq!(with_condition(uint8(2)), disabled, "SUPPRESS_IF 2");
        assert_eq!(
            with_condition(ifr_false()),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "SUPPRESS_IF FALSE"
        );
        assert_eq!(
            in_true_suppress_if(conditional(
                GRAY_OUT_IF,
                ifr_false(),
                &[flagged_option(6, 0x10, 1)]
            )),
            disabled,
            "GRAY_OUT_IF FALSE in SUPPRESS_IF TRUE"
        );
        assert_eq!(
            in_true_suppress_if(conditional(
                SUPPRESS_IF,
                eq_id_val(),
                &[flagged_option(6, 0x10, 1)]
            )),
            disabled,
            "unevaluated SUPPRESS_IF in SUPPRESS_IF TRUE"
        );
    }

    #[test]
    fn option_flag_under_unevaluated_condition_gives_unknown_default() {
        let children = [
            conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];
        let unflagged = [
            conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(6, 0x00, 1)]),
            flagged_option(5, 0x10, 0),
        ];
        let false_in_unevaluated = [
            conditional(
                SUPPRESS_IF,
                eq_id_val(),
                &[conditional(
                    SUPPRESS_IF,
                    ifr_false(),
                    &[flagged_option(6, 0x10, 1)],
                )],
            ),
            flagged_option(5, 0x10, 0),
        ];
        let unknown = format!(
            "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_SUPPRESS_IF condition not evaluated: \
             {QUESTION_1_UNAVAILABLE})>"
        );

        assert_eq!(
            one_of_default(&[], &children),
            unknown,
            "flagged option in unevaluated SUPPRESS_IF"
        );
        assert_eq!(
            one_of_default(&[], &unflagged),
            format!("{UNAVAILABLE} <IFR default: Disabled>"),
            "unflagged option in unevaluated SUPPRESS_IF"
        );
        assert_eq!(
            one_of_default(&[], &false_in_unevaluated),
            unknown,
            "SUPPRESS_IF FALSE in unevaluated SUPPRESS_IF"
        );
    }

    /// TRUE NOT as a multi-op expression, whose first op opens the scope END closes.
    fn true_not() -> Vec<u8> {
        [
            operation(TRUE, true, &[]),
            operation(NOT, false, &[]),
            END.to_vec(),
        ]
        .concat()
    }

    #[test]
    fn option_flag_under_multi_op_condition_follows_it() {
        let false_not = [
            operation(FALSE, true, &[]),
            operation(NOT, false, &[]),
            END.to_vec(),
        ]
        .concat();
        let cases = [
            ("TRUE NOT", true_not(), "Enabled"),
            ("FALSE NOT", false_not, "Disabled"),
        ];
        for (name, condition, default) in cases {
            let children = [
                conditional(SUPPRESS_IF, condition, &[flagged_option(6, 0x10, 1)]),
                flagged_option(5, 0x10, 0),
            ];

            assert_eq!(
                one_of_default(&[], &children),
                format!("{UNAVAILABLE} <IFR default: {default}>"),
                "{name}"
            );
        }
    }

    /// A SUPPRESS_IF on the value of another question decides the default once that value is
    /// known.
    #[test]
    fn option_flag_under_condition_on_a_known_value_follows_it() {
        let children = [
            conditional(
                SUPPRESS_IF,
                eq_id_val_of(2, 1),
                &[flagged_option(6, 0x10, 1)],
            ),
            flagged_option(5, 0x10, 0),
        ];
        let unreadable = QuestionValue::Unreadable {
            kind: ValueKind::Uint,
            reason: "r".to_string(),
        };
        let cases = [
            ("question 2 is 1", QuestionValue::Uint(1), "Disabled"),
            ("question 2 is 0", QuestionValue::Uint(0), "Enabled"),
            (
                "question 2 unreadable",
                unreadable,
                "unknown (EFI_IFR_SUPPRESS_IF condition not evaluated: EFI_IFR_EQ_ID_VAL of \
                 question 0x0002: r)",
            ),
        ];
        for (name, value, default) in cases {
            let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &children);
            let values = MapValues(BTreeMap::from([(2, value)]));

            assert_eq!(
                question_descriptor_with(&question, unavailable(), &values).value,
                format!("{UNAVAILABLE} <IFR default: {default}>"),
                "{name}"
            );
        }
    }

    #[test]
    fn default_2_on_a_known_value_is_evaluated() {
        let question_ref1 = operation(QUESTION_REF1, false, &2u16.to_le_bytes());
        let children = [
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
            ifr_default_2(0x0000, question_ref1),
        ];
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &children);
        let values = MapValues(BTreeMap::from([(2, QuestionValue::Uint(1))]));

        assert_eq!(
            question_descriptor_with(&question, unavailable(), &values).value,
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "DEFAULT_2 of question 2"
        );
    }

    #[test]
    fn default_under_suppress_if_and_option_under_gray_out_if_apply() {
        let suppressed_default = [
            conditional(SUPPRESS_IF, ifr_true(), &[ifr_default(0x0000, 1)]),
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
        ];
        let grayed_out_option = [
            conditional(GRAY_OUT_IF, ifr_true(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];

        let enabled = format!("{UNAVAILABLE} <IFR default: Enabled>");
        assert_eq!(
            one_of_default(&[], &suppressed_default),
            enabled,
            "DEFAULT in SUPPRESS_IF TRUE"
        );
        assert_eq!(
            one_of_default(&[], &grayed_out_option),
            enabled,
            "flagged option in GRAY_OUT_IF TRUE"
        );
    }

    #[test]
    fn default_and_option_under_true_disable_if_in_question_apply() {
        let disabled_default = [
            conditional(DISABLE_IF, ifr_true(), &[ifr_default(0x0000, 1)]),
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
        ];
        let disabled_option = [
            conditional(DISABLE_IF, ifr_true(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];
        let numeric = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[
                conditional(DISABLE_IF, ifr_true(), &[ifr_default(0x0000, 9)]),
                ifr_default(0x0000, 5),
            ],
            unavailable(),
        );

        let enabled = format!("{UNAVAILABLE} <IFR default: Enabled>");
        assert_eq!(
            one_of_default(&[], &disabled_default),
            enabled,
            "DEFAULT in DISABLE_IF TRUE"
        );
        assert_eq!(
            one_of_default(&[], &disabled_option),
            enabled,
            "flagged option in DISABLE_IF TRUE"
        );
        assert_eq!(
            numeric,
            format!("{UNAVAILABLE} <IFR default: 9>"),
            "NUMERIC DEFAULT in DISABLE_IF TRUE"
        );
    }

    #[test]
    fn option_under_non_constant_disable_if_in_question_applies() {
        let children = [
            conditional(DISABLE_IF, eq_id_val(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "flagged option in unevaluated DISABLE_IF"
        );
    }

    #[test]
    fn default_2_constant_overrides_option_flag() {
        let children = [
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
            ifr_default_2(0x0000, uint8(1)),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "constant DEFAULT_2 and option flag"
        );
    }

    #[test]
    fn default_2_non_constant_is_unknown() {
        let children = [
            flagged_option(5, 0x10, 0),
            ifr_default_2(0x0000, eq_id_val()),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!(
                "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_VALUE expression not evaluated: \
                 {QUESTION_1_UNAVAILABLE})>"
            ),
            "non-constant DEFAULT_2"
        );
    }

    #[test]
    fn default_2_without_value_is_unknown() {
        // DefaultId STANDARD, Type EFI_IFR_TYPE_OTHER, and no nested EFI_IFR_VALUE
        let children = [operation(DEFAULT, false, &[0x00, 0x00, 0x08])];

        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &children,
            unavailable(),
        );

        assert_eq!(
            got,
            format!(
                "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_DEFAULT_2 without EFI_IFR_VALUE)>"
            ),
            "DEFAULT_2 without its VALUE"
        );
    }

    /// UEFI 2.10 §33.3.8.3.9 and §33.3.8.3.47 rank a nested EFI_IFR_DEFAULT
    /// above a flagged EFI_IFR_ONE_OF_OPTION, and that above CHECKBOX Flags.
    #[test]
    fn option_flag_gives_numeric_and_checkbox_default() {
        let stores = [default_store(0x0000), default_store(0x0001)];
        let numeric = uint8_numeric(0x10, 0, 10);
        let cases = [
            (
                "NUMERIC option",
                NUMERIC,
                &numeric,
                vec![flagged_option(6, 0x10, 7)],
                " <IFR default: 7>",
            ),
            (
                "NUMERIC manufacturing option",
                NUMERIC,
                &numeric,
                vec![flagged_option(6, 0x20, 9)],
                " <IFR default (DefaultId 0x0001): 9>",
            ),
            (
                "DEFAULT beats NUMERIC option",
                NUMERIC,
                &numeric,
                vec![flagged_option(6, 0x10, 7), ifr_default(0x0000, 3)],
                " <IFR default: 3>",
            ),
            (
                "CHECKBOX option over clear flags",
                CHECKBOX,
                &checkbox(0, 0x00),
                vec![flagged_option(6, 0x10, 1)],
                " <IFR default: 1>",
            ),
            (
                "CHECKBOX option over set flags",
                CHECKBOX,
                &checkbox(0, 0x01),
                vec![flagged_option(5, 0x10, 0)],
                " <IFR default: 0>",
            ),
            (
                "DEFAULT beats CHECKBOX option",
                CHECKBOX,
                &checkbox(0, 0x00),
                vec![flagged_option(6, 0x10, 1), ifr_default(0x0000, 0)],
                " <IFR default: 0>",
            ),
        ];
        for (name, op_code, data, children, suffix) in cases {
            assert_eq!(
                answer(&stores, op_code, data, &children, unavailable()),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// The default's option is the first one with its value that no SUPPRESS_IF
    /// hides, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption finds it.
    #[test]
    fn one_of_default_text_skips_suppressed_options() {
        let unevaluated = format!(
            " <IFR default: unknown (EFI_IFR_SUPPRESS_IF condition not evaluated: \
             {QUESTION_1_UNAVAILABLE})>"
        );
        let cases = [
            (
                "suppressed duplicate first",
                vec![
                    conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(5, 0x00, 1)]),
                    flagged_option(6, 0x10, 1),
                ],
                " <IFR default: Enabled>",
            ),
            (
                "first of two shown duplicates",
                vec![flagged_option(5, 0x00, 1), flagged_option(6, 0x10, 1)],
                " <IFR default: Disabled>",
            ),
            (
                "unevaluated duplicate first",
                vec![
                    conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(5, 0x00, 1)]),
                    flagged_option(6, 0x10, 1),
                ],
                unevaluated.as_str(),
            ),
            (
                "shown before unevaluated duplicate",
                vec![
                    flagged_option(6, 0x10, 1),
                    conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(5, 0x00, 1)]),
                ],
                " <IFR default: Enabled>",
            ),
        ];
        for (name, children, suffix) in cases {
            assert_eq!(
                one_of_default(&[], &children),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// The Value of an EFI_IFR_DEFAULT of Type BUFFER, or of an option of an ORDERED_LIST flagged
    /// default, is the rest of its op; one without a Value is refused, not taken as an empty
    /// default.
    #[test]
    fn op_that_ends_before_its_value_is_refused() {
        // option 6, Enabled, of Type UINT16 and value 1, which sizes the containers
        let option = one_of_option(6, 0x01, &1_u16.to_le_bytes());
        // option 5 flagged EFI_IFR_OPTION_DEFAULT of Type EFI_IFR_TYPE_OTHER, whose op ends at Type
        let other = other_option(5, 0x10, &[]);
        let cases = [
            (
                "EFI_IFR_DEFAULT",
                buffer_default(0x0000, &[1, 0]),
                Ok("Enabled"),
            ),
            (
                "EFI_IFR_DEFAULT without its Value",
                buffer_default(0x0000, &[]),
                Err(DefaultError::DefaultValueMissing),
            ),
            (
                "option flagged default",
                buffer_option(5, 0x10, &[1, 0]),
                Ok("Enabled"),
            ),
            (
                "option flagged default without its Value",
                other,
                Err(DefaultError::OptionType(0x08)),
            ),
        ];
        for (name, child, want) in cases {
            let children = [option.clone(), child];
            let (_root, node) =
                parse_question(&[], ORDERED_LIST, &ordered_list(0, 1, 0x00), &children);
            let defaults: Vec<(DefaultId, Result<String, DefaultError>)> =
                question_descriptor(&node, unavailable())
                    .defaults
                    .into_iter()
                    .map(|default| (default.default_id, default.value.0))
                    .collect();
            assert_eq!(
                defaults,
                [(DefaultId::STANDARD, want.map(str::to_owned))],
                "{name}"
            );
        }
    }

    /// A DATE and a TIME take the default of a flagged EFI_IFR_ONE_OF_OPTION, below an
    /// EFI_IFR_DEFAULT, as UEFI 2.11 §33.2.5.8 lists them for any question, shown as the question
    /// shows its value.
    #[test]
    fn flagged_date_and_time_options_give_defaults() {
        // QF_TIME_SECOND_SUPPRESS
        const SECOND_SUPPRESS: u8 = 0x04;
        let date = |flags, value: &[u8]| typed_option(5, flags, 0x06, value);
        let time = |flags| typed_option(5, flags, 0x05, &[15, 33, 34]);
        let stores = [default_store(0x0000), default_store(0x0001)];
        let cases = [
            (
                "DATE option",
                DATE,
                0x00,
                vec![date(0x10, &[0xD4, 0x07, 1, 2])],
                " <IFR default: 2004-01-02>",
                vec![(DefaultId::STANDARD, "2004-01-02")],
            ),
            (
                "manufacturing DATE option",
                DATE,
                0x00,
                vec![date(0x20, &[0xE8, 0x07, 2, 0x1D])],
                " <IFR default (DefaultId 0x0001): 2024-02-29>",
                vec![(DefaultId::MANUFACTURING, "2024-02-29")],
            ),
            (
                "DEFAULT beats DATE option",
                DATE,
                0x00,
                vec![
                    date(0x10, &[0xD4, 0x07, 1, 2]),
                    typed_default(0x0000, 0x06, &[0xE8, 0x07, 2, 0x1D]),
                ],
                " <IFR default: 2024-02-29>",
                vec![(DefaultId::STANDARD, "2024-02-29")],
            ),
            (
                "TIME option",
                TIME,
                0x00,
                vec![time(0x10)],
                " <IFR default: 15:33:34>",
                vec![(DefaultId::STANDARD, "15:33:34")],
            ),
            (
                "manufacturing TIME option",
                TIME,
                0x00,
                vec![time(0x20)],
                " <IFR default (DefaultId 0x0001): 15:33:34>",
                vec![(DefaultId::MANUFACTURING, "15:33:34")],
            ),
            (
                "TIME option of a TIME that suppresses its second",
                TIME,
                SECOND_SUPPRESS,
                vec![time(0x10)],
                " <IFR default: 15:33:-->",
                vec![(DefaultId::STANDARD, "15:33:--")],
            ),
            (
                "DEFAULT beats TIME option",
                TIME,
                0x00,
                vec![time(0x10), typed_default(0x0000, 0x05, &[1, 2, 3])],
                " <IFR default: 01:02:03>",
                vec![(DefaultId::STANDARD, "01:02:03")],
            ),
            (
                "DEFAULT of a TIME beside its option of both flags",
                TIME,
                0x00,
                vec![time(0x30), typed_default(0x0001, 0x05, &[1, 2, 3])],
                " <IFR default: 15:33:34>",
                vec![
                    (DefaultId::STANDARD, "15:33:34"),
                    (DefaultId::MANUFACTURING, "01:02:03"),
                ],
            ),
        ];
        for (name, op_code, flags, children, suffix, defaults) in cases {
            let (_root, node) = parse_question(&stores, op_code, &date_time(0, flags), &children);
            let question = question_descriptor(&node, unavailable());
            let got: Vec<(DefaultId, String)> = question
                .defaults
                .iter()
                .map(|default| (default.default_id, default.value.to_string()))
                .collect();
            let want: Vec<(DefaultId, String)> = defaults
                .into_iter()
                .map(|(default_id, value)| (default_id, value.to_string()))
                .collect();

            assert_eq!(question.value, format!("{UNAVAILABLE}{suffix}"), "{name}");
            assert_eq!(got, want, "{name}: defaults");
        }
    }

    /// A flagged EFI_IFR_ONE_OF_OPTION of another Type than its question's value gives the default
    /// that an EFI_IFR_DEFAULT of its Type and Value gives (TypeValue::widened), as edk2-stable202608
    /// HiiDatabaseDxe/ConfigRouting.c copies the option's Value bytes into a default (:3235).
    #[test]
    fn options_of_another_type_give_defaults_as_an_ifr_default_of_it() {
        let date = (0x06, &[0xD4, 0x07, 1, 2][..]);
        let time = (0x05, &[15, 33, 34][..]);
        let cases = [
            (
                "UINT8 ONE_OF with a DATE option",
                ONE_OF,
                one_of_data(),
                date,
                "-44 (no matching option)",
            ),
            (
                "CHECKBOX with a DATE option",
                CHECKBOX,
                checkbox(0, 0x00),
                date,
                "1",
            ),
            (
                "DATE with a TIME option",
                DATE,
                date_time(0, 0x00),
                time,
                "8463-34-00",
            ),
        ];
        for (name, op_code, data, (value_type, value), want) in cases {
            let default_of = |children: &[Vec<u8>]| {
                let (_root, node) = parse_question(&[], op_code, &data, children);
                let defaults: Vec<(DefaultId, String)> = question_descriptor(&node, unavailable())
                    .defaults
                    .iter()
                    .map(|default| (default.default_id, default.value.to_string()))
                    .collect();
                defaults
            };

            let flagged = default_of(&[typed_option(5, 0x10, value_type, value)]);
            let declared = default_of(&[
                typed_option(5, 0x00, value_type, value),
                typed_default(0x0000, value_type, value),
            ]);

            assert_eq!(flagged, [(DefaultId::STANDARD, want.to_string())], "{name}");
            assert_eq!(flagged, declared, "{name}: as an EFI_IFR_DEFAULT");
        }
    }

    /// string_bytes gives the CHAR16s that a string held, as edk2-stable202608
    /// SetupBrowserDxe/Setup.c GetQuestionDefault copies them from HiiGetString, also where a
    /// character of it reads as U+FFFD: a surrogate pair or a private use character of a UCS-2
    /// string, or of its DUPLICATE. An SCSU string with SQU U+E000 holds none and refuses.
    #[test]
    fn string_bytes_are_the_char16s_that_strings_held() {
        let blocks = [
            // EFI_HII_SIBT_STRING_UCS2 "A", U+D83D U+DE00: 1
            &[0x14, 0x41, 0x00, 0x3D, 0xD8, 0x00, 0xDE, 0x00, 0x00][..],
            // EFI_HII_SIBT_STRING_UCS2 "A", U+E000: 2
            &[0x14, 0x41, 0x00, 0x00, 0xE0, 0x00, 0x00],
            // EFI_HII_SIBT_STRING_SCSU of SQU U+E000, then U+0000: 3
            &[0x10, 0x0E, 0xE0, 0x00, 0x00],
            // EFI_HII_SIBT_DUPLICATE of string 1: 4
            &[0x20, 0x01, 0x00],
            // EFI_HII_SIBT_STRING_UCS2 "B": 5
            &[0x14, 0x42, 0x00, 0x00, 0x00],
            // EFI_HII_SIBT_END
            &[0x00],
        ]
        .concat();
        let hiidb = package_list_with_guid(
            [0x22; 16],
            &[
                en_strings_package_with_blocks(&blocks),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let lists = read_db(&hiidb).expect("read the HiiDB");
        let [list] = lists.as_slice() else {
            panic!("{} package lists, not 1", lists.len());
        };
        let texts = ListTexts::new(&list.strings, &[]);
        let surrogate_pair = vec![0x41, 0x00, 0x3D, 0xD8, 0x00, 0xDE];
        let cases = [
            (1, Ok(surrogate_pair.clone())),
            (2, Ok(vec![0x41, 0x00, 0x00, 0xE0])),
            (3, Err(DefaultError::StringRuledOut { id: 3 })),
            (4, Ok(surrogate_pair)),
            (5, Ok(vec![0x42, 0x00])),
            (9, Err(DefaultError::StringNotFound(9))),
        ];
        for (id, want) in cases {
            assert_eq!(string_bytes(&texts, id), want, "string {id}");
        }
    }
}
