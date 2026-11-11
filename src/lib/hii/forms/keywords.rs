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

//! The question that EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL (UEFI 2.11 §35.3.1) reads or writes
//! for a keyword, found in the HiiDB as edk2-stable202608 HiiDatabaseDxe/ConfigKeywordHandler.c
//! finds it, and the checks that uefisettings makes before GetData() and SetData(): those
//! evaluate no READ, WRITE or EFI_IFR_VALUE expression, send no Callback(), address bytes only,
//! and check a value against nothing but the question's READ_ONLY flag (ExtractConfigResp,
//! EfiConfigKeywordHandlerSetData), so set's own checks run here first.

use std::cell::RefCell;
use std::fmt;
use std::ops::Range;
use std::rc::Rc;

use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use log::debug;
use thiserror::Error;

use super::char16_storage_width;
use super::choice_for_set;
use super::conditions::is_question;
use super::conditions::question_expression;
use super::conditions::question_state;
use super::conditions::question_value_expression;
use super::conditions::select;
use super::conditions::ExpressionInputs;
use super::conditions::QuestionExpression;
use super::conditions::QuestionValues;
use super::conditions::VarStoreValues;
use super::date_time::DateTimeStorage;
use super::declared_store;
use super::decoded_store;
use super::defaults::is_ordered_list_default;
use super::defaults::is_statement;
use super::defaults::option_value;
use super::defaults::option_visibility;
use super::defaults::question_default_values;
use super::defaults::question_scope;
use super::defaults::DefaultError;
use super::defaults::DefaultId;
use super::defaults::OptionVisibility;
use super::defaults::TypedDefault;
use super::find_corresponding_varstore;
use super::ordered_list::ListInput;
use super::question_values::describe_question;
use super::question_values::value_question;
use super::question_values::ListedQuestion;
use super::question_values::ValueQuestion;
use super::refers_to_bit_field;
use super::set::own_write;
use super::set::ChangeValueError;
use super::set::NewValue;
use super::set::VarStoreWrite;
use super::try_walk_scopes;
use super::walk_scopes;
use super::write_plan::list_own_write;
use super::AnswerOption;
use super::Choice;
use super::DeclaredStore;
use super::DisabledForm;
use super::FormSetWalk;
use super::IFROpCode;
use super::IFROperation;
use super::IgnoredIfr;
use super::IncludedStates;
use super::OptionTypeOp;
use super::OutsideOp;
use super::OutsidePlace;
use super::ParsedOperation;
use super::QuestionDescriptor;
use super::QuestionFlags;
use super::QuestionHeader;
use super::Range as IfrRange;
use super::ReadOnlyWriter;
use super::SelectionError;
use super::ShortVarStoreEfi;
use super::StringOp;
use super::TextInput;
use super::TimeStorage;
use super::TypeValue;
use super::Walk;
use super::EFI_HII_DATE_SIZE;
use super::EFI_HII_REF_SIZE;
use super::EFI_HII_TIME_SIZE;
use super::EFI_IFR_NUMERIC_SIZE;
use super::EFI_IFR_NUMERIC_SIZE_1;
use super::EFI_IFR_NUMERIC_SIZE_2;
use super::EFI_IFR_NUMERIC_SIZE_4;
use super::EFI_IFR_NUMERIC_SIZE_8;
use super::EFI_IFR_TYPE_NUM_SIZE_16;
use super::EFI_IFR_TYPE_NUM_SIZE_32;
use super::EFI_IFR_TYPE_NUM_SIZE_64;
use super::EFI_IFR_TYPE_NUM_SIZE_8;
use crate::exports::SetOptions;
use crate::hii::config_string::ConfigStringError;
use crate::hii::config_string::DataFilter;
use crate::hii::config_string::Keyword;
use crate::hii::config_string::KeywordInfo;
use crate::hii::config_string::KeywordInfoFilter;
use crate::hii::config_string::KeywordPath;
use crate::hii::config_string::KeywordResp;
use crate::hii::config_string::Namespace;
use crate::hii::config_string::Number;
use crate::hii::config_string::Numeric as KeywordNumeric;
use crate::hii::config_string::NumericWidth;
use crate::hii::config_string::Usage;
use crate::hii::config_string::ValueOption;
use crate::hii::config_string::ValueRange;
use crate::hii::package::ParsedPackageList;
use crate::hii::strings::Language;
use crate::hii::strings::ListTexts;
use crate::hii::variables::is_volatile;
use crate::hii::variables::DataPatch;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableLayout;
use crate::hii::variables::VolatileWrites;
use crate::parse_error::ReadParsed;

/// The language prefix that GetStringIdFromRecord searches without a NameSpaceId: edk2's
/// UEFI_CONFIG_LANG (ConfigKeywordHandler.c:1383), where UEFI 2.11 §35.3.3 says "x-UEFI-".
pub(crate) const UEFI_CONFIG_LANG: &str = "x-UEFI";

/// Why the defaults of a question of EFI_IFR_FLAG_CALLBACK are unknown.
const CALLBACK_DEFAULT: &str = "its question has EFI_IFR_FLAG_CALLBACK, so its driver's \
     Callback() with EFI_BROWSER_ACTION_DEFAULT_STANDARD outranks the defaults that the IFR \
     declares (UEFI 2.11 §33.2.5.8)";

/// Why uefisettings reads or writes no keyword through the Keyword Handler.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum KeywordRefusal {
    #[error("no package list has the device path PATH={0}")]
    NoDriver(String),
    #[error(
        "keyword {keyword}: no package list holds it in its first strings package of a language \
         {language}*"
    )]
    NotFound { keyword: String, language: String },
    #[error(
        "keyword {keyword}: strings packages of the languages {languages:?} of one package list \
         hold it, which firmware may search in another order"
    )]
    AmbiguousPackages {
        keyword: String,
        languages: Vec<String>,
    },
    #[error("keyword {keyword}: the language {language:?} of its strings package is no NAMESPACE")]
    Language { keyword: String, language: String },
    #[error("keyword {0}: a package list that holds it has no device path, which PATH names")]
    NoDevicePath(String),
    #[error("keyword {keyword}: the device path of its package list is no PATH: {reason}")]
    DevicePath { keyword: String, reason: String },
    #[error("keyword {0}: it prompts no statement of its package list")]
    NoStatement(String),
    #[error(
        "keyword {keyword}: it prompts {count} statements of its package list, of which firmware \
         may take another than the first"
    )]
    AmbiguousStatements { keyword: String, count: usize },
    #[error(
        "keyword {keyword}: it prompts an {op} outside any FormSet, at offset {offset} of a form \
         package, whose question uefisettings neither reads nor writes"
    )]
    OutsideFormSet {
        keyword: String,
        op: &'static str,
        offset: u64,
    },
    #[error("keyword {keyword}: it prompts an {op}, which has no question header")]
    NotQuestion { keyword: String, op: &'static str },
    #[error("keyword {keyword}: its {op} has no question header: {reason}")]
    NoHeader {
        keyword: String,
        op: &'static str,
        reason: String,
    },
    #[error("keyword {keyword}: its {op} has no Flags after its question header: {reason}")]
    NoNumericFlags {
        keyword: String,
        op: &'static str,
        reason: String,
    },
    #[error("keyword {keyword}: question \"{question}\" {reason}")]
    Question {
        keyword: String,
        question: String,
        reason: QuestionRefusal,
    },
    #[error(
        "keyword {0}: its <KeywordResp> has &READONLY, and SetData() writes no read-only keyword"
    )]
    ReadOnlyResp(String),
    #[error("keyword {keyword}: uefisettings does not yet implement keyword set of {op}")]
    Unchecked { keyword: String, op: &'static str },
    #[error(
        "keyword {keyword}: SetData() writes VALUE={value} as given, where set writes {written} \
         for question \"{question}\""
    )]
    Unwritten {
        keyword: String,
        value: String,
        written: String,
        question: String,
    },
    /// Unwritten where GetWidth, the VALUE's bytes, is not the StorageWidth that set writes: of
    /// an ORDERED_LIST, edk2-stable202608 ConfigKeywordHandler.c GetWidth (:1613-1618) takes the
    /// Type of the op right after it, and SetupBrowserDxe/IfrParse.c (:2370, :2492) that of its
    /// first option that is no default
    #[error(
        "keyword {keyword}: SetData() writes VALUE={value} as given, {get_width} bytes \
         (GetWidth), where set writes {written}, {storage_width} bytes (StorageWidth), for \
         question \"{question}\""
    )]
    UnwrittenWidth {
        keyword: String,
        value: String,
        get_width: usize,
        written: String,
        storage_width: usize,
        question: String,
    },
    /// An ORDERED_LIST whose containers GetWidth takes as wide as the Type of the op right after
    /// it, and set as that of its first option that is no default (UnwrittenWidth), with
    /// different widths: SetData() writes no VALUE as set does, whatever its bytes
    #[error(
        "keyword {keyword}: SetData() writes VALUE={value} as given, in containers of \
         {get_width} bytes as GetWidth takes them, where set writes containers of \
         {storage_width} bytes as StorageWidth takes them, for question \"{question}\""
    )]
    ContainerWidths {
        keyword: String,
        value: String,
        get_width: usize,
        storage_width: usize,
        question: String,
    },
    /// An ORDERED_LIST whose description holds no ListInput, which describe_question always
    /// gives it (handle_ordered_list)
    #[error(
        "keyword {keyword}: internal inconsistency: question \"{question}\" is an \
         EFI_IFR_ORDERED_LIST, but its description holds set's TextInput::{input}, not a \
         ListInput"
    )]
    ListInputMismatch {
        keyword: String,
        question: String,
        input: &'static str,
    },
    #[error("keyword {keyword}: VALUE={value} {reason} question \"{question}\"")]
    Value {
        keyword: String,
        value: String,
        question: String,
        reason: ValueRefusal,
    },
    #[error(
        "keywords {first} and {second} write overlapping bytes of EFI variable {variable}, which \
         SetData() writes one after the other"
    )]
    Overlapping {
        first: String,
        second: String,
        variable: String,
    },
    #[error(
        "keyword {keyword}: no question of it passes the <Filter> of {request}: {}",
        .found.join("; ")
    )]
    Filtered {
        keyword: String,
        request: String,
        /// Each question's PATH and KeywordKind
        found: Vec<String>,
    },
    #[error("keyword {keyword}: the request names its question of PATH={path} twice")]
    Duplicate { keyword: String, path: String },
}

/// What a `<Filter>` tests of a keyword's question: its `<UsageFilter>`, and its HII Keyword Data
/// Type, if UEFI 2.11 §35.2.1.6's table gives it one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeywordKind {
    pub(crate) usage: Usage,
    pub(crate) data_type: Option<DataFilter>,
}

impl fmt::Display for KeywordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.data_type {
            Some(data_type) => write!(f, "{}&{data_type}", self.usage),
            None => write!(f, "{}, of no HII Keyword Data Type", self.usage),
        }
    }
}

/// Why the Keyword Handler would not read or write a question as get and set do.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum QuestionRefusal {
    #[error("is a PASSWORD, which uefisettings neither reads nor writes")]
    Password,
    #[error("has no VarStore, which the Keyword Handler reads and writes")]
    Storageless,
    #[error("has EFI_IFR_FLAG_CALLBACK, and SetData() sends its driver no Callback()")]
    Callback,
    #[error("has a READ or EFI_IFR_VALUE expression, which GetData() does not evaluate")]
    Read,
    #[error("has a WRITE expression, which SetData() does not evaluate")]
    Write,
    #[error("is an EDKII bit field, whose bit offset the Keyword Handler takes for a byte offset")]
    BitField,
    #[error("has no VarStore that uefisettings reads: {0}")]
    UnreadVarStore(String),
    #[error(
        "is on an {}, whose VarName the Keyword Handler takes for a VarOffset in a request to \
         its driver, not for the EFI variable that get and set reach",
        ShortVarStoreEfi::LABEL
    )]
    ShortVarStore,
    #[error("spans bytes that hold a password, which uefisettings neither reads nor writes")]
    PasswordBytes,
    #[error("has VarStoreId {0}, which its package list also declares for {1}")]
    RedeclaredVarStore(u16, String),
    #[error(
        "may have the VarStoreId of a VarStore op of a FormSet of its package list that does not \
         decode: {0}"
    )]
    UndecodedVarStore(String),
    #[error("has VarStoreId {0}, which a VarStore {1} of its package list declares for {2}")]
    OutsideVarStore(u16, OutsidePlace, String),
    /// One outside a FormSet or in the scope of an unknown opcode
    #[error(
        "may have the VarStoreId of the VarStore at offset {0} of a form package of its package \
         list, which does not parse"
    )]
    MalformedOutsideVarStore(u64),
    #[error(
        "keeps its value in {0} (UEFI 2.11 §33.2.5.6), which get and set read and write, where \
         GetData() and SetData() take the bytes of its VarStore"
    )]
    TimeStorage(TimeStorage),
    #[error(
        "has UEFI Storage 0x30, which neither QF_DATE_STORAGE (UEFI 2.11 §33.3.8.3.11) nor \
         QF_TIME_STORAGE (§33.3.8.3.78) defines and get does not read, where GetData() and \
         SetData() take the bytes of its VarStore"
    )]
    ReservedStorage,
}

/// Why a VALUE is not one that set would write to a question.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueRefusal {
    #[error("is not as wide as")]
    Width,
    #[error("is no option of")]
    NoOption,
    /// A value of an ORDERED_LIST's VALUE, in its `container`th container, the first being 1
    #[error("holds {value} in container {container}, which is no option of")]
    NoContainerOption { container: usize, value: u64 },
}

/// Why uefisettings builds no `<KeywordInfoResp>` item of a keyword from the IFR.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum KeywordInfoRefusal {
    #[error(transparent)]
    Question(#[from] KeywordRefusal),
    #[error("keyword {keyword}: UEFI 2.11 §35.2.1.6 names no <DataType> of {op}")]
    NoDataType { keyword: String, op: &'static str },
    #[error("keyword {keyword}: its EFI_IFR_STRING has no MinSize and MaxSize: {reason}")]
    StringSizes { keyword: String, reason: String },
    #[error(
        "keyword {keyword}: whether SetupBrowserDxe shows its option of string {option} is \
         unknown: {reason}"
    )]
    OptionState {
        keyword: String,
        option: u16,
        reason: String,
    },
    #[error("keyword {keyword}: its option of string {option} holds no numeric value: {reason}")]
    OptionValue {
        keyword: String,
        option: u16,
        reason: String,
    },
    #[error("keyword {keyword}: its default of DefaultId {default_id} is unknown: {reason}")]
    Default {
        keyword: String,
        default_id: DefaultId,
        reason: String,
    },
    #[error("keyword {keyword}: no strings package of a display language holds its string {id}")]
    NoText { keyword: String, id: u16 },
    #[error(transparent)]
    ConfigString(#[from] ConfigStringError),
}

/// The `<DataType>` that UEFI 2.11 §35.2.1.6's table gives the question of an opcode.
enum TableType {
    /// Numeric, of the size that the EFI_IFR_NUMERIC_SIZE of the ONE_OF's or NUMERIC's Flags gives
    Numeric,
    Fixed(FixedType),
    /// None: the op is no question, or a PASSWORD or ACTION, which the table leaves out
    Untyped,
    /// None: a REF, which the table leaves out, whose value is an EFI_HII_REF
    Reference,
}

/// A `<DataType>` of the table that no width qualifies.
#[derive(Clone, Copy)]
enum FixedType {
    Boolean,
    String,
    Buffer,
    Date,
    Time,
}

impl From<FixedType> for DataFilter {
    fn from(fixed: FixedType) -> Self {
        match fixed {
            FixedType::Boolean => Self::Boolean,
            FixedType::String => Self::String,
            FixedType::Buffer => Self::Buffer,
            FixedType::Date => Self::Date,
            FixedType::Time => Self::Time,
        }
    }
}

impl TableType {
    fn of(op_code: IFROpCode) -> Self {
        match op_code {
            IFROpCode::OneOf | IFROpCode::Numeric => Self::Numeric,
            IFROpCode::CheckBox => Self::Fixed(FixedType::Boolean),
            IFROpCode::String => Self::Fixed(FixedType::String),
            IFROpCode::OrderedList => Self::Fixed(FixedType::Buffer),
            IFROpCode::Date => Self::Fixed(FixedType::Date),
            IFROpCode::Time => Self::Fixed(FixedType::Time),
            IFROpCode::Password | IFROpCode::Action => Self::Untyped,
            IFROpCode::Ref => Self::Reference,
            IFROpCode::Form
            | IFROpCode::Subtitle
            | IFROpCode::Text
            | IFROpCode::Image
            | IFROpCode::OneOfOption
            | IFROpCode::SuppressIf
            | IFROpCode::Locked
            | IFROpCode::ResetButton
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
            | IFROpCode::Default
            | IFROpCode::DefaultStore
            | IFROpCode::FormMap
            | IFROpCode::Catenate
            | IFROpCode::Guid
            | IFROpCode::Security
            | IFROpCode::ModalTag
            | IFROpCode::RefreshId
            | IFROpCode::WarningIf
            | IFROpCode::Match2
            | IFROpCode::Unknown(_) => Self::Untyped,
        }
    }
}

/// How a search for a keyword takes the strings packages of a package list whose language starts
/// with a namespace prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PackageSearch {
    /// The first of them alone, as GetStringIdFromRecord (ConfigKeywordHandler.c:1389)
    First,
    Every,
}

/// A strings package that holds a keyword, and the keyword's string ID there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeywordString<'a> {
    pub(crate) language: &'a Language,
    pub(crate) id: u16,
}

/// The strings of `keyword` in the strings packages of `list` whose language starts with
/// `prefix`, as edk2's AsciiStrnCmp compares them, of those that `search` takes: in each, the
/// lowest string ID of that text, as GetStringIdFromString finds it.
pub(crate) fn keyword_strings<'a: 'b, 'b>(
    list: &'a ParsedPackageList,
    prefix: &'b str,
    keyword: &'b str,
    search: PackageSearch,
) -> impl Iterator<Item = KeywordString<'a>> + 'b {
    let packages = match search {
        PackageSearch::First => 1,
        PackageSearch::Every => usize::MAX,
    };
    list.strings
        .iter()
        .filter(move |package| package.language.0.starts_with(prefix.as_bytes()))
        .take(packages)
        .filter_map(move |package| {
            let (&id, _) = package
                .strings
                .iter()
                .find(|(_, text)| ***text == *keyword)?;
            Some(KeywordString {
                language: &package.language,
                id,
            })
        })
}

/// What SetData() of a keyword writes, as check_set found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeywordWrite {
    /// The variable of the question's VarStore
    pub(crate) variable: VariableKey,
    /// The VarOffsets of the bytes written
    pub(crate) bytes: Vec<Range<usize>>,
    /// Whether the variable is volatile, as the reader read its attributes
    pub(crate) volatile: bool,
}

/// The statement that a keyword prompts in its package list, and `path`, what the search takes of
/// that list besides: its device path, for the Keyword Handler (resolve), or nothing, for get
/// and set, which select offline (KeywordStatement).
pub(crate) struct KeywordQuestion<'a, P = KeywordPath> {
    keyword: Keyword,
    /// The language of the strings package that holds the keyword
    namespace: Namespace,
    path: P,
    texts: ListTexts<'a>,
    /// The roots of the form packages of the package list
    roots: &'a [Rc<RefCell<IFROperation>>],
    /// The forms that read_db drops from them, which hold their VarStore ops
    disabled_forms: &'a [DisabledForm],
    /// The VarStores and statements of the form packages of the package list outside any FormSet,
    /// and the VarStores in the scope of an unknown opcode in one
    outside: &'a [OutsideOp],
    /// Those VarStores that do not parse
    malformed_stores: &'a [IgnoredIfr],
    /// The root of the form package of the statement
    root: &'a Rc<RefCell<IFROperation>>,
    op: Rc<RefCell<IFROperation>>,
}

/// A statement that a keyword prompts, found without PATH in a package list with or without a
/// device path: get and set select it offline, where no `<KeywordResp>` names its list.
pub(crate) type KeywordStatement<'a> = KeywordQuestion<'a, ()>;

impl<'a, P> KeywordQuestion<'a, P> {
    /// The statements that the Keyword Handler takes for `keyword`, in `namespace`, else in a
    /// language of the prefix "x-UEFI": in the package list of the device path `path`
    /// (GetRecordFromDevicePath), else in each list, in database order
    /// (ConfigKeywordHandler.c:2393), whose first strings package of that language has the
    /// keyword (GetStringIdFromRecord) and whose statements it prompts; there the first
    /// statement, in IFR order, that the keyword's string prompts (FindQuestionFromStringId,
    /// IsStatementOpCode). Refuses a keyword that other strings packages of the list hold too,
    /// or that prompts other statements too, which firmware may take instead, or a statement
    /// outside any FormSet, and a list that `list_path`, given the list and the keyword, refuses
    /// before its statements are searched. Its texts show in the language that
    /// ParsedPackageList::texts picks for `requested`.
    fn find(
        lists: &'a [ParsedPackageList],
        namespace: Option<&Namespace>,
        path: Option<&KeywordPath>,
        keyword: &Keyword,
        requested: &[&str],
        list_path: impl Fn(&ParsedPackageList, &str) -> Result<P, KeywordRefusal>,
    ) -> Result<Vec<Self>, KeywordRefusal> {
        let prefix = namespace.map_or_else(|| UEFI_CONFIG_LANG.to_owned(), ToString::to_string);
        let candidates: Vec<&ParsedPackageList> = match path {
            Some(path) => vec![lists
                .iter()
                .find(|list| list.device_path.as_ref() == Some(path.as_ref()))
                .ok_or_else(|| KeywordRefusal::NoDriver(path.to_string()))?],
            None => lists.iter().collect(),
        };
        let text = keyword.to_string();
        let mut questions = Vec::new();
        let mut unprompted = false;
        for list in candidates {
            let Some(string) = keyword_strings(list, &prefix, &text, PackageSearch::First).next()
            else {
                continue;
            };
            match (
                Self::in_list(list, string, &prefix, keyword, requested, &list_path),
                path,
            ) {
                (Ok(question), _) => questions.push(question),
                // a driver may add one strings package to lists whose forms differ
                (Err(KeywordRefusal::NoStatement(_)), None) => unprompted = true,
                (Err(refusal), _) => return Err(refusal),
            }
        }
        match (questions.is_empty(), unprompted) {
            (false, _) => Ok(questions),
            (true, true) => Err(KeywordRefusal::NoStatement(text)),
            (true, false) => Err(KeywordRefusal::NotFound {
                keyword: text,
                language: prefix,
            }),
        }
    }

    /// The statement that the keyword `string` of `list` prompts, refused unless `string` is the
    /// only one of the keyword under `prefix` and prompts that statement alone, or if
    /// `list_path` refuses `list`.
    fn in_list(
        list: &'a ParsedPackageList,
        string: KeywordString<'_>,
        prefix: &str,
        keyword: &Keyword,
        requested: &[&str],
        list_path: &impl Fn(&ParsedPackageList, &str) -> Result<P, KeywordRefusal>,
    ) -> Result<Self, KeywordRefusal> {
        let text = keyword.to_string();
        let holders: Vec<KeywordString<'_>> =
            keyword_strings(list, prefix, &text, PackageSearch::Every).collect();
        if holders.len() > 1 {
            return Err(KeywordRefusal::AmbiguousPackages {
                keyword: text,
                languages: holders
                    .iter()
                    .map(|holder| holder.language.0.escape_ascii().to_string())
                    .collect(),
            });
        }
        let namespace = namespace_of(string.language).ok_or_else(|| KeywordRefusal::Language {
            keyword: text.clone(),
            language: string.language.0.escape_ascii().to_string(),
        })?;
        let path = list_path(list, &text)?;
        let (root, op) = match <[_; 1]>::try_from(statements(list, string.id)) {
            Ok([Statement::InFormSet { root, op }]) => (root, op),
            Ok([Statement::Outside(outside)]) => {
                return Err(KeywordRefusal::OutsideFormSet {
                    keyword: text,
                    op: outside.op.op_code.spec_name(),
                    offset: outside.offset,
                })
            }
            Err(statements) if statements.is_empty() => {
                return Err(KeywordRefusal::NoStatement(text))
            }
            Err(statements) => {
                return Err(KeywordRefusal::AmbiguousStatements {
                    keyword: text,
                    count: statements.len(),
                })
            }
        };
        Ok(Self {
            keyword: keyword.clone(),
            namespace,
            path,
            texts: list.texts(requested),
            roots: &list.forms,
            disabled_forms: &list.disabled_forms,
            outside: &list.outside_ifr,
            malformed_stores: &list.malformed_outside_stores,
            root,
            op,
        })
    }

    pub(crate) fn namespace(&self) -> &Namespace {
        &self.namespace
    }
}

impl<'a> KeywordStatement<'a> {
    /// The statements of find for `keyword` in `namespace`, else in a language of the prefix
    /// "x-UEFI", in every list of `lists` that holds it, with or without a device path.
    pub(crate) fn resolve_offline(
        lists: &'a [ParsedPackageList],
        namespace: Option<&Namespace>,
        keyword: &Keyword,
    ) -> Result<Vec<Self>, KeywordRefusal> {
        Self::find(lists, namespace, None, keyword, &[], |_, _| Ok(()))
    }

    /// The root of the form package of the statement
    pub(crate) fn root(&self) -> &'a Rc<RefCell<IFROperation>> {
        self.root
    }

    pub(crate) fn op(&self) -> &Rc<RefCell<IFROperation>> {
        &self.op
    }
}

impl<'a> KeywordQuestion<'a> {
    /// The statements of find, for the Keyword Handler, each with the device path of its package
    /// list: `path`, else the list's, and their texts in the language that `requested` picks.
    /// Refuses a list without a device path, or with one that is no KeywordPath, as a
    /// `<KeywordResp>` names it (edk2-stable202608 GetStringIdFromDatabase asserts on such a list,
    /// ConfigKeywordHandler.c:2411).
    pub(crate) fn resolve(
        lists: &'a [ParsedPackageList],
        namespace: Option<&Namespace>,
        path: Option<&KeywordPath>,
        keyword: &Keyword,
        requested: &[&str],
    ) -> Result<Vec<Self>, KeywordRefusal> {
        Self::find(
            lists,
            namespace,
            path,
            keyword,
            requested,
            |list, text| match (path, &list.device_path) {
                (Some(path), _) => Ok(path.clone()),
                (None, Some(device_path)) => {
                    KeywordPath::try_from(device_path.clone()).map_err(|error| {
                        KeywordRefusal::DevicePath {
                            keyword: text.to_owned(),
                            reason: error.to_string(),
                        }
                    })
                }
                (None, None) => Err(KeywordRefusal::NoDevicePath(text.to_owned())),
            },
        )
    }

    pub(crate) fn path(&self) -> &KeywordPath {
        &self.path
    }

    /// Refuses a get of the question that GetData() would answer otherwise than get: with the
    /// stored value of one whose value READ or EFI_IFR_VALUE gives, with the bytes at its bit
    /// offset, or with its VarStore's bytes of a DATE or TIME of EFI Date/Time Storage or of UEFI
    /// Storage 0x30; or of a PASSWORD, or of a question whose bytes (keyword_bytes) overlap those
    /// that `reader` withholds, which hold a password.
    pub(crate) fn check_get(&self, reader: &EfivarReader) -> Result<(), KeywordRefusal> {
        self.check_question(QuestionExpression::Read, reader)?;
        Ok(())
    }

    /// Refuses a set of `resp`, the question's keyword, that SetData() would write otherwise than
    /// set: through no WRITE expression, Callback(), EFI Date/Time Storage or UEFI Storage 0x30,
    /// or with a VALUE not as wide as the GetWidth bytes (keyword_width) that SetData() writes as
    /// given (edk2-stable202608 ConfigKeywordHandler.c ExtractConfigResp :2219-2220,
    /// ConfigRouting.c HiiConfigToBlock :6353); else takes it through set's own checks, with
    /// `include`, `volatile` and the variables of `reader`: the question's state, whether it is
    /// read-only, which no `include` lifts, its option of the VALUE or the VALUE's range, the
    /// fields of a DATE or TIME (DateTimeInput::number_value), the items of an ORDERED_LIST
    /// (list_write), the EFI_HII_REF of a REF, which set does not write, the variable's, and
    /// whether the bytes written overlap those that `reader` withholds, which hold a password
    /// (ChangeValueError::PasswordBytes); and refuses a VALUE that is not the bytes that set
    /// writes. Returns what SetData() writes.
    pub(crate) fn check_set(
        &self,
        resp: &KeywordResp,
        include: IncludedStates,
        volatile: VolatileWrites,
        reader: &mut EfivarReader,
    ) -> Result<KeywordWrite> {
        let header = self.check_question(QuestionExpression::Write, reader)?;
        if resp.usage == Usage::ReadOnly {
            return Err(KeywordRefusal::ReadOnlyResp(self.keyword.to_string()).into());
        }
        let op = self.op.borrow();
        // set takes no STRING (ListedQuestion), and keyword set takes none yet
        let Some(listed) = ListedQuestion::of(&op) else {
            return Err(self.unchecked(&op).into());
        };
        let prompt = self.texts.display(header.prompt_string_id);
        if keyword_width(&op) != Some(resp.value.as_bytes().len()) {
            return Err(self.value_refusal(resp, prompt, ValueRefusal::Width).into());
        }
        let descriptor = self
            .chosen(listed, prompt, include, volatile, reader)
            .with_context(|| format!("keyword {}", self.keyword))?;
        let write = match listed {
            ListedQuestion::Value(question) => {
                self.value_write(question, &descriptor, resp, prompt, include, reader)?
            }
            ListedQuestion::OrderedList(_) => {
                let TextInput::OrderedList(input) = &descriptor.input else {
                    return Err(KeywordRefusal::ListInputMismatch {
                        keyword: self.keyword.to_string(),
                        question: descriptor.question.clone(),
                        input: descriptor.input.kind(),
                    }
                    .into());
                };
                Some(self.list_write(input, &descriptor, resp, prompt, include, reader)?)
            }
            // as set refuses it, after its choice (plan_question)
            ListedQuestion::Ref(_) => {
                return Err(ChangeValueError::CrossReference {
                    question: descriptor.question.clone(),
                })
                .with_context(|| format!("keyword {}", self.keyword));
            }
        };
        let write =
            write.ok_or_else(|| self.question_refusal(&header, QuestionRefusal::Storageless))?;
        // SetData() writes the VALUE as given: only where set writes those very bytes
        if write.patches != [(header.var_store_info, resp.value.as_bytes().to_vec())] {
            return Err(self.unwritten(resp, prompt, &write.patches)?.into());
        }
        let variable = write.store.variable_key();
        let bytes: Vec<Range<usize>> = write
            .patches
            .iter()
            .map(|(offset, bytes)| {
                let start = usize::from(*offset);
                start..start + bytes.len()
            })
            .collect();
        // SetData() writes every byte of the question's storage, changed or not
        reader
            .check_patches(
                &variable,
                write.patches.iter().map(|(offset, bytes)| DataPatch {
                    offset: *offset,
                    bytes,
                }),
            )
            .map_err(|refusal| ChangeValueError::PasswordBytes {
                question: prompt.to_owned(),
                refusal,
            })
            .with_context(|| format!("keyword {}", self.keyword))?;
        Ok(KeywordWrite {
            variable,
            bytes,
            volatile: reader.attributes(write.store).is_some_and(is_volatile),
        })
    }

    /// The `<KeywordInfoResp>` items of `filter` for the question, from its IFR alone, by UEFI
    /// 2.11 §35.2.1.6: its `<DataType>` (data_type); its `<ValueRange>` and the `<ValueOption>`s
    /// that SetupBrowserDxe shows (value_range, value_options); its defaults of the 3 standard
    /// default stores, as question_default_values finds them (default_number); and its prompt,
    /// as display shows it. Conditions and EFI_IFR_VALUEs read the variables of `reader`.
    /// Refuses an item that the IFR does not tell, rather than leave it out. The defaults are
    /// those the IFR declares (EFI_IFR_DEFAULT, flagged options, CHECKBOX flags), which a
    /// driver's Callback() with EFI_BROWSER_ACTION_DEFAULT_x and its ALTCFG response outrank
    /// (UEFI 2.11 §33.2.5.8), so a platform's default may differ; those of a question of
    /// EFI_IFR_FLAG_CALLBACK, whose driver's Callback() may answer for them, are refused.
    pub(crate) fn info(
        &self,
        filter: KeywordInfoFilter,
        reader: &mut EfivarReader,
    ) -> Result<KeywordInfo, KeywordInfoRefusal> {
        let op = self.op.borrow();
        let values = VarStoreValues::new(self.root, None);
        let mut walk = FormSetWalk::new(&self.texts, reader, &values, IncludedStates::empty());
        let mut info = KeywordInfo::default();
        if filter.contains(KeywordInfoFilter::DATA_TYPE) {
            let data_type = self.data_type(&op)?;
            info.data_type = Some(data_type.ok_or_else(|| KeywordInfoRefusal::NoDataType {
                keyword: self.keyword.to_string(),
                op: op.op_code.spec_name(),
            })?);
        }
        if filter.contains(KeywordInfoFilter::VALUE_ATTRIBUTE) {
            info.range = self.value_range(&op)?;
            info.options = self.value_options(&op, &mut walk.inputs)?;
        }
        if filter.contains(KeywordInfoFilter::DEFAULT) {
            if is_question(op.op_code)
                && self.header(&op)?.flags().contains(QuestionFlags::CALLBACK)
            {
                return Err(self.default_refusal(DefaultId::STANDARD, CALLBACK_DEFAULT.to_owned()));
            }
            let stores = walk.default_stores.of(&op, &mut walk.inputs);
            for (default_id, value) in question_default_values(&op, stores, &mut walk.inputs) {
                let default = match default_id {
                    DefaultId::STANDARD => &mut info.standard_default,
                    DefaultId::MANUFACTURING => &mut info.manufacturing_default,
                    DefaultId::SAFE => &mut info.safe_default,
                    // "Only the three standard defaults stores are supported" (UEFI 2.11
                    // §35.2.1.6)
                    _ => continue,
                };
                *default = Some(self.default_number(&op, default_id, value)?);
            }
        }
        if filter.contains(KeywordInfoFilter::DISPLAY_NAME) {
            info.display_name = Some(self.text(self.header(&op)?.prompt_string_id)?);
        }
        Ok(info)
    }

    /// The question's KeywordKind: ReadOnly if it has EFI_IFR_FLAG_READ_ONLY, the flag of the
    /// "&READONLY" of edk2-stable202608's `<KeywordResp>` and of its `<UsageFilter>`
    /// (ExtractReadOnlyFromOpCode, ConfigKeywordHandler.c:510-520), and its data_type.
    pub(crate) fn kind(&self) -> Result<KeywordKind, KeywordRefusal> {
        let op = self.op.borrow();
        let usage = match self.header(&op)?.flags().contains(QuestionFlags::READ_ONLY) {
            true => Usage::ReadOnly,
            false => Usage::ReadWrite,
        };
        Ok(KeywordKind {
            usage,
            data_type: self.data_type(&op)?,
        })
    }

    /// The HII Keyword Data Type of `op`, the question, by the table of UEFI 2.11 §35.2.1.6, None
    /// for an op that it leaves out; by op code, decoded or not, as edk2-stable202608
    /// ValidateFilter types it (ConfigKeywordHandler.c:559, :589-619): a ONE_OF's or NUMERIC's
    /// Numeric is of the EFI_IFR_NUMERIC_SIZE of the Flags after its question header, as
    /// "Numeric:2" is "a two-byte numeric value", refused if the op ends before them.
    fn data_type(&self, op: &IFROperation) -> Result<Option<DataFilter>, KeywordRefusal> {
        Ok(match TableType::of(op.op_code) {
            TableType::Numeric => Some(self.numeric_type(op)?),
            TableType::Fixed(fixed) => Some(fixed.into()),
            TableType::Untyped | TableType::Reference => None,
        })
    }

    /// The Numeric `<DataType>` of `op`, a ONE_OF or NUMERIC, of the EFI_IFR_NUMERIC_SIZE of its
    /// Flags.
    fn numeric_type(&self, op: &IFROperation) -> Result<DataFilter, KeywordRefusal> {
        let numeric: NumericFlagsOp =
            Cursor::new(&op.data)
                .parse_le()
                .map_err(|error| KeywordRefusal::NoNumericFlags {
                    keyword: self.keyword.to_string(),
                    op: op.op_code.spec_name(),
                    reason: error.to_string(),
                })?;
        let width = match numeric.flags & EFI_IFR_NUMERIC_SIZE {
            EFI_IFR_NUMERIC_SIZE_1 => NumericWidth::One,
            EFI_IFR_NUMERIC_SIZE_2 => NumericWidth::Two,
            EFI_IFR_NUMERIC_SIZE_4 => NumericWidth::Four,
            // EFI_IFR_NUMERIC_SIZE_8, the only value left
            EFI_IFR_NUMERIC_SIZE_8.. => NumericWidth::Eight,
        };
        Ok(DataFilter::Numeric(KeywordNumeric { width: Some(width) }))
    }

    /// The `<ValueRange>` of `op`: a NUMERIC's MinValue, MaxValue and Step, which a Step of 0
    /// leaves out ("the input mechanism for the numeric value is to be free-form", UEFI 2.11
    /// §33.3.8.3.47), or a STRING's MinSize and MaxSize (§33.3.8.3.70); none of another question.
    fn value_range(&self, op: &IFROperation) -> Result<Option<ValueRange>, KeywordInfoRefusal> {
        if let ParsedOperation::Numeric(numeric) = &op.parsed_data {
            let (min, max, step) = match &numeric.data {
                IfrRange::Range8(range) => (
                    range.min_value.to_le_bytes().to_vec(),
                    range.max_value.to_le_bytes().to_vec(),
                    range.step.to_le_bytes().to_vec(),
                ),
                IfrRange::Range16(range) => (
                    range.min_value.to_le_bytes().to_vec(),
                    range.max_value.to_le_bytes().to_vec(),
                    range.step.to_le_bytes().to_vec(),
                ),
                IfrRange::Range32(range) => (
                    range.min_value.to_le_bytes().to_vec(),
                    range.max_value.to_le_bytes().to_vec(),
                    range.step.to_le_bytes().to_vec(),
                ),
                IfrRange::Range64(range) => (
                    range.min_value.to_le_bytes().to_vec(),
                    range.max_value.to_le_bytes().to_vec(),
                    range.step.to_le_bytes().to_vec(),
                ),
            };
            let step = match step.iter().all(|&byte| byte == 0) {
                true => None,
                false => Some(Number::try_from(step)?),
            };
            return Ok(Some(ValueRange {
                max: Number::try_from(max)?,
                min: Number::try_from(min)?,
                step,
            }));
        }
        if op.op_code != IFROpCode::String {
            return Ok(None);
        }
        let string: StringOp =
            Cursor::new(&op.data)
                .parse_le()
                .map_err(|error| KeywordInfoRefusal::StringSizes {
                    keyword: self.keyword.to_string(),
                    reason: error.to_string(),
                })?;
        Ok(Some(ValueRange {
            max: Number::try_from(vec![string.max_size])?,
            min: Number::try_from(vec![string.min_size])?,
            step: None,
        }))
    }

    /// The `<ValueOption>`s of `op`, if a ONE_OF or an ORDERED_LIST: the options in its scope that
    /// SetupBrowserDxe shows, as `inputs` evaluate their SUPPRESS_IFs, but the flagged options of
    /// an ORDERED_LIST, which are its defaults (is_ordered_list_default); each of an ORDERED_LIST
    /// names its VALUETYPE, the type of the buffer's elements.
    fn value_options(
        &self,
        op: &IFROperation,
        inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    ) -> Result<Vec<ValueOption>, KeywordInfoRefusal> {
        if op.op_code != IFROpCode::OneOf && op.op_code != IFROpCode::OrderedList {
            return Ok(Vec::new());
        }
        let mut options = Vec::new();
        for option in question_scope(op) {
            let option = option.borrow();
            let ParsedOperation::OneOfOption(parsed) = &option.parsed_data else {
                continue;
            };
            if is_ordered_list_default(op, parsed) {
                continue;
            }
            let id = parsed.option_string_id;
            match option_visibility(&option, inputs) {
                OptionVisibility::Shown => {}
                OptionVisibility::Suppressed => continue,
                OptionVisibility::Unknown(reason) => {
                    return Err(KeywordInfoRefusal::OptionState {
                        keyword: self.keyword.to_string(),
                        option: id,
                        reason,
                    })
                }
            }
            let (bytes, width) = option_value(op, &option, parsed, inputs)
                .map_err(|error| error.to_string())
                .and_then(|value| numeric_bytes(value).ok_or_else(|| format!("{value:?}")))
                .map_err(|reason| KeywordInfoRefusal::OptionValue {
                    keyword: self.keyword.to_string(),
                    option: id,
                    reason,
                })?;
            options.push(ValueOption {
                value: Number::try_from(bytes)?,
                string: self.text(id)?,
                value_type: (op.op_code == IFROpCode::OrderedList)
                    .then_some(KeywordNumeric { width: Some(width) }),
            });
        }
        Ok(options)
    }

    /// `value`, the question's default of `default_id`, as the `<Number>` of the question's value
    /// bytes (keyword_width): a ONE_OF's, NUMERIC's or CHECKBOX's number; a DATE's or TIME's
    /// number, its EFI_HII_DATE or EFI_HII_TIME as TypeValue::widened takes it; a STRING's string, in
    /// the CHAR16s of display's language, zero-padded to MaxSize CHAR16s, as edk2-stable202608
    /// SetupBrowserDxe/Setup.c:4501-4512 stores it in a storage of MaxSize × 2 bytes
    /// (IfrParse.c:2225); an ORDERED_LIST's buffer (Setup.c:4493-4495), whose missing containers
    /// are 0 (UEFI 2.11 §33.2.5.4.8); a REF's EFI_HII_REF. Refuses a default that does not fit,
    /// of another type, or of a PASSWORD or ACTION, which the table leaves out.
    fn default_number(
        &self,
        op: &IFROperation,
        default_id: DefaultId,
        value: Result<TypedDefault, DefaultError>,
    ) -> Result<Number, KeywordInfoRefusal> {
        let value = value.map_err(|error| self.default_refusal(default_id, error.to_string()))?;
        let name = op.op_code.spec_name();
        let width = keyword_width(op).ok_or_else(|| {
            self.default_refusal(default_id, format!("{name} has no value width"))
        })?;
        let mut bytes = match (TableType::of(op.op_code), value) {
            (
                TableType::Numeric
                | TableType::Fixed(FixedType::Boolean | FixedType::Date | FixedType::Time),
                TypedDefault::Number(number),
            ) => number.to_le_bytes().to_vec(),
            (TableType::Fixed(FixedType::String), TypedDefault::String(id)) => self
                .text(id)?
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect(),
            (TableType::Fixed(FixedType::Buffer), TypedDefault::Buffer(bytes))
                if !bytes.is_empty() =>
            {
                bytes
            }
            (TableType::Reference, TypedDefault::Ref(bytes)) => bytes,
            (
                TableType::Numeric
                | TableType::Fixed(
                    FixedType::Boolean
                    | FixedType::String
                    | FixedType::Buffer
                    | FixedType::Date
                    | FixedType::Time,
                )
                | TableType::Reference,
                value @ (TypedDefault::Number(_)
                | TypedDefault::String(_)
                | TypedDefault::Buffer(_)
                | TypedDefault::Ref(_)),
            ) => {
                let reason = format!("{name} holds no {value:?}");
                return Err(self.default_refusal(default_id, reason));
            }
            (
                TableType::Untyped,
                TypedDefault::Number(_)
                | TypedDefault::String(_)
                | TypedDefault::Buffer(_)
                | TypedDefault::Ref(_),
            ) => {
                let reason = format!("uefisettings does not decode a default of {name}");
                return Err(self.default_refusal(default_id, reason));
            }
        };
        let past_width = bytes.split_off(width.min(bytes.len()));
        if past_width.iter().any(|&byte| byte != 0) {
            let reason = format!("it is wider than the question's {width} bytes");
            return Err(self.default_refusal(default_id, reason));
        }
        bytes.resize(width, 0);
        Ok(Number::try_from(bytes)?)
    }

    fn default_refusal(&self, default_id: DefaultId, reason: String) -> KeywordInfoRefusal {
        KeywordInfoRefusal::Default {
            keyword: self.keyword.to_string(),
            default_id,
            reason,
        }
    }

    /// The text of string `id` that display shows, as a `<String>`'s CHAR16s, refused unless a
    /// strings package of a display language holds it (ListTexts::shown_text), and if empty, as
    /// `<String> ::= [<Char>]+` (UEFI 2.11 §35.2.1.2).
    fn text(&self, id: u16) -> Result<Vec<u16>, KeywordInfoRefusal> {
        self.texts
            .shown_text(id)
            .filter(|text| !text.is_empty())
            .map(|text| text.encode_utf16().collect())
            .ok_or_else(|| KeywordInfoRefusal::NoText {
                keyword: self.keyword.to_string(),
                id,
            })
    }

    /// The question header of the question, refused unless GetData() (`Read`) or SetData()
    /// (`Write`) reaches it as get or set does.
    fn check_question(
        &self,
        access: QuestionExpression,
        reader: &EfivarReader,
    ) -> Result<QuestionHeader, KeywordRefusal> {
        let op = self.op.borrow();
        let header = self.header(&op)?;
        if op.op_code == IFROpCode::Password {
            return Err(self.question_refusal(&header, QuestionRefusal::Password));
        }
        if header.var_store_id == 0 {
            return Err(self.question_refusal(&header, QuestionRefusal::Storageless));
        }
        if let ParsedOperation::Date(question) | ParsedOperation::Time(question) = &op.parsed_data {
            match question.storage() {
                DateTimeStorage::Normal => {}
                DateTimeStorage::Efi(storage) => {
                    return Err(
                        self.question_refusal(&header, QuestionRefusal::TimeStorage(storage))
                    )
                }
                // edk2-stable202608 SetupBrowserDxe neither reads nor writes it (IfrParse.c gives
                // it no Storage, Setup.c GetQuestionValue returns), while ConfigKeywordHandler.c
                // GetWidth gives it the bytes of an EFI_HII_DATE or EFI_HII_TIME
                DateTimeStorage::Reserved => {
                    return Err(self.question_refusal(&header, QuestionRefusal::ReservedStorage))
                }
            }
        }
        let value_expression = question_value_expression(&op).is_some();
        let flags = header.flags();
        match access {
            QuestionExpression::Read if value_expression => {
                return Err(self.question_refusal(&header, QuestionRefusal::Read))
            }
            // set refuses a read-only question as it chooses it (chosen)
            QuestionExpression::Write if flags.contains(QuestionFlags::CALLBACK) => {
                return Err(self.question_refusal(&header, QuestionRefusal::Callback))
            }
            QuestionExpression::Read | QuestionExpression::Write => {}
        }
        if question_expression(&self.op, access).is_some() {
            return Err(self.question_refusal(
                &header,
                match access {
                    QuestionExpression::Read => QuestionRefusal::Read,
                    QuestionExpression::Write => QuestionRefusal::Write,
                },
            ));
        }
        if refers_to_bit_field(&op) {
            return Err(self.question_refusal(&header, QuestionRefusal::BitField));
        }
        let store = find_corresponding_varstore(Rc::clone(&self.op), header.var_store_id).map_err(
            |error| {
                self.question_refusal(
                    &header,
                    QuestionRefusal::UnreadVarStore(format!("{error:#}")),
                )
            },
        )?;
        // edk2-stable202608 ConfigKeywordHandler.c ExtractConfigRequest and ExtractConfigResp
        // (:2114, :2219) put its VarName in OFFSET=, and ConfigRouting.c GetVarStoreType (:1902)
        // sends a request on a VARSTORE_EFI before UEFI 2.3.1 to the driver's ExtractConfig and
        // RouteConfig
        match store.layout() {
            VariableLayout::Offsets => {}
            VariableLayout::OneValue => {
                return Err(self.question_refusal(&header, QuestionRefusal::ShortVarStore))
            }
        }
        // GetData() answers with the question's bytes; check_set refuses a SetData() of them
        if access == QuestionExpression::Read
            && reader
                .withheld_overlap(&store.variable_key(), &keyword_bytes(&op, &header))
                .is_some()
        {
            return Err(self.question_refusal(&header, QuestionRefusal::PasswordBytes));
        }
        if let Some(other) = self.other_declaration(header.var_store_id, &store.variable_key()) {
            return Err(self.question_refusal(&header, other));
        }
        if let Some((place, other)) =
            self.outside_declaration(header.var_store_id, &store.variable_key())
        {
            return Err(self.question_refusal(
                &header,
                QuestionRefusal::OutsideVarStore(header.var_store_id, place, other),
            ));
        }
        // FindStorageFromVarId reads the VarStoreId of such a VarStore as it reads any
        if let Some(malformed) = self.malformed_stores.first() {
            return Err(self.question_refusal(
                &header,
                QuestionRefusal::MalformedOutsideVarStore(malformed.offset),
            ));
        }
        Ok(header)
    }

    /// The refusal of a VarStore op of VarStoreId `id` in a FormSet of the package list, its own
    /// included, whatever the ops around it, in forms, the forms that read_db disables and unknown
    /// ops too, that is not of the EFI variable `variable`, or that does not decode, so that its
    /// VarStoreId is unknown: UEFI 2.11 §33.3.8.3.89 EFI_IFR_VARSTORE makes a VarStoreId unique
    /// only within its FormSet, and edk2-stable202608 FindStorageFromVarId
    /// (ConfigKeywordHandler.c:1519-1570), from GetData() and SetData() (:2108, :2213), takes the
    /// first VarStore op of the id in the form package, whatever its scope, which may not be the
    /// one that find_corresponding_varstore takes, and other firmware may take another.
    /// outside_declaration refuses those outside any FormSet, and those in the scope of an unknown
    /// opcode that decode (declaration_refusal).
    fn other_declaration(&self, id: u16, variable: &VariableKey) -> Option<QuestionRefusal> {
        let disabled = self.disabled_forms.iter().map(|disabled| &disabled.form);
        self.roots.iter().chain(disabled).find_map(|tree| {
            try_walk_scopes(std::slice::from_ref(tree), (), |node, ()| {
                declaration_refusal(&node.borrow(), id, variable)
            })
            .err()
        })
    }

    /// The store, as text, that a VarStore outside any FormSet of the package list, or in the
    /// scope of an unknown opcode, declares for VarStoreId `id`, unless it is the EFI variable
    /// `variable` too, with where that VarStore sits: FindStorageFromVarId walks the whole form
    /// package.
    fn outside_declaration(
        &self,
        id: u16,
        variable: &VariableKey,
    ) -> Option<(OutsidePlace, String)> {
        self.outside
            .iter()
            .filter_map(|outside| Some((outside.place, declared_store(&outside.op.parsed_data)?)))
            .filter(|&(_, (declared, _))| declared == id)
            .find_map(|(place, (_, store))| Some((place, other_store(store, variable)?)))
    }

    /// The EFI_IFR_QUESTION_HEADER of `op`, the question's.
    fn header(&self, op: &IFROperation) -> Result<QuestionHeader, KeywordRefusal> {
        let name = op.op_code.spec_name();
        if !is_question(op.op_code) {
            return Err(KeywordRefusal::NotQuestion {
                keyword: self.keyword.to_string(),
                op: name,
            });
        }
        Cursor::new(&op.data)
            .parse_le()
            .map_err(|error| KeywordRefusal::NoHeader {
                keyword: self.keyword.to_string(),
                op: name,
                reason: error.to_string(),
            })
    }

    /// The question, `question` prompted by `prompt`, as set chooses it with `include`, `volatile`
    /// and the variables of `reader`: refused in a state that `include` does not allow, read-only,
    /// or in a variable that set does not write.
    fn chosen(
        &self,
        question: ListedQuestion<'_>,
        prompt: &str,
        include: IncludedStates,
        volatile: VolatileWrites,
        reader: &mut EfivarReader,
    ) -> Result<QuestionDescriptor> {
        let selection = {
            let values = VarStoreValues::new(self.root, None);
            let mut walk = FormSetWalk::new(&self.texts, reader, &values, include);
            let state = question_state(&self.op.borrow(), &mut walk.inputs);
            select(vec![(question, state)], include)
                .map(|question| describe_question(&self.op, question, &mut walk))
        };
        let options = SetOptions {
            include,
            volatile,
            ..SetOptions::default()
        };
        let writer = ReadOnlyWriter::KeywordHandler;
        match choice_for_set(selection, prompt, &options, writer, reader)? {
            Choice::Chosen(descriptor, _) => Ok(descriptor),
            Choice::Skipped(exclusion) if exclusion.is_empty() => Err(SelectionError::NotFound {
                question: prompt.to_owned(),
            }
            .into()),
            Choice::Skipped(exclusion) => Err(exclusion.question_error(prompt).into()),
        }
    }

    /// set's write of `resp`, a keyword VALUE, to `question`, of `descriptor`, prompted by
    /// `prompt`, through variables of `reader`: of a ONE_OF its option of the VALUE that set
    /// picks with `include`, of a NUMERIC or CHECKBOX the VALUE's number as set takes its text, of
    /// a DATE or TIME the VALUE's number (NewValue::Number). None for a question whose WRITE
    /// expression alone takes the value.
    fn value_write<'d>(
        &self,
        question: ValueQuestion<'_>,
        descriptor: &'d QuestionDescriptor,
        resp: &KeywordResp,
        prompt: &str,
        include: IncludedStates,
        reader: &EfivarReader,
    ) -> Result<Option<VarStoreWrite<'d>>> {
        let number = value_number(question, resp.value.as_bytes())
            .ok_or_else(|| self.value_refusal(resp, prompt, ValueRefusal::Width))?;
        let text;
        let new_value = match question {
            ValueQuestion::OneOf(_) => NewValue::Option(
                option_of_value(descriptor, number, include)
                    .with_context(|| format!("keyword {}", self.keyword))?
                    .ok_or_else(|| self.value_refusal(resp, prompt, ValueRefusal::NoOption))?,
            ),
            ValueQuestion::DateTime(_) => NewValue::Number(number),
            ValueQuestion::Numeric(_) | ValueQuestion::CheckBox(_) => {
                // a CHECKBOX has no NumericRange, nor a NUMERIC bit field, which own_write refuses
                text = match &descriptor.input {
                    TextInput::Range(range) => range.format.decode(number).to_string(),
                    TextInput::Maximum(_)
                    | TextInput::DateTime(_)
                    | TextInput::OrderedList(_)
                    | TextInput::CrossReference => number.to_string(),
                };
                NewValue::Text(&text)
            }
        };
        let (_, write) = own_write(descriptor, new_value, reader.reach(), reader.interface())
            .with_context(|| self.value_context(resp, prompt))?;
        Ok(write)
    }

    /// set's write of `resp`, a keyword VALUE of every container, to the ORDERED_LIST of
    /// `descriptor`, of `input`, prompted by `prompt`, through variables of `reader`: the
    /// options that set picks with `include` of the values of its containers up to the first
    /// empty one, written as set writes options (ListInput::write_options, list_own_write).
    /// Refuses any VALUE where GetWidth's containers are not as wide as set's (ContainerWidths),
    /// and a VALUE that fills a container after that one (ListInput::container_values) or holds
    /// a value of no option.
    fn list_write<'d>(
        &self,
        input: &ListInput,
        descriptor: &'d QuestionDescriptor,
        resp: &KeywordResp,
        prompt: &str,
        include: IncludedStates,
        reader: &EfivarReader,
    ) -> Result<VarStoreWrite<'d>> {
        // GetWidth has a width once check_set took the VALUE's; set has none without options,
        // which container_values refuses
        if let (Some(get_width), Some(storage_width)) = (
            get_width_container_bytes(&self.op.borrow()),
            input.container_width(),
        ) {
            if get_width != storage_width {
                return Err(KeywordRefusal::ContainerWidths {
                    keyword: self.keyword.to_string(),
                    value: resp.value.to_string(),
                    get_width,
                    storage_width,
                    question: prompt.to_owned(),
                }
                .into());
            }
        }
        let values = input
            .container_values(descriptor, resp.value.as_bytes())
            .with_context(|| self.value_context(resp, prompt))?;
        let mut options = Vec::new();
        for (container, value) in (1..).zip(values) {
            let option = option_of_value(descriptor, value, include)
                .with_context(|| format!("keyword {}", self.keyword))?
                .ok_or_else(|| {
                    let reason = ValueRefusal::NoContainerOption { container, value };
                    self.value_refusal(resp, prompt, reason)
                })?;
            options.push(option);
        }
        let (list, _) = input
            .write_options(descriptor, options.into_iter().map(Ok))
            .with_context(|| self.value_context(resp, prompt))?;
        list_own_write(descriptor, list, reader.reach())
            .with_context(|| self.value_context(resp, prompt))
    }

    /// What names `resp`, the keyword's VALUE, for the question prompted by `prompt`, in the errors
    /// of set's checks of it.
    fn value_context(&self, resp: &KeywordResp, prompt: &str) -> String {
        format!(
            "keyword {}: VALUE={} of question \"{prompt}\"",
            self.keyword, resp.value
        )
    }

    /// The refusal of `resp`, the keyword's VALUE, for the question prompted by `prompt`, where
    /// set writes `patches`, each bytes at a VarOffset, which are not the VALUE at the question's
    /// VarOffset: UnwrittenWidth where they hold another number of bytes than the VALUE.
    fn unwritten(
        &self,
        resp: &KeywordResp,
        prompt: &str,
        patches: &[(u16, Vec<u8>)],
    ) -> Result<KeywordRefusal, ConfigStringError> {
        let written = patches
            .iter()
            .map(|(offset, bytes)| {
                Ok(format!(
                    "{} at VarOffset {offset}",
                    Number::try_from(bytes.clone())?
                ))
            })
            .collect::<Result<Vec<String>, ConfigStringError>>()?
            .join(", ");
        let (keyword, value, question) = (
            self.keyword.to_string(),
            resp.value.to_string(),
            prompt.to_owned(),
        );
        let get_width = resp.value.as_bytes().len();
        let storage_width = patches.iter().map(|(_, bytes)| bytes.len()).sum();
        Ok(match get_width == storage_width {
            true => KeywordRefusal::Unwritten {
                keyword,
                value,
                written,
                question,
            },
            false => KeywordRefusal::UnwrittenWidth {
                keyword,
                value,
                get_width,
                written,
                storage_width,
                question,
            },
        })
    }

    /// The refusal of a keyword set of `op`, which uefisettings does not implement yet.
    fn unchecked(&self, op: &IFROperation) -> KeywordRefusal {
        KeywordRefusal::Unchecked {
            keyword: self.keyword.to_string(),
            op: op.op_code.spec_name(),
        }
    }

    fn question_refusal(&self, header: &QuestionHeader, reason: QuestionRefusal) -> KeywordRefusal {
        KeywordRefusal::Question {
            keyword: self.keyword.to_string(),
            question: self.texts.display(header.prompt_string_id).to_owned(),
            reason,
        }
    }

    fn value_refusal(
        &self,
        resp: &KeywordResp,
        prompt: &str,
        reason: ValueRefusal,
    ) -> KeywordRefusal {
        KeywordRefusal::Value {
            keyword: self.keyword.to_string(),
            value: resp.value.to_string(),
            question: prompt.to_owned(),
            reason,
        }
    }
}

/// `language` as a NAMESPACE, if its text is one.
fn namespace_of(language: &Language) -> Option<Namespace> {
    let text = std::str::from_utf8(&language.0).ok()?;
    Namespace::try_from(text).ok()
}

/// The keyword string of the text `text` of a strings package of `language`, as a
/// `<KeywordRequest>` names it: None unless `language` is a NAMESPACE and `text` a `<Keyword>`.
pub(crate) fn keyword_of(language: &Language, text: &str) -> Option<(Namespace, Keyword)> {
    let Some(namespace) = namespace_of(language) else {
        debug!("language {} is no NAMESPACE", language.0.escape_ascii());
        return None;
    };
    match Keyword::try_from(text) {
        Ok(keyword) => Some((namespace, keyword)),
        Err(error) => {
            debug!("{namespace} string {text:?} is no keyword: {error}");
            None
        }
    }
}

/// Walk::Enter past the op `op` unless it is a VarStore op of VarStoreId `id` that is not of the
/// EFI variable `variable`, or one that does not decode, whose VarStoreId is unknown:
/// other_declaration's refusal then. A VarStore op that the parse left undecoded, in the scope of
/// an unknown opcode, and that decodes here is one of the package list's `outside` ops too, which
/// outside_declaration refuses, naming that place.
fn declaration_refusal(
    op: &IFROperation,
    id: u16,
    variable: &VariableKey,
) -> Result<Walk<()>, QuestionRefusal> {
    let in_unknown_scope = matches!(op.parsed_data, ParsedOperation::Placeholder);
    match decoded_store(op) {
        Ok(Some(_)) if in_unknown_scope => Ok(Walk::Enter(())),
        Ok(Some((declared, store))) if declared == id => match other_store(store, variable) {
            Some(other) => Err(QuestionRefusal::RedeclaredVarStore(id, other)),
            None => Ok(Walk::Enter(())),
        },
        Ok(Some(_) | None) => Ok(Walk::Enter(())),
        Err(error) => Err(QuestionRefusal::UndecodedVarStore(format!("{error:#}"))),
    }
}

/// `declared`, a VarStore of a question's VarStoreId, as text, unless it is the EFI variable
/// `variable`, the question's.
fn other_store(declared: DeclaredStore, variable: &VariableKey) -> Option<String> {
    match declared {
        DeclaredStore::Variable(store) if store.variable_key() == *variable => None,
        DeclaredStore::Variable(store) => Some(format!("EFI variable {}", store.variable_key())),
        DeclaredStore::NameValue(_) => Some("a VARSTORE_NAME_VALUE".to_owned()),
        DeclaredStore::ShortEfi(_) => Some(format!("an {}", ShortVarStoreEfi::LABEL)),
    }
}

/// A statement of a package list: in a FormSet, with the root of its form package, or outside
/// any.
enum Statement<'a> {
    InFormSet {
        root: &'a Rc<RefCell<IFROperation>>,
        op: Rc<RefCell<IFROperation>>,
    },
    Outside(&'a OutsideOp),
}

/// The ops of `list` that IsStatementOpCode (ConfigKeywordHandler.c:1420) takes for statements
/// and whose Prompt is `prompt`: in its FormSets, in IFR order, each with the root of its form
/// package, then outside any FormSet, as FindQuestionFromStringId walks the whole form package, but
/// in ignored IFR (OutsideOp::in_ignored_ifr).
fn statements(list: &ParsedPackageList, prompt: u16) -> Vec<Statement<'_>> {
    let mut found = Vec::new();
    for root in &list.forms {
        walk_scopes(std::slice::from_ref(root), (), |node, ()| {
            if prompts(&node.borrow(), prompt) {
                found.push(Statement::InFormSet {
                    root,
                    op: Rc::clone(node),
                });
            }
            Walk::Enter(())
        });
    }
    found.extend(
        list.outside_ifr
            .iter()
            .filter(|outside| !outside.in_ignored_ifr && prompts(&outside.op, prompt))
            .map(Statement::Outside),
    );
    found
}

/// Whether `op` is a statement whose Prompt is `prompt`: FindQuestionFromStringId reads the
/// Prompt of an EFI_IFR_GUID from the start of its GUID, and that of a statement shorter than its
/// Prompt from the bytes after it, as it reads the Prompt at OpCodeData + 2 whatever the op's
/// Length (ConfigKeywordHandler.c:1498-1499): such a statement prompts every keyword.
fn prompts(op: &IFROperation, prompt: u16) -> bool {
    is_statement(op.op_code)
        && op
            .data
            .get(..2)
            .is_none_or(|bytes| bytes == &prompt.to_le_bytes()[..])
}

/// The bytes of a question's value: of a ONE_OF or NUMERIC its size, of a CHECKBOX a BOOLEAN, of
/// a DATE or TIME an EFI_HII_DATE or EFI_HII_TIME.
fn value_width(question: ValueQuestion<'_>) -> u8 {
    match question {
        ValueQuestion::OneOf(one_of) => one_of.data.size(),
        ValueQuestion::Numeric(numeric) => numeric.data.size(),
        ValueQuestion::CheckBox(_) => 1,
        ValueQuestion::DateTime(question) => question.kind.size(),
    }
}

/// `value`'s bytes in memory order and its width, if of a numeric Type.
fn numeric_bytes(value: TypeValue) -> Option<(Vec<u8>, NumericWidth)> {
    match value {
        TypeValue::NumSize8(value) => Some((value.to_le_bytes().to_vec(), NumericWidth::One)),
        TypeValue::NumSize16(value) => Some((value.to_le_bytes().to_vec(), NumericWidth::Two)),
        TypeValue::NumSize32(value) => Some((value.to_le_bytes().to_vec(), NumericWidth::Four)),
        TypeValue::NumSize64(value) => Some((value.to_le_bytes().to_vec(), NumericWidth::Eight)),
        TypeValue::Boolean(_)
        | TypeValue::Time(_)
        | TypeValue::Date(_)
        | TypeValue::StringID(_)
        | TypeValue::Other
        | TypeValue::Undefined
        | TypeValue::Action(_)
        | TypeValue::Ref(_)
        | TypeValue::Unknown(_) => None,
    }
}

/// The start of an EFI_IFR_ONE_OF or EFI_IFR_NUMERIC after its op header (UEFI 2.11
/// §33.3.8.3.50, §33.3.8.3.47).
#[derive(BinRead)]
#[br(little)]
struct NumericFlagsOp {
    _question: QuestionHeader,
    flags: u8,
}

/// An EFI_IFR_ORDERED_LIST after its op header (UEFI 2.11 §33.3.8.3.53).
#[derive(BinRead)]
#[br(little)]
struct OrderedListOp {
    _question: QuestionHeader,
    max_containers: u8,
}

/// The value bytes of its variable that GetData() and SetData() take for the question `op` of
/// `header`: GetWidth's (keyword_width) from its VarOffset, or every byte of the variable for an
/// op of no such width.
fn keyword_bytes(op: &IFROperation, header: &QuestionHeader) -> Range<usize> {
    let start = usize::from(header.var_store_info);
    keyword_width(op).map_or(0..usize::MAX, |width| start..start + width)
}

/// The bytes of the question `op` that edk2-stable202608 ConfigKeywordHandler.c GetWidth
/// (:1581-1656) gives: of a ONE_OF or NUMERIC its size; of an ORDERED_LIST MaxContainers values of
/// the Type of the ONE_OF_OPTION that it starts with; of a CHECKBOX a BOOLEAN; of a STRING MaxSize
/// CHAR16s; of a DATE, TIME or REF an EFI_HII_DATE, EFI_HII_TIME or EFI_HII_REF. None for other
/// ops, and an ORDERED_LIST without such an option, where GetWidth asserts.
fn keyword_width(op: &IFROperation) -> Option<usize> {
    let mut data = Cursor::new(&op.data);
    match op.op_code {
        IFROpCode::OneOf | IFROpCode::Numeric | IFROpCode::CheckBox => {
            value_question(op).map(|question| usize::from(value_width(question)))
        }
        IFROpCode::OrderedList => {
            let list: OrderedListOp = data.parse_le().ok()?;
            Some(get_width_container_bytes(op)? * usize::from(list.max_containers))
        }
        IFROpCode::String => {
            let string: StringOp = data.parse_le().ok()?;
            Some(usize::from(char16_storage_width(string.max_size)))
        }
        IFROpCode::Date => Some(EFI_HII_DATE_SIZE),
        IFROpCode::Time => Some(EFI_HII_TIME_SIZE),
        IFROpCode::Ref => Some(EFI_HII_REF_SIZE),
        _ => None,
    }
}

/// The bytes of each container of the ORDERED_LIST `op` that edk2-stable202608
/// ConfigKeywordHandler.c GetWidth (:1613-1618) gives: those of the Type of the ONE_OF_OPTION
/// that it starts with. None without such an option, where GetWidth asserts, or of another Type.
fn get_width_container_bytes(op: &IFROperation) -> Option<usize> {
    let first = op.children.first()?.borrow();
    if first.op_code != IFROpCode::OneOfOption {
        return None;
    }
    let option: OptionTypeOp = Cursor::new(&first.data).parse_le().ok()?;
    match option.option_type {
        EFI_IFR_TYPE_NUM_SIZE_8 => Some(1),
        EFI_IFR_TYPE_NUM_SIZE_16 => Some(2),
        EFI_IFR_TYPE_NUM_SIZE_32 => Some(4),
        EFI_IFR_TYPE_NUM_SIZE_64 => Some(8),
        _ => None,
    }
}

/// `value`, a VALUE's bytes in memory order, as a number, if it is as wide as `question`'s
/// value.
fn value_number(question: ValueQuestion<'_>, value: &[u8]) -> Option<u64> {
    if value.len() != usize::from(value_width(question)) {
        return None;
    }
    let mut bytes = [0; 8];
    bytes.get_mut(..value.len())?.copy_from_slice(value);
    Some(u64::from_le_bytes(bytes))
}

/// The option of `descriptor` that set writes for `value`: of those that hold it, the one that
/// select() picks with `include`; None if none holds it.
fn option_of_value(
    descriptor: &QuestionDescriptor,
    value: u64,
    include: IncludedStates,
) -> Result<Option<&AnswerOption>, SelectionError> {
    let holders = descriptor
        .possible_options
        .iter()
        .filter(|option| option.as_u64() == Some(value))
        .collect();
    descriptor.pick_option(holders, include)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::conditions::ReadOnlyCause;
    use super::super::ifr_fixtures::checkbox_at;
    use super::super::ifr_fixtures::checkbox_on;
    use super::super::ifr_fixtures::conditional;
    use super::super::ifr_fixtures::eq_id_val_of;
    use super::super::ifr_fixtures::flagged_option;
    use super::super::ifr_fixtures::form;
    use super::super::ifr_fixtures::form_set;
    use super::super::ifr_fixtures::form_set_with_guid;
    use super::super::ifr_fixtures::ifr_default;
    use super::super::ifr_fixtures::ifr_false;
    use super::super::ifr_fixtures::ifr_true;
    use super::super::ifr_fixtures::in_unknown_scope;
    use super::super::ifr_fixtures::locked_op;
    use super::super::ifr_fixtures::nested;
    use super::super::ifr_fixtures::one_of_at;
    use super::super::ifr_fixtures::one_of_option;
    use super::super::ifr_fixtures::operation;
    use super::super::ifr_fixtures::parse_form_set;
    use super::super::ifr_fixtures::parse_form_set_dropping;
    use super::super::ifr_fixtures::password_on;
    use super::super::ifr_fixtures::question_header_with;
    use super::super::ifr_fixtures::short_var_store_efi;
    use super::super::ifr_fixtures::typed_default;
    use super::super::ifr_fixtures::uint32_default;
    use super::super::ifr_fixtures::uint8;
    use super::super::ifr_fixtures::var_store;
    use super::super::ifr_fixtures::MemoryVariables;
    use super::super::ifr_fixtures::VariableInterface;
    use super::super::ifr_fixtures::VariableReach;
    use super::super::ifr_fixtures::BIT_VARSTORE_GUID;
    use super::super::ifr_fixtures::CHECKBOX;
    use super::super::ifr_fixtures::DISABLE_IF;
    use super::super::ifr_fixtures::END;
    use super::super::ifr_fixtures::GRAY_OUT_IF;
    use super::super::ifr_fixtures::GUID;
    use super::super::ifr_fixtures::NUMERIC;
    use super::super::ifr_fixtures::ONE_OF;
    use super::super::ifr_fixtures::PASSWORD;
    use super::super::ifr_fixtures::READ;
    use super::super::ifr_fixtures::SHORT_VAR_STORE_GUID;
    use super::super::ifr_fixtures::STRING;
    use super::super::ifr_fixtures::SUPPRESS_IF;
    use super::super::ifr_fixtures::VALUE;
    use super::super::ifr_fixtures::VAR_STORE;
    use super::super::ifr_fixtures::WRITE;
    use super::super::list_questions;
    use super::super::resolve_short_var_names;
    use super::super::storage::VariableNotExported;
    use super::super::ChangeValueError;
    use super::super::PasswordQuestions;
    use super::*;
    use crate::hii::config_string::MultiKeywordResp;
    use crate::hii::package::hiidb_fixtures::form_package_of;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::read_db;
    use crate::hii::package::DevicePath;
    use crate::hii::package::Guid;
    use crate::hii::strings::StringPackage;
    use crate::hii::variables::WithheldBytes;

    /// A vendor device path node of the GUID 11111111-1111-1111-1111-111111111111, then End.
    const PATH: &str = "01041400111111111111111111111111111111117fff0400";
    const OTHER_PATH: &str = "01041400222222222222222222222222222222227fff0400";
    const THIRD_PATH: &str = "01041400444444444444444444444444444444447fff0400";
    const FOURTH_PATH: &str = "01041400555555555555555555555555555555557fff0400";
    const NAMESPACE: &str = "x-UEFI-ns";
    const KEYWORD: &str = "Keyword";
    const QUESTION: &str = "Keyword question";
    /// The string that prompts the question, in every language
    const PROMPT: u16 = 3;
    /// The VarStore of the questions, the variable Store of this GUID
    const STORE_GUID: [u8; 16] = [0x33; 16];
    /// The VarOffset of the questions
    const OFFSET: usize = 5;
    /// NV+BS+RT
    const ATTRIBUTES: u32 = 0x07;
    const DATE: u8 = 0x1A;
    const TIME: u8 = 0x1B;
    const ORDERED_LIST: u8 = 0x23;
    const ONE_OF_OPTION: u8 = 0x09;
    const REF: u8 = 0x0F;
    const VAR_STORE_NAME_VALUE: u8 = 0x25;

    /// The data of a UINT8 ONE_OF or NUMERIC of `flags` prompted by PROMPT at OFFSET of VarStore
    /// `var_store_id`, from 0 to 3.
    fn uint8_question(var_store_id: u16, flags: u8) -> Vec<u8> {
        [
            question_header_with(1, PROMPT, var_store_id, 5, flags),
            vec![0x00, 0, 3, 1], // Flags UINT8, MinValue, MaxValue, Step
        ]
        .concat()
    }

    /// A UINT8 ONE_OF of `flags` on VarStore `var_store_id` whose options hold 0, 1 and 3, then
    /// `scope` in its scope.
    fn one_of_with(var_store_id: u16, flags: u8, scope: &[Vec<u8>]) -> Vec<u8> {
        [
            operation(ONE_OF, true, &uint8_question(var_store_id, flags)),
            scope.concat(),
            flagged_option(4, 0, 0),
            flagged_option(4, 0, 1),
            flagged_option(4, 0, 3),
            END.to_vec(),
        ]
        .concat()
    }

    fn one_of(var_store_id: u16, flags: u8) -> Vec<u8> {
        one_of_with(var_store_id, flags, &[])
    }

    /// A package list of the device path `path` holding `ops` after VarStore 1, and the strings
    /// of PROMPT: QUESTION in en-US, then each (language, text) of `keywords`.
    fn list(path: &str, keywords: &[(&str, &str)], ops: Vec<u8>) -> ParsedPackageList {
        let mut strings = vec![StringPackage {
            language: Language(b"en-US".to_vec()),
            strings: BTreeMap::from([(PROMPT, QUESTION.into())]),
        }];
        for (language, text) in keywords {
            strings.push(StringPackage {
                language: Language(language.as_bytes().to_vec()),
                strings: BTreeMap::from([(PROMPT, (*text).into())]),
            });
        }
        ParsedPackageList {
            guid: Guid::from([0x22; 16]),
            device_path: Some(path_of(path).as_ref().clone()),
            strings,
            forms: vec![parse_form_set(&[
                var_store(1, STORE_GUID, "Store", 16),
                ops,
            ])],
            ignored_ifr: Vec::new(),
            outside_ifr: Vec::new(),
            malformed_outside_stores: Vec::new(),
            disabled_forms: Vec::new(),
            first_var_stores: Vec::new(),
        }
    }

    fn path_of(digits: &str) -> KeywordPath {
        digits.parse().expect("a device path")
    }

    fn keyword(text: &str) -> Keyword {
        Keyword::try_from(text).expect("a keyword")
    }

    fn namespace(text: &str) -> Namespace {
        Namespace::try_from(text).expect("a namespace")
    }

    fn resp(value: &str) -> KeywordResp {
        let text = format!("NAMESPACE={NAMESPACE}&PATH={PATH}&KEYWORD={KEYWORD}&VALUE={value}");
        text.parse::<MultiKeywordResp>()
            .expect("a <MultiKeywordResp>")
            .as_slice()[0]
            .clone()
    }

    /// The questions of KEYWORD in NAMESPACE, in the list of `path` if given.
    fn resolve<'a>(
        lists: &'a [ParsedPackageList],
        path: Option<&str>,
    ) -> Result<Vec<KeywordQuestion<'a>>, KeywordRefusal> {
        KeywordQuestion::resolve(
            lists,
            Some(&namespace(NAMESPACE)),
            path.map(path_of).as_ref(),
            &keyword(KEYWORD),
            &[],
        )
    }

    /// The question of KEYWORD in NAMESPACE in the one list of `ops`.
    fn question_of(lists: &[ParsedPackageList]) -> KeywordQuestion<'_> {
        let mut questions = resolve(lists, Some(PATH)).expect("the keyword");
        assert_eq!(questions.len(), 1, "one question of PATH");
        questions.remove(0)
    }

    /// The variable Store, NV+BS+RT, through the UEFI Shell's variable services, whose byte at
    /// OFFSET holds `byte`.
    fn variables(byte: u8) -> MemoryVariables {
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let mut data = [0; 16];
        data[OFFSET] = byte;
        variables.insert(store_key(), ATTRIBUTES, &data);
        variables
    }

    /// A reader of variables(`byte`).
    fn reader(byte: u8) -> EfivarReader {
        EfivarReader::with_variables(Box::new(variables(byte)))
    }

    /// A reader of variables(1) that withholds the bytes `password` of Store, a password's.
    fn withholding(password: Range<usize>) -> EfivarReader {
        let mut withheld = WithheldBytes::default();
        withheld.insert(store_key(), password);
        EfivarReader::withholding(Box::new(variables(1)), withheld)
    }

    fn store_key() -> VariableKey {
        VariableKey {
            name: "Store".to_owned(),
            guid: Guid::from(STORE_GUID),
        }
    }

    /// check_set of `value` on the one question of KEYWORD in a list of `ops`, with `include`.
    fn check_set_of(ops: Vec<u8>, value: &str, include: IncludedStates) -> Result<()> {
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
        question_of(&lists)
            .check_set(
                &resp(value),
                include,
                VolatileWrites::Refuse,
                &mut reader(1),
            )
            .map(|_write| ())
    }

    fn question_refusal(reason: QuestionRefusal) -> KeywordRefusal {
        KeywordRefusal::Question {
            keyword: KEYWORD.to_owned(),
            question: QUESTION.to_owned(),
            reason,
        }
    }

    fn value_refusal(value: &str, reason: ValueRefusal) -> KeywordRefusal {
        KeywordRefusal::Value {
            keyword: KEYWORD.to_owned(),
            value: value.to_owned(),
            question: QUESTION.to_owned(),
            reason,
        }
    }

    fn not_found(language: &str) -> KeywordRefusal {
        KeywordRefusal::NotFound {
            keyword: KEYWORD.to_owned(),
            language: language.to_owned(),
        }
    }

    /// The KeywordRefusal of `result`, if it failed with one.
    fn refusal_of<T>(result: Result<T>) -> Option<KeywordRefusal> {
        result
            .err()
            .and_then(|error| error.downcast_ref::<KeywordRefusal>().cloned())
    }

    /// The namespace and path of each of `questions`.
    fn places(questions: &[KeywordQuestion<'_>]) -> Vec<(String, String)> {
        questions
            .iter()
            .map(|question| {
                (
                    question.namespace().to_string(),
                    question.path().to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn resolve_takes_the_list_of_path_and_its_first_namespace_package() {
        let lists = [
            list(
                OTHER_PATH,
                &[("x-UEFI-ns-other", "Other"), (NAMESPACE, KEYWORD)],
                one_of(1, 0),
            ),
            list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0)),
        ];

        assert_eq!(
            resolve(&lists, Some(PATH)).map(|questions| places(&questions)),
            Ok(vec![(NAMESPACE.to_owned(), PATH.to_owned())]),
            "the keyword of the list of PATH"
        );
        assert_eq!(
            resolve(&lists, Some(OTHER_PATH)).err(),
            Some(not_found(NAMESPACE)),
            "only the first x-UEFI-ns* strings package of a list counts, and x-UEFI-ns-other \
             lacks the keyword"
        );
        assert_eq!(
            resolve(&lists, Some(THIRD_PATH)).err(),
            Some(KeywordRefusal::NoDriver(THIRD_PATH.to_owned())),
            "a device path of no list"
        );
        assert_eq!(
            KeywordQuestion::resolve(
                &lists,
                Some(&namespace(NAMESPACE)),
                Some(&path_of(PATH)),
                &keyword("Other"),
                &[],
            )
            .err(),
            Some(KeywordRefusal::NotFound {
                keyword: "Other".to_owned(),
                language: NAMESPACE.to_owned(),
            }),
            "an unknown keyword"
        );
    }

    /// Without PATH, "all instances are returned" (UEFI 2.11 §35.2.1.6), where edk2-stable202608
    /// GetData() returns the first list's: uefisettings reads each list by its PATH.
    #[test]
    fn resolve_without_path_finds_each_list_that_holds_the_keyword() {
        let unprompted = || list(FOURTH_PATH, &[(NAMESPACE, KEYWORD)], checkbox_on(2, 9, 1));
        let lists = [
            list(OTHER_PATH, &[("x-UEFI-other", KEYWORD)], one_of(1, 0)),
            list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0)),
            unprompted(),
            list(THIRD_PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0)),
        ];

        assert_eq!(
            resolve(&lists, None).map(|questions| places(&questions)),
            Ok(vec![
                (NAMESPACE.to_owned(), PATH.to_owned()),
                (NAMESPACE.to_owned(), THIRD_PATH.to_owned()),
            ]),
            "the lists whose x-UEFI-ns package holds the keyword and whose statement it prompts"
        );
        assert_eq!(
            resolve(&[unprompted()], None).err(),
            Some(KeywordRefusal::NoStatement(KEYWORD.to_owned())),
            "a list whose statements the keyword does not prompt"
        );
        assert_eq!(
            resolve(&[unprompted()], Some(FOURTH_PATH)).err(),
            Some(KeywordRefusal::NoStatement(KEYWORD.to_owned())),
            "the list of PATH, whose statements the keyword does not prompt"
        );
    }

    /// Without PATH, edk2-stable202608 GetStringIdFromDatabase asserts on a package list without a
    /// device path that holds the keyword (ConfigKeywordHandler.c:2411); a <KeywordResp> names one.
    #[test]
    fn resolve_without_path_refuses_a_list_without_a_device_path() {
        let mut no_path = list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0));
        no_path.device_path = None;
        let mut short_path = list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0));
        short_path.device_path = Some(DevicePath::from(vec![0x7f, 0xff, 0x04]));

        assert_eq!(
            resolve(&[no_path], None).err(),
            Some(KeywordRefusal::NoDevicePath(KEYWORD.to_owned())),
            "no device path"
        );
        assert!(
            matches!(
                resolve(&[short_path], None).err(),
                Some(KeywordRefusal::DevicePath { keyword, .. }) if keyword == KEYWORD
            ),
            "a device path shorter than an End node"
        );
    }

    /// Offline, a keyword names its statement in a package list without a device path, or with
    /// one that is no KeywordPath, too, as no <KeywordResp> names the list; the other refusals
    /// stand.
    #[test]
    fn resolve_offline_takes_a_list_without_a_device_path() {
        let mut no_path = list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0));
        no_path.device_path = None;
        let mut short_path = list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0));
        short_path.device_path = Some(DevicePath::from(vec![0x7f, 0xff, 0x04]));
        let mut two_ns = list(
            PATH,
            &[(NAMESPACE, KEYWORD), ("x-UEFI-ns-v2", KEYWORD)],
            one_of(1, 0),
        );
        two_ns.device_path = None;
        let offline = |list: ParsedPackageList| {
            let lists = [list];
            KeywordStatement::resolve_offline(&lists, None, &keyword(KEYWORD)).map(|statements| {
                statements
                    .iter()
                    .map(|statement| {
                        (
                            statement.namespace().to_string(),
                            statement.op().borrow().op_code.spec_name(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
        };

        for (case, list) in [("no device path", no_path), ("short", short_path)] {
            assert_eq!(
                offline(list),
                Ok(vec![(NAMESPACE.to_owned(), "EFI_IFR_ONE_OF")]),
                "{case}"
            );
        }
        assert_eq!(
            offline(two_ns),
            Err(KeywordRefusal::AmbiguousPackages {
                keyword: KEYWORD.to_owned(),
                languages: vec![NAMESPACE.to_owned(), "x-UEFI-ns-v2".to_owned()],
            }),
            "two strings packages under x-UEFI"
        );
    }

    /// Without a NameSpaceId, edk2-stable202608 GetStringIdFromRecord searches the first strings
    /// package whose language starts with "x-UEFI", and returns that language.
    #[test]
    fn resolve_without_namespace_searches_the_first_x_uefi_package() {
        let missing = [list(
            PATH,
            &[("x-UEFI", "Other"), ("x-UEFI-AMI", KEYWORD)],
            one_of(1, 0),
        )];
        let found = [list(PATH, &[("x-UEFI-AMI", KEYWORD)], one_of(1, 0))];

        assert_eq!(
            KeywordQuestion::resolve(&missing, None, None, &keyword(KEYWORD), &[]).err(),
            Some(not_found("x-UEFI")),
            "the x-UEFI package comes first and lacks the keyword"
        );
        assert_eq!(
            KeywordQuestion::resolve(&found, None, None, &keyword(KEYWORD), &[])
                .map(|questions| places(&questions)),
            Ok(vec![("x-UEFI-AMI".to_owned(), PATH.to_owned())]),
            "the language of the package that holds it"
        );
    }

    /// A keyword that two strings packages of a list hold under the namespace's prefix, which
    /// firmware may search in another order than edk2, is refused.
    #[test]
    fn resolve_refuses_a_keyword_of_two_strings_packages() {
        let two_ns = [list(
            PATH,
            &[(NAMESPACE, KEYWORD), ("x-UEFI-ns-v2", KEYWORD)],
            one_of(1, 0),
        )];
        let ns_and_ami = [list(
            PATH,
            &[(NAMESPACE, KEYWORD), ("x-UEFI-AMI", KEYWORD)],
            one_of(1, 0),
        )];
        let ambiguous = |languages: &[&str]| KeywordRefusal::AmbiguousPackages {
            keyword: KEYWORD.to_owned(),
            languages: languages
                .iter()
                .map(|&language| language.to_owned())
                .collect(),
        };

        assert_eq!(
            resolve(&two_ns, Some(PATH)).err(),
            Some(ambiguous(&[NAMESPACE, "x-UEFI-ns-v2"])),
            "x-UEFI-ns and x-UEFI-ns-v2 under x-UEFI-ns"
        );
        assert_eq!(
            KeywordQuestion::resolve(
                &ns_and_ami,
                None,
                Some(&path_of(PATH)),
                &keyword(KEYWORD),
                &[]
            )
            .err(),
            Some(ambiguous(&[NAMESPACE, "x-UEFI-AMI"])),
            "x-UEFI-ns and x-UEFI-AMI under x-UEFI"
        );
        assert_eq!(
            resolve(&ns_and_ami, Some(PATH)).map(|questions| places(&questions)),
            Ok(vec![(NAMESPACE.to_owned(), PATH.to_owned())]),
            "x-UEFI-AMI is not under x-UEFI-ns"
        );
    }

    /// A keyword that prompts two statements of its list is refused: edk2 takes the first, and
    /// firmware may take another.
    #[test]
    fn resolve_refuses_a_keyword_that_prompts_two_statements() {
        let ops = [one_of(1, 0), checkbox_on(2, PROMPT, 1)].concat();
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];

        assert_eq!(
            resolve(&lists, Some(PATH)).err(),
            Some(KeywordRefusal::AmbiguousStatements {
                keyword: KEYWORD.to_owned(),
                count: 2,
            }),
            "a ONE_OF and a CHECKBOX"
        );
    }

    /// edk2-stable202608 IsStatementOpCode takes an EFI_IFR_GUID for a statement, and
    /// FindQuestionFromStringId reads the start of its GUID as a Prompt.
    #[test]
    fn resolve_takes_a_guid_op_whose_guid_starts_with_the_prompt_for_a_statement() {
        let guid_op = operation(
            GUID,
            false,
            &[&PROMPT.to_le_bytes()[..], &[0x55; 14]].concat(),
        );
        let alone = [list(PATH, &[(NAMESPACE, KEYWORD)], guid_op.clone())];
        let with_question = [list(
            PATH,
            &[(NAMESPACE, KEYWORD)],
            [guid_op, one_of(1, 0)].concat(),
        )];

        assert_eq!(
            question_of(&alone).check_get(&reader(1)),
            Err(KeywordRefusal::NotQuestion {
                keyword: KEYWORD.to_owned(),
                op: "EFI_IFR_GUID",
            }),
            "the GUID op alone"
        );
        assert_eq!(
            resolve(&with_question, Some(PATH)).err(),
            Some(KeywordRefusal::AmbiguousStatements {
                keyword: KEYWORD.to_owned(),
                count: 2,
            }),
            "the GUID op and a ONE_OF"
        );
    }

    #[test]
    fn check_set_refuses_what_set_would_not_write() {
        let cases = [
            ("an option", one_of(1, 0), "03", None),
            (
                "no option",
                one_of(1, 0),
                "02",
                Some(value_refusal("02", ValueRefusal::NoOption)),
            ),
            (
                "too wide",
                one_of(1, 0),
                "0003",
                Some(value_refusal("0003", ValueRefusal::Width)),
            ),
            (
                "&READONLY",
                one_of(1, 0),
                "03&READONLY",
                Some(KeywordRefusal::ReadOnlyResp(KEYWORD.to_owned())),
            ),
            (
                "CALLBACK",
                one_of(1, QuestionFlags::CALLBACK.bits()),
                "03",
                Some(question_refusal(QuestionRefusal::Callback)),
            ),
            (
                "no VarStore",
                one_of(0, 0),
                "03",
                Some(question_refusal(QuestionRefusal::Storageless)),
            ),
        ];
        for (name, ops, value, expected) in cases {
            let result = check_set_of(ops, value, IncludedStates::empty());
            match expected {
                None => assert!(result.is_ok(), "{name}: {result:?}"),
                Some(refusal) => assert_eq!(refusal_of(result), Some(refusal), "{name}"),
            }
        }
    }

    /// set's own checks refuse an EFI_IFR_FLAG_READ_ONLY question whatever `include`, as SetData()
    /// does, naming no state that writes it.
    #[test]
    fn check_set_refuses_a_read_only_question_whatever_include() {
        let ops = one_of(1, QuestionFlags::READ_ONLY.bits());
        for include in [IncludedStates::empty(), IncludedStates::all()] {
            let error = check_set_of(ops.clone(), "03", include).expect_err("READ_ONLY");
            assert!(
                matches!(
                    error.downcast_ref::<ChangeValueError>(),
                    Some(ChangeValueError::ReadOnly {
                        cause: ReadOnlyCause::Flag,
                        ..
                    })
                ),
                "--include {include}: {error:#}"
            );
            assert_eq!(
                format!("{error:#}"),
                format!(
                    "keyword {KEYWORD}: cannot set question {QUESTION:?}: EFI_IFR_FLAG_READ_ONLY \
                     makes it read-only (UEFI 2.11 §33.3.8.2.2)"
                ),
                "--include {include}"
            );
        }
    }

    /// set's own checks refuse an ORDERED_LIST that EFI_IFR_FLAG_READ_ONLY makes read-only
    /// whatever `include`, as they refuse a ONE_OF, and take the same VALUE of a writable one.
    #[test]
    fn check_set_refuses_a_read_only_ordered_list_whatever_include() {
        let list_of = |flags: u8| {
            let data = [question_header_with(1, PROMPT, 1, 5, flags), vec![3, 0]].concat();
            [
                operation(ORDERED_LIST, true, &data),
                uint8_options().concat(),
                END.to_vec(),
            ]
            .concat()
        };
        assert!(
            check_set_of(list_of(0), "000103", IncludedStates::empty()).is_ok(),
            "writable"
        );
        for include in [IncludedStates::empty(), IncludedStates::all()] {
            let got = check_set_of(list_of(QuestionFlags::READ_ONLY.bits()), "000103", include)
                .map_err(|error| format!("{error:#}"));
            assert_eq!(
                got,
                Err(format!(
                    "keyword {KEYWORD}: cannot set question {QUESTION:?}: EFI_IFR_FLAG_READ_ONLY \
                     makes it read-only (UEFI 2.11 §33.3.8.2.2)"
                )),
                "--include {include}"
            );
        }
    }

    /// set's own checks refuse a REF on a VarStore that EFI_IFR_FLAG_READ_ONLY makes read-only as
    /// read-only, before set's refusal of the EFI_HII_REF of every REF.
    #[test]
    fn check_set_refuses_a_read_only_ref_as_read_only_first() {
        let data = [
            question_header_with(1, PROMPT, 1, 5, QuestionFlags::READ_ONLY.bits()),
            vec![1, 0],
        ]
        .concat();
        let error = check_set_of(
            operation(REF, false, &data),
            &"01".repeat(22),
            IncludedStates::empty(),
        )
        .expect_err("set of 22 bytes");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "keyword {KEYWORD}: cannot set question {QUESTION:?}: EFI_IFR_FLAG_READ_ONLY \
                 makes it read-only (UEFI 2.11 §33.3.8.2.2)"
            ),
            "set of 22 bytes"
        );
    }

    /// check_set takes the question through set's own checks, which refuse a variable that set
    /// cannot write, as a missing one.
    #[test]
    fn check_set_refuses_a_variable_that_set_would_not_write() {
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0))];
        let mut no_variables = EfivarReader::with_variables(Box::new(MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        )));

        let error = question_of(&lists)
            .check_set(
                &resp("03"),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut no_variables,
            )
            .expect_err("a missing variable");

        assert!(
            error.downcast_ref::<VariableNotExported>().is_some(),
            "missing: {error:#}"
        );
    }

    #[test]
    fn check_set_refuses_values_out_of_the_range_of_set() {
        let numeric = |minimum: u8, maximum: u8| {
            let data = [
                question_header_with(1, PROMPT, 1, 5, 0),
                vec![0x00, minimum, maximum, 1],
            ]
            .concat();
            operation(NUMERIC, false, &data)
        };
        let cases = [
            ("NUMERIC in range", numeric(2, 10), "0a", None),
            (
                "NUMERIC above",
                numeric(2, 10),
                "0b",
                Some(ChangeValueError::ExceededMaxValue.to_string()),
            ),
            (
                "NUMERIC below",
                numeric(2, 10),
                "01",
                Some(ChangeValueError::BelowMinValue.to_string()),
            ),
            ("CHECKBOX 1", checkbox_on(1, PROMPT, 1), "01", None),
            (
                "CHECKBOX 2",
                checkbox_on(1, PROMPT, 1),
                "02",
                Some(ChangeValueError::ExceededMaxValue.to_string()),
            ),
        ];
        for (name, ops, value, expected) in cases {
            let result = check_set_of(ops, value, IncludedStates::empty());
            match expected {
                None => assert!(result.is_ok(), "{name}: {result:?}"),
                Some(text) => {
                    let error = format!("{:#}", result.expect_err(name));
                    assert!(error.contains(&text), "{name}: {error}");
                }
            }
        }
    }

    /// GetData() and SetData() evaluate no READ, WRITE or EFI_IFR_VALUE expression and take a
    /// bit field's bit offset for a byte offset; a question of an undeclared VarStore has no
    /// storage that they reach.
    #[test]
    fn check_get_and_set_refuse_expressions_bit_fields_and_unknown_var_stores() {
        let expression = |op_code: u8| vec![operation(op_code, true, &[]), uint8(1), END.to_vec()];
        let read = one_of_with(1, 0, &expression(READ));
        let write = one_of_with(1, 0, &expression(WRITE));
        let value = one_of_with(1, 0, &expression(VALUE));
        let bit_field = [
            operation(GUID, true, &BIT_VARSTORE_GUID),
            checkbox_at(1, PROMPT, 1, 5),
            END.to_vec(),
        ]
        .concat();
        let unread_var_store = QuestionRefusal::UnreadVarStore(
            "no supported varstore with matching id 0x0009 found".to_owned(),
        );
        let set_refusal = |reason: QuestionRefusal| -> Result<(), String> {
            Err(question_refusal(reason).to_string())
        };
        let cases = [
            ("READ", read, Some(QuestionRefusal::Read), Ok(())),
            ("WRITE", write, None, set_refusal(QuestionRefusal::Write)),
            (
                "EFI_IFR_VALUE",
                value,
                Some(QuestionRefusal::Read),
                Err(format!(
                    "keyword {KEYWORD}: cannot set question {QUESTION:?}: its EFI_IFR_VALUE \
                     expression makes it read-only (UEFI 2.11 §33.3.8.3.88)"
                )),
            ),
            (
                "bit field",
                bit_field,
                Some(QuestionRefusal::BitField),
                set_refusal(QuestionRefusal::BitField),
            ),
            (
                "unknown VarStore",
                one_of(9, 0),
                Some(unread_var_store.clone()),
                set_refusal(unread_var_store),
            ),
        ];
        for (name, ops, get, set) in cases {
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops.clone())];
            assert_eq!(
                question_of(&lists).check_get(&reader(1)).err(),
                get.map(question_refusal),
                "{name}: get"
            );
            let result = check_set_of(ops, "03", IncludedStates::empty());
            assert_eq!(
                result.map_err(|error| format!("{error:#}")),
                set,
                "{name}: set"
            );
        }
    }

    /// set refuses a question that a SUPPRESS_IF, GRAY_OUT_IF or DISABLE_IF of TRUE, or a LOCKED,
    /// puts out of reach unless --include takes its state; SetData() checks no condition, so
    /// check_set does.
    #[test]
    fn check_set_refuses_a_question_out_of_reach_unless_included() {
        let cases = [
            (
                "SUPPRESS_IF",
                conditional(SUPPRESS_IF, ifr_true(), &[one_of(1, 0)]),
                IncludedStates::SUPPRESSED,
            ),
            (
                "GRAY_OUT_IF",
                conditional(GRAY_OUT_IF, ifr_true(), &[one_of(1, 0)]),
                IncludedStates::GRAYED_OUT,
            ),
            (
                "DISABLE_IF",
                conditional(DISABLE_IF, ifr_true(), &[one_of(1, 0)]),
                IncludedStates::DISABLED,
            ),
            (
                "LOCKED",
                one_of_with(1, 0, &[locked_op()]),
                IncludedStates::GRAYED_OUT,
            ),
        ];
        for (name, ops, state) in cases {
            let error = check_set_of(ops.clone(), "03", IncludedStates::empty()).expect_err(name);
            assert!(
                matches!(
                    error.downcast_ref::<SelectionError>(),
                    Some(SelectionError::Excluded { states, .. }) if *states == state
                ),
                "{name}: {error:#}"
            );
            let included = check_set_of(ops, "03", state);
            assert!(included.is_ok(), "{name} included: {included:?}");
        }
    }

    /// set takes the options that question_scope shows: not one that a SUPPRESS_IF of TRUE
    /// hides, unless --include takes it, and one that a SUPPRESS_IF of FALSE shows.
    #[test]
    fn check_set_takes_the_options_that_set_takes() {
        let hidden = |condition: Vec<u8>| {
            [
                operation(ONE_OF, true, &uint8_question(1, 0)),
                flagged_option(4, 0, 0),
                flagged_option(4, 0, 1),
                conditional(SUPPRESS_IF, condition, &[flagged_option(4, 0, 3)]),
                END.to_vec(),
            ]
            .concat()
        };

        assert!(
            check_set_of(hidden(ifr_true()), "01", IncludedStates::empty()).is_ok(),
            "a shown option"
        );
        let error = check_set_of(hidden(ifr_true()), "03", IncludedStates::empty())
            .expect_err("a suppressed option");
        assert!(
            matches!(
                error.downcast_ref::<SelectionError>(),
                Some(SelectionError::OptionExcluded { .. })
            ),
            "a suppressed option: {error:#}"
        );
        assert!(
            check_set_of(hidden(ifr_true()), "03", IncludedStates::SUPPRESSED).is_ok(),
            "a suppressed option, included"
        );
        assert!(
            check_set_of(hidden(ifr_false()), "03", IncludedStates::empty()).is_ok(),
            "an option that a FALSE condition shows"
        );
    }

    /// GetData() reads the EFI_HII_REF of a REF on a VarStore as stored, which check_get takes;
    /// check_set refuses a VALUE of its 22 bytes with set's error, and one of fewer bytes as not
    /// as wide.
    #[test]
    fn check_get_takes_a_ref_and_check_set_refuses_it() {
        let op = || {
            let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![1, 0]].concat();
            operation(REF, false, &data)
        };
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], op())];
        assert_eq!(question_of(&lists).check_get(&reader(1)), Ok(()), "get");
        let error = check_set_of(op(), &"01".repeat(22), IncludedStates::empty())
            .expect_err("set of 22 bytes");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "keyword {KEYWORD}: {}",
                ChangeValueError::CrossReference {
                    question: QUESTION.to_owned()
                }
            ),
            "set of 22 bytes"
        );
        assert_eq!(
            refusal_of(check_set_of(op(), "03", IncludedStates::empty())),
            Some(value_refusal("03", ValueRefusal::Width)),
            "set of 1 byte"
        );
    }

    /// GetData() and SetData() take the VarStore bytes of a DATE or TIME of EFI Date/Time Storage,
    /// whose value get and set read and write through the Time Services: both refuse it, the
    /// system time and the wake-up time.
    #[test]
    fn date_and_time_of_efi_date_time_storage_are_refused() {
        const STORAGE_TIME: u8 = 0x10;
        const STORAGE_WAKEUP: u8 = 0x20;
        for (op_code, flags, storage) in [
            (DATE, STORAGE_TIME, TimeStorage::SystemTime),
            (TIME, STORAGE_TIME, TimeStorage::SystemTime),
            (DATE, STORAGE_WAKEUP, TimeStorage::WakeupTime),
            (TIME, STORAGE_WAKEUP, TimeStorage::WakeupTime),
        ] {
            let op = || {
                let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![flags]].concat();
                operation(op_code, false, &data)
            };
            let name = format!("op {op_code:#04x}, Flags {flags:#04x}");
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], op())];
            assert_eq!(
                question_of(&lists).check_get(&reader(1)),
                Err(question_refusal(QuestionRefusal::TimeStorage(storage))),
                "{name}: get"
            );
            let error = check_set_of(op(), "03", IncludedStates::empty()).expect_err(&name);
            assert_eq!(
                error.to_string(),
                question_refusal(QuestionRefusal::TimeStorage(storage)).to_string(),
                "{name}: set"
            );
        }
        assert_eq!(
            question_refusal(QuestionRefusal::TimeStorage(TimeStorage::WakeupTime)).to_string(),
            format!(
                "keyword {KEYWORD}: question \"{QUESTION}\" keeps its value in the wake-up time \
                 (UEFI 2.11 §33.2.5.6), which get and set read and write, where GetData() and \
                 SetData() take the bytes of its VarStore"
            )
        );
    }

    /// GetData() and SetData() take the bytes of a DATE or TIME of UEFI Storage 0x30 at its
    /// VarOffset, which a browser neither reads nor writes and get does not read: check_get and
    /// check_set refuse it by name.
    #[test]
    fn date_and_time_of_reserved_storage_are_refused() {
        const STORAGE_RESERVED: u8 = 0x30;
        for op_code in [DATE, TIME] {
            let op = || {
                let data = [
                    question_header_with(1, PROMPT, 1, 5, 0),
                    vec![STORAGE_RESERVED],
                ]
                .concat();
                operation(op_code, false, &data)
            };
            let name = format!("op {op_code:#04x}");
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], op())];
            assert_eq!(
                question_of(&lists).check_get(&reader(1)),
                Err(question_refusal(QuestionRefusal::ReservedStorage)),
                "{name}: get"
            );
            let error = check_set_of(op(), "03", IncludedStates::empty()).expect_err(&name);
            assert_eq!(
                error.to_string(),
                question_refusal(QuestionRefusal::ReservedStorage).to_string(),
                "{name}: set"
            );
        }
        assert_eq!(
            question_refusal(QuestionRefusal::ReservedStorage).to_string(),
            format!(
                "keyword {KEYWORD}: question \"{QUESTION}\" has UEFI Storage 0x30, which neither \
                 QF_DATE_STORAGE (UEFI 2.11 §33.3.8.3.11) nor QF_TIME_STORAGE (§33.3.8.3.78) \
                 defines and get does not read, where GetData() and SetData() take the bytes of \
                 its VarStore"
            )
        );
    }

    /// GetData() reads a STRING, DATE, TIME or ORDERED_LIST as stored, which check_get takes;
    /// check_set refuses a STRING, as keyword set of it is not implemented yet, and a VALUE of a
    /// byte for the others, which it takes as wide as GetWidth; both refuse a PASSWORD.
    #[test]
    fn check_get_takes_string_date_time_and_ordered_list_but_not_password() {
        let question = |op_code: u8| {
            let data = [
                question_header_with(1, PROMPT, 1, 5, 0),
                vec![0x00, 0x01, 0x02, 0x00],
            ]
            .concat();
            operation(op_code, false, &data)
        };
        let unchecked = |op: &'static str| KeywordRefusal::Unchecked {
            keyword: KEYWORD.to_owned(),
            op,
        };
        for (op_code, op, refusal) in [
            (STRING, "EFI_IFR_STRING", unchecked("EFI_IFR_STRING")),
            (
                DATE,
                "EFI_IFR_DATE",
                value_refusal("03", ValueRefusal::Width),
            ),
            (
                TIME,
                "EFI_IFR_TIME",
                value_refusal("03", ValueRefusal::Width),
            ),
            (
                ORDERED_LIST,
                "EFI_IFR_ORDERED_LIST",
                value_refusal("03", ValueRefusal::Width),
            ),
        ] {
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], question(op_code))];
            assert_eq!(
                question_of(&lists).check_get(&reader(1)),
                Ok(()),
                "{op}: get"
            );
            assert_eq!(
                refusal_of(check_set_of(
                    question(op_code),
                    "03",
                    IncludedStates::empty()
                )),
                Some(refusal),
                "{op}: set"
            );
        }
        assert_eq!(
            unchecked("EFI_IFR_STRING").to_string(),
            format!("keyword {KEYWORD}: uefisettings does not yet implement keyword set of EFI_IFR_STRING")
        );
        let password = password_on(1, PROMPT, 1, 5);
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], password.clone())];
        assert_eq!(
            question_of(&lists).check_get(&reader(1)),
            Err(question_refusal(QuestionRefusal::Password)),
            "PASSWORD: get"
        );
        assert_eq!(
            refusal_of(check_set_of(password, "03", IncludedStates::empty())),
            Some(question_refusal(QuestionRefusal::Password)),
            "PASSWORD: set"
        );
    }

    /// The variable Store, NV+BS+RT, through the UEFI Shell's variable services, holding `value`
    /// at OFFSET and 0 elsewhere.
    fn reader_of(value: &[u8]) -> EfivarReader {
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let mut data = [0; 16];
        data[OFFSET..OFFSET + value.len()].copy_from_slice(value);
        variables.insert(store_key(), ATTRIBUTES, &data);
        EfivarReader::with_variables(Box::new(variables))
    }

    /// check_set of `value` on the one question of KEYWORD in a list of `ops`, with the variable
    /// Store of reader_of(`stored`): the VarOffsets that SetData() writes, or the error as the CLI
    /// prints it.
    fn keyword_set(ops: Vec<u8>, value: &str, stored: &[u8]) -> Result<Vec<Range<usize>>, String> {
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
        question_of(&lists)
            .check_set(
                &resp(value),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut reader_of(stored),
            )
            .map(|write| write.bytes)
            .map_err(|error| format!("{error:#}"))
    }

    /// The error of check_set for `value` that set's check of its fields gives with `error`.
    fn value_error(
        value: &str,
        error: impl std::fmt::Display,
    ) -> Result<Vec<Range<usize>>, String> {
        Err(format!(
            "keyword {KEYWORD}: VALUE={value} of question \"{QUESTION}\": {error}"
        ))
    }

    /// A DATE or TIME, `op_code`, of `flags` prompted by PROMPT at OFFSET of VarStore 1.
    fn date_time(op_code: u8, flags: u8) -> Vec<u8> {
        let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![flags]].concat();
        operation(op_code, false, &data)
    }

    /// SetData() writes a DATE's or TIME's VALUE, its EFI_HII_DATE or EFI_HII_TIME last byte
    /// first, as given, so check_set takes it as set takes the fields of its text: each within
    /// edk2's ranges, and a field that the question suppresses only as set writes it, the stored
    /// one, or for a day the one that a new month adjusts it to; at the question's GetWidth bytes.
    #[test]
    fn check_set_takes_the_fields_of_a_date_or_time_as_set_takes_them() {
        use super::super::date_time::DateTimeKind;
        use super::super::date_time::DateTimeTextError;
        use super::super::date_time::Field;
        const YEAR_SUPPRESS: u8 = 0x01;
        const DAY_SUPPRESS: u8 = 0x04;
        // 2024-03-31
        let stored = [0xE8, 0x07, 3, 31];
        let date = OFFSET..OFFSET + 4;
        let time = OFFSET..OFFSET + 3;
        let out_of_range = |field, value, range| DateTimeTextError::OutOfRange {
            field,
            value,
            range,
        };
        let changed = |field, given, written| DateTimeTextError::SuppressedChanged {
            kind: DateTimeKind::Date,
            field,
            given,
            written,
        };
        for (name, op, value, want) in [
            (
                "2025-12-31",
                date_time(DATE, 0),
                "1f0c07e9",
                Ok(vec![date.clone()]),
            ),
            (
                "month 13",
                date_time(DATE, 0),
                "1f0d07e9",
                value_error("1f0d07e9", out_of_range(Field::Month, 13, 1..=12)),
            ),
            (
                "2023-02-29",
                date_time(DATE, 0),
                "1d0207e7",
                value_error("1d0207e7", out_of_range(Field::Day, 29, 1..=28)),
            ),
            (
                "year 0",
                date_time(DATE, 0),
                "01010000",
                value_error("01010000", out_of_range(Field::Year, 0, 1..=u16::MAX)),
            ),
            (
                "the suppressed year kept",
                date_time(DATE, YEAR_SUPPRESS),
                "010407e8",
                Ok(vec![date.clone()]),
            ),
            (
                "the suppressed year changed",
                date_time(DATE, YEAR_SUPPRESS),
                "010407e9",
                value_error("010407e9", changed(Field::Year, 2025, 2024)),
            ),
            (
                "the suppressed day kept in May",
                date_time(DATE, DAY_SUPPRESS),
                "1f0507e8",
                Ok(vec![date.clone()]),
            ),
            (
                "the suppressed day 31 kept in April",
                date_time(DATE, DAY_SUPPRESS),
                "1f0407e8",
                value_error("1f0407e8", changed(Field::Day, 31, 30)),
            ),
            (
                "the suppressed day adjusted to 30 in April",
                date_time(DATE, DAY_SUPPRESS),
                "1e0407e8",
                Ok(vec![date.clone()]),
            ),
            ("23:59:59", date_time(TIME, 0), "3b3b17", Ok(vec![time])),
            (
                "hour 24",
                date_time(TIME, 0),
                "3b3b18",
                value_error("3b3b18", out_of_range(Field::Hour, 24, 0..=23)),
            ),
        ] {
            assert_eq!(keyword_set(op, value, &stored), want, "{name}");
        }
        assert_eq!(
            changed(Field::Day, 31, 30).to_string(),
            "the day of this DATE is suppressed (UEFI 2.11 §33.2.5.4.6), and set writes it as 30, \
             not 31"
        );
    }

    /// An ORDERED_LIST of at most 3 items and `flags` prompted by PROMPT at OFFSET of VarStore 1,
    /// with `options` in its scope.
    fn ordered_list_of(flags: u8, options: &[Vec<u8>]) -> Vec<u8> {
        let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![3, flags]].concat();
        [
            operation(ORDERED_LIST, true, &data),
            options.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// Options of Type UINT8 holding 1, 2 and 3, each of the text QUESTION.
    fn uint8_options() -> Vec<Vec<u8>> {
        (1..=3)
            .map(|value| flagged_option(PROMPT, 0, value))
            .collect()
    }

    /// SetData() writes an ORDERED_LIST's VALUE, its containers last byte first, as given, so
    /// check_set takes the options of the containers up to the first empty one as set takes items:
    /// with EFI_IFR_UNIQUE_SET each once, with EFI_IFR_NO_EMPTY_SET in every container; and
    /// refuses a VALUE that fills a container after an empty one, holds a value of no option,
    /// naming its container, or is not as wide as GetWidth's containers; and, where GetWidth takes
    /// the Type of a first option that set takes as a default, every VALUE, whatever its bytes,
    /// naming both containers' widths.
    #[test]
    fn check_set_takes_the_items_of_an_ordered_list_as_set_takes_them() {
        use super::super::ordered_list::ListRefusal;
        const UNIQUE: u8 = 0x01;
        const NO_EMPTY: u8 = 0x02;
        const OPTION_DEFAULT: u8 = 0x10;
        let stored = [1, 2, 0];
        let containers = OFFSET..OFFSET + 3;
        let list = |refusal| {
            ChangeValueError::OrderedList {
                question: QUESTION.to_owned(),
                refusal,
            }
            .to_string()
        };
        let uint16_after_a_uint8_default = [
            vec![flagged_option(PROMPT, OPTION_DEFAULT, 1)],
            (1..=3u16)
                .map(|value| one_of_option(PROMPT, 0x01, &value.to_le_bytes()))
                .collect(),
        ]
        .concat();
        let uint8_after_a_uint16_default =
            [vec![uint16_default_option()], uint8_options()].concat();
        let widths = |value: &str, get_width, storage_width| {
            Err(KeywordRefusal::ContainerWidths {
                keyword: KEYWORD.to_owned(),
                value: value.to_owned(),
                get_width,
                storage_width,
                question: QUESTION.to_owned(),
            }
            .to_string())
        };
        for (name, op, value, want) in [
            (
                "items 3 and 1",
                ordered_list_of(0, &uint8_options()),
                "000103",
                Ok(vec![containers]),
            ),
            (
                "a container after an empty one",
                ordered_list_of(0, &uint8_options()),
                "010003",
                value_error("010003", list(ListRefusal::AfterEmpty)),
            ),
            (
                "a value of no option",
                ordered_list_of(0, &uint8_options()),
                "000004",
                Err(value_refusal(
                    "000004",
                    ValueRefusal::NoContainerOption {
                        container: 1,
                        value: 4,
                    },
                )
                .to_string()),
            ),
            (
                "a value of no option in the second container",
                ordered_list_of(0, &uint8_options()),
                "000401",
                Err(value_refusal(
                    "000401",
                    ValueRefusal::NoContainerOption {
                        container: 2,
                        value: 4,
                    },
                )
                .to_string()),
            ),
            (
                "an option twice, unique",
                ordered_list_of(UNIQUE, &uint8_options()),
                "000101",
                value_error(
                    "000101",
                    list(ListRefusal::Duplicate {
                        option: QUESTION.to_owned(),
                    }),
                ),
            ),
            (
                "an empty container, no empty",
                ordered_list_of(NO_EMPTY, &uint8_options()),
                "000201",
                value_error("000201", list(ListRefusal::Empty { max: 3, given: 2 })),
            ),
            (
                "two bytes",
                ordered_list_of(0, &uint8_options()),
                "0103",
                Err(value_refusal("0103", ValueRefusal::Width).to_string()),
            ),
            (
                "1-byte GetWidth containers, 2-byte set containers",
                ordered_list_of(0, &uint16_after_a_uint8_default),
                "000001",
                widths("000001", 1, 2),
            ),
            (
                "1-byte GetWidth containers, 2-byte set containers, a byte after a set container",
                ordered_list_of(0, &uint16_after_a_uint8_default),
                "020001",
                widths("020001", 1, 2),
            ),
            (
                "2-byte GetWidth containers, 1-byte set containers, 4 of them",
                ordered_list_of(0, &uint8_after_a_uint16_default),
                "000001020301",
                widths("000001020301", 2, 1),
            ),
        ] {
            assert_eq!(keyword_set(op, value, &stored), want, "{name}");
        }
        assert_eq!(
            value_refusal(
                "000401",
                ValueRefusal::NoContainerOption {
                    container: 2,
                    value: 4
                }
            )
            .to_string(),
            format!(
                "keyword {KEYWORD}: VALUE=000401 holds 4 in container 2, which is no option of \
                 question \"{QUESTION}\""
            ),
            "the refusal of a value of no option"
        );
        assert_eq!(
            KeywordRefusal::UnwrittenWidth {
                keyword: KEYWORD.to_owned(),
                value: "000001".to_owned(),
                get_width: 3,
                written: format!("000000000001 at VarOffset {OFFSET}"),
                storage_width: 6,
                question: QUESTION.to_owned(),
            }
            .to_string(),
            format!(
                "keyword {KEYWORD}: SetData() writes VALUE=000001 as given, 3 bytes (GetWidth), \
                 where set writes 000000000001 at VarOffset 5, 6 bytes (StorageWidth), for \
                 question \"{QUESTION}\""
            ),
            "the refusal of a write of two widths"
        );
        assert_eq!(
            widths("000001", 1, 2),
            Err(format!(
                "keyword {KEYWORD}: SetData() writes VALUE=000001 as given, in containers of 1 \
                 bytes as GetWidth takes them, where set writes containers of 2 bytes as \
                 StorageWidth takes them, for question \"{QUESTION}\""
            )),
            "the refusal of containers of two widths"
        );
    }

    /// An option of Flags DEFAULT, Type UINT16 and Value 1.
    fn uint16_default_option() -> Vec<u8> {
        const OPTION_DEFAULT: u8 = 0x10;
        operation(
            ONE_OF_OPTION,
            false,
            &[
                &PROMPT.to_le_bytes()[..],
                &[OPTION_DEFAULT, 0x01],
                &1u16.to_le_bytes(),
            ]
            .concat(),
        )
    }

    /// check_set takes the containers of an ORDERED_LIST of UINT16 options, where GetWidth and set
    /// take containers of 2 bytes each.
    #[test]
    fn check_set_takes_the_uint16_containers_of_an_ordered_list() {
        let options: Vec<Vec<u8>> = [0x0101u16, 0x0202, 0x0303]
            .iter()
            .map(|value| one_of_option(PROMPT, 0x01, &value.to_le_bytes()))
            .collect();
        let containers = OFFSET..OFFSET + 6;
        assert_eq!(
            keyword_set(ordered_list_of(0, &options), "000002020101", &[0; 6]),
            Ok(vec![containers]),
            "items 0x0101 and 0x0202"
        );
    }

    /// Where GetWidth takes the Type of a UINT16 option that set takes as a default, its
    /// containers are wider than those of set's UINT8 options, so check_set refuses the VALUE,
    /// which is not the bytes that set writes.
    #[test]
    fn check_set_refuses_a_get_width_wider_than_set_s_containers() {
        let options = [vec![uint16_default_option()], uint8_options()].concat();
        assert_eq!(
            keyword_set(ordered_list_of(0, &options), "000000000103", &[1, 2, 0]),
            Err(KeywordRefusal::ContainerWidths {
                keyword: KEYWORD.to_owned(),
                value: "000000000103".to_owned(),
                get_width: 2,
                storage_width: 1,
                question: QUESTION.to_owned(),
            }
            .to_string()),
            "GetWidth 6, set 3"
        );
    }

    /// An ORDERED_LIST whose first op is an EFI_IFR_DEFAULT, whose Value's first byte reads as
    /// Type UINT8 where a ONE_OF_OPTION has its Type, has no GetWidth (edk2-stable202608
    /// ConfigKeywordHandler.c :1618 asserts), so check_set refuses any VALUE as not as wide.
    #[test]
    fn check_set_refuses_an_ordered_list_whose_first_op_is_no_option() {
        let ops = ordered_list_of(
            0,
            &[
                ifr_default(0, 0),
                flagged_option(PROMPT, 0, 1),
                flagged_option(PROMPT, 0, 2),
                flagged_option(PROMPT, 0, 3),
            ],
        );
        let got = keyword_set(ops, "000103", &[1, 2, 0]);
        assert_eq!(
            got,
            Err(value_refusal("000103", ValueRefusal::Width).to_string()),
            "a DEFAULT first"
        );
    }

    /// set keeps a TIME's suppressed second, so check_set takes a VALUE only with that second;
    /// and refuses an hour out of range.
    #[test]
    fn check_set_takes_a_suppressed_second_only_as_set_keeps_it() {
        use super::super::date_time::DateTimeKind;
        use super::super::date_time::DateTimeTextError;
        use super::super::date_time::Field;
        const SECOND_SUPPRESS: u8 = 0x04;
        // 12:34:56
        let stored = [12, 34, 56];
        let time = OFFSET..OFFSET + 3;
        assert_eq!(
            keyword_set(date_time(TIME, SECOND_SUPPRESS), "38000d", &stored),
            Ok(vec![time]),
            "13:00 keeping second 56"
        );
        assert_eq!(
            keyword_set(date_time(TIME, SECOND_SUPPRESS), "39000d", &stored),
            value_error(
                "39000d",
                DateTimeTextError::SuppressedChanged {
                    kind: DateTimeKind::Time,
                    field: Field::Second,
                    given: 57,
                    written: 56,
                }
            ),
            "second 57"
        );
        assert_eq!(
            keyword_set(date_time(TIME, SECOND_SUPPRESS), "382218", &stored),
            value_error(
                "382218",
                DateTimeTextError::OutOfRange {
                    field: Field::Hour,
                    value: 24,
                    range: 0..=23,
                }
            ),
            "hour 24"
        );
    }

    /// set takes an option of an ORDERED_LIST that a SUPPRESS_IF of TRUE hides only with
    /// --include, so check_set refuses a VALUE that holds it, unless included; and set drops no
    /// stored item of such an option, so check_set refuses a VALUE without it, included or not.
    #[test]
    fn check_set_takes_a_suppressed_option_of_an_ordered_list_only_included() {
        use super::super::ordered_list::ListRefusal;
        let ops = ordered_list_of(
            0,
            &[
                flagged_option(PROMPT, 0, 1),
                flagged_option(PROMPT, 0, 2),
                conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(PROMPT, 0, 3)]),
            ],
        );
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
        let set = |value, stored: &[u8], include| {
            question_of(&lists)
                .check_set(
                    &resp(value),
                    include,
                    VolatileWrites::Refuse,
                    &mut reader_of(stored),
                )
                .map(|write| write.bytes)
        };
        let error =
            set("000103", &[1, 2, 0], IncludedStates::empty()).expect_err("a suppressed option");
        assert!(
            matches!(
                error.downcast_ref::<SelectionError>(),
                Some(SelectionError::OptionExcluded { .. })
            ),
            "a suppressed option: {error:#}"
        );
        let containers = OFFSET..OFFSET + 3;
        assert_eq!(
            set("000103", &[1, 2, 0], IncludedStates::SUPPRESSED)
                .map_err(|error| format!("{error:#}")),
            Ok(vec![containers.clone()]),
            "included"
        );
        // the suppressed option 3 stored first
        let stored = [3, 1, 0];
        for include in [IncludedStates::empty(), IncludedStates::SUPPRESSED] {
            let error = set("000001", &stored, include).expect_err("a stored hidden item dropped");
            assert!(
                matches!(
                    error.downcast_ref::<ChangeValueError>(),
                    Some(ChangeValueError::OrderedList {
                        refusal: ListRefusal::HiddenDropped { .. },
                        ..
                    })
                ),
                "a stored hidden item dropped, include {include:?}: {error:#}"
            );
        }
        let error = set("000103", &stored, IncludedStates::empty())
            .expect_err("a stored hidden item kept, not included");
        assert!(
            matches!(
                error.downcast_ref::<SelectionError>(),
                Some(SelectionError::OptionExcluded { .. })
            ),
            "a stored hidden item kept, not included: {error:#}"
        );
        assert_eq!(
            set("000103", &stored, IncludedStates::SUPPRESSED)
                .map_err(|error| format!("{error:#}")),
            Ok(vec![containers]),
            "a stored hidden item kept, included"
        );
    }

    /// SetData() writes every byte of a DATE's, TIME's or ORDERED_LIST's storage, so check_set
    /// refuses a VALUE whose bytes overlap those of a password, which the reader withholds, at
    /// their first byte or at their last, and takes one beside them: through check_patches, or
    /// where set reads the stored value first, as it cannot read it.
    #[test]
    fn check_set_refuses_a_date_time_or_ordered_list_over_the_bytes_of_a_password() {
        use super::super::date_time::DateTimeKind;
        use super::super::date_time::DateTimeTextError;
        use super::super::ordered_list::ListRefusal;
        const YEAR_SUPPRESS: u8 = 0x01;
        const UNREAD: &str = "its bytes hold a password";
        let patches = |password: &Range<usize>| {
            Err(format!(
                "keyword {KEYWORD}: cannot set question {QUESTION:?}: EFI variable {} holds a \
                 password at bytes {password:?}, which set never writes",
                store_key()
            ))
        };
        let year_unread = |_: &Range<usize>| {
            value_error(
                "1f0c0001",
                DateTimeTextError::StoredUnreadable {
                    kind: DateTimeKind::Date,
                    reason: UNREAD.to_owned(),
                },
            )
        };
        let items_unread = |_: &Range<usize>| {
            value_error(
                "000103",
                ChangeValueError::OrderedList {
                    question: QUESTION.to_owned(),
                    refusal: ListRefusal::StoredUnread(UNREAD.to_owned()),
                },
            )
        };
        type Refusal<'f> = &'f dyn Fn(&Range<usize>) -> Result<Vec<Range<usize>>, String>;
        let cases: [(&str, Vec<u8>, &str, usize, Refusal); 4] = [
            ("DATE", date_time(DATE, 0), "1f0c07e9", 4, &patches),
            // withholding's Store holds 1 at OFFSET: year 1
            (
                "DATE, year suppressed",
                date_time(DATE, YEAR_SUPPRESS),
                "1f0c0001",
                4,
                &year_unread,
            ),
            ("TIME", date_time(TIME, 0), "3b3b17", 3, &patches),
            (
                "ORDERED_LIST",
                ordered_list_of(0, &uint8_options()),
                "000103",
                3,
                &items_unread,
            ),
        ];
        for (name, ops, value, width, refusal) in cases {
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
            let question = question_of(&lists);
            let bytes = OFFSET..OFFSET + width;
            for (password, overlaps) in [
                (OFFSET - 1..OFFSET + 1, true),
                (OFFSET + width - 1..OFFSET + width + 1, true),
                (OFFSET + width..OFFSET + width + 2, false),
            ] {
                let got = question
                    .check_set(
                        &resp(value),
                        IncludedStates::empty(),
                        VolatileWrites::Refuse,
                        &mut withholding(password.clone()),
                    )
                    .map(|write| write.bytes)
                    .map_err(|error| format!("{error:#}"));
                let want = match overlaps {
                    true => refusal(&password),
                    false => Ok(vec![bytes.clone()]),
                };
                assert_eq!(got, want, "{name}, password {password:?}");
            }
        }
    }

    /// GetData() reads a question's GetWidth bytes from its VarOffset, so check_get refuses one
    /// whose bytes overlap those of a password, which the reader withholds, at its first byte or
    /// at its last, and takes one beside them.
    #[test]
    fn check_get_refuses_a_question_over_the_bytes_of_a_password() {
        let question = |op_code: u8, tail: &[u8], scope: &[Vec<u8>]| {
            let data = [question_header_with(1, PROMPT, 1, 5, 0), tail.to_vec()].concat();
            match scope {
                [] => operation(op_code, false, &data),
                _ => [
                    operation(op_code, true, &data),
                    scope.concat(),
                    END.to_vec(),
                ]
                .concat(),
            }
        };
        let uint16_option = operation(ONE_OF_OPTION, false, &[4, 0, 0, 0x01, 1, 0]);
        let cases = [
            ("UINT8 ONE_OF", one_of(1, 0), 1),
            (
                "UINT32 NUMERIC",
                question(NUMERIC, &[0x02, 0, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0], &[]),
                4,
            ),
            ("CHECKBOX", checkbox_at(1, PROMPT, 1, 5), 1),
            ("STRING of MaxSize 3", question(STRING, &[0, 3, 0], &[]), 6),
            ("DATE", question(DATE, &[0], &[]), 4),
            ("TIME", question(TIME, &[0], &[]), 3),
            (
                "ORDERED_LIST of 3 UINT16s",
                question(ORDERED_LIST, &[3, 0], &[uint16_option]),
                6,
            ),
            ("REF", question(REF, &[1, 0], &[]), 22),
        ];
        for (name, ops, width) in cases {
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
            let question = question_of(&lists);
            for (password, overlaps) in [
                (OFFSET - 2..OFFSET, false),
                (OFFSET - 1..OFFSET + 1, true),
                (OFFSET + width - 1..OFFSET + width + 1, true),
                (OFFSET + width..OFFSET + width + 2, false),
            ] {
                assert_eq!(
                    question.check_get(&withholding(password.clone())).err(),
                    overlaps.then(|| question_refusal(QuestionRefusal::PasswordBytes)),
                    "{name} of {width} bytes at {OFFSET}, a password at {password:?}"
                );
            }
        }
        // GetWidth gives an ORDERED_LIST without a ONE_OF_OPTION no width: any password of its
        // variable may be among its bytes
        let unknown = [list(
            PATH,
            &[(NAMESPACE, KEYWORD)],
            question(ORDERED_LIST, &[3, 0], &[]),
        )];
        assert_eq!(
            question_of(&unknown)
                .check_get(&withholding(OFFSET + 20..OFFSET + 22))
                .err(),
            Some(question_refusal(QuestionRefusal::PasswordBytes)),
            "an ORDERED_LIST of no width"
        );
    }

    /// SetData() writes every byte of a question's storage, so check_set refuses a write over
    /// those of a password, which the reader withholds, as set does, and takes one beside them.
    #[test]
    fn check_set_refuses_a_write_over_the_bytes_of_a_password() {
        let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0))];
        let question = question_of(&lists);
        let set = |password: Range<usize>| {
            question
                .check_set(
                    &resp("03"),
                    IncludedStates::empty(),
                    VolatileWrites::Refuse,
                    &mut withholding(password),
                )
                .map(|write| write.bytes)
                .map_err(|error| format!("{error:#}"))
        };

        assert_eq!(
            set(OFFSET..OFFSET + 2),
            Err(format!(
                "keyword {KEYWORD}: cannot set question {QUESTION:?}: EFI variable {} holds a \
                 password at bytes 5..7, which set never writes",
                store_key()
            ))
        );
        let question_byte = OFFSET..OFFSET + 1;
        assert_eq!(set(OFFSET + 1..OFFSET + 3), Ok(vec![question_byte]));
    }

    /// The Keyword Handler takes a question's VarStore from the first declaration of its
    /// VarStoreId in the form package, so check_get and check_set refuse a VarStoreId that another
    /// FormSet of the list, before or after the question's, declares for another variable, or a
    /// VARSTORE_NAME_VALUE, and take one declared for the same variable.
    #[test]
    fn check_get_and_set_refuse_a_var_store_id_that_another_form_set_declares() {
        let refusal = |store: &str| {
            format!(
                "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which its \
                 package list also declares for {store}"
            )
        };
        let name_value = operation(
            VAR_STORE_NAME_VALUE,
            false,
            &[1_u16.to_le_bytes().to_vec(), vec![0x55; 16]].concat(),
        );
        let cases = [
            (
                "the variable Other",
                var_store(1, [0x44; 16], "Other", 16),
                Some(refusal(
                    "EFI variable Other-44444444-4444-4444-4444-444444444444",
                )),
            ),
            (
                "a VARSTORE_NAME_VALUE",
                name_value,
                Some(refusal("a VARSTORE_NAME_VALUE")),
            ),
            (
                "a VARSTORE_EFI before UEFI 2.3.1",
                short_var_store_efi(1),
                Some(refusal("an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1")),
            ),
            (
                "the variable Store",
                var_store(1, STORE_GUID, "Store", 16),
                None,
            ),
        ];
        for ((name, declaration, want), at) in cases
            .into_iter()
            .flat_map(|case| [(case.clone(), 0), (case, 1)])
        {
            let mut lists = [list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0))];
            lists[0].forms.insert(at, parse_form_set(&[declaration]));
            let question = question_of(&lists);

            let get = question.check_get(&reader(1));
            let set = question.check_set(
                &resp("03"),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut reader(1),
            );

            assert_eq!(
                (
                    get.err().map(|error| error.to_string()),
                    set.err().map(|error| error.to_string())
                ),
                (want.clone(), want),
                "VarStore 1 of {name} in FormSet {at} of the list"
            );
        }
    }

    /// GetData() and SetData() take the VarStore of FindStorageFromVarId, the first VarStore op of
    /// the id in the form package whatever its scope: check_get and check_set refuse a question on
    /// VarStore 2, the variable Other, where VarStore 2 is also declared as Store, which holds a
    /// password at the question's bytes, under a DISABLE_IF TRUE or in a FORM, which
    /// find_corresponding_varstore passes over, whether Other is declared directly or under a
    /// DISABLE_IF FALSE. A FORM that declares Store before Other refuses the lookup of the
    /// question's VarStore itself (declared_var_store), and one after it refuses as one under a
    /// DISABLE_IF TRUE does.
    #[test]
    fn check_get_and_set_refuse_a_var_store_id_that_the_question_s_form_set_also_declares() {
        let store = || var_store(2, STORE_GUID, "Store", 16);
        let other = || var_store(2, [0x44; 16], "Other", 16);
        let other_false = || conditional(DISABLE_IF, ifr_false(), &[other()]);
        let store_true = || conditional(DISABLE_IF, ifr_true(), &[store()]);
        let redeclared = "keyword Keyword: question \"Keyword question\" has VarStoreId 2, which \
                          its package list also declares for EFI variable \
                          Store-33333333-3333-3333-3333-333333333333";
        let form_first = "keyword Keyword: question \"Keyword question\" has no VarStore that \
                          uefisettings reads: VarStore 0x0002 is declared in an EFI_IFR_FORM of \
                          its FormSet before the one of its form-set-list";
        let cases = [
            (
                "Store under DISABLE_IF TRUE, then Other directly",
                vec![store_true(), other()],
                redeclared,
            ),
            (
                "Store under DISABLE_IF TRUE, then Other under DISABLE_IF FALSE",
                vec![store_true(), other_false()],
                redeclared,
            ),
            (
                "Store in a FORM, then Other directly",
                vec![form(5, &[store()]), other()],
                form_first,
            ),
            (
                "Store in a FORM, then Other under DISABLE_IF FALSE",
                vec![form(5, &[store()]), other_false()],
                form_first,
            ),
            (
                "Other directly, then Store in a FORM",
                vec![other(), form(5, &[store()])],
                redeclared,
            ),
            (
                "Other under DISABLE_IF FALSE, then Store in a FORM",
                vec![other_false(), form(5, &[store()])],
                redeclared,
            ),
        ];
        for (case, declarations, want) in cases {
            let ops = [
                declarations.concat(),
                password_on(
                    7,
                    9,
                    1,
                    u16::try_from(OFFSET).expect("OFFSET fits a VarOffset"),
                ),
                one_of(2, 0),
            ]
            .concat();
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
            let question = question_of(&lists);
            let passwords = PasswordQuestions::of_lists(&lists);
            let read = || passwords.reader(Box::new(variables(1))).expect("a reader");

            let get = question.check_get(&read());
            let set = question.check_set(
                &resp("03"),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut read(),
            );

            let refusals = [
                ("get", get.err().map(|error| error.to_string())),
                ("set", set.err().map(|error| error.to_string())),
            ];
            for (name, refusal) in refusals {
                assert!(
                    refusal
                        .as_deref()
                        .is_some_and(|refusal| refusal.starts_with(want)),
                    "{case}: {name}: {refusal:?}"
                );
            }
        }
    }

    /// edk2-stable202608 FindStorageFromVarId (ConfigKeywordHandler.c:1520-1567) takes the first
    /// VarStore op of the id in the form package, in a FormSet around the question's too: where a
    /// FormSet declares Pw for VarStoreId 1, holds a PASSWORD of id 1 at VarOffset 5, and then
    /// nests the keyword's FormSet, which declares Store for id 1, GetData() and SetData() of the
    /// keyword's ONE_OF at VarOffset 5 take byte 5 of Pw, a byte of the password. check_get and
    /// check_set refuse it, naming Pw, through variables of either reach, and take it where the
    /// FormSet around declares no Pw. Their readers withhold nothing, so that the refusal is
    /// other_declaration's: get_keyword's reader withholds the password's bytes in Store too, as a
    /// VarStore of its id in its root (PasswordQuestions), which refuses a get first.
    #[test]
    fn check_get_and_set_refuse_a_var_store_id_that_a_form_set_around_the_question_s_declares() {
        let keyword_form_set = form_set(&[var_store(1, STORE_GUID, "Store", 16), one_of(1, 0)]);
        let offset = u16::try_from(OFFSET).expect("OFFSET fits a VarOffset");
        let password = password_on(9, 9, 1, offset);
        let pw = var_store(1, [0x44; 16], "Pw", 16);
        let refusal = "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which its \
                       package list also declares for EFI variable \
                       Pw-44444444-4444-4444-4444-444444444444";
        for (case, around, want) in [
            (
                "Pw declared first",
                vec![pw, password.clone(), keyword_form_set.clone()],
                Some(refusal.to_owned()),
            ),
            ("no Pw", vec![password, keyword_form_set], None),
        ] {
            let lists = [list_read(form_set_with_guid([0x66; 16], &around))];
            let question = question_of(&lists);
            for (reach, interface) in [
                (
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                ),
                (VariableReach::Runtime, VariableInterface::Efivarfs),
            ] {
                let reader = || {
                    let variables = MemoryVariables::new(reach, interface);
                    let mut data = [0; 16];
                    data[OFFSET] = 1;
                    variables.insert(store_key(), ATTRIBUTES, &data);
                    EfivarReader::with_variables(Box::new(variables))
                };

                let get = question.check_get(&reader());
                let set = question.check_set(
                    &resp("03"),
                    IncludedStates::empty(),
                    VolatileWrites::Refuse,
                    &mut reader(),
                );

                assert_eq!(
                    (
                        get.err().map(|error| error.to_string()),
                        set.err().map(|error| error.to_string())
                    ),
                    (want.clone(), want.clone()),
                    "{case}: {reach:?}"
                );
            }
        }
    }

    /// check_get and check_set refuse a question when a VarStore op of a FormSet of its package
    /// list does not decode, as it may have the question's VarStoreId: here in the scope of an
    /// unknown op, which read_db leaves undecoded.
    #[test]
    fn check_get_and_set_refuse_a_var_store_id_that_an_undecoded_var_store_may_declare() {
        let undecoded = nested(
            &operation(0x70, true, &[]),
            1,
            &[operation(VAR_STORE, false, &[0x00; 3])],
        );
        let lists = [list(
            PATH,
            &[(NAMESPACE, KEYWORD)],
            [undecoded, one_of(1, 0)].concat(),
        )];
        let question = question_of(&lists);

        let get = question.check_get(&reader(1));
        let set = question.check_set(
            &resp("03"),
            IncludedStates::empty(),
            VolatileWrites::Refuse,
            &mut reader(1),
        );

        let refusals = [
            ("get", get.err().map(|error| error.to_string())),
            ("set", set.err().map(|error| error.to_string())),
        ];
        for (name, refusal) in refusals {
            assert!(
                refusal.as_deref().is_some_and(|refusal| refusal.contains(
                    "may have the VarStoreId of a VarStore op of a FormSet of its package list \
                     that does not decode: failed to parse VarStore's data"
                )),
                "{name}: {refusal:?}"
            );
        }
    }

    /// check_get and check_set refuse a question when a form that read_db disables, of another
    /// FormSet of its package list, declares its VarStoreId for another variable before the op
    /// that disables it: edk2, which disables no form, keeps that VarStore op, which
    /// FindStorageFromVarId may take first.
    #[test]
    fn check_get_and_set_refuse_a_var_store_id_that_a_disabled_form_declares() {
        let (root, disabled) = parse_form_set_dropping(&[form(
            5,
            &[
                var_store(1, [0x44; 16], "Other", 16),
                operation(CHECKBOX, false, &[0x00]),
            ],
        )]);
        assert_eq!(disabled.len(), 1, "form 5 disabled");
        let mut lists = [list(PATH, &[(NAMESPACE, KEYWORD)], one_of(1, 0))];
        let roots_before = lists[0].forms.len();
        lists[0].forms.push(root);
        lists[0].disabled_forms = disabled
            .into_iter()
            .map(|disabled| disabled.after_roots(roots_before))
            .collect();
        let question = question_of(&lists);

        let get = question.check_get(&reader(1));
        let set = question.check_set(
            &resp("03"),
            IncludedStates::empty(),
            VolatileWrites::Refuse,
            &mut reader(1),
        );

        let want = "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which its \
                    package list also declares for EFI variable \
                    Other-44444444-4444-4444-4444-444444444444";
        let refusals = [
            ("get", get.err().map(|error| error.to_string())),
            ("set", set.err().map(|error| error.to_string())),
        ];
        for (name, refusal) in refusals {
            assert!(
                refusal
                    .as_deref()
                    .is_some_and(|refusal| refusal.starts_with(want)),
                "{name}: {refusal:?}"
            );
        }
    }

    /// The Keyword Handler sends a question on a VARSTORE_EFI of the form before UEFI 2.3.1 to its
    /// driver with its VarName as a VarOffset (edk2-stable202608 ConfigKeywordHandler.c
    /// ExtractConfigRequest :2114, ExtractConfigResp :2219; ConfigRouting.c GetVarStoreType
    /// :1902), never to the EFI variable that its VarName names, so check_get and check_set of a
    /// ONE_OF on one refuse it, naming the store, before they look at the bytes of that variable,
    /// which here hold a password.
    #[test]
    fn check_get_and_set_refuse_a_question_on_a_short_var_store() {
        let ops = [short_var_store_efi(2), one_of(2, 0)].concat();
        let mut lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
        // VarName 5, the question's VarStoreInfo, names the variable ShortVar
        lists[0].strings[0].strings.insert(5, "ShortVar".into());
        resolve_short_var_names(&lists[0].forms, &lists[0].strings);
        let question = question_of(&lists);
        let refusal = format!(
            "keyword {KEYWORD}: question {QUESTION:?} is on an EFI_IFR_VARSTORE_EFI before UEFI \
             2.3.1, whose VarName the Keyword Handler takes for a VarOffset in a request to its \
             driver, not for the EFI variable that get and set reach"
        );
        let short_var = VariableKey {
            name: "ShortVar".to_owned(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        };
        let withholding = || {
            let mut withheld = WithheldBytes::default();
            withheld.insert(short_var.clone(), 0..OFFSET + 1);
            EfivarReader::withholding(Box::new(variables(1)), withheld)
        };

        let get = question.check_get(&withholding());
        let set = question.check_set(
            &resp("03"),
            IncludedStates::empty(),
            VolatileWrites::Refuse,
            &mut withholding(),
        );

        assert_eq!(
            (
                get.err().map(|error| error.to_string()),
                set.err().map(|error| error.to_string())
            ),
            (Some(refusal.clone()), Some(refusal)),
            "get and set"
        );
    }

    /// check_get and check_set refuse a STRING, an ORDERED_LIST and a REF on a VARSTORE_EFI before
    /// UEFI 2.3.1 as they refuse a ONE_OF there, naming the store, before they look at the bytes
    /// of the variable of its VarName, which here hold a password: the Keyword Handler sends each
    /// to the driver with its VarName as a VarOffset, whatever its kind.
    #[test]
    fn check_get_and_set_refuse_strings_ordered_lists_and_refs_on_a_short_var_store() {
        let header = question_header_with(1, PROMPT, 2, 5, 0);
        let refusal = format!(
            "keyword {KEYWORD}: question {QUESTION:?} is on an EFI_IFR_VARSTORE_EFI before UEFI \
             2.3.1, whose VarName the Keyword Handler takes for a VarOffset in a request to its \
             driver, not for the EFI variable that get and set reach"
        );
        let short_var = VariableKey {
            name: "ShortVar".to_owned(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        };
        let withholding = || {
            let mut withheld = WithheldBytes::default();
            withheld.insert(short_var.clone(), 0..22);
            EfivarReader::withholding(Box::new(variables(1)), withheld)
        };
        let cases = [
            // MinSize 0, MaxSize 4, Flags 0
            (
                "STRING",
                operation(STRING, false, &[header.clone(), vec![0, 4, 0]].concat()),
            ),
            (
                "ORDERED_LIST",
                [
                    operation(ORDERED_LIST, true, &[header.clone(), vec![2, 0]].concat()),
                    flagged_option(6, 0x00, 1),
                    END.to_vec(),
                ]
                .concat(),
            ),
            ("REF", operation(REF, false, &header)),
        ];

        for (kind, question) in cases {
            let mut lists = [list(
                PATH,
                &[(NAMESPACE, KEYWORD)],
                [short_var_store_efi(2), question].concat(),
            )];
            // VarName 5, the question's VarStoreInfo, names the variable ShortVar
            lists[0].strings[0].strings.insert(5, "ShortVar".into());
            resolve_short_var_names(&lists[0].forms, &lists[0].strings);
            let question = question_of(&lists);

            let get = question.check_get(&withholding());
            let set = question.check_set(
                &resp("03"),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut withholding(),
            );

            assert_eq!(
                (
                    get.err().map(|error| error.to_string()),
                    set.err().map(|error| error.to_string())
                ),
                (Some(refusal.clone()), Some(refusal.clone())),
                "{kind}: get and set"
            );
        }
    }

    /// check_get and check_set refuse a ONE_OF on a VARSTORE_EFI before UEFI 2.3.1 whose VarName
    /// names an existing variable, which get and set read and write: GetData() and SetData() take
    /// that VarName for a VarOffset in a request to the driver.
    #[test]
    fn check_get_and_set_refuse_a_question_on_a_var_store_efi_before_uefi_2_3_1() {
        let ops = [short_var_store_efi(2), one_of(2, 0)].concat();
        let mut lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
        lists[0].strings[0].strings.insert(5, "ShortVar".into());
        resolve_short_var_names(&lists[0].forms, &lists[0].strings);
        let question = question_of(&lists);
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let short = VariableKey {
            name: "ShortVar".to_owned(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        };
        variables.insert(short, ATTRIBUTES, &[1]);
        let mut reader = EfivarReader::with_variables(Box::new(variables));

        let get = question.check_get(&reader);
        let set = question.check_set(
            &resp("03"),
            IncludedStates::empty(),
            VolatileWrites::Refuse,
            &mut reader,
        );

        assert_eq!(
            get.err(),
            Some(question_refusal(QuestionRefusal::ShortVarStore)),
            "check_get, short store"
        );
        assert_eq!(
            refusal_of(set),
            Some(question_refusal(QuestionRefusal::ShortVarStore)),
            "check_set, short store"
        );
    }

    /// A UINT16 VALUE holds the question's two bytes, the first in memory last.
    #[test]
    fn check_set_takes_a_uint16_value_as_its_bytes_in_memory() {
        let data = [
            question_header_with(1, PROMPT, 1, 5, 0),
            vec![0x01, 0, 0, 0xff, 0xff, 1, 0], // Flags UINT16, MinValue, MaxValue, Step
        ]
        .concat();
        let one_of_16 = [
            operation(ONE_OF, true, &data),
            one_of_option(4, 0x01, &0x0001_u16.to_le_bytes()),
            one_of_option(4, 0x01, &0x0102_u16.to_le_bytes()),
            END.to_vec(),
        ]
        .concat();
        let cases = [
            ("0102", None),
            ("0201", Some(value_refusal("0201", ValueRefusal::NoOption))),
            ("02", Some(value_refusal("02", ValueRefusal::Width))),
            ("000102", Some(value_refusal("000102", ValueRefusal::Width))),
        ];
        for (value, want) in cases {
            let result = check_set_of(one_of_16.clone(), value, IncludedStates::empty());

            assert_eq!(
                (result.is_ok(), refusal_of(result)),
                (want.is_none(), want),
                "VALUE={value}"
            );
        }
    }

    /// An INT_DEC NUMERIC's VALUE is signed, as set reads its text: ff is -1, fa -6.
    #[test]
    fn check_set_takes_a_signed_numeric_value() {
        let data = [
            question_header_with(1, PROMPT, 1, 5, 0),
            // Flags UINT8 and EFI_IFR_DISPLAY_INT_DEC, MinValue -5, MaxValue 5, Step 1
            vec![0x00, 0xfb, 5, 1],
        ]
        .concat();
        let numeric = operation(NUMERIC, false, &data);
        let below = ChangeValueError::BelowMinValue.to_string();
        let cases = [("ff", false), ("fa", true), ("05", false)];
        for (value, below_min) in cases {
            let result = check_set_of(numeric.clone(), value, IncludedStates::empty())
                .map_err(|error| format!("{error:#}"));

            assert_eq!(
                (
                    result.is_err(),
                    result.err().is_some_and(|error| error.contains(&below))
                ),
                (below_min, below_min),
                "VALUE={value} in -5..5"
            );
        }
    }

    /// The package list of list(PATH, ..) with what read_db reads from a form package of `ifr`:
    /// its FormSets and the ops outside them.
    fn list_read(ifr: Vec<u8>) -> ParsedPackageList {
        let read = read_db(&package_list_with_guid(
            [0x22; 16],
            &[form_package_of(&ifr), END_PACKAGE.to_vec()].concat(),
        ))
        .expect("read_db")
        .remove(0);
        ParsedPackageList {
            forms: read.forms,
            ignored_ifr: read.ignored_ifr,
            outside_ifr: read.outside_ifr,
            malformed_outside_stores: read.malformed_outside_stores,
            first_var_stores: read.first_var_stores,
            ..list(PATH, &[(NAMESPACE, KEYWORD)], Vec::new())
        }
    }

    /// The FormSet of list(), VarStore 1 of the variable Store, holding `ops`.
    fn store_form_set(ops: &[Vec<u8>]) -> Vec<u8> {
        form_set(&[var_store(1, STORE_GUID, "Store", 16), ops.concat()])
    }

    /// edk2-stable202608 FindQuestionFromStringId (ConfigKeywordHandler.c:1478) walks the whole
    /// form package, so a statement outside any FormSet, before it, that the keyword prompts is
    /// the statement that GetData() and SetData() take: a second statement of the keyword, also
    /// one whose bytes do not parse, as FindQuestionFromStringId reads its Prompt alone
    /// (:1497-1501).
    #[test]
    fn resolve_refuses_a_keyword_that_also_prompts_a_statement_outside_a_form_set() {
        for (name, outside) in [
            ("a PASSWORD", password_on(9, PROMPT, 1, 0)),
            (
                "a ONE_OF of its Prompt alone",
                operation(ONE_OF, false, &PROMPT.to_le_bytes()),
            ),
        ] {
            let lists = [list_read(
                [outside, store_form_set(&[one_of(1, 0)])].concat(),
            )];

            assert_eq!(
                resolve(&lists, Some(PATH)).err(),
                Some(KeywordRefusal::AmbiguousStatements {
                    keyword: KEYWORD.to_owned(),
                    count: 2,
                }),
                "{name}"
            );
        }
    }

    /// A ONE_OF outside any FormSet of 1 data byte, 0x03, then an op 0x00 of no data:
    /// edk2-stable202608 FindQuestionFromStringId reads the ONE_OF's Prompt at OpCodeData + 2
    /// whatever its Length (ConfigKeywordHandler.c:1498-1499), from 0x03 and the next op's first
    /// byte, PROMPT.
    fn short_one_of() -> Vec<u8> {
        [
            operation(ONE_OF, false, &[0x03]),
            operation(0x00, false, &[]),
        ]
        .concat()
    }

    /// A statement outside any FormSet shorter than its Prompt prompts every keyword, so a keyword
    /// that a FormSet's statement prompts prompts two.
    #[test]
    fn resolve_refuses_a_keyword_that_a_short_statement_outside_a_form_set_may_prompt() {
        let lists = [list_read(
            [short_one_of(), store_form_set(&[one_of(1, 0)])].concat(),
        )];

        assert_eq!(
            resolve(&lists, Some(PATH)).err(),
            Some(KeywordRefusal::AmbiguousStatements {
                keyword: KEYWORD.to_owned(),
                count: 2,
            })
        );
    }

    /// A keyword that only a statement outside any FormSet shorter than its Prompt may prompt
    /// prompts that statement: resolve refuses it, with or without PATH.
    #[test]
    fn resolve_refuses_a_keyword_that_only_a_short_statement_outside_a_form_set_may_prompt() {
        let lists = [list_read([short_one_of(), store_form_set(&[])].concat())];

        for path in [Some(PATH), None] {
            assert_eq!(
                resolve(&lists, path).err(),
                Some(KeywordRefusal::OutsideFormSet {
                    keyword: KEYWORD.to_owned(),
                    op: "EFI_IFR_ONE_OF",
                    offset: 0,
                }),
                "PATH {path:?}"
            );
        }
    }

    /// A statement outside any FormSet that the keyword alone prompts is the one that GetData()
    /// and SetData() take, and no FormSet gives it a VarStore: resolve refuses it, with or without
    /// PATH.
    #[test]
    fn resolve_refuses_a_keyword_that_prompts_only_a_statement_outside_a_form_set() {
        let lists = [list_read(
            [password_on(9, PROMPT, 1, 0), store_form_set(&[])].concat(),
        )];
        let want =
            "keyword Keyword: it prompts an EFI_IFR_PASSWORD outside any FormSet, at offset \
                    0 of a form package, whose question uefisettings neither reads nor writes";

        for path in [Some(PATH), None] {
            assert_eq!(
                resolve(&lists, path)
                    .err()
                    .map(|refusal| refusal.to_string()),
                Some(want.to_owned()),
                "PATH {path:?}"
            );
        }
    }

    /// A PASSWORD in a FormSet that read_db ignores, which parse_form_sets returns for its
    /// withholding (OutsideOp::in_ignored_ifr), is no statement that a keyword prompts, as no other
    /// statement of IFR that read_db ignores is: resolve takes the FormSet's.
    #[test]
    fn resolve_takes_no_password_of_ignored_ifr_for_a_statement() {
        let ignored = form_set(&[
            form(1, &[password_on(9, PROMPT, 1, 0)]),
            operation(CHECKBOX, false, &[0]),
        ]);
        let lists = [list_read(
            [ignored, store_form_set(&[one_of(1, 0)])].concat(),
        )];

        assert_eq!(resolve(&lists, Some(PATH)).err(), None);
    }

    /// FindStorageFromVarId (ConfigKeywordHandler.c:1520) takes the first VarStore of the id in
    /// the form package, so a VarStore outside any FormSet, before or after the question's,
    /// declares its VarStoreId for another variable, or a VARSTORE_NAME_VALUE: check_get and
    /// check_set refuse it, and take one declared for the same variable.
    #[test]
    fn check_get_refuses_a_var_store_id_that_a_var_store_outside_a_form_set_declares() {
        let refusal = |store: &str| {
            format!(
                "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which a \
                 VarStore outside a FormSet of its package list declares for {store}"
            )
        };
        let name_value = operation(
            VAR_STORE_NAME_VALUE,
            false,
            &[1_u16.to_le_bytes().to_vec(), vec![0x55; 16]].concat(),
        );
        let cases = [
            (
                "the variable Other",
                var_store(1, [0x44; 16], "Other", 16),
                Some(refusal(
                    "EFI variable Other-44444444-4444-4444-4444-444444444444",
                )),
            ),
            (
                "a VARSTORE_NAME_VALUE",
                name_value,
                Some(refusal("a VARSTORE_NAME_VALUE")),
            ),
            (
                "a VARSTORE_EFI before UEFI 2.3.1",
                short_var_store_efi(1),
                Some(refusal("an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1")),
            ),
            (
                "the variable Store",
                var_store(1, STORE_GUID, "Store", 16),
                None,
            ),
        ];
        for ((name, declaration, want), after) in cases
            .into_iter()
            .flat_map(|case| [(case.clone(), false), (case, true)])
        {
            let form_set = store_form_set(&[one_of(1, 0)]);
            let ifr = match after {
                false => [declaration, form_set],
                true => [form_set, declaration],
            };
            let lists = [list_read(ifr.concat())];
            let question = question_of(&lists);

            let get = question.check_get(&reader(1));
            let set = question.check_set(
                &resp("03"),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut reader(1),
            );

            assert_eq!(
                (
                    get.err().map(|error| error.to_string()),
                    set.err().map(|error| error.to_string())
                ),
                (want.clone(), want),
                "VarStore 1 of {name} outside the FormSet, after it: {after}"
            );
        }
    }

    /// FindStorageFromVarId walks the whole form package, so a VarStore in the scope of an
    /// unknown opcode, which edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips
    /// (:1358-1381), declares the question's VarStoreId for another variable all the same:
    /// check_get and check_set refuse it, and take one declared for the same variable.
    #[test]
    fn check_get_refuses_a_var_store_id_that_a_var_store_in_an_unknown_scope_declares() {
        let refusal = "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which a \
                       VarStore in the scope of an unknown opcode of its package list declares \
                       for EFI variable Other-44444444-4444-4444-4444-444444444444"
            .to_owned();
        for (name, declaration, want) in [
            (
                "the variable Other",
                var_store(1, [0x44; 16], "Other", 16),
                Some(refusal),
            ),
            (
                "the variable Store",
                var_store(1, STORE_GUID, "Store", 16),
                None,
            ),
        ] {
            let lists = [list_read(store_form_set(&[
                in_unknown_scope(&declaration),
                one_of(1, 0),
            ]))];
            let question = question_of(&lists);

            let get = question.check_get(&reader(1));
            let set = question.check_set(
                &resp("03"),
                IncludedStates::empty(),
                VolatileWrites::Refuse,
                &mut reader(1),
            );

            assert_eq!(
                (
                    get.err().map(|error| error.to_string()),
                    set.err().map(|error| error.to_string())
                ),
                (want.clone(), want),
                "VarStore 1 of {name} in an unknown scope"
            );
        }
    }

    /// A VarStore outside any FormSet that does not parse hides its VarStoreId, which may be the
    /// question's: check_get and check_set refuse the question.
    #[test]
    fn check_get_and_set_refuse_a_var_store_id_that_a_malformed_outside_var_store_may_declare() {
        let lists = [list_read(
            [
                operation(VAR_STORE, false, &[1, 0]),
                store_form_set(&[one_of(1, 0)]),
            ]
            .concat(),
        )];
        let question = question_of(&lists);
        let want = "keyword Keyword: question \"Keyword question\" may have the VarStoreId of the \
                    VarStore at offset 0 of a form package of its package list, which does not \
                    parse"
            .to_owned();

        let get = question.check_get(&reader(1));
        let set = question.check_set(
            &resp("03"),
            IncludedStates::empty(),
            VolatileWrites::Refuse,
            &mut reader(1),
        );

        assert_eq!(
            (
                get.err().map(|error| error.to_string()),
                set.err().map(|error| error.to_string())
            ),
            (Some(want.clone()), Some(want))
        );
    }

    /// EFI_IFR_OPTION_DEFAULT and EFI_IFR_OPTION_DEFAULT_MFG (UEFI 2.11 §33.3.8.3.51)
    const OPTION_DEFAULT: u8 = 0x10;
    const OPTION_DEFAULT_MFG: u8 = 0x20;
    /// "Question du mot-clé", PROMPT in fr-FR
    const FRENCH_QUESTION: &str = "Question du mot-cl\u{e9}";

    /// A package list of PATH holding `ops` after VarStore 1 whose x-UEFI-ns strings package,
    /// which comes first, names PROMPT KEYWORD and holds string 8 alone, and whose en-US and fr-FR
    /// ones hold PROMPT and the option texts 4, 6 and 7, en-US also string 5, empty.
    fn info_list(ops: Vec<u8>) -> ParsedPackageList {
        let package = |language: &[u8], texts: &[(u16, &str)]| StringPackage {
            language: Language(language.to_vec()),
            strings: texts.iter().map(|&(id, text)| (id, text.into())).collect(),
        };
        let mut list = list(PATH, &[], ops);
        list.strings = vec![
            StringPackage {
                language: Language(NAMESPACE.as_bytes().to_vec()),
                strings: BTreeMap::from([(PROMPT, KEYWORD.into()), (8, "eight".into())]),
            },
            package(
                b"en-US",
                &[
                    (PROMPT, QUESTION),
                    (4, "Zero"),
                    (5, ""),
                    (6, "One"),
                    (7, "Three"),
                ],
            ),
            package(
                b"fr-FR",
                &[
                    (PROMPT, FRENCH_QUESTION),
                    (4, "Z\u{e9}ro"),
                    (6, "Un"),
                    (7, "Trois"),
                ],
            ),
        ];
        list
    }

    /// The info of `filter` of the question of KEYWORD in an info_list of `ops`, its texts in the
    /// language that `requested` picks, reading variables(1).
    fn info_in(
        ops: Vec<u8>,
        filter: KeywordInfoFilter,
        requested: &[&str],
    ) -> Result<KeywordInfo, KeywordInfoRefusal> {
        let lists = [info_list(ops)];
        let mut questions = KeywordQuestion::resolve(
            &lists,
            Some(&namespace(NAMESPACE)),
            Some(&path_of(PATH)),
            &keyword(KEYWORD),
            requested,
        )
        .expect("the keyword");
        assert_eq!(questions.len(), 1, "one question of PATH");
        questions.remove(0).info(filter, &mut reader(1))
    }

    fn info_of(ops: Vec<u8>, filter: KeywordInfoFilter) -> Result<KeywordInfo, KeywordInfoRefusal> {
        info_in(ops, filter, &[])
    }

    fn number(bytes: &[u8]) -> Number {
        Number::try_from(bytes.to_vec()).expect("a <Number>")
    }

    fn text(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn option(value: &[u8], string: &str, value_type: Option<NumericWidth>) -> ValueOption {
        ValueOption {
            value: number(value),
            string: text(string),
            value_type: value_type.map(|width| KeywordNumeric { width: Some(width) }),
        }
    }

    fn numeric_of(width: NumericWidth) -> Option<DataFilter> {
        Some(DataFilter::Numeric(KeywordNumeric { width: Some(width) }))
    }

    /// The data of a question of `op_code` prompted by PROMPT at OFFSET of VarStore 1, `rest`
    /// after its header.
    fn question(op_code: u8, rest: &[u8]) -> Vec<u8> {
        let data = [question_header_with(1, PROMPT, 1, 5, 0), rest.to_vec()].concat();
        operation(op_code, false, &data)
    }

    /// An ORDERED_LIST of `containers` at OFFSET of VarStore 1 holding `scope`.
    fn ordered_list(containers: u8, scope: &[Vec<u8>]) -> Vec<u8> {
        let data = [
            question_header_with(1, PROMPT, 1, 5, 0),
            vec![containers, 0],
        ]
        .concat();
        [
            operation(ORDERED_LIST, true, &data),
            scope.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// A PASSWORD takes no default from a flagged EFI_IFR_ONE_OF_OPTION, as edk2-stable202608
    /// HiiDatabaseDxe/ConfigRouting.c gives it none (:3135-3137), where a STRING takes that
    /// option's default, whose number no STRING stores.
    #[test]
    fn info_of_a_password_takes_no_default_from_a_flagged_option() {
        let question = |op_code, rest: Vec<u8>| {
            let data = [question_header_with(1, PROMPT, 1, 5, 0), rest].concat();
            [
                operation(op_code, true, &data),
                flagged_option(4, OPTION_DEFAULT, 1),
                END.to_vec(),
            ]
            .concat()
        };
        // MinSize 1, MaxSize 4
        let password = question(PASSWORD, vec![1, 0, 4, 0]);
        // MinSize 1, MaxSize 4, Flags
        let string = question(STRING, vec![1, 4, 0]);

        assert_eq!(
            info_of(password, KeywordInfoFilter::DEFAULT),
            Ok(KeywordInfo::default()),
            "PASSWORD"
        );
        assert_eq!(
            info_of(string, KeywordInfoFilter::DEFAULT),
            Err(KeywordInfoRefusal::Default {
                keyword: KEYWORD.to_owned(),
                default_id: DefaultId::STANDARD,
                reason: "EFI_IFR_STRING holds no Number(1)".to_owned(),
            }),
            "STRING"
        );
    }

    /// A NUMERIC's `<KeywordInfoResp>`: Numeric of its width, its MinValue, MaxValue and Step,
    /// its defaults of DefaultIds 0 and 2, not that of a platform default store, and its prompt
    /// in en-US, not the x-UEFI-ns keyword that comes first.
    #[test]
    fn info_of_a_numeric_holds_its_type_range_defaults_and_prompt() {
        let numeric = [
            operation(NUMERIC, true, &uint8_question(1, 0)),
            ifr_default(0x0000, 2),
            ifr_default(0x0002, 1),
            // EFI_HII_DEFAULT_CLASS_PLATFORM_BEGIN (UEFI 2.11 §33.2.5.8)
            ifr_default(0x4000, 3),
            END.to_vec(),
        ]
        .concat();

        assert_eq!(
            info_of(numeric, KeywordInfoFilter::all()),
            Ok(KeywordInfo {
                data_type: numeric_of(NumericWidth::One),
                range: Some(ValueRange {
                    max: number(&[3]),
                    min: number(&[0]),
                    step: Some(number(&[1])),
                }),
                options: Vec::new(),
                standard_default: Some(number(&[2])),
                manufacturing_default: None,
                safe_default: Some(number(&[1])),
                display_name: Some(text(QUESTION)),
            }),
            "UINT8 NUMERIC from 0 to 3 by 1"
        );
    }

    /// A UINT16 NUMERIC's bounds are 2 bytes each, and a Step of 0, free-form input, gives no
    /// STEP.
    #[test]
    fn info_of_a_free_form_numeric_has_no_step() {
        // Flags UINT16, MinValue 0x10, MaxValue 0x1234, Step 0
        let numeric = question(NUMERIC, &[0x01, 0x10, 0x00, 0x34, 0x12, 0x00, 0x00]);

        assert_eq!(
            info_of(
                numeric,
                KeywordInfoFilter::DATA_TYPE | KeywordInfoFilter::VALUE_ATTRIBUTE
            ),
            Ok(KeywordInfo {
                data_type: numeric_of(NumericWidth::Two),
                range: Some(ValueRange {
                    max: number(&[0x34, 0x12]),
                    min: number(&[0x10, 0x00]),
                    step: None,
                }),
                ..KeywordInfo::default()
            }),
            "UINT16 NUMERIC from 0x10 to 0x1234"
        );
    }

    /// A ONE_OF's options are those SetupBrowserDxe shows, also under a GRAY_OUT_IF, which
    /// edk2-stable202608 IfrParse.c applies to statements alone, with their en-US texts; its
    /// flagged options give its standard and manufacturing defaults; items outside the filter
    /// stay out.
    #[test]
    fn info_of_a_one_of_lists_the_options_shown_in_a_ui_language() {
        let one_of = [
            operation(ONE_OF, true, &uint8_question(1, 0)),
            flagged_option(4, OPTION_DEFAULT, 0),
            conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(6, 0, 2)]),
            conditional(GRAY_OUT_IF, ifr_true(), &[flagged_option(6, 0, 1)]),
            flagged_option(7, OPTION_DEFAULT_MFG, 3),
            END.to_vec(),
        ]
        .concat();

        assert_eq!(
            info_of(
                one_of,
                KeywordInfoFilter::VALUE_ATTRIBUTE | KeywordInfoFilter::DEFAULT
            ),
            Ok(KeywordInfo {
                options: vec![
                    option(&[0], "Zero", None),
                    option(&[1], "One", None),
                    option(&[3], "Three", None),
                ],
                standard_default: Some(number(&[0])),
                manufacturing_default: Some(number(&[3])),
                ..KeywordInfo::default()
            }),
            "UINT8 ONE_OF of options 0, 1 grayed out, and 3, 2 suppressed"
        );
    }

    /// A CHECKBOX is Boolean, its default flag its standard default, and it has no
    /// `<ValueAttribute>`.
    #[test]
    fn info_of_a_checkbox_is_boolean_with_its_flag_default() {
        let checkbox = question(CHECKBOX, &[0x01]); // EFI_IFR_CHECKBOX_DEFAULT

        assert_eq!(
            info_of(
                checkbox,
                KeywordInfoFilter::DATA_TYPE
                    | KeywordInfoFilter::VALUE_ATTRIBUTE
                    | KeywordInfoFilter::DEFAULT
            ),
            Ok(KeywordInfo {
                data_type: Some(DataFilter::Boolean),
                standard_default: Some(number(&[1])),
                ..KeywordInfo::default()
            }),
            "CHECKBOX of EFI_IFR_CHECKBOX_DEFAULT"
        );
    }

    /// A STRING's `<ValueRange>` is its MinSize and MaxSize; DATE and TIME have a `<DataType>`
    /// alone; an ORDERED_LIST is a Buffer whose options name their VALUETYPE, the width of their
    /// values.
    #[test]
    fn info_of_strings_dates_times_and_ordered_lists_follows_the_type_table() {
        let filter = KeywordInfoFilter::DATA_TYPE | KeywordInfoFilter::VALUE_ATTRIBUTE;
        let uint16_options = ordered_list(
            2,
            &[
                one_of_option(4, 0x01, &0x0001_u16.to_le_bytes()),
                one_of_option(7, 0x01, &0x0103_u16.to_le_bytes()),
            ],
        );
        let cases = [
            (
                "STRING",
                question(STRING, &[1, 20, 0]),
                KeywordInfo {
                    data_type: Some(DataFilter::String),
                    range: Some(ValueRange {
                        max: number(&[20]),
                        min: number(&[1]),
                        step: None,
                    }),
                    ..KeywordInfo::default()
                },
            ),
            (
                "DATE",
                question(DATE, &[0]),
                KeywordInfo {
                    data_type: Some(DataFilter::Date),
                    ..KeywordInfo::default()
                },
            ),
            (
                "TIME",
                question(TIME, &[0]),
                KeywordInfo {
                    data_type: Some(DataFilter::Time),
                    ..KeywordInfo::default()
                },
            ),
            (
                "ORDERED_LIST of UINT16 options",
                uint16_options,
                KeywordInfo {
                    data_type: Some(DataFilter::Buffer),
                    options: vec![
                        option(&[0x01, 0x00], "Zero", Some(NumericWidth::Two)),
                        option(&[0x03, 0x01], "Three", Some(NumericWidth::Two)),
                    ],
                    ..KeywordInfo::default()
                },
            ),
        ];
        for (name, ops, expected) in cases {
            assert_eq!(info_of(ops, filter), Ok(expected), "{name}");
        }
    }

    /// A STRING's default is its string's CHAR16s in the texts' language, zero-padded to MaxSize
    /// CHAR16s; an ORDERED_LIST's is its EFI_IFR_TYPE_BUFFER default or its flagged option's
    /// value, which is no option then, zero-padded to MaxContainers, an option of both flags
    /// giving the standard default alone; a longer one refuses, and one of a DATE is its bytes.
    #[test]
    fn info_of_string_and_ordered_list_defaults_is_their_value_bytes() {
        // MinSize 1, MaxSize 4, Flags
        let string = |default: Vec<u8>| {
            let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![1, 4, 0]].concat();
            [operation(STRING, true, &data), default, END.to_vec()].concat()
        };
        let one = typed_default(0x0000, 0x07, &6_u16.to_le_bytes()); // EFI_IFR_TYPE_STRING
        let three = typed_default(0x0000, 0x07, &7_u16.to_le_bytes());
        let options = [flagged_option(4, 0, 1), flagged_option(7, 0, 3)];
        let buffer_default = ordered_list(
            3,
            &[
                options.to_vec(),
                vec![typed_default(0x0000, 0x0B, &[3, 1])], // EFI_IFR_TYPE_BUFFER
            ]
            .concat(),
        );
        let flagged_default = ordered_list(
            3,
            &[
                flagged_option(4, OPTION_DEFAULT | OPTION_DEFAULT_MFG, 1),
                flagged_option(7, OPTION_DEFAULT_MFG, 3),
            ],
        );
        let standard = |value: &[u8]| {
            Ok(KeywordInfo {
                standard_default: Some(number(value)),
                ..KeywordInfo::default()
            })
        };
        let refusal = |reason: &str| {
            Err(KeywordInfoRefusal::Default {
                keyword: KEYWORD.to_owned(),
                default_id: DefaultId::STANDARD,
                reason: reason.to_owned(),
            })
        };
        let cases: [(&str, Vec<u8>, &[&str], _); 6] = [
            (
                "STRING of \"One\"",
                string(one.clone()),
                &[],
                standard(&[b'O', 0, b'n', 0, b'e', 0, 0, 0]),
            ),
            (
                "STRING of \"Un\", in fr-FR",
                string(one),
                &["fr-FR"],
                standard(&[b'U', 0, b'n', 0, 0, 0, 0, 0]),
            ),
            (
                "STRING of \"Three\", 5 CHAR16s",
                string(three),
                &[],
                refusal("it is wider than the question's 8 bytes"),
            ),
            (
                "ORDERED_LIST of EFI_IFR_TYPE_BUFFER 3 1",
                buffer_default,
                &[],
                standard(&[3, 1, 0]),
            ),
            (
                "ORDERED_LIST of flagged options 1, standard, and 3, manufacturing",
                flagged_default,
                &[],
                Ok(KeywordInfo {
                    standard_default: Some(number(&[1, 0, 0])),
                    manufacturing_default: Some(number(&[3, 0, 0])),
                    ..KeywordInfo::default()
                }),
            ),
            (
                "DATE",
                [
                    operation(
                        DATE,
                        true,
                        &[question_header_with(1, PROMPT, 1, 5, 0), vec![0]].concat(),
                    ),
                    ifr_default(0x0000, 1),
                    END.to_vec(),
                ]
                .concat(),
                &[],
                standard(&[1, 0, 0, 0]),
            ),
        ];
        for (name, ops, requested, expected) in cases {
            assert_eq!(
                info_in(ops, KeywordInfoFilter::DEFAULT, requested),
                expected,
                "{name}"
            );
        }

        assert_eq!(
            info_of(
                ordered_list(
                    3,
                    &[
                        flagged_option(4, 0, 1),
                        flagged_option(7, OPTION_DEFAULT, 3),
                    ]
                ),
                KeywordInfoFilter::VALUE_ATTRIBUTE
            ),
            Ok(KeywordInfo {
                options: vec![option(&[1], "Zero", Some(NumericWidth::One))],
                ..KeywordInfo::default()
            }),
            "the flagged option of an ORDERED_LIST is no option"
        );
    }

    /// A DATE's or TIME's default is the bytes of its EFI_HII_DATE or EFI_HII_TIME, whether of its
    /// Type or of a numeric one; one of Type STRING or BUFFER, or wider than the question's 4 or 3
    /// bytes, refuses.
    #[test]
    fn info_of_date_and_time_defaults_is_their_value_bytes() {
        let question = |op_code: u8, default: Vec<u8>| {
            let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![0]].concat();
            [operation(op_code, true, &data), default, END.to_vec()].concat()
        };
        let standard = |value: &[u8]| {
            Ok(KeywordInfo {
                standard_default: Some(number(value)),
                ..KeywordInfo::default()
            })
        };
        let refusal = |reason: &str| {
            Err(KeywordInfoRefusal::Default {
                keyword: KEYWORD.to_owned(),
                default_id: DefaultId::STANDARD,
                reason: reason.to_owned(),
            })
        };
        let cases = [
            (
                "DATE of EFI_IFR_TYPE_DATE 2024-02-29",
                question(DATE, typed_default(0x0000, 0x06, &[0xE8, 0x07, 2, 29])),
                standard(&[0xE8, 0x07, 2, 29]),
            ),
            (
                "TIME of EFI_IFR_TYPE_TIME 23:59:58",
                question(TIME, typed_default(0x0000, 0x05, &[23, 59, 58])),
                standard(&[23, 59, 58]),
            ),
            (
                "DATE of EFI_IFR_TYPE_STRING 6",
                question(DATE, typed_default(0x0000, 0x07, &6_u16.to_le_bytes())),
                refusal("EFI_IFR_DATE holds no String(6)"),
            ),
            (
                "DATE of EFI_IFR_TYPE_BUFFER",
                question(DATE, typed_default(0x0000, 0x0B, &[0xE8, 0x07, 2, 29])),
                refusal("EFI_IFR_DATE holds no Buffer([232, 7, 2, 29])"),
            ),
            (
                "TIME of EFI_IFR_TYPE_BUFFER",
                question(TIME, typed_default(0x0000, 0x0B, &[0xE8, 0x07, 2, 29])),
                refusal("EFI_IFR_TIME holds no Buffer([232, 7, 2, 29])"),
            ),
            (
                "TIME of EFI_IFR_TYPE_NUM_SIZE_32 0x01000000",
                question(TIME, uint32_default(0x0000, 0x0100_0000)),
                refusal("it is wider than the question's 3 bytes"),
            ),
        ];
        for (name, ops, expected) in cases {
            assert_eq!(info_of(ops, KeywordInfoFilter::DEFAULT), expected, "{name}");
        }
    }

    /// get and KEYWORDINFO answer one default of an ORDERED_LIST whose option flagged
    /// EFI_IFR_OPTION_DEFAULT comes before its EFI_IFR_DEFAULT of DefaultId STANDARD in IFR order:
    /// the EFI_IFR_DEFAULT's, which UEFI 2.11 §33.2.5.8 ranks above the option's.
    #[test]
    fn get_and_info_take_the_ifr_default_of_an_ordered_list_before_its_flagged_option() {
        let ops = ordered_list(
            3,
            &[
                flagged_option(4, 0, 1),
                flagged_option(7, OPTION_DEFAULT, 3),
                typed_default(0x0000, 0x0B, &[1, 1]), // EFI_IFR_TYPE_BUFFER
            ],
        );
        let lists = [info_list(ops.clone())];
        let texts = ListTexts::new(&lists[0].strings, &[]);
        let get: Vec<(DefaultId, String)> = list_questions(
            Rc::clone(&lists[0].forms[0]),
            &texts,
            IncludedStates::empty(),
            None,
            &mut reader(1),
        )
        .into_iter()
        .flat_map(|(descriptor, _)| descriptor.defaults)
        .map(|default| (default.default_id, default.value.to_string()))
        .collect();

        assert_eq!(
            get,
            [(DefaultId::STANDARD, "Zero, Zero".to_owned())],
            "get: the items of 1 1"
        );
        assert_eq!(
            info_of(ops, KeywordInfoFilter::DEFAULT),
            Ok(KeywordInfo {
                standard_default: Some(number(&[1, 1, 0])),
                ..KeywordInfo::default()
            }),
            "KEYWORDINFO: 1 1, zero-padded"
        );
    }

    /// A REF of QuestionId 1 at OFFSET of VarStore 1 whose EFI_IFR_DEFAULT of DefaultId STANDARD
    /// has Type `value_type` and Value `value`.
    fn ref_with_default(value_type: u8, value: &[u8]) -> Vec<u8> {
        // FormId 1
        let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![1, 0]].concat();
        [
            operation(REF, true, &data),
            typed_default(0x0000, value_type, value),
            END.to_vec(),
        ]
        .concat()
    }

    /// An EFI_HII_REF: QuestionId 5, FormId 1, FormSetGuid 11111111-1111-1111-1111-111111111111
    /// and DevicePath 0.
    fn hii_ref_bytes() -> Vec<u8> {
        [&[5, 0, 1, 0][..], &[0x11; 16], &[0, 0]].concat()
    }

    /// get and KEYWORDINFO answer one default of a REF: the EFI_HII_REF of its EFI_IFR_DEFAULT of
    /// Type EFI_IFR_TYPE_REF.
    #[test]
    fn get_and_info_take_the_hii_ref_default_of_a_ref() {
        let ops = ref_with_default(0x0C, &hii_ref_bytes()); // EFI_IFR_TYPE_REF
        let lists = [info_list(ops.clone())];
        let texts = ListTexts::new(&lists[0].strings, &[]);
        let get: Vec<(DefaultId, String)> = list_questions(
            Rc::clone(&lists[0].forms[0]),
            &texts,
            IncludedStates::empty(),
            None,
            &mut reader(1),
        )
        .into_iter()
        .flat_map(|(descriptor, _)| descriptor.defaults)
        .map(|default| (default.default_id, default.value.to_string()))
        .collect();

        assert_eq!(
            get,
            [(
                DefaultId::STANDARD,
                "QuestionId 0x0005, FormId 0x0001, FormSetGuid \
                 11111111-1111-1111-1111-111111111111, DevicePath none"
                    .to_owned()
            )],
            "get"
        );
        assert_eq!(
            info_of(ops, KeywordInfoFilter::DEFAULT),
            Ok(KeywordInfo {
                standard_default: Some(number(&hii_ref_bytes())),
                ..KeywordInfo::default()
            }),
            "KEYWORDINFO"
        );
    }

    /// KEYWORDINFO refuses a default of a REF wider than an EFI_HII_REF, or of a Type other than
    /// EFI_IFR_TYPE_REF, and gives a REF no `<DataType>`.
    #[test]
    fn info_refuses_a_ref_default_that_is_no_hii_ref() {
        let refusal = |reason: &str| {
            Err(KeywordInfoRefusal::Default {
                keyword: KEYWORD.to_owned(),
                default_id: DefaultId::STANDARD,
                reason: reason.to_owned(),
            })
        };
        let wider = [hii_ref_bytes(), vec![1]].concat();
        let cases = [
            (
                "EFI_IFR_TYPE_REF of 23 bytes",
                ref_with_default(0x0C, &wider),
                refusal("it is wider than the question's 22 bytes"),
            ),
            (
                "EFI_IFR_TYPE_NUM_SIZE_8 1",
                ref_with_default(0x00, &[1]),
                refusal("EFI_IFR_REF holds no Number(1)"),
            ),
        ];
        for (name, ops, expected) in cases {
            assert_eq!(info_of(ops, KeywordInfoFilter::DEFAULT), expected, "{name}");
        }

        assert_eq!(
            info_of(
                ref_with_default(0x0C, &hii_ref_bytes()),
                KeywordInfoFilter::DATA_TYPE
            ),
            Err(KeywordInfoRefusal::NoDataType {
                keyword: KEYWORD.to_owned(),
                op: "EFI_IFR_REF",
            }),
            "DATATYPE"
        );
    }

    /// DISPLAYNAME and OPTIONSTRING come in the language that `requested` picks, never from a
    /// configuration language's package, which holds keywords: a string that only such a package
    /// holds refuses, and so does an empty one, which no `<String>` is.
    #[test]
    fn info_texts_show_in_the_requested_language_never_a_keyword() {
        let one_of = |scope: &[Vec<u8>]| {
            [
                operation(ONE_OF, true, &uint8_question(1, 0)),
                scope.concat(),
                END.to_vec(),
            ]
            .concat()
        };
        let filter = KeywordInfoFilter::VALUE_ATTRIBUTE | KeywordInfoFilter::DISPLAY_NAME;
        let shown = one_of(&[flagged_option(4, 0, 0), flagged_option(6, 0, 1)]);
        let cases = [
            (
                "fr-FR",
                KeywordInfo {
                    options: vec![option(&[0], "Z\u{e9}ro", None), option(&[1], "Un", None)],
                    display_name: Some(text(FRENCH_QUESTION)),
                    ..KeywordInfo::default()
                },
            ),
            (
                NAMESPACE,
                KeywordInfo {
                    options: vec![option(&[0], "Zero", None), option(&[1], "One", None)],
                    display_name: Some(text(QUESTION)),
                    ..KeywordInfo::default()
                },
            ),
        ];
        for (language, expected) in cases {
            assert_eq!(
                info_in(shown.clone(), filter, &[language]),
                Ok(expected),
                "texts of {language}"
            );
        }

        assert_eq!(
            info_in(one_of(&[flagged_option(8, 0, 0)]), filter, &["fr-FR"]),
            Err(KeywordInfoRefusal::NoText {
                keyword: KEYWORD.to_owned(),
                id: 8,
            }),
            "an option of string 8, which x-UEFI-ns alone holds"
        );
        assert_eq!(
            info_in(one_of(&[flagged_option(5, 0, 0)]), filter, &["fr-FR"]),
            Err(KeywordInfoRefusal::NoText {
                keyword: KEYWORD.to_owned(),
                id: 5,
            }),
            "an option of string 5, which en-US holds empty"
        );
    }

    /// What the IFR does not tell refuses the items that need it, and only those: a default
    /// wider than the question; an option text in no display language, unless the option is
    /// suppressed; an option under a SUPPRESS_IF on a question of a VarStore that no variable
    /// holds, named by its string; the defaults of a question of EFI_IFR_FLAG_CALLBACK, which its
    /// driver's Callback() outranks; the type of a PASSWORD or REF.
    #[test]
    fn info_refuses_what_the_ifr_does_not_tell() {
        // Flags UINT16, 0 to 0xFFFF by 1
        let uint16 = [
            question_header_with(1, PROMPT, 1, 5, 0),
            vec![0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x00],
        ]
        .concat();
        let wide_default = [
            operation(NUMERIC, true, &uint16),
            uint32_default(0x0000, 0x1_0000),
            END.to_vec(),
        ]
        .concat();
        assert_eq!(
            info_of(wide_default.clone(), KeywordInfoFilter::DEFAULT),
            Err(KeywordInfoRefusal::Default {
                keyword: KEYWORD.to_owned(),
                default_id: DefaultId::STANDARD,
                reason: "it is wider than the question's 2 bytes".to_owned(),
            }),
            "a UINT32 default of a UINT16 NUMERIC"
        );
        assert!(
            info_of(wide_default, KeywordInfoFilter::VALUE_ATTRIBUTE).is_ok(),
            "its range alone"
        );

        let one_of = |scope: &[Vec<u8>]| {
            [
                var_store(2, [0x44; 16], "Unread", 16),
                one_of_at(11, 9, 2, 0, &[(4, 1)]),
                operation(ONE_OF, true, &uint8_question(1, 0)),
                flagged_option(4, 0, 0),
                scope.concat(),
                END.to_vec(),
            ]
            .concat()
        };
        let textless = one_of(&[flagged_option(9, 0, 1)]);
        assert_eq!(
            info_of(textless.clone(), KeywordInfoFilter::VALUE_ATTRIBUTE),
            Err(KeywordInfoRefusal::NoText {
                keyword: KEYWORD.to_owned(),
                id: 9,
            }),
            "an option of string 9"
        );
        assert_eq!(
            info_of(textless, KeywordInfoFilter::DATA_TYPE),
            Ok(KeywordInfo {
                data_type: numeric_of(NumericWidth::One),
                ..KeywordInfo::default()
            }),
            "its type alone"
        );
        assert_eq!(
            info_of(
                one_of(&[conditional(
                    SUPPRESS_IF,
                    ifr_true(),
                    &[flagged_option(9, 0, 1)]
                )]),
                KeywordInfoFilter::VALUE_ATTRIBUTE
            ),
            Ok(KeywordInfo {
                options: vec![option(&[0], "Zero", None)],
                ..KeywordInfo::default()
            }),
            "a suppressed option of string 9"
        );

        let unknown = one_of(&[conditional(
            SUPPRESS_IF,
            eq_id_val_of(11, 1),
            &[flagged_option(9, 0, 1)],
        )]);
        assert!(
            matches!(
                info_of(unknown.clone(), KeywordInfoFilter::VALUE_ATTRIBUTE),
                Err(KeywordInfoRefusal::OptionState { option: 9, .. })
            ),
            "an option under a SUPPRESS_IF on question 11 of an unread VarStore: {:?}",
            info_of(unknown.clone(), KeywordInfoFilter::VALUE_ATTRIBUTE)
        );
        assert_eq!(
            info_of(unknown, KeywordInfoFilter::DATA_TYPE),
            Ok(KeywordInfo {
                data_type: numeric_of(NumericWidth::One),
                ..KeywordInfo::default()
            }),
            "its type alone, under that SUPPRESS_IF"
        );

        let callback = [
            operation(NUMERIC, true, &uint8_question(1, 0x04)), // EFI_IFR_FLAG_CALLBACK
            ifr_default(0x0000, 2),
            END.to_vec(),
        ]
        .concat();
        assert_eq!(
            info_of(callback.clone(), KeywordInfoFilter::DEFAULT),
            Err(KeywordInfoRefusal::Default {
                keyword: KEYWORD.to_owned(),
                default_id: DefaultId::STANDARD,
                reason: CALLBACK_DEFAULT.to_owned(),
            }),
            "the defaults of a question of EFI_IFR_FLAG_CALLBACK"
        );
        assert!(
            info_of(
                callback,
                KeywordInfoFilter::all().difference(KeywordInfoFilter::DEFAULT)
            )
            .is_ok(),
            "its other items"
        );

        let untyped = [
            ("PASSWORD", password_on(1, PROMPT, 1, 5), "EFI_IFR_PASSWORD"),
            ("REF", question(REF, &[1, 0]), "EFI_IFR_REF"),
        ];
        for (name, ops, op) in untyped {
            assert_eq!(
                info_of(ops, KeywordInfoFilter::DATA_TYPE),
                Err(KeywordInfoRefusal::NoDataType {
                    keyword: KEYWORD.to_owned(),
                    op,
                }),
                "{name}"
            );
        }
    }

    /// check_get and check_set refuse a DATE, TIME or ORDERED_LIST where they refuse a ONE_OF, the
    /// refusal before check_set finds keyword set of them unimplemented: on a VARSTORE_EFI before
    /// UEFI 2.3.1, whose variable get reads; on a VarStoreId that a VarStore outside any FormSet
    /// declares for another variable; and beside an outside VarStore that does not parse.
    #[test]
    fn check_get_and_set_refuse_dates_times_and_ordered_lists_where_they_refuse_a_one_of() {
        let question = |op_code: u8, var_store_id: u16| {
            let data = [
                question_header_with(1, PROMPT, var_store_id, 5, 0),
                vec![0x00, 0x01, 0x02, 0x00],
            ]
            .concat();
            match op_code {
                // with an option, whose Type gives the containers of an ORDERED_LIST a width
                ORDERED_LIST => [
                    operation(op_code, true, &data),
                    flagged_option(6, 0x00, 1),
                    END.to_vec(),
                ]
                .concat(),
                _ => operation(op_code, false, &data),
            }
        };
        let outside = "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which a \
                       VarStore outside a FormSet of its package list declares for EFI \
                       variable Other-44444444-4444-4444-4444-444444444444";
        let malformed = "keyword Keyword: question \"Keyword question\" may have the VarStoreId \
                         of the VarStore at offset 0 of a form package of its package list, \
                         which does not parse";
        for (op_code, op, short) in [
            (DATE, "EFI_IFR_DATE", QuestionRefusal::ShortVarStore),
            (TIME, "EFI_IFR_TIME", QuestionRefusal::ShortVarStore),
            (
                ORDERED_LIST,
                "EFI_IFR_ORDERED_LIST",
                QuestionRefusal::ShortVarStore,
            ),
        ] {
            let mut short_lists = [list(
                PATH,
                &[(NAMESPACE, KEYWORD)],
                [short_var_store_efi(2), question(op_code, 2)].concat(),
            )];
            short_lists[0].strings[0]
                .strings
                .insert(5, "ShortVar".into());
            resolve_short_var_names(&short_lists[0].forms, &short_lists[0].strings);
            let outside_lists = [list_read(
                [
                    var_store(1, [0x44; 16], "Other", 16),
                    store_form_set(&[question(op_code, 1)]),
                ]
                .concat(),
            )];
            let malformed_lists = [list_read(
                [
                    operation(VAR_STORE, false, &[1, 0]),
                    store_form_set(&[question(op_code, 1)]),
                ]
                .concat(),
            )];
            let short = question_refusal(short).to_string();

            for (name, lists, want) in [
                ("short store", &short_lists, short.as_str()),
                ("outside VarStore", &outside_lists, outside),
                ("malformed outside VarStore", &malformed_lists, malformed),
            ] {
                let keyword_question = question_of(lists);

                let get = keyword_question.check_get(&reader(1));
                let set = keyword_question.check_set(
                    &resp("03"),
                    IncludedStates::empty(),
                    VolatileWrites::Refuse,
                    &mut reader(1),
                );

                assert_eq!(
                    (
                        get.err().map(|error| error.to_string()),
                        set.err().map(|error| error.to_string())
                    ),
                    (Some(want.to_owned()), Some(want.to_owned())),
                    "{op}, {name}: get and set"
                );
            }
        }
    }

    /// A question's KeywordKind: ReadOnly by EFI_IFR_FLAG_READ_ONLY, and the data type of UEFI
    /// 2.11 §35.2.1.6's table by op code, decoded or not: a NUMERIC's or ONE_OF's Numeric of the
    /// EFI_IFR_NUMERIC_SIZE of its Flags.
    #[test]
    fn kind_tells_the_usage_and_the_data_type_of_the_table() {
        let flagged = |op_code: u8, flags: u8, rest: &[u8]| {
            let data = [question_header_with(1, PROMPT, 1, 5, flags), rest.to_vec()].concat();
            operation(op_code, false, &data)
        };
        let numeric = |width| Some(DataFilter::Numeric(KeywordNumeric { width: Some(width) }));
        let range = |size: u8, bytes: &[u8]| [&[size][..], bytes, bytes, bytes].concat();
        let buffer_like = [0x00, 0x01, 0x02, 0x00];
        let cases = [
            (
                "UINT8 ONE_OF",
                one_of(1, 0),
                Usage::ReadWrite,
                numeric(NumericWidth::One),
            ),
            (
                "read-only ONE_OF",
                one_of(1, 0x01),
                Usage::ReadOnly,
                numeric(NumericWidth::One),
            ),
            (
                "UINT16 NUMERIC",
                flagged(NUMERIC, 0, &range(0x01, &[0; 2])),
                Usage::ReadWrite,
                numeric(NumericWidth::Two),
            ),
            (
                "UINT32 NUMERIC",
                flagged(NUMERIC, 0, &range(0x02, &[0; 4])),
                Usage::ReadWrite,
                numeric(NumericWidth::Four),
            ),
            (
                "read-only UINT64 NUMERIC",
                flagged(NUMERIC, 0x01, &range(0x03, &[0; 8])),
                Usage::ReadOnly,
                numeric(NumericWidth::Eight),
            ),
            (
                "CHECKBOX",
                checkbox_at(1, PROMPT, 1, 5),
                Usage::ReadWrite,
                Some(DataFilter::Boolean),
            ),
            (
                "STRING",
                flagged(STRING, 0, &buffer_like),
                Usage::ReadWrite,
                Some(DataFilter::String),
            ),
            (
                "ORDERED_LIST",
                flagged(ORDERED_LIST, 0, &buffer_like),
                Usage::ReadWrite,
                Some(DataFilter::Buffer),
            ),
            (
                "DATE",
                flagged(DATE, 0x01, &buffer_like),
                Usage::ReadOnly,
                Some(DataFilter::Date),
            ),
            (
                "TIME",
                flagged(TIME, 0, &buffer_like),
                Usage::ReadWrite,
                Some(DataFilter::Time),
            ),
            ("REF", flagged(REF, 0, &[1, 0]), Usage::ReadWrite, None),
            (
                "undecoded CHECKBOX without Flags",
                in_unknown_scope(&flagged(CHECKBOX, 0, &[])),
                Usage::ReadWrite,
                Some(DataFilter::Boolean),
            ),
            (
                "undecoded UINT16 ONE_OF, without its range",
                in_unknown_scope(&flagged(ONE_OF, 0x01, &[0x01])),
                Usage::ReadOnly,
                numeric(NumericWidth::Two),
            ),
            (
                "undecoded UINT64 NUMERIC, without its range",
                in_unknown_scope(&flagged(NUMERIC, 0, &[0x03])),
                Usage::ReadWrite,
                numeric(NumericWidth::Eight),
            ),
        ];
        for (name, ops, usage, data_type) in cases {
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], ops)];
            assert_eq!(
                question_of(&lists).kind(),
                Ok(KeywordKind { usage, data_type }),
                "{name}"
            );
        }
    }

    /// A ONE_OF or NUMERIC that ends before its Flags has no data type, which kind and info
    /// refuse rather than leave out.
    #[test]
    fn kind_and_info_refuse_a_one_of_or_numeric_without_flags() {
        for (op_code, op) in [(ONE_OF, "EFI_IFR_ONE_OF"), (NUMERIC, "EFI_IFR_NUMERIC")] {
            let flagless = || {
                let data = question_header_with(1, PROMPT, 1, 5, 0);
                in_unknown_scope(&operation(op_code, false, &data))
            };
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], flagless())];

            let kind = question_of(&lists).kind();
            let info = info_of(flagless(), KeywordInfoFilter::DATA_TYPE);

            assert!(
                matches!(&kind, Err(KeywordRefusal::NoNumericFlags { keyword, op: found, .. })
                    if keyword == KEYWORD && *found == op),
                "{op}: kind {kind:?}"
            );
            assert!(
                matches!(&info, Err(KeywordInfoRefusal::Question(
                    KeywordRefusal::NoNumericFlags { keyword, op: found, .. }
                )) if keyword == KEYWORD && *found == op),
                "{op}: info {info:?}"
            );
            assert!(
                info_of(flagless(), KeywordInfoFilter::DISPLAY_NAME).is_ok(),
                "{op}: its other items"
            );
        }
    }

    /// KEYWORDINFO's DATATYPE is the data type that kind gives, an undecoded ONE_OF's too.
    #[test]
    fn info_data_type_of_an_undecoded_one_of_is_that_of_its_flags() {
        let data = [question_header_with(1, PROMPT, 1, 5, 0), vec![0x02]].concat();
        let undecoded = in_unknown_scope(&operation(ONE_OF, false, &data));

        assert_eq!(
            info_of(undecoded, KeywordInfoFilter::DATA_TYPE),
            Ok(KeywordInfo {
                data_type: numeric_of(NumericWidth::Four),
                ..KeywordInfo::default()
            }),
            "a UINT32 ONE_OF without its range"
        );
    }
}
