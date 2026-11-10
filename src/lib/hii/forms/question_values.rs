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

//! The ONE_OF, NUMERIC and CHECKBOX questions that get reads and set writes, found by their
//! prompts, and the text that get shows for their values.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt;
use std::num::IntErrorKind;
use std::num::NonZeroU16;
use std::rc::Rc;
use std::str::FromStr;

use anyhow::Result;
use thiserror::Error;

use super::conditions::enclosing_form_set;
use super::conditions::option_state;
use super::conditions::retrieve_question_value;
use super::conditions::skips_scope;
use super::conditions::IncludedStates;
use super::conditions::QuestionValues;
use super::conditions::StateEvaluation;
use super::defaults::option_text;
use super::defaults::option_value;
use super::defaults::push_default;
use super::defaults::question_defaults;
use super::defaults::question_scope;
use super::find_corresponding_varstore;
use super::keywords::keyword_of;
use super::keywords::KeywordStatement;
use super::keywords::UEFI_CONFIG_LANG;
use super::numeric_format;
use super::storage::RetrievedValue;
use super::storage::ValueLocation;
use super::storage::ValueSource;
use super::storage::VariableStore;
use super::walk_scopes;
use super::AnswerOption;
use super::CheckBox;
use super::FormSetWalk;
use super::IFROperation;
use super::Numeric;
use super::NumericFormat;
use super::NumericRange;
use super::OneOf;
use super::ParsedOperation;
use super::Question;
use super::QuestionDescriptor;
use super::QuestionFlags;
use super::QuestionHeader;
use super::Range;
use super::RangeType;
use super::ValueEncoding;
use super::Walk;
use crate::hii::config_string;
use crate::hii::config_string::Namespace;
use crate::hii::package::Guid;
use crate::hii::strings::is_configuration_language;
use crate::hii::strings::ListTexts;

/// A question whose value get reads and set writes.
#[derive(Clone, Copy)]
pub(super) enum ValueQuestion<'a> {
    OneOf(&'a OneOf),
    Numeric(&'a Numeric),
    CheckBox(&'a CheckBox),
}

impl ValueQuestion<'_> {
    pub(super) fn header(self) -> QuestionHeader {
        match self {
            ValueQuestion::OneOf(question) => question.question_header(),
            ValueQuestion::Numeric(question) => question.question_header(),
            ValueQuestion::CheckBox(question) => question.question_header(),
        }
    }

    pub(super) fn location(self) -> ValueLocation {
        match self {
            ValueQuestion::OneOf(question) => question.location,
            ValueQuestion::Numeric(question) => question.location,
            ValueQuestion::CheckBox(question) => question.location,
        }
    }

    /// How the question was parsed to store its value.
    pub(super) fn encoding(self) -> ValueEncoding {
        match self {
            ValueQuestion::OneOf(question) => question.encoding,
            ValueQuestion::Numeric(question) => question.encoding,
            ValueQuestion::CheckBox(question) => question.encoding,
        }
    }
}

/// Returns `op` as a ONE_OF, NUMERIC or CHECKBOX.
pub(super) fn value_question(op: &IFROperation) -> Option<ValueQuestion<'_>> {
    match &op.parsed_data {
        ParsedOperation::OneOf(question) => Some(ValueQuestion::OneOf(question)),
        ParsedOperation::Numeric(question) => Some(ValueQuestion::Numeric(question)),
        ParsedOperation::CheckBox(question) => Some(ValueQuestion::CheckBox(question)),
        ParsedOperation::FormSet(_)
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
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Get(_)
        | ParsedOperation::Set(_)
        | ParsedOperation::FormMap(_)
        | ParsedOperation::Placeholder => None,
    }
}

/// A ONE_OF, NUMERIC or CHECKBOX whose prompt is one of the phrases of questions_named.
pub(super) struct NamedQuestion {
    pub(super) node: Rc<RefCell<IFROperation>>,
    /// Which question it is, and the languages whose text of its prompt is a phrase
    pub(super) prompt: PromptMatch,
}

/// Returns the ONE_OF, NUMERIC and CHECKBOX questions under `node`, in IFR order, whose prompt
/// in a language of `texts` of no configuration language is one of `phrases`, ignoring ASCII
/// case and surrounding whitespace, with those languages.
pub(super) fn questions_named<T>(
    node: &Rc<RefCell<IFROperation>>,
    texts: &ListTexts<'_>,
    phrases: &BTreeSet<T>,
) -> Vec<NamedQuestion>
where
    T: AsRef<str>,
{
    let mut found = Vec::new();
    visit_value_questions(node, |node, form_set, header| {
        let languages: Vec<String> = texts
            .matching(header.prompt_string_id)
            .filter(|(_, prompt)| {
                phrases
                    .iter()
                    .any(|phrase| phrase.as_ref().trim().eq_ignore_ascii_case(prompt.trim()))
            })
            .map(|(language, _)| language.to_string())
            .collect();
        if !languages.is_empty() {
            found.push(NamedQuestion {
                node: Rc::clone(node),
                prompt: PromptMatch {
                    question_id: header.question_id,
                    form_set,
                    languages,
                },
            });
        }
    });
    found
}

/// Calls `visit` with each ONE_OF, NUMERIC and CHECKBOX under `node`, in IFR order, the GUID of
/// its FormSet and its header.
fn visit_value_questions(
    node: &Rc<RefCell<IFROperation>>,
    mut visit: impl FnMut(&Rc<RefCell<IFROperation>>, Option<Guid>, QuestionHeader),
) {
    walk_scopes(std::slice::from_ref(node), None, |node, &form_set| {
        let op = node.borrow();
        if skips_scope(&op) {
            return Walk::Skip;
        }
        let form_set = match &op.parsed_data {
            ParsedOperation::FormSet(parsed) => Some(parsed.guid),
            _ => form_set,
        };
        // Only Numeric, OneOf and CheckBox are questions.
        if let Some(question) = value_question(&op) {
            visit(node, form_set, question.header());
        }
        Walk::Enter(form_set)
    });
}

/// What find_question selects questions by, in one FormSet.
pub(crate) enum QuestionMatch<'a, T> {
    /// The questions whose prompt is one of these phrases, as questions_named finds them
    Prompt(&'a BTreeSet<T>),
    /// The question of this address
    Address(&'a QuestionAddress),
    /// The questions of these statements of a keyword, those of the FormSet
    Keyword(&'a [KeywordStatement<'a>]),
}

/// Returns the ONE_OF, NUMERIC and CHECKBOX questions under `node`, in IFR order, that
/// `matching` selects, of texts `texts`.
pub(super) fn questions_matching<T>(
    node: &Rc<RefCell<IFROperation>>,
    texts: &ListTexts<'_>,
    matching: &QuestionMatch<'_, T>,
) -> Vec<Rc<RefCell<IFROperation>>>
where
    T: AsRef<str>,
{
    match *matching {
        QuestionMatch::Prompt(phrases) => questions_named(node, texts, phrases)
            .into_iter()
            .map(|named| named.node)
            .collect(),
        QuestionMatch::Address(address) => questions_addressed(node, address),
        QuestionMatch::Keyword(statements) => statements
            .iter()
            .filter(|statement| Rc::ptr_eq(statement.root(), node))
            .map(KeywordStatement::op)
            .filter(|op| value_question(&op.borrow()).is_some())
            .cloned()
            .collect(),
    }
}

/// Returns the ONE_OF, NUMERIC and CHECKBOX questions under `node`, in IFR order, of the address
/// `address`: two or more only where QuestionIds repeat in a FormSet.
pub(super) fn questions_addressed(
    node: &Rc<RefCell<IFROperation>>,
    address: &QuestionAddress,
) -> Vec<Rc<RefCell<IFROperation>>> {
    let mut found = Vec::new();
    visit_value_questions(node, |node, form_set, header| {
        if form_set == Some(address.form_set) && header.question_id == address.question_id.get() {
            found.push(Rc::clone(node));
        }
    });
    found
}

/// Where --keyword searches: the strings packages whose language starts with this NAMESPACE,
/// itself a configuration language (Language::is_configuration), as NamespaceId is "the platform
/// configuration language to search through" (UEFI 2.11 §35.3.3). It parses from such a
/// language only, so that a keyword never matches a prompt of a display language.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeywordNamespace(Namespace);

impl KeywordNamespace {
    pub(crate) fn namespace(&self) -> &Namespace {
        &self.0
    }
}

impl FromStr for KeywordNamespace {
    type Err = KeywordError;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let namespace =
            Namespace::try_from(text).map_err(|error| KeywordError::Syntax(error.to_string()))?;
        match is_configuration_language(text.as_bytes()) {
            true => Ok(Self(namespace)),
            false => Err(KeywordError::NotConfiguration(text.to_owned())),
        }
    }
}

impl fmt::Display for KeywordNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What --keyword selects by: a `<Keyword>`'s keyword of the UEFI Configuration Namespace
/// Registry, with any ':' and 1 to 4 digits of its instance (UEFI 2.11 §35.2.1.6).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeywordName(config_string::Keyword);

impl KeywordName {
    pub(crate) fn keyword(&self) -> &config_string::Keyword {
        &self.0
    }
}

impl FromStr for KeywordName {
    type Err = KeywordError;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        config_string::Keyword::try_from(text)
            .map(Self)
            .map_err(|error| KeywordError::Syntax(error.to_string()))
    }
}

impl fmt::Display for KeywordName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Why a text is no KeywordNamespace or KeywordName.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[non_exhaustive]
pub enum KeywordError {
    /// The text breaks the syntax of `<NameSpaceId>` or `<Keyword>`, as the error says
    #[error("{0}")]
    Syntax(String),
    #[error(
        "{0:?} is no configuration language: it does not start with \"x-\" (UEFI 2.11 §33.2.6.1)"
    )]
    NotConfiguration(String),
}

/// A question by its FormSet's GUID and its QuestionId (UEFI 2.11 §33.3.8.2.2), which
/// list-questions shows as form_set_guid and question_id; it parses from "GUID:ID", ID in
/// decimal or 0x hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuestionAddress {
    pub form_set: Guid,
    /// "The value of zero is reserved" (UEFI 2.11 §33.3.8.2.2)
    pub question_id: NonZeroU16,
}

impl FromStr for QuestionAddress {
    type Err = QuestionAddressError;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let (guid, id) = text
            .rsplit_once(':')
            .ok_or_else(|| QuestionAddressError::NoColon(text.to_owned()))?;
        let form_set = guid
            .parse()
            .map_err(|_| QuestionAddressError::Guid(guid.to_owned()))?;
        let (digits, radix) = match id.strip_prefix("0x").or_else(|| id.strip_prefix("0X")) {
            Some(hex) => (hex, 16),
            None => (id, 10),
        };
        // from_str_radix also takes a leading '+', which "decimal or 0x hex" does not have
        if !digits.starts_with(|digit: char| digit.is_digit(radix)) {
            return Err(QuestionAddressError::Id(id.to_owned()));
        }
        let number = u16::from_str_radix(digits, radix).map_err(|error| match error.kind() {
            IntErrorKind::PosOverflow => QuestionAddressError::Above16Bits(id.to_owned()),
            _ => QuestionAddressError::Id(id.to_owned()),
        })?;
        let question_id = NonZeroU16::new(number).ok_or(QuestionAddressError::Reserved)?;
        Ok(Self {
            form_set,
            question_id,
        })
    }
}

/// "GUID:ID", as from_str takes it, ID in decimal as list-questions shows it.
impl fmt::Display for QuestionAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.form_set, self.question_id)
    }
}

/// Why a text is no QuestionAddress.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[non_exhaustive]
pub enum QuestionAddressError {
    #[error("{0:?} is not GUID:ID: it has no ':'")]
    NoColon(String),
    #[error("{0:?} is not a GUID")]
    Guid(String),
    #[error("{0:?} is not a number in decimal or 0x hex")]
    Id(String),
    #[error("QuestionId 0 is reserved (UEFI 2.11 §33.3.8.2.2)")]
    Reserved,
    #[error("QuestionId {0} is above 0xFFFF")]
    Above16Bits(String),
}

/// The questions that get and set select, one in each FormSet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QuestionSelector {
    /// The questions whose prompt, in a language of no configuration language, is this text,
    /// ignoring ASCII case and surrounding whitespace, or one of its spellings
    Prompt(String),
    /// The question of this address, in every package list that holds its FormSet
    Address(QuestionAddress),
    /// The questions of the statements that the Keyword Handler takes for `keyword` in
    /// `namespace`, else in a language of the prefix "x-UEFI", in each package list
    /// (KeywordStatement::resolve_offline): the keyword strings (UEFI 2.11 §35.2.1.6) of KEYWORD
    /// `keyword`, any `:<DecCh>(1/4)` instance suffix included, whose NAMESPACE starts so
    Keyword {
        keyword: KeywordName,
        namespace: Option<KeywordNamespace>,
    },
}

impl QuestionSelector {
    /// What find_question selects by: by Prompt, any of `variations`, the spellings of its text;
    /// by Keyword, `statements`, its statements in the HiiDB.
    pub(crate) fn matching<'a, T>(
        &'a self,
        variations: &'a BTreeSet<T>,
        statements: &'a [KeywordStatement<'a>],
    ) -> QuestionMatch<'a, T> {
        match self {
            Self::Prompt(_) => QuestionMatch::Prompt(variations),
            Self::Address(address) => QuestionMatch::Address(address),
            Self::Keyword { .. } => QuestionMatch::Keyword(statements),
        }
    }
}

impl From<&str> for QuestionSelector {
    fn from(question: &str) -> Self {
        Self::Prompt(question.to_owned())
    }
}

impl From<String> for QuestionSelector {
    fn from(question: String) -> Self {
        Self::Prompt(question)
    }
}

impl From<&String> for QuestionSelector {
    fn from(question: &String) -> Self {
        Self::Prompt(question.clone())
    }
}

/// How errors name the questions: by the prompt's text, else by QuestionId or keyword.
impl fmt::Display for QuestionSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prompt(text) => f.write_str(text),
            Self::Address(address) => write!(
                f,
                "QuestionId {:#06X} of FormSet {}",
                address.question_id, address.form_set
            ),
            Self::Keyword {
                keyword,
                namespace: Some(namespace),
            } => write!(
                f,
                "keyword {keyword} of a namespace starting with {namespace}"
            ),
            Self::Keyword {
                keyword,
                namespace: None,
            } => write!(
                f,
                "keyword {keyword} of a namespace starting with {UEFI_CONFIG_LANG}"
            ),
        }
    }
}

/// A question that a QUESTION of get or set names, and the languages in which it is its prompt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct PromptMatch {
    pub question_id: u16,
    /// The GUID of the question's FormSet
    pub form_set: Option<Guid>,
    /// The languages, of no configuration language, whose text of the prompt is the QUESTION;
    /// for --keyword, the NAMESPACE of the keyword's strings package
    pub languages: Vec<String>,
}

impl PromptMatch {
    /// `matches` as SelectionError::Ambiguous names them.
    pub(super) fn list(matches: &[PromptMatch]) -> String {
        let listed: Vec<String> = matches.iter().map(|named| format!("of {named}")).collect();
        listed.join(" and ")
    }
}

impl fmt::Display for PromptMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QuestionId {:#06X}", self.question_id)?;
        if let Some(form_set) = &self.form_set {
            write!(f, " of FormSet {form_set}")?;
        }
        write!(f, " in {}", self.languages.join(", "))
    }
}

/// An option that a VALUE of set names, and the languages in which it is its text.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct OptionMatch {
    /// The option's text, as get shows it
    pub option: String,
    /// The languages, of no configuration language, whose text of the option is the VALUE
    pub languages: Vec<String>,
}

impl OptionMatch {
    /// `matches`, options of the question `question`, as SelectionError::AmbiguousOption names
    /// them.
    pub(super) fn list(question: &str, matches: &[OptionMatch]) -> String {
        let listed: Vec<String> = matches
            .iter()
            .enumerate()
            .map(|(index, named)| {
                let of_question = match index {
                    0 => format!(" of question {question:?}"),
                    _ => String::new(),
                };
                format!(
                    "of option {:?}{of_question} in {}",
                    named.option,
                    named.languages.join(", ")
                )
            })
            .collect();
        listed.join(" and ")
    }
}

/// Whether one language is in each of `language_sets`, comparing them as edk2-stable202608
/// HiiDatabaseDxe/String.c HiiCompareLanguage does: ignoring ASCII case.
pub(super) fn share_a_language(language_sets: &[&[String]]) -> bool {
    let Some((first, rest)) = language_sets.split_first() else {
        return true;
    };
    first.iter().any(|language| {
        rest.iter()
            .all(|set| set.iter().any(|other| other.eq_ignore_ascii_case(language)))
    })
}

/// What tells a question apart besides its prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct QuestionIdentity {
    /// The QuestionId of its question header (UEFI 2.11 §33.3.8.2.2)
    pub(crate) question_id: u16,
    /// The GUID of its FormSet
    pub(crate) form_set: Option<Guid>,
    /// Its prompt in each strings package of a configuration language, with that language, of
    /// those that a `<KeywordRequest>` can name (keyword_of)
    pub(crate) keywords: Vec<Keyword>,
}

/// A keyword string's NAMESPACE, the configuration language of a strings package, and KEYWORD,
/// a question's prompt in it (UEFI 2.11 §35.2.1.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Keyword {
    pub(crate) namespace: String,
    pub(crate) keyword: String,
}

impl QuestionIdentity {
    /// The identity of the question `op`, of header `header`, whose keywords `texts` hold.
    fn of(op: &IFROperation, header: &QuestionHeader, texts: &ListTexts<'_>) -> Self {
        Self {
            question_id: header.question_id,
            form_set: form_set_guid(op),
            keywords: texts
                .keywords(header.prompt_string_id)
                .filter_map(|(language, text)| keyword_of(language, text))
                .map(|(namespace, keyword)| Keyword {
                    namespace: namespace.to_string(),
                    keyword: keyword.to_string(),
                })
                .collect(),
        }
    }
}

/// The GUID of the FormSet that holds `op`.
pub(super) fn form_set_guid(op: &IFROperation) -> Option<Guid> {
    enclosing_form_set(op).and_then(|form_set| match &form_set.borrow().parsed_data {
        ParsedOperation::FormSet(parsed) => Some(parsed.guid),
        _ => None,
    })
}

/// Returns the QuestionDescriptor of `question`, whose op is `value_question`.
pub(super) fn describe_question(
    question: &Rc<RefCell<IFROperation>>,
    value_question: ValueQuestion<'_>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let header = value_question.header();
    let prompt = walk.texts.display(header.prompt_string_id);
    let flags = header.flags() | class_question_flags(&question.borrow());
    let varstore = find_corresponding_varstore(Rc::clone(question), header.var_store_id);
    match value_question {
        ValueQuestion::OneOf(parsed) => {
            handle_oneof(varstore, parsed, prompt, flags, question, walk)
        }
        ValueQuestion::Numeric(parsed) => {
            handle_numeric(varstore, parsed, prompt, flags, question, walk)
        }
        ValueQuestion::CheckBox(parsed) => {
            handle_checkbox(varstore, parsed, prompt, flags, question, walk)
        }
    }
}

/// Returns the question Flags that the class of the FormSet around `question` gives it.
fn class_question_flags(question: &IFROperation) -> QuestionFlags {
    enclosing_form_set(question).map_or(QuestionFlags::empty(), |form_set| {
        match &form_set.borrow().parsed_data {
            ParsedOperation::FormSet(parsed) => parsed.class_question_flags(),
            _ => QuestionFlags::empty(),
        }
    })
}

/// Returns `value`, a current value or IFR default of a CHECKBOX, as list-questions and get show
/// it: FALSE or TRUE (UEFI 2.10 §33.3.8.3.9) as 0 or 1, any nonzero value as 1, as
/// edk2-stable202608 ProcessOptions.c shows it on.
fn checkbox_text(value: u64) -> String {
    u8::from(value != 0).to_string()
}

/// Returns `value`, a current value or IFR default of a ONE_OF in `format`, as list-questions and
/// get show it: `option`, the text of the option that holds it, else its number.
fn one_of_text(value: u64, format: NumericFormat, option: Option<&str>) -> String {
    match option {
        Some(text) => text.to_string(),
        None => format!("{} (no matching option)", format.decode(value)),
    }
}

pub(super) fn handle_checkbox(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &CheckBox,
    question: &str,
    flags: QuestionFlags,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let mut answer = String::new();
    let source = match retrieve_question_value(node, &varstore, &mut walk.inputs) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            None
        }
        Ok(retrieved) => {
            answer.push_str(&checkbox_text(retrieved.value));
            Some(retrieved.source)
        }
    };
    let stores = walk.default_stores.of(current_node, &mut walk.inputs);
    let defaults = question_defaults(
        current_node,
        stores,
        walk.texts,
        &mut walk.inputs,
        |v, _| Ok(checkbox_text(v)),
    );
    if source.is_none() {
        push_default(&mut answer, &defaults, stores);
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: walk
            .texts
            .display(parsed.question_header().help_string_id)
            .to_string(),
        possible_options: Vec::new(),
        varstore,
        location: parsed.location,
        max_value: RangeType::NumSize8(1),
        numeric_range: None,
        opcode: current_node.op_code,
        flags,
        defaults,
        identity: QuestionIdentity::of(current_node, &parsed.question_header(), walk.texts),
        value_state: StateEvaluation::selectable(),
        value_source: source.unwrap_or(ValueSource::Current),
        node: Rc::clone(node),
    };
    res
}

pub(super) fn handle_oneof(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &OneOf,
    question: &str,
    flags: QuestionFlags,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let mut answer = String::new();
    // None, with the reason in `answer`, when the current value cannot be read: any u64,
    // all ones too, can be stored.
    let chosen_value = match retrieve_question_value(node, &varstore, &mut walk.inputs) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            None
        }
        Ok(stored) => Some(stored),
    };

    let stores = walk.default_stores.of(current_node, &mut walk.inputs);
    let format = numeric_format(parsed.location, parsed.flags, &parsed.data);
    let defaults = question_defaults(
        current_node,
        stores,
        walk.texts,
        &mut walk.inputs,
        |v, inputs| {
            let format = format.clone()?;
            option_text(current_node, format.cut(v), walk.texts, inputs)
                .map(|option| one_of_text(v, format, option.as_deref()))
        },
    );
    if chosen_value.is_none() {
        push_default(&mut answer, &defaults, stores);
    }

    let mut possible_options = Vec::new();
    // Some of OneOf's children are OneOfOptions

    for op in question_scope(current_node) {
        let op = op.borrow();
        if let ParsedOperation::OneOfOption(o) = &op.parsed_data {
            let taken = walk.inputs.reader.snapshot_values_taken();
            let raw_value = option_value(current_node, &op, o, &mut walk.inputs);
            possible_options.push(AnswerOption {
                raw_value,
                source: ValueSource::since(taken, walk.inputs.reader),
                value: walk.texts.display(o.option_string_id).to_string(),
                texts: walk
                    .texts
                    .matching(o.option_string_id)
                    .map(|(language, text)| (language.clone(), text.to_string()))
                    .collect(),
                state: option_state(&op, &mut walk.inputs),
            });
        }
    }
    let option = chosen_value
        .and_then(|chosen| shown_option(&possible_options, chosen.value, None))
        .and_then(|index| possible_options.get(index));
    if let Some(RetrievedValue {
        location, value, ..
    }) = chosen_value
    {
        let format = NumericFormat::from_location(location, parsed.flags, &parsed.data);
        answer.push_str(&one_of_text(
            value,
            format,
            option.map(|opt| opt.value.trim()),
        ));
    }
    let value_state = option.map_or_else(StateEvaluation::selectable, |opt| opt.state.clone());
    let value_source = chosen_value.map_or(ValueSource::Current, |chosen| {
        chosen
            .source
            .or(shown_option_source(&possible_options, chosen.value))
    });

    let res = QuestionDescriptor {
        question: question.trim().to_string(),
        value: answer,
        help: walk
            .texts
            .display(parsed.question_header().help_string_id)
            .to_string(),
        possible_options,
        varstore,
        location: parsed.location,
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        numeric_range: None,
        opcode: current_node.op_code,
        flags,
        defaults,
        identity: QuestionIdentity::of(current_node, &parsed.question_header(), walk.texts),
        value_state,
        value_source,
        node: Rc::clone(node),
    };
    res
}

/// The index of the option of `options` that shows for the stored `value`, with the option at
/// `also_matching`, if any, matching too: the first match that may be shown, as
/// edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption finds it, else the first, which a
/// SUPPRESS_IF hides.
fn shown_option(
    options: &[AnswerOption],
    value: u64,
    also_matching: Option<usize>,
) -> Option<usize> {
    let matching: Vec<(usize, &AnswerOption)> = options
        .iter()
        .enumerate()
        .filter(|&(index, option)| option.as_u64() == Some(value) || also_matching == Some(index))
        .collect();
    matching
        .iter()
        .find(|(_, option)| option.state.may_be_allowed(IncludedStates::empty()))
        .or(matching.first())
        .map(|&(index, _)| index)
}

/// Snapshot if values that options of `options` took from the snapshot decide which one shows
/// for the stored `value`: the one shown took its value from there, or one that did would show
/// if it matched.
fn shown_option_source(options: &[AnswerOption], value: u64) -> ValueSource {
    let shown = shown_option(options, value, None);
    let decided = options.iter().enumerate().any(|(index, option)| {
        matches!(option.source, ValueSource::Snapshot)
            && (shown == Some(index) || shown_option(options, value, Some(index)) != shown)
    });
    match decided {
        true => ValueSource::Snapshot,
        false => ValueSource::Current,
    }
}

pub(super) fn handle_numeric(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &Numeric,
    question: &str,
    flags: QuestionFlags,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let mut answer = String::new();

    let source = match retrieve_question_value(node, &varstore, &mut walk.inputs) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            None
        }
        Ok(retrieved) => {
            let format =
                NumericFormat::from_location(retrieved.location, parsed.flags, &parsed.data);
            answer.push_str(&format.decode(retrieved.value).to_string());
            Some(retrieved.source)
        }
    };
    let stores = walk.default_stores.of(current_node, &mut walk.inputs);
    let defaults = question_defaults(
        current_node,
        stores,
        walk.texts,
        &mut walk.inputs,
        |v, _| {
            Ok(numeric_format(parsed.location, parsed.flags, &parsed.data)?
                .decode(v)
                .to_string())
        },
    );
    if source.is_none() {
        push_default(&mut answer, &defaults, stores);
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: walk
            .texts
            .display(parsed.question_header().help_string_id)
            .to_string(),
        possible_options: Vec::new(),
        varstore,
        location: parsed.location,
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        // set refuses bit fields, whose Flags from_ifr would misread
        numeric_range: match parsed.location {
            ValueLocation::Bytes { .. } => Some(NumericRange::from_ifr(&parsed.data, parsed.flags)),
            ValueLocation::Bits { .. } => None,
        },
        opcode: current_node.op_code,
        flags,
        defaults,
        identity: QuestionIdentity::of(current_node, &parsed.question_header(), walk.texts),
        value_state: StateEvaluation::selectable(),
        value_source: source.unwrap_or(ValueSource::Current),
        node: Rc::clone(node),
    };
    res
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod question_value_tests {
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;

    use binrw::io::Cursor;

    use super::super::conditions::ExpressionInputs;
    use super::super::default_value_parser;
    use super::super::display_answer;
    use super::super::ifr_fixtures::*;
    use super::super::DefaultId;
    use super::super::IfrDefaultValue;
    use super::super::Range16;
    use super::super::Range32;
    use super::super::Range64;
    use super::super::Range8;
    use super::*;

    /// EDKII_IFR_DISPLAY_UINT_DEC_BIT
    const UINT_DEC: u8 = 0x40;

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

    /// An EFI_IFR_ONE_OF_OPTION (UEFI 2.11 §33.3.8.3.51) of Type EFI_IFR_TYPE_OTHER takes the
    /// value of its nested EFI_IFR_VALUE in the width of its ONE_OF: get answers it for that
    /// value, and its DEFAULT flag gives that default. One whose VALUE does not fit that width,
    /// is not known or is missing lists with why and matches no value. The VALUE is the
    /// option's, not one that gives the ONE_OF its value.
    #[test]
    fn one_of_option_of_type_other_takes_the_value_of_its_value_op() {
        let (data, _) = uint8_one_of(0);
        let children = [
            one_of_option(5, 0x00, &[0]),
            other_option(6, 0x10, &[uint8(1)]),
            other_option(7, 0x00, &[ifr_ones()]),
            other_option(3, 0x00, &[uint8(1), uint8(2)]),
            other_option(PADDED_ENABLED, 0x00, &[]),
        ];
        let cases = [
            ("stored 1", var_store_of(&[1]), "Enabled"),
            ("stored 0", var_store_of(&[0]), "Disabled"),
            (
                "stored 0xFF, all ones cut to the ONE_OF",
                var_store_of(&[0xFF]),
                "-1 (no matching option)",
            ),
            (
                "no VarStore",
                unavailable(),
                "<ValueUnavailable: no VarStore 1> <IFR default: Enabled>",
            ),
        ];
        for (name, var_store, want) in cases {
            assert_eq!(one_of_value(&data, &children, var_store), want, "{name}");
        }

        let (_root, node) = parse_question(&[], ONE_OF, &data, &children);
        let question = question_descriptor(&node, var_store_of(&[1]));
        assert_eq!(
            question.listed_options(IncludedStates::empty()),
            [
                "Disabled",
                "Enabled",
                "AllOnes <ValueUnavailable: its EFI_IFR_VALUE gives 0xffffffffffffffff, which \
                 does not fit in the 8 bits of the ONE_OF>",
                "Prompt <ValueUnavailable: its EFI_IFR_VALUE expression not evaluated: malformed \
                 expression: 2 values left>",
                "Enabled  <ValueUnavailable: EFI_IFR_TYPE_OTHER without a nested EFI_IFR_VALUE>",
            ],
            "listed options"
        );
    }

    /// An EFI_IFR_TYPE_OTHER option of an EDKII bit varstore ONE_OF takes the value of its
    /// EFI_IFR_VALUE within the width of the field: one that does not fit lists with why and
    /// matches no value.
    #[test]
    fn bit_field_option_of_type_other_fits_in_the_field() {
        let data = uint32_range_question(4, UINT_DEC | 2);
        let children = [
            other_option(6, 0x00, &[uint8(3)]),
            other_option(7, 0x00, &[uint8(4)]),
        ];
        let (_root, node) = parse_question_in_guid(BIT_VARSTORE_GUID, ONE_OF, &data, &children);

        let question = question_descriptor(&node, var_store_of(&[0x30]));

        assert_eq!(question.value, "Enabled", "bits 4 and 5 hold 3");
        assert_eq!(
            question.listed_options(IncludedStates::empty()),
            [
                "Enabled",
                "AllOnes <ValueUnavailable: its EFI_IFR_VALUE gives 0x4, which does not fit in \
                 the 2 bits of the ONE_OF>",
            ],
            "listed options"
        );
    }

    /// The text of a default skips an EFI_IFR_TYPE_OTHER option whose value is not known: it
    /// names the first option of that value that follows.
    #[test]
    fn default_text_skips_an_option_of_type_other_without_a_value() {
        let children = [other_option(3, 0x00, &[]), flagged_option(6, 0x10, 1)];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "OTHER option without a VALUE, then DEFAULT-flagged option 1"
        );
    }

    /// The DEFAULT flag of an EFI_IFR_TYPE_OTHER option whose value is not known gives a default
    /// listed with why, never a value.
    #[test]
    fn default_of_an_option_of_type_other_that_does_not_fit_tells_why() {
        let children = [
            one_of_option(5, 0x00, &[0]),
            other_option(7, 0x10, &[ifr_ones()]),
        ];
        let (_root, node) = parse_question(&[], ONE_OF, &one_of_data(), &children);

        let question = question_descriptor(&node, unavailable());

        let reason = "EFI_IFR_ONE_OF_OPTION value not known: its EFI_IFR_VALUE gives \
                      0xffffffffffffffff, which does not fit in the 8 bits of the ONE_OF";
        let defaults: Vec<(DefaultId, String)> = question
            .defaults
            .iter()
            .map(|default| (default.default_id, default.value.to_string()))
            .collect();
        assert_eq!(
            defaults,
            [(DefaultId(0x0000), format!("unknown ({reason})"))],
            "defaults"
        );
        assert_eq!(
            question.value,
            format!("{UNAVAILABLE} <IFR default: unknown ({reason})>"),
            "answer"
        );
    }

    /// set writes an EFI_IFR_TYPE_OTHER option's value in the width of its ONE_OF, all 64 bits of
    /// a UINT64 one too, and refuses one whose value is not known with why; the option's
    /// EFI_IFR_VALUE does not make the ONE_OF read-only.
    #[test]
    fn set_writes_an_option_of_type_other_in_the_width_of_its_one_of() {
        let data = [
            &question_header(0)[..],
            &[0x01],                 // Flags: UINT16
            &0u16.to_le_bytes(),     // MinValue
            &u16::MAX.to_le_bytes(), // MaxValue
            &1u16.to_le_bytes(),     // Step
        ]
        .concat();
        let children = [
            other_option(6, 0x00, &[uint8(0x34)]),
            other_option(7, 0x00, &[ifr_ones()]),
        ];
        let (_root, node) = parse_question(&[], ONE_OF, &data, &children);
        let variables = MemoryVariables::default();
        let question = question_descriptor(
            &node,
            writable_var_store("VarStore", &[0xAA, 0xBB], &variables),
        );
        let [enabled, all_ones] = question.possible_options.as_slice() else {
            panic!("options: {:?}", question.possible_options);
        };

        assert_eq!(
            change_option(&question, enabled, &variables).map_err(|error| error.to_string()),
            Ok(()),
            "Enabled"
        );
        assert_eq!(
            change_option(&question, all_ones, &variables).map_err(|error| error.to_string()),
            Err(
                "cannot set question \"\" to option \"AllOnes\": its EFI_IFR_VALUE gives \
                 0xffffffffffffffff, which does not fit in the 16 bits of the ONE_OF"
                    .to_string()
            ),
            "AllOnes"
        );
        assert_eq!(
            variables.writes_to(&variable_key("VarStore")),
            [(0, vec![0x34, 0x00])],
            "writes"
        );

        let data = [
            &question_header(0)[..],
            &[0x03],                 // Flags: UINT64
            &0u64.to_le_bytes(),     // MinValue
            &u64::MAX.to_le_bytes(), // MaxValue
            &1u64.to_le_bytes(),     // Step
        ]
        .concat();
        let (_root, node) =
            parse_question(&[], ONE_OF, &data, &[other_option(7, 0x00, &[ifr_ones()])]);
        assert_eq!(
            question_descriptor(&node, var_store_of(&[0xFF; 8])).value,
            "AllOnes",
            "UINT64 storing all ones"
        );
        let variables = MemoryVariables::default();
        let question =
            question_descriptor(&node, writable_var_store("VarStore", &[0; 8], &variables));
        let [all_ones] = question.possible_options.as_slice() else {
            panic!("UINT64 options: {:?}", question.possible_options);
        };
        assert_eq!(
            change_option(&question, all_ones, &variables).map_err(|error| error.to_string()),
            Ok(()),
            "UINT64 AllOnes"
        );
        assert_eq!(
            variables.writes_to(&variable_key("VarStore")),
            [(0, vec![0xFF; 8])],
            "UINT64 writes"
        );
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
                vec![
                    one_of_option(5, 0x06, &[0; 4]),
                    one_of_option(6, 0x00, &[0]),
                ],
                var_store_of(&[0]),
                "Enabled",
            ),
            (
                "DATE option without a current value",
                vec![one_of_option(5, 0x06, &[0; 4])],
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

    /// A CHECKBOX value shows as its IFR default does: a nonzero byte as 1, as
    /// edk2-stable202608 ProcessOptions.c shows it on.
    #[test]
    fn checkbox_shows_a_nonzero_byte_as_1() {
        for (byte, want) in [(0x00, "0"), (0x01, "1"), (0x02, "1"), (0xFF, "1")] {
            assert_eq!(
                answer(
                    &[],
                    CHECKBOX,
                    &checkbox(0, 0x00),
                    &[],
                    var_store_of(&[byte])
                ),
                want,
                "CHECKBOX byte {byte:#04x}"
            );
        }
    }

    /// A ONE_OF value shows as its IFR default does: a value that no option holds as its
    /// number, signed as the Flags say, and a value whose option has empty text as that text.
    #[test]
    fn one_of_value_shows_as_its_default_does() {
        // Flags: UINT8 INT_DEC; MinValue, MaxValue, Step
        let data = [&question_header(0)[..], &[0x00, 0x00, 0xFF, 0x01]].concat();
        let cases = [
            (
                "no matching option",
                one_of_option(5, 0x00, &[0]),
                "-1 (no matching option)",
            ),
            // string 9 is not in strings()
            ("option without text", one_of_option(9, 0x00, &[0xFF]), ""),
        ];
        for (name, option, want) in cases {
            let children = [option, ifr_default(0x0000, 0xFF)];
            assert_eq!(
                answer(&[], ONE_OF, &data, &children, var_store_of(&[0xFF])),
                want,
                "{name}: current value"
            );
            assert_eq!(
                answer(&[], ONE_OF, &data, &children, unavailable()),
                format!("{UNAVAILABLE} <IFR default: {want}>"),
                "{name}: default"
            );
        }

        // the current value of a bit field is signed by its StorageWidth, its default as UINT32
        let data = uint32_range_question(0, 0x08); // 8-bit INT_DEC
        let children = [
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            uint32_default(0x0000, 0xFF),
        ];
        for (name, var_store, want) in [
            (
                "current value",
                var_store_of(&[0xFF]),
                "-1 (no matching option)".to_string(),
            ),
            (
                "default",
                unavailable(),
                format!("{UNAVAILABLE} <IFR default: 255 (no matching option)>"),
            ),
        ] {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, ONE_OF, &data, &children, var_store),
                want,
                "8-bit field: {name}"
            );
        }
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

    /// show-ifr shows the value in the bits of an EDKII bit varstore field.
    #[test]
    fn show_ifr_answer_of_bit_field_is_its_value() {
        for (guid, want) in [(BIT_VARSTORE_GUID, "1"), (OTHER_GUID, "2")] {
            let (_root, node) = parse_question_in_guid(guid, CHECKBOX, &checkbox(3, 0x00), &[]);

            // bit 3, and byte 3
            let VarStoreFixture { store, efivars } = var_store_of(&[0xF8, 0x00, 0x00, 0x02]);

            let got = display_answer(
                &node,
                &store,
                &mut ExpressionInputs {
                    reader: &mut efivars.reader(),
                    values: &MapValues(BTreeMap::new()),
                },
            );

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

    /// A readable EDKII bit varstore field shows the value in its bits, without its default.
    #[test]
    fn readable_bit_field_question_shows_its_value() {
        // bits 4 to 15: 0xC8D; bits 4 and 5: 1
        let store = || var_store_of(&[0xD0, 0xC8, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let one_of_children = || {
            vec![
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                one_of_option(6, 0x02, &1u32.to_le_bytes()),
                uint32_default(0x0000, 0),
            ]
        };
        let cases = [
            (
                "12-bit UINT_DEC NUMERIC",
                NUMERIC,
                uint32_range_question(4, 0x4C),
                vec![uint32_default(0x0000, 200)],
                "3213",
            ),
            ("CHECKBOX", CHECKBOX, checkbox(4, 0x01), vec![], "1"),
            (
                "2-bit UINT_DEC ONE_OF",
                ONE_OF,
                uint32_range_question(4, 0x42),
                one_of_children(),
                "Enabled",
            ),
        ];
        for (name, op_code, data, children, want) in cases {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children, store()),
                want,
                "{name}"
            );
        }
    }

    /// A bit-field ONE_OF default is cut to the width in its Flags before it is matched to an
    /// option.
    #[test]
    fn bit_field_one_of_default_is_cut_to_its_width() {
        let children = [
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            one_of_option(6, 0x02, &1u32.to_le_bytes()),
            uint32_default(0x0000, 0b101),
        ];
        assert_eq!(
            answer_in_guid(
                BIT_VARSTORE_GUID,
                ONE_OF,
                &uint32_range_question(4, UINT_DEC | 2),
                &children,
                unavailable()
            ),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "default 0b101 of a 2-bit ONE_OF"
        );
    }

    /// A bit field's value is its width in bits from its bit VarOffset, as edk2-stable202608
    /// Setup.c GetBitsQuestionValue reads it, whatever the other bits of its bytes hold; a
    /// field over the 4 bytes that GetBitsQuestionValue copies into a UINT32 has none.
    #[test]
    fn bit_field_values_are_read_from_their_bits() {
        let payload = [0x6C, 0xBB, 0x15, 0xAF, 0xD7, 0x86];
        // at bits 8, 9 and 15, from Python's int.from_bytes(payload, "little")
        let cases = [
            (1, ["1", "1", "1"]),
            (3, ["3", "5", "3"]),
            (4, ["11", "13", "11"]),
            (12, ["1467", "2781", "3627"]),
            (17, ["71099", "101085", "89643"]),
            (18, ["202171", "232157", "220715"]),
            (19, ["464315", "494301", "482859"]),
            (
                32,
                [
                    "3618575803",
                    "<ValueUnavailable: EDKII bit field of width 32 at bit 9 spans more than 4 \
                     bytes>",
                    "<ValueUnavailable: EDKII bit field of width 32 at bit 15 spans more than 4 \
                     bytes>",
                ],
            ),
        ];
        for (width, wants) in cases {
            for (offset, want) in [8, 9, 15].into_iter().zip(wants) {
                let data = uint32_range_question(offset, UINT_DEC | width);
                assert_eq!(
                    answer_in_guid(
                        BIT_VARSTORE_GUID,
                        NUMERIC,
                        &data,
                        &[],
                        var_store_of(&payload)
                    ),
                    want,
                    "width {width} at bit {offset}"
                );
            }
        }
    }

    /// An INT_DEC bit field is signed from the type that edk2-stable202608 IfrParse.c gives
    /// it by its StorageWidth, as ProcessOptions.c shows it; its UINT32 IFR default is not.
    #[test]
    fn int_dec_bit_field_is_signed_by_its_storage_width() {
        let cases = [
            ("8-bit at bit 0, in UINT8", 0, 8, vec![0xFF], "-1"),
            ("8-bit at bit 4, in UINT16", 4, 8, vec![0xF0, 0x0F], "255"),
            ("16-bit at bit 0, in UINT16", 0, 16, vec![0xFF, 0xFF], "-1"),
            ("4-bit at bit 0, in UINT8", 0, 4, vec![0x0F], "15"),
            (
                "24-bit at bit 0, in UINT32",
                0,
                24,
                vec![0xFF; 3],
                "16777215",
            ),
            ("32-bit at bit 0, in UINT32", 0, 32, vec![0xFF; 4], "-1"),
        ];
        let default = [uint32_default(0x0000, 0xFF)];
        for (name, offset, width, payload, want) in cases {
            // Flags: EDKII_IFR_DISPLAY_INT_DEC_BIT
            let data = uint32_range_question(offset, width);
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    NUMERIC,
                    &data,
                    &default,
                    var_store_of(&payload)
                ),
                want,
                "{name}"
            );
        }
        assert_eq!(
            answer_in_guid(
                BIT_VARSTORE_GUID,
                NUMERIC,
                &uint32_range_question(0, 8),
                &default,
                unavailable()
            ),
            format!("{UNAVAILABLE} <IFR default: 255>"),
            "8-bit default"
        );
    }

    /// A bit field of width 0 or over 32, which edk2 VfrCompile does not emit, has neither a
    /// value nor a default, and gives its width as the reason before any store error.
    #[test]
    fn bit_field_width_outside_1_to_32_has_no_value() {
        for (width, flags) in [(0, UINT_DEC), (33, UINT_DEC | 33)] {
            let reason = format!("EDKII bit-field width {width}, not 1 to 32");
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    NUMERIC,
                    &uint32_range_question(0, flags),
                    &[],
                    var_store_of(&[0xFF; 8])
                ),
                format!("<ValueUnavailable: {reason}>"),
                "width {width}"
            );
            assert_eq!(
                numeric_in_guid_answer(BIT_VARSTORE_GUID, flags, 1),
                format!("<ValueUnavailable: {reason}> <IFR default: unknown ({reason})>"),
                "width {width} without a store"
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
                format!("<ValueUnavailable: {reason}> <IFR default: unknown ({reason})>"),
            ),
            (
                "non-constant DEFAULT_2",
                ifr_default_2(0x0000, eq_id_val()),
                format!(
                    "<ValueUnavailable: {reason}> <IFR default: unknown (EFI_IFR_VALUE \
                     expression not evaluated: EFI_IFR_EQ_ID_VAL of question 0x0001: \
                     <ValueUnavailable: {reason}>)>"
                ),
            ),
        ];
        for (name, default, want) in cases {
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    ONE_OF,
                    &uint32_range_question(0, UINT_DEC | 33),
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

#[cfg(test)]
mod question_address_tests {
    use super::*;
    use crate::hii::config_string::ConfigStringError;

    const FORM_SET: &str = "8C78A505-BAA0-4C4A-869F-000000000800";

    /// GUID:ID takes ID in decimal or 0x hex, from 1 to 0xFFFF, digits only, and names what it
    /// refuses.
    #[test]
    fn question_address_takes_an_id_from_1_to_0xffff() {
        let id = |id: &str| format!("{FORM_SET}:{id}");
        for (text, want) in [
            (id("0x8001"), Ok(id("32769"))),
            (id("0X8001"), Ok(id("32769"))),
            (id("32769"), Ok(id("32769"))),
            (id("1"), Ok(id("1"))),
            (id("0xFFFF"), Ok(id("65535"))),
            (id("65535"), Ok(id("65535"))),
            (id("0"), Err(QuestionAddressError::Reserved)),
            (id("0x0"), Err(QuestionAddressError::Reserved)),
            (
                id("0x10000"),
                Err(QuestionAddressError::Above16Bits("0x10000".to_owned())),
            ),
            (
                id("65536"),
                Err(QuestionAddressError::Above16Bits("65536".to_owned())),
            ),
            (id("-1"), Err(QuestionAddressError::Id("-1".to_owned()))),
            (id("0x"), Err(QuestionAddressError::Id("0x".to_owned()))),
            (id("1h"), Err(QuestionAddressError::Id("1h".to_owned()))),
            (id("+1"), Err(QuestionAddressError::Id("+1".to_owned()))),
            (id("0x+1"), Err(QuestionAddressError::Id("0x+1".to_owned()))),
            (id(""), Err(QuestionAddressError::Id(String::new()))),
            (
                FORM_SET.to_owned(),
                Err(QuestionAddressError::NoColon(FORM_SET.to_owned())),
            ),
            (
                "8C78A505:1".to_owned(),
                Err(QuestionAddressError::Guid("8C78A505".to_owned())),
            ),
        ] {
            assert_eq!(
                text.parse::<QuestionAddress>()
                    .map(|address| address.to_string()),
                want,
                "{text}"
            );
        }
    }

    /// Errors name a question that get or set selects by its prompt, by its QuestionId in hex
    /// and its FormSet's GUID, or by its keyword and namespace.
    #[test]
    fn question_selector_names_what_it_selects_by() {
        let address = format!("{FORM_SET}:1").parse().expect("parse the address");
        for (selector, want) in [
            (QuestionSelector::from("Boot Mode"), "Boot Mode".to_owned()),
            (
                QuestionSelector::Address(address),
                format!("QuestionId 0x0001 of FormSet {FORM_SET}"),
            ),
            (
                QuestionSelector::Keyword {
                    keyword: "Keyword:5".parse().expect("parse the keyword"),
                    namespace: None,
                },
                "keyword Keyword:5 of a namespace starting with x-UEFI".to_owned(),
            ),
            (
                QuestionSelector::Keyword {
                    keyword: "Keyword:5".parse().expect("parse the keyword"),
                    namespace: Some("x-i-UEFI".parse().expect("parse the namespace")),
                },
                "keyword Keyword:5 of a namespace starting with x-i-UEFI".to_owned(),
            ),
        ] {
            assert_eq!(selector.to_string(), want, "{selector:?}");
        }
    }

    /// A keyword's namespace parses from a NAMESPACE that is a configuration language only, its
    /// "x-" in either case, so that no keyword selects by a prompt of a display language.
    #[test]
    fn keyword_namespace_is_a_configuration_language() {
        let syntax = |text: &str| {
            KeywordError::Syntax(ConfigStringError::InvalidNamespace(text.to_owned()).to_string())
        };
        for (text, want) in [
            ("x-UEFI", Ok(())),
            ("x-UEFI-ns", Ok(())),
            ("x-i-UEFI", Ok(())),
            ("X-UEFI-ns", Ok(())),
            ("", Err(syntax(""))),
            ("x-UEFI=ns", Err(syntax("x-UEFI=ns"))),
            ("x-UEFI ns", Err(syntax("x-UEFI ns"))),
            ("en", Err(KeywordError::NotConfiguration("en".to_owned()))),
            (
                "en-US",
                Err(KeywordError::NotConfiguration("en-US".to_owned())),
            ),
            ("x", Err(KeywordError::NotConfiguration("x".to_owned()))),
        ] {
            assert_eq!(
                text.parse::<KeywordNamespace>()
                    .map(|namespace| namespace.to_string()),
                want.map(|()| text.to_owned()),
                "{text:?}"
            );
        }
    }

    /// --keyword parses as a <Keyword>: text without '&', '=' or control characters, any ':'
    /// followed by 1 to 4 digits only.
    #[test]
    fn keyword_name_is_a_keyword() {
        let syntax = |text: &str| {
            KeywordError::Syntax(ConfigStringError::InvalidKeyword(text.to_owned()).to_string())
        };
        for (text, want) in [
            ("BIOSVendor", Ok(())),
            ("ChipsetSATAPortEnable:5", Ok(())),
            ("Keyword:1234", Ok(())),
            ("", Err(syntax(""))),
            ("Key&word", Err(syntax("Key&word"))),
            ("Key=word", Err(syntax("Key=word"))),
            ("Keyword:12345", Err(syntax("Keyword:12345"))),
            ("Keyword:five", Err(syntax("Keyword:five"))),
        ] {
            assert_eq!(
                text.parse::<KeywordName>()
                    .map(|keyword| keyword.to_string()),
                want.map(|()| text.to_owned()),
                "{text:?}"
            );
        }
    }

    /// The library's get and set take a prompt as a &str, a String and a &String.
    #[test]
    fn question_selector_converts_from_each_string_type() {
        let text = String::from("Boot Mode");
        let want = QuestionSelector::Prompt(text.clone());
        let selectors: [QuestionSelector; 3] =
            [text.as_str().into(), (&text).into(), text.clone().into()];
        assert_eq!(selectors, [want.clone(), want.clone(), want], "prompts");
    }
}
