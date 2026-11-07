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
use std::ops::Range;
use std::rc::Rc;

use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use log::debug;
use thiserror::Error;

use super::choice_for_set;
use super::conditions::is_question;
use super::conditions::question_expression;
use super::conditions::question_state;
use super::conditions::question_value_expression;
use super::conditions::select;
use super::conditions::QuestionExpression;
use super::conditions::VarStoreValues;
use super::declared_var_store;
use super::defaults::is_statement;
use super::find_corresponding_varstore;
use super::question_values::describe_question;
use super::question_values::value_question;
use super::question_values::ValueQuestion;
use super::refers_to_bit_field;
use super::set::own_write;
use super::set::ChangeValueError;
use super::set::NewValue;
use super::walk_scopes;
use super::AnswerOption;
use super::Choice;
use super::DeclaredStore;
use super::FormSetWalk;
use super::IFROpCode;
use super::IFROperation;
use super::IncludedStates;
use super::QuestionDescriptor;
use super::QuestionFlags;
use super::QuestionHeader;
use super::SelectionError;
use super::ShortVarStoreEfi;
use super::Walk;
use super::EFI_IFR_TYPE_NUM_SIZE_16;
use super::EFI_IFR_TYPE_NUM_SIZE_32;
use super::EFI_IFR_TYPE_NUM_SIZE_64;
use super::EFI_IFR_TYPE_NUM_SIZE_8;
use crate::exports::SetOptions;
use crate::hii::config_string::Keyword;
use crate::hii::config_string::KeywordPath;
use crate::hii::config_string::KeywordResp;
use crate::hii::config_string::Namespace;
use crate::hii::config_string::Usage;
use crate::hii::package::ParsedPackageList;
use crate::hii::strings::Language;
use crate::hii::strings::ListTexts;
use crate::hii::variables::is_volatile;
use crate::hii::variables::DataPatch;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VolatileWrites;
use crate::parse_error::ReadParsed;

/// The language prefix that GetStringIdFromRecord searches without a NameSpaceId: edk2's
/// UEFI_CONFIG_LANG (ConfigKeywordHandler.c:1383), where UEFI 2.11 §35.3.3 says "x-UEFI-".
const UEFI_CONFIG_LANG: &str = "x-UEFI";

/// The states that keyword set may include: not READ_ONLY, as EfiConfigKeywordHandlerSetData
/// refuses every EFI_IFR_FLAG_READ_ONLY question (ConfigKeywordHandler.c:3033-3047).
const KEYWORD_SET_LIFTABLE: IncludedStates =
    IncludedStates::all().difference(IncludedStates::READ_ONLY);

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
    #[error("keyword {keyword}: it prompts an {op}, which has no question header")]
    NotQuestion { keyword: String, op: &'static str },
    #[error("keyword {keyword}: its {op} has no question header: {reason}")]
    NoHeader {
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
    #[error("keyword {keyword}: uefisettings does not yet check values of {op}")]
    Unchecked { keyword: String, op: &'static str },
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
    #[error("spans bytes that hold a password, which uefisettings neither reads nor writes")]
    PasswordBytes,
    #[error("has VarStoreId {0}, which another FormSet of its package list declares for {1}")]
    RedeclaredVarStore(u16, String),
}

/// Why a VALUE is not one that set would write to a question.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueRefusal {
    #[error("is not as wide as")]
    Width,
    #[error("is no option of")]
    NoOption,
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

/// The statement that a keyword prompts in its package list.
pub(crate) struct KeywordQuestion<'a> {
    keyword: Keyword,
    /// The language of the strings package that holds the keyword
    namespace: Namespace,
    /// The device path of the package list
    path: KeywordPath,
    texts: ListTexts<'a>,
    /// The roots of the form packages of the package list
    roots: &'a [Rc<RefCell<IFROperation>>],
    /// The root of the form package of the statement
    root: &'a Rc<RefCell<IFROperation>>,
    op: Rc<RefCell<IFROperation>>,
}

impl<'a> KeywordQuestion<'a> {
    /// The statements that the Keyword Handler takes for `keyword`, in `namespace`, else in a
    /// language of the prefix "x-UEFI": in the package list of the device path `path`
    /// (GetRecordFromDevicePath), else in each list, in database order
    /// (ConfigKeywordHandler.c:2393), whose first strings package of that language has the
    /// keyword (GetStringIdFromRecord) and whose statements it prompts; there the first
    /// statement, in IFR order, that the keyword's string prompts (FindQuestionFromStringId,
    /// IsStatementOpCode). Refuses a keyword that other strings packages of the list hold too,
    /// or that prompts other statements too, which firmware may take instead.
    pub(crate) fn resolve(
        lists: &'a [ParsedPackageList],
        namespace: Option<&Namespace>,
        path: Option<&KeywordPath>,
        keyword: &Keyword,
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
            match (Self::in_list(list, string, &prefix, path, keyword), path) {
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
    /// only one of the keyword under `prefix` and prompts that statement alone.
    fn in_list(
        list: &'a ParsedPackageList,
        string: KeywordString<'_>,
        prefix: &str,
        path: Option<&KeywordPath>,
        keyword: &Keyword,
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
        let path = match (path, &list.device_path) {
            (Some(path), _) => path.clone(),
            (None, Some(device_path)) => {
                KeywordPath::try_from(device_path.clone()).map_err(|error| {
                    KeywordRefusal::DevicePath {
                        keyword: text.clone(),
                        reason: error.to_string(),
                    }
                })?
            }
            (None, None) => return Err(KeywordRefusal::NoDevicePath(text)),
        };
        let Statement { root, op } = match <[_; 1]>::try_from(statements(list, string.id)) {
            Ok([statement]) => statement,
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
            texts: list.texts(&[]),
            roots: &list.forms,
            root,
            op,
        })
    }

    pub(crate) fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub(crate) fn path(&self) -> &KeywordPath {
        &self.path
    }

    /// Refuses a get of the question that GetData() would answer otherwise than get: with the
    /// stored value of one whose value READ or EFI_IFR_VALUE gives, or with the bytes at its bit
    /// offset; or of a PASSWORD, or of a question whose bytes (keyword_bytes) overlap those that
    /// `reader` withholds, which hold a password.
    pub(crate) fn check_get(&self, reader: &EfivarReader) -> Result<(), KeywordRefusal> {
        self.check_question(QuestionExpression::Read, reader)?;
        Ok(())
    }

    /// Refuses a set of `resp`, the question's keyword, that SetData() would write otherwise than
    /// set: through no WRITE expression or Callback(); else takes it through set's own checks,
    /// with `include`, `volatile` and the variables of `reader`: the question's state, whether it
    /// is read-only, which no `include` lifts, its option of the VALUE or the VALUE's range, the
    /// variable's, and whether the bytes written overlap those that `reader` withholds, which
    /// hold a password (ChangeValueError::PasswordBytes). Returns what SetData() writes.
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
        let Some(question) = value_question(&op) else {
            return Err(KeywordRefusal::Unchecked {
                keyword: self.keyword.to_string(),
                op: op.op_code.spec_name(),
            }
            .into());
        };
        let prompt = self.texts.display(header.prompt_string_id);
        let number = value_number(question, resp.value.as_bytes())
            .ok_or_else(|| self.value_refusal(resp, prompt, ValueRefusal::Width))?;
        let descriptor = self
            .chosen(question, prompt, include, volatile, reader)
            .with_context(|| format!("keyword {}", self.keyword))?;
        let text;
        let new_value = match question {
            ValueQuestion::OneOf(_) => NewValue::Option(
                option_of_value(&descriptor, number, include)
                    .with_context(|| format!("keyword {}", self.keyword))?
                    .ok_or_else(|| self.value_refusal(resp, prompt, ValueRefusal::NoOption))?,
            ),
            ValueQuestion::Numeric(_) | ValueQuestion::CheckBox(_) => {
                // a CHECKBOX has no NumericRange, nor a NUMERIC bit field, which own_write refuses
                text = descriptor.numeric_range.as_ref().map_or_else(
                    || number.to_string(),
                    |range| range.format.decode(number).to_string(),
                );
                NewValue::Text(&text)
            }
        };
        let (_, write) = own_write(&descriptor, new_value, reader.reach(), reader.interface())
            .with_context(|| {
                format!(
                    "keyword {}: VALUE={} of question \"{prompt}\"",
                    self.keyword, resp.value
                )
            })?;
        let write =
            write.ok_or_else(|| self.question_refusal(&header, QuestionRefusal::Storageless))?;
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
        // GetData() answers with the question's bytes; check_set refuses a SetData() of them
        if access == QuestionExpression::Read
            && reader
                .withheld_overlap(&store.variable_key(), &keyword_bytes(&op, &header))
                .is_some()
        {
            return Err(self.question_refusal(&header, QuestionRefusal::PasswordBytes));
        }
        if let Some(other) = self.other_declaration(header.var_store_id, &store.variable_key()) {
            return Err(self.question_refusal(
                &header,
                QuestionRefusal::RedeclaredVarStore(header.var_store_id, other),
            ));
        }
        Ok(header)
    }

    /// The store, as text, that another FormSet of the package list declares for VarStoreId `id`,
    /// unless it is the EFI variable `variable` too: UEFI 2.11 §33.3.8.3.89 EFI_IFR_VARSTORE makes
    /// a VarStoreId unique only within its FormSet, and edk2-stable202608 FindStorageFromVarId
    /// (ConfigKeywordHandler.c:1520), from GetData() and SetData() (:2108, :2213), takes the
    /// first VarStore of the id in the form package, which other firmware may take otherwise.
    fn other_declaration(&self, id: u16, variable: &VariableKey) -> Option<String> {
        self.roots
            .iter()
            .filter(|root| !Rc::ptr_eq(root, self.root))
            .flat_map(|root| root.borrow().children.clone())
            .filter(|op| op.borrow().op_code == IFROpCode::FormSet)
            .find_map(
                |form_set| match declared_var_store(&form_set.borrow(), id)? {
                    DeclaredStore::Variable(store) if store.variable_key() == *variable => None,
                    DeclaredStore::Variable(store) => {
                        Some(format!("EFI variable {}", store.variable_key()))
                    }
                    DeclaredStore::NameValue(_) => Some("a VARSTORE_NAME_VALUE".to_owned()),
                    DeclaredStore::ShortEfi => Some(format!("an {}", ShortVarStoreEfi::LABEL)),
                },
            )
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
        question: ValueQuestion<'_>,
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
        match choice_for_set(selection, prompt, &options, KEYWORD_SET_LIFTABLE, reader)? {
            Choice::Chosen(descriptor, _) => Ok(descriptor),
            Choice::Skipped(exclusion) if exclusion.is_empty() => Err(SelectionError::NotFound {
                question: prompt.to_owned(),
            }
            .into()),
            Choice::Skipped(exclusion) => Err(exclusion.question_error(prompt).into()),
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

/// A statement of a package list, with the root of its form package.
struct Statement<'a> {
    root: &'a Rc<RefCell<IFROperation>>,
    op: Rc<RefCell<IFROperation>>,
}

/// The ops of `list`, in IFR order, that IsStatementOpCode (ConfigKeywordHandler.c:1420) takes
/// for statements and whose Prompt is `prompt`, each with the root of its form package:
/// FindQuestionFromStringId reads the Prompt of an EFI_IFR_GUID from the start of its GUID.
fn statements(list: &ParsedPackageList, prompt: u16) -> Vec<Statement<'_>> {
    let mut found = Vec::new();
    for root in &list.forms {
        walk_scopes(std::slice::from_ref(root), (), |node, ()| {
            let op = node.borrow();
            if is_statement(op.op_code) && op.data.get(..2) == Some(&prompt.to_le_bytes()[..]) {
                found.push(Statement {
                    root,
                    op: Rc::clone(node),
                });
            }
            Walk::Enter(())
        });
    }
    found
}

/// The bytes of a question's value: of a ONE_OF or NUMERIC its size, of a CHECKBOX a BOOLEAN.
fn value_width(question: ValueQuestion<'_>) -> u8 {
    match question {
        ValueQuestion::OneOf(one_of) => one_of.data.size(),
        ValueQuestion::Numeric(numeric) => numeric.data.size(),
        ValueQuestion::CheckBox(_) => 1,
    }
}

/// An EFI_IFR_STRING after its op header (UEFI 2.11 §33.3.8.3.70).
#[derive(BinRead)]
#[br(little)]
struct StringOp {
    _question: QuestionHeader,
    _min_size: u8,
    max_size: u8,
}

/// An EFI_IFR_ORDERED_LIST after its op header (UEFI 2.11 §33.3.8.3.53).
#[derive(BinRead)]
#[br(little)]
struct OrderedListOp {
    _question: QuestionHeader,
    max_containers: u8,
}

/// The start of an EFI_IFR_ONE_OF_OPTION after its op header (UEFI 2.11 §33.3.8.3.51).
#[derive(BinRead)]
#[br(little)]
struct OptionTypeOp {
    _option: u16,
    _flags: u8,
    option_type: u8,
}

/// The bytes of an EFI_HII_TIME, EFI_HII_DATE and EFI_HII_REF, packed
/// (edk2-stable202608 MdePkg/Include/Uefi/UefiInternalFormRepresentation.h:659-676): Hour, Minute
/// and Second; a UINT16 Year, Month and Day; QuestionId, FormId, FormSetGuid and DevicePath.
const EFI_HII_TIME_SIZE: usize = 3;
const EFI_HII_DATE_SIZE: usize = 4;
const EFI_HII_REF_SIZE: usize = 22;

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
            let first = op.children.first()?.borrow();
            if first.op_code != IFROpCode::OneOfOption {
                return None;
            }
            let option: OptionTypeOp = Cursor::new(&first.data).parse_le().ok()?;
            let width = match option.option_type {
                EFI_IFR_TYPE_NUM_SIZE_8 => 1,
                EFI_IFR_TYPE_NUM_SIZE_16 => 2,
                EFI_IFR_TYPE_NUM_SIZE_32 => 4,
                EFI_IFR_TYPE_NUM_SIZE_64 => 8,
                _ => return None,
            };
            Some(width * usize::from(list.max_containers))
        }
        IFROpCode::String => {
            let string: StringOp = data.parse_le().ok()?;
            Some(usize::from(string.max_size) * std::mem::size_of::<u16>())
        }
        IFROpCode::Date => Some(EFI_HII_DATE_SIZE),
        IFROpCode::Time => Some(EFI_HII_TIME_SIZE),
        IFROpCode::Ref => Some(EFI_HII_REF_SIZE),
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
    use super::super::ifr_fixtures::flagged_option;
    use super::super::ifr_fixtures::ifr_false;
    use super::super::ifr_fixtures::ifr_true;
    use super::super::ifr_fixtures::locked_op;
    use super::super::ifr_fixtures::one_of_option;
    use super::super::ifr_fixtures::operation;
    use super::super::ifr_fixtures::parse_form_set;
    use super::super::ifr_fixtures::password_on;
    use super::super::ifr_fixtures::question_header_with;
    use super::super::ifr_fixtures::short_var_store_efi;
    use super::super::ifr_fixtures::uint8;
    use super::super::ifr_fixtures::var_store;
    use super::super::ifr_fixtures::MemoryVariables;
    use super::super::ifr_fixtures::VariableInterface;
    use super::super::ifr_fixtures::VariableReach;
    use super::super::ifr_fixtures::BIT_VARSTORE_GUID;
    use super::super::ifr_fixtures::DISABLE_IF;
    use super::super::ifr_fixtures::END;
    use super::super::ifr_fixtures::GRAY_OUT_IF;
    use super::super::ifr_fixtures::GUID;
    use super::super::ifr_fixtures::NUMERIC;
    use super::super::ifr_fixtures::ONE_OF;
    use super::super::ifr_fixtures::READ;
    use super::super::ifr_fixtures::SUPPRESS_IF;
    use super::super::ifr_fixtures::VALUE;
    use super::super::ifr_fixtures::WRITE;
    use super::super::storage::VariableNotExported;
    use super::super::ChangeValueError;
    use super::*;
    use crate::hii::config_string::MultiKeywordResp;
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
    const STRING: u8 = 0x1C;
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
            KeywordQuestion::resolve(&missing, None, None, &keyword(KEYWORD)).err(),
            Some(not_found("x-UEFI")),
            "the x-UEFI package comes first and lacks the keyword"
        );
        assert_eq!(
            KeywordQuestion::resolve(&found, None, None, &keyword(KEYWORD))
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
            KeywordQuestion::resolve(&ns_and_ami, None, Some(&path_of(PATH)), &keyword(KEYWORD))
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
                        lifted_with: None,
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

    /// GetData() reads a STRING, DATE, TIME or ORDERED_LIST as stored, which check_get takes;
    /// check_set refuses them, whose values uefisettings does not check yet; both refuse a
    /// PASSWORD.
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
        for (op_code, op) in [
            (STRING, "EFI_IFR_STRING"),
            (DATE, "EFI_IFR_DATE"),
            (TIME, "EFI_IFR_TIME"),
            (ORDERED_LIST, "EFI_IFR_ORDERED_LIST"),
        ] {
            let lists = [list(PATH, &[(NAMESPACE, KEYWORD)], question(op_code))];
            assert_eq!(
                question_of(&lists).check_get(&reader(1)),
                Ok(()),
                "{op}: get"
            );
            let error =
                check_set_of(question(op_code), "03", IncludedStates::empty()).expect_err(op);
            assert_eq!(
                error.to_string(),
                format!("keyword {KEYWORD}: uefisettings does not yet check values of {op}"),
                "{op}: set"
            );
        }
        let short = [list(
            PATH,
            &[(NAMESPACE, KEYWORD)],
            operation(STRING, false, &PROMPT.to_le_bytes()),
        )];
        let refusal = question_of(&short).check_get(&reader(1));
        assert!(
            matches!(
                &refusal,
                Err(KeywordRefusal::NoHeader {
                    op: "EFI_IFR_STRING",
                    reason,
                    ..
                }) if !reason.contains('\n') && !reason.contains("src/")
            ),
            "a STRING of a Prompt alone, the reason on one line: {refusal:?}"
        );
        let short_op = operation(STRING, false, &PROMPT.to_le_bytes());
        assert!(
            matches!(
                refusal_of(check_set_of(short_op, "03", IncludedStates::empty())),
                Some(KeywordRefusal::NoHeader {
                    op: "EFI_IFR_STRING",
                    ..
                })
            ),
            "set of a STRING of a Prompt alone"
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
                "keyword Keyword: question \"Keyword question\" has VarStoreId 1, which another \
                 FormSet of its package list declares for {store}"
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
}
