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

//! Get and set by keyword through EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL (UEFI 2.11 §35.3.1): every
//! keyword's question passes forms::keywords' checks before the first GetData() or SetData(),
//! which name the NAMESPACE, PATH and KEYWORD of the question that the checks passed, and set
//! reads every keyword back.

use std::collections::BTreeSet;
use std::fmt;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error;

use super::config_string::Keyword;
use super::config_string::KeywordInfo;
use super::config_string::KeywordInfoFilter;
use super::config_string::KeywordPath;
use super::config_string::KeywordRequest;
use super::config_string::KeywordResp;
use super::config_string::MultiKeywordResp;
use super::config_string::Namespace;
use super::config_string::Number;
use super::config_string::Usage;
use super::forms::keywords::KeywordInfoRefusal;
use super::forms::keywords::KeywordQuestion;
use super::forms::keywords::KeywordRefusal;
use super::forms::keywords::KeywordWrite;
use super::forms::IncludedStates;
use super::forms::PasswordQuestions;
use super::forms::SetupPasswordPolicy;
use super::package::ParsedPackageList;
use super::variables::FirmwareVariables;
use super::variables::VolatileWrites;
use super::variables::VOLATILE_ANNOTATION;

/// The ProgressErr bits of UEFI 2.11 §35.3.2, with their names.
const PROGRESS_ERRORS: [(u32, &str); 6] = [
    (0x01, "NAMESPACE_ID_NOT_FOUND"),
    (0x02, "MALFORMED_STRING"),
    (0x04, "KEYWORD_NOT_FOUND"),
    (0x08, "INCOMPATIBLE_VALUE_DETECTED"),
    (0x10, "ACCESS_NOT_PERMITTED"),
    (0x8000_0000, "UNDEFINED_PROCESSING_ERROR"),
];

/// GetData() and SetData() of EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL (UEFI 2.11 §35.3.1), each
/// failing with its status and ProgressErr.
pub(crate) trait KeywordData {
    /// The Results of GetData() of `keyword_string`, a `<MultiKeywordRequest>`, with the
    /// NamespaceId `namespace_id`.
    fn get_data(&self, namespace_id: &str, keyword_string: &str) -> Result<String>;
    /// SetData() of `keyword_string`, a `<MultiKeywordResp>`.
    fn set_data(&self, keyword_string: &str) -> Result<()>;
}

/// The keywords that get and set by keyword print: their `<MultiKeywordResp>`, as GetData()
/// returns it, each that set wrote in a volatile variable followed by VOLATILE_ANNOTATION; or,
/// serialized, an object of NAMESPACE, PATH, KEYWORD, VALUE, READONLY and the items of its
/// `<KeywordInfoResp>` per keyword, and `volatile` for one that set wrote in a volatile variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeywordValues {
    resps: MultiKeywordResp,
    /// The indices of the keywords that set wrote in volatile variables
    volatile: BTreeSet<usize>,
}

impl fmt::Display for KeywordValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, resp) in self.resps.as_slice().iter().enumerate() {
            if index > 0 {
                f.write_str("&")?;
            }
            write!(f, "{resp}")?;
            if self.volatile.contains(&index) {
                f.write_str(VOLATILE_ANNOTATION)?;
            }
        }
        Ok(())
    }
}

impl Serialize for KeywordValues {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.resps
                .as_slice()
                .iter()
                .enumerate()
                .map(|(index, resp)| KeywordValue::of(resp, self.volatile.contains(&index))),
        )
    }
}

/// A keyword of KeywordValues, serialized, with the items of its `<KeywordInfoResp>` that it
/// has: numbers as VALUE, `<String>`s as text.
#[derive(Serialize)]
struct KeywordValue {
    namespace: String,
    path: String,
    keyword: String,
    /// The hex digits of VALUE, the first byte in memory last
    value: String,
    read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    step: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    options: Vec<KeywordOption>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standard_default: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manufacturing_default: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_default: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    /// Whether set wrote the keyword in a volatile variable, serialized only if it did
    #[serde(skip_serializing_if = "is_false")]
    volatile: bool,
}

impl KeywordValue {
    fn of(resp: &KeywordResp, volatile: bool) -> Self {
        let info = &resp.info;
        let range = info.range.as_ref();
        Self {
            namespace: resp.namespace.to_string(),
            path: resp.device_path.to_string(),
            keyword: resp.keyword.to_string(),
            value: resp.value.to_string(),
            read_only: resp.usage == Usage::ReadOnly,
            data_type: info.data_type.map(|data_type| data_type.to_string()),
            max: range.map(|range| range.max.to_string()),
            min: range.map(|range| range.min.to_string()),
            step: range.and_then(|range| range.step.as_ref().map(ToString::to_string)),
            options: info
                .options
                .iter()
                .map(|option| KeywordOption {
                    value: option.value.to_string(),
                    string: String::from_utf16_lossy(&option.string),
                    value_type: option.value_type.map(|value_type| value_type.to_string()),
                })
                .collect(),
            standard_default: info.standard_default.as_ref().map(ToString::to_string),
            manufacturing_default: info.manufacturing_default.as_ref().map(ToString::to_string),
            safe_default: info.safe_default.as_ref().map(ToString::to_string),
            display_name: info.display_name.as_deref().map(String::from_utf16_lossy),
            volatile,
        }
    }
}

/// A `<ValueOption>` of a KeywordValue.
#[derive(Serialize)]
struct KeywordOption {
    value: String,
    string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_type: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

/// Where get by keyword takes the `<KeywordInfoResp>` of a KEYWORDINFO from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeywordInfoSource {
    /// The HiiDB's IFR (KeywordQuestion::info); GetData() is sent no KEYWORDINFO
    #[default]
    Ifr,
    /// GetData(), sent the KEYWORDINFO unchanged; its `<KeywordResp>`s are taken as returned
    GetData,
}

/// Why get by keyword reads no value.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum KeywordGetError {
    #[error("GetData() returned {0}, with a <KeywordInfoResp> that it was not asked for")]
    UnaskedInfo(String),
}

/// Why set by keyword writes nothing, or reports a failed write.
#[derive(Debug, Error)]
pub(crate) enum KeywordSetError {
    #[error("keyword {0}: uefisettings sends SetData() no KEYWORDINFO element")]
    KeywordInfo(String),
    /// SetData()'s error, after which GetData() read back each keyword's `<KeywordResp>`, or
    /// failed as told
    #[error("SetData() failed, after which GetData() reads back {}", .0.join("; "))]
    SetData(Vec<String>, #[source] anyhow::Error),
    #[error("SetData() of {written} succeeded, but GetData() reads back {read}")]
    ReadBack { written: String, read: String },
    #[error("SetData() of {0} succeeded, but GetData() of KEYWORD={1} failed")]
    ReadBackFailed(String, String, #[source] anyhow::Error),
}

/// The values of the keyword of `request`, a `<KeywordRequest>` of an optional PATH, a KEYWORD
/// and an optional KEYWORDINFO, in `namespace`, else in a language of the prefix "x-UEFI", in
/// `lists`: GetData() of `handler` reads each question that KeywordQuestion::resolve finds, once
/// each passes check_get with the bytes of the PASSWORD questions of `lists` in `variables`
/// withheld, which it never reads. With `info_source` KeywordInfoSource::Ifr, each
/// `<KeywordResp>` gets the `<KeywordInfoResp>` of KEYWORDINFO from the IFR, its texts in the
/// language that `requested` picks (KeywordQuestion::info), built before any call; GetData()
/// gets no KEYWORDINFO, which edk2-stable202608 GetData() fails with EFI_INVALID_PARAMETER and
/// KEYWORD_HANDLER_MALFORMED_STRING (ConfigKeywordHandler.c ValidateFilter leaves it unread,
/// ExtractDevicePath refuses it). With KeywordInfoSource::GetData, GetData() gets the KEYWORDINFO
/// unchanged and its `<KeywordResp>`s are taken as returned. Whenever GetData() gets no
/// KEYWORDINFO, a `<KeywordResp>` that holds a `<KeywordInfoResp>` is refused
/// (KeywordGetError::UnaskedInfo).
pub(crate) fn get_keyword(
    lists: &[ParsedPackageList],
    request: &str,
    namespace: Option<&str>,
    requested: &[&str],
    info_source: KeywordInfoSource,
    variables: Box<dyn FirmwareVariables>,
    handler: &impl KeywordData,
) -> Result<KeywordValues> {
    let request: KeywordRequest = request.parse()?;
    let namespace = namespace.map(Namespace::try_from).transpose()?;
    let mut reader = PasswordQuestions::of_lists(lists).reader(variables)?;
    let questions = KeywordQuestion::resolve(
        lists,
        namespace.as_ref(),
        request.device_path.as_ref(),
        &request.keyword,
        requested,
    )?;
    for question in &questions {
        question.check_get(&reader)?;
    }
    let (infos, sent_info) = match (request.info, info_source) {
        (Some(filter), KeywordInfoSource::Ifr) => (
            questions
                .iter()
                .map(|question| question.info(filter, &mut reader).map(Some))
                .collect::<Result<Vec<_>, KeywordInfoRefusal>>()?,
            None,
        ),
        (sent_info, KeywordInfoSource::GetData) | (sent_info @ None, KeywordInfoSource::Ifr) => {
            (vec![None; questions.len()], sent_info)
        }
    };
    let values = questions
        .iter()
        .zip(infos)
        .map(|(question, info)| {
            let mut resp = read_keyword(
                handler,
                question.namespace(),
                question.path(),
                &request.keyword,
                sent_info,
            )?;
            if sent_info.is_none() && resp.info != KeywordInfo::default() {
                return Err(KeywordGetError::UnaskedInfo(resp.to_string()).into());
            }
            if let Some(info) = info {
                resp.info = info;
            }
            Ok(resp)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(KeywordValues {
        resps: MultiKeywordResp::try_from(values)?,
        volatile: BTreeSet::new(),
    })
}

/// Writes `keywords`, a `<MultiKeywordResp>`, with one SetData() of `handler`, once each keyword's
/// question in `lists` passes check_set with `include`, `volatile` and `variables`, through which
/// set would write, no two keywords write a byte of one variable (check_disjoint), and `lists`
/// declare no setup password unless `setup_password` bypasses it; then reads each keyword back
/// with GetData(), which must hold the number written. When SetData() fails, it reads them back
/// too and reports each with the error.
pub(crate) fn set_keywords(
    lists: &[ParsedPackageList],
    keywords: &str,
    include: IncludedStates,
    setup_password: SetupPasswordPolicy,
    volatile: VolatileWrites,
    variables: Box<dyn FirmwareVariables>,
    handler: &impl KeywordData,
) -> Result<KeywordValues> {
    let resps: MultiKeywordResp = keywords.parse()?;
    let passwords = PasswordQuestions::of_lists(lists);
    passwords.check_set(variables.reach(), setup_password)?;
    let mut reader = passwords.reader(variables)?;
    let mut writes = Vec::new();
    for (index, resp) in resps.as_slice().iter().enumerate() {
        if resp.info != KeywordInfo::default() {
            return Err(KeywordSetError::KeywordInfo(resp.keyword.to_string()).into());
        }
        let questions = KeywordQuestion::resolve(
            lists,
            Some(&resp.namespace),
            Some(&resp.device_path),
            &resp.keyword,
            &[],
        )?;
        for question in questions {
            let write = question.check_set(resp, include, volatile, &mut reader)?;
            writes.push((index, &resp.keyword, write));
        }
    }
    check_disjoint(&writes)?;
    // the VALUEs re-serialized, each as wide as its question
    let keyword_string = resps.to_string();
    if let Err(error) = handler.set_data(&keyword_string) {
        let read_back = resps
            .as_slice()
            .iter()
            .map(|resp| {
                read_back(handler, resp).map_or_else(
                    |error| format!("KEYWORD={}: {error:#}", resp.keyword),
                    |value| value.to_string(),
                )
            })
            .collect();
        return Err(KeywordSetError::SetData(read_back, error).into());
    }
    let values = resps
        .as_slice()
        .iter()
        .map(|resp| {
            let value = read_back(handler, resp).map_err(|error| {
                KeywordSetError::ReadBackFailed(
                    keyword_string.clone(),
                    resp.keyword.to_string(),
                    error,
                )
            })?;
            if !same_number(&value.value, &resp.value) {
                return Err(KeywordSetError::ReadBack {
                    written: resp.to_string(),
                    read: value.to_string(),
                }
                .into());
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(KeywordValues {
        resps: MultiKeywordResp::try_from(values)?,
        volatile: writes
            .iter()
            .filter(|(_, _, write)| write.volatile)
            .map(|&(index, _, _)| index)
            .collect(),
    })
}

/// Refuses `writes`, each with its keyword, of which two write a byte of one variable: SetData()
/// merges the keywords' `<ConfigResp>`s into one `<MultiConfigResp>` (edk2-stable202608
/// ConfigKeywordHandler.c:3052) for one RouteConfig() (:3079), which routes each `<ConfigResp>`
/// in turn (ConfigRouting.c:5713), so a later keyword would overwrite an earlier one's bytes.
fn check_disjoint(writes: &[(usize, &Keyword, KeywordWrite)]) -> Result<(), KeywordRefusal> {
    for (at, (_, first, first_write)) in writes.iter().enumerate() {
        for (_, second, second_write) in writes.iter().skip(at + 1) {
            let overlapping = first_write.variable == second_write.variable
                && first_write.bytes.iter().any(|mine| {
                    second_write
                        .bytes
                        .iter()
                        .any(|theirs| mine.start < theirs.end && theirs.start < mine.end)
                });
            if overlapping {
                return Err(KeywordRefusal::Overlapping {
                    first: first.to_string(),
                    second: second.to_string(),
                    variable: first_write.variable.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Whether `read` and `written`, numbers in memory order, are equal, whatever high-order zero
/// bytes GetData() adds or drops.
fn same_number(read: &Number, written: &Number) -> bool {
    significant(read.as_bytes()) == significant(written.as_bytes())
}

/// `bytes`, a number in memory order, without its high-order zero bytes.
fn significant(mut bytes: &[u8]) -> &[u8] {
    while let [rest @ .., 0] = bytes {
        bytes = rest;
    }
    bytes
}

/// The `<KeywordResp>` of the keyword of `resp` that GetData() of `handler` reads.
fn read_back(handler: &impl KeywordData, resp: &KeywordResp) -> Result<KeywordResp> {
    read_keyword(
        handler,
        &resp.namespace,
        &resp.device_path,
        &resp.keyword,
        None,
    )
}

/// The `<KeywordResp>` of `keyword` in `namespace` of the package list of `path` that GetData() of
/// `handler` returns, asked with all three: UEFI 2.11 §35.3.3 takes NamespaceId as the language
/// alone, edk2-stable202608 ExtractNameSpace (ConfigKeywordHandler.c:202, from GetData() at
/// :3251) as a `<NameSpaceId>`, which this sends. The request holds KEYWORDINFO `info`, if any.
fn read_keyword(
    handler: &impl KeywordData,
    namespace: &Namespace,
    path: &KeywordPath,
    keyword: &Keyword,
    info: Option<KeywordInfoFilter>,
) -> Result<KeywordResp> {
    let request = KeywordRequest {
        device_path: Some(path.clone()),
        keyword: keyword.clone(),
        info,
        usage: None,
        data: None,
    };
    let results = handler.get_data(&format!("NAMESPACE={namespace}"), &request.to_string())?;
    let resps: MultiKeywordResp = results
        .parse()
        .with_context(|| format!("GetData() of {request} returned {results:?}"))?;
    match resps.as_slice() {
        [resp]
            if resp.namespace == *namespace
                && resp.device_path == *path
                && resp.keyword == *keyword =>
        {
            Ok(resp.clone())
        }
        _ => Err(anyhow!(
            "GetData() of {request} returned {results:?}, not that keyword's <KeywordResp> alone"
        )),
    }
}

/// The character that Progress, at the address `progress`, points at in a string of `chars`
/// characters at the address `string`, if it points into the string or at its NUL.
pub(super) fn progress_char(progress: usize, string: usize, chars: usize) -> Option<usize> {
    progress
        .checked_sub(string)
        .map(|bytes| bytes / size_of::<u16>())
        .filter(|&at| at <= chars)
}

/// The error of `function`, which failed with `status` and ProgressErr `progress_err`, whose bits
/// it names, and with Progress at character `at` of its string, if it points into it.
pub(super) fn call_error(
    function: &str,
    status: &str,
    at: Option<usize>,
    progress_err: u32,
) -> anyhow::Error {
    let bits: Vec<&str> = PROGRESS_ERRORS
        .iter()
        .filter(|(bit, _)| progress_err & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    anyhow!(
        "{function}: {status}, ProgressErr {progress_err:#x} ({}), Progress at {}",
        bits.join("|"),
        at.map_or_else(
            || "no character of the string".to_owned(),
            |at| format!("character {at}")
        ),
    )
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use super::*;
    use crate::hii::forms::ifr_fixtures::checkbox_on;
    use crate::hii::forms::ifr_fixtures::conditional;
    use crate::hii::forms::ifr_fixtures::eq_id_val_of;
    use crate::hii::forms::ifr_fixtures::flagged_option;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::operation;
    use crate::hii::forms::ifr_fixtures::parse_form_set;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::question_header_with;
    use crate::hii::forms::ifr_fixtures::short_var_store_efi_of;
    use crate::hii::forms::ifr_fixtures::var_store;
    use crate::hii::forms::ifr_fixtures::MemoryVariables;
    use crate::hii::forms::ifr_fixtures::VariableInterface;
    use crate::hii::forms::ifr_fixtures::VariableKey;
    use crate::hii::forms::ifr_fixtures::VariableReach;
    use crate::hii::forms::ifr_fixtures::END;
    use crate::hii::forms::ifr_fixtures::NUMERIC;
    use crate::hii::forms::ifr_fixtures::ONE_OF;
    use crate::hii::forms::ifr_fixtures::SHORT_VAR_STORE_GUID;
    use crate::hii::forms::ifr_fixtures::SUPPRESS_IF;
    use crate::hii::forms::keywords::KeywordRefusal;
    use crate::hii::forms::resolve_short_var_names;
    use crate::hii::forms::IgnoredIfr;
    use crate::hii::forms::IgnoredPasswords;
    use crate::hii::package::hiidb_fixtures::form_package_of;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::read_db;
    use crate::hii::package::Guid;
    use crate::hii::strings::Language;
    use crate::hii::strings::StringPackage;

    const PATH: &str = "01041400111111111111111111111111111111117fff0400";
    const OTHER_PATH: &str = "01041400222222222222222222222222222222227fff0400";
    const NAMESPACE: &str = "x-UEFI-ns";
    /// The keyword of string 3, which prompts a question at VarOffset 5
    const KEYWORD: &str = "Keyword";
    /// The keyword of string 5, which prompts a question at VarOffset 6
    const SECOND_KEYWORD: &str = "SecondKeyword";
    /// The VarStore of the questions, the variable Store of this GUID
    const STORE_GUID: [u8; 16] = [0x33; 16];
    /// NV+BS+RT
    const ATTRIBUTES: u32 = 0x07;
    /// BS+RT
    const VOLATILE: u32 = 0x06;

    /// What a MemoryKeywordHandler was called for.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum KeywordCall {
        GetData {
            namespace_id: String,
            keyword_string: String,
        },
        SetData(String),
    }

    /// A Keyword Handler of the VALUEs in `values` by "PATH=…&KEYWORD=…", which records its
    /// calls. Its SetData() fails with `set_failure` if given, and else stores the VALUEs unless
    /// `stale`.
    #[derive(Default)]
    struct MemoryKeywordHandler {
        values: RefCell<BTreeMap<String, String>>,
        calls: RefCell<Vec<KeywordCall>>,
        set_failure: Option<&'static str>,
        stale: bool,
    }

    impl MemoryKeywordHandler {
        /// Each (PATH, KEYWORD, VALUE) of `values`.
        fn with(values: &[(&str, &str, &str)]) -> Self {
            let handler = Self::default();
            for (path, keyword, value) in values {
                handler
                    .values
                    .borrow_mut()
                    .insert(keyword_string(path, keyword), (*value).to_owned());
            }
            handler
        }

        fn calls(&self) -> Vec<KeywordCall> {
            self.calls.borrow().clone()
        }
    }

    impl KeywordData for MemoryKeywordHandler {
        fn get_data(&self, namespace_id: &str, keyword_string: &str) -> Result<String> {
            self.calls.borrow_mut().push(KeywordCall::GetData {
                namespace_id: namespace_id.to_owned(),
                keyword_string: keyword_string.to_owned(),
            });
            let namespace = namespace_id
                .strip_prefix("NAMESPACE=")
                .ok_or_else(|| anyhow!("MALFORMED_STRING"))?;
            let value = self
                .values
                .borrow()
                .get(keyword_string)
                .cloned()
                .ok_or_else(|| anyhow!("KEYWORD_NOT_FOUND"))?;
            Ok(format!(
                "NAMESPACE={namespace}&{keyword_string}&VALUE={value}"
            ))
        }

        fn set_data(&self, keyword_string: &str) -> Result<()> {
            self.calls
                .borrow_mut()
                .push(KeywordCall::SetData(keyword_string.to_owned()));
            if let Some(failure) = self.set_failure {
                return Err(anyhow!(failure));
            }
            if self.stale {
                return Ok(());
            }
            let resps: MultiKeywordResp = keyword_string.parse()?;
            for resp in resps.as_slice() {
                self.values.borrow_mut().insert(
                    format!("PATH={}&KEYWORD={}", resp.device_path, resp.keyword),
                    resp.value.to_string(),
                );
            }
            Ok(())
        }
    }

    fn keyword_string(path: &str, keyword: &str) -> String {
        format!("PATH={path}&KEYWORD={keyword}")
    }

    /// A UINT8 ONE_OF prompted by string `prompt` at VarOffset `offset` of VarStore
    /// `var_store_id`, whose options hold 0, 1 and 3.
    fn one_of(prompt: u16, offset: u16, var_store_id: u16) -> Vec<u8> {
        flagged_one_of(prompt, offset, var_store_id, 0)
    }

    /// one_of, with the question Flags `flags`.
    fn flagged_one_of(prompt: u16, offset: u16, var_store_id: u16, flags: u8) -> Vec<u8> {
        let data = [
            question_header_with(prompt, prompt, var_store_id, offset, flags),
            vec![0x00, 0, 3, 1], // Flags UINT8, MinValue, MaxValue, Step
        ]
        .concat();
        [
            operation(ONE_OF, true, &data),
            flagged_option(4, 0, 0),
            flagged_option(4, 0, 1),
            flagged_option(4, 0, 3),
            END.to_vec(),
        ]
        .concat()
    }

    /// The questions of KEYWORD and SECOND_KEYWORD in VarStore 1.
    fn questions() -> Vec<Vec<u8>> {
        vec![one_of(3, 5, 1), one_of(5, 6, 1)]
    }

    /// A UINT16 NUMERIC, shown unsigned, prompted by string `prompt` at VarOffset `offset` of
    /// VarStore 1, from 0 to 1000.
    fn uint16_numeric(prompt: u16, offset: u16) -> Vec<u8> {
        let data = [
            question_header_with(prompt, prompt, 1, offset, 0),
            // Flags UINT16 and EFI_IFR_DISPLAY_UINT_DEC, MinValue 0, MaxValue 1000, Step 1
            vec![0x11, 0x00, 0x00, 0xE8, 0x03, 0x01, 0x00],
        ]
        .concat();
        operation(NUMERIC, false, &data)
    }

    /// A Keyword Handler whose GetData() answers with `from` replaced by `to`.
    struct RewritingHandler {
        inner: MemoryKeywordHandler,
        from: String,
        to: String,
    }

    impl KeywordData for RewritingHandler {
        fn get_data(&self, namespace_id: &str, keyword_string: &str) -> Result<String> {
            Ok(self
                .inner
                .get_data(namespace_id, keyword_string)?
                .replace(&self.from, &self.to))
        }

        fn set_data(&self, keyword_string: &str) -> Result<()> {
            self.inner.set_data(keyword_string)
        }
    }

    /// A Keyword Handler whose SetData() succeeds and whose GetData() fails.
    struct FailingReads(MemoryKeywordHandler);

    impl KeywordData for FailingReads {
        fn get_data(&self, namespace_id: &str, keyword_string: &str) -> Result<String> {
            self.0.get_data(namespace_id, keyword_string)?;
            Err(anyhow!("GetData(): DEVICE_ERROR"))
        }

        fn set_data(&self, keyword_string: &str) -> Result<()> {
            self.0.set_data(keyword_string)
        }
    }

    /// A package list of the device path `path` that declares VarStore 1 and holds `ops`, whose
    /// x-UEFI-ns strings package names strings 3 and 5 KEYWORD and SECOND_KEYWORD.
    fn list(path: &str, ops: &[Vec<u8>]) -> ParsedPackageList {
        let strings = |language: &[u8], first: &str, second: &str| StringPackage {
            language: Language(language.to_vec()),
            strings: BTreeMap::from([(3, first.into()), (5, second.into())]),
        };
        let device_path = path.parse::<KeywordPath>().expect("a device path");
        ParsedPackageList {
            guid: Guid::from([0x22; 16]),
            device_path: Some(device_path.as_ref().clone()),
            strings: vec![
                strings(b"en-US", "Keyword question", "Second question"),
                strings(NAMESPACE.as_bytes(), KEYWORD, SECOND_KEYWORD),
            ],
            forms: vec![parse_form_set(
                &[vec![var_store(1, STORE_GUID, "Store", 16)], ops.to_vec()].concat(),
            )],
            ignored_ifr: Vec::new(),
            outside_ifr: Vec::new(),
            malformed_outside_stores: Vec::new(),
            disabled_forms: Vec::new(),
        }
    }

    /// The variables of the UEFI Shell, where the variable Store holds 1 at VarOffsets 5 and 6.
    fn variables() -> Box<dyn FirmwareVariables> {
        variables_of(ATTRIBUTES)
    }

    /// variables(), the variable Store of `attributes`.
    fn variables_of(attributes: u32) -> Box<dyn FirmwareVariables> {
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let mut data = [0; 16];
        data[5] = 1;
        data[6] = 1;
        let key = VariableKey {
            name: "Store".to_owned(),
            guid: Guid::from(STORE_GUID),
        };
        variables.insert(key, attributes, &data);
        Box::new(variables)
    }

    fn resp(path: &str, keyword: &str, value: &str) -> String {
        format!("NAMESPACE={NAMESPACE}&PATH={path}&KEYWORD={keyword}&VALUE={value}")
    }

    fn get_call(path: &str, keyword: &str) -> KeywordCall {
        KeywordCall::GetData {
            namespace_id: format!("NAMESPACE={NAMESPACE}"),
            keyword_string: keyword_string(path, keyword),
        }
    }

    fn get(lists: &[ParsedPackageList], handler: &impl KeywordData) -> Result<KeywordValues> {
        get_keyword(
            lists,
            &format!("KEYWORD={KEYWORD}"),
            None,
            &[],
            KeywordInfoSource::Ifr,
            variables(),
            handler,
        )
    }

    fn set(
        lists: &[ParsedPackageList],
        keywords: &str,
        setup_password: SetupPasswordPolicy,
        handler: &impl KeywordData,
    ) -> Result<KeywordValues> {
        set_keywords(
            lists,
            keywords,
            IncludedStates::empty(),
            setup_password,
            VolatileWrites::Refuse,
            variables(),
            handler,
        )
    }

    /// get and set by KEYWORD of a ONE_OF on a VARSTORE_EFI before UEFI 2.3.1, on VarName 7
    /// "ShortVarK", are refused before any GetData() or SetData(): the Keyword Handler would take
    /// the VarName for a VarOffset in a request to the driver (edk2-stable202608
    /// ConfigKeywordHandler.c :2114, :2219; ConfigRouting.c GetVarStoreType :1902).
    #[test]
    fn get_and_set_by_keyword_call_no_handler_for_a_short_var_store() {
        const REFUSAL: &str = "is on an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1, whose VarName the \
            Keyword Handler takes for a VarOffset in a request to its driver";
        let mut lists = [list(
            PATH,
            &[
                short_var_store_efi_of(2, SHORT_VAR_STORE_GUID, ATTRIBUTES),
                one_of(3, 7, 2),
            ],
        )];
        lists[0].strings[0].strings.insert(7, "ShortVarK".into());
        resolve_short_var_names(&lists[0].forms, &lists[0].strings);
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let get = get(&lists, &handler)
            .map(drop)
            .map_err(|error| format!("{error:#}"));
        let set = set(
            &lists,
            &resp(PATH, KEYWORD, "03"),
            SetupPasswordPolicy::Refuse,
            &handler,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"));

        assert!(
            get.as_ref().is_err_and(|error| error.contains(REFUSAL))
                && set.as_ref().is_err_and(|error| error.contains(REFUSAL)),
            "get {get:?}, set {set:?}"
        );
        assert_eq!(handler.calls(), vec![], "no GetData() or SetData()");
    }

    /// GetData() reads the question that check_get passed: by the NAMESPACE of its strings
    /// package and the PATH of its package list, which the request names neither of, once per
    /// list.
    #[test]
    fn get_names_the_namespace_path_and_keyword_of_each_question() {
        let lists = [list(PATH, &questions()), list(OTHER_PATH, &questions())];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (OTHER_PATH, KEYWORD, "03")]);

        let values = get(&lists, &handler).expect("get by keyword");

        assert_eq!(
            values.to_string(),
            format!(
                "{}&{}",
                resp(PATH, KEYWORD, "01"),
                resp(OTHER_PATH, KEYWORD, "03")
            ),
            "a <KeywordResp> per list"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call(PATH, KEYWORD), get_call(OTHER_PATH, KEYWORD)],
            "a GetData() per list, of NAMESPACE, PATH and KEYWORD"
        );
    }

    /// Every question passes check_get before the first GetData().
    #[test]
    fn get_checks_every_question_before_any_call() {
        let undeclared = [one_of(3, 5, 9)];
        let lists = [list(PATH, &questions()), list(OTHER_PATH, &undeclared)];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (OTHER_PATH, KEYWORD, "01")]);

        let error = get(&lists, &handler).expect_err("a question of an undeclared VarStore");

        assert!(
            error.downcast_ref::<KeywordRefusal>().is_some(),
            "refused: {error:#}"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// GetData() must answer the keyword asked for alone.
    #[test]
    fn get_refuses_results_of_another_keyword() {
        let lists = [list(PATH, &questions())];
        let two = format!("01&{}", resp(PATH, "Other", "01"));
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, &two)]);

        let error = get(&lists, &handler).expect_err("results of two keywords");

        assert!(
            format!("{error:#}").contains("not that keyword's <KeywordResp> alone"),
            "refused: {error:#}"
        );
    }

    /// set checks every keyword, then calls SetData() once with them all, the VALUEs
    /// re-serialized, then reads each back by NAMESPACE, PATH and KEYWORD.
    #[test]
    fn set_writes_the_keywords_at_once_and_reads_each_back() {
        let lists = [list(PATH, &questions())];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "01")]);
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "3"),
            resp(PATH, SECOND_KEYWORD, "00")
        );

        let values =
            set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler).expect("set by keyword");

        let written = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "03"),
            resp(PATH, SECOND_KEYWORD, "00")
        );
        assert_eq!(values.to_string(), written, "the values read back");
        assert_eq!(
            handler.calls(),
            vec![
                KeywordCall::SetData(written.clone()),
                get_call(PATH, KEYWORD),
                get_call(PATH, SECOND_KEYWORD),
            ],
            "one SetData(), then a GetData() per keyword"
        );
    }

    /// A refused keyword leaves every keyword unwritten: no SetData() takes the ones before it.
    #[test]
    fn set_refusing_a_second_keyword_makes_no_call() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::default();
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "03"),
            resp(PATH, SECOND_KEYWORD, "02")
        );

        let error = set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler)
            .expect_err("a VALUE of no option");

        assert_eq!(
            error.to_string(),
            format!(
                "keyword {SECOND_KEYWORD}: VALUE=02 is no option of question \"Second question\""
            ),
            "the second keyword's refusal"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// In a HiiDB that declares a PASSWORD question, set refuses before any call, unless the
    /// setup password policy bypasses it.
    #[test]
    fn set_with_a_declared_password_refuses_before_any_call_unless_bypassed() {
        let password = [
            questions(),
            vec![
                var_store(2, [0x44; 16], "Password", 20),
                password_on(9, 9, 2, 0),
            ],
        ]
        .concat();
        let lists = [list(PATH, &password)];
        let keywords = resp(PATH, KEYWORD, "03");

        let refused = MemoryKeywordHandler::default();
        let error = set(&lists, &keywords, SetupPasswordPolicy::Refuse, &refused)
            .expect_err("a declared setup password");
        assert!(
            error.to_string().contains("--bypass-setup-password"),
            "refused: {error:#}"
        );
        assert_eq!(refused.calls(), vec![], "no call");

        let bypassed = MemoryKeywordHandler::default();
        set(&lists, &keywords, SetupPasswordPolicy::Bypass, &bypassed).expect("bypassed");
        assert_eq!(
            bypassed.calls().first(),
            Some(&KeywordCall::SetData(keywords)),
            "SetData() when bypassed"
        );
    }

    /// get and set by keyword neither read nor write the bytes of a password, those of a
    /// PASSWORD question of Store from VarOffset 6, before any call, as get and set do; the
    /// question beside them reads and writes.
    #[test]
    fn get_and_set_leave_the_bytes_of_a_password_before_any_call() {
        let lists = [list(
            PATH,
            &[questions(), vec![password_on(9, 9, 1, 6)]].concat(),
        )];
        let get_of = |keyword: &str, handler: &MemoryKeywordHandler| {
            get_keyword(
                &lists,
                &format!("KEYWORD={keyword}"),
                None,
                &[],
                KeywordInfoSource::Ifr,
                variables(),
                handler,
            )
            .map(|values| values.to_string())
            .map_err(|error| format!("{error:#}"))
        };
        let set_of = |keyword: &str, handler: &MemoryKeywordHandler| {
            set(
                &lists,
                &resp(PATH, keyword, "03"),
                SetupPasswordPolicy::Bypass,
                handler,
            )
            .map(|values| values.to_string())
            .map_err(|error| format!("{error:#}"))
        };
        let handler =
            || MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "01")]);

        let refused = handler();
        assert_eq!(
            get_of(SECOND_KEYWORD, &refused),
            Err(
                "keyword SecondKeyword: question \"Second question\" spans bytes that hold a \
                 password, which uefisettings neither reads nor writes"
                    .to_owned()
            ),
            "get over the password"
        );
        assert_eq!(
            set_of(SECOND_KEYWORD, &refused),
            Err(
                "keyword SecondKeyword: cannot set question \"Second question\": EFI variable \
                 Store-33333333-3333-3333-3333-333333333333 holds a password at bytes 6..46, which \
                 set never writes"
                    .to_owned()
            ),
            "set over the password"
        );
        assert_eq!(refused.calls(), vec![], "no call over the password");

        let beside = handler();
        assert_eq!(
            get_of(KEYWORD, &beside),
            Ok(resp(PATH, KEYWORD, "01")),
            "get beside the password"
        );
        assert_eq!(
            set_of(KEYWORD, &beside),
            Ok(resp(PATH, KEYWORD, "03")),
            "set beside the password"
        );
        assert_eq!(
            beside.calls(),
            vec![
                get_call(PATH, KEYWORD),
                KeywordCall::SetData(resp(PATH, KEYWORD, "03")),
                get_call(PATH, KEYWORD),
            ],
            "calls beside the password"
        );
    }

    /// set fails unless GetData() reads back each VALUE written.
    #[test]
    fn set_fails_on_a_differing_read_back() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler {
            stale: true,
            ..MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")])
        };

        let error = set(
            &lists,
            &resp(PATH, KEYWORD, "03"),
            SetupPasswordPolicy::Refuse,
            &handler,
        )
        .expect_err("a stale read-back");

        assert!(
            matches!(
                error.downcast_ref::<KeywordSetError>(),
                Some(KeywordSetError::ReadBack { written, read })
                    if *written == resp(PATH, KEYWORD, "03") && *read == resp(PATH, KEYWORD, "01")
            ),
            "the VALUEs written and read: {error:#}"
        );
    }

    /// set compares the read-back of every keyword, not only the first's.
    #[test]
    fn set_fails_on_a_differing_read_back_of_a_second_keyword() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler {
            stale: true,
            ..MemoryKeywordHandler::with(&[(PATH, KEYWORD, "03"), (PATH, SECOND_KEYWORD, "01")])
        };
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "03"),
            resp(PATH, SECOND_KEYWORD, "03")
        );

        let error = set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler)
            .expect_err("a stale read-back of the second keyword");

        assert!(
            matches!(
                error.downcast_ref::<KeywordSetError>(),
                Some(KeywordSetError::ReadBack { written, read })
                    if *written == resp(PATH, SECOND_KEYWORD, "03")
                        && *read == resp(PATH, SECOND_KEYWORD, "01")
            ),
            "the second keyword's VALUEs written and read: {error:#}"
        );
    }

    /// When SetData() fails, set reads every keyword back and reports each VALUE with the error.
    #[test]
    fn set_reports_what_get_reads_back_after_a_failed_set_data() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler {
            set_failure: Some("SetData(): ACCESS_DENIED"),
            ..MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")])
        };
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "03"),
            resp(PATH, SECOND_KEYWORD, "00")
        );

        let error = set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler)
            .expect_err("a failed SetData()");

        let Some(KeywordSetError::SetData(read_back, _)) = error.downcast_ref::<KeywordSetError>()
        else {
            panic!("not SetData's failure: {error:#}");
        };
        assert_eq!(
            read_back,
            &[
                resp(PATH, KEYWORD, "01"),
                format!("KEYWORD={SECOND_KEYWORD}: KEYWORD_NOT_FOUND"),
            ],
            "each keyword's VALUE, or why GetData() failed"
        );
        assert!(
            format!("{error:#}").ends_with("SetData(): ACCESS_DENIED"),
            "the error: {error:#}"
        );
        assert_eq!(
            handler.calls(),
            vec![
                KeywordCall::SetData(keywords),
                get_call(PATH, KEYWORD),
                get_call(PATH, SECOND_KEYWORD),
            ],
            "SetData(), then a GetData() per keyword"
        );
    }

    /// The firmware never parses KEYWORDINFO, so set sends none.
    #[test]
    fn set_refuses_keyword_info_before_any_call() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::default();
        let keywords = format!("{}&DATATYPE=Numeric:1", resp(PATH, KEYWORD, "03"));

        let error =
            set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler).expect_err("KEYWORDINFO");

        assert!(
            matches!(
                error.downcast_ref::<KeywordSetError>(),
                Some(KeywordSetError::KeywordInfo(keyword)) if keyword == KEYWORD
            ),
            "refused: {error:#}"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// KeywordValues serialize as an object per keyword, which names `volatile` only for a
    /// keyword that set wrote in a volatile variable.
    #[test]
    fn keyword_values_serialize_as_an_object_per_keyword() {
        let values = KeywordValues {
            resps: format!(
                "{}&READONLY&{}",
                resp(PATH, KEYWORD, "03"),
                resp(OTHER_PATH, SECOND_KEYWORD, "0100")
            )
            .parse()
            .expect("a <MultiKeywordResp>"),
            volatile: BTreeSet::from([1]),
        };

        assert_eq!(
            serde_json::to_value(&values).expect("serialize"),
            serde_json::json!([
                {
                    "namespace": NAMESPACE,
                    "path": PATH,
                    "keyword": KEYWORD,
                    "value": "03",
                    "read_only": true,
                },
                {
                    "namespace": NAMESPACE,
                    "path": OTHER_PATH,
                    "keyword": SECOND_KEYWORD,
                    "value": "0100",
                    "read_only": false,
                    "volatile": true,
                },
            ]),
            "the keywords"
        );
    }

    /// A keyword's `<KeywordInfoResp>` serializes beside VALUE: numbers as VALUE, `<String>`s as
    /// text, and VALUETYPE in its option.
    #[test]
    fn keyword_values_serialize_the_items_of_keyword_info() {
        let info = format!(
            "&DATATYPE=Buffer&MAX=0010&MIN=0001&STEP=0002&OPTIONVALUE=0100&OPTIONSTRING={}\
             &VALUETYPE=Numeric:2&MFGDEFAULT=0001&SAFEDEFAULT=0002",
            hex_string("A&B=C")
        );
        let values = KeywordValues {
            resps: format!("{}{info}", resp(PATH, KEYWORD, "03"))
                .parse()
                .expect("a <MultiKeywordResp>"),
            volatile: BTreeSet::new(),
        };

        assert_eq!(
            serde_json::to_value(&values).expect("serialize"),
            serde_json::json!([{
                "namespace": NAMESPACE,
                "path": PATH,
                "keyword": KEYWORD,
                "value": "03",
                "read_only": false,
                "data_type": "Buffer",
                "max": "0010",
                "min": "0001",
                "step": "0002",
                "options": [{"value": "0100", "string": "A&B=C", "value_type": "Numeric:2"}],
                "manufacturing_default": "0001",
                "safe_default": "0002",
            }]),
            "the keyword"
        );
    }

    /// set refuses a keyword whose question keeps its value in a volatile variable before any
    /// call, unless VolatileWrites::Allow, with which it writes the keyword and says after its
    /// <KeywordResp> that the value lasts until the next reset or power cycle.
    #[test]
    fn set_writes_a_volatile_variable_only_if_allowed() {
        let lists = [list(PATH, &questions())];
        let keywords = resp(PATH, KEYWORD, "03");
        let written = format!("{keywords} <volatile: lasts until the next reset or power cycle>");
        let refusal =
            "keyword Keyword: EFI variable Store-33333333-3333-3333-3333-333333333333 is \
                       volatile (no EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a \
                       power cycle; pass --allow-volatile to write it anyway";
        let cases = [
            (VolatileWrites::Refuse, Err(refusal.to_owned()), vec![]),
            (
                VolatileWrites::Allow,
                Ok(written),
                vec![
                    KeywordCall::SetData(keywords.clone()),
                    get_call(PATH, KEYWORD),
                ],
            ),
        ];
        for (volatile, want, want_calls) in cases {
            let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

            let got = set_keywords(
                &lists,
                &keywords,
                IncludedStates::empty(),
                SetupPasswordPolicy::Refuse,
                volatile,
                variables_of(VOLATILE),
                &handler,
            )
            .map(|values| values.to_string())
            .map_err(|error| format!("{error:#}"));

            assert_eq!(got, want, "{volatile:?}");
            assert_eq!(handler.calls(), want_calls, "{volatile:?}: calls");
        }
    }

    /// set writes no keyword of an EFI_IFR_FLAG_READ_ONLY question, which SetData() refuses
    /// (EFI_ACCESS_DENIED), whatever `include`: it refuses one before any call, naming no state
    /// that writes it.
    #[test]
    fn set_refuses_a_read_only_question_before_any_call() {
        let lists = [list(
            PATH,
            &[one_of(3, 5, 1), flagged_one_of(5, 6, 1, 0x01)],
        )];
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "03"),
            resp(PATH, SECOND_KEYWORD, "03")
        );
        for include in [IncludedStates::empty(), IncludedStates::all()] {
            let handler =
                MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "01")]);

            let got = set_keywords(
                &lists,
                &keywords,
                include,
                SetupPasswordPolicy::Refuse,
                VolatileWrites::Refuse,
                variables(),
                &handler,
            )
            .map(|values| values.to_string())
            .map_err(|error| format!("{error:#}"));

            assert_eq!(
                got,
                Err(
                    "keyword SecondKeyword: cannot set question \"Second question\": \
                     EFI_IFR_FLAG_READ_ONLY makes it read-only (UEFI 2.11 §33.3.8.2.2)"
                        .to_owned()
                ),
                "--include {include}"
            );
            assert_eq!(handler.calls(), [], "--include {include}: calls");
        }
    }

    /// A failed call names its status, the names of the ProgressErr bits and the character that
    /// Progress points at, if it points into the string or at its NUL.
    #[test]
    fn a_failed_call_names_progress_err_and_where_progress_points() {
        let string = 0x1000;
        let cases = [
            (
                string + 6,
                0x06,
                "(MALFORMED_STRING|KEYWORD_NOT_FOUND), Progress at character 3",
            ),
            (
                string + 20,
                0x8000_0000,
                "(UNDEFINED_PROCESSING_ERROR), Progress at character 10",
            ),
            (
                string + 22,
                0x01,
                "(NAMESPACE_ID_NOT_FOUND), Progress at no character of the string",
            ),
            (
                string - 2,
                0x18,
                "(INCOMPATIBLE_VALUE_DETECTED|ACCESS_NOT_PERMITTED), Progress at no character of \
                 the string",
            ),
        ];
        for (progress, progress_err, want) in cases {
            let error = call_error(
                "SetData()",
                "INVALID_PARAMETER",
                progress_char(progress, string, 10),
                progress_err,
            );

            assert_eq!(
                error.to_string(),
                format!("SetData(): INVALID_PARAMETER, ProgressErr {progress_err:#x} {want}"),
                "Progress at {progress:#x}"
            );
        }
    }

    /// A package list whose IFR the parser ignored may hold a PASSWORD of any variable, so get
    /// and set by keyword fail before any call, as get and set do (PasswordQuestions::of_lists).
    #[test]
    fn get_and_set_fail_closed_on_ifr_that_the_parser_ignores() {
        let mut dropped = list(PATH, &questions());
        dropped.ignored_ifr = vec![IgnoredIfr {
            package_list: dropped.guid,
            offset: 0x40,
            reason: "a FormSet that does not parse".to_owned(),
            passwords: IgnoredPasswords::Declared(Arc::default()),
        }];
        let lists = [dropped];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let got = get(&lists, &handler).map(|values| values.to_string());
        let written = set(
            &lists,
            &resp(PATH, KEYWORD, "03"),
            SetupPasswordPolicy::Bypass,
            &handler,
        )
        .map(|values| values.to_string());

        assert_eq!(
            (got.is_err(), written.is_err(), handler.calls()),
            (true, true, vec![]),
            "fail closed: get {got:?}, set {written:?}"
        );
    }

    /// list(path, ops), as read_db reads it from a form package whose ops `outside`, outside any
    /// FormSet, come before its FormSet.
    fn list_with_outside(path: &str, outside: &[Vec<u8>], ops: &[Vec<u8>]) -> ParsedPackageList {
        let ifr = [
            outside.concat(),
            form_set(&[var_store(1, STORE_GUID, "Store", 16), ops.concat()]),
        ]
        .concat();
        let read = read_db(&package_list_with_guid(
            [0x22; 16],
            &[form_package_of(&ifr), END_PACKAGE.to_vec()].concat(),
        ))
        .expect("read_db")
        .remove(0);
        let list = list(path, &[]);
        ParsedPackageList {
            guid: list.guid,
            device_path: list.device_path,
            strings: list.strings,
            ..read
        }
    }

    /// A PASSWORD outside any FormSet, which edk2-stable202608 ConfigKeywordHandler.c
    /// FindQuestionFromStringId finds, of VarStoreId 1 from VarOffset 6, keeps its password in
    /// Store as FindStorageFromVarId takes it: get and set by keyword fail closed before any call
    /// through variables that reach BootServices, and through those that reach Runtime neither
    /// read nor write its bytes, as get and set do (PasswordQuestions::of_lists).
    #[test]
    fn get_and_set_withhold_a_password_outside_a_form_set() {
        let lists = [list_with_outside(
            PATH,
            &[password_on(9, 9, 1, 6)],
            &questions(),
        )];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
        let got = get(&lists, &handler).map(|values| values.to_string());
        let written = set(
            &lists,
            &resp(PATH, KEYWORD, "03"),
            SetupPasswordPolicy::Bypass,
            &handler,
        )
        .map(|values| values.to_string());
        assert_eq!(
            (got.is_err(), written.is_err(), handler.calls()),
            (true, true, vec![]),
            "fail closed: get {got:?}, set {written:?}"
        );

        let runtime = || {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            let key = VariableKey {
                name: "Store".to_owned(),
                guid: Guid::from(STORE_GUID),
            };
            variables.insert(
                key,
                ATTRIBUTES,
                &[0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            );
            Box::new(variables) as Box<dyn FirmwareVariables>
        };
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "01")]);
        let get_of = |keyword: &str| {
            get_keyword(
                &lists,
                &format!("KEYWORD={keyword}"),
                None,
                &[],
                KeywordInfoSource::Ifr,
                runtime(),
                &handler,
            )
            .map(|values| values.to_string())
            .map_err(|error| format!("{error:#}"))
        };
        assert_eq!(
            get_of(SECOND_KEYWORD),
            Err(
                "keyword SecondKeyword: question \"Second question\" spans bytes that hold a \
                 password, which uefisettings neither reads nor writes"
                    .to_owned()
            ),
            "get over the password through Runtime"
        );
        assert_eq!(
            get_of(KEYWORD),
            Ok(resp(PATH, KEYWORD, "01")),
            "get beside the password through Runtime"
        );
    }

    /// SetData() writes the keywords of a <MultiKeywordResp> one after the other, so set refuses
    /// before any call one whose keywords name one question twice, or questions whose bytes of a
    /// variable overlap; keywords of other bytes it writes.
    #[test]
    fn set_refuses_keywords_of_overlapping_bytes_before_any_call() {
        let lists = [list(PATH, &[one_of(3, 5, 1), uint16_numeric(5, 4)])];
        let store = "Store-33333333-3333-3333-3333-333333333333";
        let cases = [
            (
                "one keyword twice",
                format!(
                    "{}&{}",
                    resp(PATH, KEYWORD, "00"),
                    resp(PATH, KEYWORD, "03")
                ),
                format!(
                    "keywords {KEYWORD} and {KEYWORD} write overlapping bytes of EFI variable \
                     {store}, which SetData() writes one after the other"
                ),
            ),
            (
                "a UINT16 at VarOffset 4 and a UINT8 at 5",
                format!(
                    "{}&{}",
                    resp(PATH, KEYWORD, "03"),
                    resp(PATH, SECOND_KEYWORD, "0002")
                ),
                format!(
                    "keywords {KEYWORD} and {SECOND_KEYWORD} write overlapping bytes of EFI \
                     variable {store}, which SetData() writes one after the other"
                ),
            ),
        ];
        for (name, keywords, refusal) in cases {
            let handler = MemoryKeywordHandler::with(&[
                (PATH, KEYWORD, "01"),
                (PATH, SECOND_KEYWORD, "0001"),
            ]);

            let error =
                set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler).expect_err(name);

            assert_eq!(error.to_string(), refusal, "{name}");
            assert_eq!(handler.calls(), vec![], "{name}: no call");
        }

        let apart = [list(PATH, &[one_of(3, 5, 1), uint16_numeric(5, 6)])];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "0001")]);
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "03"),
            resp(PATH, SECOND_KEYWORD, "0002")
        );
        assert_eq!(
            set(&apart, &keywords, SetupPasswordPolicy::Refuse, &handler)
                .map(|values| values.to_string())
                .map_err(|error| format!("{error:#}")),
            Ok(keywords),
            "a UINT8 at VarOffset 5 and a UINT16 at 6"
        );
    }

    /// A read-back that fails after SetData() succeeded says that SetData() succeeded.
    #[test]
    fn set_says_that_set_data_succeeded_when_the_read_back_fails() {
        let lists = [list(PATH, &questions())];
        let handler = FailingReads(MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]));

        let error = set(
            &lists,
            &resp(PATH, KEYWORD, "03"),
            SetupPasswordPolicy::Refuse,
            &handler,
        )
        .expect_err("a failed read-back");

        assert_eq!(
            handler.0.calls().first(),
            Some(&KeywordCall::SetData(resp(PATH, KEYWORD, "03"))),
            "SetData() ran"
        );
        assert_eq!(
            format!("{error:#}"),
            format!(
                "SetData() of {} succeeded, but GetData() of KEYWORD={KEYWORD} failed: GetData(): \
                 DEVICE_ERROR",
                resp(PATH, KEYWORD, "03")
            ),
            "the error"
        );
    }

    /// The read-back compares VALUEs as numbers: high-order zero digits that GetData() adds or
    /// drops fail no write, another value does.
    #[test]
    fn set_compares_the_values_read_back_as_numbers() {
        let lists = [list(PATH, &[one_of(3, 5, 1), uint16_numeric(5, 6)])];
        let cases = [
            (
                "a UINT8 read back in 4 digits",
                KEYWORD,
                "03",
                "VALUE=03",
                "VALUE=0003",
                true,
            ),
            (
                "a UINT16 read back in 2 digits",
                SECOND_KEYWORD,
                "0003",
                "VALUE=0003",
                "VALUE=03",
                true,
            ),
            (
                "a UINT8 read back as another",
                KEYWORD,
                "03",
                "VALUE=03",
                "VALUE=0004",
                false,
            ),
        ];
        for (name, keyword, value, from, to, same) in cases {
            let handler = RewritingHandler {
                inner: MemoryKeywordHandler::with(&[
                    (PATH, KEYWORD, "01"),
                    (PATH, SECOND_KEYWORD, "0001"),
                ]),
                from: from.to_owned(),
                to: to.to_owned(),
            };

            let result = set(
                &lists,
                &resp(PATH, keyword, value),
                SetupPasswordPolicy::Refuse,
                &handler,
            );

            assert_eq!(result.is_ok(), same, "{name}: {result:?}");
        }
    }

    /// get with PATH reads the list of PATH alone.
    #[test]
    fn get_with_path_reads_that_list_alone() {
        let lists = [list(PATH, &questions()), list(OTHER_PATH, &questions())];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (OTHER_PATH, KEYWORD, "03")]);

        let values = get_keyword(
            &lists,
            &format!("PATH={OTHER_PATH}&KEYWORD={KEYWORD}"),
            None,
            &[],
            KeywordInfoSource::Ifr,
            variables(),
            &handler,
        )
        .expect("get by keyword");

        assert_eq!(
            (values.to_string(), handler.calls()),
            (
                resp(OTHER_PATH, KEYWORD, "03"),
                vec![get_call(OTHER_PATH, KEYWORD)]
            ),
            "the list of PATH alone"
        );
    }

    /// GetData() Results of another NAMESPACE, PATH or KEYWORD are refused.
    #[test]
    fn get_refuses_a_resp_of_another_namespace_path_or_keyword() {
        let lists = [list(PATH, &questions())];
        let cases = [
            (
                "NAMESPACE",
                format!("NAMESPACE={NAMESPACE}&"),
                "NAMESPACE=x-UEFI-other&".to_owned(),
            ),
            (
                "PATH",
                format!("PATH={PATH}&"),
                format!("PATH={OTHER_PATH}&"),
            ),
            (
                "KEYWORD",
                format!("KEYWORD={KEYWORD}&"),
                format!("KEYWORD={SECOND_KEYWORD}&"),
            ),
        ];
        for (name, from, to) in cases {
            let handler = RewritingHandler {
                inner: MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]),
                from,
                to,
            };

            let error = get(&lists, &handler).expect_err(name);

            assert!(
                format!("{error:#}").contains("not that keyword's <KeywordResp> alone"),
                "{name}: {error:#}"
            );
        }
    }

    /// A UINT8 ONE_OF of KEYWORD at VarOffset 5 of VarStore 1 whose options hold 1, its standard
    /// default, and 3, of strings 4 and 6.
    fn defaulted_one_of() -> Vec<u8> {
        let data = [
            question_header_with(3, 3, 1, 5, 0),
            vec![0x00, 0, 3, 1], // Flags UINT8, MinValue, MaxValue, Step
        ]
        .concat();
        [
            operation(ONE_OF, true, &data),
            flagged_option(4, 0x10, 1), // EFI_IFR_OPTION_DEFAULT
            flagged_option(6, 0, 3),
            END.to_vec(),
        ]
        .concat()
    }

    /// A list of PATH holding `ops`, whose en-US strings package holds "One" and "Three" as
    /// strings 4 and 6.
    fn list_with_option_texts(ops: &[Vec<u8>]) -> ParsedPackageList {
        with_option_texts(list(PATH, ops))
    }

    /// `list`, its en-US strings package given "One" and "Three" as strings 4 and 6.
    fn with_option_texts(mut list: ParsedPackageList) -> ParsedPackageList {
        let en_us = &mut list.strings.first_mut().expect("the en-US package").strings;
        en_us.insert(4, "One".into());
        en_us.insert(6, "Three".into());
        list
    }

    /// `text` as a `<String>`: 4 hex digits per CHAR16.
    fn hex_string(text: &str) -> String {
        text.encode_utf16()
            .map(|unit| format!("{unit:04x}"))
            .collect()
    }

    /// KEYWORDINFO gets each `<KeywordResp>` the `<KeywordInfoResp>` that the IFR tells, which
    /// GetData() is not asked for, a ONE_OF's without a `<ValueRange>`; JSON shows its items
    /// beside VALUE.
    #[test]
    fn get_with_keyword_info_adds_the_ifr_info_and_sends_none() {
        let lists = [list_with_option_texts(&[defaulted_one_of()])];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let values = get_keyword(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=All"),
            None,
            &[],
            KeywordInfoSource::Ifr,
            variables(),
            &handler,
        )
        .expect("get with KEYWORDINFO");

        assert_eq!(
            values.to_string(),
            format!(
                "{}&DATATYPE=Numeric:1&OPTIONVALUE=01&OPTIONSTRING={}&OPTIONVALUE=03\
                 &OPTIONSTRING={}&STANDARDDEFAULT=01&DISPLAYNAME={}",
                resp(PATH, KEYWORD, "01"),
                hex_string("One"),
                hex_string("Three"),
                hex_string("Keyword question"),
            ),
            "the <KeywordResp>"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call(PATH, KEYWORD)],
            "GetData() without KEYWORDINFO"
        );
        assert_eq!(
            serde_json::to_value(&values).expect("serialize"),
            serde_json::json!([{
                "namespace": NAMESPACE,
                "path": PATH,
                "keyword": KEYWORD,
                "value": "01",
                "read_only": false,
                "data_type": "Numeric:1",
                "options": [
                    {"value": "01", "string": "One"},
                    {"value": "03", "string": "Three"},
                ],
                "standard_default": "01",
                "display_name": "Keyword question",
            }]),
            "JSON"
        );
    }

    /// An item that the IFR does not tell refuses the get before any GetData(): the texts of the
    /// options, string 4, are in no display language.
    #[test]
    fn get_refuses_keyword_info_it_cannot_tell_before_any_call() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let error = get_keyword(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=ValueAttribute"),
            None,
            &[],
            KeywordInfoSource::Ifr,
            variables(),
            &handler,
        )
        .expect_err("options without texts");

        assert_eq!(
            error.downcast_ref::<KeywordInfoRefusal>(),
            Some(&KeywordInfoRefusal::NoText {
                keyword: KEYWORD.to_owned(),
                id: 4,
            }),
            "the refusal"
        );
        assert_eq!(handler.calls(), Vec::new(), "no GetData()");
    }

    /// From KeywordInfoSource::GetData, GetData() gets the KEYWORDINFO unchanged and its
    /// `<KeywordResp>` is taken as returned, though the IFR tells otherwise or cannot tell; a
    /// failed GetData() fails the get, which never turns to the IFR.
    #[test]
    fn get_from_get_data_sends_keyword_info_and_takes_the_resp_as_returned() {
        let lists = [list(PATH, &questions())];
        let request = format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataTypeValueAttribute");
        let sent = format!("{KEYWORD}&KEYWORDINFO=DataTypeValueAttribute");
        let handler = RewritingHandler {
            inner: MemoryKeywordHandler::with(&[(PATH, &sent, "01")]),
            from: "&KEYWORDINFO=DataTypeValueAttribute&VALUE=01".to_owned(),
            to: "&VALUE=01&DATATYPE=Numeric:2".to_owned(),
        };
        fn get_from_get_data(
            lists: &[ParsedPackageList],
            request: &str,
            handler: &impl KeywordData,
        ) -> Result<KeywordValues> {
            get_keyword(
                lists,
                request,
                None,
                &[],
                KeywordInfoSource::GetData,
                variables(),
                handler,
            )
        }

        let values = get_from_get_data(&lists, &request, &handler).expect("get from GetData()");

        assert_eq!(
            values.to_string(),
            format!("{}&DATATYPE=Numeric:2", resp(PATH, KEYWORD, "01")),
            "GetData()'s <KeywordResp>"
        );
        assert_eq!(
            handler.inner.calls(),
            vec![get_call(PATH, &sent)],
            "GetData() of the KEYWORDINFO"
        );

        let error = get_from_get_data(&lists, &request, &MemoryKeywordHandler::default())
            .expect_err("a failed GetData()");
        assert_eq!(
            format!("{error:#}"),
            "KEYWORD_NOT_FOUND",
            "GetData()'s error"
        );
    }

    /// A `<KeywordInfoResp>` in GetData()'s `<KeywordResp>`, which was asked for none while the
    /// IFR builds the KEYWORDINFO's, is refused rather than replaced.
    #[test]
    fn get_refuses_keyword_info_that_get_data_was_not_asked_for() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01&DATATYPE=Numeric:1")]);

        let error = get_keyword(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType"),
            None,
            &[],
            KeywordInfoSource::Ifr,
            variables(),
            &handler,
        )
        .expect_err("unasked info");

        assert_eq!(
            error.downcast_ref::<KeywordGetError>(),
            Some(&KeywordGetError::UnaskedInfo(format!(
                "{}&DATATYPE=Numeric:1",
                resp(PATH, KEYWORD, "01")
            ))),
            "the refusal"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call(PATH, KEYWORD)],
            "GetData() without KEYWORDINFO"
        );
    }

    /// A request without KEYWORDINFO sends GetData() none from either source: a `<KeywordResp>`
    /// that holds a `<KeywordInfoResp>` is refused, one without it is taken as returned.
    #[test]
    fn get_refuses_keyword_info_to_a_request_without_keyword_info() {
        let lists = [list(PATH, &questions())];
        for source in [KeywordInfoSource::Ifr, KeywordInfoSource::GetData] {
            let get = |value: &str| {
                let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, value)]);
                let got = get_keyword(
                    &lists,
                    &format!("KEYWORD={KEYWORD}"),
                    None,
                    &[],
                    source,
                    variables(),
                    &handler,
                );
                assert_eq!(
                    handler.calls(),
                    vec![get_call(PATH, KEYWORD)],
                    "{source:?}: GetData() without KEYWORDINFO"
                );
                got
            };

            let Err(error) = get("01&DATATYPE=Numeric:1") else {
                panic!("{source:?}: the unasked info taken");
            };
            assert_eq!(
                error.downcast_ref::<KeywordGetError>(),
                Some(&KeywordGetError::UnaskedInfo(format!(
                    "{}&DATATYPE=Numeric:1",
                    resp(PATH, KEYWORD, "01")
                ))),
                "{source:?}: the refusal"
            );
            let values =
                get("01").unwrap_or_else(|error| panic!("{source:?}: get without info: {error:#}"));
            assert_eq!(
                values.to_string(),
                resp(PATH, KEYWORD, "01"),
                "{source:?}: the resp without info"
            );
        }
    }

    /// Option 1 of KEYWORD, its standard default, is under a SUPPRESS_IF on question 11, a byte
    /// of the variable that PASSWORD question 9 withholds, in the FormSet or outside any FormSet
    /// (PasswordQuestions::of_lists): KEYWORDINFO answers the same whatever that byte holds,
    /// while get of the keyword, whose bytes hold no password, passes.
    #[test]
    fn probe_keyword_info_shows_no_withheld_byte() {
        const PASSWORD_GUID: [u8; 16] = [0x44; 16];
        let keyword = [
            operation(
                ONE_OF,
                true,
                &[question_header_with(3, 3, 1, 5, 0), vec![0x00, 0, 3, 1]].concat(),
            ),
            flagged_option(4, 0, 0),
            conditional(
                SUPPRESS_IF,
                eq_id_val_of(11, 1),
                &[flagged_option(4, 0x10, 1)],
            ),
            flagged_option(4, 0, 3),
            END.to_vec(),
        ]
        .concat();
        let store = var_store(2, PASSWORD_GUID, "Password", 20);
        let password = password_on(9, 9, 2, 0);
        let question_11 = one_of(11, 15, 2);
        let in_form_set = [
            store.clone(),
            password.clone(),
            question_11.clone(),
            keyword.clone(),
        ];
        let outside = list_with_outside(PATH, &[password], &[store, question_11, keyword]);

        probe(
            "in its FormSet",
            &[list_with_option_texts(&in_form_set)],
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        probe(
            "outside any FormSet",
            &[with_option_texts(outside)],
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

        /// The probe on `lists`, whose PASSWORD is `placement`, through variables of `reach` and
        /// `interface`.
        fn probe(
            placement: &str,
            lists: &[ParsedPackageList],
            reach: VariableReach,
            interface: VariableInterface,
        ) {
            let answer = |byte: u8, request: &str| {
                let memory = MemoryVariables::new(reach, interface);
                let mut store = [0; 16];
                store[5] = 1;
                let key = |name: &str, guid: [u8; 16]| VariableKey {
                    name: name.to_owned(),
                    guid: Guid::from(guid),
                };
                memory.insert(key("Store", STORE_GUID), ATTRIBUTES, &store);
                let mut password = [0; 20];
                password[15] = byte;
                memory.insert(key("Password", PASSWORD_GUID), ATTRIBUTES, &password);
                let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
                match get_keyword(
                    lists,
                    request,
                    None,
                    &[],
                    KeywordInfoSource::Ifr,
                    Box::new(memory),
                    &handler,
                ) {
                    Ok(values) => values.to_string(),
                    Err(error) => format!("refused: {error:#}"),
                }
            };
            let info = format!("KEYWORD={KEYWORD}&KEYWORDINFO=ValueAttributeDefault");

            assert_eq!(
                answer(0, &format!("KEYWORD={KEYWORD}")),
                resp(PATH, KEYWORD, "01"),
                "{placement}: get of the keyword"
            );
            let refused = answer(0, &info);
            assert!(
                refused.contains("its option of string 4 is unknown")
                    && refused.contains("its bytes hold a password"),
                "{placement}: the withheld byte refuses option 4: {refused}"
            );
            assert_eq!(
                refused,
                answer(1, &info),
                "{placement}: the answers of a withheld byte 0 and 1"
            );
        }
    }

    /// KEYWORDINFO answers no keyword that get refuses for IFR outside any FormSet, and refuses
    /// it as get does, before any call: one that also prompts a CHECKBOX outside any FormSet
    /// (KeywordQuestion::resolve), one whose VarStoreId a VarStore outside any FormSet declares
    /// for another variable (check_get), and any of a list with a PASSWORD outside any FormSet,
    /// read through BootServices (PasswordQuestions::of_lists).
    #[test]
    fn get_with_keyword_info_refuses_as_get_does_for_ifr_outside_a_form_set() {
        let get_of = |lists: &[ParsedPackageList], request: &str| {
            let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
            let got = get_keyword(
                lists,
                request,
                None,
                &[],
                KeywordInfoSource::Ifr,
                variables(),
                &handler,
            )
            .map(|values| values.to_string())
            .map_err(|error| format!("{error:#}"));
            (got, handler.calls())
        };
        let info = format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType");

        assert_eq!(
            get_of(&[list_with_outside(PATH, &[], &questions())], &info),
            (
                Ok(format!("{}&DATATYPE=Numeric:1", resp(PATH, KEYWORD, "01"))),
                vec![get_call(PATH, KEYWORD)]
            ),
            "no IFR outside the FormSet"
        );
        for (name, outside) in [
            ("a CHECKBOX of KEYWORD", checkbox_on(9, 3, 1)),
            (
                "a VarStore 1 of the variable Other",
                var_store(1, [0x44; 16], "Other", 16),
            ),
            ("a PASSWORD of VarStore 1", password_on(9, 9, 1, 6)),
        ] {
            let lists = [list_with_outside(PATH, &[outside], &questions())];
            let (got, calls) = get_of(&lists, &format!("KEYWORD={KEYWORD}"));

            assert!(
                got.is_err() && calls.is_empty(),
                "{name} outside the FormSet: get refuses before any call: {got:?}, {calls:?}"
            );
            assert_eq!(
                get_of(&lists, &info),
                (got, calls),
                "{name} outside the FormSet: KEYWORDINFO refuses as get does"
            );
        }
    }
}
