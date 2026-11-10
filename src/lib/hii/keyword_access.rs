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
use super::config_string::KeywordRequest;
use super::config_string::KeywordResp;
use super::config_string::MultiKeywordRequest;
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
use super::variables::EfivarReader;
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
    fn get_data(&self, namespace_id: &str, keyword_string: &str) -> Result<String, GetDataError>;
    /// SetData() of `keyword_string`, a `<MultiKeywordResp>`.
    fn set_data(&self, keyword_string: &str) -> Result<()>;
}

/// GetData()'s failure, with the Results that it returned: UEFI 2.11 §35.3.3 leaves there the
/// values of the keywords before the one that failed.
#[derive(Debug, Error)]
pub(crate) struct GetDataError {
    pub(crate) results: Option<String>,
    pub(crate) error: anyhow::Error,
}

/// The error alone, without the Results, which may hold a password's VALUE (answers). By hand:
/// thiserror's `#[error]` binds every field, and `-D warnings` refuses `results` unread there.
impl fmt::Display for GetDataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#}", self.error)
    }
}

impl From<anyhow::Error> for GetDataError {
    /// A failure without Results.
    fn from(error: anyhow::Error) -> Self {
        Self {
            results: None,
            error,
        }
    }
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

/// What applies the `<Filter>` of a `<KeywordRequest>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeywordFilterBy {
    /// uefisettings, by the KeywordKind of each question in the HiiDB's IFR, before any
    /// GetData(), which gets no `<Filter>`. This departs from edk2-stable202608 GetData(): the
    /// `<Filter>` selects among the instances of the request (all of them without PATH, UEFI
    /// 2.11 §35.2.1.6), where edk2 fails the call with
    /// KEYWORD_HANDLER_INCOMPATIBLE_VALUE_DETECTED (ConfigKeywordHandler.c:3341-3346); a
    /// CHECKBOX is Boolean by §35.2.1.6's table, where edk2's `Numeric[:n]` passes it
    /// (:597-619); and a request that no instance passes is refused before any GetData(). edk2
    /// GetData() fails a String, Boolean, Date or Time `<DataFilter>` with
    /// KEYWORD_HANDLER_MALFORMED_STRING besides: ExtractFilter knows none of them (:373-496), so
    /// ValidateFilter leaves the element unread (:671-675) and the next ExtractDevicePath refuses
    /// it (:3284-3287).
    #[default]
    Ifr,
    /// GetData(), sent the `<Filter>` unchanged with each instance's PATH, so that on edk2 one
    /// instance that fails it fails the whole GetData()
    GetData,
}

/// How get by keyword answers a KEYWORDINFO and applies a `<Filter>`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KeywordGetOptions {
    /// Where the `<KeywordInfoResp>` of a KEYWORDINFO comes from
    pub info_source: KeywordInfoSource,
    /// What applies a `<Filter>`
    pub filter_by: KeywordFilterBy,
}

/// A refusal of get by keyword, before any GetData(): of a keyword's request or question, or of
/// the `<KeywordInfoResp>` of its KEYWORDINFO that the IFR does not tell.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum KeywordGetRefusal {
    #[error(transparent)]
    Keyword(#[from] KeywordRefusal),
    #[error(transparent)]
    Info(#[from] KeywordInfoRefusal),
}

/// Why get by keyword reads no value.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum KeywordGetError {
    /// Every refusal, in the requests' order, all before any GetData()
    #[error("{}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Refused(Vec<KeywordGetRefusal>),
    #[error("GetData() returned {0}, with a <KeywordInfoResp> that it was not asked for")]
    UnaskedInfo(String),
    #[error(
        "GetData() returned {read}, whose READONLY contradicts the <UsageFilter> of {request}"
    )]
    Usage { request: String, read: String },
}

/// GetData()'s failure, after the `<KeywordResp>`s that it read, with the `<KeywordRequest>`s of
/// the keywords that it read no value of and get's refusals of what it read.
#[derive(Debug, Error)]
pub(crate) struct KeywordGetFailure {
    read: Vec<String>,
    unread: Vec<String>,
    refused: Vec<KeywordGetError>,
    error: anyhow::Error,
}

impl fmt::Display for KeywordGetFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let read = self.read.join("&");
        let unread = self.unread.join("&");
        match (read.is_empty(), unread.is_empty()) {
            // Progress then points after the last keyword, at what GetData() could not parse
            (false, true) => write!(
                f,
                "GetData() read [{read}], a value of every keyword, then failed after the last"
            )?,
            (true, false) => write!(f, "GetData() read no value of [{unread}]")?,
            (false, false) | (true, true) => write!(
                f,
                "GetData() failed after reading [{read}]; it read no value of [{unread}]"
            )?,
        }
        if !self.refused.is_empty() {
            let refused: Vec<String> = self.refused.iter().map(ToString::to_string).collect();
            write!(f, "; get refuses what it read: {}", refused.join("; "))?;
        }
        write!(f, ": {:#}", self.error)
    }
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

/// The values of the keywords of `requests`, a `<MultiKeywordRequest>` of `<KeywordRequest>`s of
/// an optional PATH, a KEYWORD, an optional KEYWORDINFO and an optional `<Filter>`, in
/// `namespace`, else in a language of the prefix "x-UEFI", in `lists`: GetData() of `handler`
/// reads each question that KeywordQuestion::resolve finds and admitted passes, once each passes
/// check_get with the bytes of the PASSWORD questions of `lists` in `variables` withheld, which it
/// never reads, and no request names a question that another names too. With
/// `options.info_source` KeywordInfoSource::Ifr, each `<KeywordResp>` gets the
/// `<KeywordInfoResp>` of KEYWORDINFO from the IFR, its texts in the language that `requested`
/// picks (KeywordQuestion::info). get refuses every request, question and KEYWORDINFO that fails,
/// in the requests' order, all before any GetData() (KeywordGetError::Refused). GetData()
/// gets no KEYWORDINFO, which edk2-stable202608 GetData() fails with EFI_INVALID_PARAMETER and
/// KEYWORD_HANDLER_MALFORMED_STRING (ConfigKeywordHandler.c ValidateFilter leaves it unread,
/// ExtractDevicePath refuses it). With KeywordInfoSource::GetData, GetData() gets the KEYWORDINFO
/// unchanged and its `<KeywordResp>`s are taken as returned. GetData() gets the `<Filter>` with
/// `options.filter_by` KeywordFilterBy::GetData alone. read_all reads them.
pub(crate) fn get_keywords(
    lists: &[ParsedPackageList],
    requests: &str,
    namespace: Option<&str>,
    requested: &[&str],
    options: KeywordGetOptions,
    variables: Box<dyn FirmwareVariables>,
    handler: &impl KeywordData,
) -> Result<KeywordValues> {
    let requests: MultiKeywordRequest = requests.parse()?;
    let namespace = namespace.map(Namespace::try_from).transpose()?;
    let mut reader = PasswordQuestions::of_lists(lists).reader(variables)?;
    // each refusal with the index of its request, which orders them
    let mut refusals = Vec::new();
    let mut resolved = Vec::new();
    for (index, request) in requests.as_slice().iter().enumerate() {
        match KeywordQuestion::resolve(
            lists,
            namespace.as_ref(),
            request.device_path.as_ref(),
            &request.keyword,
            requested,
        ) {
            Ok(found) => resolved.push((index, request, found)),
            Err(refusal) => refusals.push((index, refusal.into())),
        }
    }
    let mut reads = Vec::new();
    for (index, request, found) in &resolved {
        let questions = match admitted(found, request, options.filter_by) {
            Ok(questions) => questions,
            Err(refusal) => {
                refusals.push((*index, refusal.into()));
                continue;
            }
        };
        for question in questions {
            match KeywordRead::checked(question, request, options.info_source, &mut reader) {
                Ok(read) => reads.push(read),
                Err(refusal) => refusals.push((*index, refusal)),
            }
        }
    }
    refusals.sort_by_key(|&(index, _)| index);
    let mut refusals: Vec<KeywordGetRefusal> =
        refusals.into_iter().map(|(_, refusal)| refusal).collect();
    refusals.extend(duplicates(&reads).into_iter().map(KeywordGetRefusal::from));
    if !refusals.is_empty() {
        return Err(KeywordGetError::Refused(refusals).into());
    }
    let values: Vec<KeywordResp> = read_all(handler, &reads, options)?
        .into_iter()
        .zip(reads)
        .map(|(mut resp, read)| {
            if let Some(info) = read.info {
                resp.info = info;
            }
            resp
        })
        .collect();
    Ok(KeywordValues {
        resps: MultiKeywordResp::try_from(values)?,
        volatile: BTreeSet::new(),
    })
}

/// A question that get reads, the request that names it, and the `<KeywordInfoResp>` of its
/// KEYWORDINFO from the IFR, if it takes one.
struct KeywordRead<'q, 'a> {
    question: &'q KeywordQuestion<'a>,
    request: &'q KeywordRequest,
    info: Option<KeywordInfo>,
}

impl<'q, 'a> KeywordRead<'q, 'a> {
    /// The read of `question`, which `request` names, once it passes check_get with `reader`,
    /// with the `<KeywordInfoResp>` of the request's KEYWORDINFO that the IFR tells
    /// (KeywordQuestion::info) if `info_source` is KeywordInfoSource::Ifr.
    fn checked(
        question: &'q KeywordQuestion<'a>,
        request: &'q KeywordRequest,
        info_source: KeywordInfoSource,
        reader: &mut EfivarReader,
    ) -> Result<Self, KeywordGetRefusal> {
        question.check_get(reader)?;
        let info = match (request.info, info_source) {
            (Some(filter), KeywordInfoSource::Ifr) => Some(question.info(filter, reader)?),
            (_, KeywordInfoSource::GetData) | (None, KeywordInfoSource::Ifr) => None,
        };
        Ok(Self {
            question,
            request,
            info,
        })
    }
}

impl KeywordRead<'_, '_> {
    /// The `<KeywordRequest>` that GetData() gets: of the question's PATH and the KEYWORD, with
    /// the request's KEYWORDINFO and `<Filter>` if `options` take them from GetData().
    fn sent(&self, options: KeywordGetOptions) -> KeywordRequest {
        let info = match options.info_source {
            KeywordInfoSource::Ifr => None,
            KeywordInfoSource::GetData => self.request.info,
        };
        let (usage, data) = match options.filter_by {
            KeywordFilterBy::Ifr => (None, None),
            KeywordFilterBy::GetData => (self.request.usage, self.request.data),
        };
        KeywordRequest {
            device_path: Some(self.question.path().clone()),
            keyword: self.request.keyword.clone(),
            info,
            usage,
            data,
        }
    }

    /// Refuses `resp`, GetData()'s `<KeywordResp>` of `sent`, that holds a `<KeywordInfoResp>`
    /// though `sent` has no KEYWORDINFO (KeywordGetError::UnaskedInfo), or whose READONLY
    /// contradicts the request's `<UsageFilter>` (KeywordGetError::Usage).
    fn check(&self, sent: &KeywordRequest, resp: &KeywordResp) -> Result<(), KeywordGetError> {
        if sent.info.is_none() && resp.info != KeywordInfo::default() {
            return Err(KeywordGetError::UnaskedInfo(resp.to_string()));
        }
        if self.request.usage.is_some_and(|usage| usage != resp.usage) {
            return Err(KeywordGetError::Usage {
                request: self.request.to_string(),
                read: resp.to_string(),
            });
        }
        Ok(())
    }
}

/// A refusal of each of `reads` of the NAMESPACE, PATH and KEYWORD of an earlier one, which
/// GetData() would read twice.
fn duplicates(reads: &[KeywordRead<'_, '_>]) -> Vec<KeywordRefusal> {
    let mut seen = BTreeSet::new();
    reads
        .iter()
        .filter(|read| {
            !seen.insert((
                read.question.namespace().to_string(),
                read.question.path().to_string(),
                read.request.keyword.to_string(),
            ))
        })
        .map(|read| KeywordRefusal::Duplicate {
            keyword: read.request.keyword.to_string(),
            path: read.question.path().to_string(),
        })
        .collect()
}

/// The `<KeywordResp>`s of `reads`, in their order, that GetData() of `handler` reads with one
/// call per NAMESPACE, in the order of its first read, of the `<KeywordRequest>` that `options`
/// send (KeywordRead::sent) of each of its reads, in order: GetData() takes one NamespaceId, and
/// edk2-stable202608's keeps the language that a NULL one finds for the first keyword for the
/// rest (GetStringIdFromRecord, ConfigKeywordHandler.c:1380-1395). Refuses the first
/// `<KeywordResp>` of a call that KeywordRead::check refuses. When GetData() fails, no later
/// NAMESPACE is read, and KeywordGetFailure holds the `<KeywordResp>`s read, the requests of the
/// keywords read no value of, and the refusals of what was read.
fn read_all(
    handler: &impl KeywordData,
    reads: &[KeywordRead<'_, '_>],
    options: KeywordGetOptions,
) -> Result<Vec<KeywordResp>> {
    let mut namespaces: Vec<&Namespace> = Vec::new();
    for read in reads {
        if !namespaces.contains(&read.question.namespace()) {
            namespaces.push(read.question.namespace());
        }
    }
    let mut values: Vec<Option<KeywordResp>> = vec![None; reads.len()];
    for namespace in namespaces {
        let group: Vec<(usize, &KeywordRead<'_, '_>)> = reads
            .iter()
            .enumerate()
            .filter(|(_, read)| read.question.namespace() == namespace)
            .collect();
        let requests = MultiKeywordRequest::try_from(
            group
                .iter()
                .map(|(_, read)| read.sent(options))
                .collect::<Vec<_>>(),
        )?;
        let (resps, failure) = match read_keywords(handler, namespace, &requests) {
            Ok(resps) => (resps, None),
            Err(ReadFailure::GetData { read, error }) => (read, Some(error)),
            Err(ReadFailure::Results(error)) => return Err(error),
        };
        let mut refused = Vec::new();
        for (((index, read), sent), resp) in group.iter().zip(requests.as_slice()).zip(resps) {
            if let Err(refusal) = read.check(sent, &resp) {
                refused.push(refusal);
            }
            if let Some(value) = values.get_mut(*index) {
                *value = Some(resp);
            }
        }
        if let Some(error) = failure {
            return Err(KeywordGetFailure {
                read: values.iter().flatten().map(ToString::to_string).collect(),
                unread: reads
                    .iter()
                    .zip(&values)
                    .filter(|(_, value)| value.is_none())
                    .map(|(read, _)| read.sent(options).to_string())
                    .collect(),
                refused,
                error,
            }
            .into());
        }
        if let Some(refusal) = refused.into_iter().next() {
            return Err(refusal.into());
        }
    }
    values
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| anyhow!("GetData() read no value of a keyword"))
}

/// The questions of `found`, those of `request`'s keyword, that get reads: with `filter_by`
/// KeywordFilterBy::Ifr, those whose KeywordKind passes the request's `<Filter>`, refused when
/// none does (KeywordRefusal::Filtered); every one with KeywordFilterBy::GetData, or of a request
/// without a `<Filter>`.
fn admitted<'q, 'a>(
    found: &'q [KeywordQuestion<'a>],
    request: &KeywordRequest,
    filter_by: KeywordFilterBy,
) -> Result<Vec<&'q KeywordQuestion<'a>>, KeywordRefusal> {
    match (filter_by, request.usage.is_some() || request.data.is_some()) {
        (KeywordFilterBy::Ifr, true) => {}
        (KeywordFilterBy::Ifr, false) | (KeywordFilterBy::GetData, _) => {
            return Ok(found.iter().collect())
        }
    }
    let mut questions = Vec::new();
    let mut filtered = Vec::new();
    for question in found {
        let kind = question.kind()?;
        match request.admits(kind.usage, kind.data_type) {
            true => questions.push(question),
            false => filtered.push(format!("PATH={}: {kind}", question.path())),
        }
    }
    match questions.is_empty() {
        true => Err(KeywordRefusal::Filtered {
            keyword: request.keyword.to_string(),
            request: request.to_string(),
            found: filtered,
        }),
        false => Ok(questions),
    }
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
    let request = KeywordRequest {
        device_path: Some(resp.device_path.clone()),
        keyword: resp.keyword.clone(),
        info: None,
        usage: None,
        data: None,
    };
    let requests = MultiKeywordRequest::try_from(vec![request])?;
    read_keywords(handler, &resp.namespace, &requests)
        .map_err(ReadFailure::into_error)?
        .pop()
        .ok_or_else(|| anyhow!("GetData() of {requests} read no value"))
}

/// Why read_keywords read no value of some keyword.
enum ReadFailure {
    /// GetData() failed, after the `<KeywordResp>`s of the first requests, which its Results held
    GetData {
        read: Vec<KeywordResp>,
        error: anyhow::Error,
    },
    /// Results that are not the `<KeywordResp>`s of the requests
    Results(anyhow::Error),
}

impl ReadFailure {
    /// The error, without the `<KeywordResp>`s that GetData() read before it.
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::GetData { read: _, error } | Self::Results(error) => error,
        }
    }
}

/// The `<KeywordResp>`s that GetData() of `handler` returns for `requests`, each of a PATH and a
/// KEYWORD, asked with the NamespaceId of `namespace`: UEFI 2.11 §35.3.3 takes NamespaceId as the
/// language alone, edk2-stable202608 ExtractNameSpace (ConfigKeywordHandler.c:202, from GetData()
/// at :3251) as a `<NameSpaceId>`, which this sends. They must be one per request, in order.
/// No error holds the text of the Results, which may be the VALUE of a question that get does
/// not read, such as a PASSWORD (answers).
fn read_keywords(
    handler: &impl KeywordData,
    namespace: &Namespace,
    requests: &MultiKeywordRequest,
) -> Result<Vec<KeywordResp>, ReadFailure> {
    let GetDataError { results, error } =
        match handler.get_data(&format!("NAMESPACE={namespace}"), &requests.to_string()) {
            Ok(results) => {
                let resps = answers(namespace, requests, &results).map_err(ReadFailure::Results)?;
                return match resps.len() == requests.as_slice().len() {
                    true => Ok(resps),
                    false => Err(ReadFailure::Results(anyhow!(
                        "GetData() of {requests} succeeded with a <KeywordResp> of only the first \
                         {} keywords",
                        resps.len()
                    ))),
                };
            }
            Err(failure) => failure,
        };
    let read = match results.as_deref() {
        // as no Results: a <MultiKeywordResp> holds at least one <KeywordResp>
        None | Some("") => Vec::new(),
        Some(results) => answers(namespace, requests, results).map_err(|reason| {
            ReadFailure::Results(reason.context(format!("GetData() failed: {error:#}")))
        })?,
    };
    Err(ReadFailure::GetData { read, error })
}

/// The `<KeywordResp>`s of `results`, GetData()'s `<MultiKeywordResp>` for `requests`, refused
/// unless each is of `namespace` and of the PATH and KEYWORD of the request in its place, no more
/// than the requests: UEFI 2.11 §35.3.3 leaves out the keywords from the one that failed. The
/// refusal names the place, NAMESPACE, PATH and KEYWORD of each `<KeywordResp>` that is not of
/// its request, or where `results` fail to parse, never their text.
fn answers(
    namespace: &Namespace,
    requests: &MultiKeywordRequest,
    results: &str,
) -> Result<Vec<KeywordResp>> {
    let resps = MultiKeywordResp::from_results(results)
        .with_context(|| {
            format!("GetData() of {requests} returned Results that are no <MultiKeywordResp>")
        })?
        .into_vec();
    let unanswered: Vec<String> = resps
        .iter()
        .enumerate()
        .filter_map(|(at, resp)| {
            let place = match requests.as_slice().get(at) {
                Some(request)
                    if resp.namespace == *namespace
                        && request.device_path.as_ref() == Some(&resp.device_path)
                        && resp.keyword == request.keyword =>
                {
                    return None
                }
                Some(_) => "",
                None => " past the last request",
            };
            Some(format!(
                "<KeywordResp> {} of NAMESPACE={}&PATH={}&KEYWORD={}{place}",
                at + 1,
                resp.namespace,
                resp.device_path,
                resp.keyword
            ))
        })
        .collect();
    match unanswered.is_empty() {
        true => Ok(resps),
        false => Err(anyhow!(
            "GetData() of {requests} returned {}: not the <KeywordResp> of each keyword asked \
             for, in order",
            unanswered.join("; ")
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
    use crate::hii::config_string::KeywordPath;
    use crate::hii::forms::ifr_fixtures::checkbox_on;
    use crate::hii::forms::ifr_fixtures::conditional;
    use crate::hii::forms::ifr_fixtures::eq_id_val_of;
    use crate::hii::forms::ifr_fixtures::flagged_option;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::form_set_with_guid;
    use crate::hii::forms::ifr_fixtures::in_unknown_scope;
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
    use crate::hii::forms::ifr_fixtures::CHECKBOX;
    use crate::hii::forms::ifr_fixtures::DATE;
    use crate::hii::forms::ifr_fixtures::END;
    use crate::hii::forms::ifr_fixtures::NUMERIC;
    use crate::hii::forms::ifr_fixtures::ONE_OF;
    use crate::hii::forms::ifr_fixtures::ORDERED_LIST;
    use crate::hii::forms::ifr_fixtures::SHORT_VAR_STORE_GUID;
    use crate::hii::forms::ifr_fixtures::SUPPRESS_IF;
    use crate::hii::forms::ifr_fixtures::TIME;
    use crate::hii::forms::keywords::KeywordRefusal;
    use crate::hii::forms::keywords::QuestionRefusal;
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
    /// The device path of no package list
    const THIRD_PATH: &str = "01041400444444444444444444444444444444447fff0400";
    const NAMESPACE: &str = "x-UEFI-ns";
    const OTHER_NAMESPACE: &str = "x-UEFI-AB";
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
    /// EFI_IFR_FLAG_READ_ONLY
    const READ_ONLY: u8 = 0x01;

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
    /// calls. Its GetData() reads each request whatever `<Filter>` follows it, and fails at the
    /// first that it has no VALUE of, with the `<KeywordResp>`s before it in Results, as UEFI
    /// 2.11 §35.3.3 leaves them. Its SetData() fails with `set_failure` if given, and else stores
    /// the VALUEs unless `stale`.
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
        fn get_data(
            &self,
            namespace_id: &str,
            keyword_string: &str,
        ) -> Result<String, GetDataError> {
            self.calls.borrow_mut().push(KeywordCall::GetData {
                namespace_id: namespace_id.to_owned(),
                keyword_string: keyword_string.to_owned(),
            });
            let namespace = namespace_id
                .strip_prefix("NAMESPACE=")
                .ok_or_else(|| anyhow!("MALFORMED_STRING"))?;
            let requests: MultiKeywordRequest =
                keyword_string.parse().map_err(anyhow::Error::from)?;
            let mut resps = Vec::new();
            for request in requests.as_slice() {
                let key = KeywordRequest {
                    usage: None,
                    data: None,
                    ..request.clone()
                }
                .to_string();
                let Some(value) = self.values.borrow().get(&key).cloned() else {
                    return Err(GetDataError {
                        results: (!resps.is_empty()).then(|| resps.join("&")),
                        error: anyhow!("KEYWORD_NOT_FOUND"),
                    });
                };
                resps.push(format!("NAMESPACE={namespace}&{key}&VALUE={value}"));
            }
            Ok(resps.join("&"))
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
        fn get_data(
            &self,
            namespace_id: &str,
            keyword_string: &str,
        ) -> Result<String, GetDataError> {
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
        fn get_data(
            &self,
            namespace_id: &str,
            keyword_string: &str,
        ) -> Result<String, GetDataError> {
            self.0.get_data(namespace_id, keyword_string)?;
            Err(anyhow!("GetData(): DEVICE_ERROR").into())
        }

        fn set_data(&self, keyword_string: &str) -> Result<()> {
            self.0.set_data(keyword_string)
        }
    }

    /// A package list of the device path `path` that declares VarStore 1 and holds `ops`, whose
    /// x-UEFI-ns strings package names strings 3 and 5 KEYWORD and SECOND_KEYWORD.
    fn list(path: &str, ops: &[Vec<u8>]) -> ParsedPackageList {
        list_in(path, NAMESPACE, ops)
    }

    /// list(), its keywords in a strings package of `namespace`.
    fn list_in(path: &str, namespace: &str, ops: &[Vec<u8>]) -> ParsedPackageList {
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
                strings(namespace.as_bytes(), KEYWORD, SECOND_KEYWORD),
            ],
            forms: vec![parse_form_set(
                &[vec![var_store(1, STORE_GUID, "Store", 16)], ops.to_vec()].concat(),
            )],
            ignored_ifr: Vec::new(),
            outside_ifr: Vec::new(),
            malformed_outside_stores: Vec::new(),
            disabled_forms: Vec::new(),
            first_var_stores: Vec::new(),
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
        resp_in(NAMESPACE, path, keyword, value)
    }

    fn resp_in(namespace: &str, path: &str, keyword: &str, value: &str) -> String {
        format!("NAMESPACE={namespace}&PATH={path}&KEYWORD={keyword}&VALUE={value}")
    }

    fn get_call(path: &str, keyword: &str) -> KeywordCall {
        get_call_of(NAMESPACE, &keyword_string(path, keyword))
    }

    fn get_call_of(namespace: &str, keyword_string: &str) -> KeywordCall {
        KeywordCall::GetData {
            namespace_id: format!("NAMESPACE={namespace}"),
            keyword_string: keyword_string.to_owned(),
        }
    }

    fn get(lists: &[ParsedPackageList], handler: &impl KeywordData) -> Result<KeywordValues> {
        get_keywords(
            lists,
            &format!("KEYWORD={KEYWORD}"),
            None,
            &[],
            KeywordGetOptions::default(),
            variables(),
            handler,
        )
    }

    /// The options of the KEYWORDINFO from `info_source`, the `<Filter>` by `filter_by`.
    fn options(info_source: KeywordInfoSource, filter_by: KeywordFilterBy) -> KeywordGetOptions {
        KeywordGetOptions {
            info_source,
            filter_by,
        }
    }

    /// get_keywords of `request` with `options`, reading variables().
    fn get_with(
        lists: &[ParsedPackageList],
        request: &str,
        options: KeywordGetOptions,
        handler: &impl KeywordData,
    ) -> Result<KeywordValues> {
        get_keywords(lists, request, None, &[], options, variables(), handler)
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

    /// GetData() reads the questions that check_get passed: by the NAMESPACE of their strings
    /// package and the PATH of each package list, which the request names neither of, in one
    /// call.
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
            vec![get_call_of(
                NAMESPACE,
                &format!(
                    "{}&{}",
                    keyword_string(PATH, KEYWORD),
                    keyword_string(OTHER_PATH, KEYWORD)
                )
            )],
            "one GetData() of NAMESPACE, and PATH and KEYWORD per list"
        );
    }

    /// Every question passes check_get before the first GetData().
    #[test]
    fn get_checks_every_question_before_any_call() {
        let undeclared = [one_of(3, 5, 9)];
        let lists = [list(PATH, &questions()), list(OTHER_PATH, &undeclared)];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (OTHER_PATH, KEYWORD, "01")]);

        let refusals = refusals_of(get(&lists, &handler));

        assert!(
            matches!(
                refusals.as_deref(),
                Some([KeywordGetRefusal::Keyword(KeywordRefusal::Question { .. })])
            ),
            "a question of an undeclared VarStore refused: {refusals:?}"
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
            format!("{error:#}").contains("not the <KeywordResp> of each keyword asked for"),
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

    /// A DATE of KEYWORD at VarOffset 8 and an ORDERED_LIST of SECOND_KEYWORD at VarOffset 12 of
    /// VarStore 1, of at most 3 items of the UINT8 options 1, 2 and 3.
    fn date_and_list() -> Vec<Vec<u8>> {
        let date = [question_header_with(3, 3, 1, 8, 0), vec![0x00]].concat();
        let list = [question_header_with(5, 5, 1, 12, 0), vec![3, 0x00]].concat();
        vec![
            operation(DATE, false, &date),
            [
                operation(ORDERED_LIST, true, &list),
                flagged_option(5, 0, 1),
                flagged_option(5, 0, 2),
                flagged_option(5, 0, 3),
                END.to_vec(),
            ]
            .concat(),
        ]
    }

    /// set by keyword writes a DATE's and an ORDERED_LIST's VALUEs in one SetData(), as given,
    /// and shows what GetData() reads back, as get shows it: text and JSON alike.
    #[test]
    fn set_writes_a_date_and_an_ordered_list_by_keyword() {
        let lists = [list(PATH, &date_and_list())];
        let handler = MemoryKeywordHandler::default();
        let written = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "1f0c07e9"),
            resp(PATH, SECOND_KEYWORD, "000103")
        );

        let values =
            set(&lists, &written, SetupPasswordPolicy::Refuse, &handler).expect("set by keyword");

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
        let json = serde_json::to_value(&values).expect("serialize");
        assert_eq!(
            [&json[0]["value"], &json[1]["value"]],
            ["1f0c07e9", "000103"],
            "JSON VALUEs"
        );
    }

    /// set by keyword refuses an ORDERED_LIST's VALUE that fills a container after an empty one
    /// before any call, though the DATE's before it is one that set writes.
    #[test]
    fn set_refusing_an_ordered_list_after_a_date_makes_no_call() {
        let lists = [list(PATH, &date_and_list())];
        let handler = MemoryKeywordHandler::default();
        let keywords = format!(
            "{}&{}",
            resp(PATH, KEYWORD, "1f0c07e9"),
            resp(PATH, SECOND_KEYWORD, "010003")
        );

        let error = set(&lists, &keywords, SetupPasswordPolicy::Refuse, &handler)
            .expect_err("a container after an empty one");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "keyword {SECOND_KEYWORD}: VALUE=010003 of question \"Second question\": cannot \
                 set question \"Second question\": a container after an empty one holds a value, \
                 where set writes 0 after the last item (UEFI 2.11 §33.3.8.3.53)"
            ),
            "the ORDERED_LIST's refusal"
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
            get_keywords(
                &lists,
                &format!("KEYWORD={keyword}"),
                None,
                &[],
                KeywordGetOptions::default(),
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
        list_of_ifr(path, &ifr)
    }

    /// The package list of the device path `path` and the strings of list(path, ops), as read_db
    /// reads it from a form package of the IFR `ifr`.
    fn list_of_ifr(path: &str, ifr: &[u8]) -> ParsedPackageList {
        let read = read_db(&package_list_with_guid(
            [0x22; 16],
            &[form_package_of(ifr), END_PACKAGE.to_vec()].concat(),
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

    /// A FormSet nested in another is another FormSet either way round, as edk2-stable202608
    /// ConfigKeywordHandler.c FindStorageFromVarId walks the form package op by op (:1520-1567):
    /// where the keyword's FormSet declares Store for VarStoreId 1 and then nests a FormSet whose
    /// PASSWORD is on id 1 from VarOffset 0, on its own Pw, and where that PASSWORD's FormSet nests
    /// the keyword's first, Store is the first VarStore of id 1 and keeps the password: get by
    /// keyword of the ONE_OF over Store's byte 5 fails before any call, through variables of
    /// either reach, with the reader that get_keywords builds. A nested PASSWORD of another
    /// VarStoreId keeps none of Store, which the keyword reads.
    #[test]
    fn get_withholds_a_password_in_the_first_var_store_of_a_nesting_or_nested_form_set() {
        let store = var_store(1, STORE_GUID, "Store", 16);
        let pw = var_store(1, [0x44; 16], "Pw", 16);
        let password = password_on(9, 9, 1, 0);
        let password_form_set = |children: &[Vec<u8>]| form_set_with_guid([0x66; 16], children);
        let password_nested_in_keyword_s = form_set(&[
            store.clone(),
            one_of(3, 5, 1),
            password_form_set(&[pw.clone(), password.clone()]),
        ]);
        let keyword_s_nested_in_password_s =
            password_form_set(&[form_set(&[store.clone(), one_of(3, 5, 1)]), pw, password]);
        let other_id_nested = form_set(&[
            store,
            one_of(3, 5, 1),
            password_form_set(&[var_store(2, [0x44; 16], "Pw", 16), password_on(9, 9, 2, 0)]),
        ]);
        for (reach, interface) in [
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
            (VariableReach::Runtime, VariableInterface::Efivarfs),
        ] {
            let variables = || {
                let variables = MemoryVariables::new(reach, interface);
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
            for (case, ifr, want) in [
                (
                    "the PASSWORD's FormSet nested in the keyword's after Store",
                    password_nested_in_keyword_s.clone(),
                    Err(
                        "keyword Keyword: question \"Keyword question\" spans bytes that hold a \
                         password, which uefisettings neither reads nor writes"
                            .to_owned(),
                    ),
                ),
                (
                    "the keyword's FormSet nested first in the PASSWORD's",
                    keyword_s_nested_in_password_s.clone(),
                    Err(
                        "keyword Keyword: question \"Keyword question\" spans bytes that hold a \
                         password, which uefisettings neither reads nor writes"
                            .to_owned(),
                    ),
                ),
                (
                    "a PASSWORD of another VarStoreId nested in the keyword's FormSet",
                    other_id_nested.clone(),
                    Ok(resp(PATH, KEYWORD, "01")),
                ),
            ] {
                let lists = [list_of_ifr(PATH, &ifr)];
                let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
                let got = get_keywords(
                    &lists,
                    &format!("KEYWORD={KEYWORD}"),
                    None,
                    &[],
                    KeywordGetOptions::default(),
                    variables(),
                    &handler,
                )
                .map(|values| values.to_string())
                .map_err(|error| format!("{error:#}"));
                let calls = match want.is_ok() {
                    true => vec![get_call(PATH, KEYWORD)],
                    false => vec![],
                };

                assert_eq!(got, want, "{case}: {reach:?}");
                assert_eq!(handler.calls(), calls, "{case}: {reach:?}: calls");
            }
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
            get_keywords(
                &lists,
                &format!("KEYWORD={keyword}"),
                None,
                &[],
                KeywordGetOptions::default(),
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

        let values = get_keywords(
            &lists,
            &format!("PATH={OTHER_PATH}&KEYWORD={KEYWORD}"),
            None,
            &[],
            KeywordGetOptions::default(),
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
                format!("{error:#}").contains("not the <KeywordResp> of each keyword asked for"),
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

        let values = get_keywords(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=All"),
            None,
            &[],
            KeywordGetOptions::default(),
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

        let refusals = refusals_of(get_keywords(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=ValueAttribute"),
            None,
            &[],
            KeywordGetOptions::default(),
            variables(),
            &handler,
        ));

        assert_eq!(
            refusals,
            Some(vec![KeywordInfoRefusal::NoText {
                keyword: KEYWORD.to_owned(),
                id: 4,
            }
            .into()]),
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
            get_keywords(
                lists,
                request,
                None,
                &[],
                options(KeywordInfoSource::GetData, KeywordFilterBy::Ifr),
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
            format!(
                "GetData() read no value of [{}]: KEYWORD_NOT_FOUND",
                keyword_string(PATH, &sent)
            ),
            "GetData()'s error"
        );
    }

    /// A `<KeywordInfoResp>` in GetData()'s `<KeywordResp>`, which was asked for none while the
    /// IFR builds the KEYWORDINFO's, is refused rather than replaced.
    #[test]
    fn get_refuses_keyword_info_that_get_data_was_not_asked_for() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01&DATATYPE=Numeric:1")]);

        let error = get_keywords(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType"),
            None,
            &[],
            KeywordGetOptions::default(),
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
                let got = get_keywords(
                    &lists,
                    &format!("KEYWORD={KEYWORD}"),
                    None,
                    &[],
                    options(source, KeywordFilterBy::Ifr),
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
                match get_keywords(
                    lists,
                    request,
                    None,
                    &[],
                    KeywordGetOptions::default(),
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
            let got = get_keywords(
                lists,
                request,
                None,
                &[],
                KeywordGetOptions::default(),
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

    /// The refusals of `result`, if get refused it.
    fn refusals_of(result: Result<KeywordValues>) -> Option<Vec<KeywordGetRefusal>> {
        match result.err()?.downcast::<KeywordGetError>() {
            Ok(KeywordGetError::Refused(refusals)) => Some(refusals),
            Ok(_) | Err(_) => None,
        }
    }

    /// A read-write question of KEYWORD in the list of PATH and a read-only one in that of
    /// OTHER_PATH, both UINT8 ONE_OFs.
    fn read_write_and_read_only() -> [ParsedPackageList; 2] {
        [
            list(PATH, &[one_of(3, 5, 1)]),
            list(OTHER_PATH, &[flagged_one_of(3, 5, 1, READ_ONLY)]),
        ]
    }

    /// By the IFR, get reads only the questions that pass the request's `<Filter>`, and sends
    /// GetData() none; it refuses a request none of whose questions passes it, before any call.
    #[test]
    fn get_reads_only_the_questions_that_pass_the_filter_by_the_ifr() {
        let lists = read_write_and_read_only();
        let read_write = resp(PATH, KEYWORD, "01");
        let read_only = format!("{}&READONLY", resp(OTHER_PATH, KEYWORD, "03"));
        let cases = [
            ("ReadOnly", vec![OTHER_PATH], vec![read_only.clone()]),
            ("ReadWrite&Numeric:1", vec![PATH], vec![read_write.clone()]),
            (
                "Numeric",
                vec![PATH, OTHER_PATH],
                vec![read_write, read_only],
            ),
        ];
        for (filter, paths, expected) in cases {
            let handler = MemoryKeywordHandler::with(&[
                (PATH, KEYWORD, "01"),
                (OTHER_PATH, KEYWORD, "03&READONLY"),
            ]);

            let values = get_with(
                &lists,
                &format!("KEYWORD={KEYWORD}&{filter}"),
                KeywordGetOptions::default(),
                &handler,
            )
            .unwrap_or_else(|error| panic!("get of {filter}: {error:#}"));

            assert_eq!(
                values.to_string(),
                expected.join("&"),
                "{filter}: the values"
            );
            let sent: Vec<String> = paths
                .iter()
                .map(|path| keyword_string(path, KEYWORD))
                .collect();
            assert_eq!(
                handler.calls(),
                vec![get_call_of(NAMESPACE, &sent.join("&"))],
                "{filter}: GetData() of the questions that pass, without a <Filter>"
            );
        }
        for filter in ["Boolean", "Numeric:2", "ReadOnly&Buffer", "Buffer"] {
            let handler = MemoryKeywordHandler::default();
            let request = format!("KEYWORD={KEYWORD}&{filter}");

            let refusals = refusals_of(get_with(
                &lists,
                &request,
                KeywordGetOptions::default(),
                &handler,
            ));

            assert_eq!(
                refusals,
                Some(vec![KeywordRefusal::Filtered {
                    keyword: KEYWORD.to_owned(),
                    request: request.clone(),
                    found: vec![
                        format!("PATH={PATH}: ReadWrite&Numeric:1"),
                        format!("PATH={OTHER_PATH}: ReadOnly&Numeric:1"),
                    ],
                }
                .into()]),
                "{filter}: no question passes"
            );
            assert_eq!(handler.calls(), vec![], "{filter}: no call");
        }
    }

    /// A question that the IFR shows the `<Filter>` takes out is not checked: check_get would
    /// refuse this one, of an undeclared VarStore.
    #[test]
    fn get_takes_out_the_questions_of_the_filter_before_checking_them() {
        let lists = [
            list(PATH, &questions()),
            list(OTHER_PATH, &[flagged_one_of(3, 5, 9, READ_ONLY)]),
        ];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (OTHER_PATH, KEYWORD, "01")]);
        let get_of =
            |request: &str| get_with(&lists, request, KeywordGetOptions::default(), &handler);

        let values = get_of(&format!("KEYWORD={KEYWORD}&ReadWrite")).expect("the read-write one");

        assert_eq!(
            values.to_string(),
            resp(PATH, KEYWORD, "01"),
            "the question that passes"
        );
        assert!(
            matches!(
                refusals_of(get_of(&format!("KEYWORD={KEYWORD}"))).as_deref(),
                Some([KeywordGetRefusal::Keyword(KeywordRefusal::Question { .. })])
            ),
            "refused without the <Filter>"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call(PATH, KEYWORD)],
            "GetData() of the question that passes alone"
        );
    }

    /// GetData()'s READONLY must be that of the `<UsageFilter>`, whichever applies it.
    #[test]
    fn get_refuses_a_readonly_of_get_data_that_contradicts_the_usage_filter() {
        let lists = [list(PATH, &[flagged_one_of(3, 5, 1, READ_ONLY)])];
        for filter_by in [KeywordFilterBy::Ifr, KeywordFilterBy::GetData] {
            let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
            let get_of = |request: &str| {
                get_with(
                    &lists,
                    request,
                    options(KeywordInfoSource::Ifr, filter_by),
                    &handler,
                )
            };
            let request = format!("KEYWORD={KEYWORD}&ReadOnly");

            let error = get_of(&request).expect_err("a READONLY that differs");

            assert_eq!(
                error.downcast_ref::<KeywordGetError>(),
                Some(&KeywordGetError::Usage {
                    request,
                    read: resp(PATH, KEYWORD, "01"),
                }),
                "{filter_by:?}: the refusal"
            );
            assert_eq!(
                get_of(&format!("KEYWORD={KEYWORD}&Numeric:1"))
                    .map(|values| values.to_string())
                    .ok(),
                Some(resp(PATH, KEYWORD, "01")),
                "{filter_by:?}: no <UsageFilter>, no check"
            );
        }
    }

    /// With the `<Filter>` by GetData(), get sends it unchanged with each question's PATH and
    /// reads every question, the IFR's KeywordKind untested.
    #[test]
    fn get_by_get_data_sends_each_filter_unchanged() {
        let lists = read_write_and_read_only();
        for filter in ["Numeric:1", "Boolean", "Date"] {
            let handler =
                MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (OTHER_PATH, KEYWORD, "03")]);

            let values = get_with(
                &lists,
                &format!("KEYWORD={KEYWORD}&{filter}"),
                options(KeywordInfoSource::Ifr, KeywordFilterBy::GetData),
                &handler,
            )
            .unwrap_or_else(|error| panic!("get of {filter}: {error:#}"));

            assert_eq!(
                values.to_string(),
                format!(
                    "{}&{}",
                    resp(PATH, KEYWORD, "01"),
                    resp(OTHER_PATH, KEYWORD, "03")
                ),
                "{filter}: what GetData() returns"
            );
            assert_eq!(
                handler.calls(),
                vec![get_call_of(
                    NAMESPACE,
                    &format!(
                        "{}&{filter}&{}&{filter}",
                        keyword_string(PATH, KEYWORD),
                        keyword_string(OTHER_PATH, KEYWORD)
                    )
                )],
                "{filter}: the <Filter> sent with each PATH"
            );
        }
    }

    /// Whichever applies the `<Filter>`, every question passes check_get before any GetData():
    /// a PASSWORD, and a question over the bytes of one, are refused.
    #[test]
    fn get_checks_every_question_before_any_call_whichever_applies_the_filter() {
        let lists = [list(
            PATH,
            &[vec![one_of(5, 6, 1)], vec![password_on(9, 3, 1, 6)]].concat(),
        )];
        let cases = [
            (
                KEYWORD,
                "Buffer",
                "keyword Keyword: question \"Keyword question\" is a PASSWORD, which uefisettings \
                 neither reads nor writes",
            ),
            (
                SECOND_KEYWORD,
                "ReadWrite&Numeric:1",
                "keyword SecondKeyword: question \"Second question\" spans bytes that hold a \
                 password, which uefisettings neither reads nor writes",
            ),
        ];
        for filter_by in [KeywordFilterBy::Ifr, KeywordFilterBy::GetData] {
            for (keyword, filter, refusal) in cases {
                let handler = MemoryKeywordHandler::with(&[
                    (PATH, KEYWORD, "01"),
                    (PATH, SECOND_KEYWORD, "01"),
                ]);

                let error = get_with(
                    &lists,
                    &format!("KEYWORD={keyword}&{filter}"),
                    options(KeywordInfoSource::Ifr, filter_by),
                    &handler,
                )
                .expect_err("a password");

                assert_eq!(
                    format!("{error:#}"),
                    refusal,
                    "{filter_by:?}, {keyword}: the refusal"
                );
                assert_eq!(handler.calls(), vec![], "{filter_by:?}, {keyword}: no call");
            }
        }
    }

    /// The IFR types a CHECKBOX Boolean by its op code, also one that is left undecoded without
    /// its Flags: Boolean passes it, Buffer does not.
    #[test]
    fn get_filters_an_undecoded_checkbox_as_boolean() {
        let data = question_header_with(3, 3, 1, 5, 0);
        let undecoded = in_unknown_scope(&operation(CHECKBOX, false, &data));
        let lists = [list(PATH, &[undecoded])];
        let get_of = |filter: &str, handler: &MemoryKeywordHandler| {
            get_with(
                &lists,
                &format!("KEYWORD={KEYWORD}&{filter}"),
                KeywordGetOptions::default(),
                handler,
            )
        };

        let read = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
        assert_eq!(
            get_of("Boolean", &read)
                .map(|values| values.to_string())
                .map_err(|error| format!("{error:#}")),
            Ok(resp(PATH, KEYWORD, "01")),
            "Boolean"
        );
        assert_eq!(read.calls(), vec![get_call(PATH, KEYWORD)], "Boolean: read");

        let refused = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
        assert_eq!(
            refusals_of(get_of("Buffer", &refused)),
            Some(vec![KeywordRefusal::Filtered {
                keyword: KEYWORD.to_owned(),
                request: format!("KEYWORD={KEYWORD}&Buffer"),
                found: vec![format!("PATH={PATH}: ReadWrite&Boolean")],
            }
            .into()]),
            "Buffer"
        );
        assert_eq!(refused.calls(), vec![], "Buffer: no call");
    }

    /// UEFI 2.11 §35.2.1.6's table gives a DATE the data type Date and a TIME Time: Date passes
    /// the DATE alone, Time the TIME alone, Buffer both, and no other `<Filter>` either.
    #[test]
    fn get_filters_dates_and_times_by_their_own_data_types() {
        let question = |op_code: u8, offset: u16| {
            // Flags: no field suppressed, EFI_QF_DATE_STORAGE / QF_TIME_STORAGE normal
            let data = [question_header_with(3, 3, 1, offset, 0), vec![0x00]].concat();
            operation(op_code, false, &data)
        };
        let lists = [
            list(PATH, &[question(DATE, 5)]),
            list(OTHER_PATH, &[question(TIME, 9)]),
        ];
        let date = resp(PATH, KEYWORD, "0a0b07e8");
        let time = resp(OTHER_PATH, KEYWORD, "001e0c");
        let get_of = |filter: &str, handler: &MemoryKeywordHandler| {
            get_with(
                &lists,
                &format!("KEYWORD={KEYWORD}&{filter}"),
                KeywordGetOptions::default(),
                handler,
            )
        };

        for (filter, paths, expected) in [
            ("Date", vec![PATH], vec![date.as_str()]),
            ("ReadWrite&Date", vec![PATH], vec![date.as_str()]),
            ("Time", vec![OTHER_PATH], vec![time.as_str()]),
            (
                "Buffer",
                vec![PATH, OTHER_PATH],
                vec![date.as_str(), time.as_str()],
            ),
        ] {
            let handler = MemoryKeywordHandler::with(&[
                (PATH, KEYWORD, "0a0b07e8"),
                (OTHER_PATH, KEYWORD, "001e0c"),
            ]);

            let values = get_of(filter, &handler)
                .unwrap_or_else(|error| panic!("get of {filter}: {error:#}"));

            assert_eq!(
                values.to_string(),
                expected.join("&"),
                "{filter}: the values"
            );
            let sent: Vec<String> = paths
                .iter()
                .map(|path| keyword_string(path, KEYWORD))
                .collect();
            assert_eq!(
                handler.calls(),
                vec![get_call_of(NAMESPACE, &sent.join("&"))],
                "{filter}: GetData() of the questions that pass"
            );
        }
        for filter in ["ReadOnly&Date", "String", "Boolean", "Numeric"] {
            let handler = MemoryKeywordHandler::default();

            assert_eq!(
                refusals_of(get_of(filter, &handler)),
                Some(vec![KeywordRefusal::Filtered {
                    keyword: KEYWORD.to_owned(),
                    request: format!("KEYWORD={KEYWORD}&{filter}"),
                    found: vec![
                        format!("PATH={PATH}: ReadWrite&Date"),
                        format!("PATH={OTHER_PATH}: ReadWrite&Time"),
                    ],
                }
                .into()]),
                "{filter}: no question passes"
            );
            assert_eq!(handler.calls(), vec![], "{filter}: no call");
        }
    }

    /// A request that no question passes is refused naming each question's KeywordKind, also of
    /// a PASSWORD, which UEFI 2.11 §35.2.1.6's table gives no data type.
    #[test]
    fn get_names_the_kind_of_a_question_of_no_data_type_that_the_filter_takes_out() {
        let lists = [
            list(PATH, &[password_on(9, 3, 1, 6)]),
            list(OTHER_PATH, &[one_of(3, 5, 1)]),
        ];
        let handler = MemoryKeywordHandler::with(&[(OTHER_PATH, KEYWORD, "01")]);

        let error = get_with(
            &lists,
            &format!("KEYWORD={KEYWORD}&Boolean"),
            KeywordGetOptions::default(),
            &handler,
        )
        .expect_err("no Boolean question");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "keyword {KEYWORD}: no question of it passes the <Filter> of \
                 KEYWORD={KEYWORD}&Boolean: PATH={PATH}: ReadWrite, of no HII Keyword Data Type; \
                 PATH={OTHER_PATH}: ReadWrite&Numeric:1"
            ),
            "the refusal"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// KEYWORDINFO from the IFR, `<Filter>` by the IFR: GetData() gets neither, for the
    /// questions that pass alone, and each `<KeywordResp>` gets the IFR's `<KeywordInfoResp>`.
    #[test]
    fn get_with_keyword_info_and_filter_both_from_the_ifr() {
        let lists = read_write_and_read_only();
        let handler = MemoryKeywordHandler::with(&[
            (PATH, KEYWORD, "01"),
            (OTHER_PATH, KEYWORD, "03&READONLY"),
        ]);

        let values = get_with(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType&ReadOnly&Numeric:1"),
            options(KeywordInfoSource::Ifr, KeywordFilterBy::Ifr),
            &handler,
        )
        .expect("get of the read-only question");

        assert_eq!(
            values.to_string(),
            format!(
                "{}&READONLY&DATATYPE=Numeric:1",
                resp(OTHER_PATH, KEYWORD, "03")
            ),
            "the read-only question, its DATATYPE from the IFR"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call(OTHER_PATH, KEYWORD)],
            "GetData() without KEYWORDINFO or <Filter>"
        );
    }

    /// KEYWORDINFO from the IFR, `<Filter>` by GetData(): GetData() gets the `<Filter>` alone,
    /// for every question, and each `<KeywordResp>` gets the IFR's `<KeywordInfoResp>`.
    #[test]
    fn get_with_keyword_info_from_the_ifr_and_filter_by_get_data() {
        let lists = read_write_and_read_only();
        let handler = MemoryKeywordHandler::with(&[
            (PATH, KEYWORD, "01&READONLY"),
            (OTHER_PATH, KEYWORD, "03&READONLY"),
        ]);

        let values = get_with(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType&ReadOnly&Numeric:1"),
            options(KeywordInfoSource::Ifr, KeywordFilterBy::GetData),
            &handler,
        )
        .expect("get of both questions");

        assert_eq!(
            values.to_string(),
            format!(
                "{}&READONLY&DATATYPE=Numeric:1&{}&READONLY&DATATYPE=Numeric:1",
                resp(PATH, KEYWORD, "01"),
                resp(OTHER_PATH, KEYWORD, "03")
            ),
            "both questions as GetData() returns them, each DATATYPE from the IFR"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call_of(
                NAMESPACE,
                &format!(
                    "{}&ReadOnly&Numeric:1&{}&ReadOnly&Numeric:1",
                    keyword_string(PATH, KEYWORD),
                    keyword_string(OTHER_PATH, KEYWORD)
                )
            )],
            "GetData() of the <Filter> without KEYWORDINFO"
        );

        let unasked = MemoryKeywordHandler::with(&[
            (PATH, KEYWORD, "01&READONLY&DATATYPE=Numeric:1"),
            (OTHER_PATH, KEYWORD, "03&READONLY"),
        ]);
        let error = get_with(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType&ReadOnly"),
            options(KeywordInfoSource::Ifr, KeywordFilterBy::GetData),
            &unasked,
        )
        .expect_err("unasked info");
        assert_eq!(
            error.downcast_ref::<KeywordGetError>(),
            Some(&KeywordGetError::UnaskedInfo(format!(
                "{}&READONLY&DATATYPE=Numeric:1",
                resp(PATH, KEYWORD, "01")
            ))),
            "a <KeywordInfoResp> that GetData() was not asked for"
        );
    }

    /// KEYWORDINFO from GetData(), `<Filter>` by the IFR: GetData() gets the KEYWORDINFO alone,
    /// for the questions that pass, and its `<KeywordResp>`s are taken as returned.
    #[test]
    fn get_with_keyword_info_from_get_data_and_filter_by_the_ifr() {
        let lists = read_write_and_read_only();
        let sent = format!("{KEYWORD}&KEYWORDINFO=DataType");
        let handler = RewritingHandler {
            inner: MemoryKeywordHandler::with(&[(PATH, &sent, "01"), (OTHER_PATH, &sent, "03")]),
            from: "&KEYWORDINFO=DataType&VALUE=01".to_owned(),
            to: "&VALUE=01&DATATYPE=Numeric:2".to_owned(),
        };

        let values = get_with(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType&ReadWrite"),
            options(KeywordInfoSource::GetData, KeywordFilterBy::Ifr),
            &handler,
        )
        .expect("get of the read-write question");

        assert_eq!(
            values.to_string(),
            format!("{}&DATATYPE=Numeric:2", resp(PATH, KEYWORD, "01")),
            "the read-write question as GetData() returns it"
        );
        assert_eq!(
            handler.inner.calls(),
            vec![get_call(PATH, &sent)],
            "GetData() of the KEYWORDINFO without <Filter>"
        );
    }

    /// KEYWORDINFO from GetData(), `<Filter>` by GetData(): GetData() gets both unchanged, for
    /// every question, and its `<KeywordResp>`s are taken as returned.
    #[test]
    fn get_with_keyword_info_and_filter_both_by_get_data() {
        let lists = read_write_and_read_only();
        let key = format!("{KEYWORD}&KEYWORDINFO=DataType");
        let handler = RewritingHandler {
            inner: MemoryKeywordHandler::with(&[(PATH, &key, "01"), (OTHER_PATH, &key, "01")]),
            from: "&KEYWORDINFO=DataType&VALUE=01".to_owned(),
            to: "&VALUE=01&DATATYPE=Boolean".to_owned(),
        };

        let values = get_with(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORDINFO=DataType&ReadWrite&Boolean"),
            options(KeywordInfoSource::GetData, KeywordFilterBy::GetData),
            &handler,
        )
        .expect("get of both questions");

        assert_eq!(
            values.to_string(),
            format!(
                "{}&DATATYPE=Boolean&{}&DATATYPE=Boolean",
                resp(PATH, KEYWORD, "01"),
                resp(OTHER_PATH, KEYWORD, "01")
            ),
            "both questions as GetData() returns them"
        );
        let sent = format!("{key}&ReadWrite&Boolean");
        assert_eq!(
            handler.inner.calls(),
            vec![get_call_of(
                NAMESPACE,
                &format!(
                    "{}&{}",
                    keyword_string(PATH, &sent),
                    keyword_string(OTHER_PATH, &sent)
                )
            )],
            "GetData() of the KEYWORDINFO and the <Filter>"
        );
    }

    /// get_keywords of `requests`, whose `<Filter>`s the IFR applies.
    fn get_of(
        lists: &[ParsedPackageList],
        requests: &str,
        handler: &impl KeywordData,
    ) -> Result<KeywordValues> {
        get_with(lists, requests, KeywordGetOptions::default(), handler)
    }

    /// The failure of `result`, if GetData() failed.
    fn failure_of(result: &Result<KeywordValues>) -> Option<&KeywordGetFailure> {
        result.as_ref().err()?.downcast_ref::<KeywordGetFailure>()
    }

    /// A Keyword Handler whose GetData() fails with INVALID_PARAMETER after reading what
    /// `inner` reads, the `<KeywordResp>` `extra` appended to its Results if given.
    struct FailingAfter {
        inner: MemoryKeywordHandler,
        extra: Option<String>,
    }

    impl KeywordData for FailingAfter {
        fn get_data(
            &self,
            namespace_id: &str,
            keyword_string: &str,
        ) -> Result<String, GetDataError> {
            let results = self.inner.get_data(namespace_id, keyword_string)?;
            Err(GetDataError {
                results: Some(match &self.extra {
                    Some(extra) => format!("{results}&{extra}"),
                    None => results,
                }),
                error: anyhow!("GetData(): INVALID_PARAMETER"),
            })
        }

        fn set_data(&self, keyword_string: &str) -> Result<()> {
            self.inner.set_data(keyword_string)
        }
    }

    /// The keywords of a `<MultiKeywordRequest>` are read with one GetData(), in order.
    #[test]
    fn get_reads_several_keywords_with_one_get_data() {
        let lists = [list(PATH, &questions())];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "03")]);

        let values = get_of(
            &lists,
            &format!("KEYWORD={SECOND_KEYWORD}&KEYWORD={KEYWORD}"),
            &handler,
        )
        .expect("get of two keywords");

        assert_eq!(
            values.to_string(),
            format!(
                "{}&{}",
                resp(PATH, SECOND_KEYWORD, "03"),
                resp(PATH, KEYWORD, "01")
            ),
            "both keywords, in order"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call_of(
                NAMESPACE,
                &format!(
                    "{}&{}",
                    keyword_string(PATH, SECOND_KEYWORD),
                    keyword_string(PATH, KEYWORD)
                )
            )],
            "one GetData()"
        );
    }

    /// Every request that get refuses is refused, in order, before any call: one not found, one
    /// of a PATH of no package list, one of a question over the bytes of a PASSWORD, and one
    /// whose `<Filter>` no question passes.
    #[test]
    fn get_refuses_every_refused_keyword_before_any_call() {
        let lists = [list(
            PATH,
            &[questions(), vec![password_on(9, 9, 1, 6)]].concat(),
        )];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "01")]);
        let requests = format!(
            "KEYWORD={KEYWORD}&KEYWORD=Missing&PATH={THIRD_PATH}&KEYWORD={KEYWORD}\
             &KEYWORD={SECOND_KEYWORD}&KEYWORD={KEYWORD}&Boolean"
        );

        let refusals = refusals_of(get_of(&lists, &requests, &handler));

        assert!(
            matches!(
                refusals.as_deref(),
                Some([
                    KeywordGetRefusal::Keyword(KeywordRefusal::NotFound { keyword, .. }),
                    KeywordGetRefusal::Keyword(KeywordRefusal::NoDriver(path)),
                    KeywordGetRefusal::Keyword(KeywordRefusal::Question {
                        reason: QuestionRefusal::PasswordBytes,
                        ..
                    }),
                    KeywordGetRefusal::Keyword(KeywordRefusal::Filtered { .. }),
                ]) if keyword == "Missing" && path == THIRD_PATH
            ),
            "each refusal: {refusals:?}"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// A KEYWORDINFO that the IFR cannot tell is refused with the other refusals, in the
    /// requests' order, before any GetData(): the texts of the options, string 4, are in no
    /// display language.
    #[test]
    fn get_refuses_every_keyword_info_with_the_other_refusals_before_any_call() {
        let lists = [list(PATH, &questions())];
        let handler =
            MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01"), (PATH, SECOND_KEYWORD, "01")]);
        let requests = format!(
            "KEYWORD={KEYWORD}&KEYWORDINFO=ValueAttribute&KEYWORD=Missing\
             &KEYWORD={SECOND_KEYWORD}&KEYWORDINFO=ValueAttribute"
        );

        let refusals = refusals_of(get_of(&lists, &requests, &handler));

        assert!(
            matches!(
                refusals.as_deref(),
                Some([
                    KeywordGetRefusal::Info(KeywordInfoRefusal::NoText { keyword: first, id: 4 }),
                    KeywordGetRefusal::Keyword(KeywordRefusal::NotFound { keyword: missing, .. }),
                    KeywordGetRefusal::Info(KeywordInfoRefusal::NoText { keyword: second, id: 4 }),
                ]) if first == KEYWORD && missing == "Missing" && second == SECOND_KEYWORD
            ),
            "each refusal: {refusals:?}"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// A request may name a question once: twice would read it twice.
    #[test]
    fn get_refuses_a_question_named_twice() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let refusals = refusals_of(get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}&PATH={PATH}&KEYWORD={KEYWORD}&ReadWrite"),
            &handler,
        ));

        assert_eq!(
            refusals,
            Some(vec![KeywordRefusal::Duplicate {
                keyword: KEYWORD.to_owned(),
                path: PATH.to_owned(),
            }
            .into()]),
            "the second naming"
        );
        assert_eq!(handler.calls(), vec![], "no call");
    }

    /// Two package lists of one PATH whose keywords are in strings packages of two NAMESPACEs
    /// hold two questions: get reads both, each with the GetData() of its NAMESPACE.
    #[test]
    fn get_reads_the_questions_of_one_path_in_two_namespaces() {
        let lists = [
            list(PATH, &questions()),
            list_in(PATH, OTHER_NAMESPACE, &questions()),
        ];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let values = get_of(&lists, &format!("KEYWORD={KEYWORD}"), &handler)
            .unwrap_or_else(|error| panic!("get in two namespaces: {error:#}"));

        assert_eq!(
            values.to_string(),
            format!(
                "{}&{}",
                resp(PATH, KEYWORD, "01"),
                resp_in(OTHER_NAMESPACE, PATH, KEYWORD, "01")
            ),
            "both values"
        );
        assert_eq!(
            handler.calls(),
            vec![
                get_call(PATH, KEYWORD),
                get_call_of(OTHER_NAMESPACE, &keyword_string(PATH, KEYWORD)),
            ],
            "a GetData() per NAMESPACE"
        );
    }

    /// A successful GetData() must hold a `<KeywordResp>` of every keyword asked for.
    #[test]
    fn get_refuses_a_successful_get_data_of_fewer_keywords_than_asked() {
        let lists = [list(PATH, &questions())];
        let handler = RewritingHandler {
            inner: MemoryKeywordHandler::with(&[
                (PATH, KEYWORD, "01"),
                (PATH, SECOND_KEYWORD, "03"),
            ]),
            from: format!("&{}", resp(PATH, SECOND_KEYWORD, "03")),
            to: String::new(),
        };

        let error = get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORD={SECOND_KEYWORD}"),
            &handler,
        )
        .expect_err("the first keyword alone");

        let text = format!("{error:#}");
        assert!(
            text.ends_with("succeeded with a <KeywordResp> of only the first 1 keywords"),
            "refused: {text}"
        );
        assert!(!text.contains("VALUE="), "no Results text: {text}");
        assert_eq!(
            handler.inner.calls(),
            vec![get_call_of(
                NAMESPACE,
                &format!(
                    "{}&{}",
                    keyword_string(PATH, KEYWORD),
                    keyword_string(PATH, SECOND_KEYWORD)
                )
            )],
            "one GetData()"
        );
    }

    /// GetData() takes one NamespaceId: the keywords of each NAMESPACE are read with a call of
    /// their own, and printed in the request's order.
    #[test]
    fn get_reads_each_namespace_with_a_get_data_of_its_own() {
        let lists = [
            list(PATH, &questions()),
            list_in(OTHER_PATH, OTHER_NAMESPACE, &questions()),
        ];
        let handler = MemoryKeywordHandler::with(&[
            (PATH, KEYWORD, "01"),
            (PATH, SECOND_KEYWORD, "03"),
            (OTHER_PATH, KEYWORD, "00"),
            (OTHER_PATH, SECOND_KEYWORD, "01"),
        ]);

        let values = get_of(
            &lists,
            &format!("KEYWORD={SECOND_KEYWORD}&KEYWORD={KEYWORD}"),
            &handler,
        )
        .expect("get in two namespaces");

        assert_eq!(
            values.to_string(),
            [
                resp(PATH, SECOND_KEYWORD, "03"),
                resp_in(OTHER_NAMESPACE, OTHER_PATH, SECOND_KEYWORD, "01"),
                resp(PATH, KEYWORD, "01"),
                resp_in(OTHER_NAMESPACE, OTHER_PATH, KEYWORD, "00"),
            ]
            .join("&"),
            "each keyword of each list, in the request's order"
        );
        assert_eq!(
            handler.calls(),
            vec![
                get_call_of(
                    NAMESPACE,
                    &format!(
                        "{}&{}",
                        keyword_string(PATH, SECOND_KEYWORD),
                        keyword_string(PATH, KEYWORD)
                    )
                ),
                get_call_of(
                    OTHER_NAMESPACE,
                    &format!(
                        "{}&{}",
                        keyword_string(OTHER_PATH, SECOND_KEYWORD),
                        keyword_string(OTHER_PATH, KEYWORD)
                    )
                ),
            ],
            "a GetData() per NAMESPACE"
        );
    }

    /// When GetData() fails, get reports the `<KeywordResp>`s that its Results held, of the
    /// keywords before the failing one, and the keywords it read no value of.
    #[test]
    fn get_reports_what_get_data_read_before_it_failed() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);

        let got = get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORD={SECOND_KEYWORD}"),
            &handler,
        );

        let failure = failure_of(&got).expect("no value of the second keyword");
        assert_eq!(failure.read, [resp(PATH, KEYWORD, "01")], "read");
        assert_eq!(
            failure.unread,
            [keyword_string(PATH, SECOND_KEYWORD)],
            "unread"
        );
        assert_eq!(
            failure.to_string(),
            format!(
                "GetData() failed after reading [{}]; it read no value of [{}]: KEYWORD_NOT_FOUND",
                resp(PATH, KEYWORD, "01"),
                keyword_string(PATH, SECOND_KEYWORD)
            ),
            "the report"
        );
    }

    /// A GetData() that fails in the first NAMESPACE leaves unread the rest of its keywords and
    /// every keyword of the NAMESPACEs after it, which get calls no GetData() for.
    #[test]
    fn get_reads_no_namespace_after_a_failed_get_data() {
        let lists = [
            list(PATH, &questions()),
            list_in(OTHER_PATH, OTHER_NAMESPACE, &questions()),
        ];
        let handler = MemoryKeywordHandler::with(&[
            (PATH, KEYWORD, "01"),
            (OTHER_PATH, KEYWORD, "00"),
            (OTHER_PATH, SECOND_KEYWORD, "01"),
        ]);

        let got = get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORD={SECOND_KEYWORD}"),
            &handler,
        );

        let failure = failure_of(&got).expect("no value of the second keyword of PATH");
        assert_eq!(failure.read, [resp(PATH, KEYWORD, "01")], "read");
        assert_eq!(
            failure.unread,
            [
                keyword_string(OTHER_PATH, KEYWORD),
                keyword_string(PATH, SECOND_KEYWORD),
                keyword_string(OTHER_PATH, SECOND_KEYWORD),
            ],
            "unread, in the request's order"
        );
        assert_eq!(
            handler.calls(),
            vec![get_call_of(
                NAMESPACE,
                &format!(
                    "{}&{}",
                    keyword_string(PATH, KEYWORD),
                    keyword_string(PATH, SECOND_KEYWORD)
                )
            )],
            "no GetData() of the second NAMESPACE"
        );
    }

    /// The Results of a failed GetData() must be `<KeywordResp>`s of the first requests, no more
    /// than them.
    #[test]
    fn get_refuses_results_of_a_failed_get_data_beyond_the_requests() {
        let lists = [list(PATH, &questions())];
        let handler = FailingAfter {
            inner: MemoryKeywordHandler::with(&[
                (PATH, KEYWORD, "01"),
                (PATH, SECOND_KEYWORD, "03"),
            ]),
            extra: Some(resp(PATH, SECOND_KEYWORD, "03")),
        };

        let got = get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}&KEYWORD={SECOND_KEYWORD}"),
            &handler,
        );

        let error = got.expect_err("three <KeywordResp>s of two requests");
        assert!(
            error.downcast_ref::<KeywordGetFailure>().is_none(),
            "not taken as read: {error:#}"
        );
        let text = format!("{error:#}");
        assert!(
            text.starts_with("GetData() failed: GetData(): INVALID_PARAMETER: GetData() of ")
                && text.ends_with("not the <KeywordResp> of each keyword asked for, in order"),
            "refused: {text}"
        );
    }

    /// A READONLY that contradicts the `<UsageFilter>` is reported with GetData()'s failure
    /// after it, and both name what was read and what was not.
    #[test]
    fn get_reports_a_contradicting_readonly_with_the_failure_after_it() {
        let lists = [list(PATH, &questions())];
        let handler = MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01&READONLY")]);

        let got = get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}&ReadWrite&KEYWORD={SECOND_KEYWORD}"),
            &handler,
        );

        let failure = failure_of(&got).expect("no value of the second keyword");
        let read = format!("{}&READONLY", resp(PATH, KEYWORD, "01"));
        assert_eq!(
            failure.refused,
            [KeywordGetError::Usage {
                request: format!("KEYWORD={KEYWORD}&ReadWrite"),
                read: read.clone(),
            }],
            "the READONLY refused"
        );
        assert_eq!(
            failure.to_string(),
            format!(
                "GetData() failed after reading [{read}]; it read no value of [{}]; get refuses \
                 what it read: GetData() returned {read}, whose READONLY contradicts the \
                 <UsageFilter> of KEYWORD={KEYWORD}&ReadWrite: KEYWORD_NOT_FOUND",
                keyword_string(PATH, SECOND_KEYWORD)
            ),
            "the report"
        );
    }

    /// A GetData() that fails once it has read a value of every keyword, as at a `<Filter>`
    /// after the last that it cannot parse, is told so, with its error.
    #[test]
    fn get_says_that_get_data_failed_after_the_last_keyword() {
        let lists = [list(PATH, &questions())];
        let handler = FailingAfter {
            inner: MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]),
            extra: None,
        };

        let got = get_of(&lists, &format!("KEYWORD={KEYWORD}"), &handler);

        let failure = failure_of(&got).expect("a failed GetData()");
        assert_eq!(
            failure.to_string(),
            format!(
                "GetData() read [{}], a value of every keyword, then failed after the last: \
                 GetData(): INVALID_PARAMETER",
                resp(PATH, KEYWORD, "01")
            ),
            "the report"
        );
    }

    /// Results that are not the `<KeywordResp>`s asked for are refused naming the place,
    /// NAMESPACE, PATH and KEYWORD of each other one, and Results that do not parse naming what
    /// was expected and the character where, never their text: here the VALUE of a PASSWORD's
    /// keyword, which firmware returns unasked after a successful or a failed GetData().
    #[test]
    fn get_refuses_results_beyond_the_requests_without_their_values() {
        const SECRET: &str = "5ec2e7";
        let lists = [
            list(PATH, &[one_of(3, 5, 1)]),
            list(OTHER_PATH, &[password_on(9, 3, 1, 6)]),
        ];
        let read = resp(PATH, KEYWORD, "01");
        let password = resp(OTHER_PATH, KEYWORD, SECRET);
        let values = || MemoryKeywordHandler::with(&[(PATH, KEYWORD, "01")]);
        let succeeding = |extra: &str| RewritingHandler {
            inner: values(),
            from: read.clone(),
            to: format!("{read}&{extra}"),
        };
        let failing = |extra: &str| FailingAfter {
            inner: values(),
            extra: Some(extra.to_owned()),
        };
        let request = format!("KEYWORD={KEYWORD}&Numeric");
        let text_of = |result: Result<KeywordValues>| format!("{:#}", result.expect_err("refused"));
        let unasked = format!(
            "<KeywordResp> 2 of NAMESPACE={NAMESPACE}&PATH={OTHER_PATH}&KEYWORD={KEYWORD} past the \
             last request"
        );
        let unparsed = format!(
            "expected the next <KeywordResp> or the end at character {}",
            read.len() + 1
        );
        let cases = [
            (
                "succeeded with an unasked <KeywordResp>",
                text_of(get_of(&lists, &request, &succeeding(&password))),
                &unasked,
            ),
            (
                "failed with an unasked <KeywordResp>",
                text_of(get_of(&lists, &request, &failing(&password))),
                &unasked,
            ),
            (
                "succeeded with an element that does not parse",
                text_of(get_of(&lists, &request, &succeeding(SECRET))),
                &unparsed,
            ),
            (
                "failed with an element that does not parse",
                text_of(get_of(&lists, &request, &failing(SECRET))),
                &unparsed,
            ),
        ];
        for (name, text, named) in cases {
            assert!(text.contains(named.as_str()), "{name}: named: {text}");
            assert!(!text.contains(SECRET), "{name}: no VALUE: {text}");
        }
    }

    /// A Keyword Handler whose GetData() fails with NOT_FOUND, its text the Results.
    struct FailingWithResults(&'static str);

    impl KeywordData for FailingWithResults {
        fn get_data(
            &self,
            _namespace_id: &str,
            _keyword_string: &str,
        ) -> Result<String, GetDataError> {
            Err(GetDataError {
                results: Some(self.0.to_owned()),
                error: anyhow!("GetData(): NOT_FOUND"),
            })
        }

        fn set_data(&self, _keyword_string: &str) -> Result<()> {
            Err(anyhow!("no SetData()"))
        }
    }

    /// A failed GetData() whose Results are empty, which no `<MultiKeywordResp>` is, read no
    /// value, as without Results.
    #[test]
    fn get_takes_the_empty_results_of_a_failed_get_data_for_none() {
        let lists = [list(PATH, &questions())];

        let got = get_of(
            &lists,
            &format!("KEYWORD={KEYWORD}"),
            &FailingWithResults(""),
        );

        let failure = failure_of(&got).expect("a failed GetData()");
        assert_eq!(
            failure.to_string(),
            format!(
                "GetData() read no value of [{}]: GetData(): NOT_FOUND",
                keyword_string(PATH, KEYWORD)
            ),
            "the report"
        );
    }
}
