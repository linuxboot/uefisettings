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

//! The conditions of SUPPRESS_IF, GRAY_OUT_IF and DISABLE_IF scopes, evaluated as
//! edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression evaluates them, and the
//! questions and options that they leave to get, set and list-questions.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::rc::Rc;
use std::rc::Weak;

use anyhow::Result;
use binrw::io::Cursor;
use thiserror::Error;

use super::ami_access_level::AMI_ACCESS_LEVEL;
use super::declared_var_store;
use super::defaults::is_parent_statement;
use super::defaults::question_scope;
use super::find_corresponding_varstore;
use super::named_records;
use super::question_values::value_question;
use super::question_values::OptionMatch;
use super::question_values::PromptMatch;
use super::question_values::ValueQuestion;
use super::storage::read_current_value_bytes;
use super::storage::read_question_value;
use super::storage::stored_value;
use super::storage::RetrievedValue;
use super::storage::ShortVarStoreEfi;
use super::storage::ValueLocation;
use super::storage::ValueSource;
use super::storage::ValueUnavailable;
use super::storage::VariableStore;
use super::storage::VariableStoreKind;
use super::storageless::NoVarStore;
use super::storageless::StoragelessRefusal;
use super::walk_scopes;
use super::AccessLevel;
use super::DeclaredStore;
use super::EfivarReader;
use super::IFROpCode;
use super::IFROperation;
use super::IgnoredIfr;
use super::ParsedOperation;
use super::QuestionFlags;
use super::QuestionHeader;
use super::VarStoreOperand;
use super::Walk;
use super::EFI_IFR_TYPE_BOOLEAN;
use super::EFI_IFR_TYPE_DATE;
use super::EFI_IFR_TYPE_NUM_SIZE_16;
use super::EFI_IFR_TYPE_NUM_SIZE_32;
use super::EFI_IFR_TYPE_NUM_SIZE_64;
use super::EFI_IFR_TYPE_NUM_SIZE_8;
use super::EFI_IFR_TYPE_REF;
use super::EFI_IFR_TYPE_STRING;
use super::EFI_IFR_TYPE_TIME;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;
use crate::parse_error::ReadParsed;

/// The opcode of IFROpCode::Match2, the highest that edk2-stable202608
/// SetupBrowserDxe/IfrParse.c IsUnKnownOpCode knows.
const EFI_IFR_MATCH2_OP: u8 = 0x64;

/// The READ expressions that the value of one question goes through at most: each retrieves
/// the value of the question that it refers to in a nested call, and the 128 KiB stack of UEFI
/// DXE (edk2-stable202608 MdeModulePkg/Core/DxeIplPeim/DxeIpl.h STACK_SIZE) holds 8 of them.
pub(super) const MAX_READ_DEPTH: usize = 8;

/// What its conditions leave of a question in the setup browser, lowest priority first, as
/// edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpressionList ranks them:
/// DisableIf > SuppressIf > GrayOutIf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum QuestionState {
    Selectable,
    GrayedOut,
    Suppressed,
    Disabled,
}

impl fmt::Display for QuestionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // the values of --include, and "selectable"
        f.write_str(match self {
            QuestionState::Selectable => "selectable",
            QuestionState::GrayedOut => "grayed-out",
            QuestionState::Suppressed => "suppressed",
            QuestionState::Disabled => "disabled",
        })
    }
}

/// Why set refuses to write a question. edk2-stable202608 SetupBrowserDxe/Presentation.c
/// InitializeDisplayStatement shows either as HII_DISPLAY_READONLY, which
/// DisplayEngineDxe/FormDisplay.c IsSelectable refuses as it refuses a grayed-out question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ReadOnlyCause {
    /// EFI_IFR_FLAG_READ_ONLY (UEFI 2.11 §33.3.8.2.2), which edk2-stable202608
    /// HiiDatabaseDxe/ConfigKeywordHandler.c EfiConfigKeywordHandlerSetData, the write by name,
    /// refuses with EFI_ACCESS_DENIED; set writes it with IncludedStates::READ_ONLY
    Flag,
    /// An EFI_IFR_VALUE, which gives the question its value (§33.3.8.3.88) and which
    /// edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue never writes; nor does set
    ValueExpression,
}

impl ReadOnlyCause {
    /// The states that set includes to write a question that this makes read-only, if any.
    pub(crate) fn lifted_with(self) -> Option<IncludedStates> {
        match self {
            ReadOnlyCause::Flag => Some(IncludedStates::READ_ONLY),
            ReadOnlyCause::ValueExpression => None,
        }
    }

    /// Whether set writes a question that this makes read-only, with `include`.
    pub(crate) fn lifted_by(self, include: IncludedStates) -> bool {
        self.lifted_with()
            .is_some_and(|states| include.contains(states))
    }
}

impl fmt::Display for ReadOnlyCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReadOnlyCause::Flag => {
                "EFI_IFR_FLAG_READ_ONLY makes it read-only (UEFI 2.11 §33.3.8.2.2)"
            }
            ReadOnlyCause::ValueExpression => VALUE_MAKES_READ_ONLY,
        })
    }
}

bitflags::bitflags! {
    /// The states, besides selectable, of the questions and options that get, set and
    /// list-questions select, and READ_ONLY. IncludedStates::all() includes READ_ONLY, so set
    /// with it writes EFI_IFR_FLAG_READ_ONLY questions too; CONDITIONS does not.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct IncludedStates: u64 {
        const GRAYED_OUT = 1;
        const SUPPRESSED = 1 << 1;
        const DISABLED = 1 << 2;
        /// set writes the questions that EFI_IFR_FLAG_READ_ONLY makes read-only; get and
        /// list-questions show read-only questions regardless
        const READ_ONLY = 1 << 3;
    }
}

impl IncludedStates {
    /// Every state that a condition gives.
    pub const CONDITIONS: Self = Self::GRAYED_OUT
        .union(Self::SUPPRESSED)
        .union(Self::DISABLED);

    pub fn allows(self, state: QuestionState) -> bool {
        self.contains(state.into())
    }

    /// The condition states, lowest priority first.
    fn states(self) -> impl Iterator<Item = QuestionState> {
        [
            QuestionState::GrayedOut,
            QuestionState::Suppressed,
            QuestionState::Disabled,
        ]
        .into_iter()
        .filter(move |&state| self.allows(state))
    }

    /// The states joined with " or ".
    fn alternatives(self) -> String {
        let states: Vec<String> = self.states().map(|state| state.to_string()).collect();
        states.join(" or ")
    }
}

impl From<QuestionState> for IncludedStates {
    fn from(state: QuestionState) -> Self {
        match state {
            QuestionState::Selectable => Self::empty(),
            QuestionState::GrayedOut => Self::GRAYED_OUT,
            QuestionState::Suppressed => Self::SUPPRESSED,
            QuestionState::Disabled => Self::DISABLED,
        }
    }
}

impl fmt::Display for IncludedStates {
    /// Writes the states as --include takes them.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = "";
        for state in self.states() {
            write!(f, "{separator}{state}")?;
            separator = ",";
        }
        if self.contains(IncludedStates::READ_ONLY) {
            write!(f, "{separator}read-only")?;
        }
        Ok(())
    }
}

/// Why get or set selects no question, or not the option asked for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
#[non_exhaustive]
pub enum SelectionError {
    #[error(
        "question {question:?} is {}; also include {states} questions to select it",
        .states.alternatives()
    )]
    Excluded {
        question: String,
        states: IncludedStates,
    },
    /// Excluded, in states that values of the ExportConfig snapshot decide
    #[error(
        "question {question:?} is {} by a value of the ExportConfig snapshot; also include \
         {states} questions to select it",
        .states.alternatives()
    )]
    SnapshotExcluded {
        question: String,
        states: IncludedStates,
    },
    #[error(
        "cannot tell whether question {question:?} is {}: {}; also include {states} questions \
         to select it regardless",
        .states.alternatives(),
        .reasons.join("; ")
    )]
    Undetermined {
        question: String,
        states: IncludedStates,
        reasons: Vec<String>,
    },
    #[error(
        "option {option:?} of question {question:?} is {}; also include {states} questions to \
         select it",
        .states.alternatives()
    )]
    OptionExcluded {
        question: String,
        option: String,
        states: IncludedStates,
    },
    /// OptionExcluded, in states that values of the ExportConfig snapshot decide
    #[error(
        "option {option:?} of question {question:?} is {} by a value of the ExportConfig \
         snapshot; also include {states} questions to select it",
        .states.alternatives()
    )]
    SnapshotOptionExcluded {
        question: String,
        option: String,
        states: IncludedStates,
    },
    #[error(
        "cannot tell whether option {option:?} of question {question:?} is {}: {}; also \
         include {states} questions to select it regardless",
        .states.alternatives(),
        .reasons.join("; ")
    )]
    OptionUndetermined {
        question: String,
        option: String,
        states: IncludedStates,
        reasons: Vec<String>,
    },
    /// set's error when no question has the text; get answers no question instead
    #[error("no question {question:?} in the HiiDB")]
    NotFound { question: String },
    /// NotFound in a HiiDB with IFR that uefisettings ignores, which may hold the question; get
    /// lists that IFR in its answer instead
    #[error(
        "no question {question:?} in the HiiDB, but it may be in {}",
        named_records(.ignored)
    )]
    MaybeInIgnoredIfr {
        question: String,
        ignored: Vec<IgnoredIfr>,
    },
    /// get's and set's refusal of a QUESTION that names questions through the prompts of
    /// different languages, and of a --keyword that names them through those of different
    /// namespaces
    #[error(
        "{question:?} is the prompt {}: no one language holds it as the prompt of every question \
         it names",
        PromptMatch::list(.matches)
    )]
    Ambiguous {
        question: String,
        matches: Vec<PromptMatch>,
    },
    /// set's refusal of a VALUE that names options through the texts of different languages
    #[error(
        "the value is the text {}: no one language holds it as the text of every option it names",
        OptionMatch::list(.question, .matches)
    )]
    AmbiguousOption {
        question: String,
        matches: Vec<OptionMatch>,
    },
    /// get's and set's refusal of a --question-id that questions of one FormSet share, of which
    /// select would pick one, though a QuestionId is "The unique value that identifies the
    /// particular question" (UEFI 2.11 §33.3.8.2.2)
    #[error(
        "{question} is that of the questions {}: a QuestionId identifies one question of its \
         FormSet",
        .prompts.iter().map(|prompt| format!("{prompt:?}")).collect::<Vec<_>>().join(" and ")
    )]
    SharedQuestionId {
        question: String,
        /// The prompts of the questions, in IFR order
        prompts: Vec<String>,
    },
}

/// The states that the conditions around a question or option can give it, and why set refuses
/// to write the question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateEvaluation {
    /// The state that the true conditions give, of those that took no value of the ExportConfig
    /// snapshot
    current: QuestionState,
    /// The conditions not evaluated: the state each gives if true, and why it is not evaluated
    unknown: Vec<(QuestionState, String)>,
    /// The conditions evaluated from values of the ExportConfig snapshot: the state each gives if
    /// true, and whether it is
    from_snapshot: Vec<(QuestionState, bool)>,
    /// Why the question is read-only, if it is; never for an option
    read_only: Option<ReadOnlyCause>,
}

/// The order in which select prefers matches equally certain to be selected, lowest first: by
/// why set refuses to write the match, then by its state; a match that `include` allows in every
/// possible state comes before a likely one whatever their Ranks. A read-only match ranks after
/// every writable one, whatever their states, as no --include of a condition state makes it
/// writable; of read-only ones, a ReadOnlyCause::Flag one, which set writes with
/// IncludedStates::READ_ONLY, ranks before a ReadOnlyCause::ValueExpression one. Rank does not
/// ask whether set may write the efivar of a match, so a writable match whose efivar set refuses
/// hides a read-only twin that set would write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Rank {
    read_only: Option<ReadOnlyCause>,
    state: QuestionState,
}

impl StateEvaluation {
    pub(crate) fn selectable() -> Self {
        StateEvaluation {
            current: QuestionState::Selectable,
            unknown: Vec::new(),
            from_snapshot: Vec::new(),
            read_only: None,
        }
    }

    /// Why the question is read-only, if it is.
    pub(crate) fn read_only(&self) -> Option<ReadOnlyCause> {
        self.read_only
    }

    /// The Rank of the match in `state`.
    fn rank(&self, state: QuestionState) -> Rank {
        Rank {
            read_only: self.read_only,
            state,
        }
    }

    /// Takes in a condition that gives `state` when true, evaluated from values of `source`.
    fn add(&mut self, state: QuestionState, truth: Truth, source: ValueSource) {
        match (truth, source) {
            (Truth::Known(true), ValueSource::Current) => self.current = self.current.max(state),
            (Truth::Known(false), ValueSource::Current) => {}
            (Truth::Known(truth), ValueSource::Snapshot) => self.from_snapshot.push((state, truth)),
            (Truth::Unknown(reason), ValueSource::Current | ValueSource::Snapshot) => {
                self.unknown.push((state, reason));
            }
        }
    }

    /// Takes in the condition of the SUPPRESS_IF, GRAY_OUT_IF or DISABLE_IF `scope`, which gives
    /// `state` when true, with where the values that it takes come from.
    fn evaluate(
        &mut self,
        state: QuestionState,
        scope: &IFROperation,
        inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    ) {
        let taken = inputs.reader.snapshot_values_taken();
        let truth = evaluate_condition(scope, inputs);
        self.add(state, truth, ValueSource::since(taken, inputs.reader));
    }

    /// The state that the true conditions give.
    fn known(&self) -> QuestionState {
        self.from_snapshot
            .iter()
            .filter(|&&(_, truth)| truth)
            .fold(self.current, |known, &(state, _)| known.max(state))
    }

    /// The conditions not evaluated that would give a state above the known one.
    fn deciding(&self) -> impl Iterator<Item = &(QuestionState, String)> {
        let known = self.known();
        self.unknown.iter().filter(move |(state, _)| *state > known)
    }

    /// Why the conditions that decide between the possible states are not evaluated, each
    /// reason once.
    pub(crate) fn reasons(&self) -> impl Iterator<Item = &str> {
        let mut seen = BTreeSet::new();
        self.deciding()
            .map(|(_, reason)| reason.as_str())
            .filter(move |reason| seen.insert(*reason))
    }

    /// The states that the question or option can be in.
    fn possible_states(&self) -> BTreeSet<QuestionState> {
        possible_states_of(self.known(), self.unknown.iter().map(|&(state, _)| state))
    }

    /// Snapshot if the values of the ExportConfig snapshot that conditions took decide the
    /// possible states: without them, those conditions would not be evaluated, and the states
    /// would differ.
    pub(crate) fn source(&self) -> ValueSource {
        let without = possible_states_of(
            self.current,
            self.unknown
                .iter()
                .map(|&(state, _)| state)
                .chain(self.from_snapshot.iter().map(|&(state, _)| state)),
        );
        match without == self.possible_states() {
            true => ValueSource::Current,
            false => ValueSource::Snapshot,
        }
    }

    /// The highest of possible_states.
    fn worst_case(&self) -> QuestionState {
        self.deciding()
            .map(|&(state, _)| state)
            .fold(self.known(), QuestionState::max)
    }

    /// The possible states that `include` does not allow.
    fn excluded_states(&self, include: IncludedStates) -> IncludedStates {
        self.possible_states()
            .into_iter()
            .filter(|&state| !include.allows(state))
            .map(IncludedStates::from)
            .collect()
    }

    /// Whether `include` allows every possible state.
    pub(crate) fn is_allowed(&self, include: IncludedStates) -> bool {
        self.excluded_states(include).is_empty()
    }

    /// Whether `include` allows some possible state.
    pub(crate) fn may_be_allowed(&self, include: IncludedStates) -> bool {
        self.lowest_allowed(include).is_some()
    }

    /// The lowest possible state that `include` allows.
    fn lowest_allowed(&self, include: IncludedStates) -> Option<QuestionState> {
        self.possible_states()
            .into_iter()
            .find(|&state| include.allows(state))
    }

    /// The suffix that get, set and list-questions add to the answer: the possible states,
    /// unless just selectable, with why the conditions are not evaluated if more than one, then
    /// the tag of source(), after which a selectable state shows too.
    pub(crate) fn annotation(&self) -> String {
        self.annotated("")
    }

    /// The annotation of the stored or written option, which precedes that of the question.
    pub(crate) fn option_annotation(&self) -> String {
        self.annotated("option ")
    }

    /// The annotation, with `subject` before the states.
    fn annotated(&self, subject: &str) -> String {
        let source = self.source();
        let reasons: Vec<&str> = self.reasons().collect();
        if !reasons.is_empty() {
            let states: Vec<String> = self
                .possible_states()
                .iter()
                .map(ToString::to_string)
                .collect();
            return format!(
                " <{subject}{}: {}>{}",
                states.join(" or "),
                reasons.join("; "),
                source.annotation()
            );
        }
        let known = self.known();
        let shown = match known {
            QuestionState::Selectable => matches!(source, ValueSource::Snapshot),
            QuestionState::GrayedOut | QuestionState::Suppressed | QuestionState::Disabled => true,
        };
        match shown {
            true => format!(" <{subject}{known}>{}", source.annotation()),
            false => String::new(),
        }
    }
}

/// The states that a question or option can be in when its true conditions give `known` and
/// those not evaluated may give `unknown`.
fn possible_states_of(
    known: QuestionState,
    unknown: impl Iterator<Item = QuestionState>,
) -> BTreeSet<QuestionState> {
    std::iter::once(known)
        .chain(unknown.filter(|&state| state > known))
        .collect()
}

/// Which of the matches of a question to select.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selection<T> {
    Picked {
        picked: (T, StateEvaluation),
        /// The states to include to select a match that ranks before it, as it is read-only
        ranked_before: IncludedStates,
    },
    /// No match is certainly in a state that `include` allows, but some may be
    Undetermined {
        /// The one that get shows regardless
        likely: (T, StateEvaluation),
        /// Why their conditions are not evaluated
        reasons: Vec<String>,
        /// The states to include to select one regardless
        states: IncludedStates,
        /// The states to include to select a match that ranks before the likely one, as it is
        /// read-only
        ranked_before: IncludedStates,
    },
    /// Every match is in a state that `include` does not allow
    Excluded(Exclusion),
    NotFound,
}

/// Selects, of `matches` in IFR order, the one with the lowest Rank of its worst-case state among
/// those that `include` allows in every possible state, the first on a tie. Of those that it may
/// allow, the likely one has the lowest Rank of the lowest possible state that it allows, the
/// first on a tie.
pub(crate) fn select<T>(
    matches: Vec<(T, StateEvaluation)>,
    include: IncludedStates,
) -> Selection<T> {
    let mut selector = Selector::new(include);
    for (candidate, evaluation) in matches {
        selector.add(candidate, evaluation);
    }
    selector.finish()
}

/// What select keeps of the matches it has seen.
struct Selector<T> {
    include: IncludedStates,
    picked: Option<(T, StateEvaluation)>,
    likely: Option<(T, StateEvaluation, Rank)>,
    reasons: Vec<String>,
    undetermined: IncludedStates,
    excluded: Exclusion,
    /// The states that `include` may not allow of the matches that it does not allow in every
    /// possible state, by why each is read-only
    unselected: BTreeMap<Option<ReadOnlyCause>, IncludedStates>,
}

impl<T> Selector<T> {
    /// Selects with `include`.
    fn new(include: IncludedStates) -> Self {
        Selector {
            include,
            picked: None,
            likely: None,
            reasons: Vec::new(),
            undetermined: IncludedStates::empty(),
            excluded: Exclusion::NONE,
            unselected: BTreeMap::new(),
        }
    }

    /// Takes in the next match in IFR order.
    fn add(&mut self, candidate: T, evaluation: StateEvaluation) {
        let excluded_states = evaluation.excluded_states(self.include);
        match (
            excluded_states.is_empty(),
            evaluation.lowest_allowed(self.include),
        ) {
            (true, _) => {
                let better = self.picked.as_ref().is_none_or(|(_, best)| {
                    evaluation.rank(evaluation.worst_case()) < best.rank(best.worst_case())
                });
                if better {
                    self.picked = Some((candidate, evaluation));
                }
            }
            (false, Some(lowest)) => {
                let new: Vec<String> = evaluation
                    .reasons()
                    .filter(|reason| !self.reasons.iter().any(|known| known == reason))
                    .map(str::to_owned)
                    .collect();
                self.reasons.extend(new);
                self.undetermined |= excluded_states;
                *self.unselected.entry(evaluation.read_only).or_default() |= excluded_states;
                let rank = evaluation.rank(lowest);
                if self.likely.as_ref().is_none_or(|&(_, _, best)| rank < best) {
                    self.likely = Some((candidate, evaluation, rank));
                }
            }
            (false, None) => {
                self.excluded |= Exclusion {
                    states: excluded_states,
                    source: evaluation.source(),
                };
                *self.unselected.entry(evaluation.read_only).or_default() |= excluded_states;
            }
        }
    }

    /// The states to include to select a match that ranks before one that `read_only` makes
    /// read-only, of those taken in: the states of the matches with a lower read_only, with
    /// those that make them writable, except the states that set includes.
    fn ranked_before(&self, read_only: Option<ReadOnlyCause>) -> IncludedStates {
        self.unselected
            .range(..read_only)
            .filter_map(|(&cause, &states)| match cause {
                None => Some(states),
                Some(cause) => cause.lifted_with().map(|lifted_with| states | lifted_with),
            })
            .fold(IncludedStates::empty(), |all, states| all | states)
            .difference(self.include)
    }

    /// The selection of the matches taken in.
    fn finish(self) -> Selection<T> {
        let chosen = match (&self.picked, &self.likely) {
            (Some((_, evaluation)), _) | (None, Some((_, evaluation, _))) => evaluation.read_only,
            (None, None) => None,
        };
        let ranked_before = self.ranked_before(chosen);
        match (self.picked, self.likely, self.excluded.is_empty()) {
            (Some(picked), _, _) => Selection::Picked {
                picked,
                ranked_before,
            },
            (None, Some((candidate, evaluation, _)), _) => Selection::Undetermined {
                likely: (candidate, evaluation),
                reasons: self.reasons,
                states: self.undetermined,
                ranked_before,
            },
            (None, None, false) => Selection::Excluded(self.excluded),
            (None, None, true) => Selection::NotFound,
        }
    }
}

/// What get or set does in a FormSet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Choice<T> {
    Chosen(T, StateEvaluation),
    /// No match: what excluded the matches, none if no question matches
    Skipped(Exclusion),
}

/// The states that exclude every match of a question or option, which `include` does not allow,
/// and whether values of the ExportConfig snapshot decide them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exclusion {
    pub(crate) states: IncludedStates,
    pub(crate) source: ValueSource,
}

impl Exclusion {
    /// Of no match.
    pub(crate) const NONE: Self = Exclusion {
        states: IncludedStates::empty(),
        source: ValueSource::Current,
    };

    pub(crate) fn is_empty(self) -> bool {
        self.states.is_empty()
    }

    /// The refusal of `question`, whose every match this excludes.
    pub(crate) fn question_error(self, question: &str) -> SelectionError {
        let question = question.to_owned();
        let states = self.states;
        match self.source {
            ValueSource::Current => SelectionError::Excluded { question, states },
            ValueSource::Snapshot => SelectionError::SnapshotExcluded { question, states },
        }
    }

    /// The refusal of option `option` of `question`, whose every match this excludes.
    pub(crate) fn option_error(self, question: String, option: String) -> SelectionError {
        let states = self.states;
        match self.source {
            ValueSource::Current => SelectionError::OptionExcluded {
                question,
                option,
                states,
            },
            ValueSource::Snapshot => SelectionError::SnapshotOptionExcluded {
                question,
                option,
                states,
            },
        }
    }
}

impl std::ops::BitOrAssign for Exclusion {
    /// Adds the states of `other`, and the snapshot if it decides them.
    fn bitor_assign(&mut self, other: Self) {
        self.states |= other.states;
        self.source = self.source.or(other.source);
    }
}

impl<T> Selection<T> {
    /// Maps the match.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Selection<U> {
        match self {
            Selection::Picked {
                picked: (candidate, evaluation),
                ranked_before,
            } => Selection::Picked {
                picked: (f(candidate), evaluation),
                ranked_before,
            },
            Selection::Undetermined {
                likely: (candidate, evaluation),
                reasons,
                states,
                ranked_before,
            } => Selection::Undetermined {
                likely: (f(candidate), evaluation),
                reasons,
                states,
                ranked_before,
            },
            Selection::Excluded(exclusion) => Selection::Excluded(exclusion),
            Selection::NotFound => Selection::NotFound,
        }
    }

    /// set writes only a match that `include` certainly allows, and fails rather than guess.
    pub(crate) fn for_set(self, question: &str) -> Result<Choice<T>, SelectionError> {
        match self {
            Selection::Picked {
                picked: (candidate, evaluation),
                ..
            } => Ok(Choice::Chosen(candidate, evaluation)),
            Selection::Undetermined {
                reasons, states, ..
            } => Err(SelectionError::Undetermined {
                question: question.to_owned(),
                states,
                reasons,
            }),
            Selection::Excluded(exclusion) => Ok(Choice::Skipped(exclusion)),
            Selection::NotFound => Ok(Choice::Skipped(Exclusion::NONE)),
        }
    }

    /// get shows the match that set writes, else the likely one, whose annotation names its
    /// possible states.
    pub(crate) fn for_get(self) -> Choice<T> {
        match self {
            Selection::Picked {
                picked: (candidate, evaluation),
                ..
            }
            | Selection::Undetermined {
                likely: (candidate, evaluation),
                ..
            } => Choice::Chosen(candidate, evaluation),
            Selection::Excluded(exclusion) => Choice::Skipped(exclusion),
            Selection::NotFound => Choice::Skipped(Exclusion::NONE),
        }
    }
}

/// Returns the states that the SUPPRESS_IF, GRAY_OUT_IF and DISABLE_IF scopes around
/// `question` can give it, those of its form and FormSet too, and GrayedOut if an EFI_IFR_LOCKED
/// locks it; and why set refuses to write it.
// edk2-stable202608 DisplayEngineDxe/FormDisplay.c UiAddMenuOption grays out
// EFI_IFR_FLAG_READ_ONLY ones too where PcdBrowerGrayOutReadOnlyMenu is set, a build setting that
// the OS cannot read.
pub(crate) fn question_state(
    question: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> StateEvaluation {
    let mut evaluation = StateEvaluation {
        read_only: read_only(question),
        ..StateEvaluation::selectable()
    };
    if locked(question) {
        evaluation.add(
            QuestionState::GrayedOut,
            Truth::Known(true),
            ValueSource::Current,
        );
    }
    let mut scope = question.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = scope {
        let op = op.borrow();
        if let OpRole::Scope(state) = OpRole::of(op.op_code) {
            evaluation.evaluate(state, &op, inputs);
        }
        scope = op.parent.as_ref().and_then(Weak::upgrade);
    }
    evaluation
}

/// Why set refuses to write `question`, if it does: an EFI_IFR_VALUE gives its value
/// (question_value_expression), else EFI_IFR_FLAG_READ_ONLY.
fn read_only(question: &IFROperation) -> Option<ReadOnlyCause> {
    if question_value_expression(question).is_some() {
        return Some(ReadOnlyCause::ValueExpression);
    }
    value_question(question)?
        .header()
        .flags()
        .contains(QuestionFlags::READ_ONLY)
        .then_some(ReadOnlyCause::Flag)
}

/// Whether an EFI_IFR_LOCKED locks `question`, which edk2-stable202608 SetupBrowserDxe grays out
/// (Presentation.c InitializeDisplayStatement, and for a locked form, DisplayEngineDxe/
/// FormDisplay.c UiAddMenuOption). UEFI 2.11 §33.3.8.3.37 addresses LOCKED to Forms Editors,
/// which change forms, not values; this follows edk2: IfrParse.c ParseOpCodes locks the FORM or
/// FORM_MAP that holds a LOCKED right in its scope, with every statement in it, else the
/// innermost statement around it whose scope holds its ops (is_parent_statement), so not a
/// question around that statement, and skips the ops in the scope of an unknown op.
fn locked(question: &IFROperation) -> bool {
    let mut locked = false;
    walk_scopes(&question.children, (), |op, ()| {
        let op = op.borrow();
        match (op.op_code, skips_scope(&op) || is_parent_statement(&op)) {
            (IFROpCode::Locked, _) => {
                locked = true;
                Walk::Skip
            }
            (_, true) => Walk::Skip,
            (_, false) => Walk::Enter(()),
        }
    });
    locked
        || enclosing_form(question).is_some_and(|form| {
            form.borrow()
                .children
                .iter()
                .any(|child| child.borrow().op_code == IFROpCode::Locked)
        })
}

/// Returns the states that the SUPPRESS_IF scopes between `option` and its ONE_OF or
/// ORDERED_LIST can give it: edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes
/// attaches no other condition to an option.
pub(crate) fn option_state(
    option: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> StateEvaluation {
    let mut evaluation = StateEvaluation::selectable();
    let mut scope = option.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = scope {
        let op = op.borrow();
        match OpRole::of(op.op_code) {
            OpRole::Question => break,
            OpRole::Scope(state @ QuestionState::Suppressed) => {
                evaluation.evaluate(state, &op, inputs);
            }
            OpRole::Scope(
                QuestionState::Selectable | QuestionState::GrayedOut | QuestionState::Disabled,
            )
            | OpRole::Expression(_)
            | OpRole::Map
            | OpRole::Other => {}
        }
        scope = op.parent.as_ref().and_then(Weak::upgrade);
    }
    evaluation
}

/// The questions of a FormSet by QuestionId, for conditions to find them as
/// edk2-stable202608 SetupBrowserDxe/Expression.c IdToQuestion does: in the form of the
/// referrer first, then in the FormSet, in form order. parse_form_sets makes each FormSet of a
/// form package a root of its own.
pub(crate) struct QuestionIndex(BTreeMap<u16, Vec<IndexedQuestion>>);

struct IndexedQuestion {
    /// The FORM or FORM_MAP that holds the question
    form: Option<Rc<RefCell<IFROperation>>>,
    question: Rc<RefCell<IFROperation>>,
}

impl QuestionIndex {
    // TODO: leave out the questions under a true DISABLE_IF outside forms, which
    // edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes does not parse, so that a
    // reference to one gives UNDEFINED.
    pub(crate) fn new(root: &Rc<RefCell<IFROperation>>) -> Self {
        let mut index: BTreeMap<u16, Vec<IndexedQuestion>> = BTreeMap::new();
        walk_scopes(std::slice::from_ref(root), None, |node, form| {
            let op = node.borrow();
            if skips_scope(&op) {
                return Walk::Skip;
            }
            // reserved (UEFI 2.10 §33.3.8.2.2)
            if let Some(id) = question_id(&op).filter(|&id| id != 0) {
                index.entry(id).or_default().push(IndexedQuestion {
                    form: form.clone(),
                    question: Rc::clone(node),
                });
            }
            let form = if matches!(op.op_code, IFROpCode::Form | IFROpCode::FormMap) {
                Some(Rc::clone(node))
            } else {
                form.clone()
            };
            Walk::Enter(form)
        });
        QuestionIndex(index)
    }

    /// Returns question `id` as `referrer` finds it.
    fn question(&self, referrer: &IFROperation, id: u16) -> Option<&Rc<RefCell<IFROperation>>> {
        let questions = self.0.get(&id)?;
        let form = enclosing_form(referrer);
        let in_form = questions
            .iter()
            .find(|indexed| match (&form, &indexed.form) {
                (Some(form), Some(question_form)) => Rc::ptr_eq(form, question_form),
                (None, _) | (_, None) => false,
            });
        // TODO: for a SUPPRESS_IF around a FORM, search that FORM first: edk2-stable202608
        // SetupBrowserDxe/Presentation.c evaluates it with Form set to that FORM.
        in_form
            .or_else(|| questions.first())
            .map(|indexed| &indexed.question)
    }
}

/// Whether edk2 skips `op` with its scope, and so every question in it: edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes skips an opcode above EFI_IFR_MATCH2_OP
/// (IsUnKnownOpCode). The root that handle_form_set adds has no parent and is no IFR op.
pub(super) fn skips_scope(op: &IFROperation) -> bool {
    op.parent.is_some()
        && matches!(op.op_code, IFROpCode::Unknown(code) if code > EFI_IFR_MATCH2_OP)
}

/// Returns the FORM or FORM_MAP that holds `op`.
fn enclosing_form(op: &IFROperation) -> Option<Rc<RefCell<IFROperation>>> {
    let mut parent = op.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = parent {
        if matches!(op.borrow().op_code, IFROpCode::Form | IFROpCode::FormMap) {
            return Some(op);
        }
        parent = op.borrow().parent.as_ref().and_then(Weak::upgrade);
    }
    None
}

/// Returns the FORM_SET that holds `op`.
pub(super) fn enclosing_form_set(op: &IFROperation) -> Option<Rc<RefCell<IFROperation>>> {
    let mut parent = op.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = parent {
        if op.borrow().op_code == IFROpCode::FormSet {
            return Some(op);
        }
        parent = op.borrow().parent.as_ref().and_then(Weak::upgrade);
    }
    None
}

/// Returns the QuestionId of the question that holds `op` in its scope.
fn enclosing_question_id(op: &IFROperation) -> Option<u16> {
    let mut parent = op.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = parent {
        if let Some(id) = question_id(&op.borrow()) {
            return Some(id);
        }
        parent = op.borrow().parent.as_ref().and_then(Weak::upgrade);
    }
    None
}

/// Returns the EFI_IFR_QUESTION_HEADER of a question op.
pub(super) fn parse_question_header(op: &IFROperation) -> Option<QuestionHeader> {
    let OpRole::Question = OpRole::of(op.op_code) else {
        return None;
    };
    Cursor::new(&op.data).parse_ne().ok()
}

/// Returns the QuestionId of a question op.
fn question_id(op: &IFROperation) -> Option<u16> {
    if !is_question(op.op_code) {
        return None;
    }
    // EFI_IFR_QUESTION_HEADER, after the Prompt and Help of its statement header
    op.data
        .first_chunk::<6>()
        .map(|&[_, _, _, _, low, high]| u16::from_le_bytes([low, high]))
}

/// Whether ops of `op_code` start with an EFI_IFR_QUESTION_HEADER.
pub(super) fn is_question(op_code: IFROpCode) -> bool {
    matches!(OpRole::of(op_code), OpRole::Question)
}

/// Reads the values of the questions that conditions refer to from their VarStores, as get
/// does.
pub(crate) struct VarStoreValues {
    index: QuestionIndex,
    /// What conditions read from AMI_ACCESS_LEVEL instead of its value, if stated
    access_level: Option<AccessLevel>,
    /// The questions whose values are being retrieved, innermost last: a READ expression that
    /// refers to one of them needs the value that it is to give
    retrieving: RefCell<Vec<Rc<RefCell<IFROperation>>>>,
}

impl VarStoreValues {
    /// Finds the questions in the FormSet of `root`, reading `access_level`, if stated, for
    /// AMI_ACCESS_LEVEL instead of its value.
    pub(crate) fn new(root: &Rc<RefCell<IFROperation>>, access_level: Option<AccessLevel>) -> Self {
        VarStoreValues {
            index: QuestionIndex::new(root),
            access_level,
            retrieving: RefCell::default(),
        }
    }
}

impl QuestionValues for VarStoreValues {
    fn value(
        &self,
        referrer: &IFROperation,
        id: u16,
        reader: &mut EfivarReader,
    ) -> Option<QuestionValue> {
        let question = self.index.question(referrer, id)?;
        let op = question.borrow();
        let Some(value_question) = value_question(&op) else {
            return Some(QuestionValue::Unreadable {
                kind: ValueKind::Other,
                reason: ValueUnavailable::NotDecoded(op.op_code).to_answer(),
            });
        };
        if self.retrieving.borrow().len() >= MAX_READ_DEPTH {
            return Some(QuestionValue::Unreadable {
                kind: value_kind(value_question),
                reason: ValueUnavailable::ReadDepth(id).to_answer(),
            });
        }
        if self
            .retrieving
            .borrow()
            .iter()
            .any(|retrieving| Rc::ptr_eq(retrieving, question))
        {
            return Some(QuestionValue::Unreadable {
                kind: value_kind(value_question),
                reason: ValueUnavailable::ReadCycle(id).to_answer(),
            });
        }
        let varstore =
            find_corresponding_varstore(Rc::clone(question), value_question.header().var_store_id);
        self.retrieving.borrow_mut().push(Rc::clone(question));
        let value = question_value(
            question,
            value_question,
            &varstore,
            self.access_level,
            &mut ExpressionInputs {
                reader,
                values: self,
            },
        );
        self.retrieving.borrow_mut().pop();
        Some(value)
    }
}

/// The EFI_HII_VALUE type of `value_question`'s value.
fn value_kind(value_question: ValueQuestion) -> ValueKind {
    match value_question {
        ValueQuestion::CheckBox(_) => ValueKind::Boolean,
        ValueQuestion::OneOf(_) | ValueQuestion::Numeric(_) => ValueKind::Uint,
    }
}

/// Returns where `question` keeps its value and the value that a browser retrieves for it (UEFI
/// 2.11 §33.2.5.4.1): THIS is the value in `varstore`, which the value of its READ expression,
/// if any, replaces; or why it has none. A READ that gives UNDEFINED or fails leaves the stored
/// value, as edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue reads storage then; a
/// question without a VarStore has none then. A question with an EFI_IFR_VALUE has the value of
/// its expression instead, which GetQuestionValue takes before any READ or storage. The value of
/// an EFI_IFR_VALUE or READ expression comes from the snapshot if THIS or a value that the
/// expression took does.
pub(super) fn retrieve_question_value(
    question: &Rc<RefCell<IFROperation>>,
    varstore: &Result<Box<dyn VariableStore>>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> std::result::Result<RetrievedValue, ValueUnavailable> {
    let op = question.borrow();
    let Some(value_question) = value_question(&op) else {
        return Err(ValueUnavailable::NotDecoded(op.op_code));
    };
    let location = value_question
        .location()
        .check()
        .map_err(ValueUnavailable::BitField)?;
    let taken = inputs.reader.snapshot_values_taken();
    if let Some(value) = question_value_expression(&op) {
        return evaluate_value(&value.borrow(), inputs)
            .map(|value| RetrievedValue {
                location,
                value,
                source: ValueSource::since(taken, inputs.reader),
            })
            .map_err(ValueUnavailable::ValueExpression);
    }
    let stored = read_question_value(&op, varstore, inputs.reader);
    let storageless = varstore
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<NoVarStore>());
    if let Some(NoVarStore(storageless)) = storageless {
        if storageless
            .refusal(QuestionExpression::Read, inputs.reader.reach())
            .is_some()
        {
            return stored;
        }
    }
    let unreadable = |reason: &ValueUnavailable| QuestionValue::Unreadable {
        kind: value_kind(value_question),
        reason: reason.to_answer(),
    };
    let this = match &stored {
        Ok(stored) => {
            typed_value(value_question, stored.value).unwrap_or_else(|reason| unreadable(&reason))
        }
        Err(reason) => unreadable(reason),
    };
    match evaluate_read(question, this, inputs) {
        ReadOutcome::NoRead => stored,
        ReadOutcome::Stored => match storageless {
            Some(_) => Err(ValueUnavailable::Storageless(
                StoragelessRefusal::ReadUndefined,
            )),
            None => stored,
        },
        ReadOutcome::Value(value) => Ok(RetrievedValue {
            location,
            value: value.as_u64(),
            source: ValueSource::since(taken, inputs.reader),
        }),
        ReadOutcome::Refused(refusal) => Err(ValueUnavailable::Expression(refusal)),
    }
}

/// Returns the value of `question`, which is `value_question`, as retrieve_question_value
/// retrieves it from `varstore`, typed as edk2-stable202608 SetupBrowserDxe/IfrParse.c
/// ParseOpCodes types it: on AMI_ACCESS_LEVEL, `access_level` instead, if stated.
fn question_value(
    question: &Rc<RefCell<IFROperation>>,
    value_question: ValueQuestion,
    varstore: &Result<Box<dyn VariableStore>>,
    access_level: Option<AccessLevel>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> QuestionValue {
    let kind = value_kind(value_question);
    // the level is the one byte of SystemAccess that AMI IFR reads
    let on_access_level = value_question.location()
        == (ValueLocation::Bytes { offset: 0, size: 1 })
        && matches!(varstore, Ok(store) if AMI_ACCESS_LEVEL.identifies(store.as_ref()));
    let value = match (on_access_level, access_level) {
        // AMI IFR also compares the level with 85, of unknown meaning, in a SUPPRESS_IF NOT
        // around a REF, which either stated level suppresses
        (true, Some(level)) => Ok(u64::from(u8::from(level))),
        (true, None) | (false, Some(_) | None) => {
            retrieve_question_value(question, varstore, inputs).map(|retrieved| retrieved.value)
        }
    };
    let reason = match value.and_then(|value| typed_value(value_question, value)) {
        Ok(value) => return value,
        Err(reason) => reason,
    };
    let reason = match on_access_level {
        true => ValueUnavailable::AmiAccessLevel(Box::new(reason)),
        false => reason,
    };
    QuestionValue::Unreadable {
        kind,
        reason: reason.to_answer(),
    }
}

/// `value`, read for `value_question`, as a QuestionValue.
fn typed_value(
    value_question: ValueQuestion,
    value: u64,
) -> std::result::Result<QuestionValue, ValueUnavailable> {
    match value_question {
        // a byte or a bit
        ValueQuestion::CheckBox(_) => u8::try_from(value)
            .map(QuestionValue::Boolean)
            .map_err(|_| ValueUnavailable::CheckboxOverByte(value)),
        ValueQuestion::OneOf(_) | ValueQuestion::Numeric(_) => Ok(QuestionValue::Uint(value)),
    }
}

/// The truth of a condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Truth {
    Known(bool),
    /// Depends on a value that cannot be read, an op that is not evaluated, or malformed IFR:
    /// the reason
    Unknown(String),
}

/// What the EFI_HII_VALUE of a question holds, as edk2-stable202608 SetupBrowserDxe/IfrParse.c
/// ParseOpCodes types it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValueKind {
    /// EFI_IFR_TYPE_BOOLEAN of a CHECKBOX
    Boolean,
    /// EFI_IFR_TYPE_NUM_SIZE_8 to _64 of a ONE_OF or NUMERIC
    Uint,
    /// Any other type, which nothing here decodes
    Other,
}

/// The value of a question that a condition refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum QuestionValue {
    /// The stored byte as is
    Boolean(u8),
    Uint(u64),
    Unreadable {
        kind: ValueKind,
        reason: String,
    },
}

/// Finds the values of the questions that conditions refer to.
pub(crate) trait QuestionValues {
    /// Returns the value of question `id` as `referrer` sees it, read through `reader`, or None
    /// if no question has `id`.
    fn value(
        &self,
        referrer: &IFROperation,
        id: u16,
        reader: &mut EfivarReader,
    ) -> Option<QuestionValue>;
}

/// What expressions take the values of questions from: `values` finds the question that an
/// expression refers to, and `reader` reads the efivar that holds its value.
pub(crate) struct ExpressionInputs<'a, V> {
    pub(crate) reader: &'a mut EfivarReader,
    pub(crate) values: &'a V,
}

/// Returns the truth of the condition of the SUPPRESS_IF, GRAY_OUT_IF or DISABLE_IF `scope`.
pub(crate) fn evaluate_condition(
    scope: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Truth {
    let mut evaluation = Evaluation::new(inputs, Role::Reads);
    match evaluation.run(scope) {
        Ok(Operand::Boolean(Some(value))) => Truth::Known(value != 0),
        Ok(Operand::Uint(Some(value))) => Truth::Known(value != 0),
        Ok(Operand::Boolean(None) | Operand::Uint(None)) => {
            Truth::Unknown(evaluation.into_unknown())
        }
        // edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression ends at an
        // UNDEFINED, keeping it as the result, which IsTrue takes as FALSE
        Err(Abort::Undefined) => Truth::Known(false),
        // edk2-stable202608 SetupBrowserDxe/Presentation.c EvaluateFormExpressions refuses to
        // show the form
        Err(Abort::Malformed(reason)) => Truth::Unknown(format!("malformed condition: {reason}")),
        Err(Abort::NotEvaluated(reason)) => Truth::Unknown(reason),
    }
}

/// Returns the value of the expression of the EFI_IFR_VALUE `scope` as a UINT64, or why it
/// is not known.
pub(crate) fn evaluate_value(
    scope: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> std::result::Result<u64, String> {
    let mut evaluation = Evaluation::new(inputs, Role::Reads);
    match evaluation.run(scope) {
        Ok(operand) => operand.as_u64().ok_or_else(|| evaluation.into_unknown()),
        Err(Abort::Undefined) => Err("UNDEFINED result".to_string()),
        Err(Abort::Malformed(reason)) => Err(format!("malformed expression: {reason}")),
        Err(Abort::NotEvaluated(reason)) => Err(reason),
    }
}

/// What the READ expression of a question gives.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReadOutcome {
    /// The question has no READ that edk2-stable202608 SetupBrowserDxe evaluates
    NoRead,
    /// READ's value, which replaces the stored one
    Value(ExpressionValue),
    /// READ gives UNDEFINED or fails, so the question keeps its stored value, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue reads storage then
    Stored,
    /// READ cannot be evaluated here
    Refused(ExpressionRefusal),
}

/// Evaluates the READ expression of `question`, with THIS its stored value `this` (UEFI 2.11
/// §33.2.5.4.1).
pub(crate) fn evaluate_read(
    question: &Rc<RefCell<IFROperation>>,
    this: QuestionValue,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> ReadOutcome {
    let Some(expression) = question_expression(question, QuestionExpression::Read) else {
        return ReadOutcome::NoRead;
    };
    let mut evaluation = Evaluation::new(inputs, Role::Read(this));
    match evaluation.run_ops(&expression) {
        Ok(operand) => match ExpressionValue::of(operand) {
            Some(value) => ReadOutcome::Value(value),
            None => ReadOutcome::Refused(
                evaluation.into_refusal(QuestionExpression::Read, "no value".to_string()),
            ),
        },
        Err(Abort::Undefined | Abort::Malformed(_)) => ReadOutcome::Stored,
        Err(Abort::NotEvaluated(reason)) => {
            ReadOutcome::Refused(evaluation.into_refusal(QuestionExpression::Read, reason))
        }
    }
}

/// Evaluates the WRITE expression of `question`, with THIS its new value `this` (UEFI 2.11
/// §33.2.5.4.1), and returns its SETs, in order, or None if it has no WRITE that
/// edk2-stable202608 SetupBrowserDxe evaluates. An UNDEFINED ends it after the SETs before, as
/// Expression.c EvaluateExpression ends there and Setup.c SetQuestionValue goes on.
pub(crate) fn evaluate_write(
    question: &Rc<RefCell<IFROperation>>,
    this: QuestionValue,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> std::result::Result<Option<Vec<PlannedSet>>, ExpressionRefusal> {
    let Some(expression) = question_expression(question, QuestionExpression::Write) else {
        return Ok(None);
    };
    let mut sets = Vec::new();
    let mut evaluation = Evaluation::new(
        inputs,
        Role::Write {
            this,
            sets: &mut sets,
        },
    );
    match evaluation.run_ops(&expression) {
        Ok(_) | Err(Abort::Undefined) => {}
        Err(Abort::Malformed(reason)) => {
            return Err(ExpressionRefusal::Malformed {
                expression: QuestionExpression::Write,
                reason,
            })
        }
        Err(Abort::NotEvaluated(reason)) => {
            return Err(evaluation.into_refusal(QuestionExpression::Write, reason))
        }
    }
    drop(evaluation);
    Ok(Some(sets))
}

/// Returns the ops of the READ or WRITE expression of `question`, if edk2-stable202608
/// SetupBrowserDxe evaluates one there: on a FORM, a standard map form, or outside forms, where
/// uefisettings lists questions too, as on a FORM. IfrParse.c ParseOpCodes keeps the last READ or
/// WRITE in the question's scope, and takes the op after it, with that op's scope, as its
/// expression; here the leading expression ops after it, as in a condition.
pub(super) fn question_expression(
    question: &Rc<RefCell<IFROperation>>,
    kind: QuestionExpression,
) -> Option<Vec<Rc<RefCell<IFROperation>>>> {
    // edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue takes the value of a question
    // with an EFI_IFR_VALUE from it, before any READ, and SetQuestionValue returns before WRITE:
    // the question is read-only (UEFI 2.11 §33.3.8.3.88)
    if question_value_expression(&question.borrow()).is_some()
        || !evaluates_read_and_write(&question.borrow())
    {
        return None;
    }
    let mut found = None;
    // each scope that the walk is in, with the index of its next op: the walk in IFR order
    let mut frames = vec![(Rc::clone(question), 0)];
    while let Some((scope, index)) = frames.pop() {
        let Some(op) = scope.borrow().children.get(index).cloned() else {
            continue;
        };
        frames.push((Rc::clone(&scope), index + 1));
        let borrowed = op.borrow();
        if skips_scope(&borrowed) || matches!(OpRole::of(borrowed.op_code), OpRole::Question) {
            continue;
        }
        if borrowed.op_code == kind.op_code() {
            found = Some(match borrowed.open_scope {
                true => leading_expression(&borrowed.children),
                false => {
                    leading_expression(scope.borrow().children.get(index + 1..).unwrap_or_default())
                }
            });
        }
        if borrowed.open_scope {
            frames.push((Rc::clone(&op), 0));
        }
    }
    found
}

/// The EFI_IFR_VALUE that gives the value of `question`: the last in its scope (question_scope),
/// never one in an EFI_IFR_DEFAULT or in a statement nested in it, as edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes makes each VALUE outside a DEFAULT the
/// ValueExpression of its ParentStatement. Nor one in an EFI_IFR_ONE_OF_OPTION, whose value it
/// gives (UEFI 2.11 §33.3.8.3.51), though ParseOpCodes takes that one as the question's too.
pub(super) fn question_value_expression(
    question: &IFROperation,
) -> Option<Rc<RefCell<IFROperation>>> {
    question_scope(question).into_iter().rfind(|op| {
        let op = op.borrow();
        op.op_code == IFROpCode::Value && !in_one_of_option(&op, question)
    })
}

/// Whether `op`, in the scope of `question`, is in the scope of an EFI_IFR_ONE_OF_OPTION there.
fn in_one_of_option(op: &IFROperation, question: &IFROperation) -> bool {
    let mut parent = op.parent.as_ref().and_then(Weak::upgrade);
    while let Some(scope) = parent {
        if std::ptr::eq(scope.as_ptr(), question) {
            return false;
        }
        if scope.borrow().op_code == IFROpCode::OneOfOption {
            return true;
        }
        parent = scope.borrow().parent.as_ref().and_then(Weak::upgrade);
    }
    false
}

/// Why set refuses a question with an EFI_IFR_VALUE.
pub(super) const VALUE_MAKES_READ_ONLY: &str =
    "its EFI_IFR_VALUE expression makes it read-only (UEFI 2.11 §33.3.8.3.88)";

/// Whether edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue and SetQuestionValue take
/// `question` through its READ and WRITE expressions: on a FORM and on a FORM_MAP with the
/// standard method (IfrParse.c ParseOpCodes); outside forms, here, as on a FORM.
fn evaluates_read_and_write(question: &IFROperation) -> bool {
    let Some(form) = enclosing_form(question) else {
        return true;
    };
    let form = form.borrow();
    if form.op_code != IFROpCode::FormMap {
        return true;
    }
    matches!(&form.parsed_data, ParsedOperation::FormMap(form_map) if form_map.has_standard_method())
}

/// An EFI_HII_VALUE on the expression stack; None is a value that cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operand {
    /// EFI_IFR_TYPE_BOOLEAN, the stored byte as is
    Boolean(Option<u8>),
    /// EFI_IFR_TYPE_NUM_SIZE_8 to _64, which edk2-stable202608 SetupBrowserDxe/Expression.c
    /// HiiValueToUINT64 widens
    Uint(Option<u64>),
}

impl Operand {
    /// Returns the value as edk2-stable202608 SetupBrowserDxe/Expression.c HiiValueToUINT64
    /// does.
    fn as_u64(self) -> Option<u64> {
        match self {
            Operand::Boolean(value) => value.map(u64::from),
            Operand::Uint(value) => value,
        }
    }

    /// Returns the BOOLEAN value as a C condition takes it, or Undefined for an integer.
    fn as_bool(self) -> Result<Option<bool>, Abort> {
        match self {
            Operand::Boolean(value) => Ok(value.map(|value| value != 0)),
            Operand::Uint(_) => Err(Abort::Undefined),
        }
    }
}

fn boolean(value: Option<bool>) -> Operand {
    Operand::Boolean(value.map(u8::from))
}

/// The label of a VARSTORE_NAME_VALUE in refusals.
const NAME_VALUE_STORE: &str = "EFI_IFR_VARSTORE_NAME_VALUE";
/// Why a GET or SET does not reach a VARSTORE_NAME_VALUE, after the VarStore.
const NAME_VALUE_REACH: &str = "which only the driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches";

/// The value that a READ expression gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExpressionValue {
    /// EFI_IFR_TYPE_BOOLEAN, the byte as is
    Boolean(u8),
    /// EFI_IFR_TYPE_NUM_SIZE_8 to _64
    Uint(u64),
}

impl ExpressionValue {
    /// Returns `operand` if its value can be read.
    fn of(operand: Operand) -> Option<Self> {
        match operand {
            Operand::Boolean(value) => value.map(Self::Boolean),
            Operand::Uint(value) => value.map(Self::Uint),
        }
    }

    /// Returns the value as edk2-stable202608 SetupBrowserDxe/Expression.c HiiValueToUINT64
    /// does.
    fn as_u64(self) -> u64 {
        match self {
            Self::Boolean(value) => u64::from(value),
            Self::Uint(value) => value,
        }
    }
}

/// The READ or WRITE expression of a question (UEFI 2.11 §33.2.5.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuestionExpression {
    Read,
    Write,
}

impl QuestionExpression {
    fn op_code(self) -> IFROpCode {
        match self {
            Self::Read => IFROpCode::Read,
            Self::Write => IFROpCode::Write,
        }
    }
}

impl fmt::Display for QuestionExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        })
    }
}

/// Whether a GET reads or a SET writes a VarStore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreAccess {
    Reads,
    Sets,
}

impl fmt::Display for StoreAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Reads => "reads",
            Self::Sets => "sets",
        })
    }
}

/// Why get or set does not take a question's value through its READ or WRITE expression.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ExpressionRefusal {
    /// It reads or sets a VarStore that this backend cannot reach
    #[error("its {expression} expression {access} VarStore {id:#06x} ({store}), {reason}")]
    VarStore {
        expression: QuestionExpression,
        access: StoreAccess,
        id: u16,
        /// The op that declares the VarStore, and its Name
        store: String,
        /// A clause after the VarStore: why
        reason: String,
    },
    /// It uses an op, or a kind of stored value, that is not evaluated here
    #[error("its {expression} expression uses {what}, which uefisettings does not evaluate")]
    NotEvaluated {
        expression: QuestionExpression,
        what: String,
    },
    /// It takes a value that cannot be read
    #[error("its {expression} expression takes a value that cannot be read: {reason}")]
    Unread {
        expression: QuestionExpression,
        reason: String,
    },
    /// A WRITE that edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue fails on
    #[error("its {expression} expression is malformed: {reason}")]
    Malformed {
        expression: QuestionExpression,
        reason: String,
    },
}

/// The first reason why a READ or WRITE expression is not evaluated here, for its refusal.
enum Gap {
    /// A VarStore that it reads or sets, which this backend cannot reach
    VarStore {
        access: StoreAccess,
        id: u16,
        store: String,
        reason: String,
    },
    /// An op, or a kind of stored value, that is not evaluated here
    NotEvaluated(String),
}

/// A SET of a WRITE expression: the little-endian `bytes` that it writes at VarOffset `offset` of
/// `store`, VarStore `var_store_id`, as edk2-stable202608 SetupBrowserDxe/Expression.c
/// EvaluateExpression copies them into its edit buffer.
pub(crate) struct PlannedSet {
    pub(crate) var_store_id: u16,
    pub(crate) store: Box<dyn VariableStore>,
    pub(crate) offset: u16,
    pub(crate) bytes: Vec<u8>,
}

impl PlannedSet {
    /// The refusal of a WRITE expression with this SET, of a VarStore that set does not write:
    /// `reason`, a clause after the VarStore.
    pub(super) fn unwritable(&self, reason: String) -> ExpressionRefusal {
        ExpressionRefusal::VarStore {
            expression: QuestionExpression::Write,
            access: StoreAccess::Sets,
            id: self.var_store_id,
            store: store_label(self.store.as_ref()),
            reason,
        }
    }
}

/// What THIS pushes and where a SET goes, by the expression that an evaluation runs.
enum Role<'a> {
    /// A condition, a default or an EFI_IFR_VALUE: THIS is the value of the question that holds
    /// it, and a SET is not evaluated
    Reads,
    /// The READ of a question: THIS is its stored value (UEFI 2.11 §33.2.5.4.1)
    Read(QuestionValue),
    /// The WRITE of a question: THIS is its new value, and each SET joins `sets`
    Write {
        this: QuestionValue,
        sets: &'a mut Vec<PlannedSet>,
    },
}

/// The kind of value that a GET reads or a SET writes.
#[derive(Clone, Copy)]
enum OperandKind {
    /// EFI_IFR_TYPE_BOOLEAN, a byte
    Boolean,
    /// An integer of this many bytes
    Uint(u8),
}

impl OperandKind {
    fn width(self) -> u8 {
        match self {
            Self::Boolean => 1,
            Self::Uint(width) => width,
        }
    }

    /// The value that `bytes`, the stored value, hold.
    fn operand(self, bytes: &[u8]) -> Operand {
        match self {
            Self::Boolean => Operand::Boolean(bytes.first().copied()),
            Self::Uint(_) => Operand::Uint(Some(stored_value(bytes))),
        }
    }

    /// A value of this kind that cannot be read.
    fn unknown(self) -> Operand {
        match self {
            Self::Boolean => Operand::Boolean(None),
            Self::Uint(_) => Operand::Uint(None),
        }
    }
}

/// Returns the VarStore that the GET or SET `op` names, as its FormSet declares it.
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes fails the FormSet on an undeclared
/// one, and Expression.c EvaluateExpression the expression on one without a VarStore, but for
/// the RTC fields of DATE and TIME, which operand_kind does not evaluate.
fn operand_store(op: &IFROperation, operand: &VarStoreOperand) -> Result<DeclaredStore, Abort> {
    let id = operand.var_store_id;
    if id == 0 {
        return Err(Abort::Malformed(format!(
            "{} of an integer without a VarStore",
            op.op_code.spec_name()
        )));
    }
    enclosing_form_set(op)
        .and_then(|form_set| declared_var_store(&form_set.borrow(), id))
        .ok_or_else(|| {
            Abort::Malformed(format!(
                "{} of undeclared VarStore {id:#06x}",
                op.op_code.spec_name()
            ))
        })
}

/// Returns `declared` as an EFI variable VarStore, or, of one that a GET or SET does not reach,
/// its label and why, after the VarStore.
fn variable_store(
    declared: DeclaredStore,
) -> Result<Box<dyn VariableStore>, (&'static str, &'static str)> {
    match declared {
        DeclaredStore::Variable(store) => Ok(store),
        DeclaredStore::NameValue(_) => Err((NAME_VALUE_STORE, NAME_VALUE_REACH)),
        DeclaredStore::ShortEfi(_) => Err((ShortVarStoreEfi::LABEL, ShortVarStoreEfi::UNREAD)),
    }
}

/// Returns the payload bytes of `store` that the GET or SET `op` of `kind` reads or writes: its
/// VarOffset in a VARSTORE or VARSTORE_EFI, all within the Size of the VarStore.
fn operand_range(
    op: &IFROperation,
    operand: &VarStoreOperand,
    kind: OperandKind,
    store: &dyn VariableStore,
) -> Result<std::ops::Range<usize>, Abort> {
    let start = usize::from(operand.var_store_info);
    let end = start + usize::from(kind.width());
    if end > usize::from(store.size()) {
        return Err(Abort::Malformed(format!(
            "{} of {} bytes at VarOffset {start:#06x} of a VarStore of {} bytes",
            op.op_code.spec_name(),
            kind.width(),
            store.size()
        )));
    }
    Ok(start..end)
}

/// The label of `store` in refusals: the op that declares it, and its Name.
fn store_label(store: &dyn VariableStore) -> String {
    let op = match store.kind() {
        VariableStoreKind::Buffer => "EFI_IFR_VARSTORE",
        VariableStoreKind::EfiVariable => "EFI_IFR_VARSTORE_EFI",
    };
    format!("{op} {:?}", store.name())
}

/// Why an evaluation ended before its last op.
enum Abort {
    /// An op gave EFI_IFR_TYPE_UNDEFINED
    Undefined,
    /// An op that edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression fails on,
    /// e.g. one on an empty stack
    Malformed(String),
    NotEvaluated(String),
}

/// Why `op` cannot be evaluated: its operands were not decoded.
fn not_decoded(op: &IFROperation) -> Abort {
    Abort::Malformed(format!("{} not decoded", op.op_code.spec_name()))
}

/// What conditions take an op for.
#[derive(Clone, Copy)]
enum OpRole {
    /// An op of edk2-stable202608 SetupBrowserDxe/IfrParse.c IsExpressionOpCode
    Expression(ExpressionOp),
    /// EFI_IFR_MAP, the expression op whose scope holds expressions that it evaluates itself
    Map,
    /// An op with an EFI_IFR_QUESTION_HEADER
    Question,
    /// A SUPPRESS_IF, GRAY_OUT_IF or DISABLE_IF, and the state its true condition gives
    Scope(QuestionState),
    Other,
}

/// An expression op, by how it is evaluated.
#[derive(Clone, Copy)]
enum ExpressionOp {
    EqIdVal,
    EqIdId,
    EqIdValList,
    QuestionRef1,
    Constant(Operand),
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Undefined,
    Not,
    ToBoolean,
    BitwiseNot,
    And,
    Or,
    Compare(Comparison),
    Arithmetic(Arithmetic),
    Dup,
    Conditional,
    This,
    Get,
    Set,
    /// Evaluated by edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression but not
    /// here
    NotEvaluated,
}

#[derive(Clone, Copy)]
enum Comparison {
    Equal,
    NotEqual,
    GreaterThan,
    GreaterEqual,
    LessThan,
    LessEqual,
}

#[derive(Clone, Copy)]
enum Arithmetic {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    BitwiseAnd,
    BitwiseOr,
    ShiftLeft,
    ShiftRight,
}

impl OpRole {
    fn of(op_code: IFROpCode) -> Self {
        use ExpressionOp as E;
        match op_code {
            IFROpCode::EqIdVal => Self::Expression(E::EqIdVal),
            IFROpCode::EqIdId => Self::Expression(E::EqIdId),
            IFROpCode::EqIdValList => Self::Expression(E::EqIdValList),
            IFROpCode::QuestionRef1 => Self::Expression(E::QuestionRef1),
            IFROpCode::True => Self::Expression(E::Constant(Operand::Boolean(Some(1)))),
            IFROpCode::False => Self::Expression(E::Constant(Operand::Boolean(Some(0)))),
            IFROpCode::One => Self::Expression(E::Constant(Operand::Uint(Some(1)))),
            IFROpCode::Zero => Self::Expression(E::Constant(Operand::Uint(Some(0)))),
            IFROpCode::Ones => Self::Expression(E::Constant(Operand::Uint(Some(u64::MAX)))),
            IFROpCode::Uint8 => Self::Expression(E::Uint8),
            IFROpCode::Uint16 => Self::Expression(E::Uint16),
            IFROpCode::Uint32 => Self::Expression(E::Uint32),
            IFROpCode::Uint64 => Self::Expression(E::Uint64),
            IFROpCode::Undefined => Self::Expression(E::Undefined),
            IFROpCode::Not => Self::Expression(E::Not),
            IFROpCode::ToBoolean => Self::Expression(E::ToBoolean),
            IFROpCode::BitwiseNot => Self::Expression(E::BitwiseNot),
            IFROpCode::And => Self::Expression(E::And),
            IFROpCode::Or => Self::Expression(E::Or),
            IFROpCode::Equal => Self::Expression(E::Compare(Comparison::Equal)),
            IFROpCode::NotEqual => Self::Expression(E::Compare(Comparison::NotEqual)),
            IFROpCode::GreaterThan => Self::Expression(E::Compare(Comparison::GreaterThan)),
            IFROpCode::GreaterEqual => Self::Expression(E::Compare(Comparison::GreaterEqual)),
            IFROpCode::LessThan => Self::Expression(E::Compare(Comparison::LessThan)),
            IFROpCode::LessEqual => Self::Expression(E::Compare(Comparison::LessEqual)),
            IFROpCode::Add => Self::Expression(E::Arithmetic(Arithmetic::Add)),
            IFROpCode::Subtract => Self::Expression(E::Arithmetic(Arithmetic::Subtract)),
            IFROpCode::Multiply => Self::Expression(E::Arithmetic(Arithmetic::Multiply)),
            IFROpCode::Divide => Self::Expression(E::Arithmetic(Arithmetic::Divide)),
            IFROpCode::Modulo => Self::Expression(E::Arithmetic(Arithmetic::Modulo)),
            IFROpCode::BitwiseAnd => Self::Expression(E::Arithmetic(Arithmetic::BitwiseAnd)),
            IFROpCode::BitwiseOr => Self::Expression(E::Arithmetic(Arithmetic::BitwiseOr)),
            IFROpCode::ShiftLeft => Self::Expression(E::Arithmetic(Arithmetic::ShiftLeft)),
            IFROpCode::ShiftRight => Self::Expression(E::Arithmetic(Arithmetic::ShiftRight)),
            IFROpCode::Dup => Self::Expression(E::Dup),
            IFROpCode::Conditional => Self::Expression(E::Conditional),
            IFROpCode::This => Self::Expression(E::This),
            IFROpCode::Get => Self::Expression(E::Get),
            IFROpCode::Set => Self::Expression(E::Set),
            IFROpCode::Map => Self::Map,
            IFROpCode::Match
            | IFROpCode::RuleRef
            | IFROpCode::QuestionRef2
            | IFROpCode::QuestionRef3
            | IFROpCode::ToUint
            | IFROpCode::ToString
            | IFROpCode::Mid
            | IFROpCode::Find
            | IFROpCode::Token
            | IFROpCode::StringRef1
            | IFROpCode::StringRef2
            | IFROpCode::Length
            | IFROpCode::Span
            | IFROpCode::Catenate
            | IFROpCode::ToLower
            | IFROpCode::ToUpper
            | IFROpCode::Version
            | IFROpCode::Security
            | IFROpCode::Match2 => Self::Expression(E::NotEvaluated),
            IFROpCode::Form
            | IFROpCode::Subtitle
            | IFROpCode::Text
            | IFROpCode::Image
            | IFROpCode::OneOfOption
            | IFROpCode::Locked
            | IFROpCode::ResetButton
            | IFROpCode::FormSet
            | IFROpCode::NoSubmitIf
            | IFROpCode::InconsistentIf
            | IFROpCode::Rule
            | IFROpCode::Refresh
            | IFROpCode::Animation
            | IFROpCode::VarStore
            | IFROpCode::VarStoreNameValue
            | IFROpCode::VarStoreEfi
            | IFROpCode::VarStoreDevice
            | IFROpCode::End
            | IFROpCode::Read
            | IFROpCode::Write
            | IFROpCode::Value
            | IFROpCode::Default
            | IFROpCode::DefaultStore
            | IFROpCode::FormMap
            | IFROpCode::Guid
            | IFROpCode::ModalTag
            | IFROpCode::RefreshId
            | IFROpCode::WarningIf
            | IFROpCode::Unknown(_) => Self::Other,
            IFROpCode::OneOf
            | IFROpCode::CheckBox
            | IFROpCode::Numeric
            | IFROpCode::Password
            | IFROpCode::Action
            | IFROpCode::Ref
            | IFROpCode::Date
            | IFROpCode::Time
            | IFROpCode::String
            | IFROpCode::OrderedList => Self::Question,
            IFROpCode::SuppressIf => Self::Scope(QuestionState::Suppressed),
            IFROpCode::GrayOutIf => Self::Scope(QuestionState::GrayedOut),
            IFROpCode::DisableIf => Self::Scope(QuestionState::Disabled),
        }
    }
}

/// The state of the evaluation of one expression.
struct Evaluation<'a, V> {
    reader: &'a mut EfivarReader,
    values: &'a V,
    role: Role<'a>,
    stack: Vec<Operand>,
    /// Why the first value that cannot be read cannot be
    unknown: Option<String>,
    /// The first VarStore that it cannot reach, or op that is not evaluated
    gap: Option<Gap>,
}

impl<'a, V: QuestionValues> Evaluation<'a, V> {
    fn new(inputs: &'a mut ExpressionInputs<'_, V>, role: Role<'a>) -> Self {
        Evaluation {
            reader: inputs.reader,
            values: inputs.values,
            role,
            stack: Vec::new(),
            unknown: None,
            gap: None,
        }
    }

    /// Returns why a value that the result depends on cannot be read.
    // TODO: name a value that the result depends on, not the first unreadable one, which AND or
    // OR may have made irrelevant: carry the reason in each Operand.
    fn into_unknown(self) -> String {
        self.unknown
            .unwrap_or_else(|| "expression not evaluated".to_string())
    }

    /// Evaluates the expression of `scope`, and returns the value it leaves.
    fn run(&mut self, scope: &IFROperation) -> Result<Operand, Abort> {
        self.run_ops(&leading_expression(&scope.children))
    }

    /// Evaluates `expression`, and returns the value it leaves: each op, then the ops in its
    /// scope, in IFR order, but those of a MAP, whose expressions it evaluates pair by pair.
    /// What is left waits on a stack on the heap, not in recursive calls, as in walk_scopes, so
    /// that nested MAPs do not grow the thread's stack.
    fn run_ops(&mut self, expression: &[Rc<RefCell<IFROperation>>]) -> Result<Operand, Abort> {
        let mut pending: Vec<Pending> = expression
            .iter()
            .rev()
            .map(|op| Pending::Op(Rc::clone(op)))
            .collect();
        while let Some(next) = pending.pop() {
            let mut done = match next {
                Pending::Op(op) => self.visit(&op, &mut pending),
                Pending::Match(progress) => self.matched(progress, &mut pending),
                Pending::Return { outer } => self.returned(outer),
            };
            // edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue matches no
            // UNDEFINED: the match expression that gives it, whatever op in it does, takes its
            // MAP to the next pair
            while let Err(Abort::Undefined) = done {
                let Some(progress) = unwind_to_match(&mut pending) else {
                    return Err(Abort::Undefined);
                };
                self.stack.clear();
                done = self.next_pair(progress.next(), &mut pending);
            }
            done?;
        }
        self.sole_value()
    }

    /// Pops the one value that the stack holds, as an expression leaves it.
    fn sole_value(&mut self) -> Result<Operand, Abort> {
        let result = self
            .stack
            .pop()
            .ok_or_else(|| Abort::Malformed("no value".to_string()))?;
        match self.stack.len() {
            0 => Ok(result),
            left => Err(Abort::Malformed(format!("{} values left", left + 1))),
        }
    }

    /// Evaluates `op`, pushing its value and then the ops of its scope; a MAP pops its value and
    /// starts its first pair.
    fn visit(
        &mut self,
        op: &Rc<RefCell<IFROperation>>,
        pending: &mut Vec<Pending>,
    ) -> Result<(), Abort> {
        let borrowed = op.borrow();
        if skips_scope(&borrowed) {
            return Ok(());
        }
        if let OpRole::Map = OpRole::of(borrowed.op_code) {
            let progress = MapProgress {
                map: Rc::clone(op),
                checked: self.pop(&borrowed)?,
                pair: 0,
                outer: std::mem::take(&mut self.stack),
            };
            return self.next_pair(progress, pending);
        }
        let value = self.step(&borrowed)?;
        self.stack.push(value);
        pending.extend(
            borrowed
                .children
                .iter()
                .rev()
                .map(|child| Pending::Op(Rc::clone(child))),
        );
        Ok(())
    }

    /// Starts the match expression of the pair that `progress` is at, on a stack of its own, as
    /// edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression evaluates each
    /// expression of a MAP; after the last pair, the MAP gives UNDEFINED (UEFI 2.11
    /// §33.3.8.3.38).
    fn next_pair(
        &mut self,
        progress: MapProgress,
        pending: &mut Vec<Pending>,
    ) -> Result<(), Abort> {
        let matched = progress.match_expression()?.ok_or(Abort::Undefined)?;
        pending.push(Pending::Match(progress));
        pending.push(Pending::Op(matched));
        Ok(())
    }

    /// Takes the value of the match expression of the pair that `progress` is at: if it equals
    /// the value that the MAP compares, starts the pair's return expression, else the next pair.
    fn matched(&mut self, progress: MapProgress, pending: &mut Vec<Pending>) -> Result<(), Abort> {
        let candidate = self.sole_value()?;
        match compare(Comparison::Equal, progress.checked, candidate) {
            Operand::Boolean(Some(0)) => self.next_pair(progress.next(), pending),
            Operand::Boolean(Some(_)) => {
                let returned = progress.return_expression()?;
                pending.push(Pending::Return {
                    outer: progress.outer,
                });
                pending.push(Pending::Op(returned));
                Ok(())
            }
            Operand::Boolean(None) | Operand::Uint(_) => Err(Abort::NotEvaluated(format!(
                "{} on a value that cannot be read",
                progress.map.borrow().op_code.spec_name()
            ))),
        }
    }

    /// Takes the value of the return expression of a MAP as the MAP's, on `outer`, the stack
    /// before the MAP.
    fn returned(&mut self, outer: Vec<Operand>) -> Result<(), Abort> {
        let value = self.sole_value()?;
        self.stack = outer;
        self.stack.push(value);
        Ok(())
    }

    /// The refusal of the READ or WRITE `expression` that this evaluated, whose evaluation ended
    /// for `reason` or on a value that cannot be read: the first gap, if any.
    fn into_refusal(self, expression: QuestionExpression, reason: String) -> ExpressionRefusal {
        match self.gap {
            Some(Gap::VarStore {
                access,
                id,
                store,
                reason,
            }) => ExpressionRefusal::VarStore {
                expression,
                access,
                id,
                store,
                reason,
            },
            Some(Gap::NotEvaluated(what)) => ExpressionRefusal::NotEvaluated { expression, what },
            None => ExpressionRefusal::Unread {
                expression,
                reason: self.unknown.unwrap_or(reason),
            },
        }
    }

    /// Notes that `what` is not evaluated here, and returns the Abort that says so.
    fn not_evaluated(&mut self, what: String) -> Abort {
        let abort = Abort::NotEvaluated(format!("{what} not evaluated"));
        self.gap.get_or_insert(Gap::NotEvaluated(what));
        abort
    }

    /// Notes that `access` of VarStore `id` of `op`, labeled `store`, cannot reach it for
    /// `reason`, a clause after the VarStore, and returns why, for a value that cannot be read.
    fn unreached(
        &mut self,
        op: &IFROperation,
        access: StoreAccess,
        id: u16,
        store: String,
        reason: String,
    ) -> String {
        let why = format!(
            "{} of VarStore {id:#06x} ({store}), {reason}",
            op.op_code.spec_name()
        );
        self.unknown.get_or_insert_with(|| why.clone());
        self.gap.get_or_insert(Gap::VarStore {
            access,
            id,
            store,
            reason,
        });
        why
    }

    /// Pops the operand of `op`.
    fn pop(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        self.stack.pop().ok_or_else(|| {
            Abort::Malformed(format!("{} without an operand", op.op_code.spec_name()))
        })
    }

    /// Returns the value of `op` (edk2-stable202608 SetupBrowserDxe/Expression.c
    /// EvaluateExpression).
    fn step(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        let OpRole::Expression(expression) = OpRole::of(op.op_code) else {
            return Err(Abort::Malformed(format!(
                "{} in an expression",
                op.op_code.spec_name()
            )));
        };
        match expression {
            ExpressionOp::EqIdVal => {
                let ParsedOperation::EqIdVal(parsed) = &op.parsed_data else {
                    return Err(not_decoded(op));
                };
                // edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue gives
                // EFI_UNSUPPORTED for a type that is no integer, which EQ_ID_VAL turns into
                // UNDEFINED
                let QuestionOperand::Value(question) = self.question(op, parsed.question_id)?
                else {
                    return Err(Abort::Undefined);
                };
                Ok(compare(
                    Comparison::Equal,
                    question,
                    Operand::Uint(Some(parsed.value.into())),
                ))
            }
            ExpressionOp::EqIdId => {
                let ParsedOperation::EqIdId(parsed) = &op.parsed_data else {
                    return Err(not_decoded(op));
                };
                let first = self.question(op, parsed.question_id_1)?;
                let second = self.question(op, parsed.question_id_2)?;
                match (first, second) {
                    (QuestionOperand::Value(first), QuestionOperand::Value(second)) => {
                        Ok(compare(Comparison::Equal, first, second))
                    }
                    // edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue gives
                    // EFI_UNSUPPORTED for an integer and a type that is no integer, which
                    // EQ_ID_ID turns into UNDEFINED
                    (QuestionOperand::Value(_), QuestionOperand::Undecoded(_))
                    | (QuestionOperand::Undecoded(_), QuestionOperand::Value(_)) => {
                        Err(Abort::Undefined)
                    }
                    // CompareHiiValue compares two strings or two buffers
                    (QuestionOperand::Undecoded(reason), QuestionOperand::Undecoded(_)) => {
                        Err(Abort::NotEvaluated(reason))
                    }
                }
            }
            ExpressionOp::EqIdValList => {
                let ParsedOperation::EqIdValList(parsed) = &op.parsed_data else {
                    return Err(not_decoded(op));
                };
                let question = self.question(op, parsed.question_id)?.decoded()?;
                // edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression compares
                // HiiValue.Value.u16
                Ok(boolean(question.as_u64().map(|value| {
                    parsed
                        .value_list
                        .iter()
                        .any(|&listed| u64::from(listed) == value & u64::from(u16::MAX))
                })))
            }
            ExpressionOp::QuestionRef1 => {
                let ParsedOperation::QuestionRef1(parsed) = &op.parsed_data else {
                    return Err(not_decoded(op));
                };
                // edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression fails,
                // rather than gives UNDEFINED, without the question
                self.question(op, parsed.question_id)
                    .map_err(|abort| match abort {
                        Abort::Undefined => Abort::Malformed(format!(
                            "{} of missing question {:#06x}",
                            op.op_code.spec_name(),
                            parsed.question_id
                        )),
                        abort => abort,
                    })?
                    .decoded()
            }
            ExpressionOp::Constant(value) => Ok(value),
            ExpressionOp::Uint8 => op
                .data
                .first()
                .map(|&value| Operand::Uint(Some(value.into())))
                .ok_or_else(|| not_decoded(op)),
            ExpressionOp::Uint16 => op
                .data
                .first_chunk()
                .map(|&bytes| Operand::Uint(Some(u16::from_le_bytes(bytes).into())))
                .ok_or_else(|| not_decoded(op)),
            ExpressionOp::Uint32 => op
                .data
                .first_chunk()
                .map(|&bytes| Operand::Uint(Some(u32::from_le_bytes(bytes).into())))
                .ok_or_else(|| not_decoded(op)),
            ExpressionOp::Uint64 => op
                .data
                .first_chunk()
                .map(|&bytes| Operand::Uint(Some(u64::from_le_bytes(bytes))))
                .ok_or_else(|| not_decoded(op)),
            ExpressionOp::Undefined => Err(Abort::Undefined),
            ExpressionOp::Not => Ok(boolean(self.pop(op)?.as_bool()?.map(|value| !value))),
            ExpressionOp::ToBoolean => Ok(boolean(self.pop(op)?.as_u64().map(|value| value != 0))),
            ExpressionOp::BitwiseNot => {
                Ok(Operand::Uint(self.pop(op)?.as_u64().map(|value| !value)))
            }
            // edk2-stable202608 SetupBrowserDxe/Expression.c pops both operands of AND and OR
            // before it checks their types
            ExpressionOp::And => {
                let (right, left) = (self.pop(op)?, self.pop(op)?);
                let (right, left) = (right.as_bool()?, left.as_bool()?);
                Ok(boolean(match (left, right) {
                    (Some(false), _) | (_, Some(false)) => Some(false),
                    (Some(true), Some(true)) => Some(true),
                    _ => None,
                }))
            }
            ExpressionOp::Or => {
                let (right, left) = (self.pop(op)?, self.pop(op)?);
                let (right, left) = (right.as_bool()?, left.as_bool()?);
                Ok(boolean(match (left, right) {
                    (Some(true), _) | (_, Some(true)) => Some(true),
                    (Some(false), Some(false)) => Some(false),
                    _ => None,
                }))
            }
            ExpressionOp::Compare(comparison) => {
                let right = self.pop(op)?;
                let left = self.pop(op)?;
                Ok(compare(comparison, left, right))
            }
            ExpressionOp::Arithmetic(arithmetic) => {
                let right = self.pop(op)?.as_u64();
                let left = self.pop(op)?.as_u64();
                arithmetic.apply(left, right).map(Operand::Uint)
            }
            ExpressionOp::Dup => self.stack.last().copied().ok_or_else(|| {
                Abort::Malformed(format!("{} without an operand", op.op_code.spec_name()))
            }),
            ExpressionOp::Conditional => {
                let when_true = self.pop(op)?;
                let when_false = self.pop(op)?;
                match self.pop(op)?.as_bool()? {
                    Some(true) => Ok(when_true),
                    Some(false) => Ok(when_false),
                    None if when_true == when_false => Ok(when_true),
                    None => Err(Abort::NotEvaluated(format!(
                        "{} on a value that cannot be read",
                        op.op_code.spec_name()
                    ))),
                }
            }
            ExpressionOp::This => self.this(op),
            ExpressionOp::Get => self.get(op),
            ExpressionOp::Set => self.set(op),
            ExpressionOp::NotEvaluated => {
                Err(self.not_evaluated(op.op_code.spec_name().to_string()))
            }
        }
    }

    /// Returns the value of question `id`, which `op` refers to; edk2-stable202608
    /// SetupBrowserDxe/Expression.c EvaluateExpression gives UNDEFINED without the question.
    fn question(&mut self, op: &IFROperation, id: u16) -> Result<QuestionOperand, Abort> {
        let value = self
            .values
            .value(op, id, self.reader)
            .ok_or(Abort::Undefined)?;
        Ok(self.operand_of(value, || {
            format!("{} of question {id:#06x}", op.op_code.spec_name())
        }))
    }

    /// Returns `value` as an operand; for one that cannot be read, notes why, after `subject`.
    fn operand_of(
        &mut self,
        value: QuestionValue,
        subject: impl FnOnce() -> String,
    ) -> QuestionOperand {
        let (kind, reason) = match value {
            QuestionValue::Boolean(value) => {
                return QuestionOperand::Value(Operand::Boolean(Some(value)))
            }
            QuestionValue::Uint(value) => {
                return QuestionOperand::Value(Operand::Uint(Some(value)))
            }
            QuestionValue::Unreadable { kind, reason } => {
                (kind, format!("{}: {reason}", subject()))
            }
        };
        match kind {
            ValueKind::Boolean => {
                self.unknown.get_or_insert(reason);
                QuestionOperand::Value(Operand::Boolean(None))
            }
            ValueKind::Uint => {
                self.unknown.get_or_insert(reason);
                QuestionOperand::Value(Operand::Uint(None))
            }
            ValueKind::Other => QuestionOperand::Undecoded(reason),
        }
    }

    /// Returns the value of THIS: the one that the role gives, else that of the question that
    /// holds `op`, which edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes reads as a
    /// QUESTION_REF1 of it.
    fn this(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        let value = match &self.role {
            Role::Read(this) | Role::Write { this, .. } => this.clone(),
            Role::Reads => {
                let id = enclosing_question_id(op).ok_or_else(|| {
                    Abort::Malformed(format!("{} outside a question", op.op_code.spec_name()))
                })?;
                return self.question(op, id)?.decoded();
            }
        };
        self.operand_of(value, || op.op_code.spec_name().to_string())
            .decoded()
    }

    /// Returns the value that the GET `op` reads from its VarStore (edk2-stable202608
    /// SetupBrowserDxe/Expression.c EvaluateExpression); one that this backend cannot read is
    /// unknown.
    fn get(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        let ParsedOperation::Get(operand) = &op.parsed_data else {
            return Err(not_decoded(op));
        };
        let kind = self.operand_kind(op, operand)?;
        let id = operand.var_store_id;
        let store = match variable_store(operand_store(op, operand)?) {
            Ok(store) => store,
            Err((store, reach)) => {
                self.unreached(
                    op,
                    StoreAccess::Reads,
                    id,
                    store.to_string(),
                    reach.to_string(),
                );
                return Ok(kind.unknown());
            }
        };
        let label = store_label(store.as_ref());
        let range = operand_range(op, operand, kind, store.as_ref())?;
        let offset = range.start;
        let varstore = Ok(store);
        let read =
            read_current_value_bytes(&varstore, range.clone(), self.reader).and_then(|bytes| {
                bytes
                    .get(EFIVARFS_HEADER_SIZE..)
                    .and_then(|payload| payload.get(range))
                    .map(<[u8]>::to_vec)
                    .ok_or(ValueUnavailable::Truncated {
                        offset,
                        len: bytes.len(),
                    })
            });
        match read {
            Ok(bytes) => Ok(kind.operand(&bytes)),
            Err(reason) => {
                self.unreached(
                    op,
                    StoreAccess::Reads,
                    id,
                    label,
                    format!("which cannot be read: {reason}"),
                );
                Ok(kind.unknown())
            }
        }
    }

    /// Plans the SET `op` of a WRITE expression, and pushes TRUE, as edk2-stable202608
    /// SetupBrowserDxe/Expression.c EvaluateExpression does once it copies the value into the edit
    /// buffer of a Buffer or EFI variable VarStore. Elsewhere a SET, which changes a stored value,
    /// is not evaluated.
    fn set(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        let ParsedOperation::Set(operand) = &op.parsed_data else {
            return Err(not_decoded(op));
        };
        let value = self.pop(op)?;
        let Role::Write { .. } = self.role else {
            return Err(self.not_evaluated(format!(
                "{} outside a WRITE expression",
                op.op_code.spec_name()
            )));
        };
        let kind = self.operand_kind(op, operand)?;
        let id = operand.var_store_id;
        let store = match variable_store(operand_store(op, operand)?) {
            Ok(store) => store,
            Err((store, reach)) => {
                let why = self.unreached(
                    op,
                    StoreAccess::Sets,
                    id,
                    store.to_string(),
                    reach.to_string(),
                );
                return Err(Abort::NotEvaluated(why));
            }
        };
        let range = operand_range(op, operand, kind, store.as_ref())?;
        let Some(value) = value.as_u64() else {
            return Err(Abort::NotEvaluated(format!(
                "{} of a value that cannot be read",
                op.op_code.spec_name()
            )));
        };
        let bytes = value
            .to_le_bytes()
            .get(..range.len())
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                Abort::Malformed(format!("{} wider than 8 bytes", op.op_code.spec_name()))
            })?;
        if let Role::Write { sets, .. } = &mut self.role {
            sets.push(PlannedSet {
                var_store_id: id,
                store,
                offset: operand.var_store_info,
                bytes,
            });
        }
        Ok(Operand::Boolean(Some(1)))
    }

    /// Returns the kind of value that the GET or SET `op` reads or writes, by its VarStoreType,
    /// as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes sizes it: it fails the
    /// FormSet on a type that names no stored value.
    fn operand_kind(
        &mut self,
        op: &IFROperation,
        operand: &VarStoreOperand,
    ) -> Result<OperandKind, Abort> {
        let not_evaluated = match operand.var_store_type {
            EFI_IFR_TYPE_BOOLEAN => return Ok(OperandKind::Boolean),
            EFI_IFR_TYPE_NUM_SIZE_8 => return Ok(OperandKind::Uint(1)),
            EFI_IFR_TYPE_NUM_SIZE_16 => return Ok(OperandKind::Uint(2)),
            EFI_IFR_TYPE_NUM_SIZE_32 => return Ok(OperandKind::Uint(4)),
            EFI_IFR_TYPE_NUM_SIZE_64 => return Ok(OperandKind::Uint(8)),
            EFI_IFR_TYPE_TIME => "TIME",
            EFI_IFR_TYPE_DATE => "DATE",
            EFI_IFR_TYPE_STRING => "STRING",
            EFI_IFR_TYPE_REF => "REF",
            other => {
                return Err(Abort::Malformed(format!(
                    "{} of value type {other:#04x}",
                    op.op_code.spec_name()
                )))
            }
        };
        Err(self.not_evaluated(format!(
            "{} of a {not_evaluated} value",
            op.op_code.spec_name()
        )))
    }
}

/// What is left of an evaluation, innermost last.
enum Pending {
    /// An op to evaluate, then the ops in its scope
    Op(Rc<RefCell<IFROperation>>),
    /// A MAP that awaits the value of the match expression of a pair
    Match(MapProgress),
    /// A MAP that awaits the value of the return expression of a pair; `outer` is the stack
    /// before the MAP
    Return { outer: Vec<Operand> },
}

/// A MAP partway through its pairs.
struct MapProgress {
    map: Rc<RefCell<IFROperation>>,
    /// The value that it compares with each match expression
    checked: Operand,
    /// The index of the pair that it is at
    pair: usize,
    /// The stack before the MAP
    outer: Vec<Operand>,
}

impl MapProgress {
    /// The MAP at its next pair.
    fn next(self) -> Self {
        Self {
            pair: self.pair + 1,
            ..self
        }
    }

    /// The expressions in the scope of the MAP, each an op with the ops of its own scope, as
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes nests them: pairs of a match
    /// expression and a return expression.
    fn expressions(&self) -> Vec<Rc<RefCell<IFROperation>>> {
        self.map
            .borrow()
            .children
            .iter()
            .filter(|child| !skips_scope(&child.borrow()))
            .cloned()
            .collect()
    }

    /// The match expression of the pair that it is at; None after the last pair. One without a
    /// return expression after it is malformed.
    fn match_expression(&self) -> Result<Option<Rc<RefCell<IFROperation>>>, Abort> {
        if self.expressions().get(2 * self.pair).is_none() {
            return Ok(None);
        }
        self.return_expression()?;
        Ok(self.expressions().get(2 * self.pair).cloned())
    }

    /// The return expression of the pair that it is at.
    fn return_expression(&self) -> Result<Rc<RefCell<IFROperation>>, Abort> {
        self.expressions()
            .get(2 * self.pair + 1)
            .cloned()
            .ok_or_else(|| {
                Abort::Malformed(format!(
                    "{} without the return expression of a pair",
                    self.map.borrow().op_code.spec_name()
                ))
            })
    }
}

/// Drops what is left of the innermost match expression of a MAP in `pending`, and returns
/// that MAP; None outside MAPs.
fn unwind_to_match(pending: &mut Vec<Pending>) -> Option<MapProgress> {
    while let Some(next) = pending.pop() {
        match next {
            Pending::Match(progress) => return Some(progress),
            Pending::Op(_) | Pending::Return { .. } => {}
        }
    }
    None
}

/// The leading expression ops of `ops`, each with the ops of its own scope, in IFR order: for
/// well-formed IFR, the first op holding the rest, as edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes takes them. AMI firmware sets the Scope bit on a later
/// op, e.g. EQ_ID_VAL NOT EQ_ID_VAL_LIST{OR}, where the first op alone leaves out NOT and OR.
/// Ops that skips_scope names are left out, with their scopes: edk2 ParseOpCodes skips them
/// before it builds expressions (IsExpressionOpCode).
fn leading_expression(ops: &[Rc<RefCell<IFROperation>>]) -> Vec<Rc<RefCell<IFROperation>>> {
    ops.iter()
        .filter(|op| !skips_scope(&op.borrow()))
        .take_while(|op| {
            matches!(
                OpRole::of(op.borrow().op_code),
                OpRole::Expression(_) | OpRole::Map
            )
        })
        .cloned()
        .collect()
}

/// The value of a question that an expression op takes.
enum QuestionOperand {
    Value(Operand),
    /// A value of a type that edk2-stable202608 SetupBrowserDxe/Expression.c IsTypeInUINT64
    /// does not take, which nothing here decodes: why
    Undecoded(String),
}

impl QuestionOperand {
    /// Returns the value, or NotEvaluated if not decoded.
    fn decoded(self) -> Result<Operand, Abort> {
        match self {
            QuestionOperand::Value(operand) => Ok(operand),
            QuestionOperand::Undecoded(reason) => Err(Abort::NotEvaluated(reason)),
        }
    }
}

/// Compares integers and BOOLEANs by the sign of their difference as an INT64, as
/// edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue does.
fn compare(comparison: Comparison, left: Operand, right: Operand) -> Operand {
    let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) else {
        return Operand::Boolean(None);
    };
    let order = left.wrapping_sub(right).cast_signed().cmp(&0);
    boolean(Some(match comparison {
        Comparison::Equal => order.is_eq(),
        Comparison::NotEqual => order.is_ne(),
        Comparison::GreaterThan => order.is_gt(),
        Comparison::GreaterEqual => order.is_ge(),
        Comparison::LessThan => order.is_lt(),
        Comparison::LessEqual => order.is_le(),
    }))
}

impl Arithmetic {
    /// Returns the UINT64 result, as edk2-stable202608 SetupBrowserDxe/Expression.c
    /// EvaluateExpression computes it: MULTIPLY, DIVIDE and MODULO take the right operand as a
    /// UINT32 (MultU64x32, DivU64x32, DivU64x32Remainder). A zero divisor and a shift of 64 bits
    /// or more are not evaluated.
    fn apply(self, left: Option<u64>, right: Option<u64>) -> Result<Option<u64>, Abort> {
        let right_u32 = right.map(|right| right & u64::from(u32::MAX));
        match (self, right_u32, right) {
            (Arithmetic::Divide | Arithmetic::Modulo, Some(0), _) => {
                return Err(Abort::NotEvaluated("division by zero".to_string()));
            }
            (Arithmetic::ShiftLeft | Arithmetic::ShiftRight, _, Some(bits)) if bits >= 64 => {
                return Err(Abort::NotEvaluated(format!("shift by {bits} bits")));
            }
            (
                Arithmetic::Add
                | Arithmetic::Subtract
                | Arithmetic::Multiply
                | Arithmetic::Divide
                | Arithmetic::Modulo
                | Arithmetic::BitwiseAnd
                | Arithmetic::BitwiseOr
                | Arithmetic::ShiftLeft
                | Arithmetic::ShiftRight,
                _,
                _,
            ) => {}
        }
        let (Some(left), Some(right), Some(right_u32)) = (left, right, right_u32) else {
            return Ok(None);
        };
        Ok(Some(match self {
            Arithmetic::Add => left.wrapping_add(right),
            Arithmetic::Subtract => left.wrapping_sub(right),
            Arithmetic::Multiply => left.wrapping_mul(right_u32),
            Arithmetic::Divide => left / right_u32,
            Arithmetic::Modulo => left % right_u32,
            Arithmetic::BitwiseAnd => left & right,
            Arithmetic::BitwiseOr => left | right,
            Arithmetic::ShiftLeft => left << right,
            Arithmetic::ShiftRight => left >> right,
        }))
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use super::super::find_question_in;
    use super::super::handle_form_set;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::storage::ValueLocation;
    use super::super::Cursor;
    use super::super::FormSetWalk;
    use super::super::QuestionDescriptor;
    use super::super::QuestionMatch;
    use super::*;

    const EQ_ID_ID: u8 = 0x13;
    const EQ_ID_VAL_LIST: u8 = 0x14;
    const AND: u8 = 0x15;
    const OR: u8 = 0x16;
    const STRING: u8 = 0x1C;
    const PASSWORD: u8 = 0x08;
    const NOT_EQUAL: u8 = 0x30;
    const GREATER_THAN: u8 = 0x31;
    const GREATER_EQUAL: u8 = 0x32;
    const LESS_THAN: u8 = 0x33;
    const LESS_EQUAL: u8 = 0x34;
    const BITWISE_AND: u8 = 0x35;
    const BITWISE_OR: u8 = 0x36;
    const BITWISE_NOT: u8 = 0x37;
    const SHIFT_LEFT: u8 = 0x38;
    const SHIFT_RIGHT: u8 = 0x39;
    const ADD: u8 = 0x3A;
    const SUBTRACT: u8 = 0x3B;
    const MULTIPLY: u8 = 0x3C;
    const DIVIDE: u8 = 0x3D;
    const MODULO: u8 = 0x3E;
    const UINT16: u8 = 0x43;
    const UINT64: u8 = 0x45;
    const TO_UINT: u8 = 0x48;
    const TO_BOOLEAN: u8 = 0x4A;
    const CONDITIONAL: u8 = 0x50;
    const ZERO: u8 = 0x52;
    const ONE: u8 = 0x53;
    const UNDEFINED: u8 = 0x55;
    const DUP: u8 = 0x57;

    fn unreadable(kind: ValueKind) -> QuestionValue {
        QuestionValue::Unreadable {
            kind,
            reason: "<ValueUnavailable: test>".to_string(),
        }
    }

    /// Question 1 is the UINT 1, 2 the UINT 0x10001, 3 the BOOLEAN 2, 4 an unreadable UINT,
    /// 5 an unreadable BOOLEAN, 6 and 7 of another type; no question has id 9.
    fn values() -> MapValues {
        MapValues(BTreeMap::from([
            (1, QuestionValue::Uint(1)),
            (2, QuestionValue::Uint(0x10001)),
            (3, QuestionValue::Boolean(2)),
            (4, unreadable(ValueKind::Uint)),
            (5, unreadable(ValueKind::Boolean)),
            (6, unreadable(ValueKind::Other)),
            (7, unreadable(ValueKind::Other)),
        ]))
    }

    fn op(op_code: u8) -> Vec<u8> {
        operation(op_code, false, &[])
    }

    fn uint64(value: u64) -> Vec<u8> {
        operation(UINT64, false, &value.to_le_bytes())
    }

    fn eq_id_id(question_id_1: u16, question_id_2: u16) -> Vec<u8> {
        let data = [question_id_1.to_le_bytes(), question_id_2.to_le_bytes()].concat();
        operation(EQ_ID_ID, false, &data)
    }

    fn eq_id_val_list(question_id: u16, list: &[u16]) -> Vec<u8> {
        let length = u16::try_from(list.len()).expect("test list fits a ListLength");
        let data = [
            &question_id.to_le_bytes()[..],
            &length.to_le_bytes(),
            &list
                .iter()
                .flat_map(|value| value.to_le_bytes())
                .collect::<Vec<u8>>(),
        ]
        .concat();
        operation(EQ_ID_VAL_LIST, false, &data)
    }

    fn question_ref1(question_id: u16) -> Vec<u8> {
        operation(QUESTION_REF1, false, &question_id.to_le_bytes())
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips an opcode above
    /// EFI_IFR_MATCH2_OP, with its scope, before it builds expressions, so such an op in a
    /// condition changes nothing; opcode 0x00 is no such opcode.
    #[test]
    fn unknown_opcodes_in_a_condition_are_left_out() {
        let unknown = |op_code: u8| operation(op_code, false, &[]);
        let cases = [
            ("0x70 before TRUE", [unknown(0x70), ifr_true()].concat()),
            ("0xFF before TRUE", [unknown(0xFF), ifr_true()].concat()),
            (
                "0x70 in the scope of TRUE",
                scoped_expression(&[ifr_true(), unknown(0x70)], 0),
            ),
            (
                "0x70 holding FALSE before TRUE",
                [
                    operation(0x70, true, &[]),
                    ifr_false(),
                    END.to_vec(),
                    ifr_true(),
                ]
                .concat(),
            ),
        ];
        for (name, condition) in cases {
            assert_eq!(truth_of(condition, &values()), Truth::Known(true), "{name}");
        }

        // only the over-match control: the filter keeps 0x00, whatever edk2 makes of it
        let truth = truth_of([unknown(0x00), ifr_true()].concat(), &values());
        assert!(
            matches!(truth, Truth::Unknown(_)),
            "0x00 before TRUE: {truth:?}"
        );
    }

    /// The truth of a SUPPRESS_IF condition of `ops`, encoded as edk2-stable202608 VfrCompile
    /// encodes it: the first op opens a scope that an End closes, unless it is the only op.
    fn truth(ops: &[Vec<u8>]) -> Truth {
        let condition = match ops {
            [] => Vec::new(),
            [single] => single.clone(),
            _ => scoped_expression(ops, 0),
        };
        truth_of(condition, &values())
    }

    /// The truth of the SUPPRESS_IF condition `condition` with `values`.
    fn truth_of(condition: Vec<u8>, values: &impl QuestionValues) -> Truth {
        let body = operation(CHECKBOX, false, &checkbox(0, 0x00));
        let data = conditional(SUPPRESS_IF, condition, &[body]);
        let root = handle_form_set(&mut Cursor::new(&[data, END.to_vec()].concat()))
            .expect("parse the SUPPRESS_IF");
        let scope = Rc::clone(&root.borrow().children[0]);
        let scope = scope.borrow();
        evaluate_condition(
            &scope,
            &mut ExpressionInputs {
                reader: &mut Efivars::new().reader(),
                values,
            },
        )
    }

    /// AMI firmware sets the Scope bit on a later op of a condition, as on this one of a ONE_OF
    /// in a HiiDB dump: NOT question 0x495 == 5 OR question 0x9A in {0, 1, 2}. Taking only the
    /// first op, as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes does, would leave
    /// out NOT and OR.
    #[test]
    fn condition_with_a_later_scope_bit_takes_every_leading_expression_op() {
        let condition = [
            0x12, 0x06, 0x95, 0x04, 0x05, 0x00, // EQ_ID_VAL 0x495 5
            0x17, 0x02, // NOT
            0x14, 0x8C, 0x9A, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02,
            0x00, // EQ_ID_VAL_LIST, opening a scope
            0x16, 0x02, // OR
            0x29, 0x02, // End of the EQ_ID_VAL_LIST
        ];
        let cases = [
            ("0x495 is 5, 0x9A not listed", 5, 7, false),
            ("0x495 is 5, 0x9A listed", 5, 1, true),
            ("0x495 is 4", 4, 7, true),
        ];
        for (name, question_495, question_9a, want) in cases {
            let values = MapValues(BTreeMap::from([
                (0x495, QuestionValue::Uint(question_495)),
                (0x9A, QuestionValue::Uint(question_9a)),
            ]));
            assert_eq!(
                truth_of(condition.to_vec(), &values),
                Truth::Known(want),
                "{name}"
            );
        }
    }

    /// The shapes of the AMI conditions with the Scope bit on a later op in HiiDB dumps, each
    /// with that op marked (S), evaluated whole for every combination of the values.
    #[test]
    fn ami_condition_shapes_are_evaluated_whole() {
        type Shape = (&'static str, Vec<Vec<u8>>, usize, fn(u64, u64, u64) -> bool);
        // question 2 in {0, 1, 2}
        let listed = || eq_id_val_list(2, &[0, 1, 2]);
        let shapes: [Shape; 5] = [
            (
                "EqIdVal EqIdValList(S) Or",
                vec![eq_id_val_of(1, 5), listed(), op(OR)],
                1,
                |q1, q2, _| q1 == 5 || q2 <= 2,
            ),
            (
                "EqIdVal Not EqIdValList(S) Or",
                vec![eq_id_val_of(1, 5), op(NOT), listed(), op(OR)],
                2,
                |q1, q2, _| q1 != 5 || q2 <= 2,
            ),
            (
                "EqIdValList EqIdValList(S) Or",
                vec![eq_id_val_list(1, &[5, 6]), listed(), op(OR)],
                1,
                |q1, q2, _| q1 == 5 || q1 == 6 || q2 <= 2,
            ),
            (
                "EqIdVal Not EqIdVal Or EqIdValList(S) Or",
                vec![
                    eq_id_val_of(1, 5),
                    op(NOT),
                    eq_id_val_of(3, 7),
                    op(OR),
                    listed(),
                    op(OR),
                ],
                4,
                |q1, q2, q3| q1 != 5 || q3 == 7 || q2 <= 2,
            ),
            (
                "EqIdVal EqIdValList(S) Or EqIdVal Or",
                vec![
                    eq_id_val_of(1, 5),
                    listed(),
                    op(OR),
                    eq_id_val_of(3, 7),
                    op(OR),
                ],
                1,
                |q1, q2, q3| q1 == 5 || q2 <= 2 || q3 == 7,
            ),
        ];
        for (name, ops, scope_at, want) in shapes {
            for q1 in [4, 5, 6] {
                for q2 in [1, 9] {
                    for q3 in [7, 8] {
                        let values = MapValues(BTreeMap::from([
                            (1, QuestionValue::Uint(q1)),
                            (2, QuestionValue::Uint(q2)),
                            (3, QuestionValue::Uint(q3)),
                        ]));
                        assert_eq!(
                            truth_of(scoped_expression(&ops, scope_at), &values),
                            Truth::Known(want(q1, q2, q3)),
                            "{name}, q1 {q1}, q2 {q2}, q3 {q3}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn scope_bit_position_does_not_change_the_condition() {
        let expressions = [
            ("1 == 1 NOT", vec![eq_id_val_of(1, 1), op(NOT)]),
            ("FALSE TRUE OR", vec![ifr_false(), ifr_true(), op(OR)]),
            ("2 2 SUBTRACT", vec![uint8(2), uint8(2), op(SUBTRACT)]),
        ];
        for (name, ops) in expressions {
            let first = truth(&ops);
            for scope_at in 1..ops.len() {
                assert_eq!(
                    truth_of(scoped_expression(&ops, scope_at), &values()),
                    first,
                    "{name}, Scope bit on op {scope_at}"
                );
            }
        }
    }

    fn unknown(reason: &str) -> Truth {
        Truth::Unknown(reason.to_string())
    }

    #[test]
    fn constants_are_true_unless_zero() {
        let cases = [
            ("TRUE", vec![ifr_true()], true),
            ("FALSE", vec![ifr_false()], false),
            ("ONE", vec![op(ONE)], true),
            ("ZERO", vec![op(ZERO)], false),
            ("ONES", vec![ifr_ones()], true),
            ("UINT8 2", vec![uint8(2)], true),
            ("UINT8 0", vec![uint8(0)], false),
            ("UINT64 2^63", vec![uint64(1 << 63)], true),
            ("UNDEFINED", vec![op(UNDEFINED)], false),
        ];
        for (name, ops, want) in cases {
            assert_eq!(truth(&ops), Truth::Known(want), "{name}");
        }
    }

    #[test]
    fn eq_id_val_compares_the_question_value() {
        let cases = [
            ("equal", eq_id_val_of(1, 1), Truth::Known(true)),
            ("not equal", eq_id_val_of(1, 0), Truth::Known(false)),
            ("all 64 bits", eq_id_val_of(2, 1), Truth::Known(false)),
            ("BOOLEAN byte as is", eq_id_val_of(3, 2), Truth::Known(true)),
            (
                "BOOLEAN 2 is not 1",
                eq_id_val_of(3, 1),
                Truth::Known(false),
            ),
            // edk2-stable202608 SetupBrowserDxe/Expression.c: IdToQuestion NULL gives UNDEFINED,
            // which IsTrue takes as FALSE
            ("no such question", eq_id_val_of(9, 0), Truth::Known(false)),
            (
                "unreadable",
                eq_id_val_of(4, 1),
                unknown("EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>"),
            ),
            // edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue gives
            // EFI_UNSUPPORTED for a type that is no integer, which EQ_ID_VAL turns into UNDEFINED
            ("type not decoded", eq_id_val_of(6, 1), Truth::Known(false)),
        ];
        for (name, op, want) in cases {
            assert_eq!(truth(&[op]), want, "{name}");
        }
    }

    /// EFI_IFR_EQ_ID_VAL_LIST compares the low 16 bits (edk2-stable202608
    /// SetupBrowserDxe/Expression.c EvaluateExpression `HiiValue.Value.u16`).
    #[test]
    fn eq_id_val_list_compares_the_low_16_bits() {
        let cases = [
            ("listed", eq_id_val_list(1, &[0, 1]), Truth::Known(true)),
            (
                "not listed",
                eq_id_val_list(1, &[0, 2]),
                Truth::Known(false),
            ),
            ("empty list", eq_id_val_list(1, &[]), Truth::Known(false)),
            ("low 16 bits", eq_id_val_list(2, &[1]), Truth::Known(true)),
            (
                "no such question",
                eq_id_val_list(9, &[0]),
                Truth::Known(false),
            ),
            (
                "unreadable",
                eq_id_val_list(4, &[1]),
                unknown("EFI_IFR_EQ_ID_VAL_LIST of question 0x0004: <ValueUnavailable: test>"),
            ),
            (
                "type not decoded",
                eq_id_val_list(6, &[1]),
                unknown("EFI_IFR_EQ_ID_VAL_LIST of question 0x0006: <ValueUnavailable: test>"),
            ),
        ];
        for (name, op, want) in cases {
            assert_eq!(truth(&[op]), want, "{name}");
        }
    }

    #[test]
    fn eq_id_id_compares_two_question_values() {
        let cases = [
            ("equal", eq_id_id(1, 1), Truth::Known(true)),
            ("not equal", eq_id_id(1, 2), Truth::Known(false)),
            ("first missing", eq_id_id(9, 1), Truth::Known(false)),
            ("second missing", eq_id_id(4, 9), Truth::Known(false)),
            (
                "second unreadable",
                eq_id_id(1, 4),
                unknown("EFI_IFR_EQ_ID_ID of question 0x0004: <ValueUnavailable: test>"),
            ),
            // edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue gives
            // EFI_UNSUPPORTED for an integer and a type that is no integer, which EQ_ID_ID
            // turns into UNDEFINED
            ("first not decoded", eq_id_id(6, 1), Truth::Known(false)),
            ("second not decoded", eq_id_id(4, 6), Truth::Known(false)),
            (
                "both not decoded",
                eq_id_id(6, 7),
                unknown("EFI_IFR_EQ_ID_ID of question 0x0006: <ValueUnavailable: test>"),
            ),
        ];
        for (name, op, want) in cases {
            assert_eq!(truth(&[op]), want, "{name}");
        }
    }

    /// NOT, AND and OR take BOOLEANs only (edk2-stable202608 SetupBrowserDxe/Expression.c
    /// EvaluateExpression gives UNDEFINED otherwise), and an unreadable operand leaves the result
    /// unknown only if it can change it.
    #[test]
    fn logic_ops_are_kleene_on_booleans() {
        let unreadable = || eq_id_val_of(4, 1);
        let reason = "EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>";
        let cases = [
            ("NOT TRUE", vec![ifr_true(), op(NOT)], Truth::Known(false)),
            ("NOT FALSE", vec![ifr_false(), op(NOT)], Truth::Known(true)),
            ("NOT UINT8 0", vec![uint8(0), op(NOT)], Truth::Known(false)),
            (
                "NOT unreadable",
                vec![unreadable(), op(NOT)],
                unknown(reason),
            ),
            (
                "TRUE AND FALSE",
                vec![ifr_true(), ifr_false(), op(AND)],
                Truth::Known(false),
            ),
            (
                "TRUE AND TRUE",
                vec![ifr_true(), ifr_true(), op(AND)],
                Truth::Known(true),
            ),
            (
                "TRUE AND UINT8 1",
                vec![ifr_true(), uint8(1), op(AND)],
                Truth::Known(false),
            ),
            (
                "unreadable AND FALSE",
                vec![unreadable(), ifr_false(), op(AND)],
                Truth::Known(false),
            ),
            (
                "unreadable AND TRUE",
                vec![unreadable(), ifr_true(), op(AND)],
                unknown(reason),
            ),
            (
                "FALSE OR TRUE",
                vec![ifr_false(), ifr_true(), op(OR)],
                Truth::Known(true),
            ),
            (
                "FALSE OR FALSE",
                vec![ifr_false(), ifr_false(), op(OR)],
                Truth::Known(false),
            ),
            (
                "TRUE OR unreadable",
                vec![ifr_true(), unreadable(), op(OR)],
                Truth::Known(true),
            ),
            (
                "FALSE OR unreadable",
                vec![ifr_false(), unreadable(), op(OR)],
                unknown(reason),
            ),
            (
                "unreadable OR UINT8 1",
                vec![unreadable(), uint8(1), op(OR)],
                Truth::Known(false),
            ),
            (
                "NOT unreadable BOOLEAN",
                vec![question_ref1(5), op(NOT)],
                unknown("EFI_IFR_QUESTION_REF1 of question 0x0005: <ValueUnavailable: test>"),
            ),
            (
                "QUESTION_REF1 BOOLEAN 2 alone",
                vec![question_ref1(3)],
                Truth::Known(true),
            ),
        ];
        for (name, ops, want) in cases {
            assert_eq!(truth(&ops), want, "{name}");
        }
    }

    /// edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression stops at the first
    /// UNDEFINED, which IsTrue takes as FALSE, even where a later op would make the result TRUE.
    #[test]
    fn undefined_ends_the_evaluation_as_false() {
        let cases = [
            (
                "missing question OR TRUE",
                vec![eq_id_val_of(9, 0), ifr_true(), op(OR)],
            ),
            ("UNDEFINED NOT", vec![op(UNDEFINED), op(NOT)]),
            (
                "unreadable OR missing question",
                vec![eq_id_val_of(4, 1), eq_id_val_of(9, 0), op(OR)],
            ),
        ];
        for (name, ops) in cases {
            assert_eq!(truth(&ops), Truth::Known(false), "{name}");
        }
    }

    /// Comparisons take integers and BOOLEANs as UINT64s and order them by the sign of their
    /// difference as an INT64 (edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue).
    #[test]
    fn comparisons_order_by_the_signed_difference() {
        let compare =
            |left: u64, right: u64, op_code: u8| truth(&[uint64(left), uint64(right), op(op_code)]);
        let cases = [
            ("1 == 1", compare(1, 1, EQUAL), true),
            ("1 == 2", compare(1, 2, EQUAL), false),
            ("1 != 2", compare(1, 2, NOT_EQUAL), true),
            ("2 > 1", compare(2, 1, GREATER_THAN), true),
            ("1 > 1", compare(1, 1, GREATER_THAN), false),
            ("1 >= 1", compare(1, 1, GREATER_EQUAL), true),
            ("1 < 2", compare(1, 2, LESS_THAN), true),
            ("2 <= 1", compare(2, 1, LESS_EQUAL), false),
            ("2^63 > 0 wraps", compare(1 << 63, 0, GREATER_THAN), false),
            ("2^63 < 0 wraps", compare(1 << 63, 0, LESS_THAN), true),
        ];
        for (name, got, want) in cases {
            assert_eq!(got, Truth::Known(want), "{name}");
        }
        assert_eq!(
            truth(&[ifr_true(), op(ONE), op(EQUAL)]),
            Truth::Known(true),
            "TRUE == ONE"
        );
        assert_eq!(
            truth(&[question_ref1(4), op(ONE), op(EQUAL)]),
            unknown("EFI_IFR_QUESTION_REF1 of question 0x0004: <ValueUnavailable: test>"),
            "unreadable == ONE"
        );
        assert_eq!(
            truth(&[question_ref1(6), op(ONE), op(EQUAL)]),
            unknown("EFI_IFR_QUESTION_REF1 of question 0x0006: <ValueUnavailable: test>"),
            "type not decoded == ONE"
        );
    }

    /// Arithmetic gives a UINT64, wrapping, and takes the right operand of MULTIPLY, DIVIDE and
    /// MODULO as a UINT32 (edk2-stable202608 SetupBrowserDxe/Expression.c MultU64x32,
    /// DivU64x32, DivU64x32Remainder); a zero divisor and a shift of 64 bits or more are not
    /// evaluated.
    #[test]
    fn arithmetic_wraps_as_uint64() {
        let result = |left: u64, right: u64, op_code: u8, want: u64| {
            truth(&[
                uint64(left),
                uint64(right),
                op(op_code),
                uint64(want),
                op(EQUAL),
            ])
        };
        let cases = [
            ("ADD wraps", result(u64::MAX, 2, ADD, 1)),
            ("SUBTRACT wraps", result(0, 1, SUBTRACT, u64::MAX)),
            (
                "MULTIPLY by a UINT32",
                result(3, (1 << 32) + 2, MULTIPLY, 6),
            ),
            ("DIVIDE by a UINT32", result(7, (1 << 32) + 2, DIVIDE, 3)),
            ("MODULO by a UINT32", result(7, (1 << 32) + 2, MODULO, 1)),
            ("BITWISE_AND", result(6, 3, BITWISE_AND, 2)),
            ("BITWISE_OR", result(6, 3, BITWISE_OR, 7)),
            ("SHIFT_LEFT", result(1, 63, SHIFT_LEFT, 1 << 63)),
            ("SHIFT_RIGHT", result(1 << 63, 63, SHIFT_RIGHT, 1)),
        ];
        for (name, got) in cases {
            assert_eq!(got, Truth::Known(true), "{name}");
        }
        assert_eq!(
            truth(&[uint8(5), op(BITWISE_NOT), uint64(!5), op(EQUAL)]),
            Truth::Known(true),
            "BITWISE_NOT"
        );
        for (name, ops) in [
            ("DIVIDE by 0", vec![uint8(1), op(ZERO), op(DIVIDE)]),
            (
                "MODULO by 2^32",
                vec![uint8(1), uint64(1 << 32), op(MODULO)],
            ),
            (
                "SHIFT_LEFT by 64",
                vec![uint8(1), uint8(64), op(SHIFT_LEFT)],
            ),
            (
                "SHIFT_RIGHT by 64",
                vec![uint8(1), uint8(64), op(SHIFT_RIGHT)],
            ),
        ] {
            assert!(
                matches!(truth(&ops), Truth::Unknown(_)),
                "{name}: {:?}",
                truth(&ops)
            );
        }
    }

    #[test]
    fn stack_ops_are_evaluated() {
        let cases = [
            (
                "CONDITIONAL TRUE",
                vec![ifr_true(), ifr_false(), ifr_true(), op(CONDITIONAL)],
                Truth::Known(true),
            ),
            (
                "CONDITIONAL FALSE",
                vec![ifr_false(), ifr_false(), ifr_true(), op(CONDITIONAL)],
                Truth::Known(false),
            ),
            (
                "CONDITIONAL on a UINT",
                vec![uint8(1), ifr_true(), ifr_true(), op(CONDITIONAL)],
                Truth::Known(false),
            ),
            (
                "CONDITIONAL on an unreadable BOOLEAN, equal values",
                vec![question_ref1(5), ifr_true(), ifr_true(), op(CONDITIONAL)],
                Truth::Known(true),
            ),
            (
                "CONDITIONAL on an unreadable BOOLEAN, different values",
                vec![question_ref1(5), ifr_false(), ifr_true(), op(CONDITIONAL)],
                unknown("EFI_IFR_CONDITIONAL on a value that cannot be read"),
            ),
            (
                "DUP",
                vec![ifr_true(), op(DUP), op(AND)],
                Truth::Known(true),
            ),
            (
                "TO_BOOLEAN 2 is TRUE",
                vec![uint8(2), op(TO_BOOLEAN), ifr_true(), op(AND)],
                Truth::Known(true),
            ),
            (
                "QUESTION_REF1",
                vec![question_ref1(2), uint64(0x10001), op(EQUAL)],
                Truth::Known(true),
            ),
        ];
        for (name, ops, want) in cases {
            assert_eq!(truth(&ops), want, "{name}");
        }
    }

    /// edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpression fails on these, and
    /// Presentation.c EvaluateFormExpressions then shows no form, so whether the condition holds
    /// is unknown.
    #[test]
    fn malformed_condition_is_unknown() {
        let cases = [
            ("no ops", vec![], "no value"),
            (
                "AND of one value",
                vec![ifr_true(), op(AND)],
                "EFI_IFR_AND without an operand",
            ),
            (
                "AND of one UINT",
                vec![uint8(1), op(AND)],
                "EFI_IFR_AND without an operand",
            ),
            (
                "OR of one UINT",
                vec![uint8(1), op(OR)],
                "EFI_IFR_OR without an operand",
            ),
            ("two values", vec![ifr_true(), ifr_true()], "2 values left"),
            (
                "QUESTION_REF1 of no question",
                vec![question_ref1(9)],
                "EFI_IFR_QUESTION_REF1 of missing question 0x0009",
            ),
            (
                "truncated UINT16",
                vec![operation(UINT16, false, &[0x01])],
                "EFI_IFR_UINT16 not decoded",
            ),
            (
                "question in an expression",
                vec![ifr_true(), checkbox_op(1, 0)],
                "EFI_IFR_CHECKBOX in an expression",
            ),
        ];
        for (name, ops, reason) in cases {
            assert_eq!(
                truth(&ops),
                unknown(&format!("malformed condition: {reason}")),
                "{name}"
            );
        }
    }

    #[test]
    fn op_that_is_not_evaluated_makes_the_condition_unknown() {
        let to_uint = operation(TO_UINT, false, &[]);
        assert_eq!(
            truth(&[ifr_true(), uint8(1), to_uint, op(OR)]),
            unknown("EFI_IFR_TO_UINT not evaluated"),
            "TRUE OR TO_UINT 1"
        );
    }

    /// A CHECKBOX of QuestionId 9 in the scopes of `scopes`, outermost first, each an op code and
    /// a condition, in a form; returns the root, which owns the parents, and the CHECKBOX.
    fn nested_question(
        scopes: &[(u8, Vec<u8>)],
    ) -> (Rc<RefCell<IFROperation>>, Rc<RefCell<IFROperation>>) {
        let question = checkbox_op(9, 0);
        let body = scopes
            .iter()
            .rev()
            .fold(question.clone(), |body, (op_code, condition)| {
                conditional(*op_code, condition.clone(), &[body])
            });
        let root = parse_form_set(&[form(1, &[body])]);
        let question = find_op(&root, &question[2..]).expect("find the CHECKBOX");
        (root, question)
    }

    fn state(scopes: &[(u8, Vec<u8>)]) -> StateEvaluation {
        let (_root, question) = nested_question(scopes);
        let question = question.borrow();
        question_state(
            &question,
            &mut ExpressionInputs {
                reader: &mut Efivars::new().reader(),
                values: &values(),
            },
        )
    }

    fn known(state: QuestionState) -> StateEvaluation {
        StateEvaluation {
            current: state,
            unknown: Vec::new(),
            read_only: None,
            from_snapshot: Vec::new(),
        }
    }

    /// The data of the CHECKBOX that locked_question_state finds.
    fn locked_question_data() -> Vec<u8> {
        [question_header_of(9, 0), vec![0x00]].concat()
    }

    /// A CHECKBOX with locked_question_data, holding `children` in its scope.
    fn locked_question(children: &[Vec<u8>]) -> Vec<u8> {
        [
            operation(CHECKBOX, true, &locked_question_data()),
            children.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// The state that question_state gives the CHECKBOX of locked_question in a FormSet holding
    /// `body`.
    fn locked_question_state(body: &[Vec<u8>]) -> StateEvaluation {
        let root = parse_form_set(body);
        let question = find_op(&root, &locked_question_data()).expect("find the CHECKBOX");
        let question = question.borrow();
        question_state(
            &question,
            &mut ExpressionInputs {
                reader: &mut Efivars::new().reader(),
                values: &values(),
            },
        )
    }

    /// An EFI_IFR_LOCKED grays out the question in whose scope it is, also inside an op that is
    /// no statement or inside an EDKII bit-varstore GUID, whose Scope edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c ParseOpCodes clears, but not inside another nested statement
    /// or an op that ParseOpCodes skips, and every question of a FORM or FORM_MAP
    /// that holds it right in its scope, as SetupBrowserDxe/Presentation.c grays them out; a
    /// question in the scope of a locked statement stays selectable (IfrParse.c ParseOpCodes locks
    /// only the innermost statement around a LOCKED).
    #[test]
    fn locked_scope_grays_out_the_question_as_edk2_does() {
        let in_scope = |op_code: u8, data: &[u8]| {
            [operation(op_code, true, data), locked_op(), END.to_vec()].concat()
        };
        let form_map = |body: &[Vec<u8>]| {
            // FormId 2, one method: MethodTitle 1, MethodIdentifier
            let data = [&[0x02, 0x00, 0x01, 0x00][..], &[0x33; 16]].concat();
            [
                operation(FORM_MAP, true, &data),
                body.concat(),
                END.to_vec(),
            ]
            .concat()
        };
        let suppressed_lock = || conditional(SUPPRESS_IF, ifr_false(), &[locked_op()]);
        let cases: [(&str, Vec<Vec<u8>>, QuestionState); 13] = [
            (
                "no LOCKED",
                vec![form(1, &[locked_question(&[])])],
                QuestionState::Selectable,
            ),
            (
                "LOCKED in its scope",
                vec![form(1, &[locked_question(&[locked_op()])])],
                QuestionState::GrayedOut,
            ),
            (
                "LOCKED in a SUPPRESS_IF in its scope",
                vec![form(1, &[locked_question(&[suppressed_lock()])])],
                QuestionState::GrayedOut,
            ),
            (
                "LOCKED in a DEFAULT in its scope",
                vec![form(
                    1,
                    &[locked_question(&[in_scope(
                        DEFAULT,
                        &[0x00, 0x00, 0x00, 0x01],
                    )])],
                )],
                QuestionState::GrayedOut,
            ),
            (
                "LOCKED in a GUID statement in its scope",
                vec![form(1, &[locked_question(&[in_scope(GUID, &[0x77; 16])])])],
                QuestionState::Selectable,
            ),
            (
                "LOCKED in an EDKII bit-varstore GUID in its scope",
                vec![form(
                    1,
                    &[locked_question(&[in_scope(GUID, &BIT_VARSTORE_GUID)])],
                )],
                QuestionState::GrayedOut,
            ),
            (
                "LOCKED in an unknown op in its scope",
                vec![form(1, &[locked_question(&[in_scope(0x70, &[])])])],
                QuestionState::Selectable,
            ),
            (
                "in a SUBTITLE holding LOCKED",
                vec![form(
                    1,
                    &[[
                        subtitle_scope(2),
                        locked_op(),
                        locked_question(&[]),
                        END.to_vec(),
                    ]
                    .concat()],
                )],
                QuestionState::Selectable,
            ),
            (
                "in a FORM holding LOCKED",
                vec![form(1, &[locked_op(), locked_question(&[])])],
                QuestionState::GrayedOut,
            ),
            (
                "before a LOCKED in its FORM",
                vec![form(1, &[locked_question(&[]), locked_op()])],
                QuestionState::GrayedOut,
            ),
            (
                "in a SUBTITLE of a FORM holding LOCKED",
                vec![form(
                    1,
                    &[
                        locked_op(),
                        [subtitle_scope(2), locked_question(&[]), END.to_vec()].concat(),
                    ],
                )],
                QuestionState::GrayedOut,
            ),
            (
                "in a FORM whose SUPPRESS_IF holds LOCKED",
                vec![form(1, &[suppressed_lock(), locked_question(&[])])],
                QuestionState::Selectable,
            ),
            (
                "in a FORM_MAP holding LOCKED",
                vec![form_map(&[locked_op(), locked_question(&[])])],
                QuestionState::GrayedOut,
            ),
        ];
        for (name, body, want) in cases {
            assert_eq!(locked_question_state(&body), known(want), "{name}");
        }
    }

    /// question_value_expression takes the last EFI_IFR_VALUE in the scope of the question, also
    /// one inside an op that is no statement or inside an EDKII bit-varstore GUID, as
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes makes each the ValueExpression of
    /// its ParentStatement, but none inside an EFI_IFR_DEFAULT, another nested statement, an op
    /// that ParseOpCodes skips, or an EFI_IFR_ONE_OF_OPTION, whose value it gives.
    #[test]
    fn question_value_expression_is_the_last_value_in_the_question_scope() {
        let value = |value: u8| value_of(uint8(value));
        let in_scope = |op_code: u8, data: &[u8], body: Vec<u8>| {
            [operation(op_code, true, data), body, END.to_vec()].concat()
        };
        let cases = [
            ("no VALUE", vec![], None),
            ("VALUE in its scope", vec![value(2)], Some(2)),
            ("two VALUEs", vec![value(2), value(3)], Some(3)),
            (
                "VALUE in a SUPPRESS_IF in its scope",
                vec![conditional(SUPPRESS_IF, ifr_false(), &[value(2)])],
                Some(2),
            ),
            (
                "VALUE in a DEFAULT in its scope",
                vec![ifr_default_2(0, uint8(2))],
                None,
            ),
            (
                "VALUE in a GUID statement in its scope",
                vec![in_scope(GUID, &[0x77; 16], value(2))],
                None,
            ),
            (
                "VALUE after a GUID statement in its scope",
                vec![in_scope(GUID, &[0x77; 16], value(2)), value(3)],
                Some(3),
            ),
            (
                "VALUE in an EDKII bit-varstore GUID in its scope",
                vec![in_scope(GUID, &BIT_VARSTORE_GUID, value(2))],
                Some(2),
            ),
            (
                "VALUE in an unknown op in its scope",
                vec![in_scope(0x70, &[], value(2))],
                None,
            ),
            (
                "VALUE in a ONE_OF_OPTION in its scope",
                vec![other_option(6, 0x00, &[uint8(2)])],
                None,
            ),
            (
                "VALUE after a ONE_OF_OPTION in its scope",
                vec![other_option(6, 0x00, &[uint8(2)]), value(3)],
                Some(3),
            ),
        ];
        for (name, children, want) in cases {
            let root = parse_form_set(&[form(1, &[locked_question(&children)])]);
            let question = find_op(&root, &locked_question_data()).expect("find the CHECKBOX");
            // the data of the expression op of the VALUE taken
            let expression = question_value_expression(&question.borrow()).map(|value| {
                value
                    .borrow()
                    .children
                    .first()
                    .map(|expression| expression.borrow().data.clone())
            });
            assert_eq!(expression, want.map(|value| Some(vec![value])), "{name}");
        }
    }

    /// The true condition of highest priority gives the state, whichever way SUPPRESS_IF,
    /// GRAY_OUT_IF and DISABLE_IF nest and whichever of them are true.
    #[test]
    fn question_state_follows_edk2_priority() {
        let scopes = [
            (SUPPRESS_IF, QuestionState::Suppressed),
            (GRAY_OUT_IF, QuestionState::GrayedOut),
            (DISABLE_IF, QuestionState::Disabled),
        ];
        let orders = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        for order in orders {
            for true_scopes in 0..8u8 {
                let is_true = |scope: usize| true_scopes & (1 << scope) != 0;
                let nested: Vec<(u8, Vec<u8>)> = order
                    .iter()
                    .map(|&scope| {
                        let condition = if is_true(scope) {
                            ifr_true()
                        } else {
                            ifr_false()
                        };
                        (scopes[scope].0, condition)
                    })
                    .collect();
                let want = (0..scopes.len())
                    .filter(|&scope| is_true(scope))
                    .map(|scope| scopes[scope].1)
                    .fold(QuestionState::Selectable, QuestionState::max);

                assert_eq!(
                    state(&nested),
                    known(want),
                    "order {order:?}, true {true_scopes:03b}"
                );
            }
        }
        assert_eq!(
            state(&[(SUPPRESS_IF, eq_id_val_of(1, 1))]),
            known(QuestionState::Suppressed),
            "question 1 is 1"
        );
    }

    /// A ONE_OF of QuestionId 9 holding `body`, in the scope of `outer` if any, in a form;
    /// returns the root, which owns the parents, and the ONE_OF.
    fn one_of_holding(
        outer: Option<u8>,
        body: &[Vec<u8>],
    ) -> (Rc<RefCell<IFROperation>>, Rc<RefCell<IFROperation>>) {
        let data = [question_header_of(9, 0), vec![0x00, 0x00, 0x03, 0x01]].concat();
        let one_of = [operation(ONE_OF, true, &data), body.concat(), END.to_vec()].concat();
        let one_of = match outer {
            Some(op_code) => conditional(op_code, ifr_true(), &[one_of]),
            None => one_of,
        };
        let root = parse_form_set(&[form(1, &[one_of])]);
        let question = find_op(&root, &data).expect("find the ONE_OF");
        (root, question)
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes attaches a SUPPRESS_IF in a
    /// ONE_OF to the options in its scope, a GRAY_OUT_IF or DISABLE_IF there to nothing, and
    /// those around the ONE_OF to the question.
    #[test]
    fn conditions_in_a_one_of_apply_to_its_options_only() {
        use QuestionState::*;
        let cases = [
            (
                "SUPPRESS_IF in",
                None,
                Some(SUPPRESS_IF),
                Selectable,
                Suppressed,
            ),
            (
                "GRAY_OUT_IF in",
                None,
                Some(GRAY_OUT_IF),
                Selectable,
                Selectable,
            ),
            (
                "DISABLE_IF in",
                None,
                Some(DISABLE_IF),
                Selectable,
                Selectable,
            ),
            (
                "SUPPRESS_IF around",
                Some(SUPPRESS_IF),
                None,
                Suppressed,
                Selectable,
            ),
        ];
        for (name, outer, inner, question_want, option_want) in cases {
            let option = flagged_option(6, 0x00, 1);
            let body = match inner {
                Some(op_code) => conditional(op_code, ifr_true(), std::slice::from_ref(&option)),
                None => option.clone(),
            };
            let (root, question) = one_of_holding(outer, &[body]);
            let option = find_op(&root, &option[2..]).expect("find the option");

            assert_eq!(
                question_state(
                    &question.borrow(),
                    &mut ExpressionInputs {
                        reader: &mut Efivars::new().reader(),
                        values: &values()
                    }
                ),
                known(question_want),
                "{name}: question"
            );
            assert_eq!(
                option_state(
                    &option.borrow(),
                    &mut ExpressionInputs {
                        reader: &mut Efivars::new().reader(),
                        values: &values()
                    }
                ),
                known(option_want),
                "{name}: option"
            );
        }
    }

    /// A SUPPRESS_IF around a form suppresses its questions, and a DISABLE_IF around forms,
    /// which edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes evaluates while parsing,
    /// disables them.
    #[test]
    fn form_and_form_set_conditions_apply_to_their_questions() {
        let cases = [
            (SUPPRESS_IF, QuestionState::Suppressed),
            (DISABLE_IF, QuestionState::Disabled),
        ];
        for (op_code, want) in cases {
            let question = checkbox_op(9, 0);
            let root = parse_form_set(&[conditional(
                op_code,
                ifr_true(),
                &[form(1, std::slice::from_ref(&question))],
            )]);
            let question = find_op(&root, &question[2..]).expect("find the CHECKBOX");

            assert_eq!(
                question_state(
                    &question.borrow(),
                    &mut ExpressionInputs {
                        reader: &mut Efivars::new().reader(),
                        values: &values()
                    }
                ),
                known(want),
                "{op_code:#04x}"
            );
        }
    }

    #[test]
    fn question_state_keeps_conditions_not_evaluated() {
        let got = state(&[
            (GRAY_OUT_IF, ifr_true()),
            (SUPPRESS_IF, eq_id_val_of(4, 1)),
            (DISABLE_IF, ifr_false()),
        ]);

        assert_eq!(
            got,
            StateEvaluation {
                current: QuestionState::GrayedOut,
                unknown: vec![(
                    QuestionState::Suppressed,
                    "EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>".to_string()
                )],
                read_only: None,
                from_snapshot: Vec::new(),
            },
            "grayed out, maybe suppressed"
        );
    }

    fn evaluation(known: QuestionState, unknown: &[(QuestionState, &str)]) -> StateEvaluation {
        StateEvaluation {
            current: known,
            unknown: unknown
                .iter()
                .map(|&(state, reason)| (state, reason.to_string()))
                .collect(),
            read_only: None,
            from_snapshot: Vec::new(),
        }
    }

    /// The exclusion in `states` that current values decide.
    fn exclusion(states: IncludedStates) -> Exclusion {
        Exclusion {
            states,
            source: ValueSource::Current,
        }
    }

    /// The tag of a state goes with the values of the ExportConfig snapshot that decide it, and
    /// only with them: a condition on one decides nothing when a state above its own is known
    /// already, or when another condition would give that state anyway.
    #[test]
    fn states_name_the_snapshot_only_where_it_decides_them() {
        use QuestionState::*;
        // name, current, unknown, from_snapshot, annotation
        type Case<'a> = (
            &'a str,
            QuestionState,
            &'a [(QuestionState, &'a str)],
            &'a [(QuestionState, bool)],
            &'a str,
        );
        let cases: [Case; 7] = [
            (
                "true",
                Selectable,
                &[],
                &[(GrayedOut, true)],
                " <grayed-out> <snapshot>",
            ),
            (
                "false",
                Selectable,
                &[],
                &[(GrayedOut, false)],
                " <selectable> <snapshot>",
            ),
            (
                "under a known higher state",
                Disabled,
                &[],
                &[(GrayedOut, true)],
                " <disabled>",
            ),
            (
                "beside the same known state",
                GrayedOut,
                &[],
                &[(GrayedOut, true)],
                " <grayed-out>",
            ),
            (
                "over a condition not evaluated",
                Selectable,
                &[(GrayedOut, "r")],
                &[(GrayedOut, true)],
                " <grayed-out> <snapshot>",
            ),
            (
                "under a condition not evaluated",
                Selectable,
                &[(Suppressed, "r")],
                &[(GrayedOut, true)],
                " <grayed-out or suppressed: r> <snapshot>",
            ),
            (
                "none",
                GrayedOut,
                &[(Suppressed, "r")],
                &[],
                " <grayed-out or suppressed: r>",
            ),
        ];
        for (case, current, unknown, from_snapshot, want) in cases {
            let evaluation = StateEvaluation {
                from_snapshot: from_snapshot.to_vec(),
                ..evaluation(current, unknown)
            };

            assert_eq!(evaluation.annotation(), want, "{case}");
            assert_eq!(
                evaluation.option_annotation(),
                want.replacen(" <", " <option ", 1),
                "{case}: option"
            );
        }
    }

    /// get's refusals name the snapshot when its values decide the states that exclude a
    /// question or option, also among other exclusions.
    #[test]
    fn exclusions_name_the_snapshot_that_decides_them() {
        let snapshot = Exclusion {
            states: IncludedStates::SUPPRESSED,
            source: ValueSource::Snapshot,
        };
        let mut merged = snapshot;
        merged |= exclusion(IncludedStates::GRAYED_OUT);

        for (case, exclusion, question_want, option_want) in [
            (
                "current values",
                exclusion(IncludedStates::SUPPRESSED),
                SelectionError::Excluded {
                    question: "Q".to_string(),
                    states: IncludedStates::SUPPRESSED,
                },
                SelectionError::OptionExcluded {
                    question: "Q".to_string(),
                    option: "O".to_string(),
                    states: IncludedStates::SUPPRESSED,
                },
            ),
            (
                "snapshot values",
                snapshot,
                SelectionError::SnapshotExcluded {
                    question: "Q".to_string(),
                    states: IncludedStates::SUPPRESSED,
                },
                SelectionError::SnapshotOptionExcluded {
                    question: "Q".to_string(),
                    option: "O".to_string(),
                    states: IncludedStates::SUPPRESSED,
                },
            ),
            (
                "snapshot values and current ones",
                merged,
                SelectionError::SnapshotExcluded {
                    question: "Q".to_string(),
                    states: IncludedStates::GRAYED_OUT | IncludedStates::SUPPRESSED,
                },
                SelectionError::SnapshotOptionExcluded {
                    question: "Q".to_string(),
                    option: "O".to_string(),
                    states: IncludedStates::GRAYED_OUT | IncludedStates::SUPPRESSED,
                },
            ),
        ] {
            assert_eq!(exclusion.question_error("Q"), question_want, "{case}");
            assert_eq!(
                exclusion.option_error("Q".to_string(), "O".to_string()),
                option_want,
                "{case}: option"
            );
        }
    }

    /// A question can be in its known state or in that of a condition not evaluated that ranks
    /// above it, and in no other.
    #[test]
    fn possible_states_are_the_known_one_and_those_of_higher_unknown_conditions() {
        use QuestionState::*;
        let cases = [
            ("no condition", Selectable, vec![], vec![Selectable], "", ""),
            (
                "grayed out",
                GrayedOut,
                vec![],
                vec![GrayedOut],
                " <grayed-out>",
                " <option grayed-out>",
            ),
            (
                "maybe suppressed",
                GrayedOut,
                vec![(Suppressed, "r")],
                vec![GrayedOut, Suppressed],
                " <grayed-out or suppressed: r>",
                " <option grayed-out or suppressed: r>",
            ),
            (
                "lower unknown",
                Suppressed,
                vec![(GrayedOut, "r")],
                vec![Suppressed],
                " <suppressed>",
                " <option suppressed>",
            ),
            (
                "equal unknown",
                Disabled,
                vec![(Disabled, "r")],
                vec![Disabled],
                " <disabled>",
                " <option disabled>",
            ),
            (
                "two unknown",
                Selectable,
                vec![(GrayedOut, "r1"), (Disabled, "r2")],
                vec![Selectable, GrayedOut, Disabled],
                " <selectable or grayed-out or disabled: r1; r2>",
                " <option selectable or grayed-out or disabled: r1; r2>",
            ),
        ];
        for (name, known, unknown, states, annotation, option_annotation) in cases {
            let evaluation = evaluation(known, &unknown);
            assert_eq!(
                evaluation.possible_states(),
                BTreeSet::from_iter(states),
                "{name}"
            );
            assert_eq!(evaluation.annotation(), annotation, "{name}");
            assert_eq!(
                evaluation.option_annotation(),
                option_annotation,
                "{name}: option"
            );
        }
    }

    #[test]
    fn conditions_not_evaluated_for_one_reason_name_it_once() {
        let reason = "EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>";
        let evaluation = state(&[
            (GRAY_OUT_IF, eq_id_val_of(4, 2)),
            (SUPPRESS_IF, eq_id_val_of(4, 1)),
        ]);
        assert_eq!(
            evaluation.reasons().collect::<Vec<_>>(),
            [reason],
            "reasons"
        );
        assert_eq!(
            evaluation.annotation(),
            format!(" <selectable or grayed-out or suppressed: {reason}>"),
            "annotation"
        );
    }

    /// Picks the match of index `index`; the test takes its evaluation from the matches.
    fn picked(index: usize) -> Selection<usize> {
        picked_as(index, StateEvaluation::selectable())
    }

    /// Picks `candidate`, in `evaluation`, with no match ranked before it.
    fn picked_as<T>(candidate: T, evaluation: StateEvaluation) -> Selection<T> {
        Selection::Picked {
            picked: (candidate, evaluation),
            ranked_before: IncludedStates::empty(),
        }
    }

    /// Undetermined, likely the match of index `likely`; the test takes its evaluation from the
    /// matches.
    fn undetermined(likely: usize, reasons: &[&str], states: IncludedStates) -> Selection<usize> {
        Selection::Undetermined {
            likely: (likely, StateEvaluation::selectable()),
            reasons: reasons.iter().map(ToString::to_string).collect(),
            states,
            ranked_before: IncludedStates::empty(),
        }
    }

    #[test]
    fn select_picks_the_least_restricted_match_that_include_certainly_allows() {
        use QuestionState::*;
        let none = IncludedStates::empty();
        let grayed_out = IncludedStates::GRAYED_OUT;
        let suppressed = IncludedStates::SUPPRESSED;
        let disabled = IncludedStates::DISABLED;
        let maybe = |state| evaluation(Selectable, &[(state, "r")]);
        let cases = [
            (
                "selectable",
                vec![evaluation(Selectable, &[])],
                none,
                picked(0),
            ),
            (
                "grayed out",
                vec![evaluation(GrayedOut, &[])],
                none,
                Selection::Excluded(exclusion(grayed_out)),
            ),
            (
                "grayed out, included",
                vec![evaluation(GrayedOut, &[])],
                grayed_out,
                picked(0),
            ),
            (
                "maybe grayed out",
                vec![maybe(GrayedOut)],
                none,
                undetermined(0, &["r"], grayed_out),
            ),
            (
                "maybe grayed out, included",
                vec![maybe(GrayedOut)],
                grayed_out,
                picked(0),
            ),
            (
                "grayed out or suppressed, grayed out included",
                vec![evaluation(GrayedOut, &[(Suppressed, "r")])],
                grayed_out,
                undetermined(0, &["r"], suppressed),
            ),
            (
                "grayed out or suppressed, suppressed included",
                vec![evaluation(GrayedOut, &[(Suppressed, "r")])],
                suppressed,
                undetermined(0, &["r"], grayed_out),
            ),
            (
                "lower worst case wins",
                vec![evaluation(GrayedOut, &[]), evaluation(Selectable, &[])],
                grayed_out,
                picked(1),
            ),
            (
                "unknown conditions count in the worst case",
                vec![maybe(Suppressed), evaluation(GrayedOut, &[])],
                grayed_out | suppressed,
                picked(1),
            ),
            (
                "first on a tie",
                vec![evaluation(Selectable, &[]), evaluation(Selectable, &[])],
                none,
                picked(0),
            ),
            (
                "certain wins over undetermined",
                vec![maybe(GrayedOut), evaluation(Selectable, &[])],
                none,
                picked(1),
            ),
            (
                "undetermined wins over excluded",
                vec![evaluation(Disabled, &[]), maybe(Suppressed)],
                none,
                undetermined(1, &["r"], suppressed),
            ),
            (
                "excluded states add up",
                vec![evaluation(Suppressed, &[]), evaluation(Disabled, &[])],
                none,
                Selection::Excluded(exclusion(suppressed | disabled)),
            ),
            (
                "undetermined states and reasons add up, once each",
                vec![
                    evaluation(Selectable, &[(GrayedOut, "r1")]),
                    evaluation(Selectable, &[(Disabled, "r2")]),
                    evaluation(Selectable, &[(GrayedOut, "r1")]),
                ],
                none,
                undetermined(0, &["r1", "r2"], grayed_out | disabled),
            ),
            (
                "likely is the one of the lowest possible state that include allows",
                vec![
                    evaluation(GrayedOut, &[(Suppressed, "r1")]),
                    evaluation(Selectable, &[(GrayedOut, "r2")]),
                ],
                suppressed,
                undetermined(1, &["r1", "r2"], grayed_out),
            ),
            ("no match", vec![], none, Selection::NotFound),
        ];
        for (name, matches, include, want) in cases {
            let want = match want {
                Selection::Picked {
                    picked: (index, _),
                    ranked_before,
                } => Selection::Picked {
                    picked: (index, matches[index].clone()),
                    ranked_before,
                },
                Selection::Undetermined {
                    likely: (index, _),
                    reasons,
                    states,
                    ranked_before,
                } => Selection::Undetermined {
                    likely: (index, matches[index].clone()),
                    reasons,
                    states,
                    ranked_before,
                },
                want => want,
            };
            let matches = matches.into_iter().enumerate().collect();
            assert_eq!(select(matches, include), want, "{name}");
        }
    }

    /// Including more states never leaves select with no pick, or with a pick of a higher
    /// worst case.
    #[test]
    fn select_is_monotonic_in_the_included_states() {
        use QuestionState::*;
        let pool = [
            evaluation(Selectable, &[]),
            evaluation(GrayedOut, &[]),
            evaluation(Suppressed, &[(Disabled, "r")]),
            evaluation(Selectable, &[(GrayedOut, "r"), (Suppressed, "r")]),
            evaluation(Disabled, &[]),
        ];
        let includes: Vec<IncludedStates> =
            (0..8).map(IncludedStates::from_bits_truncate).collect();
        for first in &pool {
            for second in &pool {
                let matches = || vec![(0, first.clone()), (1, second.clone())];
                for &smaller in &includes {
                    let Selection::Picked {
                        picked: (_, picked),
                        ..
                    } = select(matches(), smaller)
                    else {
                        continue;
                    };
                    for &larger in includes.iter().filter(|larger| larger.contains(smaller)) {
                        let selection = select(matches(), larger);
                        assert!(
                            matches!(&selection, Selection::Picked { picked: (_, more), .. } if more.worst_case() <= picked.worst_case()),
                            "{first:?}, {second:?}: {smaller} picks {picked:?}, {larger} {selection:?}"
                        );
                    }
                }
            }
        }
    }

    /// Every StateEvaluation: each known state with each set of conditions not evaluated.
    fn every_evaluation() -> Vec<StateEvaluation> {
        use QuestionState::*;
        let conditions = [(GrayedOut, "r1"), (Suppressed, "r2"), (Disabled, "r3")];
        let mut evaluations = Vec::new();
        for known in [Selectable, GrayedOut, Suppressed, Disabled] {
            for mask in 0..8 {
                let unknown: Vec<(QuestionState, &str)> = conditions
                    .iter()
                    .enumerate()
                    .filter(|(bit, _)| mask & (1 << bit) != 0)
                    .map(|(_, &condition)| condition)
                    .collect();
                evaluations.push(evaluation(known, &unknown));
            }
        }
        evaluations
    }

    /// For one or two matches of every evaluation and every `include`: get shows what set
    /// writes; get shows a match only if `include` may allow it, and marks it if not certainly
    /// selectable; get falls back to the likely match exactly when set fails.
    #[test]
    fn get_shows_what_set_writes_and_marks_what_it_guesses() {
        let evaluations = every_evaluation();
        let mut cases: Vec<Vec<(usize, StateEvaluation)>> = evaluations
            .iter()
            .map(|evaluation| vec![(0, evaluation.clone())])
            .collect();
        for first in &evaluations {
            for second in &evaluations {
                cases.push(vec![(0, first.clone()), (1, second.clone())]);
            }
        }
        for matches in cases {
            for include in (0..8).map(IncludedStates::from_bits_truncate) {
                let case = format!("{matches:?}, include {include}");
                let set = select(matches.clone(), include).for_set("Q");
                let get = select(matches.clone(), include).for_get();
                match (&set, &get) {
                    (Ok(choice), _) => assert_eq!(choice, &get, "{case}"),
                    (Err(_), Choice::Chosen(_, evaluation)) => {
                        assert!(!evaluation.is_allowed(include), "{case}")
                    }
                    (Err(error), Choice::Skipped(_)) => {
                        panic!("{case}: set fails with {error}, get shows nothing")
                    }
                }
                if let Choice::Chosen(_, evaluation) = &get {
                    assert!(evaluation.may_be_allowed(include), "{case}");
                    let selectable = evaluation.is_allowed(IncludedStates::empty());
                    assert_eq!(evaluation.annotation().is_empty(), selectable, "{case}");
                    let guessed = evaluation.possible_states().len() > 1;
                    assert_eq!(evaluation.annotation().contains(": r"), guessed, "{case}");
                }
            }
        }
    }

    /// A question that one form may suppress, and another form holds unconditionally: get and
    /// set both take the second.
    #[test]
    fn get_and_set_take_a_certainly_selectable_copy_over_an_undetermined_one() {
        let forms = [
            form(
                1,
                &[conditional(
                    SUPPRESS_IF,
                    eq_id_val_of(4, 1),
                    &[checkbox_op(1, 0)],
                )],
            ),
            form(2, &[checkbox_op(2, 1)]),
        ];
        let set = selected_in(&forms, IncludedStates::empty()).for_set(PROMPT);
        let get = selected_in(&forms, IncludedStates::empty()).for_get();
        let want = Choice::Chosen(2, StateEvaluation::selectable());
        assert_eq!(set.expect("set selects"), want, "set");
        assert_eq!(get, want, "get");
    }

    /// How find_question_in selects among the CHECKBOXes of `body`, all prompted PROMPT, by
    /// their QuestionIds.
    fn selected(body: &[Vec<u8>], include: IncludedStates) -> Selection<u16> {
        selected_in(&[form(1, body)], include)
    }

    /// How find_question_in selects among the CHECKBOXes in the forms `forms`, as selected
    /// does.
    fn selected_in(forms: &[Vec<u8>], include: IncludedStates) -> Selection<u16> {
        let root = parse_form_set(forms);
        find_question_in(
            &root,
            &QuestionMatch::Prompt(&BTreeSet::from([PROMPT])),
            &mut FormSetWalk::new(
                &ListTexts::new(&strings(), &[]),
                &mut Efivars::new().reader(),
                &values(),
                include,
            ),
        )
        .map(|question| {
            question_id_at(&root, question.location).expect("the QuestionId of the selected")
        })
    }

    /// The QuestionId of the question under `node` that keeps its value at `location`, which
    /// no other question of these tests shares.
    fn question_id_at(node: &Rc<RefCell<IFROperation>>, location: ValueLocation) -> Option<u16> {
        let op = node.borrow();
        match value_question(&op) {
            Some(question) if question.location() == location => {
                Some(question.header().question_id)
            }
            _ => op
                .children
                .iter()
                .find_map(|child| question_id_at(child, location)),
        }
    }

    #[test]
    fn find_question_selects_by_the_state_of_each_match() {
        let suppressed = || conditional(SUPPRESS_IF, ifr_true(), &[checkbox_op(1, 0)]);
        let maybe_suppressed =
            || conditional(SUPPRESS_IF, eq_id_val_of(4, 1), &[checkbox_op(1, 0)]);
        let reason = "EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>";
        let include = IncludedStates::SUPPRESSED;
        let selectable = StateEvaluation::selectable;
        let cases = [
            (
                "selectable after suppressed",
                vec![suppressed(), checkbox_op(2, 1)],
                IncludedStates::empty(),
                picked_as(2, selectable()),
            ),
            (
                "selectable after suppressed, suppressed included",
                vec![suppressed(), checkbox_op(2, 1)],
                include,
                picked_as(2, selectable()),
            ),
            (
                "suppressed",
                vec![suppressed()],
                IncludedStates::empty(),
                Selection::Excluded(exclusion(include)),
            ),
            (
                "suppressed, included",
                vec![suppressed()],
                include,
                picked_as(1, known(QuestionState::Suppressed)),
            ),
            (
                "maybe suppressed",
                vec![maybe_suppressed()],
                IncludedStates::empty(),
                Selection::Undetermined {
                    likely: (
                        1,
                        evaluation(
                            QuestionState::Selectable,
                            &[(QuestionState::Suppressed, reason)],
                        ),
                    ),
                    reasons: vec![reason.to_string()],
                    states: include,
                    ranked_before: IncludedStates::empty(),
                },
            ),
            (
                "maybe suppressed, included",
                vec![maybe_suppressed()],
                include,
                picked_as(
                    1,
                    evaluation(
                        QuestionState::Selectable,
                        &[(QuestionState::Suppressed, reason)],
                    ),
                ),
            ),
            (
                "selectable after maybe suppressed",
                vec![maybe_suppressed(), checkbox_op(2, 1)],
                IncludedStates::empty(),
                picked_as(2, selectable()),
            ),
            (
                "no question",
                vec![],
                IncludedStates::empty(),
                Selection::NotFound,
            ),
        ];
        for (name, body, include, want) in cases {
            assert_eq!(selected(&body, include), want, "{name}");
        }
    }

    #[test]
    fn selection_errors_name_the_states_to_include() {
        let cases = [
            (
                SelectionError::Excluded {
                    question: "Q".to_string(),
                    states: IncludedStates::SUPPRESSED | IncludedStates::DISABLED,
                },
                "question \"Q\" is suppressed or disabled; also include suppressed,disabled \
                 questions to select it",
            ),
            (
                SelectionError::SnapshotExcluded {
                    question: "Q".to_string(),
                    states: IncludedStates::GRAYED_OUT,
                },
                "question \"Q\" is grayed-out by a value of the ExportConfig snapshot; also \
                 include grayed-out questions to select it",
            ),
            (
                SelectionError::Undetermined {
                    question: "Q".to_string(),
                    states: IncludedStates::GRAYED_OUT | IncludedStates::SUPPRESSED,
                    reasons: vec!["r1".to_string(), "r2".to_string()],
                },
                "cannot tell whether question \"Q\" is grayed-out or suppressed: r1; r2; also \
                 include grayed-out,suppressed questions to select it regardless",
            ),
            (
                SelectionError::OptionExcluded {
                    question: "Q".to_string(),
                    option: "O".to_string(),
                    states: IncludedStates::SUPPRESSED | IncludedStates::DISABLED,
                },
                "option \"O\" of question \"Q\" is suppressed or disabled; also include \
                 suppressed,disabled questions to select it",
            ),
            (
                SelectionError::SnapshotOptionExcluded {
                    question: "Q".to_string(),
                    option: "O".to_string(),
                    states: IncludedStates::SUPPRESSED,
                },
                "option \"O\" of question \"Q\" is suppressed by a value of the ExportConfig \
                 snapshot; also include suppressed questions to select it",
            ),
            (
                SelectionError::OptionUndetermined {
                    question: "Q".to_string(),
                    option: "O".to_string(),
                    states: IncludedStates::GRAYED_OUT | IncludedStates::SUPPRESSED,
                    reasons: vec!["r1".to_string(), "r2".to_string()],
                },
                "cannot tell whether option \"O\" of question \"Q\" is grayed-out or suppressed: \
                 r1; r2; also include grayed-out,suppressed questions to select it regardless",
            ),
        ];
        for (error, want) in cases {
            assert_eq!(error.to_string(), want, "{error:?}");
        }
    }

    #[test]
    fn not_found_names_the_question() {
        let error = SelectionError::NotFound {
            question: "Q".to_string(),
        };
        assert_eq!(
            error.to_string(),
            "no question \"Q\" in the HiiDB",
            "{error:?}"
        );
    }

    /// The options of the UINT8 ONE_OF of `one_of_data()` holding `children` that get lists,
    /// with their states.
    fn options(children: &[Vec<u8>]) -> Vec<(String, StateEvaluation)> {
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), children);
        question_descriptor_with(&question, unavailable(), &values())
            .possible_options
            .into_iter()
            .map(|option| (option.value, option.state))
            .collect()
    }

    /// get collects the options in the SUPPRESS_IF, GRAY_OUT_IF and DISABLE_IF scopes of a
    /// ONE_OF too, each in the state its SUPPRESS_IFs give: set refused them before with the
    /// error of https://github.com/linuxboot/uefisettings/issues/2, "provided value did not
    /// match any possible option".
    #[test]
    fn one_of_options_in_conditions_are_collected_with_their_states() {
        use QuestionState::*;
        let reason = "EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>";
        let got = options(&[
            flagged_option(5, 0x00, 0),
            conditional(SUPPRESS_IF, ifr_false(), &[flagged_option(6, 0x00, 1)]),
            conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(7, 0x00, 2)]),
            conditional(
                GRAY_OUT_IF,
                ifr_true(),
                &[conditional(
                    SUPPRESS_IF,
                    eq_id_val_of(4, 1),
                    &[flagged_option(5, 0x00, 3)],
                )],
            ),
        ]);

        let want = [
            ("Disabled", known(Selectable)),
            ("Enabled", known(Selectable)),
            ("AllOnes", known(Suppressed)),
            ("Disabled", evaluation(Selectable, &[(Suppressed, reason)])),
        ];
        let want: Vec<(String, StateEvaluation)> = want
            .into_iter()
            .map(|(text, state)| (text.to_string(), state))
            .collect();
        assert_eq!(got, want, "options with their states");
    }

    /// The option of the ONE_OF of `one_of_data()` holding `children` that set selects for
    /// "Enabled", by its value.
    fn selected_option(
        children: &[Vec<u8>],
        include: IncludedStates,
    ) -> Result<Option<u64>, SelectionError> {
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), children);
        let descriptor: QuestionDescriptor =
            question_descriptor_with(&question, unavailable(), &values());
        let option = descriptor.select_option(&BTreeSet::from(["Enabled".to_string()]), include)?;
        Ok(option.and_then(|option| option.as_u64()))
    }

    #[test]
    fn set_selects_an_option_that_include_allows() {
        let suppressed = || conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(6, 0x00, 1)]);
        let maybe_suppressed = || {
            conditional(
                SUPPRESS_IF,
                eq_id_val_of(4, 1),
                &[flagged_option(6, 0x00, 1)],
            )
        };
        let none = IncludedStates::empty();
        let include = IncludedStates::SUPPRESSED;

        let shown_after_suppressed = [suppressed(), flagged_option(6, 0x00, 2)];
        assert_eq!(
            selected_option(&shown_after_suppressed, none),
            Ok(Some(2)),
            "shown after suppressed"
        );
        assert_eq!(
            selected_option(&shown_after_suppressed, include),
            Ok(Some(2)),
            "shown after suppressed, suppressed included"
        );
        assert_eq!(
            selected_option(&[suppressed()], include),
            Ok(Some(1)),
            "suppressed, suppressed included"
        );
        assert_eq!(
            selected_option(&[maybe_suppressed()], include),
            Ok(Some(1)),
            "maybe suppressed, suppressed included"
        );
        assert_eq!(
            selected_option(&[flagged_option(5, 0x00, 0)], none),
            Ok(None),
            "no option of the text"
        );
        assert_eq!(
            selected_option(&[suppressed()], none),
            Err(SelectionError::OptionExcluded {
                question: String::new(),
                option: "Enabled".to_string(),
                states: IncludedStates::SUPPRESSED,
            }),
            "suppressed"
        );
        assert_eq!(
            selected_option(&[maybe_suppressed()], none),
            Err(SelectionError::OptionUndetermined {
                question: String::new(),
                option: "Enabled".to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![
                    "EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: test>".to_string()
                ],
            }),
            "maybe suppressed"
        );
    }

    /// The UINT8 ONE_OF of `one_of_data()` holding `children` and storing `stored`, as get,
    /// list-questions and set see it with `values`, and variables that hold its VarStore, for set
    /// to write there.
    fn stored_one_of(
        children: &[Vec<u8>],
        stored: u8,
        values: &impl QuestionValues,
    ) -> (QuestionDescriptor, MemoryVariables) {
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), children);
        let variables = MemoryVariables::default();
        let store = writable_var_store("VarStore", &[stored], &variables);
        (
            question_descriptor_with(&question, store, values),
            variables,
        )
    }

    /// The writes to the VarStore of stored_one_of.
    fn writes(variables: &MemoryVariables) -> Vec<(u16, Vec<u8>)> {
        variables.writes_to(&variable_key("VarStore"))
    }

    /// The answer that get shows for `question`, but for the state of the question.
    fn shown_answer(question: &QuestionDescriptor) -> String {
        question.value.clone() + &question.value_state.option_annotation()
    }

    /// Sets `question` to the option `text` in `variables` as set does with `include`.
    fn set_option(
        question: &QuestionDescriptor,
        text: &str,
        include: IncludedStates,
        variables: &MemoryVariables,
    ) -> std::result::Result<(), String> {
        let option = question
            .select_option(&BTreeSet::from([text.to_string()]), include)
            .map_err(|error| error.to_string())?
            .ok_or("no such option")?;
        change_option(question, option, variables).map_err(|error| error.to_string())
    }

    /// A false SUPPRESS_IF shows the options in it, so get lists them and names the stored one,
    /// and set writes them, which set refused before with the error of
    /// https://github.com/linuxboot/uefisettings/issues/2, "provided value did not match any
    /// possible option".
    #[test]
    fn options_in_a_false_suppress_if_are_listed_shown_and_set() {
        let options = [flagged_option(5, 0x00, 0), flagged_option(6, 0x00, 1)];
        let (question, variables) = stored_one_of(
            &[conditional(SUPPRESS_IF, ifr_false(), &options)],
            1,
            &values(),
        );

        assert_eq!(
            question.listed_options(IncludedStates::empty()),
            ["Disabled", "Enabled"],
            "listed"
        );
        assert_eq!(shown_answer(&question), "Enabled", "answer");
        assert!(
            matches!(change_value(&question, "Disabled", &variables), Ok(())),
            "set Disabled"
        );
        assert_eq!(writes(&variables), [(0, vec![0])], "writes of Disabled");
    }

    #[test]
    fn option_in_a_true_suppress_if_is_hidden_unless_suppressed_is_included() {
        let children = [
            flagged_option(5, 0x00, 0),
            conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(6, 0x00, 1)]),
        ];
        let (question, variables) = stored_one_of(&children, 1, &values());

        assert_eq!(
            question.listed_options(IncludedStates::empty()),
            ["Disabled"],
            "listed"
        );
        assert_eq!(
            shown_answer(&question),
            "Enabled <option suppressed>",
            "answer"
        );
        assert_eq!(
            change_value(&question, "Enabled", &variables).map_err(|error| error.to_string()),
            Err(
                "option \"Enabled\" of question \"\" is suppressed; also include suppressed \
                 questions to select it"
                    .to_string()
            ),
            "change_value to Enabled"
        );
        assert_eq!(writes(&variables), [], "writes of change_value");

        let suppressed = IncludedStates::SUPPRESSED;
        assert_eq!(
            question.listed_options(suppressed),
            ["Disabled", "Enabled"],
            "listed, suppressed included"
        );
        assert_eq!(
            set_option(&question, "Enabled", suppressed, &variables),
            Ok(()),
            "set Enabled, suppressed included"
        );
        assert_eq!(
            writes(&variables),
            [(0, vec![1])],
            "writes, suppressed included"
        );
    }

    #[test]
    fn option_in_a_suppress_if_on_a_question_follows_its_value() {
        let children = [
            flagged_option(5, 0x00, 0),
            conditional(
                SUPPRESS_IF,
                eq_id_val_of(4, 1),
                &[flagged_option(6, 0x00, 1)],
            ),
        ];
        let undetermined = "cannot tell whether option \"Enabled\" of question \"\" is \
                            suppressed: EFI_IFR_EQ_ID_VAL of question 0x0004: <ValueUnavailable: \
                            test>; also include suppressed questions to select it regardless";
        let excluded = "option \"Enabled\" of question \"\" is suppressed; also include \
                        suppressed questions to select it";
        let cases = [
            (
                "question 4 is 1",
                QuestionValue::Uint(1),
                vec!["Disabled"],
                "Enabled <option suppressed>",
                Err(excluded.to_string()),
            ),
            (
                "question 4 is 2",
                QuestionValue::Uint(2),
                vec!["Disabled", "Enabled"],
                "Enabled",
                Ok(()),
            ),
            (
                "question 4 unreadable",
                unreadable(ValueKind::Uint),
                vec!["Disabled"],
                "Enabled <option selectable or suppressed: EFI_IFR_EQ_ID_VAL of question 0x0004: \
                 <ValueUnavailable: test>>",
                Err(undetermined.to_string()),
            ),
        ];
        for (name, question_4, listed, answer, set) in cases {
            let values = MapValues(BTreeMap::from([(4, question_4)]));
            let (question, variables) = stored_one_of(&children, 1, &values);

            assert_eq!(
                question.listed_options(IncludedStates::empty()),
                listed,
                "{name}"
            );
            assert_eq!(shown_answer(&question), answer, "{name}");
            let written = if set.is_ok() {
                vec![(0, vec![1])]
            } else {
                vec![]
            };
            assert_eq!(
                set_option(&question, "Enabled", IncludedStates::empty(), &variables),
                set,
                "{name}"
            );
            assert_eq!(writes(&variables), written, "{name}");

            let suppressed = IncludedStates::SUPPRESSED;
            assert_eq!(
                question.listed_options(suppressed),
                ["Disabled", "Enabled"],
                "{name}, suppressed included"
            );
            assert_eq!(
                set_option(&question, "Enabled", suppressed, &variables),
                Ok(()),
                "{name}, suppressed included"
            );
        }
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes attaches only SUPPRESS_IF to
    /// options, and conditions in a ONE_OF are not around the question.
    #[test]
    fn gray_out_if_and_disable_if_in_a_one_of_leave_its_options_and_state() {
        let (_root, node) = parse_question(
            &[],
            ONE_OF,
            &one_of_data(),
            &[
                conditional(GRAY_OUT_IF, ifr_true(), &[flagged_option(5, 0x00, 0)]),
                conditional(DISABLE_IF, ifr_true(), &[flagged_option(6, 0x00, 1)]),
            ],
        );
        let variables = MemoryVariables::default();
        let store = writable_var_store("VarStore", &[0], &variables);
        let question = question_descriptor_with(&node, store, &values());

        assert_eq!(
            question_state(
                &node.borrow(),
                &mut ExpressionInputs {
                    reader: &mut Efivars::new().reader(),
                    values: &values()
                }
            ),
            StateEvaluation::selectable(),
            "question state"
        );
        assert_eq!(
            question.listed_options(IncludedStates::empty()),
            ["Disabled", "Enabled"],
            "listed"
        );
        assert_eq!(shown_answer(&question), "Disabled", "answer");
        assert_eq!(
            set_option(&question, "Enabled", IncludedStates::empty(), &variables),
            Ok(()),
            "set Enabled"
        );
        assert_eq!(writes(&variables), [(0, vec![1])], "writes of Enabled");
    }

    /// As edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption, get names the first option
    /// of the stored value that may be shown.
    #[test]
    fn answer_names_the_first_shown_option_of_the_stored_value() {
        let (question, _) = stored_one_of(
            &[
                conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(5, 0x00, 1)]),
                flagged_option(6, 0x00, 1),
            ],
            1,
            &values(),
        );
        assert_eq!(
            shown_answer(&question),
            "Enabled",
            "suppressed before shown"
        );
    }

    /// get names the first option of the stored value that may be shown, with its states, over a
    /// later one that is certainly shown.
    #[test]
    fn answer_names_the_first_option_of_the_stored_value_that_may_be_shown() {
        let (question, _) = stored_one_of(
            &[
                conditional(
                    SUPPRESS_IF,
                    eq_id_val_of(4, 1),
                    &[flagged_option(5, 0x00, 1)],
                ),
                flagged_option(6, 0x00, 1),
            ],
            1,
            &values(),
        );
        assert_eq!(
            shown_answer(&question),
            "Disabled <option selectable or suppressed: EFI_IFR_EQ_ID_VAL of question 0x0004: \
             <ValueUnavailable: test>>",
            "maybe suppressed before shown"
        );
    }

    #[test]
    fn direct_and_nested_options_are_collected_in_ifr_order() {
        let (question, _) = stored_one_of(
            &[
                flagged_option(5, 0x00, 0),
                conditional(SUPPRESS_IF, ifr_false(), &[flagged_option(6, 0x00, 1)]),
                flagged_option(7, 0x00, 2),
            ],
            0,
            &values(),
        );
        let options: Vec<(&str, Option<u64>)> = question
            .possible_options
            .iter()
            .map(|option| (option.value.as_str(), option.as_u64()))
            .collect();
        assert_eq!(
            options,
            [
                ("Disabled", Some(0)),
                ("Enabled", Some(1)),
                ("AllOnes", Some(2))
            ],
            "options with their values"
        );
    }

    /// Question 7 is in both forms; question 9 only in the second, which also holds a DATE of
    /// QuestionId 12.
    fn two_forms() -> Rc<RefCell<IFROperation>> {
        let date = operation(
            0x1A,
            false,
            &[question_header_of(12, 5), vec![0x00]].concat(),
        );
        parse_form_set(&[
            form(
                1,
                &[
                    checkbox_op(7, 0),
                    conditional(SUPPRESS_IF, eq_id_val_of(7, 1), &[checkbox_op(8, 1)]),
                ],
            ),
            form(
                2,
                &[
                    checkbox_op(7, 2),
                    checkbox_op(9, 3),
                    conditional(SUPPRESS_IF, eq_id_val_of(7, 2), &[checkbox_op(10, 4)]),
                    date,
                ],
            ),
        ])
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes parses no question in the scope
    /// of an opcode above EFI_IFR_MATCH2_OP: the ONE_OF, question 1, in one is found neither by
    /// its prompt nor by its QuestionId. Opcode 0x00, which UEFI 2.10 §33.3.8.3 (Table 33.11 IFR
    /// Opcodes) does not define either, and the root are no such scopes.
    #[test]
    fn questions_in_an_unknown_opcode_scope_are_not_found() {
        let one_of = [
            operation(ONE_OF, true, &one_of_data()),
            flagged_option(5, 0x00, 0),
            END.to_vec(),
        ]
        .concat();
        let in_scope =
            |op_code: u8| [operation(op_code, true, &[]), one_of.clone(), END.to_vec()].concat();
        let cases = [
            ("no scope", one_of.clone(), true),
            ("opcode 0x00", in_scope(0x00), true),
            ("opcode 0x65", in_scope(0x65), false),
            ("opcode 0x70", in_scope(0x70), false),
        ];
        for (name, body, parsed) in cases {
            let found = selected_in(
                &[form(1, std::slice::from_ref(&body))],
                IncludedStates::empty(),
            );
            let want = if parsed {
                picked_as(1, StateEvaluation::selectable())
            } else {
                Selection::NotFound
            };
            assert_eq!(found, want, "{name}: found by its prompt");

            let referrer = checkbox_op(2, 1);
            let root = parse_form_set(&[form(1, &[body, referrer.clone()])]);
            let referrer = find_op(&root, &referrer[2..])
                .unwrap_or_else(|| panic!("{name}: find the referrer"));
            let value = VarStoreValues::new(&root, None).value(
                &referrer.borrow(),
                1,
                &mut Efivars::new().reader(),
            );
            assert_eq!(value.is_some(), parsed, "{name}: found by its QuestionId");
        }
    }

    /// list_questions leaves out the questions that find_question_in does not find: those in the
    /// scope of an opcode above EFI_IFR_MATCH2_OP, 0xFF included.
    #[test]
    fn questions_in_an_unknown_opcode_scope_are_not_listed() {
        let in_scope = |op_code: u8| {
            [
                operation(op_code, true, &[]),
                checkbox_op(2, 1),
                END.to_vec(),
            ]
            .concat()
        };
        let cases = [
            ("opcode 0x00", in_scope(0x00), vec![1, 2, 3]),
            ("opcode 0x65", in_scope(0x65), vec![1, 3]),
            ("opcode 0x70", in_scope(0x70), vec![1, 3]),
            ("opcode 0xFF", in_scope(0xFF), vec![1, 3]),
        ];
        for (name, scope, want) in cases {
            let root = parse_form_set(&[form(1, &[checkbox_op(1, 0), scope, checkbox_op(3, 2)])]);

            let got: Vec<u16> = list_questions(
                Rc::clone(&root),
                &ListTexts::new(&strings(), &[]),
                IncludedStates::empty(),
                None,
                &mut Efivars::new().reader(),
            )
            .into_iter()
            .map(|(question, _)| {
                question_id_at(&root, question.location).expect("the QuestionId of the listed")
            })
            .collect();

            assert_eq!(got, want, "{name}");
        }
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes takes no option in the scope of
    /// an opcode above EFI_IFR_MATCH2_OP either.
    #[test]
    fn options_in_an_unknown_opcode_scope_are_not_collected() {
        let in_scope = |op_code: u8| {
            [
                operation(op_code, true, &[]),
                flagged_option(6, 0x00, 1),
                END.to_vec(),
            ]
            .concat()
        };
        let cases = [
            ("opcode 0x00", in_scope(0x00), vec!["Disabled", "Enabled"]),
            ("opcode 0x65", in_scope(0x65), vec!["Disabled"]),
            ("opcode 0x70", in_scope(0x70), vec!["Disabled"]),
        ];
        for (name, scope, want) in cases {
            let got: Vec<String> = options(&[flagged_option(5, 0x00, 0), scope])
                .into_iter()
                .map(|(text, _)| text)
                .collect();
            assert_eq!(got, want, "{name}");
        }
    }

    /// The VarOffset of question `id` as `referrer` finds it.
    fn found_offset(root: &Rc<RefCell<IFROperation>>, referrer: &[u8], id: u16) -> Option<u16> {
        let referrer = find_op(root, &referrer[2..]).expect("find the referrer");
        let index = QuestionIndex::new(root);
        let question = index.question(&referrer.borrow(), id)?;
        let question = question.borrow();
        value_question(&question).map(|question| question.header().var_store_info)
    }

    #[test]
    fn question_index_searches_the_form_first() {
        let root = two_forms();
        let in_first_form = eq_id_val_of(7, 1);
        let in_second_form = eq_id_val_of(7, 2);

        assert_eq!(
            found_offset(&root, &in_first_form, 7),
            Some(0),
            "question 7 from the first form"
        );
        assert_eq!(
            found_offset(&root, &in_second_form, 7),
            Some(2),
            "question 7 from the second form"
        );
        assert_eq!(
            found_offset(&root, &in_first_form, 9),
            Some(3),
            "question 9 from the first form"
        );
        assert_eq!(
            found_offset(&root, &in_first_form, 11),
            None,
            "question 11 from the first form"
        );
        assert_eq!(
            found_offset(&root, &in_first_form, 0),
            None,
            "question 0 from the first form"
        );
        let referrer = find_op(&root, &in_first_form[2..]).expect("find the referrer");
        let index = QuestionIndex::new(&root);
        let date = index
            .question(&referrer.borrow(), 12)
            .expect("find the DATE");
        assert_eq!(date.borrow().op_code, IFROpCode::Date, "question 12");
    }

    /// A condition outside forms, e.g. a SUPPRESS_IF around a FORM, finds the first question of
    /// the QuestionId in IFR order.
    #[test]
    fn question_index_outside_forms_finds_the_first() {
        let referrer = eq_id_val_of(7, 3);
        let root = parse_form_set(&[
            conditional(
                SUPPRESS_IF,
                referrer.clone(),
                &[form(1, &[checkbox_op(7, 0)])],
            ),
            form(2, &[checkbox_op(7, 2)]),
        ]);
        assert_eq!(found_offset(&root, &referrer, 7), Some(0), "question 7");
    }

    /// QuestionId 0 is reserved (UEFI 2.10 §33.3.8.2.2): edk2-stable202608
    /// SetupBrowserDxe/Expression.c IdToQuestion2 finds no question of it.
    #[test]
    fn question_id_0_refers_to_no_question() {
        let referrer = checkbox_op(1, 1);
        let root = parse_form_set(&[form(1, &[checkbox_op(0, 0), referrer.clone()])]);
        let referrer = find_op(&root, &referrer[2..]).expect("find the referrer");
        let values = VarStoreValues::new(&root, None);
        let mut reader = Efivars::new().reader();
        assert_eq!(
            values.value(&referrer.borrow(), 0, &mut reader),
            None,
            "QuestionId 0"
        );
        assert!(
            values.value(&referrer.borrow(), 1, &mut reader).is_some(),
            "QuestionId 1"
        );
    }

    /// An EQ_ID_VAL on a STRING or PASSWORD is false: edk2-stable202608
    /// SetupBrowserDxe/Expression.c CompareHiiValue gives EFI_UNSUPPORTED for a string and an
    /// integer, which EQ_ID_VAL turns into UNDEFINED.
    #[test]
    fn eq_id_val_on_a_string_or_password_is_false() {
        for (op_code, name) in [(STRING, "String"), (PASSWORD, "Password")] {
            let question = operation(
                op_code,
                false,
                &[question_header_of(13, 0), vec![0x00; 5]].concat(),
            );
            let condition = eq_id_val_of(13, 1);
            let root = parse_form_set(&[form(
                1,
                &[
                    question,
                    conditional(SUPPRESS_IF, condition.clone(), &[checkbox_op(14, 0)]),
                ],
            )]);
            let condition = find_op(&root, &condition[2..]).expect("find the EQ_ID_VAL");
            let scope = condition
                .borrow()
                .parent
                .as_ref()
                .and_then(Weak::upgrade)
                .expect("find the SUPPRESS_IF");

            assert_eq!(
                evaluate_condition(
                    &scope.borrow(),
                    &mut ExpressionInputs {
                        reader: &mut Efivars::new().reader(),
                        values: &VarStoreValues::new(&root, None),
                    },
                ),
                Truth::Known(false),
                "{name}"
            );
        }
    }

    /// VarStoreValues reads a question's VarStore as get does.
    #[test]
    fn var_store_values_read_the_question_var_store() {
        let root = two_forms();
        let referrer = find_op(&root, &eq_id_val_of(7, 1)[2..]).expect("find the referrer");
        let referrer = referrer.borrow();
        let values = VarStoreValues::new(&root, None);

        assert_eq!(
            values.value(&referrer, 9, &mut Efivars::new().reader()),
            Some(QuestionValue::Unreadable {
                kind: ValueKind::Boolean,
                reason: "<ValueUnavailable: no supported varstore with matching id 0x0001 found>"
                    .to_string()
            }),
            "CHECKBOX 9"
        );
        assert_eq!(
            values.value(&referrer, 12, &mut Efivars::new().reader()),
            Some(QuestionValue::Unreadable {
                kind: ValueKind::Other,
                reason: "<ValueUnavailable: EFI_IFR_DATE value not decoded>".to_string()
            }),
            "DATE 12"
        );
        assert_eq!(
            values.value(&referrer, 11, &mut Efivars::new().reader()),
            None,
            "no question 11"
        );
    }

    /// VarStoreValues reads through the EfivarReader of the command: each efivar once.
    #[test]
    fn var_store_values_read_through_the_efivar_reader() {
        let root = parse_form_set(&[
            var_store_efi(1, "UefisettingsTest", NV_BS_RT, 2),
            form(1, &[checkbox_op(1, 0), checkbox_op(2, 1)]),
        ]);
        let question = find_op(&root, &checkbox_op(1, 0)[2..]).expect("find question 1");
        let store = find_corresponding_varstore(Rc::clone(&question), 1);
        let store = store.as_ref().expect("find VarStore 1");
        let efivars = Efivars::new();
        efivars.write(store.as_ref(), &[1, 0]);
        let mut reader = efivars.reader();
        let values = VarStoreValues::new(&root, None);
        let referrer = question.borrow();

        assert_eq!(
            values.value(&referrer, 1, &mut reader),
            Some(QuestionValue::Boolean(1)),
            "question 1"
        );
        efivars.write(store.as_ref(), &[0, 1]);
        assert_eq!(
            values.value(&referrer, 2, &mut reader),
            Some(QuestionValue::Boolean(0)),
            "question 2 after the file changed"
        );
        assert_eq!(
            values.value(&referrer, 2, &mut efivars.reader()),
            Some(QuestionValue::Boolean(1)),
            "question 2 through a fresh EfivarReader"
        );
    }

    /// The reason that a question on the level byte of AMI firmware's VarStore SystemAccess,
    /// buffer or EFI variable, has no value says what the setup browser keeps there; a question
    /// on another byte of it or of another width, or on a VarStore of another name or Guid,
    /// keeps its reason, and a readable SystemAccess its value.
    #[test]
    fn unreadable_ami_access_level_is_named() {
        let cases = [
            (
                "buffer SystemAccess",
                var_store(1, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
                "<ValueUnavailable: no EFI variable \
                 SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac; HII buffer varstore requires \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL; the AMI setup browser keeps its access level \
                 there (0 Administrator, 1 User); \
                 --access-level administrator|user states one>",
            ),
            (
                "EFI variable SystemAccess",
                var_store_efi_of(1, SYSTEM_ACCESS_GUID, "SystemAccess", NV_BS_RT, 1),
                "<ValueUnavailable: no EFI variable \
                 SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac; the AMI setup browser keeps \
                 its access level there (0 Administrator, 1 User); \
                 --access-level administrator|user states one>",
            ),
            (
                "boot-service-only EFI variable SystemAccess",
                var_store_efi_of(1, SYSTEM_ACCESS_GUID, "SystemAccess", NV_BS, 1),
                "<ValueUnavailable: EFI variable SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac \
                 is not present at OS runtime: efivarfs does not list it, and its form declares it \
                 boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS); the AMI setup browser keeps \
                 its access level there (0 Administrator, 1 User); \
                 --access-level administrator|user states one>",
            ),
            (
                "buffer SystemAccess of NIL_GUID",
                var_store(1, [0; 16], "SystemAccess", 1),
                "<ValueUnavailable: no EFI variable \
                 SystemAccess-00000000-0000-0000-0000-000000000000; HII buffer varstore requires \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL>",
            ),
            (
                "buffer Setup of the SystemAccess Guid",
                var_store(1, SYSTEM_ACCESS_GUID, "Setup", 1),
                "<ValueUnavailable: no EFI variable Setup-e770bb69-bcb4-4d04-9e97-23ff9456feac; \
                 HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>",
            ),
            (
                "buffer Setup of NIL_GUID",
                var_store(1, [0; 16], "Setup", 1),
                "<ValueUnavailable: no EFI variable Setup-00000000-0000-0000-0000-000000000000; \
                 HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>",
            ),
        ];
        for (name, declaration, want) in cases {
            let root = parse_form_set(&[declaration, form(1, &[checkbox_op(1, 0)])]);
            let question = find_op(&root, &checkbox_op(1, 0)[2..]).expect("find question 1");
            assert_eq!(
                VarStoreValues::new(&root, None).value(
                    &question.borrow(),
                    1,
                    &mut Efivars::new().reader()
                ),
                Some(QuestionValue::Unreadable {
                    kind: ValueKind::Boolean,
                    reason: want.to_string(),
                }),
                "{name}"
            );
        }

        let checkbox_at_1 = checkbox_op(1, 1);
        let uint16_at_0 = operation(
            NUMERIC,
            false,
            &[
                question_header_on(2, 5, 1, 0),
                vec![0x01, 0, 0, 0xFF, 0xFF, 1, 0],
            ]
            .concat(),
        );
        let root = parse_form_set(&[
            var_store(1, SYSTEM_ACCESS_GUID, "SystemAccess", 2),
            form(1, &[checkbox_at_1.clone(), uint16_at_0.clone()]),
        ]);
        let others = [
            (
                "VarOffset 1 of a 2-byte buffer SystemAccess",
                &checkbox_at_1,
                1,
                ValueKind::Boolean,
            ),
            (
                "UINT16 NUMERIC at VarOffset 0 of a 2-byte buffer SystemAccess",
                &uint16_at_0,
                2,
                ValueKind::Uint,
            ),
        ];
        for (name, op, id, kind) in others {
            let question = find_op(&root, &op[2..]).expect("find the question");
            assert_eq!(
                VarStoreValues::new(&root, None).value(
                    &question.borrow(),
                    id,
                    &mut Efivars::new().reader()
                ),
                Some(QuestionValue::Unreadable {
                    kind,
                    reason: "<ValueUnavailable: no EFI variable \
                             SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac; HII buffer \
                             varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>"
                        .to_string(),
                }),
                "{name}"
            );
        }

        let root = parse_form_set(&[
            var_store(1, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
            form(1, &[checkbox_op(1, 0)]),
        ]);
        let question = find_op(&root, &checkbox_op(1, 0)[2..]).expect("find question 1");
        let values = VarStoreValues::new(&root, None);
        assert_eq!(
            values.value(&question.borrow(), 1, &mut disabled_reader()),
            Some(QuestionValue::Unreadable {
                kind: ValueKind::Boolean,
                reason: "<ValueUnavailable: EFI variables not read; the AMI setup browser keeps \
                         its access level there (0 Administrator, 1 User); \
                         --access-level administrator|user states one>"
                    .to_string(),
            }),
            "buffer SystemAccess without reading efivars"
        );
        let store = find_corresponding_varstore(Rc::clone(&question), 1);
        let efivars = Efivars::new();
        efivars.write(store.as_ref().expect("find VarStore 1").as_ref(), &[1]);
        assert_eq!(
            values.value(&question.borrow(), 1, &mut efivars.reader()),
            Some(QuestionValue::Boolean(1)),
            "readable buffer SystemAccess"
        );
    }

    /// The state of question 1 in the scope `scope` of `condition`, which reads question 2,
    /// `access_level_question`, on AMI firmware's buffer VarStore SystemAccess, whose efivar
    /// holds `stored` if any, with conditions reading `stated`, if stated, instead of its value.
    fn access_level_state(
        access_level_question: &[u8],
        (scope, condition): (u8, Vec<u8>),
        stored: Option<u8>,
        stated: Option<AccessLevel>,
    ) -> StateEvaluation {
        let question = checkbox_on(1, 3, 1);
        let root = parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
            form(
                1,
                &[
                    access_level_question.to_vec(),
                    conditional(scope, condition, std::slice::from_ref(&question)),
                ],
            ),
        ]);
        let question = find_op(&root, &question[2..]).expect("find question 1");
        let efivars = Efivars::new();
        if let Some(stored) = stored {
            let store = find_corresponding_varstore(Rc::clone(&question), 2);
            efivars.write(store.as_ref().expect("find VarStore 2").as_ref(), &[stored]);
        }
        let question = question.borrow();
        question_state(
            &question,
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values: &VarStoreValues::new(&root, stated),
            },
        )
    }

    /// A stated access level replaces the level byte of SystemAccess in every condition,
    /// whether or not its efivar can be read; without one, and for a question on another byte
    /// or of another width, conditions read the efivar.
    #[test]
    fn stated_access_level_replaces_the_stored_one() {
        const UNREAD: &str = "EFI_IFR_EQ_ID_VAL of question 0x0002: <ValueUnavailable: no EFI \
            variable SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac; HII buffer varstore \
            requires EFI_HII_CONFIG_ACCESS_PROTOCOL; the AMI setup browser keeps its access level \
            there (0 Administrator, 1 User); --access-level administrator|user states one>";
        let user_only = || (GRAY_OUT_IF, eq_id_val_of(2, 1));
        // the one comparison with 85 in the HiiDBs of AMI firmware read so far
        let not_85 = || {
            (
                SUPPRESS_IF,
                [eq_id_val_of(2, 85), operation(NOT, false, &[])].concat(),
            )
        };
        let undetermined = StateEvaluation {
            current: QuestionState::Selectable,
            unknown: vec![(QuestionState::GrayedOut, UNREAD.to_string())],
            read_only: None,
            from_snapshot: Vec::new(),
        };
        let cases = [
            (
                "Administrator, no efivar",
                user_only(),
                None,
                Some(AccessLevel::Administrator),
                known(QuestionState::Selectable),
            ),
            (
                "User, no efivar",
                user_only(),
                None,
                Some(AccessLevel::User),
                known(QuestionState::GrayedOut),
            ),
            ("no level, no efivar", user_only(), None, None, undetermined),
            (
                "Administrator over a stored 1",
                user_only(),
                Some(1),
                Some(AccessLevel::Administrator),
                known(QuestionState::Selectable),
            ),
            (
                "User over a stored 0",
                user_only(),
                Some(0),
                Some(AccessLevel::User),
                known(QuestionState::GrayedOut),
            ),
            (
                "no level, stored 1",
                user_only(),
                Some(1),
                None,
                known(QuestionState::GrayedOut),
            ),
            (
                "no level, stored 0",
                user_only(),
                Some(0),
                None,
                known(QuestionState::Selectable),
            ),
            (
                "Administrator, NOT 85",
                not_85(),
                None,
                Some(AccessLevel::Administrator),
                known(QuestionState::Suppressed),
            ),
            (
                "User, NOT 85",
                not_85(),
                None,
                Some(AccessLevel::User),
                known(QuestionState::Suppressed),
            ),
        ];
        let access_level_questions = [
            ("CHECKBOX", checkbox_on(2, 5, 2)),
            ("UINT8 NUMERIC", uint8_numeric_on(2, 5, 2)),
        ];
        for (kind, access_level_question) in &access_level_questions {
            for (name, scope, stored, stated, want) in cases.clone() {
                assert_eq!(
                    access_level_state(access_level_question, scope, stored, stated),
                    want,
                    "{kind}: {name}"
                );
            }
        }

        let checkbox_at_1 = operation(
            CHECKBOX,
            false,
            &[question_header_on(2, 5, 2, 1), vec![0x00]].concat(),
        );
        let uint16_at_0 = operation(
            NUMERIC,
            false,
            &[
                question_header_on(3, 5, 2, 0),
                vec![0x01, 0, 0, 0xFF, 0xFF, 1, 0],
            ]
            .concat(),
        );
        let root = parse_form_set(&[
            var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
            form(1, &[checkbox_at_1.clone(), uint16_at_0.clone()]),
        ]);
        let others = [
            (
                "CHECKBOX at VarOffset 1",
                &checkbox_at_1,
                2,
                ValueKind::Boolean,
                "<ExtractEFIDataError: failed to fill whole buffer (offset: 1; buflen: 5)>",
            ),
            (
                "UINT16 NUMERIC at VarOffset 0",
                &uint16_at_0,
                3,
                ValueKind::Uint,
                "<ExtractEFIDataError: failed to fill whole buffer (offset: 0; buflen: 5)>",
            ),
        ];
        for (name, op, id, kind, reason) in others {
            let question = find_op(&root, &op[2..]).expect("find the question");
            let store = find_corresponding_varstore(Rc::clone(&question), 2);
            let efivars = Efivars::new();
            efivars.write(store.as_ref().expect("find VarStore 2").as_ref(), &[1]);
            assert_eq!(
                VarStoreValues::new(&root, Some(AccessLevel::User)).value(
                    &question.borrow(),
                    id,
                    &mut efivars.reader()
                ),
                Some(QuestionValue::Unreadable {
                    kind,
                    reason: reason.to_string(),
                }),
                "{name}, User"
            );
        }
    }

    /// A stated level replaces only the level byte: question 2 at VarOffset 1 of a 2-byte
    /// SystemAccess is read as stored.
    #[test]
    fn stated_access_level_replaces_only_the_level_byte() {
        let at_offset_1 = operation(
            NUMERIC,
            false,
            &[question_header_on(2, 5, 2, 1), vec![0x00, 0, 255, 1]].concat(),
        );
        let question = checkbox_on(1, 3, 1);
        let root = parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 2),
            form(
                1,
                &[
                    at_offset_1,
                    conditional(
                        SUPPRESS_IF,
                        eq_id_val_of(2, 7),
                        std::slice::from_ref(&question),
                    ),
                ],
            ),
        ]);
        let question = find_op(&root, &question[2..]).expect("find question 1");
        let store = find_corresponding_varstore(Rc::clone(&question), 2);
        let efivars = Efivars::new();
        efivars.write(store.as_ref().expect("find VarStore 2").as_ref(), &[1, 7]);
        let question = question.borrow();
        for level in [
            None,
            Some(AccessLevel::Administrator),
            Some(AccessLevel::User),
        ] {
            assert_eq!(
                question_state(
                    &question,
                    &mut ExpressionInputs {
                        reader: &mut efivars.reader(),
                        values: &VarStoreValues::new(&root, level),
                    },
                ),
                known(QuestionState::Suppressed),
                "{level:?}"
            );
        }
    }

    /// A stated access level leaves a condition on another VarStore's question as its efivar
    /// holds it.
    #[test]
    fn stated_access_level_reads_other_var_stores() {
        let question = checkbox_on(1, 3, 1);
        let root = parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
            var_store_efi(3, "Other", NV_BS_RT, 1),
            form(
                1,
                &[
                    checkbox_on(2, 5, 2),
                    checkbox_on(3, 6, 3),
                    conditional(
                        GRAY_OUT_IF,
                        eq_id_val_of(3, 1),
                        std::slice::from_ref(&question),
                    ),
                ],
            ),
        ]);
        let question = find_op(&root, &question[2..]).expect("find question 1");
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Other", 1), &[0]);
        for level in [
            None,
            Some(AccessLevel::Administrator),
            Some(AccessLevel::User),
        ] {
            assert_eq!(
                question_state(
                    &question.borrow(),
                    &mut ExpressionInputs {
                        reader: &mut efivars.reader(),
                        values: &VarStoreValues::new(&root, level),
                    },
                ),
                StateEvaluation {
                    current: QuestionState::Selectable,
                    unknown: Vec::new(),
                    read_only: None,
                    from_snapshot: Vec::new(),
                },
                "{level:?}"
            );
        }
    }

    /// The value of a parsed question in `var_store`.
    fn value_in(
        op_code: u8,
        data: &[u8],
        VarStoreFixture { store, efivars }: VarStoreFixture,
    ) -> QuestionValue {
        let (_root, node) = parse_question(&[], op_code, data, &[]);
        let question = node.borrow();
        let value_question = value_question(&question).expect("a ONE_OF, NUMERIC or CHECKBOX");
        question_value(
            &node,
            value_question,
            &store,
            None,
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values: &MapValues(BTreeMap::new()),
            },
        )
    }

    #[test]
    fn question_value_reads_the_stored_value_at_its_width() {
        let uint16_one_of = [&question_header(1)[..], &[0x01], &[0x00; 6]].concat();
        let cases = [
            (
                "CHECKBOX byte as is",
                value_in(CHECKBOX, &checkbox(1, 0x00), var_store_of(&[0x00, 0x02])),
                QuestionValue::Boolean(2),
            ),
            (
                "UINT16 ONE_OF",
                value_in(
                    ONE_OF,
                    &uint16_one_of,
                    var_store_of(&[0x00, 0x34, 0x12, 0xFF]),
                ),
                QuestionValue::Uint(0x1234),
            ),
            (
                "UINT32 NUMERIC",
                value_in(
                    NUMERIC,
                    &uint32_range_question(1, 0x12),
                    var_store_of(&[0xFF, 0x01, 0x00, 0x00, 0x80, 0xFF]),
                ),
                QuestionValue::Uint(0x8000_0001),
            ),
            (
                "UINT16 ONE_OF past the VarStore",
                value_in(ONE_OF, &uint16_one_of, var_store_of(&[0x00, 0x34])),
                QuestionValue::Unreadable {
                    kind: ValueKind::Uint,
                    reason: "<ExtractEFIDataError: failed to fill whole buffer (offset: 1; \
                             buflen: 6)>"
                        .to_string(),
                },
            ),
            (
                "CHECKBOX without a VarStore",
                value_in(CHECKBOX, &checkbox(0, 0x00), unavailable()),
                QuestionValue::Unreadable {
                    kind: ValueKind::Boolean,
                    reason: UNAVAILABLE.to_string(),
                },
            ),
        ];
        for (name, got, want) in cases {
            assert_eq!(got, want, "{name}");
        }

        // only the bits of an EDKII bit varstore field
        let bit_field_cases = [
            (
                "bit-field CHECKBOX clear",
                CHECKBOX,
                checkbox(1, 0x00),
                0xFD,
                QuestionValue::Boolean(0),
            ),
            (
                "bit-field CHECKBOX set",
                CHECKBOX,
                checkbox(1, 0x00),
                0x02,
                QuestionValue::Boolean(1),
            ),
            (
                "3-bit NUMERIC at bit 2",
                NUMERIC,
                uint32_range_question(2, 0x43),
                0b1111_0111,
                QuestionValue::Uint(0b101),
            ),
        ];
        for (name, op_code, data, byte, want) in bit_field_cases {
            let (_root, node) = parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &[]);
            let bit_field = node.borrow();
            let value_question = value_question(&bit_field).expect("a ONE_OF, NUMERIC or CHECKBOX");
            let VarStoreFixture { store, efivars } = var_store_of(&[byte]);
            assert_eq!(
                question_value(
                    &node,
                    value_question,
                    &store,
                    None,
                    &mut ExpressionInputs {
                        reader: &mut efivars.reader(),
                        values: &MapValues(BTreeMap::new()),
                    },
                ),
                want,
                "{name}"
            );
        }
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod store_expression_tests {
    use std::collections::BTreeMap;

    use super::super::display_answer;
    use super::super::ifr_fixtures::*;
    use super::super::setup_password::PasswordQuestions;
    use super::super::MAX_SCOPE_NESTING;
    use super::*;

    const MAP: u8 = 0x22;
    const VAR_STORE_NAME_VALUE: u8 = 0x25;
    const GET: u8 = 0x2B;
    const SET: u8 = 0x2C;
    const AND: u8 = 0x15;
    const NOT_EQUAL: u8 = 0x30;
    const BITWISE_AND: u8 = 0x35;
    const SHIFT_RIGHT: u8 = 0x39;
    const ADD: u8 = 0x3A;
    const SUBTRACT: u8 = 0x3B;
    const UINT16: u8 = 0x43;
    const TO_UINT: u8 = 0x48;
    const CONDITIONAL: u8 = 0x50;
    const ZERO: u8 = 0x52;
    const ONE: u8 = 0x53;
    const UNDEFINED: u8 = 0x55;
    const VALUE: u8 = 0x5A;

    /// The VARSTORE_EFI of the tests, of 5 bytes.
    const STORE: u16 = 2;
    /// A VARSTORE_NAME_VALUE.
    const NAME_VALUE: u16 = 3;
    /// A VARSTORE, whose same-name EFI variable holds its values here.
    const BUFFER: u16 = 4;
    /// A VARSTORE_EFI of the form before UEFI 2.3.1.
    const SHORT_EFI: u16 = 5;

    fn op(op_code: u8) -> Vec<u8> {
        operation(op_code, false, &[])
    }

    fn uint16(value: u16) -> Vec<u8> {
        operation(UINT16, false, &value.to_le_bytes())
    }

    /// A GET or SET of the `value_type` value at VarOffset `offset` of VarStore `id`.
    fn store_op(op_code: u8, id: u16, offset: u16, value_type: u8) -> Vec<u8> {
        let data = [&id.to_le_bytes()[..], &offset.to_le_bytes(), &[value_type]].concat();
        operation(op_code, false, &data)
    }

    fn get(id: u16, offset: u16, value_type: u8) -> Vec<u8> {
        store_op(GET, id, offset, value_type)
    }

    fn set(id: u16, offset: u16, value_type: u8) -> Vec<u8> {
        store_op(SET, id, offset, value_type)
    }

    /// A MAP holding the (match, return) expressions of `pairs`.
    fn map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
        let pairs: Vec<Vec<u8>> = pairs
            .iter()
            .flat_map(|(matched, returned)| [matched.clone(), returned.clone()])
            .collect();
        [operation(MAP, true, &[]), pairs.concat(), END.to_vec()].concat()
    }

    /// The VarStores of the tests: STORE, NAME_VALUE and BUFFER.
    fn declarations() -> Vec<Vec<u8>> {
        vec![
            var_store_efi(STORE, "Store", NV_BS_RT, 5),
            operation(
                VAR_STORE_NAME_VALUE,
                false,
                &[&NAME_VALUE.to_le_bytes()[..], &[0x44; 16]].concat(),
            ),
            var_store(BUFFER, [0; 16], "Buffer", 2),
        ]
    }

    /// Efivars whose variable of STORE holds `payload`.
    fn store_holding(payload: &[u8]) -> Efivars {
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Store", 5), payload);
        efivars
    }

    /// No question has a value.
    fn no_values() -> MapValues {
        MapValues(BTreeMap::new())
    }

    /// The truth of `condition` in a SUPPRESS_IF of a FormSet with declarations(), reading
    /// `efivars`.
    fn truth_in(condition: Vec<u8>, efivars: &Efivars, values: &impl QuestionValues) -> Truth {
        let body = operation(CHECKBOX, false, &checkbox(0, 0x00));
        let declarations = declarations();
        let root = parse_form_set(&[
            declarations.concat(),
            conditional(SUPPRESS_IF, condition, &[body]),
        ]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let scope = Rc::clone(&form_set.borrow().children[declarations.len()]);
        let scope = scope.borrow();
        evaluate_condition(
            &scope,
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values,
            },
        )
    }

    /// The value of `expression` in an EFI_IFR_VALUE of a FormSet with declarations(), reading
    /// `efivars`.
    fn value_in(expression: Vec<u8>, efivars: &Efivars) -> std::result::Result<u64, String> {
        let declarations = declarations();
        let root = parse_form_set(&[
            declarations.concat(),
            operation(VALUE, true, &[]),
            expression,
            END.to_vec(),
        ]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let scope = Rc::clone(&form_set.borrow().children[declarations.len()]);
        let scope = scope.borrow();
        evaluate_value(
            &scope,
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values: &no_values(),
            },
        )
    }

    /// A UINT8 ONE_OF of QuestionId 1 from 0 to 4 without a VarStore.
    fn storage_less_one_of() -> Vec<u8> {
        [question_header_on(1, 3, 0, 0), vec![0x00, 0, 4, 1]].concat()
    }

    /// The ONE_OF storage_less_one_of(), holding `children`, in `form` of a FormSet with
    /// declarations(): `form` wraps its ops in a FORM or FORM_MAP.
    fn question_in(form: impl Fn(&[Vec<u8>]) -> Vec<u8>, children: &[Vec<u8>]) -> RootAndQuestion {
        let question = [
            operation(ONE_OF, true, &storage_less_one_of()),
            children.concat(),
            END.to_vec(),
        ]
        .concat();
        let declarations = declarations();
        let root = parse_form_set(&[declarations.concat(), form(&[question])]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let form = Rc::clone(&form_set.borrow().children[declarations.len()]);
        let question = Rc::clone(&form.borrow().children[0]);
        (root, question)
    }

    /// The ONE_OF storage_less_one_of() in FORM 1, holding `children`.
    fn question_holding(children: &[Vec<u8>]) -> RootAndQuestion {
        question_in(|body| form(1, body), children)
    }

    /// The ONE_OF storage_less_one_of(), holding `children`, outside forms, in a FormSet with
    /// declarations().
    fn question_outside_forms(children: &[Vec<u8>]) -> RootAndQuestion {
        let declarations = declarations();
        let root = parse_form_set(&[
            declarations.concat(),
            operation(ONE_OF, true, &storage_less_one_of()),
            children.concat(),
            END.to_vec(),
        ]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let question = Rc::clone(&form_set.borrow().children[declarations.len()]);
        (root, question)
    }

    /// What the READ of a question holding `children` gives with THIS `this`, reading `efivars`.
    fn read_of(children: &[Vec<u8>], this: QuestionValue, efivars: &Efivars) -> ReadOutcome {
        let (_root, question) = question_holding(children);
        evaluate_read(
            &question,
            this,
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values: &no_values(),
            },
        )
    }

    /// A PlannedSet as the tests compare it: its VarStoreId, VarStore name, VarOffset and bytes.
    type ComparedSet = (u16, String, u16, Vec<u8>);

    /// The SETs of the WRITE of a question holding `children`, with THIS `this`, reading
    /// `efivars`.
    fn writes_of(
        children: &[Vec<u8>],
        this: QuestionValue,
        efivars: &Efivars,
    ) -> std::result::Result<Option<Vec<ComparedSet>>, ExpressionRefusal> {
        let (_root, question) = question_holding(children);
        let sets = evaluate_write(
            &question,
            this,
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values: &no_values(),
            },
        )?;
        Ok(sets.map(|sets| {
            sets.into_iter()
                .map(|set| (set.var_store_id, set.store.name(), set.offset, set.bytes))
                .collect()
        }))
    }

    /// THIS in a condition of a question pushes the value of that question, which
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes reads as a QUESTION_REF1 of it.
    #[test]
    fn this_in_a_condition_is_the_value_of_its_question() {
        let condition = scoped_expression(&[op(THIS), uint8(3), op(EQUAL)], 0);
        let truth = |value: QuestionValue| {
            let (_root, question) = question_holding(&[conditional(
                SUPPRESS_IF,
                condition.clone(),
                &[one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_8, &[0])],
            )]);
            let scope = Rc::clone(&question.borrow().children[0]);
            let scope = scope.borrow();
            evaluate_condition(
                &scope,
                &mut ExpressionInputs {
                    reader: &mut Efivars::new().reader(),
                    values: &MapValues(BTreeMap::from([(1, value)])),
                },
            )
        };

        assert_eq!(truth(QuestionValue::Uint(3)), Truth::Known(true), "3");
        assert_eq!(truth(QuestionValue::Uint(2)), Truth::Known(false), "2");
        assert_eq!(
            truth(QuestionValue::Unreadable {
                kind: ValueKind::Uint,
                reason: "<ValueUnavailable: test>".to_string(),
            }),
            Truth::Unknown("EFI_IFR_THIS of question 0x0001: <ValueUnavailable: test>".to_string()),
            "unreadable"
        );
    }

    /// THIS outside a question has no question to push, which edk2 fails on.
    #[test]
    fn this_outside_a_question_is_malformed() {
        assert_eq!(
            truth_in(
                scoped_expression(&[op(THIS), uint8(3), op(EQUAL)], 0),
                &Efivars::new(),
                &no_values()
            ),
            Truth::Unknown("malformed condition: EFI_IFR_THIS outside a question".to_string())
        );
    }

    /// GET reads the value of its VarStoreType at its VarOffset of the VarStore's variable: an
    /// integer of its width, little-endian, or a BOOLEAN byte.
    #[test]
    fn get_reads_its_var_store_at_its_var_offset() {
        let efivars = store_holding(&[0x11, 0x02, 0x03, 0x01, 0x00]);
        let cases = [
            ("UINT8 at 0", get(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8), 0x11),
            (
                "UINT16 at 1",
                get(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_16),
                0x0302,
            ),
            (
                "UINT32 at 1",
                get(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_32),
                0x0001_0302,
            ),
            ("BOOLEAN at 3", get(STORE, 3, EFI_IFR_TYPE_BOOLEAN), 1),
        ];
        for (name, get, want) in cases {
            assert_eq!(value_in(get, &efivars), Ok(want), "{name}");
        }

        let not_false = scoped_expression(&[get(STORE, 4, EFI_IFR_TYPE_BOOLEAN), op(NOT)], 0);
        assert_eq!(
            truth_in(not_false, &efivars, &no_values()),
            Truth::Known(true),
            "NOT of the BOOLEAN 0"
        );
        let buffer = Efivars::new();
        buffer.write(&buffer_store("Buffer", 2), &[0x34, 0x12]);
        assert_eq!(
            value_in(get(BUFFER, 0, EFI_IFR_TYPE_NUM_SIZE_16), &buffer),
            Ok(0x1234),
            "a VARSTORE's same-name variable"
        );
    }

    /// buffer() of ifr_fixtures, for a VARSTORE.
    fn buffer_store(name: &'static str, size: usize) -> DeclaredVarStore {
        buffer(name, size)
    }

    /// A GET of a VarStore that this backend cannot read pushes a value that cannot be read,
    /// which a condition may not need.
    #[test]
    fn get_of_a_var_store_that_cannot_be_read_is_unknown() {
        let missing = Efivars::new();
        let condition = scoped_expression(
            &[get(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8), uint8(1), op(EQUAL)],
            0,
        );
        let Truth::Unknown(reason) = truth_in(condition.clone(), &missing, &no_values()) else {
            panic!("a missing variable gave a value");
        };
        assert!(
            reason.starts_with(
                "EFI_IFR_GET of VarStore 0x0002 (EFI_IFR_VARSTORE_EFI \"Store\"), which cannot be \
                 read: "
            ),
            "{reason}"
        );

        let name_value = scoped_expression(
            &[
                get(NAME_VALUE, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                uint8(1),
                op(EQUAL),
            ],
            0,
        );
        assert_eq!(
            truth_in(name_value, &missing, &no_values()),
            Truth::Unknown(
                "EFI_IFR_GET of VarStore 0x0003 (EFI_IFR_VARSTORE_NAME_VALUE), which only the \
                 driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches"
                    .to_string()
            ),
            "Name/Value"
        );

        let decided = scoped_expression(&[condition, ifr_false(), op(AND)], 0);
        assert_eq!(
            truth_in(decided, &missing, &no_values()),
            Truth::Known(false),
            "AND FALSE"
        );
    }

    /// A GET reads no byte of the password of a PASSWORD question, through variables of either
    /// reach; a GET of the other bytes of its VarStore, or of another VarStore, reads them.
    #[test]
    fn get_reads_no_byte_of_a_password() {
        let value_through = |expression: Vec<u8>, (reach, interface)| {
            let declarations = declarations();
            let root = parse_form_set(&[
                declarations.concat(),
                password_on(9, 3, STORE, 1),
                operation(VALUE, true, &[]),
                expression,
                END.to_vec(),
            ]);
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(variable_key("Store"), NV_BS_RT, &[7, 0, 0, 0, 0]);
            variables.insert(variable_key("Buffer"), NV_BS_RT, &[5, 0]);
            let mut reader = PasswordQuestions::of([&root])
                .reader(Box::new(variables))
                .expect("resolve the VarStore of the PASSWORD question");
            let form_set = Rc::clone(&root.borrow().children[0]);
            let scope = Rc::clone(&form_set.borrow().children[declarations.len() + 1]);
            let scope = scope.borrow();
            evaluate_value(
                &scope,
                &mut ExpressionInputs {
                    reader: &mut reader,
                    values: &no_values(),
                },
            )
        };
        let shell = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let linux = (VariableReach::Runtime, VariableInterface::Efivarfs);
        let of_store =
            |offset| scoped_expression(&[get(STORE, offset, EFI_IFR_TYPE_NUM_SIZE_8)], 0);
        for (name, through) in [("Runtime", linux), ("BootServices", shell)] {
            assert_eq!(
                value_through(of_store(1), through),
                Err(
                    "EFI_IFR_GET of VarStore 0x0002 (EFI_IFR_VARSTORE_EFI \"Store\"), which cannot \
                     be read: its bytes hold a password"
                        .to_string()
                ),
                "{name}: a byte of the password"
            );
            assert_eq!(
                value_through(of_store(0), through),
                Ok(7),
                "{name}: a byte before the password"
            );
            assert_eq!(
                value_through(
                    scoped_expression(&[get(BUFFER, 0, EFI_IFR_TYPE_NUM_SIZE_8)], 0),
                    through
                ),
                Ok(5),
                "{name}: another VarStore"
            );
        }
    }

    /// edk2 fails the FormSet of a GET of an undeclared VarStore or of a type that names no
    /// stored value, and the expression of an integer GET without a VarStore; a GET past the
    /// Size of its VarStore, or too short for its operand, is malformed here too.
    #[test]
    fn malformed_gets_are_refused() {
        let cases = [
            (
                "undeclared",
                get(9, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                "EFI_IFR_GET of undeclared VarStore 0x0009",
            ),
            (
                "past the Size",
                get(STORE, 4, EFI_IFR_TYPE_NUM_SIZE_16),
                "EFI_IFR_GET of 2 bytes at VarOffset 0x0004 of a VarStore of 5 bytes",
            ),
            (
                "no VarStore",
                get(0, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                "EFI_IFR_GET of an integer without a VarStore",
            ),
            (
                "OTHER",
                get(STORE, 0, 0x08),
                "EFI_IFR_GET of value type 0x08",
            ),
            (
                "short",
                operation(GET, false, &[0x02, 0x00, 0x00, 0x00]),
                "EFI_IFR_GET not decoded",
            ),
        ];
        let efivars = store_holding(&[0; 5]);
        for (name, get, reason) in cases {
            assert_eq!(
                value_in(get, &efivars),
                Err(format!("malformed expression: {reason}")),
                "{name}"
            );
        }
    }

    /// GET of a TIME, DATE, STRING or REF value, which nothing here decodes, is not evaluated.
    #[test]
    fn get_of_a_value_that_is_not_an_integer_is_not_evaluated() {
        let efivars = store_holding(&[0; 5]);
        for (value_type, name) in [
            (0x05, "TIME"),
            (0x06, "DATE"),
            (0x07, "STRING"),
            (0x0C, "REF"),
        ] {
            assert_eq!(
                value_in(get(STORE, 0, value_type), &efivars),
                Err(format!("EFI_IFR_GET of a {name} value not evaluated")),
                "{name}"
            );
        }
    }

    /// MAP pushes the return expression of the first pair whose match expression equals the value
    /// it pops; each expression is an op of its scope with the ops in that op's scope, which the
    /// walk of its expression does not evaluate.
    #[test]
    fn map_pushes_the_return_value_of_the_first_matching_pair() {
        let pairs = [
            (uint8(1), uint8(10)),
            (
                scoped_expression(&[uint8(1), op(ONE), op(ADD)], 0),
                uint8(20),
            ),
            (uint8(2), uint8(30)),
            (
                uint8(3),
                scoped_expression(&[uint8(40), op(ONE), op(ADD)], 0),
            ),
        ];
        let efivars = Efivars::new();
        let cases = [
            (1, Ok(10)),
            (2, Ok(20)),
            (3, Ok(41)),
            (4, Err("UNDEFINED result".to_string())),
        ];
        for (checked, want) in cases {
            let expression = [uint8(checked), map(&pairs)].concat();
            assert_eq!(value_in(expression, &efivars), want, "MAP of {checked}");
        }

        let then_add = scoped_expression(&[uint8(2), map(&pairs), uint8(5), op(ADD)], 0);
        assert_eq!(value_in(then_add, &efivars), Ok(25), "MAP then ADD");
    }

    /// A match expression that gives UNDEFINED matches nothing, as edk2-stable202608
    /// SetupBrowserDxe/Expression.c CompareHiiValue compares no UNDEFINED; a MAP of a value that
    /// cannot be read is not evaluated; a pair without its return expression is malformed once
    /// reached.
    #[test]
    fn map_skips_undefined_matches_and_refuses_what_it_cannot_decide() {
        let efivars = Efivars::new();
        let undefined_first = [
            uint8(1),
            map(&[(op(UNDEFINED), uint8(10)), (uint8(1), uint8(20))]),
        ]
        .concat();
        assert_eq!(
            value_in(undefined_first, &efivars),
            Ok(20),
            "UNDEFINED match"
        );

        let unknown = [
            get(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8),
            map(&[(uint8(1), uint8(10))]),
        ]
        .concat();
        assert_eq!(
            value_in(unknown, &efivars),
            Err("EFI_IFR_MAP on a value that cannot be read".to_string()),
            "a value that cannot be read"
        );

        let odd = [
            operation(MAP, true, &[]),
            uint8(1),
            uint8(10),
            uint8(2),
            END.to_vec(),
        ]
        .concat();
        assert_eq!(
            value_in([uint8(1), odd.clone()].concat(), &efivars),
            Ok(10),
            "matched first"
        );
        assert_eq!(
            value_in([uint8(2), odd].concat(), &efivars),
            Err(
                "malformed expression: EFI_IFR_MAP without the return expression of a pair"
                    .to_string()
            ),
            "reached"
        );
    }

    /// A SET outside a WRITE expression would change a stored value: it is not evaluated.
    #[test]
    fn set_outside_a_write_expression_is_not_evaluated() {
        let condition = scoped_expression(&[uint8(1), set(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8)], 0);
        assert_eq!(
            truth_in(condition, &store_holding(&[0; 5]), &no_values()),
            Truth::Unknown("EFI_IFR_SET outside a WRITE expression not evaluated".to_string())
        );
    }

    /// READ gives the question's value, with THIS its stored value; the expression is the op after
    /// READ, or what READ holds in its scope, and the last READ counts.
    #[test]
    fn read_gives_the_value_of_its_expression() {
        let efivars = store_holding(&[0x11, 0, 0, 0, 0]);
        let stored = QuestionValue::Uint(4);
        let cases = [
            (
                "GET",
                vec![op(READ), get(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8)],
                0x11,
            ),
            (
                "THIS + 1",
                vec![
                    op(READ),
                    scoped_expression(&[op(THIS), op(ONE), op(ADD)], 0),
                ],
                5,
            ),
            (
                "in READ's scope",
                vec![operation(READ, true, &[]), uint8(7), END.to_vec()],
                7,
            ),
            (
                "the last READ",
                vec![op(READ), uint8(1), op(READ), uint8(2)],
                2,
            ),
        ];
        for (name, children, want) in cases {
            assert_eq!(
                read_of(&children, stored.clone(), &efivars),
                ReadOutcome::Value(ExpressionValue::Uint(want)),
                "{name}"
            );
        }
        assert_eq!(
            read_of(&[op(READ), ifr_true()], stored.clone(), &efivars),
            ReadOutcome::Value(ExpressionValue::Boolean(1)),
            "TRUE"
        );
        assert_eq!(
            read_of(
                &[one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_8, &[0])],
                stored,
                &efivars
            ),
            ReadOutcome::NoRead,
            "no READ"
        );
    }

    /// A READ that gives UNDEFINED or fails leaves the stored value, as edk2-stable202608
    /// SetupBrowserDxe/Setup.c GetQuestionValue reads storage then.
    #[test]
    fn undefined_or_failing_read_keeps_the_stored_value() {
        let efivars = Efivars::new();
        let cases = [
            ("UNDEFINED", vec![op(READ), op(UNDEFINED)]),
            (
                "two values",
                vec![op(READ), scoped_expression(&[uint8(1), uint8(2)], 0)],
            ),
            ("no expression", vec![op(READ)]),
        ];
        for (name, children) in cases {
            assert_eq!(
                read_of(&children, QuestionValue::Uint(4), &efivars),
                ReadOutcome::Stored,
                "{name}"
            );
        }
    }

    /// edk2 evaluates READ on a FORM and on a FORM_MAP with the standard method only;
    /// uefisettings outside forms too, as on a FORM.
    #[test]
    fn read_counts_except_on_map_forms_without_the_standard_method() {
        let children = [op(READ), uint8(7)];
        let cases = [
            (
                "standard",
                vec![(5, OTHER_GUID), (6, STANDARD_FORM_GUID)],
                true,
            ),
            ("not standard", vec![(5, OTHER_GUID)], false),
        ];
        for (name, methods, evaluated) in cases {
            let (_root, question) = question_in(|body| form_map(&methods, body), &children);
            let read = evaluate_read(
                &question,
                QuestionValue::Uint(4),
                &mut ExpressionInputs {
                    reader: &mut Efivars::new().reader(),
                    values: &no_values(),
                },
            );
            let want = match evaluated {
                true => ReadOutcome::Value(ExpressionValue::Uint(7)),
                false => ReadOutcome::NoRead,
            };
            assert_eq!(read, want, "{name}");
        }
        let (_root, question) = question_outside_forms(&children);
        let read = evaluate_read(
            &question,
            QuestionValue::Uint(4),
            &mut ExpressionInputs {
                reader: &mut Efivars::new().reader(),
                values: &no_values(),
            },
        );
        assert_eq!(
            read,
            ReadOutcome::Value(ExpressionValue::Uint(7)),
            "outside forms"
        );
    }

    /// A READ that this backend cannot evaluate is refused with why: the VarStore that it
    /// cannot read, the op that is not evaluated, or the value that cannot be read.
    #[test]
    fn read_that_cannot_be_evaluated_is_refused() {
        let missing = Efivars::new();
        let ReadOutcome::Refused(refusal) = read_of(
            &[op(READ), get(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8)],
            QuestionValue::Uint(4),
            &missing,
        ) else {
            panic!("a READ of a missing variable gave a value");
        };
        assert!(
            refusal.to_string().starts_with(
                "its READ expression reads VarStore 0x0002 (EFI_IFR_VARSTORE_EFI \"Store\"), \
                 which cannot be read: "
            ),
            "{refusal}"
        );

        let cases = [
            (
                "ToUint",
                vec![op(READ), scoped_expression(&[uint8(1), op(TO_UINT)], 0)],
                QuestionValue::Uint(4),
                "its READ expression uses EFI_IFR_TO_UINT, which uefisettings does not evaluate",
            ),
            (
                "THIS that cannot be read",
                vec![
                    op(READ),
                    scoped_expression(&[op(THIS), op(ONE), op(ADD)], 0),
                ],
                QuestionValue::Unreadable {
                    kind: ValueKind::Uint,
                    reason: "<ValueUnavailable: test>".to_string(),
                },
                "its READ expression takes a value that cannot be read: EFI_IFR_THIS: \
                 <ValueUnavailable: test>",
            ),
            (
                "Name/Value",
                vec![op(READ), get(NAME_VALUE, 0, EFI_IFR_TYPE_NUM_SIZE_8)],
                QuestionValue::Uint(4),
                "its READ expression reads VarStore 0x0003 (EFI_IFR_VARSTORE_NAME_VALUE), which \
                 only the driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches",
            ),
        ];
        for (name, children, this, want) in cases {
            let ReadOutcome::Refused(refusal) = read_of(&children, this, &missing) else {
                panic!("{name}: not refused");
            };
            assert_eq!(refusal.to_string(), want, "{name}");
        }
    }

    /// WRITE gives the SETs of its expression, with THIS the new value, in order: each the bytes
    /// of its VarStoreType's width, little-endian, at its VarOffset.
    #[test]
    fn write_gives_its_sets_in_order() {
        let efivars = store_holding(&[0; 5]);
        let write = scoped_expression(
            &[
                op(THIS),
                op(ZERO),
                op(NOT_EQUAL),
                set(STORE, 1, EFI_IFR_TYPE_BOOLEAN),
                op(THIS),
                map(&[(uint8(1), uint16(0x3F8)), (uint8(3), uint16(0x3E8))]),
                set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_16),
                op(AND),
            ],
            0,
        );
        assert_eq!(
            writes_of(&[op(WRITE), write], QuestionValue::Uint(3), &efivars),
            Ok(Some(vec![
                (STORE, "Store".to_string(), 1, vec![0x01]),
                (STORE, "Store".to_string(), 2, vec![0xE8, 0x03]),
            ]))
        );
        assert_eq!(
            writes_of(&[op(READ), uint8(1)], QuestionValue::Uint(3), &efivars),
            Ok(None),
            "no WRITE"
        );
    }

    /// An UNDEFINED ends a WRITE after the SETs before it, as edk2-stable202608
    /// SetupBrowserDxe/Setup.c SetQuestionValue writes the question then.
    #[test]
    fn undefined_ends_a_write_after_its_earlier_sets() {
        let write = scoped_expression(
            &[
                op(THIS),
                set(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                op(UNDEFINED),
                set(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_8),
                op(AND),
            ],
            0,
        );
        assert_eq!(
            writes_of(
                &[op(WRITE), write],
                QuestionValue::Uint(3),
                &store_holding(&[0; 5])
            ),
            Ok(Some(vec![(STORE, "Store".to_string(), 0, vec![0x03])]))
        );
    }

    /// A WRITE that cannot be evaluated is refused with why, and plans no SET.
    #[test]
    fn write_that_cannot_be_evaluated_is_refused() {
        let missing = Efivars::new();
        let cases = [
            (
                "Name/Value",
                scoped_expression(&[op(THIS), set(NAME_VALUE, 0, EFI_IFR_TYPE_NUM_SIZE_8)], 0),
                "its WRITE expression sets VarStore 0x0003 (EFI_IFR_VARSTORE_NAME_VALUE), which \
                 only the driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches",
            ),
            (
                "past the Size",
                scoped_expression(&[op(THIS), set(STORE, 4, EFI_IFR_TYPE_NUM_SIZE_16)], 0),
                "its WRITE expression is malformed: EFI_IFR_SET of 2 bytes at VarOffset 0x0004 of \
                 a VarStore of 5 bytes",
            ),
            (
                "two values left",
                scoped_expression(&[op(THIS), op(THIS)], 0),
                "its WRITE expression is malformed: 2 values left",
            ),
        ];
        for (name, write, want) in cases {
            let Err(refusal) = writes_of(&[op(WRITE), write], QuestionValue::Uint(3), &missing)
            else {
                panic!("{name}: not refused");
            };
            assert_eq!(refusal.to_string(), want, "{name}");
        }

        let from_missing = scoped_expression(
            &[
                get(STORE, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                set(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_8),
            ],
            0,
        );
        let Err(refusal) = writes_of(&[op(WRITE), from_missing], QuestionValue::Uint(3), &missing)
        else {
            panic!("a SET of a value that cannot be read was planned");
        };
        assert!(
            refusal.to_string().starts_with(
                "its WRITE expression reads VarStore 0x0002 (EFI_IFR_VARSTORE_EFI \"Store\"), \
                 which cannot be read: "
            ),
            "{refusal}"
        );
    }

    /// A GET or SET of a VARSTORE_EFI of the form before UEFI 2.3.1, whose EFI variable its
    /// VarName names (UEFI 2.11 §33.3.8.3.27 and §33.3.8.3.66 VarStoreInfo), is not evaluated: a
    /// GET pushes a value that cannot be read, and a WRITE that holds a SET is refused.
    #[test]
    fn get_and_set_of_a_var_store_efi_before_uefi_2_3_1_are_not_evaluated() {
        let get_short = scoped_expression(
            &[
                get(SHORT_EFI, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                uint8(1),
                op(EQUAL),
            ],
            0,
        );
        let set_short =
            scoped_expression(&[op(THIS), set(SHORT_EFI, 0, EFI_IFR_TYPE_NUM_SIZE_8)], 0);
        let question = [
            operation(ONE_OF, true, &storage_less_one_of()),
            conditional(
                SUPPRESS_IF,
                get_short,
                &[one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_8, &[0])],
            ),
            op(WRITE),
            set_short,
            END.to_vec(),
        ]
        .concat();
        let root = parse_form_set(&[short_var_store_efi(SHORT_EFI), form(1, &[question])]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let form = Rc::clone(&form_set.borrow().children[1]);
        let question = Rc::clone(&form.borrow().children[0]);
        let missing = Efivars::new();
        let short = "VarStore 0x0005 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1), whose EFI \
                     variables are named by VarNames, which uefisettings does not resolve";

        let scope = Rc::clone(&question.borrow().children[0]);
        let truth = evaluate_condition(
            &scope.borrow(),
            &mut ExpressionInputs {
                reader: &mut missing.reader(),
                values: &no_values(),
            },
        );
        assert_eq!(
            truth,
            Truth::Unknown(format!("EFI_IFR_GET of {short}")),
            "GET"
        );

        let Err(refusal) = evaluate_write(
            &question,
            QuestionValue::Uint(3),
            &mut ExpressionInputs {
                reader: &mut missing.reader(),
                values: &no_values(),
            },
        ) else {
            panic!("a SET of a VARSTORE_EFI before UEFI 2.3.1 was planned");
        };
        assert_eq!(
            refusal.to_string(),
            format!("its WRITE expression sets {short}"),
            "SET"
        );
    }

    /// A READ as edk2-stable202608 VfrCompile builds one of the form cond(get(status) != 0 ?
    /// 0 : cond(((get(port) & 0xF00) >> 8) == get(line) - 1 ? UNDEFINED : map(get(port) : ...))):
    /// the walk reaches its UNDEFINED, which ends the evaluation, as edk2 ends it, whatever the
    /// CONDITIONAL would pick, so the stored value stays; without the UNDEFINED, its MAP gives the
    /// value.
    #[test]
    fn read_of_stored_fields_through_conditionals_and_map() {
        let port_map = map(&[
            (uint16(0x3F8), op(ONE)),
            (uint16(0x2F8), uint8(2)),
            (uint16(0x3E8), uint8(3)),
            (uint16(0x2E8), uint8(4)),
        ]);
        let with_undefined = scoped_expression(
            &[
                get(STORE, 1, EFI_IFR_TYPE_BOOLEAN),
                op(ZERO),
                op(NOT_EQUAL),
                op(ZERO),
                get(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_16),
                uint16(0xF00),
                op(BITWISE_AND),
                uint8(8),
                op(SHIFT_RIGHT),
                get(STORE, 4, EFI_IFR_TYPE_NUM_SIZE_8),
                op(ONE),
                op(SUBTRACT),
                op(EQUAL),
                op(UNDEFINED),
                get(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_16),
                port_map.clone(),
                op(CONDITIONAL),
                op(CONDITIONAL),
            ],
            0,
        );
        let enabled = store_holding(&[0x03, 0x01, 0xE8, 0x03, 0x04]);
        assert_eq!(
            read_of(
                &[op(READ), with_undefined],
                QuestionValue::Uint(3),
                &enabled
            ),
            ReadOutcome::Stored,
            "with UNDEFINED"
        );

        let without_undefined = scoped_expression(
            &[
                get(STORE, 1, EFI_IFR_TYPE_BOOLEAN),
                op(ZERO),
                op(NOT_EQUAL),
                op(ZERO),
                get(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_16),
                port_map,
                op(CONDITIONAL),
            ],
            0,
        );
        let disabled = store_holding(&[0x03, 0x00, 0xF8, 0x02, 0x03]);
        let cases = [("enabled", &enabled, 3), ("disabled", &disabled, 0)];
        for (name, efivars, want) in cases {
            assert_eq!(
                read_of(
                    &[op(READ), without_undefined.clone()],
                    QuestionValue::Uint(3),
                    efivars
                ),
                ReadOutcome::Value(ExpressionValue::Uint(want)),
                "{name}"
            );
        }
    }

    /// Each MAP evaluates its expressions with a call of its own: nested as deep as a FormSet's
    /// scopes nest, they fit in the 128 KiB stack of UEFI DXE (edk2-stable202608
    /// MdeModulePkg/Core/DxeIplPeim/DxeIpl.h STACK_SIZE).
    #[test]
    fn maps_nested_as_deep_as_scopes_fit_a_small_stack() {
        // each level opens the scopes of a return expression and of its MAP; FORM_SET and
        // EFI_IFR_VALUE take 2 more
        let levels = (MAX_SCOPE_NESTING - 2) / 2;
        let expression = (0..levels).fold(uint8(7), |inner, _| {
            let mut first = uint8(1);
            first[1] |= 0x80;
            [
                first,
                operation(MAP, true, &[]),
                uint8(1),
                inner,
                END.to_vec(),
                END.to_vec(),
            ]
            .concat()
        });
        let value = std::thread::Builder::new()
            .stack_size(128 << 10)
            .spawn(move || value_in(expression, &Efivars::new()))
            .expect("spawn a thread with a small stack")
            .join()
            .expect("evaluate the nested MAPs");
        assert_eq!(value, Ok(7));
    }

    /// A UINT8 ONE_OF of QuestionId `id` at VarOffset 0 of VarStore `var_store_id`, with the
    /// options Disabled (1) and Enabled (3), then `children`.
    fn one_of_with(id: u16, var_store_id: u16, children: &[Vec<u8>]) -> Vec<u8> {
        let data = [
            question_header_on(id, 3, var_store_id, 0),
            vec![0x00, 0, 4, 1],
        ]
        .concat();
        [
            operation(ONE_OF, true, &data),
            one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_8, &[1]),
            one_of_option(6, EFI_IFR_TYPE_NUM_SIZE_8, &[3]),
            children.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// A FormSet with declarations() and FORM 1 holding `questions`; the root and the questions.
    fn form_set_of(
        questions: &[Vec<u8>],
    ) -> (Rc<RefCell<IFROperation>>, Vec<Rc<RefCell<IFROperation>>>) {
        let declarations = declarations();
        let root = parse_form_set(&[declarations.concat(), form(1, questions)]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let form = Rc::clone(&form_set.borrow().children[declarations.len()]);
        let questions = form.borrow().children.clone();
        (root, questions)
    }

    /// The answer that get, list-questions and show-ifr give for the first question of
    /// form_set_of(`questions`), reading `efivars`.
    fn answers_of(questions: &[Vec<u8>], efivars: Efivars) -> (String, String) {
        let (root, questions) = form_set_of(questions);
        let question = &questions[0];
        let id = value_question(&question.borrow()).map(|question| question.header().var_store_id);
        let store = || find_corresponding_varstore(Rc::clone(question), id.unwrap_or_default());
        let values = VarStoreValues::new(&root, None);
        let shown = display_answer(
            question,
            &store(),
            &mut ExpressionInputs {
                reader: &mut efivars.reader(),
                values: &values,
            },
        );
        let listed = question_descriptor_with(
            question,
            VarStoreFixture {
                store: store(),
                efivars,
            },
            &values,
        )
        .value;
        (listed, shown)
    }

    /// get, list-questions and show-ifr take a question's value from its READ expression, with
    /// THIS its stored value, and the stored value when READ gives UNDEFINED, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue does.
    #[test]
    fn get_takes_the_value_of_the_read_expression() {
        // the ONE_OF holds 1 (Disabled); byte 1 holds 8
        let stored = || store_holding(&[1, 8, 0, 0, 0]);
        let mapped = map(&[(uint8(7), uint8(1)), (uint8(8), uint8(3))]);
        let cases = [
            ("no READ", vec![], ("Disabled", "1")),
            (
                "MAP of a GET",
                vec![
                    op(READ),
                    scoped_expression(&[get(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_8), mapped], 0),
                ],
                ("Enabled", "3"),
            ),
            (
                "THIS + 2",
                vec![
                    op(READ),
                    scoped_expression(&[op(THIS), uint8(2), op(ADD)], 0),
                ],
                ("Enabled", "3"),
            ),
            (
                "UNDEFINED",
                vec![op(READ), op(UNDEFINED)],
                ("Disabled", "1"),
            ),
        ];
        for (name, children, (listed, shown)) in cases {
            assert_eq!(
                answers_of(&[one_of_with(1, STORE, &children)], stored()),
                (listed.to_string(), shown.to_string()),
                "{name}"
            );
        }
    }

    /// A READ that cannot be evaluated here makes the value unavailable, though the stored one
    /// can be read: edk2 would show what READ gives.
    #[test]
    fn get_of_a_read_that_cannot_be_evaluated_says_why() {
        let reason = "<ValueUnavailable: its READ expression uses EFI_IFR_TO_UINT, which \
                      uefisettings does not evaluate>";
        assert_eq!(
            answers_of(
                &[one_of_with(
                    1,
                    STORE,
                    &[op(READ), scoped_expression(&[uint8(3), op(TO_UINT)], 0)]
                )],
                store_holding(&[1, 0, 0, 0, 0])
            ),
            (reason.to_string(), reason.to_string())
        );
    }

    /// A question without a VarStore takes its value from READ alone: a READ that gives
    /// UNDEFINED leaves it none, and one that needs THIS, which no storage holds, says so.
    #[test]
    fn get_of_a_storageless_question_takes_only_read() {
        let cases = [
            (
                "GET",
                vec![op(READ), get(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_8)],
                "Enabled".to_string(),
                "3".to_string(),
            ),
            (
                "UNDEFINED",
                vec![op(READ), op(UNDEFINED)],
                format!("<ValueUnavailable: {}>", StoragelessRefusal::ReadUndefined),
                format!("<ValueUnavailable: {}>", StoragelessRefusal::ReadUndefined),
            ),
            (
                "THIS",
                vec![op(READ), op(THIS)],
                "<ValueUnavailable: its READ expression takes a value that cannot be read: \
                 EFI_IFR_THIS: <ValueUnavailable: question has no VarStore>>"
                    .to_string(),
                "<ValueUnavailable: its READ expression takes a value that cannot be read: \
                 EFI_IFR_THIS: <ValueUnavailable: question has no VarStore>>"
                    .to_string(),
            ),
        ];
        for (name, children, listed, shown) in cases {
            assert_eq!(
                answers_of(
                    &[one_of_with(1, 0, &children)],
                    store_holding(&[1, 3, 0, 0, 0])
                ),
                (listed, shown),
                "{name}"
            );
        }
    }

    /// get, list-questions and show-ifr take the value of a question with an EFI_IFR_VALUE from
    /// that expression, before any READ and storage, also without a VarStore, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue does (UEFI 2.11 §33.3.8.3.88).
    #[test]
    fn get_takes_the_value_of_an_efi_ifr_value_before_read() {
        let value = |expression: Vec<u8>| [operation(VALUE, true, &[]), expression, END.to_vec()];
        let undefined = "<ValueUnavailable: its EFI_IFR_VALUE expression gives no value: \
                         UNDEFINED result>";
        let cases = [
            (
                "VALUE and READ",
                one_of_with(1, STORE, &[value(uint8(3)).concat(), op(READ), uint8(1)]),
                ("Enabled", "3"),
            ),
            (
                "VALUE and READ without a VarStore",
                one_of_with(1, 0, &[value(uint8(3)).concat(), op(READ), uint8(1)]),
                ("Enabled", "3"),
            ),
            (
                "VALUE without a VarStore",
                one_of_with(1, 0, &[value(uint8(3)).concat()]),
                ("Enabled", "3"),
            ),
            (
                "VALUE of UNDEFINED",
                one_of_with(1, STORE, &[value(op(UNDEFINED)).concat()]),
                (undefined, undefined),
            ),
        ];
        for (name, question, (listed, shown)) in cases {
            assert_eq!(
                answers_of(&[question], store_holding(&[1, 0, 0, 0, 0])),
                (listed.to_string(), shown.to_string()),
                "{name}"
            );
        }
    }

    /// Conditions take the value of a question that they refer to from its READ expression too,
    /// and a READ that needs, through another question's READ, its own value, is unavailable
    /// instead of endless.
    #[test]
    fn conditions_take_values_through_read_expressions() {
        let (root, questions) = form_set_of(&[
            one_of_with(1, 0, &[op(READ), get(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_8)]),
            one_of_with(2, 0, &[op(READ), question_ref1(3)]),
            one_of_with(3, 0, &[op(READ), question_ref1(2)]),
        ]);
        let values = VarStoreValues::new(&root, None);
        let efivars = store_holding(&[0, 3, 0, 0, 0]);
        let mut reader = efivars.reader();
        let referrer = questions[0].borrow();
        assert_eq!(
            values.value(&referrer, 1, &mut reader),
            Some(QuestionValue::Uint(3)),
            "READ of a GET"
        );
        let Some(QuestionValue::Unreadable { kind, reason }) =
            values.value(&referrer, 2, &mut reader)
        else {
            panic!("question 2 has a value");
        };
        assert_eq!(kind, ValueKind::Uint, "kind of question 2");
        assert!(
            reason.contains(&ValueUnavailable::ReadCycle(2).to_string()),
            "reason of question 2: {reason}"
        );
    }

    /// QUESTION_REF1 of `id`.
    fn question_ref1(id: u16) -> Vec<u8> {
        operation(QUESTION_REF1, false, &id.to_le_bytes())
    }

    /// A question reached through more than MAX_READ_DEPTH READ expressions is unavailable, in
    /// the 128 KiB stack of UEFI DXE; one reached through MAX_READ_DEPTH has its value.
    #[test]
    fn read_chains_end_at_max_read_depth_on_a_small_stack() {
        let chain = |n: u16| {
            std::thread::Builder::new()
                .stack_size(128 << 10)
                .spawn(move || {
                    let questions: Vec<Vec<u8>> = (1..=n)
                        .map(|id| match id == n {
                            true => one_of_with(
                                id,
                                0,
                                &[op(READ), get(STORE, 1, EFI_IFR_TYPE_NUM_SIZE_8)],
                            ),
                            false => one_of_with(id, 0, &[op(READ), question_ref1(id + 1)]),
                        })
                        .collect();
                    let (root, questions) = form_set_of(&questions);
                    let values = VarStoreValues::new(&root, None);
                    let efivars = store_holding(&[0, 3, 0, 0, 0]);
                    let referrer = questions[0].borrow();
                    values.value(&referrer, 1, &mut efivars.reader())
                })
                .expect("spawn a thread with a small stack")
                .join()
                .expect("retrieve the first question of the chain")
        };
        let depth = u16::try_from(MAX_READ_DEPTH).expect("MAX_READ_DEPTH fits a QuestionId");
        assert_eq!(
            chain(depth),
            Some(QuestionValue::Uint(3)),
            "chain of MAX_READ_DEPTH"
        );
        let Some(QuestionValue::Unreadable { reason, .. }) = chain(50) else {
            panic!("a chain of 50 has a value");
        };
        assert!(
            reason.contains(&ValueUnavailable::ReadDepth(depth + 1).to_string()),
            "reason of a chain of 50: {reason}"
        );
    }
}
