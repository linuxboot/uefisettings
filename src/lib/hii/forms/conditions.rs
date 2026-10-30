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
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;
use std::rc::Weak;

use anyhow::Result;
use thiserror::Error;

use super::find_corresponding_varstore;
use super::read_question_value;
use super::value_question;
use super::EfivarReader;
use super::IFROpCode;
use super::IFROperation;
use super::ParsedOperation;
use super::ValueQuestion;
use super::ValueUnavailable;
use super::VariableStore;

/// The opcode of IFROpCode::Match2, the highest that edk2-stable202608
/// SetupBrowserDxe/IfrParse.c IsUnKnownOpCode knows.
const EFI_IFR_MATCH2_OP: u8 = 0x64;

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

bitflags::bitflags! {
    /// The states, besides selectable, of the questions and options that get, set and
    /// list-questions select.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct IncludedStates: u64 {
        const GRAYED_OUT = 1;
        const SUPPRESSED = 1 << 1;
        const DISABLED = 1 << 2;
    }
}

impl IncludedStates {
    pub fn allows(self, state: QuestionState) -> bool {
        self.contains(state.into())
    }

    /// The states, lowest priority first.
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
}

/// The states that the conditions around a question or option can give it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateEvaluation {
    /// The state that the true conditions give
    known: QuestionState,
    /// The conditions not evaluated: the state each gives if true, and why it is not evaluated
    unknown: Vec<(QuestionState, String)>,
}

impl StateEvaluation {
    pub(crate) fn selectable() -> Self {
        StateEvaluation {
            known: QuestionState::Selectable,
            unknown: Vec::new(),
        }
    }

    /// Takes in a condition that gives `state` when true.
    fn add(&mut self, state: QuestionState, truth: Truth) {
        match truth {
            Truth::Known(true) => self.known = self.known.max(state),
            Truth::Known(false) => {}
            Truth::Unknown(reason) => self.unknown.push((state, reason)),
        }
    }

    /// The conditions not evaluated that would give a state above the known one.
    fn deciding(&self) -> impl Iterator<Item = &(QuestionState, String)> {
        self.unknown
            .iter()
            .filter(move |(state, _)| *state > self.known)
    }

    /// Why the conditions that decide between the possible states are not evaluated, each
    /// reason once.
    pub(crate) fn reasons(&self) -> impl Iterator<Item = &str> {
        let mut seen = HashSet::new();
        self.deciding()
            .map(|(_, reason)| reason.as_str())
            .filter(move |reason| seen.insert(*reason))
    }

    /// The states that the question or option can be in.
    fn possible_states(&self) -> BTreeSet<QuestionState> {
        std::iter::once(self.known)
            .chain(self.deciding().map(|&(state, _)| state))
            .collect()
    }

    /// The highest of possible_states.
    fn worst_case(&self) -> QuestionState {
        self.deciding()
            .map(|&(state, _)| state)
            .fold(self.known, QuestionState::max)
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
    /// unless just selectable, with why the conditions are not evaluated if more than one.
    pub(crate) fn annotation(&self) -> String {
        self.annotated("")
    }

    /// The annotation of the stored or written option, which precedes that of the question.
    pub(crate) fn option_annotation(&self) -> String {
        self.annotated("option ")
    }

    /// The annotation, with `subject` before the states.
    fn annotated(&self, subject: &str) -> String {
        let reasons: Vec<&str> = self.reasons().collect();
        if !reasons.is_empty() {
            let states: Vec<String> = self
                .possible_states()
                .iter()
                .map(ToString::to_string)
                .collect();
            return format!(
                " <{subject}{}: {}>",
                states.join(" or "),
                reasons.join("; ")
            );
        }
        match self.known {
            QuestionState::Selectable => String::new(),
            QuestionState::GrayedOut | QuestionState::Suppressed | QuestionState::Disabled => {
                format!(" <{subject}{}>", self.known)
            }
        }
    }
}

/// Which of the matches of a question to select.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Selection<T> {
    Picked(T, StateEvaluation),
    /// No match is certainly in a state that `include` allows, but some may be
    Undetermined {
        /// The one that get shows regardless
        likely: (T, StateEvaluation),
        /// Why their conditions are not evaluated
        reasons: Vec<String>,
        /// The states to include to select one regardless
        states: IncludedStates,
    },
    /// Every match is in a state that `include` does not allow: the states to include
    Excluded(IncludedStates),
    NotFound,
}

/// Selects, of `matches` in IFR order, the one with the lowest worst-case state among those
/// that `include` allows in every possible state, the first on a tie. Of those that it may
/// allow, the likely one has the lowest possible state that it allows, the first on a tie.
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
    likely: Option<(T, StateEvaluation, QuestionState)>,
    reasons: Vec<String>,
    undetermined: IncludedStates,
    excluded: IncludedStates,
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
            excluded: IncludedStates::empty(),
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
                let better = self
                    .picked
                    .as_ref()
                    .is_none_or(|(_, best)| evaluation.worst_case() < best.worst_case());
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
                if self
                    .likely
                    .as_ref()
                    .is_none_or(|&(_, _, best)| lowest < best)
                {
                    self.likely = Some((candidate, evaluation, lowest));
                }
            }
            (false, None) => self.excluded |= excluded_states,
        }
    }

    /// The selection of the matches taken in.
    fn finish(self) -> Selection<T> {
        match (self.picked, self.likely, self.excluded.is_empty()) {
            (Some((candidate, evaluation)), _, _) => Selection::Picked(candidate, evaluation),
            (None, Some((candidate, evaluation, _)), _) => Selection::Undetermined {
                likely: (candidate, evaluation),
                reasons: self.reasons,
                states: self.undetermined,
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
    /// No match: the states that excluded matches are in, none if no question matches
    Skipped(IncludedStates),
}

impl<T> Selection<T> {
    /// Maps the match.
    pub(crate) fn map<U>(self, f: impl FnOnce(T) -> U) -> Selection<U> {
        match self {
            Selection::Picked(candidate, evaluation) => Selection::Picked(f(candidate), evaluation),
            Selection::Undetermined {
                likely: (candidate, evaluation),
                reasons,
                states,
            } => Selection::Undetermined {
                likely: (f(candidate), evaluation),
                reasons,
                states,
            },
            Selection::Excluded(states) => Selection::Excluded(states),
            Selection::NotFound => Selection::NotFound,
        }
    }

    /// set writes only a match that `include` certainly allows, and fails rather than guess.
    pub(crate) fn for_set(self, question: &str) -> Result<Choice<T>, SelectionError> {
        match self {
            Selection::Picked(candidate, evaluation) => Ok(Choice::Chosen(candidate, evaluation)),
            Selection::Undetermined {
                reasons, states, ..
            } => Err(SelectionError::Undetermined {
                question: question.to_owned(),
                states,
                reasons,
            }),
            Selection::Excluded(states) => Ok(Choice::Skipped(states)),
            Selection::NotFound => Ok(Choice::Skipped(IncludedStates::empty())),
        }
    }

    /// get shows the match that set writes, else the likely one, whose annotation names its
    /// possible states.
    pub(crate) fn for_get(self) -> Choice<T> {
        match self {
            Selection::Picked(candidate, evaluation)
            | Selection::Undetermined {
                likely: (candidate, evaluation),
                ..
            } => Choice::Chosen(candidate, evaluation),
            Selection::Excluded(states) => Choice::Skipped(states),
            Selection::NotFound => Choice::Skipped(IncludedStates::empty()),
        }
    }
}

/// Returns the states that the SUPPRESS_IF, GRAY_OUT_IF and DISABLE_IF scopes around
/// `question` can give it: those of its form and FormSet too.
// TODO: gray out a question in an EFI_IFR_LOCKED scope, as edk2-stable202608
// SetupBrowserDxe/Presentation.c InitializeDisplayStatement does. Its FormDisplay.c
// UiAddMenuOption grays out EFI_IFR_FLAG_READ_ONLY ones too where PcdBrowerGrayOutReadOnlyMenu
// is set, a build setting that the OS cannot read.
pub(crate) fn question_state(
    question: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> StateEvaluation {
    let mut evaluation = StateEvaluation::selectable();
    let mut scope = question.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = scope {
        let op = op.borrow();
        if let OpRole::Scope(state) = OpRole::of(op.op_code) {
            evaluation.add(state, evaluate_condition(&op, inputs));
        }
        scope = op.parent.as_ref().and_then(Weak::upgrade);
    }
    evaluation
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
                evaluation.add(state, evaluate_condition(&op, inputs));
            }
            OpRole::Scope(
                QuestionState::Selectable | QuestionState::GrayedOut | QuestionState::Disabled,
            )
            | OpRole::Expression(_)
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
pub(crate) struct QuestionIndex(HashMap<u16, Vec<IndexedQuestion>>);

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
        fn walk(
            node: &Rc<RefCell<IFROperation>>,
            form: Option<&Rc<RefCell<IFROperation>>>,
            index: &mut HashMap<u16, Vec<IndexedQuestion>>,
        ) {
            let op = node.borrow();
            if skips_scope(&op) {
                return;
            }
            // reserved (UEFI 2.10 §33.3.8.2.2)
            if let Some(id) = question_id(&op).filter(|&id| id != 0) {
                index.entry(id).or_default().push(IndexedQuestion {
                    form: form.cloned(),
                    question: Rc::clone(node),
                });
            }
            let form = if matches!(op.op_code, IFROpCode::Form | IFROpCode::FormMap) {
                Some(node)
            } else {
                form
            };
            for child in &op.children {
                walk(child, form, index);
            }
        }
        let mut index = HashMap::new();
        walk(root, None, &mut index);
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

/// Returns the QuestionId of a question op.
fn question_id(op: &IFROperation) -> Option<u16> {
    let OpRole::Question = OpRole::of(op.op_code) else {
        return None;
    };
    // EFI_IFR_QUESTION_HEADER, after the Prompt and Help of its statement header
    op.data
        .first_chunk::<6>()
        .map(|&[_, _, _, _, low, high]| u16::from_le_bytes([low, high]))
}

/// Reads the values of the questions that conditions refer to from their VarStores, as get
/// does.
pub(crate) struct VarStoreValues {
    index: QuestionIndex,
}

impl VarStoreValues {
    /// Finds the questions in the FormSet of `root`.
    pub(crate) fn new(root: &Rc<RefCell<IFROperation>>) -> Self {
        VarStoreValues {
            index: QuestionIndex::new(root),
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
        let varstore =
            find_corresponding_varstore(Rc::clone(question), value_question.header().var_store_id);
        Some(question_value(&op, value_question, &varstore, reader))
    }
}

/// Returns the value of `question`, which is `value_question`, in `varstore`, typed as
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes types it.
fn question_value(
    question: &IFROperation,
    value_question: ValueQuestion,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> QuestionValue {
    let kind = match value_question {
        ValueQuestion::CheckBox(_) => ValueKind::Boolean,
        ValueQuestion::OneOf(_) | ValueQuestion::Numeric(_) => ValueKind::Uint,
    };
    let value = match read_question_value(question, varstore, reader) {
        Ok((_, value)) => value,
        Err(reason) => {
            return QuestionValue::Unreadable {
                kind,
                reason: reason.to_answer(),
            }
        }
    };
    match value_question {
        // a byte or a bit
        ValueQuestion::CheckBox(_) => match u8::try_from(value) {
            Ok(byte) => QuestionValue::Boolean(byte),
            Err(_) => QuestionValue::Unreadable {
                kind,
                reason: ValueUnavailable::CheckboxOverByte(value).to_answer(),
            },
        },
        ValueQuestion::OneOf(_) | ValueQuestion::Numeric(_) => QuestionValue::Uint(value),
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
    let mut evaluation = Evaluation::new(inputs);
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
    let mut evaluation = Evaluation::new(inputs);
    match evaluation.run(scope) {
        Ok(operand) => operand.as_u64().ok_or_else(|| evaluation.into_unknown()),
        Err(Abort::Undefined) => Err("UNDEFINED result".to_string()),
        Err(Abort::Malformed(reason)) => Err(format!("malformed expression: {reason}")),
        Err(Abort::NotEvaluated(reason)) => Err(reason),
    }
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
    Abort::Malformed(format!("{:?} not decoded", op.op_code))
}

/// What conditions take an op for.
#[derive(Clone, Copy)]
enum OpRole {
    /// An op of edk2-stable202608 SetupBrowserDxe/IfrParse.c IsExpressionOpCode
    Expression(ExpressionOp),
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
            IFROpCode::Match
            | IFROpCode::Get
            | IFROpCode::Set
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
            | IFROpCode::This
            | IFROpCode::Span
            | IFROpCode::Catenate
            | IFROpCode::ToLower
            | IFROpCode::ToUpper
            | IFROpCode::Map
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
    stack: Vec<Operand>,
    /// Why the first value that cannot be read cannot be
    unknown: Option<String>,
}

impl<'a, V: QuestionValues> Evaluation<'a, V> {
    fn new(inputs: &'a mut ExpressionInputs<'_, V>) -> Self {
        Evaluation {
            reader: inputs.reader,
            values: inputs.values,
            stack: Vec::new(),
            unknown: None,
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
        // The leading expression ops, each with the ops of its own scope, in IFR order: for
        // well-formed IFR, the first op holding the rest, as edk2-stable202608
        // SetupBrowserDxe/IfrParse.c ParseOpCodes takes them. AMI firmware sets the Scope bit
        // on a later op, e.g. EQ_ID_VAL NOT EQ_ID_VAL_LIST{OR}, where the first op alone leaves
        // out NOT and OR.
        // Ops that skips_scope names are left out, with their scopes: edk2 ParseOpCodes skips
        // them before it builds expressions (IsExpressionOpCode).
        let expression = scope
            .children
            .iter()
            .filter(|child| !skips_scope(&child.borrow()))
            .take_while(|child| {
                matches!(OpRole::of(child.borrow().op_code), OpRole::Expression(_))
            });
        for op in expression {
            self.run_tree(&op.borrow())?;
        }
        let result = self
            .stack
            .pop()
            .ok_or_else(|| Abort::Malformed("no value".to_string()))?;
        match self.stack.len() {
            0 => Ok(result),
            left => Err(Abort::Malformed(format!("{} values left", left + 1))),
        }
    }

    /// Evaluates `op` and then the ops in its scope, in IFR order.
    fn run_tree(&mut self, op: &IFROperation) -> Result<(), Abort> {
        let value = self.step(op)?;
        self.stack.push(value);
        op.children
            .iter()
            .filter(|child| !skips_scope(&child.borrow()))
            .try_for_each(|child| self.run_tree(&child.borrow()))
    }

    /// Pops the operand of `op`.
    fn pop(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        self.stack
            .pop()
            .ok_or_else(|| Abort::Malformed(format!("{:?} without an operand", op.op_code)))
    }

    /// Returns the value of `op` (edk2-stable202608 SetupBrowserDxe/Expression.c
    /// EvaluateExpression).
    fn step(&mut self, op: &IFROperation) -> Result<Operand, Abort> {
        let OpRole::Expression(expression) = OpRole::of(op.op_code) else {
            return Err(Abort::Malformed(format!(
                "{:?} in an expression",
                op.op_code
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
                            "QuestionRef1 of missing question {:#06x}",
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
            ExpressionOp::Dup => self
                .stack
                .last()
                .copied()
                .ok_or_else(|| Abort::Malformed(format!("{:?} without an operand", op.op_code))),
            ExpressionOp::Conditional => {
                let when_true = self.pop(op)?;
                let when_false = self.pop(op)?;
                match self.pop(op)?.as_bool()? {
                    Some(true) => Ok(when_true),
                    Some(false) => Ok(when_false),
                    None if when_true == when_false => Ok(when_true),
                    None => Err(Abort::NotEvaluated(format!(
                        "{:?} on a value that cannot be read",
                        op.op_code
                    ))),
                }
            }
            ExpressionOp::NotEvaluated => Err(Abort::NotEvaluated(format!(
                "{:?} not evaluated",
                op.op_code
            ))),
        }
    }

    /// Returns the value of question `id`, which `op` refers to; edk2-stable202608
    /// SetupBrowserDxe/Expression.c EvaluateExpression gives UNDEFINED without the question.
    fn question(&mut self, op: &IFROperation, id: u16) -> Result<QuestionOperand, Abort> {
        let value = self
            .values
            .value(op, id, self.reader)
            .ok_or(Abort::Undefined)?;
        let (kind, reason) = match value {
            QuestionValue::Boolean(value) => {
                return Ok(QuestionOperand::Value(Operand::Boolean(Some(value))))
            }
            QuestionValue::Uint(value) => {
                return Ok(QuestionOperand::Value(Operand::Uint(Some(value))))
            }
            QuestionValue::Unreadable { kind, reason } => (
                kind,
                format!("{:?} of question {id:#06x}: {reason}", op.op_code),
            ),
        };
        match kind {
            ValueKind::Boolean => {
                self.unknown.get_or_insert(reason);
                Ok(QuestionOperand::Value(Operand::Boolean(None)))
            }
            ValueKind::Uint => {
                self.unknown.get_or_insert(reason);
                Ok(QuestionOperand::Value(Operand::Uint(None)))
            }
            ValueKind::Other => Ok(QuestionOperand::Undecoded(reason)),
        }
    }
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
mod tests {
    use std::collections::HashMap;
    use std::collections::HashSet;

    use super::super::find_question_in;
    use super::super::handle_form_set;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::Cursor;
    use super::super::FormSetWalk;
    use super::super::QuestionDescriptor;
    use super::super::ValueLocation;
    use super::*;

    const EQ_ID_ID: u8 = 0x13;
    const EQ_ID_VAL_LIST: u8 = 0x14;
    const AND: u8 = 0x15;
    const OR: u8 = 0x16;
    const GET: u8 = 0x2B;
    const STRING: u8 = 0x1C;
    const PASSWORD: u8 = 0x08;
    const EQUAL: u8 = 0x2F;
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
        MapValues(HashMap::from([
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
            let values = MapValues(HashMap::from([
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
                        let values = MapValues(HashMap::from([
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
                unknown("EqIdVal of question 0x0004: <ValueUnavailable: test>"),
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
                unknown("EqIdValList of question 0x0004: <ValueUnavailable: test>"),
            ),
            (
                "type not decoded",
                eq_id_val_list(6, &[1]),
                unknown("EqIdValList of question 0x0006: <ValueUnavailable: test>"),
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
                unknown("EqIdId of question 0x0004: <ValueUnavailable: test>"),
            ),
            // edk2-stable202608 SetupBrowserDxe/Expression.c CompareHiiValue gives
            // EFI_UNSUPPORTED for an integer and a type that is no integer, which EQ_ID_ID
            // turns into UNDEFINED
            ("first not decoded", eq_id_id(6, 1), Truth::Known(false)),
            ("second not decoded", eq_id_id(4, 6), Truth::Known(false)),
            (
                "both not decoded",
                eq_id_id(6, 7),
                unknown("EqIdId of question 0x0006: <ValueUnavailable: test>"),
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
        let reason = "EqIdVal of question 0x0004: <ValueUnavailable: test>";
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
                unknown("QuestionRef1 of question 0x0005: <ValueUnavailable: test>"),
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
            unknown("QuestionRef1 of question 0x0004: <ValueUnavailable: test>"),
            "unreadable == ONE"
        );
        assert_eq!(
            truth(&[question_ref1(6), op(ONE), op(EQUAL)]),
            unknown("QuestionRef1 of question 0x0006: <ValueUnavailable: test>"),
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
                unknown("Conditional on a value that cannot be read"),
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
                "And without an operand",
            ),
            (
                "AND of one UINT",
                vec![uint8(1), op(AND)],
                "And without an operand",
            ),
            (
                "OR of one UINT",
                vec![uint8(1), op(OR)],
                "Or without an operand",
            ),
            ("two values", vec![ifr_true(), ifr_true()], "2 values left"),
            (
                "QUESTION_REF1 of no question",
                vec![question_ref1(9)],
                "QuestionRef1 of missing question 0x0009",
            ),
            (
                "truncated UINT16",
                vec![operation(UINT16, false, &[0x01])],
                "Uint16 not decoded",
            ),
            (
                "question in an expression",
                vec![ifr_true(), checkbox_op(1, 0)],
                "CheckBox in an expression",
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
        let get = operation(GET, false, &[0x01, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            truth(&[ifr_true(), get, op(OR)]),
            unknown("Get not evaluated"),
            "TRUE OR GET"
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
            known: state,
            unknown: Vec::new(),
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
                known: QuestionState::GrayedOut,
                unknown: vec![(
                    QuestionState::Suppressed,
                    "EqIdVal of question 0x0004: <ValueUnavailable: test>".to_string()
                )],
            },
            "grayed out, maybe suppressed"
        );
    }

    fn evaluation(known: QuestionState, unknown: &[(QuestionState, &str)]) -> StateEvaluation {
        StateEvaluation {
            known,
            unknown: unknown
                .iter()
                .map(|&(state, reason)| (state, reason.to_string()))
                .collect(),
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
        let reason = "EqIdVal of question 0x0004: <ValueUnavailable: test>";
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
        Selection::Picked(index, StateEvaluation::selectable())
    }

    /// Undetermined, likely the match of index `likely`; the test takes its evaluation from the
    /// matches.
    fn undetermined(likely: usize, reasons: &[&str], states: IncludedStates) -> Selection<usize> {
        Selection::Undetermined {
            likely: (likely, StateEvaluation::selectable()),
            reasons: reasons.iter().map(ToString::to_string).collect(),
            states,
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
                Selection::Excluded(grayed_out),
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
                Selection::Excluded(suppressed | disabled),
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
                Selection::Picked(index, _) => Selection::Picked(index, matches[index].clone()),
                Selection::Undetermined {
                    likely: (index, _),
                    reasons,
                    states,
                } => Selection::Undetermined {
                    likely: (index, matches[index].clone()),
                    reasons,
                    states,
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
                    let Selection::Picked(_, picked) = select(matches(), smaller) else {
                        continue;
                    };
                    for &larger in includes.iter().filter(|larger| larger.contains(smaller)) {
                        let selection = select(matches(), larger);
                        assert!(
                            matches!(&selection, Selection::Picked(_, more) if more.worst_case() <= picked.worst_case()),
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
            &HashSet::from([PROMPT]),
            &mut FormSetWalk::new(&strings(), &mut Efivars::new().reader(), &values(), include),
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
        let reason = "EqIdVal of question 0x0004: <ValueUnavailable: test>";
        let include = IncludedStates::SUPPRESSED;
        let selectable = StateEvaluation::selectable;
        let cases = [
            (
                "selectable after suppressed",
                vec![suppressed(), checkbox_op(2, 1)],
                IncludedStates::empty(),
                Selection::Picked(2, selectable()),
            ),
            (
                "selectable after suppressed, suppressed included",
                vec![suppressed(), checkbox_op(2, 1)],
                include,
                Selection::Picked(2, selectable()),
            ),
            (
                "suppressed",
                vec![suppressed()],
                IncludedStates::empty(),
                Selection::Excluded(include),
            ),
            (
                "suppressed, included",
                vec![suppressed()],
                include,
                Selection::Picked(1, known(QuestionState::Suppressed)),
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
                },
            ),
            (
                "maybe suppressed, included",
                vec![maybe_suppressed()],
                include,
                Selection::Picked(
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
                Selection::Picked(2, selectable()),
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
        let reason = "EqIdVal of question 0x0004: <ValueUnavailable: test>";
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
        let option = descriptor.select_option(&HashSet::from(["Enabled".to_string()]), include)?;
        Ok(option.and_then(|option| option.raw_value.as_u64()))
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
                reasons: vec!["EqIdVal of question 0x0004: <ValueUnavailable: test>".to_string()],
            }),
            "maybe suppressed"
        );
    }

    /// The UINT8 ONE_OF of `one_of_data()` holding `children` and storing `stored`, as get,
    /// list-questions and set see it with `values`, and the writes to its VarStore.
    fn stored_one_of(
        children: &[Vec<u8>],
        stored: u8,
        values: &impl QuestionValues,
    ) -> (QuestionDescriptor, RecordedWrites) {
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), children);
        let (store, writes) = recording_var_store(&[stored]);
        (question_descriptor_with(&question, store, values), writes)
    }

    /// The answer that get shows for `question`, but for the state of the question.
    fn shown_answer(question: &QuestionDescriptor) -> String {
        question.value.clone() + &question.value_state.option_annotation()
    }

    /// Sets `question` to the option `text` as set does with `include`.
    fn set_option(
        question: &QuestionDescriptor,
        text: &str,
        include: IncludedStates,
    ) -> std::result::Result<(), String> {
        let option = question
            .select_option(&HashSet::from([text.to_string()]), include)
            .map_err(|error| error.to_string())?
            .ok_or("no such option")?;
        change_option(question, option).map_err(|error| error.to_string())
    }

    /// A false SUPPRESS_IF shows the options in it, so get lists them and names the stored one,
    /// and set writes them, which set refused before with the error of
    /// https://github.com/linuxboot/uefisettings/issues/2, "provided value did not match any
    /// possible option".
    #[test]
    fn options_in_a_false_suppress_if_are_listed_shown_and_set() {
        let options = [flagged_option(5, 0x00, 0), flagged_option(6, 0x00, 1)];
        let (question, writes) = stored_one_of(
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
            matches!(change_value(&question, "Disabled"), Ok(())),
            "set Disabled"
        );
        assert_eq!(*writes.borrow(), [(0, vec![0])], "writes of Disabled");
    }

    #[test]
    fn option_in_a_true_suppress_if_is_hidden_unless_suppressed_is_included() {
        let children = [
            flagged_option(5, 0x00, 0),
            conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(6, 0x00, 1)]),
        ];
        let (question, writes) = stored_one_of(&children, 1, &values());

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
            change_value(&question, "Enabled").map_err(|error| error.to_string()),
            Err(
                "option \"Enabled\" of question \"\" is suppressed; also include suppressed \
                 questions to select it"
                    .to_string()
            ),
            "change_value to Enabled"
        );
        assert_eq!(*writes.borrow(), [], "writes of change_value");

        let suppressed = IncludedStates::SUPPRESSED;
        assert_eq!(
            question.listed_options(suppressed),
            ["Disabled", "Enabled"],
            "listed, suppressed included"
        );
        assert_eq!(
            set_option(&question, "Enabled", suppressed),
            Ok(()),
            "set Enabled, suppressed included"
        );
        assert_eq!(
            *writes.borrow(),
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
                            suppressed: EqIdVal of question 0x0004: <ValueUnavailable: test>; \
                            also include suppressed questions to select it regardless";
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
                "Enabled <option selectable or suppressed: EqIdVal of question 0x0004: \
                 <ValueUnavailable: test>>",
                Err(undetermined.to_string()),
            ),
        ];
        for (name, question_4, listed, answer, set) in cases {
            let values = MapValues(HashMap::from([(4, question_4)]));
            let (question, writes) = stored_one_of(&children, 1, &values);

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
                set_option(&question, "Enabled", IncludedStates::empty()),
                set,
                "{name}"
            );
            assert_eq!(*writes.borrow(), written, "{name}");

            let suppressed = IncludedStates::SUPPRESSED;
            assert_eq!(
                question.listed_options(suppressed),
                ["Disabled", "Enabled"],
                "{name}, suppressed included"
            );
            assert_eq!(
                set_option(&question, "Enabled", suppressed),
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
        let (store, writes) = recording_var_store(&[0]);
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
            set_option(&question, "Enabled", IncludedStates::empty()),
            Ok(()),
            "set Enabled"
        );
        assert_eq!(*writes.borrow(), [(0, vec![1])], "writes of Enabled");
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
            "Disabled <option selectable or suppressed: EqIdVal of question 0x0004: \
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
            .map(|option| (option.value.as_str(), option.raw_value.as_u64()))
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
                Selection::Picked(1, StateEvaluation::selectable())
            } else {
                Selection::NotFound
            };
            assert_eq!(found, want, "{name}: found by its prompt");

            let referrer = checkbox_op(2, 1);
            let root = parse_form_set(&[form(1, &[body, referrer.clone()])]);
            let referrer = find_op(&root, &referrer[2..])
                .unwrap_or_else(|| panic!("{name}: find the referrer"));
            let value = VarStoreValues::new(&root).value(
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
                &strings(),
                IncludedStates::empty(),
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
        let values = VarStoreValues::new(&root);
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
                        values: &VarStoreValues::new(&root),
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
        let values = VarStoreValues::new(&root);

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
                reason: "<ValueUnavailable: Date value not decoded>".to_string()
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
        let values = VarStoreValues::new(&root);
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

    /// The value of a parsed question in `var_store`.
    fn value_in(
        op_code: u8,
        data: &[u8],
        VarStoreFixture { store, efivars }: VarStoreFixture,
    ) -> QuestionValue {
        let (_root, question) = parse_question(&[], op_code, data, &[]);
        let question = question.borrow();
        let value_question = value_question(&question).expect("a ONE_OF, NUMERIC or CHECKBOX");
        question_value(&question, value_question, &store, &mut efivars.reader())
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
            let (_root, bit_field) = parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &[]);
            let bit_field = bit_field.borrow();
            let value_question = value_question(&bit_field).expect("a ONE_OF, NUMERIC or CHECKBOX");
            let VarStoreFixture { store, efivars } = var_store_of(&[byte]);
            assert_eq!(
                question_value(&bit_field, value_question, &store, &mut efivars.reader()),
                want,
                "{name}"
            );
        }
    }
}
