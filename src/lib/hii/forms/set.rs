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

//! The writes of set: the value of each question named, encoded into the EFI variable of its
//! VarStore.

use std::collections::BTreeSet;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::ami_access_level::AccessLevel;
use super::conditions::ExpressionRefusal;
use super::conditions::IncludedStates;
use super::conditions::ReadOnlyCause;
use super::conditions::SelectionError;
use super::storage::ValueLocation;
use super::storage::VariableNotExported;
use super::storage::VariableStore;
use super::storageless::StoragelessRefusal;
use super::write_plan::write_in_turn;
use super::write_plan::WritePlan;
use super::AnswerOption;
use super::IFROpCode;
use super::QuestionDescriptor;
use super::RangeType;
use super::TypeValue;
use crate::hii::variables::is_volatile;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VolatileWrites;
use crate::hii::variables::VolatileWritingVariables;
use crate::hii::variables::WithholdingVariables;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;

#[derive(Error, Debug)]
pub(crate) enum ChangeValueError {
    #[error("provided value did not match any possible option")]
    InvalidOption,
    #[error("provided value exceeded max possible value")]
    ExceededMaxValue,
    #[error("provided value is below the minimum possible value")]
    BelowMinValue,
    #[error("numeric question has an invalid range")]
    InvalidNumericRange,
    #[error("setting EDKII bit-field values is not supported")]
    UnsupportedBitField,
    #[error("cannot set question {question:?}: {reason}")]
    NoVarStore { question: String, reason: String },
    #[error("cannot set question {question:?}: {refusal}")]
    Storageless {
        question: String,
        refusal: StoragelessRefusal,
    },
    #[error("cannot set question {question:?}: {refusal}")]
    Expression {
        question: String,
        refusal: ExpressionRefusal,
    },
    /// A question that `cause` makes read-only, which set writes only with the states that lift
    /// `cause`, and `undetermined`, the states that it may be in where the selection is
    /// undetermined; `ranked_before` selects a match that ranks before it
    #[error(
        "cannot set question {question:?}: {}",
        read_only_refusal(*.cause, *.undetermined, *.ranked_before)
    )]
    ReadOnly {
        question: String,
        cause: ReadOnlyCause,
        undetermined: IncludedStates,
        ranked_before: IncludedStates,
    },
    #[error(transparent)]
    Selection(#[from] SelectionError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Why set refuses a question that `cause` makes read-only, with the states to include to write
/// it, if any: those that lift `cause`, then `undetermined`; or to select a match that ranks
/// before it, `ranked_before`.
fn read_only_refusal(
    cause: ReadOnlyCause,
    undetermined: IncludedStates,
    ranked_before: IncludedStates,
) -> String {
    let to_write = cause
        .lifted_with()
        .map(|lifted_with| match undetermined.is_empty() {
            true => lifted_with.to_string(),
            false => format!("{lifted_with},{undetermined}"),
        });
    match (to_write, ranked_before.is_empty()) {
        (Some(to_write), true) => {
            format!("{cause}; also include {to_write} questions to write it")
        }
        (Some(to_write), false) => format!(
            "{cause}; also include {to_write} questions to write it, or {ranked_before} \
             questions to select a writable one"
        ),
        (None, true) => cause.to_string(),
        (None, false) => {
            format!("{cause}; also include {ranked_before} questions to select one that set writes")
        }
    }
}

/// set's write of the variable of `store`: `patches`, each little-endian bytes at a VarOffset,
/// within the Size of `store`, in order, later ones winning where they overlap.
pub(super) struct VarStoreWrite<'a> {
    pub(super) store: &'a dyn VariableStore,
    pub(super) patches: Vec<(u16, Vec<u8>)>,
}

impl<'a> VarStoreWrite<'a> {
    /// The write of `value` at VarOffset `offset` of `store`, through variables of `interface`:
    /// fails unless `value` is a number that fits in the Size of `store` there.
    pub(super) fn new(
        store: &'a dyn VariableStore,
        offset: u16,
        value: TypeValue,
        interface: VariableInterface,
    ) -> Result<Self> {
        let encoded = match value {
            TypeValue::NumSize8(value) => value.to_le_bytes().to_vec(),
            TypeValue::NumSize16(value) => value.to_le_bytes().to_vec(),
            TypeValue::NumSize32(value) => value.to_le_bytes().to_vec(),
            TypeValue::NumSize64(value) => value.to_le_bytes().to_vec(),
            TypeValue::Boolean(_)
            | TypeValue::Time(_)
            | TypeValue::Date(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => {
                return Err(anyhow!("unsupported value type for {}", interface.write()))
            }
        };
        if usize::from(offset) + encoded.len() > usize::from(store.size()) {
            return Err(anyhow!(
                "write at offset {} with width {} exceeds varstore size {}",
                offset,
                encoded.len(),
                store.size()
            ));
        }
        Ok(Self {
            store,
            patches: vec![(offset, encoded)],
        })
    }

    /// Writes `patches` through `variables`. choice_for_set and WritePlan::variable_writes are the
    /// only checks of runtime access before a write: they refuse a variable without
    /// EFI_VARIABLE_RUNTIME_ACCESS that the selection or the plan read, and set writes only
    /// variables that they read. Firmware refuses such a write if the variable changed since that
    /// read (edk2-stable202608 VariableServiceSetVariable, EFI_WRITE_PROTECTED).
    pub(super) fn write(&self, variables: &dyn FirmwareVariables) -> Result<()> {
        self.span(variables)
            .and_then(|(offset, span)| {
                variables.write_at(&self.store.variable_key(), self.store.size(), offset, &span)
            })
            .map_err(|error| {
                VariableNotExported::explain(
                    error,
                    self.store,
                    variables.reach(),
                    variables.interface(),
                )
            })
    }

    /// The first VarOffset that the patches change, and the bytes from there to the last that
    /// they change: those of more than one patch with the bytes between them as `variables`
    /// hold them now, after the writes before this one.
    fn span(&self, variables: &dyn FirmwareVariables) -> Result<(u16, Vec<u8>)> {
        let Some((first, rest)) = self.patches.split_first() else {
            return Err(anyhow!("a variable write without bytes"));
        };
        if rest.is_empty() {
            return Ok(first.clone());
        }
        let start = rest
            .iter()
            .fold(first.0, |start, (offset, _)| start.min(*offset));
        let end = self
            .patches
            .iter()
            .map(|(offset, bytes)| usize::from(*offset) + bytes.len())
            .fold(0, usize::max);
        let key = self.store.variable_key();
        let held = variables.read(&key, self.store.size())?;
        let mut span = held
            .get(EFIVARFS_HEADER_SIZE..)
            .and_then(|payload| payload.get(usize::from(start)..end))
            .ok_or_else(|| {
                anyhow!(
                    "EFI variable {key} holds {} bytes, short of the {end} that set writes",
                    held.len().saturating_sub(EFIVARFS_HEADER_SIZE)
                )
            })?
            .to_vec();
        for (offset, bytes) in &self.patches {
            offset
                .checked_sub(start)
                .map(usize::from)
                .and_then(|at| span.get_mut(at..at + bytes.len()))
                .ok_or_else(|| anyhow!("bytes at VarOffset {offset} outside their span"))?
                .copy_from_slice(bytes);
        }
        Ok((start, span))
    }
}

/// What set takes for a question: the text of its value, or of a ONE_OF the option that it
/// picked.
#[derive(Clone, Copy)]
pub(super) enum NewValue<'a> {
    Text(&'a str),
    Option(&'a AnswerOption),
}

/// The value that sets `question` to `new_value`, and its write through variables of `reach` and
/// `interface`, or None for a question without a VarStore whose WRITE expression alone takes
/// it; for a ONE_OF, a text sets the option of that text that select_option picks without
/// --include.
pub(super) fn own_write<'a>(
    question: &'a QuestionDescriptor,
    new_value: NewValue<'_>,
    reach: VariableReach,
    interface: VariableInterface,
) -> Result<(TypeValue, Option<VarStoreWrite<'a>>), ChangeValueError> {
    // writes take VarOffset in bytes
    let ValueLocation::Bytes { offset, .. } = question.location else {
        return Err(ChangeValueError::UnsupportedBitField);
    };
    let store = question.store(reach)?;
    let value = match new_value {
        NewValue::Option(option) => option.raw_value,
        NewValue::Text(text) if question.opcode == IFROpCode::OneOf => {
            question
                .select_option(&BTreeSet::from([text.to_owned()]), IncludedStates::empty())?
                .ok_or(ChangeValueError::InvalidOption)?
                .raw_value
        }
        NewValue::Text(text) => numeric_value(question, text)?,
    };
    let write = store
        .map(|store| VarStoreWrite::new(store, offset, value, interface))
        .transpose()?;
    Ok((value, write))
}

/// The value of the NUMERIC or CHECKBOX `question` that `new_value` gives, within its range.
fn numeric_value(
    question: &QuestionDescriptor,
    new_value: &str,
) -> Result<TypeValue, ChangeValueError> {
    Ok(match &question.numeric_range {
        Some(range) => range.parse_value(new_value)?,
        None => match question.max_value {
            RangeType::NumSize8(m) => {
                let data_to_write = new_value
                    .parse::<u8>()
                    .context("value should fit in a u8")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize8(data_to_write)
            }
            RangeType::NumSize16(m) => {
                let data_to_write = new_value
                    .parse::<u16>()
                    .context("value should fit in a u16")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize16(data_to_write)
            }
            RangeType::NumSize32(m) => {
                let data_to_write = new_value
                    .parse::<u32>()
                    .context("value should fit in a u32")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize32(data_to_write)
            }
            RangeType::NumSize64(m) => {
                let data_to_write = new_value
                    .parse::<u64>()
                    .context("value should fit in a u64")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize64(data_to_write)
            }
        },
    })
}

/// What set wrote for one question: the option that it picked, None for a value, and whether a
/// variable that it wrote is volatile, as the reader read its attributes before the write.
pub(crate) struct WrittenQuestion<'a> {
    pub(crate) option: Option<&'a AnswerOption>,
    pub(crate) volatile: bool,
}

/// Sets each of the `selected` questions, by the selector of its package list, to `new_value`
/// or to its option of one of `texts` that chosen_option picks with `include`, in `variables`,
/// writing a volatile variable only if `volatile` allows it, and returns a WrittenQuestion per
/// selected question, in its order; fails with SelectionError::NotFound when nothing is selected.
/// It builds the WritePlan of every question before the first write, reading with `reader`, whose
/// conditions read `access_level`, if stated, for AMI_ACCESS_LEVEL, so that a value or a SET that
/// one question refuses leaves every variable unchanged; then it writes each, also after a failed
/// one, and fails unless every write succeeds: with the error of a single question unchanged,
/// else with NotSetEverywhere.
#[expect(
    clippy::too_many_arguments,
    reason = "set's inputs: the question, its matches, the value, how to pick an option, and the \
              variables to read and write"
)]
pub(crate) fn set_questions<'a>(
    question: &str,
    selected: &[(&str, &'a QuestionDescriptor)],
    new_value: &str,
    texts: &BTreeSet<String>,
    include: IncludedStates,
    reader: &mut EfivarReader,
    access_level: Option<AccessLevel>,
    volatile: VolatileWrites,
    variables: &WithholdingVariables<impl FirmwareVariables>,
) -> Result<Vec<WrittenQuestion<'a>>> {
    if selected.is_empty() {
        return Err(SelectionError::NotFound {
            question: question.to_owned(),
        }
        .into());
    }
    let (reach, interface) = (variables.reach(), variables.interface());
    let plans = selected
        .iter()
        .map(|&(selector, descriptor)| {
            // if the descriptor provides options then set the closest one from texts
            // (example whatever matches from [Enabled, Enable])
            // else try setting the new_value because it might be some arbitrary value like a number
            // (will return error if doesn't match constraints)
            let (value, option) = match descriptor.possible_options.is_empty() {
                true => (NewValue::Text(new_value), None),
                false => {
                    let option = descriptor.chosen_option(texts, include)?;
                    (NewValue::Option(option), Some(option))
                }
            };
            let plan = WritePlan::new(descriptor, value, (reach, interface), reader, access_level)?;
            Ok((selector, plan, option))
        })
        .collect::<Result<Vec<_>>>()?;
    let writes = plans
        .iter()
        .map(|(selector, plan, _)| Ok((*selector, plan.variable_writes(reader, volatile)?)))
        .collect::<Result<Vec<_>>>()?;
    let written_questions = plans
        .iter()
        .zip(&writes)
        .map(|((_, _, option), (_, question_writes))| WrittenQuestion {
            option: *option,
            volatile: question_writes
                .iter()
                .any(|write| reader.attributes(write.store).is_some_and(is_volatile)),
        })
        .collect();
    let variables = VolatileWritingVariables::new(variables, volatile);

    if let [(_, question_writes)] = writes.as_slice() {
        write_in_turn(question_writes, &variables)?;
        return Ok(written_questions);
    }
    let mut written = Vec::new();
    let mut failed = Vec::new();
    for (selector, question_writes) in &writes {
        match write_in_turn(question_writes, &variables) {
            Ok(()) => written.push(selector.to_string()),
            Err(error) => failed.push((*selector, error)),
        }
    }
    if !failed.is_empty() {
        return Err(NotSetEverywhere::new(question, failed, written).into());
    }
    Ok(written_questions)
}

/// set's error when a write fails while set writes several questions: each Failure, and the
/// selectors written.
#[derive(Error, Debug)]
#[error(
    "question {question:?} was not set everywhere: {}",
    outcome(.failures, .written)
)]
struct NotSetEverywhere {
    question: String,
    failures: Vec<Failure>,
    written: Vec<String>,
}

/// A distinct error of NotSetEverywhere, with the selectors whose writes failed with it.
#[derive(Debug)]
struct Failure {
    error: String,
    selectors: Vec<String>,
}

/// The text of NotSetEverywhere after the question: `failures`, then the selectors `written`.
fn outcome(failures: &[Failure], written: &[String]) -> String {
    let failures: Vec<String> = failures
        .iter()
        .map(|Failure { error, selectors }| format!("{error} (in {})", selectors.join(", ")))
        .collect();
    let written = match written {
        [] => "none".to_owned(),
        _ => written.join(", "),
    };
    format!("{}; written in: {written}", failures.join("; "))
}

impl NotSetEverywhere {
    /// The error of `question`, whose writes `failed` by selector, and were `written` by the
    /// others: each error is named once.
    fn new(question: &str, failed: Vec<(&str, anyhow::Error)>, written: Vec<String>) -> Self {
        let mut failures: Vec<Failure> = Vec::new();
        for (selector, error) in failed {
            let error = format!("{error:#}");
            match failures.iter_mut().find(|failure| failure.error == error) {
                Some(failure) => failure.selectors.push(selector.to_owned()),
                None => failures.push(Failure {
                    error,
                    selectors: vec![selector.to_owned()],
                }),
            }
        }
        Self {
            question: question.to_owned(),
            failures,
            written,
        }
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod set_questions_tests {
    use super::super::ifr_fixtures::*;
    use super::*;

    const WRITE_ERROR: WriteError = WriteError {
        cause: "write failed",
        context: None,
    };

    /// A CHECKBOX at VarOffset `offset` of `var_store`, as set sees it.
    fn checkbox_at(offset: u16, var_store: VarStoreFixture) -> QuestionDescriptor {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(offset, 0x00), &[]);
        question_descriptor(&node, var_store)
    }

    /// A CHECKBOX on `var_store`, as set sees it.
    fn checkbox_on_store(var_store: VarStoreFixture) -> QuestionDescriptor {
        checkbox_at(0, var_store)
    }

    /// A UINT8 NUMERIC shown unsigned (EFI_IFR_DISPLAY_UINT_DEC) from 0 to `maximum` on
    /// `var_store`, as set sees it.
    fn numeric_on_store(maximum: u8, var_store: VarStoreFixture) -> QuestionDescriptor {
        let (_root, node) = parse_question(&[], NUMERIC, &uint8_numeric(0x10, 0, maximum), &[]);
        question_descriptor(&node, var_store)
    }

    /// A UINT8 ONE_OF with the one option `option` on `var_store`, as set sees it.
    fn one_of_on_store(option: Vec<u8>, var_store: VarStoreFixture) -> QuestionDescriptor {
        let (_root, node) = parse_question(&[], ONE_OF, &one_of_data(), &[option]);
        question_descriptor(&node, var_store)
    }

    /// An EDKII bit varstore field `op_code` with `data` and `children` on `var_store`, as set
    /// sees it.
    fn bit_field_on_store(
        op_code: u8,
        data: &[u8],
        children: &[Vec<u8>],
        var_store: VarStoreFixture,
    ) -> QuestionDescriptor {
        let (_root, node) = parse_question_in_guid(BIT_VARSTORE_GUID, op_code, data, children);
        question_descriptor(&node, var_store)
    }

    /// set_questions of PROMPT to `new_value`, or to an option of the texts `texts`, in
    /// `variables`: the texts of the options written, or the error as the CLI prints it.
    fn set_options(
        variables: &MemoryVariables,
        selected: &[(&str, &QuestionDescriptor)],
        new_value: &str,
        texts: &[&str],
    ) -> std::result::Result<Vec<Option<String>>, String> {
        // no question here has a WRITE expression, whose GETs and merges would read
        let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
            variables.reach(),
            variables.interface(),
        )));
        set_questions(
            PROMPT,
            selected,
            new_value,
            &texts.iter().map(|text| text.to_string()).collect(),
            IncludedStates::empty(),
            &mut reader,
            None,
            VolatileWrites::Refuse,
            &WithholdingVariables::new(variables, BTreeSet::new()),
        )
        .map(|written| {
            written
                .into_iter()
                .map(|question| question.option.map(|option| option.value.clone()))
                .collect()
        })
        .map_err(|error| format!("{error:#}"))
    }

    /// set_questions of PROMPT to `new_value` in `variables`, its error as the CLI prints it.
    fn set(
        variables: &MemoryVariables,
        selected: &[(&str, &QuestionDescriptor)],
        new_value: &str,
    ) -> std::result::Result<(), String> {
        set_options(variables, selected, new_value, &[]).map(drop)
    }

    /// The writes to the variable `name`.
    fn writes(variables: &MemoryVariables, name: &str) -> Vec<(u16, Vec<u8>)> {
        variables.writes_to(&variable_key(name))
    }

    #[test]
    fn every_match_is_written() {
        let variables = MemoryVariables::default();
        let a = checkbox_on_store(writable_var_store("A", &[0], &variables));
        let b = checkbox_on_store(writable_var_store("B", &[0], &variables));

        assert_eq!(set(&variables, &[("A", &a), ("B", &b)], "1"), Ok(()), "set");
        assert_eq!(writes(&variables, "A"), [(0, vec![1])], "writes of A");
        assert_eq!(writes(&variables, "B"), [(0, vec![1])], "writes of B");
    }

    #[test]
    fn no_match_is_not_found() {
        assert_eq!(
            set(&MemoryVariables::default(), &[], "1"),
            Err("no question \"Prompt\" in the HiiDB".to_string()),
            "no selected question"
        );
    }

    #[test]
    fn the_options_written_follow_the_matches() {
        let variables = MemoryVariables::default();
        let a = one_of_on_store(
            flagged_option(6, 0x00, 1),
            writable_var_store("A", &[0], &variables),
        );
        let b = one_of_on_store(
            flagged_option(5, 0x00, 2),
            writable_var_store("B", &[0], &variables),
        );

        assert_eq!(
            set_options(
                &variables,
                &[("A", &a), ("B", &b)],
                "",
                &["Enabled", "Disabled"]
            ),
            Ok(vec![
                Some("Enabled".to_string()),
                Some("Disabled".to_string())
            ]),
            "A's option Enabled, then B's option Disabled"
        );
        assert_eq!(writes(&variables, "A"), [(0, vec![1])], "writes of A");
        assert_eq!(writes(&variables, "B"), [(0, vec![2])], "writes of B");
    }

    #[test]
    fn a_failed_write_fails_set_after_the_other_writes() {
        let mut variables = MemoryVariables::default();
        let a = checkbox_on_store(failing_var_store("A", WRITE_ERROR, &mut variables));
        let b = checkbox_on_store(writable_var_store("B", &[0], &variables));

        assert_eq!(
            set(&variables, &[("A", &a), ("B", &b)], "1"),
            Err(
                "question \"Prompt\" was not set everywhere: write failed (in A); written in: B"
                    .to_string()
            ),
            "set"
        );
        assert_eq!(
            writes(&variables, "B"),
            [(0, vec![1])],
            "writes of B after A failed"
        );
    }

    #[test]
    fn the_failed_write_of_a_single_match_is_its_error() {
        let mut variables = MemoryVariables::default();
        let a = checkbox_on_store(failing_var_store("A", WRITE_ERROR, &mut variables));

        assert_eq!(
            set(&variables, &[("A", &a)], "1"),
            Err(WRITE_ERROR.cause.to_string()),
            "one match"
        );
    }

    #[test]
    fn a_value_that_one_match_refuses_writes_no_match() {
        let variables = MemoryVariables::default();
        let a = numeric_on_store(200, writable_var_store("A", &[0], &variables));
        let b = numeric_on_store(100, writable_var_store("B", &[0], &variables));

        assert_eq!(
            set(&variables, &[("A", &a), ("B", &b)], "150"),
            Err("provided value exceeded max possible value".to_string()),
            "150, above the maximum of B"
        );
        assert_eq!(writes(&variables, "A"), [], "writes of A");
        assert_eq!(writes(&variables, "B"), [], "writes of B");
    }

    #[test]
    fn a_write_that_the_ifr_of_one_match_refuses_writes_no_match() {
        let variables = MemoryVariables::default();
        let a = checkbox_on_store(writable_var_store("A", &[0], &variables));
        let boolean_option = one_of_on_store(
            one_of_option(6, 0x04, &[1]),
            writable_var_store("Boolean", &[0], &variables),
        );
        let past_the_var_store = checkbox_at(1, writable_var_store("Short", &[0], &variables));
        // 8-bit UINT_DEC fields at bit 0: writes take VarOffset in bytes
        let bit_field_numeric = bit_field_on_store(
            NUMERIC,
            &uint32_range_question(0, 0x48),
            &[],
            writable_var_store("NumericBits", &[0; 4], &variables),
        );
        let bit_field_one_of = bit_field_on_store(
            ONE_OF,
            &uint32_range_question(0, 0x48),
            &[one_of_option(6, 0x02, &1u32.to_le_bytes())],
            writable_var_store("OneOfBits", &[0; 4], &variables),
        );
        let cases = [
            (
                "B's option of Type BOOLEAN",
                &boolean_option,
                "unsupported value type for efivarfs write",
                "Boolean",
            ),
            (
                "B at VarOffset 1 of its 1-byte VarStore",
                &past_the_var_store,
                "write at offset 1 with width 1 exceeds varstore size 1",
                "Short",
            ),
            (
                "B an EDKII bit-field NUMERIC",
                &bit_field_numeric,
                "setting EDKII bit-field values is not supported",
                "NumericBits",
            ),
            (
                "B's option of an EDKII bit-field ONE_OF",
                &bit_field_one_of,
                "setting EDKII bit-field values is not supported",
                "OneOfBits",
            ),
        ];
        for (case, b, error, b_variable) in cases {
            assert_eq!(
                set_options(&variables, &[("A", &a), ("B", b)], "1", &["Enabled"]),
                Err(error.to_string()),
                "{case}"
            );
            assert_eq!(writes(&variables, "A"), [], "writes of A, {case}");
            assert_eq!(writes(&variables, b_variable), [], "writes of B, {case}");
        }
    }

    /// set refuses an option of a type that it does not write in the words of the interface of
    /// its variables, whatever their reach, and writes nothing.
    #[test]
    fn unsupported_option_is_refused_in_the_words_of_its_interface() {
        for (reach, interface, write) in [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "efivarfs write",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                "SetFirmwareEnvironmentVariableExW write",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "efivarfs write",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "SetVariable() write",
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            let boolean_option = one_of_on_store(
                one_of_option(6, 0x04, &[1]),
                writable_var_store("Boolean", &[0], &variables),
            );
            let case = format!("{reach:?}, {interface:?}");

            assert_eq!(
                set_options(&variables, &[("B", &boolean_option)], "1", &["Enabled"]),
                Err(format!("unsupported value type for {write}")),
                "{case}"
            );
            assert_eq!(writes(&variables, "Boolean"), [], "{case}: writes");
        }
    }

    #[test]
    fn each_failure_is_named_once() {
        const FIRST: WriteError = WriteError {
            cause: "first failure",
            context: None,
        };
        const SECOND: WriteError = WriteError {
            cause: "second failure",
            context: None,
        };
        const CHAINED: WriteError = WriteError {
            cause: "permission denied",
            context: Some("failed to write"),
        };
        let cases = [
            (
                "one error",
                [WRITE_ERROR, WRITE_ERROR, WRITE_ERROR],
                "write failed (in A, B, C)",
            ),
            (
                "two errors",
                [FIRST, SECOND, FIRST],
                "first failure (in A, C); second failure (in B)",
            ),
            (
                "an error in a context",
                [CHAINED, WRITE_ERROR, CHAINED],
                "failed to write: permission denied (in A, C); write failed (in B)",
            ),
        ];
        for (case, [a_error, b_error, c_error], failures) in cases {
            let mut variables = MemoryVariables::default();
            let [a, b, c] =
                [("A", a_error), ("B", b_error), ("C", c_error)].map(|(name, error)| {
                    checkbox_on_store(failing_var_store(name, error, &mut variables))
                });
            assert_eq!(
                set(&variables, &[("A", &a), ("B", &b), ("C", &c)], "1"),
                Err(format!(
                    "question \"Prompt\" was not set everywhere: {failures}; written in: none"
                )),
                "{case}"
            );
        }
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod write_validation_tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use super::super::ifr_fixtures::*;
    use super::super::question_values::handle_numeric;
    use super::super::FormSetWalk;
    use super::super::IFROperation;
    use super::super::Numeric;
    use super::super::NumericFormat;
    use super::super::ParsedOperation;
    use super::super::QuestionHeader;
    use super::super::Range;
    use super::super::Range16;
    use super::super::Range32;
    use super::super::Range64;
    use super::super::Range8;
    use super::*;

    /// The buffer VarStore NumericTest of 42 bytes, whose efivar file holds `payload`, and
    /// variables that hold it too, for set to write there.
    fn numeric_test_store(payload: &[u8]) -> (VarStoreFixture, MemoryVariables) {
        let store = buffer("NumericTest", 42);
        let variables = MemoryVariables::default();
        variables.insert(store.variable_key(), NV_BS_RT, payload);
        let efivars = Efivars::new();
        efivars.write(&store, payload);
        let fixture = VarStoreFixture {
            store: Ok(Box::new(store)),
            efivars,
        };
        (fixture, variables)
    }

    /// The writes to NumericTest.
    fn writes(variables: &MemoryVariables) -> Vec<(u16, Vec<u8>)> {
        variables.writes_to(&variable_key("NumericTest"))
    }

    fn numeric_question(
        bits: u32,
        minimum: u64,
        maximum: u64,
        step: u64,
        display: u8,
        initial: u64,
    ) -> (QuestionDescriptor, MemoryVariables) {
        let (width_code, range) = match bits {
            8 => (
                0,
                Range::Range8(Range8 {
                    min_value: minimum as u8,
                    max_value: maximum as u8,
                    step: step as u8,
                }),
            ),
            16 => (
                1,
                Range::Range16(Range16 {
                    min_value: minimum as u16,
                    max_value: maximum as u16,
                    step: step as u16,
                }),
            ),
            32 => (
                2,
                Range::Range32(Range32 {
                    min_value: minimum as u32,
                    max_value: maximum as u32,
                    step: step as u32,
                }),
            ),
            64 => (
                3,
                Range::Range64(Range64 {
                    min_value: minimum,
                    max_value: maximum,
                    step,
                }),
            ),
            _ => panic!("invalid test width"),
        };
        let parsed = Numeric {
            question_header: QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 1,
                var_store_id: 1,
                var_store_info: 2,
                question_flags: 0,
            },
            flags: width_code | display,
            location: ValueLocation::Bytes {
                offset: 2,
                size: range.size(),
            },
            data: range,
        };
        let node = Rc::new(RefCell::new(IFROperation {
            op_code: IFROpCode::Numeric,
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Numeric(parsed),
        }));
        let mut payload = vec![0; 42];
        let width = (bits / 8) as usize;
        payload[2..2 + width].copy_from_slice(&initial.to_le_bytes()[..width]);
        let (VarStoreFixture { store, efivars }, variables) = numeric_test_store(&payload);
        let current = node.borrow();
        let ParsedOperation::Numeric(parsed) = &current.parsed_data else {
            panic!("not a NUMERIC: {:?}", current.parsed_data);
        };
        let question = handle_numeric(
            store,
            parsed,
            "Numeric test",
            parsed.question_header.flags(),
            &node,
            &mut FormSetWalk::new(
                &[],
                &mut efivars.reader(),
                &MapValues(BTreeMap::new()),
                IncludedStates::empty(),
            ),
        );
        (question, variables)
    }

    fn encoded_value(bits: u32, value: i128) -> Vec<u8> {
        let width = usize::try_from(bits / 8).expect("a byte width fits usize");
        value.to_le_bytes()[..width].to_vec()
    }

    #[test]
    fn rejects_unsigned_out_of_range_values_before_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, variables) = numeric_question(bits, 10, 20, 2, 0x10, 10);
            assert!(matches!(
                change_value(&question, "9", &variables),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "21", &variables),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            for value in [
                "-1",
                "not-a-number",
                "340282366920938463463374607431768211455",
            ] {
                assert!(change_value(&question, value, &variables).is_err());
            }
            assert!(writes(&variables).is_empty());
        }
    }

    #[test]
    fn accepts_unsigned_boundaries_and_does_not_treat_step_as_a_constraint() {
        for bits in [8, 16, 32, 64] {
            for step in [0, 2] {
                for display in [0x10, 0x20] {
                    let (question, variables) = numeric_question(bits, 10, 20, step, display, 10);
                    for value in [10, 11, 20] {
                        let changed = change_value(&question, &value.to_string(), &variables);
                        if let Err(error) = changed {
                            panic!(
                                "set {value} at {bits} bits, step {step}, display {display:#x}: \
                                 {error}"
                            );
                        }
                    }
                    assert_eq!(
                        writes(&variables),
                        vec![
                            (2, encoded_value(bits, 10)),
                            (2, encoded_value(bits, 11)),
                            (2, encoded_value(bits, 20)),
                        ]
                    );
                }
            }
        }
    }

    #[test]
    fn validates_signed_bounds_and_encodes_negative_values() {
        for bits in [8, 16, 32, 64] {
            let (question, variables) =
                numeric_question(bits, (-10i64) as u64, 10, 1, 0, (-3i64) as u64);
            assert_eq!(question.value, "-3");
            assert!(matches!(
                change_value(&question, "-11", &variables),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "11", &variables),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            assert!(writes(&variables).is_empty());
            for value in [-10, 0, 10] {
                change_value(&question, &value.to_string(), &variables)
                    .unwrap_or_else(|error| panic!("set {value} at {bits} bits: {error}"));
            }
            assert_eq!(
                writes(&variables),
                vec![
                    (2, encoded_value(bits, -10)),
                    (2, encoded_value(bits, 0)),
                    (2, encoded_value(bits, 10)),
                ]
            );
        }
    }

    #[test]
    fn supports_full_signed_range_at_each_width() {
        for bits in [8, 16, 32, 64] {
            let minimum = -(1i128 << (bits - 1));
            let maximum = (1i128 << (bits - 1)) - 1;
            let (question, variables) =
                numeric_question(bits, minimum as u64, maximum as u64, 1, 0, 0);
            change_value(&question, &minimum.to_string(), &variables)
                .unwrap_or_else(|error| panic!("set {minimum} at {bits} bits: {error}"));
            change_value(&question, &maximum.to_string(), &variables)
                .unwrap_or_else(|error| panic!("set {maximum} at {bits} bits: {error}"));
            assert!(change_value(&question, &(minimum - 1).to_string(), &variables).is_err());
            assert!(change_value(&question, &(maximum + 1).to_string(), &variables).is_err());
            assert_eq!(writes(&variables).len(), 2);
        }
    }

    #[test]
    fn supports_unsigned_64_bit_values_above_signed_maximum() {
        let (question, variables) = numeric_question(64, u64::MAX - 2, u64::MAX, 1, 0x10, u64::MAX);
        assert_eq!(question.value, u64::MAX.to_string());
        change_value(&question, &u64::MAX.to_string(), &variables).expect("set u64::MAX");
        assert_eq!(
            writes(&variables),
            vec![(2, u64::MAX.to_le_bytes().to_vec())]
        );
        assert!(change_value(&question, "18446744073709551616", &variables).is_err());
        assert_eq!(writes(&variables).len(), 1);
    }

    #[test]
    fn rejects_invalid_numeric_ranges_without_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, variables) = numeric_question(bits, 20, 10, 1, 0x10, 0);
            assert!(matches!(
                change_value(&question, "15", &variables),
                Err(ChangeValueError::InvalidNumericRange)
            ));
            assert!(writes(&variables).is_empty());
        }
    }

    /// set refuses an EDKII bit varstore field, with or without a VarStore, and writes nothing.
    #[test]
    fn bit_field_question_is_not_set() {
        let one_of_children = vec![
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            one_of_option(6, 0x02, &1u32.to_le_bytes()),
        ];
        let cases = [
            (
                "18-bit NUMERIC",
                NUMERIC,
                uint32_range_question(12, 0x52),
                vec![],
                "5",
                (12, 5u32.to_le_bytes().to_vec()),
            ),
            (
                "CHECKBOX",
                CHECKBOX,
                checkbox(3, 0x00),
                vec![],
                "1",
                (3, vec![1]),
            ),
            (
                "2-bit ONE_OF",
                ONE_OF,
                uint32_range_question(8, 0x42),
                one_of_children,
                "Enabled",
                (8, 1u32.to_le_bytes().to_vec()),
            ),
        ];
        for (name, op_code, data, children, value, write) in cases {
            let set = |guid, var_store, variables: &MemoryVariables| {
                let (_root, node) = parse_question_in_guid(guid, op_code, &data, &children);
                change_value(&question_descriptor(&node, var_store), value, variables)
            };

            let (store, variables) = numeric_test_store(&[0; 42]);
            let changed = set(BIT_VARSTORE_GUID, store, &variables);
            assert!(
                matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?}: {changed:?}"
            );
            assert!(
                writes(&variables).is_empty(),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?}"
            );

            let changed = set(BIT_VARSTORE_GUID, unavailable(), &variables);
            assert!(
                matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?} without VarStore: {changed:?}"
            );

            // set writes a ONE_OF's option as change_option does, not as change_value does
            let (_root, node) =
                parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children);
            let (store, variables) = numeric_test_store(&[0; 42]);
            let question = question_descriptor(&node, store);
            for option in &question.possible_options {
                let changed = change_option(&question, option, &variables);
                assert!(
                    matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                    "{name}: change_option {:?}: {changed:?}",
                    option.value
                );
            }
            assert!(writes(&variables).is_empty(), "{name}: change_option");

            let question = question_descriptor(&node, unavailable());
            for option in &question.possible_options {
                let changed = change_option(&question, option, &variables);
                assert!(
                    matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                    "{name}: change_option {:?} without VarStore: {changed:?}",
                    option.value
                );
            }

            let other_guid = OTHER_GUID;
            let (store, variables) = numeric_test_store(&[0; 42]);
            let changed = set(other_guid, store, &variables);
            assert!(
                matches!(changed, Ok(())),
                "{name}, GUID {other_guid:02X?}: {changed:?}"
            );
            assert_eq!(
                writes(&variables),
                [write],
                "{name}, GUID {other_guid:02X?}"
            );
        }
    }

    /// encode inverts decode on every stored value of both 8-bit formats, and refuses the
    /// numbers just outside their ranges, which the `as` casts it replaced wrapped.
    #[test]
    fn encode_inverts_decode_at_8_bits() {
        for signed_type_bits in [None, Some(8)] {
            let format = NumericFormat {
                bits: 8,
                signed_type_bits,
            };
            for stored in 0..=u64::from(u8::MAX) {
                let value = format.decode(stored);
                assert_eq!(
                    format.encode(value),
                    Some(stored),
                    "{signed_type_bits:?}, stored {stored}"
                );
            }
            let outside = match signed_type_bits {
                Some(_) => [-129, 128],
                None => [-1, 256],
            };
            for value in outside {
                assert_eq!(format.encode(value), None, "{signed_type_bits:?}, {value}");
            }
        }
    }

    #[test]
    fn encode_covers_64_bits() {
        let unsigned = NumericFormat {
            bits: 64,
            signed_type_bits: None,
        };
        let signed = NumericFormat {
            bits: 64,
            signed_type_bits: Some(64),
        };
        let cases = [
            (
                "unsigned u64::MAX",
                unsigned,
                i128::from(u64::MAX),
                Some(u64::MAX),
            ),
            ("unsigned -1", unsigned, -1, None),
            (
                "signed i64::MIN",
                signed,
                i128::from(i64::MIN),
                Some(1 << 63),
            ),
            ("signed -1", signed, -1, Some(u64::MAX)),
            ("signed u64::MAX", signed, i128::from(u64::MAX), None),
        ];
        for (name, format, value, want) in cases {
            assert_eq!(format.encode(value), want, "{name}");
        }
    }
}
