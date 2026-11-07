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
use std::fmt;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::ami_access_level::AccessLevel;
use super::conditions::ExpressionRefusal;
use super::conditions::IncludedStates;
use super::conditions::ReadOnlyCause;
use super::conditions::SelectionError;
use super::defaults::OptionValueError;
use super::storage::ValueLocation;
use super::storage::VariableNotExported;
use super::storage::VariableStore;
use super::storageless::StoragelessRefusal;
use super::write_plan::batched_writes;
use super::write_plan::check_efivar_files;
use super::write_plan::BatchedWrite;
use super::write_plan::WritePlan;
use super::AnswerOption;
use super::IFROpCode;
use super::QuestionDescriptor;
use super::RangeType;
use super::TypeValue;
use crate::hii::variables::is_volatile;
use crate::hii::variables::DataPatch;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VolatileWrites;
use crate::hii::variables::VolatileWritingVariables;
use crate::hii::variables::WithheldPassword;
use crate::hii::variables::WithholdingVariables;

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
    /// A question one of whose writes overlaps the bytes of a password
    #[error("cannot set question {question:?}: {refusal}")]
    PasswordBytes {
        question: String,
        refusal: WithheldPassword,
    },
    /// A question that `cause` makes read-only, which set writes only with `lifted_with`, the
    /// states that lift `cause` where its caller can include them, else never, and
    /// `undetermined`, the states that it may be in where the selection is undetermined;
    /// `ranked_before` selects a match that ranks before it
    #[error(
        "cannot set question {question:?}: {}",
        read_only_refusal(*.cause, *.lifted_with, *.undetermined, *.ranked_before)
    )]
    ReadOnly {
        question: String,
        cause: ReadOnlyCause,
        lifted_with: Option<IncludedStates>,
        undetermined: IncludedStates,
        ranked_before: IncludedStates,
    },
    /// A value, as of a ONE_OF option of a wider type, that the question's storage cannot hold
    #[error(
        "value {value:#x} of a {value_width}-byte type does not fit in the question's \
         {storage_width}-byte storage"
    )]
    WiderThanStorage {
        value: u64,
        value_width: u8,
        storage_width: u8,
    },
    /// A ONE_OF option whose value is not known
    #[error("cannot set question {question:?} to option {option:?}: {reason}")]
    OptionValue {
        question: String,
        option: String,
        reason: OptionValueError,
    },
    #[error(transparent)]
    Selection(#[from] SelectionError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Why set refuses a question that `cause` makes read-only, with the states to include to write
/// it, if any: `lifted_with`, then `undetermined`; or to select a match that ranks
/// before it, `ranked_before`.
fn read_only_refusal(
    cause: ReadOnlyCause,
    lifted_with: Option<IncludedStates>,
    undetermined: IncludedStates,
    ranked_before: IncludedStates,
) -> String {
    let to_write = lifted_with.map(|lifted_with| match undetermined.is_empty() {
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
    /// The write of `value` in the `width` bytes of its question's storage at VarOffset `offset`
    /// of `store`, through variables of `interface`: a narrower value zero-extended, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue writes StorageWidth bytes
    /// (:2061, :2108) of a HiiValue that DisplayEngineDxe/InputHandler.c SetValuesByType fills
    /// in the option's type only (:1236-1267). Fails unless `width` is 1 to 8, `value` is a number
    /// or a BOOLEAN that fits in `width` bytes, and they fit in the Size of `store` there.
    pub(super) fn new(
        store: &'a dyn VariableStore,
        offset: u16,
        width: u8,
        value: TypeValue,
        interface: VariableInterface,
    ) -> Result<Self, ChangeValueError> {
        let (number, value_width) = match value {
            TypeValue::NumSize8(value) => (u64::from(value), 1),
            TypeValue::NumSize16(value) => (u64::from(value), 2),
            TypeValue::NumSize32(value) => (u64::from(value), 4),
            TypeValue::NumSize64(value) => (value, 8),
            TypeValue::Boolean(value) => (u64::from(value), 1),
            TypeValue::Time(_)
            | TypeValue::Date(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => {
                return Err(anyhow!("unsupported value type for {}", interface.write()).into())
            }
        };
        let bytes = number.to_le_bytes();
        let Some((encoded, rest)) = bytes
            .split_at_checked(usize::from(width))
            .filter(|(encoded, _)| !encoded.is_empty())
        else {
            return Err(anyhow!("a question's storage of {width} bytes, not 1 to 8").into());
        };
        // Setup.c:2108 writes the low StorageWidth bytes of a wider value; set refuses it instead,
        // as those bytes hold another value, where UEFI 2.11 §33.2.5.4.1 writes "the value to the
        // question's storage"
        if rest.iter().any(|&byte| byte != 0) {
            return Err(ChangeValueError::WiderThanStorage {
                value: number,
                value_width,
                storage_width: width,
            });
        }
        if usize::from(offset) + encoded.len() > usize::from(store.size()) {
            return Err(anyhow!(
                "write at offset {} with width {} exceeds varstore size {}",
                offset,
                encoded.len(),
                store.size()
            )
            .into());
        }
        Ok(Self {
            store,
            patches: vec![(offset, encoded.to_vec())],
        })
    }

    /// Writes `patches` through `variables`. choice_for_set and WritePlan::variable_writes are the
    /// only checks of runtime access before a write: they refuse a variable without
    /// EFI_VARIABLE_RUNTIME_ACCESS that the selection or the plan read, and set writes only
    /// variables that they read. Firmware refuses such a write if the variable changed since that
    /// read (edk2-stable202608 VariableServiceSetVariable, EFI_WRITE_PROTECTED).
    pub(super) fn write(&self, variables: &dyn FirmwareVariables) -> Result<()> {
        if self.patches.is_empty() {
            return Err(anyhow!("a variable write without bytes"));
        }
        let patches = self.data_patches().collect::<Vec<_>>();
        variables
            .write_patches(
                &self.store.variable_key(),
                self.store.size(),
                &patches,
                VolatileWrites::Refuse,
            )
            .map_err(|error| {
                VariableNotExported::explain(
                    error,
                    self.store,
                    variables.reach(),
                    variables.interface(),
                )
            })
    }

    /// The patches, in order.
    pub(super) fn data_patches(&self) -> impl Iterator<Item = DataPatch<'_>> {
        self.patches.iter().map(|(offset, bytes)| DataPatch {
            offset: *offset,
            bytes,
        })
    }

    /// Adds the patches of `later`, a write of the same variable, after these, through the
    /// larger of the two VarStores.
    pub(super) fn merge(&mut self, later: Self) {
        if later.store.size() > self.store.size() {
            self.store = later.store;
        }
        self.patches.extend(later.patches);
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
    let ValueLocation::Bytes { offset, size } = question.location else {
        return Err(ChangeValueError::UnsupportedBitField);
    };
    let store = question.store(reach)?;
    let value = match new_value {
        NewValue::Option(option) => option_value(question, option)?,
        NewValue::Text(text) if question.opcode == IFROpCode::OneOf => {
            let option = question
                .select_option(&BTreeSet::from([text.to_owned()]), IncludedStates::empty())?
                .ok_or(ChangeValueError::InvalidOption)?;
            option_value(question, option)?
        }
        NewValue::Text(text) => numeric_value(question, text)?,
    };
    let write = store
        .map(|store| VarStoreWrite::new(store, offset, size, value, interface))
        .transpose()?;
    Ok((value, write))
}

/// The value that set writes for `option` of the ONE_OF `question`, or why it has none.
fn option_value(
    question: &QuestionDescriptor,
    option: &AnswerOption,
) -> Result<TypeValue, ChangeValueError> {
    option
        .raw_value
        .clone()
        .map_err(|reason| ChangeValueError::OptionValue {
            question: question.question.clone(),
            option: option.value.clone(),
            reason,
        })
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
/// one question refuses leaves every variable unchanged; then it writes each variable once, with
/// the changes of every question to it (batched_writes), in order, and stops at the first write
/// that fails, with its error unchanged if it is the only write, else with NotSetEverywhere.
/// Through efivarfs it refuses, before any write, two variables of one efivar file
/// (check_efivar_files).
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

    let batch = batched_writes(writes);
    check_efivar_files(&batch, interface)?;
    let mut written = Vec::new();
    let mut unwritten = batch.iter();
    while let Some(batched) = unwritten.next() {
        let Err(error) = batched.write.write(&variables) else {
            written.push(batched.label());
            continue;
        };
        if batch.len() == 1 {
            return Err(error);
        }
        // edk2-stable202608 SetupBrowserDxe SubmitForFormSet goes on after a failed
        // RouteConfig(); set stops, as UEFI 2.11 §35.4.4 RouteConfig() reports the first failing
        // pair of a <MultiConfigResp>.
        return Err(NotSetEverywhere {
            question: question.to_owned(),
            outcome: Outcome {
                written,
                failed: FailedWrite {
                    label: batched.label(),
                    error,
                },
                not_attempted: unwritten.map(BatchedWrite::label).collect(),
            },
        }
        .into());
    }
    Ok(written_questions)
}

/// set's error when one of several writes fails.
#[derive(Error, Debug)]
#[error("question {question:?} was not set everywhere: {outcome}")]
struct NotSetEverywhere {
    question: String,
    outcome: Outcome,
}

/// How set's writes went when one failed, each by the label of its BatchedWrite: those written,
/// the one that failed with its error, and those after it, which set did not attempt.
#[derive(Debug)]
struct Outcome {
    written: Vec<String>,
    failed: FailedWrite,
    not_attempted: Vec<String>,
}

/// The write that failed, by the label of its BatchedWrite, with its error.
#[derive(Debug)]
struct FailedWrite {
    label: String,
    error: anyhow::Error,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let FailedWrite { label, error } = &self.failed;
        write!(f, "{error:#} (in {label}); written in: ")?;
        match self.written.as_slice() {
            [] => write!(f, "none")?,
            written => write!(f, "{}", written.join(", "))?,
        }
        match self.not_attempted.as_slice() {
            [] => Ok(()),
            not_attempted => write!(f, "; not attempted: {}", not_attempted.join(", ")),
        }
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod set_questions_tests {
    use std::collections::BTreeMap;

    use super::super::ifr_fixtures::*;
    use super::super::EFI_IFR_NUMERIC_SIZE_1;
    use super::super::EFI_IFR_NUMERIC_SIZE_2;
    use super::super::EFI_IFR_NUMERIC_SIZE_4;
    use super::super::EFI_IFR_NUMERIC_SIZE_8;
    use super::super::EFI_IFR_TYPE_BOOLEAN;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_16;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_32;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_64;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_8;
    use super::*;
    use crate::hii::variables::VariableKey;
    use crate::hii::variables::WithheldBytes;
    use crate::hii::variables::EFIVARFS_HEADER_SIZE;

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

    /// A ONE_OF or NUMERIC `op_code` of `size` bytes at VarOffset 0 of `var_store`, shown unsigned
    /// (EFI_IFR_DISPLAY_UINT_DEC) from 0 to its largest value, holding `children`, as set sees it.
    fn sized_on_store(
        op_code: u8,
        size: usize,
        children: &[Vec<u8>],
        var_store: VarStoreFixture,
    ) -> QuestionDescriptor {
        // EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47 EFI_IFR_NUMERIC)
        const UINT_DEC: u8 = 0x10;
        let size_flag = match size {
            1 => EFI_IFR_NUMERIC_SIZE_1,
            2 => EFI_IFR_NUMERIC_SIZE_2,
            4 => EFI_IFR_NUMERIC_SIZE_4,
            8 => EFI_IFR_NUMERIC_SIZE_8,
            other => panic!("no EFI_IFR_NUMERIC_SIZE of {other} bytes"),
        };
        let step = [vec![1], vec![0; size - 1]].concat();
        let data = [
            question_header(0),
            vec![UINT_DEC | size_flag],
            vec![0; size],
            vec![0xFF; size],
            step,
        ]
        .concat();
        let (_root, node) = parse_question(&[], op_code, &data, children);
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
        variables: &impl FirmwareVariables,
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
            &WithholdingVariables::new(variables, WithheldBytes::default()),
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
        variables: &impl FirmwareVariables,
        selected: &[(&str, &QuestionDescriptor)],
        new_value: &str,
    ) -> std::result::Result<(), String> {
        set_options(variables, selected, new_value, &[]).map(drop)
    }

    /// The writes to the variable `name`.
    fn writes(variables: &MemoryVariables, name: &str) -> Vec<(u16, Vec<u8>)> {
        variables.writes_to(&variable_key(name))
    }

    /// How NotSetEverywhere names the write of the variable `name` by the questions of the
    /// selector `name`.
    fn label(name: &str) -> String {
        format!("{name} (EFI variable {})", variable_key(name))
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

    /// set writes in order and stops at the first write that fails, which fails set: the writes
    /// before it are written, and those after it are not attempted and leave their variables
    /// unchanged. The error is named with its context.
    #[test]
    fn set_stops_at_the_first_failed_write() {
        const CHAINED: WriteError = WriteError {
            cause: "permission denied",
            context: Some("failed to write"),
        };
        let [in_a, in_b, in_c] = ["A", "B", "C"].map(label);
        let cases = [
            (
                ["A", "B", "C"],
                WRITE_ERROR,
                format!(
                    "write failed (in {in_a}); written in: none; not attempted: {in_b}, {in_c}"
                ),
                [false, false],
            ),
            (
                ["B", "A", "C"],
                WRITE_ERROR,
                format!("write failed (in {in_a}); written in: {in_b}; not attempted: {in_c}"),
                [true, false],
            ),
            (
                ["B", "C", "A"],
                WRITE_ERROR,
                format!("write failed (in {in_a}); written in: {in_b}, {in_c}"),
                [true, true],
            ),
            (
                ["A", "B", "C"],
                CHAINED,
                format!(
                    "failed to write: permission denied (in {in_a}); written in: none; not \
                     attempted: {in_b}, {in_c}"
                ),
                [false, false],
            ),
        ];
        for (order, error, outcome, [b_written, c_written]) in cases {
            let mut variables = MemoryVariables::default();
            let a = checkbox_on_store(failing_var_store("A", error, &mut variables));
            let b = checkbox_on_store(writable_var_store("B", &[0], &variables));
            let c = checkbox_on_store(writable_var_store("C", &[0], &variables));
            let questions = BTreeMap::from([("A", &a), ("B", &b), ("C", &c)]);
            let selected: Vec<(&str, &QuestionDescriptor)> =
                order.iter().map(|name| (*name, questions[name])).collect();

            assert_eq!(
                set(&variables, &selected, "1"),
                Err(format!(
                    "question \"Prompt\" was not set everywhere: {outcome}"
                )),
                "{order:?}"
            );
            for (name, written) in [("B", b_written), ("C", c_written)] {
                let want = match written {
                    true => vec![(0, vec![1])],
                    false => Vec::new(),
                };
                assert_eq!(
                    writes(&variables, name),
                    want,
                    "{order:?}: writes of {name}"
                );
                assert_eq!(
                    variables.bytes(&variable_key(name)),
                    Some(efivarfs_bytes(&[u8::from(written)])),
                    "{order:?}: {name}"
                );
            }
        }
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
        // EFI_IFR_TYPE_STRING, a type that set does not write
        let string_option = one_of_on_store(
            one_of_option(6, 0x07, &[1, 0]),
            writable_var_store("String", &[0], &variables),
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
                "B's option of Type STRING",
                &string_option,
                "unsupported value type for efivarfs write",
                "String",
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
            // EFI_IFR_TYPE_STRING, a type that set does not write
            let string_option = one_of_on_store(
                one_of_option(6, 0x07, &[1, 0]),
                writable_var_store("String", &[0], &variables),
            );
            let case = format!("{reach:?}, {interface:?}");

            assert_eq!(
                set_options(&variables, &[("B", &string_option)], "1", &["Enabled"]),
                Err(format!("unsupported value type for {write}")),
                "{case}"
            );
            assert_eq!(writes(&variables, "String"), [], "{case}: writes");
        }
    }

    /// set writes an option in all the bytes of its question's storage, as edk2-stable202608
    /// SetupBrowserDxe/Setup.c:2108 writes StorageWidth bytes: a narrower option zero-extended,
    /// also with its high bit set, and a wider-typed one whose value fits in those bytes.
    #[test]
    fn options_are_written_in_their_questions_storage_width() {
        let option = |value_type, value: &[u8]| one_of_option(6, value_type, value);
        let cases = [
            (
                "UINT8 5 in 2 bytes",
                2,
                option(EFI_IFR_TYPE_NUM_SIZE_8, &[5]),
                vec![5, 0],
            ),
            (
                "UINT8 0x85 in 2 bytes",
                2,
                option(EFI_IFR_TYPE_NUM_SIZE_8, &[0x85]),
                vec![0x85, 0],
            ),
            (
                "UINT16 0x0102 in 2 bytes",
                2,
                option(EFI_IFR_TYPE_NUM_SIZE_16, &0x0102u16.to_le_bytes()),
                vec![0x02, 0x01],
            ),
            (
                "UINT16 7 in 1 byte",
                1,
                option(EFI_IFR_TYPE_NUM_SIZE_16, &7u16.to_le_bytes()),
                vec![7],
            ),
            (
                "UINT8 5 in 4 bytes",
                4,
                option(EFI_IFR_TYPE_NUM_SIZE_8, &[5]),
                vec![5, 0, 0, 0],
            ),
            (
                "UINT16 0x8001 in 8 bytes",
                8,
                option(EFI_IFR_TYPE_NUM_SIZE_16, &0x8001u16.to_le_bytes()),
                vec![0x01, 0x80, 0, 0, 0, 0, 0, 0],
            ),
            (
                "UINT64 0x0304 in 4 bytes",
                4,
                option(EFI_IFR_TYPE_NUM_SIZE_64, &0x0304u64.to_le_bytes()),
                vec![0x04, 0x03, 0, 0],
            ),
        ];
        for (case, size, option, want) in cases {
            let variables = MemoryVariables::default();
            let store = writable_var_store("Store", &vec![0xEE; size], &variables);
            let question = sized_on_store(ONE_OF, size, &[option], store);

            assert_eq!(
                set_options(&variables, &[("Q", &question)], "", &["Enabled"]),
                Ok(vec![Some("Enabled".to_string())]),
                "{case}"
            );
            assert_eq!(writes(&variables, "Store"), [(0, want)], "{case}: writes");
        }
    }

    /// set writes a BOOLEAN option in all the bytes of its question's storage, zero-extended, as
    /// edk2-stable202608 DisplayEngineDxe/InputHandler.c SetValuesByType copies its one byte
    /// (:1243-1244) before SetupBrowserDxe/Setup.c:2108 writes StorageWidth bytes.
    #[test]
    fn boolean_options_are_written_in_their_questions_storage_width() {
        for (value, want) in [(true, vec![1, 0]), (false, vec![0, 0])] {
            let variables = MemoryVariables::default();
            let store = writable_var_store("Store", &[0xEE; 2], &variables);
            let option = one_of_option(6, EFI_IFR_TYPE_BOOLEAN, &[u8::from(value)]);
            let question = sized_on_store(ONE_OF, 2, &[option], store);

            assert_eq!(
                set_options(&variables, &[("Q", &question)], "", &["Enabled"]),
                Ok(vec![Some("Enabled".to_string())]),
                "BOOLEAN {value} in 2 bytes"
            );
            assert_eq!(
                writes(&variables, "Store"),
                [(0, want)],
                "BOOLEAN {value} in 2 bytes: writes"
            );
        }
    }

    /// set refuses an option whose value sets a byte above its question's storage other than the
    /// first, naming the option's width, and writes nothing.
    #[test]
    fn an_option_with_a_higher_byte_set_writes_no_match() {
        let variables = MemoryVariables::default();
        let wide = one_of_option(6, EFI_IFR_TYPE_NUM_SIZE_32, &0x0001_0000u32.to_le_bytes());
        let b = sized_on_store(
            ONE_OF,
            1,
            &[wide],
            writable_var_store("B", &[0xEE], &variables),
        );

        assert_eq!(
            set_options(&variables, &[("B", &b)], "", &["Enabled"]),
            Err(
                "value 0x10000 of a 4-byte type does not fit in the question's 1-byte storage"
                    .to_string()
            ),
            "B's UINT32 option 0x10000 of a 1-byte ONE_OF"
        );
        assert_eq!(writes(&variables, "B"), [], "writes of B");
    }

    /// set refuses an option whose value its question's storage cannot hold, naming both widths,
    /// before it writes any match, and leaves the stored bytes: edk2-stable202608
    /// SetupBrowserDxe/Setup.c:2108 would write the low bytes, another value.
    #[test]
    fn an_option_wider_than_its_storage_writes_no_match() {
        let variables = MemoryVariables::default();
        let a = checkbox_on_store(writable_var_store("A", &[0], &variables));
        let wide = one_of_option(6, EFI_IFR_TYPE_NUM_SIZE_16, &0x0105u16.to_le_bytes());
        let b = sized_on_store(
            ONE_OF,
            1,
            &[wide],
            writable_var_store("B", &[0xEE, 0xEE], &variables),
        );

        assert_eq!(
            set_options(&variables, &[("A", &a), ("B", &b)], "1", &["Enabled"]),
            Err(
                "value 0x105 of a 2-byte type does not fit in the question's 1-byte storage"
                    .to_string()
            ),
            "B's UINT16 option 0x105 of a 1-byte ONE_OF"
        );
        assert_eq!(writes(&variables, "A"), [], "writes of A");
        assert_eq!(writes(&variables, "B"), [], "writes of B");
        assert_eq!(
            variables.bytes(&variable_key("B")),
            Some(efivar_file_bytes(NV_BS_RT, &[0xEE, 0xEE])),
            "the bytes of B"
        );
    }

    /// set writes a NUMERIC's value in all the bytes of its storage.
    #[test]
    fn numerics_are_written_in_their_storage_width() {
        for (size, want) in [
            (1, vec![5]),
            (2, vec![5, 0]),
            (4, vec![5, 0, 0, 0]),
            (8, vec![5, 0, 0, 0, 0, 0, 0, 0]),
        ] {
            let variables = MemoryVariables::default();
            let store = writable_var_store("Store", &vec![0xEE; size], &variables);
            let question = sized_on_store(NUMERIC, size, &[], store);

            assert_eq!(
                set(&variables, &[("Q", &question)], "5"),
                Ok(()),
                "{size} bytes"
            );
            assert_eq!(
                writes(&variables, "Store"),
                [(0, want)],
                "{size} bytes: writes"
            );
        }
    }

    /// `variables` read as a withholding of a PASSWORD question's bytes that reads them as 0
    /// would read them: the data byte at `offset` of `key` reads 0; writes pass through.
    struct ZeroingByte<'v> {
        variables: &'v MemoryVariables,
        key: VariableKey,
        offset: u16,
    }

    impl ZeroingByte<'_> {
        /// `bytes` of the variable `key`, an efivarfs file's, with the byte at `offset` 0.
        fn zeroed(&self, key: &VariableKey, mut bytes: Vec<u8>) -> Vec<u8> {
            if *key == self.key {
                if let Some(byte) = bytes.get_mut(EFIVARFS_HEADER_SIZE + usize::from(self.offset)) {
                    *byte = 0;
                }
            }
            bytes
        }
    }

    impl FirmwareVariables for ZeroingByte<'_> {
        fn reach(&self) -> VariableReach {
            self.variables.reach()
        }

        fn interface(&self) -> VariableInterface {
            self.variables.interface()
        }

        fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
            Ok(self.zeroed(key, self.variables.read(key, size)?))
        }

        fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
            Ok(self.zeroed(key, self.variables.read_whole(key)?))
        }

        fn write_patches(
            &self,
            key: &VariableKey,
            size: u16,
            patches: &[DataPatch<'_>],
            volatile: VolatileWrites,
        ) -> Result<()> {
            self.variables.write_patches(key, size, patches, volatile)
        }
    }

    /// set refuses, before any write, a question one of whose patches overlaps a password's
    /// bytes, naming the question, through variables of every interface: the question before it
    /// writes nothing either, and the password's bytes stay as they are, byte for byte.
    #[test]
    fn a_patch_over_a_password_refuses_set_before_any_write() {
        // a password at byte 1 of B, between two settings
        const HELD: [u8; 3] = [0, 0xA7, 0];
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            let a = checkbox_on_store(writable_var_store("A", &[0], &variables));
            let mut b = checkbox_at(1, writable_var_store("B", &HELD, &variables));
            // as a FormSet walk names it; the fixtures leave it empty
            b.question = PROMPT.to_string();
            let mut withheld = WithheldBytes::default();
            withheld.insert(variable_key("B"), 1..2);
            let mut reader = EfivarReader::withholding(
                Box::new(MemoryVariables::new(reach, interface)),
                withheld.clone(),
            );

            let got = set_questions(
                PROMPT,
                &[("A", &a), ("B", &b)],
                "1",
                &BTreeSet::new(),
                IncludedStates::empty(),
                &mut reader,
                None,
                VolatileWrites::Refuse,
                &WithholdingVariables::new(&variables, withheld),
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"));

            assert_eq!(
                got,
                Err(format!(
                    "cannot set question \"{PROMPT}\": EFI variable {} holds a password at \
                     bytes 1..2, which set never writes",
                    variable_key("B")
                )),
                "{interface:?}"
            );
            assert_eq!(writes(&variables, "A"), [], "{interface:?}: writes of A");
            assert_eq!(writes(&variables, "B"), [], "{interface:?}: writes of B");
            assert_eq!(
                variables.bytes(&variable_key("B")),
                Some(efivarfs_bytes(&HELD)),
                "{interface:?}: B"
            );
        }
    }

    /// A write of two patches of one variable keeps the byte between them that a withholding
    /// reads as 0 as the variable holds it: the backend's read-modify-write reads the variable
    /// itself, not the view that withholds the byte.
    #[test]
    fn a_write_of_two_patches_keeps_a_withheld_byte_between_them() {
        let variables = MemoryVariables::default();
        let fixture = writable_var_store("A", &[0, 0xAA, 0], &variables);
        let store = fixture.store.as_deref().expect("VarStore A");
        let write = VarStoreWrite {
            store,
            patches: vec![(0, vec![1]), (2, vec![1])],
        };
        let zeroing = ZeroingByte {
            variables: &variables,
            key: variable_key("A"),
            offset: 1,
        };

        write.write(&zeroing).expect("write A");

        assert_eq!(
            variables.bytes(&variable_key("A")),
            Some(efivarfs_bytes(&[1, 0xAA, 1])),
            "A keeps 0xAA"
        );
    }

    /// `variables` behind firmware whose variable policy refuses a write of `key` that carries
    /// its data byte at `offset`, as edk2's VarCheck refuses data that breaks a question's
    /// constraints: that SetVariable() of a non-volatile variable saves nothing (UEFI 2.11
    /// §8.2.3).
    struct RefusingByte<'v> {
        variables: &'v MemoryVariables,
        key: VariableKey,
        offset: u16,
    }

    impl FirmwareVariables for RefusingByte<'_> {
        fn reach(&self) -> VariableReach {
            self.variables.reach()
        }

        fn interface(&self) -> VariableInterface {
            self.variables.interface()
        }

        fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
            self.variables.read(key, size)
        }

        fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
            self.variables.read_whole(key)
        }

        fn write_patches(
            &self,
            key: &VariableKey,
            size: u16,
            patches: &[DataPatch<'_>],
            volatile: VolatileWrites,
        ) -> Result<()> {
            let carries = |patch: &DataPatch<'_>| {
                let carried =
                    usize::from(patch.offset)..usize::from(patch.offset) + patch.bytes.len();
                carried.contains(&usize::from(self.offset))
            };
            if *key == self.key && patches.iter().any(carries) {
                return Err(anyhow!("EFI_SECURITY_VIOLATION"));
            }
            self.variables.write_patches(key, size, patches, volatile)
        }
    }

    /// Two questions of one variable take one write of it: a SetVariable() of a non-volatile
    /// variable saves all of its data or none (UEFI 2.11 §8.2.3), and edk2-stable202608
    /// HiiDatabaseDxe ConfigRouting.c RouteConfigRespForEfiVarStore saves a FormSet's changes to
    /// one EFI variable store in one SetVariable().
    #[test]
    fn two_questions_of_one_variable_are_written_in_one_write() {
        let variables = MemoryVariables::default();
        let first = checkbox_at(0, writable_var_store("A", &[0, 0, 0], &variables));
        let third = checkbox_at(2, writable_var_store("A", &[0, 0, 0], &variables));

        assert_eq!(
            set(&variables, &[("A", &first), ("A", &third)], "1"),
            Ok(()),
            "set"
        );
        assert_eq!(writes(&variables, "A"), [(0, vec![1, 0, 1])], "writes of A");
        assert_eq!(
            variables.bytes(&variable_key("A")),
            Some(efivarfs_bytes(&[1, 0, 1])),
            "A"
        );
    }

    /// A write that merges questions of the selectors A, B and A again is named by each of its
    /// selectors once, in question order, where it fails, is written or is not attempted.
    #[test]
    fn a_merged_write_names_each_of_its_selectors_once() {
        let merged = |name: &'static str, fails: bool| {
            [("A", name, fails), ("B", name, fails), ("A", name, fails)]
        };
        let named = |name: &str| format!("A, B (EFI variable {})", variable_key(name));
        // the selector, the variable and whether its writes fail of each question in order; the
        // outcome; and the writes of the merged variable
        let cases = [
            (
                "failed",
                [&[("W", "W", false)][..], &merged("X", true)].concat(),
                format!(
                    "write failed (in {}); written in: {}",
                    named("X"),
                    label("W")
                ),
                ("X", vec![]),
            ),
            (
                "written",
                [&merged("Y", false)[..], &[("F", "F", true)]].concat(),
                format!(
                    "write failed (in {}); written in: {}",
                    label("F"),
                    named("Y")
                ),
                ("Y", vec![(0, vec![1])]),
            ),
            (
                "not attempted",
                [&[("F", "F", true)][..], &merged("Y", false)].concat(),
                format!(
                    "write failed (in {}); written in: none; not attempted: {}",
                    label("F"),
                    named("Y")
                ),
                ("Y", vec![]),
            ),
        ];
        for (place, questions, outcome, (name, want_writes)) in cases {
            let mut variables = MemoryVariables::default();
            let descriptors: Vec<(&str, QuestionDescriptor)> = questions
                .iter()
                .map(|&(selector, name, fails)| {
                    let store = match fails {
                        true => failing_var_store(name, WRITE_ERROR, &mut variables),
                        false => writable_var_store(name, &[0], &variables),
                    };
                    (selector, checkbox_on_store(store))
                })
                .collect();
            let selected: Vec<(&str, &QuestionDescriptor)> = descriptors
                .iter()
                .map(|(selector, question)| (*selector, question))
                .collect();

            assert_eq!(
                set(&variables, &selected, "1"),
                Err(format!(
                    "question \"Prompt\" was not set everywhere: {outcome}"
                )),
                "merged write {place}"
            );
            assert_eq!(
                writes(&variables, name),
                want_writes,
                "merged write {place}: writes of {name}"
            );
        }
    }

    /// Through efivarfs, set refuses before any write two variables whose names differ only in
    /// '/' and '!', which efivarfs keeps in one file; through the other interfaces they are two
    /// variables, each written.
    #[test]
    fn variables_of_one_efivar_file_are_refused_through_efivarfs_only() {
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            let slash = checkbox_on_store(writable_var_store("A/B", &[0], &variables));
            let bang = checkbox_on_store(writable_var_store("A!B", &[0], &variables));
            let (want, want_writes) = match interface {
                VariableInterface::Efivarfs => (
                    Err(format!(
                        "the EFI variables named \"A/B\" and \"A!B\" are one efivarfs file, {}: \
                         set writes neither",
                        variable_key("A!B")
                    )),
                    vec![],
                ),
                VariableInterface::VariableServices | VariableInterface::FirmwareEnvironment => {
                    (Ok(()), vec![(0, vec![1])])
                }
            };

            assert_eq!(
                set(&variables, &[("slash", &slash), ("bang", &bang)], "1"),
                want,
                "{interface:?}"
            );
            for name in ["A/B", "A!B"] {
                assert_eq!(
                    writes(&variables, name),
                    want_writes,
                    "{interface:?}: writes of {name}"
                );
            }
        }
    }

    /// Two questions of one byte take one write, with the later question's value.
    #[test]
    fn the_later_of_two_questions_of_one_byte_wins() {
        let variables = MemoryVariables::default();
        let first = one_of_on_store(
            flagged_option(6, 0x00, 1),
            writable_var_store("A", &[0], &variables),
        );
        let second = one_of_on_store(
            flagged_option(5, 0x00, 2),
            writable_var_store("A", &[0], &variables),
        );

        assert_eq!(
            set_options(
                &variables,
                &[("first", &first), ("second", &second)],
                "",
                &["Enabled", "Disabled"]
            ),
            Ok(vec![
                Some("Enabled".to_string()),
                Some("Disabled".to_string())
            ]),
            "set"
        );
        assert_eq!(writes(&variables, "A"), [(0, vec![2])], "writes of A");
    }

    /// A write that the firmware refuses leaves its variable unchanged, though two questions
    /// change it; as the only write of set, its error is set's.
    #[test]
    fn a_refused_write_leaves_its_variable_unchanged() {
        let variables = MemoryVariables::default();
        let first = checkbox_at(0, writable_var_store("A", &[0, 0], &variables));
        let second = checkbox_at(1, writable_var_store("A", &[0, 0], &variables));
        let refusing = RefusingByte {
            variables: &variables,
            key: variable_key("A"),
            offset: 1,
        };

        let outcome = set(&refusing, &[("A", &first), ("A", &second)], "1");

        assert_eq!(
            variables.bytes(&variable_key("A")),
            Some(efivarfs_bytes(&[0, 0])),
            "A unchanged"
        );
        assert_eq!(writes(&variables, "A"), [], "writes of A");
        assert_eq!(outcome, Err("EFI_SECURITY_VIOLATION".to_string()), "set");
    }

    /// A write of two questions of one variable keeps a byte between them that a withholding
    /// reads as 0 as the variable holds it.
    #[test]
    fn a_write_of_two_questions_keeps_a_withheld_byte_between_them() {
        let variables = MemoryVariables::default();
        let first = checkbox_at(0, writable_var_store("A", &[0, 0xAA, 0], &variables));
        let third = checkbox_at(2, writable_var_store("A", &[0, 0xAA, 0], &variables));
        let zeroing = ZeroingByte {
            variables: &variables,
            key: variable_key("A"),
            offset: 1,
        };

        assert_eq!(
            set(&zeroing, &[("A", &first), ("A", &third)], "1"),
            Ok(()),
            "set"
        );
        assert_eq!(
            variables.bytes(&variable_key("A")),
            Some(efivarfs_bytes(&[1, 0xAA, 1])),
            "A keeps 0xAA"
        );
    }

    /// Two VarStores of one variable, of 2 and 4 bytes, on a variable of 3: the one write of
    /// both questions checks the larger Size, and writes nothing, as the larger one's question
    /// alone would.
    #[test]
    fn a_batch_checks_the_largest_var_store_of_its_variable() {
        let variables = MemoryVariables::default();
        let first = checkbox_at(0, writable_var_store("A", &[0, 0], &variables));
        let second = checkbox_at(1, writable_var_store("A", &[0, 0, 0, 0], &variables));
        variables.insert(variable_key("A"), NV_BS_RT, &[0, 0, 0]);

        let outcome = set(&variables, &[("A", &first), ("A", &second)], "1");

        assert!(
            outcome
                .as_ref()
                .is_err_and(|error| error.contains("shorter than the declared varstore: 3 < 4")),
            "set: {outcome:?}"
        );
        assert_eq!(writes(&variables, "A"), [], "writes of A");
        assert_eq!(
            variables.bytes(&variable_key("A")),
            Some(efivarfs_bytes(&[0, 0, 0])),
            "A unchanged"
        );
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
                &ListTexts::new(&[], &[]),
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
