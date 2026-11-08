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

//! set's writes of one question, planned before the first: a browser sets THIS to the new value,
//! evaluates the question's WRITE expression, whose SETs change its edit buffers, then stores the
//! value (UEFI 2.11 §33.2.5.4.1; edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue).
//! edk2-stable202608 SetupBrowserDxe/Setup.c SubmitForForm then routes only the bytes of the
//! form's questions, dropping SET bytes that no question covers; set writes every SET, as UEFI
//! 2.11 §33.3.8.3.66 stores the value in the VarStore.

use std::cell::RefCell;
use std::rc::Rc;
use std::rc::Weak;

use anyhow::anyhow;
use anyhow::Result;
use thiserror::Error;

use super::check_writable;
use super::conditions::evaluate_write;
use super::conditions::ExpressionInputs;
use super::conditions::PlannedSet;
use super::conditions::QuestionValue;
use super::conditions::VarStoreValues;
use super::set::own_write;
use super::set::ChangeValueError;
use super::set::NewValue;
use super::set::VarStoreWrite;
use super::storage::VariableStore;
use super::unwritable;
use super::AccessLevel;
use super::EfivarReader;
use super::IFROpCode;
use super::IFROperation;
use super::QuestionDescriptor;
use super::StoragelessRefusal;
use crate::hii::variables::EfivarRange;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VolatileWrites;

/// The writes that set one question: the SETs of its WRITE expression, in order, then its own
/// value, which wins where they overlap.
pub(super) struct WritePlan<'a> {
    question: &'a QuestionDescriptor,
    sets: Vec<PlannedSet>,
    own: Option<VarStoreWrite<'a>>,
}

impl<'a> WritePlan<'a> {
    /// The plan that sets `question` to `new_value` through variables of `reach` and
    /// `interface`, evaluating its WRITE expression with values read through `reader`, whose
    /// conditions read `access_level`, if stated, for AMI_ACCESS_LEVEL.
    pub(super) fn new(
        question: &'a QuestionDescriptor,
        new_value: NewValue<'_>,
        (reach, interface): (VariableReach, VariableInterface),
        reader: &mut EfivarReader,
        access_level: Option<AccessLevel>,
    ) -> Result<Self, ChangeValueError> {
        let (value, own) = own_write(question, new_value, reach, interface)?;
        let Some(value) = value.as_u64() else {
            return Err(anyhow!("unsupported value type for {}", interface.write()).into());
        };
        // a CHECKBOX's value is a BOOLEAN, which set writes as 0 or 1
        let this = match question.opcode == IFROpCode::CheckBox {
            true => QuestionValue::Boolean(u8::from(value != 0)),
            false => QuestionValue::Uint(value),
        };
        let values = VarStoreValues::new(&root_of(&question.node), access_level);
        let sets = evaluate_write(
            &question.node,
            this,
            &mut ExpressionInputs {
                reader,
                values: &values,
            },
        )
        .map_err(|refusal| ChangeValueError::Expression {
            question: question.question.clone(),
            refusal,
        })?
        .unwrap_or_default();
        if own.is_none() && sets.is_empty() {
            return Err(ChangeValueError::Storageless {
                question: question.question.clone(),
                refusal: StoragelessRefusal::WriteSetsNothing,
            });
        }
        Ok(Self {
            question,
            sets,
            own,
        })
    }

    /// The plan's writes, one per variable, in the order in which the plan first changes each,
    /// each of its patches in order. Refuses a SET of a VarStore whose variable set may not
    /// write, through what `reader` read of it, under `volatile`, and a write whose span overlaps
    /// the bytes of a password that `reader` withholds, so that set writes no variable of the
    /// plan.
    pub(super) fn variable_writes(
        &self,
        reader: &mut EfivarReader,
        volatile: VolatileWrites,
    ) -> Result<Vec<VarStoreWrite<'_>>, ChangeValueError> {
        let (reach, interface) = (reader.reach(), reader.interface());
        for set in &self.sets {
            let store = set.store.as_ref();
            let range = usize::from(set.offset)..usize::from(set.offset) + set.bytes.len();
            let checked = match reader.read(EfivarRange::of(store), range) {
                Ok(_) => check_writable(store, reader, volatile),
                Err(error) => Err(unwritable(store, error, reach, interface)),
            };
            checked.map_err(|error| ChangeValueError::Expression {
                question: self.question.question.clone(),
                refusal: set.unwritable(format!("which set may not write: {error:#}")),
            })?;
        }
        let patches = self
            .sets
            .iter()
            .map(|set| Patch {
                store: set.store.as_ref(),
                offset: set.offset,
                bytes: &set.bytes,
            })
            .chain(self.own.iter().flat_map(|write| {
                write.patches.iter().map(|(offset, bytes)| Patch {
                    store: write.store,
                    offset: *offset,
                    bytes,
                })
            }));
        let mut variables: Vec<(VariableKey, Vec<Patch<'_>>)> = Vec::new();
        for patch in patches {
            let key = patch.store.variable_key();
            match variables.iter_mut().find(|(variable, _)| *variable == key) {
                Some((_, patches)) => patches.push(patch),
                None => variables.push((key, vec![patch])),
            }
        }
        let writes = variables
            .into_iter()
            .map(|(_, patches)| merged_write(&patches))
            .collect::<Result<Vec<_>, _>>()?;
        for write in &writes {
            if let Some((start, end)) = write.changed() {
                reader
                    .check_write(&write.store.variable_key(), &(usize::from(start)..end))
                    .map_err(|refusal| ChangeValueError::PasswordBytes {
                        question: self.question.question.clone(),
                        refusal,
                    })?;
            }
        }
        Ok(writes)
    }
}

/// Bytes that a plan writes at VarOffset `offset` of `store`.
struct Patch<'p> {
    store: &'p dyn VariableStore,
    offset: u16,
    bytes: &'p [u8],
}

/// The one write of `patches`, all of one variable, in order, through the largest of their
/// VarStores.
fn merged_write<'p>(patches: &[Patch<'p>]) -> Result<VarStoreWrite<'p>, ChangeValueError> {
    let [first, rest @ ..] = patches else {
        return Err(anyhow!("a variable write without bytes").into());
    };
    let store = rest.iter().fold(first.store, |largest, patch| {
        match patch.store.size() > largest.size() {
            true => patch.store,
            false => largest,
        }
    });
    Ok(VarStoreWrite {
        store,
        patches: patches
            .iter()
            .map(|patch| (patch.offset, patch.bytes.to_vec()))
            .collect(),
    })
}

/// Writes `writes` through `variables` in order, stopping at the first that fails.
pub(super) fn write_in_turn(
    writes: &[VarStoreWrite<'_>],
    variables: &dyn FirmwareVariables,
) -> Result<()> {
    for (index, write) in writes.iter().enumerate() {
        if let Err(error) = write.write(variables) {
            let written: Vec<VariableKey> = writes
                .iter()
                .take(index)
                .map(|write| write.store.variable_key())
                .collect();
            return Err(match written.is_empty() {
                true => error,
                false => PartlyWritten { error, written }.into(),
            });
        }
    }
    Ok(())
}

/// A write of a question that failed after set wrote other variables for it.
#[derive(Debug, Error)]
#[error("{error:#}; set already wrote {}", written_keys(.written))]
struct PartlyWritten {
    error: anyhow::Error,
    written: Vec<VariableKey>,
}

/// `keys`, as PartlyWritten names them.
fn written_keys(keys: &[VariableKey]) -> String {
    keys.iter()
        .map(|key| format!("EFI variable {key}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns the root of the tree of `node`.
fn root_of(node: &Rc<RefCell<IFROperation>>) -> Rc<RefCell<IFROperation>> {
    let mut node = Rc::clone(node);
    loop {
        let parent = node.borrow().parent.as_ref().and_then(Weak::upgrade);
        match parent {
            Some(parent) => node = parent,
            None => return node,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use super::super::ifr_fixtures::*;
    #[cfg(efivar_dumps)]
    use super::super::set::VarStoreWrite;
    use super::super::*;
    #[cfg(efivar_dumps)]
    use super::write_in_turn;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::hii::variables::check_non_volatile;
    use crate::hii::variables::WithheldBytes;
    use crate::hii::variables::WithholdingVariables;

    const AND: u8 = 0x15;
    const SET: u8 = 0x2C;
    const ADD: u8 = 0x3A;
    const UINT16: u8 = 0x43;
    const TO_UINT: u8 = 0x48;
    const UNDEFINED: u8 = 0x55;
    const THIS: u8 = 0x58;

    /// The variables of each backend: Linux, the UEFI Shell and Windows.
    const EFIVARFS: (VariableReach, VariableInterface) =
        (VariableReach::Runtime, VariableInterface::Efivarfs);
    const VARIABLE_SERVICES: (VariableReach, VariableInterface) = (
        VariableReach::BootServices,
        VariableInterface::VariableServices,
    );
    const FIRMWARE_ENVIRONMENT: (VariableReach, VariableInterface) = (
        VariableReach::Runtime,
        VariableInterface::FirmwareEnvironment,
    );

    /// The VARSTORE_EFI of 6 bytes that the questions keep their values in.
    const STORE: u16 = 1;
    /// A VARSTORE_EFI of 2 bytes.
    const OTHER: u16 = 2;
    /// A VARSTORE whose variable does not exist.
    const ABSENT: u16 = 3;
    /// A VARSTORE_EFI, and its variable, without EFI_VARIABLE_RUNTIME_ACCESS.
    const BOOT_ONLY: u16 = 4;
    /// A VARSTORE of 3 bytes on the variable of STORE.
    const SHORT: u16 = 5;
    /// VARSTORE_EFIs whose variables have EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, with
    /// metadata that get accepts and with none.
    const ENHANCED: u16 = 6;
    const BAD_METADATA: u16 = 7;
    /// The attributes of the variables of ENHANCED and BAD_METADATA.
    const NV_BS_RT_ENHANCED: u32 = NV_BS_RT | 0x80;
    /// A VARSTORE_EFI, and its variable, without EFI_VARIABLE_NON_VOLATILE.
    const VOLATILE: u16 = 8;
    /// The bytes of the variables of STORE, OTHER, BOOT_ONLY and VOLATILE before set.
    const STORE_BYTES: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    const OTHER_BYTES: [u8; 2] = [0xB0, 0xB1];
    const BOOT_ONLY_BYTES: [u8; 1] = [0xC0];
    const VOLATILE_BYTES: [u8; 1] = [0xD0];

    /// Each question of the FormSet: its prompt, VarStore, VarOffset and the ops in its scope.
    fn questions() -> Vec<(&'static str, u16, u16, Vec<u8>)> {
        let op = |op_code| operation(op_code, false, &[]);
        let set = |id: u16, offset: u16, value_type: u8| {
            let data = [&id.to_le_bytes()[..], &offset.to_le_bytes(), &[value_type]].concat();
            operation(SET, false, &data)
        };
        let write = |ops: &[Vec<u8>]| [op(WRITE), scoped_expression(ops, 0)].concat();
        let value_of_1 = [operation(VALUE, true, &[]), uint8(1), END.to_vec()].concat();
        vec![
            (
                "Linked",
                STORE,
                0,
                write(&[
                    op(THIS),
                    set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8),
                    op(THIS),
                    operation(UINT16, false, &0x100u16.to_le_bytes()),
                    op(ADD),
                    set(STORE, 4, EFI_IFR_TYPE_NUM_SIZE_16),
                    op(AND),
                ]),
            ),
            (
                "Other store",
                STORE,
                1,
                write(&[op(THIS), set(OTHER, 0, EFI_IFR_TYPE_NUM_SIZE_16)]),
            ),
            (
                "Overlap",
                STORE,
                3,
                write(&[uint8(0x77), set(STORE, 3, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Absent target",
                STORE,
                5,
                write(&[op(THIS), set(ABSENT, 0, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Storageless",
                0,
                0,
                write(&[op(THIS), set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Unevaluated",
                STORE,
                0,
                write(&[
                    uint8(1),
                    op(TO_UINT),
                    set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8),
                ]),
            ),
            (
                "Boot only target",
                STORE,
                0,
                write(&[op(THIS), set(BOOT_ONLY, 0, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Undefined after a SET",
                STORE,
                0,
                write(&[
                    op(THIS),
                    set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8),
                    op(UNDEFINED),
                    set(STORE, 4, EFI_IFR_TYPE_NUM_SIZE_8),
                    op(AND),
                ]),
            ),
            (
                "Absent after a SET",
                STORE,
                0,
                write(&[
                    op(THIS),
                    set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8),
                    op(THIS),
                    set(ABSENT, 0, EFI_IFR_TYPE_NUM_SIZE_8),
                    op(AND),
                ]),
            ),
            (
                "Short store",
                STORE,
                4,
                write(&[op(THIS), set(SHORT, 0, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            ("No write", STORE, 0, Vec::new()),
            (
                "Value and write",
                0,
                0,
                [
                    value_of_1.clone(),
                    write(&[op(THIS), set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8)]),
                ]
                .concat(),
            ),
            ("Stored value", STORE, 1, value_of_1),
            (
                "Enhanced target",
                STORE,
                0,
                write(&[op(THIS), set(ENHANCED, 0, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Bad metadata target",
                STORE,
                0,
                write(&[op(THIS), set(BAD_METADATA, 0, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Volatile target",
                STORE,
                0,
                write(&[op(THIS), set(VOLATILE, 0, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
            (
                "Volatile store",
                VOLATILE,
                0,
                write(&[op(THIS), set(STORE, 2, EFI_IFR_TYPE_NUM_SIZE_8)]),
            ),
        ]
    }

    /// The string ID of the first prompt of questions(); the others follow.
    const FIRST_PROMPT: u16 = 10;

    /// The FormSet of questions(): each a UINT8 NUMERIC from 0 to 255 holding its WRITE.
    fn form_set() -> Rc<RefCell<IFROperation>> {
        let body: Vec<Vec<u8>> = (1..)
            .zip(questions())
            .map(|(id, (_, var_store_id, offset, write))| {
                let data = [
                    question_header_with(id, FIRST_PROMPT + id - 1, var_store_id, offset, 0),
                    // EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC, MinValue, MaxValue, Step
                    vec![0x10, 0, 255, 1],
                ]
                .concat();
                [operation(NUMERIC, true, &data), write, END.to_vec()].concat()
            })
            .collect();
        parse_form_set(&[
            var_store_efi(STORE, "Store", NV_BS_RT, 6),
            var_store_efi(OTHER, "Other", NV_BS_RT, 2),
            var_store(ABSENT, [0; 16], "Absent", 1),
            var_store_efi(BOOT_ONLY, "BootOnly", NV_BS, 1),
            var_store(SHORT, [0; 16], "Store", 3),
            var_store_efi(ENHANCED, "Enhanced", NV_BS_RT_ENHANCED, 1),
            var_store_efi(BAD_METADATA, "BadMetadata", NV_BS_RT_ENHANCED, 1),
            var_store_efi(VOLATILE, "Volatile", BS_RT, 1),
            form(1, &body),
        ])
    }

    fn key(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: NIL_GUID,
        }
    }

    /// Variables of `(reach, interface)` holding STORE, OTHER, BOOT_ONLY, ENHANCED,
    /// BAD_METADATA and VOLATILE as before set.
    fn variables((reach, interface): (VariableReach, VariableInterface)) -> MemoryVariables {
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(key("Store"), NV_BS_RT, &STORE_BYTES);
        variables.insert(key("Other"), NV_BS_RT, &OTHER_BYTES);
        variables.insert(key("BootOnly"), NV_BS, &BOOT_ONLY_BYTES);
        variables.insert(
            key("Enhanced"),
            NV_BS_RT_ENHANCED,
            &[&timestamp_metadata()[..], &[0xD0]].concat(),
        );
        variables.insert(key("BadMetadata"), NV_BS_RT_ENHANCED, &[0xE0]);
        variables.insert(key("Volatile"), BS_RT, &VOLATILE_BYTES);
        variables
    }

    /// The data offsets and bytes of the writes to each variable, by name.
    type Written = BTreeMap<&'static str, Vec<(u16, Vec<u8>)>>;

    /// The strings of form_set(): the prompts of questions().
    fn prompts() -> Vec<StringMap> {
        vec![(FIRST_PROMPT..)
            .zip(questions().into_iter().map(|(prompt, ..)| Rc::from(prompt)))
            .collect()]
    }

    /// The outcome of set of `prompt` to `value` through variables of `through`, as the CLI
    /// prints an error, and the writes to each variable.
    fn set(
        prompt: &str,
        value: &str,
        through: (VariableReach, VariableInterface),
    ) -> (Result<(), String>, Written) {
        set_in(&form_set(), &prompts(), prompt, value, through)
    }

    /// set() of `prompt` in the FormSet `root`, whose strings are `strings`.
    fn set_in(
        root: &Rc<RefCell<IFROperation>>,
        strings: &[StringMap],
        prompt: &str,
        value: &str,
        through: (VariableReach, VariableInterface),
    ) -> (Result<(), String>, Written) {
        let (outcome, written) = set_under(
            root,
            strings,
            prompt,
            value,
            through,
            VolatileWrites::Refuse,
        );
        (outcome.map(drop), written)
    }

    /// set_in() under `volatile`, with whether the writes of each question include a volatile
    /// variable.
    fn set_under(
        root: &Rc<RefCell<IFROperation>>,
        strings: &[StringMap],
        prompt: &str,
        value: &str,
        through: (VariableReach, VariableInterface),
        volatile: VolatileWrites,
    ) -> (Result<Vec<bool>, String>, Written) {
        let mut reader = EfivarReader::with_variables(Box::new(variables(through)));
        let values = VarStoreValues::new(root, None);
        let selection = find_question_in(
            root,
            &BTreeSet::from([prompt]),
            &mut FormSetWalk::new(strings, &mut reader, &values, IncludedStates::empty()),
        );
        // set refuses a read-only question as it picks it, before it plans any write
        let options = SetOptions {
            volatile,
            ..SetOptions::default()
        };
        let descriptor =
            match choice_for_set(selection, prompt, &options, IncludedStates::all(), &reader) {
                Ok(Choice::Chosen(descriptor, _)) => descriptor,
                Ok(Choice::Skipped(states)) => panic!("{prompt}: not picked, {states}"),
                Err(error) => return (Err(format!("{error:#}")), BTreeMap::new()),
            };
        let writes = variables(through);
        let outcome = set_questions(
            prompt,
            &[("selector", &descriptor)],
            value,
            &BTreeSet::from([value.to_string()]),
            IncludedStates::empty(),
            &mut reader,
            None,
            volatile,
            &WithholdingVariables::new(&writes, WithheldBytes::default()),
        )
        .map(|written| written.iter().map(|question| question.volatile).collect())
        .map_err(|error| format!("{error:#}"));
        let written = [
            "Store",
            "Other",
            "BootOnly",
            "Absent",
            "Enhanced",
            "BadMetadata",
            "Volatile",
        ]
        .into_iter()
        .map(|name| (name, writes.writes_to(&key(name))))
        .filter(|(_, writes)| !writes.is_empty())
        .collect();
        (outcome, written)
    }

    /// set writes a UINT8 option of a UINT16 ONE_OF in both bytes of its storage, zero-extended, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c:2108 writes StorageWidth bytes.
    #[test]
    fn narrow_option_writes_the_questions_storage_width() {
        let header = question_header_with(1, FIRST_PROMPT, STORE, 2, 0);
        let one_of = [
            // Flags UINT16 EFI_IFR_DISPLAY_UINT_DEC, MinValue 0, MaxValue 0xFFFF, Step 0
            operation(
                ONE_OF,
                true,
                &[header, vec![0x11, 0, 0, 0xFF, 0xFF, 0, 0]].concat(),
            ),
            one_of_option(FIRST_PROMPT + 1, EFI_IFR_TYPE_NUM_SIZE_8, &[5]),
            one_of_option(FIRST_PROMPT + 2, EFI_IFR_TYPE_NUM_SIZE_16, &[0x05, 0x01]),
            END.to_vec(),
        ]
        .concat();
        let root = parse_form_set(&[
            var_store_efi(STORE, "Store", NV_BS_RT, 6),
            form(1, &[one_of]),
        ]);
        let strings = vec![StringMap::from([
            (FIRST_PROMPT, "Width".into()),
            (FIRST_PROMPT + 1, "Narrow".into()),
            (FIRST_PROMPT + 2, "Wide".into()),
        ])];
        let got = set_in(&root, &strings, "Width", "Narrow", EFIVARFS);
        assert_eq!(
            got,
            (
                Ok(()),
                BTreeMap::from([("Store", vec![(2, vec![0x05, 0x00])])])
            ),
            "Width = Narrow"
        );
    }

    /// set writes the SETs of a question's WRITE expression and its own value with one write
    /// per variable, through its largest VarStore, from the first byte that they change to the
    /// last, keeping the bytes between; the question's own value wins where a SET overlaps it,
    /// as a browser stores it after its WRITE (edk2-stable202608 SetupBrowserDxe/Setup.c
    /// SetQuestionValue).
    #[test]
    fn set_writes_each_variable_once_with_its_sets_and_value() {
        let cases = [
            (
                "Linked",
                "5",
                vec![("Store", vec![(0, vec![5, 0xA1, 5, 0xA3, 0x05, 0x01])])],
            ),
            (
                "Other store",
                "18",
                vec![
                    ("Other", vec![(0, vec![18, 0])]),
                    ("Store", vec![(1, vec![18])]),
                ],
            ),
            ("Overlap", "9", vec![("Store", vec![(3, vec![9])])]),
            ("Storageless", "7", vec![("Store", vec![(2, vec![7])])]),
            (
                "Undefined after a SET",
                "6",
                vec![("Store", vec![(0, vec![6, 0xA1, 6])])],
            ),
            ("No write", "4", vec![("Store", vec![(0, vec![4])])]),
            (
                "Short store",
                "8",
                vec![("Store", vec![(0, vec![8, 0xA1, 0xA2, 0xA3, 8])])],
            ),
        ];
        for through in [EFIVARFS, VARIABLE_SERVICES, FIRMWARE_ENVIRONMENT] {
            for (prompt, value, want) in &cases {
                assert_eq!(
                    set(prompt, value, through),
                    (Ok(()), want.iter().cloned().collect()),
                    "{prompt} = {value} through {through:?}"
                );
            }
        }
    }

    /// Before a WRITE that writes the bytes on both sides of a password in one write, set refuses
    /// it through variables of every backend, writing nothing: that write would carry the
    /// password's bytes, which questions read as zero, back into the variable.
    #[test]
    fn a_write_across_a_password_writes_nothing() {
        let op = |op_code| operation(op_code, false, &[]);
        let set_op = |id: u16, offset: u16| {
            let data = [
                &id.to_le_bytes()[..],
                &offset.to_le_bytes(),
                &[EFI_IFR_TYPE_NUM_SIZE_8],
            ]
            .concat();
            operation(SET, false, &data)
        };
        // a PASSWORD of MaxSize 1 at byte 1 of Store: bytes 1..3
        let password = operation(
            PASSWORD,
            false,
            &[
                question_header_with(2, FIRST_PROMPT + 1, STORE, 1, 0),
                vec![1, 0, 1, 0],
            ]
            .concat(),
        );
        // a UINT8 NUMERIC at byte 0 whose WRITE also sets byte 4
        let around = [
            operation(
                NUMERIC,
                true,
                &[
                    question_header_with(1, FIRST_PROMPT, STORE, 0, 0),
                    vec![0x10, 0, 255, 1],
                ]
                .concat(),
            ),
            op(WRITE),
            scoped_expression(&[op(THIS), set_op(STORE, 4)], 0),
            END.to_vec(),
        ]
        .concat();
        let root = parse_form_set(&[
            var_store_efi(STORE, "Store", NV_BS_RT, 6),
            form(1, &[password, around]),
        ]);
        let strings = vec![StringMap::from([
            (FIRST_PROMPT, "Around".into()),
            (FIRST_PROMPT + 1, "Password".into()),
        ])];
        let passwords = PasswordQuestions::of([&root]);

        for through in [EFIVARFS, VARIABLE_SERVICES, FIRMWARE_ENVIRONMENT] {
            let mut reader = passwords
                .reader(Box::new(variables(through)))
                .expect("resolve the VarStore of the PASSWORD question");
            let values = VarStoreValues::new(&root, None);
            let selection = find_question_in(
                &root,
                &BTreeSet::from(["Around"]),
                &mut FormSetWalk::new(&strings, &mut reader, &values, IncludedStates::empty()),
            );
            let Selection::Picked {
                picked: (descriptor, _),
                ..
            } = &selection
            else {
                panic!("Around: not picked through {through:?}");
            };
            let writes = variables(through);
            let outcome = set_questions(
                "Around",
                &[("selector", descriptor)],
                "5",
                &BTreeSet::from(["5".to_string()]),
                IncludedStates::empty(),
                &mut reader,
                None,
                VolatileWrites::Refuse,
                &passwords
                    .withholding(&writes)
                    .expect("resolve the VarStore of the PASSWORD question"),
            )
            .map(|_| ())
            .map_err(|error| format!("{error:#}"));

            assert!(
                outcome.as_ref().is_err_and(|error| error
                    .contains("holds a password at bytes 1..3, which set never writes")),
                "through {through:?}: {outcome:?}"
            );
            assert_eq!(
                writes.writes_to(&key("Store")),
                [],
                "writes through {through:?}"
            );
        }
    }

    /// set of the UINT8 NUMERIC Around, at byte `own` of Store, to 5 through variables of
    /// `through`, beside a PASSWORD of MaxSize 1 at bytes 1..3 of Store: its WRITE expression sets
    /// Other's UINT16 at 0, then Store's `set_type` at `set_at`. The outcome as the CLI prints an
    /// error, and the writes to Other and Store.
    fn set_around_a_password(
        own: u16,
        set_at: u16,
        set_type: u8,
        through: (VariableReach, VariableInterface),
    ) -> (Result<(), String>, Written) {
        let op = |op_code| operation(op_code, false, &[]);
        let set_op = |id: u16, offset: u16, value_type: u8| {
            let data = [&id.to_le_bytes()[..], &offset.to_le_bytes(), &[value_type]].concat();
            operation(SET, false, &data)
        };
        let password = operation(
            PASSWORD,
            false,
            &[
                question_header_with(2, FIRST_PROMPT + 1, STORE, 1, 0),
                vec![1, 0, 1, 0],
            ]
            .concat(),
        );
        let around = [
            operation(
                NUMERIC,
                true,
                &[
                    question_header_with(1, FIRST_PROMPT, STORE, own, 0),
                    vec![0x10, 0, 255, 1],
                ]
                .concat(),
            ),
            op(WRITE),
            scoped_expression(
                &[
                    op(THIS),
                    set_op(OTHER, 0, EFI_IFR_TYPE_NUM_SIZE_16),
                    op(THIS),
                    set_op(STORE, set_at, set_type),
                    op(AND),
                ],
                0,
            ),
            END.to_vec(),
        ]
        .concat();
        let root = parse_form_set(&[
            var_store_efi(STORE, "Store", NV_BS_RT, 6),
            var_store_efi(OTHER, "Other", NV_BS_RT, 2),
            form(1, &[password, around]),
        ]);
        let strings = vec![StringMap::from([
            (FIRST_PROMPT, "Around".into()),
            (FIRST_PROMPT + 1, "Password".into()),
        ])];
        let passwords = PasswordQuestions::of([&root]);
        let mut reader = passwords
            .reader(Box::new(variables(through)))
            .expect("resolve the VarStore of the PASSWORD question");
        let values = VarStoreValues::new(&root, None);
        let selection = find_question_in(
            &root,
            &BTreeSet::from(["Around"]),
            &mut FormSetWalk::new(&strings, &mut reader, &values, IncludedStates::empty()),
        );
        let Selection::Picked {
            picked: (descriptor, _),
            ..
        } = &selection
        else {
            panic!("Around: not picked through {through:?}");
        };
        let writes = variables(through);
        let outcome = set_questions(
            "Around",
            &[("selector", descriptor)],
            "5",
            &BTreeSet::from(["5".to_string()]),
            IncludedStates::empty(),
            &mut reader,
            None,
            VolatileWrites::Refuse,
            &passwords
                .withholding(&writes)
                .expect("resolve the VarStore of the PASSWORD question"),
        )
        .map(|_| ())
        .map_err(|error| format!("{error:#}"));
        let written = ["Other", "Store"]
            .into_iter()
            .map(|name| (name, writes.writes_to(&key(name))))
            .collect();
        (outcome, written)
    }

    /// A WRITE expression whose first SET changes Other, and whose bytes in Store, with the
    /// question's own, span a password, across it or by its first or last byte only: set refuses
    /// before any write, Other's too, naming the question. A span beside the password writes both.
    #[test]
    fn a_write_plan_across_a_password_writes_no_other_variable() {
        let refused = || {
            (
                Err("cannot set question \"Around\": EFI variable \
                     Store-00000000-0000-0000-0000-000000000000 holds a password at bytes 1..3, \
                     which set never writes"
                    .to_string()),
                BTreeMap::from([("Other", vec![]), ("Store", vec![])]),
            )
        };
        // the span in Store, the question's own byte, and the offset and type of its SET of Store
        let cases = [
            ("0..5, across", 0, 4, EFI_IFR_TYPE_NUM_SIZE_8, refused()),
            (
                "0..2, its last byte",
                0,
                0,
                EFI_IFR_TYPE_NUM_SIZE_16,
                refused(),
            ),
            (
                "2..5, its first byte",
                4,
                2,
                EFI_IFR_TYPE_NUM_SIZE_8,
                refused(),
            ),
            (
                "3..5, beside it",
                4,
                3,
                EFI_IFR_TYPE_NUM_SIZE_8,
                (
                    Ok(()),
                    BTreeMap::from([
                        ("Other", vec![(0, vec![5, 0])]),
                        ("Store", vec![(3, vec![5, 5])]),
                    ]),
                ),
            ),
        ];
        for (span, own, set_at, set_type, want) in cases {
            for through in [EFIVARFS, VARIABLE_SERVICES, FIRMWARE_ENVIRONMENT] {
                assert_eq!(
                    set_around_a_password(own, set_at, set_type, through),
                    want,
                    "Store span {span} through {through:?}"
                );
            }
        }
    }

    /// A WRITE expression with a SET of a VarStore whose variable set may not write, or one that
    /// cannot be evaluated, refuses set before any write, the question's own value too.
    #[test]
    fn a_write_plan_that_refuses_writes_nothing() {
        let absent = |prompt: &'static str, through: (VariableReach, VariableInterface)| {
            (
                through,
                prompt,
                format!(
                    "cannot set question \"{prompt}\": its WRITE expression sets VarStore \
                     0x0003 (EFI_IFR_VARSTORE \"Absent\"), which set may not write: no EFI \
                     variable Absent-00000000-0000-0000-0000-000000000000: {}",
                    through.1.not_found_refusal()
                ),
            )
        };
        let cases = [
            absent("Absent target", EFIVARFS),
            absent("Absent target", VARIABLE_SERVICES),
            absent("Absent target", FIRMWARE_ENVIRONMENT),
            // the SET of STORE before the refused one is not written either
            absent("Absent after a SET", EFIVARFS),
            absent("Absent after a SET", VARIABLE_SERVICES),
            absent("Absent after a SET", FIRMWARE_ENVIRONMENT),
            (
                EFIVARFS,
                "Unevaluated",
                "cannot set question \"Unevaluated\": its WRITE expression uses EFI_IFR_TO_UINT, \
                 which uefisettings does not evaluate"
                    .to_string(),
            ),
            (
                EFIVARFS,
                "Boot only target",
                format!(
                    "cannot set question \"Boot only target\": its WRITE expression sets VarStore \
                     0x0004 (EFI_IFR_VARSTORE_EFI \"BootOnly\"), which set may not write: {:#}",
                    check_runtime_writable(&key("BootOnly"), VariableReach::Runtime, NV_BS)
                        .expect_err("refuse a boot-service-only variable at OS runtime")
                ),
            ),
        ];
        // an EFI_IFR_VALUE makes a question read-only, also one with a WRITE
        let read_only = ["Value and write", "Stored value"].map(|prompt| {
            [EFIVARFS, VARIABLE_SERVICES, FIRMWARE_ENVIRONMENT].map(|through| {
                (
                    through,
                    prompt,
                    format!(
                        "cannot set question \"{prompt}\": its EFI_IFR_VALUE expression makes it \
                         read-only (UEFI 2.11 §33.3.8.3.88)"
                    ),
                )
            })
        });
        // a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, whether or not get accepts
        // its metadata
        let authenticated = [
            ("Enhanced target", ENHANCED, "Enhanced"),
            ("Bad metadata target", BAD_METADATA, "BadMetadata"),
        ]
        .map(|(prompt, id, name)| {
            [EFIVARFS, VARIABLE_SERVICES, FIRMWARE_ENVIRONMENT].map(|through| {
                (
                    through,
                    prompt,
                    format!(
                        "cannot set question \"{prompt}\": its WRITE expression sets VarStore \
                         {id:#06x} (EFI_IFR_VARSTORE_EFI \"{name}\"), which set may not write: {:#}",
                        check_unauthenticated(&key(name), NV_BS_RT_ENHANCED)
                            .expect_err("refuse a variable with authenticated access")
                    ),
                )
            })
        });
        for (through, prompt, want) in cases
            .into_iter()
            .chain(read_only.into_iter().flatten())
            .chain(authenticated.into_iter().flatten())
        {
            assert_eq!(
                set(prompt, "1", through),
                (Err(want), BTreeMap::new()),
                "{prompt} through {through:?}"
            );
        }
        assert_eq!(
            set("Boot only target", "1", VARIABLE_SERVICES),
            (
                Ok(()),
                BTreeMap::from([
                    ("BootOnly", vec![(0, vec![1])]),
                    ("Store", vec![(0, vec![1])])
                ])
            ),
            "Boot only target through BootServices"
        );
    }

    /// A SET of a volatile variable follows the volatile policy as choice_for_set does: set writes
    /// it under VolatileWrites::Allow through variables that reach BootServices, and says that
    /// the question wrote a volatile variable; otherwise it refuses it before any write (UEFI
    /// 2.11 §8.2.3). Under Allow, a question says so for its own volatile variable after a SET of
    /// another, and says that it wrote none if none is volatile.
    #[test]
    fn a_set_of_a_volatile_variable_follows_the_volatile_policy() {
        let refused = |through: (VariableReach, VariableInterface)| {
            Err(format!(
                "cannot set question \"Volatile target\": its WRITE expression sets VarStore \
                 0x0008 (EFI_IFR_VARSTORE_EFI \"Volatile\"), which set may not write: {:#}",
                check_non_volatile(&key("Volatile"), through.1, BS_RT)
                    .expect_err("refuse a volatile variable")
            ))
        };
        let cases = [
            (
                "Volatile target",
                VARIABLE_SERVICES,
                VolatileWrites::Allow,
                Ok(vec![true]),
                BTreeMap::from([
                    ("Store", vec![(0, vec![1])]),
                    ("Volatile", vec![(0, vec![1])]),
                ]),
            ),
            (
                "Volatile target",
                VARIABLE_SERVICES,
                VolatileWrites::Refuse,
                refused(VARIABLE_SERVICES),
                BTreeMap::new(),
            ),
            (
                "Volatile target",
                EFIVARFS,
                VolatileWrites::Allow,
                refused(EFIVARFS),
                BTreeMap::new(),
            ),
            (
                "Volatile target",
                FIRMWARE_ENVIRONMENT,
                VolatileWrites::Allow,
                refused(FIRMWARE_ENVIRONMENT),
                BTreeMap::new(),
            ),
            (
                "Volatile store",
                VARIABLE_SERVICES,
                VolatileWrites::Allow,
                Ok(vec![true]),
                BTreeMap::from([
                    ("Store", vec![(2, vec![1])]),
                    ("Volatile", vec![(0, vec![1])]),
                ]),
            ),
            (
                "Other store",
                VARIABLE_SERVICES,
                VolatileWrites::Allow,
                Ok(vec![false]),
                BTreeMap::from([
                    ("Other", vec![(0, vec![1, 0])]),
                    ("Store", vec![(1, vec![1])]),
                ]),
            ),
        ];
        for (prompt, through, volatile, want, want_written) in cases {
            assert_eq!(
                set_under(&form_set(), &prompts(), prompt, "1", through, volatile),
                (want, want_written),
                "{prompt} through {through:?} under {volatile:?}"
            );
        }
    }

    /// Two package lists' questions of one prompt on one variable: the first writes byte 1, and
    /// the second's write of its own byte 0 and its WRITE's byte 2 keeps byte 1 as the first left
    /// it, not as set read it before any write.
    #[test]
    fn a_merged_write_keeps_the_bytes_that_an_earlier_write_of_the_same_set_changed() {
        let op = |op_code| operation(op_code, false, &[]);
        let list = |offset: u16, write: Vec<u8>| {
            let data = [
                question_header_with(1, FIRST_PROMPT, STORE, offset, 0),
                vec![0x10, 0, 255, 1],
            ]
            .concat();
            parse_form_set(&[
                var_store_efi(STORE, "Store", NV_BS_RT, 6),
                form(
                    1,
                    &[[operation(NUMERIC, true, &data), write, END.to_vec()].concat()],
                ),
            ])
        };
        let set_op = [
            &STORE.to_le_bytes()[..],
            &2u16.to_le_bytes(),
            &[EFI_IFR_TYPE_NUM_SIZE_8],
        ]
        .concat();
        let write = [
            op(WRITE),
            scoped_expression(&[op(THIS), operation(SET, false, &set_op)], 0),
        ]
        .concat();
        let roots = [list(1, Vec::new()), list(0, write)];
        let strings = vec![StringMap::from([(FIRST_PROMPT, "Dup".into())])];
        let mut reader = EfivarReader::with_variables(Box::new(variables(EFIVARFS)));
        let mut selections = Vec::new();
        for root in &roots {
            let values = VarStoreValues::new(root, None);
            selections.push(find_question_in(
                root,
                &BTreeSet::from(["Dup"]),
                &mut FormSetWalk::new(&strings, &mut reader, &values, IncludedStates::empty()),
            ));
        }
        let selected: Vec<(&str, &QuestionDescriptor)> = ["list 1", "list 2"]
            .into_iter()
            .zip(&selections)
            .map(|(selector, selection)| match selection {
                Selection::Picked {
                    picked: (descriptor, _),
                    ..
                } => (selector, descriptor),
                _ => panic!("{selector}: not picked"),
            })
            .collect();
        let writes = variables(EFIVARFS);

        set_questions(
            "Dup",
            &selected,
            "5",
            &BTreeSet::from(["5".to_string()]),
            IncludedStates::empty(),
            &mut reader,
            None,
            VolatileWrites::Refuse,
            &WithholdingVariables::new(&writes, WithheldBytes::default()),
        )
        .expect("set both questions");

        assert_eq!(
            writes.writes_to(&key("Store")),
            [(1, vec![5]), (0, vec![5, 5, 5])],
            "writes of Store"
        );
        let held = writes.bytes(&key("Store")).expect("Store exists");
        assert_eq!(
            held.get(crate::hii::variables::EFIVARFS_HEADER_SIZE..),
            Some(&[5, 5, 5, 0xA3, 0xA4, 0xA5][..]),
            "Store after set"
        );
    }

    /// A CHECKBOX's THIS is a BOOLEAN, which NOT negates in its WRITE; NOT of an integer would
    /// give UNDEFINED and set nothing.
    #[test]
    fn a_checkbox_write_takes_this_as_a_boolean() {
        let op = |op_code| operation(op_code, false, &[]);
        let set_store = [
            &STORE.to_le_bytes()[..],
            &2u16.to_le_bytes(),
            &[EFI_IFR_TYPE_NUM_SIZE_8],
        ]
        .concat();
        let header = question_header_with(1, FIRST_PROMPT, STORE, 0, 0);
        let checkbox = [
            operation(CHECKBOX, true, &[header, vec![0x00]].concat()),
            op(WRITE),
            scoped_expression(&[op(THIS), op(NOT), operation(SET, false, &set_store)], 0),
            END.to_vec(),
        ]
        .concat();
        let root = parse_form_set(&[
            var_store_efi(STORE, "Store", NV_BS_RT, 6),
            form(1, &[checkbox]),
        ]);
        let strings = vec![StringMap::from([(FIRST_PROMPT, "Checkbox".into())])];
        for (value, want) in [("1", vec![1, 0xA1, 0]), ("0", vec![0, 0xA1, 1])] {
            assert_eq!(
                set_in(&root, &strings, "Checkbox", value, EFIVARFS),
                (Ok(()), BTreeMap::from([("Store", vec![(0, want)])])),
                "Checkbox = {value}"
            );
        }
    }

    /// A write that fails after set wrote other variables of the question names them; one that
    /// fails first is its own error.
    #[cfg(efivar_dumps)]
    #[test]
    fn a_failed_write_names_the_variables_that_set_already_wrote() {
        let mut variables = variables(EFIVARFS);
        variables.fail_writes(
            key("Store"),
            WriteError {
                cause: "write failed",
                context: None,
            },
        );
        let (other, store) = (efi_variable("Other", 2), efi_variable("Store", 6));
        let writes = [&other, &store].map(|store| {
            VarStoreWrite::new(
                store,
                0,
                1,
                TypeValue::NumSize8(1),
                VariableInterface::Efivarfs,
            )
            .expect("a write of one byte")
        });
        let outcome = |writes: &[VarStoreWrite<'_>]| {
            write_in_turn(writes, &variables).map_err(|error| format!("{error:#}"))
        };
        assert_eq!(
            outcome(&writes),
            Err("write failed; set already wrote EFI variable \
                 Other-00000000-0000-0000-0000-000000000000"
                .to_string()),
            "Store after Other"
        );
        assert_eq!(
            outcome(&writes[1..]),
            Err("write failed".to_string()),
            "Store alone"
        );
        assert_eq!(
            variables.writes_to(&key("Other")),
            [(0, vec![1])],
            "writes of Other"
        );
    }
}
