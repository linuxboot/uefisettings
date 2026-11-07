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
    /// write, through what `reader` read of it.
    pub(super) fn variable_writes(
        &self,
        reader: &mut EfivarReader,
    ) -> Result<Vec<VarStoreWrite<'_>>, ChangeValueError> {
        let (reach, interface) = (reader.reach(), reader.interface());
        for set in &self.sets {
            let store = set.store.as_ref();
            let range = usize::from(set.offset)..usize::from(set.offset) + set.bytes.len();
            let checked = match reader.read(EfivarRange::of(store), range) {
                Ok(_) => check_writable(store, reader),
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
        variables
            .into_iter()
            .map(|(_, patches)| merged_write(&patches))
            .collect()
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
    /// The bytes of the variables of STORE, OTHER and BOOT_ONLY before set.
    const STORE_BYTES: [u8; 6] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5];
    const OTHER_BYTES: [u8; 2] = [0xB0, 0xB1];
    const BOOT_ONLY_BYTES: [u8; 1] = [0xC0];

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
            form(1, &body),
        ])
    }

    fn key(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: NIL_GUID,
        }
    }

    /// Variables of `(reach, interface)` holding STORE, OTHER, BOOT_ONLY, ENHANCED and
    /// BAD_METADATA as before set.
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
        variables
    }

    /// The data offsets and bytes of the writes to each variable, by name.
    type Written = BTreeMap<&'static str, Vec<(u16, Vec<u8>)>>;

    /// The outcome of set of `prompt` to `value` through variables of `through`, as the CLI
    /// prints an error, and the writes to each variable.
    fn set(
        prompt: &str,
        value: &str,
        through: (VariableReach, VariableInterface),
    ) -> (Result<(), String>, Written) {
        let strings = vec![(i32::from(FIRST_PROMPT)..)
            .zip(
                questions()
                    .into_iter()
                    .map(|(prompt, ..)| prompt.to_string()),
            )
            .collect()];
        set_in(&form_set(), &strings, prompt, value, through)
    }

    /// set() of `prompt` in the FormSet `root`, whose strings are `strings`.
    fn set_in(
        root: &Rc<RefCell<IFROperation>>,
        strings: &[BTreeMap<i32, String>],
        prompt: &str,
        value: &str,
        through: (VariableReach, VariableInterface),
    ) -> (Result<(), String>, Written) {
        let mut reader = EfivarReader::with_variables(Box::new(variables(through)));
        let values = VarStoreValues::new(root, None);
        let selection = find_question_in(
            root,
            &BTreeSet::from([prompt]),
            &mut FormSetWalk::new(strings, &mut reader, &values, IncludedStates::empty()),
        );
        let Selection::Picked(descriptor, _) = &selection else {
            panic!("{prompt}: not picked");
        };
        let writes = variables(through);
        let outcome = set_questions(
            prompt,
            &[("selector", descriptor)],
            value,
            &BTreeSet::from([value.to_string()]),
            IncludedStates::empty(),
            &mut reader,
            None,
            &WithholdingVariables::new(&writes, BTreeSet::new()),
        )
        .map(|_| ())
        .map_err(|error| format!("{error:#}"));
        let written = [
            "Store",
            "Other",
            "BootOnly",
            "Absent",
            "Enhanced",
            "BadMetadata",
        ]
        .into_iter()
        .map(|name| (name, writes.writes_to(&key(name))))
        .filter(|(_, writes)| !writes.is_empty())
        .collect();
        (outcome, written)
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
        let strings = vec![BTreeMap::from([(
            i32::from(FIRST_PROMPT),
            "Dup".to_string(),
        )])];
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
                Selection::Picked(descriptor, _) => (selector, descriptor),
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
            &WithholdingVariables::new(&writes, BTreeSet::new()),
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
        let strings = vec![BTreeMap::from([(
            i32::from(FIRST_PROMPT),
            "Checkbox".to_string(),
        )])];
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
