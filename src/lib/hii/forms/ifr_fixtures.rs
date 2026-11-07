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

//! IFR byte builders and question answers shared by the tests of forms.rs and its modules.

// The form tests that use most of these helpers are gated to efivar_dumps, as they read
// efivar directories, so on other targets the helpers they alone use are dead.
#![cfg_attr(
    not(efivar_dumps),
    allow(
        dead_code,
        reason = "the form tests using these helpers are gated to efivar_dumps"
    )
)]

#[cfg(efivar_dumps)]
use std::fs;
#[cfg(efivar_dumps)]
use std::path::Path;

#[cfg(efivar_dumps)]
use tempfile::TempDir;

use super::conditions::QuestionValue;
use super::conditions::QuestionValues;
#[cfg(efivar_dumps)]
use super::conditions::VarStoreValues;
#[cfg(efivar_dumps)]
use super::question_values::handle_checkbox;
#[cfg(efivar_dumps)]
use super::question_values::handle_numeric;
#[cfg(efivar_dumps)]
use super::question_values::handle_oneof;
use super::set::own_write;
use super::set::NewValue;
use super::storage::VariableStoreKind;
use super::*;
#[cfg(efivar_dumps)]
use crate::hii::efivarfs_format::EfivarFileName;
#[cfg(efivar_dumps)]
pub(super) use crate::hii::variables::tests::variable_key;
pub(crate) use crate::hii::variables::tests::MemoryVariables;
#[cfg(efivar_dumps)]
pub(super) use crate::hii::variables::tests::WriteError;
pub(crate) use crate::hii::variables::tests::BS_RT;
pub(crate) use crate::hii::variables::tests::NIL_GUID;
pub(crate) use crate::hii::variables::tests::NV_BS;
pub(crate) use crate::hii::variables::tests::NV_BS_RT;
#[cfg(efivar_dumps)]
use crate::hii::variables::EfivarSource;
use crate::hii::variables::FirmwareVariables;
pub(crate) use crate::hii::variables::VariableInterface;
pub(crate) use crate::hii::variables::VariableKey;
pub(crate) use crate::hii::variables::VariableReach;

pub(crate) const END: [u8; 2] = [0x29, IFR_OPERATION_HEADER_SIZE];

pub(crate) const ONE_OF: u8 = 0x05;
pub(crate) const CHECKBOX: u8 = 0x06;
pub(crate) const NUMERIC: u8 = 0x07;
pub(super) const PASSWORD: u8 = 0x08;

pub(crate) const SUPPRESS_IF: u8 = 0x0A;
pub(crate) const GRAY_OUT_IF: u8 = 0x19;
pub(crate) const DISABLE_IF: u8 = 0x1E;

pub(super) const FORM: u8 = 0x01;
pub(crate) const SUBTITLE: u8 = 0x02;
pub(crate) const LOCKED: u8 = 0x0B;
const ONE_OF_OPTION: u8 = 0x09;
const FORM_SET: u8 = 0x0E;
const EQ_ID_VAL: u8 = 0x12;
pub(super) const NOT: u8 = 0x17;
pub(super) const QUESTION_REF1: u8 = 0x40;
const UINT8: u8 = 0x42;
pub(super) const TRUE: u8 = 0x46;
pub(super) const FALSE: u8 = 0x47;
const ONES: u8 = 0x54;
pub(super) const VALUE: u8 = 0x5A;
pub(super) const DEFAULT: u8 = 0x5B;
const DEFAULT_STORE: u8 = 0x5C;
pub(crate) const FORM_MAP: u8 = 0x5D;

pub(crate) const VAR_STORE: u8 = 0x24;
const VAR_STORE_EFI: u8 = 0x26;
pub(super) const READ: u8 = 0x2D;
pub(super) const WRITE: u8 = 0x2E;

/// The Guid E770BB69-BCB4-4D04-9E97-23FF9456FEAC of AMI firmware's VarStore SystemAccess, as
/// stored.
pub(crate) const SYSTEM_ACCESS_GUID: [u8; 16] = [
    0x69, 0xBB, 0x70, 0xE7, 0xB4, 0xBC, 0x04, 0x4D, 0x9E, 0x97, 0x23, 0xFF, 0x94, 0x56, 0xFE, 0xAC,
];

pub(crate) const GUID: u8 = 0x5F;

/// EDKII_IFR_BIT_VARSTORE_GUID 82DDD68B-9163-4187-9B27-20A8FD60A71D as stored.
pub(super) const BIT_VARSTORE_GUID: [u8; 16] = [
    0x8B, 0xD6, 0xDD, 0x82, 0x63, 0x91, 0x87, 0x41, 0x9B, 0x27, 0x20, 0xA8, 0xFD, 0x60, 0xA7, 0x1D,
];
/// An EFI_IFR_GUID Guid other than EDKII_IFR_BIT_VARSTORE_GUID.
pub(crate) const OTHER_GUID: [u8; 16] = [0x33; 16];

/// The prompt of `question_header()`.
pub(super) const PROMPT: &str = "Prompt";
/// The string id of "Enabled " with a trailing space, as firmware may store an option's text.
pub(super) const PADDED_ENABLED: u16 = 8;

/// The reason `unavailable()` gives.
pub(super) const UNAVAILABLE: &str = "<ValueUnavailable: no VarStore 1>";

/// Bytes of stack the tests of deep IFR scopes run on: UEFI DXE's 128 KiB (edk2-stable202608
/// MdeModulePkg/Core/DxeIplPeim/DxeIpl.h STACK_SIZE), far less than a frame per IFR scope would
/// take
pub(crate) const SMALL_STACK: usize = 128 << 10;

/// A VarStore declared without IFR bytes.
pub(super) struct DeclaredVarStore {
    pub(super) name: &'static str,
    pub(super) size: u16,
    pub(super) kind: VariableStoreKind,
    pub(super) runtime_accessible: bool,
}

impl VariableStore for DeclaredVarStore {
    fn name(&self) -> String {
        self.name.to_string()
    }

    fn guid(&self) -> Guid {
        NIL_GUID
    }

    fn size(&self) -> u16 {
        self.size
    }

    fn kind(&self) -> VariableStoreKind {
        self.kind
    }

    fn is_runtime_accessible(&self) -> bool {
        self.runtime_accessible
    }
}

/// A directory of efivar files, as efivarfs is.
#[cfg(efivar_dumps)]
pub(super) struct Efivars(TempDir);

#[cfg(efivar_dumps)]
impl Efivars {
    pub(super) fn new() -> Self {
        Self(tempfile::tempdir().expect("create efivars directory"))
    }

    /// Makes `payload`, after the efivarfs attributes field, the efivar file of `store`.
    pub(super) fn write(&self, store: &dyn VariableStore, payload: &[u8]) {
        self.write_attributed(store, NV_BS_RT, payload);
    }

    /// Makes the attribute word `attributes` and then `payload` the efivar file of `store`.
    pub(super) fn write_attributed(
        &self,
        store: &dyn VariableStore,
        attributes: u32,
        payload: &[u8],
    ) {
        fs::write(
            self.0
                .path()
                .join(EfivarFileName::from(&store.variable_key())),
            efivar_file_bytes(attributes, payload),
        )
        .expect("write efivar file");
    }

    pub(super) fn path(&self) -> &Path {
        self.0.path()
    }

    /// A fresh EfivarReader of these efivar files.
    /// The reader holds only the path: keep `self` alive while it reads.
    pub(super) fn reader(&self) -> EfivarReader {
        EfivarReader::new(EfivarSource::Directory(self.path().to_path_buf()))
            .expect("create a reader of the efivars directory")
    }
}

/// A fresh EfivarReader of EfivarSource::Disabled.
#[cfg(efivar_dumps)]
pub(super) fn disabled_reader() -> EfivarReader {
    EfivarReader::new(EfivarSource::Disabled).expect("create a reader without efivars")
}

/// A question's VarStore, and the efivars that hold its value.
#[cfg(efivar_dumps)]
pub(super) struct VarStoreFixture {
    pub(super) store: Result<Box<dyn VariableStore>>,
    pub(super) efivars: Efivars,
}

/// `payload` after the efivarfs attributes field.
pub(super) fn efivarfs_bytes(payload: &[u8]) -> Vec<u8> {
    efivar_file_bytes(NV_BS_RT, payload)
}

/// The attribute word `attributes`, as efivarfs gives it, then `payload`.
pub(super) fn efivar_file_bytes(attributes: u32, payload: &[u8]) -> Vec<u8> {
    [&attributes.to_ne_bytes()[..], payload].concat()
}

/// A runtime-accessible EFI variable `name` of `size` bytes.
pub(super) fn efi_variable(name: &'static str, size: usize) -> DeclaredVarStore {
    DeclaredVarStore {
        name,
        size: u16::try_from(size).expect("test size fits a VarStore Size"),
        kind: VariableStoreKind::EfiVariable,
        runtime_accessible: true,
    }
}

/// A buffer VarStore `name` of `size` bytes.
pub(super) fn buffer(name: &'static str, size: usize) -> DeclaredVarStore {
    DeclaredVarStore {
        kind: VariableStoreKind::Buffer,
        runtime_accessible: false,
        ..efi_variable(name, size)
    }
}

/// An EFI variable VarStore whose efivar file holds `payload`.
#[cfg(efivar_dumps)]
pub(super) fn var_store_of(payload: &[u8]) -> VarStoreFixture {
    writable_var_store("VarStore", payload, &MemoryVariables::default())
}

/// var_store_of `payload` on the EFI variable `name`, which `variables` holds too, for set to
/// write there.
#[cfg(efivar_dumps)]
pub(super) fn writable_var_store(
    name: &'static str,
    payload: &[u8],
    variables: &MemoryVariables,
) -> VarStoreFixture {
    let store = efi_variable(name, payload.len());
    variables.insert(store.variable_key(), NV_BS_RT, payload);
    let efivars = Efivars::new();
    efivars.write(&store, payload);
    VarStoreFixture {
        store: Ok(Box::new(store)),
        efivars,
    }
}

/// A VarStore on the EFI variable `name`, whose efivar file holds 0, and whose writes to
/// `variables` fail with `write_error`.
#[cfg(efivar_dumps)]
pub(super) fn failing_var_store(
    name: &'static str,
    write_error: WriteError,
    variables: &mut MemoryVariables,
) -> VarStoreFixture {
    variables.fail_writes(variable_key(name), write_error);
    writable_var_store(name, &[0], variables)
}

/// Writes `new_value` to `question` in `variables` as set does: value_write, then its write.
pub(super) fn change_value(
    question: &QuestionDescriptor,
    new_value: &str,
    variables: &dyn FirmwareVariables,
) -> Result<(), ChangeValueError> {
    let (_, write) = own_write(
        question,
        NewValue::Text(new_value),
        variables.reach(),
        variables.interface(),
    )?;
    write
        .ok_or_else(|| anyhow!("a question without a VarStore"))?
        .write(variables)?;
    Ok(())
}

/// Writes `option`, one of the possible_options of the ONE_OF `question`, in `variables` as set
/// does.
pub(super) fn change_option(
    question: &QuestionDescriptor,
    option: &AnswerOption,
    variables: &dyn FirmwareVariables,
) -> Result<(), ChangeValueError> {
    let (_, write) = own_write(
        question,
        NewValue::Option(option),
        variables.reach(),
        variables.interface(),
    )?;
    write
        .ok_or_else(|| anyhow!("a question without a VarStore"))?
        .write(variables)?;
    Ok(())
}

#[cfg(efivar_dumps)]
pub(super) fn unavailable() -> VarStoreFixture {
    VarStoreFixture {
        store: Err(anyhow!("no VarStore 1")),
        efivars: Efivars::new(),
    }
}

pub(super) fn strings() -> Vec<BTreeMap<i32, String>> {
    vec![BTreeMap::from([
        (3, PROMPT.to_string()),
        (5, "Disabled".to_string()),
        (6, "Enabled".to_string()),
        (7, "AllOnes".to_string()),
        (PADDED_ENABLED.into(), "Enabled ".to_string()),
    ])]
}

/// `depth` copies of the op `scope`, each in the scope of the one before, around `body`, with
/// their End ops.
pub(crate) fn nested(scope: &[u8], depth: usize, body: &[Vec<u8>]) -> Vec<u8> {
    [scope.repeat(depth), body.concat(), END.repeat(depth)].concat()
}

/// A SUBTITLE prompted by string `prompt`, opening a scope.
pub(crate) fn subtitle_scope(prompt: u16) -> Vec<u8> {
    let data = [&prompt.to_le_bytes()[..], &[0x00, 0x00, 0x00]].concat(); // Help, Flags
    operation(SUBTITLE, true, &data)
}

/// A LOCKED op opening a scope.
pub(super) fn locked_scope() -> Vec<u8> {
    operation(LOCKED, true, &[])
}

/// A LOCKED op.
pub(crate) fn locked_op() -> Vec<u8> {
    operation(LOCKED, false, &[])
}

pub(crate) fn operation(op_code: u8, open_scope: bool, data: &[u8]) -> Vec<u8> {
    let length = u8::try_from(usize::from(IFR_OPERATION_HEADER_SIZE) + data.len())
        .ok()
        .filter(|length| length & 0x80 == 0)
        .expect("test operation fits a 7-bit Length");
    let scope = if open_scope { 0x80 } else { 0 };
    [&[op_code, scope | length][..], data].concat()
}

pub(super) fn one_of_option(string_id: u16, value_type: u8, value: &[u8]) -> Vec<u8> {
    let data = [&string_id.to_le_bytes()[..], &[0x00, value_type], value].concat();
    operation(ONE_OF_OPTION, false, &data)
}

/// A UINT8 EFI_IFR_ONE_OF_OPTION with `flags`.
pub(crate) fn flagged_option(string_id: u16, flags: u8, value: u8) -> Vec<u8> {
    let data = [&string_id.to_le_bytes()[..], &[flags, 0x00, value]].concat();
    operation(ONE_OF_OPTION, false, &data)
}

/// An EFI_IFR_DEFAULT of Type UINT8.
pub(crate) fn ifr_default(default_id: u16, value: u8) -> Vec<u8> {
    let data = [&default_id.to_le_bytes()[..], &[0x00, value]].concat();
    operation(DEFAULT, false, &data)
}

/// An EFI_IFR_DEFAULT of Type UINT32.
pub(super) fn uint32_default(default_id: u16, value: u32) -> Vec<u8> {
    let data = [&default_id.to_le_bytes()[..], &[0x02], &value.to_le_bytes()].concat();
    operation(DEFAULT, false, &data)
}

/// An EFI_IFR_DEFAULT_2 whose EFI_IFR_VALUE holds `expression`.
pub(crate) fn ifr_default_2(default_id: u16, expression: Vec<u8>) -> Vec<u8> {
    let data = [&default_id.to_le_bytes()[..], &[0x08]].concat();
    [
        operation(DEFAULT, true, &data),
        operation(VALUE, true, &[]),
        expression,
        END.to_vec(), // End of the VALUE
        END.to_vec(), // End of the DEFAULT
    ]
    .concat()
}

/// `body` in the scope of a SUPPRESS_IF, GRAY_OUT_IF or DISABLE_IF on `condition`.
pub(crate) fn conditional(op_code: u8, condition: Vec<u8>, body: &[Vec<u8>]) -> Vec<u8> {
    [
        operation(op_code, true, &[]),
        condition,
        body.concat(),
        END.to_vec(),
    ]
    .concat()
}

pub(crate) fn ifr_true() -> Vec<u8> {
    operation(TRUE, false, &[])
}

pub(crate) fn ifr_false() -> Vec<u8> {
    operation(FALSE, false, &[])
}

pub(super) fn ifr_ones() -> Vec<u8> {
    operation(ONES, false, &[])
}

pub(crate) fn uint8(value: u8) -> Vec<u8> {
    operation(UINT8, false, &[value])
}

/// EFI_IFR_EQ_ID_VAL: question 1 equals 1.
pub(super) fn eq_id_val() -> Vec<u8> {
    operation(EQ_ID_VAL, false, &[0x01, 0x00, 0x01, 0x00])
}

/// EFI_IFR_EQ_ID_VAL: question `question_id` equals `value`.
pub(crate) fn eq_id_val_of(question_id: u16, value: u16) -> Vec<u8> {
    let data = [question_id.to_le_bytes(), value.to_le_bytes()].concat();
    operation(EQ_ID_VAL, false, &data)
}

/// The ops of an expression with the Scope bit on the op at `scope_at`, and an End after the
/// last: edk2-stable202608 VfrCompile sets the bit on the first op, AMI firmware on a later one.
pub(super) fn scoped_expression(ops: &[Vec<u8>], scope_at: usize) -> Vec<u8> {
    let mut ops = ops.to_vec();
    ops[scope_at][1] |= 0x80;
    [ops.concat(), END.to_vec()].concat()
}

/// Answers from a map, whatever the referrer.
pub(super) struct MapValues(pub(super) BTreeMap<u16, QuestionValue>);

impl QuestionValues for MapValues {
    fn value(
        &self,
        _referrer: &IFROperation,
        id: u16,
        _reader: &mut EfivarReader,
    ) -> Option<QuestionValue> {
        self.0.get(&id).cloned()
    }
}

/// An EFI_IFR_DEFAULTSTORE of `default_id`, named by string 8.
pub(super) fn default_store(default_id: u16) -> Vec<u8> {
    default_store_named(8, default_id)
}

/// An EFI_IFR_DEFAULTSTORE of `default_id`, named by string `name`.
pub(crate) fn default_store_named(name: u16, default_id: u16) -> Vec<u8> {
    let data = [name.to_le_bytes(), default_id.to_le_bytes()].concat();
    operation(DEFAULT_STORE, false, &data)
}

/// Guid, FormSetTitle, Help, Flags and ClassGuid of an EFI_IFR_FORM_SET.
fn form_set_data() -> Vec<u8> {
    [
        &[0x11; 16][..],           // Guid
        &[0x01, 0x00, 0x02, 0x00], // FormSetTitle, Help
        &[0x01],                   // Flags: one ClassGuid
        &[0x22; 16],               // ClassGuid
    ]
    .concat()
}

/// The root of a parsed FormSet, which owns the parents, and its question.
pub(super) type RootAndQuestion = (Rc<RefCell<IFROperation>>, Rc<RefCell<IFROperation>>);

/// Parses a FormSet holding `declarations` and then one question, and
/// returns the root, which owns the parents, and that question.
pub(super) fn parse_question(
    declarations: &[Vec<u8>],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
) -> RootAndQuestion {
    try_parse_question(declarations, op_code, data, children).expect("parse the FormSet")
}

/// `parse_question`, returning the error of an unparsable FormSet.
pub(super) fn try_parse_question(
    declarations: &[Vec<u8>],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
) -> Result<RootAndQuestion> {
    let data = form_set(&[
        declarations.concat(),
        operation(op_code, true, data),
        children.concat(),
        END.to_vec(), // End of the question
    ]);

    let root = handle_form_set(&mut Cursor::new(&data))?;

    let form_set = Rc::clone(&root.borrow().children[0]);
    let question = Rc::clone(&form_set.borrow().children[declarations.len()]);
    assert_eq!(
        question.borrow().children.len(),
        children.len(),
        "children of the parsed question"
    );
    Ok((root, question))
}

/// An EFI_IFR_FORM_SET holding `children`.
pub(crate) fn form_set(children: &[Vec<u8>]) -> Vec<u8> {
    [
        operation(FORM_SET, true, &form_set_data()),
        children.concat(),
        END.to_vec(),
    ]
    .concat()
}

/// The FORM_SET op of form_set without its Scope bit, then `children`, with no End of its own.
pub(crate) fn scopeless_form_set(children: &[Vec<u8>]) -> Vec<u8> {
    [
        operation(FORM_SET, false, &form_set_data()),
        children.concat(),
    ]
    .concat()
}

/// Prompt 3, Help 4, QuestionId 1, VarStoreId 1, VarOffset `offset`.
pub(super) fn question_header(offset: u16) -> Vec<u8> {
    [
        &[0x03, 0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00][..],
        &offset.to_le_bytes(),
        &[0x00],
    ]
    .concat()
}

/// Prompt 3, Help 4, QuestionId `question_id`, VarStoreId 1, VarOffset `offset`.
pub(super) fn question_header_of(question_id: u16, offset: u16) -> Vec<u8> {
    question_header_on(question_id, 3, 1, offset)
}

/// Prompt `prompt`, Help 4, QuestionId `question_id`, VarStoreId `var_store_id`, VarOffset
/// `offset`.
pub(super) fn question_header_on(
    question_id: u16,
    prompt: u16,
    var_store_id: u16,
    offset: u16,
) -> Vec<u8> {
    question_header_with(question_id, prompt, var_store_id, offset, 0x00)
}

/// question_header_on() with Flags `flags`.
pub(crate) fn question_header_with(
    question_id: u16,
    prompt: u16,
    var_store_id: u16,
    offset: u16,
    flags: u8,
) -> Vec<u8> {
    [
        &prompt.to_le_bytes()[..],
        &[0x04, 0x00],
        &question_id.to_le_bytes(),
        &var_store_id.to_le_bytes(),
        &offset.to_le_bytes(),
        &[flags],
    ]
    .concat()
}

/// A CHECKBOX op of QuestionId `question_id` at VarOffset `offset`.
pub(super) fn checkbox_op(question_id: u16, offset: u16) -> Vec<u8> {
    let data = [question_header_of(question_id, offset), vec![0x00]].concat();
    operation(CHECKBOX, false, &data)
}

/// A CHECKBOX op of QuestionId `question_id`, prompted string `prompt`, at VarOffset 0 of
/// VarStore `var_store_id`.
pub(crate) fn checkbox_on(question_id: u16, prompt: u16, var_store_id: u16) -> Vec<u8> {
    checkbox_at(question_id, prompt, var_store_id, 0)
}

/// checkbox_on at VarOffset `offset`.
pub(crate) fn checkbox_at(
    question_id: u16,
    prompt: u16,
    var_store_id: u16,
    offset: u16,
) -> Vec<u8> {
    let data = [
        question_header_on(question_id, prompt, var_store_id, offset),
        vec![0x00],
    ]
    .concat();
    operation(CHECKBOX, false, &data)
}

/// A PASSWORD op of QuestionId `question_id`, prompted string `prompt`, of up to 20 characters
/// at VarOffset `offset` of VarStore `var_store_id`, as AMI firmware declares its setup
/// passwords; VarStore 0 is none.
pub(crate) fn password_on(
    question_id: u16,
    prompt: u16,
    var_store_id: u16,
    offset: u16,
) -> Vec<u8> {
    let data = [
        question_header_on(question_id, prompt, var_store_id, offset),
        [&1u16.to_le_bytes()[..], &20u16.to_le_bytes()].concat(), // MinSize, MaxSize
    ]
    .concat();
    operation(PASSWORD, false, &data)
}

/// A UINT8 NUMERIC of QuestionId `question_id`, prompted string `prompt`, from 0 to 255 at
/// VarOffset 0 of VarStore `var_store_id`.
pub(super) fn uint8_numeric_on(question_id: u16, prompt: u16, var_store_id: u16) -> Vec<u8> {
    let data = [
        question_header_on(question_id, prompt, var_store_id, 0),
        vec![0x00, 0, 255, 1], // Flags, MinValue, MaxValue, Step
    ]
    .concat();
    operation(NUMERIC, false, &data)
}

/// A UINT8 NUMERIC of QuestionId `question_id`, prompted string `prompt`, with the question Flags
/// `flags`, from 0 to 255 at VarOffset `offset` of VarStore 1, with `body` in its scope.
pub(crate) fn uint8_numeric_with(
    question_id: u16,
    prompt: u16,
    offset: u16,
    flags: u8,
    body: &[Vec<u8>],
) -> Vec<u8> {
    let data = [
        question_header_with(question_id, prompt, 1, offset, flags),
        vec![0x10, 0, 255, 1], // Flags: UINT8 UINT_DEC; MinValue, MaxValue, Step
    ]
    .concat();
    [operation(NUMERIC, true, &data), body.concat(), END.to_vec()].concat()
}

/// An EFI_IFR_VALUE whose scope holds `expression`.
pub(crate) fn value_of(expression: Vec<u8>) -> Vec<u8> {
    [operation(VALUE, true, &[]), expression, END.to_vec()].concat()
}

/// A VARSTORE of `id` named `name`, of the Guid stored as `guid`, of `size` bytes.
pub(crate) fn var_store(id: u16, guid: [u8; 16], name: &str, size: u16) -> Vec<u8> {
    let data = [
        &guid[..],
        &id.to_le_bytes(),
        &size.to_le_bytes(),
        name.as_bytes(),
        &[0x00],
    ]
    .concat();
    operation(VAR_STORE, false, &data)
}

/// A VARSTORE_EFI of `id` named `name`, of NIL_GUID, with `attributes`, of `size` bytes.
pub(crate) fn var_store_efi(id: u16, name: &str, attributes: u32, size: u16) -> Vec<u8> {
    var_store_efi_of(id, [0; 16], name, attributes, size)
}

/// var_store_efi of the Guid stored as `guid`.
pub(crate) fn var_store_efi_of(
    id: u16,
    guid: [u8; 16],
    name: &str,
    attributes: u32,
    size: u16,
) -> Vec<u8> {
    let data = [
        &id.to_le_bytes()[..],
        &guid,
        &attributes.to_le_bytes(),
        &size.to_le_bytes(),
        name.as_bytes(),
        &[0x00],
    ]
    .concat();
    operation(VAR_STORE_EFI, false, &data)
}

/// An EFI_IFR_FORM of `form_id` holding `body`.
pub(crate) fn form(form_id: u16, body: &[Vec<u8>]) -> Vec<u8> {
    let data = [form_id.to_le_bytes(), [0x01, 0x00]].concat();
    [operation(FORM, true, &data), body.concat(), END.to_vec()].concat()
}

/// EFI_HII_STANDARD_FORM_GUID 3BD2F4EC-E524-46E4-A9D8-510117425562 as stored.
pub(super) const STANDARD_FORM_GUID: [u8; 16] = [
    0xEC, 0xF4, 0xD2, 0x3B, 0x24, 0xE5, 0xE4, 0x46, 0xA9, 0xD8, 0x51, 0x01, 0x17, 0x42, 0x55, 0x62,
];

/// An EFI_IFR_FORM_MAP of form 4 with a method per (MethodTitle, MethodIdentifier), holding
/// `body`.
pub(super) fn form_map(methods: &[(u16, [u8; 16])], body: &[Vec<u8>]) -> Vec<u8> {
    let data: Vec<u8> = 4u16
        .to_le_bytes()
        .into_iter()
        .chain(
            methods
                .iter()
                .flat_map(|(title, guid)| title.to_le_bytes().into_iter().chain(*guid)),
        )
        .collect();
    [
        operation(FORM_MAP, true, &data),
        body.concat(),
        END.to_vec(),
    ]
    .concat()
}

/// Parses a FormSet holding `body`, and returns the root.
pub(crate) fn parse_form_set(body: &[Vec<u8>]) -> Rc<RefCell<IFROperation>> {
    let data = form_set(body);
    handle_form_set(&mut Cursor::new(&data)).expect("parse the FormSet")
}

/// Returns the first op under `node`, in IFR order, with `data`.
pub(super) fn find_op(
    node: &Rc<RefCell<IFROperation>>,
    data: &[u8],
) -> Option<Rc<RefCell<IFROperation>>> {
    let mut found = None;
    walk_scopes(std::slice::from_ref(node), (), |op, ()| {
        if found.is_none() && op.borrow().data == data {
            found = Some(Rc::clone(op));
        }
        Walk::Enter(())
    });
    found
}

pub(crate) fn checkbox(offset: u16, flags: u8) -> Vec<u8> {
    [question_header(offset), vec![flags]].concat()
}

/// A UINT8 NUMERIC from `minimum` to `maximum`.
pub(super) fn uint8_numeric(flags: u8, minimum: u8, maximum: u8) -> Vec<u8> {
    [&question_header(0)[..], &[flags, minimum, maximum, 1]].concat()
}

/// A NUMERIC or ONE_OF with `flags` and Range UINT32 0..=300, at VarOffset `offset`.
pub(super) fn uint32_range_question(offset: u16, flags: u8) -> Vec<u8> {
    [
        &question_header(offset)[..],
        &[flags],
        &0u32.to_le_bytes(),   // MinValue
        &300u32.to_le_bytes(), // MaxValue
        &1u32.to_le_bytes(),   // Step
    ]
    .concat()
}

/// A UINT8 ONE_OF at VarOffset 0.
pub(super) fn one_of_data() -> Vec<u8> {
    [&question_header(0)[..], &[0x00, 0x00, 0x01, 0x01]].concat()
}

/// The QuestionDescriptor that list-questions, get and set use for `node`.
#[cfg(efivar_dumps)]
pub(super) fn question_descriptor(
    node: &Rc<RefCell<IFROperation>>,
    var_store: VarStoreFixture,
) -> QuestionDescriptor {
    question_descriptor_with(node, var_store, &VarStoreValues::new(&root_of(node), None))
}

/// Returns the root of the tree of `node`.
#[cfg(efivar_dumps)]
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

/// The QuestionDescriptor of `node`, with the values that conditions refer to from `values`.
#[cfg(efivar_dumps)]
pub(super) fn question_descriptor_with(
    node: &Rc<RefCell<IFROperation>>,
    VarStoreFixture { store, efivars }: VarStoreFixture,
    values: &impl QuestionValues,
) -> QuestionDescriptor {
    let current = node.borrow();
    let strings = strings();
    let mut reader = efivars.reader();
    let walk = &mut FormSetWalk::new(&strings, &mut reader, values, IncludedStates::empty());
    let flags = value_question(&current)
        .expect("a question")
        .header()
        .flags();
    match &current.parsed_data {
        ParsedOperation::OneOf(parsed) => handle_oneof(store, parsed, "", flags, node, walk),
        ParsedOperation::Numeric(parsed) => handle_numeric(store, parsed, "", flags, node, walk),
        ParsedOperation::CheckBox(parsed) => handle_checkbox(store, parsed, "", flags, node, walk),
        other => panic!("not a question: {other:?}"),
    }
}

/// The answer list-questions and get show for the question.
#[cfg(efivar_dumps)]
pub(super) fn answer(
    declarations: &[Vec<u8>],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
    var_store: VarStoreFixture,
) -> String {
    let (_root, node) = parse_question(declarations, op_code, data, children);
    question_descriptor(&node, var_store).value
}

/// The answer of the UINT8 ONE_OF of `one_of_data()` without a VarStore.
#[cfg(efivar_dumps)]
pub(super) fn one_of_default(declarations: &[Vec<u8>], children: &[Vec<u8>]) -> String {
    answer(
        declarations,
        ONE_OF,
        &one_of_data(),
        children,
        unavailable(),
    )
}

/// The answer of a question in the scope of an EFI_IFR_GUID of `guid`.
#[cfg(efivar_dumps)]
pub(super) fn answer_in_guid(
    guid: [u8; 16],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
    var_store: VarStoreFixture,
) -> String {
    let (_root, question) = parse_question_in_guid(guid, op_code, data, children);
    question_descriptor(&question, var_store).value
}

/// Parses a FormSet holding an EFI_IFR_GUID of `guid` that holds one question, and returns
/// the root, which owns the parents, and that question.
pub(super) fn parse_question_in_guid(
    guid: [u8; 16],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
) -> RootAndQuestion {
    try_parse_question_in_guid(guid, op_code, data, children).expect("parse the FormSet")
}

/// `parse_question_in_guid`, returning the error of an unparsable FormSet.
pub(super) fn try_parse_question_in_guid(
    guid: [u8; 16],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
) -> Result<RootAndQuestion> {
    let data = form_set(&[
        operation(GUID, true, &guid),
        operation(op_code, true, data),
        children.concat(),
        END.to_vec(), // End of the question
        END.to_vec(), // End of the GUID
    ]);

    let root = handle_form_set(&mut Cursor::new(&data))?;

    let form_set = Rc::clone(&root.borrow().children[0]);
    let guid = Rc::clone(&form_set.borrow().children[0]);
    let question = Rc::clone(&guid.borrow().children[0]);
    Ok((root, question))
}

/// Runs `run` on a thread named `name` of SMALL_STACK bytes, and returns what it returns.
pub(crate) fn on_small_stack<T: Send>(name: &str, run: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name(name.to_string())
            .stack_size(SMALL_STACK)
            .spawn_scoped(scope, run)
            .expect("spawn a thread")
            .join()
            .unwrap_or_else(|_| panic!("{name} panicked"))
    })
}
