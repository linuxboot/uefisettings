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

use std::fs;

use tempfile::TempDir;

use super::conditions::QuestionValue;
use super::conditions::QuestionValues;
use super::conditions::VarStoreValues;
use super::*;

pub(super) const END: [u8; 2] = [0x29, IFR_OPERATION_HEADER_SIZE];

pub(super) const ONE_OF: u8 = 0x05;
pub(super) const CHECKBOX: u8 = 0x06;
pub(super) const NUMERIC: u8 = 0x07;

pub(super) const SUPPRESS_IF: u8 = 0x0A;
pub(super) const GRAY_OUT_IF: u8 = 0x19;
pub(super) const DISABLE_IF: u8 = 0x1E;

pub(super) const FORM: u8 = 0x01;
const ONE_OF_OPTION: u8 = 0x09;
const FORM_SET: u8 = 0x0E;
const EQ_ID_VAL: u8 = 0x12;
pub(super) const NOT: u8 = 0x17;
pub(super) const QUESTION_REF1: u8 = 0x40;
const UINT8: u8 = 0x42;
pub(super) const TRUE: u8 = 0x46;
pub(super) const FALSE: u8 = 0x47;
const ONES: u8 = 0x54;
const VALUE: u8 = 0x5A;
pub(super) const DEFAULT: u8 = 0x5B;
const DEFAULT_STORE: u8 = 0x5C;
pub(super) const FORM_MAP: u8 = 0x5D;

const VAR_STORE_EFI: u8 = 0x26;

/// EFI variable Attributes: non-volatile, boot service and runtime access.
pub(super) const NV_BS_RT: u32 = 0x07;
/// EFI variable Attributes: non-volatile and boot service access only.
pub(super) const NV_BS: u32 = 0x03;

pub(super) const GUID: u8 = 0x5F;

/// EDKII_IFR_BIT_VARSTORE_GUID 82DDD68B-9163-4187-9B27-20A8FD60A71D as stored.
pub(super) const BIT_VARSTORE_GUID: [u8; 16] = [
    0x8B, 0xD6, 0xDD, 0x82, 0x63, 0x91, 0x87, 0x41, 0x9B, 0x27, 0x20, 0xA8, 0xFD, 0x60, 0xA7, 0x1D,
];
/// An EFI_IFR_GUID Guid other than EDKII_IFR_BIT_VARSTORE_GUID.
pub(super) const OTHER_GUID: [u8; 16] = [0x33; 16];

/// The prompt of `question_header()`.
pub(super) const PROMPT: &str = "Prompt";

/// The reason `unavailable()` gives.
pub(super) const UNAVAILABLE: &str = "<ValueUnavailable: no VarStore 1>";

pub(super) const NIL_GUID: Guid = Guid {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0; 8],
};

/// The VarOffsets and values written to a VarStore.
pub(super) type RecordedWrites = Rc<RefCell<Vec<(u16, TypeValue)>>>;

/// A VarStore declared without IFR bytes.
/// Writes go to `writes`, not to efivarfs.
pub(super) struct DeclaredVarStore {
    pub(super) name: &'static str,
    pub(super) size: u16,
    pub(super) kind: VariableStoreKind,
    pub(super) runtime_accessible: bool,
    pub(super) writes: RecordedWrites,
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

    fn write_efivarfs_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
        self.writes.borrow_mut().push((offset, data));
        Ok(())
    }
}

/// A directory of efivar files, as efivarfs is.
pub(super) struct Efivars(TempDir);

impl Efivars {
    pub(super) fn new() -> Self {
        Self(tempfile::tempdir().expect("create efivars directory"))
    }

    /// Makes `payload`, after the efivarfs attributes field, the efivar file of `store`.
    pub(super) fn write(&self, store: &dyn VariableStore, payload: &[u8]) {
        fs::write(
            self.0.path().join(store.efivar_file_name()),
            efivarfs_bytes(payload),
        )
        .expect("write efivar file");
    }

    pub(super) fn path(&self) -> &Path {
        self.0.path()
    }

    /// A fresh EfivarReader of these efivar files.
    /// The reader holds only the path: keep `self` alive while it reads.
    pub(super) fn reader(&self) -> EfivarReader {
        EfivarReader::new(self.path().to_path_buf())
    }
}

/// A question's VarStore, and the efivars that hold its value.
pub(super) struct VarStoreFixture {
    pub(super) store: Result<Box<dyn VariableStore>>,
    pub(super) efivars: Efivars,
}

/// `payload` after the efivarfs attributes field.
pub(super) fn efivarfs_bytes(payload: &[u8]) -> Vec<u8> {
    [&7u32.to_le_bytes()[..], payload].concat()
}

/// A runtime-accessible EFI variable `name` of `size` bytes.
pub(super) fn efi_variable(name: &'static str, size: usize) -> DeclaredVarStore {
    DeclaredVarStore {
        name,
        size: u16::try_from(size).expect("test size fits a VarStore Size"),
        kind: VariableStoreKind::EfiVariable,
        runtime_accessible: true,
        writes: RecordedWrites::default(),
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
pub(super) fn var_store_of(payload: &[u8]) -> VarStoreFixture {
    recording_var_store(payload).0
}

/// var_store_of `payload`, and the writes to its VarStore.
pub(super) fn recording_var_store(payload: &[u8]) -> (VarStoreFixture, RecordedWrites) {
    let store = efi_variable("VarStore", payload.len());
    let writes = Rc::clone(&store.writes);
    let efivars = Efivars::new();
    efivars.write(&store, payload);
    let fixture = VarStoreFixture {
        store: Ok(Box::new(store)),
        efivars,
    };
    (fixture, writes)
}

pub(super) fn unavailable() -> VarStoreFixture {
    VarStoreFixture {
        store: Err(anyhow!("no VarStore 1")),
        efivars: Efivars::new(),
    }
}

pub(super) fn strings() -> Vec<HashMap<i32, String>> {
    vec![HashMap::from([
        (3, PROMPT.to_string()),
        (5, "Disabled".to_string()),
        (6, "Enabled".to_string()),
        (7, "AllOnes".to_string()),
    ])]
}

pub(super) fn operation(op_code: u8, open_scope: bool, data: &[u8]) -> Vec<u8> {
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
pub(super) fn flagged_option(string_id: u16, flags: u8, value: u8) -> Vec<u8> {
    let data = [&string_id.to_le_bytes()[..], &[flags, 0x00, value]].concat();
    operation(ONE_OF_OPTION, false, &data)
}

/// An EFI_IFR_DEFAULT of Type UINT8.
pub(super) fn ifr_default(default_id: u16, value: u8) -> Vec<u8> {
    let data = [&default_id.to_le_bytes()[..], &[0x00, value]].concat();
    operation(DEFAULT, false, &data)
}

/// An EFI_IFR_DEFAULT of Type UINT32.
pub(super) fn uint32_default(default_id: u16, value: u32) -> Vec<u8> {
    let data = [&default_id.to_le_bytes()[..], &[0x02], &value.to_le_bytes()].concat();
    operation(DEFAULT, false, &data)
}

/// An EFI_IFR_DEFAULT_2 whose EFI_IFR_VALUE holds `expression`.
pub(super) fn ifr_default_2(default_id: u16, expression: Vec<u8>) -> Vec<u8> {
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
pub(super) fn conditional(op_code: u8, condition: Vec<u8>, body: &[Vec<u8>]) -> Vec<u8> {
    [
        operation(op_code, true, &[]),
        condition,
        body.concat(),
        END.to_vec(),
    ]
    .concat()
}

pub(super) fn ifr_true() -> Vec<u8> {
    operation(TRUE, false, &[])
}

pub(super) fn ifr_false() -> Vec<u8> {
    operation(FALSE, false, &[])
}

pub(super) fn ifr_ones() -> Vec<u8> {
    operation(ONES, false, &[])
}

pub(super) fn uint8(value: u8) -> Vec<u8> {
    operation(UINT8, false, &[value])
}

/// EFI_IFR_EQ_ID_VAL: question 1 equals 1.
pub(super) fn eq_id_val() -> Vec<u8> {
    operation(EQ_ID_VAL, false, &[0x01, 0x00, 0x01, 0x00])
}

/// EFI_IFR_EQ_ID_VAL: question `question_id` equals `value`.
pub(super) fn eq_id_val_of(question_id: u16, value: u16) -> Vec<u8> {
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
pub(super) struct MapValues(pub(super) HashMap<u16, QuestionValue>);

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

pub(super) fn default_store(default_id: u16) -> Vec<u8> {
    let data = [&[0x08, 0x00][..], &default_id.to_le_bytes()].concat();
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

/// The root of a parsed form package, which owns the parents, and its question.
type RootAndQuestion = (Rc<RefCell<IFROperation>>, Rc<RefCell<IFROperation>>);

/// Parses a FormSet holding `declarations` and then one question, and
/// returns the root, which owns the parents, and that question.
pub(super) fn parse_question(
    declarations: &[Vec<u8>],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
) -> RootAndQuestion {
    try_parse_question(declarations, op_code, data, children).expect("parse the form package")
}

/// `parse_question`, returning the error of an unparsable form package.
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

    let root = handle_form_package(&mut Cursor::new(&data))?;

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
fn question_header_on(question_id: u16, prompt: u16, var_store_id: u16, offset: u16) -> Vec<u8> {
    [
        &prompt.to_le_bytes()[..],
        &[0x04, 0x00],
        &question_id.to_le_bytes(),
        &var_store_id.to_le_bytes(),
        &offset.to_le_bytes(),
        &[0x00],
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
pub(super) fn checkbox_on(question_id: u16, prompt: u16, var_store_id: u16) -> Vec<u8> {
    let data = [
        question_header_on(question_id, prompt, var_store_id, 0),
        vec![0x00],
    ]
    .concat();
    operation(CHECKBOX, false, &data)
}

/// A VARSTORE_EFI of `id` named `name`, of NIL_GUID, with `attributes`, of `size` bytes.
pub(super) fn var_store_efi(id: u16, name: &str, attributes: u32, size: u16) -> Vec<u8> {
    let data = [
        &id.to_le_bytes()[..],
        &[0; 16], // Guid
        &attributes.to_le_bytes(),
        &size.to_le_bytes(),
        name.as_bytes(),
        &[0x00],
    ]
    .concat();
    operation(VAR_STORE_EFI, false, &data)
}

/// An EFI_IFR_FORM of `form_id` holding `body`.
pub(super) fn form(form_id: u16, body: &[Vec<u8>]) -> Vec<u8> {
    let data = [form_id.to_le_bytes(), [0x01, 0x00]].concat();
    [operation(FORM, true, &data), body.concat(), END.to_vec()].concat()
}

/// Parses a FormSet holding `body`, and returns the root.
pub(super) fn parse_form_set(body: &[Vec<u8>]) -> Rc<RefCell<IFROperation>> {
    let data = form_set(body);
    handle_form_package(&mut Cursor::new(&data)).expect("parse the form package")
}

/// Returns the first op under `node`, in IFR order, with `data`.
pub(super) fn find_op(
    node: &Rc<RefCell<IFROperation>>,
    data: &[u8],
) -> Option<Rc<RefCell<IFROperation>>> {
    let op = node.borrow();
    if op.data == data {
        return Some(Rc::clone(node));
    }
    op.children.iter().find_map(|child| find_op(child, data))
}

pub(super) fn checkbox(offset: u16, flags: u8) -> Vec<u8> {
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
pub(super) fn question_descriptor(
    node: &Rc<RefCell<IFROperation>>,
    var_store: VarStoreFixture,
) -> QuestionDescriptor {
    question_descriptor_with(node, var_store, &VarStoreValues::new(&root_of(node)))
}

/// Returns the root of the tree of `node`.
fn root_of(node: &Rc<RefCell<IFROperation>>) -> Rc<RefCell<IFROperation>> {
    let parent = node.borrow().parent.as_ref().and_then(Weak::upgrade);
    match parent {
        Some(parent) => root_of(&parent),
        None => Rc::clone(node),
    }
}

/// The QuestionDescriptor of `node`, with the values that conditions refer to from `values`.
pub(super) fn question_descriptor_with(
    node: &Rc<RefCell<IFROperation>>,
    VarStoreFixture { store, efivars }: VarStoreFixture,
    values: &impl QuestionValues,
) -> QuestionDescriptor {
    let current = node.borrow();
    let strings = strings();
    let mut reader = efivars.reader();
    let walk = &mut FormPackageWalk::new(&strings, &mut reader, values, IncludedStates::empty());
    match &current.parsed_data {
        ParsedOperation::OneOf(parsed) => handle_oneof(store, parsed, "", &current, walk),
        ParsedOperation::Numeric(parsed) => handle_numeric(store, parsed, "", &current, walk),
        ParsedOperation::CheckBox(parsed) => handle_checkbox(store, parsed, "", &current, walk),
        other => panic!("not a question: {other:?}"),
    }
}

/// The answer list-questions and get show for the question.
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
    try_parse_question_in_guid(guid, op_code, data, children).expect("parse the form package")
}

/// `parse_question_in_guid`, returning the error of an unparsable form package.
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

    let root = handle_form_package(&mut Cursor::new(&data))?;

    let form_set = Rc::clone(&root.borrow().children[0]);
    let guid = Rc::clone(&form_set.borrow().children[0]);
    let question = Rc::clone(&guid.borrow().children[0]);
    Ok((root, question))
}
