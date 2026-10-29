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
const UINT8: u8 = 0x42;
pub(super) const TRUE: u8 = 0x46;
const FALSE: u8 = 0x47;
const ONES: u8 = 0x54;
const VALUE: u8 = 0x5A;
pub(super) const DEFAULT: u8 = 0x5B;
const DEFAULT_STORE: u8 = 0x5C;
pub(super) const FORM_MAP: u8 = 0x5D;

const GUID: u8 = 0x5F;

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

/// Serves `payload` after the efivarfs attributes field.
struct MemVarStore {
    payload: Vec<u8>,
}

impl VariableStore for MemVarStore {
    fn name(&self) -> String {
        "MemVarStore".to_string()
    }

    fn guid(&self) -> String {
        "00000000-0000-0000-0000-000000000000".to_string()
    }

    fn size(&self) -> u16 {
        u16::try_from(self.payload.len()).expect("test payload fits a VarStore Size")
    }

    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::EfiVariable
    }

    fn is_runtime_accessible(&self) -> bool {
        true
    }

    fn read_bytes(&self) -> Result<Vec<u8>> {
        Ok([&7u32.to_le_bytes()[..], &self.payload].concat())
    }
}

pub(super) fn mem_var_store(payload: &[u8]) -> Result<Box<dyn VariableStore>> {
    Ok(Box::new(MemVarStore {
        payload: payload.to_vec(),
    }))
}

pub(super) fn unavailable() -> Result<Box<dyn VariableStore>> {
    Err(anyhow!("no VarStore 1"))
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

/// Parses a FormSet holding `declarations` and then one question, and
/// returns the root, which owns the parents, and that question.
pub(super) fn parse_question(
    declarations: &[Vec<u8>],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
) -> (Rc<RefCell<IFROperation>>, Rc<RefCell<IFROperation>>) {
    let data = form_set(&[
        declarations.concat(),
        operation(op_code, true, data),
        children.concat(),
        END.to_vec(), // End of the question
    ]);

    let root = handle_form_package(&mut Cursor::new(&data)).expect("parse the form package");

    let form_set = Rc::clone(&root.borrow().children[0]);
    let question = Rc::clone(&form_set.borrow().children[declarations.len()]);
    assert_eq!(
        question.borrow().children.len(),
        children.len(),
        "children of the parsed question"
    );
    (root, question)
}

/// An EFI_IFR_FORM_SET holding `children`.
pub(super) fn form_set(children: &[Vec<u8>]) -> Vec<u8> {
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
    var_store: Result<Box<dyn VariableStore>>,
) -> QuestionDescriptor {
    let current = node.borrow();
    let strings = strings();
    let walk = &mut FormPackageWalk::new(&strings);
    match &current.parsed_data {
        ParsedOperation::OneOf(parsed) => handle_oneof(var_store, parsed, node, "", &current, walk),
        ParsedOperation::Numeric(parsed) => handle_numeric(var_store, parsed, "", &current, walk),
        ParsedOperation::CheckBox(parsed) => handle_checkbox(var_store, parsed, "", &current, walk),
        other => panic!("not a question: {other:?}"),
    }
}

/// The answer list-questions and get show for the question.
pub(super) fn answer(
    declarations: &[Vec<u8>],
    op_code: u8,
    data: &[u8],
    children: &[Vec<u8>],
    var_store: Result<Box<dyn VariableStore>>,
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
    var_store: Result<Box<dyn VariableStore>>,
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
) -> (Rc<RefCell<IFROperation>>, Rc<RefCell<IFROperation>>) {
    let data = form_set(&[
        operation(GUID, true, &guid),
        operation(op_code, true, data),
        children.concat(),
        END.to_vec(), // End of the question
        END.to_vec(), // End of the GUID
    ]);

    let root = handle_form_package(&mut Cursor::new(&data)).expect("parse the form package");

    let form_set = Rc::clone(&root.borrow().children[0]);
    let guid = Rc::clone(&form_set.borrow().children[0]);
    let question = Rc::clone(&guid.borrow().children[0]);
    (root, question)
}
