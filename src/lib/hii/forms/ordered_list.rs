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

//! ORDERED_LIST questions (UEFI 2.11 §33.2.5.4.8, §33.3.8.3.53): the containers that hold their
//! values, the text that get shows for them and the items that set takes.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use binrw::BinRead;
use thiserror::Error;

use super::conditions::option_state;
use super::conditions::ExpressionInputs;
use super::conditions::IncludedStates;
use super::conditions::QuestionValues;
use super::conditions::StateEvaluation;
use super::defaults::buffer_defaults;
use super::defaults::is_ordered_list_default;
use super::defaults::option_value;
use super::defaults::push_default;
use super::defaults::question_scope;
use super::question_values::shown_option;
use super::set::ChangeValueError;
use super::storage::read_buffer;
use super::storage::stored_value;
use super::storage::BufferExpression;
use super::storage::BufferQuestion;
use super::storage::ValueLocation;
use super::storage::ValueSource;
use super::storage::ValueUnavailable;
use super::storage::VariableStore;
use super::AnswerOption;
use super::FormSetWalk;
use super::IFROperation;
use super::ParsedOperation;
use super::Question;
use super::QuestionDescriptor;
use super::QuestionFlags;
use super::QuestionHeader;
use super::QuestionIdentity;
use super::TextInput;
use super::EFI_IFR_TYPE_NUM_SIZE_16;
use super::EFI_IFR_TYPE_NUM_SIZE_32;
use super::EFI_IFR_TYPE_NUM_SIZE_64;
use crate::hii::strings::ListTexts;
use crate::hii::variables::VariableLayout;

/// EFI_IFR_UNIQUE_SET and EFI_IFR_NO_EMPTY_SET (UEFI 2.11 §33.3.8.3.53).
const EFI_IFR_UNIQUE_SET: u8 = 0x01;
const EFI_IFR_NO_EMPTY_SET: u8 = 0x02;

/// An EFI_IFR_ORDERED_LIST (UEFI 2.11 §33.3.8.3.53), and the layout of the variable that it
/// names, as the FormSet is parsed (parsed_layout).
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(layout: VariableLayout))]
pub struct OrderedList {
    pub question_header: QuestionHeader,
    pub max_containers: u8,
    pub flags: u8,
    #[br(calc = layout)]
    pub(super) layout: VariableLayout,
}

impl Question for OrderedList {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

/// The bytes of each container of an ORDERED_LIST.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ContainerWidth(u8);

impl ContainerWidth {
    /// The width that edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes gives the
    /// containers of an ORDERED_LIST whose first option has Type `value_type`: that of a numeric
    /// Type, else 1. UEFI 2.11 §33.2.5.4.8 gives one byte, which holds no UINT16 option value.
    fn of(value_type: u8) -> Self {
        Self(match value_type {
            EFI_IFR_TYPE_NUM_SIZE_16 => 2,
            EFI_IFR_TYPE_NUM_SIZE_32 => 4,
            EFI_IFR_TYPE_NUM_SIZE_64 => 8,
            _ => 1,
        })
    }

    /// The values of the containers of this width in `bytes`, up to the first empty one, which
    /// holds 0 (UEFI 2.11 §33.3.8.3.53).
    fn containers(self, bytes: &[u8]) -> Vec<u64> {
        bytes
            .chunks_exact(usize::from(self.0))
            .map(stored_value)
            .take_while(|&value| value != 0)
            .collect()
    }
}

/// An ORDERED_LIST and the width of its containers.
#[derive(Clone, Copy)]
pub(super) struct OrderedListQuestion<'a> {
    pub(super) list: &'a OrderedList,
    /// None without options: edk2 then gives the question no storage
    width: Option<ContainerWidth>,
}

impl<'a> OrderedListQuestion<'a> {
    /// The ORDERED_LIST `list` of the op `op`.
    pub(super) fn of(op: &IFROperation, list: &'a OrderedList) -> Self {
        let width = question_scope(op).iter().find_map(|child| {
            let child = child.borrow();
            let ParsedOperation::OneOfOption(option) = &child.parsed_data else {
                return None;
            };
            (!is_ordered_list_default(op, option)).then(|| ContainerWidth::of(option.value_type))
        });
        Self { list, width }
    }

    /// Where it keeps its value: its containers from VarOffset, or from byte 0 of the variable of
    /// its VarName.
    pub(super) fn location(self) -> ValueLocation {
        ValueLocation::Bytes {
            offset: self.offset(),
            size: self.size(),
        }
    }

    /// Whether it has options, whose Type gives its containers their width.
    pub(super) fn has_options(self) -> bool {
        self.width.is_some()
    }

    /// Where its containers start in its variable.
    fn offset(self) -> u16 {
        self.list
            .layout
            .offset(self.list.question_header.var_store_info)
    }

    /// The bytes of its MaxContainers containers, the StorageWidth of edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c.
    fn size(self) -> u16 {
        let width = self.width.map_or(0, |ContainerWidth(width)| width);
        u16::from(self.list.max_containers) * u16::from(width)
    }

    /// The values of the containers in `bytes`, the bytes of its location, up to the first empty
    /// one, which holds 0 (UEFI 2.11 §33.3.8.3.53).
    fn containers(self, bytes: &[u8]) -> Vec<u64> {
        self.width
            .map_or_else(Vec::new, |width| width.containers(bytes))
    }

    /// The values of the containers that the default `buffer` fills from the first, the rest
    /// empty (UEFI 2.11 §33.2.5.4.8), as edk2-stable202608 SetupBrowserDxe/Setup.c
    /// GetQuestionDefault copies it, up to the bytes of its location.
    fn default_containers(self, buffer: &[u8]) -> Vec<u64> {
        let mut bytes = vec![0; usize::from(self.size())];
        bytes
            .iter_mut()
            .zip(buffer)
            .for_each(|(byte, default)| *byte = *default);
        self.containers(&bytes)
    }
}

/// An item that get shows: the option of a container's value, or the value, which no option has.
enum Item<'o> {
    Option(&'o AnswerOption),
    Value(u64),
}

impl Item<'_> {
    /// The option of `options` that get shows for the container value `value`, as for a ONE_OF
    /// (shown_option).
    fn of(options: &[AnswerOption], value: u64) -> Item<'_> {
        shown_option(options, value, None)
            .and_then(|index| options.get(index))
            .map_or(Item::Value(value), Item::Option)
    }

    fn text(&self) -> String {
        match self {
            Self::Option(option) => option.value.trim().to_string(),
            Self::Value(value) => format!("{value} (no matching option)"),
        }
    }

    /// Its text, then the state of its option unless selectable.
    fn annotated(&self) -> String {
        match self {
            Self::Option(option) => self.text() + &option.state.option_annotation(),
            Self::Value(_) => self.text(),
        }
    }
}

/// get's text of an ORDERED_LIST of `items`: each with its option's state, in order.
fn list_text(items: &[Item<'_>]) -> String {
    let texts: Vec<String> = items.iter().map(Item::annotated).collect();
    texts.join(", ")
}

/// The answer that set gives an ORDERED_LIST that it sets to `options`, in order, as get shows
/// it then.
pub(super) fn items_answer(options: &[&AnswerOption]) -> String {
    let items: Vec<Item<'_>> = options.iter().map(|&option| Item::Option(option)).collect();
    list_text(&items)
}

/// Why set refuses to give an ORDERED_LIST, or another question, a value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ListRefusal {
    #[error("an ORDERED_LIST takes its options in order, each with --item")]
    Text,
    #[error("--item gives the options of an ORDERED_LIST; this question takes VALUE")]
    Items,
    #[error("the ORDERED_LIST has no option, so its containers have no width")]
    NoOptions,
    #[error("{item:?} is no option of the ORDERED_LIST")]
    NotAnOption { item: String },
    #[error("the ORDERED_LIST holds at most {max} items (MaxContainers), not {given}")]
    TooMany { max: u8, given: usize },
    #[error(
        "the ORDERED_LIST has no empty container (EFI_IFR_NO_EMPTY_SET): it takes {max} items, \
         not {given}"
    )]
    Empty { max: u8, given: usize },
    #[error(
        "the ORDERED_LIST takes each option once (EFI_IFR_UNIQUE_SET): {option:?} is given twice"
    )]
    Duplicate { option: String },
    #[error(
        "option {option:?} has value 0, which marks an empty container (UEFI 2.11 §33.3.8.3.53)"
    )]
    ZeroValue { option: String },
    #[error("option {option:?} has a value that is no number, which no container holds")]
    NotNumeric { option: String },
    #[error(
        "option {option:?} has value {value}, wider than the {width}-byte containers of the \
         ORDERED_LIST"
    )]
    TooWide {
        option: String,
        value: u64,
        width: u8,
    },
    /// A stored item whose option IFR conditions hide or may hide, which `items` leaves out
    #[error(
        "it holds {option:?}{annotation}, and set drops no item of a hidden option: give it with \
         --item, and --include {states}"
    )]
    HiddenDropped {
        option: String,
        annotation: String,
        states: IncludedStates,
    },
    #[error("its items cannot be read, so set cannot keep those of hidden options: {0}")]
    StoredUnread(String),
    /// A keyword VALUE, which SetData() writes as given
    #[error(
        "a container after an empty one holds a value, where set writes 0 after the last item \
         (UEFI 2.11 §33.3.8.3.53)"
    )]
    AfterEmpty,
    #[error("{0}")]
    Expression(BufferExpression),
}

impl ListRefusal {
    /// set's error for `question` that it refuses so.
    pub(super) fn of(self, question: &QuestionDescriptor) -> ChangeValueError {
        ChangeValueError::OrderedList {
            question: question.question.clone(),
            refusal: self,
        }
    }
}

/// The bytes that set writes to the containers of an ORDERED_LIST, at VarOffset `offset`.
pub(super) struct ListWrite {
    pub(super) offset: u16,
    pub(super) bytes: Vec<u8>,
}

/// How set takes the items of an ORDERED_LIST: its containers, its Flags, and the values that it
/// holds.
pub(super) struct ListInput {
    offset: u16,
    width: Option<ContainerWidth>,
    max_containers: u8,
    flags: u8,
    stored: StoredItems,
}

/// The values of the containers of an ORDERED_LIST up to the first empty one, whose items of
/// hidden options set keeps.
enum StoredItems {
    Read(Vec<u64>),
    /// None: the EFI variable of its VarName on a VARSTORE_EFI before UEFI 2.3.1 does not exist,
    /// where edk2-stable202608 SetupBrowserDxe keeps the BufferValue that IfrParse.c zeroes
    /// (:2493) as GetVariable() fails (Setup.c:1779-1782), loads no default into it
    /// (Setup.c:5725-5727), and creates the variable through SetVariable() (Setup.c:2069-2075)
    Missing,
    /// Why they cannot be read
    Unread(String),
}

impl StoredItems {
    /// Those of `stored`, the values read from a variable of `layout`, if it has a VarStore.
    fn of(stored: Result<Vec<u64>, ValueUnavailable>, layout: Option<VariableLayout>) -> Self {
        match (stored, layout) {
            (Ok(values), _) => Self::Read(values),
            (Err(ValueUnavailable::Missing(_)), Some(VariableLayout::OneValue)) => Self::Missing,
            (Err(reason), _) => Self::Unread(reason.to_string()),
        }
    }
}

impl ListInput {
    /// The texts of the options of its stored items, in order, as get shows them without their
    /// states; None if they cannot be read.
    pub(super) fn items(&self, options: &[AnswerOption]) -> Option<Vec<String>> {
        let stored = match &self.stored {
            StoredItems::Read(values) => values,
            StoredItems::Missing | StoredItems::Unread(_) => return None,
        };
        Some(
            stored
                .iter()
                .map(|&value| Item::of(options, value).text())
                .collect(),
        )
    }

    /// The write that sets `question`, the ORDERED_LIST of this input, to `items`, in order, each
    /// the text of an option that select_option picks with `include`, and those options
    /// (write_options).
    pub(super) fn write<'q>(
        &self,
        question: &'q QuestionDescriptor,
        items: &[String],
        include: IncludedStates,
    ) -> anyhow::Result<(ListWrite, Vec<&'q AnswerOption>)> {
        let options = items
            .iter()
            .map(|item| -> anyhow::Result<&'q AnswerOption> {
                let option = question.select_option(&BTreeSet::from([item.clone()]), include)?;
                Ok(option
                    .ok_or_else(|| ListRefusal::NotAnOption { item: item.clone() }.of(question))?)
            });
        self.write_options(question, options)
    }

    /// The bytes of each of its containers (ContainerWidth::of); None without options.
    pub(super) fn container_width(&self) -> Option<usize> {
        self.width.map(|ContainerWidth(width)| usize::from(width))
    }

    /// The values of the containers in `bytes`, a keyword VALUE of every container, which
    /// SetData() writes as given, up to the first empty one: refuses a VALUE that fills a
    /// container after it.
    pub(super) fn container_values(
        &self,
        question: &QuestionDescriptor,
        bytes: &[u8],
    ) -> Result<Vec<u64>, ChangeValueError> {
        let Some(width) = self.width else {
            return Err(ListRefusal::NoOptions.of(question));
        };
        let values = width.containers(bytes);
        let filled = values.len() * usize::from(width.0);
        if bytes.iter().skip(filled).any(|&byte| byte != 0) {
            return Err(ListRefusal::AfterEmpty.of(question));
        }
        Ok(values)
    }

    /// The write that sets `question`, the ORDERED_LIST of this input, to `options`, in order,
    /// and those options. It refuses more options than MaxContainers, fewer under
    /// EFI_IFR_NO_EMPTY_SET, an option twice under EFI_IFR_UNIQUE_SET, an option whose value no
    /// container holds, and a list that drops a stored item whose option IFR conditions hide or
    /// may hide; it fails as `options` fails to give an option, in its order.
    pub(super) fn write_options<'q>(
        &self,
        question: &'q QuestionDescriptor,
        options: impl ExactSizeIterator<Item = anyhow::Result<&'q AnswerOption>>,
    ) -> anyhow::Result<(ListWrite, Vec<&'q AnswerOption>)> {
        let Some(ContainerWidth(width)) = self.width else {
            return Err(ListRefusal::NoOptions.of(question).into());
        };
        let (max, given) = (self.max_containers, options.len());
        if given > usize::from(max) {
            return Err(ListRefusal::TooMany { max, given }.of(question).into());
        }
        if self.flags & EFI_IFR_NO_EMPTY_SET != 0 && given < usize::from(max) {
            return Err(ListRefusal::Empty { max, given }.of(question).into());
        }
        let mut written = Vec::new();
        let mut values = Vec::new();
        for option in options {
            let option = option?;
            let text = || option.value.trim().to_string();
            let known =
                option
                    .raw_value
                    .clone()
                    .map_err(|reason| ChangeValueError::OptionValue {
                        question: question.question.clone(),
                        option: option.value.clone(),
                        reason,
                    })?;
            let value = match known.as_u64() {
                None => {
                    return Err(ListRefusal::NotNumeric { option: text() }
                        .of(question)
                        .into())
                }
                Some(0) => {
                    return Err(ListRefusal::ZeroValue { option: text() }
                        .of(question)
                        .into())
                }
                Some(value) => value,
            };
            if value.checked_shr(u32::from(width) * u8::BITS).unwrap_or(0) != 0 {
                return Err(ListRefusal::TooWide {
                    option: text(),
                    value,
                    width,
                }
                .of(question)
                .into());
            }
            if self.flags & EFI_IFR_UNIQUE_SET != 0 && values.contains(&value) {
                return Err(ListRefusal::Duplicate { option: text() }
                    .of(question)
                    .into());
            }
            written.push(option);
            values.push(value);
        }
        self.check_hidden_kept(&question.possible_options, &values)
            .map_err(|refusal| refusal.of(question))?;
        let mut bytes = vec![0; usize::from(max) * usize::from(width)];
        for (container, value) in bytes.chunks_exact_mut(usize::from(width)).zip(&values) {
            container
                .iter_mut()
                .zip(value.to_le_bytes())
                .for_each(|(byte, value)| *byte = value);
        }
        Ok((
            ListWrite {
                offset: self.offset,
                bytes,
            },
            written,
        ))
    }

    /// Refuses `values`, the new items, unless they keep each stored item whose options of
    /// `options` IFR conditions hide or may hide.
    fn check_hidden_kept(
        &self,
        options: &[AnswerOption],
        values: &[u64],
    ) -> Result<(), ListRefusal> {
        let stored = match &self.stored {
            StoredItems::Read(values) => values,
            StoredItems::Missing => return Ok(()),
            StoredItems::Unread(reason) => return Err(ListRefusal::StoredUnread(reason.clone())),
        };
        for &value in stored {
            if values.contains(&value) {
                continue;
            }
            let Item::Option(option) = Item::of(options, value) else {
                continue;
            };
            if !option.state.is_allowed(IncludedStates::empty()) {
                return Err(ListRefusal::HiddenDropped {
                    option: option.value.trim().to_string(),
                    annotation: option.state.option_annotation(),
                    states: option.state.hidden_states(),
                });
            }
        }
        Ok(())
    }
}

/// The options of the ORDERED_LIST `question`, in IFR order: the EFI_IFR_ONE_OF_OPTIONs of its
/// scope but those whose Value edk2-stable202608 SetupBrowserDxe/IfrParse.c takes as a default.
fn list_options(
    question: &IFROperation,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Vec<AnswerOption> {
    question_scope(question)
        .iter()
        .filter_map(|op| {
            let op = op.borrow();
            let ParsedOperation::OneOfOption(option) = &op.parsed_data else {
                return None;
            };
            (!is_ordered_list_default(question, option)).then(|| AnswerOption {
                value_type: option.value_type,
                raw_value: option_value(question, &op, option, inputs),
                // option_value evaluates the EFI_IFR_VALUE of an option of Type OTHER of a
                // ONE_OF only, so no option of an ORDERED_LIST takes a snapshot value
                source: ValueSource::Current,
                value: texts.display(option.option_string_id).to_string(),
                texts: texts
                    .matching(option.option_string_id)
                    .map(|(language, text)| (language.clone(), text.to_string()))
                    .collect(),
                state: option_state(&op, inputs),
            })
        })
        .collect()
}

/// The answer that show-ifr shows for the ORDERED_LIST `question` of the op `node` on
/// `varstore`: its items as get shows them, or why it has none.
pub(super) fn display_list_answer(
    node: &Rc<RefCell<IFROperation>>,
    question: OrderedListQuestion<'_>,
    varstore: &anyhow::Result<Box<dyn VariableStore>>,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> String {
    let options = list_options(&node.borrow(), texts, inputs);
    match read_buffer(node, BufferQuestion::OrderedList, varstore, inputs.reader) {
        Ok((bytes, source)) => {
            let items: Vec<Item<'_>> = question
                .containers(&bytes)
                .into_iter()
                .map(|value| Item::of(&options, value))
                .collect();
            list_text(&items) + source.annotation()
        }
        Err(reason) => reason.to_answer(),
    }
}

/// The QuestionDescriptor of the ORDERED_LIST `question`: the texts of the options of its
/// containers, in order, else why it has none and its default.
pub(super) fn handle_ordered_list(
    varstore: anyhow::Result<Box<dyn VariableStore>>,
    question: OrderedListQuestion<'_>,
    prompt: &str,
    flags: QuestionFlags,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let possible_options = list_options(current_node, walk.texts, &mut walk.inputs);
    let read = read_buffer(
        node,
        BufferQuestion::OrderedList,
        &varstore,
        walk.inputs.reader,
    );
    let (stored, value_source) = match read {
        Ok((bytes, source)) => (Ok(question.containers(&bytes)), source),
        Err(reason) => (Err(reason), ValueSource::Current),
    };
    let mut answer = match &stored {
        Ok(values) => {
            let items: Vec<Item<'_>> = values
                .iter()
                .map(|&value| Item::of(&possible_options, value))
                .collect();
            list_text(&items)
        }
        Err(reason) => reason.to_answer(),
    };
    let stores = walk.default_stores.of(current_node, &mut walk.inputs);
    let defaults = buffer_defaults(
        current_node,
        BufferQuestion::OrderedList,
        stores,
        walk.texts,
        &mut walk.inputs,
        |buffer| {
            let texts: Vec<String> = question
                .default_containers(buffer)
                .into_iter()
                .map(|value| Item::of(&possible_options, value).text())
                .collect();
            Ok(texts.join(", "))
        },
    );
    if stored.is_err() {
        push_default(&mut answer, &defaults, stores);
    }
    let list = question.list;
    let layout = varstore.as_ref().ok().map(|store| store.layout());
    QuestionDescriptor {
        question: prompt.trim().to_string(),
        value: answer,
        help: walk
            .texts
            .display(list.question_header().help_string_id)
            .to_string(),
        possible_options,
        // StoragelessQuestion::refusal refuses one that its driver holds
        driver_held: None,
        varstore,
        location: question.location(),
        input: TextInput::OrderedList(ListInput {
            offset: question.offset(),
            width: question.width,
            max_containers: list.max_containers,
            flags: list.flags,
            stored: StoredItems::of(stored, layout),
        }),
        opcode: current_node.op_code,
        flags,
        defaults,
        identity: QuestionIdentity::of(current_node, &list.question_header(), walk.texts),
        value_state: StateEvaluation::selectable(),
        value_source,
        node: Rc::clone(node),
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use std::rc::Rc;

    use super::super::conditions::IncludedStates;
    use super::super::display;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::DefaultId;
    use super::super::EFI_IFR_TYPE_BOOLEAN;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_16;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_32;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_64;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_8;

    /// The missing EFI variable of list_answers.
    const MISSING: &str =
        "<ValueUnavailable: no EFI variable Setup-00000000-0000-0000-0000-000000000000>";

    /// UINT16 options: Disabled 2, Enabled 1, AllOnes 3.
    fn uint16_options() -> Vec<Vec<u8>> {
        [(5, 2u16), (6, 1), (7, 3)]
            .map(|(text, value)| {
                one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_16, &value.to_le_bytes())
            })
            .to_vec()
    }

    /// The answers that list-questions gives for an ORDERED_LIST of `max_containers` and `flags`
    /// holding `children`, at VarOffset 0 of the EFI variable Setup of `size` bytes, which holds
    /// `payload` if any, and for the questions in `declarations` before it.
    fn list_answers(
        declarations: &[Vec<u8>],
        (max_containers, flags): (u8, u8),
        children: &[Vec<u8>],
        (size, payload): (u16, Option<&[u8]>),
    ) -> Vec<String> {
        let efivars = Efivars::new();
        if let Some(payload) = payload {
            efivars.write(&efi_variable("Setup", usize::from(size)), payload);
        }
        let root = parse_form_set(&[
            declarations.concat(),
            var_store_efi(1, "Setup", NV_BS_RT, size),
            operation(ORDERED_LIST, true, &ordered_list(0, max_containers, flags)),
            children.concat(),
            END.to_vec(),
        ]);
        list_questions(
            Rc::clone(&root),
            &ListTexts::new(&strings(), &[]),
            IncludedStates::all(),
            None,
            &mut efivars.reader(),
        )
        .into_iter()
        .map(|(question, _)| question.value)
        .collect()
    }

    /// An ORDERED_LIST shows the texts of the options of its containers, in order, up to the first
    /// empty one, which holds 0 (UEFI 2.11 §33.3.8.3.53), each container as wide as the Type of
    /// its first option (edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes).
    #[test]
    fn ordered_list_shows_the_options_of_its_containers_in_order() {
        let cases: [(&str, [u8; 8], &str); 5] = [
            (
                "two, then empty",
                [2, 0, 1, 0, 0, 0, 3, 0],
                "Disabled, Enabled",
            ),
            (
                "full, with a repeat",
                [3, 0, 2, 0, 1, 0, 2, 0],
                "AllOnes, Disabled, Enabled, Disabled",
            ),
            ("empty", [0; 8], ""),
            (
                "a value without an option",
                [9, 0, 1, 0, 0, 0, 0, 0],
                "9 (no matching option), Enabled",
            ),
            (
                "a container of high byte only",
                [0, 1, 2, 0, 0, 0, 0, 0],
                "256 (no matching option), Disabled",
            ),
        ];
        for (name, payload, want) in cases {
            assert_eq!(
                list_answers(&[], (4, 0x00), &uint16_options(), (8, Some(&payload))),
                [want],
                "{name}"
            );
        }
    }

    /// The width of the containers comes from the first option that is no default: a UINT8 one
    /// gives 1 byte, a BOOLEAN one 1 byte as edk2 gives any non-numeric Type, and a default
    /// option of Type BUFFER before a UINT16 one leaves 2.
    #[test]
    fn container_width_is_that_of_the_first_option_but_defaults() {
        let uint8 = |text, value| one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_8, &[value]);
        let cases = [
            (
                "UINT8",
                vec![uint8(5, 2), uint8(6, 1)],
                "Disabled, Enabled, Disabled",
            ),
            (
                "BOOLEAN first",
                vec![one_of_option(5, EFI_IFR_TYPE_BOOLEAN, &[1]), uint8(6, 2)],
                "Enabled, Disabled, Enabled",
            ),
            (
                "UINT16 after a default",
                [vec![buffer_option(7, 0x10, &[1, 0])], uint16_options()].concat(),
                "258 (no matching option), Disabled, AllOnes",
            ),
        ];
        for (name, children, want) in cases {
            assert_eq!(
                list_answers(
                    &[],
                    (4, 0x00),
                    &children,
                    (8, Some(&[2, 1, 2, 0, 3, 0, 0, 0]))
                ),
                [want],
                "{name}"
            );
        }
    }

    /// Without a value, an ORDERED_LIST shows its default of Type BUFFER, one container value per
    /// container width in order, the rest empty (UEFI 2.11 §33.2.5.4.8), from an EFI_IFR_DEFAULT
    /// or an option flagged default, each of whose Value edk2-stable202608 IfrParse.c takes as
    /// the default instead of an option; and a default of another Type refused.
    #[test]
    fn ordered_list_without_a_value_shows_its_buffer_default() {
        let cases = [
            (
                "EFI_IFR_DEFAULT",
                vec![],
                vec![buffer_default(0x0000, &[3, 0, 2, 0])],
                "<IFR default: AllOnes, Disabled>",
            ),
            (
                "option flagged EFI_IFR_OPTION_DEFAULT",
                vec![],
                vec![buffer_option(5, 0x10, &[1, 0, 3, 0])],
                "<IFR default: Enabled, AllOnes>",
            ),
            (
                "option flagged EFI_IFR_OPTION_DEFAULT_MFG",
                vec![default_store(0x0001)],
                vec![buffer_option(5, 0x20, &[2, 0])],
                "<IFR default (DefaultId 0x0001): Disabled>",
            ),
            (
                "longer than its containers",
                vec![],
                vec![buffer_default(0x0000, &[1, 0, 2, 0, 3, 0, 1, 0, 2, 0])],
                "<IFR default: Enabled, Disabled, AllOnes, Enabled>",
            ),
            (
                "UINT8 EFI_IFR_DEFAULT",
                vec![],
                vec![ifr_default(0x0000, 1)],
                "<IFR default: unknown (a default of a number where the question stores a buffer)>",
            ),
        ];
        for (name, declarations, defaults, want) in cases {
            let children = [uint16_options(), defaults].concat();
            assert_eq!(
                list_answers(&declarations, (4, 0x00), &children, (8, None)),
                [format!("{MISSING} {want}")],
                "{name}"
            );
        }
    }

    /// The defaults of an ORDERED_LIST list each DefaultId that it declares, by an EFI_IFR_DEFAULT
    /// of Type EFI_IFR_TYPE_BUFFER or by an option flagged default, valued by the texts of their
    /// items, also a manufacturing one that no DEFAULTSTORE declares.
    #[test]
    fn ordered_list_lists_each_declared_default() {
        let children = [
            uint16_options(),
            vec![
                buffer_default(0x0000, &[2, 0, 1, 0]),
                buffer_option(5, 0x20, &[3, 0]),
            ],
        ]
        .concat();
        let (_root, node) = parse_question(&[], ORDERED_LIST, &ordered_list(0, 4, 0), &children);
        let defaults: Vec<(DefaultId, String)> = question_descriptor(&node, unavailable())
            .defaults
            .iter()
            .map(|default| (default.default_id, default.value.to_string()))
            .collect();
        assert_eq!(
            defaults,
            [
                (DefaultId(0x0000), "Disabled, Enabled".to_string()),
                (DefaultId(0x0001), "AllOnes".to_string()),
            ]
        );
    }

    /// show-ifr shows an ORDERED_LIST with its MaxContainers and Flags, and its items as get
    /// shows them.
    #[test]
    fn show_ifr_shows_the_items_as_get_does() {
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 8), &[2, 0, 1, 0, 0, 0, 3, 0]);
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 8),
            operation(ORDERED_LIST, true, &ordered_list(0, 4, 0x01)),
            uint16_options().concat(),
            END.to_vec(),
        ]);
        let shown = display(
            root,
            0,
            &ListTexts::new(&strings(), &[]),
            &mut efivars.reader(),
        )
        .expect("display");
        let lines: Vec<&str> = shown.lines().map(str::trim_start).collect();
        let want = [
            "OpCode: OrderedList - Q: Prompt - Help: ",
            "-MaxContainers: 4 - Flags: 0x01",
            "-Answer: Disabled, Enabled",
        ];
        let at = lines
            .iter()
            .position(|line| *line == want[0])
            .unwrap_or_else(|| panic!("no line {:?}: {shown}", want[0]));
        assert_eq!(lines.get(at..at + 3), Some(&want[..]), "{shown}");
    }

    /// An option of a container that a SUPPRESS_IF hides shows its state after its text.
    #[test]
    fn items_show_the_states_of_their_options() {
        let children = [
            conditional(
                SUPPRESS_IF,
                ifr_true(),
                &[one_of_option(
                    7,
                    EFI_IFR_TYPE_NUM_SIZE_16,
                    &3u16.to_le_bytes(),
                )],
            ),
            one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_16, &2u16.to_le_bytes()),
        ];
        assert_eq!(
            list_answers(
                &[],
                (4, 0x00),
                &children,
                (8, Some(&[3, 0, 2, 0, 0, 0, 0, 0]))
            ),
            ["AllOnes <option suppressed>, Disabled"]
        );
    }

    /// A container value with a hidden and a shown option shows the shown one, though the
    /// hidden one comes first.
    #[test]
    fn item_shows_the_shown_option_of_its_value() {
        let children = [
            conditional(
                SUPPRESS_IF,
                ifr_true(),
                &[one_of_option(
                    7,
                    EFI_IFR_TYPE_NUM_SIZE_16,
                    &2u16.to_le_bytes(),
                )],
            ),
            one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_16, &2u16.to_le_bytes()),
        ];
        assert_eq!(
            list_answers(
                &[],
                (4, 0x00),
                &children,
                (8, Some(&[2, 0, 0, 0, 0, 0, 0, 0]))
            ),
            ["Disabled"]
        );
    }

    /// UINT32 and UINT64 options give containers of 4 and 8 bytes, each value in all of them.
    #[test]
    fn uint32_and_uint64_options_give_containers_of_4_and_8_bytes() {
        let uint32 =
            |text, value: u32| one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_32, &value.to_le_bytes());
        let uint64 =
            |text, value: u64| one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_64, &value.to_le_bytes());
        let cases = [
            (
                "UINT32",
                vec![uint32(5, 2), uint32(6, 1), uint32(7, 0x0001_0000)],
                [
                    &0x0001_0000u32.to_le_bytes()[..],
                    &1u32.to_le_bytes(),
                    &[0; 4],
                ]
                .concat(),
            ),
            (
                "UINT64",
                vec![uint64(5, 2), uint64(6, 1), uint64(7, 0x0001_0000_0000)],
                [
                    &0x0001_0000_0000u64.to_le_bytes()[..],
                    &1u64.to_le_bytes(),
                    &[0; 8],
                ]
                .concat(),
            ),
        ];
        for (name, children, payload) in cases {
            let size = u16::try_from(payload.len()).expect("payload size");
            assert_eq!(
                list_answers(&[], (3, 0x00), &children, (size, Some(&payload))),
                ["AllOnes, Enabled"],
                "{name}"
            );
        }
    }

    /// An ORDERED_LIST whose READ or EFI_IFR_VALUE expression gives its value, a buffer, shows why
    /// it has none; one without a VarStore shows why a question without one has none, as other
    /// questions do (StoragelessQuestion takes ORDERED_LIST).
    #[test]
    fn ordered_list_shows_why_an_expression_or_no_var_store_gives_no_value() {
        let read = "<ValueUnavailable: its READ expression gives the buffer of an ORDERED_LIST, \
                    which uefisettings does not evaluate>";
        let value = "<ValueUnavailable: its EFI_IFR_VALUE expression gives the buffer of an \
                     ORDERED_LIST, which uefisettings does not evaluate>";
        let expression =
            |op_code| [operation(op_code, true, &[]), ifr_true(), END.to_vec()].concat();
        let cases = [
            ("READ", expression(READ), read),
            ("EFI_IFR_VALUE", expression(VALUE), value),
        ];
        for (name, child, want) in cases {
            let children = [uint16_options(), vec![child]].concat();
            assert_eq!(
                list_answers(
                    &[],
                    (4, 0x00),
                    &children,
                    (8, Some(&[1, 0, 0, 0, 0, 0, 0, 0]))
                ),
                [want],
                "{name}"
            );
        }

        let efivars = Efivars::new();
        let data = [question_header_on(1, 3, 0, 0), vec![4, 0x00]].concat();
        let root = parse_form_set(&[
            operation(ORDERED_LIST, true, &data),
            uint16_options().concat(),
            END.to_vec(),
        ]);
        let answers: Vec<String> = list_questions(
            root,
            &ListTexts::new(&strings(), &[]),
            IncludedStates::all(),
            None,
            &mut efivars.reader(),
        )
        .into_iter()
        .map(|(question, _)| question.value)
        .collect();
        assert_eq!(
            answers,
            [
                "<ValueUnavailable: question has no VarStore, READ or WRITE expression, or \
              EFI_IFR_FLAG_CALLBACK, one of which UEFI 2.11 §33.2.5.6 requires>"
            ],
            "without a VarStore"
        );
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod write_tests {
    use std::collections::BTreeSet;
    use std::rc::Rc;

    use super::super::conditions::IncludedStates;
    use super::super::ifr_fixtures::*;
    use super::super::set::NewAnswer;
    use super::super::set_questions;
    use super::super::IFROperation;
    use super::super::QuestionDescriptor;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_16;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_32;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_64;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_8;
    use super::StoredItems;
    use super::ValueUnavailable;
    use super::VariableLayout;
    use crate::hii::variables::EfivarReader;
    use crate::hii::variables::FirmwareVariables;
    use crate::hii::variables::VariableNotFound;
    use crate::hii::variables::VolatileWrites;
    use crate::hii::variables::WithheldBytes;
    use crate::hii::variables::WithholdingVariables;
    use crate::unsafe_operations::PendingOperations;
    use crate::unsafe_operations::UnsafeOperations;

    /// UINT16 options: Disabled 2, Enabled 1, AllOnes 3.
    fn uint16_options() -> Vec<Vec<u8>> {
        [(5, 2u16), (6, 1), (7, 3)]
            .map(|(text, value)| {
                one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_16, &value.to_le_bytes())
            })
            .to_vec()
    }

    /// The UINT16 options, AllOnes in a SUPPRESS_IF TRUE.
    fn suppressed_all_ones() -> Vec<Vec<u8>> {
        let options = uint16_options();
        vec![
            options[0].clone(),
            options[1].clone(),
            conditional(SUPPRESS_IF, ifr_true(), &[options[2].clone()]),
        ]
    }

    /// An ORDERED_LIST of 4 containers with `flags` holding `children`, at VarOffset 0 of the EFI
    /// variable List, which holds `payload`, as set sees it, the root of its FormSet, and the
    /// variables that hold it too.
    fn list_on(
        flags: u8,
        children: &[Vec<u8>],
        payload: &[u8],
    ) -> (
        QuestionDescriptor,
        Rc<std::cell::RefCell<IFROperation>>,
        MemoryVariables,
    ) {
        let variables = MemoryVariables::default();
        let (root, node) = parse_question(&[], ORDERED_LIST, &ordered_list(0, 4, flags), children);
        let question = question_descriptor(&node, writable_var_store("List", payload, &variables));
        (question, root, variables)
    }

    /// What set of a question did: the answer and items it gives, or its error as the CLI prints
    /// it, and the writes to List.
    type Outcome = (
        Result<(String, Option<Vec<String>>), String>,
        Vec<(u16, Vec<u8>)>,
    );

    /// set of `question` to `answer` with `include` in `variables`.
    fn set_to(
        question: &QuestionDescriptor,
        answer: NewAnswer<'_>,
        include: IncludedStates,
        variables: &MemoryVariables,
    ) -> Outcome {
        // no ORDERED_LIST write reads
        let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
            variables.reach(),
            variables.interface(),
        )));
        let set = set_questions(
            "",
            &[("L", question)],
            answer,
            include,
            &mut reader,
            None,
            VolatileWrites::Refuse,
            PendingOperations::new(UnsafeOperations::Refuse),
            &WithholdingVariables::new(variables, WithheldBytes::default()),
        )
        .map(|(written, _)| {
            let [written] = written.as_slice() else {
                panic!("one question written");
            };
            (written.given.answer(""), written.given.items())
        })
        .map_err(|error| format!("{error:#}"));
        (set, variables.writes_to(&variable_key("List")))
    }

    /// set of `question` to `items`.
    fn set_items(
        question: &QuestionDescriptor,
        items: &[&str],
        include: IncludedStates,
        variables: &MemoryVariables,
    ) -> Outcome {
        let items: Vec<String> = items.iter().map(|item| item.to_string()).collect();
        set_to(question, NewAnswer::Items(&items), include, variables)
    }

    /// The outcome of a set that writes `bytes` and answers `answer` with `items`.
    fn written(bytes: [u8; 8], answer: &str, items: &[&str]) -> Outcome {
        let items = items.iter().map(|item| item.to_string()).collect();
        (
            Ok((answer.to_string(), Some(items))),
            vec![(0, bytes.to_vec())],
        )
    }

    /// A list that set writes: the items, the bytes written, the answer, and the items shown.
    type WrittenCase = (
        &'static [&'static str],
        [u8; 8],
        &'static str,
        &'static [&'static str],
    );

    /// A set of a list that holds an item of a hidden option: the name, the payload, the items,
    /// the states to include, and what set did.
    type KeptCase = (
        &'static str,
        [u8; 8],
        &'static [&'static str],
        IncludedStates,
        Outcome,
    );

    /// The outcome of a set refused for `refusal`, which writes nothing.
    fn refused(refusal: &str) -> Outcome {
        (Err(format!("cannot set question \"\": {refusal}")), vec![])
    }

    /// set writes the values of the options of the items to the containers in order, in their
    /// width, the rest empty, and answers them as get shows them; an item matches the text of an
    /// option ignoring ASCII case, and may repeat without EFI_IFR_UNIQUE_SET.
    #[test]
    fn items_are_written_to_the_containers_in_order() {
        let cases: [WrittenCase; 4] = [
            (
                &["Enabled", "Disabled"],
                [1, 0, 2, 0, 0, 0, 0, 0],
                "Enabled, Disabled",
                &["Enabled", "Disabled"],
            ),
            (
                &["allones"],
                [3, 0, 0, 0, 0, 0, 0, 0],
                "AllOnes",
                &["AllOnes"],
            ),
            (
                &["AllOnes", "AllOnes", "Enabled", "Disabled"],
                [3, 0, 3, 0, 1, 0, 2, 0],
                "AllOnes, AllOnes, Enabled, Disabled",
                &["AllOnes", "AllOnes", "Enabled", "Disabled"],
            ),
            (&[], [0; 8], "", &[]),
        ];
        for (items, bytes, answer, shown) in cases {
            let (question, _root, variables) = list_on(0x00, &uint16_options(), &[9; 8]);
            assert_eq!(
                set_items(&question, items, IncludedStates::empty(), &variables),
                written(bytes, answer, shown),
                "{items:?}"
            );
        }
    }

    /// set refuses more items than MaxContainers, and, before any write, fewer under
    /// EFI_IFR_NO_EMPTY_SET, an option twice under EFI_IFR_UNIQUE_SET, and a text that no option
    /// has; each list that the flags allow is written.
    #[test]
    fn items_that_the_flags_or_containers_refuse_write_nothing() {
        const UNIQUE_SET: u8 = 0x01;
        const NO_EMPTY_SET: u8 = 0x02;
        let cases: [(&str, u8, &[&str], Outcome); 7] = [
            (
                "more than MaxContainers",
                0x00,
                &["Enabled", "Enabled", "Enabled", "Enabled", "Enabled"],
                refused("the ORDERED_LIST holds at most 4 items (MaxContainers), not 5"),
            ),
            (
                "fewer than MaxContainers under EFI_IFR_NO_EMPTY_SET",
                NO_EMPTY_SET,
                &["Enabled", "Disabled", "AllOnes"],
                refused(
                    "the ORDERED_LIST has no empty container (EFI_IFR_NO_EMPTY_SET): it takes 4 \
                     items, not 3",
                ),
            ),
            (
                "MaxContainers under EFI_IFR_NO_EMPTY_SET",
                NO_EMPTY_SET,
                &["Enabled", "Disabled", "AllOnes", "Enabled"],
                written(
                    [1, 0, 2, 0, 3, 0, 1, 0],
                    "Enabled, Disabled, AllOnes, Enabled",
                    &["Enabled", "Disabled", "AllOnes", "Enabled"],
                ),
            ),
            (
                "a repeat under EFI_IFR_UNIQUE_SET",
                UNIQUE_SET,
                &["Enabled", "Disabled", "enabled"],
                refused(
                    "the ORDERED_LIST takes each option once (EFI_IFR_UNIQUE_SET): \"Enabled\" is \
                     given twice",
                ),
            ),
            (
                "no repeat under EFI_IFR_UNIQUE_SET",
                UNIQUE_SET,
                &["Enabled", "Disabled"],
                written(
                    [1, 0, 2, 0, 0, 0, 0, 0],
                    "Enabled, Disabled",
                    &["Enabled", "Disabled"],
                ),
            ),
            (
                "no option",
                0x00,
                &["Enabled", "USB"],
                refused("\"USB\" is no option of the ORDERED_LIST"),
            ),
            (
                "an empty text",
                0x00,
                &[""],
                refused("\"\" is no option of the ORDERED_LIST"),
            ),
        ];
        for (name, flags, items, want) in cases {
            let (question, _root, variables) = list_on(flags, &uint16_options(), &[9; 8]);
            assert_eq!(
                set_items(&question, items, IncludedStates::empty(), &variables),
                want,
                "{name}"
            );
        }
    }

    /// set refuses an option whose value no container holds: 0, which marks an empty container,
    /// and one wider than the containers, whose width the first option gives.
    #[test]
    fn options_whose_values_no_container_holds_write_nothing() {
        let uint8 = |text, value| one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_8, &[value]);
        let cases = [
            (
                "value 0",
                vec![uint8(5, 2), uint8(6, 0)],
                "Enabled",
                "option \"Enabled\" has value 0, which marks an empty container (UEFI 2.11 \
                 §33.3.8.3.53)",
            ),
            (
                "UINT16 0x0100 in 1-byte containers",
                vec![
                    uint8(5, 2),
                    one_of_option(6, EFI_IFR_TYPE_NUM_SIZE_16, &0x100u16.to_le_bytes()),
                ],
                "Enabled",
                "option \"Enabled\" has value 256, wider than the 1-byte containers of the \
                 ORDERED_LIST",
            ),
        ];
        for (name, children, item, refusal) in cases {
            let (question, _root, variables) = list_on(0x00, &children, &[9; 4]);
            assert_eq!(
                set_items(&question, &[item], IncludedStates::empty(), &variables),
                refused(refusal),
                "{name}"
            );
        }
    }

    /// set refuses an item whose option is of Type EFI_IFR_TYPE_OTHER, whose value only a ONE_OF
    /// gives, before any write; the list's other options it writes.
    #[test]
    fn item_of_an_option_of_type_other_writes_nothing() {
        let children = [
            one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_8, &[2]),
            other_option(6, 0, &[]),
        ];
        let (question, _root, variables) = list_on(0x00, &children, &[0; 4]);
        assert_eq!(
            set_items(
                &question,
                &["Disabled", "Enabled"],
                IncludedStates::empty(),
                &variables
            ),
            (
                Err(
                    "cannot set question \"\" to option \"Enabled\": EFI_IFR_TYPE_OTHER outside \
                     a ONE_OF"
                        .to_string()
                ),
                vec![]
            )
        );
        assert_eq!(
            set_items(
                &question,
                &["Disabled"],
                IncludedStates::empty(),
                &variables
            ),
            (
                Ok(("Disabled".to_string(), Some(vec!["Disabled".to_string()]))),
                vec![(0, vec![2, 0, 0, 0])]
            )
        );
    }

    /// set takes an item whose option a SUPPRESS_IF hides only with --include suppressed, as a
    /// ONE_OF's option, and answers it with its state.
    #[test]
    fn item_of_a_hidden_option_needs_include() {
        let (question, _root, variables) = list_on(0x00, &suppressed_all_ones(), &[0; 8]);
        assert_eq!(
            set_items(
                &question,
                &["Enabled", "AllOnes"],
                IncludedStates::empty(),
                &variables
            ),
            (
                Err(
                    "option \"AllOnes\" of question \"\" is suppressed; also include suppressed \
                     questions to select it"
                        .to_string()
                ),
                vec![]
            ),
            "without --include"
        );
        assert_eq!(
            set_items(
                &question,
                &["Enabled", "AllOnes"],
                IncludedStates::SUPPRESSED,
                &variables
            ),
            written(
                [1, 0, 3, 0, 0, 0, 0, 0],
                "Enabled, AllOnes <option suppressed>",
                &["Enabled", "AllOnes"]
            ),
            "with --include suppressed"
        );
    }

    /// set writes UINT32 and UINT64 option values to containers of 4 and 8 bytes, MaxContainers
    /// of them.
    #[test]
    fn items_of_uint32_and_uint64_options_fill_containers_of_4_and_8_bytes() {
        let uint32 =
            |text, value: u32| one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_32, &value.to_le_bytes());
        let uint64 =
            |text, value: u64| one_of_option(text, EFI_IFR_TYPE_NUM_SIZE_64, &value.to_le_bytes());
        let cases = [
            (
                "UINT32",
                vec![uint32(5, 2), uint32(6, 1), uint32(7, 0x0001_0000)],
                [
                    &0x0001_0000u32.to_le_bytes()[..],
                    &1u32.to_le_bytes(),
                    &[0; 2 * 4],
                ]
                .concat(),
            ),
            (
                "UINT64",
                vec![uint64(5, 2), uint64(6, 1), uint64(7, 0x0001_0000_0000)],
                [
                    &0x0001_0000_0000u64.to_le_bytes()[..],
                    &1u64.to_le_bytes(),
                    &[0; 2 * 8],
                ]
                .concat(),
            ),
        ];
        for (name, children, bytes) in cases {
            let (question, _root, variables) = list_on(0x00, &children, &vec![9; bytes.len()]);
            assert_eq!(
                set_items(
                    &question,
                    &["AllOnes", "Enabled"],
                    IncludedStates::empty(),
                    &variables
                ),
                (
                    Ok((
                        "AllOnes, Enabled".to_string(),
                        Some(vec!["AllOnes".to_string(), "Enabled".to_string()])
                    )),
                    vec![(0, bytes)]
                ),
                "{name}"
            );
        }
    }

    /// set drops a stored item whose value has a hidden and a shown option, as get shows it with
    /// the shown one, though the hidden one comes first.
    #[test]
    fn stored_item_of_a_shown_option_may_be_dropped() {
        let options = uint16_options();
        let children = [
            conditional(
                SUPPRESS_IF,
                ifr_true(),
                &[one_of_option(
                    7,
                    EFI_IFR_TYPE_NUM_SIZE_16,
                    &2u16.to_le_bytes(),
                )],
            ),
            options[0].clone(),
            options[1].clone(),
        ];
        let (question, _root, variables) = list_on(0x00, &children, &[2, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            set_items(&question, &["Enabled"], IncludedStates::empty(), &variables),
            written([1, 0, 0, 0, 0, 0, 0, 0], "Enabled", &["Enabled"])
        );
    }

    /// set refuses a list that drops a stored item whose option a SUPPRESS_IF hides, also with
    /// --include suppressed, writes one that keeps it, and drops a stored value that no option
    /// has, or whose option is shown.
    #[test]
    fn items_keep_the_stored_items_of_hidden_options() {
        let hidden = refused(
            "it holds \"AllOnes\" <option suppressed>, and set drops no item of a hidden option: \
             give it with --item, and --include suppressed",
        );
        let cases: [KeptCase; 5] = [
            (
                "drops the hidden item",
                [3, 0, 2, 0, 0, 0, 0, 0],
                &["Disabled"],
                IncludedStates::empty(),
                hidden.clone(),
            ),
            (
                "drops it with --include suppressed",
                [3, 0, 2, 0, 0, 0, 0, 0],
                &["Disabled", "Enabled"],
                IncludedStates::SUPPRESSED,
                hidden,
            ),
            (
                "keeps it, moved",
                [3, 0, 2, 0, 0, 0, 0, 0],
                &["Disabled", "AllOnes"],
                IncludedStates::SUPPRESSED,
                written(
                    [2, 0, 3, 0, 0, 0, 0, 0],
                    "Disabled, AllOnes <option suppressed>",
                    &["Disabled", "AllOnes"],
                ),
            ),
            (
                "drops a value without an option",
                [9, 0, 2, 0, 0, 0, 0, 0],
                &["Enabled"],
                IncludedStates::empty(),
                written([1, 0, 0, 0, 0, 0, 0, 0], "Enabled", &["Enabled"]),
            ),
            (
                "drops a hidden value after the first empty container",
                [2, 0, 0, 0, 3, 0, 0, 0],
                &["Enabled"],
                IncludedStates::empty(),
                written([1, 0, 0, 0, 0, 0, 0, 0], "Enabled", &["Enabled"]),
            ),
        ];
        for (name, payload, items, include, want) in cases {
            let (question, _root, variables) = list_on(0x00, &suppressed_all_ones(), &payload);
            assert_eq!(
                set_items(&question, items, include, &variables),
                want,
                "{name}"
            );
        }
    }

    /// set refuses an ORDERED_LIST whose items it cannot read, which might hold items of hidden
    /// options.
    #[test]
    fn unread_items_write_nothing() {
        let (_root, node) = parse_question(
            &[],
            ORDERED_LIST,
            &ordered_list(0, 4, 0x00),
            &uint16_options(),
        );
        let question = question_descriptor(&node, unavailable());
        let variables = MemoryVariables::default();
        assert_eq!(
            set_items(&question, &["Enabled"], IncludedStates::empty(), &variables),
            refused(
                "its items cannot be read, so set cannot keep those of hidden options: no \
                 VarStore 1"
            )
        );
    }

    /// set takes the options of an ORDERED_LIST only as items, and items only for an
    /// ORDERED_LIST; it refuses one with a WRITE expression, which takes its buffer.
    #[test]
    fn items_go_to_ordered_lists_only() {
        let (question, _root, variables) = list_on(0x00, &uint16_options(), &[0; 8]);
        assert_eq!(
            set_to(
                &question,
                NewAnswer::Text {
                    text: "Enabled",
                    variations: &BTreeSet::from(["Enabled".to_string()]),
                },
                IncludedStates::empty(),
                &variables
            ),
            refused("an ORDERED_LIST takes its options in order, each with --item"),
            "text for an ORDERED_LIST"
        );

        let (_root, node) = parse_question(&[], ONE_OF, &one_of_data(), &[flagged_option(6, 0, 1)]);
        let one_of = question_descriptor(&node, writable_var_store("List", &[0; 8], &variables));
        assert_eq!(
            set_items(&one_of, &["Enabled"], IncludedStates::empty(), &variables),
            refused("--item gives the options of an ORDERED_LIST; this question takes VALUE"),
            "items for a ONE_OF"
        );

        let write = [operation(WRITE, true, &[]), ifr_true(), END.to_vec()].concat();
        let children = [uint16_options(), vec![write]].concat();
        let (question, _root, variables) = list_on(0x00, &children, &[0; 8]);
        assert_eq!(
            set_items(&question, &["Enabled"], IncludedStates::empty(), &variables),
            refused(
                "its WRITE expression takes the buffer of an ORDERED_LIST, which uefisettings \
                 does not evaluate"
            ),
            "WRITE expression"
        );
    }

    /// set keeps no stored item of an ORDERED_LIST whose variable is missing only where that is
    /// the variable of a VarName on a VARSTORE_EFI before UEFI 2.3.1, which edk2 creates; it
    /// refuses any other value that it cannot read, the missing variable of a VarStore of offsets
    /// too.
    #[test]
    fn stored_items_are_none_only_of_a_missing_one_value_variable() {
        let missing = || ValueUnavailable::Missing(VariableNotFound(variable_key("List")));
        let unread = "unread: no EFI variable List-00000000-0000-0000-0000-000000000000";
        let cases = [
            (Err(missing()), Some(VariableLayout::OneValue), "none"),
            (Err(missing()), Some(VariableLayout::Offsets), unread),
            (Err(missing()), None, unread),
            (
                Err(ValueUnavailable::PasswordBytes),
                Some(VariableLayout::OneValue),
                "unread: its bytes hold a password",
            ),
            (Ok(vec![1]), Some(VariableLayout::OneValue), "read [1]"),
        ];
        for (stored, layout, want) in cases {
            let case = format!("{stored:?} of {layout:?}");
            let items = match StoredItems::of(stored, layout) {
                StoredItems::Read(values) => format!("read {values:?}"),
                StoredItems::Missing => "none".to_owned(),
                StoredItems::Unread(reason) => format!("unread: {reason}"),
            };
            assert_eq!(items, want, "{case}");
        }
    }
}
