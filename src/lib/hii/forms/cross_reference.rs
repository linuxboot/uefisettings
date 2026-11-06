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

//! Cross-reference questions (UEFI 2.11 §33.2.5.4.10, §33.3.8.3.59): the EFI_HII_REF that one on
//! a VarStore holds, which get shows and set does not write.

use std::cell::RefCell;
use std::rc::Rc;

use binrw::BinRead;

use super::conditions::ExpressionInputs;
use super::conditions::QuestionValues;
use super::conditions::StateEvaluation;
use super::defaults::buffer_defaults;
use super::defaults::push_default;
use super::storage::read_buffer;
use super::storage::BufferQuestion;
use super::storage::ValueLocation;
use super::storage::ValueSource;
use super::storage::VariableStore;
use super::FormSetWalk;
use super::IFROperation;
use super::Question;
use super::QuestionDescriptor;
use super::QuestionFlags;
use super::QuestionHeader;
use super::QuestionIdentity;
use super::Ref;
use super::TextInput;
use crate::hii::strings::ListTexts;
use crate::hii::variables::VariableLayout;

/// An EFI_IFR_REF of any of the lengths of EFI_IFR_REF to EFI_IFR_REF5 (UEFI 2.11 §33.3.8.3.59):
/// their question header. The fields of the target after it, as many as its length holds, stay
/// undecoded: get shows only the EFI_HII_REF that one on a VarStore holds. With the layout of the
/// variable that it names, as the FormSet is parsed (parsed_layout).
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(layout: VariableLayout))]
pub struct CrossReference {
    pub question_header: QuestionHeader,
    #[br(calc = layout)]
    pub(super) layout: VariableLayout,
}

impl Question for CrossReference {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

impl CrossReference {
    /// Where one on a VarStore keeps its value: an EFI_HII_REF, the StorageWidth of every REF in
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c, from VarOffset or from byte 0 of the
    /// variable of its VarName.
    pub(super) fn location(&self) -> ValueLocation {
        ValueLocation::Bytes {
            offset: self.layout.offset(self.question_header.var_store_info),
            size: Ref::SIZE,
        }
    }
}

/// The EFI_HII_REF that `bytes` begin, zero past their end, as edk2-stable202608
/// SetupBrowserDxe/IfrParse.c copies a shorter default into a zeroed value.
fn hii_ref(bytes: &[u8]) -> Ref {
    let mut value = [0; Ref::SIZE as usize];
    value
        .iter_mut()
        .zip(bytes)
        .for_each(|(byte, stored)| *byte = *stored);
    Ref::from_bytes(value)
}

/// The text that get shows for `reference`: its fields, its DevicePath as the text of that string
/// in the language of the other texts (ListTexts::shown_text), none for string 0, which links within the
/// device path of the question's FormSet (UEFI 2.11 §33.3.8.3.59), or the id of a string without
/// such a text.
fn ref_text(reference: Ref, texts: &ListTexts<'_>) -> String {
    let device_path = match reference.device_path_string_id {
        0 => "none".to_string(),
        id => match texts.shown_text(id) {
            Some(text) => format!("{text:?}"),
            None => format!("string {id:#06x} not found"),
        },
    };
    format!(
        "QuestionId {:#06x}, FormId {:#06x}, FormSetGuid {}, DevicePath {device_path}",
        reference.question_id, reference.form_id, reference.form_set_guid,
    )
}

/// The answer that show-ifr shows for the REF of the op `node` on `varstore`: its EFI_HII_REF as
/// get shows it, or why it has none.
pub(super) fn display_ref_answer(
    node: &Rc<RefCell<IFROperation>>,
    varstore: &anyhow::Result<Box<dyn VariableStore>>,
    texts: &ListTexts<'_>,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> String {
    match read_buffer(
        node,
        BufferQuestion::CrossReference,
        varstore,
        inputs.reader,
    ) {
        Ok((bytes, source)) => ref_text(hii_ref(&bytes), texts) + source.annotation(),
        Err(reason) => reason.to_answer(),
    }
}

/// The QuestionDescriptor of the REF `reference` on a VarStore: the EFI_HII_REF stored there,
/// else why it has none and its default.
pub(super) fn handle_cross_reference(
    varstore: anyhow::Result<Box<dyn VariableStore>>,
    reference: &CrossReference,
    prompt: &str,
    flags: QuestionFlags,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let texts = walk.texts;
    let buffer = BufferQuestion::CrossReference;
    let stored = read_buffer(node, buffer, &varstore, walk.inputs.reader)
        .map(|(bytes, source)| (ref_text(hii_ref(&bytes), texts), source));
    let stores = walk.default_stores.of(current_node, &mut walk.inputs);
    let defaults = buffer_defaults(
        current_node,
        buffer,
        stores,
        texts,
        &mut walk.inputs,
        |value| Ok(ref_text(hii_ref(value), texts)),
    );
    let (answer, value_source) = match stored {
        Ok(stored) => stored,
        Err(reason) => {
            let mut answer = reason.to_answer();
            push_default(&mut answer, &defaults, stores);
            (answer, ValueSource::Current)
        }
    };
    QuestionDescriptor {
        question: prompt.trim().to_string(),
        value: answer,
        help: texts
            .display(reference.question_header.help_string_id)
            .to_string(),
        possible_options: Vec::new(),
        // a REF without a VarStore is no listed question
        driver_held: None,
        varstore,
        location: reference.location(),
        input: TextInput::CrossReference,
        opcode: current_node.op_code,
        flags,
        defaults,
        identity: QuestionIdentity::of(current_node, &reference.question_header(), texts),
        value_state: StateEvaluation::selectable(),
        value_source,
        node: Rc::clone(node),
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use std::collections::BTreeSet;
    use std::rc::Rc;

    use super::super::conditions::IncludedStates;
    use super::super::display;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::set::NewAnswer;
    use super::super::set_questions;
    use super::super::storageless::StoragelessQuestion;
    use super::super::DefaultId;
    use super::hii_ref;
    use super::ref_text;
    use crate::hii::strings::ListTexts;
    use crate::hii::variables::EfivarReader;
    use crate::hii::variables::FirmwareVariables;
    use crate::hii::variables::VolatileWrites;
    use crate::hii::variables::WithheldBytes;
    use crate::hii::variables::WithholdingVariables;
    use crate::unsafe_operations::PendingOperations;
    use crate::unsafe_operations::UnsafeOperations;

    /// The FormSetGuid of stored_ref.
    const GUID_TEXT: &str = "8C78A505-BAA0-4C4A-869F-000000000502";
    /// The bytes of GUID_TEXT: Data1, Data2 and Data3 little-endian.
    const GUID_BYTES: [u8; 16] = [
        0x05, 0xA5, 0x78, 0x8C, 0xA0, 0xBA, 0x4A, 0x4C, 0x86, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x05,
        0x02,
    ];

    /// An EFI_HII_REF as stored: QuestionId 5, FormId 1, the FormSetGuid of GUID_TEXT and
    /// DevicePath `device_path`.
    fn stored_ref(device_path: u16) -> Vec<u8> {
        [
            &5u16.to_le_bytes()[..],
            &1u16.to_le_bytes(),
            &GUID_BYTES,
            &device_path.to_le_bytes(),
        ]
        .concat()
    }

    /// The data of a REF prompted Prompt at VarOffset 0 of VarStore `var_store_id`, `target` its
    /// fields after the question header.
    fn ref_data(var_store_id: u16, target: &[u8]) -> Vec<u8> {
        [question_header_on(1, 3, var_store_id, 0), target.to_vec()].concat()
    }

    /// The questions and answers that list-questions gives for `body` after the VARSTORE_EFI 1 of
    /// the EFI variable Ref of 22 bytes, which holds `payload` if any.
    fn list_answers(body: &[Vec<u8>], payload: Option<&[u8]>) -> Vec<String> {
        let efivars = Efivars::new();
        if let Some(payload) = payload {
            efivars.write(&efi_variable("Ref", 22), payload);
        }
        let root = parse_form_set(&[
            [var_store_efi(1, "Ref", NV_BS_RT, 22)].concat(),
            body.concat(),
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

    /// Each REF on a VarStore, of any of the lengths of REF to REF5, shows the EFI_HII_REF stored
    /// there, as edk2-stable202608 SetupBrowserDxe/IfrParse.c gives each storage, though UEFI
    /// 2.11 §33.2.5.4.10 names REF5 only.
    #[test]
    fn ref_on_a_var_store_shows_its_stored_efi_hii_ref() {
        let guid: Vec<u8> = (0x20..0x30).collect();
        let targets = [
            ("REF5", vec![]),
            ("REF", vec![2, 0]),
            ("REF2", vec![2, 0, 7, 0]),
            ("REF3", [&[2, 0, 7, 0][..], &guid].concat()),
            ("REF4", [&[2, 0, 7, 0][..], &guid, &[3, 0]].concat()),
        ];
        for (name, target) in targets {
            assert_eq!(
                list_answers(
                    &[operation(REF, false, &ref_data(1, &target))],
                    Some(&stored_ref(3))
                ),
                [format!(
                    "QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, DevicePath \"Prompt\""
                )],
                "{name}"
            );
        }
    }

    /// get shows the DevicePath of an EFI_HII_REF as the text of its string, none for string 0,
    /// and the string id where no string has it.
    #[test]
    fn ref_shows_the_text_of_its_device_path() {
        let cases = [
            (0, "DevicePath none"),
            (3, "DevicePath \"Prompt\""),
            (0x63, "DevicePath string 0x0063 not found"),
        ];
        for (device_path, want) in cases {
            assert_eq!(
                list_answers(
                    &[operation(REF, false, &ref_data(1, &[]))],
                    Some(&stored_ref(device_path))
                ),
                [format!(
                    "QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, {want}"
                )],
                "{device_path:#06x}"
            );
        }
    }

    /// The DevicePath of an EFI_HII_REF shows in the language of the other texts, else in a
    /// display language, never in a configuration language.
    #[test]
    fn ref_shows_its_device_path_in_the_language_of_the_texts() {
        let package = |language: &[u8], strings: &[(u16, &str)]| StringPackage {
            language: Language(language.to_vec()),
            strings: strings
                .iter()
                .map(|&(id, text)| (id, text.into()))
                .collect(),
        };
        let packages = [
            package(b"x-UEFI-ns", &[(3, "Keyword"), (9, "OnlyKeyword")]),
            package(b"en-US", &[(3, "Prompt"), (4, "Help")]),
            package(b"fr-FR", &[(3, "Invite")]),
        ];
        let texts = ListTexts::new(&packages, &["fr-FR"]);
        let cases = [
            (3, "\"Invite\""),
            (4, "\"Help\""),
            (9, "string 0x0009 not found"),
        ];
        for (device_path, want) in cases {
            assert_eq!(
                ref_text(hii_ref(&stored_ref(device_path)), &texts),
                format!(
                    "QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, DevicePath {want}"
                ),
                "{device_path:#06x}"
            );
        }
    }

    /// Without a value, a REF on a VarStore shows its EFI_IFR_DEFAULT of Type EFI_IFR_TYPE_REF.
    #[test]
    fn ref_without_a_value_shows_its_default() {
        let default = [&[0x00, 0x00, 0x0C][..], &stored_ref(0)].concat();
        let body = [
            operation(REF, true, &ref_data(1, &[2, 0])),
            operation(0x5B, false, &default),
            END.to_vec(),
        ]
        .concat();
        assert_eq!(
            list_answers(&[body], None),
            [format!(
                "<ValueUnavailable: no EFI variable Ref-00000000-0000-0000-0000-000000000000> \
                 <IFR default: QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, \
                 DevicePath none>"
            )]
        );
    }

    /// The defaults of a REF on a VarStore list its EFI_IFR_DEFAULT of Type EFI_IFR_TYPE_REF, shown
    /// as get shows an EFI_HII_REF, and no default of another DefaultId.
    #[test]
    fn ref_lists_its_declared_default() {
        let default = [&[0x00, 0x00, 0x0C][..], &stored_ref(3)].concat();
        let (_root, node) = parse_question(
            &[],
            REF,
            &ref_data(1, &[2, 0]),
            &[operation(0x5B, false, &default)],
        );
        let defaults: Vec<(DefaultId, String)> = question_descriptor(&node, unavailable())
            .defaults
            .iter()
            .map(|default| (default.default_id, default.value.to_string()))
            .collect();
        assert_eq!(
            defaults,
            [(
                DefaultId(0x0000),
                format!(
                    "QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, DevicePath \"Prompt\""
                )
            )]
        );
    }

    /// A REF on a VarStore takes no default from a flagged EFI_IFR_ONE_OF_OPTION, which its grammar
    /// does not nest (UEFI 2.11 §33.2.5.4.10), and still lists its EFI_IFR_DEFAULT of Type
    /// EFI_IFR_TYPE_REF beside one.
    #[test]
    fn ref_takes_no_default_from_a_flagged_option() {
        let default = [&[0x00, 0x00, 0x0C][..], &stored_ref(3)].concat();
        let declared = format!(
            "QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, DevicePath \"Prompt\""
        );
        let cases = [
            ("flagged option", vec![flagged_option(6, 0x10, 1)], vec![]),
            (
                "flagged option and EFI_IFR_DEFAULT",
                vec![flagged_option(6, 0x10, 1), operation(0x5B, false, &default)],
                vec![(DefaultId(0x0000), declared)],
            ),
        ];
        for (name, children, want) in cases {
            let (_root, node) = parse_question(&[], REF, &ref_data(1, &[2, 0]), &children);
            let defaults: Vec<(DefaultId, String)> = question_descriptor(&node, unavailable())
                .defaults
                .iter()
                .map(|default| (default.default_id, default.value.to_string()))
                .collect();
            assert_eq!(defaults, want, "{name}");
        }
    }

    /// A REF on a VarStore refuses an EFI_IFR_DEFAULT of a Type other than EFI_IFR_TYPE_REF, here
    /// UINT8, whose number is no EFI_HII_REF.
    #[test]
    fn ref_refuses_a_default_of_another_type() {
        let (_root, node) =
            parse_question(&[], REF, &ref_data(1, &[2, 0]), &[ifr_default(0x0000, 1)]);
        let defaults: Vec<(DefaultId, String)> = question_descriptor(&node, unavailable())
            .defaults
            .iter()
            .map(|default| (default.default_id, default.value.to_string()))
            .collect();
        assert_eq!(
            defaults,
            [(
                DefaultId(0x0000),
                "unknown (a default of a number where the question stores an EFI_HII_REF)"
                    .to_string()
            )]
        );
    }

    /// A REF without a VarStore is a link with no value: list-questions leaves it out, and the
    /// classifier of questions without a VarStore does not take it (UEFI 2.11 §33.2.5.4.10:
    /// "Storage is optional for a cross-reference question").
    #[test]
    fn ref_without_a_var_store_is_unlisted() {
        let data = ref_data(0, &[2, 0]);
        let body = [
            operation(REF, false, &data),
            operation(CHECKBOX, false, &checkbox(0, 0x00)),
        ];
        assert_eq!(list_answers(&body, Some(&[1; 22])), ["1"]);
        let root = parse_form_set(&body);
        let question = find_op(&root, &data).expect("the REF");
        assert_eq!(StoragelessQuestion::of(&question), None);
    }

    /// show-ifr shows a REF on a VarStore with its EFI_HII_REF as get shows it, and one without a
    /// VarStore, a link with no value, by its op only.
    #[test]
    fn show_ifr_shows_the_efi_hii_ref_of_a_ref_on_a_var_store() {
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Ref", 22), &stored_ref(3));
        let root = parse_form_set(&[
            var_store_efi(1, "Ref", NV_BS_RT, 22),
            operation(REF, false, &ref_data(1, &[])),
            operation(REF, false, &ref_data(0, &[2, 0])),
        ]);
        let shown = display(
            root,
            0,
            &ListTexts::new(&strings(), &[]),
            &mut efivars.reader(),
        )
        .expect("display");
        let lines: Vec<&str> = shown
            .lines()
            .map(str::trim_start)
            .filter(|line| line.starts_with("OpCode: Ref") || line.starts_with("-Answer: "))
            .collect();
        let answer = format!(
            "-Answer: QuestionId 0x0005, FormId 0x0001, FormSetGuid {GUID_TEXT}, DevicePath \"Prompt\""
        );
        assert_eq!(
            lines,
            ["OpCode: Ref - Q: Prompt - Help: ", &answer, "OpCode: Ref"],
            "{shown}"
        );
    }

    /// A REF too short for its question header is malformed (UEFI 2.11 §33.2.5.10.1) and disables
    /// its form alone: get still lists the questions of the FormSet's other forms.
    #[test]
    fn short_ref_disables_its_form() {
        let body = [
            form(1, &[operation(REF, false, &question_header(0)[..10])]),
            form(2, &[operation(CHECKBOX, false, &checkbox(0, 0x00))]),
        ];
        let (_root, disabled) = parse_form_set_dropping(&body);
        assert_eq!(disabled.len(), 1, "the REF's form, disabled");
        assert_eq!(
            list_answers(&body, Some(&[1; 22])),
            ["1"],
            "the CHECKBOX of form 2"
        );
    }

    /// set refuses a REF on a VarStore, with VALUE or items, before any write.
    #[test]
    fn set_refuses_a_ref() {
        let variables = MemoryVariables::default();
        let (_root, node) = parse_question(&[], REF, &ref_data(1, &[]), &[]);
        let question =
            question_descriptor(&node, writable_var_store("Ref", &stored_ref(0), &variables));
        let items = ["x".to_string()];
        let variations = BTreeSet::from(["x".to_string()]);
        for answer in [
            NewAnswer::Text {
                text: "x",
                variations: &variations,
            },
            NewAnswer::Items(&items),
        ] {
            let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
                variables.reach(),
                variables.interface(),
            )));
            let set = set_questions(
                "",
                &[("R", &question)],
                answer,
                IncludedStates::empty(),
                &mut reader,
                None,
                VolatileWrites::Refuse,
                PendingOperations::new(UnsafeOperations::Refuse),
                &WithholdingVariables::new(&variables, WithheldBytes::default()),
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"));
            assert_eq!(
                (set, variables.writes_to(&variable_key("Ref"))),
                (
                    Err(
                        "cannot set question \"\": set does not write the EFI_HII_REF of a \
                         cross-reference question, the target of its link (UEFI 2.11 \
                         §33.2.5.4.10)"
                            .to_string()
                    ),
                    vec![]
                ),
                "{answer:?}"
            );
        }
    }
}
