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

//! The ONE_OF, NUMERIC and CHECKBOX questions that get reads and set writes, found by their
//! prompts, and the text that get shows for their values.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::rc::Rc;

use anyhow::Result;

use super::conditions::option_state;
use super::conditions::retrieve_question_value;
use super::conditions::skips_scope;
use super::conditions::IncludedStates;
use super::conditions::QuestionValues;
use super::conditions::StateEvaluation;
use super::defaults::option_text;
use super::defaults::push_default;
use super::defaults::question_scope;
use super::find_corresponding_string;
use super::find_corresponding_varstore;
use super::numeric_format;
use super::storage::ValueLocation;
use super::storage::VariableStore;
use super::walk_scopes;
use super::AnswerOption;
use super::CheckBox;
use super::FormSetWalk;
use super::IFROperation;
use super::Numeric;
use super::NumericFormat;
use super::NumericRange;
use super::OneOf;
use super::ParsedOperation;
use super::Question;
use super::QuestionDescriptor;
use super::QuestionHeader;
use super::Range;
use super::RangeType;
use super::Walk;

/// A question whose value get reads and set writes.
#[derive(Clone, Copy)]
pub(super) enum ValueQuestion<'a> {
    OneOf(&'a OneOf),
    Numeric(&'a Numeric),
    CheckBox(&'a CheckBox),
}

impl ValueQuestion<'_> {
    pub(super) fn header(self) -> QuestionHeader {
        match self {
            ValueQuestion::OneOf(question) => question.question_header(),
            ValueQuestion::Numeric(question) => question.question_header(),
            ValueQuestion::CheckBox(question) => question.question_header(),
        }
    }

    pub(super) fn location(self) -> ValueLocation {
        match self {
            ValueQuestion::OneOf(question) => question.location,
            ValueQuestion::Numeric(question) => question.location,
            ValueQuestion::CheckBox(question) => question.location,
        }
    }
}

/// Returns `op` as a ONE_OF, NUMERIC or CHECKBOX.
pub(super) fn value_question(op: &IFROperation) -> Option<ValueQuestion<'_>> {
    match &op.parsed_data {
        ParsedOperation::OneOf(question) => Some(ValueQuestion::OneOf(question)),
        ParsedOperation::Numeric(question) => Some(ValueQuestion::Numeric(question)),
        ParsedOperation::CheckBox(question) => Some(ValueQuestion::CheckBox(question)),
        ParsedOperation::FormSet(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::VarStore(_)
        | ParsedOperation::VarStoreNameValue(_)
        | ParsedOperation::VarStoreEfi(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Get(_)
        | ParsedOperation::Set(_)
        | ParsedOperation::FormMap(_)
        | ParsedOperation::Placeholder => None,
    }
}

/// Returns the ONE_OF, NUMERIC and CHECKBOX questions under `node`, in IFR order, whose
/// prompt is one of `phrases`, ignoring ASCII case and surrounding whitespace.
pub(super) fn questions_named<T>(
    node: &Rc<RefCell<IFROperation>>,
    string_packages: &[BTreeMap<i32, String>],
    phrases: &BTreeSet<T>,
) -> Vec<Rc<RefCell<IFROperation>>>
where
    T: AsRef<str>,
{
    let mut found = Vec::new();
    walk_scopes(std::slice::from_ref(node), (), |node, ()| {
        let op = node.borrow();
        if skips_scope(&op) {
            return Walk::Skip;
        }
        let prompt = prompt(&op, string_packages).trim();
        // Only Numeric, OneOf and CheckBox are questions.
        if value_question(&op).is_some()
            && phrases
                .iter()
                .any(|phrase| phrase.as_ref().trim().eq_ignore_ascii_case(prompt))
        {
            found.push(Rc::clone(node));
        }
        Walk::Enter(())
    });
    found
}

/// Returns the prompt of a ONE_OF, NUMERIC or CHECKBOX, empty for other ops.
fn prompt<'a>(op: &IFROperation, string_packages: &'a [BTreeMap<i32, String>]) -> &'a str {
    value_question(op).map_or("", |question| {
        find_corresponding_string(question.header().prompt_string_id, string_packages)
    })
}

/// Returns the QuestionDescriptor of `question`, whose op is `value_question`.
pub(super) fn describe_question(
    question: &Rc<RefCell<IFROperation>>,
    value_question: ValueQuestion<'_>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let header = value_question.header();
    let prompt = find_corresponding_string(header.prompt_string_id, walk.string_packages);
    let varstore = find_corresponding_varstore(Rc::clone(question), header.var_store_id);
    match value_question {
        ValueQuestion::OneOf(parsed) => handle_oneof(varstore, parsed, prompt, question, walk),
        ValueQuestion::Numeric(parsed) => handle_numeric(varstore, parsed, prompt, question, walk),
        ValueQuestion::CheckBox(parsed) => {
            handle_checkbox(varstore, parsed, prompt, question, walk)
        }
    }
}

/// Returns `value`, a current value or IFR default of a CHECKBOX, as list-questions and get show
/// it: FALSE or TRUE (UEFI 2.10 §33.3.8.3.9) as 0 or 1, any nonzero value as 1, as
/// edk2-stable202608 ProcessOptions.c shows it on.
fn checkbox_text(value: u64) -> String {
    u8::from(value != 0).to_string()
}

/// Returns `value`, a current value or IFR default of a ONE_OF in `format`, as list-questions and
/// get show it: `option`, the text of the option that holds it, else its number.
fn one_of_text(value: u64, format: NumericFormat, option: Option<&str>) -> String {
    match option {
        Some(text) => text.to_string(),
        None => format!("{} (no matching option)", format.decode(value)),
    }
}

pub(super) fn handle_checkbox(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &CheckBox,
    question: &str,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let mut answer = String::new();
    let available = match retrieve_question_value(node, &varstore, &mut walk.inputs) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            false
        }
        Ok((_, value)) => {
            answer.push_str(&checkbox_text(value));
            true
        }
    };
    if !available {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        push_default(
            &mut answer,
            current_node,
            default_ids,
            &mut walk.inputs,
            |v, _| Ok::<_, Infallible>(checkbox_text(v)),
        );
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options: Vec::new(),
        varstore,
        location: parsed.location,
        max_value: RangeType::NumSize8(1),
        numeric_range: None,
        opcode: current_node.op_code,
        value_state: StateEvaluation::selectable(),
    };
    res
}

pub(super) fn handle_oneof(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &OneOf,
    question: &str,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let mut answer = String::new();
    // None, with the reason in `answer`, when the current value cannot be read: any u64,
    // all ones too, can be stored.
    let chosen_value = match retrieve_question_value(node, &varstore, &mut walk.inputs) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            None
        }
        Ok(stored) => Some(stored),
    };

    if chosen_value.is_none() {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        match numeric_format(parsed.location, parsed.flags, &parsed.data) {
            Ok(format) => push_default(
                &mut answer,
                current_node,
                default_ids,
                &mut walk.inputs,
                |v, inputs| {
                    option_text(current_node, format.cut(v), walk.string_packages, inputs)
                        .map(|option| one_of_text(v, format, option.as_deref()))
                },
            ),
            Err(error) => push_default(
                &mut answer,
                current_node,
                default_ids,
                &mut walk.inputs,
                |_, _| Err::<String, _>(error),
            ),
        }
    }

    let mut possible_options = Vec::new();
    // Some of OneOf's children are OneOfOptions

    for op in question_scope(current_node) {
        let op = op.borrow();
        if let ParsedOperation::OneOfOption(o) = &op.parsed_data {
            possible_options.push(AnswerOption {
                raw_value: o.value,
                value: find_corresponding_string(o.option_string_id, walk.string_packages)
                    .to_string(),
                state: option_state(&op, &mut walk.inputs),
            });
        }
    }
    let chosen: Vec<&AnswerOption> = possible_options
        .iter()
        .filter(|opt| chosen_value.is_some_and(|(_, value)| opt.raw_value.as_u64() == Some(value)))
        .collect();
    // the first that may be shown, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption
    // finds it, else the first, which a SUPPRESS_IF hides
    let option = chosen
        .iter()
        .find(|opt| opt.state.may_be_allowed(IncludedStates::empty()))
        .or(chosen.first());
    if let Some((location, value)) = chosen_value {
        let format = NumericFormat::from_location(location, parsed.flags, &parsed.data);
        answer.push_str(&one_of_text(
            value,
            format,
            option.map(|opt| opt.value.trim()),
        ));
    }
    let value_state = option.map_or_else(StateEvaluation::selectable, |opt| opt.state.clone());

    let res = QuestionDescriptor {
        question: question.trim().to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options,
        varstore,
        location: parsed.location,
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        numeric_range: None,
        opcode: current_node.op_code,
        value_state,
    };
    res
}

pub(super) fn handle_numeric(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &Numeric,
    question: &str,
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let current_node = &node.borrow();
    let mut answer = String::new();

    let available = match retrieve_question_value(node, &varstore, &mut walk.inputs) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            false
        }
        Ok((location, value)) => {
            let format = NumericFormat::from_location(location, parsed.flags, &parsed.data);
            answer.push_str(&format.decode(value).to_string());
            true
        }
    };
    if !available {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        push_default(
            &mut answer,
            current_node,
            default_ids,
            &mut walk.inputs,
            |v, _| {
                numeric_format(parsed.location, parsed.flags, &parsed.data)
                    .map(|format| format.decode(v).to_string())
            },
        );
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options: Vec::new(),
        varstore,
        location: parsed.location,
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        // set refuses bit fields, whose Flags from_ifr would misread
        numeric_range: match parsed.location {
            ValueLocation::Bytes { .. } => Some(NumericRange::from_ifr(&parsed.data, parsed.flags)),
            ValueLocation::Bits { .. } => None,
        },
        opcode: current_node.op_code,
        value_state: StateEvaluation::selectable(),
    };
    res
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod question_value_tests {
    use std::io::Read;
    use std::io::Seek;
    use std::io::SeekFrom;

    use binrw::io::Cursor;

    use super::super::conditions::ExpressionInputs;
    use super::super::default_value_parser;
    use super::super::display_answer;
    use super::super::ifr_fixtures::*;
    use super::super::IfrDefaultValue;
    use super::super::Range16;
    use super::super::Range32;
    use super::super::Range64;
    use super::super::Range8;
    use super::*;

    /// EDKII_IFR_DISPLAY_UINT_DEC_BIT
    const UINT_DEC: u8 = 0x40;

    #[test]
    fn readable_checkbox_shows_no_default() {
        assert_eq!(
            answer(&[], CHECKBOX, &checkbox(0, 0x01), &[], var_store_of(&[0])),
            "0",
            "readable CHECKBOX"
        );
    }

    #[test]
    fn checkbox_past_var_store_shows_bracketed_error_and_default() {
        assert_eq!(
            answer(&[], CHECKBOX, &checkbox(1, 0x01), &[], var_store_of(&[0])),
            "<ExtractEFIDataError: failed to fill whole buffer (offset: 1; buflen: 5)> \
             <IFR default: 1>",
            "CHECKBOX past its VarStore"
        );
    }

    fn one_of_value(data: &[u8], children: &[Vec<u8>], var_store: VarStoreFixture) -> String {
        answer(&[], ONE_OF, data, children, var_store)
    }

    /// A UINT8 ONE_OF of options Disabled (0) and Enabled (1) whose
    /// manufacturing EFI_IFR_DEFAULT (DefaultId 1) has Value 0.
    fn uint8_one_of(offset: u16) -> (Vec<u8>, Vec<Vec<u8>>) {
        let data = [&question_header(offset)[..], &[0x00, 0x00, 0x01, 0x01]].concat();
        let children = vec![
            one_of_option(5, 0x00, &[0]),
            one_of_option(6, 0x00, &[1]),
            ifr_default(0x0001, 0),
        ];
        (data, children)
    }

    #[test]
    fn one_of_storing_all_ones_shows_that_option() {
        let data = [
            &question_header(0)[..],
            &[0x03],                 // Flags: UINT64
            &0u64.to_le_bytes(),     // MinValue
            &u64::MAX.to_le_bytes(), // MaxValue
            &1u64.to_le_bytes(),     // Step
        ]
        .concat();
        let children = [
            one_of_option(5, 0x03, &0u64.to_le_bytes()),
            one_of_option(7, 0x03, &u64::MAX.to_le_bytes()),
            ifr_default(0x0000, 0),
        ];

        let got = one_of_value(&data, &children, var_store_of(&u64::MAX.to_le_bytes()));

        assert_eq!(got, "AllOnes", "ONE_OF storing all ones");
    }

    /// The DefaultId (1 = Enabled) is not a value, and nothing is shown as
    /// the current value when it cannot be read.
    #[test]
    fn one_of_past_var_store_shows_extraction_error() {
        let (data, children) = uint8_one_of(8);
        let declarations = [default_store(0x0000), default_store(0x0001)];
        let var_store = var_store_of(&[1; 8]);

        let got = answer(&declarations, ONE_OF, &data, &children, var_store);

        assert_eq!(
            got,
            "<ExtractEFIDataError: failed to fill whole buffer (offset: 8; buflen: 12)> \
             <IFR default (DefaultId 0x0001): Disabled>",
            "ONE_OF past its VarStore"
        );
    }

    #[test]
    fn one_of_without_var_store_shows_only_the_reason() {
        let (data, children) = uint8_one_of(0);

        let got = one_of_value(&data, &children, unavailable());

        assert_eq!(got, UNAVAILABLE, "ONE_OF without VarStore");
    }

    #[test]
    fn one_of_shows_stored_option() {
        let (data, children) = uint8_one_of(7);

        let got = one_of_value(&data, &children, var_store_of(&[0, 0, 0, 0, 0, 0, 0, 1]));

        assert_eq!(got, "Enabled", "ONE_OF storing option 1");
    }

    /// A ONE_OF answers the option whose value, decoded as defaults are, is the
    /// stored one: a BOOLEAN option TRUE is 1, and an option of another Type
    /// matches nothing, not even an unreadable value.
    #[test]
    fn one_of_matches_options_by_their_decoded_value() {
        let cases = [
            (
                "BOOLEAN options",
                vec![one_of_option(5, 0x04, &[0]), one_of_option(6, 0x04, &[1])],
                var_store_of(&[1]),
                "Enabled",
            ),
            (
                "DATE option before a UINT8 option of 0",
                vec![one_of_option(5, 0x06, &[0]), one_of_option(6, 0x00, &[0])],
                var_store_of(&[0]),
                "Enabled",
            ),
            (
                "DATE option without a current value",
                vec![one_of_option(5, 0x06, &[0])],
                unavailable(),
                UNAVAILABLE,
            ),
        ];
        for (name, children, var_store, want) in cases {
            assert_eq!(
                answer(&[], ONE_OF, &one_of_data(), &children, var_store),
                want,
                "{name}"
            );
        }
    }

    #[test]
    fn one_of_shows_default_only_without_current_value() {
        let children = [
            one_of_option(5, 0x00, &[0]),
            one_of_option(6, 0x00, &[1]),
            ifr_default(0x0000, 1),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "unreadable ONE_OF"
        );
        assert_eq!(
            answer(&[], ONE_OF, &one_of_data(), &children, var_store_of(&[0])),
            "Disabled",
            "readable ONE_OF"
        );
    }

    #[test]
    fn one_of_default_without_option_shows_its_value() {
        let children = [one_of_option(5, 0x00, &[0]), ifr_default(0x0000, 7)];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: 7 (no matching option)>"),
            "ONE_OF default without option"
        );
    }

    /// A CHECKBOX value shows as its IFR default does: a nonzero byte as 1, as
    /// edk2-stable202608 ProcessOptions.c shows it on.
    #[test]
    fn checkbox_shows_a_nonzero_byte_as_1() {
        for (byte, want) in [(0x00, "0"), (0x01, "1"), (0x02, "1"), (0xFF, "1")] {
            assert_eq!(
                answer(
                    &[],
                    CHECKBOX,
                    &checkbox(0, 0x00),
                    &[],
                    var_store_of(&[byte])
                ),
                want,
                "CHECKBOX byte {byte:#04x}"
            );
        }
    }

    /// A ONE_OF value shows as its IFR default does: a value that no option holds as its
    /// number, signed as the Flags say, and a value whose option has empty text as that text.
    #[test]
    fn one_of_value_shows_as_its_default_does() {
        // Flags: UINT8 INT_DEC; MinValue, MaxValue, Step
        let data = [&question_header(0)[..], &[0x00, 0x00, 0xFF, 0x01]].concat();
        let cases = [
            (
                "no matching option",
                one_of_option(5, 0x00, &[0]),
                "-1 (no matching option)",
            ),
            // string 9 is not in strings()
            ("option without text", one_of_option(9, 0x00, &[0xFF]), ""),
        ];
        for (name, option, want) in cases {
            let children = [option, ifr_default(0x0000, 0xFF)];
            assert_eq!(
                answer(&[], ONE_OF, &data, &children, var_store_of(&[0xFF])),
                want,
                "{name}: current value"
            );
            assert_eq!(
                answer(&[], ONE_OF, &data, &children, unavailable()),
                format!("{UNAVAILABLE} <IFR default: {want}>"),
                "{name}: default"
            );
        }

        // the current value of a bit field is signed by its StorageWidth, its default as UINT32
        let data = uint32_range_question(0, 0x08); // 8-bit INT_DEC
        let children = [
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            uint32_default(0x0000, 0xFF),
        ];
        for (name, var_store, want) in [
            (
                "current value",
                var_store_of(&[0xFF]),
                "-1 (no matching option)".to_string(),
            ),
            (
                "default",
                unavailable(),
                format!("{UNAVAILABLE} <IFR default: 255 (no matching option)>"),
            ),
        ] {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, ONE_OF, &data, &children, var_store),
                want,
                "8-bit field: {name}"
            );
        }
    }

    /// A ONE_OF default is cut to the ONE_OF's width before it is matched to an
    /// option, and a CHECKBOX has only FALSE and TRUE (UEFI 2.10 §33.3.8.3.9).
    #[test]
    fn one_of_and_checkbox_defaults_are_cut_to_question_values() {
        // Type UINT16, Value 0x0101 and 0x0107
        let uint16_default = |value: u16| {
            let data = [&[0x00, 0x00, 0x01][..], &value.to_le_bytes()].concat();
            operation(DEFAULT, false, &data)
        };
        let options = || vec![one_of_option(5, 0x00, &[0]), one_of_option(6, 0x00, &[1])];
        let cases = [
            (
                "UINT16 default of a UINT8 ONE_OF",
                ONE_OF,
                one_of_data(),
                [options(), vec![uint16_default(0x0101)]].concat(),
                " <IFR default: Enabled>",
            ),
            (
                "UINT16 default of a UINT8 ONE_OF without its option",
                ONE_OF,
                one_of_data(),
                [options(), vec![uint16_default(0x0107)]].concat(),
                " <IFR default: 7 (no matching option)>",
            ),
            (
                "ONES default of a UINT8 ONE_OF",
                ONE_OF,
                one_of_data(),
                vec![
                    one_of_option(5, 0x00, &[0]),
                    one_of_option(7, 0x00, &[0xFF]),
                    ifr_default_2(0x0000, ifr_ones()),
                ],
                " <IFR default: AllOnes>",
            ),
            (
                "ONES default of a CHECKBOX",
                CHECKBOX,
                checkbox(0, 0x00),
                vec![ifr_default_2(0x0000, ifr_ones())],
                " <IFR default: 1>",
            ),
            (
                "UINT8 2 default of a CHECKBOX",
                CHECKBOX,
                checkbox(0, 0x00),
                vec![ifr_default(0x0000, 2)],
                " <IFR default: 1>",
            ),
        ];
        for (name, op_code, data, children, suffix) in cases {
            assert_eq!(
                answer(&[], op_code, &data, &children, unavailable()),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// Fails every read with an error other than a short read.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated read failure"))
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn default_value_read_failure_other_than_short_read_is_an_error() {
        let short = default_value_parser(
            &mut Cursor::new(&[0x00][..]),
            binrw::Endian::Little,
            (0x01,),
        );
        let failed = default_value_parser(&mut FailingReader, binrw::Endian::Little, (0x00,));

        assert!(
            matches!(short, Ok(IfrDefaultValue::Missing)),
            "short read: {short:?}"
        );
        assert!(
            matches!(
                &failed,
                Err(binrw::Error::Io(error)) if error.kind() == std::io::ErrorKind::Other
            ),
            "failed read: {failed:?}"
        );
    }

    #[test]
    fn numeric_shows_default_only_without_current_value() {
        let data = uint8_numeric(0x10, 0, 10);
        let children = [ifr_default(0x0000, 5)];

        assert_eq!(
            answer(&[], NUMERIC, &data, &children, unavailable()),
            format!("{UNAVAILABLE} <IFR default: 5>"),
            "unreadable NUMERIC"
        );
        assert_eq!(
            answer(&[], NUMERIC, &data, &children, var_store_of(&[7])),
            "7",
            "readable NUMERIC"
        );
    }

    #[test]
    fn signed_numeric_default_is_signed() {
        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x00, 0xFB, 5),
            &[ifr_default(0x0000, 0xFF)],
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: -1>"),
            "signed UINT8 NUMERIC"
        );
    }

    #[test]
    fn signed_uint16_numeric_default_is_signed() {
        let data = [
            &question_header(0)[..],
            &[0x01],                 // Flags: UINT16, EFI_IFR_DISPLAY_INT_DEC
            &(-10i16).to_le_bytes(), // MinValue
            &10i16.to_le_bytes(),    // MaxValue
            &1u16.to_le_bytes(),     // Step
        ]
        .concat();
        // Type UINT16, Value 0xFFFE
        let default = operation(DEFAULT, false, &[0x00, 0x00, 0x01, 0xFE, 0xFF]);

        let got = answer(&[], NUMERIC, &data, &[default], unavailable());

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: -2>"),
            "signed UINT16 NUMERIC"
        );
    }

    #[test]
    fn unsigned_numeric_default_is_cut_to_question_size() {
        // Type UINT16, Value 0x01FF
        let default = operation(DEFAULT, false, &[0x00, 0x00, 0x01, 0xFF, 0x01]);

        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[default],
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: 255>"),
            "UINT16 default of a UINT8 NUMERIC"
        );
    }

    /// The answer of a NUMERIC with `flags`, Range UINT32 0..=300 and a UINT32
    /// standard default of `default`, in the scope of an EFI_IFR_GUID of `guid`.
    fn numeric_in_guid_answer(guid: [u8; 16], flags: u8, default: u32) -> String {
        answer_in_guid(
            guid,
            NUMERIC,
            &uint32_range_question(0, flags),
            &[uint32_default(0x0000, default)],
            unavailable(),
        )
    }

    /// A bit-field default is cut to the width in EDKII_IFR_NUMERIC_SIZE_BIT, 1 to 32, and
    /// EDKII_IFR_DISPLAY_INT_DEC_BIT signs it as a UINT32.
    #[test]
    fn bit_field_numeric_default_has_edkii_width_and_display() {
        let cases = [
            (
                "12-bit UINT_DEC",
                BIT_VARSTORE_GUID,
                0x4C,
                200,
                " <IFR default: 200>",
            ),
            (
                "8-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x08,
                0xFF,
                " <IFR default: 255>",
            ),
            (
                "12-bit UINT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x4C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit UINT_HEX all ones",
                BIT_VARSTORE_GUID,
                0x8C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x0C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit INT_DEC over 2047",
                BIT_VARSTORE_GUID,
                0x0C,
                3000,
                " <IFR default: 3000>",
            ),
            (
                "32-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x20,
                u32::MAX,
                " <IFR default: -1>",
            ),
            // Flags 0x00: UINT8 INT_DEC
            ("other GUID", OTHER_GUID, 0x00, 0xC8, " <IFR default: -56>"),
        ];
        for (name, guid, flags, default, suffix) in cases {
            assert_eq!(
                numeric_in_guid_answer(guid, flags, default),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// show-ifr shows the value in the bits of an EDKII bit varstore field.
    #[test]
    fn show_ifr_answer_of_bit_field_is_its_value() {
        for (guid, want) in [(BIT_VARSTORE_GUID, "1"), (OTHER_GUID, "2")] {
            let (_root, node) = parse_question_in_guid(guid, CHECKBOX, &checkbox(3, 0x00), &[]);

            // bit 3, and byte 3
            let VarStoreFixture { store, efivars } = var_store_of(&[0xF8, 0x00, 0x00, 0x02]);

            let got = display_answer(
                &node,
                &store,
                &mut ExpressionInputs {
                    reader: &mut efivars.reader(),
                    values: &MapValues(BTreeMap::new()),
                },
            );

            assert_eq!(got, want, "GUID {guid:02X?}");
        }
    }

    /// An unmatched ONE_OF default is the number that its Flags, those of a NUMERIC (UEFI
    /// 2.10 §33.3.8.3.50), display, as for a NUMERIC default.
    #[test]
    fn unmatched_one_of_default_is_displayed_as_its_flags_say() {
        let cases = [
            (
                "12-bit INT_DEC over 2047",
                BIT_VARSTORE_GUID,
                0x0C,
                3000,
                "3000",
            ),
            (
                "12-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x0C,
                u32::MAX,
                "4095",
            ),
            (
                "32-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x20,
                u32::MAX,
                "-1",
            ),
            (
                "32-bit UINT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x60,
                u32::MAX,
                "4294967295",
            ),
            // Flags 0x02: UINT32 INT_DEC; 0x12: UINT32 UINT_DEC
            ("UINT32 INT_DEC all ones", OTHER_GUID, 0x02, u32::MAX, "-1"),
            (
                "UINT32 UINT_DEC all ones",
                OTHER_GUID,
                0x12,
                u32::MAX,
                "4294967295",
            ),
        ];
        for (name, guid, flags, default, number) in cases {
            let children = [
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                uint32_default(0x0000, default),
            ];
            assert_eq!(
                answer_in_guid(
                    guid,
                    ONE_OF,
                    &uint32_range_question(0, flags),
                    &children,
                    unavailable()
                ),
                format!("{UNAVAILABLE} <IFR default: {number} (no matching option)>"),
                "{name}"
            );
        }
    }

    /// A readable EDKII bit varstore field shows the value in its bits, without its default.
    #[test]
    fn readable_bit_field_question_shows_its_value() {
        // bits 4 to 15: 0xC8D; bits 4 and 5: 1
        let store = || var_store_of(&[0xD0, 0xC8, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let one_of_children = || {
            vec![
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                one_of_option(6, 0x02, &1u32.to_le_bytes()),
                uint32_default(0x0000, 0),
            ]
        };
        let cases = [
            (
                "12-bit UINT_DEC NUMERIC",
                NUMERIC,
                uint32_range_question(4, 0x4C),
                vec![uint32_default(0x0000, 200)],
                "3213",
            ),
            ("CHECKBOX", CHECKBOX, checkbox(4, 0x01), vec![], "1"),
            (
                "2-bit UINT_DEC ONE_OF",
                ONE_OF,
                uint32_range_question(4, 0x42),
                one_of_children(),
                "Enabled",
            ),
        ];
        for (name, op_code, data, children, want) in cases {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children, store()),
                want,
                "{name}"
            );
        }
    }

    /// A bit-field ONE_OF default is cut to the width in its Flags before it is matched to an
    /// option.
    #[test]
    fn bit_field_one_of_default_is_cut_to_its_width() {
        let children = [
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            one_of_option(6, 0x02, &1u32.to_le_bytes()),
            uint32_default(0x0000, 0b101),
        ];
        assert_eq!(
            answer_in_guid(
                BIT_VARSTORE_GUID,
                ONE_OF,
                &uint32_range_question(4, UINT_DEC | 2),
                &children,
                unavailable()
            ),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "default 0b101 of a 2-bit ONE_OF"
        );
    }

    /// A bit field's value is its width in bits from its bit VarOffset, as edk2-stable202608
    /// Setup.c GetBitsQuestionValue reads it, whatever the other bits of its bytes hold; a
    /// field over the 4 bytes that GetBitsQuestionValue copies into a UINT32 has none.
    #[test]
    fn bit_field_values_are_read_from_their_bits() {
        let payload = [0x6C, 0xBB, 0x15, 0xAF, 0xD7, 0x86];
        // at bits 8, 9 and 15, from Python's int.from_bytes(payload, "little")
        let cases = [
            (1, ["1", "1", "1"]),
            (3, ["3", "5", "3"]),
            (4, ["11", "13", "11"]),
            (12, ["1467", "2781", "3627"]),
            (17, ["71099", "101085", "89643"]),
            (18, ["202171", "232157", "220715"]),
            (19, ["464315", "494301", "482859"]),
            (
                32,
                [
                    "3618575803",
                    "<ValueUnavailable: EDKII bit field of width 32 at bit 9 spans more than 4 \
                     bytes>",
                    "<ValueUnavailable: EDKII bit field of width 32 at bit 15 spans more than 4 \
                     bytes>",
                ],
            ),
        ];
        for (width, wants) in cases {
            for (offset, want) in [8, 9, 15].into_iter().zip(wants) {
                let data = uint32_range_question(offset, UINT_DEC | width);
                assert_eq!(
                    answer_in_guid(
                        BIT_VARSTORE_GUID,
                        NUMERIC,
                        &data,
                        &[],
                        var_store_of(&payload)
                    ),
                    want,
                    "width {width} at bit {offset}"
                );
            }
        }
    }

    /// An INT_DEC bit field is signed from the type that edk2-stable202608 IfrParse.c gives
    /// it by its StorageWidth, as ProcessOptions.c shows it; its UINT32 IFR default is not.
    #[test]
    fn int_dec_bit_field_is_signed_by_its_storage_width() {
        let cases = [
            ("8-bit at bit 0, in UINT8", 0, 8, vec![0xFF], "-1"),
            ("8-bit at bit 4, in UINT16", 4, 8, vec![0xF0, 0x0F], "255"),
            ("16-bit at bit 0, in UINT16", 0, 16, vec![0xFF, 0xFF], "-1"),
            ("4-bit at bit 0, in UINT8", 0, 4, vec![0x0F], "15"),
            (
                "24-bit at bit 0, in UINT32",
                0,
                24,
                vec![0xFF; 3],
                "16777215",
            ),
            ("32-bit at bit 0, in UINT32", 0, 32, vec![0xFF; 4], "-1"),
        ];
        let default = [uint32_default(0x0000, 0xFF)];
        for (name, offset, width, payload, want) in cases {
            // Flags: EDKII_IFR_DISPLAY_INT_DEC_BIT
            let data = uint32_range_question(offset, width);
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    NUMERIC,
                    &data,
                    &default,
                    var_store_of(&payload)
                ),
                want,
                "{name}"
            );
        }
        assert_eq!(
            answer_in_guid(
                BIT_VARSTORE_GUID,
                NUMERIC,
                &uint32_range_question(0, 8),
                &default,
                unavailable()
            ),
            format!("{UNAVAILABLE} <IFR default: 255>"),
            "8-bit default"
        );
    }

    /// A bit field of width 0 or over 32, which edk2 VfrCompile does not emit, has neither a
    /// value nor a default, and gives its width as the reason before any store error.
    #[test]
    fn bit_field_width_outside_1_to_32_has_no_value() {
        for (width, flags) in [(0, UINT_DEC), (33, UINT_DEC | 33)] {
            let reason = format!("EDKII bit-field width {width}, not 1 to 32");
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    NUMERIC,
                    &uint32_range_question(0, flags),
                    &[],
                    var_store_of(&[0xFF; 8])
                ),
                format!("<ValueUnavailable: {reason}>"),
                "width {width}"
            );
            assert_eq!(
                numeric_in_guid_answer(BIT_VARSTORE_GUID, flags, 1),
                format!("<ValueUnavailable: {reason}> <IFR default: unknown ({reason})>"),
                "width {width} without a store"
            );
        }
    }

    /// A ONE_OF bit field of width 33 shows its default as unknown for its width, unless the
    /// default itself is unknown, whose reason shows instead.
    #[test]
    fn one_of_bit_field_width_33_default_is_unknown() {
        let reason = "EDKII bit-field width 33, not 1 to 32";
        let cases = [
            (
                "constant DEFAULT",
                uint32_default(0x0000, 1),
                format!("<ValueUnavailable: {reason}> <IFR default: unknown ({reason})>"),
            ),
            (
                "non-constant DEFAULT_2",
                ifr_default_2(0x0000, eq_id_val()),
                format!(
                    "<ValueUnavailable: {reason}> <IFR default: unknown (EFI_IFR_VALUE \
                     expression not evaluated: EFI_IFR_EQ_ID_VAL of question 0x0001: \
                     <ValueUnavailable: {reason}>)>"
                ),
            ),
        ];
        for (name, default, want) in cases {
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    ONE_OF,
                    &uint32_range_question(0, UINT_DEC | 33),
                    &[default],
                    unavailable()
                ),
                want,
                "{name}"
            );
        }
    }

    /// The Range of the NUMERIC or ONE_OF `question`.
    fn question_range(question: &IFROperation) -> &Range {
        match &question.parsed_data {
            ParsedOperation::Numeric(parsed) => &parsed.data,
            ParsedOperation::OneOf(parsed) => &parsed.data,
            other => panic!("not a NUMERIC or ONE_OF: {other:?}"),
        }
    }

    /// A NUMERIC or ONE_OF at VarOffset 0 with `flags` and the MinValue, MaxValue and Step of
    /// `range`, in its size.
    fn range_question(flags: u8, range: &Range) -> Vec<u8> {
        let values = match range {
            Range::Range8(r) => [r.min_value, r.max_value, r.step]
                .map(u8::to_le_bytes)
                .concat(),
            Range::Range16(r) => [r.min_value, r.max_value, r.step]
                .map(u16::to_le_bytes)
                .concat(),
            Range::Range32(r) => [r.min_value, r.max_value, r.step]
                .map(u32::to_le_bytes)
                .concat(),
            Range::Range64(r) => [r.min_value, r.max_value, r.step]
                .map(u64::to_le_bytes)
                .concat(),
        };
        [question_header(0), vec![flags], values].concat()
    }

    /// An EDKII bit varstore field's Range is UINT32, whatever its width in Flags.
    #[test]
    fn bit_field_range_is_uint32() {
        let want = Range::Range32(Range32 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let cases = [
            ("3-bit UINT_DEC", 0x43),
            ("19-bit UINT_HEX", 0x93),
            ("19-bit INT_DEC", 0x13),
            ("1-bit UINT_DEC", 0x41),
            ("17-bit UINT_DEC", 0x51),
            ("12-bit UINT_DEC", 0x4C),
            ("zero width", 0x40),
            ("33-bit width", 0x61),
        ];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, flags) in cases {
                let data = range_question(flags, &want);
                let (_root, question) =
                    try_parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &[])
                        .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    &want,
                    "{name}, op {op_code:#04x}"
                );
            }
        }
    }

    /// A question outside an EDKII bit varstore field's GUID has the Range size of
    /// EFI_IFR_NUMERIC_SIZE, also right after such a field and in another GUID.
    #[test]
    fn non_bit_field_range_has_efi_ifr_numeric_size() {
        let want = Range::Range64(Range64 {
            min_value: 0,
            max_value: 1 << 40,
            step: 1,
        });
        let data = range_question(0x13, &want); // UINT64 UINT_DEC
        let bit_field = [
            operation(GUID, true, &BIT_VARSTORE_GUID),
            operation(NUMERIC, true, &uint32_range_question(0, 0x42)),
            END.to_vec(), // End of the NUMERIC
            END.to_vec(), // End of the GUID
        ]
        .concat();
        let cases = [("alone", vec![]), ("after a bit field", vec![bit_field])];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, declarations) in &cases {
                let (_root, question) = try_parse_question(declarations, op_code, &data, &[])
                    .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    &want,
                    "{name}, op {op_code:#04x}"
                );
            }

            let (_root, question) = try_parse_question_in_guid(OTHER_GUID, op_code, &data, &[])
                .unwrap_or_else(|e| panic!("parse other GUID, op {op_code:#04x}: {e:#}"));

            assert_eq!(
                question_range(&question.borrow()),
                &want,
                "other GUID, op {op_code:#04x}"
            );
        }
    }

    /// Reserved Flags bits 2-3 do not change the Range size that EFI_IFR_NUMERIC_SIZE gives.
    #[test]
    fn reserved_flags_bits_do_not_change_range_size() {
        let uint8 = Range::Range8(Range8 {
            min_value: 0,
            max_value: 10,
            step: 1,
        });
        let uint16 = Range::Range16(Range16 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let uint32 = Range::Range32(Range32 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let uint64 = Range::Range64(Range64 {
            min_value: 0,
            max_value: 1 << 40,
            step: 1,
        });
        let cases = [
            ("UINT8", 0x00, &uint8),
            ("UINT8 with reserved bit 2", 0x04, &uint8),
            ("UINT16", 0x01, &uint16),
            ("UINT16 with reserved bit 2", 0x05, &uint16),
            ("UINT32", 0x02, &uint32),
            ("UINT32 with reserved bits 2-3", 0x0E, &uint32),
            ("UINT64", 0x03, &uint64),
            ("UINT64 with reserved bit 2", 0x07, &uint64),
            ("UINT64 with reserved bits 2-3", 0x0F, &uint64),
        ];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, flags, want) in cases {
                let data = range_question(flags, want);
                let (_root, question) = try_parse_question(&[], op_code, &data, &[])
                    .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    want,
                    "{name}, op {op_code:#04x}"
                );
            }
        }
    }
}
