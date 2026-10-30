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

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::rc::Rc;
use std::rc::Weak;

use binrw::BinRead;
use thiserror::Error;

use super::conditions::evaluate_condition;
use super::conditions::evaluate_value;
use super::conditions::option_state;
use super::conditions::skips_scope;
use super::conditions::ExpressionInputs;
use super::conditions::QuestionValues;
use super::conditions::Truth;
use super::find_corresponding_string;
use super::IFRDefault;
use super::IFROpCode;
use super::IFROperation;
use super::IfrDefaultValue;
use super::IncludedStates;
use super::ParsedOperation;

// UEFI 2.10 §33.3.8.3.9, §33.3.8.3.51
const EFI_IFR_CHECKBOX_DEFAULT: u8 = 0x01;
const EFI_IFR_CHECKBOX_DEFAULT_MFG: u8 = 0x02;
const EFI_IFR_OPTION_DEFAULT: u8 = 0x10;
const EFI_IFR_OPTION_DEFAULT_MFG: u8 = 0x20;

/// The identifier of a default store, from an open set (UEFI 2.10 §33.2.5.8).
#[derive(BinRead, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[br(little)]
pub struct DefaultId(pub u16);

impl DefaultId {
    // EFI_HII_DEFAULT_CLASS_STANDARD and EFI_HII_DEFAULT_CLASS_MANUFACTURING
    const STANDARD: Self = Self(0x0000);
    const MANUFACTURING: Self = Self(0x0001);
}

impl fmt::Display for DefaultId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.0)
    }
}

/// A question's default and the default store it comes from.
struct QuestionDefault {
    default_id: DefaultId,
    value: Result<u64, DefaultError>,
}

/// Why a question's default is not known.
#[derive(Debug, Error)]
pub(super) enum DefaultError {
    #[error("EFI_IFR_DEFAULT Type {0:#04x} value not decoded")]
    DefaultType(u8),
    #[error("EFI_IFR_DEFAULT value missing")]
    DefaultValueMissing,
    #[error("EFI_IFR_DEFAULT_2 without EFI_IFR_VALUE")]
    ValueOpMissing,
    #[error("EFI_IFR_VALUE expression not evaluated: {0}")]
    ValueExpression(String),
    #[error("EFI_IFR_SUPPRESS_IF condition not evaluated: {0}")]
    SuppressIfCondition(String),
    #[error("EFI_IFR_ONE_OF_OPTION Type {0:#04x} value not decoded")]
    OptionType(u8),
}

/// What question_scope takes from the scope of an op nested in a question.
enum NestedScope {
    /// Nothing: the ops belong to the nested op (a statement, a question, a DEFAULT's value,
    /// vendor data)
    Own,
    /// The question's ops
    Question,
}

impl NestedScope {
    /// Classifies an op as edk2-stable202608 SetupBrowserDxe/IfrParse.c attaches the ops in its
    /// scope.
    fn of(op_code: IFROpCode) -> Self {
        match op_code {
            IFROpCode::Default
            | IFROpCode::Subtitle
            | IFROpCode::Text
            | IFROpCode::ResetButton
            | IFROpCode::Ref
            | IFROpCode::Action
            | IFROpCode::Numeric
            | IFROpCode::OrderedList
            | IFROpCode::CheckBox
            | IFROpCode::String
            | IFROpCode::Password
            | IFROpCode::Date
            | IFROpCode::Time
            | IFROpCode::Guid
            | IFROpCode::OneOf => Self::Own,
            IFROpCode::Form
            | IFROpCode::Image
            | IFROpCode::OneOfOption
            | IFROpCode::SuppressIf
            | IFROpCode::Locked
            | IFROpCode::FormSet
            | IFROpCode::NoSubmitIf
            | IFROpCode::InconsistentIf
            | IFROpCode::EqIdVal
            | IFROpCode::EqIdId
            | IFROpCode::EqIdValList
            | IFROpCode::And
            | IFROpCode::Or
            | IFROpCode::Not
            | IFROpCode::Rule
            | IFROpCode::GrayOutIf
            | IFROpCode::Refresh
            | IFROpCode::DisableIf
            | IFROpCode::Animation
            | IFROpCode::ToLower
            | IFROpCode::ToUpper
            | IFROpCode::Map
            | IFROpCode::VarStore
            | IFROpCode::VarStoreNameValue
            | IFROpCode::VarStoreEfi
            | IFROpCode::VarStoreDevice
            | IFROpCode::Version
            | IFROpCode::End
            | IFROpCode::Match
            | IFROpCode::Get
            | IFROpCode::Set
            | IFROpCode::Read
            | IFROpCode::Write
            | IFROpCode::Equal
            | IFROpCode::NotEqual
            | IFROpCode::GreaterThan
            | IFROpCode::GreaterEqual
            | IFROpCode::LessThan
            | IFROpCode::LessEqual
            | IFROpCode::BitwiseAnd
            | IFROpCode::BitwiseOr
            | IFROpCode::BitwiseNot
            | IFROpCode::ShiftLeft
            | IFROpCode::ShiftRight
            | IFROpCode::Add
            | IFROpCode::Subtract
            | IFROpCode::Multiply
            | IFROpCode::Divide
            | IFROpCode::Modulo
            | IFROpCode::RuleRef
            | IFROpCode::QuestionRef1
            | IFROpCode::QuestionRef2
            | IFROpCode::Uint8
            | IFROpCode::Uint16
            | IFROpCode::Uint32
            | IFROpCode::Uint64
            | IFROpCode::True
            | IFROpCode::False
            | IFROpCode::ToUint
            | IFROpCode::ToString
            | IFROpCode::ToBoolean
            | IFROpCode::Mid
            | IFROpCode::Find
            | IFROpCode::Token
            | IFROpCode::StringRef1
            | IFROpCode::StringRef2
            | IFROpCode::Conditional
            | IFROpCode::QuestionRef3
            | IFROpCode::Zero
            | IFROpCode::One
            | IFROpCode::Ones
            | IFROpCode::Undefined
            | IFROpCode::Length
            | IFROpCode::Dup
            | IFROpCode::This
            | IFROpCode::Span
            | IFROpCode::Value
            | IFROpCode::DefaultStore
            | IFROpCode::FormMap
            | IFROpCode::Catenate
            | IFROpCode::Security
            | IFROpCode::ModalTag
            | IFROpCode::RefreshId
            | IFROpCode::WarningIf
            | IFROpCode::Match2
            | IFROpCode::Unknown(_) => Self::Question,
        }
    }
}

/// Returns the ops in the question's scope in IFR order.
// TODO: drop options and expressions (e.g. EFI_IFR_DEFAULT_2's EFI_IFR_VALUE) under a true
// DISABLE_IF, as UEFI 2.10 §33.3.8.3.14 says, for firmware that does; edk2-stable202608
// IfrParse.c keeps them inside a question, as this does.
pub(super) fn question_scope(question: &IFROperation) -> Vec<Rc<RefCell<IFROperation>>> {
    fn walk(op: &IFROperation, scope: &mut Vec<Rc<RefCell<IFROperation>>>) {
        for child in &op.children {
            if skips_scope(&child.borrow()) {
                continue;
            }
            scope.push(Rc::clone(child));
            let child = child.borrow();
            match NestedScope::of(child.op_code) {
                NestedScope::Own => {}
                NestedScope::Question => walk(&child, scope),
            }
        }
    }
    let mut scope = Vec::new();
    walk(question, &mut scope);
    scope
}

/// Whether edk2-stable202608 SetupBrowserDxe shows an option.
enum OptionVisibility {
    Shown,
    /// A SUPPRESS_IF hides it
    Suppressed,
    /// Why it is not known
    Unknown(String),
}

/// Returns whether edk2-stable202608 SetupBrowserDxe shows the option `op`.
fn option_visibility(
    op: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> OptionVisibility {
    let state = option_state(op, inputs);
    let shown = IncludedStates::empty();
    match (state.is_allowed(shown), state.may_be_allowed(shown)) {
        (true, _) => OptionVisibility::Shown,
        (false, true) => {
            let reasons: Vec<&str> = state.reasons().collect();
            OptionVisibility::Unknown(reasons.join("; "))
        }
        (false, false) => OptionVisibility::Suppressed,
    }
}

/// form_set_default_ids of the FormSet of the last question asked about: questions come FormSet
/// by FormSet, so that a FormSet is walked once per run of its questions.
#[derive(Default)]
pub(super) struct FormSetDefaultIds(Option<(Rc<RefCell<IFROperation>>, Vec<DefaultId>)>);

impl FormSetDefaultIds {
    /// Returns form_set_default_ids of the question's FormSet, or STANDARD outside FormSets.
    pub(super) fn of(
        &mut self,
        question: &IFROperation,
        inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    ) -> &[DefaultId] {
        let Some(form_set) = form_set_of(question) else {
            return &[DefaultId::STANDARD];
        };
        let entry = match self.0.take() {
            Some((known, default_ids)) if Rc::ptr_eq(&known, &form_set) => (known, default_ids),
            _ => {
                let default_ids = form_set_default_ids(&form_set.borrow(), inputs);
                (form_set, default_ids)
            }
        };
        &self.0.insert(entry).1
    }
}

/// Returns the innermost FormSet around `op`.
fn form_set_of(op: &IFROperation) -> Option<Rc<RefCell<IFROperation>>> {
    let mut scope = op.parent.as_ref().and_then(Weak::upgrade);
    while let Some(op) = scope {
        if op.borrow().op_code == IFROpCode::FormSet {
            return Some(op);
        }
        scope = op.borrow().parent.as_ref().and_then(Weak::upgrade);
    }
    None
}

/// Returns STANDARD, then the DefaultIds of the DEFAULTSTOREs in `form_set`, ascending.
fn form_set_default_ids(
    form_set: &IFROperation,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Vec<DefaultId> {
    // Nested ones too (UEFI 2.10 §33.2.5.1), except under a true DISABLE_IF
    // outside forms (§33.3.8.3.14), the only one edk2-stable202608
    // SetupBrowserDxe/IfrParse.c evaluates while parsing.
    fn walk(
        op: &IFROperation,
        in_form: bool,
        default_ids: &mut Vec<DefaultId>,
        inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
    ) {
        for child in &op.children {
            let child = child.borrow();
            if skips_scope(&child) {
                continue;
            }
            if let ParsedOperation::DefaultStore(store) = &child.parsed_data {
                default_ids.push(store.default_id);
            }
            if !in_form
                && child.op_code == IFROpCode::DisableIf
                && evaluate_condition(&child, inputs) == Truth::Known(true)
            {
                continue;
            }
            let in_form = in_form || matches!(child.op_code, IFROpCode::Form | IFROpCode::FormMap);
            walk(&child, in_form, default_ids, inputs);
        }
    }
    let mut default_ids = Vec::new();
    walk(form_set, false, &mut default_ids, inputs);
    default_ids.sort_unstable();
    default_ids.dedup();
    default_ids.retain(|&id| id != DefaultId::STANDARD);
    default_ids.insert(0, DefaultId::STANDARD);
    default_ids
}

/// Returns the value of the EFI_IFR_DEFAULT `op`.
fn ifr_default_value(
    op: &IFROperation,
    default: &IFRDefault,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Result<u64, DefaultError> {
    let value = op
        .children
        .iter()
        .find(|child| child.borrow().op_code == IFROpCode::Value);
    let Some(value) = value else {
        return match default.value {
            IfrDefaultValue::Decoded(value) => value
                .as_u64()
                .ok_or(DefaultError::DefaultType(default.value_type)),
            IfrDefaultValue::InValueOp => Err(DefaultError::ValueOpMissing),
            IfrDefaultValue::NotDecoded => Err(DefaultError::DefaultType(default.value_type)),
            IfrDefaultValue::Missing => Err(DefaultError::DefaultValueMissing),
        };
    };
    let value = value.borrow();
    evaluate_value(&value, inputs).map_err(DefaultError::ValueExpression)
}

/// Returns the question's default and its DefaultId, trying STANDARD, then the declared
/// DEFAULTSTOREs ascending (edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionDefault).
fn question_default(
    question: &IFROperation,
    default_ids: &[DefaultId],
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Option<QuestionDefault> {
    let scope = question_scope(question);
    default_ids.iter().find_map(|&default_id| {
        default_for_id(question, &scope, default_id, inputs)
            .map(|value| QuestionDefault { default_id, value })
    })
}

/// Returns the question's default for `default_id`: EFI_IFR_DEFAULT, then a flagged
/// EFI_IFR_ONE_OF_OPTION, then CHECKBOX Flags (UEFI 2.10 §33.3.8.3.9, §33.3.8.3.47).
fn default_for_id(
    question: &IFROperation,
    scope: &[Rc<RefCell<IFROperation>>],
    default_id: DefaultId,
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Option<Result<u64, DefaultError>> {
    // EFI_IFR_DEFAULT, wherever it is in the question's scope
    let ifr_default = scope.iter().find_map(|op| {
        let op = op.borrow();
        match &op.parsed_data {
            ParsedOperation::IFRDefault(default) if default.default_id == default_id => {
                Some(ifr_default_value(&op, default, inputs))
            }
            _ => None,
        }
    });
    if ifr_default.is_some() {
        return ifr_default;
    }

    let (option_flag, checkbox_flag) = match default_id {
        DefaultId::STANDARD => (EFI_IFR_OPTION_DEFAULT, EFI_IFR_CHECKBOX_DEFAULT),
        DefaultId::MANUFACTURING => (EFI_IFR_OPTION_DEFAULT_MFG, EFI_IFR_CHECKBOX_DEFAULT_MFG),
        _ => return None,
    };
    let option_default = scope.iter().find_map(|op| {
        let op = op.borrow();
        let ParsedOperation::OneOfOption(option) = &op.parsed_data else {
            return None;
        };
        if option.flags & option_flag == 0 {
            return None;
        }
        match option_visibility(&op, inputs) {
            OptionVisibility::Shown => Some(
                option
                    .value
                    .as_u64()
                    .ok_or(DefaultError::OptionType(option.value_type)),
            ),
            OptionVisibility::Suppressed => None,
            OptionVisibility::Unknown(reason) => {
                Some(Err(DefaultError::SuppressIfCondition(reason)))
            }
        }
    });
    if option_default.is_some() {
        return option_default;
    }

    // The flags end the search, as in edk2-stable202608 SetupBrowserDxe/Setup.c
    // GetQuestionDefault, and a clear one is FALSE, as in its HiiDatabaseDxe/ConfigRouting.c:
    // with only the MFG flag set, the standard default is 0, though ConfigRouting.c copies the
    // MFG TRUE to every DefaultId.
    let ParsedOperation::CheckBox(checkbox) = &question.parsed_data else {
        return None;
    };
    Some(Ok(u64::from(checkbox.flags & checkbox_flag != 0)))
}

/// Appends the question's default, a value shown by `text`, to the reason its current
/// value is unavailable.
pub(super) fn push_default<V: QuestionValues, E: fmt::Display>(
    answer: &mut String,
    question: &IFROperation,
    default_ids: &[DefaultId],
    inputs: &mut ExpressionInputs<'_, V>,
    text: impl FnOnce(u64, &mut ExpressionInputs<'_, V>) -> Result<String, E>,
) {
    let Some(QuestionDefault { default_id, value }) =
        question_default(question, default_ids, inputs)
    else {
        return;
    };
    let value = match value.map(|value| text(value, inputs)) {
        Ok(Ok(shown)) => shown,
        Ok(Err(reason)) => format!("unknown ({reason})"),
        Err(reason) => format!("unknown ({reason})"),
    };
    match default_id {
        DefaultId::STANDARD => answer.push_str(&format!(" <IFR default: {value}>")),
        _ => answer.push_str(&format!(" <IFR default (DefaultId {default_id}): {value}>")),
    }
}

/// Returns the text of the first option in the question's scope with `value` that no
/// SUPPRESS_IF hides, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption finds it.
pub(super) fn option_text(
    question: &IFROperation,
    value: u64,
    string_packages: &[HashMap<i32, String>],
    inputs: &mut ExpressionInputs<'_, impl QuestionValues>,
) -> Result<Option<String>, DefaultError> {
    question_scope(question)
        .iter()
        .find_map(|op| {
            let op = op.borrow();
            let ParsedOperation::OneOfOption(option) = &op.parsed_data else {
                return None;
            };
            if option.value.as_u64() != Some(value) {
                return None;
            }
            match option_visibility(&op, inputs) {
                OptionVisibility::Shown => Some(Ok(find_corresponding_string(
                    option.option_string_id,
                    string_packages,
                )
                .trim()
                .to_string())),
                OptionVisibility::Suppressed => None,
                OptionVisibility::Unknown(reason) => {
                    Some(Err(DefaultError::SuppressIfCondition(reason)))
                }
            }
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::collections::HashSet;
    use std::rc::Rc;

    use binrw::io::Cursor;

    use super::super::conditions::QuestionValue;
    use super::super::conditions::ValueKind;
    use super::super::find_question;
    use super::super::handle_form_set;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::IncludedStates;
    use super::super::Selection;

    /// The MethodIdentifier of the test EFI_IFR_FORM_MAP method.
    const METHOD_IDENTIFIER: [u8; 16] = [0x33; 16];

    /// Why a condition on question 1, the question of `parse_question()`, is not evaluated.
    const QUESTION_1_UNAVAILABLE: &str = "EqIdVal of question 0x0001: <ValueUnavailable: no \
                                          supported varstore with matching id 0x0001 found>";

    #[test]
    fn checkbox_default_comes_from_default_then_flags() {
        let stores = [default_store(0), default_store(1)];
        let cases: [(&str, u8, Vec<Vec<u8>>, &str); 5] = [
            ("standard flag", 0x01, vec![], " <IFR default: 1>"),
            ("clear flags", 0x00, vec![], " <IFR default: 0>"),
            (
                "DEFAULT beats the flag",
                0x01,
                vec![ifr_default(0, 0)],
                " <IFR default: 0>",
            ),
            (
                "constant DEFAULT_2",
                0x00,
                vec![ifr_default_2(0, uint8(1))],
                " <IFR default: 1>",
            ),
            (
                "manufacturing DEFAULT does not hide the standard flag",
                0x01,
                vec![ifr_default(1, 0)],
                " <IFR default: 1>",
            ),
        ];
        for (name, flags, children, suffix) in cases {
            assert_eq!(
                answer(
                    &stores,
                    CHECKBOX,
                    &checkbox(0, flags),
                    &children,
                    unavailable()
                ),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    #[test]
    fn one_of_option_flag_gives_standard_default() {
        let children = [flagged_option(5, 0x20, 0), flagged_option(6, 0x10, 1)];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "standard option flag"
        );
    }

    #[test]
    fn ifr_default_overrides_option_flag() {
        let children = [
            flagged_option(5, 0x00, 0),
            flagged_option(6, 0x10, 1),
            ifr_default(0x0000, 0),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Disabled>"),
            "DEFAULT and option flag"
        );
    }

    #[test]
    fn manufacturing_default_needs_declared_default_store() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];

        assert_eq!(
            one_of_default(&[], &children),
            UNAVAILABLE,
            "no DEFAULTSTORE"
        );
        assert_eq!(
            one_of_default(&[default_store(0x0000), default_store(0x0001)], &children),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>"),
            "STANDARD and manufacturing DEFAULTSTOREs"
        );
    }

    #[test]
    fn default_store_under_form_set_suppress_if_is_declared() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];
        let suppressed_store = |default_id| {
            [conditional(
                SUPPRESS_IF,
                ifr_true(),
                &[default_store(default_id)],
            )]
        };

        assert_eq!(
            one_of_default(&suppressed_store(0x0001), &children),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>"),
            "DEFAULTSTORE 0x0001 under SUPPRESS_IF"
        );
        assert_eq!(
            one_of_default(&suppressed_store(0x0002), &children),
            UNAVAILABLE,
            "DEFAULTSTORE 0x0002 under SUPPRESS_IF"
        );
    }

    #[test]
    fn default_store_under_true_form_set_disable_if_is_ignored() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];
        let disabled_store =
            |condition| conditional(DISABLE_IF, condition, &[default_store(0x0001)]);
        let in_form = |op_code, data: &[u8]| {
            [
                operation(op_code, true, data),
                disabled_store(ifr_true()),
                END.to_vec(),
            ]
            .concat()
        };
        // FormId 1, FormTitle 1
        let form = in_form(FORM, &[0x01, 0x00, 0x01, 0x00]);
        // FormId 2, one method: MethodTitle 1, METHOD_IDENTIFIER
        let form_map = in_form(
            FORM_MAP,
            &[&[0x02, 0x00, 0x01, 0x00][..], &METHOD_IDENTIFIER].concat(),
        );
        let mfg_default = format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>");

        assert_eq!(
            one_of_default(&[disabled_store(ifr_true())], &children),
            UNAVAILABLE,
            "DISABLE_IF TRUE"
        );
        assert_eq!(
            one_of_default(&[disabled_store(ifr_false())], &children),
            mfg_default,
            "DISABLE_IF FALSE"
        );
        assert_eq!(
            one_of_default(&[disabled_store(eq_id_val())], &children),
            mfg_default,
            "unevaluated DISABLE_IF"
        );
        assert_eq!(
            one_of_default(&[form], &children),
            mfg_default,
            "DISABLE_IF TRUE in a FORM"
        );
        assert_eq!(
            one_of_default(&[form_map], &children),
            mfg_default,
            "DISABLE_IF TRUE in a FORM_MAP"
        );
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes declares no DEFAULTSTORE in the
    /// scope of an opcode above EFI_IFR_MATCH2_OP.
    #[test]
    fn default_store_in_an_unknown_opcode_scope_is_not_declared() {
        let children = [flagged_option(5, 0x00, 0), flagged_option(6, 0x20, 1)];
        let in_scope = |op_code: u8| {
            [
                operation(op_code, true, &[]),
                default_store(0x0001),
                END.to_vec(),
            ]
            .concat()
        };
        let mfg_default = format!("{UNAVAILABLE} <IFR default (DefaultId 0x0001): Enabled>");
        let cases = [
            ("opcode 0x00", in_scope(0x00), mfg_default.as_str()),
            ("opcode 0x65", in_scope(0x65), UNAVAILABLE),
            ("opcode 0x70", in_scope(0x70), UNAVAILABLE),
        ];
        for (name, scope, want) in cases {
            assert_eq!(one_of_default(&[scope], &children), want, "{name}");
        }
    }

    #[test]
    fn declared_default_stores_are_tried_in_ascending_order() {
        let data = uint8_numeric(0x10, 0, 10);
        let children = [ifr_default(0x4000, 3), ifr_default(0x0002, 4)];
        let numeric = |declarations: &[Vec<u8>]| {
            answer(declarations, NUMERIC, &data, &children, unavailable())
        };

        assert_eq!(numeric(&[]), UNAVAILABLE, "no DEFAULTSTORE");
        assert_eq!(
            numeric(&[default_store(0x4000), default_store(0x0002)]),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x0002): 4>"),
            "DEFAULTSTOREs 0x4000 and 0x0002"
        );
        assert_eq!(
            numeric(&[default_store(0x4000)]),
            format!("{UNAVAILABLE} <IFR default (DefaultId 0x4000): 3>"),
            "DEFAULTSTORE 0x4000"
        );
    }

    /// list_questions and find_question try the DEFAULTSTOREs of the FormSet they walk into.
    #[test]
    fn list_and_find_question_try_the_form_set_default_stores() {
        let (root, _question) = parse_question(
            &[default_store(0x0000), default_store(0x0001)],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[ifr_default(0x0001, 4)],
        );
        let want = "<ValueUnavailable: no supported varstore with matching id 0x0001 found> \
                    <IFR default (DefaultId 0x0001): 4>";

        let efivars = Efivars::new();
        let listed = list_questions(
            Rc::clone(&root),
            &strings(),
            IncludedStates::empty(),
            &mut efivars.reader(),
        );
        let Selection::Picked(found, _) = find_question(
            root,
            &strings(),
            &HashSet::from([PROMPT]),
            IncludedStates::empty(),
            &mut efivars.reader(),
        ) else {
            panic!("find the question by its prompt");
        };

        let answers: Vec<&str> = listed
            .iter()
            .map(|(question, _)| question.value.as_str())
            .collect();
        assert_eq!(answers, [want], "list_questions");
        assert_eq!(found.value, want, "find_question");
    }

    /// A question outside every FormSet tries the standard default store.
    #[test]
    fn question_outside_form_sets_tries_the_standard_default_store() {
        let data = [
            operation(NUMERIC, true, &uint8_numeric(0x10, 0, 10)),
            ifr_default(0x0000, 4),
            END.to_vec(),
        ]
        .concat();
        let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the Numeric");
        let unavailable = "<ValueUnavailable: varstore not found because we reached root>";

        let listed = list_questions(
            root,
            &strings(),
            IncludedStates::empty(),
            &mut Efivars::new().reader(),
        );

        let answers: Vec<&str> = listed.iter().map(|(q, _)| q.value.as_str()).collect();
        assert_eq!(
            answers,
            [format!("{unavailable} <IFR default: 4>")],
            "answer of a question outside FormSets"
        );
    }

    /// The questions of a FormSet in a FormSet try the DEFAULTSTOREs of the inner FormSet, and
    /// those after it the DEFAULTSTOREs of the outer one again.
    #[test]
    fn questions_try_the_default_stores_of_their_form_set() {
        let numeric = |default: u8| {
            [
                operation(NUMERIC, true, &uint8_numeric(0x10, 0, 10)),
                ifr_default(0x0001, default),
                END.to_vec(),
            ]
            .concat()
        };
        let data = form_set(&[
            default_store(0x0001),
            // in a FORM, FormId 1, FormTitle 1, so the FormSet is not its parent
            [
                operation(FORM, true, &[0x01, 0x00, 0x01, 0x00]),
                numeric(4),
                END.to_vec(),
            ]
            .concat(),
            form_set(&[numeric(5)]),
            numeric(6),
        ]);
        let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the FormSet");
        let unavailable = "<ValueUnavailable: no supported varstore with matching id 0x0001 found>";

        let listed = list_questions(
            root,
            &strings(),
            IncludedStates::empty(),
            &mut Efivars::new().reader(),
        );

        let answers: Vec<&str> = listed
            .iter()
            .map(|(question, _)| question.value.as_str())
            .collect();
        assert_eq!(
            answers,
            [
                format!("{unavailable} <IFR default (DefaultId 0x0001): 4>"),
                unavailable.to_string(),
                format!("{unavailable} <IFR default (DefaultId 0x0001): 6>"),
            ],
            "answers before, in and after the inner FormSet"
        );
    }

    /// A question outside every FormSet, after a question in one, tries the standard default store
    /// and not the DEFAULTSTOREs of that FormSet.
    #[test]
    fn question_outside_form_sets_after_a_form_set_tries_the_standard_default_store() {
        let numeric = |default: u8| {
            [
                operation(NUMERIC, true, &uint8_numeric(0x10, 0, 10)),
                ifr_default(0x0001, default),
                END.to_vec(),
            ]
            .concat()
        };
        // a scope that is no FormSet holds both
        let data = conditional(
            SUPPRESS_IF,
            ifr_false(),
            &[form_set(&[default_store(0x0001), numeric(4)]), numeric(5)],
        );
        let root = handle_form_set(&mut Cursor::new(&data)).expect("parse the SUPPRESS_IF");

        let listed = list_questions(
            root,
            &strings(),
            IncludedStates::empty(),
            &mut Efivars::new().reader(),
        );

        let answers: Vec<&str> = listed.iter().map(|(q, _)| q.value.as_str()).collect();
        assert_eq!(
            answers,
            [
                "<ValueUnavailable: no supported varstore with matching id 0x0001 found> \
                 <IFR default (DefaultId 0x0001): 4>",
                "<ValueUnavailable: varstore not found because we reached root>",
            ],
            "answers in the FormSet and after it"
        );
    }

    #[test]
    fn suppressed_option_flag_is_skipped() {
        let with_condition = |condition| {
            one_of_default(
                &[],
                &[
                    conditional(SUPPRESS_IF, condition, &[flagged_option(6, 0x10, 1)]),
                    flagged_option(5, 0x10, 0),
                ],
            )
        };

        let in_true_suppress_if = |inner| {
            one_of_default(
                &[],
                &[
                    conditional(SUPPRESS_IF, ifr_true(), &[inner]),
                    flagged_option(5, 0x10, 0),
                ],
            )
        };

        let disabled = format!("{UNAVAILABLE} <IFR default: Disabled>");
        assert_eq!(with_condition(ifr_true()), disabled, "SUPPRESS_IF TRUE");
        assert_eq!(with_condition(uint8(2)), disabled, "SUPPRESS_IF 2");
        assert_eq!(
            with_condition(ifr_false()),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "SUPPRESS_IF FALSE"
        );
        assert_eq!(
            in_true_suppress_if(conditional(
                GRAY_OUT_IF,
                ifr_false(),
                &[flagged_option(6, 0x10, 1)]
            )),
            disabled,
            "GRAY_OUT_IF FALSE in SUPPRESS_IF TRUE"
        );
        assert_eq!(
            in_true_suppress_if(conditional(
                SUPPRESS_IF,
                eq_id_val(),
                &[flagged_option(6, 0x10, 1)]
            )),
            disabled,
            "unevaluated SUPPRESS_IF in SUPPRESS_IF TRUE"
        );
    }

    #[test]
    fn option_flag_under_unevaluated_condition_gives_unknown_default() {
        let children = [
            conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];
        let unflagged = [
            conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(6, 0x00, 1)]),
            flagged_option(5, 0x10, 0),
        ];
        let false_in_unevaluated = [
            conditional(
                SUPPRESS_IF,
                eq_id_val(),
                &[conditional(
                    SUPPRESS_IF,
                    ifr_false(),
                    &[flagged_option(6, 0x10, 1)],
                )],
            ),
            flagged_option(5, 0x10, 0),
        ];
        let unknown = format!(
            "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_SUPPRESS_IF condition not evaluated: \
             {QUESTION_1_UNAVAILABLE})>"
        );

        assert_eq!(
            one_of_default(&[], &children),
            unknown,
            "flagged option in unevaluated SUPPRESS_IF"
        );
        assert_eq!(
            one_of_default(&[], &unflagged),
            format!("{UNAVAILABLE} <IFR default: Disabled>"),
            "unflagged option in unevaluated SUPPRESS_IF"
        );
        assert_eq!(
            one_of_default(&[], &false_in_unevaluated),
            unknown,
            "SUPPRESS_IF FALSE in unevaluated SUPPRESS_IF"
        );
    }

    /// TRUE NOT as a multi-op expression, whose first op opens the scope END closes.
    fn true_not() -> Vec<u8> {
        [
            operation(TRUE, true, &[]),
            operation(NOT, false, &[]),
            END.to_vec(),
        ]
        .concat()
    }

    #[test]
    fn option_flag_under_multi_op_condition_follows_it() {
        let false_not = [
            operation(FALSE, true, &[]),
            operation(NOT, false, &[]),
            END.to_vec(),
        ]
        .concat();
        let cases = [
            ("TRUE NOT", true_not(), "Enabled"),
            ("FALSE NOT", false_not, "Disabled"),
        ];
        for (name, condition, default) in cases {
            let children = [
                conditional(SUPPRESS_IF, condition, &[flagged_option(6, 0x10, 1)]),
                flagged_option(5, 0x10, 0),
            ];

            assert_eq!(
                one_of_default(&[], &children),
                format!("{UNAVAILABLE} <IFR default: {default}>"),
                "{name}"
            );
        }
    }

    /// A SUPPRESS_IF on the value of another question decides the default once that value is
    /// known.
    #[test]
    fn option_flag_under_condition_on_a_known_value_follows_it() {
        let children = [
            conditional(
                SUPPRESS_IF,
                eq_id_val_of(2, 1),
                &[flagged_option(6, 0x10, 1)],
            ),
            flagged_option(5, 0x10, 0),
        ];
        let unreadable = QuestionValue::Unreadable {
            kind: ValueKind::Uint,
            reason: "r".to_string(),
        };
        let cases = [
            ("question 2 is 1", QuestionValue::Uint(1), "Disabled"),
            ("question 2 is 0", QuestionValue::Uint(0), "Enabled"),
            (
                "question 2 unreadable",
                unreadable,
                "unknown (EFI_IFR_SUPPRESS_IF condition not evaluated: EqIdVal of question \
                 0x0002: r)",
            ),
        ];
        for (name, value, default) in cases {
            let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &children);
            let values = MapValues(HashMap::from([(2, value)]));

            assert_eq!(
                question_descriptor_with(&question, unavailable(), &values).value,
                format!("{UNAVAILABLE} <IFR default: {default}>"),
                "{name}"
            );
        }
    }

    #[test]
    fn default_2_on_a_known_value_is_evaluated() {
        let question_ref1 = operation(QUESTION_REF1, false, &2u16.to_le_bytes());
        let children = [
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
            ifr_default_2(0x0000, question_ref1),
        ];
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &children);
        let values = MapValues(HashMap::from([(2, QuestionValue::Uint(1))]));

        assert_eq!(
            question_descriptor_with(&question, unavailable(), &values).value,
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "DEFAULT_2 of question 2"
        );
    }

    #[test]
    fn default_under_suppress_if_and_option_under_gray_out_if_apply() {
        let suppressed_default = [
            conditional(SUPPRESS_IF, ifr_true(), &[ifr_default(0x0000, 1)]),
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
        ];
        let grayed_out_option = [
            conditional(GRAY_OUT_IF, ifr_true(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];

        let enabled = format!("{UNAVAILABLE} <IFR default: Enabled>");
        assert_eq!(
            one_of_default(&[], &suppressed_default),
            enabled,
            "DEFAULT in SUPPRESS_IF TRUE"
        );
        assert_eq!(
            one_of_default(&[], &grayed_out_option),
            enabled,
            "flagged option in GRAY_OUT_IF TRUE"
        );
    }

    #[test]
    fn default_and_option_under_true_disable_if_in_question_apply() {
        let disabled_default = [
            conditional(DISABLE_IF, ifr_true(), &[ifr_default(0x0000, 1)]),
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
        ];
        let disabled_option = [
            conditional(DISABLE_IF, ifr_true(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];
        let numeric = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[
                conditional(DISABLE_IF, ifr_true(), &[ifr_default(0x0000, 9)]),
                ifr_default(0x0000, 5),
            ],
            unavailable(),
        );

        let enabled = format!("{UNAVAILABLE} <IFR default: Enabled>");
        assert_eq!(
            one_of_default(&[], &disabled_default),
            enabled,
            "DEFAULT in DISABLE_IF TRUE"
        );
        assert_eq!(
            one_of_default(&[], &disabled_option),
            enabled,
            "flagged option in DISABLE_IF TRUE"
        );
        assert_eq!(
            numeric,
            format!("{UNAVAILABLE} <IFR default: 9>"),
            "NUMERIC DEFAULT in DISABLE_IF TRUE"
        );
    }

    #[test]
    fn option_under_non_constant_disable_if_in_question_applies() {
        let children = [
            conditional(DISABLE_IF, eq_id_val(), &[flagged_option(6, 0x10, 1)]),
            flagged_option(5, 0x10, 0),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "flagged option in unevaluated DISABLE_IF"
        );
    }

    #[test]
    fn default_2_constant_overrides_option_flag() {
        let children = [
            flagged_option(5, 0x10, 0),
            flagged_option(6, 0x00, 1),
            ifr_default_2(0x0000, uint8(1)),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "constant DEFAULT_2 and option flag"
        );
    }

    #[test]
    fn default_2_non_constant_is_unknown() {
        let children = [
            flagged_option(5, 0x10, 0),
            ifr_default_2(0x0000, eq_id_val()),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!(
                "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_VALUE expression not evaluated: \
                 {QUESTION_1_UNAVAILABLE})>"
            ),
            "non-constant DEFAULT_2"
        );
    }

    #[test]
    fn truncated_default_is_unknown() {
        let children = [operation(DEFAULT, false, &[0x00, 0x00, 0x00])];

        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &children,
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: unknown (EFI_IFR_DEFAULT value missing)>"),
            "DEFAULT without its value"
        );
    }

    #[test]
    fn default_2_without_value_is_unknown() {
        // DefaultId STANDARD, Type EFI_IFR_TYPE_OTHER, and no nested EFI_IFR_VALUE
        let children = [operation(DEFAULT, false, &[0x00, 0x00, 0x08])];

        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &children,
            unavailable(),
        );

        assert_eq!(
            got,
            format!(
                "{UNAVAILABLE} <IFR default: unknown (EFI_IFR_DEFAULT_2 without EFI_IFR_VALUE)>"
            ),
            "DEFAULT_2 without its VALUE"
        );
    }

    /// UEFI 2.10 §33.3.8.3.9 and §33.3.8.3.47 rank a nested EFI_IFR_DEFAULT
    /// above a flagged EFI_IFR_ONE_OF_OPTION, and that above CHECKBOX Flags.
    #[test]
    fn option_flag_gives_numeric_and_checkbox_default() {
        let stores = [default_store(0x0000), default_store(0x0001)];
        let numeric = uint8_numeric(0x10, 0, 10);
        let cases = [
            (
                "NUMERIC option",
                NUMERIC,
                &numeric,
                vec![flagged_option(6, 0x10, 7)],
                " <IFR default: 7>",
            ),
            (
                "NUMERIC manufacturing option",
                NUMERIC,
                &numeric,
                vec![flagged_option(6, 0x20, 9)],
                " <IFR default (DefaultId 0x0001): 9>",
            ),
            (
                "DEFAULT beats NUMERIC option",
                NUMERIC,
                &numeric,
                vec![flagged_option(6, 0x10, 7), ifr_default(0x0000, 3)],
                " <IFR default: 3>",
            ),
            (
                "CHECKBOX option over clear flags",
                CHECKBOX,
                &checkbox(0, 0x00),
                vec![flagged_option(6, 0x10, 1)],
                " <IFR default: 1>",
            ),
            (
                "CHECKBOX option over set flags",
                CHECKBOX,
                &checkbox(0, 0x01),
                vec![flagged_option(5, 0x10, 0)],
                " <IFR default: 0>",
            ),
            (
                "DEFAULT beats CHECKBOX option",
                CHECKBOX,
                &checkbox(0, 0x00),
                vec![flagged_option(6, 0x10, 1), ifr_default(0x0000, 0)],
                " <IFR default: 0>",
            ),
        ];
        for (name, op_code, data, children, suffix) in cases {
            assert_eq!(
                answer(&stores, op_code, data, &children, unavailable()),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// The default's option is the first one with its value that no SUPPRESS_IF
    /// hides, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption finds it.
    #[test]
    fn one_of_default_text_skips_suppressed_options() {
        let unevaluated = format!(
            " <IFR default: unknown (EFI_IFR_SUPPRESS_IF condition not evaluated: \
             {QUESTION_1_UNAVAILABLE})>"
        );
        let cases = [
            (
                "suppressed duplicate first",
                vec![
                    conditional(SUPPRESS_IF, ifr_true(), &[flagged_option(5, 0x00, 1)]),
                    flagged_option(6, 0x10, 1),
                ],
                " <IFR default: Enabled>",
            ),
            (
                "first of two shown duplicates",
                vec![flagged_option(5, 0x00, 1), flagged_option(6, 0x10, 1)],
                " <IFR default: Disabled>",
            ),
            (
                "unevaluated duplicate first",
                vec![
                    conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(5, 0x00, 1)]),
                    flagged_option(6, 0x10, 1),
                ],
                unevaluated.as_str(),
            ),
            (
                "shown before unevaluated duplicate",
                vec![
                    flagged_option(6, 0x10, 1),
                    conditional(SUPPRESS_IF, eq_id_val(), &[flagged_option(5, 0x00, 1)]),
                ],
                " <IFR default: Enabled>",
            ),
        ];
        for (name, children, suffix) in cases {
            assert_eq!(
                one_of_default(&[], &children),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }
}
