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

//! Questions whose value only their driver holds: a ONE_OF, NUMERIC or CHECKBOX without a VarStore
//! that storageless.rs routes through its driver's EFI_HII_CONFIG_ACCESS_PROTOCOL.Callback()
//! (UEFI 2.11 §33.2.5.6): what get needs to reach it through the driver, and the stores
//! that the question's FormSet declares, with the settings that a forms browser requests of each.

use std::fmt;

use thiserror::Error;

use super::conditions::enclosing_form_set;
use super::defaults::standard_default;
#[cfg(any(target_os = "uefi", all(test, efivar_dumps)))]
use super::question_values::checkbox_text;
use super::question_values::form_set_guid;
#[cfg(any(target_os = "uefi", all(test, efivar_dumps)))]
use super::question_values::one_of_text;
use super::question_values::ValueQuestion;
use super::storage::store_declarations;
use super::storage::StoreDeclaration;
use super::storage::VariableStore;
use super::storageless::NoVarStore;
use super::storageless::StoragelessQuestion;
use super::storageless::StoragelessRoute;
use super::DisabledForm;
use super::FormSetWalk;
use super::IFROperation;
#[cfg(any(target_os = "uefi", all(test, efivar_dumps)))]
use super::IncludedStates;
use super::NumericFormat;
use super::ParsedOperation;
use super::QuestionDescriptor;
use super::QuestionExpression;
use super::QuestionValues;
use crate::hii::package::Guid;

/// EFI_IFR_TYPE_x (UEFI 2.11 §33.3.8.3.51) of the values of the questions that this module
/// describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum IfrValueType {
    NumSize8 = 0x00,
    NumSize16 = 0x01,
    NumSize32 = 0x02,
    NumSize64 = 0x03,
    Boolean = 0x04,
}

impl IfrValueType {
    /// The type of a ONE_OF or NUMERIC value of `size` bytes.
    fn of_size(size: u8) -> Option<Self> {
        match size {
            1 => Some(Self::NumSize8),
            2 => Some(Self::NumSize16),
            4 => Some(Self::NumSize32),
            8 => Some(Self::NumSize64),
            _ => None,
        }
    }

    /// The bits of a u64 that a value of the type uses.
    pub(crate) fn mask(self) -> u64 {
        match self {
            Self::NumSize8 | Self::Boolean => u64::from(u8::MAX),
            Self::NumSize16 => u64::from(u16::MAX),
            Self::NumSize32 => u64::from(u32::MAX),
            Self::NumSize64 => u64::MAX,
        }
    }
}

/// A question whose value only its driver holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DriverHeldQuestion {
    /// The GUID of its FormSet
    pub(crate) form_set: Guid,
    pub(crate) question_id: u16,
    pub(crate) value_type: IfrValueType,
    /// Its value before the driver's: its standard default, else 0, as a forms browser starts a
    /// question without storage (edk2-stable202608 SetupBrowserDxe Setup.c:5956)
    pub(crate) initial: u64,
    /// The stores its FormSet declares
    pub(crate) stores: Vec<StoreDeclaration>,
    /// The READ (get) and WRITE (set) expressions that a forms browser evaluates beside its
    /// Callback()s, which uefisettings does not apply
    pub(crate) read_expression: bool,
    pub(crate) write_expression: bool,
    /// How get shows a value
    display: ValueDisplay,
}

/// How get shows a value of a question, as it shows a stored one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueDisplay {
    OneOf(NumericFormat),
    Numeric(NumericFormat),
    CheckBox,
}

impl fmt::Display for IfrValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NumSize8 => "EFI_IFR_TYPE_NUM_SIZE_8",
            Self::NumSize16 => "EFI_IFR_TYPE_NUM_SIZE_16",
            Self::NumSize32 => "EFI_IFR_TYPE_NUM_SIZE_32",
            Self::NumSize64 => "EFI_IFR_TYPE_NUM_SIZE_64",
            Self::Boolean => "EFI_IFR_TYPE_BOOLEAN",
        })
    }
}

/// The refusal of a question whose READ or WRITE expression a forms browser evaluates beside its
/// driver's Callback()s: uefisettings evaluates them only for questions without
/// EFI_IFR_FLAG_CALLBACK.
#[cfg_attr(
    not(all(variable_data, any(target_os = "uefi", test))),
    allow(
        dead_code,
        reason = "only the UEFI Shell build calls a driver's Callback()"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "question has no VarStore, and uefisettings does not apply its {0} expression beside its \
     driver's Callback()s"
)]
pub(crate) struct ExpressionBesideCallback(pub(crate) QuestionExpression);

/// The refusal of a question whose FormSet has a form that read_db disables, as UEFI 2.11
/// §33.2.5.10.1 disables the form of a malformed op, holding a PASSWORD or VarStore op: read_db
/// drops that form from the FormSet's tree, so store_declarations sees neither, and uefisettings
/// cannot tell which stores a restore through RouteConfig() would change.
#[cfg_attr(
    not(any(target_os = "uefi", all(test, efivar_dumps))),
    allow(
        dead_code,
        reason = "only the UEFI Shell build calls a driver's Callback()"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "{reason}; that form holds an {op}, so uefisettings cannot tell which stores a restore \
     through RouteConfig() would change"
)]
pub(crate) struct DisabledFormStore {
    /// The form's DisabledForm reason: its FormId, its FormSet and why read_db disables it
    reason: String,
    op: &'static str,
}

/// The DriverHeldQuestion of the question op `op`, which is `value_question` of `varstore`, if
/// it has no VarStore and get or set reaches its value through its driver's Callback().
pub(super) fn driver_held(
    op: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>, anyhow::Error>,
    value_question: ValueQuestion<'_>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Option<DriverHeldQuestion> {
    let NoVarStore(storageless) = varstore.as_ref().err()?.downcast_ref::<NoVarStore>()?;
    // StoragelessQuestion::refusal refuses it: no CallBack() could name it alone
    if storageless.shares_question_id() {
        return None;
    }
    let (read_expression, write_expression) = (
        callback_expression(*storageless, QuestionExpression::Read)?,
        callback_expression(*storageless, QuestionExpression::Write)?,
    );
    let header = value_question.header();
    let form_set = enclosing_form_set(op)?;
    let ParsedOperation::FormSet(parsed_form_set) = &form_set.borrow().parsed_data else {
        return None;
    };
    let form_set_guid = parsed_form_set.guid;
    let (value_type, display) = match value_question {
        ValueQuestion::OneOf(parsed) => (
            IfrValueType::of_size(parsed.data.size())?,
            ValueDisplay::OneOf(NumericFormat::from_ifr(&parsed.data, parsed.flags)),
        ),
        ValueQuestion::Numeric(parsed) => (
            IfrValueType::of_size(parsed.data.size())?,
            ValueDisplay::Numeric(NumericFormat::from_ifr(&parsed.data, parsed.flags)),
        ),
        ValueQuestion::CheckBox(_) => (IfrValueType::Boolean, ValueDisplay::CheckBox),
        // StoragelessQuestion::refusal refuses it by its op
        ValueQuestion::DateTime(_) => return None,
    };
    let initial = match standard_default(op, &mut walk.inputs) {
        Some(Ok(value)) => value & value_type.mask(),
        Some(Err(_)) | None => 0,
    };
    let stores = store_declarations(&form_set.borrow(), walk.texts);
    Some(DriverHeldQuestion {
        form_set: form_set_guid,
        question_id: header.question_id,
        value_type,
        initial,
        stores,
        read_expression,
        write_expression,
        display,
    })
}

/// Whether a browser evaluates the `expression` of `storageless` beside its driver's Callback()s;
/// None unless get or set reaches its value through them.
fn callback_expression(
    storageless: StoragelessQuestion,
    expression: QuestionExpression,
) -> Option<bool> {
    match storageless.route(expression) {
        Ok(StoragelessRoute::DriverCallback) => Some(false),
        Ok(StoragelessRoute::Expression { callback: true }) => Some(true),
        Ok(StoragelessRoute::Expression { callback: false } | StoragelessRoute::Value) | Err(_) => {
            None
        }
    }
}

impl DriverHeldQuestion {
    /// Refuses the question if one of `disabled`, the forms that read_db drops from its package
    /// list, is a form of its FormSet, of another of its GUID there, or of no FormSet whose GUID
    /// is known, that holds a PASSWORD or VarStore op (DisabledFormStore).
    #[cfg_attr(
        not(any(target_os = "uefi", all(test, efivar_dumps))),
        allow(
            dead_code,
            reason = "only the UEFI Shell build calls a driver's Callback()"
        )
    )]
    pub(crate) fn check_disabled_forms(
        &self,
        disabled: &[DisabledForm],
    ) -> Result<(), DisabledFormStore> {
        let held_store = disabled
            .iter()
            .filter(|disabled| {
                form_set_guid(&disabled.form.borrow()).is_none_or(|guid| guid == self.form_set)
            })
            .find_map(|disabled| Some((disabled, disabled.store_op?)));
        match held_store {
            Some((disabled, op)) => Err(DisabledFormStore {
                reason: disabled.reason.clone(),
                op,
            }),
            None => Ok(()),
        }
    }
}

impl QuestionDescriptor {
    /// What get needs of a question whose value only its driver holds, if it is one.
    pub(crate) fn driver_held(&self) -> Option<&DriverHeldQuestion> {
        self.driver_held.as_ref()
    }

    /// `value`, of a question whose driver holds it, as get shows a stored value: the option's
    /// text, the number, or 0 or 1; None for another question.
    #[cfg(any(target_os = "uefi", all(test, efivar_dumps)))]
    pub(crate) fn driver_held_text(&self, value: u64) -> Option<String> {
        let held = self.driver_held.as_ref()?;
        Some(match held.display {
            ValueDisplay::OneOf(format) => {
                let options: Vec<_> = self
                    .possible_options
                    .iter()
                    .filter(|option| option.as_u64() == Some(value))
                    .collect();
                // the first that may be shown, as handle_oneof picks it
                let option = options
                    .iter()
                    .find(|option| option.state.may_be_allowed(IncludedStates::empty()))
                    .or(options.first());
                one_of_text(value, format, option.map(|option| option.value.trim()))
            }
            ValueDisplay::Numeric(format) => format.decode(value).to_string(),
            ValueDisplay::CheckBox => checkbox_text(value),
        })
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use std::num::NonZeroUsize;
    use std::rc::Rc;

    use super::super::ifr_fixtures::*;
    use super::super::storage::DeclaredKind;
    use super::super::walk_scopes;
    use super::super::Walk;
    use super::*;

    /// EFI_IFR_FLAG_CALLBACK (UEFI 2.11 §33.3.8.2.2)
    const EFI_IFR_FLAG_CALLBACK: u8 = 0x04;

    /// A question header of QuestionId `id` on VarStore `var_store_id` at VarOffset `info`, with
    /// `flags`.
    fn header(id: u16, var_store_id: u16, info: u16, flags: u8) -> Vec<u8> {
        [
            &3u16.to_le_bytes()[..],
            &4u16.to_le_bytes(),
            &id.to_le_bytes(),
            &var_store_id.to_le_bytes(),
            &info.to_le_bytes(),
            &[flags],
        ]
        .concat()
    }

    /// A UINT8 ONE_OF without a VarStore, with `flags` and options 0 and 1, the second the
    /// standard default.
    fn storage_less_one_of(id: u16, flags: u8) -> Vec<u8> {
        storage_less_one_of_with(id, flags, &[])
    }

    /// storage_less_one_of, with `children` after its options.
    fn storage_less_one_of_with(id: u16, flags: u8, children: &[Vec<u8>]) -> Vec<u8> {
        [
            operation(
                ONE_OF,
                true,
                &[header(id, 0, 0xFFFF, flags), vec![0x00, 0, 1, 1]].concat(),
            ),
            one_of_option(5, 0x00, &[0]),
            // EFI_IFR_OPTION_DEFAULT
            operation(
                ONE_OF_OPTION,
                false,
                &[&6u16.to_le_bytes()[..], &[0x10, 0x00, 1]].concat(),
            ),
            children.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// A READ or WRITE expression of TRUE.
    fn expression(op_code: u8) -> Vec<u8> {
        [operation(op_code, false, &[]), ifr_true()].concat()
    }

    fn descriptor_of(body: &[Vec<u8>], question_id: u16) -> QuestionDescriptor {
        let root = parse_form_set(body);
        let mut found = None;
        walk_scopes(std::slice::from_ref(&root), (), |node, ()| {
            let matches = super::super::question_values::value_question(&node.borrow())
                .is_some_and(|question| question.header().question_id == question_id);
            if matches && found.is_none() {
                found = Some(Rc::clone(node));
            }
            Walk::Enter(())
        });
        let node = found.expect("the question");
        let var_store_id = super::super::question_values::value_question(&node.borrow())
            .expect("a value question")
            .header()
            .var_store_id;
        let fixture = VarStoreFixture {
            store: super::super::find_corresponding_varstore(Rc::clone(&node), var_store_id),
            efivars: Efivars::new(),
        };
        question_descriptor(&node, fixture)
    }

    #[test]
    fn a_storage_less_callback_question_is_driver_held_with_its_form_set_stores() {
        let body = [
            var_store(2, [0x22; 16], "Buffer", 8),
            var_store_efi(1, "Store", NV_BS_RT, 4),
            form(
                1,
                &[
                    storage_less_one_of(0x0201, EFI_IFR_FLAG_CALLBACK),
                    checkbox_at(0x0301, 7, 2, 3),
                    uint8_numeric_on(0x0302, 7, 2),
                    checkbox_at(0x0303, 7, 1, 0),
                ],
            ),
        ];

        let descriptor = descriptor_of(&body, 0x0201);
        let held = descriptor.driver_held().expect("driver held");

        assert_eq!(
            (held.question_id, held.value_type, held.initial),
            (0x0201, IfrValueType::NumSize8, 1),
            "QuestionId, type, standard default"
        );
        assert_eq!(
            held.stores,
            [
                StoreDeclaration {
                    id: 2,
                    guid: [0x22; 16].into(),
                    kind: DeclaredKind::Buffer {
                        name: "Buffer".into(),
                        blocks: vec![
                            (3, NonZeroUsize::new(1).expect("1")),
                            (0, NonZeroUsize::new(1).expect("1"))
                        ],
                    },
                    holds_password: false,
                },
                StoreDeclaration {
                    id: 1,
                    guid: [0; 16].into(),
                    kind: DeclaredKind::EfiVariable {
                        name: "Store".into()
                    },
                    holds_password: false,
                },
            ],
            "the FormSet's stores, the Buffer one with its questions' blocks"
        );
    }

    #[test]
    fn a_question_with_a_varstore_or_without_callback_is_not_driver_held() {
        let body = [
            var_store_efi(1, "Store", NV_BS_RT, 4),
            form(
                1,
                &[
                    storage_less_one_of(0x0201, 0),
                    storage_less_one_of_with(0x0202, 0, &[expression(READ), expression(WRITE)]),
                    checkbox_at(0x0301, 7, 1, 0),
                    operation(
                        CHECKBOX,
                        false,
                        &[header(0x0302, 1, 1, EFI_IFR_FLAG_CALLBACK), vec![0x00]].concat(),
                    ),
                ],
            ),
        ];
        for id in [0x0201, 0x0202, 0x0301, 0x0302] {
            assert_eq!(
                descriptor_of(&body, id).driver_held(),
                None,
                "question {id:#06x}"
            );
        }
    }

    /// No CallBack() names a PASSWORD question: a PASSWORD is no ValueQuestion, of which only a
    /// ONE_OF, NUMERIC or CHECKBOX is driver held, and a storage-less CALLBACK question whose
    /// QuestionId a PASSWORD of its FormSet also has is not driver held either, as its driver
    /// could take a CallBack() for it for one of the PASSWORD; with a QuestionId of its own it
    /// is.
    #[test]
    fn no_callback_names_a_password_question() {
        for (password_id, held) in [(0x0201, false), (0x0202, true)] {
            let password = password_on(password_id, 0, 0, 0);
            let body = [form(
                1,
                &[
                    storage_less_one_of(0x0201, EFI_IFR_FLAG_CALLBACK),
                    password.clone(),
                ],
            )];
            let root = parse_form_set(&body);
            let password_op = find_op(&root, &password[2..]).expect("the PASSWORD");
            assert!(
                super::super::question_values::value_question(&password_op.borrow()).is_none(),
                "the PASSWORD is no ValueQuestion"
            );
            assert_eq!(
                descriptor_of(&body, 0x0201).driver_held().is_some(),
                held,
                "with a PASSWORD of QuestionId {password_id:#06x}"
            );
        }
    }

    #[test]
    fn a_storage_less_callback_numeric_or_checkbox_is_driver_held() {
        let numeric = operation(
            NUMERIC,
            false,
            &[
                header(0x0401, 0, 0xFFFF, EFI_IFR_FLAG_CALLBACK),
                // EFI_IFR_NUMERIC_SIZE_2 with EFI_IFR_DISPLAY_INT_DEC; MinValue, MaxValue, Step
                vec![0x01],
                [0u16, 300, 1]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
            ]
            .concat(),
        );
        let checkbox = operation(
            CHECKBOX,
            false,
            &[header(0x0402, 0, 0xFFFF, EFI_IFR_FLAG_CALLBACK), vec![0x00]].concat(),
        );
        let body = [form(1, &[numeric, checkbox])];
        let cases = [
            (0x0401, IfrValueType::NumSize16, 0xFFFF, "-1"),
            (0x0402, IfrValueType::Boolean, 1, "1"),
        ];
        for (id, value_type, value, shown) in cases {
            let descriptor = descriptor_of(&body, id);
            let held = descriptor.driver_held().expect("driver held");
            assert_eq!(held.value_type, value_type, "question {id:#06x}'s type");
            assert_eq!(
                descriptor.driver_held_text(value).as_deref(),
                Some(shown),
                "question {id:#06x} shows {value:#x} as get shows a stored value"
            );
        }
    }

    #[test]
    fn a_callback_question_records_its_read_and_write_expressions() {
        let cases = [
            (0x0201, Vec::new(), (false, false)),
            (0x0202, vec![expression(READ)], (true, false)),
            (0x0203, vec![expression(WRITE)], (false, true)),
            (
                0x0204,
                vec![expression(READ), expression(WRITE)],
                (true, true),
            ),
        ];
        let questions: Vec<Vec<u8>> = cases
            .iter()
            .map(|(id, children, _)| storage_less_one_of_with(*id, EFI_IFR_FLAG_CALLBACK, children))
            .collect();
        let body = [form(1, &questions)];
        for (id, _, want) in cases {
            let descriptor = descriptor_of(&body, id);
            let held = descriptor.driver_held().expect("driver held");
            assert_eq!(
                (held.read_expression, held.write_expression),
                want,
                "question {id:#06x}"
            );
        }
    }

    /// A question whose FormSet has a form that UEFI 2.11 §33.2.5.10.1 disables holding a
    /// PASSWORD or VarStore op, or whose disabled form's FormSet is unknown, is refused, as
    /// store_declarations sees neither, with the form's DisabledForm reason, which names the form,
    /// its FormSet and why it is disabled; one whose disabled form holds neither, or is of another
    /// FormSet, is not.
    #[test]
    fn a_disabled_form_with_a_password_or_var_store_refuses_the_driver() {
        let short_checkbox = operation(CHECKBOX, false, &[0x00]);
        let cases = [
            (
                "PASSWORD",
                vec![password_on(0x0501, 3, 2, 4), short_checkbox.clone()],
                Some("EFI_IFR_PASSWORD"),
            ),
            (
                "VARSTORE",
                vec![var_store(4, [0x44; 16], "Inner", 8), short_checkbox.clone()],
                Some("EFI_IFR_VARSTORE"),
            ),
            (
                "neither",
                vec![checkbox_at(0x0502, 7, 2, 0), short_checkbox.clone()],
                None,
            ),
        ];
        for (case, disabled_body, want) in cases {
            let body = [
                var_store(2, [0x22; 16], "Buffer", 8),
                form(1, &[storage_less_one_of(0x0201, EFI_IFR_FLAG_CALLBACK)]),
                form(2, &disabled_body),
            ];
            let descriptor = descriptor_of(&body, 0x0201);
            let held = descriptor.driver_held().expect("driver held");
            let (root, disabled) = parse_form_set_dropping(&body);
            assert_eq!(disabled.len(), 1, "{case}: the disabled forms");
            let refusal = want.map(|op| DisabledFormStore {
                reason: disabled[0].reason.clone(),
                op,
            });
            if let Some(refusal) = &refusal {
                let text = refusal.to_string();
                assert!(
                    text.starts_with(
                        "the form 2 of the FormSet 11111111-1111-1111-1111-111111111111, whose \
                         EFI_IFR_CHECKBOX op is malformed; UEFI 2.11 §33.2.5.10.1 disables the \
                         form of a malformed op: "
                    ) && text.ends_with(&format!(
                        "; that form holds an {}, so uefisettings cannot tell which stores a \
                         restore through RouteConfig() would change",
                        refusal.op
                    )),
                    "{case}: the refusal names the form, its FormSet and why: {text}"
                );
            }

            assert_eq!(
                held.check_disabled_forms(&disabled),
                refusal.clone().map_or(Ok(()), Err),
                "{case}"
            );
            let other = DriverHeldQuestion {
                form_set: [0x33; 16].into(),
                ..held.clone()
            };
            assert_eq!(
                other.check_disabled_forms(&disabled),
                Ok(()),
                "{case}: of another FormSet"
            );
            drop(root);
            assert_eq!(
                other.check_disabled_forms(&disabled),
                refusal.map_or(Ok(()), Err),
                "{case}: of no FormSet whose GUID is known"
            );
        }
    }

    #[test]
    fn values_show_as_get_shows_them() {
        let body = [form(
            1,
            &[storage_less_one_of(0x0201, EFI_IFR_FLAG_CALLBACK)],
        )];
        let descriptor = descriptor_of(&body, 0x0201);
        let option = descriptor.possible_options[1].value.clone();

        assert_eq!(
            descriptor.driver_held_text(1),
            Some(option.trim().to_string()),
            "an option's value shows its text"
        );
        assert_eq!(
            descriptor.driver_held_text(7).as_deref(),
            Some("7 (no matching option)"),
            "another value shows its number"
        );
    }
}
