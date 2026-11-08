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

//! How get and set reach the value of a question without a VarStore, which UEFI 2.11 §33.2.5.6
//! gives a READ or WRITE expression or EFI_IFR_FLAG_CALLBACK, and §33.3.8.3.88 an EFI_IFR_VALUE,
//! and why they refuse one. The classifier reads only the IFR, so it runs on every backend.

use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use thiserror::Error;

use super::conditions::question_expression;
use super::conditions::question_value_expression;
use super::conditions::QuestionExpression;
use super::conditions::VALUE_MAKES_READ_ONLY;
use super::question_values::value_question;
use super::IFROperation;
use super::QuestionFlags;
use crate::hii::variables::VariableReach;

/// What a question without a VarStore declares for its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoragelessQuestion {
    /// A READ expression that edk2-stable202608 SetupBrowserDxe evaluates
    read: bool,
    /// A WRITE expression that edk2-stable202608 SetupBrowserDxe evaluates
    write: bool,
    /// EFI_IFR_FLAG_CALLBACK
    callback: bool,
    /// An EFI_IFR_VALUE, which gives the value and makes the question read-only
    value: bool,
}

impl StoragelessQuestion {
    /// Classifies `question`; None unless it is a ONE_OF, NUMERIC or CHECKBOX without a VarStore.
    pub(crate) fn of(question: &Rc<RefCell<IFROperation>>) -> Option<Self> {
        let header = value_question(&question.borrow())?.header();
        (header.var_store_id == 0).then(|| Self {
            read: question_expression(question, QuestionExpression::Read).is_some(),
            write: question_expression(question, QuestionExpression::Write).is_some(),
            callback: header.flags().contains(QuestionFlags::CALLBACK),
            value: question_value_expression(&question.borrow()).is_some(),
        })
    }

    /// How get (`Read`) or set (`Write`) reaches the value.
    pub(crate) fn route(
        self,
        expression: QuestionExpression,
    ) -> Result<StoragelessRoute, StoragelessRefusal> {
        if self.value {
            return match expression {
                QuestionExpression::Read => Ok(StoragelessRoute::Value),
                QuestionExpression::Write => Err(StoragelessRefusal::ReadOnly),
            };
        }
        let (this, other) = match expression {
            QuestionExpression::Read => (self.read, self.write),
            QuestionExpression::Write => (self.write, self.read),
        };
        match (this, self.callback, other) {
            (true, callback, _) => Ok(StoragelessRoute::Expression { callback }),
            (false, true, _) => Ok(StoragelessRoute::DriverCallback),
            (false, false, false) => Err(StoragelessRefusal::NoValueSource),
            (false, false, true) => Err(match expression {
                QuestionExpression::Read => StoragelessRefusal::NoRead,
                QuestionExpression::Write => StoragelessRefusal::NoWrite,
            }),
        }
    }

    /// Why get (`Read`) or set (`Write`) on a backend of `reach` gives or takes no value
    /// without the expression; None if the expression alone does: a route through CallBack()
    /// waits for a caller that calls it.
    pub(crate) fn refusal(
        self,
        expression: QuestionExpression,
        reach: VariableReach,
    ) -> Option<StoragelessRefusal> {
        match self.route(expression) {
            Ok(StoragelessRoute::Expression { callback: false } | StoragelessRoute::Value) => None,
            Ok(StoragelessRoute::Expression { callback: true }) => {
                Some(StoragelessRefusal::CallbackDecides(expression, reach))
            }
            Ok(StoragelessRoute::DriverCallback) => Some(StoragelessRefusal::DriverHeld(reach)),
            Err(refusal) => Some(refusal),
        }
    }
}

/// find_corresponding_varstore's error for a question without a VarStore, which get and set
/// turn into a StoragelessRefusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("question has no VarStore")]
pub(crate) struct NoVarStore(pub(crate) StoragelessQuestion);

/// How get or set reaches the value of a question without a VarStore. A browser never sends
/// such a question EFI_BROWSER_ACTION_SUBMITTED: edk2-stable202608 SetupBrowserDxe/Setup.c
/// SubmitCallbackForForm skips every question without storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoragelessRoute {
    /// Its READ (get) or WRITE (set) expression. With `callback` its driver's CallBack() has the
    /// last word: a browser evaluates READ, then CallBack(EFI_BROWSER_ACTION_RETRIEVE) overrides
    /// it; set calls CHANGING, evaluates WRITE, then calls CHANGED (edk2-stable202608
    /// SetupBrowserDxe/Setup.c GetQuestionValue, Presentation.c ProcessCallBackFunction)
    Expression { callback: bool },
    /// Only its driver's CallBack() reaches the value; after ExitBootServices() no EFI
    /// device-handle-based protocol may be used (UEFI 2.11 §7.4.6)
    DriverCallback,
    /// Its EFI_IFR_VALUE expression, which gives the value of get before any READ
    /// (edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue); set refuses the question as
    /// read-only (UEFI 2.11 §33.3.8.3.88)
    Value,
}

/// Why get or set refuses a question without a VarStore.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum StoragelessRefusal {
    #[error(
        "question has no VarStore, READ or WRITE expression, or EFI_IFR_FLAG_CALLBACK, one of \
         which UEFI 2.11 §33.2.5.6 requires"
    )]
    NoValueSource,
    /// get of a question with only a WRITE expression
    #[error(
        "question has no VarStore, READ expression or EFI_IFR_FLAG_CALLBACK, so it has no value \
         to retrieve (UEFI 2.11 §33.2.5.4.1)"
    )]
    NoRead,
    /// set of a question with only a READ expression
    #[error(
        "question has no VarStore, WRITE expression or EFI_IFR_FLAG_CALLBACK, so nothing keeps \
         a changed value (UEFI 2.11 §33.2.5.4.1)"
    )]
    NoWrite,
    /// get of a question whose READ expression gives UNDEFINED or fails
    #[error(
        "its READ expression gives no value, and without a VarStore the question has no other \
         (UEFI 2.11 §33.2.5.4.1)"
    )]
    ReadUndefined,
    /// set of a question whose WRITE expression gives UNDEFINED, or fails, before any SET
    #[error(
        "its WRITE expression sets no VarStore, and without a VarStore nothing keeps the value \
         (UEFI 2.11 §33.2.5.4.1)"
    )]
    WriteSetsNothing,
    /// A question with EFI_IFR_FLAG_CALLBACK whose CallBack() this run does not call: after
    /// ExitBootServices() (`Runtime`) none may, and list-questions, show-ifr and dumps never do
    #[error("{}", DriverHeld(*.0))]
    DriverHeld(VariableReach),
    /// get (`Read`) or set (`Write`) of a question with EFI_IFR_FLAG_CALLBACK and that
    /// expression, whose CallBack() this run does not call, though it may override the
    /// expression: RETRIEVE may replace the value of READ, and CHANGING may change or refuse the
    /// value before WRITE (UEFI 2.11 §35.5.4)
    #[error("{}", CallbackDecides(*.0, *.1))]
    CallbackDecides(QuestionExpression, VariableReach),
    /// set of a question with an EFI_IFR_VALUE
    #[error("{}", VALUE_MAKES_READ_ONLY)]
    ReadOnly,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
        )
    )]
    #[error(
        "question has no VarStore, and no driver handle of its package list has \
         EFI_HII_CONFIG_ACCESS_PROTOCOL, whose CallBack() alone reaches its value (UEFI 2.11 \
         §33.2.5.6)"
    )]
    NoConfigAccess,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
        )
    )]
    /// get of a question on StoragelessRoute::DriverCallback whose
    /// CallBack(EFI_BROWSER_ACTION_RETRIEVE) failed; on Expression { callback: true } the READ
    /// value stands (UEFI 2.11 §35.5.4)
    #[error(
        "its driver's CallBack(EFI_BROWSER_ACTION_RETRIEVE) returned {status}; without a VarStore \
         the question has no other value (UEFI 2.11 §33.2.5.4.1)"
    )]
    RetrieveFailed { status: String },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
        )
    )]
    /// `status`: the EFI_STATUS that CallBack(EFI_BROWSER_ACTION_CHANGING) returned
    #[error("its driver's CallBack(EFI_BROWSER_ACTION_CHANGING) refused the value: {status}")]
    ChangingRefused { status: String },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
        )
    )]
    /// `status`: the EFI_STATUS of the read of VarStore `var_store_id` before the first CallBack()
    #[error("cannot snapshot store {var_store_id:#06x}: {status}")]
    SnapshotFailed { var_store_id: u16, status: String },
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
        )
    )]
    /// The VarStores of the FormSet that differ after the CallBack() sequence, and their restore
    #[error(
        "the Callback sequence changed stores of the FormSet: {}; {restore}",
        .stores.join(", ")
    )]
    StoresChanged {
        stores: Vec<String>,
        restore: StoreRestore,
    },
}

/// How restoring the VarStores that a CallBack() sequence changed ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "for the CallBack() sequence of the UEFI Shell build, which does not exist yet"
    )
)]
pub(crate) enum StoreRestore {
    /// Every store reads back as before the sequence
    Verified,
    /// Why a restore failed
    Failed(String),
}

impl fmt::Display for StoreRestore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => f.write_str("restored and verified"),
            Self::Failed(reason) => write!(f, "restore failed: {reason}"),
        }
    }
}

/// StoragelessRefusal::DriverHeld's text: where the question's value is, and why this run does not
/// reach it.
struct DriverHeld(VariableReach);

impl fmt::Display for DriverHeld {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "question has no VarStore; its driver keeps the value, which only \
             EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() reaches (UEFI 2.11 §33.2.5.6)",
        )?;
        f.write_str(no_callback(self.0))
    }
}

/// StoragelessRefusal::CallbackDecides's text: what the driver's CallBack() may do to the value
/// of the expression, and why this run does not call it.
struct CallbackDecides(QuestionExpression, VariableReach);

impl fmt::Display for CallbackDecides {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            QuestionExpression::Read => {
                "question has no VarStore, and its driver's \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack(EFI_BROWSER_ACTION_RETRIEVE) may replace \
                 the value of its READ expression (UEFI 2.11 §35.5.4)"
            }
            QuestionExpression::Write => {
                "question has no VarStore, and its driver's \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack(EFI_BROWSER_ACTION_CHANGING) may change \
                 or refuse the value before its WRITE expression (UEFI 2.11 §35.5.4)"
            }
        })?;
        f.write_str(no_callback(self.1))
    }
}

/// Why a run of `reach` calls no CallBack(): after ExitBootServices() no EFI device-handle-based
/// protocol may be used; uefisettings.efi does not call it yet.
fn no_callback(reach: VariableReach) -> &'static str {
    match reach {
        VariableReach::Runtime => {
            ", and after ExitBootServices() no EFI device-handle-based protocol may be used (UEFI \
             2.11 §7.4.6); use uefisettings.efi in the UEFI Shell"
        }
        VariableReach::BootServices => ", which uefisettings.efi does not call yet",
    }
}

#[cfg(test)]
mod tests {
    use super::super::ifr_fixtures::*;
    use super::*;

    /// A UINT8 ONE_OF of QuestionId 1 without a VarStore, flagged `flags`.
    fn storageless_one_of(flags: u8) -> Vec<u8> {
        [question_header_with(1, 3, 0, 0, flags), vec![0x00, 0, 4, 1]].concat()
    }

    /// The classification of a ONE_OF of `data` holding `children`, in `form` of a FormSet.
    fn classify(
        form: impl Fn(&[Vec<u8>]) -> Vec<u8>,
        data: &[u8],
        children: &[Vec<u8>],
    ) -> Option<StoragelessQuestion> {
        let question = [
            operation(ONE_OF, true, data),
            children.concat(),
            END.to_vec(),
        ]
        .concat();
        let root = parse_form_set(&[form(&[question])]);
        let question = find_op(&root, data).expect("the ONE_OF");
        StoragelessQuestion::of(&question)
    }

    /// A READ or WRITE op and its expression, TRUE.
    fn expression_of(op_code: u8) -> Vec<u8> {
        [operation(op_code, false, &[]), ifr_true()].concat()
    }

    /// Each combination of READ, WRITE and EFI_IFR_FLAG_CALLBACK routes get and set through the
    /// expression it uses, else CallBack(), and else refuses with what the question lacks.
    #[test]
    fn get_and_set_follow_read_write_and_callback() {
        use StoragelessRefusal as R;
        use StoragelessRoute::DriverCallback;
        use StoragelessRoute::Expression;
        let expression = |callback| Ok(Expression { callback });
        let cases = [
            (
                "nothing",
                false,
                false,
                false,
                Err(R::NoValueSource),
                Err(R::NoValueSource),
            ),
            (
                "READ",
                true,
                false,
                false,
                expression(false),
                Err(R::NoWrite),
            ),
            (
                "WRITE",
                false,
                true,
                false,
                Err(R::NoRead),
                expression(false),
            ),
            (
                "READ, WRITE",
                true,
                true,
                false,
                expression(false),
                expression(false),
            ),
            (
                "CALLBACK",
                false,
                false,
                true,
                Ok(DriverCallback),
                Ok(DriverCallback),
            ),
            (
                "READ, CALLBACK",
                true,
                false,
                true,
                expression(true),
                Ok(DriverCallback),
            ),
            (
                "WRITE, CALLBACK",
                false,
                true,
                true,
                Ok(DriverCallback),
                expression(true),
            ),
            (
                "READ, WRITE, CALLBACK",
                true,
                true,
                true,
                expression(true),
                expression(true),
            ),
        ];
        for (name, read, write, callback, get, set) in cases {
            let children: Vec<Vec<u8>> = [(read, READ), (write, WRITE)]
                .into_iter()
                .filter(|(present, _)| *present)
                .map(|(_, op_code)| expression_of(op_code))
                .collect();
            let flags = if callback {
                QuestionFlags::CALLBACK.bits()
            } else {
                0
            };
            let question = classify(|body| form(1, body), &storageless_one_of(flags), &children)
                .unwrap_or_else(|| panic!("{name}: classified as having a VarStore"));
            assert_eq!(question.route(QuestionExpression::Read), get, "{name}: get");
            assert_eq!(
                question.route(QuestionExpression::Write),
                set,
                "{name}: set"
            );
        }
    }

    /// READ and WRITE on a FORM_MAP without the standard method route nothing, as edk2 evaluates
    /// neither there, while on one with it they route get and set.
    #[test]
    fn read_and_write_route_only_where_a_browser_evaluates_them() {
        let children = [expression_of(READ), expression_of(WRITE)];
        let cases = [
            (
                "FORM_MAP without the standard method",
                [(2, OTHER_GUID)],
                false,
            ),
            ("standard FORM_MAP", [(2, STANDARD_FORM_GUID)], true),
        ];
        for (name, methods, evaluated) in cases {
            let question = classify(
                |body| form_map(&methods, body),
                &storageless_one_of(0),
                &children,
            )
            .unwrap_or_else(|| panic!("{name}: classified as having a VarStore"));
            let want = match evaluated {
                true => (
                    Ok(StoragelessRoute::Expression { callback: false }),
                    Ok(StoragelessRoute::Expression { callback: false }),
                ),
                false => (
                    Err(StoragelessRefusal::NoValueSource),
                    Err(StoragelessRefusal::NoValueSource),
                ),
            };
            assert_eq!(
                (
                    question.route(QuestionExpression::Read),
                    question.route(QuestionExpression::Write)
                ),
                want,
                "{name}"
            );
        }
    }

    /// An EFI_IFR_VALUE gives get the value, before any READ, also on a FORM_MAP without the
    /// standard method, as edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue evaluates it
    /// on every form, and makes set refuse the question as read-only, with READ, WRITE or
    /// EFI_IFR_FLAG_CALLBACK too (UEFI 2.11 §33.3.8.3.88).
    #[test]
    fn a_value_gives_get_its_value_and_makes_set_read_only() {
        let value = [operation(VALUE, true, &[]), ifr_true(), END.to_vec()].concat();
        let with_value = |children: &[Vec<u8>]| [&[value.clone()][..], children].concat();
        let cases = [
            ("VALUE", 0, with_value(&[])),
            (
                "VALUE, READ, WRITE, CALLBACK",
                QuestionFlags::CALLBACK.bits(),
                with_value(&[expression_of(READ), expression_of(WRITE)]),
            ),
        ];
        for (name, flags, children) in cases {
            for (place, question) in [
                (
                    "FORM",
                    classify(|body| form(1, body), &storageless_one_of(flags), &children),
                ),
                (
                    "FORM_MAP without the standard method",
                    classify(
                        |body| form_map(&[(2, OTHER_GUID)], body),
                        &storageless_one_of(flags),
                        &children,
                    ),
                ),
            ] {
                let question = question.unwrap_or_else(|| {
                    panic!("{name} on {place}: classified as having a VarStore")
                });
                assert_eq!(
                    (
                        question.route(QuestionExpression::Read),
                        question.route(QuestionExpression::Write)
                    ),
                    (
                        Ok(StoragelessRoute::Value),
                        Err(StoragelessRefusal::ReadOnly)
                    ),
                    "{name} on {place}: routes"
                );
                for reach in [VariableReach::Runtime, VariableReach::BootServices] {
                    assert_eq!(
                        (
                            question.refusal(QuestionExpression::Read, reach),
                            question.refusal(QuestionExpression::Write, reach)
                        ),
                        (None, Some(StoragelessRefusal::ReadOnly)),
                        "{name} on {place} through {reach:?}: refusals"
                    );
                }
            }
        }
    }

    /// A question with EFI_IFR_FLAG_CALLBACK and the expression of get or set is refused because
    /// its driver's CallBack() may override that expression; one without it, because its driver
    /// keeps the value.
    #[test]
    fn callback_refusals_say_whether_the_driver_may_override_the_expression() {
        use QuestionExpression::Read;
        use QuestionExpression::Write;
        let cases = [
            ("CALLBACK", false, false),
            ("READ, CALLBACK", true, false),
            ("WRITE, CALLBACK", false, true),
            ("READ, WRITE, CALLBACK", true, true),
        ];
        for (name, read, write) in cases {
            let children: Vec<Vec<u8>> = [(read, READ), (write, WRITE)]
                .into_iter()
                .filter(|(present, _)| *present)
                .map(|(_, op_code)| expression_of(op_code))
                .collect();
            let question = classify(
                |body| form(1, body),
                &storageless_one_of(QuestionFlags::CALLBACK.bits()),
                &children,
            )
            .unwrap_or_else(|| panic!("{name}: classified as having a VarStore"));
            for reach in [VariableReach::Runtime, VariableReach::BootServices] {
                let want = |expression, present| match present {
                    true => StoragelessRefusal::CallbackDecides(expression, reach),
                    false => StoragelessRefusal::DriverHeld(reach),
                };
                assert_eq!(
                    (
                        question.refusal(Read, reach),
                        question.refusal(Write, reach)
                    ),
                    (Some(want(Read, read)), Some(want(Write, write))),
                    "{name} through {reach:?}"
                );
            }
        }
    }

    /// A question that names a VarStore is not classified, flagged or not.
    #[test]
    fn questions_on_a_var_store_are_not_storageless() {
        for flags in [0, QuestionFlags::CALLBACK.bits()] {
            let data = [question_header_with(1, 3, 1, 0, flags), vec![0x00, 0, 4, 1]].concat();
            assert_eq!(
                classify(|body| form(1, body), &data, &[expression_of(READ)]),
                None,
                "flags {flags:#04x}"
            );
        }
    }

    /// Each refusal names what the question lacks or what its driver answered, in UEFI terms.
    #[test]
    fn refusals_say_why_in_uefi_terms() {
        let cases = [
            (
                StoragelessRefusal::NoValueSource,
                "question has no VarStore, READ or WRITE expression, or EFI_IFR_FLAG_CALLBACK, \
                 one of which UEFI 2.11 §33.2.5.6 requires",
            ),
            (
                StoragelessRefusal::NoRead,
                "question has no VarStore, READ expression or EFI_IFR_FLAG_CALLBACK, so it has \
                 no value to retrieve (UEFI 2.11 §33.2.5.4.1)",
            ),
            (
                StoragelessRefusal::NoWrite,
                "question has no VarStore, WRITE expression or EFI_IFR_FLAG_CALLBACK, so nothing \
                 keeps a changed value (UEFI 2.11 §33.2.5.4.1)",
            ),
            (
                StoragelessRefusal::ReadUndefined,
                "its READ expression gives no value, and without a VarStore the question has no \
                 other (UEFI 2.11 §33.2.5.4.1)",
            ),
            (
                StoragelessRefusal::WriteSetsNothing,
                "its WRITE expression sets no VarStore, and without a VarStore nothing keeps the \
                 value (UEFI 2.11 §33.2.5.4.1)",
            ),
            (
                StoragelessRefusal::DriverHeld(VariableReach::Runtime),
                "question has no VarStore; its driver keeps the value, which only \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() reaches (UEFI 2.11 §33.2.5.6), and \
                 after ExitBootServices() no EFI device-handle-based protocol may be used (UEFI \
                 2.11 §7.4.6); use uefisettings.efi in the UEFI Shell",
            ),
            (
                StoragelessRefusal::DriverHeld(VariableReach::BootServices),
                "question has no VarStore; its driver keeps the value, which only \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() reaches (UEFI 2.11 §33.2.5.6), which \
                 uefisettings.efi does not call yet",
            ),
            (
                StoragelessRefusal::CallbackDecides(
                    QuestionExpression::Read,
                    VariableReach::Runtime,
                ),
                "question has no VarStore, and its driver's \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack(EFI_BROWSER_ACTION_RETRIEVE) may replace \
                 the value of its READ expression (UEFI 2.11 §35.5.4), and after \
                 ExitBootServices() no EFI device-handle-based protocol may be used (UEFI 2.11 \
                 §7.4.6); use uefisettings.efi in the UEFI Shell",
            ),
            (
                StoragelessRefusal::CallbackDecides(
                    QuestionExpression::Write,
                    VariableReach::Runtime,
                ),
                "question has no VarStore, and its driver's \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack(EFI_BROWSER_ACTION_CHANGING) may change \
                 or refuse the value before its WRITE expression (UEFI 2.11 §35.5.4), and after \
                 ExitBootServices() no EFI device-handle-based protocol may be used (UEFI 2.11 \
                 §7.4.6); use uefisettings.efi in the UEFI Shell",
            ),
            (
                StoragelessRefusal::CallbackDecides(
                    QuestionExpression::Read,
                    VariableReach::BootServices,
                ),
                "question has no VarStore, and its driver's \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack(EFI_BROWSER_ACTION_RETRIEVE) may replace \
                 the value of its READ expression (UEFI 2.11 §35.5.4), which uefisettings.efi does \
                 not call yet",
            ),
            (
                StoragelessRefusal::ReadOnly,
                "its EFI_IFR_VALUE expression makes it read-only (UEFI 2.11 §33.3.8.3.88)",
            ),
            (
                StoragelessRefusal::NoConfigAccess,
                "question has no VarStore, and no driver handle of its package list has \
                 EFI_HII_CONFIG_ACCESS_PROTOCOL, whose CallBack() alone reaches its value (UEFI \
                 2.11 §33.2.5.6)",
            ),
            (
                StoragelessRefusal::RetrieveFailed {
                    status: "EFI_UNSUPPORTED".to_string(),
                },
                "its driver's CallBack(EFI_BROWSER_ACTION_RETRIEVE) returned EFI_UNSUPPORTED; \
                 without a VarStore the question has no other value (UEFI 2.11 §33.2.5.4.1)",
            ),
            (
                StoragelessRefusal::RetrieveFailed {
                    status: "EFI_DEVICE_ERROR".to_string(),
                },
                "its driver's CallBack(EFI_BROWSER_ACTION_RETRIEVE) returned EFI_DEVICE_ERROR; \
                 without a VarStore the question has no other value (UEFI 2.11 §33.2.5.4.1)",
            ),
            (
                StoragelessRefusal::ChangingRefused {
                    status: "EFI_ACCESS_DENIED".to_string(),
                },
                "its driver's CallBack(EFI_BROWSER_ACTION_CHANGING) refused the value: \
                 EFI_ACCESS_DENIED",
            ),
            (
                StoragelessRefusal::SnapshotFailed {
                    var_store_id: 0x1234,
                    status: "EFI_NOT_FOUND".to_string(),
                },
                "cannot snapshot store 0x1234: EFI_NOT_FOUND",
            ),
            (
                StoragelessRefusal::StoresChanged {
                    stores: vec!["0x0001".to_string(), "0x0002".to_string()],
                    restore: StoreRestore::Verified,
                },
                "the Callback sequence changed stores of the FormSet: 0x0001, 0x0002; restored \
                 and verified",
            ),
            (
                StoragelessRefusal::StoresChanged {
                    stores: vec!["0x0001".to_string()],
                    restore: StoreRestore::Failed("EFI_WRITE_PROTECTED".to_string()),
                },
                "the Callback sequence changed stores of the FormSet: 0x0001; restore failed: \
                 EFI_WRITE_PROTECTED",
            ),
        ];
        for (refusal, want) in cases {
            assert_eq!(refusal.to_string(), want, "{refusal:?}");
        }
    }
}

#[cfg(test)]
mod get_and_set_tests {
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use super::super::ifr_fixtures::*;
    use super::super::*;
    use crate::hii::variables::WithheldBytes;
    use crate::hii::variables::WithholdingVariables;

    /// Each storage-less CHECKBOX of storageless_form_set(): its prompt, then whether it has
    /// EFI_IFR_FLAG_CALLBACK, a READ and a WRITE.
    const QUESTIONS: [(&str, bool, bool, bool); 6] = [
        ("Nothing", false, false, false),
        ("Write only", false, false, true),
        ("Read only", false, true, false),
        ("Callback", true, false, false),
        ("Read and callback", true, true, false),
        ("Write and callback", true, false, true),
    ];
    /// The string ID of the first prompt of QUESTIONS; the others follow.
    const FIRST_PROMPT: u16 = 10;
    /// A CHECKBOX on VarStore 1, after QUESTIONS.
    const STORED: &str = "Stored";
    /// What answers add for the standard default that each CHECKBOX's Flags 0 give.
    const CHECKBOX_DEFAULT: &str = " <IFR default: 0>";

    fn string_packages() -> Vec<StringMap> {
        let prompts = QUESTIONS.iter().map(|(prompt, ..)| *prompt).chain([STORED]);
        vec![(FIRST_PROMPT..).zip(prompts.map(Rc::from)).collect()]
    }

    /// A FormSet holding a CHECKBOX without a VarStore for each of QUESTIONS, each READ and WRITE
    /// giving TRUE, then STORED.
    fn storageless_form_set() -> Rc<RefCell<IFROperation>> {
        let checkbox = |id: u16, var_store_id, flags, children: Vec<Vec<u8>>| {
            let data = [
                question_header_with(id, FIRST_PROMPT + id - 1, var_store_id, 0, flags),
                vec![0x00],
            ]
            .concat();
            [
                operation(CHECKBOX, true, &data),
                children.concat(),
                END.to_vec(),
            ]
            .concat()
        };
        let mut questions: Vec<Vec<u8>> = (1..)
            .zip(QUESTIONS)
            .map(|(id, (_, callback, read, write))| {
                let children = [(read, READ), (write, WRITE)]
                    .into_iter()
                    .filter(|(present, _)| *present)
                    .map(|(_, op_code)| [operation(op_code, false, &[]), ifr_true()].concat())
                    .collect();
                let flags = if callback {
                    QuestionFlags::CALLBACK.bits()
                } else {
                    0x00
                };
                checkbox(id, 0, flags, children)
            })
            .collect();
        let stored_id = u16::try_from(QUESTIONS.len() + 1).expect("question ids fit a u16");
        questions.push(checkbox(
            stored_id,
            1,
            QuestionFlags::CALLBACK.bits(),
            Vec::new(),
        ));
        parse_form_set(&[var_store_efi(1, "Store", NV_BS_RT, 1), form(1, &questions)])
    }

    /// A reader of no variables, reaching `reach`.
    fn reader_reaching(reach: VariableReach) -> EfivarReader {
        let interface = match reach {
            VariableReach::Runtime => VariableInterface::Efivarfs,
            VariableReach::BootServices => VariableInterface::VariableServices,
        };
        EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)))
    }

    /// Why get (`Read`) or set (`Write`) through a reader of `reach` gives or takes no value of
    /// the question of QUESTIONS that has `callback`, `read` and `write`; None if its expression
    /// alone does.
    fn refusal(
        (callback, read, write): (bool, bool, bool),
        expression: QuestionExpression,
        reach: VariableReach,
    ) -> Option<StoragelessRefusal> {
        let (this, other) = match expression {
            QuestionExpression::Read => (read, write),
            QuestionExpression::Write => (write, read),
        };
        match (callback, this, other) {
            (true, true, _) => Some(StoragelessRefusal::CallbackDecides(expression, reach)),
            (true, false, _) => Some(StoragelessRefusal::DriverHeld(reach)),
            (false, true, _) => None,
            (false, false, true) => Some(match expression {
                QuestionExpression::Read => StoragelessRefusal::NoRead,
                QuestionExpression::Write => StoragelessRefusal::NoWrite,
            }),
            (false, false, false) => Some(StoragelessRefusal::NoValueSource),
        }
    }

    /// list-questions and get show the value of the READ expression of a question without a
    /// VarStore or EFI_IFR_FLAG_CALLBACK, TRUE, and each other one as unavailable, for the reason
    /// that the classifier gives get on the reader's reach.
    #[test]
    fn get_shows_why_each_storageless_question_has_no_value() {
        let root = storageless_form_set();
        let strings = string_packages();
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            let mut reader = reader_reaching(reach);
            let listed: BTreeMap<String, String> = list_questions(
                Rc::clone(&root),
                &strings,
                IncludedStates::empty(),
                None,
                &mut reader,
            )
            .into_iter()
            .map(|(question, _)| (question.question, question.value))
            .collect();
            for (prompt, callback, read, write) in QUESTIONS {
                let want = match refusal((callback, read, write), QuestionExpression::Read, reach) {
                    Some(refusal) => format!("<ValueUnavailable: {refusal}>{CHECKBOX_DEFAULT}"),
                    None => "1".to_string(),
                };
                assert_eq!(
                    listed.get(prompt),
                    Some(&want),
                    "{prompt} through {reach:?}"
                );
            }
            assert_eq!(
                listed.get(STORED).map(String::as_str),
                Some(
                    format!(
                        "<ValueUnavailable: no EFI variable \
                         Store-00000000-0000-0000-0000-000000000000>{CHECKBOX_DEFAULT}"
                    )
                    .as_str()
                ),
                "{STORED} through {reach:?}"
            );
        }
    }

    /// set refuses each question without a VarStore, for the reason that the classifier gives
    /// set on the reader's reach, both when it picks the question and when it plans its writes;
    /// a WRITE expression that sets nothing leaves nothing to keep the value.
    #[test]
    fn set_refuses_each_storageless_question_with_why() {
        let root = storageless_form_set();
        let strings = string_packages();
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            for (prompt, callback, read, write) in QUESTIONS {
                let refusal = refusal((callback, read, write), QuestionExpression::Write, reach);
                let mut reader = reader_reaching(reach);
                let values = VarStoreValues::new(&root, None);
                let selection = find_question_in(
                    &root,
                    &BTreeSet::from([prompt]),
                    &mut FormSetWalk::new(&strings, &mut reader, &values, IncludedStates::empty()),
                );
                let Selection::Picked {
                    picked: (descriptor, _),
                    ..
                } = &selection
                else {
                    panic!("{prompt}: not picked");
                };
                let variables = MemoryVariables::new(reach, reader.interface());
                let planned = set_questions(
                    prompt,
                    &[("selector", descriptor)],
                    "1",
                    &BTreeSet::from(["1".to_string()]),
                    IncludedStates::empty(),
                    &mut reader,
                    None,
                    VolatileWrites::Refuse,
                    &WithholdingVariables::new(&variables, WithheldBytes::default()),
                )
                .map(|_| ())
                .map_err(|error| error.to_string());
                let want = refusal
                    .clone()
                    .unwrap_or(StoragelessRefusal::WriteSetsNothing);
                assert_eq!(
                    planned,
                    Err(format!("cannot set question {prompt:?}: {want}")),
                    "{prompt}: set through {reach:?}"
                );
                assert_eq!(
                    choice_for_set(selection, prompt, &SetOptions::default(), &reader)
                        .map(|_| ())
                        .map_err(|error| error.to_string()),
                    refusal.map_or(Ok(()), |refusal| {
                        Err(format!("cannot set question {prompt:?}: {refusal}"))
                    }),
                    "{prompt}: choice through {reach:?}"
                );
            }
        }
    }

    /// QuestionDescriptor::storageless_route gives the classifier's routes of a question
    /// without a VarStore, and nothing for one with a VarStore.
    #[test]
    fn descriptors_give_the_routes_of_storageless_questions() {
        let root = storageless_form_set();
        let mut reader = reader_reaching(VariableReach::BootServices);
        let listed: BTreeMap<String, QuestionDescriptor> = list_questions(
            Rc::clone(&root),
            &string_packages(),
            IncludedStates::empty(),
            None,
            &mut reader,
        )
        .into_iter()
        .map(|(question, _)| (question.question.clone(), question))
        .collect();
        for (prompt, callback, read, write) in QUESTIONS {
            let routes = [QuestionExpression::Read, QuestionExpression::Write].map(|expression| {
                listed
                    .get(prompt)
                    .and_then(|descriptor| descriptor.storageless_route(expression))
            });
            let want = [(read, write), (write, read)].map(|(this, other)| {
                Some(match (this, callback, other) {
                    (true, callback, _) => Ok(StoragelessRoute::Expression { callback }),
                    (false, true, _) => Ok(StoragelessRoute::DriverCallback),
                    (false, false, _) => Err(()),
                })
            });
            assert_eq!(
                routes.map(|route| route.map(|route| route.map_err(|_| ()))),
                want,
                "{prompt}"
            );
        }
        assert_eq!(
            listed
                .get(STORED)
                .map(|descriptor| descriptor.storageless_route(QuestionExpression::Read)),
            Some(None),
            "{STORED}"
        );
    }
}
