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

//! The value of a question without a VarStore, which only its driver keeps: get calls the
//! driver's EFI_HII_CONFIG_ACCESS_PROTOCOL.Callback() for that one question with the browser
//! actions a forms browser sends (UEFI 2.11 §35.5.4), as no forms browser runs: FORM_OPEN,
//! RETRIEVE and FORM_CLOSE.
//!
//! The sequence runs between two reads of the stores that the question's FormSet declares
//! (form_set_stores.rs): a store that cannot be read refuses before the first Callback(), and a
//! store that the Callback()s changed is restored and refuses the value, which the driver has
//! already acted on.

use std::fmt;

use crate::efi_status::EfiStatus;
use crate::efi_variables::VariableData;
use crate::hii::config_routing::ConfigRouting;
use crate::hii::form_set_stores::Baseline;
use crate::hii::form_set_stores::FormSetStore;
use crate::hii::forms::ExpressionBesideCallback;
pub(crate) use crate::hii::forms::IfrValueType;
use crate::hii::forms::QuestionExpression;
use crate::hii::forms::StoragelessRefusal;

/// EFI_BROWSER_ACTION (UEFI 2.11 §35.5.4): what a Callback() is told happened, of the actions
/// that get sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum BrowserAction {
    Retrieve = 2,
    FormOpen = 3,
    FormClose = 4,
}

/// Its name without EFI_BROWSER_ACTION_, as messages write Callback(CHANGING).
impl fmt::Display for BrowserAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Retrieve => "RETRIEVE",
            Self::FormOpen => "FORM_OPEN",
            Self::FormClose => "FORM_CLOSE",
        })
    }
}

/// EFI_BROWSER_ACTION_REQUEST (UEFI 2.11 §35.5.4): what a Callback() asks the forms browser to
/// do, a UINTN of which unknown values pass through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActionRequest(pub(crate) usize);

impl ActionRequest {
    pub(crate) const NONE: Self = Self(0);
    pub(crate) const RESET: Self = Self(1);
    pub(crate) const SUBMIT: Self = Self(2);
    pub(crate) const EXIT: Self = Self(3);
    pub(crate) const FORM_SUBMIT_EXIT: Self = Self(4);
    pub(crate) const FORM_DISCARD_EXIT: Self = Self(5);
    pub(crate) const FORM_APPLY: Self = Self(6);
    pub(crate) const FORM_DISCARD: Self = Self(7);
    pub(crate) const RECONNECT: Self = Self(8);
    pub(crate) const QUESTION_APPLY: Self = Self(9);

    /// What a forms browser does for the request, as the outcome treats it.
    fn kind(self) -> RequestKind {
        match self {
            Self::NONE => RequestKind::None,
            Self::RESET => RequestKind::Reset,
            Self::SUBMIT | Self::FORM_SUBMIT_EXIT | Self::FORM_APPLY | Self::QUESTION_APPLY => {
                RequestKind::Save
            }
            Self::EXIT | Self::FORM_DISCARD_EXIT | Self::FORM_DISCARD => RequestKind::Discard,
            Self::RECONNECT => RequestKind::Reconnect,
            Self(_) => RequestKind::Undefined,
        }
    }
}

impl fmt::Display for ActionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::NONE => "NONE",
            Self::RESET => "RESET",
            Self::SUBMIT => "SUBMIT",
            Self::EXIT => "EXIT",
            Self::FORM_SUBMIT_EXIT => "FORM_SUBMIT_EXIT",
            Self::FORM_DISCARD_EXIT => "FORM_DISCARD_EXIT",
            Self::FORM_APPLY => "FORM_APPLY",
            Self::FORM_DISCARD => "FORM_DISCARD",
            Self::RECONNECT => "RECONNECT",
            Self::QUESTION_APPLY => "QUESTION_APPLY",
            Self(value) => return write!(f, "EFI_BROWSER_ACTION_REQUEST {value}"),
        };
        write!(f, "EFI_BROWSER_ACTION_REQUEST_{name}")
    }
}

/// What a forms browser does for an ActionRequest (UEFI 2.11 §35.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    None,
    /// Exit and reset the platform
    Reset,
    /// Save modified question values to storage: SUBMIT, FORM_SUBMIT_EXIT, FORM_APPLY and
    /// QUESTION_APPLY
    Save,
    /// Discard modified question values: EXIT, FORM_DISCARD_EXIT and FORM_DISCARD
    Discard,
    /// DisconnectController(), then ConnectController() of the driver's handle
    Reconnect,
    /// A value that UEFI 2.11 does not define
    Undefined,
}

/// The Type and Value of a Callback(): a number in the bits that `value_type` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IfrValue {
    pub(crate) value_type: IfrValueType,
    pub(crate) value: u64,
}

impl IfrValue {
    /// The value as EFI_IFR_TYPE_VALUE holds it: little-endian in its first bytes, the rest
    /// zero; 24 bytes hold the union's largest member, EFI_HII_REF, with alignment.
    pub(crate) fn to_union(self) -> [u64; 3] {
        [(self.value & self.value_type.mask()).to_le(), 0, 0]
    }

    /// The value of this type that `union` holds, as a Callback() left it.
    pub(crate) fn from_union(value_type: IfrValueType, union: &[u64; 3]) -> Self {
        Self {
            value_type,
            value: u64::from_le(union[0]) & value_type.mask(),
        }
    }
}

/// What a Callback() returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallbackReturn {
    pub(crate) status: EfiStatus,
    pub(crate) request: ActionRequest,
}

/// The driver that owns a FormSet: its EFI_HII_CONFIG_ACCESS_PROTOCOL.Callback().
pub(crate) trait DriverCallback {
    /// Callback(`action`) of the question `question_id` with `value`, which it may change.
    fn callback(
        &self,
        action: BrowserAction,
        question_id: u16,
        value: &mut IfrValue,
    ) -> CallbackReturn;
}

/// The question that a sequence calls the driver for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DriverQuestion {
    pub(crate) question_id: u16,
    /// Its value before the driver's: its IFR standard default, else 0, as a forms browser
    /// starts a question without storage (edk2-stable202608 SetupBrowserDxe Setup.c:5956)
    pub(crate) initial: IfrValue,
    /// Whether the FormSet declares any store, which a save request would write
    pub(crate) form_set_has_stores: bool,
    /// Whether a forms browser evaluates a READ expression of it beside the Callback()s, which
    /// uefisettings does not
    pub(crate) read_expression: bool,
}

/// What the sequence reads and writes besides the driver: the FormSet's stores and the EFI
/// variables.
pub(crate) struct FormSetAccess<'a, R, V> {
    pub(crate) stores: Vec<FormSetStore>,
    pub(crate) routing: &'a R,
    pub(crate) variables: &'a V,
}

/// One Callback() of a sequence, as logs and outcomes list it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Call {
    pub(crate) action: BrowserAction,
    pub(crate) value: IfrValue,
    pub(crate) returned: CallbackReturn,
}

/// The Callback()s of one sequence, which sends FORM_CLOSE once FORM_OPEN was sent, unless
/// RETRIEVE failed with an error other than EFI_UNSUPPORTED.
struct Sequence<'a, D> {
    driver: &'a D,
    question: DriverQuestion,
    calls: Vec<Call>,
}

impl<'a, D: DriverCallback> Sequence<'a, D> {
    fn new(driver: &'a D, question: DriverQuestion) -> Self {
        Self {
            driver,
            question,
            calls: Vec::new(),
        }
    }

    /// Callback(`action`) with `value`, which it updates as the driver left it.
    fn call(&mut self, action: BrowserAction, value: &mut IfrValue) -> CallbackReturn {
        let returned = self
            .driver
            .callback(action, self.question.question_id, value);
        self.calls.push(Call {
            action,
            value: *value,
            returned,
        });
        returned
    }

    /// FORM_OPEN, RETRIEVE, FORM_CLOSE with `value`; the value that RETRIEVE gave, or its
    /// status.
    fn retrieve(&mut self, value: IfrValue) -> Result<IfrValue, EfiStatus> {
        let mut open = value;
        self.call(BrowserAction::FormOpen, &mut open);
        let mut retrieved = value;
        let status = self.call(BrowserAction::Retrieve, &mut retrieved).status;
        // FORM_CLOSE carries the value the question now has
        let (mut close, retrieval) = match status {
            EfiStatus::SUCCESS => (retrieved, Ok(retrieved)),
            EfiStatus::UNSUPPORTED => (value, Err(EfiStatus::UNSUPPORTED)),
            // FORM_CLOSE follows a form's submit actions (UEFI 2.11 §35.5.4), which a form that a
            // failed RETRIEVE ends never reaches: edk2-stable202608 SetupBrowserDxe Presentation.c
            // goes to Done (:2575-2577, :2716), past FORM_CLOSE, unless the error is
            // EFI_UNSUPPORTED, which it counts as success (:2281-2285)
            status => return Err(status),
        };
        self.call(BrowserAction::FormClose, &mut close);
        retrieval
    }

    /// Why the outcome is refused, from the ActionRequests so far, if any asks what no forms
    /// browser here does: a save of the FormSet's stores, which only a browser's edit buffer
    /// holds, or a value that UEFI 2.11 does not define.
    fn request_refusal(&self) -> Option<String> {
        self.calls.iter().find_map(|call| {
            let request = call.returned.request;
            match request.kind() {
                RequestKind::Save if self.question.form_set_has_stores => Some(format!(
                    "Callback({}) asked the forms browser to save the FormSet's modified values \
                     ({request}), which only a forms browser's edit buffer holds",
                    call.action
                )),
                RequestKind::Undefined => Some(format!(
                    "Callback({}) returned {request}, which UEFI 2.11 section 35.5.4 does not \
                     define",
                    call.action
                )),
                RequestKind::None
                | RequestKind::Save
                | RequestKind::Reset
                | RequestKind::Discard
                | RequestKind::Reconnect => None,
            }
        })
    }

    /// The notes of the ActionRequests that ask for a reset or a discard.
    fn request_notes(&self) -> Vec<String> {
        self.calls
            .iter()
            .filter_map(|call| {
                let request = call.returned.request;
                match request.kind() {
                    RequestKind::Reset => Some(format!(
                        "Callback({}) asks for a platform reset ({request})",
                        call.action
                    )),
                    RequestKind::Discard => Some(format!(
                        "Callback({}) asked the forms browser to discard modified values \
                         ({request}); outside a forms browser none are pending",
                        call.action
                    )),
                    RequestKind::None
                    | RequestKind::Save
                    | RequestKind::Reconnect
                    | RequestKind::Undefined => None,
                }
            })
            .collect()
    }
}

/// get's outcome for a question without a VarStore.
#[derive(Debug)]
pub(crate) struct Retrieval {
    /// The value RETRIEVE gave, or why there is none
    pub(crate) value: Result<IfrValue, String>,
    /// Notes on ActionRequests and settings left out, each a phrase
    pub(crate) notes: Vec<String>,
    pub(crate) calls: Vec<Call>,
}

/// Runs get's sequence for `question`: FORM_OPEN, RETRIEVE, FORM_CLOSE, between the reads of
/// the FormSet's stores.
pub(crate) fn retrieve<D, R, V>(
    driver: &D,
    question: DriverQuestion,
    access: FormSetAccess<'_, R, V>,
) -> Retrieval
where
    D: DriverCallback,
    R: ConfigRouting,
    V: VariableData,
{
    let baseline = match Baseline::take(access.stores, access.routing, access.variables) {
        Ok(baseline) => baseline,
        Err(refusal) => {
            return Retrieval {
                value: Err(refusal.to_string()),
                notes: Vec::new(),
                calls: Vec::new(),
            }
        }
    };
    let mut sequence = Sequence::new(driver, question);
    let retrieved = sequence.retrieve(question.initial);
    let check = baseline.check(access.routing, access.variables);
    let mut notes = sequence.request_notes();
    notes.extend(dynamic_note(&baseline));
    let value = match (check.refusal(), sequence.request_refusal(), retrieved) {
        (Some(reason), _, _) | (None, Some(reason), _) => Err(reason),
        (None, None, Ok(value)) => Ok(value),
        // without RETRIEVE's value, a forms browser keeps READ's
        (None, None, Err(status)) => Err(match question.read_expression {
            true => ExpressionBesideCallback(QuestionExpression::Read).to_string(),
            false => StoragelessRefusal::RetrieveFailed {
                status: status.to_string(),
            }
            .to_string(),
        }),
    };
    Retrieval {
        value,
        notes,
        calls: sequence.calls,
    }
}

/// The note listing the settings of the stores that the check left out, if any.
fn dynamic_note(baseline: &Baseline) -> Option<String> {
    let dynamic = baseline.dynamic();
    (!dynamic.is_empty()).then(|| {
        format!(
            "not compared, as they changed between two reads before the first Callback(): {}",
            dynamic.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::efi_variables::VariableContents;
    use crate::hii::form_set_stores::tests::buffer_declaration;
    use crate::hii::form_set_stores::tests::efi_declaration;
    use crate::hii::form_set_stores::tests::header_of;
    use crate::hii::form_set_stores::tests::store;
    use crate::hii::form_set_stores::tests::FakeRouting;
    use crate::hii::form_set_stores::tests::STORE_GUID;

    const QUESTION: u16 = 0x0201;
    const U8: IfrValueType = IfrValueType::NumSize8;

    /// What a scripted Callback() does: return this, after setting the value to `writes` and
    /// running `effect`.
    #[derive(Clone, Copy)]
    struct Step {
        status: EfiStatus,
        request: ActionRequest,
        writes: Option<u64>,
        effect: Effect,
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Effect {
        None,
        /// writes byte 0 of the Buffer store
        Buffer,
        /// writes the EFI variable store
        Variable,
    }

    fn step(status: EfiStatus) -> Step {
        Step {
            status,
            request: ActionRequest::NONE,
            writes: None,
            effect: Effect::None,
        }
    }

    /// A driver whose Callback() follows a script per action, EFI_SUCCESS after it ends, and
    /// logs each call; it writes the stores of `routing` and `variables` as told.
    struct ScriptedDriver<'a> {
        script: RefCell<Vec<(BrowserAction, VecDeque<Step>)>>,
        log: RefCell<Vec<(BrowserAction, u16, u64)>>,
        routing: &'a FakeRouting,
        variables: &'a HeldVariables,
    }

    impl<'a> ScriptedDriver<'a> {
        fn new(routing: &'a FakeRouting, variables: &'a HeldVariables) -> Self {
            Self {
                script: RefCell::new(Vec::new()),
                log: RefCell::new(Vec::new()),
                routing,
                variables,
            }
        }

        fn on(self, action: BrowserAction, step: Step) -> Self {
            {
                let mut script = self.script.borrow_mut();
                match script.iter_mut().find(|(each, _)| *each == action) {
                    Some((_, steps)) => steps.push_back(step),
                    None => script.push((action, VecDeque::from([step]))),
                }
            }
            self
        }

        fn actions(&self) -> Vec<BrowserAction> {
            self.log
                .borrow()
                .iter()
                .map(|(action, _, _)| *action)
                .collect()
        }
    }

    impl DriverCallback for ScriptedDriver<'_> {
        fn callback(
            &self,
            action: BrowserAction,
            question_id: u16,
            value: &mut IfrValue,
        ) -> CallbackReturn {
            self.log
                .borrow_mut()
                .push((action, question_id, value.value));
            let step = self
                .script
                .borrow_mut()
                .iter_mut()
                .find(|(each, _)| *each == action)
                .and_then(|(_, steps)| steps.pop_front())
                .unwrap_or(step(EfiStatus::SUCCESS));
            if let Some(written) = step.writes {
                value.value = written;
            }
            match step.effect {
                Effect::None => {}
                Effect::Buffer => {
                    let header = self
                        .routing
                        .buffers
                        .borrow()
                        .keys()
                        .next()
                        .cloned()
                        .expect("a buffer");
                    self.routing
                        .buffers
                        .borrow_mut()
                        .get_mut(&header)
                        .expect("buffer")[0] = 0xEE;
                }
                Effect::Variable => {
                    self.variables.variables.borrow_mut().insert(
                        key("Store", STORE_GUID),
                        VariableContents::new(NV_BS_RT, vec![1, 2]).expect("data"),
                    );
                }
            }
            CallbackReturn {
                status: step.status,
                request: step.request,
            }
        }
    }

    struct Fixture {
        routing: FakeRouting,
        variables: HeldVariables,
        stores: Vec<FormSetStore>,
    }

    /// A FormSet with a 2-byte Buffer store and an EFI variable store.
    fn fixture() -> Fixture {
        let stores = vec![
            store(&buffer_declaration(2, "Buffer", &[(0, 2)])),
            store(&efi_declaration(1, "Store")),
        ];
        let routing = FakeRouting::default().with_buffer(&header_of(&stores[0]), &[0xA5, 0xA5]);
        let variables = HeldVariables::default().with("Store", STORE_GUID, &[0x5A; 4]);
        Fixture {
            routing,
            variables,
            stores,
        }
    }

    fn question(has_stores: bool) -> DriverQuestion {
        DriverQuestion {
            question_id: QUESTION,
            initial: IfrValue {
                value_type: U8,
                value: 0,
            },
            form_set_has_stores: has_stores,
            read_expression: false,
        }
    }

    fn access(fixture: &Fixture) -> FormSetAccess<'_, FakeRouting, HeldVariables> {
        FormSetAccess {
            stores: fixture.stores.clone(),
            routing: &fixture.routing,
            variables: &fixture.variables,
        }
    }

    fn value(value: u64) -> IfrValue {
        IfrValue {
            value_type: U8,
            value,
        }
    }

    use BrowserAction::FormClose;
    use BrowserAction::FormOpen;
    use BrowserAction::Retrieve;

    #[test]
    fn get_sends_form_open_retrieve_form_close_and_gives_the_value() {
        let fixture = fixture();
        let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables).on(
            Retrieve,
            Step {
                writes: Some(2),
                ..step(EfiStatus::SUCCESS)
            },
        );

        let got = retrieve(&driver, question(true), access(&fixture));

        assert_eq!(got.value, Ok(value(2)), "RETRIEVE's value: {got:?}");
        assert_eq!(
            *driver.log.borrow(),
            [
                (FormOpen, QUESTION, 0),
                (Retrieve, QUESTION, 0),
                (FormClose, QUESTION, 2)
            ],
            "the calls, each for the question, FORM_CLOSE with the retrieved value"
        );
    }

    #[test]
    fn get_without_retrieve_has_no_value() {
        let fixture = fixture();
        // a forms browser counts EFI_UNSUPPORTED as success and closes the form; any other error
        // ends the form before its FORM_CLOSE
        let cases = [
            (
                EfiStatus::UNSUPPORTED,
                "its driver's CallBack(EFI_BROWSER_ACTION_RETRIEVE) returned EFI_UNSUPPORTED; \
                 without a VarStore the question has no other value (UEFI 2.11 §33.2.5.4.1)",
                &[FormOpen, Retrieve, FormClose][..],
            ),
            (
                EfiStatus::DEVICE_ERROR,
                "its driver's CallBack(EFI_BROWSER_ACTION_RETRIEVE) returned EFI_DEVICE_ERROR; \
                 without a VarStore the question has no other value (UEFI 2.11 §33.2.5.4.1)",
                &[FormOpen, Retrieve],
            ),
        ];
        for (status, want, want_actions) in cases {
            let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables)
                .on(Retrieve, step(status));
            let got = retrieve(&driver, question(true), access(&fixture));
            assert_eq!(
                got.value,
                Err(want.to_string()),
                "RETRIEVE returns {status}"
            );
            assert_eq!(
                driver.actions(),
                want_actions,
                "the calls when RETRIEVE returns {status}"
            );
        }
    }

    #[test]
    fn get_with_a_read_expression_takes_retrieve_or_says_read_is_not_applied() {
        let fixture = fixture();
        let with_read = DriverQuestion {
            read_expression: true,
            ..question(true)
        };
        let retrieved = ScriptedDriver::new(&fixture.routing, &fixture.variables).on(
            Retrieve,
            Step {
                writes: Some(2),
                ..step(EfiStatus::SUCCESS)
            },
        );
        let unsupported = ScriptedDriver::new(&fixture.routing, &fixture.variables)
            .on(Retrieve, step(EfiStatus::UNSUPPORTED));

        let got = retrieve(&retrieved, with_read, access(&fixture));
        let missing = retrieve(&unsupported, with_read, access(&fixture));

        assert_eq!(got.value, Ok(value(2)), "RETRIEVE overrides READ");
        assert_eq!(
            missing.value,
            Err(
                "question has no VarStore, and uefisettings does not apply its READ expression \
                 beside its driver's Callback()s"
                    .to_string()
            ),
            "without RETRIEVE's value, READ's would stand"
        );
    }

    #[test]
    fn get_whose_retrieve_writes_a_store_gives_no_value_and_restores() {
        let cases = [
            (Effect::Buffer, "VARSTORE 0x0002 Buffer".to_string()),
            (
                Effect::Variable,
                format!("VARSTORE_EFI 0x0001 {}", key("Store", STORE_GUID)),
            ),
        ];
        for (effect, store) in cases {
            let fixture = fixture();
            let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables).on(
                Retrieve,
                Step {
                    writes: Some(1),
                    effect,
                    ..step(EfiStatus::SUCCESS)
                },
            );

            let got = retrieve(&driver, question(true), access(&fixture));

            assert_eq!(
                got.value,
                Err(format!(
                    "the Callback sequence changed stores of the FormSet: {store}; restored and \
                     verified"
                )),
                "a RETRIEVE that writes {store}"
            );
            assert_eq!(
                fixture.routing.buffer(&header_of(&fixture.stores[0])),
                [0xA5, 0xA5],
                "the Buffer store after a write of {store}"
            );
            assert_eq!(
                fixture
                    .variables
                    .variables
                    .borrow()
                    .get(&key("Store", STORE_GUID))
                    .map(|contents| contents.data().to_vec()),
                Some(vec![0x5A; 4]),
                "the EFI variable store after a write of {store}"
            );
        }
    }

    #[test]
    fn get_notes_requests_and_records_its_calls() {
        let fixture = fixture();
        let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables).on(
            Retrieve,
            Step {
                request: ActionRequest::RESET,
                writes: Some(3),
                ..step(EfiStatus::SUCCESS)
            },
        );

        let got = retrieve(&driver, question(true), access(&fixture));

        assert_eq!(got.value, Ok(value(3)), "a reset request keeps the value");
        assert_eq!(
            got.notes,
            ["Callback(RETRIEVE) asks for a platform reset (EFI_BROWSER_ACTION_REQUEST_RESET)"],
            "the notes"
        );
        assert_eq!(
            got.calls
                .iter()
                .map(|call| (call.action, call.value.value, call.returned.request))
                .collect::<Vec<_>>(),
            [
                (FormOpen, 0, ActionRequest::NONE),
                (Retrieve, 3, ActionRequest::RESET),
                (FormClose, 3, ActionRequest::NONE),
            ],
            "the recorded calls"
        );
    }

    #[test]
    fn get_refuses_before_any_callback_when_a_store_is_unreadable() {
        let fixture = fixture();
        fixture.routing.extract_fails_from.set(Some(0));
        let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables);

        let got = retrieve(&driver, question(true), access(&fixture));

        assert!(
            got.value
                .as_ref()
                .is_err_and(|reason| reason.starts_with("cannot snapshot store VARSTORE 0x0002")),
            "the refusal: {got:?}"
        );
        assert!(driver.actions().is_empty(), "no Callback()");
    }

    #[test]
    fn get_lists_settings_that_change_on_their_own() {
        let fixture = fixture();
        // byte 1 of the Buffer store ticks at every ExtractConfig(), as a timestamp would
        fixture.routing.ticking.borrow_mut().push(1);
        let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables);

        let got = retrieve(&driver, question(true), access(&fixture));

        assert_eq!(got.value, Ok(value(0)), "a ticking setting is no change");
        assert_eq!(
            got.notes,
            [
                "not compared, as they changed between two reads before the first Callback(): \
                 VARSTORE 0x0002 Buffer: OFFSET=0000&WIDTH=0002"
            ],
            "the setting left out"
        );
    }

    #[test]
    fn get_refuses_save_and_undefined_requests_and_notes_a_discard() {
        let fixture = fixture();
        let cases = [
            (
                ActionRequest::SUBMIT,
                true,
                Err(
                    "Callback(RETRIEVE) asked the forms browser to save the FormSet's modified \
                     values (EFI_BROWSER_ACTION_REQUEST_SUBMIT), which only a forms browser's \
                     edit buffer holds"
                        .to_string(),
                ),
                Vec::new(),
            ),
            (ActionRequest::SUBMIT, false, Ok(value(1)), Vec::new()),
            (
                ActionRequest(10),
                true,
                Err(
                    "Callback(RETRIEVE) returned EFI_BROWSER_ACTION_REQUEST 10, which UEFI 2.11 \
                     section 35.5.4 does not define"
                        .to_string(),
                ),
                Vec::new(),
            ),
            (
                ActionRequest::FORM_DISCARD,
                true,
                Ok(value(1)),
                vec![
                    "Callback(RETRIEVE) asked the forms browser to discard modified values \
                      (EFI_BROWSER_ACTION_REQUEST_FORM_DISCARD); outside a forms browser none are \
                      pending"
                        .to_string(),
                ],
            ),
        ];
        for (request, has_stores, want, want_notes) in cases {
            let driver = ScriptedDriver::new(&fixture.routing, &fixture.variables).on(
                Retrieve,
                Step {
                    request,
                    writes: Some(1),
                    ..step(EfiStatus::SUCCESS)
                },
            );

            let got = retrieve(&driver, question(has_stores), access(&fixture));

            let case = format!("{request}, the FormSet declaring stores: {has_stores}");
            assert_eq!(got.value, want, "{case}");
            assert_eq!(got.notes, want_notes, "{case}: the notes");
        }
    }

    #[test]
    fn values_pass_through_the_union_in_their_width() {
        let cases = [
            (IfrValueType::NumSize8, 0x1FF, 0xFF),
            (IfrValueType::NumSize16, 0x1_2345, 0x2345),
            (IfrValueType::NumSize32, 0x1_2345_6789, 0x2345_6789),
            (IfrValueType::NumSize64, u64::MAX, u64::MAX),
            (IfrValueType::Boolean, 0x101, 0x01),
        ];
        for (value_type, value, want) in cases {
            let union = IfrValue { value_type, value }.to_union();
            assert_eq!(
                union[1..],
                [0, 0],
                "{value_type:?} uses only the first word"
            );
            assert_eq!(
                u64::from_le(union[0]),
                want,
                "{value_type:?}'s bytes in memory, least significant first"
            );
            assert_eq!(
                IfrValue::from_union(value_type, &union).value,
                want,
                "{value_type:?} keeps its width"
            );
        }
    }
}
