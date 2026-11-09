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

//! apply-staged: what uefisettings.efi does when the staged set's Boot#### starts it, before the
//! OS.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use super::boot_next_key;
use super::boot_option_name;
use super::read_record;
use super::remove_boot_option;
use super::starts_staged_set;
use super::write_record;
use super::Nonce;
use super::Outcome;
use super::RequestOutcome;
use super::StagedRequest;
use super::StagedSet;
use super::STAGED_OUTCOME;
use super::STAGED_SET;
use crate::efi_variables::globals::boot_current;
use crate::efi_variables::globals::boot_next;
use crate::efi_variables::VariableData;
use crate::hii::forms::PasswordQuestions;
use crate::hii::package::ParsedPackageList;
use crate::hii::VariableKey;
use crate::hii::VariableReach;
use crate::unsafe_operations::LiftedOperations;
use crate::unsafe_operations::UnsafeOperation;

/// What applies a staged request before the OS starts: the question's driver.
pub(crate) trait StagedRequestDriver {
    /// Sets the question of `request` through its driver: the annotation of set's answer and the
    /// unsafe operations that it lifted, or why it is not applied, with those that it lifted
    /// before it failed (LiftedOperations).
    fn apply(&self, request: &StagedRequest) -> Result<(String, Vec<UnsafeOperation>)>;
}

/// What apply_staged did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Application {
    /// The result of each request, as recorded; None if it applied none
    pub(crate) results: Option<Vec<RequestOutcome>>,
    /// The variables that it deleted, in order
    pub(crate) deleted: Vec<VariableKey>,
    /// The steps that failed, in order; the steps after each still ran
    pub(crate) failures: Vec<String>,
}

impl Application {
    /// What uefisettings.efi prints of it: each request and its result, after the warning of each
    /// unsafe operation that applying it lifted, as set prints them; each deletion, then each
    /// failure.
    pub(crate) fn lines(&self) -> Vec<String> {
        let results = self.results.iter().flatten().flat_map(|outcome| {
            let request = &outcome.request;
            let applied = match outcome.applied {
                true => "applied",
                false => "not applied",
            };
            // the name as it is: uefisettings.efi prints the line as TerminalText, which
            // escapes it once
            let result = format!(
                "question \"{}\", QuestionId {:#06x} of FormSet {}, to {}: {applied}: {}",
                request.question,
                request.question_id,
                request.form_set,
                request.value,
                outcome.result
            );
            let warnings = outcome
                .warnings
                .iter()
                .map(|warning| format!("warning: {warning}"));
            warnings.chain(std::iter::once(result))
        });
        let deleted = self
            .deleted
            .iter()
            .map(|key| format!("deleted {}", key.name));
        let failures = self
            .failures
            .iter()
            .map(|failure| format!("failed: {failure}"));
        results.chain(deleted).chain(failures).collect()
    }
}

/// apply_staged through `variables` without the bytes of the PASSWORD questions of the package
/// lists `lists`, which no step writes over. Before the OS, a PASSWORD question whose VarStore is
/// unknown could keep its password in any variable, so then it fails, and applies, records and
/// deletes nothing.
pub(crate) fn apply_staged_withholding(
    lists: &[ParsedPackageList],
    variables: impl VariableData,
    nonce: &str,
    driver: &impl StagedRequestDriver,
) -> Result<Application> {
    let variables = PasswordQuestions::of_lists(lists)
        .withholding_of(variables, VariableReach::BootServices)?;
    Ok(apply_staged(&variables, nonce, driver))
}

/// apply-staged of `nonce`, the text that ends the command line of the staged set's Boot####:
/// records that uefisettings.efi started, applies each request of the staged set of `nonce`
/// through `driver`, records each result, then deletes the set's Boot#### and BootNext if it names
/// BootCurrent, whose Boot#### holds that command line. The set's record and image stay for the OS
/// to settle. A step that fails is mapped to the outcome or listed in the failures, and the steps
/// after it still run, but no request is applied unless the start is recorded. A nonce that has an
/// outcome applies nothing again: a recorded start becomes Interrupted. Without a staged set of
/// `nonce`, nothing is applied or recorded, and BootCurrent's Boot#### goes only if it holds the
/// command line of `nonce`.
fn apply_staged(
    variables: &impl VariableData,
    nonce: &str,
    driver: &impl StagedRequestDriver,
) -> Application {
    let mut deleted = Vec::new();
    let mut failures = Vec::new();
    let results = match staged_set_of(variables, nonce) {
        Ok(set) => {
            let results = match first_start(variables, &set) {
                Ok(()) => Some(apply_requests(variables, &set, driver, &mut failures)),
                Err(error) => {
                    failures.push(format!("{error:#}"));
                    None
                }
            };
            match remove_boot_option(variables, boot_option_name(set.boot_option), set.nonce) {
                Ok(removed) => deleted.extend(removed),
                Err(error) => {
                    failures.push(format!("delete Boot{:04X}: {error:#}", set.boot_option));
                }
            }
            results
        }
        Err(error) => {
            failures.push(format!("{error:#}"));
            match remove_current_option(variables, nonce) {
                Ok(removed) => deleted.extend(removed),
                Err(error) => failures.push(format!("delete BootCurrent's Boot####: {error:#}")),
            }
            None
        }
    };
    match remove_boot_next_of_current(variables, nonce) {
        Ok(removed) => deleted.extend(removed),
        Err(error) => failures.push(format!("delete BootNext: {error:#}")),
    }
    Application {
        results,
        deleted,
        failures,
    }
}

/// Refuses a second start of `set`, whose nonce already has an outcome, as when its Boot#### starts
/// again after a crash, a hang or a failed deletion, so that no boot loops on it: a recorded start
/// becomes Interrupted, as the OS would read it, and any other outcome stays.
fn first_start(variables: &impl VariableData, set: &StagedSet) -> Result<()> {
    let outcome = read_record::<Outcome>(variables, STAGED_OUTCOME)?
        .filter(|outcome| outcome.nonce() == set.nonce);
    match outcome {
        None => return Ok(()),
        Some(Outcome::Started { nonce }) => write_record(
            variables,
            STAGED_OUTCOME,
            &Outcome::Interrupted {
                nonce,
                requests: set.requests.clone(),
            },
        )?,
        Some(
            Outcome::Finished { .. } | Outcome::Interrupted { .. } | Outcome::NotStarted { .. },
        ) => {}
    }
    Err(anyhow!(
        "the staged set of the nonce {} already started in an earlier boot, so none of its \
         requests is applied again",
        set.nonce
    ))
}

/// The staged set of `nonce`, refused unless the records hold it.
fn staged_set_of(variables: &impl VariableData, nonce: &str) -> Result<StagedSet> {
    let nonce: Nonce = nonce.parse().context("the command line's nonce")?;
    match read_record::<StagedSet>(variables, STAGED_SET)? {
        Some(set) if set.nonce == nonce => Ok(set),
        Some(set) => Err(anyhow!(
            "the staged set has the nonce {}, not {nonce}",
            set.nonce
        )),
        None => Err(anyhow!("no set is staged, so none of the nonce {nonce}")),
    }
}

/// Records that uefisettings.efi started, applies each request of `set` through `driver` if that
/// is recorded, then records Finished with each result, which it returns; a record that fails goes
/// to `failures`.
fn apply_requests(
    variables: &impl VariableData,
    set: &StagedSet,
    driver: &impl StagedRequestDriver,
    failures: &mut Vec<String>,
) -> Vec<RequestOutcome> {
    let started = write_record(
        variables,
        STAGED_OUTCOME,
        &Outcome::Started { nonce: set.nonce },
    );
    let results: Vec<RequestOutcome> = set
        .requests
        .iter()
        .map(|request| {
            let applied = match &started {
                Ok(()) => driver.apply(request),
                Err(error) => Err(anyhow!(
                    "not applied, as recording that uefisettings.efi started failed: {error:#}"
                )),
            };
            request_outcome(request, applied)
        })
        .collect();
    if let Err(error) = started {
        failures.push(format!("record that uefisettings.efi started: {error:#}"));
    }
    let outcome = Outcome::Finished {
        nonce: set.nonce,
        results: results.clone(),
    };
    if let Err(error) = write_record(variables, STAGED_OUTCOME, &outcome) {
        failures.push(format!("record the outcome: {error:#}"));
    }
    results
}

/// The outcome of `request` that `applied` tells, with the warning of each unsafe operation that
/// applying it lifted, also before it failed (LiftedOperations).
fn request_outcome(
    request: &StagedRequest,
    applied: Result<(String, Vec<UnsafeOperation>)>,
) -> RequestOutcome {
    let (applied, result, lifted) = match applied {
        Ok((annotation, lifted)) => (true, annotation, lifted),
        Err(error) => {
            let lifted = match error.downcast_ref::<LiftedOperations>() {
                Some(LiftedOperations(lifted)) => lifted.clone(),
                None => Vec::new(),
            };
            (false, format!("{error:#}"), lifted)
        }
    };
    RequestOutcome {
        request: request.clone(),
        applied,
        result,
        warnings: lifted.iter().map(UnsafeOperation::lifted_warning).collect(),
    }
}

/// Deletes BootCurrent's Boot#### if it holds the command line of a staged set of `nonce`; the
/// variables deleted.
fn remove_current_option(variables: &impl VariableData, nonce: &str) -> Result<Vec<VariableKey>> {
    match (nonce.parse::<Nonce>(), boot_current(variables)?) {
        (Ok(nonce), Some(current)) => remove_boot_option(variables, current, nonce),
        (Err(_), _) | (Ok(_), None) => Ok(Vec::new()),
    }
}

/// Deletes BootNext if it names BootCurrent and BootCurrent's Boot#### holds the command line of
/// `nonce`, so that another tool's BootNext stays; the variables deleted. The boot manager deletes
/// BootNext before it starts that option (UEFI 2.11 §3.1.2), so one that names it now was written
/// since, and would start it at the next boot again.
fn remove_boot_next_of_current(
    variables: &impl VariableData,
    nonce: &str,
) -> Result<Vec<VariableKey>> {
    let (Ok(nonce), Some(current), Some(next)) = (
        nonce.parse::<Nonce>(),
        boot_current(variables)?,
        boot_next(variables)?,
    ) else {
        return Ok(Vec::new());
    };
    if current != next || !starts_staged_set(variables, current, nonce)? {
        return Ok(Vec::new());
    }
    variables.delete_variable(&boot_next_key())?;
    Ok(vec![boot_next_key()])
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
    use crate::efi_variables::UEFISETTINGS_VENDOR_GUID;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::parse_form_set;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::var_store_efi_of;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::IFROperation;
    use crate::hii::forms::IgnoredIfr;
    use crate::hii::forms::IgnoredPasswords;
    use crate::hii::forms::IncludedStates;
    use crate::staged_set::tests::boot_option;
    use crate::staged_set::tests::finished;
    use crate::staged_set::tests::held;
    use crate::staged_set::tests::including_request;
    use crate::staged_set::tests::record;
    use crate::staged_set::tests::request;
    use crate::staged_set::tests::staged;
    use crate::staged_set::tests::staged_set;
    use crate::staged_set::tests::started;
    use crate::staged_set::tests::FailingSet;
    use crate::staged_set::tests::BOOT_OPTION;
    use crate::staged_set::tests::NONCE;
    use crate::staged_set::tests::OTHER_NONCE;
    use crate::unsafe_operations::UnsafeOperations;

    /// A driver that applies each request of an even value and refuses each of an odd one, and
    /// records each request with the outcome recorded when it was asked.
    struct StagedDriver<'a> {
        variables: &'a HeldVariables,
        asked: RefCell<Vec<(u64, Option<Outcome>)>>,
    }

    impl<'a> StagedDriver<'a> {
        fn new(variables: &'a HeldVariables) -> Self {
            Self {
                variables,
                asked: RefCell::new(Vec::new()),
            }
        }
    }

    /// The unsafe operation that StagedDriver lifts for a request staged with
    /// --i-am-fine-to-brick-this-system.
    fn read_only_write() -> UnsafeOperation {
        UnsafeOperation::ReadOnlyQuestion {
            question: "Generic Question".to_owned(),
            writable: IncludedStates::empty(),
        }
    }

    impl StagedRequestDriver for StagedDriver<'_> {
        /// Lifts read_only_write for a request staged with --i-am-fine-to-brick-this-system.
        fn apply(&self, request: &StagedRequest) -> Result<(String, Vec<UnsafeOperation>)> {
            self.asked
                .borrow_mut()
                .push((request.value, record(self.variables, STAGED_OUTCOME)));
            let lifted = match request.unsafe_operations {
                UnsafeOperations::Refuse => Vec::new(),
                UnsafeOperations::Allow => vec![read_only_write()],
            };
            match request.value % 2 {
                0 => Ok((format!("<applied {}>", request.value), lifted)),
                _ => Err(LiftedOperations::attach(
                    lifted,
                    anyhow!("the driver refused {}", request.value),
                )),
            }
        }
    }

    /// The results of staged_set() as StagedDriver applies it: request(1) refused, request(2)
    /// applied with the warning of read_only_write.
    fn applied() -> Vec<RequestOutcome> {
        vec![
            RequestOutcome {
                request: request(1),
                applied: false,
                result: "the driver refused 1".to_owned(),
                warnings: Vec::new(),
            },
            RequestOutcome {
                request: including_request(),
                applied: true,
                result: "<applied 2>".to_owned(),
                warnings: vec![read_only_write().lifted_warning()],
            },
        ]
    }

    #[test]
    fn apply_staged_records_its_start_then_each_result_and_deletes_its_boot_option() {
        let nonce = NONCE.to_string();
        let variables = staged(None, Some(&finished(OTHER_NONCE))).with(
            "BootCurrent",
            EFI_GLOBAL_VARIABLE,
            &BOOT_OPTION.to_le_bytes(),
        );
        let driver = StagedDriver::new(&variables);

        let application = apply_staged(&variables, &nonce, &driver);

        assert_eq!(
            application,
            Application {
                results: Some(applied()),
                deleted: vec![key("Boot0007", EFI_GLOBAL_VARIABLE)],
                failures: Vec::new(),
            },
            "the application"
        );
        assert_eq!(
            *driver.asked.borrow(),
            [(1, Some(started(NONCE))), (2, Some(started(NONCE)))],
            "each request, once its start is recorded"
        );
        assert_eq!(
            record(&variables, STAGED_OUTCOME),
            Some(Outcome::Finished {
                nonce: NONCE,
                results: applied(),
            }),
            "the outcome"
        );
        assert_eq!(
            application.lines(),
            [
                "question \"Generic Question\", QuestionId 0x0201 of FormSet \
                 8C78A505-BAA0-4C4A-869F-000000001A09, to 1: not applied: the driver refused 1",
                "warning: cannot set question \"Generic Question\": EFI_IFR_FLAG_READ_ONLY makes it \
                 read-only (UEFI 2.11 §33.3.8.2.2); --i-am-fine-to-brick-this-system lets \
                 uefisettings write it",
                "question \"Generic Question\", QuestionId 0x0201 of FormSet \
                 8C78A505-BAA0-4C4A-869F-000000001A09, to 2: applied: <applied 2>",
                "deleted Boot0007",
            ],
            "the lines"
        );
        assert_eq!(
            *variables.set.borrow(),
            [
                key(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID),
                key(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID),
            ],
            "the writes: started, then finished"
        );
        assert_eq!(
            *variables.deleted.borrow(),
            [key("Boot0007", EFI_GLOBAL_VARIABLE)],
            "the deletions"
        );
        assert_eq!(
            record(&variables, STAGED_SET),
            Some(staged_set()),
            "the record stays for the OS"
        );

        // BootNext as the boot manager leaves it, or as written since
        for (case, boot_current, boot_next, current_command, deleted) in [
            (
                "BootNext of the set's Boot####",
                0x0007u16,
                Some(0x0007u16),
                None,
                true,
            ),
            (
                "BootNext of BootCurrent, a copy of the set's Boot####",
                0x0009,
                Some(0x0009),
                Some(NONCE),
                true,
            ),
            // another tool's BootNext
            (
                "BootNext of BootCurrent, whose Boot#### holds another command line",
                0x0009,
                Some(0x0009),
                Some(OTHER_NONCE),
                false,
            ),
            (
                "BootNext of BootCurrent, which is absent",
                0x0009,
                Some(0x0009),
                None,
                false,
            ),
            (
                "BootNext of another option",
                0x0007,
                Some(0x0003),
                None,
                false,
            ),
        ] {
            let variables = staged(boot_next, None).with(
                "BootCurrent",
                EFI_GLOBAL_VARIABLE,
                &boot_current.to_le_bytes(),
            );
            let variables = match current_command {
                Some(nonce) => variables.with("Boot0009", EFI_GLOBAL_VARIABLE, &boot_option(nonce)),
                None => variables,
            };

            let application = apply_staged(&variables, &nonce, &StagedDriver::new(&variables));

            assert_eq!(application.failures, Vec::<String>::new(), "{case}");
            assert_eq!(
                held(&variables, "BootNext", EFI_GLOBAL_VARIABLE),
                !deleted,
                "{case}: BootNext"
            );
            assert!(
                !held(&variables, "Boot0007", EFI_GLOBAL_VARIABLE),
                "{case}: the set's Boot####"
            );
        }
    }

    /// A line names the staged question as it is, in quotes, as the warning of a read-only
    /// question does: uefisettings.efi prints each line as TerminalText, which escapes it once,
    /// where a Debug escape would be escaped again.
    #[test]
    fn apply_staged_lines_name_the_question_as_it_is() {
        let question = "C:\\A\u{1b}[2J";
        let application = Application {
            results: Some(vec![RequestOutcome {
                request: StagedRequest {
                    question: question.to_owned(),
                    ..request(1)
                },
                applied: true,
                result: "<applied 1>".to_owned(),
                warnings: Vec::new(),
            }]),
            deleted: Vec::new(),
            failures: Vec::new(),
        };

        assert_eq!(
            application.lines(),
            [format!(
                "question \"{question}\", QuestionId 0x0201 of FormSet \
                 8C78A505-BAA0-4C4A-869F-000000001A09, to 1: applied: <applied 1>"
            )],
            "the lines"
        );
    }

    /// A set whose nonce already has an outcome, as when its Boot#### starts again after a crash
    /// or a failed deletion, applies no request again: a start becomes Interrupted and any other
    /// outcome stays, and its Boot#### and BootNext still go.
    #[test]
    fn apply_staged_applies_nothing_again_for_a_nonce_with_an_outcome() {
        let nonce = NONCE.to_string();
        let interrupted = Outcome::Interrupted {
            nonce: NONCE,
            requests: staged_set().requests,
        };
        for (outcome, want) in [
            (started(NONCE), interrupted.clone()),
            (finished(NONCE), finished(NONCE)),
            (interrupted.clone(), interrupted.clone()),
        ] {
            let variables = staged(Some(BOOT_OPTION), Some(&outcome)).with(
                "BootCurrent",
                EFI_GLOBAL_VARIABLE,
                &BOOT_OPTION.to_le_bytes(),
            );
            let driver = StagedDriver::new(&variables);

            let application = apply_staged(&variables, &nonce, &driver);

            assert!(
                driver.asked.borrow().is_empty(),
                "{outcome:?}: nothing applied"
            );
            assert_eq!(application.results, None, "{outcome:?}: no results");
            assert_eq!(
                application.failures,
                [format!(
                    "the staged set of the nonce {NONCE} already started in an earlier boot, so \
                     none of its requests is applied again"
                )],
                "{outcome:?}: the failure"
            );
            assert_eq!(
                record(&variables, STAGED_OUTCOME),
                Some(want),
                "{outcome:?}: the outcome"
            );
            assert_eq!(
                application.deleted,
                [
                    key("BootNext", EFI_GLOBAL_VARIABLE),
                    key("Boot0007", EFI_GLOBAL_VARIABLE),
                ],
                "{outcome:?}: deleted"
            );
        }
    }

    /// A request that fails after its driver lifted an unsafe operation keeps the warning of that
    /// operation all the same, and its error after them, as set does.
    #[test]
    fn a_request_that_fails_keeps_the_warnings_of_what_it_lifted() {
        let variables = staged(None, None);
        let set = StagedSet {
            requests: vec![StagedRequest {
                value: 3,
                ..including_request()
            }],
            ..staged_set()
        };
        let mut failures = Vec::new();

        let results = apply_requests(
            &variables,
            &set,
            &StagedDriver::new(&variables),
            &mut failures,
        );

        let want = vec![RequestOutcome {
            request: set.requests[0].clone(),
            applied: false,
            result: "after 1 unsafe operation(s) that --i-am-fine-to-brick-this-system let \
                     through: the driver refused 3"
                .to_owned(),
            warnings: vec![read_only_write().lifted_warning()],
        }];
        assert_eq!(results, want, "the results");
        assert_eq!(failures, Vec::<String>::new(), "the failures");
        assert_eq!(
            record(&variables, STAGED_OUTCOME),
            Some(Outcome::Finished {
                nonce: NONCE,
                results: want,
            }),
            "the outcome"
        );
    }

    #[test]
    fn apply_staged_applies_nothing_unless_its_start_is_recorded() {
        let held_variables = staged(None, None).with(
            "BootCurrent",
            EFI_GLOBAL_VARIABLE,
            &BOOT_OPTION.to_le_bytes(),
        );
        let variables = FailingSet {
            held: &held_variables,
            failing: key(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID),
        };
        let driver = StagedDriver::new(&held_variables);

        let application = apply_staged(&variables, &NONCE.to_string(), &driver);

        let full = "no space for UefisettingsStagedOutcome-dd16f539-09ed-41b9-8b64-d85d6cd93a8e";
        let not_applied =
            format!("not applied, as recording that uefisettings.efi started failed: {full}");
        let want = vec![
            RequestOutcome {
                request: request(1),
                applied: false,
                result: not_applied.clone(),
                warnings: Vec::new(),
            },
            RequestOutcome {
                request: including_request(),
                applied: false,
                result: not_applied,
                warnings: Vec::new(),
            },
        ];
        assert_eq!(
            application,
            Application {
                results: Some(want),
                deleted: vec![key("Boot0007", EFI_GLOBAL_VARIABLE)],
                failures: vec![
                    format!("record that uefisettings.efi started: {full}"),
                    format!("record the outcome: {full}"),
                ],
            },
            "the application"
        );
        assert!(driver.asked.borrow().is_empty(), "no request applied");
        assert!(
            !held(&held_variables, "Boot0007", EFI_GLOBAL_VARIABLE),
            "the Boot#### deleted all the same"
        );
    }

    /// The package list of `root`, with no strings.
    fn package_list(root: &Rc<RefCell<IFROperation>>) -> ParsedPackageList {
        ParsedPackageList {
            guid: NIL_GUID,
            device_path: None,
            strings: Vec::new(),
            forms: vec![Rc::clone(root)],
            ignored_ifr: Vec::new(),
            outside_ifr: Vec::new(),
            malformed_outside_stores: Vec::new(),
            disabled_forms: Vec::new(),
            first_var_stores: Vec::new(),
        }
    }

    /// The package list of a PASSWORD question that keeps its password in the outcome record.
    fn password_in_outcome_record() -> ParsedPackageList {
        package_list(&parse_form_set(&[
            var_store_efi_of(
                1,
                UEFISETTINGS_VENDOR_GUID.into(),
                STAGED_OUTCOME,
                NV_BS_RT,
                40,
            ),
            form(1, &[password_on(0x10, 1, 1, 0)]),
        ]))
    }

    /// apply-staged writes through the variables without the bytes of PASSWORD questions: where
    /// a PASSWORD question keeps its password in the outcome record, its start is never recorded,
    /// so it applies no request, and the record is never written; the Boot#### goes all the same.
    #[test]
    fn apply_staged_writes_no_password_byte() {
        let held_variables = staged(None, None).with(
            "BootCurrent",
            EFI_GLOBAL_VARIABLE,
            &BOOT_OPTION.to_le_bytes(),
        );
        let driver = StagedDriver::new(&held_variables);

        let application = apply_staged_withholding(
            &[password_in_outcome_record()],
            &held_variables,
            &NONCE.to_string(),
            &driver,
        )
        .expect("the bytes of every password known");

        let refusal = format!(
            "EFI variable {} holds a password at bytes 0..40, which set never writes",
            key(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID)
        );
        let not_applied =
            format!("not applied, as recording that uefisettings.efi started failed: {refusal}");
        assert_eq!(
            application,
            Application {
                results: Some(vec![
                    RequestOutcome {
                        request: request(1),
                        applied: false,
                        result: not_applied.clone(),
                        warnings: Vec::new(),
                    },
                    RequestOutcome {
                        request: including_request(),
                        applied: false,
                        result: not_applied,
                        warnings: Vec::new(),
                    },
                ]),
                deleted: vec![key("Boot0007", EFI_GLOBAL_VARIABLE)],
                failures: vec![
                    format!("record that uefisettings.efi started: {refusal}"),
                    format!("record the outcome: {refusal}"),
                ],
            },
            "the application"
        );
        assert!(driver.asked.borrow().is_empty(), "no request applied");
        assert!(
            !held_variables
                .set
                .borrow()
                .contains(&key(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID)),
            "the outcome record never written"
        );
        assert!(
            !held(&held_variables, "Boot0007", EFI_GLOBAL_VARIABLE),
            "the Boot#### deleted all the same"
        );
    }

    /// Where IFR that uefisettings ignores may hold a PASSWORD question, whose bytes are then
    /// unknown, apply-staged applies, records and deletes nothing.
    #[test]
    fn apply_staged_writes_nothing_without_the_bytes_of_every_password() {
        let held_variables = staged(None, None).with(
            "BootCurrent",
            EFI_GLOBAL_VARIABLE,
            &BOOT_OPTION.to_le_bytes(),
        );
        let mut ignored = password_in_outcome_record();
        ignored.ignored_ifr = vec![IgnoredIfr {
            package_list: NIL_GUID,
            offset: 4,
            reason: "an op that uefisettings cannot decode".to_owned(),
            passwords: IgnoredPasswords::Declared(Arc::default()),
        }];
        let driver = StagedDriver::new(&held_variables);

        let application =
            apply_staged_withholding(&[ignored], &held_variables, &NONCE.to_string(), &driver);

        assert_eq!(
            application.map_err(|error| format!("{error:#}")),
            Err(format!(
                "PASSWORD questions of package list {NIL_GUID} may be in the IFR that \
                 uefisettings ignores at offset 4 of a form package: an op that uefisettings \
                 cannot decode; as the variable of that password is unknown, the UEFI Shell \
                 build reads and writes no variable of this HiiDB"
            )),
            "the application"
        );
        assert!(driver.asked.borrow().is_empty(), "no request applied");
        assert!(
            held_variables.set.borrow().is_empty() && held_variables.deleted.borrow().is_empty(),
            "nothing written or deleted"
        );
        assert!(
            held(&held_variables, "Boot0007", EFI_GLOBAL_VARIABLE),
            "the Boot#### stays"
        );
    }

    /// Beside a PASSWORD that its driver may keep in any variable, one of VarStoreId 0, which
    /// names no VarStore, or one that edk2 may route to a VARSTORE_NAME_VALUE, apply-staged
    /// reads, applies, records and deletes nothing, as the password is unresolved, also of
    /// staged_set()'s request staged with --i-am-fine-to-brick-this-system. Beside a PASSWORD on
    /// a buffer VarStore it applies the requests.
    #[test]
    fn apply_staged_writes_nothing_where_a_driver_may_keep_a_password_in_any_variable() {
        use crate::hii::forms::ifr_fixtures::var_store;
        use crate::hii::forms::ifr_fixtures::var_store_name_value;

        for var_store_id in [0, 3, 1] {
            let held_variables = staged(None, None).with(
                "BootCurrent",
                EFI_GLOBAL_VARIABLE,
                &BOOT_OPTION.to_le_bytes(),
            );
            let name_value = package_list(&parse_form_set(&[
                var_store(1, [0x11; 16], "Store", 48),
                var_store_name_value(3, [0x33; 16]),
                form(1, &[password_on(0x10, 1, var_store_id, 4)]),
            ]));
            let driver = StagedDriver::new(&held_variables);

            let application = apply_staged_withholding(
                &[name_value],
                &held_variables,
                &NONCE.to_string(),
                &driver,
            )
            .map_err(|error| format!("{error:#}"));

            match var_store_id {
                1 => assert_eq!(
                    driver.asked.borrow().len(),
                    2,
                    "VarStoreId 1: the requests applied: {application:?}"
                ),
                _ => {
                    assert!(
                        application.as_ref().is_err_and(|error| {
                            error.starts_with("PASSWORD question 0x0010 in FormSet ")
                                && (var_store_id != 0
                                    || error.contains(": VarStoreId 0 names no VarStore, "))
                                && error.ends_with(
                                    "; as the variable of that password is unknown, the UEFI \
                                     Shell build reads and writes no variable of this HiiDB",
                                )
                        }),
                        "VarStoreId {var_store_id}: the application: {application:?}"
                    );
                    assert_eq!(
                        held_variables.read.borrow().as_slice(),
                        [],
                        "VarStoreId {var_store_id}: no variable read"
                    );
                    assert!(driver.asked.borrow().is_empty(), "no request applied");
                    assert!(
                        held_variables.set.borrow().is_empty()
                            && held_variables.deleted.borrow().is_empty(),
                        "nothing written or deleted"
                    );
                    assert!(
                        held(&held_variables, "Boot0007", EFI_GLOBAL_VARIABLE),
                        "the Boot#### stays"
                    );
                }
            }
        }
    }

    #[test]
    fn apply_staged_without_a_staged_set_of_its_nonce_applies_and_records_nothing() {
        let other = OTHER_NONCE.to_string();
        let started_from = |variables: HeldVariables, nonce: Nonce| {
            variables
                .with("Boot0009", EFI_GLOBAL_VARIABLE, &boot_option(nonce))
                .with("BootCurrent", EFI_GLOBAL_VARIABLE, &0x0009u16.to_le_bytes())
        };
        let cases = [
            (
                "another nonce's set",
                started_from(staged(None, None), OTHER_NONCE),
                other.clone(),
                format!("the staged set has the nonce {NONCE}, not {other}"),
                vec![key("Boot0009", EFI_GLOBAL_VARIABLE)],
            ),
            (
                "no set",
                started_from(HeldVariables::default(), OTHER_NONCE),
                other.clone(),
                format!("no set is staged, so none of the nonce {other}"),
                vec![key("Boot0009", EFI_GLOBAL_VARIABLE)],
            ),
            (
                "BootCurrent of another command line",
                started_from(HeldVariables::default(), NONCE),
                other.clone(),
                format!("no set is staged, so none of the nonce {other}"),
                Vec::new(),
            ),
            (
                "a malformed nonce",
                started_from(staged(None, None), OTHER_NONCE),
                "a5".to_owned(),
                "the command line's nonce: \"a5\" is not 32 lowercase hexadecimal digits"
                    .to_owned(),
                Vec::new(),
            ),
        ];
        for (case, variables, nonce, failure, deleted) in cases {
            let driver = StagedDriver::new(&variables);

            let application = apply_staged(&variables, &nonce, &driver);

            assert_eq!(
                application,
                Application {
                    results: None,
                    deleted: deleted.clone(),
                    failures: vec![failure.clone()],
                },
                "{case}"
            );
            assert_eq!(
                application.lines(),
                deleted
                    .iter()
                    .map(|key| format!("deleted {}", key.name))
                    .chain([format!("failed: {failure}")])
                    .collect::<Vec<_>>(),
                "{case}: the lines"
            );
            assert!(driver.asked.borrow().is_empty(), "{case}: nothing applied");
            assert!(
                variables.set.borrow().is_empty(),
                "{case}: nothing recorded"
            );
            assert_eq!(*variables.deleted.borrow(), deleted, "{case}: deleted");
        }
    }
}
