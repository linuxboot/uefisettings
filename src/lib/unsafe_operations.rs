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

//! The one grant that lets uefisettings do what it otherwise refuses because it can leave the
//! machine unbootable, weaken Secure Boot or bypass its setup password: UnsafeOperations::Allow,
//! which the CLI's --i-am-fine-to-brick-this-system gives. Each command checks it after every
//! refusal that it cannot lift, so a refusal names the flag only where the flag lets the
//! operation through, and returns the operations that it lifted, with its error too when it then
//! fails (LiftedOperations).

use std::fmt;

use thiserror::Error;

use crate::hii::forms::IncludedStates;
use crate::hii::forms::ReadOnlyCause;

/// The flag of the CLI that grants UnsafeOperations::Allow, which every refusal of an
/// UnsafeOperation names.
pub const UNSAFE_OPERATIONS_FLAG: &str = "--i-am-fine-to-brick-this-system";

/// Whether a command does the unsafe operations that it meets, or refuses them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum UnsafeOperations {
    #[default]
    Refuse,
    Allow,
}

impl UnsafeOperations {
    /// Refuses `operation` unless this allows it; returns it, lifted, if it does.
    pub(crate) fn check(
        self,
        operation: UnsafeOperation,
    ) -> Result<UnsafeOperation, UnsafeOperationRefused> {
        match self {
            Self::Refuse => Err(UnsafeOperationRefused { operation }),
            Self::Allow => Ok(operation),
        }
    }
}

/// An operation that uefisettings refuses unless UnsafeOperations allows it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UnsafeOperation {
    /// A write, in the UEFI Shell, in a HiiDB that declares a setup password question, which no
    /// setup browser there asks for
    SetupPassword,
    /// A write of `question`, which EFI_IFR_FLAG_READ_ONLY makes read-only; including the
    /// condition states `writable` selects a writable question of its text instead
    ReadOnlyQuestion {
        question: String,
        writable: IncludedStates,
    },
}

impl UnsafeOperation {
    /// What UnsafeOperations::Allow lets uefisettings do, as a refusal and a warning name it.
    fn unlock(&self) -> &'static str {
        match self {
            Self::SetupPassword => "write without it",
            Self::ReadOnlyQuestion { .. } => "write it",
        }
    }

    /// What a refusal of the operation names besides the flag: another way to an operation
    /// that is not unsafe, if any.
    fn alternative(&self) -> String {
        match self {
            Self::ReadOnlyQuestion { writable, .. } if !writable.is_empty() => {
                format!(", or also include {writable} questions to select a writable one")
            }
            Self::SetupPassword | Self::ReadOnlyQuestion { .. } => String::new(),
        }
    }

    /// The warning, without its "warning: ", that the CLI prints for the operation once it was
    /// lifted.
    pub fn lifted_warning(&self) -> String {
        format!(
            "{self}; {UNSAFE_OPERATIONS_FLAG} lets uefisettings {}",
            self.unlock()
        )
    }
}

impl fmt::Display for UnsafeOperation {
    /// What the operation is, and what it can do.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SetupPassword => f.write_str(
                "this HiiDB declares a setup password question, and the UEFI Shell runs no setup \
                 browser, so no password is asked or checked",
            ),
            Self::ReadOnlyQuestion { question, .. } => write!(
                f,
                "cannot set question {question:?}: {}",
                ReadOnlyCause::Flag
            ),
        }
    }
}

/// The refusal of `operation`, without UnsafeOperations::Allow.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "{operation}; pass {UNSAFE_OPERATIONS_FLAG} to {}{}",
    .operation.unlock(),
    .operation.alternative()
)]
pub struct UnsafeOperationRefused {
    /// What was refused
    pub operation: UnsafeOperation,
}

/// The unsafe operations of one command, which it checks together after every refusal that the
/// grant cannot lift, right before its first write.
#[derive(Debug)]
pub(crate) struct PendingOperations {
    grant: UnsafeOperations,
    operations: Vec<UnsafeOperation>,
}

impl PendingOperations {
    /// No operation yet, to check against `grant`.
    pub(crate) fn new(grant: UnsafeOperations) -> Self {
        Self {
            grant,
            operations: Vec::new(),
        }
    }

    /// The grant that it checks against.
    pub(crate) fn grant(&self) -> UnsafeOperations {
        self.grant
    }

    /// Takes in `operation`, which the command does, once.
    pub(crate) fn add(&mut self, operation: UnsafeOperation) {
        if !self.operations.contains(&operation) {
            self.operations.push(operation);
        }
    }

    /// Refuses the first operation taken in unless the grant allows them; returns them all,
    /// lifted, if it does.
    pub(crate) fn check(self) -> Result<Vec<UnsafeOperation>, UnsafeOperationRefused> {
        let grant = self.grant;
        self.operations
            .into_iter()
            .map(|operation| grant.check(operation))
            .collect()
    }
}

/// The unsafe operations that a command lifted before it failed, as the context of its error,
/// which the CLI warns of as it warns of those of a command that succeeds.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedOperations(pub Vec<UnsafeOperation>);

impl LiftedOperations {
    /// `error` with `lifted` before the operations of its LiftedOperations, if it has one, else
    /// with LiftedOperations of `lifted` as its context; `error` as it is if `lifted` is empty.
    pub fn attach(lifted: Vec<UnsafeOperation>, mut error: anyhow::Error) -> anyhow::Error {
        if lifted.is_empty() {
            return error;
        }
        match error.downcast_mut::<Self>() {
            Some(Self(carried)) => {
                carried.splice(0..0, lifted);
                error
            }
            None => error.context(Self(lifted)),
        }
    }

    /// `result` of what a command did after it lifted `lifted`: its value with them, or its
    /// error with them (attach).
    pub fn after<T>(
        lifted: Vec<UnsafeOperation>,
        result: anyhow::Result<T>,
    ) -> anyhow::Result<(T, Vec<UnsafeOperation>)> {
        match result {
            Ok(value) => Ok((value, lifted)),
            Err(error) => Err(Self::attach(lifted, error)),
        }
    }
}

impl fmt::Display for LiftedOperations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "after {} unsafe operation(s) that {UNSAFE_OPERATIONS_FLAG} let through",
            self.0.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No default grants an unsafe operation.
    #[test]
    fn the_default_refuses() {
        assert_eq!(UnsafeOperations::default(), UnsafeOperations::Refuse);
        assert_eq!(
            UnsafeOperations::default().check(UnsafeOperation::SetupPassword),
            Err(UnsafeOperationRefused {
                operation: UnsafeOperation::SetupPassword
            }),
            "the default grant"
        );
    }

    /// Allow lifts an operation and returns it; Refuse refuses it, naming the flag and what it
    /// unlocks after what the operation is.
    #[test]
    fn check_lifts_only_with_allow() {
        assert_eq!(
            UnsafeOperations::Allow.check(UnsafeOperation::SetupPassword),
            Ok(UnsafeOperation::SetupPassword),
            "Allow"
        );
        let refused = UnsafeOperations::Refuse
            .check(UnsafeOperation::SetupPassword)
            .expect_err("Refuse");
        assert_eq!(
            refused.to_string(),
            "this HiiDB declares a setup password question, and the UEFI Shell runs no setup \
             browser, so no password is asked or checked; pass --i-am-fine-to-brick-this-system \
             to write without it",
            "the refusal"
        );
        assert_eq!(
            UnsafeOperation::SetupPassword.lifted_warning(),
            "this HiiDB declares a setup password question, and the UEFI Shell runs no setup \
             browser, so no password is asked or checked; --i-am-fine-to-brick-this-system lets \
             uefisettings write without it",
            "the warning"
        );
    }

    /// A write of a read-only question names the question and the flag, and the states that
    /// select a writable question of its text where there are any; its warning names those of
    /// neither.
    #[test]
    fn read_only_question_names_a_writable_one() {
        let read_only = |writable| UnsafeOperation::ReadOnlyQuestion {
            question: "R".to_owned(),
            writable,
        };
        let cases = [
            (IncludedStates::empty(), ""),
            (
                IncludedStates::GRAYED_OUT | IncludedStates::DISABLED,
                ", or also include grayed-out,disabled questions to select a writable one",
            ),
        ];
        for (writable, alternative) in cases {
            let operation = read_only(writable);
            assert_eq!(
                UnsafeOperations::Refuse
                    .check(operation.clone())
                    .map_err(|refused| refused.to_string()),
                Err(format!(
                    "cannot set question \"R\": EFI_IFR_FLAG_READ_ONLY makes it read-only (UEFI \
                     2.11 §33.3.8.2.2); pass --i-am-fine-to-brick-this-system to write \
                     it{alternative}"
                )),
                "{writable:?}: the refusal"
            );
            assert_eq!(
                operation.lifted_warning(),
                "cannot set question \"R\": EFI_IFR_FLAG_READ_ONLY makes it read-only (UEFI 2.11 \
                 §33.3.8.2.2); --i-am-fine-to-brick-this-system lets uefisettings write it",
                "{writable:?}: the warning"
            );
        }
    }

    /// PendingOperations refuses the first operation without Allow, returns each once with it,
    /// and checks nothing when it holds none.
    #[test]
    fn pending_operations_are_checked_together() {
        let pending = |grant| {
            let mut pending = PendingOperations::new(grant);
            pending.add(UnsafeOperation::SetupPassword);
            pending.add(UnsafeOperation::SetupPassword);
            pending.check()
        };
        assert_eq!(
            pending(UnsafeOperations::Allow),
            Ok(vec![UnsafeOperation::SetupPassword]),
            "Allow"
        );
        assert_eq!(
            pending(UnsafeOperations::Refuse),
            Err(UnsafeOperationRefused {
                operation: UnsafeOperation::SetupPassword
            }),
            "Refuse"
        );
        assert_eq!(
            PendingOperations::new(UnsafeOperations::Refuse).check(),
            Ok(Vec::new()),
            "none"
        );
    }

    /// attach gives an error LiftedOperations as its context, which later contexts keep and
    /// which the error's own type still downcasts beside; it puts the operations of an earlier
    /// step before those that the error already carries, in one context, and leaves an error
    /// without operations as it is.
    #[test]
    fn attach_keeps_every_lifted_operation_with_the_error() {
        let refused = UnsafeOperationRefused {
            operation: UnsafeOperation::SetupPassword,
        };

        let error =
            LiftedOperations::attach(vec![UnsafeOperation::SetupPassword], refused.clone().into())
                .context("set failed");
        assert_eq!(
            error.downcast_ref::<LiftedOperations>(),
            Some(&LiftedOperations(vec![UnsafeOperation::SetupPassword])),
            "attached"
        );
        assert_eq!(
            error.downcast_ref::<UnsafeOperationRefused>(),
            Some(&refused),
            "the error's own type"
        );
        assert_eq!(
            format!("{error:#}"),
            format!(
                "set failed: after 1 unsafe operation(s) that --i-am-fine-to-brick-this-system \
                 let through: {refused}"
            ),
            "the error as the CLI prints it"
        );

        let merged = LiftedOperations::attach(vec![UnsafeOperation::SetupPassword], error);
        assert_eq!(
            merged.downcast_ref::<LiftedOperations>(),
            Some(&LiftedOperations(vec![UnsafeOperation::SetupPassword; 2])),
            "merged"
        );
        assert_eq!(
            merged.chain().count(),
            3,
            "one LiftedOperations context: {merged:#}"
        );
        let read_only = UnsafeOperation::ReadOnlyQuestion {
            question: "R".to_owned(),
            writable: IncludedStates::empty(),
        };
        let earlier = LiftedOperations::attach(vec![read_only.clone()], merged);
        assert_eq!(
            earlier.downcast_ref::<LiftedOperations>(),
            Some(&LiftedOperations(vec![
                read_only,
                UnsafeOperation::SetupPassword,
                UnsafeOperation::SetupPassword
            ])),
            "an earlier step's first"
        );

        let unchanged = LiftedOperations::attach(Vec::new(), anyhow::anyhow!("write failed"));
        assert_eq!(
            unchanged.downcast_ref::<LiftedOperations>(),
            None,
            "nothing lifted"
        );
        assert_eq!(format!("{unchanged:#}"), "write failed", "nothing lifted");
    }

    /// after returns the value of what succeeded with the operations lifted before it, and the
    /// error of what failed with them as its context.
    #[test]
    fn after_returns_the_lifted_operations_with_the_result() {
        assert_eq!(
            LiftedOperations::after(vec![UnsafeOperation::SetupPassword], Ok(7))
                .map_err(|error| format!("{error:#}")),
            Ok((7, vec![UnsafeOperation::SetupPassword])),
            "success"
        );

        let error = LiftedOperations::after::<()>(
            vec![UnsafeOperation::SetupPassword],
            Err(anyhow::anyhow!("write failed")),
        )
        .expect_err("failure");
        assert_eq!(
            error.downcast_ref::<LiftedOperations>(),
            Some(&LiftedOperations(vec![UnsafeOperation::SetupPassword])),
            "failure"
        );
    }
}
