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

//! The Secure Boot modes of UEFI 2.11 §32.3, which SetupMode, AuditMode and DeployedMode tell
//! (§3.3), and the transitions between them that variable set makes, each behind its own flag.
//! Firmware may queue a transition to Audit Mode for the next reset instead of making it at once
//! (§32.3), which SetVariable() returns as EFI_WARN_RESET_REQUIRED, or EFI_ALREADY_STARTED while
//! one is queued; set reports either as returned. The transition to Deployed Mode takes effect
//! immediately (§32.3, §32.3.4), so EFI_WARN_RESET_REQUIRED there is a firmware departure that set
//! reports as returned too.

use std::fmt;

use anyhow::Result;
use serde::Serialize;
use thiserror::Error;

use super::globals::GlobalContents;
use super::globals::GlobalValue;
use super::globals::GlobalVariable;
use super::globals::EFI_GLOBAL_VARIABLE;
use super::SetVariableStatus;
use super::VariableContents;
use super::VariableData;
use crate::hii::VariableAttributes;
use crate::hii::VariableKey;
use crate::hii::VariableReach;

/// The variable of EFI_GLOBAL_VARIABLE that tells whether the firmware writes the Secure Boot
/// Policy Variables without checking their signatures (UEFI 2.11 §3.3): 1 in Setup Mode and in
/// Audit Mode (§32.3.3).
pub(super) const SETUP_MODE: &str = "SetupMode";
const AUDIT_MODE: &str = "AuditMode";
const DEPLOYED_MODE: &str = "DeployedMode";
/// What a transition sets its variable to: "a new UEFI variable AuditMode is set to 1" (UEFI
/// 2.11 §32.3.3).
const ENTER: u8 = 1;
/// ENTER as variable set takes it.
const ENTER_TEXT: &str = "1";

/// A Secure Boot mode transition of UEFI 2.11 §32.3 that variable set makes behind its own flag.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModeTransition {
    /// AuditMode set to 1: "Entering Audit Mode has the side effect of changing SetupMode == 1,
    /// PK is cleared, and the new DeployedMode == 0" (§32.3.3)
    EnterAuditModeClearingPk,
    /// DeployedMode set to 1, from User Mode: "Entering Deployed Mode has the side effect of
    /// changing SetupMode == 0, AuditMode == 0 and is made read-only, and DeployedMode == 1 and
    /// is made read-only" (§32.3.4)
    EnterDeployedModeIrreversibly,
}

impl ModeTransition {
    /// The variable that the transition sets to 1.
    pub const fn variable(self) -> &'static str {
        match self {
            Self::EnterAuditModeClearingPk => AUDIT_MODE,
            Self::EnterDeployedModeIrreversibly => DEPLOYED_MODE,
        }
    }

    /// The flag of variable set that asks for the transition.
    pub const fn flag(self) -> &'static str {
        match self {
            Self::EnterAuditModeClearingPk => "--enter-audit-mode-clearing-pk",
            Self::EnterDeployedModeIrreversibly => "--enter-deployed-mode-irreversibly",
        }
    }

    /// Why the transition takes its flag, in the words of UEFI 2.11.
    pub(crate) const fn consequence(self) -> &'static str {
        match self {
            Self::EnterAuditModeClearingPk => {
                "\"Entering Audit Mode has the side effect of changing SetupMode == 1, PK is \
                 cleared, and the new DeployedMode == 0\" (UEFI 2.11 section 32.3.3)"
            }
            Self::EnterDeployedModeIrreversibly => {
                "\"to move from Deployed Mode to any other mode requires a secure \
                 platform-specific method, or deleting the PK, which is authenticated\" (UEFI \
                 2.11 section 32.3)"
            }
        }
    }

    /// Refuses the transition from `mode` unless UEFI 2.11 §32.3 allows it.
    fn check_from(self, mode: SecureBootMode) -> std::result::Result<(), ModeTransitionError> {
        match (self, mode) {
            (Self::EnterAuditModeClearingPk, SecureBootMode::Setup | SecureBootMode::User) => {
                Ok(())
            }
            (Self::EnterAuditModeClearingPk, SecureBootMode::Audit) => {
                Err(ModeTransitionError::AlreadyIn(mode))
            }
            (Self::EnterAuditModeClearingPk, SecureBootMode::Deployed) => {
                Err(ModeTransitionError::AuditModeInDeployedMode)
            }
            (Self::EnterDeployedModeIrreversibly, SecureBootMode::User) => Ok(()),
            (Self::EnterDeployedModeIrreversibly, SecureBootMode::Setup) => {
                Err(ModeTransitionError::DeployedModeInSetupMode)
            }
            (Self::EnterDeployedModeIrreversibly, SecureBootMode::Audit) => {
                Err(ModeTransitionError::DeployedModeInAuditMode)
            }
            (Self::EnterDeployedModeIrreversibly, SecureBootMode::Deployed) => {
                Err(ModeTransitionError::AlreadyIn(mode))
            }
        }
    }
}

/// A Secure Boot mode of UEFI 2.11 §32.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecureBootMode {
    Setup,
    User,
    Audit,
    Deployed,
}

impl SecureBootMode {
    /// The mode that SetupMode `setup`, AuditMode `audit` and DeployedMode `deployed` tell, each 1
    /// as true and 0 as false, if any: "The system is in "Setup Mode" when SetupMode==1,
    /// AuditMode==0, and DeployedMode==0" (UEFI 2.11 §3.3); User Mode is the PK enrolled, so
    /// SetupMode 0 (§32.3), "while the variable AuditMode == 0" and outside Deployed Mode;
    /// Audit Mode is AuditMode 1 with "SetupMode == 1, PK is cleared, and the new DeployedMode
    /// == 0" (§32.3.3); Deployed Mode is DeployedMode 1 with "SetupMode == 0, AuditMode == 0"
    /// (§32.3.4).
    fn from_variables(setup: bool, audit: bool, deployed: bool) -> Option<Self> {
        match (setup, audit, deployed) {
            (true, false, false) => Some(Self::Setup),
            (false, false, false) => Some(Self::User),
            (true, true, false) => Some(Self::Audit),
            (false, false, true) => Some(Self::Deployed),
            _ => None,
        }
    }
}

impl fmt::Display for SecureBootMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Setup => "Setup Mode",
            Self::User => "User Mode",
            Self::Audit => "Audit Mode",
            Self::Deployed => "Deployed Mode",
        })
    }
}

/// What variable set tells of a transition that it asked the firmware for: what it wrote, as
/// variable get prints it, and what SetVariable() returned.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModeTransitionWrite {
    /// What it wrote, as variable get prints it
    #[serde(flatten)]
    pub written: GlobalVariable,
    /// What SetVariable() returned
    pub status: ModeTransitionStatus,
}

/// What SetVariable() returned for a transition that the firmware took (UEFI 2.11 §32.3).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum ModeTransitionStatus {
    /// The firmware made the transition
    #[serde(rename = "EFI_SUCCESS")]
    Success,
    /// The firmware queued the transition, which a reset processes; until then "The Secure Boot
    /// Mode and Policy variables SHALL remain unchanged"
    #[serde(rename = "EFI_WARN_RESET_REQUIRED")]
    WarnResetRequired,
}

/// A transition that variable set asks for by setting its variable to 1 through variables that
/// boot services still reach, which set_mode makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModeRequest {
    transition: ModeTransition,
}

impl ModeRequest {
    /// `transition`, which setting the global variable `name` to `text` through variables that
    /// reach `reach` asks for. Refuses, before any variable is read, any other variable or value,
    /// and a write after ExitBootServices().
    pub(crate) fn new(
        transition: ModeTransition,
        reach: VariableReach,
        name: &str,
        text: &str,
    ) -> Result<Self> {
        if name != transition.variable() {
            return Err(ModeTransitionError::OtherVariable {
                transition,
                name: name.to_owned(),
            }
            .into());
        }
        if text != ENTER_TEXT {
            return Err(ModeTransitionError::OtherValue {
                transition,
                text: text.to_owned(),
            }
            .into());
        }
        match reach {
            VariableReach::Runtime => {
                Err(ModeTransitionError::AfterExitBootServices(transition).into())
            }
            VariableReach::BootServices => Ok(Self { transition }),
        }
    }
}

/// Sets the variable of `request` to 1 in `variables` to make its transition, after checking
/// that the current Secure Boot mode allows it; returns what it wrote and what SetVariable()
/// returned. Refuses, before any write, a firmware without the mode variables or with values that
/// tell no mode, and a transition that UEFI 2.11 §32.3 does not make from the current mode.
pub(crate) fn set_mode(
    variables: &impl VariableData,
    request: ModeRequest,
) -> Result<ModeTransitionWrite> {
    let transition = request.transition;
    let modes = ModeVariables::read(variables)?;
    transition.check_from(modes.mode()?)?;

    let key = mode_key(transition.variable());
    let attributes = modes.attributes(transition);
    let contents = VariableContents::new(attributes, vec![ENTER])?;
    let status = match variables.set_variable(&key, &contents) {
        Ok(()) => ModeTransitionStatus::Success,
        Err(error) => match error.downcast_ref::<SetVariableStatus>() {
            Some(SetVariableStatus::WarnResetRequired(_)) => {
                ModeTransitionStatus::WarnResetRequired
            }
            Some(SetVariableStatus::AlreadyStarted(_)) => {
                return Err(ModeTransitionError::AlreadyStarted.into())
            }
            None => return Err(error),
        },
    };
    Ok(ModeTransitionWrite {
        written: GlobalVariable {
            variable: key.to_string(),
            contents: Some(GlobalContents {
                attributes: attributes.bits(),
                value: GlobalValue::Byte(ENTER),
            }),
        },
        status,
    })
}

/// SetupMode, AuditMode and DeployedMode as a firmware holds them, 1 as true and 0 as false,
/// with the attributes of the two that transitions set.
struct ModeVariables {
    setup: bool,
    audit: (VariableAttributes, bool),
    deployed: (VariableAttributes, bool),
}

impl ModeVariables {
    /// The mode variables of `variables`, unless any is absent or holds other than a UINT8 of 0
    /// or 1 (UEFI 2.11 §3.3).
    fn read(variables: &impl VariableData) -> Result<Self> {
        let setup = mode_variable(variables, SETUP_MODE)?;
        let audit = mode_variable(variables, AUDIT_MODE)?;
        let deployed = mode_variable(variables, DEPLOYED_MODE)?;
        match (setup, audit, deployed) {
            (Some((_, setup)), Some(audit), Some(deployed)) => Ok(Self {
                setup,
                audit,
                deployed,
            }),
            (setup, audit, deployed) => {
                let absent = [
                    (SETUP_MODE, setup.is_none()),
                    (AUDIT_MODE, audit.is_none()),
                    (DEPLOYED_MODE, deployed.is_none()),
                ]
                .into_iter()
                .filter_map(|(name, absent)| absent.then_some(name))
                .collect();
                Err(ModeTransitionError::Absent(absent).into())
            }
        }
    }

    /// The Secure Boot mode that these tell.
    fn mode(&self) -> std::result::Result<SecureBootMode, ModeTransitionError> {
        let (setup, audit, deployed) = (self.setup, self.audit.1, self.deployed.1);
        SecureBootMode::from_variables(setup, audit, deployed).ok_or(ModeTransitionError::NoMode {
            setup,
            audit,
            deployed,
        })
    }

    /// The attributes of the variable that `transition` sets, which it keeps.
    fn attributes(&self, transition: ModeTransition) -> VariableAttributes {
        match transition {
            ModeTransition::EnterAuditModeClearingPk => self.audit.0,
            ModeTransition::EnterDeployedModeIrreversibly => self.deployed.0,
        }
    }
}

/// The attributes and value of the mode variable `name` of `variables`, if present, unless it
/// holds other than a UINT8 of 0 or 1 (UEFI 2.11 §3.3).
pub(super) fn mode_variable(
    variables: &impl VariableData,
    name: &'static str,
) -> Result<Option<(VariableAttributes, bool)>> {
    let Some(contents) = variables.variable_data(&mode_key(name))? else {
        return Ok(None);
    };
    let value = match contents.data() {
        [0] => false,
        [1] => true,
        [value] => {
            return Err(ModeVariableError::Value {
                name,
                value: *value,
            }
            .into())
        }
        data => {
            return Err(ModeVariableError::Size {
                name,
                size: data.len(),
            }
            .into())
        }
    };
    Ok(Some((contents.attributes(), value)))
}

/// The global variable `name`.
fn mode_key(name: &str) -> VariableKey {
    VariableKey {
        name: name.to_owned(),
        guid: EFI_GLOBAL_VARIABLE,
    }
}

/// A mode variable that holds other than a UINT8 of 0 or 1 (UEFI 2.11 §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum ModeVariableError {
    #[error("{name} holds {size} bytes, not the 1 of a UINT8 (UEFI 2.11 section 3.3)")]
    Size { name: &'static str, size: usize },
    #[error("{name} is {value}, neither 0 nor 1 (UEFI 2.11 section 3.3)")]
    Value { name: &'static str, value: u8 },
}

/// A transition that variable set refuses before it writes anything, or that the firmware did
/// not take.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum ModeTransitionError {
    #[error("{} sets {}, not {name}", .transition.flag(), .transition.variable())]
    OtherVariable {
        transition: ModeTransition,
        name: String,
    },
    #[error("{} sets {} to {ENTER_TEXT}, not \"{text}\"", .transition.flag(), .transition.variable())]
    OtherValue {
        transition: ModeTransition,
        text: String,
    },
    #[error(
        "{} \"Always becomes read-only after ExitBootServices() is called\" (UEFI 2.11 section \
         3.3): run `uefisettings.efi variable set {} {ENTER_TEXT} {}` in the UEFI Shell",
        .0.variable(),
        .0.variable(),
        .0.flag()
    )]
    AfterExitBootServices(ModeTransition),
    #[error(
        "{} absent, which UEFI 2.11 sections 3.3 and 32.3 define for the Secure Boot modes, so \
         the firmware tells no mode to check the transition against",
        absent_names(.0)
    )]
    Absent(Vec<&'static str>),
    #[error(
        "SetupMode {}, AuditMode {} and DeployedMode {} tell no Secure Boot mode of UEFI 2.11 \
         section 32.3",
        u8::from(*setup),
        u8::from(*audit),
        u8::from(*deployed)
    )]
    NoMode {
        setup: bool,
        audit: bool,
        deployed: bool,
    },
    #[error("the firmware is in {0} already")]
    AlreadyIn(SecureBootMode),
    #[error(
        "\"The AuditMode variable is only writable before ExitBootServices() is called when the \
         system is not in Deployed Mode\" (UEFI 2.11 section 32.3.3), and the firmware is in \
         Deployed Mode"
    )]
    AuditModeInDeployedMode,
    #[error(
        "the firmware is in Setup Mode, and \"both User Mode and Audit Mode support \
         unauthenticated transitions to Deployed Mode\" (UEFI 2.11 section 32.3), not Setup Mode: \
         enrolling PK enters User Mode first (section 32.3.1)"
    )]
    DeployedModeInSetupMode,
    #[error(
        "the firmware is in Audit Mode, where \"To enter Deployed Mode from Audit Mode, set the \
         variable PK\" (UEFI 2.11 section 32.3.4): `uefisettings.efi variable write-signed PK \
         8BE4DF61-93CA-11D2-AA0D-00E098032B8C` writes it, with \
         --allow-setup-mode-write-without-signature-check while SetupMode is 1"
    )]
    DeployedModeInAuditMode,
    #[error(
        "the firmware queued a Secure Boot Mode transition already, which a reset processes, so \
         it queued no other (EFI_ALREADY_STARTED, UEFI 2.11 section 32.3)"
    )]
    AlreadyStarted,
}

/// `names`, "NAME is" for one, "NAME and NAME are" for two, "NAME, NAME and NAME are" for three.
fn absent_names(names: &[&str]) -> String {
    match names {
        [] => "no variable is".to_owned(),
        [name] => format!("{name} is"),
        [init @ .., last] => format!("{} and {last} are", init.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use anyhow::anyhow;

    use super::*;
    use crate::hii::VariableInterface;

    /// BS+RT: the attributes of SetupMode, AuditMode and DeployedMode in UEFI 2.11 §3.3.
    const BS_RT: VariableAttributes =
        VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);
    /// NV+BS+RT: attributes that the mode variables lack in UEFI 2.11 §3.3, which a firmware may
    /// give them anyway.
    const NV_BS_RT: VariableAttributes = VariableAttributes::NON_VOLATILE
        .union(VariableAttributes::BOOTSERVICE_ACCESS)
        .union(VariableAttributes::RUNTIME_ACCESS);
    /// NV+BS+RT+AT: the attributes of PK in UEFI 2.11 §3.3.
    const NV_BS_RT_AT: VariableAttributes = VariableAttributes::NON_VOLATILE
        .union(VariableAttributes::BOOTSERVICE_ACCESS)
        .union(VariableAttributes::RUNTIME_ACCESS)
        .union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS);
    /// A PK's data, which the firmware here never parses.
    const PK_DATA: &[u8] = b"PK's signature list";
    /// The modes of UEFI 2.11 §32.3 and their (SetupMode, AuditMode, DeployedMode): §3.3 for
    /// Setup Mode, §32.3 for User Mode, §32.3.3 for Audit Mode and §32.3.4 for Deployed Mode.
    const MODES: [(SecureBootMode, [u8; 3]); 4] = [
        (SecureBootMode::Setup, [1, 0, 0]),
        (SecureBootMode::User, [0, 0, 0]),
        (SecureBootMode::Audit, [1, 1, 0]),
        (SecureBootMode::Deployed, [0, 0, 1]),
    ];

    /// How the fake firmware takes a transition: at once, queued for the next reset (UEFI 2.11
    /// §32.3), or not at all, as a firmware that refuses AuditMode for a reason of its own.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Taking {
        AtOnce,
        Queued,
        Refused,
    }

    /// A firmware that implements the Secure Boot modes as UEFI 2.11 §32.3 words them, a fake of
    /// the §32.3.3 firmware that no edk2 build is: its SetVariable() of AuditMode or DeployedMode
    /// to 1 makes the transition with its side effects, or queues it, and refuses one from a mode
    /// that does not allow it. It records each read and write.
    struct ModeFirmware {
        variables: RefCell<BTreeMap<VariableKey, VariableContents>>,
        taking: Taking,
        queued: RefCell<Option<VariableKey>>,
        read: RefCell<Vec<VariableKey>>,
        written: RefCell<Vec<VariableKey>>,
    }

    impl ModeFirmware {
        /// A firmware in `mode`, with a PK unless SetupMode is 1, that takes transitions as
        /// `taking`.
        fn in_mode(mode: SecureBootMode, taking: Taking) -> Self {
            let (_, values) = MODES
                .into_iter()
                .find(|(each, _)| *each == mode)
                .expect("MODES lists every mode");
            let firmware = Self::with_mode_values(values.map(|value| Some(vec![value])), taking);
            if values[0] == 0 {
                firmware.hold("PK", NV_BS_RT_AT, PK_DATA);
            }
            firmware
        }

        /// A firmware whose SetupMode, AuditMode and DeployedMode hold `values`, None for
        /// absent, without a PK.
        fn with_mode_values(values: [Option<Vec<u8>>; 3], taking: Taking) -> Self {
            let firmware = Self {
                variables: RefCell::default(),
                taking,
                queued: RefCell::default(),
                read: RefCell::default(),
                written: RefCell::default(),
            };
            for (name, value) in [SETUP_MODE, AUDIT_MODE, DEPLOYED_MODE]
                .into_iter()
                .zip(values)
            {
                if let Some(value) = value {
                    firmware.hold(name, BS_RT, &value);
                }
            }
            firmware
        }

        fn hold(&self, name: &str, attributes: VariableAttributes, data: &[u8]) {
            let contents = VariableContents::new(attributes, data.to_vec()).expect("hold data");
            self.variables.borrow_mut().insert(mode_key(name), contents);
        }

        fn value(&self, name: &str) -> Option<Vec<u8>> {
            self.variables
                .borrow()
                .get(&mode_key(name))
                .map(|contents| contents.data().to_vec())
        }

        /// SetupMode, AuditMode and DeployedMode, and whether PK is present.
        fn state(&self) -> ([Option<Vec<u8>>; 3], bool) {
            (
                [SETUP_MODE, AUDIT_MODE, DEPLOYED_MODE].map(|name| self.value(name)),
                self.value("PK").is_some(),
            )
        }

        /// Makes the transition that setting `key` to 1 asks for from the current mode, as
        /// UEFI 2.11 §32.3.3 and §32.3.4 word it, or refuses it.
        fn transition(&self, key: &VariableKey) -> Result<()> {
            let modes = [SETUP_MODE, AUDIT_MODE, DEPLOYED_MODE].map(|name| self.value(name));
            let [setup, audit, deployed] = modes.map(|value| value == Some(vec![1]));
            match (key.name.as_str(), setup, audit, deployed) {
                // "The AuditMode variable is only writable before ExitBootServices() is
                // called when the system is not in Deployed Mode" (§32.3.3)
                (AUDIT_MODE, _, _, false) => {
                    self.hold(SETUP_MODE, BS_RT, &[1]);
                    self.hold(AUDIT_MODE, BS_RT, &[1]);
                    self.hold(DEPLOYED_MODE, BS_RT, &[0]);
                    self.variables.borrow_mut().remove(&mode_key("PK"));
                    Ok(())
                }
                // "To enter Deployed Mode from User Mode, set the variable DeployedMode to 1"
                // (§32.3.4)
                (DEPLOYED_MODE, false, false, false) => {
                    self.hold(SETUP_MODE, BS_RT, &[0]);
                    self.hold(AUDIT_MODE, BS_RT, &[0]);
                    self.hold(DEPLOYED_MODE, BS_RT, &[1]);
                    Ok(())
                }
                _ => Err(anyhow!(
                    "SetVariable() of EFI variable {key}: WRITE_PROTECTED"
                )),
            }
        }
    }

    impl VariableData for ModeFirmware {
        fn interface(&self) -> VariableInterface {
            VariableInterface::VariableServices
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.read.borrow_mut().push(key.clone());
            Ok(self.variables.borrow().get(key).cloned())
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            self.written.borrow_mut().push(key.clone());
            assert_eq!(contents.data(), [ENTER], "the data written to {key}");
            match self.taking {
                Taking::AtOnce => self.transition(key),
                Taking::Queued => match self.queued.replace(Some(key.clone())) {
                    Some(_) => Err(SetVariableStatus::AlreadyStarted(key.clone()).into()),
                    None => Err(SetVariableStatus::WarnResetRequired(key.clone()).into()),
                },
                Taking::Refused => Err(anyhow!(
                    "SetVariable() of EFI variable {key}: SECURITY_VIOLATION"
                )),
            }
        }
    }

    /// What set_mode writes to `name` and tells of the write, as variable get prints it.
    fn write_of(name: &str, status: ModeTransitionStatus) -> ModeTransitionWrite {
        ModeTransitionWrite {
            written: GlobalVariable {
                variable: mode_key(name).to_string(),
                contents: Some(GlobalContents {
                    attributes: BS_RT.bits(),
                    value: GlobalValue::Byte(ENTER),
                }),
            },
            status,
        }
    }

    /// What VariableBackend::set_mode does with `firmware`, which `reach`es: asks for
    /// `transition` by setting `name` to `text`, then makes it.
    fn request_and_set_mode(
        firmware: &ModeFirmware,
        reach: VariableReach,
        name: &str,
        text: &str,
        transition: ModeTransition,
    ) -> Result<ModeTransitionWrite> {
        set_mode(firmware, ModeRequest::new(transition, reach, name, text)?)
    }

    /// The error that request_and_set_mode of `name` to `text` refuses `transition` with in
    /// `firmware`, through `reach`, which must write nothing.
    #[track_caller]
    fn refusal<E>(
        firmware: &ModeFirmware,
        reach: VariableReach,
        name: &str,
        text: &str,
        transition: ModeTransition,
    ) -> E
    where
        E: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        let state = firmware.state();
        let error = request_and_set_mode(firmware, reach, name, text, transition)
            .expect_err("set_mode refuses the transition");
        assert_eq!(
            firmware.written.borrow().as_slice(),
            [],
            "{transition:?} of {name} {text}: no write"
        );
        assert_eq!(
            firmware.state(),
            state,
            "{transition:?} of {name} {text}: the mode variables and PK as they were"
        );
        error
            .downcast::<E>()
            .unwrap_or_else(|error| panic!("{transition:?} of {name} {text}: {error:#}"))
    }

    /// set_mode enters Audit Mode from Setup Mode and from User Mode, writing AuditMode alone:
    /// the firmware sets SetupMode to 1 and DeployedMode to 0, and clears PK (UEFI 2.11
    /// §32.3.3).
    #[test]
    fn set_mode_enters_audit_mode_from_setup_and_user_mode() {
        for mode in [SecureBootMode::Setup, SecureBootMode::User] {
            let firmware = ModeFirmware::in_mode(mode, Taking::AtOnce);

            let write = request_and_set_mode(
                &firmware,
                VariableReach::BootServices,
                AUDIT_MODE,
                ENTER_TEXT,
                ModeTransition::EnterAuditModeClearingPk,
            )
            .unwrap_or_else(|error| panic!("enter Audit Mode from {mode}: {error:#}"));

            assert_eq!(
                write,
                write_of(AUDIT_MODE, ModeTransitionStatus::Success),
                "from {mode}"
            );
            assert_eq!(
                firmware.written.borrow().as_slice(),
                [mode_key(AUDIT_MODE)],
                "from {mode}: AuditMode alone is written"
            );
            assert_eq!(
                firmware.state(),
                ([Some(vec![1]), Some(vec![1]), Some(vec![0])], false),
                "from {mode}: Audit Mode, without PK"
            );
        }
    }

    /// set_mode refuses to enter Audit Mode from Audit Mode, which it is in already, and from
    /// Deployed Mode, where AuditMode is read-only (UEFI 2.11 §32.3.3, §3.3).
    #[test]
    fn set_mode_refuses_audit_mode_from_audit_and_deployed_mode() {
        let cases = [
            (
                SecureBootMode::Audit,
                ModeTransitionError::AlreadyIn(SecureBootMode::Audit),
            ),
            (
                SecureBootMode::Deployed,
                ModeTransitionError::AuditModeInDeployedMode,
            ),
        ];
        for (mode, expected) in cases {
            let firmware = ModeFirmware::in_mode(mode, Taking::AtOnce);

            let error: ModeTransitionError = refusal(
                &firmware,
                VariableReach::BootServices,
                AUDIT_MODE,
                ENTER_TEXT,
                ModeTransition::EnterAuditModeClearingPk,
            );

            assert_eq!(error, expected, "from {mode}");
        }
    }

    /// set_mode enters Deployed Mode from User Mode, writing DeployedMode alone: the firmware
    /// sets SetupMode and AuditMode to 0 and keeps PK (UEFI 2.11 §32.3.4).
    #[test]
    fn set_mode_enters_deployed_mode_from_user_mode() {
        let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::AtOnce);

        let write = request_and_set_mode(
            &firmware,
            VariableReach::BootServices,
            DEPLOYED_MODE,
            ENTER_TEXT,
            ModeTransition::EnterDeployedModeIrreversibly,
        )
        .unwrap_or_else(|error| panic!("enter Deployed Mode from User Mode: {error:#}"));

        assert_eq!(
            write,
            write_of(DEPLOYED_MODE, ModeTransitionStatus::Success),
            "from User Mode"
        );
        assert_eq!(
            firmware.written.borrow().as_slice(),
            [mode_key(DEPLOYED_MODE)],
            "DeployedMode alone is written"
        );
        assert_eq!(
            firmware.state(),
            ([Some(vec![0]), Some(vec![0]), Some(vec![1])], true),
            "Deployed Mode, with PK"
        );
    }

    /// set_mode refuses to enter Deployed Mode from Setup Mode, which UEFI 2.11 §32.3 lists no
    /// unauthenticated transition to it from, from Audit Mode, where enrolling PK enters it
    /// (§32.3.4), and from Deployed Mode, which it is in already.
    #[test]
    fn set_mode_refuses_deployed_mode_from_setup_audit_and_deployed_mode() {
        let cases = [
            (
                SecureBootMode::Setup,
                ModeTransitionError::DeployedModeInSetupMode,
            ),
            (
                SecureBootMode::Audit,
                ModeTransitionError::DeployedModeInAuditMode,
            ),
            (
                SecureBootMode::Deployed,
                ModeTransitionError::AlreadyIn(SecureBootMode::Deployed),
            ),
        ];
        for (mode, expected) in cases {
            let firmware = ModeFirmware::in_mode(mode, Taking::AtOnce);

            let error: ModeTransitionError = refusal(
                &firmware,
                VariableReach::BootServices,
                DEPLOYED_MODE,
                ENTER_TEXT,
                ModeTransition::EnterDeployedModeIrreversibly,
            );

            assert_eq!(error, expected, "from {mode}");
        }
    }

    /// set_mode writes the variable of a transition with that variable's own attributes, as set
    /// keeps those of an existing variable.
    #[test]
    fn set_mode_keeps_the_attributes_of_the_variable_it_sets() {
        let cases = [
            (ModeTransition::EnterAuditModeClearingPk, BS_RT),
            (ModeTransition::EnterDeployedModeIrreversibly, NV_BS_RT),
        ];
        for (transition, attributes) in cases {
            let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::AtOnce);
            firmware.hold(DEPLOYED_MODE, NV_BS_RT, &[0]);

            let write = request_and_set_mode(
                &firmware,
                VariableReach::BootServices,
                transition.variable(),
                ENTER_TEXT,
                transition,
            )
            .unwrap_or_else(|error| panic!("{transition:?}: {error:#}"));

            assert_eq!(
                write.written.contents.map(|contents| contents.attributes),
                Some(attributes.bits()),
                "{transition:?}"
            );
        }
    }

    /// ModeRequest refuses any variable but the transition's, and any value but 1, so set_mode
    /// reads no variable.
    #[test]
    fn set_mode_refuses_other_variables_and_values() {
        let audit = ModeTransition::EnterAuditModeClearingPk;
        let deployed = ModeTransition::EnterDeployedModeIrreversibly;
        let other_variable = |transition, name: &str| ModeTransitionError::OtherVariable {
            transition,
            name: name.to_owned(),
        };
        let other_value = |transition, text: &str| ModeTransitionError::OtherValue {
            transition,
            text: text.to_owned(),
        };
        let cases = [
            (
                audit,
                DEPLOYED_MODE,
                ENTER_TEXT,
                other_variable(audit, DEPLOYED_MODE),
            ),
            (
                audit,
                "Timeout",
                ENTER_TEXT,
                other_variable(audit, "Timeout"),
            ),
            (audit, AUDIT_MODE, "0", other_value(audit, "0")),
            (audit, AUDIT_MODE, "01", other_value(audit, "01")),
            (
                deployed,
                AUDIT_MODE,
                ENTER_TEXT,
                other_variable(deployed, AUDIT_MODE),
            ),
            (deployed, DEPLOYED_MODE, "0", other_value(deployed, "0")),
        ];
        for (transition, name, text, expected) in cases {
            let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::AtOnce);

            let error: ModeTransitionError = refusal(
                &firmware,
                VariableReach::BootServices,
                name,
                text,
                transition,
            );

            assert_eq!(error, expected, "{transition:?} of {name} {text}");
            assert_eq!(
                firmware.read.borrow().as_slice(),
                [],
                "{transition:?} of {name} {text}: no read"
            );
        }
    }

    /// ModeRequest refuses every transition after ExitBootServices(), as from Linux or Windows,
    /// so set_mode reads no variable: AuditMode and DeployedMode "Always become read-only after
    /// ExitBootServices() is called" (UEFI 2.11 §3.3).
    #[test]
    fn set_mode_refuses_after_exit_boot_services() {
        let cases = [
            (
                ModeTransition::EnterAuditModeClearingPk,
                "AuditMode \"Always becomes read-only after ExitBootServices() is called\" (UEFI \
                 2.11 section 3.3): run `uefisettings.efi variable set AuditMode 1 \
                 --enter-audit-mode-clearing-pk` in the UEFI Shell",
            ),
            (
                ModeTransition::EnterDeployedModeIrreversibly,
                "DeployedMode \"Always becomes read-only after ExitBootServices() is called\" \
                 (UEFI 2.11 section 3.3): run `uefisettings.efi variable set DeployedMode 1 \
                 --enter-deployed-mode-irreversibly` in the UEFI Shell",
            ),
        ];
        for (transition, text) in cases {
            let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::AtOnce);

            let error: ModeTransitionError = refusal(
                &firmware,
                VariableReach::Runtime,
                transition.variable(),
                ENTER_TEXT,
                transition,
            );

            assert_eq!(
                error,
                ModeTransitionError::AfterExitBootServices(transition),
                "{transition:?}"
            );
            assert_eq!(
                firmware.read.borrow().as_slice(),
                [],
                "{transition:?}: no read"
            );
            assert_eq!(error.to_string(), text, "{transition:?}");
        }
    }

    /// set_mode refuses a firmware without SetupMode, AuditMode or DeployedMode, such as edk2,
    /// which implements no Audit or Deployed Mode, naming each absent one.
    #[test]
    fn set_mode_refuses_absent_mode_variables() {
        let one = || Some(vec![1]);
        let zero = || Some(vec![0]);
        let cases = [
            ([one(), None, None], vec![AUDIT_MODE, DEPLOYED_MODE]),
            ([zero(), None, None], vec![AUDIT_MODE, DEPLOYED_MODE]),
            (
                [None, None, None],
                vec![SETUP_MODE, AUDIT_MODE, DEPLOYED_MODE],
            ),
            ([zero(), zero(), None], vec![DEPLOYED_MODE]),
            ([zero(), None, zero()], vec![AUDIT_MODE]),
            ([None, zero(), zero()], vec![SETUP_MODE]),
        ];
        let transitions = [
            ModeTransition::EnterAuditModeClearingPk,
            ModeTransition::EnterDeployedModeIrreversibly,
        ];
        for ((values, absent), transition) in cases
            .into_iter()
            .flat_map(|case| transitions.map(|transition| (case.clone(), transition)))
        {
            let firmware = ModeFirmware::with_mode_values(values.clone(), Taking::AtOnce);

            let error: ModeTransitionError = refusal(
                &firmware,
                VariableReach::BootServices,
                transition.variable(),
                ENTER_TEXT,
                transition,
            );

            assert_eq!(
                error,
                ModeTransitionError::Absent(absent),
                "{transition:?} with mode values {values:?}"
            );
        }
    }

    /// set_mode refuses mode variables of other sizes than a UINT8's or of reserved values.
    #[test]
    fn set_mode_refuses_malformed_mode_variables() {
        let byte = |value: u8| Some(vec![value]);
        let cases = [
            (
                [Some(vec![0, 0]), byte(0), byte(0)],
                ModeVariableError::Size {
                    name: SETUP_MODE,
                    size: 2,
                },
            ),
            (
                [byte(0), Some(vec![0, 0, 0, 0]), byte(0)],
                ModeVariableError::Size {
                    name: AUDIT_MODE,
                    size: 4,
                },
            ),
            (
                [byte(0), byte(0), byte(2)],
                ModeVariableError::Value {
                    name: DEPLOYED_MODE,
                    value: 2,
                },
            ),
            (
                [byte(0xFF), byte(0), byte(0)],
                ModeVariableError::Value {
                    name: SETUP_MODE,
                    value: 0xFF,
                },
            ),
        ];
        for (values, expected) in cases {
            let firmware = ModeFirmware::with_mode_values(values.clone(), Taking::AtOnce);

            let error: ModeVariableError = refusal(
                &firmware,
                VariableReach::BootServices,
                AUDIT_MODE,
                ENTER_TEXT,
                ModeTransition::EnterAuditModeClearingPk,
            );

            assert_eq!(error, expected, "mode values {values:?}");
        }
    }

    /// set_mode refuses mode variables whose values tell no mode of UEFI 2.11 §32.3.
    #[test]
    fn set_mode_refuses_mode_variables_that_tell_no_mode() {
        let byte = |value: u8| Some(vec![value]);
        let cases = [
            (
                [byte(0), byte(1), byte(0)],
                ModeTransitionError::NoMode {
                    setup: false,
                    audit: true,
                    deployed: false,
                },
            ),
            (
                [byte(1), byte(0), byte(1)],
                ModeTransitionError::NoMode {
                    setup: true,
                    audit: false,
                    deployed: true,
                },
            ),
            (
                [byte(0), byte(1), byte(1)],
                ModeTransitionError::NoMode {
                    setup: false,
                    audit: true,
                    deployed: true,
                },
            ),
            (
                [byte(1), byte(1), byte(1)],
                ModeTransitionError::NoMode {
                    setup: true,
                    audit: true,
                    deployed: true,
                },
            ),
        ];
        for (values, expected) in cases {
            let firmware = ModeFirmware::with_mode_values(values.clone(), Taking::AtOnce);

            let error: ModeTransitionError = refusal(
                &firmware,
                VariableReach::BootServices,
                AUDIT_MODE,
                ENTER_TEXT,
                ModeTransition::EnterAuditModeClearingPk,
            );

            assert_eq!(error, expected, "mode values {values:?}");
        }
    }

    /// set_mode reports a transition that the firmware queues as EFI_WARN_RESET_REQUIRED, the
    /// mode variables unchanged, and refuses the next, which the firmware refuses with
    /// EFI_ALREADY_STARTED (UEFI 2.11 §32.3).
    #[test]
    fn set_mode_reports_a_queued_transition() {
        let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::Queued);
        let state = firmware.state();
        let set = || {
            request_and_set_mode(
                &firmware,
                VariableReach::BootServices,
                AUDIT_MODE,
                ENTER_TEXT,
                ModeTransition::EnterAuditModeClearingPk,
            )
        };

        let queued = set().expect("the queued transition");
        let error = set().expect_err("a second queued transition");

        assert_eq!(
            queued,
            write_of(AUDIT_MODE, ModeTransitionStatus::WarnResetRequired),
            "the first transition"
        );
        assert_eq!(
            error.downcast_ref::<ModeTransitionError>(),
            Some(&ModeTransitionError::AlreadyStarted),
            "the second transition: {error:#}"
        );
        assert_eq!(
            firmware.state(),
            state,
            "the mode variables and PK as they were"
        );
        assert_eq!(
            firmware.written.borrow().as_slice(),
            [mode_key(AUDIT_MODE), mode_key(AUDIT_MODE)],
            "AuditMode is written twice"
        );
    }

    /// set_mode passes on a failure of SetVariable() other than the two of a queued
    /// transition, which the firmware leaves unmade.
    #[test]
    fn set_mode_passes_on_other_set_variable_failures() {
        let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::Refused);
        let state = firmware.state();

        let error = request_and_set_mode(
            &firmware,
            VariableReach::BootServices,
            AUDIT_MODE,
            ENTER_TEXT,
            ModeTransition::EnterAuditModeClearingPk,
        )
        .expect_err("the firmware's refusal");

        assert_eq!(
            error.to_string(),
            format!(
                "SetVariable() of EFI variable {}: SECURITY_VIOLATION",
                mode_key(AUDIT_MODE)
            ),
            "the firmware's refusal"
        );
        assert_eq!(
            firmware.state(),
            state,
            "the mode variables and PK as they were"
        );
    }

    /// set_mode reports EFI_WARN_RESET_REQUIRED of the Deployed Mode transition as returned,
    /// although UEFI 2.11 §32.3.4 says it "takes effect immediately with no reset required".
    #[test]
    fn set_mode_reports_a_queued_deployed_mode_transition_as_returned() {
        let firmware = ModeFirmware::in_mode(SecureBootMode::User, Taking::Queued);
        let state = firmware.state();

        let queued = request_and_set_mode(
            &firmware,
            VariableReach::BootServices,
            DEPLOYED_MODE,
            ENTER_TEXT,
            ModeTransition::EnterDeployedModeIrreversibly,
        )
        .expect("the queued transition");

        assert_eq!(
            queued,
            write_of(DEPLOYED_MODE, ModeTransitionStatus::WarnResetRequired),
            "the Deployed Mode transition"
        );
        assert_eq!(
            firmware.written.borrow().as_slice(),
            [mode_key(DEPLOYED_MODE)],
            "DeployedMode alone is written"
        );
        assert_eq!(
            firmware.state(),
            state,
            "the mode variables and PK as they were"
        );
    }

    /// What variable set prints of a transition: the variable as get prints it, then the status
    /// of SetVariable().
    #[test]
    fn mode_transition_write_serializes_as_set_prints_it() {
        let cases = [
            (
                ModeTransitionStatus::Success,
                r#"{"variable":"AuditMode-8be4df61-93ca-11d2-aa0d-00e098032b8c","attributes":6,"value":1,"status":"EFI_SUCCESS"}"#,
            ),
            (
                ModeTransitionStatus::WarnResetRequired,
                r#"{"variable":"AuditMode-8be4df61-93ca-11d2-aa0d-00e098032b8c","attributes":6,"value":1,"status":"EFI_WARN_RESET_REQUIRED"}"#,
            ),
        ];
        for (status, json) in cases {
            assert_eq!(
                serde_json::to_string(&write_of(AUDIT_MODE, status)).expect("serialize"),
                json,
                "{status:?}"
            );
        }
    }

    /// The refusals name the variables, the values and the spec's words.
    #[test]
    fn refusals_name_their_reasons() {
        let transition = ModeTransition::EnterAuditModeClearingPk;
        let cases = [
            (
                ModeTransitionError::OtherVariable {
                    transition,
                    name: "Timeout".to_owned(),
                },
                "--enter-audit-mode-clearing-pk sets AuditMode, not Timeout",
            ),
            (
                ModeTransitionError::OtherValue {
                    transition,
                    text: "0".to_owned(),
                },
                "--enter-audit-mode-clearing-pk sets AuditMode to 1, not \"0\"",
            ),
            (
                ModeTransitionError::Absent(vec![AUDIT_MODE, DEPLOYED_MODE]),
                "AuditMode and DeployedMode are absent, which UEFI 2.11 sections 3.3 and 32.3 \
                 define for the Secure Boot modes, so the firmware tells no mode to check the \
                 transition against",
            ),
            (
                ModeTransitionError::Absent(vec![SETUP_MODE, AUDIT_MODE, DEPLOYED_MODE]),
                "SetupMode, AuditMode and DeployedMode are absent, which UEFI 2.11 sections 3.3 \
                 and 32.3 define for the Secure Boot modes, so the firmware tells no mode to \
                 check the transition against",
            ),
            (
                ModeTransitionError::Absent(vec![DEPLOYED_MODE]),
                "DeployedMode is absent, which UEFI 2.11 sections 3.3 and 32.3 define for the \
                 Secure Boot modes, so the firmware tells no mode to check the transition \
                 against",
            ),
            (
                ModeTransitionError::NoMode {
                    setup: false,
                    audit: true,
                    deployed: false,
                },
                "SetupMode 0, AuditMode 1 and DeployedMode 0 tell no Secure Boot mode of UEFI \
                 2.11 section 32.3",
            ),
            (
                ModeTransitionError::AlreadyIn(SecureBootMode::Audit),
                "the firmware is in Audit Mode already",
            ),
            (
                ModeTransitionError::AuditModeInDeployedMode,
                "\"The AuditMode variable is only writable before ExitBootServices() is called \
                 when the system is not in Deployed Mode\" (UEFI 2.11 section 32.3.3), and the \
                 firmware is in Deployed Mode",
            ),
            (
                ModeTransitionError::OtherVariable {
                    transition: ModeTransition::EnterDeployedModeIrreversibly,
                    name: AUDIT_MODE.to_owned(),
                },
                "--enter-deployed-mode-irreversibly sets DeployedMode, not AuditMode",
            ),
            (
                ModeTransitionError::AlreadyIn(SecureBootMode::Deployed),
                "the firmware is in Deployed Mode already",
            ),
            (
                ModeTransitionError::DeployedModeInSetupMode,
                "the firmware is in Setup Mode, and \"both User Mode and Audit Mode support \
                 unauthenticated transitions to Deployed Mode\" (UEFI 2.11 section 32.3), not \
                 Setup Mode: enrolling PK enters User Mode first (section 32.3.1)",
            ),
            (
                ModeTransitionError::DeployedModeInAuditMode,
                "the firmware is in Audit Mode, where \"To enter Deployed Mode from Audit Mode, \
                 set the variable PK\" (UEFI 2.11 section 32.3.4): `uefisettings.efi variable \
                 write-signed PK 8BE4DF61-93CA-11D2-AA0D-00E098032B8C` writes it, with \
                 --allow-setup-mode-write-without-signature-check while SetupMode is 1",
            ),
            (
                ModeTransitionError::AlreadyStarted,
                "the firmware queued a Secure Boot Mode transition already, which a reset \
                 processes, so it queued no other (EFI_ALREADY_STARTED, UEFI 2.11 section 32.3)",
            ),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text, "{error:?}");
        }
    }

    /// The refusals of malformed mode variables name the variable, its size or value, and §3.3.
    #[test]
    fn mode_variable_refusals_name_their_reasons() {
        let cases = [
            (
                ModeVariableError::Size {
                    name: AUDIT_MODE,
                    size: 4,
                },
                "AuditMode holds 4 bytes, not the 1 of a UINT8 (UEFI 2.11 section 3.3)",
            ),
            (
                ModeVariableError::Value {
                    name: DEPLOYED_MODE,
                    value: 2,
                },
                "DeployedMode is 2, neither 0 nor 1 (UEFI 2.11 section 3.3)",
            ),
        ];
        for (error, text) in cases {
            assert_eq!(error.to_string(), text, "{error:?}");
        }
    }
}
