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

//! The variable command: this machine's EFI variables.

use anyhow::anyhow;
use anyhow::Result;
#[cfg(variable_data)]
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
#[cfg(variable_storage_info)]
use serde::Serialize;
#[cfg(variable_data)]
use uefisettings::exports::GlobalVariable;
#[cfg(variable_data)]
use uefisettings::exports::ModeTransition;
#[cfg(variable_storage_info)]
use uefisettings::exports::VariableAttributes;
#[cfg(any(variable_names, variable_info, variable_storage_info, variable_data))]
use uefisettings::exports::VariableBackend;
#[cfg(variable_names)]
use uefisettings::exports::VariableKey;
#[cfg(variable_storage_info)]
use uefisettings::exports::VariableStorage;

#[cfg(any(variable_names, variable_info, variable_storage_info, variable_data))]
use crate::print_line;

#[cfg(variable_data)]
mod write_signed;

#[derive(Debug, Parser)]
#[command(next_display_order = None)]
pub(super) struct VariableCommand {
    #[command(subcommand)]
    command: VariableSubcommands,
}

#[derive(Debug, Subcommand)]
enum VariableSubcommands {
    /// List the name and vendor GUID of every EFI variable, never its data
    #[command(next_display_order = None)]
    List {
        /// List only the variables of this vendor GUID, such as
        /// 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
        #[arg(long)]
        guid: Option<String>,
    },
    /// Show the attributes and the size of an EFI variable, never its data
    #[cfg(variable_info)]
    #[command(next_display_order = None)]
    Info {
        name: String,
        /// The vendor GUID of the variable, such as 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
        guid: String,
    },
    /// Show the attributes and the decoded value of a global variable of UEFI 2.11 section 3.3,
    /// but its load options, hot keys and device paths, or of a signature database, or that it is
    /// absent
    #[cfg(variable_data)]
    #[command(next_display_order = None)]
    Get {
        /// The variable, such as Timeout, BootOrder, SecureBoot, db or devdb
        name: String,
        /// The vendor GUID of the variable, which must be its own:
        /// D719B2CB-3D3A-4596-A3BC-DAD00E67656F for db, dbx, dbt and dbr,
        /// B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD for devdb, else
        /// 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
        guid: Option<String>,
    },
    /// Set a global variable of UEFI 2.11 section 3.3 that the OS may write: Timeout, BootOrder,
    /// DriverOrder, SysPrepOrder, BootNext, PlatformLang or OsIndications; or, in the UEFI Shell,
    /// AuditMode with --enter-audit-mode-clearing-pk and DeployedMode with
    /// --enter-deployed-mode-irreversibly
    #[cfg(variable_data)]
    #[command(next_display_order = None)]
    Set(SetArgs),
    /// Show the storage space of the EFI variables of some attributes, and how much of it is left
    #[command(next_display_order = None)]
    Storage {
        /// The attributes of the variables whose storage to show
        #[arg(
            long,
            value_enum,
            value_delimiter = ',',
            default_values_t = [
                AttributeArg::NonVolatile,
                AttributeArg::BootserviceAccess,
                AttributeArg::RuntimeAccess,
            ],
        )]
        attributes: Vec<AttributeArg>,
    },
    /// Write an EFI variable from a signed payload, or from new data that a key signs; the firmware verifies the signature
    #[cfg(variable_data)]
    #[command(next_display_order = None)]
    WriteSigned(write_signed::WriteSignedArgs),
}

/// What variable set takes.
#[cfg(variable_data)]
#[derive(Debug, Args)]
struct SetArgs {
    /// The variable, such as Timeout
    name: String,
    /// Its value as get shows it, the list comma-separated: seconds or "wait for user input"
    /// for Timeout, load options such as Boot0002,Boot0001 for the orders, one for BootNext,
    /// a code of PlatformLangCodes for PlatformLang, bits such as BOOT_TO_FW_UI, or none,
    /// for OsIndications, which keeps its reserved bits; 1 for AuditMode and DeployedMode
    value: String,
    /// Set AuditMode to 1, in the UEFI Shell, from Setup Mode or User Mode, to enter Audit Mode,
    /// which clears PK and sets SetupMode to 1 and DeployedMode to 0 (UEFI 2.11 section 32.3.3);
    /// the firmware may queue it for the next reset (section 32.3); setting PK then enters
    /// Deployed Mode, not User Mode (UEFI 2.11 section 32.3.4)
    #[arg(long, conflicts_with = "enter_deployed_mode_irreversibly")]
    enter_audit_mode_clearing_pk: bool,
    /// Set DeployedMode to 1, in the UEFI Shell, from User Mode, to enter Deployed Mode
    /// irreversibly: leaving it "requires a secure platform-specific method, or deleting the PK,
    /// which is authenticated" (UEFI 2.11 section 32.3). From Audit Mode, where SetupMode is 1,
    /// enrolling PK enters it instead, as `variable write-signed PK` does with its flag for Setup
    /// Mode (section 32.3.4)
    #[arg(long)]
    enter_deployed_mode_irreversibly: bool,
}

#[cfg(variable_data)]
impl SetArgs {
    /// Sets the variable and prints what it wrote, as print_global prints it, and, for a Secure
    /// Boot mode transition, what SetVariable() returned.
    fn run(&self) -> Result<()> {
        match self.transition()? {
            None => print_global_variable(&VariableBackend::set(&self.name, &self.value)?),
            Some(transition) => {
                let write = VariableBackend::set_mode(&self.name, &self.value, transition)?;
                print_line(format_args!("{}", serde_json::to_string(&write)?))?;
                Ok(())
            }
        }
    }

    /// The Secure Boot mode transition that the flags ask for, if any; clap refuses both.
    fn transition(&self) -> Result<Option<ModeTransition>> {
        match (
            self.enter_audit_mode_clearing_pk,
            self.enter_deployed_mode_irreversibly,
        ) {
            (false, false) => Ok(None),
            (true, false) => Ok(Some(ModeTransition::EnterAuditModeClearingPk)),
            (false, true) => Ok(Some(ModeTransition::EnterDeployedModeIrreversibly)),
            (true, true) => Err(anyhow!(
                "--enter-audit-mode-clearing-pk and --enter-deployed-mode-irreversibly ask for \
                 two transitions"
            )),
        }
    }
}

/// An attribute of EFI variables (UEFI 2.10 §8.2.1), but EFI_VARIABLE_APPEND_WRITE, which
/// QueryVariableInfo() ignores (§8.2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum AttributeArg {
    NonVolatile,
    BootserviceAccess,
    RuntimeAccess,
    HardwareErrorRecord,
    AuthenticatedWriteAccess,
    TimeBasedAuthenticatedWriteAccess,
    EnhancedAuthenticatedAccess,
}

#[cfg(variable_storage_info)]
impl From<AttributeArg> for VariableAttributes {
    fn from(attribute: AttributeArg) -> Self {
        match attribute {
            AttributeArg::NonVolatile => Self::NON_VOLATILE,
            AttributeArg::BootserviceAccess => Self::BOOTSERVICE_ACCESS,
            AttributeArg::RuntimeAccess => Self::RUNTIME_ACCESS,
            AttributeArg::HardwareErrorRecord => Self::HARDWARE_ERROR_RECORD,
            AttributeArg::AuthenticatedWriteAccess => Self::AUTHENTICATED_WRITE_ACCESS,
            AttributeArg::TimeBasedAuthenticatedWriteAccess => {
                Self::TIME_BASED_AUTHENTICATED_WRITE_ACCESS
            }
            AttributeArg::EnhancedAuthenticatedAccess => Self::ENHANCED_AUTHENTICATED_ACCESS,
        }
    }
}

impl VariableCommand {
    pub(super) fn run(&self) -> Result<()> {
        match &self.command {
            VariableSubcommands::List { guid } => list(guid.as_deref()),
            #[cfg(variable_info)]
            VariableSubcommands::Info { name, guid } => print_info(name, guid),
            #[cfg(variable_data)]
            VariableSubcommands::Get { name, guid } => print_global(name, guid.as_deref()),
            #[cfg(variable_data)]
            VariableSubcommands::Set(args) => args.run(),
            VariableSubcommands::Storage { attributes } => storage(attributes),
            #[cfg(variable_data)]
            VariableSubcommands::WriteSigned(args) => args.run(),
        }
    }
}

/// Prints the name and vendor GUID of every EFI variable, of the vendor `guid` only if given.
#[cfg(variable_names)]
fn list(guid: Option<&str>) -> Result<()> {
    let keys = VariableBackend::list(guid)?;
    print_line(format_args!("{}", list_report(&keys)))?;
    Ok(())
}

/// Fails: the Windows build reaches each variable by its name only.
#[cfg(not(variable_names))]
fn list(_guid: Option<&str>) -> Result<()> {
    Err(anyhow!(
        "uefisettings cannot list EFI variables on Windows: the Win32 calls that it uses, \
         GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW, reach a \
         variable by its name only; list them on Linux, or in the UEFI Shell with \
         uefisettings.efi"
    ))
}

/// What list prints on stdout about `keys`: a JSON array of their names and vendor GUIDs,
/// outside the thrift IDL that the hii commands print, and JSON always, as list takes no -j.
#[cfg(variable_names)]
fn list_report(keys: &[VariableKey]) -> serde_json::Value {
    keys.iter()
        .map(|key| serde_json::json!({ "name": key.name, "guid": key.guid.to_string() }))
        .collect()
}

/// Prints the attributes and the size of the EFI variable `name` of the vendor GUID `guid`: info,
/// and hii variable-info of the UEFI Shell build.
#[cfg(variable_info)]
pub(super) fn print_info(name: &str, guid: &str) -> Result<()> {
    let info = VariableBackend::info(name, guid)?;
    // its own JSON object, outside the thrift IDL that the hii commands print, and JSON always,
    // as info takes no -j
    print_line(format_args!("{}", serde_json::to_value(info)?))?;
    Ok(())
}

/// Prints the variable `name`, of the vendor GUID `guid` if given, decoded, as JSON always, as
/// get takes no -j, outside the thrift IDL that the hii commands print.
#[cfg(variable_data)]
fn print_global(name: &str, guid: Option<&str>) -> Result<()> {
    print_global_variable(&VariableBackend::get(name, guid)?)
}

/// Prints `global` as one line of JSON, for print_global and set.
#[cfg(variable_data)]
fn print_global_variable(global: &GlobalVariable) -> Result<()> {
    print_line(format_args!("{}", serde_json::to_string(global)?))?;
    Ok(())
}

/// Prints the storage of the EFI variables of `attributes`.
#[cfg(variable_storage_info)]
fn storage(attributes: &[AttributeArg]) -> Result<()> {
    let attributes = attributes
        .iter()
        .copied()
        .map(VariableAttributes::from)
        .collect();
    let storage = VariableBackend::storage(attributes)?;
    let report = StorageReport {
        attributes: attributes.bits(),
        storage,
    };
    print_line(format_args!("{}", serde_json::to_value(report)?))?;
    Ok(())
}

/// Fails: the Windows build has no QueryVariableInfo().
#[cfg(not(variable_storage_info))]
fn storage(_attributes: &[AttributeArg]) -> Result<()> {
    Err(anyhow!(
        "uefisettings cannot tell the storage of EFI variables on Windows: the Win32 calls that \
         it uses, GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW, have \
         no QueryVariableInfo(); ask Linux, or the UEFI Shell with uefisettings.efi"
    ))
}

/// What storage prints on stdout about the storage of the variables of some attributes: its own
/// JSON object, outside the thrift IDL that the hii commands print, and JSON always, as storage
/// takes no -j.
#[cfg(variable_storage_info)]
#[derive(Serialize)]
struct StorageReport {
    /// The attributes bitmask asked about
    attributes: u32,
    #[serde(flatten)]
    storage: VariableStorage,
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::Commands;
    use crate::UefiSettingsToolArgs;

    /// The variable subcommand that `args`, after `uefisettings variable`, parse to.
    fn variable(args: &[&str]) -> VariableSubcommands {
        let argv = [&["uefisettings", "variable"][..], args].concat();
        match UefiSettingsToolArgs::try_parse_from(&argv)
            .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"))
            .command
        {
            Commands::Variable(variable) => variable.command,
            other => panic!("{argv:?} is no variable command: {other:?}"),
        }
    }

    #[test]
    fn list_takes_a_vendor_guid_if_any() {
        let guid = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C";
        for (args, want) in [
            (&["list"][..], None),
            (&["list", "--guid", guid], Some(guid)),
        ] {
            let guid = match variable(args) {
                VariableSubcommands::List { guid } => guid,
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{args:?} is no list: {parsed:?}")
                }
                #[cfg(variable_data)]
                parsed @ (VariableSubcommands::Get { .. }
                | VariableSubcommands::Set(_)
                | VariableSubcommands::WriteSigned(_)) => {
                    panic!("{args:?} is no list: {parsed:?}")
                }
                parsed @ VariableSubcommands::Storage { .. } => {
                    panic!("{args:?} is no list: {parsed:?}")
                }
            };

            assert_eq!(guid.as_deref(), want, "{args:?}");
        }
    }

    #[cfg(variable_info)]
    #[test]
    fn info_takes_a_name_and_a_vendor_guid() {
        let args = ["info", "Timeout", "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"];

        let (name, guid) = match variable(&args) {
            VariableSubcommands::Info { name, guid } => (name, guid),
            #[cfg(variable_data)]
            parsed @ (VariableSubcommands::Get { .. }
            | VariableSubcommands::Set(_)
            | VariableSubcommands::WriteSigned(_)) => {
                panic!("{args:?} is no info: {parsed:?}")
            }
            parsed @ (VariableSubcommands::List { .. } | VariableSubcommands::Storage { .. }) => {
                panic!("{args:?} is no info: {parsed:?}")
            }
        };

        assert_eq!(
            (name.as_str(), guid.as_str()),
            ("Timeout", "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"),
            "{args:?}"
        );
        let missing =
            UefiSettingsToolArgs::try_parse_from(["uefisettings", "variable", "info", "Timeout"])
                .map_err(|error| error.kind());
        assert_eq!(
            missing.err(),
            Some(clap::error::ErrorKind::MissingRequiredArgument),
            "info without a vendor GUID"
        );
    }

    /// get takes a variable name, and its vendor GUID if given.
    #[cfg(variable_data)]
    #[test]
    fn get_takes_a_name_and_a_vendor_guid_if_any() {
        let db = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F";
        for (args, want) in [
            (&["get", "Timeout"][..], ("Timeout", None)),
            (&["get", "db", db], ("db", Some(db))),
        ] {
            let (name, guid) = match variable(args) {
                VariableSubcommands::Get { name, guid } => (name, guid),
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{args:?} is no get: {parsed:?}")
                }
                parsed @ (VariableSubcommands::List { .. }
                | VariableSubcommands::Set(_)
                | VariableSubcommands::Storage { .. }
                | VariableSubcommands::WriteSigned(_)) => {
                    panic!("{args:?} is no get: {parsed:?}")
                }
            };

            assert_eq!((name.as_str(), guid.as_deref()), want, "{args:?}");
        }
        let missing = UefiSettingsToolArgs::try_parse_from(["uefisettings", "variable", "get"])
            .map_err(|error| error.kind());
        assert_eq!(
            missing.err(),
            Some(clap::error::ErrorKind::MissingRequiredArgument),
            "get without a name"
        );
    }

    /// set takes a variable name and its value, and needs both.
    #[cfg(variable_data)]
    #[test]
    fn set_takes_a_name_and_a_value() {
        for (args, want) in [
            (&["set", "Timeout", "5"][..], ("Timeout", "5")),
            (&["set", "OsIndications", "none"], ("OsIndications", "none")),
        ] {
            let (name, value) = match variable(args) {
                VariableSubcommands::Set(SetArgs { name, value, .. }) => (name, value),
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{args:?} is no set: {parsed:?}")
                }
                parsed @ (VariableSubcommands::List { .. }
                | VariableSubcommands::Get { .. }
                | VariableSubcommands::Storage { .. }
                | VariableSubcommands::WriteSigned(_)) => {
                    panic!("{args:?} is no set: {parsed:?}")
                }
            };

            assert_eq!((name.as_str(), value.as_str()), want, "{args:?}");
        }
        let missing =
            UefiSettingsToolArgs::try_parse_from(["uefisettings", "variable", "set", "Timeout"])
                .map_err(|error| error.kind());
        assert_eq!(
            missing.err(),
            Some(clap::error::ErrorKind::MissingRequiredArgument),
            "set without a value"
        );
    }

    /// set takes --enter-audit-mode-clearing-pk after its name and value, which asks for the
    /// transition to Audit Mode, and asks for none without it.
    #[cfg(variable_data)]
    #[test]
    fn set_takes_the_audit_mode_flag() {
        let transition = ModeTransition::EnterAuditModeClearingPk;
        let (name, flag) = (transition.variable(), transition.flag());
        let argv = ["uefisettings", "variable", "set", name, "1", flag];

        let parsed = UefiSettingsToolArgs::try_parse_from(argv);

        assert!(
            matches!(
                parsed.as_ref().map(|args| &args.command),
                Ok(Commands::Variable(VariableCommand {
                    command: VariableSubcommands::Set(_)
                }))
            ),
            "{argv:?}: {parsed:?}"
        );
        let cases = [
            (&["set", name, "1", flag][..], Some(transition)),
            (&["set", name, "1"], None),
            (&["set", "Timeout", "5"], None),
        ];
        for (args, want) in cases {
            let asked = match variable(args) {
                VariableSubcommands::Set(set) => set.transition().expect("one transition"),
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{args:?} is no set: {parsed:?}")
                }
                parsed @ (VariableSubcommands::List { .. }
                | VariableSubcommands::Get { .. }
                | VariableSubcommands::Storage { .. }
                | VariableSubcommands::WriteSigned(_)) => {
                    panic!("{args:?} is no set: {parsed:?}")
                }
            };

            assert_eq!(asked, want, "{args:?}");
        }
    }

    /// set takes --enter-deployed-mode-irreversibly after its name and value, which asks for the
    /// transition to Deployed Mode, and refuses it with --enter-audit-mode-clearing-pk.
    #[cfg(variable_data)]
    #[test]
    fn set_takes_the_deployed_mode_flag() {
        let deployed = ModeTransition::EnterDeployedModeIrreversibly;
        let argv = [
            "uefisettings",
            "variable",
            "set",
            deployed.variable(),
            "1",
            deployed.flag(),
        ];

        let parsed = UefiSettingsToolArgs::try_parse_from(argv);

        assert!(
            matches!(
                parsed.as_ref().map(|args| &args.command),
                Ok(Commands::Variable(VariableCommand {
                    command: VariableSubcommands::Set(_)
                }))
            ),
            "{argv:?}: {parsed:?}"
        );
        let transition = match variable(&argv[2..]) {
            VariableSubcommands::Set(set) => set.transition().expect("one transition"),
            #[cfg(variable_info)]
            parsed @ VariableSubcommands::Info { .. } => panic!("{argv:?} is no set: {parsed:?}"),
            parsed @ (VariableSubcommands::List { .. }
            | VariableSubcommands::Get { .. }
            | VariableSubcommands::Storage { .. }
            | VariableSubcommands::WriteSigned(_)) => panic!("{argv:?} is no set: {parsed:?}"),
        };
        assert_eq!(transition, Some(deployed), "{argv:?}");
        let both = UefiSettingsToolArgs::try_parse_from(
            [
                &argv[..],
                &[ModeTransition::EnterAuditModeClearingPk.flag()],
            ]
            .concat(),
        )
        .map_err(|error| error.kind());
        assert_eq!(
            both.err(),
            Some(clap::error::ErrorKind::ArgumentConflict),
            "both flags"
        );
    }

    /// storage takes the attributes of non-volatile variables that the OS reaches unless
    /// --attributes names others, and none that it does not name.
    #[test]
    fn storage_takes_attributes() {
        use AttributeArg::*;

        let cases: [(&[&str], Vec<AttributeArg>); 3] = [
            (
                &["storage"],
                vec![NonVolatile, BootserviceAccess, RuntimeAccess],
            ),
            (
                &["storage", "--attributes", "bootservice-access"],
                vec![BootserviceAccess],
            ),
            (
                &[
                    "storage",
                    "--attributes",
                    "non-volatile,bootservice-access",
                    "--attributes",
                    "hardware-error-record",
                ],
                vec![NonVolatile, BootserviceAccess, HardwareErrorRecord],
            ),
        ];
        for (args, want) in cases {
            let attributes = match variable(args) {
                VariableSubcommands::Storage { attributes } => attributes,
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{args:?} is no storage: {parsed:?}")
                }
                #[cfg(variable_data)]
                parsed @ (VariableSubcommands::Get { .. }
                | VariableSubcommands::Set(_)
                | VariableSubcommands::WriteSigned(_)) => {
                    panic!("{args:?} is no storage: {parsed:?}")
                }
                parsed @ VariableSubcommands::List { .. } => {
                    panic!("{args:?} is no storage: {parsed:?}")
                }
            };

            assert_eq!(attributes, want, "{args:?}");
        }
        for value in ["append-write", "0x7", ""] {
            let parsed = UefiSettingsToolArgs::try_parse_from([
                "uefisettings",
                "variable",
                "storage",
                "--attributes",
                value,
            ])
            .map_err(|error| error.kind());

            assert_eq!(
                parsed.err(),
                Some(clap::error::ErrorKind::InvalidValue),
                "--attributes {value:?}"
            );
        }
    }

    /// Each attribute of storage names the one of its spec name.
    #[cfg(variable_storage_info)]
    #[test]
    fn storage_attributes_are_the_spec_attributes() {
        for attribute in AttributeArg::value_variants() {
            let name = attribute
                .to_possible_value()
                .expect("a possible value")
                .get_name()
                .replace('-', "_")
                .to_ascii_uppercase();

            assert_eq!(
                VariableAttributes::from(*attribute).to_string(),
                name,
                "{attribute:?}"
            );
        }
    }

    #[cfg(variable_names)]
    #[test]
    fn list_report_is_a_json_array_of_names_and_vendor_guids() {
        let keys: Vec<VariableKey> = [
            ("BootOrder", "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"),
            ("a!b", "a04a27f4-df00-4d42-b552-39511302113d"),
        ]
        .into_iter()
        .map(|(name, guid)| VariableKey {
            name: name.to_string(),
            guid: guid.parse().expect("parse a GUID"),
        })
        .collect();

        assert_eq!(
            list_report(&keys),
            serde_json::json!([
                { "name": "BootOrder", "guid": "8BE4DF61-93CA-11D2-AA0D-00E098032B8C" },
                { "name": "a!b", "guid": "A04A27F4-DF00-4D42-B552-39511302113D" },
            ]),
            "report"
        );
    }
}
