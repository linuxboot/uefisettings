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

#[cfg(not(all(variable_names, variable_storage_info)))]
use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
#[cfg(variable_storage_info)]
use serde::Serialize;
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
        /// The variable, such as Timeout, BootOrder, SecureBoot or db
        name: String,
        /// The vendor GUID of the variable, which must be its own:
        /// D719B2CB-3D3A-4596-A3BC-DAD00E67656F for db, dbx, dbt and dbr, else
        /// 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
        guid: Option<String>,
    },
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
            VariableSubcommands::Storage { attributes } => storage(attributes),
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
    let global = VariableBackend::get(name, guid)?;
    print_line(format_args!("{}", serde_json::to_string(&global)?))?;
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
                parsed @ VariableSubcommands::Get { .. } => {
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
            parsed @ VariableSubcommands::Get { .. } => panic!("{args:?} is no info: {parsed:?}"),
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
                | VariableSubcommands::Storage { .. }) => {
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
                parsed @ VariableSubcommands::Get { .. } => {
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
