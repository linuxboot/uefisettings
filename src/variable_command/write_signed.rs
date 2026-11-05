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

//! variable write-signed: writes a pre-signed payload to an EFI variable, which the firmware
//! verifies (UEFI 2.11 §8.2.6).

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use clap::ValueEnum;
use uefisettings::exports::VariableAttributes;
use uefisettings::exports::VariableBackend;

use crate::platform;

/// The variable, the attributes and the payload file of a signed write.
#[derive(Debug, Args)]
pub(super) struct WriteSignedArgs {
    /// The variable, such as db
    name: String,
    /// The vendor GUID of the variable, such as D719B2CB-3D3A-4596-A3BC-DAD00E67656F
    guid: String,
    /// The attributes that the payload was signed with, but EFI_VARIABLE_APPEND_WRITE, which --append names, and EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, which uefisettings adds
    #[arg(long, value_enum, value_delimiter = ',', required = true)]
    attributes: Vec<SignedAttributeArg>,
    /// Append the payload's data to the variable (EFI_VARIABLE_APPEND_WRITE), if the payload was signed with that attribute
    #[arg(long)]
    append: bool,
    /// The payload: an EFI_VARIABLE_AUTHENTICATION_2 descriptor and then the new data of the variable (UEFI 2.11 section 8.2.6), which uefisettings writes unchanged
    #[arg(long)]
    payload_file: PathBuf,
}

/// An attribute of EFI variables (UEFI 2.11 §8.2.1) that a signed write takes as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SignedAttributeArg {
    NonVolatile,
    BootserviceAccess,
    RuntimeAccess,
}

impl From<SignedAttributeArg> for VariableAttributes {
    fn from(attribute: SignedAttributeArg) -> Self {
        match attribute {
            SignedAttributeArg::NonVolatile => Self::NON_VOLATILE,
            SignedAttributeArg::BootserviceAccess => Self::BOOTSERVICE_ACCESS,
            SignedAttributeArg::RuntimeAccess => Self::RUNTIME_ACCESS,
        }
    }
}

impl WriteSignedArgs {
    /// Writes the payload file to the variable, printing nothing.
    pub(super) fn run(&self) -> Result<()> {
        let payload = platform::read_payload(&self.payload_file)?;
        VariableBackend::write_signed(&self.name, &self.guid, self.attributes(), &payload)
    }

    /// The attributes that these name.
    fn attributes(&self) -> VariableAttributes {
        self.attributes
            .iter()
            .copied()
            .map(VariableAttributes::from)
            .chain(self.append.then_some(VariableAttributes::APPEND_WRITE))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::Parser;

    use super::*;
    use crate::variable_command::VariableSubcommands;
    use crate::Commands;
    use crate::UefiSettingsToolArgs;

    /// The arguments of `uefisettings variable write-signed` and then `args`, or the kind of
    /// error that their parse fails with.
    fn write_signed(args: &[&str]) -> std::result::Result<WriteSignedArgs, clap::error::ErrorKind> {
        let argv = [&["uefisettings", "variable", "write-signed"][..], args].concat();
        let command = UefiSettingsToolArgs::try_parse_from(&argv)
            .map_err(|error| error.kind())?
            .command;
        match command {
            Commands::Variable(variable) => match variable.command {
                VariableSubcommands::WriteSigned(args) => Ok(args),
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{argv:?} is no write-signed: {parsed:?}")
                }
                parsed @ (VariableSubcommands::List { .. }
                | VariableSubcommands::Get { .. }
                | VariableSubcommands::Set { .. }
                | VariableSubcommands::Storage { .. }) => {
                    panic!("{argv:?} is no write-signed: {parsed:?}")
                }
            },
            other => panic!("{argv:?} is no variable command: {other:?}"),
        }
    }

    /// write-signed takes the variable, its vendor GUID, the attributes and the payload file,
    /// and APPEND_WRITE only with --append.
    #[test]
    fn write_signed_takes_a_variable_attributes_and_a_payload_file() {
        let db = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F";
        let nv_bs_rt = VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS;
        let cases: [(&[&str], VariableAttributes); 3] = [
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "non-volatile,bootservice-access,runtime-access",
                    "--append",
                    "--payload-file",
                    "db.auth",
                ],
                nv_bs_rt | VariableAttributes::APPEND_WRITE,
            ),
            (
                &[
                    "db",
                    db,
                    "--payload-file",
                    "db.auth",
                    "--attributes",
                    "non-volatile,bootservice-access",
                    "--attributes",
                    "runtime-access",
                ],
                nv_bs_rt,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "bootservice-access",
                    "--payload-file",
                    "db.auth",
                ],
                VariableAttributes::BOOTSERVICE_ACCESS,
            ),
        ];

        for (args, want) in cases {
            let parsed = write_signed(args).unwrap_or_else(|kind| panic!("parse {args:?}: {kind}"));

            assert_eq!(
                (
                    parsed.name.as_str(),
                    parsed.guid.as_str(),
                    parsed.attributes(),
                    parsed.payload_file.as_path()
                ),
                ("db", db, want, Path::new("db.auth")),
                "{args:?}"
            );
        }
    }

    /// write-signed needs the variable, its vendor GUID, --attributes and --payload-file, and
    /// takes no attribute that a signed write does not take as given.
    #[test]
    fn write_signed_refuses_missing_arguments_and_other_attributes() {
        use clap::error::ErrorKind::InvalidValue;
        use clap::error::ErrorKind::MissingRequiredArgument;

        let db = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F";
        let cases: [(&[&str], clap::error::ErrorKind); 7] = [
            (
                &["db", "--attributes", "non-volatile", "--payload-file", "p"],
                MissingRequiredArgument,
            ),
            (&["db", db, "--payload-file", "p"], MissingRequiredArgument),
            (
                &["db", db, "--attributes", "non-volatile"],
                MissingRequiredArgument,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "append-write",
                    "--payload-file",
                    "p",
                ],
                InvalidValue,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "time-based-authenticated-write-access",
                    "--payload-file",
                    "p",
                ],
                InvalidValue,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "hardware-error-record",
                    "--payload-file",
                    "p",
                ],
                InvalidValue,
            ),
            (
                &["db", db, "--attributes", "", "--payload-file", "p"],
                InvalidValue,
            ),
        ];

        for (args, want) in cases {
            assert_eq!(write_signed(args).err(), Some(want), "{args:?}");
        }
    }

    /// Each attribute of write-signed names the one of its spec name.
    #[test]
    fn signed_attributes_are_the_spec_attributes() {
        for attribute in SignedAttributeArg::value_variants() {
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

    /// The payload is the bytes of its file, and a missing file is an error that names it.
    #[cfg(not(target_os = "uefi"))]
    #[test]
    fn payload_is_the_file_byte_for_byte() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("db.auth");
        let payload = (0..=255).collect::<Vec<u8>>();
        std::fs::write(&path, &payload).expect("write the payload file");

        assert_eq!(
            platform::read_payload(&path).map_err(|error| error.to_string()),
            Ok(payload),
            "present"
        );
        let missing = dir.path().join("missing.auth");
        assert_eq!(
            platform::read_payload(&missing).map_err(|error| error.to_string()),
            Err(format!("read the payload {}", missing.display())),
            "missing"
        );
    }
}
