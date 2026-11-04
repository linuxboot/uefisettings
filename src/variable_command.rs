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

//! The variable command: this machine's EFI variables, never their data.

#[cfg(not(variable_names))]
use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
#[cfg(variable_names)]
use uefisettings::exports::VariableBackend;
#[cfg(variable_names)]
use uefisettings::exports::VariableKey;

#[cfg(variable_names)]
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
}

impl VariableCommand {
    pub(super) fn run(&self) -> Result<()> {
        match &self.command {
            VariableSubcommands::List { guid } => list(guid.as_deref()),
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
            let VariableSubcommands::List { guid } = variable(args);

            assert_eq!(guid.as_deref(), want, "{args:?}");
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
