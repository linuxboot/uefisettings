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

//! The part of the CLI that only the Linux build has: the commands ilo, identify, hii
//! extract-db and hii dump-efivars, the flag --efivars, and the machine's backend for get and
//! set.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use uefisettings::exports::identify_machine;
use uefisettings::exports::DumpEfivarsOptions;
use uefisettings::exports::EfivarDump;
use uefisettings::exports::EfivarRedaction;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::IloBackend;
use uefisettings::exports::SetOptions;
use uefisettings::exports::SettingsBackend;
use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::MachineInfo;

use crate::get_db_dump_bytes;
use crate::print_line;
use crate::print_with_style;
use crate::JsonArgs;
use crate::SelectionArgs;

#[derive(Debug, Subcommand)]
pub(super) enum PlatformCommands {
    /// Commands which work on machines having HPE's Ilo BMC
    Ilo(IloCommand),
    /// Auto-identify backend and display hardware/bios-information
    #[command(next_display_order = None)]
    Identify {
        #[command(flatten)]
        output: JsonArgs,
    },
}

impl PlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::Ilo(ilo_command) => match &ilo_command.command {
                IloSubcommands::Get { question, output } => {
                    let res = IloBackend::get(question, None)?;
                    print_with_style(res, output.json)?;
                }
                IloSubcommands::Set {
                    question,
                    value,
                    output,
                } => {
                    let res = IloBackend::set(question, value, None)?;
                    print_with_style(res, output.json)?;
                }
                IloSubcommands::ShowAttributes { output } => {
                    let res = IloBackend::show_attributes()?;
                    print_with_style(res, output.json)?;
                }
                IloSubcommands::ShowPendingAttributes { output } => {
                    let res = IloBackend::show_pending_attributes()?;
                    print_with_style(res, output.json)?;
                }
            },
            Self::Identify { output } => {
                let machine = identify_machine();
                print_with_style(machine, output.json)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(next_display_order = None)]
pub(super) struct IloCommand {
    #[command(subcommand)]
    command: IloSubcommands,
}

#[derive(Debug, Subcommand)]
enum IloSubcommands {
    /// Get the current value of a question
    #[command(next_display_order = None)]
    Get {
        question: String,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// Set/change the value of a question
    #[command(next_display_order = None)]
    Set {
        question: String,
        value: String,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// List bios attributes and their current values
    #[command(next_display_order = None)]
    ShowAttributes {
        #[command(flatten)]
        output: JsonArgs,
    },
    /// List all pending changes that will take effect after reboot
    #[command(next_display_order = None)]
    ShowPendingAttributes {
        #[command(flatten)]
        output: JsonArgs,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {
    /// Dump HiiDB into a file
    #[command(next_display_order = None)]
    ExtractDB { filename: PathBuf },
    /// Copy the HiiDB and the EFI variables that its questions read into a new directory, for --efivars on another machine
    #[command(next_display_order = None)]
    DumpEfivars {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[arg(short, long)]
        filename: Option<PathBuf>,
        /// Copy whole EFI variables, not only the bytes that questions decode; the others can hold secrets such as password hashes
        #[arg(long)]
        unredacted: bool,
        /// The directory to create
        #[arg(value_name = "DIR")]
        directory: PathBuf,
    },
}

impl HiiPlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::ExtractDB { filename } => {
                let mut file = File::create(filename)?;
                let res = HiiBackend::extract_db()?;
                file.write_all(&res.db)?;

                print_line(format_args!("{}", extract_db_report(filename)))?;
            }
            Self::DumpEfivars {
                filename,
                unredacted,
                directory,
            } => {
                let mut options = DumpEfivarsOptions::default();
                options.redaction = match unredacted {
                    true => EfivarRedaction::Unredacted,
                    false => EfivarRedaction::DecodedBytes,
                };
                let dump = HiiBackend::dump_efivars(
                    &get_db_dump_bytes(filename.as_deref())?,
                    directory,
                    &options,
                )?;
                eprintln!("{}", dump_warning(directory, options.redaction));
                print_line(format_args!(
                    "{}",
                    dump_report(directory, options.redaction, dump)
                ))?;
            }
        }
        Ok(())
    }
}

/// Where get, show-ifr and list-questions read question values.
#[derive(Debug, Args)]
pub(super) struct EfivarArgs {
    /// Read question values from the efivar files in this directory (efivarfs format) instead of this machine's efivarfs; without --filename, also the HiiDB if dump-efivars wrote the directory
    #[arg(long, value_name = "DIR", conflicts_with = "no_efivars")]
    efivars: Option<PathBuf>,
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB still comes from --filename or this machine)
    #[arg(long)]
    no_efivars: bool,
}

impl EfivarArgs {
    /// The source these flags name.
    pub(super) fn source(&self) -> Result<EfivarSource> {
        match (&self.efivars, self.no_efivars) {
            (None, false) => Ok(EfivarSource::System),
            (None, true) => Ok(EfivarSource::Disabled),
            (Some(dir), false) => Ok(EfivarSource::Directory(dir.clone())),
            (Some(_), true) => Err(anyhow!("--efivars and --no-efivars conflict")),
        }
    }
}

impl SelectionArgs {
    /// Fails if any state is included or an access level stated: Ilo attributes have no IFR
    /// conditions.
    pub(super) fn refuse_on_ilo(&self) -> Result<()> {
        match (self.include.as_slice(), self.access_level) {
            ([], None) => Ok(()),
            ([_, ..], None) => Err(anyhow!(
                "--include applies to the HII backend, not to the Ilo backend of this machine"
            )),
            ([], Some(_)) => Err(anyhow!(
                "--access-level applies to the HII backend, not to the Ilo backend of this machine"
            )),
            ([_, ..], Some(_)) => Err(anyhow!(
                "--include and --access-level apply to the HII backend, not to the Ilo backend of \
                 this machine"
            )),
        }
    }
}

/// get, on this machine's backend.
pub(super) fn auto_get(question: &str, json: bool, selection: &SelectionArgs) -> Result<()> {
    let machine = identify_machine();
    if machine.backend.contains(&Backend::Unknown) {
        return Err(anyhow!("unknown backend"));
    }
    if prioritize_backend(&machine, json)? == Backend::Ilo {
        selection.refuse_on_ilo()?;
        let res = IloBackend::get(question, None)?;
        print_with_style(res, json)?;
    } else {
        let res = HiiBackend::get_using(
            &get_db_dump_bytes(None)?,
            question,
            None,
            &GetOptions::from(selection),
        )?;
        print_with_style(res, json)?;
    }
    Ok(())
}

/// set, on this machine's backend.
pub(super) fn auto_set(
    question: &str,
    value: &str,
    json: bool,
    selection: &SelectionArgs,
) -> Result<()> {
    let machine = identify_machine();
    if machine.backend.contains(&Backend::Unknown) {
        return Err(anyhow!("unknown backend"));
    }
    if prioritize_backend(&machine, json)? == Backend::Ilo {
        selection.refuse_on_ilo()?;
        let res = IloBackend::set(question, value, None)?;
        print_with_style(res, json)?;
    } else {
        let res = HiiBackend::set_using(question, value, None, &SetOptions::from(selection))?;
        print_with_style(res, json)?;
    }
    Ok(())
}

fn prioritize_backend(machine: &MachineInfo, json: bool) -> Result<Backend> {
    if machine.backend.len() > 1 && !json {
        print_line(format_args!(
            "Multiple backends found: {:#?}",
            machine.backend
        ))?;
        print_line(format_args!("Using the Ilo backend"))?;
    }
    // ilo is prioritized because its more structured than hii if there are multiple supported backends
    // only those two are supported for now
    if machine.backend.contains(&Backend::Ilo) {
        Ok(Backend::Ilo)
    } else {
        Ok(Backend::Hii)
    }
}

/// What extract-db prints on stdout about the HiiDB written to `path`.
fn extract_db_report(path: &Path) -> serde_json::Value {
    serde_json::json!({ "info": format!("HiiDB written to {}", path.display()) })
}

/// What dump-efivars prints on stdout about `dump` into `dir`.
fn dump_report(dir: &Path, redaction: EfivarRedaction, dump: EfivarDump) -> serde_json::Value {
    serde_json::json!({
        "info": format!(
            "copied {} of the {} EFI variables that questions read, and the HiiDB, to {}",
            dump.copied.len(),
            dump.copied.len() + dump.missing.len(),
            dir.display()
        ),
        "directory": dir.display().to_string(),
        // as the dump's manifest records it
        "redaction": redaction,
        "copied": dump.copied,
        "missing": dump.missing,
    })
}

/// What dump-efivars warns on stderr about a dump into `dir`.
fn dump_warning(dir: &Path, redaction: EfivarRedaction) -> String {
    match redaction {
        EfivarRedaction::DecodedBytes => format!(
            "warning: {} holds the HiiDB, whose strings can name the machine, and EFI variables \
             redacted to the bytes that questions decode, whose values can still be secrets; \
             share it only with people you trust",
            dir.display()
        ),
        EfivarRedaction::Unredacted => format!(
            "warning: {} holds the HiiDB, whose strings can name the machine, and whole EFI \
             variables, not redacted, which can hold secrets such as password hashes; share it \
             only with people you trust",
            dir.display()
        ),
        _ => format!(
            "warning: {} holds the HiiDB, whose strings can name the machine, and EFI variables, \
             which can hold secrets such as password hashes; share it only with people you trust",
            dir.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_db_report_is_json_of_the_path() {
        let report = extract_db_report(Path::new("db \"q\" \\ x.bin")).to_string();

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&report).expect("parse the report"),
            serde_json::json!({ "info": "HiiDB written to db \"q\" \\ x.bin" }),
            "a path holding a quote and a backslash"
        );
    }

    #[test]
    fn dump_report_is_json_of_the_dump() {
        let mut dump = EfivarDump::default();
        dump.copied = vec!["Setup-guid".to_string()];
        dump.missing = vec!["Gone-guid".to_string()];
        let cases = [
            ("redacted", EfivarRedaction::DecodedBytes, "decoded-bytes"),
            ("unredacted", EfivarRedaction::Unredacted, "unredacted"),
        ];

        for (case, redaction, json) in cases {
            let report = dump_report(Path::new("out"), redaction, dump.clone()).to_string();

            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&report).expect("parse the report"),
                serde_json::json!({
                    "info": "copied 1 of the 2 EFI variables that questions read, and the HiiDB, \
                             to out",
                    "directory": "out",
                    "redaction": json,
                    "copied": ["Setup-guid"],
                    "missing": ["Gone-guid"],
                }),
                "{case}"
            );
        }
    }

    #[test]
    fn dump_warning_names_redaction_and_secrets() {
        let cases = [
            (
                "redacted",
                EfivarRedaction::DecodedBytes,
                "warning: out holds the HiiDB, whose strings can name the machine, and EFI \
                 variables redacted to the bytes that questions decode, whose values can still \
                 be secrets; share it only with people you trust",
            ),
            (
                "unredacted",
                EfivarRedaction::Unredacted,
                "warning: out holds the HiiDB, whose strings can name the machine, and whole \
                 EFI variables, not redacted, which can hold secrets such as password hashes; \
                 share it only with people you trust",
            ),
        ];

        for (case, redaction, warning) in cases {
            assert_eq!(dump_warning(Path::new("out"), redaction), warning, "{case}");
        }
    }
}
