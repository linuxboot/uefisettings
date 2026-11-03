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

//! The part of the CLI that only the Windows build has: the HiiDB of this machine through
//! the HiiDB driver, its variables through the firmware environment calls, and -f/--filename
//! for a HiiDB file.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::SetupPasswordPolicy;

use crate::extract_db_report;
use crate::hii_get;
use crate::hii_set;
use crate::print_line;
use crate::write_extracted_db;
use crate::SelectionArgs;

/// The about of hii, whose commands read this machine's HiiDB or a file.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this machine's HiiDB, as hii get does.
pub(super) const GET_ABOUT: &str = "Get the current value of a question";
/// The about of top-level set, which writes this machine's variables, as hii set does.
pub(super) const SET_ABOUT: &str = "Set/change the value of a question";

/// Installs no logger, so that log's macros write nothing.
pub(super) fn init_logging() {}

/// None: ilo and identify need Linux.
#[derive(Debug, Subcommand)]
pub(super) enum PlatformCommands {}

impl PlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match *self {}
    }
}

/// extract-db only: dump-efivars needs the portable dump reader, which does not exist.
#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {
    /// Dump HiiDB into a file
    #[command(next_display_order = None)]
    ExtractDB { filename: PathBuf },
}

impl HiiPlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::ExtractDB { filename } => {
                write_extracted_db(filename, HiiBackend::export_hiidb)?;

                print_line(format_args!("{}", extract_db_report(filename)))?;
            }
        }
        Ok(())
    }
}

/// Where list-strings, which takes no --efivars, reads the HiiDB: as the other hii commands do.
pub(super) type ListStringsHiiDbArgs = HiiDbArgs;

/// Where a hii command reads the HiiDB.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiDbArgs {
    /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
    #[arg(short, long)]
    pub(super) filename: Option<PathBuf>,
}

impl HiiDbArgs {
    /// The HiiDB: the file, else this machine's, through the HiiDB driver.
    pub(super) fn read(&self, efivars: &EfivarSource) -> Result<Vec<u8>> {
        HiiBackend::read_hiidb(self.filename.as_deref(), efivars)
    }
}

/// Where get, show-ifr and list-questions read question values.
#[derive(Debug, Args)]
pub(super) struct EfivarArgs {
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB still comes from -f or the HiiDB driver)
    #[arg(long)]
    no_efivars: bool,
}

impl EfivarArgs {
    /// The source these flags name.
    pub(super) fn source(&self) -> Result<EfivarSource> {
        Ok(match self.no_efivars {
            false => EfivarSource::System,
            true => EfivarSource::Disabled,
        })
    }
}

/// None: Windows writes through the firmware environment calls, which reach runtime
/// variables like efivarfs, so set takes no setup password policy, as on Linux.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct SetupPasswordArgs {}

impl SetupPasswordArgs {
    /// The default, which set through the firmware environment calls does not consult.
    pub(super) fn policy(&self) -> SetupPasswordPolicy {
        SetupPasswordPolicy::default()
    }
}

/// get, in this machine's HiiDB.
pub(super) fn auto_get(question: &str, json: bool, selection: &SelectionArgs) -> Result<()> {
    hii_get(
        &HiiBackend::export_hiidb()?,
        question,
        &GetOptions::from(selection),
        json,
    )
}

/// set, in this machine's HiiDB.
pub(super) fn auto_set(
    question: &str,
    value: &str,
    json: bool,
    selection: &SelectionArgs,
    setup_password: &SetupPasswordArgs,
) -> Result<()> {
    hii_set(question, value, selection, setup_password, json)
}
