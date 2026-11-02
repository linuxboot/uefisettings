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

//! The part of the CLI that only the UEFI Shell build has: the HiiDB and the variables of the
//! firmware it runs on, and --bypass-setup-password.

use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::SetupPasswordPolicy;
use uefisettings::exports::VariableInfo;

use crate::hii_get;
use crate::hii_set;
use crate::print_line;
use crate::SelectionArgs;

/// The about of hii, whose commands read this firmware's HII database.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this firmware's HII database, as hii get does.
pub(super) const GET_ABOUT: &str = "Get the current value of a question";
/// The about of top-level set, which writes this firmware's HII database, as hii set does.
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

/// variable-info; extract-db and dump-efivars write files, which this build does not.
#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {
    /// Show the attributes and the size of an EFI variable, never its data
    #[command(next_display_order = None)]
    VariableInfo {
        name: String,
        /// The vendor GUID of the variable, such as 8C78A505-BAA0-4C4A-869F-000000000101
        guid: String,
    },
}

impl HiiPlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::VariableInfo { name, guid } => {
                let info = HiiBackend::variable_info(name, guid)?;
                print_line(format_args!("{}", variable_info_report(&info)))?;
            }
        }
        Ok(())
    }
}

/// What variable-info prints on stdout about `info`: its own JSON object, outside the thrift
/// IDL that the other commands print, and JSON always, as variable-info takes no -j.
fn variable_info_report(info: &VariableInfo) -> serde_json::Value {
    serde_json::json!({
        "variable": info.variable,
        "attributes": info.attributes,
        "size": info.size,
    })
}

/// None: a hii command reads the HiiDB of the firmware that it runs on.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiDbArgs {}

impl HiiDbArgs {
    /// The HiiDB of this firmware, whatever `_efivars` names.
    pub(super) fn read(&self, _efivars: &EfivarSource) -> Result<Vec<u8>> {
        HiiBackend::export_hiidb()
    }
}

/// Where get, show-ifr and list-questions read question values.
#[derive(Debug, Args)]
pub(super) struct EfivarArgs {
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB still comes from this firmware)
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

/// What set does in a HiiDB that declares a setup password question.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct SetupPasswordArgs {
    /// Write even though the HiiDB declares a setup password question. The UEFI Shell runs no setup browser, so no password is asked or checked.
    #[arg(long)]
    bypass_setup_password: bool,
}

impl SetupPasswordArgs {
    pub(super) fn policy(&self) -> SetupPasswordPolicy {
        match self.bypass_setup_password {
            false => SetupPasswordPolicy::Refuse,
            true => SetupPasswordPolicy::Bypass,
        }
    }
}

/// get, in this firmware's HII database.
pub(super) fn auto_get(question: &str, json: bool, selection: &SelectionArgs) -> Result<()> {
    hii_get(
        &HiiBackend::export_hiidb()?,
        question,
        &GetOptions::from(selection),
        json,
    )
}

/// set, in this firmware's HII database.
pub(super) fn auto_set(
    question: &str,
    value: &str,
    json: bool,
    selection: &SelectionArgs,
    setup_password: &SetupPasswordArgs,
) -> Result<()> {
    hii_set(question, value, selection, setup_password, json)
}
