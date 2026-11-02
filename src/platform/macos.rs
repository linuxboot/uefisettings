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

//! The part of the CLI that only the macOS build has: -f/--filename, the HiiDB file that every
//! hii command reads, as this build reads no HiiDB or EFI variables of the machine it runs on.

use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::HiiBackend;

/// The about of hii, whose commands read a HiiDB file and no EFI variables.
pub(super) const HII_ABOUT: &str = "Commands which read a UEFI HiiDB file, and no EFI variables";

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

/// None: extract-db, dump-efivars and variable-info read the firmware of the machine.
#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {}

impl HiiPlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match *self {}
    }
}

/// Where a hii command reads the HiiDB.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiDbArgs {
    /// The HiiDB file, such as one that extract-db wrote on Linux. This build reads no EFI variables: each question value shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined
    #[arg(short, long)]
    filename: PathBuf,
}

impl HiiDbArgs {
    /// The HiiDB in the file, whatever `_efivars` names.
    pub(super) fn read(&self, _efivars: &EfivarSource) -> Result<Vec<u8>> {
        HiiBackend::read_hiidb_file(&self.filename)
    }
}

/// None: this build reads no EFI variables, as the help of -f/--filename says.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct EfivarArgs {}

impl EfivarArgs {
    /// The source of get, show-ifr and list-questions: Disabled, the only one of this build.
    pub(super) fn source(&self) -> Result<EfivarSource> {
        Ok(EfivarSource::Disabled)
    }
}
