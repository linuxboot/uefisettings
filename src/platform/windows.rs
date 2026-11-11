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

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::QuestionSelector;
use uefisettings::exports::SetOptions;
use uefisettings::exports::SetValue;
use uefisettings::exports::UnsafeOperation;
use uefisettings::exports::VolatileWrites;
use uefisettings::secret_file;
use uefisettings::secret_file::Secret;
use uefisettings::secret_file::MAX_SECRET_LEN;
use uefisettings::terminal_text::UnicodeTerminal;
use uefisettings_backend_thrift::SetResponseList;

use crate::extract_db_report;
use crate::hii_get;
use crate::hii_set;
use crate::print_json;
use crate::write_extracted_db;
use crate::QuestionArgs;
use crate::SelectionArgs;
use crate::SetArgs;
use crate::READ_ONLY_WRITE;
use crate::STAGED_SETUP_PASSWORD;

/// The about of hii, whose commands read this machine's HiiDB or a file.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this machine's HiiDB, as hii get does.
pub(super) const GET_ABOUT: &str = "Get the current value of a question";
/// The about of top-level set, which writes this machine's variables, as hii set does.
pub(super) const SET_ABOUT: &str = "Set/change the value of a question";

/// None: this build reads this machine's HiiDB through the HiiDB driver alone, so it has no
/// --hii-source or --efivar-memory, which clap refuses as unexpected arguments rather than ignore
/// them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiSourceArgs {}

impl HiiSourceArgs {
    /// Ok: neither flag exists here.
    pub(super) fn refuse_given(&self, _why: &str) -> Result<()> {
        Ok(())
    }
}

/// The Linux build's seam to the HII backend, which its tests replace; empty, as the commands
/// here reach the HiiDB driver directly.
pub(super) trait MachineHii {}

/// This machine's firmware.
pub(super) struct Firmware;

impl MachineHii for Firmware {}

/// Installs no logger, so that log's macros write nothing.
pub(super) fn init_logging() {}

/// The terminal of stdout, which renders every character: TerminalText and JsonText do all the
/// escaping.
pub(super) fn stdout_output() -> io::Result<UnicodeTerminal> {
    Ok(UnicodeTerminal)
}

/// The terminal of stderr, as stdout_output's.
pub(super) fn stderr_output() -> io::Result<UnicodeTerminal> {
    Ok(UnicodeTerminal)
}

/// None: ilo and identify need Linux.
#[derive(Debug, Subcommand)]
pub(super) enum PlatformCommands {}

impl PlatformCommands {
    pub(super) fn run(&self, _source: &HiiSourceArgs, _hii: &impl MachineHii) -> Result<()> {
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
    pub(super) fn run(&self, _source: &HiiSourceArgs, _hii: &impl MachineHii) -> Result<()> {
        match self {
            Self::ExtractDB { filename } => {
                write_extracted_db(filename, HiiBackend::export_hiidb)?;

                print_json(&extract_db_report(filename))?;
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
    /// The HiiDB: the file, else this machine's, through the HiiDB driver, whatever `_source`
    /// names.
    pub(super) fn read(
        &self,
        efivars: &EfivarSource,
        _source: &HiiSourceArgs,
        _hii: &impl MachineHii,
    ) -> Result<Vec<u8>> {
        HiiBackend::read_hiidb(self.filename.as_deref(), efivars)
    }
}

/// None: this build reads no memory itself; the HiiDB driver maps the range that the HiiDB efivar
/// names, whatever its memory type (hiidb_driver.rs:56-70), which this build cannot bound.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiSourceUnsafeArgs {}

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

/// The unsafe operations of set, which its long help lists: Windows writes through the
/// firmware environment calls, which reach runtime variables like efivarfs, so no setup password
/// gates them, as on Linux, and a set staged for the next boot, which one does.
pub(super) const SET_UNSAFE_OPERATIONS: &[&str] = &[READ_ONLY_WRITE, STAGED_SETUP_PASSWORD];

/// What set stages for the next boot.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct StagingArgs {
    /// The uefisettings.efi that set copies to the EFI system partition when it stages a question whose value only its driver holds, which the next boot applies. Under Secure Boot, it must be signed for db.
    #[arg(long, value_name = "UEFISETTINGS_EFI")]
    image: Option<PathBuf>,
    /// Where you mounted the EFI system partition, such as S: after `mountvol S: /s`, for set to write the staged files through instead of the partition's volume GUID path. set checks that the volume there is the EFI system partition that it finds.
    #[arg(long, value_name = "MOUNT_POINT")]
    esp: Option<PathBuf>,
}

impl StagingArgs {
    pub(super) fn image(&self) -> Option<PathBuf> {
        self.image.clone()
    }

    pub(super) fn esp(&self) -> Option<PathBuf> {
        self.esp.clone()
    }
}

/// get, in this machine's HiiDB.
pub(super) fn auto_get(
    question: &QuestionArgs,
    json: bool,
    selection: &SelectionArgs,
    _unsafe_operations: &HiiSourceUnsafeArgs,
    _source: &HiiSourceArgs,
    _hii: &impl MachineHii,
) -> Result<()> {
    hii_get(
        &HiiBackend::export_hiidb()?,
        question.selector()?,
        &GetOptions::from(selection),
        json,
    )
}

/// None: Windows writes through the firmware environment calls, after ExitBootServices, when
/// SetVariable() sets no volatile variable (UEFI 2.11 §8.2.3), as on Linux.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct VolatileArgs {}

impl VolatileArgs {
    /// The default, which set through runtime variables does not consult.
    pub(super) fn policy(&self) -> VolatileWrites {
        VolatileWrites::default()
    }
}

/// set, in this machine's HiiDB.
pub(super) fn auto_set(
    target: &SetArgs,
    json: bool,
    _selection: &SelectionArgs,
    _staging: &StagingArgs,
    options: &SetOptions,
    source: &HiiSourceArgs,
    hii: &impl MachineHii,
) -> Result<()> {
    let (question, value) = target.target()?;
    hii_set(question, &value, options, json, source, hii)
}

/// HiiBackend::set_using, whatever `_source` names.
pub(super) fn set_using(
    question: QuestionSelector,
    value: &SetValue,
    options: &SetOptions,
    _source: &HiiSourceArgs,
    _hii: &impl MachineHii,
) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
    HiiBackend::set_using(question, value, None, options)
}

/// The bytes of the file `path`, the payload of variable write-signed.
pub(super) fn read_payload(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).with_context(|| format!("read the payload {}", path.display()))
}

/// The secret in the file `path`, the key or the certificate bundle of variable write-signed, in
/// file mode: at most MAX_SECRET_LEN bytes. Errors name it as `what`.
pub(super) fn read_secret_file(path: &Path, what: &str) -> Result<Secret> {
    let file =
        fs::File::open(path).with_context(|| format!("open the {what} {}", path.display()))?;
    secret_file::read_secret_file(file, MAX_SECRET_LEN)
        .with_context(|| format!("read the {what} {}", path.display()))
}

/// The clock of the TimeStamp that variable write-signed signs: the system clock.
pub(super) fn signing_clock() -> Option<SystemTime> {
    Some(SystemTime::now())
}
