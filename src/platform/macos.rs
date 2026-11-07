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

//! The part of the CLI that only the macOS build has: -f/--filename, the HiiDB file, and
//! --efivars and --no-efivars, of which get, show-ifr and list-questions take exactly one, as this
//! build reads no HiiDB or EFI variables of the machine it runs on.

use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::HiiBackend;

use crate::HiiSourceArgs;

/// The about of hii, whose commands read a HiiDB file or an efivars dump, and no EFI variables of
/// this machine.
pub(super) const HII_ABOUT: &str =
    "Commands which read a UEFI HiiDB file or an efivars dump, and no EFI variables of this machine";

/// The help of --hii-source, which this build ignores.
pub(super) const HII_SOURCE_HELP: &str =
    "Accepted as on Linux, and ignored: this build reads only HiiDB files and efivars dumps";
/// The help of --efivar-memory, which this build ignores.
pub(super) const EFIVAR_MEMORY_HELP: &str =
    "Accepted as on Linux, and ignored: this build reads only HiiDB files and efivars dumps";

/// Installs no logger, so that log's macros write nothing.
pub(super) fn init_logging() {}

/// None: ilo and identify need Linux.
#[derive(Debug, Subcommand)]
pub(super) enum PlatformCommands {}

impl PlatformCommands {
    pub(super) fn run(&self, _source: &HiiSourceArgs) -> Result<()> {
        match *self {}
    }
}

/// None: extract-db, dump-efivars and variable-info read the firmware of the machine.
#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {}

impl HiiPlatformCommands {
    pub(super) fn run(&self, _source: &HiiSourceArgs) -> Result<()> {
        match *self {}
    }
}

/// Where get, show-ifr and list-questions read the HiiDB.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiDbArgs {
    /// The HiiDB file, such as one that extract-db wrote on Linux; without it, the HiiDB in the directory that --efivars names, if dump-efivars wrote it
    #[arg(short, long)]
    filename: Option<PathBuf>,
}

impl HiiDbArgs {
    /// The HiiDB: the file, else the one in `efivars` if dump-efivars wrote it, whatever
    /// `_source` names.
    pub(super) fn read(&self, efivars: &EfivarSource, _source: &HiiSourceArgs) -> Result<Vec<u8>> {
        HiiBackend::read_hiidb(self.filename.as_deref(), efivars)
    }
}

/// Where list-strings, which takes no --efivars, reads the HiiDB: the file, which it needs.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct ListStringsHiiDbArgs {
    /// The HiiDB file, such as one that extract-db wrote on Linux
    #[arg(short, long)]
    filename: PathBuf,
}

impl ListStringsHiiDbArgs {
    /// The HiiDB in the file, whatever `_efivars` and `_source` name.
    pub(super) fn read(&self, _efivars: &EfivarSource, _source: &HiiSourceArgs) -> Result<Vec<u8>> {
        HiiBackend::read_hiidb_file(&self.filename)
    }
}

/// Where get, show-ifr and list-questions read question values: exactly one of --efivars and
/// --no-efivars, as this build reads none of this machine's.
#[derive(Debug, Args)]
// an ArgGroup, so that usage names both flags as the alternatives they are
#[group(required = true, multiple = false)]
pub(super) struct EfivarArgs {
    /// Read question values from the efivar files in this directory (efivarfs format), such as one that dump-efivars wrote on Linux; without --filename, also the HiiDB if dump-efivars wrote the directory
    #[arg(long, value_name = "DIR")]
    efivars: Option<PathBuf>,
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB comes from --filename)
    #[arg(long, requires = "filename")]
    no_efivars: bool,
}

impl EfivarArgs {
    /// The source these flags name, of which the ArgGroup requires exactly one.
    pub(super) fn source(&self) -> Result<EfivarSource> {
        match (&self.efivars, self.no_efivars) {
            (Some(dir), false) => Ok(EfivarSource::Directory(dir.clone())),
            (None, true) => Ok(EfivarSource::Disabled),
            (None, false) | (Some(_), true) => {
                Err(anyhow!("pass exactly one of --efivars and --no-efivars"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::tests::flags_named_in;
    use crate::tests::flags_of;
    use crate::tests::hii;
    use crate::tests::READING_COMMANDS;
    use crate::HiiSubcommands;
    use crate::UefiSettingsToolArgs;

    /// The HiiDB and efivar flags of a get, show-ifr or list-questions.
    fn reading_args(command: &HiiSubcommands) -> (&HiiDbArgs, &EfivarArgs) {
        match command {
            HiiSubcommands::Get { hiidb, efivars, .. }
            | HiiSubcommands::ShowIFR { hiidb, efivars, .. }
            | HiiSubcommands::ListQuestions { hiidb, efivars, .. } => (hiidb, efivars),
            HiiSubcommands::ListStrings { .. } | HiiSubcommands::Platform(_) => {
                panic!("no efivar flags: {command:?}")
            }
        }
    }

    #[test]
    fn efivar_flags_name_their_source() {
        let dir = tempfile::tempdir().expect("create directory");
        let dir_arg = dir.path().to_str().expect("UTF-8 temporary path");
        let cases = [
            (
                "--efivars",
                vec!["--efivars", dir_arg],
                EfivarSource::Directory(dir.path().to_path_buf()),
            ),
            (
                "-f and --no-efivars",
                vec!["-f", "hiidb.bin", "--no-efivars"],
                EfivarSource::Disabled,
            ),
        ];

        for command in READING_COMMANDS {
            for (case, flags, want) in &cases {
                let parsed = hii(&[command, &flags[..]].concat()).expect("parse the flags");
                let source = reading_args(&parsed).1.source().expect("name the source");

                assert_eq!(&source, want, "{command:?} {case}");
            }
        }
    }

    /// get, show-ifr and list-questions take exactly one of --efivars and --no-efivars, and
    /// --no-efivars only with -f, its only HiiDB.
    #[test]
    fn efivar_flags_take_exactly_one_source() {
        let cases = [
            (
                "neither",
                vec!["-f", "hiidb.bin"],
                clap::error::ErrorKind::MissingRequiredArgument,
                "<--efivars <DIR>|--no-efivars>",
            ),
            (
                "both",
                vec!["--efivars", "dir", "--no-efivars", "-f", "hiidb.bin"],
                clap::error::ErrorKind::ArgumentConflict,
                "the argument '--efivars <DIR>' cannot be used with '--no-efivars'",
            ),
            (
                "--no-efivars without -f",
                vec!["--no-efivars"],
                clap::error::ErrorKind::MissingRequiredArgument,
                "--filename <FILENAME>",
            ),
        ];

        for command in READING_COMMANDS {
            for (case, flags, kind, names) in &cases {
                let error = hii(&[command, &flags[..]].concat()).expect_err("parse the flags");

                assert_eq!(error.kind(), *kind, "{command:?} {case}");
                assert!(
                    error.to_string().contains(names),
                    "{command:?} {case}: {error}"
                );
            }
        }
    }

    /// list-strings takes no --efivars, so its HiiDB is the file, which clap requires.
    #[test]
    fn list_strings_needs_a_hiidb_file() {
        let error = hii(&["list-strings"]).expect_err("parse list-strings without -f");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "list-strings without -f"
        );
        assert!(
            error.to_string().contains("--filename <FILENAME>"),
            "list-strings without -f: {error}"
        );

        let parsed = hii(&["list-strings", "-f", "hiidb.bin"]).expect("parse list-strings -f");
        let HiiSubcommands::ListStrings { hiidb, .. } = parsed else {
            panic!("not list-strings: {parsed:?}");
        };
        assert_eq!(
            hiidb.filename,
            PathBuf::from("hiidb.bin"),
            "list-strings -f"
        );
    }

    /// Without -f, a directory that no dump wrote gives no HiiDB, and the error names only flags
    /// of the command that reads it.
    #[test]
    fn no_hiidb_names_only_flags_of_its_command() {
        let dir = tempfile::tempdir().expect("create directory");
        let dir_arg = dir.path().to_str().expect("UTF-8 temporary path");
        let mut root = UefiSettingsToolArgs::command();
        root.build();
        let hii_command = root.find_subcommand("hii").expect("the hii command");

        for command in READING_COMMANDS {
            let parsed = hii(&[command, &["--efivars", dir_arg]].concat()).expect("parse");
            let (hiidb, efivars) = reading_args(&parsed);
            let source = efivars.source().expect("name the source");

            let error = hiidb
                .read(&source, &HiiSourceArgs::default())
                .expect_err("read the HiiDB of a directory that no dump wrote");

            let message = error.to_string();
            assert!(message.starts_with("no HiiDB: "), "{command:?}: {message}");
            let taken = flags_of(
                hii_command
                    .find_subcommand(command[0])
                    .expect("the reading command"),
            );
            for flag in flags_named_in(&message) {
                assert!(taken.contains(&flag), "{command:?}: names {flag}");
            }
        }
    }
}
