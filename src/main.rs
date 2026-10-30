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

use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use fbthrift::simplejson_protocol;
use fbthrift::simplejson_protocol::Serializable;
use log::info;
use uefisettings::exports::identify_machine;
use uefisettings::exports::DumpEfivarsOptions;
use uefisettings::exports::EfivarDump;
use uefisettings::exports::EfivarRedaction;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::IloBackend;
use uefisettings::exports::IncludedStates;
use uefisettings::exports::ListQuestionsOptions;
use uefisettings::exports::SetOptions;
use uefisettings::exports::SettingsBackend;
use uefisettings::exports::ShowIfrOptions;
use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::MachineInfo;
use uefisettings_spellings_db_thrift::consts::translation_db;

const MAX_ALLOWED_FILESIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[clap(
    name = "uefisettings",
    about = "UEFI Settings Manipulation Tool",
    long_about = None
)]
struct UefiSettingsToolArgs {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Commands which work on machines exposing the UEFI HiiDB
    Hii(HiiCommand),
    /// Commands which work on machines having HPE's Ilo BMC
    Ilo(IloCommand),
    // TODO: Auto(AutoCommand) after building a backend identifier function
    // TODO: Get/Set without having to specify Auto
    /// Auto-identify backend and display hardware/bios-information
    Identify {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Auto-identify backend and get the current value of a question
    Get {
        #[clap(value_parser)]
        question: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
        #[clap(flatten)]
        include: IncludeArgs,
    },
    /// Auto-identify backend and set/change the value of a question
    Set {
        #[clap(value_parser)]
        question: String,
        #[clap(value_parser)]
        value: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
        #[clap(flatten)]
        include: IncludeArgs,
    },
    /// Show the translation/spellings database for questions and answers
    ShowTranslations {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
}

#[derive(Debug, Parser)]
struct HiiCommand {
    #[clap(subcommand)]
    command: HiiSubcommands,
}

#[derive(Debug, Subcommand)]
enum HiiSubcommands {
    /// Get the current value of a question
    Get {
        #[clap(value_parser)]
        question: String,
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
        #[clap(flatten)]
        include: IncludeArgs,
        #[clap(flatten)]
        efivars: EfivarArgs,
    },
    /// Set/change the value of a question
    Set {
        #[clap(value_parser)]
        question: String,
        #[clap(value_parser)]
        value: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
        #[clap(flatten)]
        include: IncludeArgs,
    },
    /// Show a human readable representation of the Hii Forms
    ShowIFR {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        #[clap(flatten)]
        efivars: EfivarArgs,
    },
    /// Dump HiiDB into a file
    ExtractDB {
        #[clap(parse(from_os_str))]
        filename: PathBuf,
    },
    /// Copy the EFI variables that the HiiDB's questions read into a new directory, for --efivars on another machine
    DumpEfivars {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        /// Copy whole EFI variables, not only the bytes that questions decode; the others can hold secrets such as password hashes
        #[clap(long)]
        unredacted: bool,
        /// The directory to create
        #[clap(parse(from_os_str), value_name = "DIR")]
        directory: PathBuf,
    },
    /// List all strings-id, string pairs in HiiDB
    ListStrings {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// List questions HiiDB. Note that these are not all possible questions, because we don't parse certain non-useful question types.
    ListQuestions {
        /// If filename of HiiDB isn't specified then this tool will try to automatically extract it
        #[clap(parse(from_os_str), short, long)]
        filename: Option<PathBuf>,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
        #[clap(flatten)]
        include: IncludeArgs,
        #[clap(flatten)]
        efivars: EfivarArgs,
    },
}

/// Where get, show-ifr and list-questions read question values.
#[derive(Debug, Args)]
struct EfivarArgs {
    /// Read question values from the efivar files in this directory (efivarfs format) instead of this machine's efivarfs
    #[clap(
        long,
        value_name = "DIR",
        parse(from_os_str),
        conflicts_with = "no-efivars"
    )]
    efivars: Option<PathBuf>,
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB still comes from --filename or this machine)
    #[clap(long)]
    no_efivars: bool,
}

impl EfivarArgs {
    /// The source these flags name.
    fn source(&self) -> Result<EfivarSource> {
        match (&self.efivars, self.no_efivars) {
            (None, false) => Ok(EfivarSource::System),
            (None, true) => Ok(EfivarSource::Disabled),
            (Some(dir), false) => Ok(EfivarSource::Directory(dir.clone())),
            (Some(_), true) => Err(anyhow!("--efivars and --no-efivars conflict")),
        }
    }
}

#[derive(Debug, Args)]
struct IncludeArgs {
    /// Also select questions that conditions gray out, suppress or disable. The edk2 setup
    /// browser (edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpressionList) ranks
    /// DisableIf > SuppressIf > GrayOutIf, so a question that is both grayed out and suppressed
    /// counts as suppressed.
    #[clap(long, value_enum, value_delimiter = ',')]
    include: Vec<IncludeState>,
}

impl IncludeArgs {
    fn states(&self) -> IncludedStates {
        self.include
            .iter()
            .copied()
            .map(IncludedStates::from)
            .collect()
    }

    /// Fails if any state is included: Ilo attributes have no IFR conditions.
    fn refuse_on_ilo(&self) -> Result<()> {
        match self.include.as_slice() {
            [] => Ok(()),
            [..] => Err(anyhow!(
                "--include applies to the HII backend, not to the Ilo backend of this machine"
            )),
        }
    }
}

impl From<&IncludeArgs> for GetOptions {
    fn from(args: &IncludeArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options
    }
}

impl From<&IncludeArgs> for SetOptions {
    fn from(args: &IncludeArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options
    }
}

impl From<&IncludeArgs> for ListQuestionsOptions {
    fn from(args: &IncludeArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum IncludeState {
    GrayedOut,
    Suppressed,
    Disabled,
}

impl From<IncludeState> for IncludedStates {
    fn from(state: IncludeState) -> Self {
        match state {
            IncludeState::GrayedOut => IncludedStates::GRAYED_OUT,
            IncludeState::Suppressed => IncludedStates::SUPPRESSED,
            IncludeState::Disabled => IncludedStates::DISABLED,
        }
    }
}

#[derive(Debug, Parser)]
struct IloCommand {
    #[clap(subcommand)]
    command: IloSubcommands,
}

#[derive(Debug, Subcommand)]
enum IloSubcommands {
    /// Get the current value of a question
    Get {
        #[clap(value_parser)]
        question: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// Set/change the value of a question
    Set {
        #[clap(value_parser)]
        question: String,
        #[clap(value_parser)]
        value: String,
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// List bios attributes and their current values
    ShowAttributes {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
    /// List all pending changes that will take effect after reboot
    ShowPendingAttributes {
        #[clap(short = 'j', long = "json", action, value_parser)]
        json: bool,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let args = UefiSettingsToolArgs::parse();

    if let Err(why) = handle_cmds(args) {
        if is_broken_pipe(&why) {
            return Ok(());
        }

        let _ = print_with_style(
            uefisettings_backend_thrift::Error {
                error_message: format!("{:#}", why),
                ..Default::default()
            },
            true,
        );
        process::exit(1);
    }

    info!("Exiting UEFI Settings Manipulation Tool");
    Ok(())
}

fn handle_cmds(args: UefiSettingsToolArgs) -> Result<()> {
    match &args.command {
        Commands::Hii(hii_command) => match &hii_command.command {
            HiiSubcommands::Get {
                question,
                filename,
                json,
                include,
                efivars,
            } => {
                let mut options = GetOptions::from(include);
                options.efivars = efivars.source()?;
                // before the HiiDB is read
                options.efivars.validate()?;
                let res = HiiBackend::get_using(
                    &get_db_dump_bytes(filename.as_deref())?,
                    question,
                    None,
                    &options,
                )?;
                print_with_style(res, *json)?;
            }
            HiiSubcommands::Set {
                question,
                value,
                json,
                include,
            } => {
                let res = HiiBackend::set_using(question, value, None, &SetOptions::from(include))?;
                print_with_style(res, *json)?;
            }
            HiiSubcommands::ShowIFR { filename, efivars } => {
                let mut options = ShowIfrOptions::default();
                options.efivars = efivars.source()?;
                // before the HiiDB is read
                options.efivars.validate()?;
                let res =
                    HiiBackend::show_ifr_using(&get_db_dump_bytes(filename.as_deref())?, &options)?;
                print_line(format_args!("{}", res.readable_representation))?;
            }
            HiiSubcommands::ExtractDB { filename } => {
                let mut file = File::create(filename)?;
                let res = HiiBackend::extract_db()?;
                file.write_all(&res.db)?;

                print_line(format_args!("{}", extract_db_report(filename)))?;
            }
            HiiSubcommands::DumpEfivars {
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
            HiiSubcommands::ListStrings { filename, json } => {
                let res = HiiBackend::list_strings(&get_db_dump_bytes(filename.as_deref())?)?;
                print_with_style(res, *json)?;
            }
            HiiSubcommands::ListQuestions {
                filename,
                json,
                include,
                efivars,
            } => {
                let mut options = ListQuestionsOptions::from(include);
                options.efivars = efivars.source()?;
                // before the HiiDB is read
                options.efivars.validate()?;
                let res = HiiBackend::list_questions_using(
                    &get_db_dump_bytes(filename.as_deref())?,
                    &options,
                )?;
                print_with_style(res, *json)?;
            }
        },
        Commands::Ilo(ilo_command) => match &ilo_command.command {
            IloSubcommands::Get { question, json } => {
                let res = IloBackend::get(question, None)?;
                print_with_style(res, *json)?;
            }
            IloSubcommands::Set {
                question,
                value,
                json,
            } => {
                let res = IloBackend::set(question, value, None)?;
                print_with_style(res, *json)?;
            }
            IloSubcommands::ShowAttributes { json } => {
                let res = IloBackend::show_attributes()?;
                print_with_style(res, *json)?;
            }
            IloSubcommands::ShowPendingAttributes { json } => {
                let res = IloBackend::show_pending_attributes()?;
                print_with_style(res, *json)?;
            }
        },
        Commands::Identify { json } => {
            let machine = identify_machine();
            print_with_style(machine, *json)?;
        }
        Commands::Get {
            question,
            json,
            include,
        } => {
            let machine = identify_machine();
            if machine.backend.contains(&Backend::Unknown) {
                return Err(anyhow!("unknown backend"));
            }
            if prioritize_backend(&machine, *json)? == Backend::Ilo {
                include.refuse_on_ilo()?;
                let res = IloBackend::get(question, None)?;
                print_with_style(res, *json)?;
            } else {
                let res = HiiBackend::get_using(
                    &get_db_dump_bytes(None)?,
                    question,
                    None,
                    &GetOptions::from(include),
                )?;
                print_with_style(res, *json)?;
            }
        }
        Commands::Set {
            question,
            value,
            json,
            include,
        } => {
            let machine = identify_machine();
            if machine.backend.contains(&Backend::Unknown) {
                return Err(anyhow!("unknown backend"));
            }
            if prioritize_backend(&machine, *json)? == Backend::Ilo {
                include.refuse_on_ilo()?;
                let res = IloBackend::set(question, value, None)?;
                print_with_style(res, *json)?;
            } else {
                let res = HiiBackend::set_using(question, value, None, &SetOptions::from(include))?;
                print_with_style(res, *json)?;
            }
        }
        Commands::ShowTranslations { json } => {
            print_with_style(&*translation_db, *json)?;
        }
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

fn get_db_dump_bytes(filename: Option<&Path>) -> Result<Vec<u8>> {
    // If dbdump's path is provided use that
    if let Some(dbdump_path) = filename {
        info!("Using database dump from file: {}", dbdump_path.display());

        let mut file = File::open(dbdump_path)
            .context(format!("opening dbdump from{}", dbdump_path.display()))?;

        // Most Hii DBs are a few hundred kilobytes in size and the largest we've seen so far is close to 3 MB.
        // Since we're reading the entire DB into a Vec<u8> we need to have a check here.
        if file
            .metadata()
            .context("failed to read metadata for open file")?
            .len()
            > MAX_ALLOWED_FILESIZE
        {
            return Err(anyhow!(
                "File size is too big for the file to be a HII database."
            ));
        }

        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents)
            .context("Couldn't convert file bytes to Vec<u8>")?;

        Ok(file_contents)
    } else {
        Ok(HiiBackend::extract_db()?.db)
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
            "copied {} of the {} EFI variables that questions read to {}",
            dump.copied.len(),
            dump.copied.len() + dump.missing.len(),
            dir.display()
        ),
        "directory": dir.display().to_string(),
        "redaction": redaction,
        "copied": dump.copied,
        "missing": dump.missing,
    })
}

/// What dump-efivars warns on stderr about a dump into `dir`.
fn dump_warning(dir: &Path, redaction: EfivarRedaction) -> String {
    match redaction {
        EfivarRedaction::DecodedBytes => format!(
            "warning: {} is redacted to the bytes that questions decode, whose values can still \
             be secrets; share it only with people you trust",
            dir.display()
        ),
        EfivarRedaction::Unredacted => format!(
            "warning: {} holds whole EFI variables, not redacted, which can hold secrets such as \
             password hashes; share it only with people you trust",
            dir.display()
        ),
        _ => format!(
            "warning: {} holds EFI variables, which can hold secrets such as password hashes; \
             share it only with people you trust",
            dir.display()
        ),
    }
}

fn print_line(arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{}", arguments)
}

// print_with_style either prints as json or with rust's debug pretty-printer
fn print_with_style<T>(result: T, json: bool) -> io::Result<()>
where
    T: Serializable + Debug,
{
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_with_style(&mut output, result, json)
}

fn write_with_style<W, T>(output: &mut W, result: T, json: bool) -> io::Result<()>
where
    W: Write,
    T: Serializable + Debug,
{
    if json {
        let buf = simplejson_protocol::serialize(result);
        writeln!(output, "{}", String::from_utf8_lossy(&buf))
    } else {
        writeln!(output, "{:#?}", result)
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .map(|error| error.kind() == io::ErrorKind::BrokenPipe)
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const READING_COMMANDS: [&[&str]; 3] =
        [&["get", "Question"], &["show-ifr"], &["list-questions"]];

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The --include of `uefisettings set Q V` with `args` after it.
    fn include_of(args: &[&str]) -> IncludeArgs {
        let command = [&["uefisettings", "set", "Q", "V"][..], args].concat();
        let parsed = UefiSettingsToolArgs::try_parse_from(&command)
            .unwrap_or_else(|error| panic!("parse {command:?}: {error}"));
        let Commands::Set { include, .. } = parsed.command else {
            panic!("{command:?} is no set: {parsed:?}");
        };
        include
    }

    #[test]
    fn include_maps_each_state_to_its_flag() {
        let cases = [
            ("no flag", vec![], IncludedStates::empty()),
            (
                "grayed-out",
                vec!["--include", "grayed-out"],
                IncludedStates::GRAYED_OUT,
            ),
            (
                "suppressed",
                vec!["--include", "suppressed"],
                IncludedStates::SUPPRESSED,
            ),
            (
                "disabled",
                vec!["--include", "disabled"],
                IncludedStates::DISABLED,
            ),
            (
                "all three",
                vec!["--include", "grayed-out,suppressed,disabled"],
                IncludedStates::all(),
            ),
            (
                "repeated",
                vec!["--include", "grayed-out", "--include", "disabled"],
                IncludedStates::GRAYED_OUT | IncludedStates::DISABLED,
            ),
        ];
        for (name, args, states) in cases {
            let include = include_of(&args);
            assert_eq!(include.states(), states, "{name}");
            assert_eq!(GetOptions::from(&include).include, states, "{name}: get");
            assert_eq!(SetOptions::from(&include).include, states, "{name}: set");
            assert_eq!(
                ListQuestionsOptions::from(&include).include,
                states,
                "{name}: list-questions"
            );
            assert_eq!(
                include.refuse_on_ilo().is_ok(),
                args.is_empty(),
                "{name}: refuse_on_ilo"
            );
        }
    }

    /// The hii subcommand that `args`, after `uefisettings hii`, parse to.
    fn hii(args: &[&str]) -> clap::Result<HiiSubcommands> {
        let argv = [&["uefisettings", "hii"][..], args].concat();
        UefiSettingsToolArgs::try_parse_from(argv).map(|parsed| match parsed.command {
            Commands::Hii(hii) => hii.command,
            other => panic!("not a hii command: {other:?}"),
        })
    }

    /// The efivar flags of a get, show-ifr or list-questions.
    fn efivar_args(command: &HiiSubcommands) -> &EfivarArgs {
        match command {
            HiiSubcommands::Get { efivars, .. }
            | HiiSubcommands::ShowIFR { efivars, .. }
            | HiiSubcommands::ListQuestions { efivars, .. } => efivars,
            other => panic!("no efivar flags: {other:?}"),
        }
    }

    #[test]
    fn efivar_flags_name_their_source() {
        let dir = tempfile::tempdir().expect("create directory");
        let dir_arg = dir.path().to_str().expect("UTF-8 temporary path");
        let missing = dir.path().join("missing");
        let missing_arg = missing.to_str().expect("UTF-8 temporary path");
        let cases = [
            ("no flag", vec![], EfivarSource::System),
            ("--no-efivars", vec!["--no-efivars"], EfivarSource::Disabled),
            (
                "--efivars",
                vec!["--efivars", dir_arg],
                EfivarSource::Directory(dir.path().to_path_buf()),
            ),
            // EfivarSource::validate checks the directory
            (
                "--efivars of a missing directory",
                vec!["--efivars", missing_arg],
                EfivarSource::Directory(missing.clone()),
            ),
        ];

        for command in READING_COMMANDS {
            for (case, flags, want) in &cases {
                let parsed = hii(&[command, &flags[..]].concat()).expect("parse the flags");
                let source = efivar_args(&parsed).source().expect("name the source");

                assert_eq!(&source, want, "{command:?} {case}");
            }
        }
    }

    #[test]
    fn efivar_flags_conflict() {
        for command in READING_COMMANDS {
            let error = hii(&[command, &["--efivars", "dir", "--no-efivars"]].concat())
                .expect_err("parse both flags");

            assert_eq!(
                error.kind(),
                clap::ErrorKind::ArgumentConflict,
                "{command:?}"
            );
        }
    }

    #[test]
    fn bad_efivars_fail_before_the_hiidb_is_read() {
        let dir = tempfile::tempdir().expect("create directory");
        let missing = dir.path().join("missing");
        let missing_arg = missing.to_str().expect("UTF-8 temporary path");
        let db = dir.path().join("no-hiidb");
        let db_arg = db.to_str().expect("UTF-8 temporary path");

        for command in READING_COMMANDS {
            let argv = [
                &["uefisettings", "hii"][..],
                command,
                &["-f", db_arg, "--efivars", missing_arg],
            ]
            .concat();
            let args = UefiSettingsToolArgs::try_parse_from(argv).expect("parse the flags");

            let error = handle_cmds(args).expect_err("read with a missing efivars directory");

            assert_eq!(
                error.to_string(),
                format!("efivars directory {} is not a directory", missing.display()),
                "{command:?}"
            );
        }
    }

    #[test]
    fn set_takes_no_efivar_flags() {
        for flags in [&["--no-efivars"][..], &["--efivars", "dir"]] {
            let error = hii(&[&["set", "Question", "Value"][..], flags].concat())
                .expect_err("parse an efivar flag of set");

            assert_eq!(error.kind(), clap::ErrorKind::UnknownArgument, "{flags:?}");
        }
    }

    #[test]
    fn hii_get_takes_a_hiidb_file() {
        let parsed = hii(&["get", "Question", "-f", "hiidb.bin"]).expect("parse get -f");

        let HiiSubcommands::Get { filename, .. } = parsed else {
            panic!("not get: {parsed:?}");
        };
        assert_eq!(filename, Some(PathBuf::from("hiidb.bin")), "get -f");
    }

    #[test]
    fn dump_efivars_takes_a_directory() {
        let cases = [
            ("DIR", vec!["dump-efivars", "out"], None, false),
            (
                "-f and --unredacted",
                vec!["dump-efivars", "-f", "hiidb.bin", "--unredacted", "out"],
                Some(PathBuf::from("hiidb.bin")),
                true,
            ),
        ];

        for (case, args, want_filename, want_unredacted) in cases {
            let parsed = hii(&args).expect("parse dump-efivars");
            let HiiSubcommands::DumpEfivars {
                filename,
                unredacted,
                directory,
            } = parsed
            else {
                panic!("{case}: not dump-efivars: {parsed:?}");
            };

            assert_eq!(
                (filename, unredacted, directory),
                (want_filename, want_unredacted, PathBuf::from("out")),
                "{case}"
            );
        }
        let error = hii(&["dump-efivars"]).expect_err("parse dump-efivars without DIR");
        assert_eq!(
            error.kind(),
            clap::ErrorKind::MissingRequiredArgument,
            "no DIR"
        );
    }

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
                    "info": "copied 1 of the 2 EFI variables that questions read to out",
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
                "warning: out is redacted to the bytes that questions decode, whose values can \
                 still be secrets; share it only with people you trust",
            ),
            (
                "unredacted",
                EfivarRedaction::Unredacted,
                "warning: out holds whole EFI variables, not redacted, which can hold secrets \
                 such as password hashes; share it only with people you trust",
            ),
        ];

        for (case, redaction, warning) in cases {
            assert_eq!(dump_warning(Path::new("out"), redaction), warning, "{case}");
        }
    }

    #[test]
    fn write_with_style_returns_broken_pipe() {
        let mut output = BrokenPipeWriter;
        let error = write_with_style(
            &mut output,
            uefisettings_backend_thrift::Error::default(),
            false,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(is_broken_pipe(&error.into()));
    }
}
