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
#[cfg(all(system_hiidb, hiidb_files))]
use std::fs;
use std::io;
use std::io::Write;
#[cfg(all(system_hiidb, hiidb_files))]
use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use fbthrift::simplejson_protocol;
use fbthrift::simplejson_protocol::Serializable;
use log::info;
use uefisettings::exports::AccessLevel;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::IncludedStates;
use uefisettings::exports::ListQuestionsOptions;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::SetOptions;
use uefisettings::exports::ShowIfrOptions;
use uefisettings_spellings_db_thrift::consts::translation_db;

#[cfg(system_variables)]
use capsule_command::CapsuleCommand;
use platform::EfivarArgs;
use platform::HiiDbArgs;
use platform::HiiPlatformCommands;
use platform::ListStringsHiiDbArgs;
use platform::PlatformCommands;
#[cfg(all(system_hiidb, system_variables))]
use platform::SetupPasswordArgs;
#[cfg(system_variables)]
use variable_command::VariableCommand;

/// The commands and flags that only this build has, and where it reads the HiiDB.
#[cfg_attr(target_os = "linux", path = "platform/linux.rs")]
#[cfg_attr(target_os = "macos", path = "platform/macos.rs")]
#[cfg_attr(target_os = "uefi", path = "platform/uefi.rs")]
#[cfg_attr(target_os = "windows", path = "platform/windows.rs")]
mod platform;
// The UEFI Shell's `-` is in platform/uefi.rs; the macOS build has no secret flags, as it reads
// only HiiDB files and efivar dumps.
#[cfg(system_variables)]
mod capsule_command;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod secret_stdin;
#[cfg(system_variables)]
mod variable_command;

// Every command lists its options and subcommands alphabetically, as under clap 3:
// next_display_order = None leaves them unordered, and clap sorts those by name.
#[derive(Debug, Parser)]
#[command(
    name = "uefisettings",
    version,
    about = "UEFI Settings Manipulation Tool",
    long_about = None,
    next_display_order = None
)]
struct UefiSettingsToolArgs {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    // The platform word hii: the macOS build reads HiiDB files and efivars dumps only.
    #[command(about = platform::HII_ABOUT)]
    Hii(HiiCommand),
    // TODO: Auto(AutoCommand) after building a backend identifier function
    // TODO: Get/Set without having to specify Auto
    // The platform words get and set: only the Linux build identifies a backend.
    // The questions and values of get and set take negative numbers, such as -1 for a numeric
    // question; another value that starts with - follows --.
    #[cfg(all(system_hiidb, system_variables))]
    #[command(about = platform::GET_ABOUT, next_display_order = None)]
    Get {
        #[arg(allow_negative_numbers = true)]
        question: String,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
    },
    #[cfg(all(system_hiidb, system_variables))]
    #[command(about = platform::SET_ABOUT, next_display_order = None)]
    Set {
        #[arg(allow_negative_numbers = true)]
        question: String,
        #[arg(allow_negative_numbers = true)]
        value: String,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        setup_password: SetupPasswordArgs,
    },
    /// Show the translation/spellings database for questions and answers
    #[command(next_display_order = None)]
    ShowTranslations {
        #[command(flatten)]
        output: JsonArgs,
    },
    /// Commands on this machine's EFI variables
    #[cfg(system_variables)]
    Variable(VariableCommand),
    /// Commands that pass capsules to this machine's firmware
    #[cfg(system_variables)]
    Capsule(CapsuleCommand),
    #[command(flatten)]
    Platform(PlatformCommands),
}

#[derive(Debug, Parser)]
#[command(next_display_order = None)]
struct HiiCommand {
    #[command(subcommand)]
    command: HiiSubcommands,
}

#[derive(Debug, Subcommand)]
enum HiiSubcommands {
    /// Get the current value of a question
    #[command(next_display_order = None)]
    Get {
        #[arg(allow_negative_numbers = true)]
        question: String,
        #[command(flatten)]
        hiidb: HiiDbArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        efivars: EfivarArgs,
    },
    /// Set/change the value of a question
    #[cfg(all(system_hiidb, system_variables))]
    #[command(next_display_order = None)]
    Set {
        #[arg(allow_negative_numbers = true)]
        question: String,
        #[arg(allow_negative_numbers = true)]
        value: String,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        setup_password: SetupPasswordArgs,
    },
    /// Show a human readable representation of the Hii Forms
    #[command(next_display_order = None)]
    ShowIFR {
        #[command(flatten)]
        hiidb: HiiDbArgs,
        #[command(flatten)]
        efivars: EfivarArgs,
    },
    /// List all strings-id, string pairs in HiiDB
    #[command(next_display_order = None)]
    ListStrings {
        #[command(flatten)]
        hiidb: ListStringsHiiDbArgs,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// List questions HiiDB. Note that these are not all possible questions, because we don't parse certain non-useful question types.
    #[command(next_display_order = None)]
    ListQuestions {
        #[command(flatten)]
        hiidb: HiiDbArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        efivars: EfivarArgs,
    },
    #[command(flatten)]
    Platform(HiiPlatformCommands),
}

/// -j/--json, which overrides itself: it may repeat, as under clap 3.
#[derive(Debug, Args)]
struct JsonArgs {
    #[arg(short = 'j', long = "json", overrides_with = "json")]
    json: bool,
}

/// Which questions and options get, set and list-questions select.
#[derive(Debug, Args)]
struct SelectionArgs {
    /// Also select questions that conditions gray out, suppress or disable. The edk2 setup
    /// browser (edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpressionList) ranks
    /// DisableIf > SuppressIf > GrayOutIf, so a question that is both grayed out and suppressed
    /// counts as suppressed.
    #[arg(long, value_enum, value_delimiter = ',')]
    include: Vec<IncludeState>,
    /// Evaluate the conditions that read the AMI Setup access level (VarStore SystemAccess
    /// E770BB69-BCB4-4D04-9E97-23FF9456FEAC: 0 Administrator, 1 User) at this level instead of
    /// the stored value. This states a Setup privilege; it is no password and authenticates
    /// nothing (UEFI variable writes carry no password).
    #[arg(long, value_enum, value_name = "LEVEL")]
    access_level: Option<AccessLevelArg>,
}

impl SelectionArgs {
    fn states(&self) -> IncludedStates {
        self.include
            .iter()
            .copied()
            .map(IncludedStates::from)
            .collect()
    }

    fn access_level(&self) -> Option<AccessLevel> {
        self.access_level.map(AccessLevel::from)
    }
}

impl From<&SelectionArgs> for GetOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.access_level = args.access_level();
        options
    }
}

#[cfg(all(system_hiidb, system_variables))]
impl From<&SelectionArgs> for SetOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.access_level = args.access_level();
        options
    }
}

impl From<&SelectionArgs> for ListQuestionsOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.access_level = args.access_level();
        options
    }
}

/// The SetOptions of `selection` and `setup_password`.
#[cfg(all(system_hiidb, system_variables))]
fn set_options(selection: &SelectionArgs, setup_password: &SetupPasswordArgs) -> SetOptions {
    let mut options = SetOptions::from(selection);
    options.setup_password = setup_password.policy();
    options
}

/// get of `question` in the HiiDB `db_bytes` with `options`, printed as JSON if `json`.
fn hii_get(db_bytes: &[u8], question: &str, options: &GetOptions, json: bool) -> Result<()> {
    let res = HiiBackend::get_using(db_bytes, question, None, options)?;
    print_with_style(res, json)?;
    Ok(())
}

/// set of `question` to `value` with `selection` and `setup_password`, in this machine's HiiDB
/// and variables, printed as JSON if `json`.
#[cfg(all(system_hiidb, system_variables))]
fn hii_set(
    question: &str,
    value: &str,
    selection: &SelectionArgs,
    setup_password: &SetupPasswordArgs,
    json: bool,
) -> Result<()> {
    let res = HiiBackend::set_using(
        question,
        value,
        None,
        &set_options(selection, setup_password),
    )?;
    print_with_style(res, json)?;
    Ok(())
}

/// Writes the HiiDB that `extract` reads to `path`, which it creates only after the read
/// succeeded, so a failed read leaves no file and an existing one unchanged; a failed write can
/// still leave it truncated, as it writes through a symlink or to /dev/stdout instead of
/// renaming a temporary file.
#[cfg(all(system_hiidb, hiidb_files))]
fn write_extracted_db(path: &Path, extract: impl FnOnce() -> Result<Vec<u8>>) -> Result<()> {
    let db = extract()?;
    fs::write(path, &db)?;
    Ok(())
}

/// What extract-db prints on stdout about the HiiDB written to `path`.
#[cfg(all(system_hiidb, hiidb_files))]
fn extract_db_report(path: &Path) -> serde_json::Value {
    serde_json::json!({ "info": format!("HiiDB written to {}", path.display()) })
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

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum AccessLevelArg {
    Administrator,
    User,
}

impl From<AccessLevelArg> for AccessLevel {
    fn from(level: AccessLevelArg) -> Self {
        match level {
            AccessLevelArg::Administrator => AccessLevel::Administrator,
            AccessLevelArg::User => AccessLevel::User,
        }
    }
}

// Every exit returns from main, whose ExitCode::FAILURE the UEFI Shell build's entry point turns
// into EFI_ABORTED: std::process::exit, also through clap's Error::exit, would exit that image
// with its code as the status, a warning such as 1 or 2.
fn main() -> ExitCode {
    platform::init_logging();
    let args = match UefiSettingsToolArgs::try_parse() {
        Ok(args) => args,
        Err(error) => {
            // As clap's Error::exit, which ignores every print error: the exit code stays
            // clap's, as nothing is left to report a failed print to.
            if let Err(print_error) = error.print() {
                log::debug!("failed to print the parse error: {print_error}");
            }
            return parse_error_exit_code(&error);
        }
    };

    if let Err(why) = handle_cmds(args) {
        if is_broken_pipe(&why) {
            return ExitCode::SUCCESS;
        }

        let _ = print_with_style(
            uefisettings_backend_thrift::Error {
                error_message: format!("{:#}", why),
                ..Default::default()
            },
            true,
        );
        return ExitCode::FAILURE;
    }

    info!("Exiting UEFI Settings Manipulation Tool");
    ExitCode::SUCCESS
}

/// The exit code of clap's Error::exit for `error`: 0 for help or the version, else 2.
fn parse_error_exit_code(error: &clap::Error) -> ExitCode {
    u8::try_from(error.exit_code()).map_or(ExitCode::FAILURE, ExitCode::from)
}

fn handle_cmds(args: UefiSettingsToolArgs) -> Result<()> {
    match &args.command {
        Commands::Hii(hii_command) => match &hii_command.command {
            HiiSubcommands::Get {
                question,
                hiidb,
                output,
                selection,
                efivars,
            } => {
                let mut options = GetOptions::from(selection);
                options.efivars = efivars.source()?;
                // before the HiiDB is read
                options.efivars.validate()?;
                hii_get(
                    &hiidb.read(&options.efivars)?,
                    question,
                    &options,
                    output.json,
                )?;
            }
            #[cfg(all(system_hiidb, system_variables))]
            HiiSubcommands::Set {
                question,
                value,
                output,
                selection,
                setup_password,
            } => hii_set(question, value, selection, setup_password, output.json)?,
            HiiSubcommands::ShowIFR { hiidb, efivars } => {
                let mut options = ShowIfrOptions::default();
                options.efivars = efivars.source()?;
                // before the HiiDB is read
                options.efivars.validate()?;
                let res = HiiBackend::show_ifr_using(&hiidb.read(&options.efivars)?, &options)?;
                print_line(format_args!("{}", res.readable_representation))?;
            }
            HiiSubcommands::ListStrings { hiidb, output } => {
                let res = HiiBackend::list_strings(&hiidb.read(&EfivarSource::Disabled)?)?;
                print_with_style(res, output.json)?;
            }
            HiiSubcommands::ListQuestions {
                hiidb,
                output,
                selection,
                efivars,
            } => {
                let mut options = ListQuestionsOptions::from(selection);
                options.efivars = efivars.source()?;
                // before the HiiDB is read
                options.efivars.validate()?;
                let res =
                    HiiBackend::list_questions_using(&hiidb.read(&options.efivars)?, &options)?;
                print_with_style(res, output.json)?;
            }
            HiiSubcommands::Platform(command) => command.run()?,
        },
        #[cfg(all(system_hiidb, system_variables))]
        Commands::Get {
            question,
            output,
            selection,
        } => platform::auto_get(question, output.json, selection)?,
        #[cfg(all(system_hiidb, system_variables))]
        Commands::Set {
            question,
            value,
            output,
            selection,
            setup_password,
        } => platform::auto_set(question, value, output.json, selection, setup_password)?,
        Commands::ShowTranslations { output } => {
            print_with_style(&*translation_db, output.json)?;
        }
        #[cfg(system_variables)]
        Commands::Variable(command) => command.run()?,
        #[cfg(system_variables)]
        Commands::Capsule(command) => command.run()?,
        Commands::Platform(command) => command.run()?,
    }
    Ok(())
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
    use clap::CommandFactory;

    use super::*;

    #[cfg(efivar_dumps)]
    pub(super) const READING_COMMANDS: [&[&str]; 3] =
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

    /// The flags with which hii get, list-questions and show-ifr read offline on every build that
    /// runs the tests: the HiiDB file of -f and no EFI variables, as Windows takes no --efivars
    /// and macOS takes --no-efivars only with -f. Only the tests of the efivar flags themselves
    /// pass others, on the builds that take them.
    const OFFLINE_SOURCE: [&str; 3] = ["-f", "hiidb.bin", "--no-efivars"];

    // clap_lex's is_number takes these for negative numbers, which allow_negative_numbers lets a
    // positional take; it refuses the others, which need "--" before them.
    const NEGATIVE_NUMBERS: [&str; 3] = ["-1", "-0.5", "-1e5"];
    const OTHER_HYPHEN_VALUES: [&str; 3] = ["-0x10", "-.5", "-inf"];

    /// The selection flags of `uefisettings hii list-questions` with OFFLINE_SOURCE and `args`
    /// after it.
    pub(super) fn selection_of(args: &[&str]) -> SelectionArgs {
        let command = [&["list-questions"][..], &OFFLINE_SOURCE, args].concat();
        let parsed = hii(&command).unwrap_or_else(|error| panic!("parse {command:?}: {error}"));
        let HiiSubcommands::ListQuestions { selection, .. } = parsed else {
            panic!("{command:?} is no list-questions: {parsed:?}");
        };
        selection
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
            let selection = selection_of(&args);
            assert_eq!(selection.states(), states, "{name}");
            assert_eq!(GetOptions::from(&selection).include, states, "{name}: get");
            #[cfg(all(system_hiidb, system_variables))]
            assert_eq!(SetOptions::from(&selection).include, states, "{name}: set");
            assert_eq!(
                ListQuestionsOptions::from(&selection).include,
                states,
                "{name}: list-questions"
            );
        }
    }

    #[test]
    fn access_level_maps_to_its_flag() {
        let cases = [
            ("no flag", vec![], None),
            (
                "administrator",
                vec!["--access-level", "administrator"],
                Some(AccessLevel::Administrator),
            ),
            (
                "user",
                vec!["--access-level", "user"],
                Some(AccessLevel::User),
            ),
        ];
        for (name, args, level) in cases {
            let selection = selection_of(&args);
            assert_eq!(
                GetOptions::from(&selection).access_level,
                level,
                "{name}: get"
            );
            #[cfg(all(system_hiidb, system_variables))]
            assert_eq!(
                SetOptions::from(&selection).access_level,
                level,
                "{name}: set"
            );
            assert_eq!(
                ListQuestionsOptions::from(&selection).access_level,
                level,
                "{name}: list-questions"
            );
        }

        let error = hii(&[
            &["list-questions"][..],
            &OFFLINE_SOURCE,
            &["--access-level", "0"],
        ]
        .concat())
        .expect_err("parse --access-level 0");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue, "0");
    }

    /// --access-level comes with --include: on hii get, set and list-questions and on get and
    /// set, not on show-ifr, which evaluates no conditions, nor on ilo.
    #[test]
    fn access_level_is_taken_where_include_is() {
        let reading: [(&[&str], bool); 3] = [
            (&["hii", "get", "Q"], true),
            (&["hii", "list-questions"], true),
            (&["hii", "show-ifr"], false),
        ];
        let reading = reading.map(|(command, takes)| ([command, &OFFLINE_SOURCE].concat(), takes));
        let commands = reading
            .iter()
            .map(|(command, takes)| (&command[..], *takes));
        #[cfg(all(system_hiidb, system_variables))]
        let commands = commands.into_iter().chain([
            (&["hii", "set", "Q", "V"][..], true),
            (&["get", "Q"], true),
            (&["set", "Q", "V"], true),
        ]);
        // the Linux build's own command
        #[cfg(target_os = "linux")]
        let commands = commands
            .into_iter()
            .chain([(&["ilo", "get", "Q"][..], false)]);
        for (command, takes) in commands {
            let argv = [&["uefisettings"][..], command, &["--access-level", "user"]].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            match takes {
                true => assert!(parsed.is_ok(), "{command:?}: {parsed:?}"),
                false => assert_eq!(
                    parsed.err(),
                    Some(clap::error::ErrorKind::UnknownArgument),
                    "{command:?}"
                ),
            }
        }
    }

    /// -j and --json may repeat, as clap 3.2 let them (ArgAction::SetTrue); --no-efivars may
    /// not, as before.
    #[test]
    fn json_flag_may_repeat() {
        let reading: [&[&str]; 2] = [
            &["hii", "list-questions", "--json", "--json"],
            &["hii", "get", "Q", "-j", "--json"],
        ];
        let reading = reading.map(|command| [command, &OFFLINE_SOURCE].concat());
        let commands = reading.iter().map(|command| &command[..]);
        let commands = commands.chain([&["show-translations", "-j", "-j"][..]]);
        // the Linux build's own command
        #[cfg(target_os = "linux")]
        let commands = commands
            .into_iter()
            .chain([&["ilo", "show-attributes", "--json", "-j"][..]]);
        for command in commands {
            let argv = [&["uefisettings"][..], command].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            assert!(parsed.is_ok(), "{command:?}: {parsed:?}");
        }

        let error = hii(&[
            "list-questions",
            "-f",
            "hiidb.bin",
            "--no-efivars",
            "--no-efivars",
        ])
        .expect_err("parse --no-efivars twice");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::ArgumentConflict,
            "--no-efivars twice"
        );
    }

    /// Every command lists its subcommands and options by name, as under clap 3: clap sorts those
    /// of one display order by name, and next_display_order = None leaves each at the default.
    /// clap's help subcommand renders none of its own subcommands, which mirror the commands.
    #[test]
    fn help_lists_every_command_s_entries_by_name() {
        let unordered = clap::Arg::new("unordered").get_display_order();
        let mut root = UefiSettingsToolArgs::command();
        root.build();
        let mut commands = vec![&root];
        while let Some(command) = commands.pop() {
            for subcommand in command.get_subcommands() {
                assert_eq!(
                    subcommand.get_display_order(),
                    unordered,
                    "subcommand {} of {}",
                    subcommand.get_name(),
                    command.get_name()
                );
                if subcommand.get_name() != "help" {
                    commands.push(subcommand);
                }
            }
            for arg in command.get_arguments().filter(|arg| !arg.is_positional()) {
                assert_eq!(
                    arg.get_display_order(),
                    unordered,
                    "option {} of {}",
                    arg.get_id(),
                    command.get_name()
                );
            }
        }
    }

    /// The flags, such as --efivars, that `text` names.
    pub(super) fn flags_named_in(text: &str) -> Vec<String> {
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|word| word.len() > 2 && word.starts_with("--"))
            .map(str::to_string)
            .collect()
    }

    /// The flags that `command` takes, as --<long>.
    pub(super) fn flags_of(command: &clap::Command) -> Vec<String> {
        command
            .get_arguments()
            .filter_map(clap::Arg::get_long)
            .map(|long| format!("--{long}"))
            .collect()
    }

    /// The help of each option names only flags that its command takes, so that it never sends a
    /// user to a flag that the command refuses.
    #[test]
    fn help_names_only_flags_of_its_command() {
        let mut root = UefiSettingsToolArgs::command();
        root.build();
        let mut commands = vec![&root];
        let mut checked = 0;
        while let Some(command) = commands.pop() {
            commands.extend(command.get_subcommands());
            let taken = flags_of(command);
            let named = command.get_arguments().flat_map(|arg| {
                [arg.get_help(), arg.get_long_help()]
                    .into_iter()
                    .flatten()
                    .flat_map(|help| flags_named_in(&help.to_string()))
                    .map(move |flag| (arg.get_id(), flag))
            });
            for (arg, flag) in named {
                assert!(
                    taken.contains(&flag),
                    "the help of {arg} of {} names {flag}",
                    command.get_name()
                );
                checked += 1;
            }
        }
        // Windows: no help names a flag (EfivarArgs names only -f), so only the builds with efivar
        // dumps, whose --efivars and --no-efivars helps name --filename, check something.
        assert!(
            checked > 0 || cfg!(not(efivar_dumps)),
            "no help names a flag"
        );
    }

    /// The hii subcommand that `args`, after `uefisettings hii`, parse to.
    pub(super) fn hii(args: &[&str]) -> clap::error::Result<HiiSubcommands> {
        let argv = [&["uefisettings", "hii"][..], args].concat();
        UefiSettingsToolArgs::try_parse_from(argv).map(|parsed| match parsed.command {
            Commands::Hii(hii) => hii.command,
            other => panic!("not a hii command: {other:?}"),
        })
    }

    #[cfg(efivar_dumps)]
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
    #[cfg(all(system_hiidb, system_variables))]
    fn set_takes_no_efivar_flags() {
        for flags in [&["--no-efivars"][..], &["--efivars", "dir"]] {
            let error = hii(&[&["set", "Question", "Value"][..], flags].concat())
                .expect_err("parse an efivar flag of set");

            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{flags:?}"
            );
        }
    }

    /// The variable commands parse, which the macOS build lacks, as it has no variables.
    #[cfg(system_variables)]
    #[test]
    fn variable_commands_parse() {
        let commands: [&[&str]; 4] = [
            &["variable", "list"],
            &[
                "variable",
                "list",
                "--guid",
                "8BE4DF61-93CA-11D2-AA0D-00E098032B8C",
            ],
            &["variable", "storage"],
            &[
                "variable",
                "storage",
                "--attributes",
                "bootservice-access,runtime-access",
            ],
        ];
        #[cfg(variable_info)]
        let commands = commands.into_iter().chain([&[
            "variable",
            "info",
            "Timeout",
            "8BE4DF61-93CA-11D2-AA0D-00E098032B8C",
        ][..]]);
        #[cfg(variable_data)]
        let commands = commands.into_iter().chain([
            &["variable", "get", "Timeout"][..],
            &[
                "variable",
                "get",
                "db",
                "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",
            ],
        ]);
        for command in commands {
            let argv = [&["uefisettings"][..], command].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            assert!(parsed.is_ok(), "{command:?}: {parsed:?}");
        }
    }

    /// The capsule commands parse, which the macOS build lacks, as it reaches no firmware.
    #[cfg(system_variables)]
    #[test]
    fn capsule_commands_parse() {
        for command in [
            &["capsule", "deliver", "payload.json", "--capsule-id", "1"][..],
            &[
                "capsule",
                "deliver",
                "--capsule-id",
                "4294967295",
                "payload.json",
            ],
        ] {
            let argv = [&["uefisettings"][..], command].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            assert!(parsed.is_ok(), "{command:?}: {parsed:?}");
        }
    }

    /// A parse error exits as clap's Error::exit exits: 2 for a usage error, 0 for --help.
    #[test]
    fn parse_errors_exit_as_clap_exits() {
        let cases: [(&[&str], ExitCode); 4] = [
            (&["hii", "set", "Q"], ExitCode::from(2)),
            (&["nonsense"], ExitCode::from(2)),
            (&["--help"], ExitCode::SUCCESS),
            (&["hii", "get", "--help"], ExitCode::SUCCESS),
        ];
        for (args, want) in cases {
            let argv = [&["uefisettings"][..], args].concat();
            let error = UefiSettingsToolArgs::try_parse_from(argv).expect_err("parse error");

            assert_eq!(parse_error_exit_code(&error), want, "{args:?}");
        }
    }

    /// --version and -V print the name and the package's version on stdout and exit 0; no
    /// subcommand takes either.
    #[test]
    fn version_flags_print_the_package_version() {
        for flag in ["--version", "-V"] {
            let error = UefiSettingsToolArgs::try_parse_from(["uefisettings", flag])
                .expect_err("print the version");

            assert_eq!(
                (
                    error.kind(),
                    error.to_string(),
                    parse_error_exit_code(&error)
                ),
                (
                    clap::error::ErrorKind::DisplayVersion,
                    format!("uefisettings {}\n", env!("CARGO_PKG_VERSION")),
                    ExitCode::SUCCESS
                ),
                "{flag}"
            );
        }
        let root = UefiSettingsToolArgs::command();
        let mut commands: Vec<(Vec<&str>, &clap::Command)> = root
            .get_subcommands()
            .map(|command| (vec![command.get_name()], command))
            .collect();
        while let Some((path, command)) = commands.pop() {
            commands.extend(
                command
                    .get_subcommands()
                    .map(|sub| ([&path[..], &[sub.get_name()]].concat(), sub)),
            );
            for flag in ["--version", "-V"] {
                let argv = [&["uefisettings"][..], &path, &[flag]].concat();
                let error = UefiSettingsToolArgs::try_parse_from(&argv)
                    .expect_err("refuse the version flag of a subcommand");

                assert_eq!(
                    (error.kind(), parse_error_exit_code(&error)),
                    (clap::error::ErrorKind::UnknownArgument, ExitCode::from(2)),
                    "{argv:?}"
                );
            }
        }
    }

    /// The values of the positionals `ids` of the innermost subcommand that `args` parse to.
    fn positionals_of(args: &[&str], ids: &[&str]) -> Result<Vec<String>, clap::error::ErrorKind> {
        let argv = [&["uefisettings"][..], args].concat();
        let mut matches = UefiSettingsToolArgs::command()
            .try_get_matches_from(argv)
            .map_err(|error| error.kind())?;
        while let Some((_, subcommand)) = matches.remove_subcommand() {
            matches = subcommand;
        }
        Ok(ids
            .iter()
            .map(|id| {
                matches
                    .remove_one::<String>(id)
                    .unwrap_or_else(|| panic!("{args:?} gives no {id}"))
            })
            .collect())
    }

    /// get commands take a negative number as the question, on every build.
    #[test]
    fn get_takes_a_negative_number_as_its_question() {
        let hii_get = [&["hii", "get"][..], &OFFLINE_SOURCE].concat();
        let commands: [&[&str]; 1] = [&hii_get];
        #[cfg(all(system_hiidb, system_variables))]
        let commands = commands.into_iter().chain([&["get"][..]]);
        // the Linux build's own command
        #[cfg(target_os = "linux")]
        let commands = commands.into_iter().chain([&["ilo", "get"][..]]);
        for command in commands {
            for question in NEGATIVE_NUMBERS {
                let args = [command, &[question]].concat();
                assert_eq!(
                    positionals_of(&args, &["question"]),
                    Ok(vec![question.to_owned()]),
                    "{args:?}"
                );
            }
            for question in OTHER_HYPHEN_VALUES {
                let args = [command, &[question]].concat();
                assert_eq!(
                    positionals_of(&args, &["question"]),
                    Err(clap::error::ErrorKind::UnknownArgument),
                    "{args:?}"
                );
                let args = [command, &["--", question]].concat();
                assert_eq!(
                    positionals_of(&args, &["question"]),
                    Ok(vec![question.to_owned()]),
                    "{args:?}"
                );
            }
        }
    }

    /// set commands take a negative number as the value, and flags stay flags around it.
    #[test]
    #[cfg(all(system_hiidb, system_variables))]
    fn set_takes_a_negative_number_as_its_value() {
        let commands: [&[&str]; 2] = [&["hii", "set"], &["set"]];
        // the Linux build's own command
        #[cfg(target_os = "linux")]
        let commands = commands.into_iter().chain([&["ilo", "set"][..]]);
        let positionals = ["question", "value"];
        for command in commands {
            for value in NEGATIVE_NUMBERS {
                for (args, question) in [
                    ([command, &["Q", value]].concat(), "Q"),
                    ([command, &["Q", value, "--json"]].concat(), "Q"),
                    ([command, &["-j", "Q", value]].concat(), "Q"),
                    ([command, &[value, value]].concat(), value),
                ] {
                    assert_eq!(
                        positionals_of(&args, &positionals),
                        Ok(vec![question.to_owned(), value.to_owned()]),
                        "{args:?}"
                    );
                }
            }
            for value in OTHER_HYPHEN_VALUES {
                let args = [command, &["Q", value]].concat();
                assert_eq!(
                    positionals_of(&args, &positionals),
                    Err(clap::error::ErrorKind::UnknownArgument),
                    "{args:?}"
                );
                let args = [command, &["Q", "--", value]].concat();
                assert_eq!(
                    positionals_of(&args, &positionals),
                    Ok(vec!["Q".to_owned(), value.to_owned()]),
                    "{args:?}"
                );
            }
            let args = [command, &["Q", "--json"]].concat();
            assert_eq!(
                positionals_of(&args, &positionals),
                Err(clap::error::ErrorKind::MissingRequiredArgument),
                "{args:?}"
            );
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

#[cfg(test)]
#[cfg(all(system_hiidb, hiidb_files))]
mod extract_db_tests {
    use anyhow::anyhow;

    use super::*;

    /// A failed read creates no file and leaves an existing one unchanged; a read writes its
    /// HiiDB.
    #[test]
    fn write_extracted_db_writes_only_a_read_hii_db() {
        let dir = tempfile::tempdir().expect("create a directory");
        let absent = dir.path().join("absent.bin");
        let existing = dir.path().join("existing.bin");
        fs::write(&existing, b"old").expect("write the existing file");

        for path in [&absent, &existing] {
            let error = write_extracted_db(path, || Err(anyhow!("no HII database")))
                .expect_err("a failed read");
            assert_eq!(
                format!("{error:#}"),
                "no HII database",
                "{}",
                path.display()
            );
        }
        assert!(
            !absent.try_exists().expect("look for the absent file"),
            "a failed read created {}",
            absent.display()
        );
        assert_eq!(
            fs::read(&existing).expect("read the existing file"),
            b"old",
            "a failed read changed the existing file"
        );

        for path in [&absent, &existing] {
            write_extracted_db(path, || Ok(b"db".to_vec())).expect("write a read HiiDB");
            assert_eq!(
                fs::read(path).expect("read the written file"),
                b"db",
                "{}",
                path.display()
            );
        }
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
}
