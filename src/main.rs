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
use std::io;
use std::io::Write;
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
use uefisettings::exports::SetOptions;
use uefisettings::exports::ShowIfrOptions;
use uefisettings_spellings_db_thrift::consts::translation_db;

use platform::EfivarArgs;
use platform::HiiDbArgs;
use platform::HiiPlatformCommands;
use platform::PlatformCommands;
use platform::SetupPasswordArgs;

/// The commands and flags that only this build has, and where it reads the HiiDB.
#[cfg_attr(target_os = "linux", path = "platform/linux.rs")]
#[cfg_attr(target_os = "uefi", path = "platform/uefi.rs")]
mod platform;

// Every command lists its options and subcommands alphabetically, as under clap 3:
// next_display_order = None leaves them unordered, and clap sorts those by name.
#[derive(Debug, Parser)]
#[command(
    name = "uefisettings",
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
    /// Commands which work on machines exposing the UEFI HiiDB
    Hii(HiiCommand),
    // TODO: Auto(AutoCommand) after building a backend identifier function
    // TODO: Get/Set without having to specify Auto
    // The platform words get and set: only the Linux build identifies a backend.
    #[command(about = platform::GET_ABOUT, next_display_order = None)]
    Get {
        question: String,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
    },
    #[command(about = platform::SET_ABOUT, next_display_order = None)]
    Set {
        question: String,
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
    #[command(next_display_order = None)]
    Set {
        question: String,
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
        hiidb: HiiDbArgs,
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

/// The exit code of clap's Error::exit for `error`: 0 for help, else 2.
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
                let res = HiiBackend::list_strings(&hiidb.read(&EfivarSource::System)?)?;
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
        Commands::Get {
            question,
            output,
            selection,
        } => platform::auto_get(question, output.json, selection)?,
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

    /// The selection flags of `uefisettings set Q V` with `args` after it.
    pub(super) fn selection_of(args: &[&str]) -> SelectionArgs {
        let command = [&["uefisettings", "set", "Q", "V"][..], args].concat();
        let parsed = UefiSettingsToolArgs::try_parse_from(&command)
            .unwrap_or_else(|error| panic!("parse {command:?}: {error}"));
        let Commands::Set { selection, .. } = parsed.command else {
            panic!("{command:?} is no set: {parsed:?}");
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

        let error = UefiSettingsToolArgs::try_parse_from([
            "uefisettings",
            "set",
            "Q",
            "V",
            "--access-level",
            "0",
        ])
        .expect_err("parse --access-level 0");
        assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue, "0");
    }

    /// --access-level comes with --include: on hii get, set and list-questions and on get and
    /// set, not on show-ifr, which evaluates no conditions, nor on ilo.
    #[test]
    fn access_level_is_taken_where_include_is() {
        let commands: [(&[&str], bool); 7] = [
            (&["hii", "get", "Q"], true),
            (&["hii", "set", "Q", "V"], true),
            (&["hii", "list-questions"], true),
            (&["get", "Q"], true),
            (&["set", "Q", "V"], true),
            (&["hii", "show-ifr"], false),
            (&["ilo", "get", "Q"], false),
        ];
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
        let commands: [&[&str]; 4] = [
            &["hii", "list-questions", "--json", "--json"],
            &["hii", "get", "Q", "-j", "--json"],
            &["show-translations", "-j", "-j"],
            &["ilo", "show-attributes", "--json", "-j"],
        ];
        for command in commands {
            let argv = [&["uefisettings"][..], command].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            assert!(parsed.is_ok(), "{command:?}: {parsed:?}");
        }

        let error = hii(&["list-questions", "--no-efivars", "--no-efivars"])
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

    /// The hii subcommand that `args`, after `uefisettings hii`, parse to.
    pub(super) fn hii(args: &[&str]) -> clap::error::Result<HiiSubcommands> {
        let argv = [&["uefisettings", "hii"][..], args].concat();
        UefiSettingsToolArgs::try_parse_from(argv).map(|parsed| match parsed.command {
            Commands::Hii(hii) => hii.command,
            other => panic!("not a hii command: {other:?}"),
        })
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

            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{flags:?}"
            );
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
