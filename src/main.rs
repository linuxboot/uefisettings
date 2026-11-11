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

use anyhow::anyhow;
use anyhow::Result;
#[cfg(all(system_hiidb, system_variables))]
use clap::ArgGroup;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use fbthrift::simplejson_protocol;
use fbthrift::simplejson_protocol::Serializable;
use log::info;
use uefisettings::exports::AssumedVarStore;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::IncludedStates;
use uefisettings::exports::KeywordName;
use uefisettings::exports::KeywordNamespace;
#[cfg(system_variables)]
use uefisettings::exports::LiftedOperations;
use uefisettings::exports::ListQuestionsOptions;
use uefisettings::exports::QuestionAddress;
use uefisettings::exports::QuestionSelector;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::SetOptions;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::SetValue;
use uefisettings::exports::ShowIfrOptions;
#[cfg(system_variables)]
use uefisettings::exports::UnsafeOperation;
#[cfg(system_variables)]
use uefisettings::exports::UnsafeOperations;
use uefisettings::terminal_text::escape_unrendered;
use uefisettings::terminal_text::JsonText;
use uefisettings::terminal_text::OutputSyntax;
use uefisettings::terminal_text::TerminalText;
use uefisettings::terminal_text::TextLines;
use uefisettings::terminal_text::TextOutput;
use uefisettings_spellings_db_thrift::consts::translation_db;

#[cfg(system_variables)]
use capsule_command::CapsuleCommand;
use platform::EfivarArgs;
use platform::HiiDbArgs;
use platform::HiiPlatformCommands;
use platform::HiiSourceArgs;
#[cfg(all(system_hiidb, system_variables))]
use platform::HiiSourceUnsafeArgs;
use platform::ListStringsHiiDbArgs;
use platform::MachineHii;
use platform::PlatformCommands;
#[cfg(all(system_hiidb, system_variables))]
use platform::StagingArgs;
#[cfg(all(system_hiidb, system_variables))]
use platform::VolatileArgs;
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
    #[command(flatten)]
    hii_source: HiiSourceArgs,
}

#[derive(Debug, Subcommand)]
#[cfg_attr(
    target_os = "macos",
    expect(
        clippy::large_enum_variant,
        reason = "parsed once per run; without get and set, no other variant is as large as hii"
    )
)]
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
        #[command(flatten)]
        question: QuestionArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        unsafe_operations: HiiSourceUnsafeArgs,
    },
    // clap takes an optional QUESTION before the required VALUE with allow_missing_positional: a
    // lone positional is VALUE, so `set QUESTION` fails for its missing selector.
    #[cfg(all(system_hiidb, system_variables))]
    #[command(about = platform::SET_ABOUT, next_display_order = None, allow_missing_positional = true)]
    #[cfg_attr(system_time, command(long_about = platform::SET_LONG_ABOUT))]
    // With --item, which leaves no VALUE, a lone positional is QUESTION (SetArgs::target), so
    // SetTarget, which --item meets too, stands in for the requirement of QuestionSelectorArgs.
    #[command(mut_group("QuestionSelectorArgs", |group| group.required(false)))]
    #[command(group(ArgGroup::new("SetTarget")
        .args(["question", "question_id", "keyword", "items"])
        .required(true)
        .multiple(true)))]
    #[command(mut_arg(UNSAFE_ARG, |arg| unsafe_long_help(arg, platform::SET_UNSAFE_OPERATIONS)))]
    Set {
        #[command(flatten)]
        target: SetArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        unsafe_operations: UnsafeArgs,
        #[command(flatten)]
        volatile: VolatileArgs,
        #[command(flatten)]
        staging: StagingArgs,
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
    /// Commands that pass capsules to this machine's firmware, or show the configuration data and the capsule processing results that it reports
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
        #[command(flatten)]
        question: QuestionArgs,
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
    #[command(next_display_order = None, allow_missing_positional = true)]
    #[cfg_attr(system_time, command(long_about = platform::SET_LONG_ABOUT))]
    // With --item, which leaves no VALUE, a lone positional is QUESTION (SetArgs::target), so
    // SetTarget, which --item meets too, stands in for the requirement of QuestionSelectorArgs.
    #[command(mut_group("QuestionSelectorArgs", |group| group.required(false)))]
    #[command(group(ArgGroup::new("SetTarget")
        .args(["question", "question_id", "keyword", "items"])
        .required(true)
        .multiple(true)))]
    #[command(mut_arg(UNSAFE_ARG, |arg| unsafe_long_help(arg, platform::SET_UNSAFE_OPERATIONS)))]
    Set {
        #[command(flatten)]
        target: SetArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs,
        #[command(flatten)]
        unsafe_operations: UnsafeArgs,
        #[command(flatten)]
        volatile: VolatileArgs,
        #[command(flatten)]
        staging: StagingArgs,
    },
    /// Show a human readable representation of the Hii Forms
    #[command(next_display_order = None)]
    ShowIFR {
        #[command(flatten)]
        hiidb: HiiDbArgs,
        #[command(flatten)]
        efivars: EfivarArgs,
        #[command(flatten)]
        language: LanguageArgs,
    },
    /// List all strings-id, string pairs in HiiDB, with each strings package's language
    #[command(next_display_order = None)]
    ListStrings {
        #[command(flatten)]
        hiidb: ListStringsHiiDbArgs,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// List the one-of, numeric, checkbox, date, time, ordered-list and string questions of the HiiDB, and its cross-reference questions on a VarStore, whose values get reads; set does not write a cross-reference's value, the target of its link.
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

/// What set selects, and the value or the items that it gives.
#[cfg(all(system_hiidb, system_variables))]
#[derive(Debug, Args)]
struct SetArgs {
    #[command(flatten)]
    question: QuestionArgs,
    /// The new value; required unless --item gives the items of an ORDERED_LIST
    #[arg(allow_negative_numbers = true, required_unless_present = "items")]
    value: Option<String>,
    /// Give an ORDERED_LIST question the option of this text in its next container, in order,
    /// instead of VALUE: repeat it for each item (UEFI 2.11 §33.3.8.3.53)
    #[arg(long = "item", value_name = "TEXT")]
    items: Vec<String>,
}

#[cfg(all(system_hiidb, system_variables))]
impl SetArgs {
    /// The questions that set selects and the value that it gives them, VALUE or the items.
    /// clap takes a lone positional as VALUE (allow_missing_positional), so with items, which
    /// leave no VALUE, a lone positional is QUESTION; beside --question-id or --keyword it is
    /// neither.
    fn target(&self) -> Result<(QuestionSelector, SetValue)> {
        let QuestionSelectorArgs {
            question: prompt,
            question_id,
            keyword,
        } = &self.question.selector;
        let selects_nothing = prompt.is_none() && question_id.is_none() && keyword.is_none();
        match (&self.value, self.items.is_empty()) {
            (Some(value), true) => Ok((self.question.selector()?, SetValue::Text(value.clone()))),
            (None, false) => Ok((
                self.question.selector()?,
                SetValue::Items(self.items.clone()),
            )),
            (Some(lone), false) if selects_nothing => Ok((
                QuestionSelector::Prompt(lone.clone()),
                SetValue::Items(self.items.clone()),
            )),
            (Some(_), false) if prompt.is_none() => Err(anyhow::anyhow!(
                "set takes no QUESTION or VALUE beside --item and --question-id or --keyword"
            )),
            (Some(_), false) | (None, true) => {
                Err(anyhow::anyhow!("set takes either VALUE or --item"))
            }
        }
    }
}

/// -j/--json, which overrides itself: it may repeat, as under clap 3.
#[derive(Debug, Args)]
struct JsonArgs {
    #[arg(short = 'j', long = "json", overrides_with = "json")]
    json: bool,
}

/// Which questions get and set select: by QUESTION, --question-id or --keyword.
#[derive(Debug, Args)]
struct QuestionArgs {
    #[command(flatten)]
    selector: QuestionSelectorArgs,
    /// Search --keyword in strings packages whose language starts with LANGUAGE instead of
    /// "x-UEFI", as edk2's Keyword Handler does without a NamespaceId (UEFI 2.11 §35.3.3),
    /// LANGUAGE a configuration language: one that starts with "x-"; requires --keyword
    // clap lets a `requires` go unmet where its target conflicts with a given argument, as
    // --keyword does with the rest of its group, so those conflict here too.
    #[arg(
        long,
        value_name = "LANGUAGE",
        requires = "keyword",
        conflicts_with_all = ["question", "question_id"]
    )]
    keyword_namespace: Option<KeywordNamespace>,
}

/// The one of QUESTION, --question-id and --keyword that get and set take.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct QuestionSelectorArgs {
    /// one of QUESTION, --question-id and --keyword is required
    #[arg(allow_negative_numbers = true)]
    question: Option<String>,
    /// Select the question of QuestionId ID in the FormSet of GUID, in every package list that
    /// holds that FormSet, instead of by QUESTION; ID in decimal or 0x hex, 1 to 0xFFFF (0 is
    /// reserved), as list-questions shows question_id and form_set_guid
    #[arg(long, value_name = "GUID:ID")]
    question_id: Option<QuestionAddress>,
    /// Select the question whose prompt is KEYWORD, exactly and with its case, any ":<digits>"
    /// instance suffix included, in the first strings package of a configuration language of
    /// each package list, as the Keyword Handler finds it, instead of by QUESTION
    #[allow(
        rustdoc::invalid_html_tags,
        reason = "clap prints this doc comment as the help of --keyword, where <digits> is text"
    )]
    #[arg(long, value_name = "KEYWORD")]
    keyword: Option<KeywordName>,
}

impl QuestionArgs {
    /// The questions that these flags select.
    fn selector(&self) -> Result<QuestionSelector> {
        let QuestionSelectorArgs {
            question,
            question_id,
            keyword,
        } = &self.selector;
        match (question, question_id, keyword) {
            (Some(question), None, None) => Ok(QuestionSelector::Prompt(question.clone())),
            (None, Some(address), None) => Ok(QuestionSelector::Address(*address)),
            (None, None, Some(keyword)) => Ok(QuestionSelector::Keyword {
                keyword: keyword.clone(),
                namespace: self.keyword_namespace.clone(),
            }),
            // QuestionSelectorArgs's group lets clap parse none of these
            _ => Err(anyhow!(
                "exactly one of QUESTION, --question-id and --keyword is required"
            )),
        }
    }
}

/// The states of the questions and options that get, set, list-questions and the UEFI Shell
/// build's hii keyword set select too.
#[derive(Debug, Args)]
struct IncludeArgs {
    /// Also select questions that conditions gray out, suppress or disable. The edk2 setup
    /// browser (edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpressionList) ranks
    /// DisableIf > SuppressIf > GrayOutIf, so a question that is both grayed out and suppressed
    /// counts as suppressed.
    #[arg(long, value_enum, value_delimiter = ',')]
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
}

/// Which questions and options get, set and list-questions select.
#[derive(Debug, Args)]
struct SelectionArgs {
    #[command(flatten)]
    include: IncludeArgs,
    /// Evaluate conditions as if the VarStore whose efivar file is NAME-GUID held the bytes HEX,
    /// two hex digits each, from byte OFFSET of its payload on (decimal, or hexadecimal after 0x;
    /// default 0), whatever its variable holds; the reason of an unreadable value names
    /// NAME-GUID+OFFSET. States, the options that conditions hide and the defaults they pick
    /// follow these bytes; the questions on them still answer with what their variable holds,
    /// and writes write the variable. This states what a setup browser holds; it is no password
    /// and authenticates nothing (UEFI variable writes carry no password).
    #[arg(long, value_name = "NAME-GUID[+OFFSET]=HEX")]
    assume_var_store: Vec<AssumedVarStore>,
    #[command(flatten)]
    language: LanguageArgs,
}

/// The language that texts show in, which commands that show texts take.
#[derive(Debug, Args)]
struct LanguageArgs {
    /// Show prompts, help and option texts in this language instead of the platform language
    /// (PlatformLang): in each package list, the strings package that edk2 GetBestLanguage picks
    /// for TAG (TAG, then TAG cut at each '-', ignoring ASCII case), else the one it picks for
    /// PlatformLang, else the first whose language does not start with "x-". QUESTION and VALUE
    /// still match the texts of every such language.
    #[arg(long, value_name = "TAG")]
    language: Option<String>,
}

impl SelectionArgs {
    fn states(&self) -> IncludedStates {
        self.include.states()
    }
}

impl From<&SelectionArgs> for GetOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.assume_var_stores.clone_from(&args.assume_var_store);
        options.language.clone_from(&args.language.language);
        options
    }
}

#[cfg(all(system_hiidb, system_variables))]
impl From<&SelectionArgs> for SetOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.assume_var_stores.clone_from(&args.assume_var_store);
        options.language.clone_from(&args.language.language);
        options
    }
}

impl From<&SelectionArgs> for ListQuestionsOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.assume_var_stores.clone_from(&args.assume_var_store);
        options.language.clone_from(&args.language.language);
        options
    }
}

/// The id of --i-am-fine-to-brick-this-system, under which each command's long help lists its own
/// unsafe operations.
#[cfg(system_variables)]
const UNSAFE_ARG: &str = "i_am_fine_to_brick_this_system";

/// The help of --i-am-fine-to-brick-this-system, in every command that takes it.
#[cfg(system_variables)]
const UNSAFE_HELP: &str = "Do what this command otherwise refuses because it can bypass this \
                           machine's setup password, write a value that its firmware declares \
                           read-only, weaken Secure Boot, change it irreversibly or read device \
                           memory; each refusal names what this flag does there";

/// What set refuses without --i-am-fine-to-brick-this-system on every build.
#[cfg(all(system_hiidb, system_variables))]
const READ_ONLY_WRITE: &str = "a write of a question that EFI_IFR_FLAG_READ_ONLY makes read-only \
                               (UEFI 2.11 §33.3.8.2.2), never one that an EFI_IFR_VALUE makes \
                               read-only (§33.3.8.3.88); of questions with the same text, set \
                               picks a writable one first among matches equally certain to be \
                               selected";

/// What set refuses without --i-am-fine-to-brick-this-system on the builds that stage a set for
/// the next boot.
#[cfg(all(
    system_hiidb,
    system_variables,
    any(target_os = "linux", target_os = "windows")
))]
const STAGED_SETUP_PASSWORD: &str = "a set staged for the next boot in a HiiDB that declares a \
                                     setup password question, which the next boot applies before \
                                     the OS, where no setup browser asks for or checks it";

/// --i-am-fine-to-brick-this-system, which only the commands that have an unsafe operation take.
#[cfg(system_variables)]
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
struct UnsafeArgs {
    #[arg(long, help = UNSAFE_HELP)]
    i_am_fine_to_brick_this_system: bool,
}

#[cfg(system_variables)]
impl UnsafeArgs {
    fn operations(&self) -> UnsafeOperations {
        match self.i_am_fine_to_brick_this_system {
            false => UnsafeOperations::Refuse,
            true => UnsafeOperations::Allow,
        }
    }
}

/// `arg`, --i-am-fine-to-brick-this-system, with a long help that lists `operations`, the unsafe
/// operations of its command.
#[cfg(system_variables)]
fn unsafe_long_help(arg: clap::Arg, operations: &[&str]) -> clap::Arg {
    arg.long_help(format!(
        "{UNSAFE_HELP}. This command refuses without it: {}",
        operations.join("; ")
    ))
}

/// The SetOptions of `selection`, `unsafe_operations`, `volatile` and `staging`.
#[cfg(all(system_hiidb, system_variables))]
fn set_options(
    selection: &SelectionArgs,
    unsafe_operations: &UnsafeArgs,
    volatile: &VolatileArgs,
    staging: &StagingArgs,
) -> SetOptions {
    let mut options = SetOptions::from(selection);
    options.unsafe_operations = unsafe_operations.operations();
    options.volatile = volatile.policy();
    options.staging_image = staging.image();
    options.staging_esp = staging.esp();
    options
}

/// get of `question` in the HiiDB `db_bytes` with `options`, printed as JSON if `json`.
fn hii_get(
    db_bytes: &[u8],
    question: QuestionSelector,
    options: &GetOptions,
    json: bool,
) -> Result<()> {
    let res = HiiBackend::get_using(db_bytes, question, None, options)?;
    print_with_style(res, json)?;
    Ok(())
}

/// set of `question` to `value` with `options`, in this machine's HiiDB, read as `source` says,
/// and variables, printed as JSON if `json`, after a warning per unsafe operation that it lifted.
#[cfg(all(system_hiidb, system_variables))]
fn hii_set(
    question: QuestionSelector,
    value: &SetValue,
    options: &SetOptions,
    json: bool,
    source: &HiiSourceArgs,
    hii: &impl MachineHii,
) -> Result<()> {
    let (res, lifted) = platform::set_using(question, value, options, source, hii)?;
    print_lifted(&lifted)?;
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
        #[cfg(system_variables)]
        if let Err(print_error) = print_lifted_of(&why) {
            log::debug!("failed to print the warnings of the error: {print_error}");
        }
        if is_broken_pipe(&why) {
            return ExitCode::SUCCESS;
        }

        if let Err(print_error) = print_with_style(
            uefisettings_backend_thrift::Error {
                error_message: format!("{:#}", why),
                ..Default::default()
            },
            true,
        ) {
            log::debug!("failed to print the error: {print_error}");
        }
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
    handle_cmds_with(args, &platform::Firmware)
}

/// handle_cmds, with this machine's HII backend reached through `hii`.
fn handle_cmds_with(args: UefiSettingsToolArgs, hii: &impl MachineHii) -> Result<()> {
    let source = &args.hii_source;
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
                    &hiidb.read(&options.efivars, source, hii)?,
                    question.selector()?,
                    &options,
                    output.json,
                )?;
            }
            #[cfg(all(system_hiidb, system_variables))]
            HiiSubcommands::Set {
                target,
                output,
                selection,
                unsafe_operations,
                volatile,
                staging,
            } => {
                let (question, value) = target.target()?;
                let options = set_options(selection, unsafe_operations, volatile, staging);
                hii_set(question, &value, &options, output.json, source, hii)?
            }
            HiiSubcommands::ShowIFR {
                hiidb,
                efivars,
                language,
            } => {
                let mut options = ShowIfrOptions::default();
                options.efivars = efivars.source()?;
                options.language.clone_from(&language.language);
                // before the HiiDB is read
                options.efivars.validate()?;
                let lines = HiiBackend::show_ifr_lines_using(
                    &hiidb.read(&options.efivars, source, hii)?,
                    &options,
                )?;
                print_terminal_lines(&lines)?;
            }
            HiiSubcommands::ListStrings { hiidb, output } => {
                let res =
                    HiiBackend::list_strings(&hiidb.read(&EfivarSource::Disabled, source, hii)?)?;
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
                let (res, ignored_ifr) = HiiBackend::list_questions_and_ignored_ifr_using(
                    &hiidb.read(&options.efivars, source, hii)?,
                    &options,
                )?;
                print_with_style(res, output.json)?;
                // the questions' list keeps its form, so the IFR that may hold more goes to stderr
                for ignored in ignored_ifr {
                    print_warning(format_args!("questions may be in {ignored}"))?;
                }
            }
            HiiSubcommands::Platform(command) => command.run(source, hii)?,
        },
        #[cfg(all(system_hiidb, system_variables))]
        Commands::Get {
            question,
            output,
            selection,
            unsafe_operations,
        } => platform::auto_get(
            question,
            output.json,
            selection,
            unsafe_operations,
            source,
            hii,
        )?,
        #[cfg(all(system_hiidb, system_variables))]
        Commands::Set {
            target,
            output,
            selection,
            unsafe_operations,
            volatile,
            staging,
        } => {
            let options = set_options(selection, unsafe_operations, volatile, staging);
            platform::auto_set(
                target,
                output.json,
                selection,
                staging,
                &options,
                source,
                hii,
            )?
        }
        Commands::ShowTranslations { output } => {
            source.refuse_given("show-translations reads none")?;
            print_with_style(&*translation_db, output.json)?;
        }
        #[cfg(system_variables)]
        Commands::Variable(command) => {
            source.refuse_given("variable reads none")?;
            command.run()?
        }
        #[cfg(system_variables)]
        Commands::Capsule(command) => {
            source.refuse_given("capsule reads none")?;
            command.run()?
        }
        Commands::Platform(command) => command.run(source, hii)?,
    }
    Ok(())
}

// the Linux build's ilo notes; the other text goes through TerminalText or Debug
#[cfg(target_os = "linux")]
fn print_line(arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    let stdout = io::stdout();
    write_lines(
        &mut stdout.lock(),
        &mut platform::stdout_output()?,
        OutputSyntax::Text,
        &arguments.to_string(),
    )
}

/// Prints `value` as its JSON text, as JsonText.
#[cfg(any(system_variables, all(system_hiidb, hiidb_files)))]
fn print_json(value: &impl serde::Serialize) -> io::Result<()> {
    let stdout = io::stdout();
    write_json(&mut stdout.lock(), &mut platform::stdout_output()?, value)
}

/// Writes `value` to `output` as its JSON text, as JsonText.
#[cfg(any(system_variables, all(system_hiidb, hiidb_files), test))]
fn write_json(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    value: &impl serde::Serialize,
) -> io::Result<()> {
    let json = serde_json::to_string(value)?;
    write_lines(
        output,
        console,
        OutputSyntax::Json,
        &JsonText(&json).to_string(),
    )
}

/// Writes `text`, of `syntax`, to `output` line by line, each with what `console` cannot render
/// escaped (escape_unrendered), and ended with `\n`. Its line breaks are the ones that
/// uefisettings writes: TerminalText, JSON and Debug escape those of the texts that it prints.
fn write_lines(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    syntax: OutputSyntax,
    text: &str,
) -> io::Result<()> {
    text.split('\n')
        .try_for_each(|line| writeln!(output, "{}", escape_unrendered(line, syntax, console)?))
}

/// Prints `lines`, which may show the HiiDB's strings, each as TerminalText, so that a line break
/// of a string shows as `\n` and starts no line, then an empty line, as show-ifr always has.
fn print_terminal_lines(lines: &TextLines) -> io::Result<()> {
    let stdout = io::stdout();
    write_terminal_lines(&mut stdout.lock(), &mut platform::stdout_output()?, lines)
}

fn write_terminal_lines(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    lines: &TextLines,
) -> io::Result<()> {
    lines.lines().try_for_each(|line| {
        write_lines(
            output,
            console,
            OutputSyntax::Text,
            &TerminalText(line).to_string(),
        )
    })?;
    writeln!(output)
}

/// Prints the warning `arguments` on stderr as TerminalText, as it may name the HiiDB's strings.
fn print_warning(arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    let stderr = io::stderr();
    write_warning(
        &mut stderr.lock(),
        &mut platform::stderr_output()?,
        arguments,
    )
}

fn write_warning(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    arguments: std::fmt::Arguments<'_>,
) -> io::Result<()> {
    let warning = format!("warning: {}", TerminalText(&arguments.to_string()));
    write_lines(output, console, OutputSyntax::Text, &warning)
}

/// Prints `line` of what apply-staged did, which may name the HiiDB's strings, such as the prompt
/// of a staged question, as TerminalText after `apply-staged: `.
#[cfg(target_os = "uefi")]
fn print_apply_staged_line(line: &str) -> io::Result<()> {
    let stdout = io::stdout();
    write_apply_staged_line(&mut stdout.lock(), &mut platform::stdout_output()?, line)
}

#[cfg(any(target_os = "uefi", test))]
fn write_apply_staged_line(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    line: &str,
) -> io::Result<()> {
    let line = format!("apply-staged: {}", TerminalText(line));
    write_lines(output, console, OutputSyntax::Text, &line)
}

/// Prints `value` as TerminalText, or as its JSON text, as JsonText, if `json`.
#[cfg(target_os = "uefi")]
fn print_display_or_json(
    value: &(impl std::fmt::Display + serde::Serialize),
    json: bool,
) -> io::Result<()> {
    let stdout = io::stdout();
    write_display_or_json(
        &mut stdout.lock(),
        &mut platform::stdout_output()?,
        value,
        json,
    )
}

/// Writes `value` to `output` as TerminalText, or as its JSON text, as JsonText, if `json`.
#[cfg(any(target_os = "uefi", test))]
fn write_display_or_json(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    value: &(impl std::fmt::Display + serde::Serialize),
    json: bool,
) -> io::Result<()> {
    match json {
        true => write_json(output, console, value),
        false => {
            let text = TerminalText(&value.to_string()).to_string();
            write_lines(output, console, OutputSyntax::Text, &text)
        }
    }
}

/// Prints a warning per unsafe operation in `lifted`, which --i-am-fine-to-brick-this-system let
/// a command do.
#[cfg(system_variables)]
fn print_lifted(lifted: &[UnsafeOperation]) -> io::Result<()> {
    let stderr = io::stderr();
    write_lifted(&mut stderr.lock(), &mut platform::stderr_output()?, lifted)
}

#[cfg(system_variables)]
fn write_lifted(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    lifted: &[UnsafeOperation],
) -> io::Result<()> {
    lifted.iter().try_for_each(|operation| {
        write_warning(
            output,
            console,
            format_args!("{}", operation.lifted_warning()),
        )
    })
}

/// Prints a warning per unsafe operation that `error`, a command's, carries as lifted before
/// the command failed (LiftedOperations).
#[cfg(system_variables)]
fn print_lifted_of(error: &anyhow::Error) -> io::Result<()> {
    let stderr = io::stderr();
    write_lifted_of(&mut stderr.lock(), &mut platform::stderr_output()?, error)
}

#[cfg(system_variables)]
fn write_lifted_of(
    output: &mut impl Write,
    console: &mut impl TextOutput,
    error: &anyhow::Error,
) -> io::Result<()> {
    match error.downcast_ref::<LiftedOperations>() {
        Some(lifted) => write_lifted(output, console, &lifted.0),
        None => Ok(()),
    }
}

// print_with_style either prints as json or with rust's debug pretty-printer
fn print_with_style<T>(result: T, json: bool) -> io::Result<()>
where
    T: Serializable + Debug,
{
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_with_style(&mut output, &mut platform::stdout_output()?, result, json)
}

fn write_with_style<W, T>(
    output: &mut W,
    console: &mut impl TextOutput,
    result: T,
    json: bool,
) -> io::Result<()>
where
    W: Write,
    T: Serializable + Debug,
{
    if json {
        let buf = simplejson_protocol::serialize(result);
        let json = JsonText(&String::from_utf8_lossy(&buf)).to_string();
        write_lines(output, console, OutputSyntax::Json, &json)
    } else {
        write_lines(
            output,
            console,
            OutputSyntax::Text,
            &format!("{:#?}", result),
        )
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
    use uefisettings::terminal_text::UnicodeTerminal;

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

    /// A variable write-signed that parses.
    #[cfg(variable_data)]
    const WRITE_SIGNED: [&str; 8] = [
        "variable",
        "write-signed",
        "db",
        "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",
        "--attributes",
        "non-volatile",
        "--payload-file",
        "db.auth",
    ];

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

    /// The selection flags of `uefisettings hii set Q V` with `args` after it.
    #[cfg(all(system_hiidb, system_variables))]
    fn set_selection_of(args: &[&str]) -> SelectionArgs {
        let command = [&["set", "Q", "V"][..], args].concat();
        let parsed = hii(&command).unwrap_or_else(|error| panic!("parse {command:?}: {error}"));
        let HiiSubcommands::Set { selection, .. } = parsed else {
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
                IncludedStates::CONDITIONS,
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
            assert_eq!(
                SetOptions::from(&set_selection_of(&args)).include,
                states,
                "{name}: set"
            );
            assert_eq!(
                ListQuestionsOptions::from(&selection).include,
                states,
                "{name}: list-questions"
            );
        }
    }

    /// --assume-var-store, repeatable, gives get, set and list-questions its statements in order;
    /// a value that is no NAME-GUID[+OFFSET]=HEX is refused before any command runs.
    #[test]
    fn assume_var_store_maps_to_its_flag() {
        const MODE: &str = "Mode-11111111-1111-1111-1111-111111111111";
        let cases = [
            ("no flag", vec![], vec![]),
            (
                "one",
                vec!["--assume-var-store".to_string(), format!("{MODE}=01")],
                vec![format!("{MODE}+0=01")],
            ),
            (
                "two",
                vec![
                    "--assume-var-store".to_string(),
                    format!("{MODE}+2=0a0b"),
                    "--assume-var-store".to_string(),
                    format!("{MODE}+0x10=ff"),
                ],
                vec![format!("{MODE}+2=0a0b"), format!("{MODE}+16=ff")],
            ),
        ];
        for (name, args, want) in cases {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let shown = |assumed: &[AssumedVarStore]| -> Vec<String> {
                assumed.iter().map(ToString::to_string).collect()
            };
            let selection = selection_of(&args);
            assert_eq!(
                shown(&GetOptions::from(&selection).assume_var_stores),
                want,
                "{name}: get"
            );
            #[cfg(all(system_hiidb, system_variables))]
            assert_eq!(
                shown(&SetOptions::from(&set_selection_of(&args)).assume_var_stores),
                want,
                "{name}: set"
            );
            assert_eq!(
                shown(&ListQuestionsOptions::from(&selection).assume_var_stores),
                want,
                "{name}: list-questions"
            );
        }

        for value in [MODE, &format!("{MODE}=0"), &format!("{MODE}+x=00")] {
            let error = hii(&[
                &["list-questions"][..],
                &OFFLINE_SOURCE,
                &["--assume-var-store", value],
            ]
            .concat())
            .expect_err("parse --assume-var-store");
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::ValueValidation,
                "{value}"
            );
        }
    }

    /// --assume-var-store comes with --include: on hii get, set and list-questions and on get and
    /// set, not on show-ifr, which evaluates no conditions, nor on ilo.
    #[test]
    fn assume_var_store_is_taken_where_include_is() {
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
            let argv = [
                &["uefisettings"][..],
                command,
                &[
                    "--assume-var-store",
                    "Mode-11111111-1111-1111-1111-111111111111=01",
                ],
            ]
            .concat();
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

    /// No command's --include takes read-only: get and list-questions show read-only questions
    /// regardless, and set writes one with --i-am-fine-to-brick-this-system.
    #[test]
    fn include_takes_no_read_only() {
        let reading: [&[&str]; 2] = [&["hii", "get", "Q"], &["hii", "list-questions"]];
        let reading = reading.map(|command| [command, &OFFLINE_SOURCE].concat());
        let commands = reading.iter().map(|command| &command[..]);
        #[cfg(all(system_hiidb, system_variables))]
        let commands = commands.chain([
            &["get", "Q"][..],
            &["hii", "set", "Q", "V"],
            &["set", "Q", "V"],
        ]);
        for command in commands {
            let argv = [&["uefisettings"][..], command, &["--include", "read-only"]].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            assert_eq!(
                parsed.err(),
                Some(clap::error::ErrorKind::InvalidValue),
                "{command:?}"
            );
        }
    }

    /// --i-am-fine-to-brick-this-system is taken by set and hii set, which grant
    /// UnsafeOperations::Allow with it and Refuse without, and whose long help lists their unsafe
    /// operations; get, list-questions and show-ifr, which read this machine's HiiDB, take it on
    /// Linux only, for --efivar-memory firmware-reserved; variable get, which has none, refuses it.
    #[test]
    fn unsafe_flag_is_taken_where_an_operation_is_unsafe() {
        let reading: [&[&str]; 3] = [
            &["hii", "get", "Q"],
            &["hii", "list-questions"],
            &["hii", "show-ifr"],
        ];
        let reading = reading.map(|command| [command, &OFFLINE_SOURCE].concat());
        let commands = reading.iter().map(|command| (&command[..], false));
        #[cfg(all(system_hiidb, system_variables))]
        let commands = commands.chain([(&["get", "Q"][..], false)]);
        // the Linux build's readers take it, for --efivar-memory firmware-reserved
        #[cfg(target_os = "linux")]
        let commands = commands.map(|(command, _)| (command, true));
        #[cfg(variable_data)]
        let commands = commands.chain([(&["variable", "get", "Timeout"][..], false)]);
        for (command, takes) in commands {
            let argv = [
                &["uefisettings"][..],
                command,
                &["--i-am-fine-to-brick-this-system"],
            ]
            .concat();
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

        #[cfg(all(system_hiidb, system_variables))]
        for (args, want) in [
            (&[][..], UnsafeOperations::Refuse),
            (
                &["--i-am-fine-to-brick-this-system"],
                UnsafeOperations::Allow,
            ),
        ] {
            let command = [&["set", "Q", "V"][..], args].concat();
            let parsed = hii(&command).unwrap_or_else(|error| panic!("parse {command:?}: {error}"));
            let HiiSubcommands::Set {
                unsafe_operations, ..
            } = parsed
            else {
                panic!("{command:?} is no set: {parsed:?}");
            };
            assert_eq!(unsafe_operations.operations(), want, "hii {command:?}");

            let argv = [&["uefisettings", "set", "Q", "V"][..], args].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));
            let Commands::Set {
                unsafe_operations, ..
            } = parsed.command
            else {
                panic!("{argv:?} is no set");
            };
            assert_eq!(unsafe_operations.operations(), want, "{argv:?}");
        }

        #[cfg(all(system_hiidb, system_variables))]
        for path in [&["set"][..], &["hii", "set"]] {
            let mut command = UefiSettingsToolArgs::command();
            command.build();
            let set = path.iter().fold(&command, |command, name| {
                command
                    .find_subcommand(name)
                    .unwrap_or_else(|| panic!("no subcommand {name}"))
            });
            let flag = set
                .get_arguments()
                .find(|arg| arg.get_long() == Some("i-am-fine-to-brick-this-system"))
                .unwrap_or_else(|| panic!("{path:?} takes no --i-am-fine-to-brick-this-system"));
            let long_help = flag.get_long_help().map(ToString::to_string);
            assert!(
                long_help.as_deref().is_some_and(|help| {
                    help.starts_with(UNSAFE_HELP)
                        && platform::SET_UNSAFE_OPERATIONS
                            .iter()
                            .all(|operation| help.contains(operation))
                }),
                "{path:?}: {long_help:?}"
            );
        }
    }

    /// --language goes to the options of hii get, set and list-questions, get and set through
    /// their selection flags, and show-ifr; list-strings, which shows every language, and ilo
    /// take none.
    #[test]
    fn language_is_taken_where_texts_show() {
        let selection = selection_of(&["--language", "fr-FR"]);
        let stated = Some("fr-FR".to_string());
        assert_eq!(GetOptions::from(&selection).language, stated, "get");
        #[cfg(all(system_hiidb, system_variables))]
        assert_eq!(
            SetOptions::from(&set_selection_of(&["--language", "fr-FR"])).language,
            stated,
            "set"
        );
        assert_eq!(
            ListQuestionsOptions::from(&selection).language,
            stated,
            "list-questions"
        );
        assert_eq!(selection_of(&[]).language.language, None, "no flag");
        let show_ifr = [&["show-ifr"][..], &OFFLINE_SOURCE, &["--language", "fr-FR"]].concat();
        match hii(&show_ifr).expect("parse show-ifr --language fr-FR") {
            HiiSubcommands::ShowIFR { language, .. } => {
                assert_eq!(language.language, stated, "show-ifr")
            }
            other => panic!("not show-ifr: {other:?}"),
        }

        // list-strings takes -f but no --no-efivars
        let reading: [(&[&str], &[&str], bool); 4] = [
            (&["hii", "get", "Q"], &OFFLINE_SOURCE, true),
            (&["hii", "list-questions"], &OFFLINE_SOURCE, true),
            (&["hii", "show-ifr"], &OFFLINE_SOURCE, true),
            (&["hii", "list-strings"], &OFFLINE_SOURCE[..2], false),
        ];
        let reading = reading.map(|(command, source, takes)| ([command, source].concat(), takes));
        let commands = reading
            .iter()
            .map(|(command, takes)| (&command[..], *takes));
        #[cfg(all(system_hiidb, system_variables))]
        let commands = commands.into_iter().chain([
            (&["hii", "set", "Q", "V"][..], true),
            (&["get", "Q"], true),
            (&["set", "Q", "V"], true),
        ]);
        #[cfg(target_os = "linux")]
        let commands = commands
            .into_iter()
            .chain([(&["ilo", "get", "Q"][..], false)]);
        for (command, takes) in commands {
            let argv = [&["uefisettings"][..], command, &["--language", "fr-FR"]].concat();
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

    /// write_lifted writes a "warning:" line per lifted unsafe operation, and none for none.
    #[cfg(system_variables)]
    #[test]
    fn write_lifted_warns_per_operation() {
        let mut none = Vec::new();
        write_lifted(&mut none, &mut UnicodeTerminal, &[]).expect("write no warning");
        assert_eq!(String::from_utf8_lossy(&none), "", "none");

        let mut warned = Vec::new();
        let lifted = [UnsafeOperation::SetupPassword];
        write_lifted(&mut warned, &mut UnicodeTerminal, &lifted).expect("write the warning");
        assert_eq!(
            String::from_utf8_lossy(&warned),
            format!(
                "warning: {}\n",
                UnsafeOperation::SetupPassword.lifted_warning()
            ),
            "SetupPassword"
        );
    }

    /// A lifted warning shows a question's name escaped once, as show-ifr shows it: `\` as `\\`
    /// and ESC as `\u{1b}`.
    #[cfg(system_variables)]
    #[test]
    fn write_lifted_escapes_a_question_name_once() {
        let lifted = [UnsafeOperation::ReadOnlyQuestion {
            question: "C:\\A\u{1b}[2J".to_owned(),
            writable: IncludedStates::empty(),
        }];
        let mut warned = Vec::new();

        write_lifted(&mut warned, &mut UnicodeTerminal, &lifted).expect("write the warning");

        let warned = String::from_utf8(warned).expect("UTF-8");
        assert!(
            warned.starts_with("warning: cannot set question \"C:\\\\A\\u{1b}[2J\": "),
            "{warned:?}"
        );
    }

    /// The error path writes a "warning:" line per unsafe operation that the error carries as
    /// lifted, also under a later context, and none for an error without.
    #[cfg(system_variables)]
    #[test]
    fn write_lifted_of_warns_of_the_operations_before_an_error() {
        let error = LiftedOperations::attach(
            vec![UnsafeOperation::SetupPassword],
            anyhow!("write failed"),
        )
        .context("set failed");
        let mut warned = Vec::new();
        write_lifted_of(&mut warned, &mut UnicodeTerminal, &error).expect("write the warning");
        assert_eq!(
            String::from_utf8_lossy(&warned),
            format!(
                "warning: {}\n",
                UnsafeOperation::SetupPassword.lifted_warning()
            ),
            "lifted"
        );

        let mut none = Vec::new();
        write_lifted_of(&mut none, &mut UnicodeTerminal, &anyhow!("write failed"))
            .expect("write no warning");
        assert_eq!(String::from_utf8_lossy(&none), "", "none lifted");
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

    #[test]
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn set_takes_the_image_that_it_stages() {
        let image = "/boot/uefisettings.efi";
        let cases: [(&[&str], Option<std::path::PathBuf>); 2] = [
            (&["set", "Question", "Value"], None),
            (
                &["set", "Question", "Value", "--image", image],
                Some(image.into()),
            ),
        ];
        for (args, want) in cases {
            let parsed = hii(args).unwrap_or_else(|error| panic!("parse {args:?}: {error}"));
            let HiiSubcommands::Set {
                selection,
                unsafe_operations,
                volatile,
                staging,
                ..
            } = parsed
            else {
                panic!("{args:?} is no set: {parsed:?}");
            };

            let options = set_options(&selection, &unsafe_operations, &volatile, &staging);

            assert_eq!(options.staging_image, want, "{args:?}");
        }
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn set_on_windows_takes_the_mount_point_of_the_esp() {
        let cases: [(&[&str], Option<std::path::PathBuf>); 2] = [
            (&["set", "Question", "Value"], None),
            (
                &["set", "Question", "Value", "--esp", "S:"],
                Some("S:".into()),
            ),
        ];
        for (args, want) in cases {
            let parsed = hii(args).unwrap_or_else(|error| panic!("parse {args:?}: {error}"));
            let HiiSubcommands::Set {
                selection,
                unsafe_operations,
                volatile,
                staging,
                ..
            } = parsed
            else {
                panic!("{args:?} is no set: {parsed:?}");
            };

            let options = set_options(&selection, &unsafe_operations, &volatile, &staging);

            assert_eq!(options.staging_esp, want, "{args:?}");
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
            &["variable", "set", "Timeout", "5"],
            &["variable", "set", "BootOrder", "Boot0002,Boot0001"],
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

    /// Each removed flag of an unsafe operation fails as an unknown flag does, with exit 2:
    /// --i-am-fine-to-brick-this-system replaces it, with no alias.
    #[cfg(all(system_hiidb, system_variables))]
    #[test]
    fn removed_unsafe_flags_exit_2() {
        let cases: [(&[&str], &[&str], clap::error::ErrorKind); 4] = [
            (
                &["hii", "set", "Q", "V"],
                &["--bypass-setup-password"],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["set", "Q", "V"],
                &["--bypass-setup-password"],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["hii", "set", "Q", "V"],
                &["--include", "read-only"],
                clap::error::ErrorKind::InvalidValue,
            ),
            (
                &["set", "Q", "V"],
                &["--include", "read-only"],
                clap::error::ErrorKind::InvalidValue,
            ),
        ];
        #[cfg(variable_data)]
        let cases = cases.into_iter().chain([
            (
                &WRITE_SIGNED[..],
                &["--allow-setup-mode-write-without-signature-check"][..],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["variable", "set", "AuditMode", "1"],
                &["--enter-audit-mode-clearing-pk"],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["variable", "set", "DeployedMode", "1"],
                &["--enter-deployed-mode-irreversibly"],
                clap::error::ErrorKind::UnknownArgument,
            ),
        ]);
        for (command, flag, kind) in cases {
            let argv = [&["uefisettings"][..], command, flag].concat();
            let error =
                UefiSettingsToolArgs::try_parse_from(argv).expect_err("parse a removed flag");

            assert_eq!(error.kind(), kind, "{command:?} {flag:?}");
            assert_eq!(
                parse_error_exit_code(&error),
                ExitCode::from(2),
                "{command:?} {flag:?}"
            );
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

    /// The questions that the get or set command `args`, after `uefisettings`, selects, and
    /// set's VALUE.
    fn selected_by(
        args: &[&str],
    ) -> Result<(QuestionSelector, Option<String>), clap::error::ErrorKind> {
        let argv = [&["uefisettings"][..], args].concat();
        let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind())?;
        let (question, value) = match parsed.command {
            Commands::Hii(HiiCommand {
                command: HiiSubcommands::Get { question, .. },
            }) => (question, None),
            #[cfg(all(system_hiidb, system_variables))]
            Commands::Hii(HiiCommand {
                command:
                    HiiSubcommands::Set {
                        target:
                            SetArgs {
                                question, value, ..
                            },
                        ..
                    },
            }) => (question, value),
            #[cfg(all(system_hiidb, system_variables))]
            Commands::Get { question, .. } => (question, None),
            #[cfg(all(system_hiidb, system_variables))]
            Commands::Set {
                target: SetArgs {
                    question, value, ..
                },
                ..
            } => (question, value),
            other => panic!("{args:?} is no get or set: {other:?}"),
        };
        let selector = question
            .selector()
            .unwrap_or_else(|error| panic!("{args:?}: {error}"));
        Ok((selector, value))
    }

    /// get and set take exactly one of QUESTION, --question-id and --keyword, and
    /// --keyword-namespace only with --keyword and only a configuration language; set takes
    /// VALUE with each, and refuses QUESTION alone. --question-id takes digits after the ':'
    /// and after its "0x", not a sign.
    #[test]
    fn get_and_set_select_by_question_question_id_or_keyword() {
        use clap::error::ErrorKind::ArgumentConflict;
        use clap::error::ErrorKind::MissingRequiredArgument;
        use clap::error::ErrorKind::ValueValidation;

        const ADDRESS: &str = "8C78A505-BAA0-4C4A-869F-000000000800:0x8001";
        let address = QuestionSelector::Address(ADDRESS.parse().expect("parse the address"));
        let keyword = |namespace: Option<&str>| QuestionSelector::Keyword {
            keyword: "K:5".parse().expect("parse the keyword"),
            namespace: namespace.map(|text| text.parse().expect("parse the namespace")),
        };
        let cases: [(&[&str], Result<QuestionSelector, clap::error::ErrorKind>); 21] = [
            (&["Q"], Ok(QuestionSelector::from("Q"))),
            (&["--question-id", ADDRESS], Ok(address.clone())),
            (&["--keyword", "K:5"], Ok(keyword(None))),
            (
                &["--keyword", "K:5", "--keyword-namespace", "x-i-UEFI"],
                Ok(keyword(Some("x-i-UEFI"))),
            ),
            (
                &["--keyword", "K:5", "--keyword-namespace", "X-UEFI-ns"],
                Ok(keyword(Some("X-UEFI-ns"))),
            ),
            (&["--keyword", "K&V"], Err(ValueValidation)),
            (&["--keyword", "K:12345"], Err(ValueValidation)),
            (
                &["--keyword", "K", "--keyword-namespace", "x-UEFI=ns"],
                Err(ValueValidation),
            ),
            (
                &["--keyword", "K", "--keyword-namespace", ""],
                Err(ValueValidation),
            ),
            (
                &["--keyword", "K", "--keyword-namespace", "en"],
                Err(ValueValidation),
            ),
            (
                &["--keyword", "K", "--keyword-namespace", "en-US"],
                Err(ValueValidation),
            ),
            (&[], Err(MissingRequiredArgument)),
            (&["Q", "--keyword", "K"], Err(ArgumentConflict)),
            (
                &["--question-id", ADDRESS, "--keyword", "K"],
                Err(ArgumentConflict),
            ),
            (
                &["Q", "--keyword-namespace", "x-i-UEFI"],
                Err(ArgumentConflict),
            ),
            (
                &["--question-id", ADDRESS, "--keyword-namespace", "x-i-UEFI"],
                Err(ArgumentConflict),
            ),
            (
                &["--keyword-namespace", "x-i-UEFI"],
                Err(MissingRequiredArgument),
            ),
            (
                &["--question-id", "8C78A505-BAA0-4C4A-869F-000000000800:0"],
                Err(ValueValidation),
            ),
            (
                &[
                    "--question-id",
                    "8C78A505-BAA0-4C4A-869F-000000000800:0x10000",
                ],
                Err(ValueValidation),
            ),
            (
                &["--question-id", "8C78A505-BAA0-4C4A-869F-000000000800:+1"],
                Err(ValueValidation),
            ),
            (
                &["--question-id", "8C78A505-BAA0-4C4A-869F-000000000800:0x+1"],
                Err(ValueValidation),
            ),
        ];
        let hii_get = [&["hii", "get"][..], &OFFLINE_SOURCE].concat();
        let gets: [&[&str]; 1] = [&hii_get];
        #[cfg(all(system_hiidb, system_variables))]
        let gets = gets.into_iter().chain([&["get"][..]]);
        for command in gets {
            for (flags, want) in &cases {
                let args = [command, *flags].concat();
                assert_eq!(
                    selected_by(&args),
                    want.clone().map(|selector| (selector, None)),
                    "{args:?}"
                );
            }
        }

        #[cfg(all(system_hiidb, system_variables))]
        for command in [&["hii", "set"][..], &["set"]] {
            let sets: [(&[&str], Result<QuestionSelector, clap::error::ErrorKind>); 5] = [
                (&["Q", "1"], Ok(QuestionSelector::from("Q"))),
                (&["--question-id", ADDRESS, "1"], Ok(address.clone())),
                (&["--keyword", "K:5", "1"], Ok(keyword(None))),
                (&["Q"], Err(MissingRequiredArgument)),
                (&["Q", "1", "--keyword", "K"], Err(ArgumentConflict)),
            ];
            for (flags, want) in sets {
                let args = [command, flags].concat();
                assert_eq!(
                    selected_by(&args),
                    want.map(|selector| (selector, Some("1".to_owned()))),
                    "{args:?}"
                );
            }
        }
    }

    /// hii set and set take the items of an ordered list, in order, as repeated --item instead of
    /// VALUE, with QUESTION, which clap takes as VALUE when it is the lone positional, or with
    /// --question-id or --keyword; they refuse VALUE beside QUESTION and --item, a lone
    /// positional beside --item and --question-id or --keyword, each with its own error, and
    /// --item without a question.
    #[test]
    #[cfg(all(system_hiidb, system_variables))]
    fn set_takes_items_instead_of_a_value() {
        const ADDRESS: &str = "8C78A505-BAA0-4C4A-869F-000000000800:0x8001";
        let items = |items: &[&str]| SetValue::Items(items.iter().map(|&i| i.to_owned()).collect());
        let prompt = || QuestionSelector::from("Q");
        let keyword = QuestionSelector::Keyword {
            keyword: "K:5".parse().expect("parse the keyword"),
            namespace: None,
        };
        let either = "set takes either VALUE or --item".to_owned();
        let beside = "set takes no QUESTION or VALUE beside --item and --question-id or --keyword"
            .to_owned();
        type Target = Result<(QuestionSelector, SetValue), String>;
        let cases: [(&[&str], Target); 11] = [
            (
                &["Q", "--item", "B", "--item", "A"],
                Ok((prompt(), items(&["B", "A"]))),
            ),
            (&["--item", "B", "Q"], Ok((prompt(), items(&["B"])))),
            (&["Q", "V"], Ok((prompt(), SetValue::Text("V".to_owned())))),
            (
                &["--question-id", ADDRESS, "--item", "A"],
                Ok((
                    QuestionSelector::Address(ADDRESS.parse().expect("parse the address")),
                    items(&["A"]),
                )),
            ),
            (
                &["--keyword", "K:5", "--item", "A"],
                Ok((keyword, items(&["A"]))),
            ),
            (&["Q", "V", "--item", "A"], Err(either)),
            (
                &["--keyword", "K:5", "Q", "--item", "A"],
                Err(beside.clone()),
            ),
            (&["--question-id", ADDRESS, "Q", "--item", "A"], Err(beside)),
            (
                &["--item", "A"],
                Err("exactly one of QUESTION, --question-id and --keyword is required".to_owned()),
            ),
            (
                &["Q"],
                Err(format!(
                    "{:?}",
                    clap::error::ErrorKind::MissingRequiredArgument
                )),
            ),
            (
                &["Q", "V", "--keyword", "K"],
                Err(format!("{:?}", clap::error::ErrorKind::ArgumentConflict)),
            ),
        ];
        for command in [&["hii", "set"][..], &["set"]] {
            for (args, want) in &cases {
                let argv = [&["uefisettings"][..], command, args].concat();
                let got = UefiSettingsToolArgs::try_parse_from(argv)
                    .map_err(|error| format!("{:?}", error.kind()))
                    .and_then(|parsed| match parsed.command {
                        Commands::Set { target, .. }
                        | Commands::Hii(HiiCommand {
                            command: HiiSubcommands::Set { target, .. },
                        }) => target.target().map_err(|error| error.to_string()),
                        other => panic!("{command:?} {args:?}: {other:?}"),
                    });
                assert_eq!(&got, want, "{command:?} {args:?}");
            }
        }
    }

    #[test]
    fn write_with_style_returns_broken_pipe() {
        let mut output = BrokenPipeWriter;
        let error = write_with_style(
            &mut output,
            &mut UnicodeTerminal,
            uefisettings_backend_thrift::Error::default(),
            false,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(is_broken_pipe(&error.into()));
    }

    /// --hii-source and --efivar-memory exist on the Linux build only, the one build that reads
    /// this machine's HiiDB in more than one way: elsewhere clap refuses them as unexpected
    /// arguments, before and after the command, so that no build accepts and ignores them.
    #[test]
    fn hii_source_flags_exist_on_linux_only() {
        let takes = false;
        #[cfg(target_os = "linux")]
        let takes = !takes;
        let want = match takes {
            true => Ok(()),
            false => Err(clap::error::ErrorKind::UnknownArgument),
        };
        for (flag, value) in [
            ("--hii-source", "efivar"),
            ("--efivar-memory", "firmware-reserved"),
        ] {
            for args in [
                &[flag, value, "show-translations"][..],
                &["show-translations", flag, value],
            ] {
                let argv = [&["uefisettings"][..], args].concat();
                let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                    .map(drop)
                    .map_err(|error| error.kind());
                assert_eq!(parsed, want, "{argv:?}");
            }
        }
    }

    /// A text output that renders U+0020-U+007E only, as edk2-stable202608 TerminalDxe's PC-ANSI
    /// and VT100 types do but for their controls and text graphics (Ansi.c:61-72).
    struct AsciiConsole;

    impl TextOutput for AsciiConsole {
        fn test_string(&mut self, text: &str) -> io::Result<bool> {
            Ok(text.chars().all(|character| matches!(character, ' '..='~')))
        }
    }

    /// show-ifr's text: each line as TerminalText, ended with its line break, so that a text's
    /// own line break shows as `\n` inside its line and forges no line, such as an -Answer line
    /// before the question's own; then the empty line that ends it.
    #[test]
    fn terminal_lines_escape_each_line_and_its_own_line_breaks() {
        let forged = "    -Answer: 1";
        let cases: [(&[&str], &str); 4] = [
            (
                &["FormSet - T\u{1b}[2J", "  -Prompt: A\r\u{202e}B"],
                "FormSet - T\\u{1b}[2J\n  -Prompt: A\\r\\u{202e}B\n\n",
            ),
            (
                &[
                    "OpCode: CheckBox - Q: - Q - Help: - Real help\n    -Answer: 1",
                    "    -Answer: 0",
                ],
                "OpCode: CheckBox - Q: - Q - Help: - Real help\\n    -Answer: 1\n    -Answer: 0\n\n",
            ),
            (&["Packagelist X", "OpCode: ROOT"], "Packagelist X\nOpCode: ROOT\n\n"),
            (&[], "\n"),
        ];
        for (lines, want) in cases {
            let lines = TextLines(lines.iter().map(|&line| line.to_owned()).collect());
            let mut output = Vec::new();

            write_terminal_lines(&mut output, &mut UnicodeTerminal, &lines)
                .expect("write the lines");

            let shown = String::from_utf8(output).expect("UTF-8");
            assert_eq!(shown, want, "{lines:?}");
            assert!(
                !shown.lines().any(|line| line == forged),
                "{lines:?}: forged line"
            );
        }
    }

    /// get's answer and set's refusal of a question that its driver holds, which name the HiiDB's
    /// strings, its prompt and what its driver did, such as the EFI variables that it changed,
    /// print as every answer and error does: text as Debug, its control characters and
    /// Bidi_Control characters escaped, JSON exact but for what JsonText spells, and through a
    /// console that renders ASCII only, every other character escaped too.
    #[test]
    fn driver_held_answers_and_refusals_escape_firmware_texts() {
        let prompt = "Q\u{1b}[2J\u{202e}\u{10d}";
        let answer = uefisettings_backend_thrift::GetResponseList {
            responses: vec![uefisettings_backend_thrift::GetResponse {
                question: uefisettings_backend_thrift::Question {
                    name: prompt.to_owned(),
                    answer: "On <EFI variables changed: V\u{1b}-8c78a505-baa0-4c4a-869f-\
                             000000000a01 (created)>"
                        .to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let refusal = uefisettings_backend_thrift::Error {
            error_message: format!(
                "cannot set question {prompt:?}: its driver's \
                 CallBack(EFI_BROWSER_ACTION_CHANGING) refused the value: EFI_ACCESS_DENIED"
            ),
            ..Default::default()
        };
        let raw = ['\u{1b}', '\u{202e}', '\u{10d}'];
        for json in [false, true] {
            let mut ascii = Vec::new();
            write_with_style(&mut ascii, &mut AsciiConsole, answer.clone(), json)
                .expect("the answer through ASCII");
            write_with_style(&mut ascii, &mut AsciiConsole, refusal.clone(), json)
                .expect("the refusal through ASCII");
            let ascii = String::from_utf8(ascii).expect("UTF-8");
            assert!(
                !ascii.contains(raw),
                "json {json}, ASCII console: {ascii:?}"
            );

            let mut unicode = Vec::new();
            write_with_style(&mut unicode, &mut UnicodeTerminal, answer.clone(), json)
                .expect("the answer");
            write_with_style(&mut unicode, &mut UnicodeTerminal, refusal.clone(), json)
                .expect("the refusal");
            let unicode = String::from_utf8(unicode).expect("UTF-8");
            assert!(
                !unicode.contains(['\u{1b}', '\u{202e}']),
                "json {json}, UTF-8 terminal: {unicode:?}"
            );
            match json {
                true => {
                    let names: Vec<String> = unicode
                        .lines()
                        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
                        .filter_map(|value| {
                            value["responses"][0]["question"]["name"]
                                .as_str()
                                .map(str::to_owned)
                        })
                        .collect();
                    assert_eq!(names, [prompt], "the prompt read back from the JSON");
                }
                false => assert!(
                    unicode.contains("Q\\u{1b}[2J\\u{202e}\u{10d}"),
                    "the prompt as Debug: {unicode:?}"
                ),
            }
        }
    }

    /// A line of what apply-staged did, which names a staged question's prompt and its driver's
    /// refusal, prints as TerminalText after `apply-staged: `, its line breaks escaped inside its
    /// line, and through a console that renders ASCII only, every other character escaped too.
    #[test]
    fn apply_staged_lines_escape_firmware_texts() {
        let line = "question \"Q\u{1b}[2J\u{202e}\u{10d}\": its driver refused\nthe value \\ \
                    EFI_ACCESS_DENIED";
        let mut unicode = Vec::new();
        let mut ascii = Vec::new();

        write_apply_staged_line(&mut unicode, &mut UnicodeTerminal, line).expect("write the line");
        write_apply_staged_line(&mut ascii, &mut AsciiConsole, line)
            .expect("write the line through ASCII");

        assert_eq!(
            String::from_utf8(unicode).expect("UTF-8"),
            "apply-staged: question \"Q\\u{1b}[2J\\u{202e}\u{10d}\": its driver refused\\nthe \
             value \\\\ EFI_ACCESS_DENIED\n",
            "UTF-8 terminal"
        );
        assert_eq!(
            String::from_utf8(ascii).expect("UTF-8"),
            "apply-staged: question \"Q\\u{1b}[2J\\u{202e}\\u{10d}\": its driver refused\\nthe \
             value \\\\ EFI_ACCESS_DENIED\n",
            "ASCII console"
        );
    }

    /// Text and JSON through a console that renders ASCII only: each other character escaped as
    /// its syntax spells it, and each line break that uefisettings writes kept.
    #[test]
    fn write_lines_escape_what_the_console_refuses() {
        let cases = [
            (
                OutputSyntax::Text,
                "P07<\u{10d}>Q\nP08<\u{200d}>Q",
                "P07<\\u{10d}>Q\nP08<\\u{200d}>Q\n",
            ),
            (
                OutputSyntax::Json,
                "{\"a\":\"K\u{10d}\u{1f60a}K\"}",
                "{\"a\":\"K\\u010d\\ud83d\\ude0aK\"}\n",
            ),
        ];
        for (syntax, text, want) in cases {
            let mut output = Vec::new();

            write_lines(&mut output, &mut AsciiConsole, syntax, text).expect("write the lines");

            assert_eq!(
                String::from_utf8(output).expect("UTF-8"),
                want,
                "{syntax:?}"
            );
        }
    }

    /// print_json's and write_with_style's JSON through a console that renders ASCII only: a
    /// refused character in a string is spelled as a JSON escape, which parses back to the same
    /// string.
    #[test]
    fn json_through_an_ascii_console_parses_back() {
        let text = "K\u{10d}K";
        let mut json = Vec::new();

        write_json(&mut json, &mut AsciiConsole, &text).expect("write the JSON");

        let json = String::from_utf8(json).expect("UTF-8");
        let value: String = serde_json::from_str(&json).expect("parse write_json's JSON");
        assert_eq!(value, text, "write_json: {json:?}");

        let error = uefisettings_backend_thrift::Error {
            error_message: text.to_string(),
            ..Default::default()
        };
        let mut styled = Vec::new();

        write_with_style(&mut styled, &mut AsciiConsole, error, true).expect("write the error");

        let styled = String::from_utf8(styled).expect("UTF-8");
        let value: serde_json::Value =
            serde_json::from_str(&styled).expect("parse write_with_style's JSON");
        assert_eq!(value["error_message"], text, "write_with_style: {styled:?}");
    }

    #[test]
    fn warnings_escape_control_characters() {
        let mut output = Vec::new();

        write_warning(
            &mut output,
            &mut UnicodeTerminal,
            format_args!("questions may be in {}", "A\u{9b}2J\nB"),
        )
        .expect("write the warning");

        assert_eq!(
            String::from_utf8(output).expect("UTF-8"),
            "warning: questions may be in A\\u{9b}2J\\nB\n"
        );
    }

    /// The UEFI Shell build's keyword text: as TerminalText, so that a KEYWORD's Bidi_Control
    /// character reorders nothing; its JSON keeps the value, through JsonText.
    #[test]
    fn display_or_json_escapes_the_text_and_keeps_the_json_value() {
        struct Keywords(&'static str);
        impl std::fmt::Display for Keywords {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "KEYWORD={}", self.0)
            }
        }
        impl serde::Serialize for Keywords {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.0)
            }
        }
        let keywords = Keywords("K\u{202e}K");
        let cases = [(false, "KEYWORD=K\\u{202e}K\n"), (true, "\"K\\u202eK\"\n")];
        for (json, want) in cases {
            let mut output = Vec::new();

            write_display_or_json(&mut output, &mut UnicodeTerminal, &keywords, json)
                .expect("write the keywords");

            let shown = String::from_utf8(output).expect("UTF-8");
            assert_eq!(shown, want, "json {json}");
            if json {
                let value: String = serde_json::from_str(&shown).expect("parse");
                assert_eq!(value, keywords.0, "the JSON's value");
            }
        }
    }

    /// set takes VALUE and each --item as they are: nothing unescapes the `\\` of a text pasted
    /// from TerminalText.
    #[test]
    #[cfg(all(system_hiidb, system_variables))]
    fn set_takes_the_value_and_items_verbatim() {
        let shown = TerminalText("A\\u{1b}B").to_string();
        let items = SetValue::Items(vec![shown.clone(), "C\\\\D".to_owned()]);
        let cases = [
            (vec!["Q", shown.as_str()], SetValue::Text(shown.clone())),
            (
                vec!["Q", "--item", shown.as_str(), "--item", "C\\\\D"],
                items.clone(),
            ),
            (
                vec![
                    "--keyword",
                    "K:5",
                    "--item",
                    shown.as_str(),
                    "--item",
                    "C\\\\D",
                ],
                items,
            ),
        ];
        for (args, want) in cases {
            let argv = [&["uefisettings", "set"][..], &args].concat();
            let target = match UefiSettingsToolArgs::try_parse_from(argv)
                .expect("parse set")
                .command
            {
                Commands::Set { target, .. } => target.target().expect("the target"),
                other => panic!("{args:?}: {other:?}"),
            };

            assert_eq!(target.1, want, "{args:?}");
        }
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
