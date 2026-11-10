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
#[cfg(all(system_hiidb, system_variables))]
use std::sync::LazyLock;

use anyhow::anyhow;
use anyhow::Result;
#[cfg(all(system_hiidb, system_variables))]
use clap::builder::PossibleValue;
#[cfg(all(system_hiidb, system_variables))]
use clap::ArgGroup;
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
use uefisettings::exports::KeywordName;
use uefisettings::exports::KeywordNamespace;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::LiftedOperations;
use uefisettings::exports::ListQuestionsOptions;
use uefisettings::exports::QuestionAddress;
use uefisettings::exports::QuestionSelector;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::SetOptions;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::SetValue;
use uefisettings::exports::ShowIfrOptions;
#[cfg(all(system_hiidb, system_variables))]
use uefisettings::exports::UnsafeOperation;
#[cfg(target_os = "uefi")]
use uefisettings::exports::UnsafeOperations;
use uefisettings_spellings_db_thrift::consts::translation_db;

#[cfg(system_variables)]
use capsule_command::CapsuleCommand;
use platform::EfivarArgs;
use platform::HiiDbArgs;
use platform::HiiPlatformCommands;
use platform::ListStringsHiiDbArgs;
use platform::PlatformCommands;
#[cfg(all(system_hiidb, system_variables))]
use platform::SetUnsafeArgs;
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

/// Where the commands read this machine's HiiDB; global, so that the flags may also follow the
/// command. Only the Linux build reads it in more than one way.
#[derive(Debug, Default, Args)]
struct HiiSourceArgs {
    #[arg(long, global = true, value_enum, default_value_t, help = platform::HII_SOURCE_HELP)]
    hii_source: HiiSourceArg,
    #[arg(long, global = true, value_enum, default_value_t, help = platform::EFIVAR_MEMORY_HELP)]
    efivar_memory: EfivarMemoryArg,
}

/// The values of --hii-source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
enum HiiSourceArg {
    /// acpi, then efivar, then systab: the next while a method finds its source absent or fails, none after a refusal (kernel lockdown, /dev/mem or /proc/kcore refused)
    #[default]
    Auto,
    /// The memory that the OCP HiiDB variable points to, from /dev/mem
    Efivar,
    /// The vendor ACPI table QHII or HIID, from /sys/firmware/acpi/tables, without /dev/mem
    Acpi,
    /// The HII database export that the EFI System Table lists as a configuration table, from /dev/mem
    Systab,
}

/// The values of --efivar-memory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
enum EfivarMemoryArg {
    /// One EFI runtime region of the firmware's memory map that is no memory-mapped I/O
    #[default]
    Runtime,
    /// One firmware-reserved region of the firmware's memory map (x86: Reserved or ACPI Non-volatile Storage in /sys/firmware/memmap; aarch64: reserved, runtime services code or data, ACPI NVS or PAL code), never one that touches runtime memory-mapped I/O
    FirmwareReserved,
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
    #[cfg_attr(
        target_os = "uefi",
        command(mut_arg(UNSAFE_ARG, |arg| unsafe_long_help(arg, platform::SET_UNSAFE_OPERATIONS)))
    )]
    Set {
        #[command(flatten)]
        target: SetArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs<SetIncludeState>,
        #[command(flatten)]
        unsafe_operations: SetUnsafeArgs,
        #[command(flatten)]
        volatile: VolatileArgs,
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
    #[cfg_attr(
        target_os = "uefi",
        command(mut_arg(UNSAFE_ARG, |arg| unsafe_long_help(arg, platform::SET_UNSAFE_OPERATIONS)))
    )]
    Set {
        #[command(flatten)]
        target: SetArgs,
        #[command(flatten)]
        output: JsonArgs,
        #[command(flatten)]
        selection: SelectionArgs<SetIncludeState>,
        #[command(flatten)]
        unsafe_operations: SetUnsafeArgs,
        #[command(flatten)]
        volatile: VolatileArgs,
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
    /// List the one-of, numeric, checkbox, date, time and ordered-list questions of the HiiDB, and its cross-reference questions on a VarStore, whose values get reads; set does not write a cross-reference's value, the target of its link.
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
/// build's hii keyword set select too, `S` as SelectionArgs takes it: keyword set takes
/// IncludeState, as the Keyword Handler writes no read-only question.
#[derive(Debug, Args)]
struct IncludeArgs<S = IncludeState>
where
    S: clap::ValueEnum + Clone + Send + Sync + 'static,
{
    /// Also select questions that conditions gray out, suppress or disable. The edk2 setup
    /// browser (edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpressionList) ranks
    /// DisableIf > SuppressIf > GrayOutIf, so a question that is both grayed out and suppressed
    /// counts as suppressed.
    #[arg(long, value_enum, value_delimiter = ',')]
    include: Vec<S>,
}

impl<S> IncludeArgs<S>
where
    S: clap::ValueEnum + Copy + Send + Sync + 'static,
    IncludedStates: From<S>,
{
    fn states(&self) -> IncludedStates {
        self.include
            .iter()
            .copied()
            .map(IncludedStates::from)
            .collect()
    }
}

/// Which questions and options get, set and list-questions select. `S` is the value of
/// --include: set's (SetIncludeState) also takes read-only, which get and list-questions refuse,
/// as they show read-only questions regardless.
#[derive(Debug, Args)]
struct SelectionArgs<S = IncludeState>
where
    S: clap::ValueEnum + Clone + Send + Sync + 'static,
{
    #[command(flatten)]
    include: IncludeArgs<S>,
    /// Evaluate the conditions that read the AMI Setup access level (VarStore SystemAccess
    /// E770BB69-BCB4-4D04-9E97-23FF9456FEAC: 0 Administrator, 1 User) at this level instead of
    /// the stored value. This states a Setup privilege; it is no password and authenticates
    /// nothing (UEFI variable writes carry no password).
    #[arg(long, value_enum, value_name = "LEVEL")]
    access_level: Option<AccessLevelArg>,
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

impl<S> SelectionArgs<S>
where
    S: clap::ValueEnum + Copy + Send + Sync + 'static,
    IncludedStates: From<S>,
{
    fn states(&self) -> IncludedStates {
        self.include.states()
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
        options.language.clone_from(&args.language.language);
        options
    }
}

#[cfg(all(system_hiidb, system_variables))]
impl From<&SelectionArgs<SetIncludeState>> for SetOptions {
    fn from(args: &SelectionArgs<SetIncludeState>) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.access_level = args.access_level();
        options.language.clone_from(&args.language.language);
        options
    }
}

impl From<&SelectionArgs> for ListQuestionsOptions {
    fn from(args: &SelectionArgs) -> Self {
        let mut options = Self::default();
        options.include = args.states();
        options.access_level = args.access_level();
        options.language.clone_from(&args.language.language);
        options
    }
}

/// The id of --i-am-fine-to-brick-this-system, under which each command's long help lists its own
/// unsafe operations.
#[cfg(target_os = "uefi")]
const UNSAFE_ARG: &str = "i_am_fine_to_brick_this_system";

/// The help of --i-am-fine-to-brick-this-system, in every command that takes it.
#[cfg(target_os = "uefi")]
const UNSAFE_HELP: &str = "Do what this command otherwise refuses because it can bypass this \
                           machine's setup password; each refusal names what this flag does there";

/// --i-am-fine-to-brick-this-system, which only the commands that have an unsafe operation take.
#[cfg(target_os = "uefi")]
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
struct UnsafeArgs {
    #[arg(long, help = UNSAFE_HELP)]
    i_am_fine_to_brick_this_system: bool,
}

#[cfg(target_os = "uefi")]
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
#[cfg(target_os = "uefi")]
fn unsafe_long_help(arg: clap::Arg, operations: &[&str]) -> clap::Arg {
    arg.long_help(format!(
        "{UNSAFE_HELP}. This command refuses without it: {}",
        operations.join("; ")
    ))
}

/// The SetOptions of `selection`, `unsafe_operations` and `volatile`.
#[cfg(all(system_hiidb, system_variables))]
fn set_options(
    selection: &SelectionArgs<SetIncludeState>,
    unsafe_operations: &SetUnsafeArgs,
    volatile: &VolatileArgs,
) -> SetOptions {
    let mut options = SetOptions::from(selection);
    options.unsafe_operations = unsafe_operations.operations();
    options.volatile = volatile.policy();
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
) -> Result<()> {
    let (res, lifted) = platform::set_using(question, value, options, source)?;
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

/// The values of set's --include: those of IncludeState, and read-only.
#[cfg(all(system_hiidb, system_variables))]
#[derive(Debug, Clone, Copy)]
enum SetIncludeState {
    Condition(IncludeState),
    ReadOnly,
}

#[cfg(all(system_hiidb, system_variables))]
impl clap::ValueEnum for SetIncludeState {
    fn value_variants<'a>() -> &'a [Self] {
        static VARIANTS: LazyLock<Vec<SetIncludeState>> = LazyLock::new(|| {
            let conditions = IncludeState::value_variants().iter().copied();
            conditions
                .map(SetIncludeState::Condition)
                .chain([SetIncludeState::ReadOnly])
                .collect()
        });
        VARIANTS.as_slice()
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            SetIncludeState::Condition(state) => state.to_possible_value(),
            SetIncludeState::ReadOnly => Some(PossibleValue::new("read-only").help(
                "Also write questions that EFI_IFR_FLAG_READ_ONLY makes read-only (UEFI 2.11 \
                 §33.3.8.2.2), never one that an EFI_IFR_VALUE makes read-only (§33.3.8.3.88). \
                 Of questions with the same text, set picks a writable one first among matches \
                 equally certain to be selected",
            )),
        }
    }
}

#[cfg(all(system_hiidb, system_variables))]
impl From<SetIncludeState> for IncludedStates {
    fn from(state: SetIncludeState) -> Self {
        match state {
            SetIncludeState::Condition(state) => state.into(),
            SetIncludeState::ReadOnly => IncludedStates::READ_ONLY,
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
        #[cfg(all(system_hiidb, system_variables))]
        if let Err(print_error) = print_lifted_of(&why) {
            log::debug!("failed to print the warnings of the error: {print_error}");
        }
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
                    &hiidb.read(&options.efivars, source)?,
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
            } => {
                let (question, value) = target.target()?;
                let options = set_options(selection, unsafe_operations, volatile);
                hii_set(question, &value, &options, output.json, source)?
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
                let res =
                    HiiBackend::show_ifr_using(&hiidb.read(&options.efivars, source)?, &options)?;
                print_line(format_args!("{}", res.readable_representation))?;
            }
            HiiSubcommands::ListStrings { hiidb, output } => {
                let res = HiiBackend::list_strings(&hiidb.read(&EfivarSource::Disabled, source)?)?;
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
                    &hiidb.read(&options.efivars, source)?,
                    &options,
                )?;
                print_with_style(res, output.json)?;
                // the questions' list keeps its form, so the IFR that may hold more goes to stderr
                for ignored in ignored_ifr {
                    print_warning(format_args!("questions may be in {ignored}"))?;
                }
            }
            HiiSubcommands::Platform(command) => command.run(source)?,
        },
        #[cfg(all(system_hiidb, system_variables))]
        Commands::Get {
            question,
            output,
            selection,
        } => platform::auto_get(question, output.json, selection, source)?,
        #[cfg(all(system_hiidb, system_variables))]
        Commands::Set {
            target,
            output,
            selection,
            unsafe_operations,
            volatile,
        } => {
            let options = set_options(selection, unsafe_operations, volatile);
            platform::auto_set(target, output.json, selection, &options, source)?
        }
        Commands::ShowTranslations { output } => {
            print_with_style(&*translation_db, output.json)?;
        }
        #[cfg(system_variables)]
        Commands::Variable(command) => command.run()?,
        #[cfg(system_variables)]
        Commands::Capsule(command) => command.run()?,
        Commands::Platform(command) => command.run(source)?,
    }
    Ok(())
}

fn print_line(arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "{}", arguments)
}

fn print_warning(arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_warning(&mut output, arguments)
}

fn write_warning(output: &mut impl Write, arguments: std::fmt::Arguments<'_>) -> io::Result<()> {
    writeln!(output, "warning: {}", arguments)
}

/// Prints a warning per unsafe operation in `lifted`, which --i-am-fine-to-brick-this-system let
/// a command do.
#[cfg(all(system_hiidb, system_variables))]
fn print_lifted(lifted: &[UnsafeOperation]) -> io::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_lifted(&mut output, lifted)
}

#[cfg(all(system_hiidb, system_variables))]
fn write_lifted(output: &mut impl Write, lifted: &[UnsafeOperation]) -> io::Result<()> {
    lifted.iter().try_for_each(|operation| {
        write_warning(output, format_args!("{}", operation.lifted_warning()))
    })
}

/// Prints a warning per unsafe operation that `error`, a command's, carries as lifted before
/// the command failed (LiftedOperations).
#[cfg(all(system_hiidb, system_variables))]
fn print_lifted_of(error: &anyhow::Error) -> io::Result<()> {
    let stderr = io::stderr();
    let mut output = stderr.lock();
    write_lifted_of(&mut output, error)
}

#[cfg(all(system_hiidb, system_variables))]
fn write_lifted_of(output: &mut impl Write, error: &anyhow::Error) -> io::Result<()> {
    match error.downcast_ref::<LiftedOperations>() {
        Some(lifted) => write_lifted(output, &lifted.0),
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

    /// The selection flags of `uefisettings hii set Q V` with `args` after it.
    #[cfg(all(system_hiidb, system_variables))]
    fn set_selection_of(args: &[&str]) -> SelectionArgs<SetIncludeState> {
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
                SetOptions::from(&set_selection_of(&args)).access_level,
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

    /// set's --include takes read-only, which lifts EFI_IFR_FLAG_READ_ONLY; get and
    /// list-questions refuse it as a value they do not take, as they show read-only questions
    /// regardless.
    #[test]
    fn include_takes_read_only_only_on_set() {
        let refusing: [&[&str]; 2] = [&["hii", "get", "Q"], &["hii", "list-questions"]];
        let refusing = refusing.map(|command| [command, &OFFLINE_SOURCE].concat());
        let commands = refusing.iter().map(|command| (&command[..], false));
        #[cfg(all(system_hiidb, system_variables))]
        let commands = commands.chain([
            (&["get", "Q"][..], false),
            (&["hii", "set", "Q", "V"], true),
            (&["set", "Q", "V"], true),
        ]);
        for (command, takes) in commands {
            let argv = [&["uefisettings"][..], command, &["--include", "read-only"]].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(argv).map_err(|error| error.kind());
            match takes {
                true => assert!(parsed.is_ok(), "{command:?}: {parsed:?}"),
                false => assert_eq!(
                    parsed.err(),
                    Some(clap::error::ErrorKind::InvalidValue),
                    "{command:?}"
                ),
            }
        }

        #[cfg(all(system_hiidb, system_variables))]
        for (args, states) in [
            (&["--include", "read-only"][..], IncludedStates::READ_ONLY),
            (
                &["--include", "grayed-out,suppressed,disabled,read-only"],
                IncludedStates::CONDITIONS | IncludedStates::READ_ONLY,
            ),
        ] {
            assert_eq!(
                SetOptions::from(&set_selection_of(args)).include,
                states,
                "set {args:?}"
            );
        }
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
    #[cfg(all(system_hiidb, system_variables))]
    #[test]
    fn write_lifted_warns_per_operation() {
        let mut none = Vec::new();
        write_lifted(&mut none, &[]).expect("write no warning");
        assert_eq!(String::from_utf8_lossy(&none), "", "none");

        let mut warned = Vec::new();
        let lifted = [UnsafeOperation::SetupPassword];
        write_lifted(&mut warned, &lifted).expect("write the warning");
        assert_eq!(
            String::from_utf8_lossy(&warned),
            format!(
                "warning: {}\n",
                UnsafeOperation::SetupPassword.lifted_warning()
            ),
            "SetupPassword"
        );
    }

    /// The error path writes a "warning:" line per unsafe operation that the error carries as
    /// lifted, also under a later context, and none for an error without.
    #[cfg(all(system_hiidb, system_variables))]
    #[test]
    fn write_lifted_of_warns_of_the_operations_before_an_error() {
        let error = LiftedOperations::attach(
            vec![UnsafeOperation::SetupPassword],
            anyhow!("write failed"),
        )
        .context("set failed");
        let mut warned = Vec::new();
        write_lifted_of(&mut warned, &error).expect("write the warning");
        assert_eq!(
            String::from_utf8_lossy(&warned),
            format!(
                "warning: {}\n",
                UnsafeOperation::SetupPassword.lifted_warning()
            ),
            "lifted"
        );

        let mut none = Vec::new();
        write_lifted_of(&mut none, &anyhow!("write failed")).expect("write no warning");
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
        let cases: [(&[&str], &[&str], clap::error::ErrorKind); 2] = [
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
        ];
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
            uefisettings_backend_thrift::Error::default(),
            false,
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(is_broken_pipe(&error.into()));
    }

    /// The flags of the HiiDB source default to auto and runtime, take each of their values, are
    /// global, so that they also follow the command, and refuse another value, on every build.
    #[test]
    fn hii_source_flags_default_and_follow_the_command() {
        let parse = |args: &[&str]| {
            let argv = [&["uefisettings"][..], args].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));
            (
                parsed.hii_source.hii_source,
                parsed.hii_source.efivar_memory,
            )
        };
        assert_eq!(
            parse(&["show-translations"]),
            (HiiSourceArg::Auto, EfivarMemoryArg::Runtime),
            "the defaults"
        );
        for (value, want) in [
            ("auto", HiiSourceArg::Auto),
            ("efivar", HiiSourceArg::Efivar),
            ("acpi", HiiSourceArg::Acpi),
            ("systab", HiiSourceArg::Systab),
        ] {
            for args in [
                &["--hii-source", value, "show-translations"][..],
                &["show-translations", "--hii-source", value],
            ] {
                assert_eq!(parse(args).0, want, "{args:?}");
            }
        }
        for (value, want) in [
            ("runtime", EfivarMemoryArg::Runtime),
            ("firmware-reserved", EfivarMemoryArg::FirmwareReserved),
        ] {
            for args in [
                &["--efivar-memory", value, "show-translations"][..],
                &["show-translations", "--efivar-memory", value],
            ] {
                assert_eq!(parse(args).1, want, "{args:?}");
            }
        }
        for flag in ["--hii-source", "--efivar-memory"] {
            let error = UefiSettingsToolArgs::try_parse_from([
                "uefisettings",
                flag,
                "hiidb",
                "show-translations",
            ])
            .expect_err("an unknown value");
            assert_eq!(error.kind(), clap::error::ErrorKind::InvalidValue, "{flag}");
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
