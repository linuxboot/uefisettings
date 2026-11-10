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

//! The part of the CLI that only the Linux build has: the commands ilo, identify and hii
//! dump-efivars, the flag --efivars, and the machine's identified backend for get and set; it
//! shares hii extract-db and an optional -f/--filename with the Windows build.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use uefisettings::exports::identify_machine_using;
use uefisettings::exports::DumpEfivarsOptions;
use uefisettings::exports::EfivarDump;
use uefisettings::exports::EfivarMemory;
use uefisettings::exports::EfivarRedaction;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::HiiMethod;
use uefisettings::exports::HiiSource;
use uefisettings::exports::HiiSourceOptions;
use uefisettings::exports::IloBackend;
use uefisettings::exports::QuestionSelector;
use uefisettings::exports::SetOptions;
use uefisettings::exports::SetValue;
use uefisettings::exports::SettingsBackend;
use uefisettings::exports::SetupPasswordPolicy;
use uefisettings::exports::VolatileWrites;
use uefisettings::secret_file;
use uefisettings::secret_file::Secret;
use uefisettings::secret_file::MAX_SECRET_LEN;
use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::MachineInfo;
use uefisettings_backend_thrift::SetResponseList;

use crate::extract_db_report;
use crate::hii_get;
use crate::hii_set;
use crate::print_line;
use crate::print_with_style;
use crate::write_extracted_db;
use crate::EfivarMemoryArg;
use crate::HiiSourceArg;
use crate::HiiSourceArgs;
use crate::JsonArgs;
use crate::QuestionArgs;
use crate::SelectionArgs;
use crate::SetArgs;
use crate::SetIncludeState;

/// The about of hii, whose commands read this machine's HiiDB or a file.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this machine's backend.
pub(super) const GET_ABOUT: &str = "Auto-identify backend and get the current value of a question";
/// The about of top-level set, which writes this machine's backend.
pub(super) const SET_ABOUT: &str = "Auto-identify backend and set/change the value of a question";

/// The help of --hii-source.
pub(super) const HII_SOURCE_HELP: &str =
    "Where the commands read this machine's HiiDB, where no HiiDB file or efivars dump gives one";
/// The help of --efivar-memory.
pub(super) const EFIVAR_MEMORY_HELP: &str =
    "The memory that the efivar method of --hii-source may read";

/// The HiiDB source that `args` name.
fn hii_source_options(args: &HiiSourceArgs) -> HiiSourceOptions {
    let mut options = HiiSourceOptions::default();
    options.source = match args.hii_source {
        HiiSourceArg::Auto => HiiSource::Auto,
        HiiSourceArg::Efivar => HiiSource::Method(HiiMethod::Efivar),
        HiiSourceArg::Acpi => HiiSource::Method(HiiMethod::Acpi),
        HiiSourceArg::Systab => HiiSource::Method(HiiMethod::Systab),
    };
    options.efivar_memory = match args.efivar_memory {
        EfivarMemoryArg::Runtime => EfivarMemory::Runtime,
        EfivarMemoryArg::FirmwareReserved => EfivarMemory::FirmwareReserved,
    };
    options
}

/// Logs as RUST_LOG says.
pub(super) fn init_logging() {
    env_logger::init();
}

#[derive(Debug, Subcommand)]
pub(super) enum PlatformCommands {
    /// Commands which work on machines having HPE's Ilo BMC
    Ilo(IloCommand),
    /// Auto-identify backend and display hardware/bios-information
    #[command(next_display_order = None)]
    Identify {
        #[command(flatten)]
        output: JsonArgs,
    },
}

impl PlatformCommands {
    pub(super) fn run(&self, source: &HiiSourceArgs) -> Result<()> {
        match self {
            Self::Ilo(ilo_command) => match &ilo_command.command {
                IloSubcommands::Get { question, output } => {
                    let res = IloBackend::get(question, None)?;
                    print_with_style(res, output.json)?;
                }
                IloSubcommands::Set {
                    question,
                    value,
                    output,
                } => {
                    let res = IloBackend::set(question, value, None)?;
                    print_with_style(res, output.json)?;
                }
                IloSubcommands::ShowAttributes { output } => {
                    let res = IloBackend::show_attributes()?;
                    print_with_style(res, output.json)?;
                }
                IloSubcommands::ShowPendingAttributes { output } => {
                    let res = IloBackend::show_pending_attributes()?;
                    print_with_style(res, output.json)?;
                }
            },
            Self::Identify { output } => {
                let machine = identify_machine_using(&hii_source_options(source));
                print_with_style(machine, output.json)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
#[command(next_display_order = None)]
pub(super) struct IloCommand {
    #[command(subcommand)]
    command: IloSubcommands,
}

#[derive(Debug, Subcommand)]
enum IloSubcommands {
    /// Get the current value of a question
    #[command(next_display_order = None)]
    Get {
        // as the get and set of main.rs
        #[arg(allow_negative_numbers = true)]
        question: String,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// Set/change the value of a question
    #[command(next_display_order = None)]
    Set {
        #[arg(allow_negative_numbers = true)]
        question: String,
        #[arg(allow_negative_numbers = true)]
        value: String,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// List bios attributes and their current values
    #[command(next_display_order = None)]
    ShowAttributes {
        #[command(flatten)]
        output: JsonArgs,
    },
    /// List all pending changes that will take effect after reboot
    #[command(next_display_order = None)]
    ShowPendingAttributes {
        #[command(flatten)]
        output: JsonArgs,
    },
}

#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {
    /// Dump HiiDB into a file
    #[command(next_display_order = None)]
    ExtractDB { filename: PathBuf },
    /// Copy the HiiDB and the EFI variables that its questions read into a new directory, for --efivars on another machine
    #[command(next_display_order = None)]
    DumpEfivars {
        #[command(flatten)]
        hiidb: HiiDbArgs,
        /// Copy whole EFI variables, not only the bytes that questions decode; the others can hold secrets such as password hashes
        #[arg(long)]
        unredacted: bool,
        /// The directory to create
        #[arg(value_name = "DIR")]
        directory: PathBuf,
    },
}

impl HiiPlatformCommands {
    pub(super) fn run(&self, source: &HiiSourceArgs) -> Result<()> {
        match self {
            Self::ExtractDB { filename } => {
                write_extracted_db(filename, || {
                    HiiBackend::extract_db_from(&hii_source_options(source)).map(|res| res.db)
                })?;

                print_line(format_args!("{}", extract_db_report(filename)))?;
            }
            Self::DumpEfivars {
                hiidb,
                unredacted,
                directory,
            } => {
                let mut options = DumpEfivarsOptions::default();
                options.redaction = match unredacted {
                    true => EfivarRedaction::Unredacted,
                    false => EfivarRedaction::DecodedBytes,
                };
                let dump = HiiBackend::dump_efivars(
                    &hiidb.read(&EfivarSource::System, source)?,
                    directory,
                    &options,
                )?;
                eprintln!("{}", dump_warning(directory, options.redaction));
                print_line(format_args!(
                    "{}",
                    dump_report(directory, options.redaction, dump)
                ))?;
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
    /// The HiiDB: the file, else the one in `efivars` if dump-efivars wrote it, else this
    /// machine's, read as `source` says.
    pub(super) fn read(&self, efivars: &EfivarSource, source: &HiiSourceArgs) -> Result<Vec<u8>> {
        HiiBackend::read_hiidb_from(
            self.filename.as_deref(),
            efivars,
            &hii_source_options(source),
        )
    }
}

/// Where get, show-ifr and list-questions read question values.
#[derive(Debug, Args)]
pub(super) struct EfivarArgs {
    /// Read question values from the efivar files in this directory (efivarfs format) instead of this machine's efivarfs; without --filename, also the HiiDB if dump-efivars wrote the directory
    #[arg(long, value_name = "DIR", conflicts_with = "no_efivars")]
    efivars: Option<PathBuf>,
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB still comes from --filename or this machine)
    #[arg(long)]
    no_efivars: bool,
}

impl EfivarArgs {
    /// The source these flags name.
    pub(super) fn source(&self) -> Result<EfivarSource> {
        match (&self.efivars, self.no_efivars) {
            (None, false) => Ok(EfivarSource::System),
            (None, true) => Ok(EfivarSource::Disabled),
            (Some(dir), false) => Ok(EfivarSource::Directory(dir.clone())),
            (Some(_), true) => Err(anyhow!("--efivars and --no-efivars conflict")),
        }
    }
}

/// None: efivarfs writes from Linux, where set takes no setup password policy.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct SetupPasswordArgs {}

impl SetupPasswordArgs {
    /// The default, which set through efivarfs does not consult.
    pub(super) fn policy(&self) -> SetupPasswordPolicy {
        SetupPasswordPolicy::default()
    }
}

/// The QUESTION of `question` for the Ilo backend; fails if a flag of the HII backend is given:
/// Ilo attributes have no QuestionId, no keywords, no IFR conditions and no HII strings.
fn refuse_on_ilo<'a, S>(question: &'a QuestionArgs, selection: &SelectionArgs<S>) -> Result<&'a str>
where
    S: clap::ValueEnum + Clone + Send + Sync + 'static,
{
    let stated: Vec<&str> = [
        ("--question-id", question.selector.question_id.is_some()),
        ("--keyword", question.selector.keyword.is_some()),
        ("--keyword-namespace", question.keyword_namespace.is_some()),
        ("--include", !selection.include.include.is_empty()),
        ("--access-level", selection.access_level.is_some()),
        ("--language", selection.language.language.is_some()),
    ]
    .into_iter()
    .filter_map(|(flag, stated)| stated.then_some(flag))
    .collect();
    let flags = match stated.as_slice() {
        [] => {
            return question
                .selector
                .question
                .as_deref()
                .ok_or_else(|| anyhow!("the Ilo backend selects only by QUESTION"))
        }
        [flag] => format!("{flag} applies"),
        [first @ .., last] => format!("{} and {last} apply", first.join(", ")),
    };
    Err(anyhow!(
        "{flags} to the HII backend, not to the Ilo backend of this machine"
    ))
}

/// get, on this machine's backend, whose HiiDB it reads as `source` says.
pub(super) fn auto_get(
    question: &QuestionArgs,
    json: bool,
    selection: &SelectionArgs,
    source: &HiiSourceArgs,
) -> Result<()> {
    let options = hii_source_options(source);
    let machine = identify_machine_using(&options);
    if machine.backend.contains(&Backend::Unknown) {
        return Err(anyhow!("unknown backend"));
    }
    if prioritize_backend(&machine, json)? == Backend::Ilo {
        let res = IloBackend::get(refuse_on_ilo(question, selection)?, None)?;
        print_with_style(res, json)?;
    } else {
        hii_get(
            &HiiBackend::read_hiidb_from(None, &EfivarSource::System, &options)?,
            question.selector()?,
            &GetOptions::from(selection),
            json,
        )?;
    }
    Ok(())
}

/// None: efivarfs writes from Linux, after ExitBootServices, when SetVariable() sets no volatile
/// variable (UEFI 2.11 §8.2.3).
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

/// set, on this machine's backend, whose HiiDB it reads as `source` says.
pub(super) fn auto_set(
    target: &SetArgs,
    json: bool,
    selection: &SelectionArgs<SetIncludeState>,
    options: &SetOptions,
    source: &HiiSourceArgs,
) -> Result<()> {
    let machine = identify_machine_using(&hii_source_options(source));
    if machine.backend.contains(&Backend::Unknown) {
        return Err(anyhow!("unknown backend"));
    }
    let (selector, value) = target.target()?;
    if prioritize_backend(&machine, json)? == Backend::Ilo {
        let SetValue::Text(value) = value else {
            return Err(anyhow!(
                "--item gives the options of an ORDERED_LIST of the HII backend; the iLO backend \
                 takes VALUE"
            ));
        };
        let res = IloBackend::set(refuse_on_ilo(&target.question, selection)?, &value, None)?;
        print_with_style(res, json)?;
    } else {
        hii_set(selector, &value, options, json, source)?;
    }
    Ok(())
}

/// HiiBackend::set_using, in this machine's HiiDB read as `source` says.
pub(super) fn set_using(
    question: QuestionSelector,
    value: &SetValue,
    options: &SetOptions,
    source: &HiiSourceArgs,
) -> Result<SetResponseList> {
    HiiBackend::set_from(question, value, None, options, &hii_source_options(source))
}

/// The bytes of the file `path`, the payload of capsule deliver or variable write-signed.
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

/// What dump-efivars prints on stdout about `dump` into `dir`.
fn dump_report(dir: &Path, redaction: EfivarRedaction, dump: EfivarDump) -> serde_json::Value {
    serde_json::json!({
        "info": format!(
            "copied {} of the {} EFI variables that questions read, and the HiiDB, to {}",
            dump.copied.len(),
            dump.copied.len() + dump.missing.len(),
            dir.display()
        ),
        "directory": dir.display().to_string(),
        // as the dump's manifest records it
        "redaction": redaction,
        "copied": dump.copied,
        "missing": dump.missing,
    })
}

/// What dump-efivars warns on stderr about a dump into `dir`.
fn dump_warning(dir: &Path, redaction: EfivarRedaction) -> String {
    match redaction {
        EfivarRedaction::DecodedBytes => format!(
            "warning: {} holds the HiiDB, whose strings can name the machine, and EFI variables \
             redacted to the bytes that questions decode, whose values can still be secrets, and \
             also, for variables with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, to the \
             EFI_VARIABLE_AUTHENTICATION_3 metadata that get accepts (time stamp or nonce, and \
             certificate digest), which it needs to find their values; share it only with people \
             you trust",
            dir.display()
        ),
        EfivarRedaction::Unredacted => format!(
            "warning: {} holds the HiiDB, whose strings can name the machine, and whole EFI \
             variables, not redacted, which can hold secrets such as password hashes; share it \
             only with people you trust",
            dir.display()
        ),
        _ => format!(
            "warning: {} holds the HiiDB, whose strings can name the machine, and EFI variables, \
             which can hold secrets such as password hashes; share it only with people you trust",
            dir.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::hii;
    use crate::tests::READING_COMMANDS;
    use crate::Commands;
    use crate::HiiSubcommands;
    use crate::UefiSettingsToolArgs;

    /// The flags name the library's HiiDB source: the automatic order or one method, and the
    /// memory of the efivar method, also after a hii command.
    #[test]
    fn hii_source_options_follow_the_flags() {
        use EfivarMemory::FirmwareReserved;
        use EfivarMemory::Runtime;
        for (args, source, memory) in [
            (vec![], HiiSource::Auto, Runtime),
            (vec!["--hii-source", "auto"], HiiSource::Auto, Runtime),
            (
                vec!["--hii-source", "acpi"],
                HiiSource::Method(HiiMethod::Acpi),
                Runtime,
            ),
            (
                vec![
                    "--hii-source",
                    "efivar",
                    "--efivar-memory",
                    "firmware-reserved",
                ],
                HiiSource::Method(HiiMethod::Efivar),
                FirmwareReserved,
            ),
            (
                vec!["--hii-source", "systab"],
                HiiSource::Method(HiiMethod::Systab),
                Runtime,
            ),
            (vec!["--efivar-memory", "runtime"], HiiSource::Auto, Runtime),
        ] {
            let argv = [&["uefisettings", "hii", "extract-db", "db.bin"][..], &args].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));

            let options = hii_source_options(&parsed.hii_source);

            assert_eq!(
                (options.source, options.efivar_memory),
                (source, memory),
                "{args:?}"
            );
        }
    }

    /// refuse_on_ilo of `uefisettings get Q` with the flags `args`, or of `uefisettings get` with
    /// `args` if they select by --question-id or --keyword.
    fn refused_on_ilo(args: &[&str]) -> Result<String, String> {
        let selects = args
            .iter()
            .any(|arg| matches!(*arg, "--question-id" | "--keyword"));
        let question: &[&str] = if selects { &[] } else { &["Q"] };
        let argv = [&["uefisettings", "get"][..], question, args].concat();
        let parsed = UefiSettingsToolArgs::try_parse_from(argv)
            .unwrap_or_else(|error| panic!("parse get {args:?}: {error}"));
        let Commands::Get {
            question,
            selection,
            ..
        } = parsed.command
        else {
            panic!("not get: {args:?}");
        };
        refuse_on_ilo(&question, &selection)
            .map(str::to_owned)
            .map_err(|error| error.to_string())
    }

    /// refuse_on_ilo names the flags that apply to the HII backend only, of which Ilo attributes
    /// take none, and passes QUESTION without them.
    #[test]
    fn refuse_on_ilo_names_the_flags_of_the_hii_backend() {
        let cases = [
            ("no flag", vec![], Ok("Q")),
            (
                "--question-id",
                vec!["--question-id", "8C78A505-BAA0-4C4A-869F-000000000800:1"],
                Err(
                    "--question-id applies to the HII backend, not to the Ilo backend of this \
                     machine",
                ),
            ),
            (
                "--keyword and --keyword-namespace",
                vec!["--keyword", "K", "--keyword-namespace", "x-i-UEFI"],
                Err(
                    "--keyword and --keyword-namespace apply to the HII backend, not to the Ilo \
                     backend of this machine",
                ),
            ),
            (
                "--include",
                vec!["--include", "grayed-out"],
                Err("--include applies to the HII backend, not to the Ilo backend of this machine"),
            ),
            (
                "--access-level",
                vec!["--access-level", "user"],
                Err(
                    "--access-level applies to the HII backend, not to the Ilo backend of this \
                     machine",
                ),
            ),
            (
                "--include and --access-level",
                vec!["--include", "grayed-out", "--access-level", "user"],
                Err(
                    "--include and --access-level apply to the HII backend, not to the Ilo \
                     backend of this machine",
                ),
            ),
            (
                "--language",
                vec!["--language", "fr-FR"],
                Err(
                    "--language applies to the HII backend, not to the Ilo backend of this machine",
                ),
            ),
            (
                "--include, --access-level and --language",
                vec![
                    "--include",
                    "grayed-out",
                    "--access-level",
                    "user",
                    "--language",
                    "fr-FR",
                ],
                Err(
                    "--include, --access-level and --language apply to the HII backend, not to \
                     the Ilo backend of this machine",
                ),
            ),
        ];
        for (case, args, want) in cases {
            assert_eq!(
                refused_on_ilo(&args),
                want.map(str::to_string).map_err(str::to_string),
                "{case}"
            );
        }
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
                clap::error::ErrorKind::ArgumentConflict,
                "{command:?}"
            );
        }
    }

    #[test]
    fn hii_get_takes_a_hiidb_file() {
        let parsed = hii(&["get", "Question", "-f", "hiidb.bin"]).expect("parse get -f");

        let HiiSubcommands::Get { hiidb, .. } = parsed else {
            panic!("not get: {parsed:?}");
        };
        assert_eq!(hiidb.filename, Some(PathBuf::from("hiidb.bin")), "get -f");
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
            let HiiSubcommands::Platform(HiiPlatformCommands::DumpEfivars {
                hiidb,
                unredacted,
                directory,
            }) = parsed
            else {
                panic!("{case}: not dump-efivars: {parsed:?}");
            };

            assert_eq!(
                (hiidb.filename, unredacted, directory),
                (want_filename, want_unredacted, PathBuf::from("out")),
                "{case}"
            );
        }
        let error = hii(&["dump-efivars"]).expect_err("parse dump-efivars without DIR");
        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument,
            "no DIR"
        );
    }

    /// The Linux build takes no --allow-volatile: efivarfs writes after ExitBootServices, when
    /// SetVariable() sets no volatile variable (UEFI 2.11 §8.2.3).
    #[test]
    fn set_takes_no_allow_volatile_flag() {
        let commands: [&[&str]; 2] = [&["hii", "set", "Q", "V"], &["set", "Q", "V"]];
        for command in commands {
            let argv = [&["uefisettings"][..], command, &["--allow-volatile"]].concat();
            let error =
                UefiSettingsToolArgs::try_parse_from(argv).expect_err("parse --allow-volatile");

            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{command:?}"
            );
        }
    }

    /// The Linux build takes no --bypass-setup-password: set through efivarfs has no setup
    /// password policy.
    #[test]
    fn set_takes_no_setup_password_flag() {
        let commands: [&[&str]; 2] = [&["hii", "set", "Q", "V"], &["set", "Q", "V"]];
        for command in commands {
            let argv = [&["uefisettings"][..], command, &["--bypass-setup-password"]].concat();
            let error = UefiSettingsToolArgs::try_parse_from(argv)
                .expect_err("parse --bypass-setup-password");

            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{command:?}"
            );
        }
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
                    "info": "copied 1 of the 2 EFI variables that questions read, and the HiiDB, \
                             to out",
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
                "warning: out holds the HiiDB, whose strings can name the machine, and EFI \
                 variables redacted to the bytes that questions decode, whose values can still \
                 be secrets, and also, for variables with \
                 EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, to the \
                 EFI_VARIABLE_AUTHENTICATION_3 metadata that get accepts (time stamp or nonce, \
                 and certificate digest), which it needs to find their values; share it only \
                 with people you trust",
            ),
            (
                "unredacted",
                EfivarRedaction::Unredacted,
                "warning: out holds the HiiDB, whose strings can name the machine, and whole \
                 EFI variables, not redacted, which can hold secrets such as password hashes; \
                 share it only with people you trust",
            ),
        ];

        for (case, redaction, warning) in cases {
            assert_eq!(dump_warning(Path::new("out"), redaction), warning, "{case}");
        }
    }
}
