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

use std::fmt::Display;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Parser;
use clap::Subcommand;
use env_logger::fmt::Color;
use env_logger::fmt::Formatter;
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
use uefisettings::exports::UnsafeOperation;
use uefisettings::exports::UnsafeOperations;
use uefisettings::exports::VolatileWrites;
use uefisettings::secret_file;
use uefisettings::secret_file::Secret;
use uefisettings::secret_file::MAX_SECRET_LEN;
use uefisettings::terminal_text::TerminalText;
use uefisettings::terminal_text::UnicodeTerminal;
use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::MachineInfo;
use uefisettings_backend_thrift::SetResponseList;

use crate::extract_db_report;
use crate::hii_get;
use crate::hii_set;
use crate::print_json;
use crate::print_lifted;
use crate::print_line;
use crate::print_with_style;
use crate::unsafe_long_help;
use crate::write_extracted_db;
use crate::JsonArgs;
use crate::QuestionArgs;
use crate::SelectionArgs;
use crate::SetArgs;
use crate::UnsafeArgs;
use crate::READ_ONLY_WRITE;
use crate::STAGED_SETUP_PASSWORD;
use crate::UNSAFE_ARG;

/// The about of hii, whose commands read this machine's HiiDB or a file.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this machine's backend.
pub(super) const GET_ABOUT: &str = "Auto-identify backend and get the current value of a question";
/// The about of top-level set, which writes this machine's backend.
pub(super) const SET_ABOUT: &str = "Auto-identify backend and set/change the value of a question";

/// The help of --hii-source, with the default that hii_source_options takes.
const HII_SOURCE_HELP: &str = "Where the commands read this machine's HiiDB, where no HiiDB file \
                               or efivars dump gives one [default: auto]";
/// The help of --efivar-memory, with the default that hii_source_options takes.
const EFIVAR_MEMORY_HELP: &str =
    "The memory that the efivar method of --hii-source may read; firmware-reserved is an unsafe \
     operation, whose refusal names the flag that lifts it [default: runtime]";

/// Where the commands read this machine's HiiDB; global, so that the flags may also follow the
/// command. Only this build reads it in more than one way, so only it has the flags. Each is
/// None unless given, so that a command that would ignore it can refuse it.
#[derive(Debug, Clone, PartialEq, Eq, Args)]
pub(super) struct HiiSourceArgs {
    #[arg(long, global = true, value_enum, help = HII_SOURCE_HELP)]
    hii_source: Option<HiiSourceArg>,
    #[arg(long, global = true, value_enum, help = EFIVAR_MEMORY_HELP)]
    efivar_memory: Option<EfivarMemoryArg>,
}

impl HiiSourceArgs {
    /// Fails if --hii-source or --efivar-memory is given where `why` names how no HiiDB of this
    /// machine is read, so that neither is ignored.
    pub(super) fn refuse_given(&self, why: &str) -> Result<()> {
        let given: Vec<&str> = [
            ("--hii-source", self.hii_source.is_some()),
            ("--efivar-memory", self.efivar_memory.is_some()),
        ]
        .into_iter()
        .filter_map(|(flag, given)| given.then_some(flag))
        .collect();
        let flags = match given.as_slice() {
            [] => return Ok(()),
            [flag] => format!("{flag} names"),
            [first @ .., last] => format!("{} and {last} name", first.join(", ")),
        };
        Err(anyhow!(
            "{flags} where this machine's HiiDB is read, and {why}"
        ))
    }

    /// Fails if --efivar-memory is given where `why` names how no memory of the efivar method is
    /// read, so that it is not ignored.
    fn refuse_efivar_memory(&self, why: &str) -> Result<()> {
        match self.efivar_memory {
            None => Ok(()),
            Some(_) => Err(anyhow!(
                "--efivar-memory names the memory of the efivar method, and {why}"
            )),
        }
    }
}

/// The values of --hii-source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum HiiSourceArg {
    /// acpi, then efivar, then systab: the next while a method finds its source absent or fails, none after a refusal (kernel lockdown, /dev/mem or /proc/kcore refused, or an unsafe operation without --i-am-fine-to-brick-this-system)
    Auto,
    /// The memory that the OCP HiiDB variable points to, from /dev/mem
    Efivar,
    /// The vendor ACPI table QHII or HIID, from /sys/firmware/acpi/tables, without /dev/mem
    Acpi,
    /// The HII database export that the EFI System Table lists as a configuration table, from /dev/mem
    Systab,
}

/// The values of --efivar-memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum EfivarMemoryArg {
    /// One EFI runtime region of the firmware's memory map that is no memory-mapped I/O
    Runtime,
    /// One firmware-reserved region of the firmware's memory map (x86: Reserved or ACPI Non-volatile Storage in /sys/firmware/memmap; aarch64: reserved, runtime services code or data, ACPI NVS or PAL code), never one that touches runtime memory-mapped I/O
    FirmwareReserved,
}

/// The HiiDB source that `args` name, auto and runtime where not given; refuses --efivar-memory
/// with a method other than efivar, the one method that reads that memory.
fn hii_source_options(args: &HiiSourceArgs) -> Result<HiiSourceOptions> {
    let mut options = HiiSourceOptions::default();
    options.source = match args.hii_source {
        None | Some(HiiSourceArg::Auto) => HiiSource::Auto,
        Some(HiiSourceArg::Efivar) => HiiSource::Method(HiiMethod::Efivar),
        Some(HiiSourceArg::Acpi) => HiiSource::Method(HiiMethod::Acpi),
        Some(HiiSourceArg::Systab) => HiiSource::Method(HiiMethod::Systab),
    };
    options.efivar_memory = match (args.efivar_memory, options.source) {
        (None, _) => EfivarMemory::Runtime,
        (Some(_), HiiSource::Method(method)) if method != HiiMethod::Efivar => {
            return Err(anyhow!(
                "--efivar-memory names the memory of the efivar method, which --hii-source \
                 {method} does not run"
            ))
        }
        (Some(EfivarMemoryArg::Runtime), _) => EfivarMemory::Runtime,
        (Some(EfivarMemoryArg::FirmwareReserved), _) => EfivarMemory::FirmwareReserved,
    };
    Ok(options)
}

/// This machine's HII backend, which the commands reach with the HiiSourceOptions of the flags;
/// tests replace it.
pub(super) trait MachineHii {
    /// The backends of this machine, as identify_machine_using finds them.
    fn identify(&self, source: &HiiSourceOptions) -> MachineInfo;

    /// This machine's HiiDB, as HiiBackend::extract_db_from reads it, and the unsafe operations
    /// that the read lifted.
    fn extract_db(
        &self,
        source: &HiiSourceOptions,
        unsafe_operations: UnsafeOperations,
    ) -> Result<(Vec<u8>, Vec<UnsafeOperation>)>;

    /// HiiBackend::set_from.
    fn set(
        &self,
        question: QuestionSelector,
        value: &SetValue,
        options: &SetOptions,
        source: &HiiSourceOptions,
    ) -> Result<(SetResponseList, Vec<UnsafeOperation>)>;
}

/// The library's reads and writes of this machine's firmware.
pub(super) struct Firmware;

impl MachineHii for Firmware {
    fn identify(&self, source: &HiiSourceOptions) -> MachineInfo {
        identify_machine_using(source)
    }

    fn extract_db(
        &self,
        source: &HiiSourceOptions,
        unsafe_operations: UnsafeOperations,
    ) -> Result<(Vec<u8>, Vec<UnsafeOperation>)> {
        let (database, lifted) = HiiBackend::extract_db_from(source, unsafe_operations)?;
        Ok((database.db, lifted))
    }

    fn set(
        &self,
        question: QuestionSelector,
        value: &SetValue,
        options: &SetOptions,
        source: &HiiSourceOptions,
    ) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
        HiiBackend::set_from(question, value, None, options, source)
    }
}

/// Logs as RUST_LOG says, each message as TerminalText, as a message may name the HiiDB's
/// strings.
pub(super) fn init_logging() {
    env_logger::Builder::from_default_env()
        .format(write_log_record)
        .init();
}

/// Writes `record` with the header that env_logger 0.10.1's DefaultFormat writes under
/// init_logging's defaults (src/fmt/mod.rs:155-158, :225-232): its timestamp in seconds, its
/// styled level and its target, in subtle braces (:235-249).
fn write_log_record(buf: &mut Formatter, record: &log::Record<'_>) -> io::Result<()> {
    let mut brace = buf.style();
    brace.set_color(Color::Black).set_intense(true);
    let timestamp = buf.timestamp();
    let level = buf.default_styled_level(record.level());
    write_log_line(
        buf,
        (brace.value("["), brace.value("]")),
        timestamp,
        level,
        record,
    )
}

/// Writes `record` to `output` as DefaultFormat lays it out, `[{timestamp} {level:<5} {target}] `
/// with `open` and `close` as the braces and without an empty target, and then its message as
/// TerminalText.
fn write_log_line(
    output: &mut impl Write,
    (open, close): (impl Display, impl Display),
    timestamp: impl Display,
    level: impl Display,
    record: &log::Record<'_>,
) -> io::Result<()> {
    write!(output, "{open}{timestamp} {level:<5}")?;
    match record.target() {
        "" => {}
        target => write!(output, " {target}")?,
    }
    writeln!(
        output,
        "{close} {}",
        TerminalText(&record.args().to_string())
    )
}

/// The terminal of stdout, which renders every character: TerminalText and JsonText do all the
/// escaping.
pub(super) fn stdout_output() -> io::Result<UnicodeTerminal> {
    Ok(UnicodeTerminal)
}

/// The terminal of stderr, as stdout_output's.
pub(super) fn stderr_output() -> io::Result<UnicodeTerminal> {
    Ok(UnicodeTerminal)
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
    pub(super) fn run(&self, source: &HiiSourceArgs, hii: &impl MachineHii) -> Result<()> {
        match self {
            Self::Ilo(ilo_command) => {
                source.refuse_given("ilo reads none")?;
                match &ilo_command.command {
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
                }
            }
            Self::Identify { output } => {
                let options = hii_source_options(source)?;
                source.refuse_efivar_memory(
                    "identify reads none: its efivar method checks only that the HiiDB variable \
                     exists",
                )?;
                let machine = hii.identify(&options);
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
    ExtractDB {
        filename: PathBuf,
        #[command(flatten)]
        unsafe_operations: HiiSourceUnsafeArgs,
    },
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
    pub(super) fn run(&self, source: &HiiSourceArgs, hii: &impl MachineHii) -> Result<()> {
        match self {
            Self::ExtractDB {
                filename,
                unsafe_operations,
            } => {
                write_extracted_db(filename, || {
                    let (db, lifted) = hii
                        .extract_db(&hii_source_options(source)?, unsafe_operations.operations())?;
                    print_lifted(&lifted)?;
                    Ok(db)
                })?;

                print_json(&extract_db_report(filename))?;
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
                    &hiidb.read(&EfivarSource::System, source, hii)?,
                    directory,
                    &options,
                )?;
                eprintln!("{}", dump_warning(directory, options.redaction));
                print_json(&dump_report(directory, options.redaction, dump))?;
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
    #[command(flatten)]
    unsafe_operations: HiiSourceUnsafeArgs,
}

impl HiiDbArgs {
    /// The HiiDB: the file, else the one in `efivars` if dump-efivars wrote it, either of which
    /// refuses a given `source`, else this machine's, read as `source` says, after a warning per
    /// unsafe operation that it lifted.
    pub(super) fn read(
        &self,
        efivars: &EfivarSource,
        source: &HiiSourceArgs,
        hii: &impl MachineHii,
    ) -> Result<Vec<u8>> {
        let given = match self.filename {
            Some(_) => "--filename gives the HiiDB",
            None => "the efivars dump of --efivars gives the HiiDB",
        };
        if let Some(db) = HiiBackend::read_given_hiidb(self.filename.as_deref(), efivars)? {
            source.refuse_given(given)?;
            return Ok(db);
        }
        let (db, lifted) = hii.extract_db(
            &hii_source_options(source)?,
            self.unsafe_operations.operations(),
        )?;
        print_lifted(&lifted)?;
        Ok(db)
    }
}

/// What a command that reads this machine's HiiDB through --hii-source refuses without
/// --i-am-fine-to-brick-this-system, besides those of set.
const FIRMWARE_RESERVED_READ: &str = "a read of the HiiDB with --efivar-memory firmware-reserved, \
                                      which may read device memory, whose reads can have side \
                                      effects";

/// --i-am-fine-to-brick-this-system of a command that reads this machine's HiiDB through
/// --hii-source, which --efivar-memory firmware-reserved needs.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
#[command(mut_arg(UNSAFE_ARG, |arg| unsafe_long_help(arg, &[FIRMWARE_RESERVED_READ])))]
pub(super) struct HiiSourceUnsafeArgs {
    #[command(flatten)]
    unsafe_operations: UnsafeArgs,
}

impl HiiSourceUnsafeArgs {
    pub(super) fn operations(&self) -> UnsafeOperations {
        self.unsafe_operations.operations()
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

/// The unsafe operations of set, which its long help lists: efivarfs writes from Linux, which
/// no setup password gates, a set staged for the next boot, which one does, and the read of the
/// HiiDB.
pub(super) const SET_UNSAFE_OPERATIONS: &[&str] = &[
    READ_ONLY_WRITE,
    STAGED_SETUP_PASSWORD,
    FIRMWARE_RESERVED_READ,
];

/// What set stages for the next boot.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct StagingArgs {
    /// The uefisettings.efi that set copies to the EFI system partition when it stages a question whose value only its driver holds, which the next boot applies. Under Secure Boot, it must be signed for db.
    #[arg(long, value_name = "UEFISETTINGS_EFI")]
    image: Option<PathBuf>,
}

impl StagingArgs {
    pub(super) fn image(&self) -> Option<PathBuf> {
        self.image.clone()
    }

    /// None: Linux writes through the mount point where it finds the ESP mounted.
    pub(super) fn esp(&self) -> Option<PathBuf> {
        None
    }

    /// Fails if --image is given: Ilo attributes have no driver that holds their value.
    pub(super) fn refuse_on_ilo(&self) -> Result<()> {
        match self.image {
            None => Ok(()),
            Some(_) => Err(anyhow!(
                "--image applies to the HII backend, not to the Ilo backend of this machine"
            )),
        }
    }
}

/// The QUESTION of `question` for the Ilo backend; fails if a flag of the HII backend is given:
/// Ilo attributes have no QuestionId, no keywords, no IFR conditions and no HII strings.
fn refuse_on_ilo<'a>(question: &'a QuestionArgs, selection: &SelectionArgs) -> Result<&'a str> {
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
    unsafe_operations: &HiiSourceUnsafeArgs,
    source: &HiiSourceArgs,
    hii: &impl MachineHii,
) -> Result<()> {
    let options = hii_source_options(source)?;
    let machine = hii.identify(&options);
    if machine.backend.contains(&Backend::Unknown) {
        return Err(anyhow!("unknown backend"));
    }
    if prioritize_backend(&machine, json)? == Backend::Ilo {
        source.refuse_given("get takes the Ilo backend of this machine, which reads none")?;
        let res = IloBackend::get(refuse_on_ilo(question, selection)?, None)?;
        print_with_style(res, json)?;
    } else {
        let (db, lifted) = hii.extract_db(&options, unsafe_operations.operations())?;
        print_lifted(&lifted)?;
        hii_get(
            &db,
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
    selection: &SelectionArgs,
    staging: &StagingArgs,
    options: &SetOptions,
    source: &HiiSourceArgs,
    hii: &impl MachineHii,
) -> Result<()> {
    let machine = hii.identify(&hii_source_options(source)?);
    if machine.backend.contains(&Backend::Unknown) {
        return Err(anyhow!("unknown backend"));
    }
    let (selector, value) = target.target()?;
    if prioritize_backend(&machine, json)? == Backend::Ilo {
        source.refuse_given("set takes the Ilo backend of this machine, which reads none")?;
        let SetValue::Text(value) = value else {
            return Err(anyhow!(
                "--item gives the options of an ORDERED_LIST of the HII backend; the iLO backend \
                 takes VALUE"
            ));
        };
        let question = refuse_on_ilo(&target.question, selection)?;
        staging.refuse_on_ilo()?;
        let res = IloBackend::set(question, &value, None)?;
        print_with_style(res, json)?;
    } else {
        hii_set(selector, &value, options, json, source, hii)?;
    }
    Ok(())
}

/// HiiBackend::set_using, in this machine's HiiDB read as `source` says.
pub(super) fn set_using(
    question: QuestionSelector,
    value: &SetValue,
    options: &SetOptions,
    source: &HiiSourceArgs,
    hii: &impl MachineHii,
) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
    hii.set(question, value, options, &hii_source_options(source)?)
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
    use clap::CommandFactory;

    use super::*;
    use crate::tests::hii;
    use crate::tests::READING_COMMANDS;
    use crate::Commands;
    use crate::HiiSubcommands;
    use crate::UefiSettingsToolArgs;

    /// The grant of the HiiDB read of `uefisettings` and then `args`, a command that reads this
    /// machine's HiiDB through --hii-source.
    fn hii_source_grant(args: &[&str]) -> UnsafeOperations {
        let argv = [&["uefisettings"][..], args].concat();
        let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
            .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));
        let unsafe_operations = match parsed.command {
            Commands::Get {
                unsafe_operations, ..
            } => unsafe_operations,
            Commands::Hii(hii) => match hii.command {
                HiiSubcommands::Get { hiidb, .. }
                | HiiSubcommands::ShowIFR { hiidb, .. }
                | HiiSubcommands::ListStrings { hiidb, .. }
                | HiiSubcommands::ListQuestions { hiidb, .. }
                | HiiSubcommands::Platform(HiiPlatformCommands::DumpEfivars { hiidb, .. }) => {
                    hiidb.unsafe_operations
                }
                HiiSubcommands::Platform(HiiPlatformCommands::ExtractDB {
                    unsafe_operations,
                    ..
                }) => unsafe_operations,
                other => panic!("{argv:?} reads no HiiDB: {other:?}"),
            },
            other => panic!("{argv:?} reads no HiiDB: {other:?}"),
        };
        unsafe_operations.operations()
    }

    /// Every Linux command that reads this machine's HiiDB through --hii-source grants its read
    /// UnsafeOperations::Allow with --i-am-fine-to-brick-this-system and Refuse without, and
    /// the flag's long help lists the read of firmware-reserved memory.
    #[test]
    fn hii_source_readers_take_the_unsafe_flag() {
        let commands: [(&[&str], &[&str]); 7] = [
            (&["get"], &["Q"]),
            (&["hii", "get"], &["Q"]),
            (&["hii", "show-ifr"], &[]),
            (&["hii", "list-strings"], &[]),
            (&["hii", "list-questions"], &[]),
            (&["hii", "dump-efivars"], &["dir"]),
            (&["hii", "extract-db"], &["hiidb.bin"]),
        ];
        let mut root = UefiSettingsToolArgs::command();
        root.build();
        for (path, positionals) in commands {
            for (flag, want) in [
                (&[][..], UnsafeOperations::Refuse),
                (
                    &["--i-am-fine-to-brick-this-system"],
                    UnsafeOperations::Allow,
                ),
            ] {
                assert_eq!(
                    hii_source_grant(&[path, positionals, flag].concat()),
                    want,
                    "{path:?} {flag:?}"
                );
            }

            let reader = path.iter().fold(&root, |command, name| {
                command
                    .find_subcommand(name)
                    .unwrap_or_else(|| panic!("no subcommand {name}"))
            });
            let long_help = reader
                .get_arguments()
                .find(|arg| arg.get_long() == Some("i-am-fine-to-brick-this-system"))
                .and_then(|flag| flag.get_long_help())
                .map(ToString::to_string);
            assert_eq!(
                long_help,
                Some(format!(
                    "{}. This command refuses without it: {FIRMWARE_RESERVED_READ}",
                    crate::UNSAFE_HELP
                )),
                "{path:?}"
            );
        }
    }

    /// The flags of the HiiDB source are None unless given, take each of their values, are
    /// global, so that they also follow the command, and refuse another value.
    #[test]
    fn hii_source_flags_are_none_unless_given_and_follow_the_command() {
        let parse = |args: &[&str]| {
            let argv = [&["uefisettings"][..], args].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));
            (
                parsed.hii_source.hii_source,
                parsed.hii_source.efivar_memory,
            )
        };
        assert_eq!(parse(&["show-translations"]), (None, None), "no flag");
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
                assert_eq!(parse(args).0, Some(want), "{args:?}");
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
                assert_eq!(parse(args).1, Some(want), "{args:?}");
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

    /// The flags name the library's HiiDB source: the automatic order or one method, and the
    /// memory of the efivar method, also after a hii command; --efivar-memory with acpi or
    /// systab, which never read that memory, is refused.
    #[test]
    fn hii_source_options_follow_the_flags() {
        use EfivarMemory::FirmwareReserved;
        use EfivarMemory::Runtime;
        let unread = |method: &str| {
            Err(format!(
                "--efivar-memory names the memory of the efivar method, which --hii-source \
                 {method} does not run"
            ))
        };
        for (args, want) in [
            (vec![], Ok((HiiSource::Auto, Runtime))),
            (vec!["--hii-source", "auto"], Ok((HiiSource::Auto, Runtime))),
            (
                vec!["--hii-source", "acpi"],
                Ok((HiiSource::Method(HiiMethod::Acpi), Runtime)),
            ),
            (
                vec![
                    "--hii-source",
                    "efivar",
                    "--efivar-memory",
                    "firmware-reserved",
                ],
                Ok((HiiSource::Method(HiiMethod::Efivar), FirmwareReserved)),
            ),
            (
                vec!["--hii-source", "systab"],
                Ok((HiiSource::Method(HiiMethod::Systab), Runtime)),
            ),
            (
                vec!["--efivar-memory", "runtime"],
                Ok((HiiSource::Auto, Runtime)),
            ),
            (
                vec!["--efivar-memory", "firmware-reserved"],
                Ok((HiiSource::Auto, FirmwareReserved)),
            ),
            (
                vec![
                    "--hii-source",
                    "auto",
                    "--efivar-memory",
                    "firmware-reserved",
                ],
                Ok((HiiSource::Auto, FirmwareReserved)),
            ),
            (
                vec!["--hii-source", "acpi", "--efivar-memory", "runtime"],
                unread("acpi"),
            ),
            (
                vec![
                    "--hii-source",
                    "systab",
                    "--efivar-memory",
                    "firmware-reserved",
                ],
                unread("systab"),
            ),
        ] {
            let argv = [&["uefisettings", "hii", "extract-db", "db.bin"][..], &args].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));

            let options = hii_source_options(&parsed.hii_source);

            assert_eq!(
                options
                    .map(|options| (options.source, options.efivar_memory))
                    .map_err(|error| error.to_string()),
                want,
                "{args:?}"
            );
        }
    }

    /// This machine's HII backend in the tests: it records each call with the HiiDB source that
    /// it is given, finds the HII backend only, and fails each read and set.
    #[derive(Default)]
    struct RecordedHii(std::cell::RefCell<Vec<(&'static str, HiiSourceOptions)>>);

    impl RecordedHii {
        fn record(&self, call: &'static str, source: &HiiSourceOptions) {
            self.0.borrow_mut().push((call, *source));
        }
    }

    impl MachineHii for RecordedHii {
        fn identify(&self, source: &HiiSourceOptions) -> MachineInfo {
            self.record("identify", source);
            MachineInfo {
                backend: [Backend::Hii].into(),
                ..Default::default()
            }
        }

        fn extract_db(
            &self,
            source: &HiiSourceOptions,
            _: UnsafeOperations,
        ) -> Result<(Vec<u8>, Vec<UnsafeOperation>)> {
            self.record("extract_db", source);
            Err(anyhow!("recorded"))
        }

        fn set(
            &self,
            _: QuestionSelector,
            _: &SetValue,
            _: &SetOptions,
            source: &HiiSourceOptions,
        ) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
            self.record("set", source);
            Err(anyhow!("recorded"))
        }
    }

    /// handle_cmds_with of `uefisettings` and then `args` on a RecordedHii, as its error text, and
    /// the calls that it recorded.
    fn run_recorded(args: &[&str]) -> (Result<(), String>, Vec<(&'static str, HiiSourceOptions)>) {
        let argv = [&["uefisettings"][..], args].concat();
        let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
            .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));
        let hii = RecordedHii::default();

        let result = crate::handle_cmds_with(parsed, &hii).map_err(|error| error.to_string());

        (result, hii.0.into_inner())
    }

    /// Each command that reads this machine's HiiDB or backends hands this machine's HII backend
    /// the source that --hii-source and --efivar-memory name, before the command, after it or,
    /// for hii, between hii and its command; and the default source without them.
    #[test]
    fn machine_commands_read_from_the_flags_source() {
        let dir = tempfile::tempdir().expect("create a directory");
        let db = dir.path().join("hiidb.bin");
        let db_arg = db.to_str().expect("UTF-8 temporary path");
        let dump = dir.path().join("dump");
        let dump_arg = dump.to_str().expect("UTF-8 temporary path");
        let flags = [
            "--hii-source",
            "efivar",
            "--efivar-memory",
            "firmware-reserved",
        ];
        let mut given = HiiSourceOptions::default();
        given.source = HiiSource::Method(HiiMethod::Efivar);
        given.efivar_memory = EfivarMemory::FirmwareReserved;
        let check = |command: &[&str], want: Result<(), String>, calls: &[&str]| {
            let mut argvs = vec![
                ([command, &flags].concat(), given),
                ([&flags, command].concat(), given),
                (command.to_vec(), HiiSourceOptions::default()),
            ];
            if let Some((&"hii", rest)) = command.split_first() {
                argvs.push(([&["hii"][..], &flags, rest].concat(), given));
            }
            for (args, source) in argvs {
                let (result, recorded) = run_recorded(&args);

                assert_eq!(result, want, "{args:?}");
                let want_calls: Vec<_> = calls.iter().map(|call| (*call, source)).collect();
                assert_eq!(recorded, want_calls, "{args:?}: the calls");
            }
        };
        // each fails with RecordedHii's error, after its calls
        let failing: [(&[&str], &[&str]); 9] = [
            (&["hii", "get", "Q", "--no-efivars"], &["extract_db"]),
            (&["hii", "show-ifr", "--no-efivars"], &["extract_db"]),
            (&["hii", "list-questions", "--no-efivars"], &["extract_db"]),
            (&["hii", "list-strings"], &["extract_db"]),
            (&["hii", "set", "Q", "V"], &["set"]),
            (&["hii", "extract-db", db_arg], &["extract_db"]),
            (&["hii", "dump-efivars", dump_arg], &["extract_db"]),
            (&["get", "Q"], &["identify", "extract_db"]),
            (&["set", "Q", "V"], &["identify", "set"]),
        ];
        for (command, calls) in failing {
            check(command, Err("recorded".to_owned()), calls);
        }
        let mut efivar = HiiSourceOptions::default();
        efivar.source = HiiSource::Method(HiiMethod::Efivar);
        for (args, source) in [
            (&["identify", "--hii-source", "efivar"][..], efivar),
            (&["--hii-source", "efivar", "identify"], efivar),
            (&["identify"], HiiSourceOptions::default()),
        ] {
            assert_eq!(
                run_recorded(args),
                (Ok(()), vec![("identify", source)]),
                "{args:?}"
            );
        }
        assert!(
            !db.exists(),
            "extract-db wrote a HiiDB that it failed to read"
        );
        assert!(
            !dump.exists(),
            "dump-efivars wrote a dump of a HiiDB that it failed to read"
        );
    }

    /// The refusal of `flags` given where `why` names how no HiiDB of this machine is read.
    fn refused(flags: &[&str], why: &str) -> String {
        let named = match (
            flags.contains(&"--hii-source"),
            flags.contains(&"--efivar-memory"),
        ) {
            (true, true) => "--hii-source and --efivar-memory name",
            (true, false) => "--hii-source names",
            (false, true) => "--efivar-memory names",
            (false, false) => panic!("no flag in {flags:?}"),
        };
        format!("{named} where this machine's HiiDB is read, and {why}")
    }

    /// --hii-source and --efivar-memory are refused, not ignored, where no HiiDB of this machine
    /// is read: in show-translations, variable and capsule, and where -f or the efivars dump of
    /// --efivars gives the HiiDB, once that file or dump is read; before anything of this machine
    /// is read. Without them, those commands run, and read the HiiDB of the file or the dump,
    /// which differ in size and hold no package list.
    /// ilo, whose every command first reaches the BMC, is in the QEMU tests instead.
    #[test]
    fn machine_hiidb_flags_are_refused_where_no_machine_hiidb_is_read() {
        let dir = tempfile::tempdir().expect("create a directory");
        let db = dir.path().join("hiidb.bin");
        fs::write(&db, [0; 16]).expect("write the HiiDB");
        let db_arg = db.to_str().expect("UTF-8 temporary path");
        let dump = dir.path().join("dump");
        fs::create_dir(&dump).expect("create the dump");
        fs::write(dump.join("hiidb.bin"), [0; 32]).expect("write the dump's HiiDB");
        fs::write(
            dump.join("uefisettings-dump.json"),
            r#"{"format": 1, "uefisettings": "0.1.6", "redaction": "unredacted"}"#,
        )
        .expect("write the dump's manifest");
        let dump_arg = dump.to_str().expect("UTF-8 temporary path");
        let missing = dir.path().join("missing");
        let missing_arg = missing.to_str().expect("UTF-8 temporary path");
        let unread = Err(format!("read the payload {}", missing.display()));
        let file = "--filename gives the HiiDB";
        let dumped = "the efivars dump of --efivars gives the HiiDB";
        let file_read = Err("no package lists in 16-byte HiiDB".to_owned());
        let cases: [(&[&str], &str, Result<(), String>); 7] = [
            (
                &["show-translations"],
                "show-translations reads none",
                Ok(()),
            ),
            (
                &[
                    "variable",
                    "write-signed",
                    "V",
                    "8BE4DF61-93CA-11D2-AA0D-00E098032B8C",
                    "--attributes",
                    "non-volatile",
                    "--payload-file",
                    missing_arg,
                ],
                "variable reads none",
                unread.clone(),
            ),
            (
                &["capsule", "deliver", missing_arg, "--capsule-id", "1"],
                "capsule reads none",
                unread,
            ),
            (
                &["hii", "list-strings", "-f", db_arg],
                file,
                file_read.clone(),
            ),
            (
                &["hii", "list-questions", "--no-efivars", "-f", db_arg],
                file,
                file_read.clone(),
            ),
            (
                &["hii", "show-ifr", "--efivars", dump_arg, "-f", db_arg],
                file,
                file_read,
            ),
            (
                &["hii", "list-questions", "--efivars", dump_arg],
                dumped,
                Err("no package lists in 32-byte HiiDB".to_owned()),
            ),
        ];
        for (command, why, without) in cases {
            for flags in [
                &["--hii-source", "auto"][..],
                &["--efivar-memory", "runtime"],
                &[
                    "--hii-source",
                    "systab",
                    "--efivar-memory",
                    "firmware-reserved",
                ],
            ] {
                for args in [[command, flags].concat(), [flags, command].concat()] {
                    assert_eq!(
                        run_recorded(&args),
                        (Err(refused(flags, why)), Vec::new()),
                        "{args:?}"
                    );
                }
            }
            assert_eq!(
                run_recorded(command),
                (without, Vec::new()),
                "{command:?} without flags"
            );
        }
    }

    /// --efivar-memory with --hii-source acpi or systab fails each command that reads this
    /// machine's HiiDB or backends before it reads anything.
    #[test]
    fn efivar_memory_is_refused_with_a_method_that_never_reads_it() {
        let commands: [&[&str]; 6] = [
            &["hii", "get", "Q", "--no-efivars"],
            &["hii", "list-strings"],
            &["hii", "set", "Q", "V"],
            &["get", "Q"],
            &["set", "Q", "V"],
            &["identify"],
        ];
        for command in commands {
            for (method, memory) in [("acpi", "firmware-reserved"), ("systab", "runtime")] {
                let args = [
                    command,
                    &["--hii-source", method, "--efivar-memory", memory],
                ]
                .concat();
                assert_eq!(
                    run_recorded(&args),
                    (
                        Err(format!(
                            "--efivar-memory names the memory of the efivar method, which \
                             --hii-source {method} does not run"
                        )),
                        Vec::new()
                    ),
                    "{args:?}"
                );
            }
        }
    }

    /// This machine's HII backend in a test of a machine whose backends include Ilo: it records
    /// each call, finds the Ilo backend only, and fails each read and set.
    #[derive(Default)]
    struct IloMachine(std::cell::RefCell<Vec<&'static str>>);

    impl MachineHii for IloMachine {
        fn identify(&self, _: &HiiSourceOptions) -> MachineInfo {
            self.0.borrow_mut().push("identify");
            MachineInfo {
                backend: [Backend::Ilo].into(),
                ..Default::default()
            }
        }

        fn extract_db(
            &self,
            _: &HiiSourceOptions,
            _: UnsafeOperations,
        ) -> Result<(Vec<u8>, Vec<UnsafeOperation>)> {
            self.0.borrow_mut().push("extract_db");
            Err(anyhow!("recorded"))
        }

        fn set(
            &self,
            _: QuestionSelector,
            _: &SetValue,
            _: &SetOptions,
            _: &HiiSourceOptions,
        ) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
            self.0.borrow_mut().push("set");
            Err(anyhow!("recorded"))
        }
    }

    /// get and set refuse --hii-source and --efivar-memory where they take the Ilo backend, which
    /// reads no HiiDB, after identify only; without them, the Ilo branch runs (its refusal of
    /// --access-level shows it, before the BMC is reached). identify refuses --efivar-memory,
    /// whose memory its efivar method never reads, before it identifies.
    #[test]
    fn the_flags_are_refused_where_only_identify_would_see_them() {
        let run = |args: &[&str], hii: &IloMachine| {
            let argv = [&["uefisettings"][..], args].concat();
            let parsed = UefiSettingsToolArgs::try_parse_from(&argv)
                .unwrap_or_else(|error| panic!("parse {argv:?}: {error}"));
            crate::handle_cmds_with(parsed, hii).map_err(|error| error.to_string())
        };
        for (command, why) in [
            (
                &["get", "Q", "--access-level", "user"][..],
                "get takes the Ilo backend of this machine, which reads none",
            ),
            (
                &["set", "Q", "V", "--access-level", "user"],
                "set takes the Ilo backend of this machine, which reads none",
            ),
        ] {
            for flags in [
                &["--hii-source", "acpi"][..],
                &["--efivar-memory", "firmware-reserved"],
                &["--hii-source", "efivar", "--efivar-memory", "runtime"],
            ] {
                let args = [command, flags].concat();
                let hii = IloMachine::default();
                assert_eq!(run(&args, &hii), Err(refused(flags, why)), "{args:?}");
                assert_eq!(hii.0.into_inner(), vec!["identify"], "{args:?}: the calls");
            }
            let hii = IloMachine::default();
            assert_eq!(
                run(command, &hii),
                Err(
                    "--access-level applies to the HII backend, not to the Ilo backend of this \
                     machine"
                        .to_owned()
                ),
                "{command:?} without flags"
            );
        }
        for args in [
            &["identify", "--efivar-memory", "runtime"][..],
            &[
                "identify",
                "--hii-source",
                "efivar",
                "--efivar-memory",
                "firmware-reserved",
            ],
        ] {
            assert_eq!(
                run_recorded(args),
                (
                    Err(
                        "--efivar-memory names the memory of the efivar method, and identify \
                         reads none: its efivar method checks only that the HiiDB variable exists"
                            .to_owned()
                    ),
                    Vec::new()
                ),
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

    /// A log line shows its message as TerminalText, as a warning may name the HiiDB's strings.
    #[test]
    fn log_records_escape_control_characters() {
        let mut output = Vec::new();

        write_log_line(
            &mut output,
            ("[", "]"),
            "T",
            log::Level::Warn,
            &log::Record::builder()
                .args(format_args!("no value of {}", "A\u{1b}[2J\u{202e}\nB"))
                .level(log::Level::Warn)
                .target("uefisettings::hii")
                .build(),
        )
        .expect("write the record");

        assert_eq!(
            String::from_utf8(output).expect("UTF-8"),
            "[T WARN  uefisettings::hii] no value of A\\u{1b}[2J\\u{202e}\\nB\n"
        );
    }

    /// A log line keeps the header of env_logger's DefaultFormat: the level padded to 5 columns
    /// and the target, which an empty one leaves out.
    #[test]
    fn log_lines_pad_the_level_and_keep_the_target() {
        let cases = [
            (
                log::Level::Info,
                "uefisettings::hii::strings",
                "[T INFO  uefisettings::hii::strings] M\n",
            ),
            (
                log::Level::Error,
                "uefisettings",
                "[T ERROR uefisettings] M\n",
            ),
            (log::Level::Warn, "", "[T WARN ] M\n"),
        ];
        for (level, target, want) in cases {
            let mut output = Vec::new();

            write_log_line(
                &mut output,
                ("[", "]"),
                "T",
                level,
                &log::Record::builder()
                    .args(format_args!("M"))
                    .level(level)
                    .target(target)
                    .build(),
            )
            .expect("write the record");

            assert_eq!(
                String::from_utf8(output).expect("UTF-8"),
                want,
                "{level} {target:?}"
            );
        }
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

    /// StagingArgs::refuse_on_ilo refuses --image, which Ilo attributes take no use of, and
    /// passes its absence.
    #[test]
    fn staging_refuse_on_ilo_names_image() {
        let cases = [
            ("no --image", None, Ok(())),
            (
                "--image",
                Some(PathBuf::from("uefisettings.efi")),
                Err("--image applies to the HII backend, not to the Ilo backend of this machine"),
            ),
        ];
        for (case, image, want) in cases {
            assert_eq!(
                StagingArgs { image }
                    .refuse_on_ilo()
                    .map_err(|error| error.to_string()),
                want.map_err(str::to_string),
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
