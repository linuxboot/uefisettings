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

//! The part of the CLI that only the UEFI Shell build has: the HiiDB and the variables of the
//! firmware it runs on, --bypass-setup-password, --allow-volatile, whose written value lasts only
//! until the next reset or power cycle, and the `-` of the secret flags.

use std::fmt::Debug;
use std::io;
use std::path::Path;
use std::ptr;
use std::ptr::NonNull;
use std::time::SystemTime;

use anyhow::Context;
use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use log::warn;
use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::boot::ScopedProtocol;
use uefi::proto::console::text::Input;
use uefi::proto::console::text::InputEx;
use uefi::proto::console::text::Key;
use uefi::proto::console::text::ScanCode;
use uefi::proto::unsafe_protocol;
use uefi::CStr16;
use uefi::CString16;
use uefi::Handle;
use uefi::StatusExt;
use uefi_raw::protocol::file_system::FileMode;
use uefi_raw::protocol::shell::ShellProtocol;
use uefi_raw::protocol::shell_params::ShellFileHandle;
use uefi_raw::protocol::shell_params::ShellParametersProtocol;
use uefi_raw::table::system::SystemTable;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::KeywordInfoSource;
use uefisettings::exports::KeywordSetOptions;
use uefisettings::exports::KeywordValues;
use uefisettings::exports::QuestionSelector;
use uefisettings::exports::SetOptions;
use uefisettings::exports::SetupPasswordPolicy;
use uefisettings::exports::VolatileWrites;
use uefisettings::secret_file;
use uefisettings::secret_file::read_shell_secret;
use uefisettings::secret_file::Keystroke;
use uefisettings::secret_file::Secret;
use uefisettings::secret_file::ShellConsole;
use uefisettings::secret_file::ShellStdin;
use uefisettings::secret_file::StdinClaim;
use uefisettings::secret_file::MAX_SECRET_LEN;
use uefisettings_backend_thrift::SetResponseList;

use crate::hii_get;
use crate::hii_set;
use crate::print_line;
use crate::variable_command::print_info;
use crate::HiiSourceArgs;
use crate::IncludeArgs;
use crate::JsonArgs;
use crate::QuestionArgs;
use crate::SelectionArgs;
use crate::SetIncludeState;

/// The about of hii, whose commands read this firmware's HII database.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this firmware's HII database, as hii get does.
pub(super) const GET_ABOUT: &str = "Get the current value of a question";
/// The about of top-level set, which writes this firmware's HII database, as hii set does.
pub(super) const SET_ABOUT: &str = "Set/change the value of a question";
/// The long about of set and hii set, which write the wake-up time through this firmware's Time
/// Services, arming the alarm.
pub(super) const SET_LONG_ABOUT: &str = "Set/change the value of a question.\n\n\
     A date or time question whose UEFI Storage is the wake-up time (QF_DATE_STORAGE_WAKEUP or \
     QF_TIME_STORAGE_WAKEUP) is set through SetWakeupTime(TRUE, ...), arming the alarm, which \
     \"causes the system to wake up or power on at the set time\" (UEFI 2.11 §8.3.4), as \
     edk2-stable202608 SetupBrowserDxe/Setup.c:2051 does.";

/// The help of --hii-source, which this build ignores.
pub(super) const HII_SOURCE_HELP: &str =
    "Accepted as on Linux, and ignored: this build reads the HiiDB by the HII Database Protocol";
/// The help of --efivar-memory, which this build ignores.
pub(super) const EFIVAR_MEMORY_HELP: &str =
    "Accepted as on Linux, and ignored: this build reads the HiiDB by the HII Database Protocol";

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

/// variable-info, which variable info is too, and keyword; extract-db and dump-efivars write
/// files, which this build does not.
#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {
    /// Show the attributes and the size of an EFI variable, never its data
    #[command(next_display_order = None)]
    VariableInfo {
        name: String,
        /// The vendor GUID of the variable, such as 8C78A505-BAA0-4C4A-869F-000000000101
        guid: String,
    },
    /// Get and set the keywords of UEFI configuration languages, such as x-UEFI-ns, through EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL
    #[command(subcommand, next_display_order = None)]
    Keyword(KeywordCommands),
}

impl HiiPlatformCommands {
    pub(super) fn run(&self, _source: &HiiSourceArgs) -> Result<()> {
        match self {
            Self::VariableInfo { name, guid } => print_info(name, guid),
            Self::Keyword(command) => command.run(),
        }
    }
}

/// GetData() and SetData() of EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL (UEFI 2.11 §35.3.1), after the
/// checks of get and set.
#[derive(Debug, Subcommand)]
pub(super) enum KeywordCommands {
    /// Get the value of a keyword, as GetData() returns it, with the KeywordInfoResp of a KEYWORDINFO built from the HiiDB's IFR, which GetData() is not sent: a KeywordResp per package list
    ///
    /// Its defaults are those the IFR declares (EFI_IFR_DEFAULT, flagged options, CHECKBOX flags), which a driver's Callback() with EFI_BROWSER_ACTION_DEFAULT_x and its ALTCFG response outrank (UEFI 2.11 §33.2.5.8), so a platform's default may differ; those of a question of EFI_IFR_FLAG_CALLBACK are refused.
    #[command(next_display_order = None)]
    Get {
        // a doc comment would make rustdoc take the placeholders for HTML tags
        #[arg(
            help = "A KeywordRequest, [PATH=<hex digits>&]KEYWORD=<keyword>[&KEYWORDINFO=<filter>]: an optional PATH, the device path of the keyword's package list, the KEYWORD, and an optional KEYWORDINFO, All or DataType, ValueAttribute, Default and DisplayName in this order"
        )]
        request: String,
        /// The configuration language of the keyword, such as x-UEFI-ns; else one of the prefix x-UEFI
        #[arg(long)]
        namespace: Option<String>,
        /// Send GetData() the KEYWORDINFO unchanged and print its KeywordResps as returned, instead of building the KeywordInfoResp from the HiiDB's IFR
        #[arg(long)]
        keyword_info_from_get_data: bool,
        #[command(flatten)]
        output: JsonArgs,
    },
    /// Set keywords with one SetData(), unless set would refuse a keyword's question or value, and get them back; never a read-only question, which the Keyword Handler refuses
    #[command(next_display_order = None)]
    Set {
        #[arg(
            help = "A MultiKeywordResp, NAMESPACE=<language>&PATH=<hex digits>&KEYWORD=<keyword>&VALUE=<hex digits> per keyword, joined by &"
        )]
        keywords: String,
        #[command(flatten)]
        include: IncludeArgs,
        #[command(flatten)]
        setup_password: SetupPasswordArgs,
        #[command(flatten)]
        volatile: VolatileArgs,
        #[command(flatten)]
        output: JsonArgs,
    },
}

impl KeywordCommands {
    fn run(&self) -> Result<()> {
        let (values, output) = match self {
            Self::Get {
                request,
                namespace,
                keyword_info_from_get_data,
                output,
            } => {
                let info_source = match keyword_info_from_get_data {
                    false => KeywordInfoSource::Ifr,
                    true => KeywordInfoSource::GetData,
                };
                (
                    HiiBackend::keyword_get(request, namespace.as_deref(), info_source)?,
                    output,
                )
            }
            Self::Set {
                keywords,
                include,
                setup_password,
                volatile,
                output,
            } => {
                let mut options = KeywordSetOptions::default();
                options.include = include.states();
                options.setup_password = setup_password.policy();
                options.volatile = volatile.policy();
                (HiiBackend::keyword_set(keywords, &options)?, output)
            }
        };
        print_keyword_values(&values, output.json)
    }
}

/// Prints `values` as their `<MultiKeywordResp>`, or as JSON if `json`, an object per keyword,
/// outside the thrift IDL that the other hii commands print.
fn print_keyword_values(values: &KeywordValues, json: bool) -> Result<()> {
    match json {
        true => print_line(format_args!("{}", serde_json::to_string(values)?))?,
        false => print_line(format_args!("{values}"))?,
    }
    Ok(())
}

/// Where list-strings, which takes no --no-efivars, reads the HiiDB: as the other hii commands
/// do.
pub(super) type ListStringsHiiDbArgs = HiiDbArgs;

/// None: a hii command reads the HiiDB of the firmware that it runs on.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct HiiDbArgs {}

impl HiiDbArgs {
    /// The HiiDB of this firmware, whatever `_efivars` and `_source` name.
    pub(super) fn read(&self, _efivars: &EfivarSource, _source: &HiiSourceArgs) -> Result<Vec<u8>> {
        HiiBackend::export_hiidb()
    }
}

/// Where get, show-ifr and list-questions read question values.
#[derive(Debug, Args)]
pub(super) struct EfivarArgs {
    /// Read no question values from EFI variables: each shows as unavailable (get and list-questions add its IFR default) and conditions on values stay undetermined (the HiiDB still comes from this firmware)
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

/// What set does in a HiiDB that declares a setup password question.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct SetupPasswordArgs {
    /// Write even though the HiiDB declares a setup password question. The UEFI Shell runs no setup browser, so no password is asked or checked.
    #[arg(long)]
    bypass_setup_password: bool,
}

impl SetupPasswordArgs {
    pub(super) fn policy(&self) -> SetupPasswordPolicy {
        match self.bypass_setup_password {
            false => SetupPasswordPolicy::Refuse,
            true => SetupPasswordPolicy::Bypass,
        }
    }
}

/// Whether set writes a volatile variable.
#[derive(Debug, Args)]
// no ArgGroup, which usage would name instead of the flag
#[group(skip)]
pub(super) struct VolatileArgs {
    /// Write a variable without EFI_VARIABLE_NON_VOLATILE too. Its new value lasts only until the next reset or power cycle.
    #[arg(long)]
    allow_volatile: bool,
}

impl VolatileArgs {
    pub(super) fn policy(&self) -> VolatileWrites {
        match self.allow_volatile {
            false => VolatileWrites::Refuse,
            true => VolatileWrites::Allow,
        }
    }
}

/// get, in this firmware's HII database.
pub(super) fn auto_get(
    question: &QuestionArgs,
    json: bool,
    selection: &SelectionArgs,
    _source: &HiiSourceArgs,
) -> Result<()> {
    hii_get(
        &HiiBackend::export_hiidb()?,
        question.selector()?,
        &GetOptions::from(selection),
        json,
    )
}

/// set, in this firmware's HII database.
pub(super) fn auto_set(
    question: &QuestionArgs,
    value: &str,
    json: bool,
    _selection: &SelectionArgs<SetIncludeState>,
    options: &SetOptions,
    source: &HiiSourceArgs,
) -> Result<()> {
    hii_set(question.selector()?, value, options, json, source)
}

/// HiiBackend::set_using, whatever `_source` names.
pub(super) fn set_using(
    question: QuestionSelector,
    value: &str,
    options: &SetOptions,
    _source: &HiiSourceArgs,
) -> Result<SetResponseList> {
    HiiBackend::set_using(question, value, None, options)
}

/// The claim on standard input that every secret flag of the command shares.
static STDIN: StdinClaim = StdinClaim::new();

/// The secret that a flag naming `-` names, in line mode at most `max_len` bytes, as
/// read_shell_secret reads it.
#[expect(dead_code, reason = "no flag reads a secret from - yet")]
pub(super) fn read_stdin_secret_line(max_len: usize) -> Result<Secret> {
    STDIN.claim()?;
    let mut stdin = ShellStdinFile::open()?;
    Ok(read_shell_secret(
        &mut stdin,
        &mut FirmwareConsole,
        max_len,
    )?)
}

/// EFI_SHELL_PARAMETERS_PROTOCOL, whose StdIn uefi's ShellParameters keeps private.
#[repr(transparent)]
// SAFETY: uefi-raw's GUID of the struct this wraps with repr(transparent)
#[unsafe_protocol(ShellParametersProtocol::GUID)]
struct ShellParametersStdIn(ShellParametersProtocol);

/// EFI_SHELL_PROTOCOL, whose GetFileInfo() and ReadFile() uefi's Shell does not wrap.
#[repr(transparent)]
// SAFETY: uefi-raw's GUID of the struct this wraps with repr(transparent)
#[unsafe_protocol(ShellProtocol::GUID)]
struct ShellFileIo(ShellProtocol);

/// EFI_SHELL_PROTOCOL, for this image.
fn open_shell_protocol() -> io::Result<ScopedProtocol<ShellFileIo>> {
    let shell = boot::get_handle_for_protocol::<ShellFileIo>()
        .map_err(|error| firmware_error("EFI_SHELL_PROTOCOL", error))?;
    // SAFETY: the Shell uninstalls EFI_SHELL_PROTOCOL only as it exits (edk2-stable202608
    // Shell.c:693, CleanUpShellEnvironment), after this image returns
    unsafe {
        boot::open_protocol::<ShellFileIo>(
            OpenProtocolParams {
                handle: shell,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    }
    .map_err(|error| firmware_error("OpenProtocol() of EFI_SHELL_PROTOCOL", error))
}

/// The bytes of the file `path`, the payload of capsule deliver or variable write-signed, which
/// EFI_SHELL_PROTOCOL opens as the Shell's own commands do: on a mapping such as fs0:, or
/// relative to the current directory (edk2-stable202608 ShellProtocol.c:519-537,
/// EfiShellGetDevicePathFromFilePath()).
pub(super) fn read_payload(path: &Path) -> Result<Vec<u8>> {
    read_shell_file(path, "payload", |mut file| Ok(file.read_whole()?))
}

/// The secret in the file `path`, the key or the certificate bundle of variable write-signed, in
/// file mode: at most MAX_SECRET_LEN bytes, which ReadFile() reads into the secret's buffer.
/// Errors name it as `what`.
pub(super) fn read_secret_file(path: &Path, what: &str) -> Result<Secret> {
    read_shell_file(path, what, |file| {
        Ok(secret_file::read_secret_file(file, MAX_SECRET_LEN)?)
    })
}

/// What `read` reads of the file `path`, which EFI_SHELL_PROTOCOL opens as read_payload tells;
/// errors name it as `what`.
fn read_shell_file<T>(
    path: &Path,
    what: &str,
    read: impl FnOnce(ShellFile<'_>) -> Result<T>,
) -> Result<T> {
    let name = path
        .to_str()
        .and_then(|name| CString16::try_from(name).ok())
        .with_context(|| format!("the {what} path {} is not UCS-2", path.display()))?;
    let protocol = open_shell_protocol()?;
    let shell = protocol
        .get()
        .ok_or_else(|| io::Error::other("EFI_SHELL_PROTOCOL has no interface"))?;
    let file = ShellFile::open(&shell.0, &name)
        .with_context(|| format!("open the {what} {}", path.display()))?;
    read(file).with_context(|| format!("read the {what} {}", path.display()))
}

/// The clock of the TimeStamp that variable write-signed signs: none yet. GetTime() tells the
/// local time, which gives UTC only through a TimeZone other than EFI_UNSPECIFIED_TIMEZONE
/// ("Localtime = UTC - TimeZone", UEFI 2.11 §8.3.1), which uefisettings does not convert yet.
pub(super) fn signing_clock() -> Option<SystemTime> {
    None
}

/// A file that EFI_SHELL_PROTOCOL.OpenFileByName() opened for reading, which drop closes.
struct ShellFile<'shell> {
    shell: &'shell ShellProtocol,
    handle: ShellFileHandle,
}

impl<'shell> ShellFile<'shell> {
    fn open(shell: &'shell ShellProtocol, name: &CStr16) -> io::Result<Self> {
        let mut handle = ptr::null_mut();
        // SAFETY: OpenFileByName() of a NUL-terminated UCS-2 name, which stores a handle or NULL
        // in `handle`
        unsafe {
            (shell.open_file_by_name)(name.as_ptr().cast(), &mut handle, FileMode::READ.bits())
        }
        .to_result()
        .map_err(|error| firmware_error("OpenFileByName()", error))?;
        Ok(Self { shell, handle })
    }

    /// Every byte of the file: GetFileSize() of them, which ReadFile() reads in turn.
    fn read_whole(&mut self) -> io::Result<Vec<u8>> {
        let mut size = 0;
        // SAFETY: GetFileSize() of the open handle, which stores its size in `size`
        unsafe { (self.shell.get_file_size)(self.handle, &mut size) }
            .to_result()
            .map_err(|error| firmware_error("GetFileSize()", error))?;
        let size = usize::try_from(size).map_err(io::Error::other)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(size).map_err(io::Error::other)?;
        bytes.resize(size, 0);

        let mut filled = 0;
        while let Some(rest) = bytes.get_mut(filled..).filter(|rest| !rest.is_empty()) {
            match io::Read::read(self, rest)? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("ReadFile() ended after {filled} of its {size} bytes"),
                    ))
                }
                read => filled += read,
            }
        }
        Ok(bytes)
    }
}

impl io::Read for ShellFile<'_> {
    /// ReadFile() of at most as many bytes as `buffer` holds, none at the end of the file.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let asked = buffer.len();
        let mut read = asked;
        // SAFETY: ReadFile() of the open handle stores at most BufferSize bytes, as many as
        // buffer holds, and their number in `read`
        unsafe { (self.shell.read_file)(self.handle, &mut read, buffer.as_mut_ptr().cast()) }
            .to_result()
            .map_err(|error| firmware_error("ReadFile()", error))?;
        match read {
            read if read > asked => Err(io::Error::other(format!(
                "ReadFile() read {read} bytes into a buffer of {asked}"
            ))),
            read => Ok(read),
        }
    }
}

impl Drop for ShellFile<'_> {
    fn drop(&mut self) {
        // SAFETY: CloseFile() of the handle that OpenFileByName() opened, once
        if let Err(error) = unsafe { (self.shell.close_file)(self.handle) }.to_result() {
            warn!("CloseFile() of a file: {:?}", error.status());
        }
    }
}

/// The Shell's standard input: EFI_SHELL_PARAMETERS_PROTOCOL.StdIn of this image, through
/// EFI_SHELL_PROTOCOL.
struct ShellStdinFile {
    parameters: ScopedProtocol<ShellParametersStdIn>,
    shell: ScopedProtocol<ShellFileIo>,
}

impl ShellStdinFile {
    fn open() -> Result<Self> {
        let image = boot::image_handle();
        // SAFETY: the Shell installs EFI_SHELL_PARAMETERS_PROTOCOL on this image's handle before
        // StartImage() and uninstalls it after the image returns (edk2-stable202608
        // ShellProtocol.c:1621-1641), so it outlives the ScopedProtocol
        let parameters = unsafe {
            boot::open_protocol::<ShellParametersStdIn>(
                OpenProtocolParams {
                    handle: image,
                    agent: image,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map_err(|error| {
            firmware_error("OpenProtocol() of EFI_SHELL_PARAMETERS_PROTOCOL", error)
        })?;
        Ok(Self {
            parameters,
            shell: open_shell_protocol()?,
        })
    }

    /// StdIn and the Shell's functions.
    fn std_in_and_shell(&self) -> io::Result<(ShellFileHandle, &ShellProtocol)> {
        let parameters = self
            .parameters
            .get()
            .ok_or_else(|| io::Error::other("EFI_SHELL_PARAMETERS_PROTOCOL has no interface"))?;
        let shell = self
            .shell
            .get()
            .ok_or_else(|| io::Error::other("EFI_SHELL_PROTOCOL has no interface"))?;
        Ok((parameters.0.std_in, &shell.0))
    }
}

impl ShellStdin for ShellStdinFile {
    fn file_size(&self) -> io::Result<Option<u64>> {
        let (std_in, shell) = self.std_in_and_shell()?;
        // SAFETY: GetFileInfo() of StdIn, which the Shell keeps open while this image runs
        let info = unsafe { (shell.get_file_info)(std_in) };
        let Some(info) = NonNull::new(info) else {
            return Ok(None);
        };
        // SAFETY: GetFileInfo() returned an EFI_FILE_INFO in pool memory, 8-byte aligned
        let file_size = unsafe { info.as_ref() }.file_size;
        // SAFETY: that pool memory, which the caller frees (edk2-stable202608
        // MdePkg/Include/Protocol/Shell.h:573-574), freed once, after its last use
        unsafe { boot::free_pool(info.cast()) }.map_err(|error| {
            firmware_error("FreePool() of GetFileInfo()'s EFI_FILE_INFO", error)
        })?;
        Ok(Some(file_size))
    }

    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let (std_in, shell) = self.std_in_and_shell()?;
        let mut size = buffer.len();
        // SAFETY: ReadFile() of StdIn stores at most BufferSize bytes, as many as buffer holds
        unsafe { (shell.read_file)(std_in, &mut size, buffer.as_mut_ptr().cast()) }
            .to_result()
            .map_err(|error| firmware_error("ReadFile() of standard input", error))?;
        Ok(size)
    }
}

/// The console that a flag naming `-` reads a typed secret from: gST->ConsoleInHandle and
/// gST->ConIn, which the Shell swaps together for a redirect (edk2-stable202608
/// ShellParametersProtocol.c:1306, 1333).
struct FirmwareConsole;

impl ShellConsole for FirmwareConsole {
    type Keystrokes = ConsoleKeystrokes;

    fn has_text_input_ex(&self) -> io::Result<bool> {
        let console_in_handle = system_table()?.stdin_handle;
        // SAFETY: gST->ConsoleInHandle, a handle or NULL
        let Some(handle) = (unsafe { Handle::from_ptr(console_in_handle) }) else {
            return Ok(false);
        };
        boot::test_protocol::<InputEx>(OpenProtocolParams {
            handle,
            agent: boot::image_handle(),
            controller: None,
        })
        .map_err(|error| {
            firmware_error(
                "OpenProtocol() test of EFI_SIMPLE_TEXT_INPUT_EX_PROTOCOL",
                error,
            )
        })
    }

    // Not uefi::system::with_stdin, which panics on a NULL gST->ConIn and after
    // ExitBootServices().
    fn keystrokes(&mut self) -> io::Result<ConsoleKeystrokes> {
        let con_in =
            NonNull::new(system_table()?.stdin).ok_or_else(|| io::Error::other("no gST->ConIn"))?;
        // Input is an EFI_SIMPLE_TEXT_INPUT_PROTOCOL under repr(transparent).
        Ok(ConsoleKeystrokes(con_in.cast::<Input>()))
    }
}

/// The firmware's system table.
fn system_table() -> io::Result<&'static SystemTable> {
    let system_table =
        uefi::table::system_table_raw().ok_or_else(|| io::Error::other("no system table"))?;
    // SAFETY: the firmware's system table, which the entry point set and boot services keep
    Ok(unsafe { system_table.as_ref() })
}

/// The error of the firmware's `call`, which names the status it returned.
fn firmware_error<Data: Debug>(call: &str, error: uefi::Error<Data>) -> io::Error {
    io::Error::other(format!("{call}: {:?}", error.status()))
}

/// The keys of gST->ConIn as they arrive, unechoed.
struct ConsoleKeystrokes(NonNull<Input>);

impl Iterator for ConsoleKeystrokes {
    type Item = io::Result<Keystroke>;

    fn next(&mut self) -> Option<Self::Item> {
        // SAFETY: gST->ConIn, which boot services keep, and which nothing else uses while the
        // secret is typed
        let input = unsafe { self.0.as_mut() };
        Some(read_keystroke(input))
    }
}

/// The next key of `input`, once one arrives.
fn read_keystroke(input: &mut Input) -> io::Result<Keystroke> {
    loop {
        match input.read_key() {
            Ok(Some(key)) => return Ok(keystroke(key)),
            Ok(None) => {}
            Err(error) => return Err(firmware_error("ReadKeyStroke()", error)),
        }
        let key_event = input
            .wait_for_key_event()
            .map_err(|error| firmware_error("ConIn's WaitForKey", error))?;
        boot::wait_for_event(&[key_event])
            .map_err(|error| firmware_error("WaitForEvent() of WaitForKey", error))?;
    }
}

/// What `key` does to a typed secret: CHAR_BACKSPACE, CHAR_CARRIAGE_RETURN and SCAN_ESC
/// (edk2-stable202608 MdePkg/Include/Protocol/SimpleTextIn.h:42, 45, 71) edit it.
fn keystroke(key: Key) -> Keystroke {
    match key {
        Key::Printable(character) => match char::from(character) {
            '\r' => Keystroke::Enter,
            '\u{8}' => Keystroke::Backspace,
            character => Keystroke::Char(character),
        },
        Key::Special(ScanCode::ESCAPE) => Keystroke::Escape,
        Key::Special(_) => Keystroke::Other,
    }
}
