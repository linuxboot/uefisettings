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
//! firmware it runs on, --bypass-setup-password, and the `-` of the secret flags.

use std::fmt::Debug;
use std::io;
use std::ptr::NonNull;

use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::boot::ScopedProtocol;
use uefi::proto::console::text::Input;
use uefi::proto::console::text::InputEx;
use uefi::proto::console::text::Key;
use uefi::proto::console::text::ScanCode;
use uefi::proto::unsafe_protocol;
use uefi::Handle;
use uefi::StatusExt;
use uefi_raw::protocol::shell::ShellProtocol;
use uefi_raw::protocol::shell_params::ShellFileHandle;
use uefi_raw::protocol::shell_params::ShellParametersProtocol;
use uefi_raw::table::system::SystemTable;
use uefisettings::exports::EfivarSource;
use uefisettings::exports::GetOptions;
use uefisettings::exports::HiiBackend;
use uefisettings::exports::SetupPasswordPolicy;
use uefisettings::exports::VariableInfo;
use uefisettings::secret_file::read_shell_secret;
use uefisettings::secret_file::Keystroke;
use uefisettings::secret_file::Secret;
use uefisettings::secret_file::ShellConsole;
use uefisettings::secret_file::ShellStdin;
use uefisettings::secret_file::StdinClaim;

use crate::hii_get;
use crate::hii_set;
use crate::print_line;
use crate::SelectionArgs;

/// The about of hii, whose commands read this firmware's HII database.
pub(super) const HII_ABOUT: &str = "Commands which work on machines exposing the UEFI HiiDB";
/// The about of top-level get, which reads this firmware's HII database, as hii get does.
pub(super) const GET_ABOUT: &str = "Get the current value of a question";
/// The about of top-level set, which writes this firmware's HII database, as hii set does.
pub(super) const SET_ABOUT: &str = "Set/change the value of a question";

/// Installs no logger, so that log's macros write nothing.
pub(super) fn init_logging() {}

/// None: ilo and identify need Linux.
#[derive(Debug, Subcommand)]
pub(super) enum PlatformCommands {}

impl PlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match *self {}
    }
}

/// variable-info; extract-db and dump-efivars write files, which this build does not.
#[derive(Debug, Subcommand)]
pub(super) enum HiiPlatformCommands {
    /// Show the attributes and the size of an EFI variable, never its data
    #[command(next_display_order = None)]
    VariableInfo {
        name: String,
        /// The vendor GUID of the variable, such as 8C78A505-BAA0-4C4A-869F-000000000101
        guid: String,
    },
}

impl HiiPlatformCommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::VariableInfo { name, guid } => {
                let info = HiiBackend::variable_info(name, guid)?;
                print_line(format_args!("{}", variable_info_report(&info)))?;
            }
        }
        Ok(())
    }
}

/// What variable-info prints on stdout about `info`: its own JSON object, outside the thrift
/// IDL that the other commands print, and JSON always, as variable-info takes no -j.
fn variable_info_report(info: &VariableInfo) -> serde_json::Value {
    serde_json::json!({
        "variable": info.variable,
        "attributes": info.attributes,
        "size": info.size,
    })
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
    /// The HiiDB of this firmware, whatever `_efivars` names.
    pub(super) fn read(&self, _efivars: &EfivarSource) -> Result<Vec<u8>> {
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

/// get, in this firmware's HII database.
pub(super) fn auto_get(question: &str, json: bool, selection: &SelectionArgs) -> Result<()> {
    hii_get(
        &HiiBackend::export_hiidb()?,
        question,
        &GetOptions::from(selection),
        json,
    )
}

/// set, in this firmware's HII database.
pub(super) fn auto_set(
    question: &str,
    value: &str,
    json: bool,
    selection: &SelectionArgs,
    setup_password: &SetupPasswordArgs,
) -> Result<()> {
    hii_set(question, value, selection, setup_password, json)
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
        let shell = boot::get_handle_for_protocol::<ShellFileIo>()
            .map_err(|error| firmware_error("EFI_SHELL_PROTOCOL", error))?;
        // SAFETY: the Shell uninstalls EFI_SHELL_PROTOCOL only as it exits (edk2-stable202608
        // Shell.c:693, CleanUpShellEnvironment), after this image returns
        let shell = unsafe {
            boot::open_protocol::<ShellFileIo>(
                OpenProtocolParams {
                    handle: shell,
                    agent: image,
                    controller: None,
                },
                OpenProtocolAttributes::GetProtocol,
            )
        }
        .map_err(|error| firmware_error("OpenProtocol() of EFI_SHELL_PROTOCOL", error))?;
        Ok(Self { parameters, shell })
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
