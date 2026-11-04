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

//! The `set-auth-variables=PATH[,PATH]...` task, for the Secure Boot scenarios: appends to db
//! each AUTH_2 payload that tests/qemu/auth-payload.sh built, at PATH on the driver's own file
//! system (UEFI 2.11 §8.2.6), and tries to set AuditMode and DeployedMode (§3.3), then puts what
//! it saw in the volatile variable `AuthProbeLog`, as `KEY=VALUE` tokens separated by spaces:
//! per payload, by its file name without `.auth`, the write's status, how much db grew and the
//! size of the payload's data, and the status of each mode write. The variable has the UEFI
//! Shell's vendor GUID, so the Shell imports it as the environment variable %AuthProbeLog% when
//! it starts (edk2 ShellPkg ShellEnvVar.c GetEnvironmentVariableList). The paths are one comma
//! list, as virt-fw-vars 25.12, Ubuntu 26.04's, puts only the first word after the image path
//! in a load option.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi::boot;
use uefi::cstr16;
use uefi::fs;
use uefi::fs::FileSystem;
use uefi::guid;
use uefi::runtime;
use uefi::runtime::VariableAttributes;
use uefi::runtime::VariableVendor;
use uefi::CStr16;
use uefi::CString16;
use uefi::Guid;
use uefi::Status;

use crate::Failure;

/// What a load option of this task starts with, before the payload paths.
const TASK_PREFIX: &str = "set-auth-variables=";
/// The file name extension of a payload, which its log tokens drop.
const PAYLOAD_EXTENSION: &str = ".auth";
/// The variable that the payloads append to.
const DB_NAME: &CStr16 = cstr16!("db");
/// The attributes of a db append: db's NV+BS+RT+AT, and EFI_VARIABLE_APPEND_WRITE.
const DB_APPEND_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS)
    .union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    .union(VariableAttributes::APPEND_WRITE);
/// The mode variables whose writes the scenarios record, which have these attributes in §3.3.
const MODE_VARIABLES: [&CStr16; 2] = [cstr16!("AuditMode"), cstr16!("DeployedMode")];
/// BS+RT: the attributes of the mode variables and of the log.
const VOLATILE_ATTRIBUTES: VariableAttributes =
    VariableAttributes::BOOTSERVICE_ACCESS.union(VariableAttributes::RUNTIME_ACCESS);
/// The log variable.
const AUTH_PROBE_LOG_NAME: &CStr16 = cstr16!("AuthProbeLog");
/// Its vendor GUID, gShellVariableGuid (edk2 ShellPkg.dec).
const SHELL_VARIABLE_GUID: Guid = guid!("158def5a-f656-419c-b027-7a3192c079d2");
/// The size of EFI_TIME, which starts an AUTH_2 descriptor, before WIN_CERTIFICATE.
const EFI_TIME_SIZE: usize = 16;

/// An AUTH_2 payload that a load option of this task names.
#[derive(Clone, Debug)]
pub(crate) struct Payload {
    /// Its path on the driver's file system.
    path: CString16,
    /// Its file name without the extension, which names its log tokens.
    token: String,
}

impl Payload {
    /// The payload at `path`, or `None` unless its file name is a name and `.auth`.
    fn from_path(path: &str) -> Option<Self> {
        // virt-fw-vars turns each '/' of --append-boot-filepath, the optional data's too, into
        // '\' (vars.py:237 in 25.12, :240 in 26.9).
        let file = path.rsplit('\\').next()?;
        let token = file
            .strip_suffix(PAYLOAD_EXTENSION)
            .filter(|token| !token.is_empty())?;
        Some(Self {
            path: CString16::try_from(path).ok()?,
            token: token.into(),
        })
    }
}

/// The payloads of the load option `set-auth-variables=PATH[,PATH]...`, or `None` for another
/// option or an empty or malformed path.
pub(crate) fn payloads(option: &CStr16) -> Option<Vec<Payload>> {
    let option = String::from(option);
    option
        .strip_prefix(TASK_PREFIX)?
        .split(',')
        .map(Payload::from_path)
        .collect()
}

/// Runs the writes and returns the log, which it also puts in `AuthProbeLog`.
pub(crate) fn set_auth_variables(payloads: &[Payload]) -> Result<String, Failure> {
    let mut file_system = boot::get_image_file_system(boot::image_handle())
        .map(FileSystem::new)
        .map_err(|error| ("opening the driver's file system", error.status()))?;
    let mut tokens = Vec::new();
    for Payload { path, token } in payloads {
        let payload = file_system
            .read(&**path)
            .map_err(|error| ("reading an AUTH_2 payload", file_system_status(&error)))?;
        let data = auth2_data_size(&payload)?;
        let before = db_size()?;
        let status = status_name(runtime::set_variable(
            DB_NAME,
            &VariableVendor::IMAGE_SECURITY_DATABASE,
            DB_APPEND_ATTRIBUTES,
            &payload,
        ));
        let growth = db_size()?
            .checked_sub(before)
            .ok_or(("db shrank on an append", Status::ABORTED))?;
        tokens.push(format!(
            "{token}={status} {token}-growth={growth} {token}-data={data}"
        ));
    }
    for name in MODE_VARIABLES {
        let status = status_name(runtime::set_variable(
            name,
            &VariableVendor::GLOBAL_VARIABLE,
            VOLATILE_ATTRIBUTES,
            &[1],
        ));
        tokens.push(format!("{name}={status}"));
    }
    let log = tokens.join(" ");
    let value = CString16::try_from(log.as_str())
        .map_err(|_| ("encoding the AuthProbeLog value", Status::INVALID_PARAMETER))?;
    runtime::set_variable(
        AUTH_PROBE_LOG_NAME,
        &VariableVendor(SHELL_VARIABLE_GUID),
        VOLATILE_ATTRIBUTES,
        value.as_bytes(),
    )
    .map_err(|error| ("setting the AuthProbeLog variable", error.status()))?;
    Ok(log)
}

/// The firmware status behind a file system error.
fn file_system_status(error: &fs::Error) -> Status {
    match error {
        fs::Error::Io(error) => error.uefi_error.status(),
        fs::Error::Path(_) | fs::Error::Utf8Encoding(_) => Status::INVALID_PARAMETER,
    }
}

/// The size of the variable data in an AUTH_2 payload: what follows EFI_TIME and
/// WIN_CERTIFICATE, whose first field, dwLength, is its size.
fn auth2_data_size(payload: &[u8]) -> Result<usize, Failure> {
    let malformed = ("parsing an AUTH_2 payload", Status::INVALID_PARAMETER);
    let length = payload
        .get(EFI_TIME_SIZE..EFI_TIME_SIZE + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(malformed)?;
    let start = usize::try_from(length)
        .ok()
        .and_then(|length| length.checked_add(EFI_TIME_SIZE))
        .ok_or(malformed)?;
    payload.len().checked_sub(start).ok_or(malformed)
}

/// The size of db's data.
fn db_size() -> Result<usize, Failure> {
    let step = "reading the size of db";
    match runtime::get_variable(DB_NAME, &VariableVendor::IMAGE_SECURITY_DATABASE, &mut []) {
        Err(error) if error.status() == Status::BUFFER_TOO_SMALL => {
            (*error.data()).ok_or((step, Status::BUFFER_TOO_SMALL))
        }
        Err(error) => Err((step, error.status())),
        Ok((data, _)) => Ok(data.len()),
    }
}

/// The status of a write, as the uefi crate names it: SUCCESS, SECURITY_VIOLATION and so on.
fn status_name(result: uefi::Result) -> String {
    match result {
        Ok(()) => format!("{:?}", Status::SUCCESS),
        Err(error) => format!("{:?}", error.status()),
    }
}
