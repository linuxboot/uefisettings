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

//! The firmware variables of the Windows build: GetFirmwareEnvironmentVariableExW and
//! SetFirmwareEnvironmentVariableExW, which after ExitBootServices reach only variables
//! with EFI_VARIABLE_RUNTIME_ACCESS. Reading them needs the SeSystemEnvironmentPrivilege,
//! which FirmwareEnvironment enables once, when made, in this process's token.

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

#[cfg(variable_data)]
use crate::efi_variables::VariableContents;
#[cfg(variable_data)]
use crate::efi_variables::VariableData;
#[cfg(variable_info)]
use crate::efi_variables::VariableInfo;
#[cfg(variable_info)]
use crate::efi_variables::VariableInfoSource;
use crate::hii::variables::attributes_and_data;
use crate::hii::variables::modify_variable_bytes;
use crate::hii::variables::DataPatch;
use crate::hii::variables::FirmwareVariables;
#[cfg(variable_data)]
use crate::hii::variables::VariableAttributes;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VolatileWrites;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;
use crate::hii::win32::nul_terminated_utf16;
use crate::hii::win32::Win32Error;

// The Win32 calls, built for Windows alone; the rest builds for the tests of every host too.
#[cfg(target_os = "windows")]
mod win32_calls;

#[cfg(target_os = "windows")]
pub(crate) use win32_calls::RealFirmwareEnvironmentCalls;

/// The first buffer size that read_all reads a variable into, doubling from it.
const INITIAL_VARIABLE_CAPACITY: usize = 256;

/// The largest firmware variable that read_all reads, far above the largest EFI variables
/// that firmware exposes to Windows.
const MAX_VARIABLE_BYTES: usize = 16 * 1024 * 1024;

/// The attributes and the number of data bytes that a firmware-environment read wrote
/// into its buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GotVariable {
    attributes: u32,
    written: u32,
}

/// The Win32 calls that FirmwareEnvironment reads and writes through, behind which tests
/// fake them.
///
/// The methods take `&self` because the calls object is stateless: each call stands
/// alone, holding no open handle and no read order, unlike the stateful device
/// transport of `hiidb_driver.rs`, whose reads take `&mut self`. The name and GUID
/// slices of `get_variable` and `set_variable` must be NUL-terminated UTF-16, as the
/// Win32 calls take them, and the buffer-size contract binds every implementation:
/// `get_variable` may write no more than `buffer.len()` bytes and reports what it
/// wrote, while `set_variable` sets exactly the `data` bytes it is given, with the
/// `attributes` it is given.
pub(crate) trait FirmwareEnvironmentCalls {
    fn enable_system_environment_privilege(&self) -> std::result::Result<(), Win32Error>;
    fn get_variable(
        &self,
        name: &[u16],
        guid: &[u16],
        buffer: &mut [u8],
    ) -> std::result::Result<GotVariable, Win32Error>;
    fn set_variable(
        &self,
        name: &[u16],
        guid: &[u16],
        data: &[u8],
        attributes: u32,
    ) -> std::result::Result<(), Win32Error>;
}

/// The firmware environment variables of a Windows machine: GetFirmwareEnvironmentVariableExW
/// and SetFirmwareEnvironmentVariableExW, through `calls`.
#[derive(Debug)]
pub(crate) struct FirmwareEnvironment<C> {
    calls: C,
}

impl<C: FirmwareEnvironmentCalls> FirmwareEnvironment<C> {
    /// What GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW reach.
    pub(crate) const REACH: VariableReach = VariableReach::Runtime;
    /// GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW, which errors
    /// name.
    const INTERFACE: VariableInterface = VariableInterface::FirmwareEnvironment;

    /// Firmware variables through `calls`, which tests fake, after it enables the
    /// SeSystemEnvironmentPrivilege: this process's token keeps it for every read and write.
    fn with_calls(calls: C) -> Result<Self> {
        calls
            .enable_system_environment_privilege()
            .map_err(enable_privilege_error)?;
        Ok(Self { calls })
    }

    /// The attributes and all the data of `key`, growing its buffer from 256 bytes to the
    /// 16 MiB cap while the call reports it too small.
    fn read_all(&self, key: &VariableKey) -> Result<(u32, Vec<u8>)> {
        let name = variable_name(key)?;
        let guid = variable_guid(key)?;
        // Growing the buffer on ERROR_INSUFFICIENT_BUFFER assumes the call reports a
        // too-small buffer that way. The assumption fails safe: any other code aborts
        // the read in the match below, the loop is capped at MAX_VARIABLE_BYTES, and a
        // written count past the buffer is an error rather than a longer read.
        let mut capacity = INITIAL_VARIABLE_CAPACITY;
        loop {
            let mut buffer = vec![0u8; capacity];
            match self.calls.get_variable(&name, &guid, &mut buffer) {
                Ok(got) => {
                    let written = usize::try_from(got.written)
                        .context("firmware variable size fits in usize")?;
                    let Some(data) = buffer.get(..written) else {
                        return Err(anyhow!(
                            "GetFirmwareEnvironmentVariableExW of EFI variable {key} wrote \
                             {written} bytes into a buffer of {} bytes",
                            buffer.len()
                        ));
                    };
                    return Ok((got.attributes, data.to_vec()));
                }
                Err(code) => match code {
                    Win32Error::INSUFFICIENT_BUFFER => {
                        let Some(next) = capacity.checked_mul(2) else {
                            return Err(variable_too_large(key));
                        };
                        if next > MAX_VARIABLE_BYTES {
                            return Err(variable_too_large(key));
                        }
                        capacity = next;
                    }
                    // ERROR_ENVVAR_NOT_FOUND is "The system could not find the environment
                    // option that was entered" (Microsoft Learn, System Error Codes).
                    // ERROR_NOACCESS, "Invalid access to memory location", fails as any
                    // other code: the GetFirmwareEnvironmentVariableExW Remarks (Microsoft
                    // Learn, updated 2023-02-09) name it only for a probe of a GUID namespace
                    // that does not exist.
                    Win32Error::ENVVAR_NOT_FOUND => {
                        return Err(VariableNotFound(key.clone()).into());
                    }
                    Win32Error::INVALID_FUNCTION => {
                        return Err(FirmwareVariablesNotExposed { key: key.clone() }.into());
                    }
                    code => {
                        return Err(anyhow!(
                            "GetFirmwareEnvironmentVariableExW of EFI variable {key} failed \
                             with {code}"
                        ));
                    }
                },
            }
        }
    }
}

impl<C: FirmwareEnvironmentCalls> FirmwareVariables for FirmwareEnvironment<C> {
    fn reach(&self) -> VariableReach {
        Self::REACH
    }

    fn interface(&self) -> VariableInterface {
        Self::INTERFACE
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        let (attributes, data) = self.read_all(key)?;
        attributes_and_data(key, attributes, &data, size)
    }

    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
        let (attributes, data) = self.read_all(key)?;
        Ok([&attributes.to_ne_bytes()[..], &data].concat())
    }

    fn write_patches(
        &self,
        key: &VariableKey,
        size: u16,
        patches: &[DataPatch<'_>],
        volatile: VolatileWrites,
    ) -> Result<()> {
        // As VariableServices::write_patches (variable_services.rs): read the whole variable,
        // modify its bytes, and write the whole data back with the same attributes.
        let name = variable_name(key)?;
        let guid = variable_guid(key)?;
        let (attributes, data) = self.read_all(key)?;
        let mut bytes = [&attributes.to_ne_bytes()[..], &data].concat();
        modify_variable_bytes(self, key, volatile, &mut bytes, size, patches)?;
        let data = bytes
            .get(EFIVARFS_HEADER_SIZE..)
            .context("data after the attributes word")?;
        if data.is_empty() {
            return Err(anyhow!(
                "refusing to write an empty EFI variable {key}: a zero-size \
                 SetFirmwareEnvironmentVariableExW deletes the variable"
            ));
        }
        self.calls
            .set_variable(&name, &guid, data, attributes)
            .map_err(|code| {
                anyhow!(
                    "SetFirmwareEnvironmentVariableExW of EFI variable {key} failed with {code}"
                )
            })?;
        Ok(())
    }
}

#[cfg(variable_info)]
impl<C: FirmwareEnvironmentCalls> VariableInfoSource for FirmwareEnvironment<C> {
    /// The VariableInfo of `key`, from all of its data, which is dropped:
    /// GetFirmwareEnvironmentVariableExW tells the size only as "the number of bytes stored in
    /// the pValue buffer" (Microsoft Learn, updated 2024-11-20).
    fn variable_info(&self, key: &VariableKey) -> Result<VariableInfo> {
        let (attributes, data) = self.read_all(key)?;
        Ok(VariableInfo {
            variable: key.to_string(),
            attributes,
            size: data.len(),
        })
    }
}

#[cfg(variable_data)]
impl<C: FirmwareEnvironmentCalls> VariableData for FirmwareEnvironment<C> {
    fn interface(&self) -> VariableInterface {
        Self::INTERFACE
    }

    fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
        let (attributes, data) = match self.read_all(key) {
            Err(error) if error.is::<VariableNotFound>() => return Ok(None),
            result => result?,
        };
        VariableContents::new(VariableAttributes::from_bits_retain(attributes), data)
            .map(Some)
            .with_context(|| format!("GetFirmwareEnvironmentVariableExW of EFI variable {key}"))
    }

    fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
        let name = variable_name(key)?;
        let guid = variable_guid(key)?;
        self.calls
            .set_variable(&name, &guid, contents.data(), contents.attributes().bits())
            .map_err(|code| {
                anyhow!(
                    "SetFirmwareEnvironmentVariableExW of EFI variable {key} failed with {code}"
                )
            })
    }
}

/// The UTF-16 NUL-terminated name of `key`, for the Win32 calls: an interior NUL is an
/// error before any call.
fn variable_name(key: &VariableKey) -> Result<Vec<u16>> {
    nul_terminated_utf16(&key.name).ok_or_else(|| {
        anyhow!(
            "EFI variable {key} has a name with an interior NUL, which the Win32 firmware \
             calls cannot hold"
        )
    })
}

/// The UTF-16 NUL-terminated "{UPPERCASE-GUID}" of `key`, for the Win32 calls: Guid
/// displays uppercase.
fn variable_guid(key: &VariableKey) -> Result<Vec<u16>> {
    nul_terminated_utf16(&format!("{{{}}}", key.guid))
        .with_context(|| format!("the GUID of EFI variable {key} holds a NUL"))
}

/// read_all's error for a variable larger than MAX_VARIABLE_BYTES.
fn variable_too_large(key: &VariableKey) -> anyhow::Error {
    anyhow!(
        "EFI variable {key} is larger than the {MAX_VARIABLE_BYTES}-byte maximum for a \
         firmware variable"
    )
}

/// The error of an enable-system-environment-privilege outcome with Win32 code `code`:
/// ERROR_NOT_ALL_ASSIGNED names elevation and the commands that take --no-efivars, other codes
/// name the call.
fn enable_privilege_error(code: Win32Error) -> anyhow::Error {
    match code {
        Win32Error::NOT_ALL_ASSIGNED => SystemEnvironmentPrivilegeNotAssigned.into(),
        code => anyhow!("failed to enable the SeSystemEnvironmentPrivilege: {code}"),
    }
}

/// GetFirmwareEnvironmentVariableExW's ERROR_INVALID_FUNCTION for `key`: the machine runs
/// a legacy BIOS, or its firmware does not expose firmware variables to Windows, so the
/// variable is not a missing one.
#[derive(Debug, Error)]
#[error(
    "GetFirmwareEnvironmentVariableExW of EFI variable {key} failed with {} \
     (ERROR_INVALID_FUNCTION): this machine runs a legacy BIOS, or its firmware does not \
     expose firmware variables to Windows",
    Win32Error::INVALID_FUNCTION
)]
struct FirmwareVariablesNotExposed {
    key: VariableKey,
}

/// AdjustTokenPrivileges' ERROR_NOT_ALL_ASSIGNED: the privilege is not assigned to this
/// process's token, so only an elevated process can read firmware variables.
#[derive(Debug, Error)]
#[error(
    "cannot enable the SeSystemEnvironmentPrivilege ({}, ERROR_NOT_ALL_ASSIGNED): run \
     elevated; hii get, hii list-questions and hii show-ifr also run with --no-efivars, \
     reading no EFI variables",
    Win32Error::NOT_ALL_ASSIGNED
)]
struct SystemEnvironmentPrivilegeNotAssigned;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows_sys::Win32::Foundation::ERROR_NOACCESS;

    use super::*;
    use crate::hii::variables::tests::variable_key;
    use crate::hii::variables::tests::WriteAt;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
    use crate::hii::variables::tests::NV_BS;
    use crate::hii::variables::tests::NV_BS_RT;
    use crate::hii::variables::VolatileVariable;

    /// A scripted outcome of a fake firmware-environment read.
    #[derive(Debug, Clone)]
    enum FakeGet {
        Got {
            attributes: u32,
            data: Vec<u8>,
            written: u32,
        },
        Failed(Win32Error),
    }

    /// A recorded Set call: the name, GUID, data and attributes it set.
    type SetCall = (Vec<u16>, Vec<u16>, Vec<u8>, u32);

    /// The scripted outcomes and the calls recorded by FakeFirmwareEnvironmentCalls.
    #[derive(Debug, Default)]
    struct FakeState {
        privilege: VecDeque<std::result::Result<(), Win32Error>>,
        privilege_calls: usize,
        gets: VecDeque<FakeGet>,
        get_calls: Vec<(usize, Vec<u16>, Vec<u16>)>,
        sets: Vec<SetCall>,
        set_results: VecDeque<std::result::Result<(), Win32Error>>,
    }

    /// FirmwareEnvironmentCalls scripted with FakeGets, which records every enable, get
    /// and set. Clones share the script and the record.
    #[derive(Debug, Clone)]
    struct FakeFirmwareEnvironmentCalls {
        state: Rc<RefCell<FakeState>>,
    }

    impl FakeFirmwareEnvironmentCalls {
        fn new() -> Self {
            Self {
                state: Rc::new(RefCell::new(FakeState::default())),
            }
        }

        fn fail_privilege(&self, code: Win32Error) {
            self.state.borrow_mut().privilege.push_back(Err(code));
        }

        fn queue_get(&self, get: FakeGet) {
            self.state.borrow_mut().gets.push_back(get);
        }

        fn fail_set(&self, code: Win32Error) {
            self.state.borrow_mut().set_results.push_back(Err(code));
        }

        fn privilege_calls(&self) -> usize {
            self.state.borrow().privilege_calls
        }

        fn get_calls(&self) -> Vec<(usize, Vec<u16>, Vec<u16>)> {
            self.state.borrow().get_calls.clone()
        }

        fn sets(&self) -> Vec<SetCall> {
            self.state.borrow().sets.clone()
        }
    }

    impl FirmwareEnvironmentCalls for FakeFirmwareEnvironmentCalls {
        fn enable_system_environment_privilege(&self) -> std::result::Result<(), Win32Error> {
            let mut state = self.state.borrow_mut();
            state.privilege_calls += 1;
            state.privilege.pop_front().unwrap_or(Ok(()))
        }

        fn get_variable(
            &self,
            name: &[u16],
            guid: &[u16],
            buffer: &mut [u8],
        ) -> std::result::Result<GotVariable, Win32Error> {
            let mut state = self.state.borrow_mut();
            state
                .get_calls
                .push((buffer.len(), name.to_vec(), guid.to_vec()));
            match state.gets.pop_front().expect("script a get for every read") {
                FakeGet::Got {
                    attributes,
                    data,
                    written,
                } => {
                    let copied = data.len().min(buffer.len());
                    buffer[..copied].copy_from_slice(&data[..copied]);
                    Ok(GotVariable {
                        attributes,
                        written,
                    })
                }
                FakeGet::Failed(code) => Err(code),
            }
        }

        fn set_variable(
            &self,
            name: &[u16],
            guid: &[u16],
            data: &[u8],
            attributes: u32,
        ) -> std::result::Result<(), Win32Error> {
            let mut state = self.state.borrow_mut();
            state
                .sets
                .push((name.to_vec(), guid.to_vec(), data.to_vec(), attributes));
            state.set_results.pop_front().unwrap_or(Ok(()))
        }
    }

    /// FirmwareEnvironment through `calls`, which enable the privilege.
    fn fake_environment(
        calls: &FakeFirmwareEnvironmentCalls,
    ) -> FirmwareEnvironment<FakeFirmwareEnvironmentCalls> {
        FirmwareEnvironment::with_calls(calls.clone()).expect("enable the privilege")
    }

    /// The attributes word and the first `size` data bytes of a variable read as `got`.
    fn got(attributes: u32, data: &[u8]) -> FakeGet {
        FakeGet::Got {
            attributes,
            data: data.to_vec(),
            written: u32::try_from(data.len()).expect("test data fits in u32"),
        }
    }

    /// ERROR_ENVVAR_NOT_FOUND is VariableNotFound, after enabling the privilege once; a
    /// variable that reads returns its attributes and the bytes asked for.
    #[test]
    fn missing_variable_code_is_not_found() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        let error = environment
            .read(&key, 1)
            .expect_err("read a missing variable");

        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(key)),
            "ERROR_ENVVAR_NOT_FOUND"
        );
        assert_eq!(
            calls.privilege_calls(),
            1,
            "ERROR_ENVVAR_NOT_FOUND: privilege"
        );
        assert_eq!(calls.get_calls().len(), 1, "ERROR_ENVVAR_NOT_FOUND: gets");

        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS_RT, &[1, 2, 3]));
        let environment = fake_environment(&calls);

        assert_eq!(
            environment.read(&variable_key("Setup"), 2).ok(),
            Some([&NV_BS_RT.to_ne_bytes()[..], &[1, 2]].concat()),
            "a variable that reads"
        );
    }

    /// ERROR_INVALID_FUNCTION is the legacy-BIOS error, not VariableNotFound.
    #[test]
    fn invalid_function_is_a_legacy_bios_error() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Failed(Win32Error::INVALID_FUNCTION));
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        let error = environment
            .read(&key, 1)
            .expect_err("read on a legacy BIOS");

        assert_eq!(
            error.to_string(),
            "GetFirmwareEnvironmentVariableExW of EFI variable \
             Setup-00000000-0000-0000-0000-000000000000 failed with Win32 error 1 \
             (ERROR_INVALID_FUNCTION): this machine runs a legacy BIOS, or its firmware \
             does not expose firmware variables to Windows",
            "legacy BIOS"
        );
        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            None,
            "legacy BIOS: not NotFound"
        );
    }

    /// Other Win32 codes, ERROR_NOACCESS among them, are reported with the variable and the
    /// code, not as VariableNotFound.
    #[test]
    fn other_win32_codes_are_reported_with_the_key_and_code() {
        for code in [ERROR_ACCESS_DENIED, ERROR_NOACCESS] {
            let calls = FakeFirmwareEnvironmentCalls::new();
            calls.queue_get(FakeGet::Failed(Win32Error(code)));
            let environment = fake_environment(&calls);

            let error = environment
                .read(&variable_key("Setup"), 1)
                .expect_err("read with a Win32 error");

            assert_eq!(
                error.to_string(),
                format!(
                    "GetFirmwareEnvironmentVariableExW of EFI variable \
                     Setup-00000000-0000-0000-0000-000000000000 failed with Win32 error {code}"
                ),
                "code {code}"
            );
            assert_eq!(
                error.downcast_ref::<VariableNotFound>(),
                None,
                "code {code}: not NotFound"
            );
        }
    }

    /// The name and the GUID that a read passes are UTF-16 NUL-terminated, the GUID in
    /// "{UPPERCASE-GUID}" form.
    #[test]
    fn name_and_guid_are_utf16_nul_terminated() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS_RT, &[1]));
        let environment = fake_environment(&calls);
        let key = VariableKey {
            name: "Setup".to_string(),
            guid: EFI_GLOBAL_VARIABLE,
        };

        environment.read(&key, 1).expect("read Setup");

        let utf16 = |text: &str| text.encode_utf16().chain([0]).collect::<Vec<u16>>();
        assert_eq!(
            calls.get_calls(),
            [(
                INITIAL_VARIABLE_CAPACITY,
                utf16("Setup"),
                utf16("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}")
            )],
            "name and GUID"
        );
    }

    /// A read grows its buffer, doubling from 256 bytes, while the call reports it too
    /// small, enabling the privilege once; a variable that fits the first buffer needs
    /// one read.
    #[test]
    fn read_grows_its_buffer_to_the_variable() {
        let data = vec![0xAA; 600];
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Failed(Win32Error::INSUFFICIENT_BUFFER));
        calls.queue_get(FakeGet::Failed(Win32Error::INSUFFICIENT_BUFFER));
        calls.queue_get(got(NV_BS_RT, &data));
        let environment = fake_environment(&calls);

        let read = environment
            .read(&variable_key("Setup"), 600)
            .expect("read a 600-byte variable");

        assert_eq!(
            read,
            [&NV_BS_RT.to_ne_bytes()[..], &data].concat(),
            "600-byte variable"
        );
        assert_eq!(calls.privilege_calls(), 1, "privilege");
        assert_eq!(
            calls
                .get_calls()
                .iter()
                .map(|(capacity, _, _)| *capacity)
                .collect::<Vec<_>>(),
            [256, 512, 1024],
            "buffer sizes"
        );

        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS_RT, &[1]));
        let environment = fake_environment(&calls);

        environment
            .read(&variable_key("Setup"), 1)
            .expect("read a small variable");

        assert_eq!(
            calls
                .get_calls()
                .iter()
                .map(|(capacity, _, _)| *capacity)
                .collect::<Vec<_>>(),
            [256],
            "a small variable: one read"
        );
    }

    /// A variable that stays too small through the 16 MiB buffer is refused, after one
    /// read per doubled size and no larger read.
    #[test]
    fn read_refuses_a_variable_over_the_cap() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        for _ in 0..20 {
            calls.queue_get(FakeGet::Failed(Win32Error::INSUFFICIENT_BUFFER));
        }
        let environment = fake_environment(&calls);

        let error = environment
            .read(&variable_key("Setup"), 1)
            .expect_err("read a variable over the cap");

        assert_eq!(
            error.to_string(),
            format!(
                "EFI variable Setup-00000000-0000-0000-0000-000000000000 is larger than the \
                 {MAX_VARIABLE_BYTES}-byte maximum for a firmware variable"
            ),
            "over the cap"
        );
        assert_eq!(calls.privilege_calls(), 1, "privilege");
        assert_eq!(
            calls
                .get_calls()
                .iter()
                .map(|(capacity, _, _)| *capacity)
                .collect::<Vec<_>>(),
            [
                256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288,
                1048576, 2097152, 4194304, 8388608, 16777216
            ],
            "buffer sizes"
        );
    }

    /// A read that reports more bytes written than its buffer holds is an error.
    #[test]
    fn written_past_the_buffer_is_an_error() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Got {
            attributes: NV_BS_RT,
            data: vec![1],
            written: 999,
        });
        let environment = fake_environment(&calls);

        let error = environment
            .read(&variable_key("Setup"), 1)
            .expect_err("read past the buffer");

        assert_eq!(
            error.to_string(),
            "GetFirmwareEnvironmentVariableExW of EFI variable \
             Setup-00000000-0000-0000-0000-000000000000 wrote 999 bytes into a buffer of \
             256 bytes",
            "overflow write"
        );
    }

    /// A FirmwareEnvironment enables the privilege once, for all the reads and writes it makes.
    #[test]
    fn privilege_is_enabled_once_per_environment() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        for _ in 0..4 {
            calls.queue_get(got(NV_BS_RT, &[1]));
        }
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        for read in 0..3 {
            environment
                .read(&key, 1)
                .unwrap_or_else(|error| panic!("read {read}: {error:#}"));
        }
        environment.write_at(&key, 1, 0, &[2]).expect("write Setup");

        assert_eq!(calls.privilege_calls(), 1, "3 reads and 1 write: privilege");
        assert_eq!(calls.get_calls().len(), 4, "3 reads and 1 write: gets");
        assert_eq!(calls.sets().len(), 1, "3 reads and 1 write: sets");
    }

    /// ERROR_NOT_ALL_ASSIGNED fails the FirmwareEnvironment with an error naming elevation
    /// and the commands that take --no-efivars; other privilege codes name the call; neither
    /// reads.
    #[test]
    fn privilege_error_names_elevation() {
        let cases = [
            (
                "not all assigned",
                Win32Error::NOT_ALL_ASSIGNED,
                "cannot enable the SeSystemEnvironmentPrivilege (Win32 error 1300, \
                 ERROR_NOT_ALL_ASSIGNED): run elevated; hii get, hii list-questions and hii \
                 show-ifr also run with --no-efivars, reading no EFI variables",
            ),
            (
                "code 5",
                Win32Error(ERROR_ACCESS_DENIED),
                "failed to enable the SeSystemEnvironmentPrivilege: Win32 error 5",
            ),
        ];
        for (case, code, want) in cases {
            let calls = FakeFirmwareEnvironmentCalls::new();
            calls.fail_privilege(code);

            let error = FirmwareEnvironment::with_calls(calls.clone())
                .expect_err("make a FirmwareEnvironment without the privilege");

            assert_eq!(error.to_string(), want, "{case}");
            assert_eq!(calls.privilege_calls(), 1, "{case}: privilege");
            assert_eq!(calls.get_calls(), [], "{case}: no read");
        }
    }

    /// A name with an interior NUL is an error before any get or set call, on read and on
    /// write.
    #[test]
    fn interior_nul_is_an_error_before_any_call() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        let environment = fake_environment(&calls);
        let key = variable_key("A\0B");

        let read = environment.read(&key, 1).expect_err("read a NUL name");
        let written = environment
            .write_at(&key, 1, 0, &[1])
            .expect_err("write a NUL name");

        for (case, error) in [("read", read), ("write", written)] {
            assert!(
                error.to_string().contains("interior NUL"),
                "{case}: {error}"
            );
        }
        assert_eq!(calls.privilege_calls(), 1, "privilege, when made");
        assert_eq!(calls.get_calls(), [], "gets");
        assert_eq!(calls.sets(), [], "sets");
    }

    /// write_at reads the whole variable, modifies it, and writes the whole bytes back
    /// with the same attributes and name; a volatile variable, a missing variable, and a
    /// failing set write nothing.
    #[test]
    fn write_at_writes_the_whole_variable_back() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS_RT, &[1, 2, 3, 4]));
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        environment
            .write_at(&key, 4, 1, &[9, 9])
            .expect("write two bytes");

        assert_eq!(
            calls.sets(),
            [(
                "Setup".encode_utf16().chain([0]).collect(),
                "{00000000-0000-0000-0000-000000000000}"
                    .encode_utf16()
                    .chain([0])
                    .collect(),
                vec![1, 9, 9, 4],
                NV_BS_RT
            )],
            "write"
        );

        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(0x06, &[0]));
        let environment = fake_environment(&calls);

        let error = environment
            .write_at(&key, 1, 0, &[1])
            .expect_err("write a volatile variable");

        assert!(
            error.downcast_ref::<VolatileVariable>().is_some(),
            "volatile: {error:#}"
        );
        assert_eq!(calls.sets(), [], "volatile: no set");

        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
        let environment = fake_environment(&calls);

        let error = environment
            .write_at(&key, 1, 0, &[1])
            .expect_err("write a missing variable");

        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(key.clone())),
            "missing"
        );
        assert_eq!(calls.sets(), [], "missing: no set");

        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS_RT, &[1]));
        calls.fail_set(Win32Error(ERROR_ACCESS_DENIED));
        let environment = fake_environment(&calls);

        let error = environment
            .write_at(&key, 1, 0, &[2])
            .expect_err("write with a failing set");

        assert_eq!(
            error.to_string(),
            "SetFirmwareEnvironmentVariableExW of EFI variable \
             Setup-00000000-0000-0000-0000-000000000000 failed with Win32 error 5",
            "failing set"
        );
        assert_eq!(
            calls.sets(),
            [(
                "Setup".encode_utf16().chain([0]).collect(),
                "{00000000-0000-0000-0000-000000000000}"
                    .encode_utf16()
                    .chain([0])
                    .collect(),
                vec![2],
                NV_BS_RT
            )],
            "failing set: the write attempted"
        );
    }

    /// Two patches of one variable take one SetFirmwareEnvironmentVariableExW, with the
    /// variable's own attributes, here not NV_BS_RT.
    #[test]
    fn write_patches_writes_two_patches_in_one_call_with_the_variables_attributes() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS, &[1, 2, 3, 4]));
        // what a read-modify-write of each patch in turn would read second, so that it fails at
        // the count of calls
        calls.queue_get(got(NV_BS, &[9, 2, 3, 4]));
        let environment = fake_environment(&calls);

        environment
            .write_patches(
                &variable_key("Setup"),
                4,
                &[
                    DataPatch {
                        offset: 0,
                        bytes: &[9],
                    },
                    DataPatch {
                        offset: 3,
                        bytes: &[8],
                    },
                ],
                VolatileWrites::Refuse,
            )
            .expect("write two patches");

        let sets = calls.sets();
        assert_eq!(sets.len(), 1, "one call for two patches");
        assert_eq!(
            sets.first().map(|set| (set.2.clone(), set.3)),
            Some((vec![9, 2, 3, 8], NV_BS)),
            "data and attributes of the call"
        );
    }

    /// write_at refuses a variable whose data to write is empty: a zero-size Set
    /// would delete the variable, so no Set call is made.
    #[test]
    fn write_at_refuses_an_empty_variable() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(got(NV_BS_RT, &[]));
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        let error = environment
            .write_at(&key, 0, 0, &[])
            .expect_err("write an empty variable");

        assert_eq!(
            error.to_string(),
            "refusing to write an empty EFI variable \
             Setup-00000000-0000-0000-0000-000000000000: a zero-size \
             SetFirmwareEnvironmentVariableExW deletes the variable",
            "empty variable"
        );
        assert_eq!(calls.sets(), [], "empty variable: no set");
        assert_eq!(calls.privilege_calls(), 1, "empty variable: privilege");
    }

    /// variable_info tells the attributes and the data size of a variable larger than the first
    /// buffer, writing nothing, and VariableNotFound for ERROR_ENVVAR_NOT_FOUND.
    #[cfg(variable_info)]
    #[test]
    fn variable_info_tells_a_variable_or_that_it_is_missing() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Failed(Win32Error::INSUFFICIENT_BUFFER));
        calls.queue_get(got(NV_BS_RT, &[0xAA; 300]));
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        assert_eq!(
            environment
                .variable_info(&key)
                .map_err(|error| error.to_string()),
            Ok(VariableInfo {
                variable: "Setup-00000000-0000-0000-0000-000000000000".to_string(),
                attributes: NV_BS_RT,
                size: 300,
            }),
            "a variable of 300 bytes"
        );
        assert_eq!(calls.get_calls().len(), 2, "a variable of 300 bytes: gets");
        assert_eq!(calls.sets(), [], "a variable of 300 bytes: sets");

        calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
        let error = environment
            .variable_info(&key)
            .expect_err("info of a missing variable");

        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(key)),
            "ERROR_ENVVAR_NOT_FOUND"
        );
    }

    /// variable_data reads the attributes and all the data of a variable larger than the first
    /// buffer, writing nothing, None for ERROR_ENVVAR_NOT_FOUND, and an error for other codes.
    #[cfg(variable_data)]
    #[test]
    fn variable_data_reads_a_variable_or_tells_it_absent() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.queue_get(FakeGet::Failed(Win32Error::INSUFFICIENT_BUFFER));
        calls.queue_get(got(NV_BS_RT, &[0xAA; 300]));
        calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
        calls.queue_get(FakeGet::Failed(Win32Error(ERROR_ACCESS_DENIED)));
        let environment = fake_environment(&calls);
        let key = variable_key("Setup");

        let contents = environment
            .variable_data(&key)
            .expect("read a variable of 300 bytes")
            .expect("a variable of 300 bytes is present");
        let missing = environment
            .variable_data(&key)
            .expect("read a missing variable");
        let denied = environment
            .variable_data(&key)
            .expect_err("read a denied variable");

        assert_eq!(
            (contents.attributes().bits(), contents.data()),
            (NV_BS_RT, &[0xAA; 300][..]),
            "a variable of 300 bytes"
        );
        assert_eq!(missing, None, "ERROR_ENVVAR_NOT_FOUND");
        assert_eq!(
            denied.to_string(),
            format!(
                "GetFirmwareEnvironmentVariableExW of EFI variable \
                 Setup-00000000-0000-0000-0000-000000000000 failed with {}",
                Win32Error(ERROR_ACCESS_DENIED)
            ),
            "ERROR_ACCESS_DENIED"
        );
        assert_eq!(calls.get_calls().len(), 4, "gets");
        assert_eq!(calls.sets(), [], "sets");
    }

    /// set_variable sets the whole data with the attributes given, by the Win32 name and GUID
    /// of the variable, and names the code of a refused set.
    #[cfg(variable_data)]
    #[test]
    fn set_variable_sets_the_data_and_attributes_given() {
        let calls = FakeFirmwareEnvironmentCalls::new();
        calls.fail_set(Win32Error(ERROR_ACCESS_DENIED));
        let environment = fake_environment(&calls);
        let key = variable_key("Timeout");
        let contents =
            VariableContents::new(VariableAttributes::from_bits_retain(NV_BS_RT), vec![5, 0])
                .expect("hold two bytes");

        let refused = environment
            .set_variable(&key, &contents)
            .expect_err("a refused set");
        environment
            .set_variable(&key, &contents)
            .expect("set Timeout");

        assert_eq!(
            refused.to_string(),
            format!(
                "SetFirmwareEnvironmentVariableExW of EFI variable \
                 Timeout-00000000-0000-0000-0000-000000000000 failed with {}",
                Win32Error(ERROR_ACCESS_DENIED)
            ),
            "ERROR_ACCESS_DENIED"
        );
        let set = (
            variable_name(&key).expect("a name"),
            variable_guid(&key).expect("a GUID"),
            vec![5, 0],
            NV_BS_RT,
        );
        assert_eq!(calls.sets(), [set.clone(), set], "sets");
        assert_eq!(calls.get_calls(), [], "gets");
    }

    /// probe_capsule_results, through this fake.
    #[cfg(variable_data)]
    mod probe_capsule_results_tests {
        use super::*;
        use crate::efi_variables::probe_capsule_results;
        use crate::efi_variables::CapsuleResult;
        use crate::efi_variables::CapsuleResultDetails;
        use crate::efi_variables::CapsuleResultError;
        use crate::efi_variables::CapsuleResults;
        use crate::efi_variables::EfiTime;
        use crate::efi_variables::JsonCapsuleResult;
        use crate::efi_variables::NamedCapsuleResult;
        use crate::efi_variables::ResultName;
        use crate::efi_variables::Undecoded;
        use crate::firmware_width::FirmwareWidth;
        use crate::hii::package::Guid;

        /// EFI_CAPSULE_REPORT_GUID, the vendor GUID of the result variables (UEFI 2.11 §8.5.6.1).
        const EFI_CAPSULE_REPORT_GUID: &str = "39B68C46-F7FB-441B-B6EC-16B0F69821F3";
        /// EFI_JSON_CAPSULE_ID_GUID (UEFI 2.11 §23.5.1).
        const EFI_JSON_CAPSULE_ID_GUID: &str = "67D6F4CD-D6B8-4573-BF4A-DE5E252D61AE";
        /// A CapsuleGuid that no specification defines.
        const OTHER_CAPSULE_GUID: &str = "8C78A505-BAA0-4C4A-869F-000000001300";

        /// The GUID `text`.
        fn guid(text: &str) -> Guid {
            text.parse()
                .unwrap_or_else(|error| panic!("parse GUID {text}: {error}"))
        }

        /// The CHAR16 of `text` without a terminator, as CapsuleMax and CapsuleLast hold it.
        fn char16_bytes(text: &str) -> Vec<u8> {
            text.encode_utf16().flat_map(u16::to_le_bytes).collect()
        }

        /// A result of 64-bit firmware for the CapsuleGuid `capsule_guid` with CapsuleStatus
        /// `status`, processed at 2026-11-07 12:34:56 UTC, then `rest`.
        fn result_bytes(capsule_guid: &str, status: u64, rest: &[u8]) -> Vec<u8> {
            let total_size = u32::try_from(48 + rest.len()).expect("a UINT32 VariableTotalSize");
            let processed = [0xea, 0x07, 11, 7, 12, 34, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            [
                &total_size.to_le_bytes()[..],
                &[0; 4],
                &<[u8; 16]>::from(guid(capsule_guid)),
                &processed,
                &status.to_le_bytes(),
                rest,
            ]
            .concat()
        }

        /// The result of result_bytes.
        fn result(
            capsule_guid: &str,
            status: u64,
            rest_len: usize,
            details: CapsuleResultDetails,
        ) -> CapsuleResult {
            CapsuleResult {
                variable_total_size: u32::try_from(48 + rest_len).expect("a UINT32"),
                capsule_guid: guid(capsule_guid),
                capsule_processed: EfiTime {
                    year: 2026,
                    month: 11,
                    day: 7,
                    hour: 12,
                    minute: 34,
                    second: 56,
                    nanosecond: 0,
                    time_zone: 0,
                    daylight: 0,
                },
                capsule_status: status,
                details,
            }
        }

        /// The result name `name`.
        fn result_name(name: &str) -> ResultName {
            ResultName::parse(name).unwrap_or_else(|| panic!("{name} is a result name"))
        }

        /// The names that `calls` read, in order, each of EFI_CAPSULE_REPORT_GUID.
        fn report_names_read(calls: &FakeFirmwareEnvironmentCalls) -> Vec<String> {
            let report = variable_guid(&VariableKey {
                name: "CapsuleMax".to_owned(),
                guid: guid(EFI_CAPSULE_REPORT_GUID),
            })
            .expect("the report GUID");
            calls
                .get_calls()
                .into_iter()
                .map(|(_, name, vendor)| {
                    assert_eq!(vendor, report, "the vendor of {name:?}");
                    let units = name.strip_suffix(&[0]).expect("a NUL-terminated name");
                    String::from_utf16(units).expect("a UTF-16 name")
                })
                .collect()
        }

        /// probe_capsule_results reads CapsuleMax, CapsuleLast, then Capsule0000 to CapsuleMax by
        /// name, leaves out an absent one, and reads no name past CapsuleMax.
        #[test]
        fn probe_capsule_results_reads_by_name_up_to_capsule_max() {
            let json = [
                &1_u32.to_le_bytes()[..],
                &7_u32.to_le_bytes(),
                &2_u32.to_le_bytes(),
                b"{}",
            ]
            .concat();
            let calls = FakeFirmwareEnvironmentCalls::new();
            calls.queue_get(got(NV_BS_RT, &char16_bytes("Capsule0002")));
            calls.queue_get(got(NV_BS_RT, &char16_bytes("Capsule0000")));
            calls.queue_get(got(
                NV_BS_RT,
                &result_bytes(EFI_JSON_CAPSULE_ID_GUID, 0, &json),
            ));
            calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
            calls.queue_get(got(
                NV_BS_RT,
                &result_bytes(OTHER_CAPSULE_GUID, 0x8000_0000_0000_0003, &[9]),
            ));
            let environment = fake_environment(&calls);

            let results = probe_capsule_results(&environment, FirmwareWidth::Bits64);

            assert_eq!(
                results.expect("probe the results"),
                CapsuleResults {
                    capsule_max: Some(Ok(result_name("Capsule0002"))),
                    capsule_last: Some(Ok(result_name("Capsule0000"))),
                    results: vec![
                        NamedCapsuleResult {
                            name: result_name("Capsule0000"),
                            result: Ok(result(
                                EFI_JSON_CAPSULE_ID_GUID,
                                0,
                                14,
                                CapsuleResultDetails::Json(JsonCapsuleResult {
                                    capsule_id: 7,
                                    resp: b"{}".to_vec(),
                                }),
                            )),
                        },
                        NamedCapsuleResult {
                            name: result_name("Capsule0002"),
                            result: Ok(result(
                                OTHER_CAPSULE_GUID,
                                0x8000_0000_0000_0003,
                                1,
                                CapsuleResultDetails::Other(vec![9]),
                            )),
                        },
                    ],
                },
                "results"
            );
            assert_eq!(
                report_names_read(&calls),
                [
                    "CapsuleMax",
                    "CapsuleLast",
                    "Capsule0000",
                    "Capsule0001",
                    "Capsule0002"
                ],
                "names read"
            );
        }

        /// Scripts the gets of the probe of `names`, in turn: the data that `present` holds under
        /// the name, else ERROR_ENVVAR_NOT_FOUND.
        fn queue_probe(
            calls: &FakeFirmwareEnvironmentCalls,
            names: &[String],
            present: &[(&str, Vec<u8>)],
        ) {
            for name in names {
                match present.iter().find(|(held, _)| held == name) {
                    Some((_, data)) => calls.queue_get(got(NV_BS_RT, data)),
                    None => calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND)),
                }
            }
        }

        /// CapsuleMax and CapsuleLast, then the names of the indexes from 0 up to `last` that
        /// `spell` gives.
        fn probed(last: u16, spell: impl Fn(u16) -> Vec<String>) -> Vec<String> {
            ["CapsuleMax".to_owned(), "CapsuleLast".to_owned()]
                .into_iter()
                .chain((0..=last).flat_map(spell))
                .collect()
        }

        /// The name of `index` in uppercase digits.
        fn upper(index: u16) -> Vec<String> {
            vec![format!("Capsule{index:04X}")]
        }

        /// The name of `index` in lowercase digits.
        fn lower(index: u16) -> Vec<String> {
            vec![format!("Capsule{index:04x}")]
        }

        /// probe_capsule_results reports no results without CapsuleMax and CapsuleLast, reading no
        /// result variable.
        #[test]
        fn probe_capsule_results_without_capsule_max_and_last_reads_no_result() {
            let calls = FakeFirmwareEnvironmentCalls::new();
            calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
            calls.queue_get(FakeGet::Failed(Win32Error::ENVVAR_NOT_FOUND));
            let environment = fake_environment(&calls);

            let results = probe_capsule_results(&environment, FirmwareWidth::Bits64);

            assert_eq!(
                results.expect("probe no results"),
                CapsuleResults {
                    capsule_max: None,
                    capsule_last: None,
                    results: Vec::new(),
                },
                "results"
            );
            assert_eq!(
                report_names_read(&calls),
                ["CapsuleMax", "CapsuleLast"],
                "names read"
            );
        }

        /// probe_capsule_results reads up to the greater of CapsuleMax and CapsuleLast, either
        /// missing or not a result name, which it reports with why and its data.
        #[test]
        fn probe_capsule_results_reads_up_to_the_greater_of_capsule_max_and_last() {
            let other = result_bytes(OTHER_CAPSULE_GUID, 0, &[9]);
            let malformed = char16_bytes("Capsule00G2");
            for (case, max, last, want_max, want_last) in [
                (
                    "CapsuleLast past CapsuleMax",
                    Some(char16_bytes("Capsule0001")),
                    Some(char16_bytes("Capsule0002")),
                    Some(Ok(result_name("Capsule0001"))),
                    Some(Ok(result_name("Capsule0002"))),
                ),
                (
                    "no CapsuleMax",
                    None,
                    Some(char16_bytes("Capsule0002")),
                    None,
                    Some(Ok(result_name("Capsule0002"))),
                ),
                (
                    "a malformed CapsuleMax",
                    Some(malformed.clone()),
                    Some(char16_bytes("Capsule0002")),
                    Some(Err(capsule_max_undecoded(&malformed))),
                    Some(Ok(result_name("Capsule0002"))),
                ),
            ] {
                let calls = FakeFirmwareEnvironmentCalls::new();
                let mut present = vec![("Capsule0002", other.clone())];
                present.extend(max.map(|max| ("CapsuleMax", max)));
                present.extend(last.map(|last| ("CapsuleLast", last)));
                let names = probed(2, upper);
                queue_probe(&calls, &names, &present);
                let environment = fake_environment(&calls);

                let results = probe_capsule_results(&environment, FirmwareWidth::Bits64);

                assert_eq!(
                    results.unwrap_or_else(|error| panic!("{case}: {error:#}")),
                    CapsuleResults {
                        capsule_max: want_max,
                        capsule_last: want_last,
                        results: vec![NamedCapsuleResult {
                            name: result_name("Capsule0002"),
                            result: Ok(result(
                                OTHER_CAPSULE_GUID,
                                0,
                                1,
                                CapsuleResultDetails::Other(vec![9]),
                            )),
                        }],
                    },
                    "{case}: results"
                );
                assert_eq!(report_names_read(&calls), names, "{case}: names read");
            }
        }

        /// probe_capsule_results spells the names in the case of the letter digits of CapsuleMax,
        /// else in that of CapsuleLast's, as the firmware chose the case (UEFI 2.11 §8.5.6).
        #[test]
        fn probe_capsule_results_spells_names_in_the_case_of_capsule_max_or_last() {
            /// A case: CapsuleMax, CapsuleLast, the last index probed, how names are spelled,
            /// and the one name present.
            struct Case {
                name: &'static str,
                max: &'static str,
                last: &'static str,
                bound: u16,
                spell: fn(u16) -> Vec<String>,
                found: &'static str,
            }
            let other = result_bytes(OTHER_CAPSULE_GUID, 0, &[9]);
            let cases = [
                Case {
                    name: "CapsuleMax lowercase",
                    max: "Capsule000b",
                    last: "Capsule000A",
                    bound: 0xb,
                    spell: lower,
                    found: "Capsule000a",
                },
                Case {
                    name: "CapsuleMax uppercase",
                    max: "Capsule000B",
                    last: "Capsule000a",
                    bound: 0xb,
                    spell: upper,
                    found: "Capsule000A",
                },
                Case {
                    name: "CapsuleLast lowercase",
                    max: "Capsule0010",
                    last: "Capsule000c",
                    bound: 0x10,
                    spell: lower,
                    found: "Capsule000c",
                },
                Case {
                    name: "CapsuleLast uppercase",
                    max: "Capsule0010",
                    last: "Capsule000C",
                    bound: 0x10,
                    spell: upper,
                    found: "Capsule000C",
                },
            ];
            for Case {
                name: case,
                max,
                last,
                bound,
                spell,
                found,
            } in cases
            {
                let calls = FakeFirmwareEnvironmentCalls::new();
                let names = probed(bound, spell);
                let present = [
                    ("CapsuleMax", char16_bytes(max)),
                    ("CapsuleLast", char16_bytes(last)),
                    (found, other.clone()),
                ];
                queue_probe(&calls, &names, &present);
                let environment = fake_environment(&calls);

                let results = probe_capsule_results(&environment, FirmwareWidth::Bits64)
                    .unwrap_or_else(|error| panic!("{case}: {error:#}"));

                assert_eq!(report_names_read(&calls), names, "{case}: names read");
                assert_eq!(
                    results
                        .results
                        .iter()
                        .map(|named| named.name.as_str())
                        .collect::<Vec<_>>(),
                    [found],
                    "{case}: results"
                );
            }
        }

        /// Where neither CapsuleMax nor CapsuleLast has a letter digit, probe_capsule_results
        /// spells names in uppercase, as edk2 does, and reads an absent one with a letter digit
        /// again in lowercase.
        #[test]
        fn probe_capsule_results_retries_absent_names_with_letters_in_lowercase() {
            let other = result_bytes(OTHER_CAPSULE_GUID, 0, &[9]);
            let calls = FakeFirmwareEnvironmentCalls::new();
            // Capsule000C is present, so it is not read again
            let names = probed(0x10, |index| {
                let [upper, lower] = [upper(index), lower(index)].map(|mut name| name.remove(0));
                match upper == lower || upper == "Capsule000C" {
                    true => vec![upper],
                    false => vec![upper, lower],
                }
            });
            let present = [
                ("CapsuleMax", char16_bytes("Capsule0010")),
                ("CapsuleLast", char16_bytes("Capsule0003")),
                ("Capsule000C", other.clone()),
                ("Capsule000d", other.clone()),
            ];
            queue_probe(&calls, &names, &present);
            let environment = fake_environment(&calls);

            let results = probe_capsule_results(&environment, FirmwareWidth::Bits64)
                .expect("probe the results");

            assert_eq!(report_names_read(&calls), names, "names read");
            assert_eq!(
                results
                    .results
                    .iter()
                    .map(|named| named.name.as_str())
                    .collect::<Vec<_>>(),
                ["Capsule000C", "Capsule000d"],
                "results"
            );
        }

        /// The Undecoded of a CapsuleMax of `data` that holds "Capsule00G2".
        fn capsule_max_undecoded(data: &[u8]) -> Undecoded {
            Undecoded {
                error: CapsuleResultError::NameText {
                    variable: "CapsuleMax",
                    text: "Capsule00G2".to_owned(),
                },
                data: data.to_vec(),
            }
        }
    }
}
