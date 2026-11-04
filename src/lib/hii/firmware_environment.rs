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

use crate::hii::variables::attributes_and_data;
use crate::hii::variables::modify_variable_bytes;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;
use crate::hii::win32::nul_terminated_utf16;
use crate::hii::win32::Win32Error;

// The Win32 calls, built for Windows alone; the rest builds for the tests of every host too.
#[cfg(target_os = "windows")]
mod win32_calls;

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
    const REACH: VariableReach = VariableReach::Runtime;
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

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        // As VariableServices::write_at (variable_services.rs): read the whole variable,
        // modify its bytes, and write the whole data back with the same attributes.
        let name = variable_name(key)?;
        let guid = variable_guid(key)?;
        let (attributes, data) = self.read_all(key)?;
        let mut bytes = [&attributes.to_ne_bytes()[..], &data].concat();
        modify_variable_bytes(key, Self::INTERFACE, &mut bytes, size, offset, encoded)?;
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
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
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
}
