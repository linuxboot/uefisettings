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

//! The HiiDB of a Windows machine, through a HiiDB driver. No driver in this
//! repository implements the contract below, no driver is shipped with it, and none
//! has been tested against it: this module is only the contract's consumer, and must
//! not trust a driver that claims to implement it.
//!
//! The contract a driver must implement, in normative terms:
//!
//! The driver must expose the device `\\.\UefiSettingsHiiDB`, created with the vendor
//! DeviceType 0x8000, with two IOCTLs of that DeviceType, each FILE_READ_ACCESS (1) and
//! taking no input:
//!
//! - The size query, CTL_CODE(0x8000, function 0x801, METHOD_OUT_DIRECT, FILE_READ_ACCESS) =
//!   0x8000_6006. The driver must complete it with STATUS_SUCCESS, the HiiDB's size in bytes
//!   as a little-endian u32 in the first 4 bytes of the buffer that Irp->MdlAddress describes,
//!   and IoStatus.Information = 4, so that DeviceIoControl succeeds with lpBytesReturned = 4.
//!   An output of fewer than 4 bytes must fail.
//! - The read, CTL_CODE(0x8000, function 0x800, METHOD_OUT_DIRECT, FILE_READ_ACCESS) =
//!   0x8000_6002. With an output of at least the HiiDB's size, the driver must complete it
//!   with STATUS_SUCCESS, the raw HiiDB bytes in the buffer that Irp->MdlAddress describes,
//!   and IoStatus.Information = their count; with a smaller output it must fail.
//!
//! For both, IoStatus.Information must not exceed the output length. Both are direct, so the
//! driver writes into this consumer's buffer through the MDL, which describes exactly the
//! output length, and the I/O manager copies nothing back: Microsoft Learn's "Using Direct
//! I/O" says that direct I/O eliminates "the memory allocation and copying operations
//! inherent in buffered I/O". A wrong IoStatus.Information then reaches only
//! lpBytesReturned, which `read_hiidb_from` refuses. For a buffered IOCTL, the I/O manager
//! would copy that many bytes back into the output, as it "assumes that the value in the
//! Information field is valid" ("Failure to Check the Size of Buffers").
//!
//! Microsoft Learn's "Defining I/O Control Codes" says that vendors "should use a value from
//! 32768 through 65535 (0x8000 through 0xffff)" for the DeviceType, which must match the
//! device object's, and the read is direct because its "Using Buffered I/O" says that
//! "drivers that do multipage transfers, should not attempt to use buffered I/O"; the HiiDB
//! may take up to 16 MiB.
//!
//! The size has an IOCTL of its own because a failed DeviceIoControl reports no size: per
//! Microsoft Learn's DeviceIoControl page (lpBytesReturned), when the output buffer "is too
//! small to receive any data, the call fails, GetLastError returns ERROR_INSUFFICIENT_BUFFER,
//! and lpBytesReturned is zero". A future revision of the contract must use new IOCTL function
//! codes; no runtime version check is added here, so a driver for a later revision and
//! this consumer would not agree on the codes.
//!
//! The driver must read the HiiDB EFI variable in kernel mode: the variable named
//! `HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0`, whose GUID is
//! `1b838190-4625-4ead-abc9-cd5e6af18fe0` (the `OCP_HIIDB_PATH` of
//! `src/lib/hii/extract.rs`). The descriptor has two forms, which must not be
//! confused. The efivarfs-file form is what `src/lib/hii/extract.rs` parses
//! (`HiiDBEFIVar32` and `HiiDBEFIVar64`, little-endian): the 12-byte layout of
//! `flags: u32`, `length: u32` and `address: u32`, or the 16-byte layout of
//! `flags: u32`, `length: u32` and `address: u64`, where the first 4 bytes are
//! the UEFI variable attributes. The kernel-payload form is what the driver
//! receives: the 8-byte layout of `length: u32` and `address: u32`, or the
//! 12-byte layout of `length: u32` and `address: u64`, little-endian, with no
//! attributes word in the payload, as the kernel call returns the attributes
//! separately. The driver must use the payload form's `length` and `address`
//! (and the separately returned attributes) to map only the range the
//! descriptor names, read-only, copy it into the read's output buffer, and unmap it;
//! the size query answers that `length`. There must be no caller-supplied address and no
//! write IOCTL.
//!
//! The driver must gate access to the device itself, with an admin-only device ACL or
//! privilege gating on the driver side: FILE_READ_ACCESS (1) in the IOCTL codes has the I/O
//! manager check only that the caller's handle may read, so this consumer cannot enforce who
//! may read the HiiDB through the device. An ACL alone must come with the
//! FILE_DEVICE_SECURE_OPEN characteristic on the device object, or the driver must fail every
//! IRP_MJ_CREATE with a nonzero FileName: otherwise an open of a name in the device's
//! namespace, such as `\\.\UefiSettingsHiiDB\x`, is not checked against the ACL (Microsoft
//! Learn, "Controlling Device Namespace Access": "the device object ACL is not checked by the
//! operating system").
//!
//! Conformance to this contract is assumed and unchecked by this consumer beyond the
//! checks in `read_hiidb_from`: a size answer of other than 4 bytes, an answered size of
//! 0 or over the cap, and a read that fails, reports more bytes written than the buffer
//! holds or writes another size than the size query answered are refused. This module
//! never parses any HiiDB-variable descriptor.

use std::cmp::Ordering;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use windows_sys::Win32::System::Ioctl::FILE_READ_ACCESS;
use windows_sys::Win32::System::Ioctl::METHOD_OUT_DIRECT;

use crate::hii::package::db_file::MAX_ALLOWED_FILESIZE;
use crate::hii::win32::Win32Error;
#[cfg(target_os = "windows")]
use device_io_control::DeviceIoControlTransport;

// The Win32 calls, built for Windows alone; the rest builds for the tests of every host too.
#[cfg(target_os = "windows")]
mod device_io_control;

/// The device path of the HiiDB driver.
const DEVICE_PATH: &str = r"\\.\UefiSettingsHiiDB";

/// The DeviceType of the HiiDB driver's device and IOCTLs: a vendor one, as "Defining I/O
/// Control Codes" (Microsoft Learn) has vendors use 0x8000 through 0xFFFF.
const HIIDB_DEVICE_TYPE: u32 = 0x8000;

/// CTL_CODE of devioctl.h, as "Defining I/O Control Codes" gives it.
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// The IOCTL the contract assigns to the size query, direct like the read, so that no IOCTL of
/// the contract has the I/O manager copy back as many bytes as IoStatus.Information says.
const IOCTL_HIIDB_SIZE: u32 = ctl_code(
    HIIDB_DEVICE_TYPE,
    0x801,
    METHOD_OUT_DIRECT,
    FILE_READ_ACCESS,
);

/// The IOCTL the contract assigns to reading the HiiDB, direct for its up to 16 MiB: "Using
/// Buffered I/O" (Microsoft Learn) keeps multipage transfers off buffered I/O.
const IOCTL_READ_HIIDB: u32 = ctl_code(
    HIIDB_DEVICE_TYPE,
    0x800,
    METHOD_OUT_DIRECT,
    FILE_READ_ACCESS,
);

/// The largest HiiDB that read_hiidb_from accepts, derived from
/// `MAX_ALLOWED_FILESIZE` in `db_file.rs`: a HiiDB read through the driver is capped
/// at the same size as the largest HiiDB file, so the two ways of reading a HiiDB
/// share one cap. The file cap fits in a `u32`, as the const assertion checks, so the
/// narrowing cast below cannot truncate.
const _: () = assert!(MAX_ALLOWED_FILESIZE <= u32::MAX as u64);
const MAX_HIIDB_BYTES: u32 = MAX_ALLOWED_FILESIZE as u32;

/// The DeviceIoControl calls of the HiiDB driver: the real device, or a fake in tests.
///
/// `control` takes `&mut self` because the transport is stateful: it holds the open
/// device, and `read_hiidb_from` controls it in order, the size query first and then the
/// read that the answer sized. `control` sends `ioctl` with no input and `buffer` as the
/// whole output buffer the driver may write, and returns the bytes written, which must not
/// exceed `buffer.len()`, or the error of a failed call, which reports no size.
pub(crate) trait DriverTransport {
    fn control(&mut self, ioctl: u32, buffer: &mut [u8]) -> Result<u32>;
}

/// The HiiDB bytes of this machine, through the HiiDB driver.
#[cfg(target_os = "windows")]
pub(crate) fn read_hiidb() -> Result<Vec<u8>> {
    read_hiidb_from(&mut DeviceIoControlTransport::open()?)
}

/// The HiiDB bytes that `transport` reads: the size query, then one read into a buffer of
/// the size it answered, capped at MAX_HIIDB_BYTES. A read that fails or writes another
/// size than the size query answered is refused rather than truncated: driver bytes are
/// never silently cut to fit a buffer they outgrew or shrank from.
fn read_hiidb_from(transport: &mut impl DriverTransport) -> Result<Vec<u8>> {
    let mut answer = [0u8; 4];
    let written = transport
        .control(IOCTL_HIIDB_SIZE, &mut answer)
        .context("HiiDB driver failed the size query")?;
    if written != 4 {
        return Err(anyhow!(
            "HiiDB driver answered the size query with {written} bytes, not the 4 of a \
             little-endian u32"
        ));
    }
    let size = match u32::from_le_bytes(answer) {
        0 => return Err(anyhow!("HiiDB driver answered an empty HiiDB")),
        size @ 1..=MAX_HIIDB_BYTES => size,
        size => {
            return Err(anyhow!(
                "HiiDB driver answered a HiiDB of {size} bytes, over the maximum of \
                 {MAX_HIIDB_BYTES} bytes"
            ))
        }
    };
    let mut buffer = vec![0u8; usize::try_from(size).context("HiiDB size fits in usize")?];
    let written = transport
        .control(IOCTL_READ_HIIDB, &mut buffer)
        .with_context(|| {
            format!(
                "HiiDB driver answered a HiiDB of {size} bytes to the size query, then failed \
                 to read it"
            )
        })?;
    let written = usize::try_from(written).context("written HiiDB size fits in usize")?;
    match written.cmp(&buffer.len()) {
        Ordering::Equal => Ok(buffer),
        Ordering::Greater => Err(anyhow!(
            "HiiDB driver wrote {written} bytes into a buffer of {} bytes",
            buffer.len()
        )),
        Ordering::Less => Err(anyhow!(
            "HiiDB driver wrote {written} bytes of the HiiDB of {size} bytes that it answered \
             to the size query; the HiiDB changed size, so rerun the command"
        )),
    }
}

/// The error of opening the HiiDB driver device with Win32 error `code`: ERROR_FILE_NOT_FOUND
/// names the missing driver and -f, ERROR_ACCESS_DENIED elevation and -f, other codes name the
/// device.
fn open_error(code: Win32Error) -> anyhow::Error {
    match code {
        Win32Error::FILE_NOT_FOUND => anyhow!(
            "the HiiDB driver is not installed: failed to open the HiiDB driver \
             device {DEVICE_PATH} ({}, ERROR_FILE_NOT_FOUND); the driver \
             must implement the IOCTL contract in src/lib/hii/hiidb_driver.rs; pass \
             -f to read a HiiDB file instead",
            Win32Error::FILE_NOT_FOUND
        ),
        Win32Error::ACCESS_DENIED => anyhow!(
            "failed to open the HiiDB driver device {DEVICE_PATH} ({}, ERROR_ACCESS_DENIED): \
             the driver admits only administrators, so run elevated, or pass -f to read a \
             HiiDB file instead",
            Win32Error::ACCESS_DENIED
        ),
        code => anyhow!("failed to open the HiiDB driver device {DEVICE_PATH}: {code}"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    use super::*;

    /// A scripted answer of FakeDriverTransport::control: the bytes it copies into the
    /// buffer and the count it reports written, or a failure.
    enum FakeControl {
        Complete { payload: Vec<u8>, written: u32 },
        Error(&'static str),
    }

    /// The size query's answer of `size`: its 4 little-endian bytes, all written.
    fn size_answer(size: u32) -> FakeControl {
        FakeControl::Complete {
            payload: size.to_le_bytes().to_vec(),
            written: 4,
        }
    }

    /// A DriverTransport scripted with FakeControls, which records the IOCTL and the
    /// buffer length of every call.
    struct FakeDriverTransport {
        script: VecDeque<FakeControl>,
        calls: Vec<(u32, usize)>,
    }

    impl FakeDriverTransport {
        fn new(script: Vec<FakeControl>) -> Self {
            Self {
                script: script.into(),
                calls: Vec::new(),
            }
        }
    }

    impl DriverTransport for FakeDriverTransport {
        fn control(&mut self, ioctl: u32, buffer: &mut [u8]) -> Result<u32> {
            self.calls.push((ioctl, buffer.len()));
            match self.script.pop_front() {
                None => Err(anyhow!("FakeDriverTransport ran out of scripted calls")),
                Some(FakeControl::Complete { payload, written }) => {
                    let copied = payload.len().min(buffer.len());
                    buffer[..copied].copy_from_slice(&payload[..copied]);
                    Ok(written)
                }
                Some(FakeControl::Error(message)) => Err(anyhow!(message)),
            }
        }
    }

    /// The IOCTLs are the CTL_CODEs of the contract: the vendor DeviceType 0x8000, read
    /// access, the size query function 0x801 and the read function 0x800, both direct. The
    /// fields are CTL_CODE's arguments, whose DeviceType and Function hold the Common and
    /// Custom bits of the IOCTL layout in "Defining I/O Control Codes".
    #[test]
    fn ioctls_are_the_ctl_codes_of_the_contract() {
        assert_eq!(
            (IOCTL_HIIDB_SIZE, IOCTL_READ_HIIDB),
            (0x8000_6006, 0x8000_6002),
            "IOCTL values"
        );
        for (name, ioctl, function, method) in [
            ("size query", IOCTL_HIIDB_SIZE, 0x801, METHOD_OUT_DIRECT),
            ("read", IOCTL_READ_HIIDB, 0x800, METHOD_OUT_DIRECT),
        ] {
            assert_eq!(
                (
                    ioctl >> 16,
                    (ioctl >> 14) & 3,
                    (ioctl >> 2) & 0xfff,
                    ioctl & 3
                ),
                (0x8000, FILE_READ_ACCESS, function, method),
                "{name}: DeviceType, Access, Function, Method"
            );
        }
    }

    /// The size query's answer sizes the one read, which returns the HiiDB.
    #[test]
    fn size_query_then_read_returns_the_hiidb() {
        let mut transport = FakeDriverTransport::new(vec![
            size_answer(3),
            FakeControl::Complete {
                payload: vec![1, 2, 3],
                written: 3,
            },
        ]);

        let read = read_hiidb_from(&mut transport);

        assert_eq!(read.ok(), Some(vec![1, 2, 3]), "HiiDB");
        assert_eq!(
            transport.calls,
            [(IOCTL_HIIDB_SIZE, 4), (IOCTL_READ_HIIDB, 3)],
            "calls"
        );
    }

    /// A read that writes fewer bytes than the size query answered is an error naming
    /// both sizes and telling the user to rerun, after both calls: the bytes are never
    /// silently truncated to the shorter read.
    #[test]
    fn read_shorter_than_the_answered_size_is_an_error() {
        for (size, written, payload) in [(4, 2, vec![9, 8]), (3, 2, vec![9, 8]), (2, 0, vec![])] {
            let mut transport = FakeDriverTransport::new(vec![
                size_answer(size),
                FakeControl::Complete { payload, written },
            ]);

            let error = read_hiidb_from(&mut transport)
                .expect_err("read a HiiDB that shrank between the calls");

            assert_eq!(
                format!("{error:#}"),
                format!(
                    "HiiDB driver wrote {written} bytes of the HiiDB of {size} bytes that it \
                     answered to the size query; the HiiDB changed size, so rerun the command"
                ),
                "size {size}, written {written}"
            );
            assert_eq!(
                transport.calls,
                [
                    (IOCTL_HIIDB_SIZE, 4),
                    (
                        IOCTL_READ_HIIDB,
                        usize::try_from(size).expect("size fits in usize")
                    )
                ],
                "size {size}: both calls"
            );
        }
    }

    /// An answered size over the cap is an error after the size query alone, while an
    /// answered size at the cap is read.
    #[test]
    fn answered_size_over_the_cap_reads_nothing_more() {
        let mut over = FakeDriverTransport::new(vec![size_answer(MAX_HIIDB_BYTES + 1)]);

        let error = read_hiidb_from(&mut over).expect_err("read a HiiDB over the cap");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "HiiDB driver answered a HiiDB of {} bytes, over the maximum of \
                 {MAX_HIIDB_BYTES} bytes",
                MAX_HIIDB_BYTES + 1
            ),
            "over the cap"
        );
        assert_eq!(
            over.calls,
            [(IOCTL_HIIDB_SIZE, 4)],
            "over the cap: only the size query"
        );

        let cap = usize::try_from(MAX_HIIDB_BYTES).expect("cap fits in usize");
        let mut payload = vec![0u8; cap];
        payload[0] = 7;
        payload[cap - 1] = 9;
        let mut at_cap = FakeDriverTransport::new(vec![
            size_answer(MAX_HIIDB_BYTES),
            FakeControl::Complete {
                payload,
                written: MAX_HIIDB_BYTES,
            },
        ]);

        // the length and the end bytes alone, so that a failure prints no 16 MiB Vec
        assert_eq!(
            read_hiidb_from(&mut at_cap)
                .map(|db| (db.len(), db.first().copied(), db.last().copied()))
                .map_err(|error| format!("{error:#}")),
            Ok((cap, Some(7), Some(9))),
            "at the cap: HiiDB"
        );
        assert_eq!(
            at_cap.calls,
            [(IOCTL_HIIDB_SIZE, 4), (IOCTL_READ_HIIDB, cap)],
            "at the cap: calls"
        );
    }

    /// A size query answered with other than 4 bytes is an error naming the count, after
    /// the size query alone.
    #[test]
    fn size_answer_of_another_length_is_an_error() {
        for written in [0, 3, 5] {
            let mut transport = FakeDriverTransport::new(vec![FakeControl::Complete {
                payload: vec![1, 0, 0, 0],
                written,
            }]);

            let error = read_hiidb_from(&mut transport)
                .expect_err("read with a size answer of a bad length");

            assert_eq!(
                format!("{error:#}"),
                format!(
                    "HiiDB driver answered the size query with {written} bytes, not the 4 of a \
                     little-endian u32"
                ),
                "{written} bytes"
            );
            assert_eq!(
                transport.calls,
                [(IOCTL_HIIDB_SIZE, 4)],
                "{written} bytes: only the size query"
            );
        }
    }

    /// A failed read is an error naming the size that the size query answered, after
    /// both calls.
    #[test]
    fn failed_read_names_the_answered_size() {
        let mut transport = FakeDriverTransport::new(vec![
            size_answer(4),
            FakeControl::Error("DeviceIoControl failed"),
        ]);

        let error = read_hiidb_from(&mut transport).expect_err("read through a failing read");

        assert_eq!(
            format!("{error:#}"),
            "HiiDB driver answered a HiiDB of 4 bytes to the size query, then failed to read \
             it: DeviceIoControl failed",
            "failed read"
        );
        assert_eq!(
            transport.calls,
            [(IOCTL_HIIDB_SIZE, 4), (IOCTL_READ_HIIDB, 4)],
            "failed read: both calls"
        );
    }

    /// A read that reports more bytes written than the buffer holds is an error.
    #[test]
    fn written_past_the_buffer_is_an_error() {
        let mut transport = FakeDriverTransport::new(vec![
            size_answer(2),
            FakeControl::Complete {
                payload: vec![1, 2],
                written: 3,
            },
        ]);

        let error = read_hiidb_from(&mut transport).expect_err("read past the buffer");

        assert_eq!(
            format!("{error:#}"),
            "HiiDB driver wrote 3 bytes into a buffer of 2 bytes",
            "overflow write"
        );
        assert_eq!(
            transport.calls,
            [(IOCTL_HIIDB_SIZE, 4), (IOCTL_READ_HIIDB, 2)],
            "overflow write: both calls"
        );
    }

    /// A size query that answers 0 is an empty HiiDB, an error after the size query alone.
    #[test]
    fn empty_hiidb_is_an_error() {
        let mut transport = FakeDriverTransport::new(vec![size_answer(0)]);

        let error = read_hiidb_from(&mut transport).expect_err("read an empty HiiDB");

        assert_eq!(
            format!("{error:#}"),
            "HiiDB driver answered an empty HiiDB",
            "empty"
        );
        assert_eq!(
            transport.calls,
            [(IOCTL_HIIDB_SIZE, 4)],
            "empty: only the size query"
        );
    }

    /// A failed size query is an error naming it, after the size query alone.
    #[test]
    fn failed_size_query_is_an_error() {
        let mut transport =
            FakeDriverTransport::new(vec![FakeControl::Error("DeviceIoControl failed")]);

        let error = read_hiidb_from(&mut transport).expect_err("read through a failing driver");

        assert_eq!(
            format!("{error:#}"),
            "HiiDB driver failed the size query: DeviceIoControl failed",
            "failed size query"
        );
        assert_eq!(
            transport.calls,
            [(IOCTL_HIIDB_SIZE, 4)],
            "failed size query: one call"
        );
    }

    /// ERROR_FILE_NOT_FOUND names the missing driver and -f, ERROR_ACCESS_DENIED elevation and
    /// -f; other codes name the device.
    #[test]
    fn open_error_names_the_missing_driver() {
        assert_eq!(
            open_error(Win32Error::FILE_NOT_FOUND).to_string(),
            format!(
                "the HiiDB driver is not installed: failed to open the HiiDB driver device \
                 {DEVICE_PATH} (Win32 error 2, ERROR_FILE_NOT_FOUND); the driver must \
                 implement the IOCTL contract in src/lib/hii/hiidb_driver.rs; pass -f to read \
                 a HiiDB file instead"
            ),
            "ERROR_FILE_NOT_FOUND"
        );
        assert_eq!(
            open_error(Win32Error::ACCESS_DENIED).to_string(),
            format!(
                "failed to open the HiiDB driver device {DEVICE_PATH} (Win32 error 5, \
                 ERROR_ACCESS_DENIED): the driver admits only administrators, so run elevated, \
                 or pass -f to read a HiiDB file instead"
            ),
            "ERROR_ACCESS_DENIED"
        );
        assert_eq!(
            open_error(Win32Error(ERROR_SHARING_VIOLATION)).to_string(),
            format!("failed to open the HiiDB driver device {DEVICE_PATH}: Win32 error 32"),
            "ERROR_SHARING_VIOLATION"
        );
    }
}
