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

//! What Linux's boot log says of an EFI_RT_PROPERTIES_TABLE. efi_config_parse_tables() logs one
//! kernel record "efi: " that names each configuration table it knows, as "NAME=0xADDRESS " for
//! each that it applies, RTPROP among them, and, from v6.3, "(NAME=0xADDRESS unusable) " for each
//! that it ignores (Linux v5.8 to v6.7 drivers/firmware/efi/efi.c match_config_table()). It logs
//! that record before Linux applies the table's RuntimeServicesSupported, so a log that keeps the
//! record and names no usable RTPROP after it shows a kernel that applied none.
//!
//! The kernel log loses its oldest records first, so a kept record keeps those after it. A
//! /dev/kmsg reader learns of records lost while it reads (EPIPE), and setup_log_buf() logs
//! "printk: dropped N messages" for those that it lost (Linux v6.7 kernel/printk/printk.c).

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

/// The kernel log, one record per read() (Linux v6.7 kernel/printk/printk.c devkmsg_read()).
pub(super) const KMSG_PATH: &str = "/dev/kmsg";

/// The kernel log's character device, 1:11 (Linux v6.7 drivers/char/mem.c devlist and
/// include/uapi/linux/major.h MEM_MAJOR).
pub(super) const KMSG_DEVICE: libc::dev_t = libc::makedev(1, 11);

/// Bigger than any /dev/kmsg record: PRINTK_MESSAGE_MAX, 2048 bytes, in Linux v6.7
/// (kernel/printk/internal.h), and CONSOLE_EXT_LOG_MAX, 8192 bytes, in Linux v5.8
/// (include/linux/printk.h).
const RECORD_BUFFER_LEN: usize = 16 * 1024;

/// What the log of setup_log_buf() starts with when it lost records (Linux v6.7
/// kernel/printk/printk.c, whose pr_fmt is "printk: ").
const DROPPED_RECORDS: &str = "printk: dropped ";

/// The prefix of efi_config_parse_tables()'s record (drivers/firmware/efi/efi.c pr_fmt).
const CONFIG_TABLES_PREFIX: &str = "efi: ";

/// The token of an applied RT properties table, before its address.
const RT_PROPERTIES_TOKEN: &str = "RTPROP=0x";

/// syslog(2)'s actions (Linux v6.7 include/linux/syslog.h).
const SYSLOG_ACTION_READ_ALL: libc::c_int = 3;
const SYSLOG_ACTION_SIZE_BUFFER: libc::c_int = 10;

/// Whether Linux applied an EFI_RT_PROPERTIES_TABLE, as its boot log says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RtPropertiesInBootLog {
    /// The log keeps the configuration table record and names no usable RTPROP.
    Absent,
    /// A kernel record names a usable RTPROP.
    Present,
}

/// The kernel log through syslog(2), which printk.devkmsg=off leaves readable: do_syslog() does
/// not check devkmsg_log, while devkmsg_open() refuses every open with EPERM (Linux v6.7
/// kernel/printk/printk.c).
pub(super) trait KernelLog {
    /// SYSLOG_ACTION_READ_ALL, into a buffer of SYSLOG_ACTION_SIZE_BUFFER bytes: the records as
    /// lines `<PRIORITY>[TIME] MESSAGE`, the newest that fit.
    fn read_all(&self) -> io::Result<Vec<u8>>;
}

/// This kernel's syslog(2).
pub(super) struct Syslog;

impl KernelLog for Syslog {
    fn read_all(&self) -> io::Result<Vec<u8>> {
        let size = syslog(SYSLOG_ACTION_SIZE_BUFFER, &mut [])?;
        let mut buffer = vec![0; size];
        let len = syslog(SYSLOG_ACTION_READ_ALL, &mut buffer)?;
        buffer.truncate(len);
        Ok(buffer)
    }
}

/// syslog(2)'s `action` with `buffer`, which READ_ALL fills; its return value.
fn syslog(action: libc::c_int, buffer: &mut [u8]) -> io::Result<usize> {
    let len = libc::c_int::try_from(buffer.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: klogctl(3) writes at most `len` bytes at `buffer`, which holds `len` bytes, and
    // keeps no pointer to it; SIZE_BUFFER ignores both.
    let ret = unsafe { libc::klogctl(action, buffer.as_mut_ptr().cast(), len) };
    usize::try_from(ret).map_err(|_| io::Error::last_os_error())
}

/// Opens the kernel log at `path` for reads that end at its end, as /dev/kmsg does with
/// O_NONBLOCK (EAGAIN).
pub(super) fn open_kmsg(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
}

/// `file`, which was opened at `path`, if it is the character device `device`: anything else,
/// such as a file that a privileged container bind-mounts over /dev/kmsg, may mimic its records.
pub(super) fn require_char_device(
    path: &Path,
    file: File,
    device: libc::dev_t,
) -> io::Result<File> {
    let metadata = file.metadata()?;
    if metadata.file_type().is_char_device() && metadata.rdev() == device {
        return Ok(file);
    }
    Err(io::Error::other(format!(
        "{} is not the character device {}:{}",
        path.display(),
        libc::major(device),
        libc::minor(device)
    )))
}

/// What the kernel log says of the RT properties table: the log at `kmsg`, which `open` opens,
/// or `log` where the kernel refuses `kmsg` with EPERM. An error means that the log is
/// unreadable or tells nothing.
pub(super) fn rt_properties_in_boot_log<R: Read>(
    kmsg: &Path,
    open: impl FnOnce(&Path) -> io::Result<R>,
    log: &dyn KernelLog,
) -> Result<RtPropertiesInBootLog> {
    let records = match open(kmsg) {
        Ok(records) => records,
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
            let lines = log
                .read_all()
                .context("Failed to read the kernel log through syslog(2)")?;
            return scan_syslog(&lines).with_context(|| {
                format!("{} refused ({error}), so through syslog(2)", kmsg.display())
            });
        }
        Err(error) => {
            return Err(error).with_context(|| format!("Failed to open {}", kmsg.display()))
        }
    };
    scan_kmsg(records).with_context(|| format!("Failed to read {}", kmsg.display()))
}

/// The scan of the /dev/kmsg records that `records` returns, one per read: "PRIORITY,SEQ,TIME,
/// FLAGS;MESSAGE", then " KEY=VALUE" lines (Linux v6.7 kernel/printk/printk.c
/// info_print_ext_header()).
fn scan_kmsg(mut records: impl Read) -> Result<RtPropertiesInBootLog> {
    let mut buffer = vec![0; RECORD_BUFFER_LEN];
    let mut scan = BootLogScan::default();
    loop {
        match records.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                let record = String::from_utf8_lossy(buffer.get(..len).unwrap_or_default());
                let line = record.lines().next().unwrap_or_default();
                let (header, message) = line
                    .split_once(';')
                    .with_context(|| format!("a kernel log record without a header: {line:?}"))?;
                let priority = header.split(',').next().unwrap_or_default();
                let priority = priority
                    .parse()
                    .with_context(|| format!("a kernel log record priority {priority:?}"))?;
                scan.record(priority, message)?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            // devkmsg_read(): the kernel overwrote the next record.
            Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
                bail!("the kernel overwrote records of its log while uefisettings read them")
            }
            Err(error) => return Err(error.into()),
        }
    }
    scan.finish()
}

/// The scan of the syslog(2) records `lines`: `<PRIORITY>`, the time `[%5lu.%06lu]` unless
/// printk.time is off, the caller `[%6s]` with CONFIG_PRINTK_CALLER, a space after either, then
/// the message (Linux v6.7 kernel/printk/printk.c info_print_prefix()).
fn scan_syslog(lines: &[u8]) -> Result<RtPropertiesInBootLog> {
    let mut scan = BootLogScan::default();
    for line in String::from_utf8_lossy(lines).lines() {
        let Some((priority, rest)) = line.strip_prefix('<').and_then(|line| line.split_once('>'))
        else {
            bail!("a syslog(2) line without a priority: {line:?}");
        };
        let priority = priority
            .parse()
            .with_context(|| format!("a syslog(2) priority {priority:?}"))?;
        scan.record(priority, strip_syslog_prefix(rest))?;
    }
    scan.finish()
}

/// `rest`, a syslog(2) line after its priority, without its time and caller.
fn strip_syslog_prefix(rest: &str) -> &str {
    let mut message = rest;
    let mut stripped = false;
    for is_group in [is_syslog_time, is_syslog_caller] {
        if let Some((group, after)) = message
            .strip_prefix('[')
            .and_then(|message| message.split_once(']'))
        {
            if is_group(group.trim_start()) {
                message = after;
                stripped = true;
            }
        }
    }
    match stripped {
        true => message.strip_prefix(' ').unwrap_or(message),
        false => message,
    }
}

/// Whether `group` is print_time()'s seconds and microseconds.
fn is_syslog_time(group: &str) -> bool {
    group.split_once('.').is_some_and(|(seconds, micros)| {
        !seconds.is_empty()
            && seconds.bytes().all(|byte| byte.is_ascii_digit())
            && micros.len() == 6
            && micros.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Whether `group` is print_caller()'s thread or CPU id.
fn is_syslog_caller(group: &str) -> bool {
    group
        .strip_prefix(['T', 'C'])
        .is_some_and(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The records of a kernel log seen so far.
#[derive(Debug, Default)]
struct BootLogScan {
    /// Whether a kernel record is efi_config_parse_tables()'s.
    config_tables: bool,
    /// Whether a kernel record names a usable RT properties table.
    rt_properties: bool,
}

impl BootLogScan {
    /// Takes a record of `priority`, facility << 3 | level, and `message`. Only the kernel logs
    /// facility 0: devkmsg_write() gives a writer's record facility 1 unless it names another,
    /// nonzero one (Linux v6.7 kernel/printk/printk.c).
    fn record(&mut self, priority: u32, message: &str) -> Result<()> {
        if priority >> 3 != 0 {
            return Ok(());
        }
        if message.starts_with(DROPPED_RECORDS) {
            bail!("the kernel lost records of its log: {message:?}");
        }
        if message
            .strip_prefix(CONFIG_TABLES_PREFIX)
            .is_some_and(is_config_table_list)
        {
            self.config_tables = true;
        }
        // Also a part of the record that the kernel logged apart, as it does when another
        // printk() comes between two pr_cont() calls.
        if names_usable_rt_properties(message) {
            self.rt_properties = true;
        }
        Ok(())
    }

    /// What the records say, if they hold efi_config_parse_tables()'s.
    fn finish(self) -> Result<RtPropertiesInBootLog> {
        match (self.config_tables, self.rt_properties) {
            (_, true) => Ok(RtPropertiesInBootLog::Present),
            (true, false) => Ok(RtPropertiesInBootLog::Absent),
            (false, false) => bail!(
                "the kernel log holds no record of the EFI configuration tables, which a log \
                 that lost its oldest records lacks"
            ),
        }
    }
}

/// Whether `list`, a record after "efi: ", is one or more of match_config_table()'s tokens and
/// nothing else: "NAME=0xADDRESS " or "(NAME=0xADDRESS unusable) ", where NAME, such as
/// "ACPI 2.0", has no "=", "(" or ")", and ADDRESS is lowercase hex (%lx).
fn is_config_table_list(list: &str) -> bool {
    let mut rest = list;
    let mut tokens = 0;
    while !rest.is_empty() {
        let (unusable, token) = match rest.strip_prefix('(') {
            Some(token) => (true, token),
            None => (false, rest),
        };
        let Some((name, after)) = token.split_once("=0x") else {
            return false;
        };
        if name.is_empty() || name.contains(['=', '(', ')']) {
            return false;
        }
        let digits = after
            .bytes()
            .take_while(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            .count();
        let end = match unusable {
            true => " unusable) ",
            false => " ",
        };
        let Some(next) = after
            .get(digits..)
            .filter(|_| digits > 0)
            .and_then(|after| after.strip_prefix(end))
        else {
            return false;
        };
        rest = next;
        tokens += 1;
    }
    tokens > 0
}

/// Whether `message` names an RT properties table that Linux applied: "RTPROP=0x" not in a
/// "(RTPROP=0xADDRESS unusable)" token, which Linux v6.3 and later log for a table that they
/// ignore (drivers/firmware/efi/efi.c match_config_table() returns before it records it).
fn names_usable_rt_properties(message: &str) -> bool {
    message
        .match_indices(RT_PROPERTIES_TOKEN)
        .any(|(at, token)| {
            let before = message.get(..at).unwrap_or_default();
            let after = message.get(at + token.len()..).unwrap_or_default();
            let digits = after.bytes().take_while(u8::is_ascii_hexdigit).count();
            let unusable = before.ends_with('(')
                && after
                    .get(digits..)
                    .is_some_and(|after| after.starts_with(" unusable)"));
            !unusable
        })
}

#[cfg(test)]
pub(super) mod fixture {
    use std::io;

    use super::KernelLog;

    /// A kernel log whose syslog(2) reads these lines, or fails with this errno.
    pub(in crate::hii) struct FakeSyslog(pub(in crate::hii) Result<String, i32>);

    impl KernelLog for FakeSyslog {
        fn read_all(&self) -> io::Result<Vec<u8>> {
            self.0
                .clone()
                .map(String::into_bytes)
                .map_err(io::Error::from_raw_os_error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;

    use super::fixture::FakeSyslog;
    use super::*;

    /// efi_config_parse_tables()'s records on the QEMU guests of tests/qemu: Fedora's x86_64
    /// Linux v5.8.15 and v6.5.6 and aarch64 v6.5.6, and Debian's i686 v6.1.27, with OVMF or
    /// AAVMF and an RT properties table.
    const V5_8: &str = "efi: SMBIOS=0x3f988000 ACPI=0x3fb7e000 ACPI 2.0=0x3fb7e014 \
                        MEMATTR=0x3d9fd018 RTPROP=0x3f989998 ";
    const V6_5: &str = "efi: SMBIOS=0x3f988000 ACPI=0x3fb7e000 ACPI 2.0=0x3fb7e014 \
                        MEMATTR=0x3d749018 RTPROP=0x3f989998 INITRD=0x3d743f18 ";
    const AARCH64: &str = "efi: SMBIOS 3.0=0x7fed0000 MEMATTR=0x7d789018 ACPI 2.0=0x7c760018 \
                           RTPROP=0x7ffdd498 INITRD=0x7cb43f18 MEMRESERVE=0x7cb43f98 ";
    const I686: &str = "efi: SMBIOS=0x3f974000 ACPI=0x3fb7e000 ACPI 2.0=0x3fb7e014 \
                        MEMATTR=0x3e11a010 RTPROP=0x3f97f910 INITRD=0x3e114f10 ";
    /// The v6.5 record without the RT properties table.
    const NO_RTPROP: &str = "efi: SMBIOS=0x3f988000 ACPI=0x3fb7e000 ACPI 2.0=0x3fb7e014 \
                             MEMATTR=0x3d742018 INITRD=0x3d744f18 ";
    /// A Xen dom0's record of an RT properties table that Linux v6.3 and later ignore.
    const UNUSABLE: &str = "efi: SMBIOS=0x3f988000 ACPI=0x3fb7e000 (RTPROP=0x3f989998 unusable) ";

    /// The records `messages` as /dev/kmsg returns them, one per read, kernel ones of level 6
    /// unless prefixed with "user:" (facility 1), numbered from `first`, then EAGAIN, or `end`.
    struct Kmsg {
        records: VecDeque<Vec<u8>>,
        end: i32,
    }

    impl Kmsg {
        fn new(first: u64, messages: &[&str], end: i32) -> Self {
            let records = (first..)
                .zip(messages)
                .map(|(seq, message)| {
                    let (priority, message) = match message.strip_prefix("user:") {
                        Some(message) => (14, message),
                        None => (6, *message),
                    };
                    format!("{priority},{seq},1000,-,caller=T1;{message}\n SUBSYSTEM=efi\n")
                        .into_bytes()
                })
                .collect();
            Self { records, end }
        }
    }

    impl Read for Kmsg {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let Some(record) = self.records.pop_front() else {
                return Err(io::Error::from_raw_os_error(self.end));
            };
            buffer
                .get_mut(..record.len())
                .expect("a record that fits")
                .copy_from_slice(&record);
            Ok(record.len())
        }
    }

    /// The boot log of `messages` from record `first` on, through /dev/kmsg.
    fn kmsg_scan(first: u64, messages: &[&str]) -> Result<RtPropertiesInBootLog> {
        scan_kmsg(Kmsg::new(first, messages, libc::EAGAIN))
    }

    /// Records of the consoles decide: a whole record of each kernel names its RT properties
    /// table, and a log without one names none.
    #[test]
    fn kernel_records_of_the_test_guests_decide() {
        for (case, message, want) in [
            ("v5.8", V5_8, RtPropertiesInBootLog::Present),
            ("v6.5", V6_5, RtPropertiesInBootLog::Present),
            ("aarch64", AARCH64, RtPropertiesInBootLog::Present),
            ("i686", I686, RtPropertiesInBootLog::Present),
            ("no RTPROP", NO_RTPROP, RtPropertiesInBootLog::Absent),
        ] {
            let got = kmsg_scan(0, &["Linux version 6.5.6", message, "efi: Remove mem"]);
            assert_eq!(got.ok(), Some(want), "{case}");
        }
    }

    /// Only a usable RTPROP counts: an unusable one alone leaves the table absent, beside a
    /// usable one it is present, and a part of the record that names it apart counts too.
    #[test]
    fn only_a_usable_rt_properties_token_is_present() {
        let usable_and_unusable =
            "efi: ACPI=0x3fb7e000 (RTPROP=0x3f989998 unusable) RTPROP=0x3f989998 ";
        for (case, messages, want) in [
            (
                "unusable only",
                vec![UNUSABLE],
                RtPropertiesInBootLog::Absent,
            ),
            (
                "usable and unusable",
                vec![usable_and_unusable],
                RtPropertiesInBootLog::Present,
            ),
            (
                "a continuation part",
                vec![
                    "efi: SMBIOS=0x3f988000 ACPI=0x3fb7e000 ",
                    "RTPROP=0x3f989998 ",
                ],
                RtPropertiesInBootLog::Present,
            ),
            (
                "a continuation part after a space",
                vec![
                    "efi: SMBIOS=0x3f988000 ",
                    "ACPI=0x3fb7e000 RTPROP=0x3f989998 ",
                ],
                RtPropertiesInBootLog::Present,
            ),
        ] {
            let got = kmsg_scan(0, &messages);
            assert_eq!(got.ok(), Some(want), "{case}");
        }
    }

    /// Records that a writer of /dev/kmsg logs, of a facility other than the kernel's, count for
    /// nothing: neither as the configuration table record nor as an RTPROP.
    #[test]
    fn user_records_are_ignored() {
        let user_config = format!("user:{NO_RTPROP}");
        let user_rtprop = "user:RTPROP=0x3f989998 ";
        assert!(
            kmsg_scan(0, &[&user_config]).is_err(),
            "a user's configuration table record"
        );
        assert_eq!(
            kmsg_scan(0, &[NO_RTPROP, user_rtprop]).ok(),
            Some(RtPropertiesInBootLog::Absent),
            "a user's RTPROP"
        );
    }

    /// A log that lost its oldest records still decides while it keeps the configuration table
    /// record, whose RTPROP comes in or after it, and tells nothing once it lost that record.
    #[test]
    fn a_log_decides_while_it_keeps_the_configuration_table_record() {
        assert_eq!(
            kmsg_scan(5, &[NO_RTPROP, "pci 0000:00:00.0: [8086:29c0]"]).ok(),
            Some(RtPropertiesInBootLog::Absent),
            "first record 5, with the record"
        );
        for (case, message) in [
            ("another record", "pci 0000:00:00.0: [8086:29c0]"),
            (
                "another efi: record",
                "efi: Remove mem31: MMIO range=[0xffc00000-0xffffffff] (4MB) from e820 map",
            ),
        ] {
            let error = kmsg_scan(5, &[message]).expect_err(case);
            assert!(
                error
                    .to_string()
                    .contains("holds no record of the EFI configuration tables"),
                "{case}: {error:#}"
            );
        }
    }

    /// Records lost while uefisettings reads (EPIPE), or that setup_log_buf() reports lost, make
    /// the log tell nothing.
    #[test]
    fn lost_records_tell_nothing() {
        let error = scan_kmsg(Kmsg::new(0, &[NO_RTPROP], libc::EPIPE)).expect_err("EPIPE");
        assert!(error.to_string().contains("overwrote"), "EPIPE: {error:#}");

        let error =
            kmsg_scan(0, &["printk: dropped 3 messages", NO_RTPROP]).expect_err("dropped records");
        assert!(
            error.to_string().contains("printk: dropped 3 messages"),
            "dropped: {error:#}"
        );
    }

    /// Only match_config_table()'s whole grammar after "efi: " is the record.
    #[test]
    fn is_config_table_list_takes_the_whole_grammar_only() {
        for (list, want) in [
            ("SMBIOS 3.0=0x7fed0000 ACPI 2.0=0x7c760018 ", true),
            ("ACPI=0x3fb7e000 (RTPROP=0x3f989998 unusable) ", true),
            ("(RTPROP=0x3f989998 unusable) ", true),
            ("", false),
            ("ACPI=0x3fb7e000", false),
            ("ACPI=0x ", false),
            ("ACPI=0x3FB7E000 ", false),
            ("=0x3fb7e000 ", false),
            ("ACPI=0x3fb7e000 Remove mem", false),
            ("(RTPROP=0x3f989998 unusable ", false),
            ("mem00: [Runtime Data] range=0x3f989000-0x3f98a000 ", false),
            (
                "Remove mem31: MMIO range=[0xffc00000-0xffffffff] (4MB) from e820 map",
                false,
            ),
        ] {
            assert_eq!(is_config_table_list(list), want, "{list:?}");
        }
    }

    /// printk.devkmsg=off makes the kernel refuse /dev/kmsg with EPERM: syslog(2) reads the log
    /// then, and a log there decides as through /dev/kmsg, with or without times and callers.
    #[test]
    fn syslog_reads_the_log_that_devkmsg_off_refuses() {
        let refused = |path: &Path| -> io::Result<Kmsg> {
            assert_eq!(path, Path::new("kmsg"), "the opened path");
            Err(io::Error::from_raw_os_error(libc::EPERM))
        };
        for (case, lines, want) in [
            (
                "times",
                format!("<5>[    0.000000] Linux version 6.5.6\n<6>[    0.000000] {NO_RTPROP}\n"),
                Some(RtPropertiesInBootLog::Absent),
            ),
            (
                "times and callers",
                format!("<6>[    0.000000][    T0] {V6_5}\n"),
                Some(RtPropertiesInBootLog::Present),
            ),
            (
                "no time",
                format!("<6>{NO_RTPROP}\n"),
                Some(RtPropertiesInBootLog::Absent),
            ),
            (
                "a user's record",
                format!("<14>[   10.000000] {NO_RTPROP}\n"),
                None,
            ),
            (
                "a user's RTPROP",
                format!("<6>[    0.000000] {NO_RTPROP}\n<14>[   10.000000] RTPROP=0x1 \n"),
                Some(RtPropertiesInBootLog::Absent),
            ),
        ] {
            let got = rt_properties_in_boot_log(Path::new("kmsg"), refused, &FakeSyslog(Ok(lines)));
            assert_eq!(got.ok(), want, "{case}");
        }
    }

    /// A failed syslog(2) and a refusal of /dev/kmsg other than EPERM tell nothing; syslog(2)
    /// is read only for EPERM.
    #[test]
    fn other_failures_tell_nothing() {
        let error = rt_properties_in_boot_log(
            Path::new("kmsg"),
            |_| -> io::Result<Kmsg> { Err(io::Error::from_raw_os_error(libc::EPERM)) },
            &FakeSyslog(Err(libc::EPERM)),
        )
        .expect_err("syslog(2) refused too");
        assert!(
            format!("{error:#}").contains("Failed to read the kernel log through syslog(2)"),
            "{error:#}"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let missing: PathBuf = dir.path().join("kmsg");
        let error = rt_properties_in_boot_log(
            &missing,
            open_kmsg,
            &FakeSyslog(Ok("<6>[    0.000000] efi: ACPI=0x1 \n".to_owned())),
        )
        .expect_err("a missing /dev/kmsg");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "Failed to open {}: No such file or directory (os error 2)",
                missing.display()
            )
        );
    }

    /// require_char_device takes a character device of the numbers given, and refuses one of
    /// others and a regular file, naming the path and the device it wants.
    #[test]
    fn require_char_device_takes_only_that_device() {
        let null = Path::new("/dev/null");
        let open = || File::open(null).expect("open /dev/null");
        require_char_device(null, open(), libc::makedev(1, 3)).expect("take /dev/null as 1:3");
        let error = require_char_device(null, open(), KMSG_DEVICE).expect_err("/dev/null as 1:11");
        assert_eq!(
            error.to_string(),
            "/dev/null is not the character device 1:11",
            "/dev/null"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("kmsg");
        std::fs::write(&path, format!("6,12,1000,-;{NO_RTPROP}\n")).expect("write the log");
        let file = File::open(&path).expect("open the file");
        let error = require_char_device(&path, file, KMSG_DEVICE).expect_err("a regular file");
        assert_eq!(
            error.to_string(),
            format!("{} is not the character device 1:11", path.display()),
            "a regular file"
        );
    }

    /// open_kmsg reads a file of one record to its end.
    #[test]
    fn open_kmsg_reads_a_file_of_one_record() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("kmsg");
        std::fs::write(&path, format!("6,12,1000,-;{NO_RTPROP}\n")).expect("write the log");

        let got = rt_properties_in_boot_log(&path, open_kmsg, &FakeSyslog(Err(libc::ENOSYS)));

        assert_eq!(got.ok(), Some(RtPropertiesInBootLog::Absent));
    }
}
