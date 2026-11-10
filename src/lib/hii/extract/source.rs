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

//! Which methods read this machine's HII database on Linux: one that the caller names, or each in
//! the automatic order, which moves on while a method finds its source absent or fails otherwise,
//! and stops at a refusal.

use std::fmt;
use std::io;

use log::debug;
use log::warn;
use thiserror::Error;

use super::EfivarMemory;
use crate::hii::memory_access_denied::MemoryAccessDenied;
use crate::unsafe_operations::UnsafeOperationRefused;

/// A way in which the Linux build reads this machine's HII database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HiiMethod {
    /// The vendor ACPI tables QHII and HIID in /sys/firmware/acpi/tables, which need no /dev/mem.
    Acpi,
    /// The OCP HiiDB variable in efivarfs, and the memory that it points to in /dev/mem, inside
    /// the memory that EfivarMemory names.
    Efivar,
    /// The HII database export that the EFI System Table lists as the configuration table of
    /// EFI_HII_DATABASE_PROTOCOL_GUID (UEFI 2.11 §33.2.11.1, §4.6.5), in /dev/mem.
    Systab,
}

impl HiiMethod {
    /// The automatic order: first the vendor ACPI tables, which need no /dev/mem and so read under
    /// kernel lockdown too, then the OCP HiiDB variable, then the configuration table.
    pub const AUTOMATIC_ORDER: [Self; 3] = [Self::Acpi, Self::Efivar, Self::Systab];
}

impl fmt::Display for HiiMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Acpi => "acpi",
            Self::Efivar => "efivar",
            Self::Systab => "systab",
        })
    }
}

/// Which methods read this machine's HII database.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HiiSource {
    /// Each of HiiMethod::AUTOMATIC_ORDER in turn, until one reads the database or is refused
    /// (HiiMethodError::Refused).
    #[default]
    Auto,
    /// This method only.
    Method(HiiMethod),
}

impl HiiSource {
    /// The methods to try, in order.
    pub(super) fn methods(&self) -> &[HiiMethod] {
        match self {
            Self::Auto => &HiiMethod::AUTOMATIC_ORDER,
            Self::Method(method) => std::slice::from_ref(method),
        }
    }
}

/// How the Linux build reads this machine's HII database.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct HiiSourceOptions {
    /// The methods.
    pub source: HiiSource,
    /// The memory that HiiMethod::Efivar reads.
    pub efivar_memory: EfivarMemory,
}

/// Why a method gave no HII database. The method's own error comes with it, whose type tells
/// more, such as MemoryAccessDenied, HiiDbVariableAbsent or HiiExportError.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HiiMethodError {
    /// The method's source does not exist: the firmware does not publish its HII database this
    /// way.
    #[error("absent: {0:#}")]
    Absent(anyhow::Error),
    /// The kernel or a file's permissions refused a read that the method needs: kernel lockdown,
    /// the kernel's checks of /dev/mem or /proc/kcore (MemoryAccessDenied), or a file that this
    /// user may not read; or UnsafeOperations refused it (UnsafeOperationRefused). The automatic
    /// order stops here, so that no later method reads around what the administrator or the
    /// kernel refused.
    #[error("refused: {0:#}")]
    Refused(anyhow::Error),
    /// Anything else: the source holds no HII database that uefisettings reads, or what the
    /// method needs to read it is missing or fails.
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

impl HiiMethodError {
    /// The method's own error.
    pub fn error(&self) -> &anyhow::Error {
        match self {
            Self::Absent(error) | Self::Refused(error) | Self::Failed(error) => error,
        }
    }

    /// `error`, of a method whose source exists: Refused if any of its layers is a refusal.
    pub(super) fn of_present(error: anyhow::Error) -> Self {
        match is_refusal(&error) {
            true => Self::Refused(error),
            false => Self::Failed(error),
        }
    }
}

/// Whether `error` says that the kernel or a file's permissions refused a read: a
/// MemoryAccessDenied, or EACCES or EPERM in any of its layers; or that UnsafeOperations refused
/// it, an UnsafeOperationRefused.
fn is_refusal(error: &anyhow::Error) -> bool {
    error.is::<MemoryAccessDenied>()
        || error.is::<UnsafeOperationRefused>()
        || error.chain().any(|cause| {
            cause
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::PermissionDenied)
        })
}

/// No method gave the HII database: each that was tried, in order, with why.
#[derive(Debug, Error)]
#[non_exhaustive]
pub struct NoHiiDatabase {
    pub tried: Vec<(HiiMethod, HiiMethodError)>,
}

impl fmt::Display for NoHiiDatabase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no HII database: ")?;
        for (index, (method, error)) in self.tried.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{method}: {error}")?;
        }
        Ok(())
    }
}

/// The HII database that the first of `source`'s methods reads with `read`, trying the next only
/// after one that is not refused; logs at debug level which method gave it, and at warn level
/// each method before it that failed, which the CLI prints where RUST_LOG admits warn:
/// env_logger prints errors only where RUST_LOG is unset.
pub(super) fn read_through(
    source: &HiiSource,
    mut read: impl FnMut(HiiMethod) -> Result<Vec<u8>, HiiMethodError>,
) -> Result<Vec<u8>, NoHiiDatabase> {
    let mut tried = Vec::new();
    for &method in source.methods() {
        let error = match read(method) {
            Ok(db) => {
                for (failed, error) in &tried {
                    if let HiiMethodError::Failed(error) = error {
                        warn!(
                            "HII database: the {method} method read it after the {failed} \
                             method failed: {error:#}"
                        );
                    }
                }
                debug!("HII database: read by the {method} method");
                return Ok(db);
            }
            Err(error) => error,
        };
        debug!("HII database: the {method} method: {error}");
        let refused = matches!(error, HiiMethodError::Refused(_));
        tried.push((method, error));
        if refused {
            break;
        }
    }
    Err(NoHiiDatabase { tried })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use anyhow::anyhow;

    use super::*;
    use crate::hii::config_snapshot::tests::leveled_by;
    use crate::hii::lockdown::LockdownMode;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryDevice;
    use crate::hii::memory_access_denied::MemoryOperation;
    use crate::unsafe_operations::UnsafeOperation;

    /// What a fake method gives.
    #[derive(Debug, Clone, Copy)]
    enum Outcome {
        Database,
        Absent,
        Refused,
        Failed,
    }

    /// read_through of `source` by methods that give `outcomes`, in AUTOMATIC_ORDER: what it
    /// gives, and the methods asked.
    fn read_with(
        source: HiiSource,
        outcomes: [Outcome; 3],
    ) -> (Result<Vec<u8>, NoHiiDatabase>, Vec<HiiMethod>) {
        let asked = RefCell::new(Vec::new());
        let result = read_through(&source, |method| {
            asked.borrow_mut().push(method);
            let index = HiiMethod::AUTOMATIC_ORDER
                .iter()
                .position(|&known| known == method)
                .expect("a known method");
            match outcomes[index] {
                Outcome::Database => Ok(method.to_string().into_bytes()),
                Outcome::Absent => Err(HiiMethodError::Absent(anyhow!("no {method} source"))),
                Outcome::Refused => Err(HiiMethodError::Refused(anyhow!("{method} refused"))),
                Outcome::Failed => Err(HiiMethodError::Failed(anyhow!("{method} failed"))),
            }
        });
        (result, asked.into_inner())
    }

    /// The automatic order reads with the first method that gives the database, past those whose
    /// source is absent or that fail otherwise.
    #[test]
    fn auto_moves_past_absent_and_failed_methods() {
        use HiiMethod::*;
        use Outcome::*;
        for (outcomes, want, asked) in [
            ([Database, Database, Database], "acpi", vec![Acpi]),
            ([Absent, Database, Database], "efivar", vec![Acpi, Efivar]),
            ([Failed, Database, Database], "efivar", vec![Acpi, Efivar]),
            (
                [Absent, Absent, Database],
                "systab",
                vec![Acpi, Efivar, Systab],
            ),
            (
                [Failed, Failed, Database],
                "systab",
                vec![Acpi, Efivar, Systab],
            ),
        ] {
            let (result, got_asked) = read_with(HiiSource::Auto, outcomes);

            let db = result.unwrap_or_else(|error| panic!("{outcomes:?}: {error}"));
            assert_eq!(db, want.as_bytes(), "{outcomes:?}");
            assert_eq!(got_asked, asked, "{outcomes:?}: asked");
        }
    }

    /// What `f` gives, and the records that it logs at debug level and above, as "LEVEL message",
    /// through the crate's one test logger (leveled_by).
    fn captured<T>(f: impl FnOnce() -> T) -> (T, Vec<String>) {
        let mut got = None;
        let records = leveled_by(|| got = Some(f()))
            .into_iter()
            .filter(|(level, _)| *level <= log::Level::Debug)
            .map(|(level, message)| format!("{level} {message}"))
            .collect();
        (got.expect("captured runs f"), records)
    }

    /// Where the automatic order reads the database past a method that failed, it warns of that
    /// method with its error; past an absent method, and where no method reads the database, it
    /// logs at debug level only.
    #[test]
    fn auto_warns_of_each_failed_method_that_it_reads_past() {
        use Outcome::*;
        for (outcomes, want) in [
            (
                [Failed, Database, Database],
                vec![
                    "DEBUG HII database: the acpi method: acpi failed",
                    "WARN HII database: the efivar method read it after the acpi method failed: \
                     acpi failed",
                    "DEBUG HII database: read by the efivar method",
                ],
            ),
            (
                [Failed, Absent, Database],
                vec![
                    "DEBUG HII database: the acpi method: acpi failed",
                    "DEBUG HII database: the efivar method: absent: no efivar source",
                    "WARN HII database: the systab method read it after the acpi method failed: \
                     acpi failed",
                    "DEBUG HII database: read by the systab method",
                ],
            ),
            (
                [Failed, Failed, Database],
                vec![
                    "DEBUG HII database: the acpi method: acpi failed",
                    "DEBUG HII database: the efivar method: efivar failed",
                    "WARN HII database: the systab method read it after the acpi method failed: \
                     acpi failed",
                    "WARN HII database: the systab method read it after the efivar method failed: \
                     efivar failed",
                    "DEBUG HII database: read by the systab method",
                ],
            ),
            (
                [Absent, Database, Database],
                vec![
                    "DEBUG HII database: the acpi method: absent: no acpi source",
                    "DEBUG HII database: read by the efivar method",
                ],
            ),
            (
                [Failed, Failed, Absent],
                vec![
                    "DEBUG HII database: the acpi method: acpi failed",
                    "DEBUG HII database: the efivar method: efivar failed",
                    "DEBUG HII database: the systab method: absent: no systab source",
                ],
            ),
            (
                [Failed, Refused, Database],
                vec![
                    "DEBUG HII database: the acpi method: acpi failed",
                    "DEBUG HII database: the efivar method: refused: efivar refused",
                ],
            ),
        ] {
            let (_, records) = captured(|| read_with(HiiSource::Auto, outcomes));

            assert_eq!(records, want, "{outcomes:?}");
        }
    }

    /// The automatic order stops at a refused method, and its error names each method that it
    /// tried, in order, with why.
    #[test]
    fn auto_stops_at_a_refusal_and_names_each_method_tried() {
        use Outcome::*;
        for (outcomes, want) in [
            (
                [Refused, Database, Database],
                "no HII database: acpi: refused: acpi refused",
            ),
            (
                [Absent, Refused, Database],
                "no HII database: acpi: absent: no acpi source; efivar: refused: efivar refused",
            ),
            (
                [Failed, Absent, Refused],
                "no HII database: acpi: acpi failed; efivar: absent: no efivar source; systab: \
                 refused: systab refused",
            ),
            (
                [Absent, Absent, Absent],
                "no HII database: acpi: absent: no acpi source; efivar: absent: no efivar \
                 source; systab: absent: no systab source",
            ),
        ] {
            let (result, _) = read_with(HiiSource::Auto, outcomes);

            let error = result.expect_err("read no database");
            assert_eq!(error.to_string(), want, "{outcomes:?}");
        }
    }

    /// A named method is the only one tried, whatever it gives.
    #[test]
    fn a_named_method_is_the_only_one_tried() {
        use Outcome::*;
        for method in HiiMethod::AUTOMATIC_ORDER {
            let (result, asked) = read_with(HiiSource::Method(method), [Absent; 3]);

            let error = result.expect_err("read no database");
            assert_eq!(asked, [method], "{method}");
            assert_eq!(
                error.to_string(),
                format!("no HII database: {method}: absent: no {method} source"),
                "{method}"
            );

            let (result, asked) = read_with(HiiSource::Method(method), [Database; 3]);
            assert_eq!(
                result.ok(),
                Some(method.to_string().into_bytes()),
                "{method}"
            );
            assert_eq!(asked, [method], "{method}");
        }
    }

    /// A refusal is a MemoryAccessDenied, as kernel lockdown and the kernel's checks of /dev/mem
    /// give, EACCES or EPERM, or an UnsafeOperationRefused, under any context; other errors are
    /// not.
    #[test]
    fn of_present_tells_a_refusal() {
        let denied = || MemoryAccessDenied {
            device: MemoryDevice::DevMem,
            operation: MemoryOperation::Open,
            cause: DenialCause::Lockdown(LockdownMode::Integrity),
        };
        let io_error = |kind: io::ErrorKind| anyhow::Error::new(io::Error::from(kind));
        for (case, error, refused) in [
            ("a refusal", anyhow::Error::new(denied()), true),
            (
                "a refusal under a context",
                anyhow::Error::new(denied()).context("Failed to read"),
                true,
            ),
            (
                "a refusal as a context",
                anyhow!("EPERM").context(denied()).context("Failed to read"),
                true,
            ),
            (
                "a permission error under a context",
                io_error(io::ErrorKind::PermissionDenied).context("Failed to open"),
                true,
            ),
            (
                "a missing file",
                io_error(io::ErrorKind::NotFound).context("Failed to open"),
                false,
            ),
            ("an invalid database", anyhow!("not an HII database"), false),
            (
                "an unsafe operation refused under a context",
                anyhow::Error::new(UnsafeOperationRefused {
                    operation: UnsafeOperation::SetupPassword,
                })
                .context("Failed to read"),
                true,
            ),
        ] {
            let got = HiiMethodError::of_present(error);

            assert_eq!(
                matches!(got, HiiMethodError::Refused(_)),
                refused,
                "{case}: {got:?}"
            );
        }
    }
}
