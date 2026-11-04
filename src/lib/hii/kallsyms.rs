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

//! /proc/kallsyms, the kernel's symbol table: one `ADDRESS TYPE NAME` line per symbol, with
//! `\t[MODULE]` after a module's (Linux v6.7 kernel/kallsyms.c s_show()).

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;

/// The kernel's symbol table.
pub(super) const KALLSYMS_PATH: &str = "/proc/kallsyms";

/// The function with which upstream Linux 0e8d2444168d (v6.8; stable 5.10.209, 5.15.148,
/// 6.1.75, 6.6.14 and 6.7.2) refuses a read-write efivarfs without a runtime SetVariable()
/// (fs/efivarfs/super.c). The compiler may emit parts or copies of it under its name and a
/// suffix after a dot, such as efivarfs_reconfigure.cold.
const EFIVARFS_RECONFIGURE: &str = "efivarfs_reconfigure";

/// What one pass over the symbol table finds.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct KernelSymbols {
    /// Whether it names efivarfs_reconfigure or one of its parts, in the kernel or a module.
    pub(super) efivarfs_reconfigure: bool,
}

impl KernelSymbols {
    /// The symbols of the symbol table at `path`.
    pub(super) fn read(path: &Path) -> Result<Self> {
        let file =
            File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
        Self::scan(BufReader::new(file))
            .with_context(|| format!("Failed to read {}", path.display()))
    }

    /// The symbols of the symbol table `table`.
    fn scan(table: impl BufRead) -> Result<Self> {
        let mut symbols = Self::default();
        for line in table.lines() {
            let line = line?;
            let Some(name) = line.split_whitespace().nth(2) else {
                continue;
            };
            if name
                .strip_prefix(EFIVARFS_RECONFIGURE)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.'))
            {
                symbols.efivarfs_reconfigure = true;
            }
        }
        Ok(symbols)
    }
}

/// Symbol tables for the tests.
#[cfg(test)]
pub(super) mod fixture {
    use std::path::Path;

    /// A symbol table of Linux v6.17 with efivarfs_reconfigure built in, as kptr_restrict 2 shows
    /// it, without addresses.
    pub(in crate::hii) const FIXED_KALLSYMS: &str = "\
0000000000000000 T _text
0000000000000000 t __pfx_efivarfs_reconfigure
0000000000000000 t efivarfs_reconfigure
0000000000000000 t efivarfs_parse_param
";

    /// A symbol table without efivarfs_reconfigure.
    pub(in crate::hii) const UNFIXED_KALLSYMS: &str = "\
ffffffff81000000 T _text
ffffffff81a1c2d0 t efivarfs_parse_param
ffffffff81a1c3b0 t efivarfs_fill_super
";

    /// Writes the symbol table `table` at `path`.
    pub(in crate::hii) fn write_kallsyms(path: &Path, table: &str) {
        std::fs::write(path, table).expect("write the symbol table");
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    /// efivarfs_reconfigure counts built in, in a module, and as a part with a suffix after a
    /// dot, with or without addresses; a name that only contains it or starts with it does not.
    #[test]
    fn scan_finds_efivarfs_reconfigure_and_its_parts_only() {
        for (case, table, want) in [
            ("built in", FIXED_KALLSYMS, true),
            (
                "in a module",
                "f8a1c2d0 t efivarfs_reconfigure\t[efivarfs]\n",
                true,
            ),
            (
                "a cold part",
                "ffffffff81a1c2d0 t efivarfs_reconfigure.cold\n",
                true,
            ),
            (
                "an LLVM copy",
                "ffffffff81a1c2d0 t efivarfs_reconfigure.llvm.1234\n",
                true,
            ),
            (
                "its __pfx_ alone",
                "ffffffff81a1c2c0 t __pfx_efivarfs_reconfigure\n",
                false,
            ),
            (
                "a near miss",
                "ffffffff81a1c2d0 t efivarfs_reconfigure_ro\n",
                false,
            ),
            ("without it", UNFIXED_KALLSYMS, false),
            ("empty", "", false),
        ] {
            let symbols = KernelSymbols::scan(table.as_bytes()).expect(case);

            assert_eq!(symbols.efivarfs_reconfigure, want, "{case}");
        }
    }

    #[test]
    fn read_reads_the_file_and_refuses_a_missing_one() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("kallsyms");
        write_kallsyms(&path, FIXED_KALLSYMS);
        assert!(
            KernelSymbols::read(&path)
                .expect("read the symbol table")
                .efivarfs_reconfigure,
            "the fixed symbol table"
        );

        let missing = dir.path().join("missing");
        let error = KernelSymbols::read(&missing).expect_err("read a missing symbol table");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "Failed to open {}: No such file or directory (os error 2)",
                missing.display()
            )
        );
    }
}
