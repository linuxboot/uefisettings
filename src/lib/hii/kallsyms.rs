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
//! `\t[MODULE]` after a module's (Linux v6.7 kernel/kallsyms.c s_show()). Its addresses are
//! zeros for a reader without CAP_SYSLOG, unless kernel.kptr_restrict is 0 and
//! kernel.perf_event_paranoid at most 1, and for every reader under kernel.kptr_restrict 2
//! (kernel/ksyms_common.c kallsyms_show_value()).

use std::collections::BTreeSet;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::Path;

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

/// The kernel's symbol table.
pub(super) const KALLSYMS_PATH: &str = "/proc/kallsyms";

/// The function with which upstream Linux 0e8d2444168d (v6.8; stable 5.10.209, 5.15.148,
/// 6.1.75, 6.6.14 and 6.7.2) refuses a read-write efivarfs without a runtime SetVariable()
/// (fs/efivarfs/super.c). The compiler may emit parts or copies of it under its name and a
/// suffix after a dot, such as efivarfs_reconfigure.cold.
const EFIVARFS_RECONFIGURE: &str = "efivarfs_reconfigure";

/// The efivar_operations through which efivarfs calls the runtime services (Linux v5.8 to v6.7
/// drivers/firmware/efi/efi.c generic_ops_register()), unless another efivars_register() caller
/// replaced it (gsmi before v6.3, qcom uefisecapp in v6.7), where a NULL set_variable refuses a
/// write that would not crash; a static variable that kallsyms lists with CONFIG_KALLSYMS_ALL.
/// Modules do not count: sound/pci/hda/patch_hdmi.c names one too.
const GENERIC_OPS: &str = "generic_ops";

/// The suffixes of the functions that generic_ops_register() takes for get_variable,
/// get_next_variable and set_variable from efi, such as virt_efi_get_variable (Linux v6.7
/// drivers/firmware/efi/runtime-wrappers.c) or efi_thunk_set_variable
/// (arch/x86/platform/efi/efi_64.c).
const GET_VARIABLE_SUFFIX: &str = "_get_variable";
const GET_NEXT_VARIABLE_SUFFIX: &str = "_get_next_variable";
const SET_VARIABLE_SUFFIX: &str = "_set_variable";

/// The size of a pointer of the kernel, which reads generic_ops: the kernels whose /proc/kcore
/// this reads are 64-bit.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
const POINTER_SIZE: usize = 8;

/// Whether generic_ops holds a SetVariable(), which efivarfs calls on a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    all(target_arch = "x86", not(test)),
    allow(
        dead_code,
        reason = "uefisettings reads generic_ops only on 64-bit Linux"
    )
)]
pub(super) enum GenericSetVariable {
    /// set_variable is NULL: the kernel left it out without a runtime SetVariable().
    Absent,
    /// set_variable is a `*_set_variable` function.
    Present,
}

/// What one pass over the symbol table finds. Zero addresses count for nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct KernelSymbols {
    /// Whether it names efivarfs_reconfigure or one of its parts, in the kernel or a module.
    pub(super) efivarfs_reconfigure: bool,
    /// The addresses of the kernel's generic_ops.
    generic_ops: BTreeSet<u64>,
    /// The addresses of the kernel's functions of these suffixes.
    get_variable: BTreeSet<u64>,
    get_next_variable: BTreeSet<u64>,
    set_variable: BTreeSet<u64>,
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
            let mut fields = line.split_whitespace();
            let (Some(address), Some(_type), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if name
                .strip_prefix(EFIVARFS_RECONFIGURE)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('.'))
            {
                symbols.efivarfs_reconfigure = true;
            }
            let in_module = fields.next().is_some();
            let address = u64::from_str_radix(address, 16)
                .with_context(|| format!("a symbol address {address:?}"))?;
            // __pfx_ symbols name the padding before a function, which no pointer points at.
            if in_module || address == 0 || name.starts_with("__pfx_") {
                continue;
            }
            let addresses = match name {
                GENERIC_OPS => &mut symbols.generic_ops,
                name if name.ends_with(GET_NEXT_VARIABLE_SUFFIX) => &mut symbols.get_next_variable,
                name if name.ends_with(GET_VARIABLE_SUFFIX) => &mut symbols.get_variable,
                name if name.ends_with(SET_VARIABLE_SUFFIX) => &mut symbols.set_variable,
                _ => continue,
            };
            addresses.insert(address);
        }
        Ok(symbols)
    }

    /// Fails unless the symbol table gives an address of the kernel's generic_ops.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
    pub(super) fn require_generic_ops(&self) -> Result<()> {
        if self.generic_ops.is_empty() {
            bail!(
                "the kernel's symbol table gives no address of generic_ops, which needs \
                 CONFIG_KALLSYMS_ALL, CAP_SYSLOG unless kernel.kptr_restrict is 0 and \
                 kernel.perf_event_paranoid at most 1, and kernel.kptr_restrict below 2"
            );
        }
        Ok(())
    }

    /// Whether the kernel's generic_ops holds a SetVariable(), from its words get_variable,
    /// get_next_variable and set_variable (Linux v5.8 and v6.7 include/linux/efi.h struct
    /// efivar_operations), which `read_words` reads at its address: of the kernel's generic_ops,
    /// the one whose first two words are a `*_get_variable` and a `*_get_next_variable` decides,
    /// by a NULL or a `*_set_variable` third word. Anything else is an error, as a layout that
    /// changed would be.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", test))]
    pub(super) fn generic_set_variable(
        &self,
        mut read_words: impl FnMut(u64, usize) -> Result<Vec<u8>>,
    ) -> Result<GenericSetVariable> {
        self.require_generic_ops()?;
        let mut found = None;
        for &address in &self.generic_ops {
            let bytes = read_words(address, 3 * POINTER_SIZE)?;
            let mut words = bytes
                .chunks_exact(POINTER_SIZE)
                .filter_map(|word| word.try_into().ok().map(u64::from_le_bytes));
            let (Some(get), Some(get_next), Some(set)) = (words.next(), words.next(), words.next())
            else {
                bail!("generic_ops at {address:#x} reads short");
            };
            if !self.get_variable.contains(&get) || !self.get_next_variable.contains(&get_next) {
                continue;
            }
            let set_variable = match set {
                0 => GenericSetVariable::Absent,
                set if self.set_variable.contains(&set) => GenericSetVariable::Present,
                set => bail!(
                    "generic_ops at {address:#x} holds a set_variable {set:#x} that is no \
                     *{SET_VARIABLE_SUFFIX} function"
                ),
            };
            if found.replace(set_variable).is_some() {
                bail!("more than one generic_ops holds runtime services");
            }
        }
        found.with_context(|| {
            format!(
                "no generic_ops holds a *{GET_VARIABLE_SUFFIX} and a *{GET_NEXT_VARIABLE_SUFFIX} \
                 function"
            )
        })
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

    /// The address of generic_ops in GENERIC_OPS_KALLSYMS.
    pub(in crate::hii) const GENERIC_OPS_AT: u64 = 0xffff_ffff_83c1_a2e0;
    /// The functions of GENERIC_OPS_KALLSYMS that generic_ops points at.
    pub(in crate::hii) const GET_VARIABLE_AT: u64 = 0xffff_ffff_81e3_5d70;
    pub(in crate::hii) const GET_NEXT_VARIABLE_AT: u64 = 0xffff_ffff_81e3_5e30;
    pub(in crate::hii) const SET_VARIABLE_AT: u64 = 0xffff_ffff_81e3_5ef0;

    /// A symbol table of Linux v6.5 without efivarfs_reconfigure, with CONFIG_KALLSYMS_ALL, as
    /// root reads it under kernel.kptr_restrict 1, and a module's generic_ops.
    pub(in crate::hii) const GENERIC_OPS_KALLSYMS: &str = "\
ffffffff81000000 T _text
ffffffff81e35d60 t __pfx_virt_efi_get_variable
ffffffff81e35d70 t virt_efi_get_variable
ffffffff81e35e30 t virt_efi_get_next_variable
ffffffff81e35ef0 t virt_efi_set_variable
ffffffff81e35fb0 t virt_efi_set_variable_nb
ffffffff81a1c2d0 t efivarfs_parse_param
ffffffff83c1a2e0 b generic_ops
ffffffffc0a3e1c0 d generic_ops\t[snd_hda_codec_hdmi]
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

    /// The words get_variable, get_next_variable and set_variable.
    fn words(words: [u64; 3]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// One pass collects the kernel's generic_ops and functions of the suffixes, but none of a
    /// module, nor any of a zero address.
    #[test]
    fn scan_collects_the_kernel_addresses_of_generic_ops_and_its_functions() {
        let symbols = KernelSymbols::scan(GENERIC_OPS_KALLSYMS.as_bytes()).expect("scan");
        assert_eq!(
            symbols,
            KernelSymbols {
                efivarfs_reconfigure: false,
                generic_ops: BTreeSet::from([GENERIC_OPS_AT]),
                get_variable: BTreeSet::from([GET_VARIABLE_AT]),
                get_next_variable: BTreeSet::from([GET_NEXT_VARIABLE_AT]),
                set_variable: BTreeSet::from([SET_VARIABLE_AT]),
            }
        );

        let zeroed = GENERIC_OPS_KALLSYMS
            .lines()
            .map(|line| format!("0000000000000000{}\n", &line[16..]))
            .collect::<String>();
        let symbols = KernelSymbols::scan(zeroed.as_bytes()).expect("scan zeros");
        assert_eq!(symbols, KernelSymbols::default(), "zero addresses");
    }

    /// generic_ops decides by its set_variable once its first two words are the runtime
    /// services', and anything else, or no address, tells nothing.
    #[test]
    fn generic_set_variable_reads_generic_ops() {
        let symbols = KernelSymbols::scan(GENERIC_OPS_KALLSYMS.as_bytes()).expect("scan");
        for (case, read, want) in [
            (
                "SetVariable() left out",
                words([GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, 0]),
                Ok(GenericSetVariable::Absent),
            ),
            (
                "SetVariable()",
                words([GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, SET_VARIABLE_AT]),
                Ok(GenericSetVariable::Present),
            ),
            (
                "zeros",
                words([0, 0, 0]),
                Err("no generic_ops holds a *_get_variable and a *_get_next_variable function"),
            ),
            (
                "a foreign get_variable",
                words([GET_NEXT_VARIABLE_AT, GET_NEXT_VARIABLE_AT, 0]),
                Err("no generic_ops holds a *_get_variable and a *_get_next_variable function"),
            ),
            (
                "a foreign set_variable",
                words([GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, GET_VARIABLE_AT]),
                Err(
                    "generic_ops at 0xffffffff83c1a2e0 holds a set_variable 0xffffffff81e35d70 \
                     that is no *_set_variable function",
                ),
            ),
            (
                "a foreign get_next_variable",
                words([GET_VARIABLE_AT, GET_VARIABLE_AT, 0]),
                Err("no generic_ops holds a *_get_variable and a *_get_next_variable function"),
            ),
            (
                "a short read",
                words([GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, 0])[..20].to_vec(),
                Err("generic_ops at 0xffffffff83c1a2e0 reads short"),
            ),
        ] {
            let got = symbols.generic_set_variable(|address, length| {
                assert_eq!((address, length), (GENERIC_OPS_AT, 24), "{case}: the read");
                Ok(read.clone())
            });
            match (got, want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{case}"),
                (Err(error), Err(want)) => assert_eq!(error.to_string(), want, "{case}"),
                (got, want) => panic!("{case}: got {got:?}, want {want:?}"),
            }
        }

        let error = KernelSymbols::default()
            .generic_set_variable(|_, _| panic!("read without an address"))
            .expect_err("no address");
        assert!(
            error.to_string().contains("no address of generic_ops"),
            "{error:#}"
        );
    }

    /// Of two kernel generic_ops, such as a built-in sound/pci/hda/patch_hdmi.c's, the one that
    /// holds the runtime services decides, and two that hold them tell nothing.
    #[test]
    fn generic_set_variable_takes_the_one_generic_ops_of_the_runtime_services() {
        const OTHER_AT: u64 = 0xffff_ffff_83c1_b000;
        let table = format!("{GENERIC_OPS_KALLSYMS}ffffffff83c1b000 d generic_ops\n");
        let symbols = KernelSymbols::scan(table.as_bytes()).expect("scan");
        for (case, other, want) in [
            (
                "a foreign one",
                words([0x1, 0x2, 0x3]),
                Ok(GenericSetVariable::Absent),
            ),
            (
                "two",
                words([GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, SET_VARIABLE_AT]),
                Err("more than one generic_ops holds runtime services"),
            ),
        ] {
            let got = symbols.generic_set_variable(|address, _| match address {
                GENERIC_OPS_AT => Ok(words([GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, 0])),
                OTHER_AT => Ok(other.clone()),
                address => panic!("{case}: read {address:#x}"),
            });
            match (got, want) {
                (Ok(got), Ok(want)) => assert_eq!(got, want, "{case}"),
                (Err(error), Err(want)) => assert_eq!(error.to_string(), want, "{case}"),
                (got, want) => panic!("{case}: got {got:?}, want {want:?}"),
            }
        }
    }

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
