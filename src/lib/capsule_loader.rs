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

//! Linux's EFI capsule loader, /dev/efi_capsule_loader (Linux v6.11
//! drivers/firmware/efi/capsule-loader.c), which passes a capsule written to it to the firmware's
//! UpdateCapsule().

use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use crate::efi_variables::CapsuleCapabilities;
use crate::efi_variables::CapsuleDelivery;
use crate::efi_variables::JsonCapsule;
use crate::efi_variables::Processing;

/// The device of the loader, which CONFIG_EFI_CAPSULE_LOADER builds.
const CAPSULE_LOADER: &str = "/dev/efi_capsule_loader";

/// The capsule loader at `path`: /dev/efi_capsule_loader, or the tests' stand-in.
pub(crate) struct CapsuleLoader {
    path: PathBuf,
}

impl CapsuleLoader {
    /// This machine's loader.
    pub(crate) fn system() -> Self {
        Self {
            path: PathBuf::from(CAPSULE_LOADER),
        }
    }
}

impl CapsuleDelivery for CapsuleLoader {
    /// After a reset: Linux calls UpdateCapsule() at runtime, where "firmware configuration and
    /// firmware update are not available" (UEFI 2.11 §23.5.1), and makes its next reboot that reset
    /// (Linux v6.11 drivers/firmware/efi/reboot.c efi_reboot(), which x86 reaches by forcing
    /// BOOT_EFI in arch/x86/kernel/reboot.c and arm64 from machine_restart()).
    const PROCESSING: Processing = Processing::AfterReset;

    /// Writes `capsule` to the loader, which takes at most a page per write, asks
    /// QueryCapsuleCapabilities() once it has the EFI_CAPSULE_HEADER, and calls UpdateCapsule()
    /// once it has CapsuleImageSize bytes (capsule-loader.c efi_capsule_write()); it tells its
    /// writer neither MaximumCapsuleSize nor ResetType: a refusal is the write's errno (EINVAL for
    /// EFI_UNSUPPORTED, ENOSPC for EFI_OUT_OF_RESOURCES or a capsule over MaximumCapsuleSize), and
    /// the reset type appears only in the kernel record of a successful upload.
    fn deliver(&self, capsule: &JsonCapsule) -> Result<Option<CapsuleCapabilities>> {
        // no create: a missing loader is no file to make
        let mut loader = match OpenOptions::new().write(true).open(&self.path) {
            Ok(loader) => loader,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CapsuleLoaderAbsent(self.path.clone()).into());
            }
            Err(error) => {
                return Err(error).with_context(|| format!("open {}", self.path.display()));
            }
        };
        write_capsule(&mut loader, capsule).with_context(|| {
            format!(
                "write the capsule to {}, whose refusal the kernel log explains",
                self.path.display()
            )
        })?;
        Ok(None)
    }
}

/// Writes `capsule` to `loader` whole, though the loader takes at most a page per write
/// (capsule-loader.c efi_capsule_write()).
fn write_capsule(loader: &mut impl Write, capsule: &JsonCapsule) -> io::Result<()> {
    loader.write_all(capsule.as_bytes())
}

/// A loader that does not exist: capsule-loader.c registers /dev/efi_capsule_loader only with
/// EFI runtime services (efi_capsule_loader_init()).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "{} does not exist: Linux has no EFI capsule loader without CONFIG_EFI_CAPSULE_LOADER, while \
     its module capsule-loader is not loaded, or without EFI runtime services",
    .0.display()
)]
struct CapsuleLoaderAbsent(PathBuf);

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    /// A device that refuses every write with ENOSPC, as the loader refuses a capsule that the
    /// firmware's QueryCapsuleCapabilities() finds too large or EFI_OUT_OF_RESOURCES (Linux
    /// v6.11 drivers/firmware/efi/capsule.c efi_capsule_supported(), efi.c
    /// efi_status_to_err()).
    const FULL: &str = "/dev/full";

    fn capsule() -> JsonCapsule {
        JsonCapsule::new(b"{\"a\":1}", 9, Processing::AfterReset).expect("make a capsule")
    }

    /// The loader at `path`.
    fn loader(path: &Path) -> CapsuleLoader {
        CapsuleLoader {
            path: path.to_path_buf(),
        }
    }

    /// A capsule goes to the loader whole, with the header that asks for processing after a
    /// reset, and the loader tells no capabilities.
    #[test]
    fn capsule_loader_takes_the_whole_capsule() {
        let dir = tempfile::tempdir().expect("make a directory");
        let path = dir.path().join("efi_capsule_loader");
        fs::write(&path, b"").expect("make the stand-in loader");
        let capsule =
            JsonCapsule::new(&[b'x'; 10000], 9, CapsuleLoader::PROCESSING).expect("make a capsule");

        let capabilities = loader(&path).deliver(&capsule).expect("deliver a capsule");

        assert_eq!(capabilities, None, "capabilities");
        assert_eq!(
            fs::read(&path).expect("read the stand-in loader"),
            capsule.as_bytes(),
            "written"
        );
        assert_eq!(
            capsule.as_bytes().get(20..24),
            Some(&[0, 0, 1, 0][..]),
            "CAPSULE_FLAGS_PERSIST_ACROSS_RESET"
        );
    }

    /// The PAGE_SIZE of a kernel of 4 KiB pages, the most that efi_capsule_write() takes per
    /// write.
    const PAGE_SIZE: usize = 4096;

    /// A writer that takes at most a page per write, as efi_capsule_write() does, and records
    /// each write.
    struct PageWrites(Vec<Vec<u8>>);

    impl Write for PageWrites {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let page = buf.get(..PAGE_SIZE).unwrap_or(buf);
            self.0.push(page.to_vec());
            Ok(page.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A capsule larger than a page reaches the loader whole, a page per write.
    #[test]
    fn capsule_loader_takes_a_capsule_a_page_per_write() {
        let capsule =
            JsonCapsule::new(&[b'x'; 10000], 9, CapsuleLoader::PROCESSING).expect("make a capsule");
        let mut loader = PageWrites(Vec::new());

        write_capsule(&mut loader, &capsule).expect("write a capsule");

        assert_eq!(
            loader.0.iter().map(Vec::len).collect::<Vec<_>>(),
            [PAGE_SIZE, PAGE_SIZE, 1848],
            "writes"
        );
        assert_eq!(loader.0.concat(), capsule.as_bytes(), "written");
    }

    /// A missing loader is named as absent, and delivery makes no file there.
    #[test]
    fn capsule_loader_names_its_absence_and_makes_no_file() {
        let dir = tempfile::tempdir().expect("make a directory");
        let path = dir.path().join("efi_capsule_loader");

        let error = loader(&path)
            .deliver(&capsule())
            .expect_err("deliver to a missing loader");

        assert_eq!(
            error.to_string(),
            format!(
                "{} does not exist: Linux has no EFI capsule loader without \
                 CONFIG_EFI_CAPSULE_LOADER, while its module capsule-loader is not loaded, or \
                 without EFI runtime services",
                path.display()
            ),
            "error"
        );
        assert!(!path.exists(), "{} made", path.display());
        assert_eq!(
            CapsuleLoader::system().path,
            Path::new("/dev/efi_capsule_loader"),
            "the system loader"
        );
    }

    /// A loader that cannot be opened or written is named with the OS error.
    #[test]
    fn capsule_loader_names_its_open_and_write_errors() {
        let dir = tempfile::tempdir().expect("make a directory");

        let open = loader(dir.path())
            .deliver(&capsule())
            .expect_err("deliver to a directory");
        let write = loader(Path::new(FULL))
            .deliver(&capsule())
            .expect_err("deliver to a full device");

        assert_eq!(
            format!("{open:#}"),
            format!(
                "open {}: Is a directory (os error 21)",
                dir.path().display()
            ),
            "open"
        );
        assert_eq!(
            format!("{write:#}"),
            "write the capsule to /dev/full, whose refusal the kernel log explains: No space \
             left on device (os error 28)",
            "write"
        );
    }
}
