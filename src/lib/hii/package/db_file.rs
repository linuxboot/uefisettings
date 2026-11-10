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

//! HiiDB files, which the Linux, macOS and Windows builds read with -f, and the HiiDB of an
//! efivars dump, which the Linux and macOS builds read.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use log::debug;
use thiserror::Error;

pub(crate) use super::MAX_ALLOWED_FILESIZE;

/// The HiiDB in the file at `path`.
pub(crate) fn read_db_file(path: &Path) -> Result<Vec<u8>> {
    debug!("HII database file: {}", path.display());

    let mut file = File::open(path)
        .with_context(|| format!("failed to open HiiDB file '{}'", path.display()))?;
    read_db_bytes(&mut file)
        .with_context(|| format!("failed to read HiiDB file '{}'", path.display()))
}

/// The HiiDB in `file`.
pub(crate) fn read_db_bytes(file: &mut File) -> Result<Vec<u8>> {
    // Most Hii DBs are a few hundred kilobytes in size and the largest we've seen so far is close to 3 MB.
    // Since we're reading the entire DB into a Vec<u8> we need to have a check here.
    if file
        .metadata()
        .context("failed to read metadata for open file")?
        .len()
        > MAX_ALLOWED_FILESIZE
    {
        return Err(DbFileTooBig.into());
    }

    let mut file_contents = Vec::new();
    // one byte past the maximum, so that a file that grew past it since the check above shows
    let mut file = Read::take(&mut *file, MAX_ALLOWED_FILESIZE + 1);
    file.read_to_end(&mut file_contents)
        .context("Couldn't convert file bytes to Vec<u8>")?;
    if file.limit() == 0 {
        return Err(DbFileTooBig.into());
    }

    Ok(file_contents)
}

/// read_db_bytes's error for a file of more than MAX_ALLOWED_FILESIZE bytes.
#[derive(Debug, Error)]
#[error("longer than its maximum of {MAX_ALLOWED_FILESIZE} bytes")]
pub(in crate::hii) struct DbFileTooBig;

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::fs;
    use std::io;

    use super::*;

    /// A missing HiiDB file fails to open with an error that names it.
    #[test]
    fn missing_file_error_names_its_path() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("missing.bin");

        let error = read_db_file(&path).expect_err("read a missing HiiDB file");

        let chain = format!("{error:#}");
        assert!(
            chain.contains(&format!("failed to open HiiDB file '{}'", path.display())),
            "missing file: {chain}"
        );
        assert_eq!(
            error.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::NotFound),
            "missing file: {chain}"
        );
    }

    /// A HiiDB file whose metadata gives more than MAX_ALLOWED_FILESIZE bytes is refused with an
    /// error that names the file and the maximum.
    #[test]
    fn file_longer_than_the_maximum_is_refused() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("hiidb.bin");
        File::create(&path)
            .and_then(|file| file.set_len(MAX_ALLOWED_FILESIZE + 1))
            .expect("create a file one byte longer than the maximum");

        let error = read_db_file(&path).expect_err("read a file past the maximum");

        assert_eq!(
            (format!("{error:#}"), error.is::<DbFileTooBig>()),
            (
                format!(
                    "failed to read HiiDB file '{}': longer than its maximum of \
                     {MAX_ALLOWED_FILESIZE} bytes",
                    path.display()
                ),
                true
            ),
            "a file one byte longer than the maximum"
        );
    }

    /// A HiiDB file that fails to read, a directory here, gives an error that names the file and
    /// the read before the system's error. Unix only: File::open opens no directory on Windows,
    /// whose CreateFileW needs FILE_FLAG_BACKUP_SEMANTICS for one.
    #[cfg(unix)]
    #[test]
    fn failed_read_names_the_file_and_the_read() {
        let dir = tempfile::tempdir().expect("create a directory");

        let error = read_db_file(dir.path()).expect_err("read a directory as a HiiDB file");

        assert_eq!(
            (
                error.chain().next().map(|cause| cause.to_string()),
                error.downcast_ref::<io::Error>().map(io::Error::kind)
            ),
            (
                Some(format!(
                    "failed to read HiiDB file '{}'",
                    dir.path().display()
                )),
                Some(io::ErrorKind::IsADirectory)
            ),
            "a directory"
        );
    }

    /// read_db_bytes refuses a file of more than MAX_ALLOWED_FILESIZE bytes by its metadata,
    /// unread: a read of this write-only handle would fail. Unix only: fstat(2) needs no read
    /// access.
    #[cfg(unix)]
    #[test]
    fn read_db_bytes_refuses_a_long_file_unread() {
        let dir = tempfile::tempdir().expect("create a directory");
        let mut file = File::create(dir.path().join("hiidb.bin")).expect("create a file");
        file.set_len(MAX_ALLOWED_FILESIZE + 1)
            .expect("make the file one byte longer than the maximum");

        let error = read_db_bytes(&mut file).expect_err("read a write-only long file");

        assert!(
            error.is::<DbFileTooBig>(),
            "a write-only long file: {error:#}"
        );
    }

    /// A file of more than MAX_ALLOWED_FILESIZE bytes whose metadata says less, as a FIFO's does,
    /// is read one byte past the maximum and refused.
    #[cfg(unix)]
    #[test]
    fn read_db_bytes_reads_no_more_than_its_maximum() {
        let dir = tempfile::tempdir().expect("create a directory");
        let max = usize::try_from(MAX_ALLOWED_FILESIZE).expect("a usize maximum");
        for (case, length, fits) in [
            ("a FIFO of the maximum size", max, true),
            ("a FIFO one byte longer than the maximum", max + 1, false),
        ] {
            let fifo = dir.path().join(length.to_string());
            nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).expect("create a FIFO");

            let read = std::thread::scope(|scope| {
                scope.spawn(|| fs::write(&fifo, vec![0x5A; length]).expect("write the FIFO"));
                read_db_bytes(&mut File::open(&fifo).expect("open the FIFO"))
            });

            match (read, fits) {
                (Ok(bytes), true) => assert_eq!(bytes.len(), length, "{case}: length"),
                (Err(error), false) => assert_eq!(
                    error.to_string(),
                    format!("longer than its maximum of {MAX_ALLOWED_FILESIZE} bytes"),
                    "{case}"
                ),
                (read, _) => panic!("{case}: read {:?} bytes", read.map(|bytes| bytes.len())),
            }
        }
    }
}
