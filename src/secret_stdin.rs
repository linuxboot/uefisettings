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

//! The `-` of the secret flags on Linux and Windows: standard input, duplicated into a File of
//! its own, which reads unbuffered, so that no Stdin buffer keeps a copy of the secret.

use std::fs::File;
use std::io;
use std::io::IsTerminal;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(windows)]
use std::os::windows::io::AsHandle;

use anyhow::Context;
use anyhow::Result;
use uefisettings::secret_file::SecretError;
use uefisettings::secret_file::StdinClaim;

/// The claim on standard input that every secret flag of the command shares.
static STDIN: StdinClaim = StdinClaim::new();

/// Standard input, for read_secret_line or read_secret_file to read the secret that a flag naming
/// `-` names. Refuses a terminal, which would echo the secret, and a second `-`.
#[expect(dead_code, reason = "no flag reads a secret from - yet")]
pub(super) fn open_secret_stdin() -> Result<File> {
    claim_stdin_duplicate(&STDIN, &io::stdin())
}

/// A descriptor or handle that duplicates into a File of its own.
trait Duplicate {
    fn duplicate(&self) -> io::Result<File>;
}

#[cfg(unix)]
impl<T: AsFd> Duplicate for T {
    fn duplicate(&self) -> io::Result<File> {
        Ok(File::from(self.as_fd().try_clone_to_owned()?))
    }
}

#[cfg(windows)]
impl<T: AsHandle> Duplicate for T {
    fn duplicate(&self) -> io::Result<File> {
        Ok(File::from(self.as_handle().try_clone_to_owned()?))
    }
}

/// A duplicate of `stdin` under `claim`, unless it is a terminal.
fn claim_stdin_duplicate(claim: &StdinClaim, stdin: &impl Duplicate) -> Result<File> {
    claim.claim()?;
    let file = stdin
        .duplicate()
        .context("cannot duplicate standard input")?;
    match file.is_terminal() {
        true => Err(SecretError::StdinTerminal.into()),
        false => Ok(file),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::io::Read;
    use std::io::Write;

    use super::*;

    /// A pipe that holds `bytes`, its writer closed
    fn pipe_holding(bytes: &[u8]) -> io::PipeReader {
        let (reader, mut writer) = io::pipe().expect("create a pipe");
        writer.write_all(bytes).expect("write into the pipe");
        reader
    }

    fn secret_error(error: &anyhow::Error) -> Option<&SecretError> {
        error.downcast_ref::<SecretError>()
    }

    #[test]
    fn reads_a_pipe_unbuffered() {
        let mut pipe = pipe_holding(b"pw\nrest");
        let mut file = claim_stdin_duplicate(&StdinClaim::new(), &pipe).expect("a pipe");
        let mut first = [0; 1];
        file.read_exact(&mut first)
            .expect("read one byte through the duplicate");
        drop(file);
        let mut left = Vec::new();
        pipe.read_to_end(&mut left).expect("read the pipe");
        assert_eq!(
            (&first[..], &left[..]),
            (&b"p"[..], &b"w\nrest"[..]),
            "the duplicate read one byte and buffered none"
        );
    }

    #[test]
    fn refuses_a_second_dash() {
        let claim = StdinClaim::new();
        claim_stdin_duplicate(&claim, &pipe_holding(b"first")).expect("the first -");
        let mut second = pipe_holding(b"second");
        let error = claim_stdin_duplicate(&claim, &second).expect_err("a second -");
        assert!(
            matches!(secret_error(&error), Some(SecretError::StdinClaimed)),
            "a second -: {error:#}"
        );
        let mut left = Vec::new();
        second.read_to_end(&mut left).expect("read the second pipe");
        assert_eq!(left, b"second", "the second - read nothing");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refuses_a_terminal() {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        use nix::fcntl::OFlag;
        use nix::pty::grantpt;
        use nix::pty::posix_openpt;
        use nix::pty::ptsname_r;
        use nix::pty::unlockpt;

        let controller = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY).expect("open a pty");
        grantpt(&controller).expect("grantpt");
        unlockpt(&controller).expect("unlockpt");
        let terminal = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(OFlag::O_NOCTTY.bits())
            .open(ptsname_r(&controller).expect("ptsname"))
            .expect("open the pty's terminal");
        let error = claim_stdin_duplicate(&StdinClaim::new(), &terminal).expect_err("a terminal");
        assert!(
            matches!(secret_error(&error), Some(SecretError::StdinTerminal)),
            "a terminal: {error:#}"
        );
    }
}
