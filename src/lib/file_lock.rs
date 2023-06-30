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

use std::fs::OpenOptions;
use std::os::unix::prelude::IntoRawFd;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::error;
use nix::fcntl::flock;
use nix::fcntl::FlockArg;

pub struct FileLock {
    path: String,
    file_descriptor: i32,
}

impl FileLock {
    pub fn new<T>(file_path: T) -> Self
    where
        T: AsRef<Path> + ToString,
    {
        Self {
            file_descriptor: -1,
            path: file_path.to_string(),
        }
    }

    pub fn lock(&mut self) -> Result<()> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&self.path)
            .context(format!("failed to open or create {}", &self.path))?;

        self.file_descriptor = file.into_raw_fd();

        match flock(self.file_descriptor, FlockArg::LockExclusiveNonblock) {
            Err(_) => {
                return Err(anyhow!(format!(
                    "failed to get lock on fd {} path {}",
                    &self.file_descriptor, &self.path
                )));
            }
            Ok(_) => Ok(()),
        }
    }
}
impl Drop for FileLock {
    fn drop(&mut self) {
        if self.file_descriptor != -1 {
            match flock(self.file_descriptor, FlockArg::UnlockNonblock) {
                Err(error_code) => {
                    error!("file lock unlock failed with error code {}", error_code)
                }
                Ok(_) => {}
            }
        }
    }
}
