use std::fs::File;
use std::os::unix::prelude::IntoRawFd;
use std::path::Path;

use log::error;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
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
        let file = File::open(&self.path).context(format!("failed to open {}", &self.path))?;

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
