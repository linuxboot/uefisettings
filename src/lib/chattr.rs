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

use std::ffi::c_long;
use std::fs::OpenOptions;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::error;

// FS_IOC_SET/GETFLAGS definition https://github.com/torvalds/linux/blob/master/include/uapi/linux/fs.h#L205
const FS_IOC_MAGIC: u8 = b'f';
const FS_IOC_GETFLAGS: u8 = 1;
const FS_IOC_SETFLAGS: u8 = 2;

// full list of flags https://github.com/torvalds/linux/blob/master/include/uapi/linux/fs.h#L239
pub const FS_IMMUTABLE_FL: i32 = 0x00000010; // Immutable file

nix::ioctl_read!(
    ioctl_fs_get_attrs,
    FS_IOC_MAGIC,
    FS_IOC_GETFLAGS,
    ::std::os::raw::c_long
);

nix::ioctl_write_ptr!(
    ioctl_fs_set_attrs,
    FS_IOC_MAGIC,
    FS_IOC_SETFLAGS,
    ::std::os::raw::c_long
);

/// returns all extended fs attributes for the given path as a set of bit flags
pub fn get_all_attrs(path: impl AsRef<Path>) -> Result<i32> {
    let path = path.as_ref();
    let file = OpenOptions::new()
        .write(false)
        .read(true)
        .open(path)
        .context(format!(
            "failed to open {} for attributes reading",
            path.to_string_lossy()
        ))?;
    let fd = file.as_raw_fd();
    let mut attrs: c_long = 0;
    let attrs_ptr = &mut attrs as *mut c_long;

    unsafe {
        ioctl_fs_get_attrs(fd, attrs_ptr).context("ioctl failed")?;
    }

    Ok(attrs as i32)
}

/// writes extended fs attributes for the given path as a set of bit flags
/// all existing attributes will be overwritten
pub fn set_all_attrs(path: impl AsRef<Path>, attrs: i32) -> Result<()> {
    let path = path.as_ref();
    let file = OpenOptions::new()
        .write(false)
        .read(true)
        .open(path)
        .context(format!(
            "failed to open {} for attributes writing",
            path.to_string_lossy()
        ))?;
    let fd = file.as_raw_fd();
    let mut tmp = attrs as c_long;
    let attrs_ptr = &mut tmp as *mut c_long;
    unsafe {
        ioctl_fs_set_attrs(fd, attrs_ptr).context("ioctl failed")?;
    }
    Ok(())
}

/// sets list of extended fs attributes for the given path, preserving others
/// if the attributes are set already produces no effect
/// Ex: set_attrs!("/my/file", FS_IMMUTABLE_FL, FS_NODUMP_FL)
macro_rules! set_attrs {
    ($path:expr, $( $attrs:expr ),*) => {{
        match get_all_attrs($path) {
            Ok(current_attrs) => {
                let mut new_attrs = current_attrs;
                $(
                    new_attrs |= $attrs;
                )*
                set_all_attrs($path, new_attrs)
            }
            Err(err) => Err(err).context("Failed to get attrs before setting them")
        }
    }};
}

/// clears list of extended fs attributes for the given path, preserving others
/// if the attributes are cleared already produces no effect
/// Ex: clear_attrs!("/my/file", FS_IMMUTABLE_FL, FS_NODUMP_FL)
macro_rules! clear_attrs {
    ($path:expr, $( $attrs:expr ),*) => {{
        match get_all_attrs($path) {
            Ok(current_attrs) => {
                let mut new_attrs = current_attrs;
                $(
                    new_attrs &= !$attrs;
                )*
                set_all_attrs($path, new_attrs)
            }
            Err(err) => Err(err).context("Failed to get attrs before setting them")
        }
    }};
}

pub struct EfivarsImmutabilityGuard {
    path: PathBuf,
    attrs_before_writing: i32,
}

impl EfivarsImmutabilityGuard {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self> {
        let path: PathBuf = path.into();
        let attrs_before_writing =
            get_all_attrs(&path).context("cannot obtain store file's extended attributes")?;
        if attrs_before_writing & FS_IMMUTABLE_FL == FS_IMMUTABLE_FL {
            debug!(
                "Clearing immutability attribute for {}",
                path.to_string_lossy()
            );
            clear_attrs!(&path, FS_IMMUTABLE_FL)
                .context("failed to clear immutability attribute")?;
        }
        Ok(Self {
            attrs_before_writing,
            path,
        })
    }
}

impl Drop for EfivarsImmutabilityGuard {
    fn drop(&mut self) {
        if self.attrs_before_writing & FS_IMMUTABLE_FL == FS_IMMUTABLE_FL {
            // it's best effort. We don't want to override an error
            // from the write operation or return the error if write
            // was successful, since it's more important
            // /sys/firmware/efi/efivars/.. is virtual, so all attributes will be
            // restored on reboot/kexec anyway
            debug!(
                "Setting immutability attribute for {}",
                self.path.to_string_lossy()
            );
            let res = set_attrs!(&self.path, FS_IMMUTABLE_FL);
            if let Err(why) = res {
                error!(
                    "failed to set immutability attribute for {} because of {:#}",
                    self.path.to_string_lossy(),
                    why
                );
            }
        }
    }
}
#[cfg(test)]
pub mod tests {
    use anyhow::Context;
    use anyhow::Result;

    use super::*;
    //in the tests we expect that FS_NODUMP_FL is initially cleared, might be a weak assumption..
    pub const FS_NODUMP_FL: i32 = 0x00000040; // do not dump file
    #[test]
    fn test_get_all_attrs() -> Result<()> {
        let test_file = tempfile::NamedTempFile::new().expect("Failed to create test file");
        get_all_attrs(test_file.path()).context("No error expected from get_all_attrs")?;
        // TODO it would be good to compare output with what lsattr is saying
        Ok(())
    }
    #[test]
    fn test_set_all_attrs() -> Result<()> {
        let test_file = tempfile::NamedTempFile::new().expect("Failed to create test file");
        let attrs = get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;
        assert_eq!(attrs & FS_NODUMP_FL, 0);
        let new_attrs = attrs | FS_NODUMP_FL;
        set_all_attrs(test_file.path(), new_attrs).context("No error expected from set_attrs")?;
        let attrs_after_set =
            get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;
        // checking that FS_NODUMP_FL is set
        assert_eq!(attrs_after_set & FS_NODUMP_FL, FS_NODUMP_FL);
        // checking that everything else is still the same
        assert_eq!(attrs_after_set & !FS_NODUMP_FL, attrs & !FS_NODUMP_FL);
        Ok(())
    }
    #[test]
    fn test_set_attrs() -> Result<()> {
        let test_file = tempfile::NamedTempFile::new().expect("Failed to create test file");
        let attrs = get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;
        assert_eq!(attrs & FS_NODUMP_FL, 0);
        set_attrs!(test_file.path(), FS_NODUMP_FL, FS_NODUMP_FL)
            .context("No error expected from set_attrs")?;
        let attrs_after_set =
            get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;

        // checking that FS_NODUMP_FL is set
        assert_eq!(attrs_after_set & FS_NODUMP_FL, FS_NODUMP_FL);
        // checking that everything else is still the same
        assert_eq!(attrs_after_set & !FS_NODUMP_FL, attrs & !FS_NODUMP_FL);
        Ok(())
    }
    #[test]
    fn test_clear_attrs() -> Result<()> {
        let test_file = tempfile::NamedTempFile::new().expect("Failed to create test file");
        let attrs = get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;
        assert_eq!(attrs & FS_NODUMP_FL, 0);
        set_attrs!(test_file.path(), FS_NODUMP_FL, FS_NODUMP_FL)
            .context("No error expected from set_attrs")?;
        let attrs_after_set =
            get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;
        // checking that FS_NODUMP_FL is set
        assert_eq!(attrs_after_set & FS_NODUMP_FL, FS_NODUMP_FL);
        clear_attrs!(test_file.path(), FS_NODUMP_FL, FS_NODUMP_FL)
            .context("No error expected from clear_attrs")?;
        let attrs_after_clear =
            get_all_attrs(test_file.path()).context("No error expected from get_attrs")?;
        // checking that FS_NODUMP_FL is cleared
        assert_eq!(attrs_after_clear & FS_NODUMP_FL, 0);
        // checking that everything else is still the same
        assert_eq!(attrs_after_set & !FS_NODUMP_FL, attrs & !FS_NODUMP_FL);
        Ok(())
    }
}
