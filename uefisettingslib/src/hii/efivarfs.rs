// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

use std::process::Command;

use anyhow::Result;
use log::error;

pub struct EfivarsMountGuard;

impl EfivarsMountGuard {
    pub fn mount(&self) -> Result<()> {
        Command::new("mount")
            .arg("-o")
            .arg("remount,rw")
            .arg("efivarfs")
            .output()?;

        Ok(())
    }
}

impl Drop for EfivarsMountGuard {
    fn drop(&mut self) {
        // efivarfs being rw is scary. We should unmount it ASAP.
        // If efivarfs is set as ro in fstab (the ideal), "remount" along will change it back.

        let res = Command::new("mount")
            .arg("-o")
            .arg("remount,ro")
            .arg("efivarfs")
            .output();

        if let Err(why) = res {
            error!("failed to remount efivarfs because {}", why);
        }
    }
}
