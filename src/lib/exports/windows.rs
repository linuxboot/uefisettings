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

//! The exports that only the Windows build has: those that read the HiiDB of this machine
//! through the HiiDB driver and its variables through the firmware environment calls.

use std::path::Path;

use anyhow::Result;

use super::CapsuleBackend;
use super::HiiBackend;
use super::VariableBackend;
use crate::efi_variables::VariableData;
use crate::efi_variables::VariableInfoSource;
use crate::firmware_width::FirmwareWidth;
use crate::hii::package::db_file;
use crate::hii::read_hiidb;
use crate::hii::EfivarSource;
use crate::hii::FirmwareEnvironment;
use crate::hii::FirmwareVariables;
use crate::hii::RealFirmwareEnvironmentCalls;
use crate::hii::VariableReach;

/// What set and get read and write when no file names them: this machine's HiiDB, through
/// the HiiDB driver, and its firmware environment variables.
impl HiiBackend {
    /// This machine's HiiDB, through the HiiDB driver.
    pub(super) fn system_hiidb() -> Result<Vec<u8>> {
        read_hiidb()
    }

    /// This machine's firmware environment variables.
    pub(super) fn system_variables() -> Result<impl FirmwareVariables> {
        FirmwareEnvironment::new()
    }
}

/// What the variable commands read: this machine's firmware environment variables.
impl VariableBackend {
    /// The attributes and sizes of this machine's firmware environment variables.
    pub(super) fn system_variable_info() -> Result<impl VariableInfoSource> {
        FirmwareEnvironment::new()
    }

    /// What system_variable_data reaches.
    pub(super) const SYSTEM_VARIABLE_REACH: VariableReach =
        FirmwareEnvironment::<RealFirmwareEnvironmentCalls>::REACH;

    /// The attributes and data of this machine's firmware environment variables.
    pub(super) fn system_variable_data() -> Result<impl VariableData> {
        FirmwareEnvironment::new()
    }
}

/// What the capsule commands read: this machine's firmware environment variables.
impl CapsuleBackend {
    /// The width of this machine's firmware, taken to be this build's: "The 64-bit version of
    /// Windows PE can boot 64-bit UEFI and BIOS PCs", and its 32-bit version 32-bit UEFI PCs
    /// (learn.microsoft.com/windows-hardware/manufacture/desktop/winpe-intro), and uefisettings
    /// builds for Windows on x86_64 and aarch64 only (Makefile TARGETS). It is wrong for an i686
    /// build under WOW64 and for 64-bit Windows on 32-bit UEFI.
    pub(super) fn system_firmware_width() -> Result<FirmwareWidth> {
        Ok(FirmwareWidth::of_this_build())
    }
}

impl HiiBackend {
    /// The HiiDB of this machine, through the HiiDB driver, for the extract-db command.
    pub fn export_hiidb() -> Result<Vec<u8>> {
        Self::system_hiidb()
    }

    /// Reads the HiiDB that get, list-questions and show-ifr read with `efivars`: the file
    /// `filename` if given, else this machine's, through the HiiDB driver.
    pub fn read_hiidb(filename: Option<&Path>, efivars: &EfivarSource) -> Result<Vec<u8>> {
        match filename {
            Some(filename) => db_file::read_db_file(filename),
            None => match efivars {
                EfivarSource::System | EfivarSource::Disabled => Self::system_hiidb(),
            },
        }
    }
}
