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

//! The exports that only the UEFI Shell build has: those that read the HII database of the
//! firmware it runs on and write its variables, through boot services.
//!
//! Every export that reaches this firmware, export_hiidb here and get, set, list-questions and
//! show-ifr of EfivarSource::System, calls the uefi crate, which panics unless the image has
//! initialized it: uefi::table::set_system_table, then uefi::boot::set_image_handle.

use anyhow::Result;

use super::HiiBackend;
use crate::hii::export_package_lists;
use crate::hii::FirmwareVariables;
use crate::hii::VariableServices;

/// What set and get read and write when no file names them: this firmware's HII database and
/// variables, through boot services.
impl HiiBackend {
    /// This firmware's HiiDB.
    pub(super) fn system_hiidb() -> Result<Vec<u8>> {
        Self::export_hiidb()
    }

    /// This firmware's variables.
    pub(super) fn system_variables() -> impl FirmwareVariables {
        VariableServices
    }
}

impl HiiBackend {
    /// The HiiDB of this firmware: every package list that EFI_HII_DATABASE_PROTOCOL exports.
    pub fn export_hiidb() -> Result<Vec<u8>> {
        export_package_lists()
    }
}
