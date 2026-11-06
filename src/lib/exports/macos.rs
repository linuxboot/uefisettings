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

//! The exports that only the macOS build has: the HiiDB of a file or of an efivars dump, as it
//! reads no HiiDB or variables of the machine it runs on.

use std::path::Path;

use anyhow::anyhow;
use anyhow::Result;

use super::DriverHeldValues;
use super::HiiBackend;
use crate::hii::package::db_file;
use crate::hii::EfivarSource;
use crate::hii::SavedDump;

impl HiiBackend {
    /// The HiiDB in the file `filename`, such as one that extract-db wrote on Linux.
    pub fn read_hiidb_file(filename: &Path) -> Result<Vec<u8>> {
        db_file::read_db_file(filename)
    }

    /// Reads the HiiDB that get, list-questions and show-ifr read with `efivars`: the file
    /// `filename` if given, else the one that an efivars dump in `efivars` saved. A redacted dump
    /// refuses another `filename`, whose questions would read its zeros as values.
    pub fn read_hiidb(filename: Option<&Path>, efivars: &EfivarSource) -> Result<Vec<u8>> {
        SavedDump::read_given_hiidb(filename, efivars)?.ok_or_else(|| {
            anyhow!(
                "no HiiDB: this build reads none of this machine's, so pass --filename, or \
                 --efivars with a directory that dump-efivars wrote"
            )
        })
    }
}

/// What get does with a question whose driver holds its value: no driver is reached here.
impl HiiBackend {
    pub(super) fn driver_held_values(
        _hiidb: &[u8],
        _efivars: &EfivarSource,
    ) -> Option<Box<dyn DriverHeldValues>> {
        None
    }
}
