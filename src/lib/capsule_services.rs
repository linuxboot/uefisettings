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

//! The Capsule Services of the UEFI Shell build: QueryCapsuleCapabilities() and UpdateCapsule()
//! (UEFI 2.11 §8.5.3) through the uefi crate, which the image's entry point initializes, while
//! boot services run.

use std::mem;
use std::ptr::NonNull;

use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use uefi::runtime;
use uefi::runtime::CapsuleHeader;
use uefi::StatusExt;

use crate::efi_variables::CapsuleCapabilities;
use crate::efi_variables::CapsuleServices;
use crate::efi_variables::JsonCapsule;
use crate::efi_variables::ResetType;

// AlignedCapsule's words align a CapsuleHeader.
const _: () = assert!(mem::align_of::<CapsuleHeader>() <= mem::align_of::<u64>());

/// The firmware's Capsule Services.
pub(crate) struct RuntimeCapsuleServices;

impl CapsuleServices for RuntimeCapsuleServices {
    fn query_capsule_capabilities(&self, capsule: &JsonCapsule) -> Result<CapsuleCapabilities> {
        let capsule = AlignedCapsule::new(capsule);
        let info = runtime::query_capsule_capabilities(&[capsule.header()?]).map_err(|error| {
            anyhow!(
                "QueryCapsuleCapabilities() of the JSON capsule: {:?}",
                error.status()
            )
        })?;
        Ok(CapsuleCapabilities {
            maximum_capsule_size: info.maximum_capsule_size,
            reset_type: ResetType(info.reset_type.0),
        })
    }

    fn update_capsule(&self, capsule: &JsonCapsule) -> Result<()> {
        let capsule = AlignedCapsule::new(capsule);
        let headers = [capsule.header()?];
        // Through the table, not uefi 0.41's runtime::update_capsule, which passes the empty
        // slice's dangling pointer as ScatterGatherList.
        let system_table = uefi::table::system_table_raw().context("no UEFI System Table")?;
        // SAFETY: uefi_std_entry set the System Table, which the firmware keeps valid while boot
        // services run, before main ran (uefi::table::set_system_table)
        let runtime_services = unsafe { system_table.as_ref() }.runtime_services;
        let runtime_services =
            NonNull::new(runtime_services).context("no UEFI Runtime Services")?;
        // SAFETY: the System Table's RuntimeServices pointer, not null, points at the firmware's
        // EFI_RUNTIME_SERVICES, valid while boot services run
        let update_capsule = unsafe { runtime_services.as_ref() }.update_capsule;
        // SAFETY: headers holds one pointer to a CapsuleHeader followed by the rest of its capsule
        // in contiguous memory (AlignedCapsule), both of which outlive the call; ScatterGatherList
        // is 0, which "is only referenced if the capsules are defined to persist across system
        // reset" (UEFI 2.11 §8.5.3.1), as those of UpdateCapsuleDelivery are not
        unsafe { update_capsule(headers.as_ptr().cast(), headers.len(), 0) }
            .to_result()
            .map_err(|error| anyhow!("UpdateCapsule() of the JSON capsule: {:?}", error.status()))
    }
}

/// A capsule copied into u64 words, which align its EFI_CAPSULE_HEADER, as the
/// CapsuleHeaderArray of the Capsule Services points at each capsule's header, "stored in
/// contiguous virtual memory" (UEFI 2.11 §8.5.3.4) with its body.
struct AlignedCapsule(Vec<u64>);

impl AlignedCapsule {
    fn new(capsule: &JsonCapsule) -> Self {
        Self(
            capsule
                .as_bytes()
                .chunks(mem::size_of::<u64>())
                .map(|chunk| {
                    let mut word = [0; mem::size_of::<u64>()];
                    word.iter_mut()
                        .zip(chunk)
                        .for_each(|(byte, chunk_byte)| *byte = *chunk_byte);
                    u64::from_ne_bytes(word)
                })
                .collect(),
        )
    }

    /// Its EFI_CAPSULE_HEADER, followed in memory by the rest of the capsule.
    fn header(&self) -> Result<&CapsuleHeader> {
        let words = self.0.as_slice();
        ensure!(
            mem::size_of_val(words) >= mem::size_of::<CapsuleHeader>(),
            "a capsule of {} bytes is shorter than its EFI_CAPSULE_HEADER",
            mem::size_of_val(words)
        );
        // SAFETY: words holds at least size_of::<CapsuleHeader>() initialized bytes, aligned for
        // CapsuleHeader as for u64 (the assertion above), and CapsuleHeader is repr(C) of a Guid
        // (a u32 and bytes), u32s and CapsuleFlags (a u32), which every bit pattern makes
        Ok(unsafe { &*words.as_ptr().cast::<CapsuleHeader>() })
    }
}
