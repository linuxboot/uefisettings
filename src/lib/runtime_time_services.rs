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

//! The Time Services of the UEFI Shell build: GetTime(), SetTime(), GetWakeupTime() and
//! SetWakeupTime() (UEFI 2.11 §8.3) through the System Table's EFI_RUNTIME_SERVICES, as
//! capsule_services.rs calls UpdateCapsule(), while boot services run: uefi 0.41 wraps no
//! GetWakeupTime() or SetWakeupTime().

use std::ptr;
use std::ptr::NonNull;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use uefi::StatusExt;
use uefi_raw::table::runtime::RuntimeServices;
use uefi_raw::time::Daylight;
use uefi_raw::time::Time;
use uefi_raw::Boolean;

use crate::hii::time_services::EfiTime;
use crate::hii::time_services::TimeServices;
use crate::hii::time_services::WakeupAlarm;

/// The firmware's Time Services.
pub(crate) struct RuntimeTimeServices;

/// The firmware's EFI_RUNTIME_SERVICES.
fn runtime_services() -> Result<&'static RuntimeServices> {
    let system_table = uefi::table::system_table_raw().context("no UEFI System Table")?;
    // SAFETY: uefi_std_entry set the System Table, which the firmware keeps valid while boot
    // services run, before main ran (uefi::table::set_system_table)
    let runtime_services = unsafe { system_table.as_ref() }.runtime_services;
    let runtime_services = NonNull::new(runtime_services).context("no UEFI Runtime Services")?;
    // SAFETY: the System Table's RuntimeServices pointer, not null, points at the firmware's
    // EFI_RUNTIME_SERVICES, valid while boot services run, which outlast the image
    Ok(unsafe { runtime_services.as_ref() })
}

impl From<Time> for EfiTime {
    fn from(time: Time) -> Self {
        Self {
            year: time.year,
            month: time.month,
            day: time.day,
            hour: time.hour,
            minute: time.minute,
            second: time.second,
            nanosecond: time.nanosecond,
            time_zone: time.time_zone,
            daylight: time.daylight.bits(),
        }
    }
}

impl From<&EfiTime> for Time {
    fn from(time: &EfiTime) -> Self {
        Self {
            year: time.year,
            month: time.month,
            day: time.day,
            hour: time.hour,
            minute: time.minute,
            second: time.second,
            pad1: 0,
            nanosecond: time.nanosecond,
            time_zone: time.time_zone,
            daylight: Daylight::from_bits_retain(time.daylight),
            pad2: 0,
        }
    }
}

impl TimeServices for RuntimeTimeServices {
    fn get_time(&self) -> Result<EfiTime> {
        let get_time = runtime_services()?.get_time;
        let mut time = Time::invalid();
        // SAFETY: Time points at an EFI_TIME that outlives the call; Capabilities is OPTIONAL
        // (UEFI 2.11 §8.3.1)
        unsafe { get_time(&mut time, ptr::null_mut()) }
            .to_result()
            .map_err(|error| anyhow!("GetTime(): {:?}", error.status()))?;
        Ok(time.into())
    }

    fn set_time(&self, time: &EfiTime) -> Result<()> {
        let set_time = runtime_services()?.set_time;
        let time = Time::from(time);
        // SAFETY: Time points at an EFI_TIME that outlives the call (UEFI 2.11 §8.3.2)
        unsafe { set_time(&time) }
            .to_result()
            .map_err(|error| anyhow!("SetTime(): {:?}", error.status()))
    }

    fn get_wakeup_time(&self) -> Result<WakeupAlarm> {
        let get_wakeup_time = runtime_services()?.get_wakeup_time;
        let mut enabled = Boolean::FALSE;
        let mut pending = Boolean::FALSE;
        let mut time = Time::invalid();
        // SAFETY: Enabled, Pending and Time point at two BOOLEANs and an EFI_TIME that outlive
        // the call (UEFI 2.11 §8.3.3)
        unsafe { get_wakeup_time(&mut enabled, &mut pending, &mut time) }
            .to_result()
            .map_err(|error| anyhow!("GetWakeupTime(): {:?}", error.status()))?;
        Ok(WakeupAlarm {
            enabled: enabled.into(),
            pending: pending.into(),
            time: time.into(),
        })
    }

    fn set_wakeup_time(&self, enable: bool, time: &EfiTime) -> Result<()> {
        let set_wakeup_time = runtime_services()?.set_wakeup_time;
        let time = Time::from(time);
        // SAFETY: Time points at an EFI_TIME that outlives the call (UEFI 2.11 §8.3.4)
        unsafe { set_wakeup_time(enable.into(), &time) }
            .to_result()
            .map_err(|error| anyhow!("SetWakeupTime(): {:?}", error.status()))
    }
}
