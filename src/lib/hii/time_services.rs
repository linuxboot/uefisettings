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

//! The Time Services of UEFI 2.11 §8.3, through which DATE and TIME questions of EFI Date/Time
//! Storage (§33.2.5.6) read and write the system time and the system wake-up time. The UEFI Shell
//! build calls them through EFI_RUNTIME_SERVICES (runtime_time_services.rs); no other build
//! reaches them.

use std::fmt;

use anyhow::Result;
use thiserror::Error;

/// EFI_TIME.TimeZone of a local time (UEFI 2.11 §8.3.1).
const EFI_UNSPECIFIED_TIMEZONE: i16 = 0x07FF;

/// An EFI_TIME (UEFI 2.11 §8.3.1), without its padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EfiTime {
    pub(crate) year: u16,
    pub(crate) month: u8,
    pub(crate) day: u8,
    pub(crate) hour: u8,
    pub(crate) minute: u8,
    pub(crate) second: u8,
    pub(crate) nanosecond: u32,
    pub(crate) time_zone: i16,
    pub(crate) daylight: u8,
}

impl EfiTime {
    /// Refuses a field outside the range that UEFI 2.11 §8.3.1 gives it, as SetTime() and
    /// SetWakeupTime() return EFI_INVALID_PARAMETER for "a time field ... out of range".
    pub(crate) fn check(&self) -> Result<(), EfiTimeOutOfRange> {
        let fields = [
            (
                "Year",
                i64::from(self.year),
                (1900..=9999).contains(&self.year),
                "1900 to 9999",
            ),
            (
                "Month",
                i64::from(self.month),
                (1..=12).contains(&self.month),
                "1 to 12",
            ),
            (
                "Day",
                i64::from(self.day),
                (1..=31).contains(&self.day),
                "1 to 31",
            ),
            ("Hour", i64::from(self.hour), self.hour <= 23, "0 to 23"),
            (
                "Minute",
                i64::from(self.minute),
                self.minute <= 59,
                "0 to 59",
            ),
            (
                "Second",
                i64::from(self.second),
                self.second <= 59,
                "0 to 59",
            ),
            (
                "Nanosecond",
                i64::from(self.nanosecond),
                self.nanosecond <= 999_999_999,
                "0 to 999,999,999",
            ),
            (
                "TimeZone",
                i64::from(self.time_zone),
                (-1440..=1440).contains(&self.time_zone)
                    || self.time_zone == EFI_UNSPECIFIED_TIMEZONE,
                "-1440 to 1440 or 2047",
            ),
        ];
        match fields.into_iter().find(|&(_, _, valid, _)| !valid) {
            Some((field, value, _, range)) => Err(EfiTimeOutOfRange {
                time: *self,
                field,
                value,
                range,
            }),
            None => Ok(()),
        }
    }
}

impl fmt::Display for EfiTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// An EFI_TIME with a field outside the range of UEFI 2.11 §8.3.1.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("EFI_TIME {time} has {field} {value}, outside {range} (UEFI 2.11 §8.3.1)")]
pub(crate) struct EfiTimeOutOfRange {
    time: EfiTime,
    field: &'static str,
    value: i64,
    range: &'static str,
}

/// The wake-up alarm that GetWakeupTime() returns (UEFI 2.11 §8.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WakeupAlarm {
    pub(crate) enabled: bool,
    pub(crate) pending: bool,
    pub(crate) time: EfiTime,
}

/// The Time Services of UEFI 2.11 §8.3; each error names the service and its EFI_STATUS.
pub(crate) trait TimeServices {
    /// GetTime() (§8.3.1), without Capabilities
    fn get_time(&self) -> Result<EfiTime>;
    /// SetTime() (§8.3.2)
    fn set_time(&self, time: &EfiTime) -> Result<()>;
    /// GetWakeupTime() (§8.3.3)
    fn get_wakeup_time(&self) -> Result<WakeupAlarm>;
    /// SetWakeupTime() (§8.3.4), whose `enable` arms or disarms the alarm
    fn set_wakeup_time(&self, enable: bool, time: &EfiTime) -> Result<()>;
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;

    use anyhow::anyhow;

    use super::*;

    /// A service of TimeServices.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[expect(
        clippy::enum_variant_names,
        reason = "the names of the UEFI 2.11 §8.3 services"
    )]
    pub(crate) enum TimeService {
        GetTime,
        SetTime,
        GetWakeupTime,
        SetWakeupTime,
    }

    /// A call of TimeServices, with its arguments.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[expect(
        clippy::enum_variant_names,
        reason = "the names of the UEFI 2.11 §8.3 services"
    )]
    pub(crate) enum TimeCall {
        GetTime,
        SetTime(EfiTime),
        GetWakeupTime,
        SetWakeupTime(bool, EfiTime),
    }

    /// Time Services that hold a time and an alarm, which their Set calls change, log each call,
    /// and fail `failing`, if any, with EFI_DEVICE_ERROR.
    pub(crate) struct FakeTimeServices {
        pub(crate) time: Cell<EfiTime>,
        pub(crate) alarm: Cell<WakeupAlarm>,
        pub(crate) failing: Cell<Option<TimeService>>,
        pub(crate) calls: RefCell<Vec<TimeCall>>,
    }

    /// The time of FakeTimeServices::new: a TimeZone and Daylight that a write must keep.
    pub(crate) const NOW: EfiTime = EfiTime {
        year: 2026,
        month: 11,
        day: 7,
        hour: 1,
        minute: 2,
        second: 3,
        nanosecond: 4,
        time_zone: 60,
        daylight: 1,
    };

    /// The alarm time of FakeTimeServices::new, which is disabled.
    pub(crate) const ALARM: EfiTime = EfiTime {
        year: 2026,
        month: 11,
        day: 8,
        hour: 0,
        minute: 30,
        second: 0,
        nanosecond: 5,
        time_zone: -60,
        daylight: 3,
    };

    impl FakeTimeServices {
        /// The time NOW and the disabled alarm ALARM, failing `failing`.
        pub(crate) fn new(failing: Option<TimeService>) -> Self {
            Self {
                time: Cell::new(NOW),
                alarm: Cell::new(WakeupAlarm {
                    enabled: false,
                    pending: false,
                    time: ALARM,
                }),
                failing: Cell::new(failing),
                calls: RefCell::default(),
            }
        }

        /// Logs `call` of `service`, and fails if it is `failing`.
        fn call(&self, service: TimeService, call: TimeCall) -> Result<()> {
            self.calls.borrow_mut().push(call);
            match self.failing.get() == Some(service) {
                true => Err(anyhow!("{service:?}(): DEVICE_ERROR")),
                false => Ok(()),
            }
        }
    }

    impl TimeServices for FakeTimeServices {
        fn get_time(&self) -> Result<EfiTime> {
            self.call(TimeService::GetTime, TimeCall::GetTime)?;
            Ok(self.time.get())
        }

        fn set_time(&self, time: &EfiTime) -> Result<()> {
            self.call(TimeService::SetTime, TimeCall::SetTime(*time))?;
            self.time.set(*time);
            Ok(())
        }

        fn get_wakeup_time(&self) -> Result<WakeupAlarm> {
            self.call(TimeService::GetWakeupTime, TimeCall::GetWakeupTime)?;
            Ok(self.alarm.get())
        }

        fn set_wakeup_time(&self, enable: bool, time: &EfiTime) -> Result<()> {
            self.call(
                TimeService::SetWakeupTime,
                TimeCall::SetWakeupTime(enable, *time),
            )?;
            self.alarm.set(WakeupAlarm {
                enabled: enable,
                pending: false,
                time: *time,
            });
            Ok(())
        }
    }

    const TIME: EfiTime = EfiTime {
        year: 2026,
        month: 11,
        day: 7,
        hour: 23,
        minute: 59,
        second: 58,
        nanosecond: 999_999_999,
        time_zone: -1440,
        daylight: 3,
    };

    /// Each field at either end of its range passes; one past it is refused, naming the field.
    #[test]
    fn efi_time_fields_are_checked_against_their_ranges() {
        let valid = [
            TIME,
            EfiTime {
                year: 1900,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                nanosecond: 0,
                time_zone: 1440,
                ..TIME
            },
            EfiTime {
                year: 9999,
                day: 31,
                time_zone: EFI_UNSPECIFIED_TIMEZONE,
                ..TIME
            },
        ];
        for time in valid {
            assert_eq!(time.check(), Ok(()), "{time:?}");
        }
        let refused = [
            (
                EfiTime { year: 1899, ..TIME },
                "Year 1899, outside 1900 to 9999",
            ),
            (
                EfiTime {
                    year: 10000,
                    ..TIME
                },
                "Year 10000, outside 1900 to 9999",
            ),
            (EfiTime { month: 0, ..TIME }, "Month 0, outside 1 to 12"),
            (EfiTime { month: 13, ..TIME }, "Month 13, outside 1 to 12"),
            (EfiTime { day: 0, ..TIME }, "Day 0, outside 1 to 31"),
            (EfiTime { day: 32, ..TIME }, "Day 32, outside 1 to 31"),
            (EfiTime { hour: 24, ..TIME }, "Hour 24, outside 0 to 23"),
            (EfiTime { minute: 60, ..TIME }, "Minute 60, outside 0 to 59"),
            (EfiTime { second: 60, ..TIME }, "Second 60, outside 0 to 59"),
            (
                EfiTime {
                    nanosecond: 1_000_000_000,
                    ..TIME
                },
                "Nanosecond 1000000000, outside 0 to 999,999,999",
            ),
            (
                EfiTime {
                    time_zone: -1441,
                    ..TIME
                },
                "TimeZone -1441, outside -1440 to 1440 or 2047",
            ),
            (
                EfiTime {
                    time_zone: 2046,
                    ..TIME
                },
                "TimeZone 2046, outside -1440 to 1440 or 2047",
            ),
        ];
        for (time, want) in refused {
            let error = time.check().expect_err("check of an EFI_TIME out of range");
            assert!(
                error.to_string().contains(want),
                "{time:?}: {error} should say {want:?}"
            );
            assert!(
                error.to_string().ends_with("(UEFI 2.11 §8.3.1)"),
                "{time:?}: {error}"
            );
        }
    }

    #[test]
    fn efi_time_displays_its_date_and_time() {
        assert_eq!(TIME.to_string(), "2026-11-07 23:59:58");
        let early = EfiTime {
            year: 1900,
            month: 1,
            day: 2,
            hour: 3,
            minute: 4,
            second: 5,
            ..TIME
        };
        assert_eq!(early.to_string(), "1900-01-02 03:04:05");
    }
}
