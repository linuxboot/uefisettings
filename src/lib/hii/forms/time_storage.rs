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

//! EFI Date/Time Storage (UEFI 2.11 §33.2.5.6): the system time and the system wake-up time,
//! which DATE and TIME questions of QF_DATE_STORAGE_TIME/_WAKEUP or QF_TIME_STORAGE_TIME/_WAKEUP
//! read through GetTime() and GetWakeupTime() and set writes through SetTime() and
//! SetWakeupTime(): "the date and time will be read first, the modifications made and changes
//! will be written back" (§33.2.5.4.6). The write keeps every field that the question does not
//! change, GetTime()'s or the alarm's TimeZone and Daylight too, which an EFI_HII_DATE or
//! EFI_HII_TIME lacks, as edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue does; a
//! write of the wake-up time arms the alarm, SetWakeupTime(TRUE, …), as SetQuestionValue does.

use std::fmt;
use std::rc::Rc;

use anyhow::Result;
use thiserror::Error;

use super::date_time::DateTimeKind;
use super::date_time::Field;
use super::TypeValue;
use crate::hii::time_services::EfiTime;
use crate::hii::time_services::EfiTimeOutOfRange;
use crate::hii::time_services::TimeServices;

/// The EFI Date/Time Storage of a DATE or TIME.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeStorage {
    /// QF_DATE_STORAGE_TIME or QF_TIME_STORAGE_TIME: GetTime() and SetTime()
    SystemTime,
    /// QF_DATE_STORAGE_WAKEUP or QF_TIME_STORAGE_WAKEUP: GetWakeupTime() and SetWakeupTime()
    WakeupTime,
}

impl TimeStorage {
    /// The service that reads it.
    fn reader(self) -> &'static str {
        match self {
            Self::SystemTime => "GetTime()",
            Self::WakeupTime => "GetWakeupTime()",
        }
    }

    /// The service that writes it.
    fn writer(self) -> &'static str {
        match self {
            Self::SystemTime => "SetTime()",
            Self::WakeupTime => "SetWakeupTime()",
        }
    }

    /// Its EFI_TIME, through `services`: GetTime()'s, or the time of GetWakeupTime()'s alarm.
    pub(super) fn read(self, services: &dyn TimeServices) -> Result<EfiTime> {
        match self {
            Self::SystemTime => services.get_time(),
            Self::WakeupTime => Ok(services.get_wakeup_time()?.time),
        }
    }
}

impl fmt::Display for TimeStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SystemTime => "the system time",
            Self::WakeupTime => "the wake-up time",
        })
    }
}

/// Why get reads no value of a question of EFI Date/Time Storage on a backend without Time
/// Services.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is read only through {}; run uefisettings.efi \
     in the UEFI Shell",
    .0.reader()
)]
pub(crate) struct TimeStorageUnread(pub(crate) TimeStorage);

/// find_corresponding_varstore's error for a DATE or TIME of EFI Date/Time Storage without a
/// VarStore, which keeps its value there only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("question keeps its value in {0} only (UEFI 2.11 §33.2.5.6)")]
pub(crate) struct TimeStorageOnly(pub(crate) TimeStorage);

/// The value of a question of `kind` in `time`: the bytes of its EFI_HII_DATE or EFI_HII_TIME,
/// little-endian, as read_question_value gives a value.
pub(super) fn question_value(kind: DateTimeKind, time: &EfiTime) -> u64 {
    let mut bytes = [0; 4];
    for field in kind.fields() {
        field.put(&mut bytes, field_value(time, field));
    }
    u32::from_le_bytes(bytes).into()
}

/// The field of `kind` at VarOffset `offset` of a GET or SET without a VarStore, which
/// edk2-stable202608 SetupBrowserDxe/Expression.c reads or writes in GetTime()'s EFI_TIME: of a
/// DATE, 0 the year, 2 the month and 3 the day; of a TIME, 0 the hour, 1 the minute and 2 the
/// second.
pub(super) fn system_time_field(kind: DateTimeKind, offset: u16) -> Option<Field> {
    kind.fields()
        .into_iter()
        .find(|field| field.bytes().start == usize::from(offset))
}

/// The value of `field` in `time`.
pub(super) fn field_value(time: &EfiTime, field: Field) -> u16 {
    match field {
        Field::Year => time.year,
        Field::Month => time.month.into(),
        Field::Day => time.day.into(),
        Field::Hour => time.hour.into(),
        Field::Minute => time.minute.into(),
        Field::Second => time.second.into(),
    }
}

/// A field of an EFI_TIME that a write changes, to `value`, whose low byte a field of a byte
/// takes, as SET takes Value.u8 there (edk2-stable202608 SetupBrowserDxe/Expression.c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldChange {
    pub(crate) field: Field,
    pub(crate) value: u16,
}

/// The changes of the fields of an EFI_TIME that the new value `value` of a DATE or TIME makes:
/// each of its fields, its suppressed ones too, which hold what set keeps of their stored values
/// (DateTimeFormat::value); None for another value.
pub(super) fn value_changes(value: TypeValue) -> Option<Vec<FieldChange>> {
    let (kind, bytes) = match value {
        TypeValue::Date(date) => (DateTimeKind::Date, date.to_bytes()),
        TypeValue::Time(time) => {
            let [hour, minute, second] = time.to_bytes();
            (DateTimeKind::Time, [hour, minute, second, 0])
        }
        TypeValue::NumSize8(_)
        | TypeValue::NumSize16(_)
        | TypeValue::NumSize32(_)
        | TypeValue::NumSize64(_)
        | TypeValue::Boolean(_)
        | TypeValue::StringID(_)
        | TypeValue::Other
        | TypeValue::Undefined
        | TypeValue::Action(_)
        | TypeValue::Ref(_)
        | TypeValue::Unknown(_) => return None,
    };
    Some(
        kind.fields()
            .into_iter()
            .map(|field| FieldChange {
                field,
                value: field.value(&bytes),
            })
            .collect(),
    )
}

/// `time` with `change` made.
fn changed(time: EfiTime, FieldChange { field, value }: FieldChange) -> EfiTime {
    let [low, _] = value.to_le_bytes();
    match field {
        Field::Year => EfiTime {
            year: value,
            ..time
        },
        Field::Month => EfiTime { month: low, ..time },
        Field::Day => EfiTime { day: low, ..time },
        Field::Hour => EfiTime { hour: low, ..time },
        Field::Minute => EfiTime {
            minute: low,
            ..time
        },
        Field::Second => EfiTime {
            second: low,
            ..time
        },
    }
}

/// A write of the system time or wake-up time, which set plans before its first write: the
/// changes of the fields of the question and of the SETs of its WRITE expression, which the plan
/// checked on the EFI_TIME that its read gave against UEFI 2.11 §8.3.1's ranges.
pub(crate) struct TimeWrite {
    storage: TimeStorage,
    changes: Vec<FieldChange>,
    services: Rc<dyn TimeServices>,
}

impl TimeWrite {
    /// The write of `storage` through `services`, if the backend has any, that makes `changes`
    /// in order: reads it, makes them and checks the result, before any write.
    pub(super) fn plan(
        storage: TimeStorage,
        services: Option<&Rc<dyn TimeServices>>,
        changes: &[FieldChange],
    ) -> Result<Self, TimeWriteRefusal> {
        let services = services.ok_or(TimeWriteRefusal::Unwritten(storage))?;
        let read = storage
            .read(services.as_ref())
            .map_err(|error| TimeWriteRefusal::Unread { storage, error })?;
        let time = changes.iter().copied().fold(read, changed);
        time.check().map_err(TimeWriteRefusal::OutOfRange)?;
        Ok(Self {
            storage,
            changes: changes.to_vec(),
            services: Rc::clone(services),
        })
    }

    /// The storage that it writes.
    pub(super) fn storage(&self) -> TimeStorage {
        self.storage
    }

    /// Reads the time again and writes it with the planned changes, so that its other fields are
    /// as fresh as edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue keeps them (:2019 or
    /// :2023, then :2049 or :2051): SetTime(), or SetWakeupTime(TRUE, …), which arms the alarm,
    /// which "causes the system to wake up or power on at the set time" (UEFI 2.11 §8.3.4).
    /// Refuses, before the write, a result outside UEFI 2.11 §8.3.1's ranges, for which the
    /// service would return EFI_INVALID_PARAMETER. Returns what it wrote.
    pub(super) fn write(&self) -> Result<WrittenTime> {
        let storage = self.storage;
        let read = storage
            .read(self.services.as_ref())
            .map_err(|error| TimeWriteRefusal::Unread { storage, error })?;
        let time = self.changes.iter().copied().fold(read, changed);
        time.check().map_err(TimeWriteRefusal::OutOfRange)?;
        match storage {
            TimeStorage::SystemTime => self.services.set_time(&time),
            TimeStorage::WakeupTime => self.services.set_wakeup_time(true, &time),
        }?;
        Ok(WrittenTime { storage, time })
    }
}

/// The EFI_TIME that a TimeWrite wrote to its storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WrittenTime {
    storage: TimeStorage,
    time: EfiTime,
}

impl fmt::Display for WrittenTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.storage, self.time)
    }
}

/// Why set plans no write of the system time or wake-up time.
#[derive(Debug, Error)]
pub(crate) enum TimeWriteRefusal {
    /// The backend has no Time Services
    #[error(
        "EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is written only through {}; run \
         uefisettings.efi in the UEFI Shell",
        .0.writer()
    )]
    Unwritten(TimeStorage),
    /// The read of `storage` that the write starts from failed
    #[error("{storage} cannot be read: {error:#}")]
    Unread {
        storage: TimeStorage,
        error: anyhow::Error,
    },
    #[error("{0}")]
    OutOfRange(EfiTimeOutOfRange),
}

#[cfg(test)]
mod tests {
    use super::super::Date;
    use super::super::Time;
    use super::*;
    use crate::hii::time_services::tests::FakeTimeServices;
    use crate::hii::time_services::tests::TimeCall;
    use crate::hii::time_services::tests::TimeService;
    use crate::hii::time_services::tests::ALARM;
    use crate::hii::time_services::tests::NOW;
    use crate::hii::time_services::WakeupAlarm;

    /// The changes of the date 2027-02-28.
    const DATE_CHANGES: [FieldChange; 3] = [
        FieldChange {
            field: Field::Year,
            value: 2027,
        },
        FieldChange {
            field: Field::Month,
            value: 2,
        },
        FieldChange {
            field: Field::Day,
            value: 28,
        },
    ];

    /// The changes of the time 23:59:58.
    const TIME_CHANGES: [FieldChange; 3] = [
        FieldChange {
            field: Field::Hour,
            value: 23,
        },
        FieldChange {
            field: Field::Minute,
            value: 59,
        },
        FieldChange {
            field: Field::Second,
            value: 58,
        },
    ];

    /// FakeTimeServices failing `failing`, and the same as TimeWrite::plan takes them.
    fn fake_services(failing: Option<TimeService>) -> (Rc<FakeTimeServices>, Rc<dyn TimeServices>) {
        let services = Rc::new(FakeTimeServices::new(failing));
        let shared: Rc<dyn TimeServices> = Rc::<FakeTimeServices>::clone(&services);
        (services, shared)
    }

    #[test]
    fn each_storage_reads_through_its_service() {
        let cases = [
            (TimeStorage::SystemTime, NOW, TimeCall::GetTime),
            (TimeStorage::WakeupTime, ALARM, TimeCall::GetWakeupTime),
        ];
        for (storage, want, call) in cases {
            let (services, _) = fake_services(None);
            assert_eq!(
                storage.read(services.as_ref()).expect("read"),
                want,
                "{storage}"
            );
            assert_eq!(*services.calls.borrow(), [call], "{storage}: calls");
        }
    }

    /// A DATE takes the year, month and day of an EFI_TIME, as the bytes of an EFI_HII_DATE, a
    /// TIME its hour, minute and second, as an EFI_HII_TIME.
    #[test]
    fn question_value_is_the_bytes_of_its_fields() {
        assert_eq!(
            question_value(DateTimeKind::Date, &NOW),
            u64::from(u32::from_le_bytes([0xEA, 0x07, 11, 7])),
            "DATE"
        );
        assert_eq!(
            question_value(DateTimeKind::Time, &NOW),
            u64::from(u32::from_le_bytes([1, 2, 3, 0])),
            "TIME"
        );
    }

    #[test]
    fn system_time_fields_are_at_their_offsets() {
        let cases = [
            (DateTimeKind::Date, 0, Some(Field::Year)),
            (DateTimeKind::Date, 1, None),
            (DateTimeKind::Date, 2, Some(Field::Month)),
            (DateTimeKind::Date, 3, Some(Field::Day)),
            (DateTimeKind::Date, 4, None),
            (DateTimeKind::Time, 0, Some(Field::Hour)),
            (DateTimeKind::Time, 1, Some(Field::Minute)),
            (DateTimeKind::Time, 2, Some(Field::Second)),
            (DateTimeKind::Time, 3, None),
        ];
        for (kind, offset, want) in cases {
            assert_eq!(system_time_field(kind, offset), want, "{kind} at {offset}");
        }
        let fields = [
            (Field::Year, 2026),
            (Field::Month, 11),
            (Field::Day, 7),
            (Field::Hour, 1),
            (Field::Minute, 2),
            (Field::Second, 3),
        ];
        for (field, want) in fields {
            assert_eq!(field_value(&NOW, field), want, "{field}");
        }
    }

    #[test]
    fn value_changes_are_every_field_of_a_date_or_time() {
        let date = TypeValue::Date(Date::from_bytes([0xEB, 0x07, 2, 28]));
        assert_eq!(value_changes(date), Some(DATE_CHANGES.to_vec()), "DATE");
        let time = TypeValue::Time(Time::from_bytes([23, 59, 58]));
        assert_eq!(value_changes(time), Some(TIME_CHANGES.to_vec()), "TIME");
        assert_eq!(value_changes(TypeValue::NumSize8(1)), None, "UINT8");
    }

    /// A DATE on the system time writes GetTime()'s EFI_TIME back with only its date changed:
    /// its time, Nanosecond, TimeZone and Daylight stay.
    #[test]
    fn system_time_write_changes_only_the_fields_of_its_value() {
        let (services, shared) = fake_services(None);
        let write = TimeWrite::plan(TimeStorage::SystemTime, Some(&shared), &DATE_CHANGES)
            .expect("plan the write of a date");
        assert_eq!(
            *services.calls.borrow(),
            [TimeCall::GetTime],
            "calls of the plan"
        );
        let written = write.write().expect("write the date");
        let want = EfiTime {
            year: 2027,
            month: 2,
            day: 28,
            ..NOW
        };
        assert_eq!(
            *services.calls.borrow(),
            [
                TimeCall::GetTime,
                TimeCall::GetTime,
                TimeCall::SetTime(want)
            ],
            "calls"
        );
        assert_eq!(written.to_string(), "the system time 2027-02-28 01:02:03");
    }

    /// A TIME on the wake-up time writes the alarm's EFI_TIME back with only its time changed,
    /// and arms the alarm, which GetWakeupTime() gave disabled.
    #[test]
    fn wakeup_time_write_arms_the_alarm_and_keeps_its_other_fields() {
        let (services, shared) = fake_services(None);
        let write = TimeWrite::plan(TimeStorage::WakeupTime, Some(&shared), &TIME_CHANGES)
            .expect("plan the write of a time");
        let written = write.write().expect("write the time");
        let want = EfiTime {
            hour: 23,
            minute: 59,
            second: 58,
            ..ALARM
        };
        assert_eq!(
            *services.calls.borrow(),
            [
                TimeCall::GetWakeupTime,
                TimeCall::GetWakeupTime,
                TimeCall::SetWakeupTime(true, want)
            ],
            "calls"
        );
        assert_eq!(
            services.alarm.get(),
            WakeupAlarm {
                enabled: true,
                pending: false,
                time: want,
            }
        );
        assert_eq!(written.to_string(), "the wake-up time 2026-11-08 23:59:58");
    }

    /// The write reads the time again right before SetTime() and changes only the planned fields
    /// of that read: the clock that moved on since the plan keeps its fresh time.
    #[test]
    fn write_changes_the_planned_fields_of_a_fresh_read() {
        let (services, shared) = fake_services(None);
        let write = TimeWrite::plan(TimeStorage::SystemTime, Some(&shared), &DATE_CHANGES)
            .expect("plan the write of a date");
        let later = EfiTime {
            hour: 1,
            minute: 3,
            second: 4,
            nanosecond: 5,
            ..NOW
        };
        services.time.set(later);
        write.write().expect("write the date");
        let want = EfiTime {
            year: 2027,
            month: 2,
            day: 28,
            ..later
        };
        assert_eq!(
            *services.calls.borrow(),
            [
                TimeCall::GetTime,
                TimeCall::GetTime,
                TimeCall::SetTime(want)
            ],
            "calls"
        );
    }

    /// The fresh read with the planned fields must be within UEFI 2.11 §8.3.1's ranges too: a
    /// TimeZone that left them since the plan is refused without SetWakeupTime().
    #[test]
    fn fresh_read_outside_efi_time_ranges_is_refused_without_a_set() {
        let (services, shared) = fake_services(None);
        let write = TimeWrite::plan(TimeStorage::WakeupTime, Some(&shared), &TIME_CHANGES)
            .expect("plan the write of a time");
        let alarm = services.alarm.get();
        services.alarm.set(WakeupAlarm {
            time: EfiTime {
                time_zone: 1441,
                ..alarm.time
            },
            ..alarm
        });
        let error = write.write().expect_err("write over a TimeZone of 1441");
        assert_eq!(
            format!("{error:#}"),
            "EFI_TIME 2026-11-08 23:59:58 has TimeZone 1441, outside -1440 to 1440 or 2047 (UEFI \
             2.11 §8.3.1)"
        );
        assert_eq!(
            *services.calls.borrow(),
            [TimeCall::GetWakeupTime, TimeCall::GetWakeupTime],
            "calls"
        );
    }

    /// A read with a field outside UEFI 2.11 §8.3.1's ranges that the write replaces, as of an RTC
    /// that lost its date, is written: the plan and the write check the changed time only.
    #[test]
    fn field_outside_efi_time_ranges_that_the_write_replaces_is_written() {
        let (services, shared) = fake_services(None);
        services.time.set(EfiTime { year: 1899, ..NOW });
        let write = TimeWrite::plan(TimeStorage::SystemTime, Some(&shared), &DATE_CHANGES)
            .unwrap_or_else(|refusal| panic!("plan over a read of year 1899: {refusal}"));
        services.time.set(EfiTime {
            year: 0,
            month: 0,
            day: 0,
            ..NOW
        });
        let written = write.write().map_err(|error| format!("{error:#}"));
        assert_eq!(
            written.map(|written| written.to_string()),
            Ok("the system time 2027-02-28 01:02:03".to_string()),
            "write over a fresh read of 0000-00-00"
        );
        assert_eq!(
            *services.calls.borrow(),
            [
                TimeCall::GetTime,
                TimeCall::GetTime,
                TimeCall::SetTime(EfiTime {
                    year: 2027,
                    month: 2,
                    day: 28,
                    ..NOW
                })
            ],
            "calls"
        );
    }

    /// A failed read is the refusal, with the service's error, and nothing is set after it.
    #[test]
    fn a_failed_get_is_refused_without_a_set() {
        let cases = [
            (
                TimeStorage::SystemTime,
                TimeService::GetTime,
                TimeCall::GetTime,
                "the system time cannot be read: GetTime(): DEVICE_ERROR",
            ),
            (
                TimeStorage::WakeupTime,
                TimeService::GetWakeupTime,
                TimeCall::GetWakeupTime,
                "the wake-up time cannot be read: GetWakeupTime(): DEVICE_ERROR",
            ),
        ];
        for (storage, failing, call, want) in cases {
            let (services, shared) = fake_services(Some(failing));
            let refusal = TimeWrite::plan(storage, Some(&shared), &DATE_CHANGES)
                .err()
                .unwrap_or_else(|| panic!("{storage}: plan with {failing:?} failing"));
            assert_eq!(refusal.to_string(), want, "{storage}");
            assert_eq!(*services.calls.borrow(), [call], "{storage}: calls");
            assert_eq!(services.time.get(), NOW, "{storage}: time");
            assert_eq!(services.alarm.get().time, ALARM, "{storage}: alarm");
        }
    }

    /// A read that fails at the write, after the plan's read, is the write's error, with the
    /// service's error, and nothing is set after it.
    #[test]
    fn a_get_that_fails_at_the_write_is_returned_without_a_set() {
        let cases = [
            (
                TimeStorage::SystemTime,
                TimeService::GetTime,
                TimeCall::GetTime,
                "the system time cannot be read: GetTime(): DEVICE_ERROR",
            ),
            (
                TimeStorage::WakeupTime,
                TimeService::GetWakeupTime,
                TimeCall::GetWakeupTime,
                "the wake-up time cannot be read: GetWakeupTime(): DEVICE_ERROR",
            ),
        ];
        for (storage, failing, call, want) in cases {
            let (services, shared) = fake_services(None);
            let write = TimeWrite::plan(storage, Some(&shared), &TIME_CHANGES)
                .unwrap_or_else(|refusal| panic!("{storage}: plan: {refusal}"));
            services.failing.set(Some(failing));
            let error = write
                .write()
                .expect_err("write with the read failing after the plan");
            assert_eq!(format!("{error:#}"), want, "{storage}");
            assert_eq!(*services.calls.borrow(), [call, call], "{storage}: calls");
            assert_eq!(services.time.get(), NOW, "{storage}: time");
            assert_eq!(services.alarm.get().time, ALARM, "{storage}: alarm");
        }
    }

    /// A failed SetTime() or SetWakeupTime() is the write's error.
    #[test]
    fn a_failed_set_is_returned() {
        let cases = [
            (
                TimeStorage::SystemTime,
                TimeService::SetTime,
                "SetTime(): DEVICE_ERROR",
            ),
            (
                TimeStorage::WakeupTime,
                TimeService::SetWakeupTime,
                "SetWakeupTime(): DEVICE_ERROR",
            ),
        ];
        for (storage, failing, want) in cases {
            let (services, shared) = fake_services(Some(failing));
            let write = TimeWrite::plan(storage, Some(&shared), &TIME_CHANGES)
                .unwrap_or_else(|refusal| panic!("{storage}: plan: {refusal}"));
            let error = write
                .write()
                .err()
                .unwrap_or_else(|| panic!("{storage}: write with {failing:?} failing"));
            assert_eq!(format!("{error:#}"), want, "{storage}");
            assert_eq!(services.calls.borrow().len(), 3, "{storage}: calls");
            assert_eq!(services.time.get(), NOW, "{storage}: time");
            assert_eq!(services.alarm.get().time, ALARM, "{storage}: alarm");
        }
    }

    /// The changed EFI_TIME must be within UEFI 2.11 §8.3.1's ranges, which the plan checks
    /// before any write: a year before 1900, which a DATE may hold, is refused.
    #[test]
    fn a_time_outside_efi_time_ranges_is_refused_before_any_set() {
        let early = [FieldChange {
            field: Field::Year,
            value: 1899,
        }];
        let (services, shared) = fake_services(None);
        let refusal = TimeWrite::plan(TimeStorage::SystemTime, Some(&shared), &early)
            .err()
            .expect("plan of the year 1899");
        assert_eq!(
            refusal.to_string(),
            "EFI_TIME 1899-11-07 01:02:03 has Year 1899, outside 1900 to 9999 (UEFI 2.11 §8.3.1)"
        );
        assert_eq!(*services.calls.borrow(), [TimeCall::GetTime], "calls");

        let late = [FieldChange {
            field: Field::Hour,
            value: 24,
        }];
        let (services, shared) = fake_services(None);
        let refusal = TimeWrite::plan(TimeStorage::WakeupTime, Some(&shared), &late)
            .err()
            .expect("plan of the hour 24");
        assert!(
            refusal.to_string().contains("has Hour 24, outside 0 to 23"),
            "{refusal}"
        );
        assert_eq!(*services.calls.borrow(), [TimeCall::GetWakeupTime], "calls");
    }

    /// Without Time Services, get and set name the service and the UEFI Shell.
    #[test]
    fn a_backend_without_time_services_names_the_service() {
        let cases = [
            (TimeStorage::SystemTime, "GetTime()", "SetTime()"),
            (
                TimeStorage::WakeupTime,
                "GetWakeupTime()",
                "SetWakeupTime()",
            ),
        ];
        for (storage, reader, writer) in cases {
            assert_eq!(
                TimeStorageUnread(storage).to_string(),
                format!(
                    "EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is read only through {reader}; \
                     run uefisettings.efi in the UEFI Shell"
                ),
                "{storage}: get"
            );
            let refusal = TimeWrite::plan(storage, None, &TIME_CHANGES)
                .err()
                .unwrap_or_else(|| panic!("{storage}: plan without Time Services"));
            assert_eq!(
                refusal.to_string(),
                format!(
                    "EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is written only through \
                     {writer}; run uefisettings.efi in the UEFI Shell"
                ),
                "{storage}: set"
            );
        }
    }

    /// Changes apply in order, the last of a field winning; a field of a byte takes the low byte
    /// of its value, the year both.
    #[test]
    fn changes_apply_in_order_each_in_its_width() {
        let changes = [
            FieldChange {
                field: Field::Month,
                value: 3,
            },
            FieldChange {
                field: Field::Month,
                value: 4,
            },
            FieldChange {
                field: Field::Hour,
                value: 0x0117,
            },
            FieldChange {
                field: Field::Year,
                value: 0x07EB,
            },
        ];
        let (services, shared) = fake_services(None);
        let write = TimeWrite::plan(TimeStorage::SystemTime, Some(&shared), &changes)
            .expect("plan the changes");
        write.write().expect("write the changes");
        assert_eq!(
            services.time.get(),
            EfiTime {
                year: 2027,
                month: 4,
                hour: 0x17,
                ..NOW
            }
        );
    }
}
