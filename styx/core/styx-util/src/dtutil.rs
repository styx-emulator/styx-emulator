// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! UtcDataTime wrapping Date and Time utilities from [chrono::DateTime]

use chrono::prelude::{DateTime, Local, Utc};
use chrono::SecondsFormat;
use chrono::{FixedOffset, TimeZone};
use std::cmp::Ordering;
use std::fmt::Display;
use std::time::SystemTime;

#[derive(Clone, Debug)]
/// Convenience wrapper around chrono's  [DateTime]
pub struct UtcDateTime {
    inner: DateTime<Utc>,
}

impl Default for UtcDateTime {
    fn default() -> Self {
        Self { inner: Utc::now() }
    }
}
impl UtcDateTime {
    /// Make a new `SimpleDateTime` that wraps a `Utc` [DateTime] with current date and time
    pub fn now() -> Self {
        Self { inner: Utc::now() }
    }

    /// Make a new `SimpleDateTime` that wraps a [DateTime] with current date and time
    pub fn new() -> Self {
        Self::now()
    }

    /// Make a new `SimpleDateTime` that wraps a `Utc` [DateTime] from parameters
    pub fn build_from(year: i32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Self {
        Self {
            inner: Utc::with_ymd_and_hms(&Utc, year, month, day, hour, min, sec).unwrap(),
        }
    }

    /// truncate from nanosecond resolution to microsecond resolution
    pub fn trunc(self) -> Self {
        Self {
            inner: truncate_to_microseconds(self.inner),
        }
    }

    /// get elapsed milliseconds from inner [DateTime]
    pub fn elapsed_millis(&self) -> u64 {
        let millis = Utc::now().timestamp_millis() - self.inner.timestamp_millis();
        if millis > 0 {
            millis as u64
        } else {
            0
        }
    }

    /// get elapsed milliseconds from inner [DateTime]
    pub fn elapsed_secs(&self) -> u64 {
        let millis = self.elapsed_millis();
        if millis > 0 {
            millis / 1000
        } else {
            0
        }
    }

    /// display as rfc3339 (also consistent with iso8601), no whitespace,
    /// millisecond precision, UTC but with offset at the end
    /// example: `2024-01-15T12:15:55.950-05:00`
    pub fn local_string(&self) -> String {
        let dt_local: DateTime<Local> = self.inner.into();
        // dt_local.format("%Y-%m-%d_%H:%M:%S").to_string()
        dt_local.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    /// display as rfc3339 (also consistent with iso8601), no whitespace,
    /// millisecond precision, UTC
    /// example: `2024-01-15T17:15:55.950Z`
    pub fn utc_string(&self) -> String {
        self.inner.to_rfc3339_opts(SecondsFormat::Millis, true)
    }

    // Offset of actual Local time from UTC, in seconds
    pub fn local_offset() -> i32 {
        Local::now().offset().local_minus_utc()
    }

    /// Return a [FixedOffset] [DateTime] based on offset hours which is
    /// intended to be in the range `-12..12`. *panics if `offset_hours` not
    /// in range `-12..12`
    pub fn fixed_offset(
        offset_hours: i32,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> DateTime<FixedOffset> {
        let fu = match offset_hours.cmp(&0) {
            // Western hemisphere
            Ordering::Less => FixedOffset::west_opt,
            // Eastern hemisphere
            Ordering::Greater | Ordering::Equal => FixedOffset::east_opt,
        };
        fu(offset_hours.abs() * 3600)
            .unwrap()
            .with_ymd_and_hms(year, month, day, hour, min, sec)
            .unwrap()
    }

    /// Return a new `SimpleDateTime` based on offset hours which is
    /// intended to be in the range `-12..12`. *panics if `offset_hours` not
    /// in range `-12..12`
    pub fn utc_from_offset(
        offset_hours: i32,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> Self {
        Self {
            inner: Self::fixed_offset(offset_hours, year, month, day, hour, min, sec).into(),
        }
    }

    // get the inner `DateTime<Utc>`
    pub fn into_inner(&self) -> DateTime<Utc> {
        self.inner.to_owned()
    }
}

impl Display for UtcDateTime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.utc_string())
    }
}

impl From<DateTime<Utc>> for UtcDateTime {
    fn from(value: DateTime<Utc>) -> Self {
        Self { inner: value }
    }
}

impl From<DateTime<FixedOffset>> for UtcDateTime {
    fn from(value: DateTime<FixedOffset>) -> Self {
        Self {
            inner: value.into(),
        }
    }
}

impl From<SystemTime> for UtcDateTime {
    fn from(value: SystemTime) -> Self {
        Self {
            inner: DateTime::<Utc>::from(value),
        }
    }
}

/// Convert a [prost_wkt_types::Timestamp] to a [UtcDateTime].
///
/// Note: `prost_wkg_types::Timestamp` is a compiled version of
/// prost type for `Timestamp`.
impl From<prost_wkt_types::Timestamp> for UtcDateTime {
    fn from(value: prost_wkt_types::Timestamp) -> Self {
        Self {
            inner: value.into(),
        }
    }
}

fn truncate_to_microseconds(dt: DateTime<Utc>) -> DateTime<Utc> {
    let micros = (dt.timestamp_subsec_nanos() / 1000) * 1000;
    let cmicros = (dt.timestamp() * 1000000) + micros as i64;
    DateTime::from_timestamp_micros(cmicros).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_simple_datetime_elapsed() {
        let sdt = UtcDateTime::now();
        println!("{}", sdt.utc_string());
        println!("{}", sdt.local_string());
        let n = 1001;
        std::thread::sleep(std::time::Duration::from_millis(n));
        let ms = sdt.elapsed_millis();
        let s = sdt.elapsed_secs();
        assert!(ms > (n - 2));
        assert!(ms < (n + 2));
        assert_eq!(s, 1);
    }
}
