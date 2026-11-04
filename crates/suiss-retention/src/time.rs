//! Trusted time and UTC calendar arithmetic that never ends a period early (OP-147 m.2).

use crate::schedule::Period;

const MS_PER_DAY: u64 = 86_400_000;
const EPOCH_SHIFT: u64 = 719_468;
const DAYS_PER_ERA: u64 = 146_097;

/// A point in trusted time, Unix milliseconds UTC (TI-RT2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
pub struct Timestamp(u64);

impl Timestamp {
    /// The time `ms` milliseconds after the Unix epoch.
    #[must_use]
    pub const fn from_unix_millis(ms: u64) -> Self {
        Self(ms)
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn unix_millis(self) -> u64 {
        self.0
    }

    /// `self` plus `period` on the UTC calendar, or `None` past the representable range.
    /// A day that does not exist in the target month moves to the first of the next month
    /// (29 February plus one year is 1 March), so the result is never earlier than any other
    /// reading of the period.
    #[must_use]
    pub fn checked_add(self, period: Period) -> Option<Self> {
        match period {
            Period::Days(n) => u64::from(n)
                .checked_mul(MS_PER_DAY)
                .and_then(|ms| self.0.checked_add(ms))
                .map(Self),
            Period::Months(n) => self.add_months(u64::from(n)),
            Period::Years(n) => u64::from(n)
                .checked_mul(12)
                .and_then(|m| self.add_months(m)),
        }
    }

    /// 00:00 UTC on 1 January of the year after the one `self` falls in: the latest reading of
    /// "the end of the calendar year".
    #[must_use]
    pub fn next_year_start(self) -> Option<Self> {
        let (y, _, _) = civil(self.0 / MS_PER_DAY)?;
        let days = days_from_civil(y.checked_add(1)?, 1, 1)?;
        days.checked_mul(MS_PER_DAY).map(Self)
    }

    fn add_months(self, months: u64) -> Option<Self> {
        let days = self.0 / MS_PER_DAY;
        let in_day = self.0 % MS_PER_DAY;
        let (y, m, d) = civil(days)?;
        let total = m.checked_sub(1)?.checked_add(months)?;
        let year = y.checked_add(total / 12)?;
        let month = (total % 12).checked_add(1)?;
        let (year, month, day) = if d <= days_in_month(year, month) {
            (year, month, d)
        } else if month == 12 {
            (year.checked_add(1)?, 1, 1)
        } else {
            (year, month.checked_add(1)?, 1)
        };
        days_from_civil(year, month, day)?
            .checked_mul(MS_PER_DAY)?
            .checked_add(in_day)
            .map(Self)
    }
}

const fn is_leap(y: u64) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}

const fn days_in_month(y: u64, m: u64) -> u64 {
    match m {
        2 if is_leap(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// (year, month, day) of a day count since 1970-01-01.
pub(crate) fn civil(days: u64) -> Option<(u64, u64, u64)> {
    let z = days.checked_add(EPOCH_SHIFT)?;
    let era = z / DAYS_PER_ERA;
    let doe = z % DAYS_PER_ERA;
    let yoe = doe
        .checked_sub(doe / 1460)?
        .checked_add(doe / 36_524)?
        .checked_sub(doe / 146_096)?
        / 365;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe / 4)?
            .checked_sub(yoe / 100)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)? / 153;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)? / 5)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = era.checked_mul(400)?.checked_add(yoe)?;
    let y = if m <= 2 { y.checked_add(1)? } else { y };
    Some((y, m, d))
}

/// Day count since 1970-01-01 of a date on or after it.
pub(crate) fn days_from_civil(y: u64, m: u64, d: u64) -> Option<u64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y / 400;
    let yoe = y % 400;
    let mp = m.checked_add(9)? % 12;
    let doy = (mp.checked_mul(153)?.checked_add(2)? / 5)
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(DAYS_PER_ERA)?
        .checked_add(doe)?
        .checked_sub(EPOCH_SHIFT)
}

#[cfg(test)]
mod tests;
