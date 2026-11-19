//! Birth dates (TN-158): an ISO calendar date, never in the future, and the age it gives on a day.

use time::{Date, Month, OffsetDateTime};

/// `raw` as an ISO date (`YYYY-MM-DD`), when it is a real day not after `today_ms`.
#[must_use]
pub fn parse(raw: &str, today_ms: u64) -> Option<Date> {
    let t = raw.trim();
    let mut parts = t.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let date = Date::from_calendar_date(
        y.parse().ok()?,
        Month::try_from(m.parse::<u8>().ok()?).ok()?,
        d.parse().ok()?,
    )
    .ok()?;
    (date <= today(today_ms)?).then_some(date)
}

fn today(ms: u64) -> Option<Date> {
    let s = i64::try_from(ms.checked_div(1000)?).ok()?;
    Some(OffsetDateTime::from_unix_timestamp(s).ok()?.date())
}

/// Whole years from `born` to the day of `today_ms`.
#[must_use]
pub fn age(born: Date, today_ms: u64) -> Option<u32> {
    let now = today(today_ms)?;
    let years = now.year().checked_sub(born.year())?;
    let before_birthday = (u8::from(now.month()), now.day()) < (u8::from(born.month()), born.day());
    let years = if before_birthday {
        years.checked_sub(1)?
    } else {
        years
    };
    u32::try_from(years).ok()
}

/// Whether someone born on `raw` is at least `min` years old on the day of `today_ms`; `None`
/// when `raw` is not a birth date.
#[must_use]
pub fn old_enough(raw: &str, min: u32, today_ms: u64) -> Option<bool> {
    let born = parse(raw, today_ms)?;
    Some(age(born, today_ms)? >= min)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_795_089_600_000;

    // TN-158
    #[test]
    fn an_age_counts_whole_years_and_a_date_is_a_real_past_day() {
        assert_eq!(old_enough("2008-11-19", 18, NOW), Some(true));
        assert_eq!(old_enough("2008-11-20", 18, NOW), Some(false));
        assert_eq!(old_enough("1990-02-28", 18, NOW), Some(true));
        assert_eq!(
            old_enough("2030-01-01", 18, NOW),
            None,
            "the future is no birth date"
        );
        assert_eq!(old_enough("2001-02-29", 18, NOW), None, "no such day");
        assert_eq!(old_enough("19-01-2001", 18, NOW), None);
        assert_eq!(old_enough("2001-1-01", 18, NOW), None);
    }
}
