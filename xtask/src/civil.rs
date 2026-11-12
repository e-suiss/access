//! UTC calendar arithmetic for the disclosure tools: RFC 3339 instants as Unix seconds,
//! calendar dates, and calendar-month steps (OP-159 m.3 (jj)).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "calendar arithmetic on four-digit years and saturating offsets"
)]

const DAY: i64 = 86_400;

/// Days since 1970-01-01 of a proleptic Gregorian date.
pub(crate) fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The date of a day count since 1970-01-01.
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn digits(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parses `YYYY-MM-DD`.
pub(crate) fn parse_date(s: &str) -> Option<i64> {
    let mut parts = s.split('-');
    let (y, m, d) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d) = (i64::from(digits(y)?), digits(m)?, digits(d)?);
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Parses an RFC 3339 date-time (`2026-11-12T09:30:00Z`, fractions and offsets allowed) into
/// Unix seconds.
pub(crate) fn parse_rfc3339(s: &str) -> Option<i64> {
    let (date, rest) = s.split_once(['T', 't'])?;
    let days = parse_date(date)?;
    let (time, offset) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
        (t, 0)
    } else {
        let at = rest.rfind(['+', '-'])?;
        let (t, off) = rest.split_at(at);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off.get(1..)?.split_once(':')?;
        if oh.len() != 2 || om.len() != 2 {
            return None;
        }
        let (oh, om) = (digits(oh)?, digits(om)?);
        if oh > 23 || om > 59 {
            return None;
        }
        (t, sign * i64::from(oh * 3600 + om * 60))
    };
    let time = time.split_once('.').map_or(
        time,
        |(t, frac)| {
            if digits(frac).is_some() { t } else { "" }
        },
    );
    let mut hms = time.split(':');
    let (h, mi, se) = (hms.next()?, hms.next()?, hms.next()?);
    if hms.next().is_some() || h.len() != 2 || mi.len() != 2 || se.len() != 2 {
        return None;
    }
    let (h, mi, se) = (digits(h)?, digits(mi)?, digits(se)?);
    if h > 23 || mi > 59 || se > 60 {
        return None;
    }
    Some(days * DAY + i64::from(h * 3600 + mi * 60 + se) - offset)
}

/// Formats Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn format_rfc3339(t: i64) -> String {
    let (year, month, day) = civil_from_days(t.div_euclid(DAY));
    let secs = t.rem_euclid(DAY);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Formats a day count as `YYYY-MM-DD`.
pub(crate) fn format_date(days: i64) -> String {
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `t` plus `hours`.
pub(crate) fn add_hours(t: i64, hours: i64) -> i64 {
    t.saturating_add(hours.saturating_mul(3600))
}

/// `t` plus `days`.
pub(crate) fn add_days(t: i64, days: i64) -> i64 {
    t.saturating_add(days.saturating_mul(DAY))
}

/// `t` plus calendar months; a day past the end of the target month becomes its last day.
pub(crate) fn add_months(t: i64, months: u32) -> i64 {
    let days = t.div_euclid(DAY);
    let secs = t.rem_euclid(DAY);
    let (y, m, d) = civil_from_days(days);
    let index = y * 12 + i64::from(m - 1) + i64::from(months);
    let (ny, nm) = (
        index.div_euclid(12),
        u32::try_from(index.rem_euclid(12)).unwrap_or(0) + 1,
    );
    days_from_civil(ny, nm, d.min(days_in_month(ny, nm))) * DAY + secs
}

/// A day count plus calendar years; 29 February becomes 28 February in a common year.
pub(crate) fn add_years(days: i64, years: u32) -> i64 {
    add_months(days * DAY, years.saturating_mul(12)).div_euclid(DAY)
}

/// The current time in Unix seconds.
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_dates_and_instants() {
        for (y, m, d) in [(1970, 1, 1), (2000, 2, 29), (2026, 11, 12), (2100, 12, 31)] {
            assert_eq!(civil_from_days(days_from_civil(y, m, d)), (y, m, d));
        }
        let t = parse_rfc3339("2026-11-12T09:30:00Z").unwrap();
        assert_eq!(format_rfc3339(t), "2026-11-12T09:30:00Z");
        assert_eq!(parse_rfc3339("2026-11-12T12:30:00.250+03:00"), Some(t));
        assert_eq!(parse_rfc3339("2026-11-12"), None);
        assert_eq!(parse_rfc3339("2026-02-30T00:00:00Z"), None);
        assert_eq!(parse_date("2026-1-01"), None);
    }

    #[test]
    fn month_steps_clamp_to_the_last_day() {
        let t = parse_rfc3339("2027-01-31T10:00:00Z").unwrap();
        assert_eq!(format_rfc3339(add_months(t, 1)), "2027-02-28T10:00:00Z");
        let t = parse_rfc3339("2026-12-15T00:00:00Z").unwrap();
        assert_eq!(format_rfc3339(add_months(t, 1)), "2027-01-15T00:00:00Z");
        let leap = parse_date("2028-02-29").unwrap();
        assert_eq!(format_date(add_years(leap, 5)), "2033-02-28");
    }
}
