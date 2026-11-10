//! RFC 3339 instants in UTC (`YYYY-MM-DDTHH:MM:SS[.fraction]Z`), as mdoc `tdate`, trusted
//! lists and Bitstring Status List credentials carry them.

fn digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Days since 1970-01-01 of a proleptic Gregorian date.
#[must_use]
pub fn days_from_civil(year: i64, month: u64, day: u64) -> Option<i64> {
    let m = i64::try_from(month).ok()?;
    let d = i64::try_from(day).ok()?;
    let y = if m <= 2 { year.checked_sub(1)? } else { year };
    let era = y.div_euclid(400);
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = (153_i64.checked_mul(mp)?.checked_add(2)?)
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

fn days_in_month(year: i64, month: u64) -> u64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Unix milliseconds of an RFC 3339 UTC instant; `None` for anything else, including offsets
/// other than `Z` and `+00:00` and instants before 1970.
#[must_use]
pub fn rfc3339_ms(text: &str) -> Option<u64> {
    let (date, time) = text.split_once(['T', 't'])?;
    let time = time
        .strip_suffix(['Z', 'z'])
        .or_else(|| time.strip_suffix("+00:00"))?;
    let mut ymd = date.split('-');
    let (y, mo, da) = (ymd.next()?, ymd.next()?, ymd.next()?);
    if ymd.next().is_some() || y.len() != 4 || mo.len() != 2 || da.len() != 2 {
        return None;
    }
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut hms = clock.split(':');
    let (h, mi, se) = (hms.next()?, hms.next()?, hms.next()?);
    if hms.next().is_some() || h.len() != 2 || mi.len() != 2 || se.len() != 2 {
        return None;
    }
    let year = i64::try_from(digits(y)?).ok()?;
    let (month, day) = (digits(mo)?, digits(da)?);
    let (hour, minute, second) = (digits(h)?, digits(mi)?, digits(se)?);
    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let millis = if fraction.is_empty() {
        0
    } else {
        if fraction.len() > 9 {
            return None;
        }
        let head: String = fraction.chars().chain("000".chars()).take(3).collect();
        digits(fraction)?;
        digits(&head)?
    };
    let days = u64::try_from(days_from_civil(year, month, day)?).ok()?;
    days.checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?
        .checked_mul(1000)?
        .checked_add(millis)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::rfc3339_ms;

    #[test]
    fn reads_utc_instants_only() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            rfc3339_ms("2026-11-10T12:00:00.5Z"),
            Some(1_794_312_000_500)
        );
        assert_eq!(
            rfc3339_ms("2024-02-29T00:00:00+00:00"),
            Some(1_709_164_800_000)
        );
        assert_eq!(rfc3339_ms("2023-02-29T00:00:00Z"), None);
        assert_eq!(rfc3339_ms("2026-11-10T12:00:00+01:00"), None);
        assert_eq!(rfc3339_ms("2026-11-10"), None);
    }
}
