//! RFC 3339 UTC timestamps as vendors write them, to Unix milliseconds.

fn digits(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Days from 1970-01-01 to `y-m-d` in the proleptic Gregorian calendar.
fn days(y: u64, m: u64, d: u64) -> Option<u64> {
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (y, m) = if m <= 2 {
        (y.checked_sub(1)?, m.checked_add(12)?)
    } else {
        (y, m)
    };
    let era_days = y
        .checked_mul(365)?
        .checked_add(y / 4)?
        .checked_sub(y / 100)?
        .checked_add(y / 400)?;
    let month_days = (153u64.checked_mul(m.checked_sub(3)?)?.checked_add(2)?) / 5;
    era_days
        .checked_add(month_days)?
        .checked_add(d)?
        .checked_sub(719_469)
}

/// `YYYY-MM-DDTHH:MM:SS[.fff…]Z` (or `+00:00`) as Unix milliseconds; any other offset or
/// form is `None`.
#[must_use]
pub fn rfc3339_ms(text: &str) -> Option<u64> {
    let rest = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))?;
    let (date, time) = rest.split_once('T')?;
    let mut parts = date.split('-');
    let (year, month, day) = (
        digits(parts.next()?)?,
        digits(parts.next()?)?,
        digits(parts.next()?)?,
    );
    if parts.next().is_some() {
        return None;
    }
    let (hms, frac) = time.split_once('.').unwrap_or((time, ""));
    let mut clock = hms.split(':');
    let (hour, min, sec) = (
        digits(clock.next()?)?,
        digits(clock.next()?)?,
        digits(clock.next()?)?,
    );
    if clock.next().is_some() || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let ms = if frac.is_empty() {
        0
    } else {
        digits(frac)?;
        let three: String = frac.chars().chain("000".chars()).take(3).collect();
        digits(&three)?
    };
    days(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(min.checked_mul(60)?)?
        .checked_add(sec)?
        .checked_mul(1_000)?
        .checked_add(ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_timestamps_read_as_utc_milliseconds() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_ms("2026-11-01T10:00:00Z"), Some(1_793_527_200_000));
        assert_eq!(
            rfc3339_ms("2026-11-01T10:00:00.250+00:00"),
            Some(1_793_527_200_250)
        );
        assert_eq!(rfc3339_ms("2024-02-29T00:00:00Z"), Some(1_709_164_800_000));
        assert_eq!(rfc3339_ms("2026-11-01T10:00:00+03:00"), None);
        assert_eq!(rfc3339_ms("2026-13-01T10:00:00Z"), None);
        assert_eq!(rfc3339_ms("yesterday"), None);
    }
}
