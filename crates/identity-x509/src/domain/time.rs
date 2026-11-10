//! `UTCTime` and `GeneralizedTime` (RFC 5280 §4.1.2.5): Zulu, whole seconds, no fractions.

/// Seconds since the Unix epoch of a proleptic Gregorian date and time; `None` when out of
/// range.
fn unix(year: u64, month: u64, day: u64, (h, m, s): (u64, u64, u64)) -> Option<u64> {
    let leap = |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let days_in = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let month_days = *days_in.get(usize::try_from(month.checked_sub(1)?).ok()?)?;
    if !(1970..=9999).contains(&year) || day == 0 || day > month_days || h > 23 || m > 59 || s > 59
    {
        return None;
    }
    let mut days: u64 = 0;
    for y in 1970..year {
        days = days.checked_add(if leap(y) { 366 } else { 365 })?;
    }
    for d in days_in
        .iter()
        .take(usize::try_from(month.checked_sub(1)?).ok()?)
    {
        days = days.checked_add(*d)?;
    }
    days = days.checked_add(day.checked_sub(1)?)?;
    days.checked_mul(86_400)?
        .checked_add(h.checked_mul(3600)?)?
        .checked_add(m.checked_mul(60)?)?
        .checked_add(s)
}

fn digits(s: &[u8]) -> Option<u64> {
    s.iter().try_fold(0_u64, |acc, c| {
        c.is_ascii_digit()
            .then(|| {
                acc.checked_mul(10)?
                    .checked_add(u64::from(c.checked_sub(b'0')?))
            })
            .flatten()
    })
}

fn clock(s: &[u8]) -> Option<(u64, u64, u64)> {
    Some((
        digits(s.get(0..2)?)?,
        digits(s.get(2..4)?)?,
        digits(s.get(4..6)?)?,
    ))
}

/// A `GeneralizedTime` value (`YYYYMMDDHHMMSSZ`) in Unix seconds.
#[must_use]
pub fn generalized(value: &[u8]) -> Option<u64> {
    if value.len() != 15 || value.last() != Some(&b'Z') {
        return None;
    }
    unix(
        digits(value.get(0..4)?)?,
        digits(value.get(4..6)?)?,
        digits(value.get(6..8)?)?,
        clock(value.get(8..14)?)?,
    )
}

/// A `UTCTime` value (`YYMMDDHHMMSSZ`, 1950–2049) in Unix seconds.
#[must_use]
pub fn utc(value: &[u8]) -> Option<u64> {
    if value.len() != 13 || value.last() != Some(&b'Z') {
        return None;
    }
    let yy = digits(value.get(0..2)?)?;
    let year = if yy >= 50 {
        yy.checked_add(1900)?
    } else {
        yy.checked_add(2000)?
    };
    unix(
        year,
        digits(value.get(2..4)?)?,
        digits(value.get(4..6)?)?,
        clock(value.get(6..12)?)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 5280 §4.1.2.5
    #[test]
    fn times_are_read_strictly() {
        assert_eq!(generalized(b"19700101000000Z"), Some(0));
        assert_eq!(generalized(b"20270115123456Z"), Some(1_800_016_496));
        assert_eq!(generalized(b"20240229000000Z"), Some(1_709_164_800));
        assert_eq!(generalized(b"20230229000000Z"), None);
        assert_eq!(generalized(b"20270115123456.5Z"), None);
        assert_eq!(generalized(b"20270115123456+0100"), None);
        assert_eq!(generalized(b"2027011512345Z"), None);
        assert_eq!(utc(b"270115123456Z"), Some(1_800_016_496));
        assert_eq!(utc(b"700101000000Z"), Some(0));
        assert_eq!(utc(b"271315123456Z"), None);
    }
}
