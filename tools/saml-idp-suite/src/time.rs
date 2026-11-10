//! `xs:dateTime` in UTC, as SAML requires (Core §1.3.3): no offset other than `Z`.

fn digits(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
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

#[allow(clippy::many_single_char_names, reason = "date and time fields")]
/// Seconds since the Unix epoch of `YYYY-MM-DDThh:mm:ss[.fff]Z`; `None` otherwise.
#[must_use]
pub fn parse_instant(v: &str) -> Option<i64> {
    let v = v.strip_suffix('Z')?;
    let (date, time) = v.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da) = (digits(d.next()?)?, digits(d.next()?)?, digits(d.next()?)?);
    if d.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&da) {
        return None;
    }
    let time = time.split_once('.').map_or(time, |(t, frac)| {
        if frac.bytes().all(|b| b.is_ascii_digit()) && !frac.is_empty() {
            t
        } else {
            ""
        }
    });
    let mut t = time.split(':');
    let (h, mi, s) = (digits(t.next()?)?, digits(t.next()?)?, digits(t.next()?)?);
    if t.next().is_some() || h > 23 || mi > 59 || s > 60 {
        return None;
    }
    days_from_civil(y, mo, da)?
        .checked_mul(86_400)?
        .checked_add(h.checked_mul(3600)?)?
        .checked_add(mi.checked_mul(60)?)?
        .checked_add(s)
}

/// `YYYY-MM-DDThh:mm:ssZ` of seconds since the Unix epoch.
#[must_use]
pub fn format_instant(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.saturating_sub(era.saturating_mul(146_097));
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365;
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    );
    let mp = (doy.saturating_mul(5).saturating_add(2)) / 153;
    let d = doy
        .saturating_sub((mp.saturating_mul(153).saturating_add(2)) / 5)
        .saturating_add(1);
    let m = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    };
    let y = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(m <= 2));
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Now, in seconds since the Unix epoch.
#[must_use]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_utc_instants() {
        for s in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T12:34:56Z",
            "2026-11-10T10:00:00Z",
        ] {
            assert_eq!(format_instant(parse_instant(s).unwrap()), s);
        }
        assert_eq!(
            parse_instant("2026-11-10T10:00:00.123Z"),
            parse_instant("2026-11-10T10:00:00Z")
        );
        assert_eq!(parse_instant("1970-01-02T00:00:00Z"), Some(86_400));
        assert!(parse_instant("2026-11-10T10:00:00+01:00").is_none());
        assert!(parse_instant("2026-13-10T10:00:00Z").is_none());
    }
}
