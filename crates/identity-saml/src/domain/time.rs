//! SAML time (§10.6.1, OP-155 m.3 (e)): UTC `xs:dateTime` with `Z`, and the windows Access
//! writes and accepts.

/// `NotBefore` is this far before issue.
pub const NOT_BEFORE_MS: u64 = 60_000;

/// `NotOnOrAfter` is this far after issue.
pub const NOT_ON_OR_AFTER_MS: u64 = 5 * 60_000;

/// `NotOnOrAfter` of an IdP-initiated assertion.
pub const IDP_INITIATED_MS: u64 = 2 * 60_000;

/// Clock skew tolerated on a request's `IssueInstant`.
pub const SKEW_MS: u64 = 3 * 60_000;

/// `SessionNotOnOrAfter` is this far after the authentication.
pub const SESSION_MS: u64 = 8 * 3_600_000;

/// How long a request identifier is kept against replay.
pub const REPLAY_MS: u64 = 10 * 60_000;

/// Oldest `IssueInstant` a request may carry.
pub const REQUEST_MAX_AGE_MS: u64 = REPLAY_MS;

#[allow(
    clippy::arithmetic_side_effects,
    reason = "proleptic Gregorian conversion over bounded day counts"
)]
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let m = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "proleptic Gregorian conversion over parsed calendar fields"
)]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `ms` since the epoch as `YYYY-MM-DDThh:mm:ssZ`.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "bounded calendar arithmetic on a u64 of milliseconds"
)]
pub fn format(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX / 2);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn num(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Reads a UTC `xs:dateTime` (`Z` only, optional fraction) as milliseconds since the epoch.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "bounded calendar arithmetic over parsed two- and four-digit fields"
)]
pub fn parse(s: &str) -> Option<u64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, mo, da) = (d.next()?, d.next()?, d.next()?);
    if d.next().is_some() || y.len() != 4 || mo.len() != 2 || da.len() != 2 {
        return None;
    }
    let (time, frac) = match time.split_once('.') {
        Some((t, f)) if !f.is_empty() && f.len() <= 9 && f.bytes().all(|b| b.is_ascii_digit()) => {
            (t, f)
        }
        Some(_) => return None,
        None => (time, ""),
    };
    let mut t = time.split(':');
    let (h, mi, se) = (t.next()?, t.next()?, t.next()?);
    if t.next().is_some() || h.len() != 2 || mi.len() != 2 || se.len() != 2 {
        return None;
    }
    let (y, mo, da, h, mi, se) = (num(y)?, num(mo)?, num(da)?, num(h)?, num(mi)?, num(se)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&da) || h > 23 || mi > 59 || se > 59 {
        return None;
    }
    let days = days_from_civil(i64::from(y), mo, da);
    if civil(days) != (i64::from(y), mo, da) {
        return None;
    }
    let secs = days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(se);
    let ms = u64::try_from(secs).ok()?.checked_mul(1000)?;
    let frac_ms = frac
        .get(..frac.len().min(3))
        .map_or(0, |f| num(&format!("{f:0<3}")).unwrap_or(0));
    ms.checked_add(u64::from(frac_ms))
}

/// Whether a request issued at `issued` is acceptable at `now`: not more than the skew ahead and
/// not older than the replay window.
#[must_use]
pub fn request_fresh(issued: u64, now: u64) -> bool {
    issued <= now.saturating_add(SKEW_MS)
        && issued >= now.saturating_sub(REQUEST_MAX_AGE_MS.saturating_add(SKEW_MS))
}

#[cfg(test)]
mod tests {
    use super::*;

    // §10.6.1
    #[test]
    fn times_are_utc_with_z_and_round_trip() {
        assert_eq!(format(0), "1970-01-01T00:00:00Z");
        let t = 1_794_304_800_000;
        let s = format(t);
        assert_eq!(s, "2026-11-10T10:00:00Z");
        assert_eq!(parse(&s), Some(t));
        assert_eq!(parse("2026-11-10T10:00:00.123Z"), Some(t + 123));
        assert_eq!(parse("2026-11-10T10:00:00+01:00"), None);
        assert_eq!(parse("2026-02-30T10:00:00Z"), None);
        assert_eq!(
            parse("2024-02-29T00:00:00Z").map(format).as_deref(),
            Some("2024-02-29T00:00:00Z")
        );
    }

    // OP-155 m.3 (e)
    #[test]
    fn request_windows() {
        let now = 1_794_304_800_000;
        assert!(request_fresh(now + SKEW_MS, now));
        assert!(!request_fresh(now + SKEW_MS + 1, now));
        assert!(request_fresh(now - REPLAY_MS, now));
        assert!(!request_fresh(now - REPLAY_MS - SKEW_MS - 1, now));
    }
}
