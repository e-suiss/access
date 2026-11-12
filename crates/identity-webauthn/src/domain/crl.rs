//! Certificate revocation lists of attestation chains (RFC 5280 §5; §10.2.4, OP-159 m.3 (ll)):
//! what a registration fetched for each distribution point, and the fields a cache needs. Path
//! validation checks the signature, `nextUpdate` and the serial with rustls-webpki.

/// Ceiling for one CRL (PD).
pub const MAX_CRL: usize = 1024 * 1024;

/// What each distribution point gave: the CRL bytes, or nothing when it could not be read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Crls(Vec<(String, Option<Vec<u8>>)>);

impl Crls {
    /// Records what `url` gave.
    pub fn insert(&mut self, url: String, crl: Option<Vec<u8>>) {
        let crl = crl.filter(|c| !c.is_empty() && c.len() <= MAX_CRL);
        match self.0.iter_mut().find(|(u, _)| *u == url) {
            Some(entry) => entry.1 = crl,
            None => self.0.push((url, crl)),
        }
    }

    /// The CRL `url` gave; `None` when it was not fetched or could not be read.
    #[must_use]
    pub fn get(&self, url: &str) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(u, _)| u == url)
            .and_then(|(_, c)| c.as_deref())
    }
}

/// The header of a CRL: `TBSCertList` up to `nextUpdate`.
fn header(der: &[u8]) -> Option<&[u8]> {
    let (outer, _) = definite(der, 0x30)?;
    let (tbs, _) = definite(outer, 0x30)?;
    Some(tbs)
}

/// The contents of the element `tag` at the start of `input`, and what follows it; lengths up
/// to four octets, as a large CRL needs.
fn definite(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    let (&t, rest) = input.split_first()?;
    if t != tag {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let bytes = rest.get(..n)?;
        rest = rest.get(n..)?;
        if bytes.first() == Some(&0) {
            return None;
        }
        let len = bytes.iter().try_fold(0_usize, |acc, b| {
            acc.checked_mul(256)?.checked_add(usize::from(*b))
        })?;
        if len < 0x80 {
            return None;
        }
        len
    };
    Some((rest.get(..len)?, rest.get(len..)?))
}

fn digits(text: &[u8]) -> Option<u64> {
    if text.is_empty() || !text.iter().all(u8::is_ascii_digit) {
        return None;
    }
    text.iter().try_fold(0_u64, |acc, d| {
        acc.checked_mul(10)?
            .checked_add(u64::from(d.checked_sub(b'0')?))
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date (years 1970–9999).
fn epoch_day(y: u64, m: u64, d: u64) -> Option<u64> {
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.checked_div(400)?;
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
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

/// A `UTCTime` (tag 0x17) or `GeneralizedTime` (tag 0x18) in Zulu, as Unix seconds.
fn time(tag: u8, value: &[u8]) -> Option<u64> {
    let (year, rest) = match tag {
        0x17 => {
            let yy = digits(value.get(..2)?)?;
            let century = if yy >= 50 { 1900 } else { 2000 };
            (yy.checked_add(century)?, value.get(2..)?)
        }
        0x18 => (digits(value.get(..4)?)?, value.get(4..)?),
        _ => return None,
    };
    if rest.len() != 11 || rest.last() != Some(&b'Z') {
        return None;
    }
    let field = |i: usize| digits(rest.get(i..i.checked_add(2)?)?);
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    epoch_day(year, month, day)?
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)
}

/// `nextUpdate` of a CRL as Unix seconds; `None` when it is absent or the CRL is malformed.
#[must_use]
pub fn next_update(der: &[u8]) -> Option<u64> {
    let mut rest = header(der)?;
    if rest.first() == Some(&0x02) {
        rest = definite(rest, 0x02)?.1;
    }
    rest = definite(rest, 0x30)?.1;
    rest = definite(rest, 0x30)?.1;
    let (&this_tag, _) = rest.split_first()?;
    rest = definite(rest, this_tag)?.1;
    let (&tag, _) = rest.split_first()?;
    let (value, _) = definite(rest, tag)?;
    time(tag, value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // OP-159 m.3 (ll)
    #[test]
    fn times_and_lengths() {
        assert_eq!(time(0x17, b"261101000000Z"), Some(1_793_491_200));
        assert_eq!(time(0x18, b"20261101000000Z"), Some(1_793_491_200));
        assert_eq!(time(0x17, b"261301000000Z"), None);
        assert_eq!(time(0x18, b"20261101000000"), None);
        assert_eq!(definite(&[0x30, 0x82, 0x00, 0x80], 0x30), None);
        assert_eq!(definite(&[0x30, 0x81, 0x7f], 0x30), None);
        assert!(next_update(&[0x30, 0x00]).is_none());
        let mut c = Crls::default();
        c.insert("https://a.test/c.crl".into(), None);
        assert_eq!(c.get("https://a.test/c.crl"), None);
        c.insert("https://a.test/c.crl".into(), Some(vec![0x30]));
        assert_eq!(c.get("https://a.test/c.crl"), Some(&[0x30][..]));
        assert_eq!(c.get("https://b.test/c.crl"), None);
    }
}
