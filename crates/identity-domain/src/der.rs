//! A small DER writer for the requests and certificates a custom domain needs (RFC 2986,
//! RFC 5280, RFC 8737): definite shortest-form lengths, no allocation beyond the output.

/// `BOOLEAN`.
pub const BOOLEAN: u8 = 0x01;
/// `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub const BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// `OBJECT IDENTIFIER`.
pub const OID: u8 = 0x06;
/// `UTF8String`.
pub const UTF8: u8 = 0x0c;
/// `UTCTime`.
pub const UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
pub const GENERALIZED_TIME: u8 = 0x18;
/// `SEQUENCE`.
pub const SEQUENCE: u8 = 0x30;
/// `SET`.
pub const SET: u8 = 0x31;

/// `id-ecPublicKey` (RFC 5480).
pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `prime256v1` (RFC 5480).
pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// `ecdsa-with-SHA256` (RFC 5758).
pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// `id-at-commonName`.
pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
/// `id-ce-subjectAltName`.
pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
/// `id-ce-basicConstraints`.
pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// `id-ce-keyUsage`.
pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
/// `id-ce-extKeyUsage`.
pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
/// `id-kp-serverAuth`.
pub const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
/// `pkcs-9-at-extensionRequest` (RFC 2985).
pub const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
/// `id-pe-acmeIdentifier` (RFC 8737 §6.1).
pub const ACME_IDENTIFIER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];

/// One element with `tag` and `content`.
#[must_use]
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len().saturating_add(6));
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let used = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(0));
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
    out
}

/// A `SEQUENCE` of the concatenated `parts`.
#[must_use]
pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// A `SET` of the concatenated `parts`, already in DER order.
#[must_use]
pub fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SET, &parts.concat())
}

/// An `OBJECT IDENTIFIER` from its encoded arcs.
#[must_use]
pub fn oid(arcs: &[u8]) -> Vec<u8> {
    tlv(OID, arcs)
}

/// A non-negative `INTEGER` from big-endian magnitude bytes.
#[must_use]
pub fn uint(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude
        .iter()
        .take_while(|b| **b == 0)
        .count()
        .min(magnitude.len().saturating_sub(1));
    let trimmed = magnitude.get(skip..).unwrap_or_default();
    let mut content = Vec::with_capacity(trimmed.len().saturating_add(1));
    if trimmed.is_empty() || trimmed.first().is_some_and(|b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    tlv(INTEGER, &content)
}

/// A `BIT STRING` with no unused bits.
#[must_use]
pub fn bits(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len().saturating_add(1));
    content.push(0);
    content.extend_from_slice(bytes);
    tlv(BIT_STRING, &content)
}

/// An `OCTET STRING`.
#[must_use]
pub fn octets(bytes: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, bytes)
}

/// A context-specific constructed `[n]` around `content` (explicit tagging).
#[must_use]
pub fn explicit(n: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | (n & 0x1f), content)
}

/// `BOOLEAN TRUE`.
#[must_use]
pub fn true_() -> Vec<u8> {
    tlv(BOOLEAN, &[0xff])
}

/// A `Name` of one common name, or the empty name.
#[must_use]
pub fn name(common_name: Option<&str>) -> Vec<u8> {
    match common_name {
        Some(cn) => seq(&[&set(&[&seq(&[
            &oid(COMMON_NAME),
            &tlv(UTF8, cn.as_bytes()),
        ])])]),
        None => seq(&[]),
    }
}

/// The `SubjectPublicKeyInfo` of an uncompressed SEC1 P-256 point.
#[must_use]
pub fn p256_spki(sec1: &[u8]) -> Vec<u8> {
    seq(&[&seq(&[&oid(EC_PUBLIC_KEY), &oid(P256)]), &bits(sec1)])
}

/// The `ecdsa-with-SHA256` `AlgorithmIdentifier` (no parameters, RFC 5758 §3.2).
#[must_use]
pub fn ecdsa_sha256() -> Vec<u8> {
    seq(&[&oid(ECDSA_SHA256)])
}

/// An `Ecdsa-Sig-Value` from a raw `r ‖ s` signature.
///
/// # Errors
/// [`DerWriteError::Signature`] for a signature that is not 64 bytes.
pub fn ecdsa_sig_value(raw: &[u8]) -> Result<Vec<u8>, DerWriteError> {
    if raw.len() != 64 {
        return Err(DerWriteError::Signature);
    }
    let (r, s) = raw.split_at(32);
    Ok(seq(&[&uint(r), &uint(s)]))
}

/// The raw `r ‖ s` of an `Ecdsa-Sig-Value`.
///
/// # Errors
/// [`DerWriteError::Signature`].
pub fn ecdsa_raw(der: &[u8]) -> Result<[u8; 64], DerWriteError> {
    use access_parse::der::{INTEGER as INT, Reader, SEQUENCE as SEQ};
    let mut outer = Reader::new(der).map_err(|_| DerWriteError::Signature)?;
    let body = outer.tagged(SEQ).map_err(|_| DerWriteError::Signature)?;
    let mut r = Reader::new(body).map_err(|_| DerWriteError::Signature)?;
    let mut out = [0_u8; 64];
    for half in out.chunks_mut(32) {
        let v = r.tagged(INT).map_err(|_| DerWriteError::Signature)?;
        let v = match v {
            [0, rest @ ..] => rest,
            all => all,
        };
        let at = 32_usize
            .checked_sub(v.len())
            .ok_or(DerWriteError::Signature)?;
        half.get_mut(at..)
            .ok_or(DerWriteError::Signature)?
            .copy_from_slice(v);
    }
    if !r.is_empty() || !outer.is_empty() {
        return Err(DerWriteError::Signature);
    }
    Ok(out)
}

/// Why DER could not be written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DerWriteError {
    /// A signature that is not an ECDSA P-256 `r ‖ s`.
    #[error("signature")]
    Signature,
    /// A time outside 1950–9999.
    #[error("time")]
    Time,
}

/// The X.509 `Time` of `unix_s`: `UTCTime` through 2049, `GeneralizedTime` after (RFC 5280
/// §4.1.2.5).
///
/// # Errors
/// [`DerWriteError::Time`].
pub fn time(unix_s: i64) -> Result<Vec<u8>, DerWriteError> {
    let t = time::OffsetDateTime::from_unix_timestamp(unix_s).map_err(|_| DerWriteError::Time)?;
    let year = t.year();
    if !(1950..=9999).contains(&year) {
        return Err(DerWriteError::Time);
    }
    let rest = format!(
        "{:02}{:02}{:02}{:02}{:02}Z",
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    if year < 2050 {
        let yy = year.checked_rem(100).ok_or(DerWriteError::Time)?;
        Ok(tlv(UTC_TIME, format!("{yy:02}{rest}").as_bytes()))
    } else {
        Ok(tlv(GENERALIZED_TIME, format!("{year:04}{rest}").as_bytes()))
    }
}

/// The Unix seconds of an X.509 `Time` element (`tag`, `value`).
#[must_use]
pub fn parse_time(tag: u8, value: &[u8]) -> Option<i64> {
    let text = core::str::from_utf8(value).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |from: usize, len: usize| {
        digits
            .get(from..from.checked_add(len)?)
            .and_then(|s| s.parse::<u16>().ok())
    };
    let (year, at): (u16, usize) = match (tag, digits.len()) {
        (UTC_TIME, 12) => {
            let yy = n(0, 2)?;
            (
                if yy >= 50 {
                    yy.checked_add(1900)?
                } else {
                    yy.checked_add(2000)?
                },
                2,
            )
        }
        (GENERALIZED_TIME, 14) => (n(0, 4)?, 4),
        _ => return None,
    };
    let part =
        |k: usize| n(at.checked_add(k.checked_mul(2)?)?, 2).and_then(|v| u8::try_from(v).ok());
    let month = time::Month::try_from(part(0)?).ok()?;
    let date = time::Date::from_calendar_date(i32::from(year), month, part(1)?).ok()?;
    let clock = time::Time::from_hms(part(2)?, part(3)?, part(4)?).ok()?;
    Some(
        time::PrimitiveDateTime::new(date, clock)
            .assume_utc()
            .unix_timestamp(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_are_shortest_form() {
        assert_eq!(tlv(OCTET_STRING, &[]), vec![0x04, 0x00]);
        assert_eq!(tlv(OCTET_STRING, &[0; 0x7f])[..2], [0x04, 0x7f]);
        assert_eq!(tlv(OCTET_STRING, &[0; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(
            tlv(OCTET_STRING, &[0; 0x100])[..4],
            [0x04, 0x82, 0x01, 0x00]
        );
    }

    #[test]
    fn integers_are_minimal_and_positive() {
        assert_eq!(uint(&[0, 0, 1]), vec![0x02, 0x01, 0x01]);
        assert_eq!(uint(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0]), vec![0x02, 0x01, 0x00]);
    }

    #[test]
    fn signatures_round_trip() {
        let mut raw = [0_u8; 64];
        raw[0] = 0x80;
        raw[31] = 1;
        raw[63] = 2;
        let der = ecdsa_sig_value(&raw).unwrap();
        assert_eq!(ecdsa_raw(&der).unwrap(), raw);
    }

    #[test]
    fn times_round_trip() {
        for t in [
            0_i64,
            951_782_400,
            2_524_608_000,
            1_794_355_200,
            4_102_444_799,
        ] {
            let der = time(t).unwrap();
            assert_eq!(parse_time(der[0], &der[2..]), Some(t), "{t}");
        }
        assert_eq!(time(1_794_355_200).unwrap()[0], UTC_TIME);
        assert_eq!(time(2_524_608_000).unwrap()[0], GENERALIZED_TIME);
    }
}
