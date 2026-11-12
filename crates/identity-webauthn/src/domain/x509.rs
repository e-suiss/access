//! The X.509 fields attestation statements depend on and path validation does not expose
//! (RFC 5280; WebAuthn L3 §8): a bounded DER reader with the high tag numbers Android's
//! `AuthorizationList` uses (CR-10), the certificate fields, its extensions and its public key.

use super::cose::CoseKey;

/// Ceiling for one certificate or extension (CR-10, PD).
pub(crate) const MAX_INPUT: usize = 16 * 1024;

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OID: u8 = 0x06;
pub(crate) const ENUMERATED: u8 = 0x0a;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// 2.5.29.17, subjectAltName.
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// 2.5.29.19, basicConstraints.
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// 2.5.29.37, extKeyUsage.
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
/// 2.5.29.14, subjectKeyIdentifier.
const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
/// 2.5.29.31, cRLDistributionPoints.
const OID_CRL_DP: &[u8] = &[0x55, 0x1d, 0x1f];
/// 1.2.840.10045.2.1, id-ecPublicKey.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// 1.2.840.10045.3.1.7, prime256v1.
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// 1.3.101.112, id-Ed25519.
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
/// 1.2.840.113549.1.1.1, rsaEncryption.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/// Most distribution point URIs read from one certificate (PD).
pub(crate) const MAX_POINTS: usize = 4;
/// Longest distribution point URI (PD).
pub(crate) const MAX_URI: usize = 512;

/// Why DER input is rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DerError;

/// A tag: its first octet and its number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag {
    pub(crate) first: u8,
    pub(crate) number: u32,
}

impl Tag {
    /// Whether it is the single-octet tag `byte`.
    pub(crate) const fn is(self, byte: u8) -> bool {
        self.first == byte && self.first & 0x1f != 0x1f
    }

    /// Whether it is the context-specific tag `[number]`.
    pub(crate) const fn context(self, number: u32) -> bool {
        self.first & 0xc0 == 0x80 && self.number == number
    }
}

/// One element.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: Tag,
    pub(crate) value: &'a [u8],
}

/// A cursor over consecutive elements: definite, shortest-form lengths; tag numbers up to three
/// octets; nothing is allocated.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(input: &'a [u8]) -> Result<Self, DerError> {
        if input.len() > MAX_INPUT {
            Err(DerError)
        } else {
            Ok(Self { rest: input })
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn tag(&mut self) -> Result<Tag, DerError> {
        let (&first, rest) = self.rest.split_first().ok_or(DerError)?;
        self.rest = rest;
        if first & 0x1f != 0x1f {
            return Ok(Tag {
                first,
                number: u32::from(first & 0x1f),
            });
        }
        let mut number = 0_u32;
        for i in 0..3 {
            let (&b, rest) = self.rest.split_first().ok_or(DerError)?;
            self.rest = rest;
            if i == 0 && b == 0x80 {
                return Err(DerError);
            }
            number = number.checked_mul(128).ok_or(DerError)? | u32::from(b & 0x7f);
            if b & 0x80 == 0 {
                if number < 31 {
                    return Err(DerError);
                }
                return Ok(Tag { first, number });
            }
        }
        Err(DerError)
    }

    pub(crate) fn next_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
        let tag = self.tag()?;
        let (&first, mut rest) = self.rest.split_first().ok_or(DerError)?;
        let len = if first < 0x80 {
            usize::from(first)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 2 {
                return Err(DerError);
            }
            let bytes = rest.get(..n).ok_or(DerError)?;
            rest = rest.get(n..).ok_or(DerError)?;
            let len = bytes
                .iter()
                .fold(0_usize, |acc, b| acc.wrapping_shl(8) | usize::from(*b));
            if len < 0x80 || bytes.first() == Some(&0) {
                return Err(DerError);
            }
            len
        };
        let value = rest.get(..len).ok_or(DerError)?;
        self.rest = rest.get(len..).ok_or(DerError)?;
        Ok(Tlv { tag, value })
    }

    pub(crate) fn tagged(&mut self, byte: u8) -> Result<&'a [u8], DerError> {
        let tlv = self.next_tlv()?;
        if tlv.tag.is(byte) {
            Ok(tlv.value)
        } else {
            Err(DerError)
        }
    }

    /// The next element when it carries the single-octet tag `byte`; nothing is read otherwise.
    pub(crate) fn optional(&mut self, byte: u8) -> Result<Option<&'a [u8]>, DerError> {
        let mut peek = *self;
        match peek.next_tlv() {
            Ok(t) if t.tag.is(byte) => {
                *self = peek;
                Ok(Some(t.value))
            }
            Ok(_) => Ok(None),
            Err(_) if self.rest.is_empty() => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A non-negative DER INTEGER of at most eight octets.
pub(crate) fn uint(value: &[u8]) -> Result<u64, DerError> {
    let body = match value {
        [0, rest @ ..] if rest.first().is_some_and(|b| b & 0x80 != 0) => rest,
        [b, ..] if b & 0x80 != 0 => return Err(DerError),
        [0, _, ..] => return Err(DerError),
        other => other,
    };
    if body.is_empty() || body.len() > 8 {
        return Err(DerError);
    }
    Ok(body
        .iter()
        .fold(0_u64, |acc, b| acc.wrapping_shl(8) | u64::from(*b)))
}

/// A DER BOOLEAN.
pub(crate) fn boolean(value: &[u8]) -> Result<bool, DerError> {
    match value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(DerError),
    }
}

/// A positive big-endian integer without leading zero octets.
pub(crate) fn magnitude(value: &[u8]) -> &[u8] {
    let mut v = value;
    while let [0, rest @ ..] = v {
        v = rest;
    }
    v
}

/// One extension.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Extension<'a> {
    pub(crate) oid: &'a [u8],
    pub(crate) critical: bool,
    pub(crate) value: &'a [u8],
}

/// The fields of a certificate attestation checks read.
#[derive(Clone, Debug)]
pub(crate) struct Cert<'a> {
    pub(crate) version: u64,
    pub(crate) issuer: &'a [u8],
    pub(crate) subject: &'a [u8],
    pub(crate) key_algorithm: &'a [u8],
    pub(crate) key_parameters: Option<&'a [u8]>,
    pub(crate) public_key: &'a [u8],
    pub(crate) extensions: Vec<Extension<'a>>,
}

impl<'a> Cert<'a> {
    /// Reads the `TBSCertificate` of `der`.
    pub(crate) fn parse(der: &'a [u8]) -> Result<Self, DerError> {
        let mut outer = Reader::new(der)?;
        let cert = outer.tagged(SEQUENCE)?;
        if !outer.is_empty() {
            return Err(DerError);
        }
        let mut c = Reader::new(cert)?;
        let mut tbs = Reader::new(c.tagged(SEQUENCE)?)?;
        let mut version = 0;
        let mut first = tbs.next_tlv()?;
        if first.tag.first == 0xa0 {
            version = uint(Reader::new(first.value)?.tagged(INTEGER)?)?;
            first = tbs.next_tlv()?;
        }
        if !first.tag.is(INTEGER) {
            return Err(DerError);
        }
        tbs.tagged(SEQUENCE)?;
        let issuer = tbs.tagged(SEQUENCE)?;
        tbs.tagged(SEQUENCE)?;
        let subject = tbs.tagged(SEQUENCE)?;
        let mut spki = Reader::new(tbs.tagged(SEQUENCE)?)?;
        let mut alg = Reader::new(spki.tagged(SEQUENCE)?)?;
        let key_algorithm = alg.tagged(OID)?;
        let key_parameters = if alg.is_empty() {
            None
        } else {
            let p = alg.next_tlv()?;
            if p.tag.is(OID) { Some(p.value) } else { None }
        };
        let bits = spki.tagged(BIT_STRING)?;
        let [0, public_key @ ..] = bits else {
            return Err(DerError);
        };
        let mut extensions = Vec::new();
        while !tbs.is_empty() {
            let t = tbs.next_tlv()?;
            if t.tag.first != 0xa3 {
                continue;
            }
            let mut list = Reader::new(Reader::new(t.value)?.tagged(SEQUENCE)?)?;
            while !list.is_empty() {
                let mut e = Reader::new(list.tagged(SEQUENCE)?)?;
                let oid = e.tagged(OID)?;
                let critical = e.optional(BOOLEAN)?.map(boolean).transpose()?;
                let value = e.tagged(OCTET_STRING)?;
                if !e.is_empty() {
                    return Err(DerError);
                }
                extensions.push(Extension {
                    oid,
                    critical: critical.unwrap_or(false),
                    value,
                });
            }
        }
        Ok(Self {
            version,
            issuer,
            subject,
            key_algorithm,
            key_parameters,
            public_key,
            extensions,
        })
    }

    /// The extension `oid`; `Err` when it appears more than once (RFC 5280 §4.2).
    pub(crate) fn extension(&self, oid: &[u8]) -> Result<Option<Extension<'a>>, DerError> {
        let mut found = self.extensions.iter().filter(|e| e.oid == oid);
        let first = found.next().copied();
        if found.next().is_some() {
            return Err(DerError);
        }
        Ok(first)
    }

    /// Whether the subjectAltName extension is present and critical.
    pub(crate) fn san_critical(&self) -> Result<bool, DerError> {
        Ok(self.extension(OID_SAN)?.is_some_and(|e| e.critical))
    }

    /// `cA` of the basicConstraints extension; `None` when the extension is absent.
    pub(crate) fn is_ca(&self) -> Result<Option<bool>, DerError> {
        let Some(e) = self.extension(OID_BASIC_CONSTRAINTS)? else {
            return Ok(None);
        };
        let mut seq = Reader::new(Reader::new(e.value)?.tagged(SEQUENCE)?)?;
        let ca = seq.optional(BOOLEAN)?.map(boolean).transpose()?;
        Ok(Some(ca.unwrap_or(false)))
    }

    /// The key purposes of the extKeyUsage extension.
    pub(crate) fn ext_key_usage(&self) -> Result<Vec<&'a [u8]>, DerError> {
        let Some(e) = self.extension(OID_EXT_KEY_USAGE)? else {
            return Ok(Vec::new());
        };
        let mut list = Reader::new(Reader::new(e.value)?.tagged(SEQUENCE)?)?;
        let mut out = Vec::new();
        while !list.is_empty() {
            out.push(list.tagged(OID)?);
        }
        Ok(out)
    }

    /// The subjectKeyIdentifier.
    pub(crate) fn subject_key_id(&self) -> Result<Option<&'a [u8]>, DerError> {
        let Some(e) = self.extension(OID_SKI)? else {
            return Ok(None);
        };
        Reader::new(e.value)?.tagged(OCTET_STRING).map(Some)
    }

    /// The `uniformResourceIdentifier` full names of the cRLDistributionPoints extension
    /// (RFC 5280 §4.2.1.13). A point that names only a CRL issuer or reasons, or is relative to
    /// the issuer, has no URI to fetch and is refused, so a chain that declares one cannot be
    /// read as unrevoked.
    pub(crate) fn crl_points(&self) -> Result<Vec<&'a str>, DerError> {
        let Some(e) = self.extension(OID_CRL_DP)? else {
            return Ok(Vec::new());
        };
        let mut points = Reader::new(Reader::new(e.value)?.tagged(SEQUENCE)?)?;
        let mut out = Vec::new();
        while !points.is_empty() {
            let mut point = Reader::new(points.tagged(SEQUENCE)?)?;
            let name = point.next_tlv()?;
            if name.tag.first != 0xa0 || !point.is_empty() {
                return Err(DerError);
            }
            let full = Reader::new(name.value)?.next_tlv()?;
            if full.tag.first != 0xa0 {
                return Err(DerError);
            }
            let mut names = Reader::new(full.value)?;
            let mut found = false;
            while !names.is_empty() {
                let n = names.next_tlv()?;
                if n.tag.first == 0x86 {
                    if n.value.len() > MAX_URI || out.len() >= MAX_POINTS {
                        return Err(DerError);
                    }
                    out.push(core::str::from_utf8(n.value).map_err(|_| DerError)?);
                    found = true;
                }
            }
            if !found {
                return Err(DerError);
            }
        }
        Ok(out)
    }
}

/// Whether the certificate's public key is the credential's (WebAuthn L3 §8.4 step 3, §8.8
/// step 5).
pub(crate) fn same_key(cert: &Cert<'_>, key: &CoseKey) -> bool {
    match key {
        CoseKey::P256 { point, .. } => {
            cert.key_algorithm == OID_EC_PUBLIC_KEY
                && cert.key_parameters == Some(OID_P256)
                && cert.public_key == point.as_slice()
        }
        CoseKey::Ed25519 { x, .. } => {
            cert.key_algorithm == OID_ED25519 && cert.public_key == x.as_slice()
        }
        CoseKey::Rsa { n, e } => {
            if cert.key_algorithm != OID_RSA {
                return false;
            }
            let read = || -> Result<bool, DerError> {
                let mut outer = Reader::new(cert.public_key)?;
                let mut seq = Reader::new(outer.tagged(SEQUENCE)?)?;
                let cn = seq.tagged(INTEGER)?;
                let ce = seq.tagged(INTEGER)?;
                Ok(outer.is_empty()
                    && seq.is_empty()
                    && magnitude(cn) == magnitude(n)
                    && magnitude(ce) == magnitude(e))
            };
            read().unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // CR-10
    #[test]
    fn high_tag_numbers_and_canonical_lengths() {
        let input = [0xbf, 0x84, 0x58, 0x02, 0x05, 0x00];
        let mut r = Reader::new(&input).unwrap();
        let t = r.next_tlv().unwrap();
        assert!(t.tag.context(600));
        assert_eq!(t.value, &[0x05, 0x00]);
        assert!(r.is_empty());
        for bad in [
            &[0xbf, 0x1e, 0x00][..],
            &[0xbf, 0x80, 0x01, 0x00],
            &[0x04, 0x81, 0x01, 0x00],
            &[0x04, 0x80],
            &[0x04, 0x02, 0x00],
        ] {
            assert!(Reader::new(bad).unwrap().next_tlv().is_err(), "{bad:?}");
        }
        assert!(Reader::new(&vec![0; MAX_INPUT + 1]).is_err());
        assert_eq!(uint(&[0x00, 0x80]).unwrap(), 128);
        assert!(uint(&[0x80]).is_err());
        assert_eq!(magnitude(&[0, 0, 1, 0]), &[1, 0]);
    }
}
