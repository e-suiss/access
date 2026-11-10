//! The fields of an X.509 certificate that path validation does not expose (RFC 5280 §4.1):
//! serial, issuer and subject names, public key, and the extensions sign-in and revocation read.
//! Every certificate is at most 8 KB (CR-10).

use access_parse::der::DerError;

use super::der::{self, Cursor, Element};
use crate::X509Error;

/// 2.5.29.17, subjectAltName.
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
/// 2.5.29.31, cRLDistributionPoints.
const OID_CRL_DP: &[u8] = &[0x55, 0x1d, 0x1f];
/// 2.5.29.32, certificatePolicies.
const OID_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
/// 1.3.6.1.5.5.7.1.1, authorityInfoAccess.
const OID_AIA: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
/// 1.3.6.1.5.5.7.48.1, id-ad-ocsp.
const OID_AD_OCSP: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];
/// 1.3.6.1.4.1.311.20.2.3, the Microsoft user principal name `otherName`.
const OID_UPN: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03];

/// Longest URL read from an extension.
const MAX_URL: usize = 2048;

/// One extension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension<'a> {
    /// Its OID contents.
    pub oid: &'a [u8],
    /// Whether it is critical.
    pub critical: bool,
    /// The `extnValue` contents.
    pub value: &'a [u8],
}

/// The fields of a certificate this crate reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert<'a> {
    /// The whole certificate.
    pub der: &'a [u8],
    /// The serial number's contents.
    pub serial: &'a [u8],
    /// The issuer `Name`, whole encoding.
    pub issuer: &'a [u8],
    /// The subject `Name`, whole encoding.
    pub subject: &'a [u8],
    /// The subject public key, the `BIT STRING` contents without the unused-bits octet.
    pub public_key: &'a [u8],
    /// The extensions.
    pub extensions: Vec<Extension<'a>>,
}

fn malformed(_: DerError) -> X509Error {
    X509Error::Malformed
}

fn url(e: Element<'_>) -> Option<String> {
    (e.tag == 0x86 && e.value.len() <= MAX_URL)
        .then(|| core::str::from_utf8(e.value).ok().map(String::from))
        .flatten()
}

impl<'a> Cert<'a> {
    /// Reads `der`.
    ///
    /// # Errors
    /// [`X509Error::Malformed`].
    #[expect(clippy::many_single_char_names, reason = "one cursor per DER level")]
    pub fn parse(der: &'a [u8]) -> Result<Self, X509Error> {
        let cert = Cursor::only(der, der::SEQUENCE).map_err(malformed)?;
        let mut c = Cursor::new(cert.value).map_err(malformed)?;
        let tbs = c.tagged(der::SEQUENCE).map_err(malformed)?;
        let mut t = Cursor::new(tbs.value).map_err(malformed)?;
        t.optional(0xa0).map_err(malformed)?;
        let serial = t.tagged(der::INTEGER).map_err(malformed)?.value;
        t.tagged(der::SEQUENCE).map_err(malformed)?;
        let issuer = t.tagged(der::SEQUENCE).map_err(malformed)?.whole;
        t.tagged(der::SEQUENCE).map_err(malformed)?;
        let subject = t.tagged(der::SEQUENCE).map_err(malformed)?.whole;
        let spki = t.tagged(der::SEQUENCE).map_err(malformed)?;
        let mut s = Cursor::new(spki.value).map_err(malformed)?;
        s.tagged(der::SEQUENCE).map_err(malformed)?;
        let public_key =
            der::bits(s.tagged(der::BIT_STRING).map_err(malformed)?.value).map_err(malformed)?;
        let mut extensions = Vec::new();
        while !t.is_empty() {
            let e = t.next().map_err(malformed)?;
            if e.tag != 0xa3 {
                continue;
            }
            let list = Cursor::only(e.value, der::SEQUENCE).map_err(malformed)?;
            let mut l = Cursor::new(list.value).map_err(malformed)?;
            while !l.is_empty() {
                let mut x = Cursor::new(l.tagged(der::SEQUENCE).map_err(malformed)?.value)
                    .map_err(malformed)?;
                let oid = x.tagged(der::OID).map_err(malformed)?.value;
                let critical = x
                    .optional(der::BOOLEAN)
                    .map_err(malformed)?
                    .is_some_and(|b| b.value == [0xff]);
                let value = x.tagged(der::OCTET_STRING).map_err(malformed)?.value;
                if !x.is_empty() {
                    return Err(X509Error::Malformed);
                }
                if extensions.iter().any(|e: &Extension<'_>| e.oid == oid) {
                    return Err(X509Error::Malformed);
                }
                extensions.push(Extension {
                    oid,
                    critical,
                    value,
                });
            }
        }
        Ok(Self {
            der,
            serial,
            issuer,
            subject,
            public_key,
            extensions,
        })
    }

    /// The extension `oid`.
    #[must_use]
    pub fn extension(&self, oid: &[u8]) -> Option<Extension<'a>> {
        self.extensions.iter().find(|e| e.oid == oid).copied()
    }

    /// The `http` and `https` OCSP responder URLs of the authorityInfoAccess extension.
    ///
    /// # Errors
    /// [`X509Error::Malformed`].
    pub fn ocsp_urls(&self) -> Result<Vec<String>, X509Error> {
        let Some(e) = self.extension(OID_AIA) else {
            return Ok(Vec::new());
        };
        let list = Cursor::only(e.value, der::SEQUENCE).map_err(malformed)?;
        let mut l = Cursor::new(list.value).map_err(malformed)?;
        let mut out = Vec::new();
        while !l.is_empty() {
            let mut d = Cursor::new(l.tagged(der::SEQUENCE).map_err(malformed)?.value)
                .map_err(malformed)?;
            let method = d.tagged(der::OID).map_err(malformed)?.value;
            let location = d.next().map_err(malformed)?;
            if method == OID_AD_OCSP
                && let Some(u) = url(location)
            {
                out.push(u);
            }
        }
        Ok(out)
    }

    /// The URLs of the cRLDistributionPoints extension's full names.
    ///
    /// # Errors
    /// [`X509Error::Malformed`].
    pub fn crl_urls(&self) -> Result<Vec<String>, X509Error> {
        let Some(e) = self.extension(OID_CRL_DP) else {
            return Ok(Vec::new());
        };
        let list = Cursor::only(e.value, der::SEQUENCE).map_err(malformed)?;
        let mut l = Cursor::new(list.value).map_err(malformed)?;
        let mut out = Vec::new();
        while !l.is_empty() {
            let mut dp = Cursor::new(l.tagged(der::SEQUENCE).map_err(malformed)?.value)
                .map_err(malformed)?;
            let Some(name) = dp.optional(0xa0).map_err(malformed)? else {
                continue;
            };
            let mut n = Cursor::new(name.value).map_err(malformed)?;
            let Some(full) = n.optional(0xa0).map_err(malformed)? else {
                continue;
            };
            let mut g = Cursor::new(full.value).map_err(malformed)?;
            while !g.is_empty() {
                if let Some(u) = url(g.next().map_err(malformed)?) {
                    out.push(u);
                }
            }
        }
        Ok(out)
    }

    /// The certificate policy OIDs, in dotted form.
    ///
    /// # Errors
    /// [`X509Error::Malformed`].
    pub fn policies(&self) -> Result<Vec<String>, X509Error> {
        let Some(e) = self.extension(OID_POLICIES) else {
            return Ok(Vec::new());
        };
        let list = Cursor::only(e.value, der::SEQUENCE).map_err(malformed)?;
        let mut l = Cursor::new(list.value).map_err(malformed)?;
        let mut out = Vec::new();
        while !l.is_empty() {
            let mut p = Cursor::new(l.tagged(der::SEQUENCE).map_err(malformed)?.value)
                .map_err(malformed)?;
            let oid = p.tagged(der::OID).map_err(malformed)?.value;
            out.push(der::dotted(oid).ok_or(X509Error::Malformed)?);
        }
        Ok(out)
    }

    fn general_names(&self) -> Result<Vec<Element<'a>>, X509Error> {
        let Some(e) = self.extension(OID_SAN) else {
            return Ok(Vec::new());
        };
        let list = Cursor::only(e.value, der::SEQUENCE).map_err(malformed)?;
        let mut l = Cursor::new(list.value).map_err(malformed)?;
        let mut out = Vec::new();
        while !l.is_empty() {
            out.push(l.next().map_err(malformed)?);
        }
        Ok(out)
    }

    /// The `rfc822Name` entries of the subjectAltName extension.
    ///
    /// # Errors
    /// [`X509Error::Malformed`].
    pub fn san_emails(&self) -> Result<Vec<&'a str>, X509Error> {
        self.general_names()?
            .into_iter()
            .filter(|g| g.tag == 0x81)
            .map(|g| core::str::from_utf8(g.value).map_err(|_| X509Error::Malformed))
            .collect()
    }

    /// The user principal names (`otherName` 1.3.6.1.4.1.311.20.2.3) of the subjectAltName
    /// extension.
    ///
    /// # Errors
    /// [`X509Error::Malformed`].
    pub fn san_upns(&self) -> Result<Vec<&'a str>, X509Error> {
        let mut out = Vec::new();
        for g in self.general_names()?.into_iter().filter(|g| g.tag == 0xa0) {
            let mut o = Cursor::new(g.value).map_err(malformed)?;
            if o.tagged(der::OID).map_err(malformed)?.value != OID_UPN {
                continue;
            }
            let wrapped = o.tagged(0xa0).map_err(malformed)?;
            let s = Cursor::only(wrapped.value, der::UTF8_STRING).map_err(malformed)?;
            out.push(core::str::from_utf8(s.value).map_err(|_| X509Error::Malformed)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::testing::{Ca, LeafSpec};

    // CR-10, RFC 5280 §4.2.1.6, §4.2.1.13, §4.2.2.1
    #[test]
    fn the_sign_in_and_revocation_fields_are_read() {
        let ca = Ca::root("Fields Root");
        let leaf = ca.leaf(&LeafSpec {
            email: Some("ada@example.org"),
            upn: Some("ada@corp.example"),
            policies: &["2.16.840.1.101.3.2.1.3.13"],
            ocsp: Some("http://ocsp.example/"),
            crl: Some("http://crl.example/root.crl"),
            ..LeafSpec::default()
        });
        let c = Cert::parse(&leaf.der).unwrap();
        assert_eq!(c.san_emails().unwrap(), vec!["ada@example.org"]);
        assert_eq!(c.san_upns().unwrap(), vec!["ada@corp.example"]);
        assert_eq!(c.policies().unwrap(), vec!["2.16.840.1.101.3.2.1.3.13"]);
        assert_eq!(c.ocsp_urls().unwrap(), vec!["http://ocsp.example/"]);
        assert_eq!(c.crl_urls().unwrap(), vec!["http://crl.example/root.crl"]);
        let root = Cert::parse(&ca.der).unwrap();
        assert_eq!(c.issuer, root.subject);
        assert_ne!(c.serial, &[] as &[u8]);
        assert!(Cert::parse(&leaf.der[..leaf.der.len() - 1]).is_err());
        assert!(Cert::parse(&vec![0x30; 9000]).is_err());
    }
}
