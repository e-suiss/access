//! The in-house OCSP client (RFC 6960, RFC 5019, OP-155 m.3 (m)): a bounded DER request naming
//! one certificate, and the checks of the signed answer. A response is at most 8 KB (CR-10).
//!
//! - The request names the certificate by a SHA-1 `CertID` (RFC 5019 §2.1.1) and carries no
//!   nonce, so cached answers stay usable; an answer naming it by SHA-256 is accepted too.
//! - The answer is signed by the issuing CA or by a responder certificate the CA issued for
//!   `id-kp-OCSPSigning` (§4.2.2.2); SHA-1 signatures are refused.
//! - `thisUpdate` may be at most [`SKEW`] ahead; an answer is current until its `nextUpdate`, or
//!   for [`NO_NEXT_UPDATE`] after `thisUpdate` when it has none.

use access_parse::der::DerError;
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

use super::cert::Cert;
use super::der::{self, Cursor, tlv};
use super::path::unix;
use super::time::generalized;

/// Largest OCSP response read (CR-10).
pub const MAX_RESPONSE: usize = access_parse::der::MAX_INPUT;

/// How far `thisUpdate` may lie ahead of the server's clock, seconds (PD).
pub const SKEW: u64 = 300;

/// How long an answer without `nextUpdate` stays current after `thisUpdate`, seconds: the
/// cache floor of OP-155 m.3 (m).
pub const NO_NEXT_UPDATE: u64 = 300;

/// The `Content-Type` of a request.
pub const REQUEST_TYPE: &str = "application/ocsp-request";

/// The `Content-Type` of a response.
pub const RESPONSE_TYPE: &str = "application/ocsp-response";

/// 1.3.14.3.2.26, SHA-1.
const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
/// 2.16.840.1.101.3.4.2.1, SHA-256.
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// 1.3.6.1.5.5.7.48.1.1, id-pkix-ocsp-basic.
const OID_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];
/// 1.3.6.1.5.5.7.3.9, id-kp-OCSPSigning.
const OID_OCSP_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

/// What the responder said about the certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not revoked.
    Good,
    /// Revoked.
    Revoked,
    /// The responder does not know it.
    Unknown,
}

/// A checked answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The status.
    pub status: Status,
    /// `thisUpdate`, Unix seconds.
    pub this_update: u64,
    /// Until when the answer is current, Unix seconds.
    pub current_until: u64,
}

/// Why an answer is not used; every one refuses the certificate unless another source answers
/// (MD-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OcspError {
    /// Not a well-formed response, larger than allowed, or not a successful basic response.
    #[error("malformed response")]
    Malformed,
    /// The signature, the signer or the responder name does not check.
    #[error("bad signature")]
    Signature,
    /// The response says nothing about this certificate.
    #[error("not about this certificate")]
    NotForCertificate,
    /// `thisUpdate` lies ahead, or the answer is no longer current.
    #[error("stale")]
    Stale,
}

impl From<DerError> for OcspError {
    fn from(_: DerError) -> Self {
        Self::Malformed
    }
}

fn sha1(b: &[u8]) -> Vec<u8> {
    access_crypto::ocsp::cert_id_sha1(b).to_vec()
}

fn sha256(b: &[u8]) -> Vec<u8> {
    suiss_crypto::digest::sha256(b).to_vec()
}

/// The DER request for `cert` issued by `issuer` (RFC 6960 §4.1.1).
///
/// # Errors
/// [`OcspError::Malformed`] when either certificate is not readable.
pub fn request(cert: &Cert<'_>, issuer: &Cert<'_>) -> Result<Vec<u8>, OcspError> {
    let alg = der::seq(&[&tlv(der::OID, OID_SHA1)?, &[der::NULL, 0]])?;
    let cert_id = der::seq(&[
        &alg,
        &tlv(der::OCTET_STRING, &sha1(cert.issuer))?,
        &tlv(der::OCTET_STRING, &sha1(issuer.public_key))?,
        &tlv(der::INTEGER, cert.serial)?,
    ])?;
    let one = der::seq(&[&cert_id])?;
    let list = der::seq(&[&one])?;
    let tbs = der::seq(&[&list])?;
    Ok(der::seq(&[&tbs])?)
}

type Algs = &'static [&'static dyn SignatureVerificationAlgorithm];

const ES256: Algs = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
];
const ES384: Algs = &[
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
];
const RS256: Algs = &[webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256];
const RS384: Algs = &[webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384];
const RS512: Algs = &[webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512];
const ED25519: Algs = &[webpki::aws_lc_rs::ED25519];

fn algorithms(oid: &[u8]) -> Algs {
    match oid {
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] => ES256,
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03] => ES384,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b] => RS256,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c] => RS384,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d] => RS512,
        [0x2b, 0x65, 0x70] => ED25519,
        _ => &[],
    }
}

/// Whether `responder` (RFC 6960 §4.2.1 `ResponderID`) names `signer`.
fn names(responder: der::Element<'_>, signer: &Cert<'_>) -> Result<bool, OcspError> {
    match responder.tag {
        0xa1 => Ok(Cursor::only(responder.value, der::SEQUENCE)?.whole == signer.subject),
        0xa2 => Ok(Cursor::only(responder.value, der::OCTET_STRING)?.value
            == sha1(signer.public_key).as_slice()),
        _ => Err(OcspError::Malformed),
    }
}

/// Whether `id` (a `CertID`) names `cert` issued by `issuer`.
fn about(id: &[u8], cert: &Cert<'_>, issuer: &Cert<'_>) -> Result<bool, OcspError> {
    let mut c = Cursor::new(id)?;
    let mut alg = Cursor::new(c.tagged(der::SEQUENCE)?.value)?;
    let hash: fn(&[u8]) -> Vec<u8> = match alg.tagged(der::OID)?.value {
        OID_SHA1 => sha1,
        OID_SHA256 => sha256,
        _ => return Ok(false),
    };
    let name = c.tagged(der::OCTET_STRING)?.value;
    let key = c.tagged(der::OCTET_STRING)?.value;
    let serial = c.tagged(der::INTEGER)?.value;
    Ok(name == hash(cert.issuer).as_slice()
        && key == hash(issuer.public_key).as_slice()
        && serial == cert.serial)
}

/// The signer of a response: the issuer itself, or a certificate it carries that the issuer
/// issued for `id-kp-OCSPSigning`, valid at `now`.
fn signer<'a>(
    responder: der::Element<'_>,
    carried: &'a [Vec<u8>],
    issuer: &'a Cert<'a>,
    now: u64,
) -> Result<&'a [u8], OcspError> {
    if names(responder, issuer)? {
        return Ok(issuer.der);
    }
    let issuer_der = CertificateDer::from(issuer.der);
    let anchor = anchor_from_trusted_cert(&issuer_der).map_err(|_| OcspError::Signature)?;
    for d in carried {
        let c = Cert::parse(d).map_err(|_| OcspError::Malformed)?;
        if !names(responder, &c)? {
            continue;
        }
        let cd = CertificateDer::from(d.as_slice());
        let ee = EndEntityCert::try_from(&cd).map_err(|_| OcspError::Signature)?;
        // RFC 6960 §4.2.2.2
        ee.verify_for_usage(
            super::path::ALGS,
            core::slice::from_ref(&anchor),
            &[],
            unix(now),
            KeyUsage::required(OID_OCSP_SIGNING),
            None,
            None,
        )
        .map_err(|_| OcspError::Signature)?;
        return Ok(d.as_slice());
    }
    Err(OcspError::Signature)
}

fn status(e: der::Element<'_>) -> Result<Status, OcspError> {
    match (e.tag, e.value) {
        (0x80, []) => Ok(Status::Good),
        (0xa1, _) => Ok(Status::Revoked),
        (0x82, []) => Ok(Status::Unknown),
        _ => Err(OcspError::Malformed),
    }
}

/// Checks `response` about `cert` issued by `issuer` at `now` (Unix seconds).
///
/// # Errors
/// [`OcspError`].
#[expect(clippy::many_single_char_names, reason = "one cursor per DER level")]
pub fn check(
    response: &[u8],
    cert: &Cert<'_>,
    issuer: &Cert<'_>,
    now: u64,
) -> Result<Answer, OcspError> {
    if response.len() > MAX_RESPONSE {
        return Err(OcspError::Malformed);
    }
    let outer = Cursor::only(response, der::SEQUENCE)?;
    let mut o = Cursor::new(outer.value)?;
    if o.tagged(der::ENUMERATED)?.value != [0] {
        return Err(OcspError::Malformed);
    }
    let bytes = Cursor::only(o.tagged(0xa0)?.value, der::SEQUENCE)?;
    let mut b = Cursor::new(bytes.value)?;
    if b.tagged(der::OID)?.value != OID_BASIC {
        return Err(OcspError::Malformed);
    }
    let basic = Cursor::only(b.tagged(der::OCTET_STRING)?.value, der::SEQUENCE)?;
    let mut r = Cursor::new(basic.value)?;
    let tbs = r.tagged(der::SEQUENCE)?;
    let mut alg = Cursor::new(r.tagged(der::SEQUENCE)?.value)?;
    let algs = algorithms(alg.tagged(der::OID)?.value);
    let signature = der::bits(r.tagged(der::BIT_STRING)?.value)?;
    let mut carried = Vec::new();
    if let Some(certs) = r.optional(0xa0)? {
        let list = Cursor::only(certs.value, der::SEQUENCE)?;
        let mut l = Cursor::new(list.value)?;
        while !l.is_empty() {
            carried.push(l.tagged(der::SEQUENCE)?.whole.to_vec());
        }
    }
    let mut t = Cursor::new(tbs.value)?;
    t.optional(0xa0)?;
    let responder = t.next()?;
    t.tagged(der::GENERALIZED_TIME)?;
    let signer_der = signer(responder, &carried, issuer, now)?;
    let signer_cd = CertificateDer::from(signer_der);
    let ee = EndEntityCert::try_from(&signer_cd).map_err(|_| OcspError::Signature)?;
    if !algs
        .iter()
        .any(|a| ee.verify_signature(*a, tbs.whole, signature).is_ok())
    {
        return Err(OcspError::Signature);
    }
    let list = t.tagged(der::SEQUENCE)?;
    let mut singles = Cursor::new(list.value)?;
    while !singles.is_empty() {
        let mut s = Cursor::new(singles.tagged(der::SEQUENCE)?.value)?;
        let id = s.tagged(der::SEQUENCE)?;
        if !about(id.value, cert, issuer)? {
            continue;
        }
        let st = status(s.next()?)?;
        let this_update =
            generalized(s.tagged(der::GENERALIZED_TIME)?.value).ok_or(OcspError::Malformed)?;
        let next_update = match s.optional(0xa0)? {
            Some(n) => Some(
                generalized(Cursor::only(n.value, der::GENERALIZED_TIME)?.value)
                    .ok_or(OcspError::Malformed)?,
            ),
            None => None,
        };
        let current_until = match next_update {
            Some(n) if n > this_update => n,
            Some(_) => return Err(OcspError::Malformed),
            None => this_update.saturating_add(NO_NEXT_UPDATE),
        };
        if this_update > now.saturating_add(SKEW) || now >= current_until {
            return Err(OcspError::Stale);
        }
        return Ok(Answer {
            status: st,
            this_update,
            current_until,
        });
    }
    Err(OcspError::NotForCertificate)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::testing::{Ca, DAY, LeafSpec, NOW, OcspAnswer, Status as S, ocsp_unauthorized};

    fn fixture() -> (Ca, Vec<u8>) {
        let ca = Ca::root("OCSP Root");
        let leaf = ca.leaf(&LeafSpec::default());
        (ca, leaf.der)
    }

    // RFC 6960 §4.1.1, RFC 5019 §2.1.1
    #[test]
    fn the_request_names_one_certificate_by_sha1() {
        let (ca, leaf) = fixture();
        let (c, i) = (Cert::parse(&leaf).unwrap(), Cert::parse(&ca.der).unwrap());
        let req = request(&c, &i).unwrap();
        let mut r = Cursor::new(Cursor::only(&req, der::SEQUENCE).unwrap().value).unwrap();
        let tbs = r.tagged(der::SEQUENCE).unwrap();
        let list = Cursor::only(tbs.value, der::SEQUENCE).unwrap();
        let one = Cursor::only(list.value, der::SEQUENCE).unwrap();
        let id = Cursor::only(one.value, der::SEQUENCE).unwrap();
        assert!(about(id.value, &c, &i).unwrap());
        assert!(r.is_empty());
    }

    // MD-8, OP-155 m.3 (m), RFC 6960 §4.2.2
    #[test]
    fn a_signed_current_answer_states_the_status() {
        let (ca, leaf) = fixture();
        let (c, i) = (Cert::parse(&leaf).unwrap(), Cert::parse(&ca.der).unwrap());
        for (s, want) in [
            (S::Good, Status::Good),
            (S::Revoked, Status::Revoked),
            (S::Unknown, Status::Unknown),
        ] {
            let resp = ca.ocsp(&leaf, &OcspAnswer::current(s), None);
            let a = check(&resp, &c, &i, NOW).unwrap();
            assert_eq!(a.status, want);
            assert_eq!(a.current_until, NOW + DAY);
        }
        let responder = ca.responder(true);
        let resp = ca.ocsp(&leaf, &OcspAnswer::current(S::Good), Some(&responder));
        assert_eq!(check(&resp, &c, &i, NOW).unwrap().status, Status::Good);
    }

    // MD-8, RFC 6960 §4.2.2.2, §3.2
    #[test]
    fn an_unsigned_foreign_or_stale_answer_is_not_used() {
        let (ca, leaf) = fixture();
        let (c, i) = (Cert::parse(&leaf).unwrap(), Cert::parse(&ca.der).unwrap());
        let tampered = OcspAnswer {
            tamper: true,
            ..OcspAnswer::current(S::Good)
        };
        assert_eq!(
            check(&ca.ocsp(&leaf, &tampered, None), &c, &i, NOW),
            Err(OcspError::Signature)
        );
        let not_signer = ca.responder(false);
        assert_eq!(
            check(
                &ca.ocsp(&leaf, &OcspAnswer::current(S::Good), Some(&not_signer)),
                &c,
                &i,
                NOW
            ),
            Err(OcspError::Signature)
        );
        let other = Ca::root("Other OCSP Root");
        assert_eq!(
            check(
                &other.ocsp(&leaf, &OcspAnswer::current(S::Good), None),
                &c,
                &i,
                NOW
            ),
            Err(OcspError::Signature)
        );
        let sibling = ca.leaf(&LeafSpec {
            serial: 9,
            ..LeafSpec::default()
        });
        assert_eq!(
            check(
                &ca.ocsp(&sibling.der, &OcspAnswer::current(S::Good), None),
                &c,
                &i,
                NOW
            ),
            Err(OcspError::NotForCertificate)
        );
        let stale = OcspAnswer {
            this_update: NOW - 2 * DAY,
            next_update: Some(NOW - DAY),
            ..OcspAnswer::current(S::Good)
        };
        assert_eq!(
            check(&ca.ocsp(&leaf, &stale, None), &c, &i, NOW),
            Err(OcspError::Stale)
        );
        let ahead = OcspAnswer {
            this_update: NOW + 3600,
            next_update: Some(NOW + DAY),
            ..OcspAnswer::current(S::Good)
        };
        assert_eq!(
            check(&ca.ocsp(&leaf, &ahead, None), &c, &i, NOW),
            Err(OcspError::Stale)
        );
        let open = OcspAnswer {
            this_update: NOW - 600,
            next_update: None,
            ..OcspAnswer::current(S::Good)
        };
        assert_eq!(
            check(&ca.ocsp(&leaf, &open, None), &c, &i, NOW),
            Err(OcspError::Stale)
        );
        let open = OcspAnswer {
            this_update: NOW - 60,
            ..open
        };
        assert_eq!(
            check(&ca.ocsp(&leaf, &open, None), &c, &i, NOW)
                .unwrap()
                .current_until,
            NOW - 60 + NO_NEXT_UPDATE
        );
        assert_eq!(
            check(&ocsp_unauthorized(), &c, &i, NOW),
            Err(OcspError::Malformed)
        );
        assert_eq!(
            check(&vec![0x30; MAX_RESPONSE + 1], &c, &i, NOW),
            Err(OcspError::Malformed)
        );
    }
}
