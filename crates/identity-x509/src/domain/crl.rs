//! CRLs (RFC 5280 §5), read and checked by rustls-webpki (OP-155 m.3 (m)): every certificate of
//! the path must be covered by an authoritative CRL that is current; a revoked, uncovered or
//! expired one refuses the path.

use webpki::{
    CertRevocationList, ExpirationPolicy, OwnedCertRevocationList, RevocationCheckDepth,
    RevocationOptionsBuilder, UnknownStatusPolicy,
};

use super::der::{self, Cursor};
use super::path::{Refused, verify_with};
use super::time::{generalized, utc};

/// Largest CRL fetched: the guarded outbound client's body ceiling (OP-155 m.3 (m)).
pub const MAX_CRL: usize = 1024 * 1024;

/// The `Accept` of a CRL fetch.
pub const CRL_TYPE: &str = "application/pkix-crl";

/// What the CRL check found.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CrlError {
    /// Not a CRL webpki reads, or larger than allowed.
    #[error("malformed CRL")]
    Malformed,
    /// A certificate of the path is revoked.
    #[error("revoked")]
    Revoked,
    /// A certificate of the path is covered by no authoritative CRL.
    #[error("status unknown")]
    Unknown,
    /// A CRL is past its `nextUpdate`.
    #[error("stale")]
    Stale,
}

/// A parsed CRL and until when it is current.
#[derive(Debug)]
pub struct Crl {
    /// The list.
    pub list: OwnedCertRevocationList,
    /// `nextUpdate`, Unix seconds.
    pub next_update: u64,
}

fn time(e: der::Element<'_>) -> Option<u64> {
    match e.tag {
        der::UTC_TIME => utc(e.value),
        der::GENERALIZED_TIME => generalized(e.value),
        _ => None,
    }
}

/// `nextUpdate` of a CRL (RFC 5280 §5.1.2.5), read from the head of its `TBSCertList`; a CRL
/// without one is never current.
fn next_update(crl: &[u8]) -> Option<u64> {
    let (list, _) = der::long_tagged(crl, der::SEQUENCE)?;
    let (tbs, _) = der::long_tagged(list, der::SEQUENCE)?;
    let mut rest = tbs;
    let mut next = || {
        let head = rest.get(..rest.len().min(access_parse::der::MAX_INPUT))?;
        let e = Cursor::new(head).ok()?.next().ok()?;
        rest = rest.get(e.whole.len()..)?;
        Some(e)
    };
    let mut e = next()?;
    if e.tag == der::INTEGER {
        e = next()?;
    }
    if e.tag != der::SEQUENCE || next()?.tag != der::SEQUENCE {
        return None;
    }
    time(next()?)?;
    time(next()?)
}

/// Reads a fetched CRL.
///
/// # Errors
/// [`CrlError::Malformed`].
pub fn parse(der: &[u8]) -> Result<Crl, CrlError> {
    if der.len() > MAX_CRL {
        return Err(CrlError::Malformed);
    }
    let next_update = next_update(der).ok_or(CrlError::Malformed)?;
    let list = OwnedCertRevocationList::from_der(der).map_err(|_| CrlError::Malformed)?;
    Ok(Crl { list, next_update })
}

/// Checks the whole path of `chain` to `ca` against `crls` at `now`.
///
/// # Errors
/// [`CrlError`].
pub fn check(chain: &[Vec<u8>], ca: &[Vec<u8>], crls: &[&Crl], now: u64) -> Result<(), CrlError> {
    let lists: Vec<CertRevocationList<'_>> = crls
        .iter()
        .map(|c| CertRevocationList::from(c.list.clone()))
        .collect();
    let refs: Vec<&CertRevocationList<'_>> = lists.iter().collect();
    let options = RevocationOptionsBuilder::new(&refs)
        .map_err(|_| CrlError::Unknown)?
        .with_depth(RevocationCheckDepth::Chain)
        .with_status_policy(UnknownStatusPolicy::Deny)
        .with_expiration_policy(ExpirationPolicy::Enforce)
        .build();
    match verify_with(chain, ca, now, Some(options)) {
        Ok(_) => Ok(()),
        Err(Refused::Path(webpki::Error::CertRevoked)) => Err(CrlError::Revoked),
        Err(Refused::Path(webpki::Error::CrlExpired { .. })) => Err(CrlError::Stale),
        Err(_) => Err(CrlError::Unknown),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::testing::{Ca, DAY, LeafSpec, NOW, serial};

    // MD-8, OP-155 m.3 (m), RFC 5280 §6.3
    #[test]
    fn the_path_is_refused_unless_every_certificate_is_covered_and_not_revoked() {
        let root = Ca::root("CRL Root");
        let mid = root.intermediate("CRL Issuing", None, Some("http://crl.example/root.crl"));
        let leaf = mid.leaf(&LeafSpec {
            crl: Some("http://crl.example/mid.crl"),
            ..LeafSpec::default()
        });
        let chain = vec![leaf.der.clone(), mid.der.clone()];
        let ca = vec![root.der.clone()];
        let root_crl = parse(&root.crl(&[], NOW - DAY, NOW + DAY)).unwrap();
        assert_eq!(root_crl.next_update, NOW + DAY);
        let mid_crl = parse(&mid.crl(&[], NOW - DAY, NOW + DAY)).unwrap();
        assert_eq!(check(&chain, &ca, &[&root_crl, &mid_crl], NOW), Ok(()));
        assert_eq!(check(&chain, &ca, &[&mid_crl], NOW), Err(CrlError::Unknown));
        let revoked = parse(&mid.crl(&[&serial(&leaf.der)], NOW - DAY, NOW + DAY)).unwrap();
        assert_eq!(
            check(&chain, &ca, &[&root_crl, &revoked], NOW),
            Err(CrlError::Revoked)
        );
        let stale = parse(&mid.crl(&[], NOW - 3 * DAY, NOW - DAY)).unwrap();
        assert_eq!(
            check(&chain, &ca, &[&root_crl, &stale], NOW),
            Err(CrlError::Stale)
        );
        assert_eq!(parse(&[0x30, 0x00]).unwrap_err(), CrlError::Malformed);
    }
}
