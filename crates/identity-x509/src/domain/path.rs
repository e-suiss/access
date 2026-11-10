//! Path validation with rustls-webpki (RFC 5280 §6, OP-155 m.3 (m)): the presented chain must
//! lead to one of the realm's accepted CAs, every certificate valid now, the leaf for client
//! authentication (an extKeyUsage, when present, names `id-kp-clientAuth`).

use core::time::Duration;

use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm, TrustAnchor, UnixTime};
use webpki::{EndEntityCert, KeyUsage, RevocationOptions, anchor_from_trusted_cert};

use crate::X509Error;

/// Most certificates a client presents, leaf included (PD).
pub const MAX_CHAIN: usize = 8;

/// Largest certificate (CR-10).
pub const MAX_CERT: usize = access_parse::der::MAX_INPUT;

/// Certificate and response signature algorithms accepted.
pub const ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::aws_lc_rs::ECDSA_P256_SHA256,
    webpki::aws_lc_rs::ECDSA_P256_SHA384,
    webpki::aws_lc_rs::ECDSA_P384_SHA256,
    webpki::aws_lc_rs::ECDSA_P384_SHA384,
    webpki::aws_lc_rs::ED25519,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA384,
    webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA512,
];

/// A verified path: the presented certificates it used, leaf first, and the accepted CA it ends
/// at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Path {
    /// The leaf, then each intermediate up to the CA, DER.
    pub certs: Vec<Vec<u8>>,
    /// The index of the CA among the anchors given.
    pub anchor: usize,
}

impl Path {
    /// The leaf.
    #[must_use]
    pub fn leaf(&self) -> &[u8] {
        self.certs.first().map_or(&[], Vec::as_slice)
    }
}

/// `t` seconds since the epoch as webpki's time.
#[must_use]
pub fn unix(t: u64) -> UnixTime {
    UnixTime::since_unix_epoch(Duration::from_secs(t))
}

fn anchors(ca: &[Vec<u8>]) -> Vec<Option<TrustAnchor<'static>>> {
    ca.iter()
        .map(|d| {
            if d.len() > MAX_CERT {
                return None;
            }
            let der = CertificateDer::from(d.as_slice());
            anchor_from_trusted_cert(&der).ok().map(|a| a.to_owned())
        })
        .collect()
}

/// Validates `chain` (leaf first) to one of `ca` at `now` (Unix seconds), checking revocation
/// against `revocation` when given.
///
/// # Errors
/// [`X509Error::Malformed`] for an oversized or unreadable chain; [`X509Error::Path`] when no
/// path leads to a CA; with `revocation`, webpki's revocation errors as [`webpki::Error`].
pub fn verify_with(
    chain: &[Vec<u8>],
    ca: &[Vec<u8>],
    now: u64,
    revocation: Option<RevocationOptions<'_>>,
) -> Result<Path, Refused> {
    if chain.is_empty() || chain.len() > MAX_CHAIN || chain.iter().any(|c| c.len() > MAX_CERT) {
        return Err(Refused::Malformed);
    }
    let parsed = anchors(ca);
    let usable: Vec<TrustAnchor<'_>> = parsed.iter().flatten().cloned().collect();
    if usable.is_empty() {
        return Err(Refused::Path(webpki::Error::UnknownIssuer));
    }
    let leaf_der = CertificateDer::from(chain.first().map_or(&[][..], Vec::as_slice));
    let leaf = EndEntityCert::try_from(&leaf_der).map_err(|_| Refused::Malformed)?;
    let intermediates: Vec<CertificateDer<'_>> = chain
        .iter()
        .skip(1)
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let path = leaf
        .verify_for_usage(
            ALGS,
            &usable,
            &intermediates,
            unix(now),
            KeyUsage::client_auth(),
            revocation,
            None,
        )
        .map_err(Refused::Path)?;
    let used = path.anchor();
    let anchor = parsed
        .iter()
        .position(|a| {
            a.as_ref().is_some_and(|a| {
                a.subject == used.subject
                    && a.subject_public_key_info == used.subject_public_key_info
            })
        })
        .ok_or(Refused::Path(webpki::Error::UnknownIssuer))?;
    let mut certs = vec![leaf_der.as_ref().to_vec()];
    certs.extend(
        path.intermediate_certificates()
            .map(|c| c.der().as_ref().to_vec()),
    );
    Ok(Path { certs, anchor })
}

/// Why a path was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Oversized or unreadable.
    Malformed,
    /// webpki refused it.
    Path(webpki::Error),
}

impl From<Refused> for X509Error {
    fn from(r: Refused) -> Self {
        match r {
            Refused::Malformed => Self::Malformed,
            Refused::Path(_) => Self::Path,
        }
    }
}

/// Validates `chain` (leaf first) to one of `ca` at `now` (Unix seconds), revocation aside.
///
/// # Errors
/// [`X509Error::Malformed`]; [`X509Error::Path`].
pub fn verify(chain: &[Vec<u8>], ca: &[Vec<u8>], now: u64) -> Result<Path, X509Error> {
    verify_with(chain, ca, now, None).map_err(X509Error::from)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use crate::testing::{Ca, LeafSpec, NOW};

    // OP-155 m.3 (m), RFC 5280 §6
    #[test]
    fn a_chain_verifies_only_to_an_accepted_ca_for_client_authentication() {
        let root = Ca::root("Path Root");
        let mid = root.intermediate("Path Issuing", None, None);
        let leaf = mid.leaf(&LeafSpec::default());
        let chain = vec![leaf.der.clone(), mid.der.clone()];
        let p = verify(&chain, core::slice::from_ref(&root.der), NOW).unwrap();
        assert_eq!(p.certs, chain);
        assert_eq!(p.anchor, 0);
        let other = Ca::root("Other Root");
        let p = verify(&chain, &[other.der.clone(), mid.der.clone()], NOW).unwrap();
        assert_eq!(p.anchor, 1);
        assert_eq!(p.certs, vec![leaf.der.clone()]);
        assert_eq!(verify(&chain, &[other.der], NOW), Err(X509Error::Path));
        assert_eq!(verify(&chain, &[], NOW), Err(X509Error::Path));
        let server = mid.leaf(&LeafSpec {
            server_only: true,
            ..LeafSpec::default()
        });
        assert_eq!(
            verify(
                &[server.der, mid.der.clone()],
                core::slice::from_ref(&root.der),
                NOW
            ),
            Err(X509Error::Path)
        );
        let expired = mid.leaf(&LeafSpec {
            expired: true,
            ..LeafSpec::default()
        });
        assert_eq!(
            verify(
                &[expired.der, mid.der.clone()],
                core::slice::from_ref(&root.der),
                NOW
            ),
            Err(X509Error::Path)
        );
        let long = vec![leaf.der; MAX_CHAIN + 1];
        assert_eq!(verify(&long, &[root.der], NOW), Err(X509Error::Malformed));
    }
}
