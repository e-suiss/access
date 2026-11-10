//! Issuer certificate chains (`x5c`, `x5chain`) checked against the trust anchors a trusted list
//! names (Ek B 4834): a path to one of them at the verifier's time, and the leaf's P-256 key.
//! A leaf that is itself listed but has no path is not trusted.

use access_kernel::verify::cose::PublicKey;
use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{EndEntityCert, KeyPurposeIdIter, KeyUsage};

/// The mdoc document signer EKU, 1.0.18013.5.1.2 (ISO 18013-5 Annex B).
pub const MDOC_DS_EKU: &[u8] = &[0x28, 0x81, 0x8c, 0x5d, 0x05, 0x01, 0x02];

/// The DER prefix of a P-256 `SubjectPublicKeyInfo` before its 65-byte point.
const P256_SPKI: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// Which EKU the leaf must carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    /// An mdoc document signer: the EKU, if the certificate has one, names [`MDOC_DS_EKU`].
    MdocSigner,
    /// An SD-JWT VC issuer: no EKU is defined, any is accepted.
    SdJwtIssuer,
}

struct AnyEku;

impl webpki::ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        for p in iter {
            p?;
        }
        Ok(())
    }
}

/// Why a chain is not trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    /// No chain, or a certificate that does not parse.
    #[error("issuer-chain")]
    Chain,
    /// No path to a listed anchor at this time.
    #[error("issuer-untrusted")]
    Untrusted,
    /// The leaf's key is not P-256.
    #[error("issuer-key")]
    Key,
}

/// The P-256 key of a certificate.
///
/// # Errors
/// [`TrustError`].
pub fn leaf_key(der: &[u8]) -> Result<PublicKey, TrustError> {
    let cert = CertificateDer::from(der);
    let ee = EndEntityCert::try_from(&cert).map_err(|_| TrustError::Chain)?;
    let spki = ee.subject_public_key_info();
    let point = spki
        .as_ref()
        .strip_prefix(P256_SPKI)
        .ok_or(TrustError::Key)?;
    let key = PublicKey::P256(point.to_vec());
    key.check().map_err(|_| TrustError::Key)?;
    Ok(key)
}

/// Checks `chain` (leaf first) against `anchors` (DER certificates from the trusted list) at
/// `now_ms` and answers the leaf's key and the index of the anchor it chains to.
///
/// # Errors
/// [`TrustError`].
pub fn trusted(
    chain: &[Vec<u8>],
    anchors: &[Vec<u8>],
    now_ms: u64,
    usage: Usage,
) -> Result<(PublicKey, usize), TrustError> {
    let (leaf, rest) = chain.split_first().ok_or(TrustError::Chain)?;
    let leaf_der = CertificateDer::from(leaf.as_slice());
    let ee = EndEntityCert::try_from(&leaf_der).map_err(|_| TrustError::Chain)?;
    let intermediates: Vec<CertificateDer<'_>> = rest
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let time = UnixTime::since_unix_epoch(core::time::Duration::from_millis(now_ms));
    let algs = &[webpki::aws_lc_rs::ECDSA_P256_SHA256];
    for (i, anchor) in anchors.iter().enumerate() {
        let der = CertificateDer::from(anchor.as_slice());
        let Ok(ta) = webpki::anchor_from_trusted_cert(&der) else {
            continue;
        };
        let tas = [ta];
        let ok = match usage {
            Usage::MdocSigner => ee.verify_for_usage(
                algs,
                &tas,
                &intermediates,
                time,
                KeyUsage::required_if_present(MDOC_DS_EKU),
                None,
                None,
            ),
            Usage::SdJwtIssuer => {
                ee.verify_for_usage(algs, &tas, &intermediates, time, AnyEku, None, None)
            }
        };
        if ok.is_ok() {
            return Ok((leaf_key(leaf)?, i));
        }
    }
    Err(TrustError::Untrusted)
}
