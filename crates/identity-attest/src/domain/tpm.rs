//! TPM 2.0 key attestation (§12.2.1, L21, AG-31 model 1): a `TPM2_Certify` of the key by an
//! attestation key whose certificate chains to an embedded manufacturer root
//! ([`crate::domain::roots::TPM`]); the checklist is WebAuthn's TPM attestation statement (§8.3).
//!
//! 1. `certInfo` is a `TPMS_ATTEST` with `magic` `TPM_GENERATED_VALUE` and type
//!    `TPM_ST_ATTEST_CERTIFY`, its `extraData` the challenge Access issued.
//! 2. Its certified name is `nameAlg ‖ H(pubArea)` with SHA-256, and `pubArea` says the key was
//!    generated inside the TPM and cannot leave it (`fixedTPM`, `fixedParent`,
//!    `sensitiveDataOrigin`).
//! 3. The attestation key's certificate signed `certInfo`: version 3, empty subject, a critical
//!    subjectAltName, the `tcg-kp-AIKCertificate` purpose, not a CA; its chain verifies.

use rustls_pki_types::SignatureVerificationAlgorithm;
use suiss_crypto::digest::sha256;

use crate::AttestError;
use crate::domain::x509::{self, AnyUsage, Cert, OID_SAN};

/// `TPM_GENERATED_VALUE`.
pub const TPM_GENERATED: u32 = 0xff54_4347;
/// `TPM_ST_ATTEST_CERTIFY`.
pub const ST_ATTEST_CERTIFY: u16 = 0x8017;
/// `TPM_ALG_SHA256`.
pub const ALG_SHA256: u16 = 0x000b;
/// `TPM_ALG_RSA`.
pub const ALG_RSA: u16 = 0x0001;
/// `TPM_ALG_ECC`.
pub const ALG_ECC: u16 = 0x0023;

const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;

/// 2.23.133.8.3, `tcg-kp-AIKCertificate`.
const OID_AIK: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x03];

/// The signature scheme of `sig`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigAlg {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// ECDSA P-256 with SHA-256, ASN.1 DER signature.
    Es256,
}

impl SigAlg {
    fn webpki(self) -> &'static dyn SignatureVerificationAlgorithm {
        match self {
            Self::Rs256 => webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256,
            Self::Es256 => webpki::aws_lc_rs::ECDSA_P256_SHA256,
        }
    }
}

/// The evidence of a TPM 2.0 key attestation.
#[derive(Clone, Copy, Debug)]
pub struct Evidence<'a> {
    /// `certInfo`, a `TPMS_ATTEST`.
    pub cert_info: &'a [u8],
    /// The attestation key's signature over `certInfo`.
    pub sig: &'a [u8],
    /// Its scheme.
    pub alg: SigAlg,
    /// `pubArea` of the certified key, a `TPMT_PUBLIC`.
    pub pub_area: &'a [u8],
    /// The attestation key's certificate, then its chain, DER.
    pub x5c: &'a [Vec<u8>],
}

/// A verified TPM key attestation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    /// `TPM_ALG_RSA` or `TPM_ALG_ECC`.
    pub key_type: u16,
    /// The certified key's TPM name.
    pub name: Vec<u8>,
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], AttestError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(AttestError::Format)?;
        self.0 = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, AttestError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes(
            b.try_into().map_err(|_| AttestError::Format)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, AttestError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes(
            b.try_into().map_err(|_| AttestError::Format)?,
        ))
    }

    fn sized(&mut self) -> Result<&'a [u8], AttestError> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }
}

/// Verifies `evidence` to `roots` at `now_s` (Unix seconds); `extra_data` is the challenge
/// Access issued.
///
/// # Errors
/// [`AttestError`].
pub fn verify(
    evidence: &Evidence<'_>,
    roots: &[&[u8]],
    extra_data: &[u8],
    now_s: u64,
) -> Result<Attested, AttestError> {
    let mut c = Cursor(evidence.cert_info);
    if c.u32()? != TPM_GENERATED || c.u16()? != ST_ATTEST_CERTIFY {
        return Err(AttestError::Format);
    }
    c.sized()?;
    if c.sized()? != extra_data {
        return Err(AttestError::Challenge);
    }
    c.take(17)?;
    c.take(8)?;
    let name = c.sized()?;
    c.sized()?;
    if !c.0.is_empty() {
        return Err(AttestError::Format);
    }
    let mut p = Cursor(evidence.pub_area);
    let key_type = p.u16()?;
    let name_alg = p.u16()?;
    let attributes = p.u32()?;
    if !matches!(key_type, ALG_RSA | ALG_ECC) || name_alg != ALG_SHA256 {
        return Err(AttestError::Policy);
    }
    let mut expected = ALG_SHA256.to_be_bytes().to_vec();
    expected.extend(sha256(evidence.pub_area));
    if name != expected.as_slice() {
        return Err(AttestError::Key);
    }
    let resident = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN;
    if attributes & resident != resident {
        return Err(AttestError::Policy);
    }
    let (aik, chain) = evidence.x5c.split_first().ok_or(AttestError::Format)?;
    let cert = Cert::parse(aik).map_err(|_| AttestError::Format)?;
    let san_critical = cert
        .extension(OID_SAN)
        .map_err(|_| AttestError::Format)?
        .is_some_and(|e| e.critical);
    let aik_purpose = cert
        .ext_key_usage()
        .map_err(|_| AttestError::Format)?
        .contains(&OID_AIK);
    let empty_subject = cert.subject.is_empty();
    let not_ca = cert.is_ca().map_err(|_| AttestError::Format)? == Some(false);
    if cert.version != 2 || !empty_subject || !san_critical || !aik_purpose || !not_ca {
        return Err(AttestError::Certificate);
    }
    x509::verify_signature(aik, evidence.alg.webpki(), evidence.cert_info, evidence.sig)
        .map_err(|_| AttestError::Signature)?;
    x509::verify_chain(aik, chain, roots, now_s, AnyUsage).map_err(|_| AttestError::Chain)?;
    Ok(Attested {
        key_type,
        name: name.to_vec(),
    })
}

#[cfg(test)]
mod tests;
