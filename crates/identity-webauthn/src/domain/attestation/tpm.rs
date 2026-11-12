//! `tpm` attestation (WebAuthn L3 §8.3): a `TPMS_ATTEST` of type `TPM_ST_ATTEST_CERTIFY`
//! whose `extraData` is the hash of `authenticatorData ‖ clientDataHash` and whose certified
//! name is that of `pubArea`, the credential's own key, signed by an attestation identity key
//! whose certificate carries the TPM profile's extensions (§8.3.1).

use access_crypto::webauthn::sha256;
use access_parse::cbor::Item;

use super::{Input, Lookup, Statement, aaguid_matches, chain, signature_alg, verify_by};
use crate::domain::Rejection;
use crate::domain::cose::{CoseAlgorithm, CoseKey};
use crate::domain::x509::{Cert, magnitude};

/// `TPM_GENERATED_VALUE`.
const TPM_GENERATED: u32 = 0xff54_4347;
/// `TPM_ST_ATTEST_CERTIFY`.
const ST_ATTEST_CERTIFY: u16 = 0x8017;
/// `TPM_ALG_RSA`.
const ALG_RSA: u16 = 0x0001;
/// `TPM_ALG_SHA256`.
const ALG_SHA256: u16 = 0x000b;
/// `TPM_ALG_NULL`.
const ALG_NULL: u16 = 0x0010;
/// `TPM_ALG_ECC`.
const ALG_ECC: u16 = 0x0023;
/// `TPM_ECC_NIST_P256`.
const ECC_NIST_P256: u16 = 0x0003;
/// 2.23.133.8.3, `tcg-kp-AIKCertificate`.
const OID_AIK: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x03];
/// The RSA exponent `pubArea` writes as 0.
const DEFAULT_EXPONENT: u64 = 65_537;

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Rejection> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or(Rejection::AttestationStatement)?;
        self.0 = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, Rejection> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes(
            b.try_into().map_err(|_| Rejection::AttestationStatement)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, Rejection> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes(
            b.try_into().map_err(|_| Rejection::AttestationStatement)?,
        ))
    }

    fn sized(&mut self) -> Result<&'a [u8], Rejection> {
        let n = self.u16()?;
        self.take(usize::from(n))
    }

    fn done(&self) -> Result<(), Rejection> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(Rejection::AttestationStatement)
        }
    }
}

/// The key of a `TPMT_PUBLIC`.
enum Public<'a> {
    Rsa { n: &'a [u8], e: u64 },
    P256 { x: &'a [u8], y: &'a [u8] },
}

fn public(area: &[u8]) -> Result<(u16, Public<'_>), Rejection> {
    let mut p = Cursor(area);
    let kind = p.u16()?;
    let name_alg = p.u16()?;
    p.u32()?;
    p.sized()?;
    let mut skip_unless_null = |n: usize| -> Result<(), Rejection> {
        if p.u16()? != ALG_NULL {
            p.take(n)?;
        }
        Ok(())
    };
    skip_unless_null(4)?;
    skip_unless_null(2)?;
    let key = match kind {
        ALG_RSA => {
            p.u16()?;
            let e = match p.u32()? {
                0 => DEFAULT_EXPONENT,
                e => u64::from(e),
            };
            Public::Rsa { n: p.sized()?, e }
        }
        ALG_ECC => {
            if p.u16()? != ECC_NIST_P256 {
                return Err(Rejection::AttestationStatement);
            }
            if p.u16()? != ALG_NULL {
                p.take(2)?;
            }
            Public::P256 {
                x: p.sized()?,
                y: p.sized()?,
            }
        }
        _ => return Err(Rejection::AttestationStatement),
    };
    p.done()?;
    Ok((name_alg, key))
}

/// L3 §8.3 step 2: `pubArea` is the credential public key.
fn same_key(public: &Public<'_>, key: &CoseKey) -> bool {
    match (public, key) {
        (Public::P256 { x, y }, CoseKey::P256 { point, .. }) => {
            point.get(1..33) == Some(*x) && point.get(33..) == Some(*y)
        }
        (Public::Rsa { n, e }, CoseKey::Rsa { n: kn, e: ke }) => {
            let ke = magnitude(ke);
            ke.len() <= 8
                && ke
                    .iter()
                    .fold(0_u64, |acc, b| acc.wrapping_shl(8) | u64::from(*b))
                    == *e
                && magnitude(n) == magnitude(kn)
        }
        _ => false,
    }
}

/// L3 §8.3.1: version 3, an empty subject, a critical subjectAltName, the
/// `tcg-kp-AIKCertificate` purpose, basic constraints with `cA = false`, and a non-critical
/// AAGUID extension equal to the credential's when present.
fn aik_profile(cert: &Cert<'_>, input: &Input<'_, '_>) -> bool {
    cert.version == 2
        && cert.subject.is_empty()
        && cert.san_critical().unwrap_or(false)
        && cert.ext_key_usage().is_ok_and(|u| u.contains(&OID_AIK))
        && cert.is_ca().ok() == Some(Some(false))
        && aaguid_matches(cert, input.credential)
}

pub(super) fn verify<'a>(input: &Input<'_, 'a>) -> Result<Statement<'a>, Rejection> {
    let stmt = input.stmt;
    if stmt.get_text("ver").and_then(Item::as_text) != Some("2.0") {
        return Err(Rejection::AttestationFormat);
    }
    let alg_id = stmt
        .get_text("alg")
        .and_then(Item::as_i64)
        .ok_or(Rejection::AttestationFormat)?;
    if !matches!(
        CoseAlgorithm::from_id(alg_id),
        Some(CoseAlgorithm::Es256 | CoseAlgorithm::Esp256 | CoseAlgorithm::Rs256)
    ) {
        return Err(Rejection::AttestationFormat);
    }
    let alg = signature_alg(alg_id).ok_or(Rejection::AttestationFormat)?;
    let field = |k: &str| {
        stmt.get_text(k)
            .and_then(Item::as_bytes)
            .ok_or(Rejection::AttestationStatement)
    };
    let (sig, cert_info, pub_area) = (field("sig")?, field("certInfo")?, field("pubArea")?);
    let chain = chain(stmt).map_err(|e| match e {
        Rejection::AttestationTrust => Rejection::AttestationFormat,
        other => other,
    })?;
    let (name_alg, key) = public(pub_area)?;
    if name_alg != ALG_SHA256 {
        return Err(Rejection::AttestationStatement);
    }
    if !same_key(&key, &input.credential.public_key) {
        return Err(Rejection::AttestationStatement);
    }
    let mut c = Cursor(cert_info);
    if c.u32()? != TPM_GENERATED || c.u16()? != ST_ATTEST_CERTIFY {
        return Err(Rejection::AttestationStatement);
    }
    c.sized()?;
    if c.sized()? != sha256(&input.signed()) {
        return Err(Rejection::AttestationStatement);
    }
    c.take(17)?;
    c.take(8)?;
    let name = c.sized()?;
    c.sized()?;
    c.done()?;
    let mut expected = ALG_SHA256.to_be_bytes().to_vec();
    expected.extend(sha256(pub_area));
    if name != expected.as_slice() {
        return Err(Rejection::AttestationStatement);
    }
    let aik = *chain.first().ok_or(Rejection::AttestationStatement)?;
    verify_by(aik, alg, cert_info, sig)?;
    let cert = Cert::parse(aik).map_err(|_| Rejection::AttestationStatement)?;
    if !aik_profile(&cert, input) {
        return Err(Rejection::AttestationStatement);
    }
    Ok(Statement {
        chain,
        lookup: Lookup::Aaguid,
    })
}
