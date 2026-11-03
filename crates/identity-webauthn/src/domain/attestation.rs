//! Attestation objects and the realm's attestation policy (§10.2.4, OP-146 m.4 (d)). Under
//! `none` attestation is never a trust input. Under `direct`, only `packed` full attestation
//! verified to a root from fresh FIDO metadata is accepted.

use access_parse::cbor::{Item, Limits, decode};
use access_parse::der::{self, DerError, Reader};
use rustls_pki_types::{CertificateDer, SignatureVerificationAlgorithm};
use webpki::EndEntityCert;

use super::Rejection;
use super::authenticator_data::{AttestedCredential, AuthenticatorData};
use super::cose::CoseAlgorithm;
use super::credential::AttestationKind;
use super::mds::{AnyUsage, MdsBlob, verify_chain};
use super::policy::AttestationPolicy;

/// 2.5.4.11, organizationalUnitName.
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b];
/// 1.3.6.1.4.1.45724.1.1.4, id-fido-gen-ce-aaguid.
const OID_AAGUID: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
];
const TAG_VERSION: u8 = 0xa0;
const TAG_EXTENSIONS: u8 = 0xa3;
const MAX_CHAIN: usize = 8;

/// A decoded attestation object.
pub struct AttestationObject<'a> {
    /// `fmt`.
    pub fmt: &'a str,
    /// `attStmt`.
    pub statement: Item<'a>,
    /// `authData` bytes.
    pub auth_data: &'a [u8],
}

impl<'a> AttestationObject<'a> {
    /// Decodes within the WebAuthn CBOR limits (CR-10).
    ///
    /// # Errors
    /// [`Rejection`].
    pub fn parse(raw: &'a [u8]) -> Result<Self, Rejection> {
        let item = decode(raw, Limits::CEILING)?;
        let fmt = item
            .get_text("fmt")
            .and_then(Item::as_text)
            .ok_or(Rejection::AttestationFormat)?;
        let statement = item
            .get_text("attStmt")
            .filter(|s| s.as_map().is_some())
            .ok_or(Rejection::AttestationFormat)?
            .clone();
        let auth_data = item
            .get_text("authData")
            .and_then(Item::as_bytes)
            .ok_or(Rejection::AuthenticatorData)?;
        Ok(Self {
            fmt,
            statement,
            auth_data,
        })
    }
}

fn signature_alg(alg: i64) -> Option<&'static dyn SignatureVerificationAlgorithm> {
    match CoseAlgorithm::from_id(alg)? {
        CoseAlgorithm::Es256 | CoseAlgorithm::Esp256 => Some(webpki::aws_lc_rs::ECDSA_P256_SHA256),
        CoseAlgorithm::Rs256 => Some(webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256),
        CoseAlgorithm::Ed25519 | CoseAlgorithm::EdDsa => Some(webpki::aws_lc_rs::ED25519),
    }
}

fn subject_has_ou(name: &[u8]) -> Result<bool, DerError> {
    let mut rdns = Reader::new(name)?;
    while !rdns.is_empty() {
        let mut set = Reader::new(rdns.tagged(der::SET)?)?;
        while !set.is_empty() {
            let mut atv = Reader::new(set.tagged(der::SEQUENCE)?)?;
            let oid = atv.tagged(der::OID)?;
            let value = atv.next_tlv()?;
            if oid == OID_OU && value.value == b"Authenticator Attestation" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The AAGUID extension, if present: `(critical, extnValue)`.
fn aaguid_extension(extensions: &[u8]) -> Result<Option<(bool, &[u8])>, DerError> {
    let mut list = Reader::new(Reader::new(extensions)?.tagged(der::SEQUENCE)?)?;
    while !list.is_empty() {
        let mut ext = Reader::new(list.tagged(der::SEQUENCE)?)?;
        let oid = ext.tagged(der::OID)?;
        let mut next = ext.next_tlv()?;
        let critical = if next.tag == der::BOOLEAN {
            let flag = next.value == [0xff];
            next = ext.next_tlv()?;
            flag
        } else {
            false
        };
        if next.tag != der::OCTET_STRING {
            return Err(DerError::Tag);
        }
        if oid == OID_AAGUID {
            return Ok(Some((critical, next.value)));
        }
    }
    Ok(None)
}

/// FIDO packed attestation certificate requirements (WebAuthn L3 §8.2.1): version 3, subject
/// OU "Authenticator Attestation", and a non-critical AAGUID extension equal to the
/// credential's when present. `cA = false` is enforced by path validation.
fn check_certificate(cert: &[u8], credential: &AttestedCredential<'_>) -> Result<(), DerError> {
    let mut outer = Reader::new(cert)?;
    let mut tbs = Reader::new(Reader::new(outer.tagged(der::SEQUENCE)?)?.tagged(der::SEQUENCE)?)?;
    let version = Reader::new(tbs.tagged(TAG_VERSION)?)?.tagged(der::INTEGER)?;
    if version != [2] {
        return Err(DerError::Tag);
    }
    let _serial = tbs.tagged(der::INTEGER)?;
    let _signature = tbs.tagged(der::SEQUENCE)?;
    let _issuer = tbs.tagged(der::SEQUENCE)?;
    let _validity = tbs.tagged(der::SEQUENCE)?;
    let subject = tbs.tagged(der::SEQUENCE)?;
    let _spki = tbs.tagged(der::SEQUENCE)?;
    if !subject_has_ou(subject)? {
        return Err(DerError::Tag);
    }
    let mut extensions = None;
    while !tbs.is_empty() {
        let field = tbs.next_tlv()?;
        if field.tag == TAG_EXTENSIONS {
            extensions = Some(field.value);
        }
    }
    let found = match extensions {
        Some(e) => aaguid_extension(e)?,
        None => None,
    };
    if let Some((critical, value)) = found {
        let inner = Reader::new(value)?.tagged(der::OCTET_STRING)?;
        if critical || inner != credential.aaguid.0 {
            return Err(DerError::Tag);
        }
    }
    Ok(())
}

/// Applies the realm's attestation policy. `client_data_hash` completes the signed message;
/// `metadata` must be fresh at `now` for `direct`.
///
/// # Errors
/// [`Rejection`].
pub fn verify_attestation(
    object: &AttestationObject<'_>,
    auth_data: &AuthenticatorData<'_>,
    client_data_hash: &[u8; 32],
    policy: &AttestationPolicy,
    metadata: Option<&MdsBlob>,
    now: u64,
) -> Result<AttestationKind, Rejection> {
    let credential = auth_data
        .attested
        .as_ref()
        .ok_or(Rejection::AttestedCredential)?;
    let aaguids = match policy {
        AttestationPolicy::None => {
            return if object.fmt == "none" {
                if object.statement.as_map().is_some_and(<[_]>::is_empty) {
                    Ok(AttestationKind::None)
                } else {
                    Err(Rejection::AttestationStatement)
                }
            } else {
                Ok(AttestationKind::Unverified(object.fmt.to_owned()))
            };
        }
        AttestationPolicy::Direct { aaguids, .. } => aaguids,
    };
    // OP-146 m.4 (d)
    let metadata = metadata
        .filter(|m| m.is_fresh(now))
        .ok_or(Rejection::MetadataUnavailable)?;
    if !aaguids.is_empty() && !aaguids.contains(&credential.aaguid) {
        return Err(Rejection::AaguidNotAllowed);
    }
    let entry = metadata
        .entry(credential.aaguid)
        .ok_or(Rejection::AttestationTrust)?;
    if entry.compromised {
        return Err(Rejection::AuthenticatorStatus);
    }
    if object.fmt != "packed" {
        return Err(Rejection::AttestationFormat);
    }
    let stmt = &object.statement;
    let alg = stmt
        .get_text("alg")
        .and_then(Item::as_i64)
        .and_then(signature_alg)
        .ok_or(Rejection::AttestationFormat)?;
    let sig = stmt
        .get_text("sig")
        .and_then(Item::as_bytes)
        .ok_or(Rejection::AttestationStatement)?;
    let x5c = stmt
        .get_text("x5c")
        .and_then(Item::as_array)
        .ok_or(Rejection::AttestationTrust)?;
    if x5c.is_empty() || x5c.len() > MAX_CHAIN {
        return Err(Rejection::AttestationStatement);
    }
    let chain = x5c
        .iter()
        .map(|c| c.as_bytes().map(CertificateDer::from))
        .collect::<Option<Vec<_>>>()
        .ok_or(Rejection::AttestationStatement)?;
    let (leaf, intermediates) = chain.split_first().ok_or(Rejection::AttestationStatement)?;
    let mut message = auth_data.raw.to_vec();
    message.extend_from_slice(client_data_hash);
    EndEntityCert::try_from(leaf)
        .and_then(|ee| ee.verify_signature(alg, &message, sig))
        .map_err(|_| Rejection::AttestationStatement)?;
    check_certificate(leaf.as_ref(), credential).map_err(|_| Rejection::AttestationStatement)?;
    let roots: Vec<CertificateDer<'_>> = entry
        .roots
        .iter()
        .map(|r| CertificateDer::from(r.as_slice()))
        .collect();
    verify_chain(leaf, intermediates, &roots, now, AnyUsage)
        .map_err(|_| Rejection::AttestationTrust)?;
    Ok(AttestationKind::Verified)
}
