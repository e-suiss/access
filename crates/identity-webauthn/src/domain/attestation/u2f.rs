//! `fido-u2f` attestation (WebAuthn L3 §8.6): one P-256 attestation certificate signed
//! `0x00 ‖ rpIdHash ‖ clientDataHash ‖ credentialId ‖ publicKeyU2F`. The credential key must be
//! ES256; U2F has no AAGUID, so the model is found by the certificate's key identifier.

use access_parse::cbor::Item;

use super::{Input, Lookup, Statement, chain, verify_by};
use crate::domain::Rejection;
use crate::domain::cose::{CoseAlgorithm, CoseKey};
use crate::domain::x509::Cert;

/// 1.2.840.10045.2.1, id-ecPublicKey.
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// 1.2.840.10045.3.1.7, prime256v1.
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

pub(super) fn verify<'a>(input: &Input<'_, 'a>) -> Result<Statement<'a>, Rejection> {
    let sig = input
        .stmt
        .get_text("sig")
        .and_then(Item::as_bytes)
        .ok_or(Rejection::AttestationStatement)?;
    let chain = chain(input.stmt).map_err(|e| match e {
        Rejection::AttestationTrust => Rejection::AttestationFormat,
        other => other,
    })?;
    let [leaf] = chain.as_slice() else {
        return Err(Rejection::AttestationStatement);
    };
    let leaf = *leaf;
    let CoseKey::P256 {
        alg: CoseAlgorithm::Es256,
        point,
    } = &input.credential.public_key
    else {
        return Err(Rejection::AttestationFormat);
    };
    let cert = Cert::parse(leaf).map_err(|_| Rejection::AttestationStatement)?;
    if cert.key_algorithm != OID_EC_PUBLIC_KEY || cert.key_parameters != Some(OID_P256) {
        return Err(Rejection::AttestationStatement);
    }
    let mut message = vec![0x00];
    message.extend_from_slice(&input.auth_data.rp_id_hash);
    message.extend_from_slice(input.client_data_hash);
    message.extend_from_slice(input.credential.credential_id.as_bytes());
    message.extend_from_slice(point);
    verify_by(leaf, webpki::aws_lc_rs::ECDSA_P256_SHA256, &message, sig)?;
    let key_id = cert
        .subject_key_id()
        .map_err(|_| Rejection::AttestationStatement)?
        .ok_or(Rejection::AttestationTrust)?;
    Ok(Statement {
        chain: vec![leaf],
        lookup: Lookup::KeyId(key_id),
    })
}
