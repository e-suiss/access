//! `apple` anonymous attestation (WebAuthn L3 §8.8): the leaf certificate holds the credential
//! key and its nonce extension is `SHA-256(authenticatorData ‖ clientDataHash)`.

use access_crypto::webauthn::sha256;

use super::{Input, Lookup, Statement, chain};
use crate::domain::Rejection;
use crate::domain::x509::{self, Cert, DerError, Reader, same_key};

/// 1.2.840.113635.100.8.2, the Apple nonce extension.
const OID_NONCE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x08, 0x02];

fn nonce(value: &[u8]) -> Result<&[u8], DerError> {
    let mut outer = Reader::new(value)?;
    let mut seq = Reader::new(outer.tagged(x509::SEQUENCE)?)?;
    let t = seq.next_tlv()?;
    if t.tag.first != 0xa1 || !seq.is_empty() || !outer.is_empty() {
        return Err(DerError);
    }
    Reader::new(t.value)?.tagged(x509::OCTET_STRING)
}

pub(super) fn verify<'a>(input: &Input<'_, 'a>) -> Result<Statement<'a>, Rejection> {
    let chain = chain(input.stmt).map_err(|e| match e {
        Rejection::AttestationTrust => Rejection::AttestationFormat,
        other => other,
    })?;
    let leaf = *chain.first().ok_or(Rejection::AttestationStatement)?;
    let cert = Cert::parse(leaf).map_err(|_| Rejection::AttestationStatement)?;
    let ext = cert
        .extension(OID_NONCE)
        .map_err(|_| Rejection::AttestationStatement)?
        .ok_or(Rejection::AttestationStatement)?;
    let found = nonce(ext.value).map_err(|_| Rejection::AttestationStatement)?;
    if found != sha256(&input.signed()) || !same_key(&cert, &input.credential.public_key) {
        return Err(Rejection::AttestationStatement);
    }
    Ok(Statement {
        chain,
        lookup: Lookup::Aaguid,
    })
}
