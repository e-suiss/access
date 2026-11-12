//! `packed` full attestation (WebAuthn L3 §8.2): the attestation certificate signed
//! `authenticatorData ‖ clientDataHash`. Self attestation has no chain and is not trusted.

use access_parse::cbor::Item;

use super::{Input, Lookup, Statement, aaguid_matches, chain, signature_alg, verify_by};
use crate::domain::Rejection;
use crate::domain::x509::{self, Cert, DerError, Reader};

/// 2.5.4.11, organizationalUnitName.
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b];

fn subject_has_ou(name: &[u8]) -> Result<bool, DerError> {
    let mut rdns = Reader::new(name)?;
    while !rdns.is_empty() {
        let mut set = Reader::new(rdns.tagged(x509::SET)?)?;
        while !set.is_empty() {
            let mut atv = Reader::new(set.tagged(x509::SEQUENCE)?)?;
            let oid = atv.tagged(x509::OID)?;
            let value = atv.next_tlv()?;
            if oid == OID_OU && value.value == b"Authenticator Attestation" {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// L3 §8.2.1: version 3, subject OU "Authenticator Attestation", and a non-critical AAGUID
/// extension equal to the credential's when present. `cA = false` is enforced by path
/// validation.
pub(super) fn verify<'a>(input: &Input<'_, 'a>) -> Result<Statement<'a>, Rejection> {
    let alg = input
        .stmt
        .get_text("alg")
        .and_then(Item::as_i64)
        .and_then(signature_alg)
        .ok_or(Rejection::AttestationFormat)?;
    let sig = input
        .stmt
        .get_text("sig")
        .and_then(Item::as_bytes)
        .ok_or(Rejection::AttestationStatement)?;
    let chain = chain(input.stmt)?;
    let leaf = *chain.first().ok_or(Rejection::AttestationStatement)?;
    verify_by(leaf, alg, &input.signed(), sig)?;
    let cert = Cert::parse(leaf).map_err(|_| Rejection::AttestationStatement)?;
    let ou = subject_has_ou(cert.subject).map_err(|_| Rejection::AttestationStatement)?;
    if cert.version != 2 || !ou || !aaguid_matches(&cert, input.credential) {
        return Err(Rejection::AttestationStatement);
    }
    Ok(Statement {
        chain,
        lookup: Lookup::Aaguid,
    })
}
