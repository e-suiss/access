//! `android-key` attestation (WebAuthn L3 §8.4): the credential key signed
//! `authenticatorData ‖ clientDataHash`, the leaf certificate holds that key, and its
//! `KeyDescription` extension binds `clientDataHash` as `attestationChallenge`, scopes the key
//! to this RP (no `allApplications`) and, in the hardware-enforced list, says the key was
//! generated inside the authenticator for signing.

use access_parse::cbor::Item;

use super::{Input, Lookup, Statement, chain, signature_alg, verify_by};
use crate::domain::Rejection;
use crate::domain::x509::{self, Cert, DerError, Reader, same_key};

/// 1.3.6.1.4.1.11129.2.1.17, the key attestation extension.
const OID_KEY_DESCRIPTION: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11];
const TAG_PURPOSE: u32 = 1;
const TAG_ALL_APPLICATIONS: u32 = 600;
const TAG_ORIGIN: u32 = 702;
const PURPOSE_SIGN: u64 = 2;
const ORIGIN_GENERATED: u64 = 0;

/// What one `AuthorizationList` says.
#[derive(Default)]
struct Authorizations {
    all_applications: bool,
    origin: Option<u64>,
    sign: bool,
}

fn authorizations(list: &[u8]) -> Result<Authorizations, DerError> {
    let mut r = Reader::new(list)?;
    let mut out = Authorizations::default();
    while !r.is_empty() {
        let t = r.next_tlv()?;
        if t.tag.context(TAG_ALL_APPLICATIONS) {
            out.all_applications = true;
        } else if t.tag.context(TAG_ORIGIN) {
            out.origin = Some(x509::uint(Reader::new(t.value)?.tagged(x509::INTEGER)?)?);
        } else if t.tag.context(TAG_PURPOSE) {
            let mut set = Reader::new(Reader::new(t.value)?.tagged(x509::SET)?)?;
            while !set.is_empty() {
                if x509::uint(set.tagged(x509::INTEGER)?)? == PURPOSE_SIGN {
                    out.sign = true;
                }
            }
        }
    }
    Ok(out)
}

/// `(attestationChallenge, softwareEnforced, hardwareEnforced)` of a `KeyDescription`.
fn key_description(value: &[u8]) -> Result<(&[u8], Authorizations, Authorizations), DerError> {
    let mut outer = Reader::new(value)?;
    let mut kd = Reader::new(outer.tagged(x509::SEQUENCE)?)?;
    kd.tagged(x509::INTEGER)?;
    kd.tagged(x509::ENUMERATED)?;
    kd.tagged(x509::INTEGER)?;
    kd.tagged(x509::ENUMERATED)?;
    let challenge = kd.tagged(x509::OCTET_STRING)?;
    kd.tagged(x509::OCTET_STRING)?;
    let software = authorizations(kd.tagged(x509::SEQUENCE)?)?;
    let hardware = authorizations(kd.tagged(x509::SEQUENCE)?)?;
    if !outer.is_empty() || !kd.is_empty() {
        return Err(DerError);
    }
    Ok((challenge, software, hardware))
}

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
    let chain = chain(input.stmt).map_err(|e| match e {
        Rejection::AttestationTrust => Rejection::AttestationFormat,
        other => other,
    })?;
    let leaf = *chain.first().ok_or(Rejection::AttestationStatement)?;
    verify_by(leaf, alg, &input.signed(), sig)?;
    let cert = Cert::parse(leaf).map_err(|_| Rejection::AttestationStatement)?;
    if !same_key(&cert, &input.credential.public_key) {
        return Err(Rejection::AttestationStatement);
    }
    let ext = cert
        .extension(OID_KEY_DESCRIPTION)
        .map_err(|_| Rejection::AttestationStatement)?
        .ok_or(Rejection::AttestationStatement)?;
    let (challenge, software, hardware) =
        key_description(ext.value).map_err(|_| Rejection::AttestationStatement)?;
    if challenge != input.client_data_hash.as_slice()
        || software.all_applications
        || hardware.all_applications
        || hardware.origin != Some(ORIGIN_GENERATED)
        || !hardware.sign
    {
        return Err(Rejection::AttestationStatement);
    }
    Ok(Statement {
        chain,
        lookup: Lookup::Aaguid,
    })
}
