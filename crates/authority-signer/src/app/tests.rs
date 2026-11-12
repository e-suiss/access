//! The keyring over simulated time, checked by the Kernel verifier.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks and counters in test code"
)]

use std::collections::BTreeSet;

use access_kernel::digest::Digest;
use access_kernel::verify::key_scope::{KeyScopeError, operational_key, verify_metadata};
use suiss_crypto::cose::{Algorithm, KeySet, verify_sign1};
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::{SignError, SoftSigner};

use super::*;
use crate::ports::Generated;

const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;
const RECEIPT: &str = "application/access-receipt+cbor";

struct Factory {
    down: bool,
}

impl KeyFactory for Factory {
    fn generate(&mut self, alg: Algorithm) -> Result<Generated, SignError> {
        if self.down {
            return Err(SignError::Key);
        }
        assert_eq!(alg, Algorithm::Ed25519);
        let (signer, doc) = SoftSigner::generate_ed25519()?;
        Ok(Generated {
            signer: Box::new(signer),
            sealed: doc.expose().clone(),
        })
    }

    fn load(&mut self, _: Algorithm, sealed: &[u8]) -> Result<Box<dyn Signer + Send>, SignError> {
        let doc = suiss_crypto::secret::Secret::new(sealed.to_vec());
        Ok(Box::new(SoftSigner::ed25519_from_pkcs8(&doc)?))
    }
}

fn template() -> Template {
    Template {
        domain: Digest([7; 32]),
        genesis: Digest([8; 32]),
        algorithms: BTreeSet::from([Algorithm::Ed25519]),
        operational_alg: Algorithm::Ed25519,
        operational_window_max_ms: 24 * HOUR,
        min_versions: access_kernel::verify::key_scope::SpecVersions::default(),
        adopted: access_kernel::verify::key_scope::SpecVersions::default(),
        caps: None,
        hybrid: None,
        discovery: None,
        declared: crate::domain::declared_default(),
    }
}

fn keyring() -> Keyring {
    let (binding, _) = SoftSigner::generate_ed25519().unwrap();
    Keyring::new(template(), Box::new(binding), Policy::AUTHORITY)
}

fn trusted(ring: &Keyring) -> KeySet {
    let mut set = KeySet::default();
    set.insert(ring.binding_key().kid, ring.binding_key().key.clone())
        .unwrap();
    set.allowed.insert(Algorithm::Ed25519);
    set
}

fn advance(ring: &mut Keyring, factory: &mut Factory, from: u64, to: u64) {
    let mut now = from;
    while now <= to {
        ring.tick(factory, now, now / MINUTE).unwrap();
        now += MINUTE;
    }
}

/// Verifies `signed` as a receipt of the template's domain at `now`, as a verifier would.
fn verify(ring: &Keyring, signed: &Signed, now: u64) -> Result<(), KeyScopeError> {
    let metadata = verify_metadata(&PureBackend, ring.metadata().unwrap(), &trusted(ring))?;
    let key = operational_key(
        &PureBackend,
        &metadata,
        &Digest([7; 32]),
        &signed.excerpt,
        KeyUsage::Receipt,
        now,
        None,
    )?;
    let v = verify_sign1(&PureBackend, &signed.sign1, &key.key_set(), RECEIPT).unwrap();
    assert_eq!(v.payload, b"receipt");
    Ok(())
}

// T20, CR-18, CR-58
#[test]
fn an_artefact_verifies_through_metadata_and_excerpt() {
    // G35, HL-8, SAI-9
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let now = Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE;
    advance(&mut ring, &mut factory, 0, now);
    let signed = ring
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", now)
        .unwrap();
    verify(&ring, &signed, now).unwrap();
    // G35
    let metadata =
        verify_metadata(&PureBackend, ring.metadata().unwrap(), &trusted(&ring)).unwrap();
    assert_eq!(
        operational_key(
            &PureBackend,
            &metadata,
            &Digest([9; 32]),
            &signed.excerpt,
            KeyUsage::Receipt,
            now,
            None
        ),
        Err(KeyScopeError::OutOfScope)
    );
}

// §9.9.3 rule 7, PI-11, G18, AGI-3, CR-19
#[test]
fn a_token_is_holder_bound_and_within_the_key_publication() {
    // CR-24, MD-7, U41
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let now = Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE;
    advance(&mut ring, &mut factory, 0, now);
    let exp = (now + 5 * MINUTE) / 1000;
    let claims = format!(r#"{{"aud":"https://rs.example","exp":{exp},"cnf":{{"jkt":"x"}}}}"#);
    let t = ring.sign_token(claims.as_bytes(), now).unwrap();
    let mut parts = t.jws.split('.');
    let header = access_kernel::json::b64url_decode(parts.next().unwrap()).unwrap();
    let header = access_kernel::json::parse(&header, 1024).unwrap();
    assert_eq!(header.get("typ").and_then(|v| v.as_str()), Some(TOKEN_TYP));
    assert_eq!(
        header.get("kid").and_then(|v| v.as_str()),
        Some(access_kernel::json::b64url_encode(&t.kid).as_str())
    );
    // PI-11
    let bearer = format!(r#"{{"aud":"https://rs.example","exp":{exp}}}"#);
    assert_eq!(
        ring.sign_token(bearer.as_bytes(), now),
        Err(SignerError::Token)
    );
    let empty = format!(r#"{{"exp":{exp},"cnf":{{}}}}"#);
    assert_eq!(
        ring.sign_token(empty.as_bytes(), now),
        Err(SignerError::Token)
    );
    assert_eq!(
        ring.sign_token(br#"{"cnf":{"jkt":"x"}}"#, now),
        Err(SignerError::Token)
    );
    // CR-19
    let far = (now + 30 * 24 * HOUR) / 1000;
    let long = format!(r#"{{"exp":{far},"cnf":{{"jkt":"x"}}}}"#);
    assert_eq!(
        ring.sign_token(long.as_bytes(), now),
        Err(SignerError::TokenHorizon)
    );
    assert_eq!(SignerError::TokenHorizon.code(), "signer-token-horizon");
}

// CR-59, CR-25, SAI-46
#[test]
fn the_founding_key_signs_at_genesis_and_the_next_waits_for_the_lead() {
    // SAI-46, G61
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    ring.tick(&mut factory, 0, 0).unwrap();
    let at_genesis = ring
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", 0)
        .unwrap();
    verify(&ring, &at_genesis, 0).unwrap();
    let records = ring.records();
    assert_eq!(records.len(), 2);
    let founding = records.iter().find(|k| k.kid == at_genesis.kid).unwrap();
    assert!(founding.founding && founding.valid_from == 0);
    let second = records.iter().find(|k| !k.founding).unwrap();
    assert_eq!(second.state, State::Published);
    assert_eq!(second.valid_from, Policy::AUTHORITY.publish_lead_ms);
    let early = Policy::AUTHORITY.publish_lead_ms - MINUTE;
    advance(&mut ring, &mut factory, MINUTE, early);
    let still = ring
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", early)
        .unwrap();
    assert_eq!(still.kid, at_genesis.kid);
    assert!(
        ring.records()
            .iter()
            .all(|k| k.founding || k.state == State::Published)
    );
    let lead = Policy::AUTHORITY.publish_lead_ms;
    ring.tick(&mut factory, lead, 0).unwrap();
    let next = ring
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", lead)
        .unwrap();
    assert_eq!(next.kid, second.kid);
    verify(&ring, &next, lead).unwrap();
    assert_eq!(ring.records().iter().filter(|k| k.founding).count(), 1);
}

// CR-27
#[test]
fn artefacts_verify_across_rotations() {
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let mut now = 0;
    let mut kids = BTreeSet::new();
    let mut earlier = Vec::new();
    while now <= 12 * HOUR {
        ring.tick(&mut factory, now, now / MINUTE).unwrap();
        if let Ok(signed) = ring.sign(KeyUsage::Receipt, RECEIPT, b"receipt", now) {
            verify(&ring, &signed, now).unwrap();
            kids.insert(signed.kid);
            earlier.push((signed, now));
        }
        now += 10 * MINUTE;
    }
    assert!(kids.len() >= 9, "{}", kids.len());
    for (signed, at) in earlier.iter().rev().take(20) {
        verify(&ring, signed, *at).unwrap();
    }
}

// CR-23, G42
#[test]
fn an_outage_delays_artefacts_after_the_window() {
    // G42
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let start = Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE;
    advance(&mut ring, &mut factory, 0, start);
    factory.down = true;
    let mut now = start;
    let mut outage = false;
    while now <= start + 23 * HOUR {
        outage |= ring.tick(&mut factory, now, 1).unwrap().outage;
        let signed = ring
            .sign(KeyUsage::Receipt, RECEIPT, b"receipt", now)
            .unwrap();
        verify(&ring, &signed, now).unwrap();
        now += 30 * MINUTE;
    }
    assert!(outage);
    let after = start + 26 * HOUR;
    ring.tick(&mut factory, after, 1).unwrap();
    assert_eq!(
        ring.sign(KeyUsage::Receipt, RECEIPT, b"receipt", after),
        Err(SignerError::NoKey)
    );
}

// CR-23, OP-143 m.4
#[test]
fn a_restart_restores_the_keys() {
    let (binding, binding_doc) = SoftSigner::generate_ed25519().unwrap();
    let mut ring = Keyring::new(template(), Box::new(binding), Policy::AUTHORITY);
    let mut factory = Factory { down: false };
    let now = Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE;
    advance(&mut ring, &mut factory, 0, now);
    let before = ring
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", now)
        .unwrap();
    let saved = ring.saved();
    let binding = SoftSigner::ed25519_from_pkcs8(&binding_doc).unwrap();
    let mut restored = Keyring::restore(
        template(),
        Box::new(binding),
        Policy::AUTHORITY,
        saved,
        &mut factory,
        now + MINUTE,
    )
    .unwrap();
    let after = restored
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", now + MINUTE)
        .unwrap();
    assert_eq!(after.kid, before.kid);
    verify(&restored, &after, now + MINUTE).unwrap();
    advance(&mut restored, &mut factory, now + MINUTE, now + 100 * HOUR);
    assert!(
        restored
            .saved()
            .iter()
            .any(|s| s.record.state == State::Dropped && s.sealed.is_none())
    );
}

// CR-15, HL-27, OP-159 m.3 (r)
#[test]
fn the_metadata_declares_the_build_s_fips_module_whatever_the_caller_declares() {
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let now = Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE;
    advance(&mut ring, &mut factory, 0, now);
    let mut claimed = access_kernel::verify::key_scope::Declarations::default();
    claimed.fips_module = Some(true);
    ring.declare(claimed, now).unwrap();
    let metadata =
        verify_metadata(&PureBackend, ring.metadata().unwrap(), &trusted(&ring)).unwrap();
    assert_eq!(
        metadata.declared.fips_module,
        Some(suiss_crypto::fips::BUILD)
    );
}
