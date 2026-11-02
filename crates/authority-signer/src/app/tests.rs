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
    )?;
    let v = verify_sign1(&PureBackend, &signed.sign1, &key.key_set(), RECEIPT).unwrap();
    assert_eq!(v.payload, b"receipt");
    Ok(())
}

// T20, CR-18, CR-58: the metadata is signed by the binding key, the excerpt names the
// operational key and the artefact verifies through them
#[test]
fn an_artefact_verifies_through_metadata_and_excerpt() {
    // G35, HL-8
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let now = Policy::AUTHORITY.publish_lead_ms + 2 * MINUTE;
    advance(&mut ring, &mut factory, 0, now);
    let signed = ring
        .sign(KeyUsage::Receipt, RECEIPT, b"receipt", now)
        .unwrap();
    verify(&ring, &signed, now).unwrap();
    // another domain's artefact does not verify with this domain's excerpt (G35)
    let metadata =
        verify_metadata(&PureBackend, ring.metadata().unwrap(), &trusted(&ring)).unwrap();
    assert_eq!(
        operational_key(
            &PureBackend,
            &metadata,
            &Digest([9; 32]),
            &signed.excerpt,
            KeyUsage::Receipt,
            now
        ),
        Err(KeyScopeError::OutOfScope)
    );
}

// CR-25, SAI-46: nothing is signed before a key has been published for the lead
#[test]
fn nothing_signs_before_the_lead() {
    // SAI-46, G61
    let mut ring = keyring();
    let mut factory = Factory { down: false };
    let early = Policy::AUTHORITY.publish_lead_ms - MINUTE;
    advance(&mut ring, &mut factory, 0, early);
    assert_eq!(
        ring.sign(KeyUsage::Receipt, RECEIPT, b"receipt", early),
        Err(SignerError::NoKey)
    );
}

// CR-27: across rotations every artefact verifies against the metadata current when it is
// signed, and a retired key's artefacts still verify while it is published
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

// CR-23, G42: through a key-generation outage the active key signs to the end of its window;
// after that nothing is signed, never an unsigned artefact
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

// CR-23, OP-143 m.4: a restarted signer loads its sealed keys back and signs on with the same
// key; a dropped key's sealed material is gone
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
