#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::adapters::SealedFactory;

fn factory() -> SealedFactory<SoftKek> {
    let mut k = [0_u8; 32];
    aws_lc_rs::rand::fill(&mut k).unwrap();
    SealedFactory::new(SoftKek::new("realm-kek", k))
}

const REALM: Realm = Realm([4; 16]);

fn body() -> Vec<u8> {
    let mut b = CERT_PREFIX.to_vec();
    b.extend_from_slice(&[7; 40]);
    b
}

fn active(ring: &Ring) -> [u8; 32] {
    ring.keys()
        .iter()
        .find(|k| k.phase == Phase::Active)
        .unwrap()
        .key
}

// OP-156 m.3 (o), IDP-32
#[test]
fn the_realm_ca_key_signs_certificate_bodies_only() {
    let mut f = factory();
    let mut ring = Ring::new(REALM);
    assert_eq!(ring.sign(&[0; 32], &body()), Err(SshKeyError::NoKey));
    assert!(ring.open(1_000, &mut f).unwrap());
    assert!(!ring.open(2_000, &mut f).unwrap());
    let key = active(&ring);
    let sig = ring.sign(&key, &body()).unwrap();
    assert!(
        UnparsedPublicKey::new(&ED25519, key)
            .verify(&body(), &sig)
            .is_ok()
    );
    assert_eq!(ring.sign(&key, b"a JWS"), Err(SshKeyError::Data));
    assert_eq!(ring.sign(&[1; 32], &body()), Err(SshKeyError::Changed));
    let restored = Ring::restore(REALM, &ring.stored().unwrap(), &mut f).unwrap();
    assert_eq!(restored.keys(), ring.keys());
    assert!(Ring::restore(Realm([5; 16]), &ring.stored().unwrap(), &mut f).is_err());
}

// OP-156 m.3 (o)
#[test]
fn rotation_publishes_switches_and_removes() {
    let mut f = factory();
    let mut ring = Ring::new(REALM);
    ring.open(1, &mut f).unwrap();
    let first = active(&ring);
    assert_eq!(
        ring.rotate(Step::Switch, 2, &mut f),
        Err(SshKeyError::Order)
    );
    ring.rotate(Step::Add, 3, &mut f).unwrap();
    assert_eq!(active(&ring), first);
    assert_eq!(ring.keys().len(), 2);
    ring.rotate(Step::Switch, 4, &mut f).unwrap();
    assert_ne!(active(&ring), first);
    assert_eq!(ring.keys()[0].phase, Phase::Retiring);
    assert_eq!(ring.sign(&first, &body()), Err(SshKeyError::Changed));
    ring.rotate(Step::Remove, 5, &mut f).unwrap();
    assert_eq!(ring.keys().len(), 1);
    let second = active(&ring);
    ring.rotate(Step::Emergency, 6, &mut f).unwrap();
    assert_eq!(ring.keys().len(), 1);
    assert_ne!(active(&ring), second);
    ring.rotate(Step::Close, 7, &mut f).unwrap();
    assert_eq!(ring.keys(), Vec::<KeyInfo>::new());
    assert!(ring.open(8, &mut f).unwrap());
}

#[test]
fn requests_and_answers_round_trip() {
    for r in [
        SshRequest::Open(REALM),
        SshRequest::Keys(REALM),
        SshRequest::Sign {
            realm: REALM,
            key: [1; 32],
            data: body(),
        },
        SshRequest::Rotate {
            realm: REALM,
            step: Step::Emergency,
        },
    ] {
        assert_eq!(SshRequest::from_value(&r.to_value()).unwrap(), r);
        assert_eq!(r.realm(), REALM);
    }
    for a in [
        SshResponse::Keys(vec![KeyInfo {
            key: [2; 32],
            phase: Phase::Published,
            since: 9,
        }]),
        SshResponse::Signed([3; 64]),
    ] {
        assert_eq!(SshResponse::from_value(&a.to_value()).unwrap(), a);
    }
}
