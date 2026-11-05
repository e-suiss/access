#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks in test code"
)]

use std::collections::BTreeMap;

use access_kernel::claim::body::{AuthMethod, Authentication, Body, Class, body_digest};
use access_kernel::model::EqValue;
use suiss_crypto::envelope::SoftKek;

use super::*;
use crate::adapters::SealedFactory;

const REALM: [u8; 16] = [1; 16];
const PARTY: [u8; 16] = [2; 16];
const DOMAIN: [u8; 32] = [3; 32];

fn factory() -> SealedFactory<SoftKek> {
    SealedFactory::new(SoftKek::new("realm-kek", [5; 32]))
}

fn statement(class: &str, issuer: [u8; 16], at: u64) -> Statement {
    let body = Body::Authentication(Authentication {
        method: AuthMethod::Webauthn,
        auth_time: at,
        statement: None,
        evidence: None,
        webauthn: None,
        upstream: None,
    });
    let value = body_digest(Class::Authentication, &body.to_value()).unwrap();
    Statement {
        domain: Digest(DOMAIN),
        issuer: Id(issuer),
        subject: Id([9; 16]),
        class: String::from(class),
        value: Some(EqValue::Bytes(value.to_vec())),
        issued_at: at,
        validity: Window {
            from: at,
            until: at + 1_000,
        },
        assurance: BTreeMap::from([(String::from("aal"), 2)]),
        bound_intent: None,
        bound_instance: Some(Id([7; 16])),
        bound_resource: None,
        supersedes: None,
    }
}

// OP-144, §10.1.7, MD-3, L2-CLM-1: the realm issuer's own Ed25519 key signs a Claim that verifies
// as its Party's in the domain under the Instance key Access holds for it
#[test]
fn the_issuer_key_signs_claims_of_its_party() {
    let key = IssuerKey::generate(REALM, PARTY, &mut factory()).unwrap();
    let payload = statement("authentication", PARTY, 50).to_bytes().unwrap();
    let sign1 = key.sign_claim(&payload, 50).unwrap();
    let got = claim::verify(
        &sign1,
        &PublicKey::Ed25519(key.key()),
        &Id(PARTY),
        &Digest(DOMAIN),
    )
    .unwrap();
    assert_eq!(got, statement("authentication", PARTY, 50));
    assert_eq!(claim::kid(&sign1).unwrap(), key.kid());
}

// §10.1.5, §13.2, K07 (identity issuer ≠ authority issuer): the key signs only its own Party's
// statements, only identity issuer classes, only canonical bytes, only at the stated time
#[test]
fn the_issuer_key_refuses_what_is_not_its_own() {
    let key = IssuerKey::generate(REALM, PARTY, &mut factory()).unwrap();
    let refused = |payload: &[u8], at| key.sign_claim(payload, at).err();
    let other = statement("authentication", [8; 16], 50).to_bytes().unwrap();
    assert_eq!(refused(&other, 50), Some(SignerError::Payload));
    for class in [
        "party_key_state",
        "party_compromise",
        "controller_of",
        "risk_",
    ] {
        let s = Statement {
            value: None,
            ..statement(class, PARTY, 50)
        };
        assert_eq!(
            refused(&s.to_bytes().unwrap(), 50),
            Some(SignerError::Payload)
        );
    }
    let ok = statement("authentication", PARTY, 50).to_bytes().unwrap();
    assert_eq!(refused(&ok, 51), Some(SignerError::Payload));
    assert_eq!(refused(b"not cbor", 50), Some(SignerError::Payload));
    assert!(issues("risk_new_device"));
    assert!(issues("account_status"));
    assert!(!issues("party_terminated"));
}

// OP-149 m.16 (a), L0-META-7: the key signs the AIS of its own Party's registration and of the
// Instance that is itself, under the bootstrap basis, and nothing else
#[test]
fn the_issuer_key_signs_its_own_registration() {
    let key = IssuerKey::generate(REALM, PARTY, &mut factory()).unwrap();
    let pk = PublicKey::Ed25519(key.key());
    let domain = Digest(DOMAIN);
    for (step, payload) in [
        (
            Step::Register,
            Payload::PartyRegister {
                party: Id(PARTY),
                root: Root::Sole(Id(PARTY)),
                actor_kind: ActorKind::System,
            },
        ),
        (
            Step::Create,
            Payload::InstanceCreate {
                party: Id(PARTY),
                key: pk.clone(),
                mandate: None,
            },
        ),
    ] {
        let r = Registration {
            domain: DOMAIN,
            nonce: vec![4; 32],
            validity: (10, 20),
            iat: 15,
            pep: String::from("identity"),
            step,
        };
        let sign1 = key.sign_registration(&r).unwrap();
        let intent = self_signed_intent(
            &payload,
            Id(PARTY),
            Window {
                from: 10,
                until: 20,
            },
        )
        .and_then(|i| intent_digest(&i).ok())
        .unwrap();
        let basis = bootstrap_basis(&domain);
        let s = ais::verify(
            &sign1,
            &pk,
            &ais::Expected {
                domain: &domain,
                nonce: &r.nonce,
                intent: &intent,
                mode: Mode::Commit,
                pep: "identity",
                capacity: Capacity::Own,
                basis: &basis,
                exercise: None,
            },
            15,
        )
        .unwrap();
        assert_eq!(s.iat, 15);
        assert_eq!(Step::parse(step.name()), Some(step));
    }
    let bad = Registration {
        domain: DOMAIN,
        nonce: Vec::new(),
        validity: (20, 10),
        iat: 15,
        pep: String::from("identity"),
        step: Step::Create,
    };
    assert_eq!(
        key.sign_registration(&bad).err(),
        Some(SignerError::Payload)
    );
}

// OP-73, CR-21 m.3: the stored form is sealed, restores the same key, and is never another
// realm's
#[test]
fn the_issuer_key_restores_from_its_sealed_form() {
    let key = IssuerKey::generate(REALM, PARTY, &mut factory()).unwrap();
    let stored = key.stored().unwrap();
    let again = IssuerKey::restore(REALM, &stored, &mut factory()).unwrap();
    assert_eq!((again.key(), again.party()), (key.key(), PARTY));
    assert_eq!(
        IssuerKey::restore([9; 16], &stored, &mut factory()).err(),
        Some(IssuerError::OtherIssuer)
    );
    assert_eq!(
        IssuerKey::restore(REALM, b"junk", &mut factory()).err(),
        Some(IssuerError::Stored)
    );
}
