#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks in test code"
)]

use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

use super::*;

const ISSUER: &str = "https://acme.suiss.example";
const CHALLENGE: [u8; 32] = [7; 32];

fn ed25519() -> SoftSigner {
    SoftSigner::generate_ed25519().unwrap().0
}

fn p256() -> SoftSigner {
    SoftSigner::generate_p256().unwrap().0
}

fn pop(signer: &SoftSigner, content_type: &str, payload: &[u8]) -> Vec<u8> {
    sign_sign1(signer, kid(&signer.public_key()), content_type, payload).unwrap()
}

// OP-149 m.6, PD: AAL2 and an authentication within five minutes
#[test]
fn registration_needs_aal2_and_a_fresh_step_up() {
    let now = 10_000_000;
    assert_eq!(assurance(Aal::Aal2, now - 1_000, now), Assurance::Fresh);
    assert_eq!(
        assurance(Aal::Aal3, now - STEP_UP_WINDOW_MS, now),
        Assurance::Fresh
    );
    assert_eq!(assurance(Aal::Aal1, now, now), Assurance::TooWeak);
    assert_eq!(
        assurance(Aal::Aal2, now - STEP_UP_WINDOW_MS - 1, now),
        Assurance::Stale
    );
}

// OP-149 m.6, m.14 (a), CR-24: Ed25519 and P-256 COSE_Keys round-trip and carry their RFC 7638 kid
#[test]
fn ed25519_and_p256_keys_parse_and_round_trip() {
    for signer in [ed25519(), p256()] {
        let key = signer.public_key();
        let encoded = cose_key(&key);
        assert_eq!(instance_key(&encoded).unwrap(), key);
        assert_eq!(
            kid(&key),
            access_kernel::verify::key_scope::thumbprint(&key)
        );
    }
}

// OP-149 m.14 (a): only Ed25519 and P-256 are Instance keys; the algorithm must fit the curve
#[test]
fn other_keys_are_refused() {
    let x = ed25519().public_key();
    let PublicKey::Ed25519(x) = x else { panic!() };
    let with_alg = |alg: i64| {
        dcbor::encode(
            &Value::Map(vec![
                (Value::Unsigned(1), Value::Unsigned(1)),
                (Value::Unsigned(3), Value::int(alg)),
                (Value::int(-1), Value::Unsigned(6)),
                (Value::int(-2), Value::Bytes(x.to_vec())),
            ]),
            dcbor::Limits::CEILING,
        )
        .unwrap()
    };
    assert!(instance_key(&with_alg(-19)).is_ok());
    assert!(instance_key(&with_alg(-8)).is_ok());
    assert_eq!(instance_key(&with_alg(-9)), Err(KeyRejection::Key));
    assert_eq!(instance_key(&with_alg(-48)), Err(KeyRejection::Key));
    let x448 = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(1)),
            (Value::int(-1), Value::Unsigned(7)),
            (Value::int(-2), Value::Bytes(vec![1; 57])),
        ]),
        dcbor::Limits::CEILING,
    )
    .unwrap();
    assert_eq!(instance_key(&x448), Err(KeyRejection::Key));
    let off_curve = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::int(-1), Value::Unsigned(1)),
            (Value::int(-2), Value::Bytes(vec![1; 32])),
            (Value::int(-3), Value::Bytes(vec![2; 32])),
        ]),
        dcbor::Limits::CEILING,
    )
    .unwrap();
    assert_eq!(instance_key(&off_curve), Err(KeyRejection::Key));
    assert_eq!(instance_key(&[0xa0]), Err(KeyRejection::Key));
    assert_eq!(instance_key(b"not cbor"), Err(KeyRejection::Key));
}

// OP-149 m.6, CR-9: the proof is a COSE_Sign1 by the presented key over this realm's challenge
#[test]
fn the_proof_binds_key_realm_and_challenge() {
    for signer in [ed25519(), p256()] {
        let key = signer.public_key();
        let good = pop(&signer, POP_CONTENT_TYPE, &pop_payload(ISSUER, &CHALLENGE));
        assert_eq!(verify_pop(&key, &good, ISSUER, &CHALLENGE), Ok(()));
        assert_eq!(pop_challenge(&good), Some(CHALLENGE));
        assert_eq!(pop_challenge(b"junk"), None);
        assert_eq!(
            verify_pop(&key, &good, ISSUER, &[8; 32]),
            Err(KeyRejection::Pop)
        );
        assert_eq!(
            verify_pop(&key, &good, "https://other.suiss.example", &CHALLENGE),
            Err(KeyRejection::Pop)
        );
        let other = ed25519();
        assert_eq!(
            verify_pop(&other.public_key(), &good, ISSUER, &CHALLENGE),
            Err(KeyRejection::Pop)
        );
        let wrong_type = pop(
            &signer,
            "application/cose",
            &pop_payload(ISSUER, &CHALLENGE),
        );
        assert_eq!(
            verify_pop(&key, &wrong_type, ISSUER, &CHALLENGE),
            Err(KeyRejection::Pop)
        );
        assert_eq!(
            verify_pop(&key, &[0xd2; 2000], ISSUER, &CHALLENGE),
            Err(KeyRejection::Pop)
        );
    }
}
