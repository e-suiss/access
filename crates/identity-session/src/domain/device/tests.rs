#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks in test code"
)]

use suiss_crypto::dcbor::{self, Value};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};

use super::*;

fn ed25519() -> SoftSigner {
    SoftSigner::generate_ed25519().unwrap().0
}

fn p256() -> SoftSigner {
    SoftSigner::generate_p256().unwrap().0
}

// OP-149 m.6, PD
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

// OP-149 m.6, m.14 (a), CR-24, P-256
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

// OP-149 m.14 (a), P-256
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

// OP-149 m.32, m.6, CR-9
#[test]
fn a_known_device_proves_its_key_over_the_challenge() {
    let challenge = [0x5a; 32];
    for signer in [ed25519(), p256()] {
        let key = signer.public_key();
        let pop = sign_sign1(&signer, kid(&key), POP_CONTENT_TYPE, &challenge).unwrap();
        assert_eq!(verify_pop(&key, &pop, &challenge), Ok(()));
        assert_eq!(verify_pop(&key, &pop, &[0x5b; 32]), Err(KeyRejection::Pop));
        let other = ed25519();
        let forged = sign_sign1(&other, kid(&key), POP_CONTENT_TYPE, &challenge).unwrap();
        assert_eq!(
            verify_pop(&key, &forged, &challenge),
            Err(KeyRejection::Pop)
        );
        let ais = sign_sign1(
            &signer,
            kid(&key),
            access_kernel::ais::CONTENT_TYPE,
            &challenge,
        )
        .unwrap();
        assert_eq!(verify_pop(&key, &ais, &challenge), Err(KeyRejection::Pop));
        let unnamed = sign_sign1(&signer, [7; 32], POP_CONTENT_TYPE, &challenge).unwrap();
        assert_eq!(
            verify_pop(&key, &unnamed, &challenge),
            Err(KeyRejection::Pop)
        );
        assert_eq!(verify_pop(&key, b"", &challenge), Err(KeyRejection::Pop));
    }
}
