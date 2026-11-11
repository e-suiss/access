//! CR-51 m.3: the known answers hold, and any wrong answer refuses.

use super::*;

#[test]
fn the_known_answers_hold() {
    assert_eq!(run(), Ok(()));
}

#[test]
fn a_wrong_ed25519_signature_refuses() {
    let wrong = flipped(&ED25519_SIGNATURE);
    let v = Vector {
        signature: &wrong,
        ..ED25519
    };
    assert_eq!(ed25519(&v), Err(KatError::Ed25519));
}

#[test]
fn a_wrong_ed25519_message_refuses() {
    let v = Vector {
        message: b"s",
        ..ED25519
    };
    assert_eq!(ed25519(&v), Err(KatError::Ed25519));
}

#[test]
fn a_wrong_ed25519_public_key_refuses() {
    let v = Vector {
        public: &P256_PUBLIC,
        ..ED25519
    };
    assert_eq!(ed25519(&v), Err(KatError::Ed25519));
}

#[test]
fn a_wrong_p256_signature_refuses() {
    let wrong = flipped(&P256_SIGNATURE);
    let v = Vector {
        signature: &wrong,
        ..P256
    };
    assert_eq!(p256(&v), Err(KatError::P256));
}

#[test]
fn a_high_s_p256_signature_refuses() {
    let mut high = P256_SIGNATURE;
    let s = &mut high[32..];
    let mut borrow = false;
    for (out, n) in s.iter_mut().rev().zip(sig::P256_N.iter().rev()) {
        let (d1, b1) = n.overflowing_sub(*out);
        let (d2, b2) = d1.overflowing_sub(u8::from(borrow));
        *out = d2;
        borrow = b1 || b2;
    }
    let v = Vector {
        signature: &high,
        ..P256
    };
    assert_eq!(p256(&v), Err(KatError::P256));
}

#[test]
fn a_wrong_p256_key_refuses() {
    let v = Vector {
        pkcs8: &ED25519_PKCS8,
        ..P256
    };
    assert_eq!(p256(&v), Err(KatError::P256));
}

#[test]
fn every_failure_has_a_stable_code() {
    assert_eq!(KatError::Ed25519.code(), "signer-kat-ed25519");
    assert_eq!(KatError::P256.code(), "signer-kat-p256");
}
