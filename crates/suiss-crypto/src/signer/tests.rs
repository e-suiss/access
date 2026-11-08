use alloc::format;

use super::*;
use crate::aws::AwsLcBackend;
use crate::cose::{KeySet, verify_sign1};
use crate::note::{Checkpoint, verify_checkpoint};
use crate::sig::PureBackend;

fn keys(kid: [u8; 32], signer: &dyn Signer) -> KeySet {
    let mut ks = KeySet::default();
    ks.insert(kid, signer.public_key()).unwrap();
    ks.allowed.extend([Algorithm::Ed25519, Algorithm::Esp256]);
    ks
}

// OP-140 m.4, L2-SIG-1
#[test]
fn signed_cose_verifies() {
    for (signer, _) in [
        SoftSigner::generate_ed25519().unwrap(),
        SoftSigner::generate_p256().unwrap(),
    ] {
        let msg = sign_sign1(&signer, [4; 32], "application/test+cbor", b"payload").unwrap();
        let ks = keys([4; 32], &signer);
        let v = verify_sign1(&PureBackend, &msg, &ks, "application/test+cbor").unwrap();
        assert_eq!(v.payload, b"payload");
        assert!(verify_sign1(&AwsLcBackend, &msg, &ks, "application/test+cbor").is_ok());
    }
}

// CR-9, P-256
#[test]
fn p256_signatures_are_low_s() {
    let (signer, _) = SoftSigner::generate_p256().unwrap();
    for i in 0..64_u8 {
        let sig = signer.sign(&[i]).unwrap();
        assert!(sig[32..] <= P256_HALF_N[..]);
    }
    let mut high = [0_u8; 64];
    high[32..].copy_from_slice(&P256_N);
    high[63] = high[63].wrapping_sub(1);
    low_s(&mut high).unwrap();
    assert_eq!(high[32..63], [0; 31]);
    assert_eq!(high[63], 1);
}

// OP-140 m.4
#[test]
fn keys_round_trip_through_pkcs8() {
    let (a, doc) = SoftSigner::generate_ed25519().unwrap();
    let b = SoftSigner::ed25519_from_pkcs8(&doc).unwrap();
    assert_eq!(a.public_key(), b.public_key());
    let (p, doc) = SoftSigner::generate_p256().unwrap();
    assert_eq!(
        SoftSigner::p256_from_pkcs8(&doc).unwrap().public_key(),
        p.public_key()
    );
    assert!(SoftSigner::ed25519_from_pkcs8(&doc).is_err());
}

// L2-CKP-3, L2-CKP-4
#[test]
fn signed_and_cosigned_checkpoint_verifies() {
    let (log, _) = SoftSigner::generate_ed25519().unwrap();
    let (witness, _) = SoftSigner::generate_ed25519().unwrap();
    let body = Checkpoint {
        origin: alloc::string::String::from("example.com/log"),
        size: 3,
        root: [5; 32],
        extensions: alloc::vec::Vec::new(),
    }
    .to_body()
    .unwrap();
    let (lv, l) = sign_note(&log, "example.com/log", &body).unwrap();
    let (wv, w) = cosign(&witness, "witness.example", 1_700_000_000, &body).unwrap();
    let note = format!("{body}\n{l}{w}");
    let (_, ok) = verify_checkpoint(&PureBackend, &note, "example.com/log", &lv, &[wv]).unwrap();
    assert_eq!(ok[1].timestamp, Some(1_700_000_000));
    let (p, _) = SoftSigner::generate_p256().unwrap();
    assert_eq!(
        sign_note(&p, "x.example", &body).unwrap_err(),
        SignError::Algorithm
    );
}

// CR-10
#[test]
fn oversized_payload_is_not_signed() {
    let (signer, _) = SoftSigner::generate_ed25519().unwrap();
    let big = alloc::vec![0_u8; crate::dcbor::Limits::MAX_STRING + 1];
    assert!(matches!(
        sign_sign1(&signer, [4; 32], "application/test+cbor", &big),
        Err(SignError::Encode)
    ));
}
