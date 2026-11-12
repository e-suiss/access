use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::verify::PureBackend;

const CT: &str = "application/access-receipt+cbor";

struct Marker;

impl Backend for Marker {
    fn ed25519(&self, _: &[u8; 32], _: &[u8], _: &[u8; 64]) -> bool {
        false
    }

    fn p256(&self, _: &[u8], _: &[u8], _: &[u8; 64]) -> bool {
        false
    }

    fn ml_dsa(&self, _: Algorithm, _: &[u8], _: &[u8], signature: &[u8]) -> bool {
        signature.first() == Some(&1)
    }

    fn supports(&self, _: Algorithm) -> bool {
        true
    }
}

fn sign1(alg: Algorithm, sig: &[u8]) -> Vec<u8> {
    let protected = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(alg.cose())),
            (Value::Unsigned(CONTENT_TYPE), Value::text(CT)),
            (Value::Unsigned(KID), Value::Bytes(vec![3; 32])),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let body = Value::Array(vec![
        Value::Bytes(protected),
        Value::Map(vec![]),
        Value::Bytes(b"payload".to_vec()),
        Value::Bytes(sig.to_vec()),
    ]);
    [vec![0xd2], dcbor::encode(&body, Limits::CEILING).unwrap()].concat()
}

fn keys(alg: Algorithm, len: usize) -> KeySet {
    let mut k = KeySet::default();
    k.keys
        .insert([3; 32], PublicKey::MlDsa(alg, vec![0x5a; len]));
    k.allowed.insert(alg);
    k
}

// L0-SIG-8, OP-159 m.3 (c)
#[test]
fn a_backend_without_ml_dsa_denies_every_ml_dsa_signature() {
    for (alg, k, s) in [
        (Algorithm::MlDsa44, 1312, 2420),
        (Algorithm::MlDsa65, 1952, 3309),
        (Algorithm::MlDsa87, 2592, 4627),
    ] {
        let mut sig = vec![0; s];
        sig[0] = 1;
        let bytes = sign1(alg, &sig);
        assert_eq!(
            verify_sign1(&PureBackend, &bytes, &keys(alg, k), CT).map(|_| ()),
            Err(CoseError::Algorithm)
        );
        assert!(verify_sign1(&Marker, &bytes, &keys(alg, k), CT).is_ok());
        assert_eq!(algorithm_of(&bytes), Ok(alg));
        assert_eq!(key_length(alg), Some(k));
        assert_eq!(signature_length(alg), Some(s));
    }
}

// L0-SIG-8
#[test]
fn lengths_are_checked_before_the_backend() {
    let mut sig = vec![0; 3309];
    sig[0] = 1;
    let ks = keys(Algorithm::MlDsa65, 1952);
    assert!(verify_sign1(&Marker, &sign1(Algorithm::MlDsa65, &sig), &ks, CT).is_ok());
    sig.push(0);
    assert_eq!(
        verify_sign1(&Marker, &sign1(Algorithm::MlDsa65, &sig), &ks, CT).map(|_| ()),
        Err(CoseError::Signature(SignatureError::Length))
    );
    sig.truncate(3309);
    assert_eq!(
        verify_sign1(
            &Marker,
            &sign1(Algorithm::MlDsa65, &sig),
            &keys(Algorithm::MlDsa65, 1951),
            CT
        )
        .map(|_| ()),
        Err(CoseError::Signature(SignatureError::Length))
    );
    sig[0] = 0;
    assert_eq!(
        verify_sign1(&Marker, &sign1(Algorithm::MlDsa65, &sig), &ks, CT).map(|_| ()),
        Err(CoseError::Signature(SignatureError::Invalid))
    );
    assert_eq!(
        signature(&Marker, Algorithm::Ed25519, &[], &[], &[]),
        Err(SignatureError::Invalid)
    );
}
