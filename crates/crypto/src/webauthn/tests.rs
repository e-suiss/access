#![allow(clippy::arithmetic_side_effects, reason = "test fixtures")]

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256,
};

use super::*;

const N: [u8; 32] = suiss_crypto::sig::P256_N;

fn p256() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, doc.as_ref()).unwrap()
}

fn der(r: &[u8; 32], s: &[u8; 32]) -> Vec<u8> {
    let int = |x: &[u8; 32]| {
        let start = x.iter().position(|b| *b != 0).unwrap_or(31);
        let mut v = x[start..].to_vec();
        if v[0] & 0x80 != 0 {
            v.insert(0, 0);
        }
        let mut out = vec![0x02, u8::try_from(v.len()).unwrap()];
        out.extend(v);
        out
    };
    let body = [int(r), int(s)].concat();
    let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
    out.extend(body);
    out
}

fn sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut borrow = 0_i16;
    for i in (0..32).rev() {
        let mut d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = 0;
        if d < 0 {
            d += 256;
            borrow = 1;
        }
        out[i] = u8::try_from(d).unwrap();
    }
    out
}

// CR-9 m.4
#[test]
fn es256_accepts_both_s_forms() {
    let key = p256();
    let rng = SystemRandom::new();
    let msg = b"authData || clientDataHash";
    let sig = key.sign(&rng, msg).unwrap();
    let pk = key.public_key().as_ref();
    assert!(p256_point_valid(pk));
    verify_es256(pk, msg, sig.as_ref()).unwrap();
    let fixed = ecdsa_der_to_fixed(sig.as_ref()).unwrap();
    let r: [u8; 32] = fixed[..32].try_into().unwrap();
    let s: [u8; 32] = fixed[32..].try_into().unwrap();
    let flipped = der(&r, &sub(&N, &s));
    verify_es256(pk, msg, &flipped).unwrap();
    assert_eq!(
        verify_es256(pk, b"other", sig.as_ref()),
        Err(VerifyError::Signature(SignatureError::Invalid))
    );
}

// CR-9
#[test]
fn es256_rejects_malformed_der() {
    let key = p256();
    let pk = key.public_key().as_ref();
    let one = [1_u8; 32];
    let good = der(&one, &one);
    assert!(ecdsa_der_to_fixed(&good).is_ok());
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(ecdsa_der_to_fixed(&trailing), Err(VerifyError::Der));
    let padded = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
    assert_eq!(ecdsa_der_to_fixed(&padded), Err(VerifyError::Der));
    let negative = [0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01];
    assert_eq!(ecdsa_der_to_fixed(&negative), Err(VerifyError::Der));
    let zero = der(&[0; 32], &one);
    assert_eq!(
        verify_es256(pk, b"m", &zero),
        Err(VerifyError::Signature(SignatureError::ScalarRange))
    );
    assert!(!p256_point_valid(&[4; 65]));
    assert!(!p256_point_valid(&pk[..33]));
}

// CR-9 m.1, CR-53
#[test]
fn ed25519_runs_the_strict_profile() {
    let rng = SystemRandom::new();
    let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let key = Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
    let sig = key.sign(b"m");
    verify_ed25519(key.public_key().as_ref(), b"m", sig.as_ref()).unwrap();
    let mut s_unreduced = sig.as_ref().to_vec();
    s_unreduced[63] |= 0xf0;
    assert!(verify_ed25519(key.public_key().as_ref(), b"m", &s_unreduced).is_err());
    assert_eq!(
        verify_ed25519(&[0; 32], b"m", sig.as_ref()),
        Err(VerifyError::Signature(SignatureError::SmallOrderKey))
    );
}

struct Parts {
    n: Vec<u8>,
    e: Vec<u8>,
}

fn der_take(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let tag = input[0];
    let (len, at) = if input[1] & 0x80 == 0 {
        (usize::from(input[1]), 2)
    } else {
        let k = usize::from(input[1] & 0x7f);
        let mut n = 0_usize;
        for b in &input[2..2 + k] {
            n = n * 256 + usize::from(*b);
        }
        (n, 2 + k)
    };
    (tag, &input[at..at + len], &input[at + len..])
}

pub(super) fn rsa_parts(pkcs1: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (_, seq, _) = der_take(pkcs1);
    let (_, n, rest) = der_take(seq);
    let (_, e, _) = der_take(rest);
    (n.to_vec(), e.to_vec())
}

// CR-9 m.5, §10.2.4
#[test]
fn rs256_verifies_and_bounds_the_key() {
    let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let (n, e) = rsa_parts(key.public_key().as_ref());
    let parts = Parts { n, e };
    let rng = SystemRandom::new();
    let mut sig = vec![0; key.public_modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &rng, b"m", &mut sig).unwrap();
    verify_rs256(&parts.n, &parts.e, b"m", &sig).unwrap();
    assert!(verify_rs256(&parts.n, &parts.e, b"x", &sig).is_err());
    assert_eq!(
        verify_rs256(&parts.n[..128], &parts.e, b"m", &sig),
        Err(VerifyError::RsaKey)
    );
    assert!(!rsa_key_valid(&parts.n, &[2]));
    assert!(!rsa_key_valid(&parts.n, &[1]));
    assert!(rsa_key_valid(&parts.n, &[1, 0, 1]));
}

// TN-97, CR-3 (a)
#[test]
fn decoy_key_is_deterministic() {
    let a = DecoyKey::new(Secret::new([7; 32]));
    let b = DecoyKey::new(Secret::new([8; 32]));
    assert_eq!(a.derive(b"alice").unwrap(), a.derive(b"alice").unwrap());
    assert_ne!(a.derive(b"alice").unwrap(), a.derive(b"bob").unwrap());
    assert_ne!(a.derive(b"alice").unwrap(), b.derive(b"alice").unwrap());
    assert_eq!(
        decoy_label(&[0xab; 16]).len(),
        "access/webauthn-decoy/".len() + 32
    );
    assert_eq!(sha256(b"").len(), 32);
}
