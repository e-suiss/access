#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use super::*;

fn message() -> Vec<u8> {
    let mut m = vec![0_u8; 98];
    SystemRandom::new().fill(&mut m).unwrap();
    m
}

// OP-156 m.3 (z), E58
#[test]
fn a_blinded_message_signed_raw_finalizes_to_a_standard_pss_signature() {
    let (key, der) = IssuerKey::generate().unwrap();
    let again = IssuerKey::from_pkcs8(&der).unwrap();
    assert_eq!(again.modulus(), key.modulus());
    let msg = message();
    let b = blind(key.modulus(), &msg).unwrap();
    let sig = key.blind_sign(&b.message).unwrap();
    let out = finalize(key.modulus(), &msg, &b, &sig).unwrap();
    RsaPublicKeyComponents {
        n: key.modulus(),
        e: key.exponent(),
    }
    .verify(&RSA_PSS_2048_8192_SHA384, &msg, &out)
    .unwrap();
    assert!(finalize(key.modulus(), b"another", &b, &sig).is_err());
}

// E58
#[test]
fn two_blindings_of_one_message_differ() {
    let (key, _) = IssuerKey::generate().unwrap();
    let msg = message();
    let a = blind(key.modulus(), &msg).unwrap();
    let b = blind(key.modulus(), &msg).unwrap();
    assert_ne!(a.message, b.message);
}

// RFC 9474 §4.3
#[test]
fn a_message_not_below_the_modulus_is_refused() {
    let (key, _) = IssuerKey::generate().unwrap();
    assert_eq!(key.blind_sign(key.modulus()), Err(BlindError::Input));
    assert_eq!(key.blind_sign(&[0xff; MODULUS_LEN]), Err(BlindError::Input));
    assert_eq!(key.blind_sign(&[1; 255]), Err(BlindError::Input));
}

// RFC 9578 §6.5
#[test]
fn the_token_key_is_the_pss_spki_and_gives_back_its_modulus() {
    let (key, _) = IssuerKey::generate().unwrap();
    let tk = key.token_key();
    assert_eq!(tk.len(), 4 + 0x152);
    assert_eq!(&tk[..4], &[0x30, 0x82, 0x01, 0x52]);
    assert_eq!(token_key_modulus(&tk), Some(key.modulus()));
    let msg = message();
    let b = blind(key.modulus(), &msg).unwrap();
    let sig = finalize(
        key.modulus(),
        &msg,
        &b,
        &key.blind_sign(&b.message).unwrap(),
    )
    .unwrap();
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &RSA_PSS_2048_8192_SHA384,
        token_key_public(&tk).unwrap(),
    )
    .verify(&msg, &sig)
    .unwrap();
    let mut bad = tk.clone();
    bad[10] ^= 1;
    assert_eq!(token_key_modulus(&bad), None);
}

// OP-156 m.3 (z)
#[test]
fn another_key_size_is_refused() {
    let pair = KeyPair::generate(KeySize::Rsa3072).unwrap();
    let der = pair.as_der().unwrap();
    assert_eq!(
        IssuerKey::from_pkcs8(der.as_ref()).err(),
        Some(BlindError::Key)
    );
    assert_eq!(
        IssuerKey::from_pkcs8(b"not a key").err(),
        Some(BlindError::Key)
    );
}
