#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;

use super::*;

fn p256() -> (RecipientKey, DecryptKey) {
    let private = agreement::PrivateKey::generate(&ECDH_P256).unwrap();
    let public = private.compute_public_key().unwrap();
    (
        RecipientKey::P256(public.as_ref().to_vec()),
        DecryptKey::P256(private),
    )
}

fn rsa(size: KeySize) -> (RecipientKey, Vec<u8>) {
    let pair = RsaKeyPair::generate(size).unwrap();
    let (n, e) = crate::rsa_id::pkcs1_parts(pair.public_key().as_ref()).unwrap();
    let key = RecipientKey::Rsa { n, e };
    (key, pair.as_der().unwrap().as_ref().to_vec())
}

// CR-4, OP-155 m.3 (k)
#[test]
fn ecdh_es_a256kw_round_trips() {
    let (to, key) = p256();
    let jwe = encrypt(&to, Some("k1"), Some("JWT"), b"payload").unwrap();
    assert_eq!(jwe.split('.').count(), 5);
    let opened = decrypt(&key, &jwe).unwrap();
    assert_eq!(opened.plaintext, b"payload");
    assert_eq!(opened.kid.as_deref(), Some("k1"));
    assert_eq!(opened.cty.as_deref(), Some("JWT"));
    let header = b64url_decode(jwe.split('.').next().unwrap()).unwrap();
    let header = String::from_utf8(header).unwrap();
    assert!(
        header.contains(r#""alg":"ECDH-ES+A256KW","enc":"A256GCM""#),
        "{header}"
    );
}

// CR-4
#[test]
fn rsa_oaep_256_round_trips() {
    let (to, pkcs8) = rsa(KeySize::Rsa2048);
    let jwe = encrypt(&to, None, None, b"userinfo").unwrap();
    let key = DecryptKey::rsa(&pkcs8).unwrap();
    assert_eq!(decrypt(&key, &jwe).unwrap().plaintext, b"userinfo");
    let (_, other) = p256();
    assert_eq!(decrypt(&other, &jwe), Err(JweError::Algorithm));
}

fn forged(header: &str, rest: &str) -> String {
    format!("{}.{rest}", b64url_encode(header.as_bytes()))
}

// CR-4
#[test]
fn rsa1_5_and_unknown_algorithms_are_refused() {
    let (_, pkcs8) = rsa(KeySize::Rsa2048);
    let key = DecryptKey::rsa(&pkcs8).unwrap();
    assert_eq!(KeyAlg::from_name("RSA1_5"), None);
    assert_eq!(KeyAlg::from_name("RSA-OAEP"), None);
    for alg in ["RSA1_5", "RSA-OAEP", "dir", "A256KW", "ECDH-ES"] {
        let jwe = forged(
            &format!(r#"{{"alg":"{alg}","enc":"A256GCM"}}"#),
            "AA.AA.AA.AA",
        );
        assert_eq!(decrypt(&key, &jwe), Err(JweError::Algorithm), "{alg}");
    }
    let cbc = forged(
        r#"{"alg":"RSA-OAEP-256","enc":"A128CBC-HS256"}"#,
        "AA.AA.AA.AA",
    );
    assert_eq!(decrypt(&key, &cbc), Err(JweError::Algorithm));
}

#[test]
fn compression_and_critical_headers_are_refused() {
    let (_, key) = p256();
    for extra in [
        r#","zip":"DEF""#,
        r#","crit":["exp"]"#,
        r#","jku":"https://x""#,
    ] {
        let jwe = forged(
            &format!(r#"{{"alg":"ECDH-ES+A256KW","enc":"A256GCM"{extra}}}"#),
            "AA.AA.AA.AA",
        );
        assert_eq!(decrypt(&key, &jwe), Err(JweError::Header), "{extra}");
    }
}

#[test]
fn tampering_and_the_wrong_key_fail() {
    let (to, key) = p256();
    let jwe = encrypt(&to, None, None, b"secret").unwrap();
    let mut parts: Vec<String> = jwe.split('.').map(String::from).collect();
    let mut body = b64url_decode(&parts[3]).unwrap();
    body[0] ^= 1;
    parts[3] = b64url_encode(&body);
    assert_eq!(decrypt(&key, &parts.join(".")), Err(JweError::Decrypt));
    let (_, other) = p256();
    assert_eq!(decrypt(&other, &jwe), Err(JweError::Decrypt));
    assert_eq!(decrypt(&key, "a.b.c"), Err(JweError::Format));
}

#[test]
fn weak_or_malformed_recipient_keys_are_refused() {
    assert_eq!(
        encrypt(&RecipientKey::P256(vec![4; 10]), None, None, b"x"),
        Err(JweError::Key)
    );
    assert_eq!(
        encrypt(&RecipientKey::P256(vec![0; 65]), None, None, b"x"),
        Err(JweError::Key)
    );
    let (to, _) = p256();
    assert_eq!(
        encrypt(&to, Some("bad\"kid"), None, b"x"),
        Err(JweError::Header)
    );
}
