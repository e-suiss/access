use access_kernel::json::b64url_decode;
use access_kernel::verify::cose::KeySet;
use access_kernel::verify::jws::{JwsError, Origin, verify_compact};
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::sig::PureBackend;
use suiss_crypto::signer::SoftSigner;

use super::*;

fn keys(signer: &dyn Signer, alg: JwsAlg) -> ([u8; 32], KeySet) {
    let key = signer.public_key();
    let kid = thumbprint(&key);
    let mut set = KeySet::default();
    set.insert(kid, key).unwrap();
    set.allowed.insert(alg.algorithm());
    (kid, set)
}

// CR-5, CR-9, CR-55 m.8
#[test]
fn signed_tokens_verify_in_the_kernel() {
    let (p256, _) = SoftSigner::generate_p256().unwrap();
    let (ed, _) = SoftSigner::generate_ed25519().unwrap();
    for (signer, alg) in [(&p256, JwsAlg::Es256), (&ed, JwsAlg::Ed25519)] {
        let (kid, set) = keys(signer, alg);
        for _ in 0..32 {
            let token = sign_compact(signer, &kid, "at+jwt", br#"{"sub":"a"}"#).unwrap();
            let v = verify_compact(&PureBackend, &token, &set, "at+jwt", Origin::Native).unwrap();
            assert_eq!(v.algorithm, alg.algorithm());
            assert_eq!(v.kid, kid);
            assert_eq!(v.payload, br#"{"sub":"a"}"#);
        }
    }
}

// CR-5
#[test]
fn the_header_is_alg_kid_typ() {
    let (ed, _) = SoftSigner::generate_ed25519().unwrap();
    let token = sign_compact(&ed, &[1; 32], "JWT", b"{}").unwrap();
    let header = token.split('.').next().unwrap();
    let header = String::from_utf8(b64url_decode(header).unwrap()).unwrap();
    assert_eq!(
        header,
        format!(
            r#"{{"alg":"Ed25519","kid":"{}","typ":"JWT"}}"#,
            b64url_encode(&[1; 32])
        )
    );
    assert!(!token.contains("EdDSA"));
}

// CR-56 row 16
#[test]
fn another_typ_is_rejected() {
    let (p256, _) = SoftSigner::generate_p256().unwrap();
    let (kid, set) = keys(&p256, JwsAlg::Es256);
    let token = sign_compact(&p256, &kid, "logout+jwt", b"{}").unwrap();
    assert_eq!(
        verify_compact(&PureBackend, &token, &set, "at+jwt", Origin::Native),
        Err(JwsError::Type)
    );
}

// OP-117 m.14
#[test]
fn bad_typ_and_payload_are_refused() {
    let (ed, _) = SoftSigner::generate_ed25519().unwrap();
    for typ in ["", r#"JWT","alg":"none"#, "a b", &"x".repeat(65)] {
        assert_eq!(
            sign_compact(&ed, &[1; 32], typ, b"{}"),
            Err(JoseError::Type)
        );
    }
    for payload in [&b"[]"[..], b"\"s\"", b"{", b"{\"a\":1,\"a\":2}"] {
        assert_eq!(
            sign_compact(&ed, &[1; 32], "JWT", payload),
            Err(JoseError::Payload)
        );
    }
}

// CR-24, RFC 7638
#[test]
fn public_jwks_name_their_key() {
    let (p256, _) = SoftSigner::generate_p256().unwrap();
    let key = p256.public_key();
    let jwk = public_jwk(&thumbprint(&key), &key).unwrap();
    let Json::Object(members) = json::parse(jwk.as_bytes(), 4096).unwrap() else {
        panic!("not an object");
    };
    let get = |n: &str| {
        members
            .iter()
            .find(|(k, _)| k == n)
            .and_then(|(_, v)| v.as_str())
            .unwrap()
            .to_owned()
    };
    assert_eq!(get("kty"), "EC");
    assert_eq!(get("crv"), "P-256");
    assert_eq!(get("alg"), "ES256");
    assert_eq!(get("use"), "sig");
    assert_eq!(get("kid"), b64url_encode(&thumbprint(&key)));
    let PublicKey::P256(sec1) = &key else {
        panic!("not P-256");
    };
    let mut xy = b64url_decode(&get("x")).unwrap();
    xy.extend(b64url_decode(&get("y")).unwrap());
    assert_eq!(&sec1[1..], &xy[..]);

    let (ed, _) = SoftSigner::generate_ed25519().unwrap();
    let key = ed.public_key();
    let jwk = public_jwk(&thumbprint(&key), &key).unwrap();
    assert!(jwk.contains(r#""kty":"OKP","crv":"Ed25519""#));
    assert!(jwk.contains(r#""alg":"Ed25519""#));
}

// MD-3, CR-6
#[test]
fn akp_keys_are_not_published() {
    let key = PublicKey::MlDsa(Algorithm::MlDsa65, vec![0; 1952]);
    assert_eq!(public_jwk(&[0; 32], &key), Err(JoseError::Key));
    assert_eq!(JwsAlg::of(&key), None);
}
