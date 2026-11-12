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

// CR-41 m.3, OP-159 m.3 (o)
#[test]
fn akp_keys_are_published_with_alg_and_exact_length() {
    use suiss_crypto::signer::MlDsaSigner;
    for alg in [JwsAlg::MlDsa44, JwsAlg::MlDsa65, JwsAlg::MlDsa87] {
        let (signer, _) = MlDsaSigner::generate(alg.algorithm()).unwrap();
        let key = signer.public_key();
        assert_eq!(JwsAlg::of(&key), Some(alg));
        assert!(alg.post_quantum());
        assert_eq!(JwsAlg::ml_dsa(alg.name()), Some(alg));
        let jwk = public_jwk(&thumbprint(&key), &key).unwrap();
        assert!(jwk.starts_with(r#"{"kty":"AKP","alg":""#), "{jwk}");
        assert!(jwk.contains(&format!(r#""alg":"{}""#, alg.name())));
        assert!(!jwk.contains(r#""priv""#));
        let PublicKey::MlDsa(a, mut short) = key else {
            panic!("ml-dsa");
        };
        short.pop();
        assert_eq!(
            public_jwk(&[1; 32], &PublicKey::MlDsa(a, short)),
            Err(JoseError::Key)
        );
    }
    assert_eq!(JwsAlg::ml_dsa("ES256"), None);
    assert!(!JwsAlg::Es256.post_quantum());
}

// CR-41, L0-SIG-8, OP-159 m.3 (o)
#[test]
fn ml_dsa_tokens_verify_in_the_kernel_only_with_an_ml_dsa_backend() {
    use suiss_crypto::aws::AwsLcBackend;
    use suiss_crypto::signer::MlDsaSigner;
    let (signer, _) = MlDsaSigner::generate(Algorithm::MlDsa65).unwrap();
    let (kid, set) = keys(&signer, JwsAlg::MlDsa65);
    let token = sign_compact(&signer, &kid, "JWT", br#"{"sub":"a"}"#).unwrap();
    assert!(token.len() < 8192, "{}", token.len());
    let v = verify_compact(&AwsLcBackend, &token, &set, "JWT", Origin::Native).unwrap();
    assert_eq!(v.algorithm, Algorithm::MlDsa65);
    assert_eq!(
        verify_compact(&PureBackend, &token, &set, "JWT", Origin::Native).unwrap_err(),
        JwsError::Algorithm
    );
}
