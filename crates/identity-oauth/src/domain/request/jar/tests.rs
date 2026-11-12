#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use access_kernel::json::b64url_encode;
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair as RsaKeyPair, KeySize};
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256,
};

use super::*;
use crate::domain::jwt::parse_jwks;

const NOW: u64 = 1_800_000_000_000;
const ISS: &str = "https://acme.id.test";

fn rules(rs256: bool) -> JarRules<'static> {
    JarRules {
        client_id: "cli_x",
        issuer: ISS,
        now_ms: NOW,
        rs256,
    }
}

fn input(header: &str, claims: &str) -> String {
    format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(claims.as_bytes())
    )
}

fn es256(k: &EcdsaKeyPair, header: &str, claims: &str) -> String {
    let i = input(header, claims);
    let sig = k.sign(&SystemRandom::new(), i.as_bytes()).unwrap();
    format!("{i}.{}", b64url_encode(sig.as_ref()))
}

fn ec_jwks(k: &EcdsaKeyPair) -> Vec<Jwk> {
    let p = k.public_key().as_ref();
    let doc = format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"k1","x":"{}","y":"{}"}}]}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    );
    parse_jwks(doc.as_bytes()).unwrap()
}

fn claims(extra: &str) -> String {
    format!(
        r#"{{"iss":"cli_x","aud":"{ISS}","client_id":"cli_x","exp":{},"nbf":{},"response_type":"code","redirect_uri":"https://c.example/cb","scope":"openid","max_age":60{extra}}}"#,
        NOW / 1000 + 300,
        NOW / 1000 - 10
    )
}

const H: &str = r#"{"alg":"ES256","kid":"k1","typ":"oauth-authz-req+jwt"}"#;

// RFC 9101 §6, OP-155 m.3 (k)
#[test]
fn signed_request_objects_carry_the_request() {
    let k = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let p = verify(&es256(&k, H, &claims("")), &ec_jwks(&k), &rules(false)).unwrap();
    assert_eq!(p.get("response_type"), Some("code"));
    assert_eq!(p.get("max_age"), Some("60"));
    assert_eq!(p.get("iss"), None);
    let other = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    assert_eq!(
        verify(&es256(&other, H, &claims("")), &ec_jwks(&k), &rules(false)),
        Err(JarError::Signature)
    );
}

// IDI-6, MD-3
#[test]
fn an_algorithm_outside_the_client_allowlist_is_refused() {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
    let (n, e) = access_crypto::rsa_id::pkcs1_parts(pair.public_key().as_ref()).unwrap();
    let doc = format!(
        r#"{{"keys":[{{"kty":"RSA","kid":"r1","n":"{}","e":"{}"}}]}}"#,
        b64url_encode(&n),
        b64url_encode(&e)
    );
    let keys = parse_jwks(doc.as_bytes()).unwrap();
    let i = input(r#"{"alg":"RS256","kid":"r1"}"#, &claims(""));
    let mut sig = vec![0; pair.public_modulus_len()];
    pair.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        i.as_bytes(),
        &mut sig,
    )
    .unwrap();
    let token = format!("{i}.{}", b64url_encode(&sig));
    assert_eq!(
        verify(&token, &keys, &rules(false)),
        Err(JarError::Algorithm)
    );
    assert!(verify(&token, &keys, &rules(true)).is_ok());
    let _ = pair.as_der().unwrap();
    let k = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    for alg in ["none", "HS256", "EdDSA", "PS256"] {
        let token = es256(&k, &format!(r#"{{"alg":"{alg}","kid":"k1"}}"#), &claims(""));
        assert_eq!(
            verify(&token, &ec_jwks(&k), &rules(true)),
            Err(JarError::Algorithm),
            "{alg}"
        );
    }
}

#[test]
fn claims_and_times_are_held() {
    let k = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let keys = ec_jwks(&k);
    let wrong_aud = claims("").replace(ISS, "https://other.test");
    assert_eq!(
        verify(&es256(&k, H, &wrong_aud), &keys, &rules(false)),
        Err(JarError::Claims)
    );
    // OP-155 m.3 (k)
    let among = claims("").replace(
        &format!(r#""aud":"{ISS}""#),
        &format!(r#""aud":["https://other.test","{ISS}"]"#),
    );
    assert!(verify(&es256(&k, H, &among), &keys, &rules(false)).is_ok());
    let mixed = H.replace("oauth-authz-req+jwt", "OAutH-auThZ-REQ+jWt");
    assert!(verify(&es256(&k, &mixed, &claims("")), &keys, &rules(false)).is_ok());
    let without = claims("").replace(
        &format!(r#""aud":"{ISS}""#),
        r#""aud":["https://other.test","invalid"]"#,
    );
    assert_eq!(
        verify(&es256(&k, H, &without), &keys, &rules(false)),
        Err(JarError::Claims)
    );
    let nested = claims(r#","request_uri":"urn:x""#);
    assert_eq!(
        verify(&es256(&k, H, &nested), &keys, &rules(false)),
        Err(JarError::Claims)
    );
    let long = format!(
        r#"{{"iss":"cli_x","aud":"{ISS}","client_id":"cli_x","exp":{},"nbf":{}}}"#,
        NOW / 1000 + 4000,
        NOW / 1000 - 10
    );
    assert_eq!(
        verify(&es256(&k, H, &long), &keys, &rules(false)),
        Err(JarError::Time)
    );
    let no_nbf = format!(
        r#"{{"iss":"cli_x","aud":"{ISS}","client_id":"cli_x","exp":{}}}"#,
        NOW / 1000 + 60
    );
    assert_eq!(
        verify(&es256(&k, H, &no_nbf), &keys, &rules(false)),
        Err(JarError::Time)
    );
}

#[test]
fn outer_parameters_add_nothing() {
    let p = |pairs: &[(&str, &str)]| {
        Params::new(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        )
        .unwrap()
    };
    assert!(outer_ok(&p(&[("client_id", "c"), ("request", "x")])));
    assert!(!outer_ok(&p(&[("request", "x"), ("scope", "openid")])));
}
