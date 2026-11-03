use access_kernel::json::b64url_encode;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

use super::*;

const NOW: u64 = 1_800_000_000_000;

fn key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

fn jwks(k: &EcdsaKeyPair, kid: &str) -> String {
    let p = k.public_key().as_ref();
    format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{kid}","use":"sig","x":"{}","y":"{}"}}]}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    )
}

fn jwt(k: &EcdsaKeyPair, header: &str, claims: &str) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(claims.as_bytes())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

fn claims(aud: &str, exp_s: u64, jti: &str) -> String {
    format!(
        r#"{{"iss":"cli_x","sub":"cli_x","aud":"{aud}","exp":{exp_s},"iat":{},"jti":"{jti}"}}"#,
        NOW / 1000
    )
}

const RULES: AssertionRules<'static> = AssertionRules {
    client_id: "cli_x",
    issuer: "https://acme.id.test",
    endpoint: "https://acme.id.test/token",
    now_ms: NOW,
};

// RFC 7523 §3, §10.4.5, IDI-6, MD-3: iss = sub = client, one audience (issuer or endpoint),
// exp required and short, jti required, the algorithm from the allowlist
#[test]
fn client_assertions_follow_the_profile() {
    let k = key();
    let keys = parse_jwks(jwks(&k, "k1").as_bytes()).unwrap();
    let h = r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#;
    let exp = NOW / 1000 + 60;
    let ok = verify_assertion(
        &jwt(&k, h, &claims("https://acme.id.test", exp, "j1")),
        &keys,
        &RULES,
    )
    .unwrap();
    assert_eq!(ok.exp_ms, exp * 1000);
    let ok2 = verify_assertion(
        &jwt(&k, h, &claims("https://acme.id.test/token", exp, "j2")),
        &keys,
        &RULES,
    )
    .unwrap();
    assert_ne!(ok.replay_key, ok2.replay_key);
    let bad = |token: String| verify_assertion(&token, &keys, &RULES).unwrap_err();
    assert_eq!(
        bad(jwt(&k, h, &claims("https://evil.test", exp, "j"))),
        JwtError::Claims
    );
    assert_eq!(
        bad(jwt(
            &k,
            h,
            &claims("https://acme.id.test", NOW / 1000 + 3600, "j")
        )),
        JwtError::Time
    );
    assert_eq!(
        bad(jwt(
            &k,
            h,
            &claims("https://acme.id.test", NOW / 1000 - 120, "j")
        )),
        JwtError::Time
    );
    assert_eq!(
        bad(jwt(
            &k,
            h,
            &format!(r#"{{"iss":"cli_x","sub":"cli_x","aud":"https://acme.id.test","exp":{exp}}}"#)
        )),
        JwtError::Claims
    );
    assert_eq!(
        bad(jwt(
            &k,
            h,
            &format!(
                r#"{{"iss":"cli_y","sub":"cli_x","aud":"https://acme.id.test","exp":{exp},"jti":"j"}}"#
            )
        )),
        JwtError::Claims
    );
    for header in [
        r#"{"alg":"HS256","kid":"k1"}"#,
        r#"{"alg":"none","kid":"k1"}"#,
        r#"{"alg":"EdDSA","kid":"k1"}"#,
    ] {
        assert_eq!(
            bad(jwt(&k, header, &claims("https://acme.id.test", exp, "j"))),
            JwtError::Algorithm
        );
    }
    assert_eq!(
        bad(jwt(
            &k,
            r#"{"alg":"ES256","kid":"k2"}"#,
            &claims("https://acme.id.test", exp, "j")
        )),
        JwtError::Key
    );
    let other = key();
    assert_eq!(
        bad(jwt(&other, h, &claims("https://acme.id.test", exp, "j"))),
        JwtError::Signature
    );
    assert_eq!(
        bad(jwt(
            &k,
            r#"{"alg":"ES256","jku":"https://evil.test"}"#,
            &claims("https://acme.id.test", exp, "j")
        )),
        JwtError::Header
    );
}

// §11.3.1, CR-38: a JWKS with private key material is refused whole; unknown key types are
// skipped
#[test]
fn jwks_with_private_material_are_refused() {
    let doc = r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"AA"}]}"#;
    assert_eq!(parse_jwks(doc.as_bytes()), Err(JwtError::Jwks));
    let doc = r#"{"keys":[{"kty":"oct","k":"AA"}]}"#;
    assert_eq!(parse_jwks(doc.as_bytes()), Err(JwtError::Jwks));
    let doc = r#"{"keys":[{"kty":"XYZ"}]}"#;
    assert_eq!(parse_jwks(doc.as_bytes()), Ok(Vec::new()));
    assert_eq!(parse_jwks(b"{}"), Err(JwtError::Jwks));
}
