#![allow(clippy::unwrap_used, reason = "test code")]

use access_crypto::oauth::ClientKey;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::json;

use super::*;
use crate::domain::preset::Presets;

const T0: u64 = 1_800_000_000_000;

fn preset() -> Preset {
    let mut p = Presets::shipped().unwrap().get("google").unwrap().clone();
    p.algorithms = vec!["ES256".into()];
    p
}

fn key() -> (EcdsaKeyPair, Jwk) {
    let k = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let jwk = Jwk {
        kid: Some("k1".into()),
        key: ClientKey::P256(k.public_key().as_ref().to_vec()),
    };
    (k, jwk)
}

fn sign(k: &EcdsaKeyPair, header: &Value, claims: &Value) -> String {
    let input = format!(
        "{}.{}",
        b64url_encode(&serde_json::to_vec(header).unwrap()),
        b64url_encode(&serde_json::to_vec(claims).unwrap())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

fn claims() -> Value {
    json!({
        "iss": "https://accounts.google.com",
        "aud": "client-1",
        "sub": "1234",
        "exp": T0 / 1000 + 600,
        "iat": T0 / 1000,
        "nonce": "n-1",
        "email": "ada@gmail.com",
        "email_verified": true,
    })
}

const EXPECT: Expect<'static> = Expect {
    client_id: "client-1",
    nonce: "n-1",
    now_ms: T0,
};

fn header() -> Value {
    json!({ "alg": "ES256", "kid": "k1" })
}

// §10.2.6, OP-153 m.3 (l)
#[test]
fn a_well_formed_id_token_is_accepted() {
    let (k, jwk) = key();
    let t = sign(&k, &header(), &claims());
    let c = check_id_token(&t, &preset(), &[jwk], &EXPECT).unwrap();
    assert_eq!(subject_of(&preset(), &c).unwrap(), "1234");
}

// §10.2.6
#[test]
fn a_wrong_audience_or_nonce_is_refused() {
    let (k, jwk) = key();
    let keys = [jwk];
    let mut c = claims();
    c["aud"] = json!("someone-else");
    let t = sign(&k, &header(), &c);
    assert_eq!(
        check_id_token(&t, &preset(), &keys, &EXPECT),
        Err(TokenError::Audience)
    );
    let mut c = claims();
    c["aud"] = json!(["client-1", "other"]);
    let t = sign(&k, &header(), &c);
    assert_eq!(
        check_id_token(&t, &preset(), &keys, &EXPECT),
        Err(TokenError::Audience),
        "several audiences need azp"
    );
    c["azp"] = json!("client-1");
    let t = sign(&k, &header(), &c);
    assert!(check_id_token(&t, &preset(), &keys, &EXPECT).is_ok());
    let mut c = claims();
    c["nonce"] = json!("n-2");
    let t = sign(&k, &header(), &c);
    assert_eq!(
        check_id_token(&t, &preset(), &keys, &EXPECT),
        Err(TokenError::Nonce)
    );
    let mut c = claims();
    c.as_object_mut().unwrap().remove("nonce");
    let t = sign(&k, &header(), &c);
    assert_eq!(
        check_id_token(&t, &preset(), &keys, &EXPECT),
        Err(TokenError::Nonce)
    );
}

// §10.2.6, MD-3
#[test]
fn issuer_time_algorithm_and_key_are_checked() {
    let (k, jwk) = key();
    let keys = [jwk];
    let mut c = claims();
    c["iss"] = json!("https://evil.example");
    assert_eq!(
        check_id_token(&sign(&k, &header(), &c), &preset(), &keys, &EXPECT),
        Err(TokenError::Issuer)
    );
    let mut c = claims();
    c["exp"] = json!(T0 / 1000 - 120);
    assert_eq!(
        check_id_token(&sign(&k, &header(), &c), &preset(), &keys, &EXPECT),
        Err(TokenError::Time)
    );
    let none = json!({ "alg": "none", "kid": "k1" });
    assert_eq!(
        check_id_token(&sign(&k, &none, &claims()), &preset(), &keys, &EXPECT),
        Err(TokenError::Algorithm)
    );
    let rs = json!({ "alg": "RS256", "kid": "k1" });
    assert_eq!(
        check_id_token(&sign(&k, &rs, &claims()), &preset(), &keys, &EXPECT),
        Err(TokenError::Algorithm),
        "the preset names the algorithm, not the header"
    );
    let (other, _) = key();
    assert_eq!(
        check_id_token(
            &sign(&other, &header(), &claims()),
            &preset(),
            &keys,
            &EXPECT
        ),
        Err(TokenError::Signature)
    );
}

// IDP-31 (3), OP-153 m.3 (l)
#[test]
fn email_assurance_follows_the_preset() {
    let p = Presets::shipped().unwrap();
    let google = p.get("google").unwrap();
    let e = email_of(google, &claims(), None).unwrap();
    assert!(e.vouched);
    let workspace =
        json!({ "email": "ada@acme.example", "email_verified": true, "hd": "acme.example" });
    assert!(email_of(google, &workspace, None).unwrap().vouched);
    let foreign = json!({ "email": "ada@acme.example", "email_verified": true });
    assert!(
        !email_of(google, &foreign, None).unwrap().vouched,
        "outside its domains Google does not vouch"
    );
    let ms = p.get("microsoft").unwrap();
    assert!(
        !email_of(ms, &json!({ "email": "a@b.example" }), None)
            .unwrap()
            .vouched
    );
    assert!(
        email_of(
            ms,
            &json!({ "email": "a@b.example", "xms_edov": true }),
            None
        )
        .unwrap()
        .vouched
    );
    let fb = p.get("facebook").unwrap();
    assert!(
        !email_of(
            fb,
            &json!({ "email": "a@b.example", "email_verified": true }),
            None
        )
        .unwrap()
        .vouched
    );
    let gh = p.get("github").unwrap();
    let list = json!([
        { "email": "old@b.example", "primary": false, "verified": true },
        { "email": "a@b.example", "primary": true, "verified": true },
    ]);
    let e = email_of(gh, &json!({}), Some(&list)).unwrap();
    assert_eq!(e.address, "a@b.example");
    assert!(e.vouched);
    let unverified = json!([{ "email": "a@b.example", "primary": true, "verified": false }]);
    assert!(!email_of(gh, &json!({}), Some(&unverified)).unwrap().vouched);
    assert_eq!(subject_of(gh, &json!({ "id": 583_231 })).unwrap(), "583231");
    assert_eq!(
        subject_of(ms, &json!({ "tid": "t", "oid": "o", "sub": "pairwise" })).unwrap(),
        "t:o"
    );
}

// RFC 7636, OP-153 m.3 (l)
#[test]
fn the_authorization_request_carries_pkce_state_and_nonce() {
    let p = Presets::shipped().unwrap();
    let mut r = [0_u8; 96];
    for (i, b) in r.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    let s = Secrets::from_random(&r);
    let u = authorization_url(
        p.get("google").unwrap(),
        "c",
        "https://acme.example/v1/login/social/google/callback",
        &s,
    );
    assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?response_type=code&"));
    assert!(u.contains("&code_challenge_method=S256"));
    assert!(u.contains(&format!("&state={}", s.state)));
    assert!(u.contains(&format!("&nonce={}", s.nonce)));
    assert!(!u.contains(&s.verifier));
    let gh = authorization_url(p.get("github").unwrap(), "c", "https://x.example/cb", &s);
    assert!(!gh.contains("nonce="));
    let apple = authorization_url(p.get("apple").unwrap(), "c", "https://x.example/cb", &s);
    assert!(apple.ends_with("&response_mode=form_post"));
    assert_eq!(
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert!(format!("{s:?}").contains("redacted"));
}

// TN-90, Ek B 3611
#[test]
fn an_upstream_asserts_only_the_verified_addresss_hosted_domain() {
    let p = Presets::shipped().unwrap();
    let google = p.get("google").unwrap();
    let workspace =
        json!({ "email": "ada@acme.example", "email_verified": true, "hd": "Acme.Example" });
    assert_eq!(
        asserted_domain(google, &workspace),
        Some((String::from("acme.example"), None))
    );
    let unverified = json!({ "email": "ada@acme.example", "hd": "acme.example" });
    assert_eq!(asserted_domain(google, &unverified), None);
    let elsewhere =
        json!({ "email": "ada@other.example", "email_verified": true, "hd": "acme.example" });
    assert_eq!(asserted_domain(google, &elsewhere), None);
    assert_eq!(asserted_domain(google, &claims()), None);
    let ms = p.get("microsoft").unwrap();
    let tenant = json!({ "email": "a@acme.example", "email_verified": true, "tid": "t-1" });
    assert_eq!(asserted_domain(ms, &tenant), None);
}
