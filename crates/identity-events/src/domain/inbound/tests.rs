use access_identity_oauth::domain::jwt::parse_jwks;
use access_kernel::json::b64url_encode;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

use super::*;
use crate::domain::mapping::signal_uri;

const NOW: u64 = 1_800_000_000_000;
const ISS: &str = "https://idp.example";

fn key() -> EcdsaKeyPair {
    EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap()
}

fn keys(k: &EcdsaKeyPair) -> Vec<Jwk> {
    let p = k.public_key().as_ref();
    let doc = format!(
        r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","x":"{}","y":"{}"}}]}}"#,
        b64url_encode(&p[1..33]),
        b64url_encode(&p[33..])
    );
    parse_jwks(doc.as_bytes()).unwrap()
}

fn sign(k: &EcdsaKeyPair, header: &str, claims: &str) -> Vec<u8> {
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(claims.as_bytes())
    );
    let sig = k.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref())).into_bytes()
}

const HEADER: &str = r#"{"alg":"ES256","kid":"k1","typ":"secevent+jwt"}"#;

fn set(kind: SignalKind, iat_s: u64, aud: &str, events: usize) -> String {
    let uri = signal_uri(kind);
    let mut ev = format!(r#""{uri}":{{"event_timestamp":{iat_s},"current_level":"LOW"}}"#);
    if events == 2 {
        ev = format!(
            r#"{ev},"{}":{{}}"#,
            signal_uri(SignalKind::SessionPresented)
        );
    }
    format!(
        r#"{{"iss":"{ISS}","aud":"{aud}","iat":{iat_s},"jti":"j-1","sub_id":{{"format":"iss_sub","iss":"{ISS}","sub":"u-1"}},"events":{{{ev}}}}}"#
    )
}

fn declared() -> Vec<String> {
    SignalKind::ALL.into_iter().map(signal_uri).collect()
}

fn expect(events: &[String]) -> Expect<'_> {
    Expect {
        issuer: ISS,
        audience: "https://access.example/realms/shop",
        events,
        now_ms: NOW,
    }
}

// TN-42, OP-151 m.3 (l), RFC 8935 §2.3
#[test]
fn inbound_sets_are_checked() {
    let k = key();
    let ks = keys(&k);
    let ev = declared();
    let e = expect(&ev);
    let aud = e.audience;
    let ok = verify(
        &sign(
            &k,
            HEADER,
            &set(SignalKind::SessionRevoked, NOW / 1000, aud, 1),
        ),
        &ks,
        &e,
    )
    .unwrap();
    assert_eq!(ok.kind, SignalKind::SessionRevoked);
    assert_eq!(ok.subject, Some((String::from(ISS), String::from("u-1"))));
    let refused =
        |token: Vec<u8>, keys: &[Jwk], e: &Expect<'_>| verify(&token, keys, e).unwrap_err();
    let stale = NOW / 1000 - 301;
    assert_eq!(
        refused(
            sign(&k, HEADER, &set(SignalKind::SessionRevoked, stale, aud, 1)),
            &ks,
            &e
        ),
        Reject::Request
    );
    assert_eq!(
        refused(
            sign(
                &k,
                HEADER,
                &set(SignalKind::SessionRevoked, NOW / 1000, "other", 1)
            ),
            &ks,
            &e
        ),
        Reject::Audience
    );
    assert_eq!(
        refused(
            sign(
                &k,
                HEADER,
                &set(SignalKind::SessionRevoked, NOW / 1000, aud, 2)
            ),
            &ks,
            &e
        ),
        Reject::Request
    );
    assert_eq!(
        refused(
            sign(
                &key(),
                HEADER,
                &set(SignalKind::SessionRevoked, NOW / 1000, aud, 1)
            ),
            &ks,
            &e
        ),
        Reject::Key
    );
    let jwt = r#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#;
    assert_eq!(
        refused(
            sign(
                &k,
                jwt,
                &set(SignalKind::SessionRevoked, NOW / 1000, aud, 1)
            ),
            &ks,
            &e
        ),
        Reject::Request
    );
    let none = r#"{"alg":"none","typ":"secevent+jwt"}"#;
    assert_eq!(
        refused(
            sign(
                &k,
                none,
                &set(SignalKind::SessionRevoked, NOW / 1000, aud, 1)
            ),
            &ks,
            &e
        ),
        Reject::Key
    );
}

// TN-42, RFC 8935 §2.3
#[test]
fn inbound_sets_name_their_transmitter_and_types() {
    let k = key();
    let ks = keys(&k);
    let ev = declared();
    let aud = expect(&ev).audience;
    let refused =
        |token: Vec<u8>, keys: &[Jwk], e: &Expect<'_>| verify(&token, keys, e).unwrap_err();
    let only = vec![signal_uri(SignalKind::CredentialChange)];
    assert_eq!(
        refused(
            sign(
                &k,
                HEADER,
                &set(SignalKind::SessionRevoked, NOW / 1000, aud, 1)
            ),
            &ks,
            &expect(&only)
        ),
        Reject::Denied
    );
    let mut other = expect(&ev);
    other.issuer = "https://elsewhere.example";
    assert_eq!(
        refused(
            sign(
                &k,
                HEADER,
                &set(SignalKind::SessionRevoked, NOW / 1000, aud, 1)
            ),
            &ks,
            &other
        ),
        Reject::Issuer
    );
    assert_eq!(Reject::Key.body()["err"], "invalid_key");
}

// §9.16.2 k.4, TN-42, PI-9, CI-2
#[test]
fn inbound_events_only_narrow_and_never_revoke_a_grant() {
    // EI-19
    let body = |s: &str| json::parse(s.as_bytes(), 1024).unwrap();
    for kind in SignalKind::ALL {
        let e = effect(kind, &body("{}"));
        assert!(matches!(
            e,
            Effect::EndSessions | Effect::Risk(_) | Effect::Suspended | Effect::None
        ));
    }
    assert_eq!(
        effect(SignalKind::SessionRevoked, &body("{}")),
        Effect::EndSessions
    );
    assert_eq!(
        effect(
            SignalKind::RiskLevelChange,
            &body(r#"{"current_level":"LOW"}"#)
        ),
        Effect::None
    );
    assert_eq!(
        effect(
            SignalKind::RiskLevelChange,
            &body(r#"{"current_level":"HIGH"}"#)
        ),
        Effect::Risk("ssf.risk-level-change")
    );
    assert_eq!(
        effect(
            SignalKind::DeviceComplianceChange,
            &body(r#"{"current_status":"compliant"}"#)
        ),
        Effect::None
    );
    assert_eq!(
        effect(SignalKind::AccountDisabled, &body("{}")),
        Effect::Suspended
    );
}

// §8.13, L18
#[test]
fn delay_is_declared() {
    assert_eq!(delayed_since(Some(1_000), 0, 60, 60_000), None);
    assert_eq!(delayed_since(Some(1_000), 0, 60, 61_001), Some(61_000));
    assert_eq!(delayed_since(None, 5_000, 60, 70_000), Some(65_000));
    let n = delay_notice("Okta", 14 * 3_600_000 + 2 * 60_000);
    assert_eq!(
        n,
        "Signals from Okta delayed since 14:02 UTC — decisions use declared validity windows"
    );
}

// TN-42
#[test]
fn transmitter_declarations_are_checked() {
    let ok = serde_json::json!({
        "issuer": ISS,
        "jwks_uri": "https://idp.example/jwks",
        "aud": "https://access.example/realms/shop",
        "events": [signal_uri(SignalKind::SessionRevoked)],
    });
    let c = TransmitterConfig::parse(&ok).unwrap();
    assert_eq!(c.expected_interval_s, DEFAULT_INTERVAL_S);
    for bad in [
        serde_json::json!({"issuer": "http://idp.example", "jwks_uri": "https://a.example/j", "aud": "x", "events": [signal_uri(SignalKind::SessionRevoked)]}),
        serde_json::json!({"issuer": ISS, "jwks_uri": "https://a.example/j", "aud": "x", "events": ["urn:other"]}),
        serde_json::json!({"issuer": ISS, "jwks_uri": "https://a.example/j", "aud": "x", "events": []}),
        serde_json::json!({"issuer": ISS, "jwks_uri": "https://a.example/j", "aud": "x", "events": [signal_uri(SignalKind::SessionRevoked)], "expected_interval_s": 1}),
    ] {
        assert!(TransmitterConfig::parse(&bad).is_err());
    }
    assert_ne!(subject_digest(ISS, "a"), subject_digest(ISS, "b"));
}
