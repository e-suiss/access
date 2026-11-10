use super::*;
use crate::testkit::{Entity, HOUR, Key, LEAF, NOW, j, rp_metadata};

fn payload(extra: &str) -> String {
    format!(
        r#"{{"iss":"{LEAF}","sub":"{LEAF}","iat":{},"exp":{}{extra}}}"#,
        NOW / 1000,
        NOW.saturating_add(HOUR) / 1000
    )
}

fn with_jwks(key: &Key, extra: &str) -> String {
    let jwks = access_crypto::jose::output::to_string(&key.jwks());
    payload(&format!(r#","jwks":{jwks}{extra}"#))
}

// IDP-19, OP-155 m.3 (j)
#[test]
fn a_self_signed_configuration_verifies() {
    let leaf = Entity::new(LEAF);
    let ec = leaf.config(&["https://int.example"], &rp_metadata(), &[]);
    let s = verify_configuration(&ec, LEAF, NOW).unwrap();
    assert!(s.is_configuration());
    assert_eq!(s.authority_hints, vec![String::from("https://int.example")]);
    assert!(s.metadata_of("openid_relying_party").is_some());
    assert_eq!(peek(&ec).unwrap(), (String::from(LEAF), String::from(LEAF)));
    assert_eq!(
        configuration_url("https://rp.example/"),
        "https://rp.example/.well-known/openid-federation"
    );
    assert_eq!(
        verify_configuration(&ec, "https://other.example", NOW),
        Err(OidfError::Claims)
    );
}

// IDP-19, MD-3
#[test]
fn the_header_profile_is_enforced() {
    let k = Key::new("k1");
    let body = with_jwks(&k, "");
    let keys = k.keys();
    let wrong_typ = k.sign("JWT", &body);
    assert_eq!(
        verify_statement(&wrong_typ, &keys, NOW),
        Err(OidfError::Typ)
    );
    let none = k.sign_header(
        r#"{"alg":"none","kid":"k1","typ":"entity-statement+jwt"}"#,
        &body,
    );
    assert_eq!(
        verify_statement(&none, &keys, NOW),
        Err(OidfError::Algorithm)
    );
    let eddsa = k.sign_header(
        r#"{"alg":"EdDSA","kid":"k1","typ":"entity-statement+jwt"}"#,
        &body,
    );
    assert_eq!(
        verify_statement(&eddsa, &keys, NOW),
        Err(OidfError::Algorithm)
    );
    let ed = k.sign_header(
        r#"{"alg":"Ed25519","kid":"k1","typ":"entity-statement+jwt"}"#,
        &body,
    );
    assert_eq!(verify_statement(&ed, &keys, NOW), Err(OidfError::Algorithm));
    let no_kid = k.sign_header(r#"{"alg":"ES256","typ":"entity-statement+jwt"}"#, &body);
    assert_eq!(verify_statement(&no_kid, &keys, NOW), Err(OidfError::Key));
    let jku = k.sign_header(
        r#"{"alg":"ES256","kid":"k1","typ":"entity-statement+jwt","jku":"https://x.example"}"#,
        &body,
    );
    assert_eq!(verify_statement(&jku, &keys, NOW), Err(OidfError::Header));
    let other = Key::new("k1");
    let forged = other.sign(ENTITY_TYP, &body);
    assert_eq!(
        verify_statement(&forged, &keys, NOW),
        Err(OidfError::Signature)
    );
    assert_eq!(verify_statement("a.b", &keys, NOW), Err(OidfError::Format));
}

// IDP-19
#[test]
fn time_claims_use_a_sixty_second_skew() {
    let k = Key::new("k1");
    let ec = k.sign(ENTITY_TYP, &with_jwks(&k, ""));
    let keys = k.keys();
    assert!(verify_statement(&ec, &keys, NOW.saturating_add(HOUR).saturating_add(59_000)).is_ok());
    assert_eq!(
        verify_statement(&ec, &keys, NOW.saturating_add(HOUR).saturating_add(SKEW_MS)),
        Err(OidfError::Time)
    );
    assert_eq!(
        verify_statement(&ec, &keys, NOW.saturating_sub(SKEW_MS).saturating_sub(1000)),
        Err(OidfError::Time)
    );
}

// IDP-19
#[test]
fn crit_and_claim_placement_fail_closed() {
    let k = Key::new("k1");
    let keys = k.keys();
    let refused = |extra: &str| {
        let ec = k.sign(ENTITY_TYP, &with_jwks(&k, extra));
        verify_statement(&ec, &keys, NOW).unwrap_err()
    };
    assert_eq!(refused(r#","crit":["x"],"x":1"#), OidfError::Crit);
    assert_eq!(
        refused(r#","metadata_policy_crit":["regexp"]"#),
        OidfError::Crit
    );
    assert_eq!(
        refused(r#","metadata":{"openid_relying_party":1}"#),
        OidfError::Claims
    );
    assert_eq!(
        refused(r#","metadata_policy":{"openid_relying_party":{}}"#),
        OidfError::Claims
    );
    assert_eq!(refused(r#","authority_hints":[]"#), OidfError::Claims);
    assert_eq!(
        refused(r#","authority_hints":["http://int.example"]"#),
        OidfError::Claims
    );
    let no_jwks = k.sign(ENTITY_TYP, &payload(""));
    assert_eq!(verify_statement(&no_jwks, &keys, NOW), Err(OidfError::Jwks));
    let sub = format!(
        r#"{{"iss":"https://int.example","sub":"{LEAF}","iat":{},"exp":{},"jwks":{},"authority_hints":["https://ta.example"]}}"#,
        NOW / 1000,
        NOW.saturating_add(HOUR) / 1000,
        access_crypto::jose::output::to_string(&k.jwks())
    );
    assert_eq!(
        verify_statement(&k.sign(ENTITY_TYP, &sub), &keys, NOW),
        Err(OidfError::Claims)
    );
    let naming = sub.replace(
        r#""authority_hints":["https://ta.example"]"#,
        r#""constraints":{"naming_constraints":{"permitted":[]}}"#,
    );
    assert_eq!(
        verify_statement(&k.sign(ENTITY_TYP, &naming), &keys, NOW),
        Err(OidfError::Constraints)
    );
    let query = with_jwks(&k, "").replace(
        &format!(r#""sub":"{LEAF}""#),
        r#""sub":"https://rp.example/?a=b""#,
    );
    assert_eq!(
        verify_statement(&k.sign(ENTITY_TYP, &query), &keys, NOW),
        Err(OidfError::EntityId)
    );
}

#[test]
fn private_key_material_refuses_the_whole_set() {
    let set = j(r#"{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA","d":"AA"}]}"#);
    assert_eq!(parse_jwks(&set), Err(OidfError::Jwks));
    let skipped = j(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"AA"},{"kty":"EC","crv":"P-256","x":"AA","y":"AA","use":"enc"}]}"#,
    );
    assert_eq!(parse_jwks(&skipped), Ok(Vec::new()));
    assert_eq!(parse_jwks(&j("{}")), Err(OidfError::Jwks));
    assert_eq!(OidfError::Crit.code(), "oidf-crit");
}
