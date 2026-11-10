use super::*;
use crate::statement::verify_configuration;
use crate::testkit::{Entity, HOUR, NOW, TA, j};

// IDP-19
#[test]
fn a_leaf_configuration_round_trips() {
    let e = Entity::new("https://op.example");
    let metadata = j(r#"{"openid_provider":{"issuer":"https://op.example"}}"#);
    let hints = vec![String::from(TA)];
    let payload = configuration(&Configuration {
        entity_id: "https://op.example",
        iat_ms: NOW,
        exp_ms: NOW.saturating_add(HOUR),
        jwks: &e.key.jwks(),
        authority_hints: &hints,
        metadata: &metadata,
        trust_marks: &[],
        trust_mark_issuers: None,
    })
    .unwrap();
    let ec = e.key.sign(ENTITY_TYP, &payload);
    let s = verify_configuration(&ec, "https://op.example", NOW).unwrap();
    assert_eq!(s.authority_hints, hints);
    assert!(
        s.federation_entity_endpoint("federation_fetch_endpoint")
            .is_none()
    );
    assert!(!payload.contains("trust_marks"));
    assert_eq!(
        configuration(&Configuration {
            entity_id: "https://op.example",
            iat_ms: NOW,
            exp_ms: NOW,
            jwks: &e.key.jwks(),
            authority_hints: &[],
            metadata: &metadata,
            trust_marks: &[],
            trust_mark_issuers: None,
        }),
        Err(BuildError::Time)
    );
}

#[test]
fn answers_are_compact_json() {
    assert_eq!(
        list_response(&[
            String::from("https://a.example"),
            String::from("https://b.example")
        ]),
        r#"["https://a.example","https://b.example"]"#
    );
    let r = resolve_response(
        ("https://ta.example", "https://rp.example"),
        (NOW, NOW.saturating_add(HOUR)),
        &j("{}"),
        &[String::from("x.y.z")],
        &[],
    )
    .unwrap();
    assert!(r.contains(r#""trust_chain":["x.y.z"]"#));
    assert_eq!(
        jwks_json(&[(String::from("k"), vec![4; 10])]),
        Err(BuildError::Key)
    );
}
