use serde_json::json;

use super::*;

fn map(v: &Json) -> &Map<String, Json> {
    v.as_object().unwrap()
}

fn jwks() -> Json {
    json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "AA", "y": "AA"}]})
}

// OP-155 m.3 (a), (j), IDP-19
#[test]
fn each_body_compiles_to_its_action() {
    let on = FederationChange::put_federation(map(&json!({
        "enabled": true,
        "authority_hints": ["https://ta.example", "https://int.example"],
    })))
    .unwrap();
    assert_eq!(on.action(), IdpAction::FederationEnable);
    assert_eq!(on.check(), Ok(()));
    let off = FederationChange::put_federation(map(&json!({"enabled": false}))).unwrap();
    assert_eq!(off.action(), IdpAction::FederationDisable);
    assert!(
        FederationChange::put_federation(map(
            &json!({"enabled": false, "authority_hints": ["https://x.example"]})
        ))
        .is_err()
    );
    let add = FederationChange::add_anchor(map(&json!({
        "entity_id": "https://ta.example",
        "jwks": jwks(),
    })))
    .unwrap();
    assert_eq!(add.action(), IdpAction::FederationTrustAnchorAdd);
    assert_eq!(add.check(), Ok(()));
    assert_eq!(
        FederationChange::TrustAnchorRemove(String::from("https://ta.example")).action(),
        IdpAction::FederationTrustAnchorRemove
    );
    let ta = FederationChange::put_authority(map(&json!({
        "subordinates": [{"entity_id": "https://rp.example", "jwks": jwks()}],
    })))
    .unwrap();
    assert_eq!(ta.action(), IdpAction::FederationTaEnable);
    assert_eq!(ta.check(), Ok(()));
    assert_eq!(
        FederationChange::put_registration(map(&json!({"open": true})))
            .unwrap()
            .action(),
        IdpAction::FederationRegistrationOpen
    );
    assert_eq!(
        FederationChange::Registration(false).action(),
        IdpAction::FederationRegistrationClose
    );
}

#[test]
fn keys_and_identifiers_are_checked() {
    let private = json!({"keys": [{"kty": "EC", "crv": "P-256", "kid": "k", "d": "AA"}]});
    assert!(!public_jwks(&private));
    assert!(!public_jwks(&json!({"keys": []})));
    assert!(!public_jwks(
        &json!({"keys": [{"kty": "OKP", "crv": "Ed25519", "kid": "k"}]})
    ));
    assert!(public_jwks(&jwks()));
    assert!(entity_id("https://ta.example/fed"));
    assert!(!entity_id("http://ta.example"));
    assert!(!entity_id("https://ta.example/?q=1"));
    assert!(!entity_id("https://"));
    let bad = FederationChange::TrustAnchorAdd {
        entity_id: String::from("https://ta.example"),
        jwks: private.to_string(),
    };
    assert_eq!(bad.check(), Err(Bad));
}
