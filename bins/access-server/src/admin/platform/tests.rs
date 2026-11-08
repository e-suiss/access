#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_crypto::Secret;
use serde_json::json;

use super::*;

fn ids() -> IdKey {
    IdKey::new(Secret::new([7; 32]))
}

fn body(v: &Value) -> Map<String, Value> {
    v.as_object().unwrap().clone()
}

const SOLE: &str = "AQEBAQEBAQEBAQEBAQEBAQ";
const OTHER: &str = "AgICAgICAgICAgICAgICAg";

// OP-151 m.3 (m)
#[test]
fn the_sandbox_flag_picks_the_template() {
    let k = ids();
    let tenant = k.encode(TENANT_PREFIX, [3; 16]).unwrap();
    let joint =
        json!({ "slug": "shop", "root": { "joint": { "k": 2, "parties": [SOLE, OTHER] } } });
    let prod = change(&k, "createRealm", Some(&tenant), &body(&joint)).unwrap();
    assert!(matches!(prod, PlatformChange::Realm(_)));
    let mut flagged = joint.clone();
    flagged["sandbox"] = json!(true);
    let sandbox = change(&k, "createRealm", Some(&tenant), &body(&flagged)).unwrap();
    assert!(matches!(sandbox, PlatformChange::Sandbox(_)));
    assert!(matches!(
        change(&k, "createSandboxDomain", Some(&tenant), &body(&joint)).unwrap(),
        PlatformChange::Sandbox(_)
    ));
    let mut refused = joint;
    refused["sandbox"] = json!(false);
    assert_eq!(
        change(&k, "createSandboxDomain", Some(&tenant), &body(&refused)).err(),
        Some(&codes::realm::INVALID_BODY)
    );
}

// TN-111
#[test]
fn roots_are_read_strictly() {
    assert!(matches!(
        root(Some(&json!({ "sole": SOLE }))),
        Ok(Root::Sole(_))
    ));
    assert!(matches!(
        root(Some(
            &json!({ "joint": { "k": 2, "parties": [SOLE, OTHER] } })
        )),
        Ok(Root::Joint { k: 2, .. })
    ));
    for bad in [
        json!({ "joint": { "k": 2, "parties": [SOLE, SOLE] } }),
        json!({ "sole": SOLE, "joint": { "k": 2, "parties": [SOLE, OTHER] } }),
        json!({ "sole": "short" }),
        json!({ "joint": { "k": 2, "parties": [SOLE, OTHER], "extra": 1 } }),
        json!("sole"),
    ] {
        assert_eq!(
            root(Some(&bad)).err(),
            Some(&codes::platform::INVALID_ROOT),
            "{bad}"
        );
    }
    assert_eq!(root(None).err(), Some(&codes::platform::INVALID_ROOT));
}

// TN-112
#[test]
fn unknown_members_and_foreign_tenant_ids_are_refused() {
    let k = ids();
    let tenant = k.encode(TENANT_PREFIX, [3; 16]).unwrap();
    let extra = json!({ "slug": "shop", "root": { "sole": SOLE }, "owner_email": "x@y.example" });
    assert_eq!(
        change(&k, "createRealm", Some(&tenant), &body(&extra)).err(),
        Some(&codes::realm::INVALID_BODY)
    );
    let ok = json!({ "slug": "shop", "root": { "sole": SOLE } });
    assert_eq!(
        change(&k, "createRealm", Some("tnt_forged"), &body(&ok)).err(),
        Some(&codes::NOT_FOUND)
    );
    assert_eq!(
        change(&k, "createTenant", None, &body(&json!({}))).err(),
        Some(&codes::realm::INVALID_BODY)
    );
}

// CR-25
#[test]
fn signing_is_available_one_publish_lead_after_creation() {
    assert_eq!(signing_available_ms(1_000), 1_000 + 90 * 60_000);
}
