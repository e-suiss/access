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

// OP-159 m.47 (c), TN-89 (4)
#[test]
fn a_tenant_creation_names_its_founder_and_management_slug() {
    let k = ids();
    let tenant = k.encode(TENANT_PREFIX, [3; 16]).unwrap();
    let ok = json!({
        "tenant_id": tenant,
        "display_name": "Acme",
        "management_slug": "acme-admin",
        "founder_email": " Admin@Acme.Example ",
    });
    assert_eq!(
        parse(&k, "createTenant", None, &body(&ok)).unwrap(),
        Parsed::Tenant {
            tenant: [3; 16],
            display_name: String::from("Acme"),
            slug: String::from("acme-admin"),
            email: String::from("admin@acme.example"),
            placement: String::from(DEFAULT_PLACEMENT),
        }
    );
    let mut bad = ok.clone();
    bad["founder_email"] = json!("not-an-address");
    assert_eq!(
        parse(&k, "createTenant", None, &body(&bad)).err(),
        Some(&codes::platform::INVALID_EMAIL)
    );
    let mut extra = ok;
    extra["root"] = json!({ "sole": "AQEBAQEBAQEBAQEBAQEBAQ" });
    assert_eq!(
        parse(&k, "createTenant", None, &body(&extra)).err(),
        Some(&codes::environment::INVALID_BODY)
    );
}

// TN-112, OP-159 m.47 (h)
#[test]
fn tenant_changes_take_their_own_members_and_a_known_tenant() {
    let k = ids();
    let tenant = k.encode(TENANT_PREFIX, [3; 16]).unwrap();
    assert_eq!(
        parse(&k, "suspendTenant", Some(&tenant), &body(&json!({}))).unwrap(),
        Parsed::Suspend { tenant: [3; 16] }
    );
    assert_eq!(
        parse(&k, "reactivateTenant", Some(&tenant), &body(&json!({}))).unwrap(),
        Parsed::Reactivate { tenant: [3; 16] }
    );
    assert_eq!(
        parse(
            &k,
            "moveTenantPlacement",
            Some(&tenant),
            &body(&json!({ "placement": "pool-eu" }))
        )
        .unwrap(),
        Parsed::Placement {
            tenant: [3; 16],
            placement: String::from("pool-eu")
        }
    );
    assert_eq!(
        parse(
            &k,
            "suspendTenant",
            Some(&tenant),
            &body(&json!({ "placement": "x" }))
        )
        .err(),
        Some(&codes::environment::INVALID_BODY)
    );
    assert_eq!(
        parse(&k, "suspendTenant", Some("tnt_forged"), &body(&json!({}))).err(),
        Some(&codes::NOT_FOUND)
    );
    assert_eq!(
        parse(&k, "createEnvironment", Some(&tenant), &body(&json!({}))).err(),
        Some(&codes::environment::UNKNOWN_OPERATION)
    );
    assert_eq!(
        parse(&k, "createTenant", None, &body(&json!({}))).err(),
        Some(&codes::environment::INVALID_BODY)
    );
}

// CR-25
#[test]
fn signing_is_available_one_publish_lead_after_creation() {
    assert_eq!(signing_available_ms(1_000), 1_000 + 90 * 60_000);
}
