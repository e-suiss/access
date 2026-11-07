#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

use serde_json::json;

use super::*;
use crate::api::contract;
use crate::yaml;

fn runtime() -> Runtime {
    let mut lists = Map::new();
    lists.insert(
        "clients".into(),
        json!([
            {"client_id": "c-2", "display_name": "Zeta", "token_endpoint_auth_method": "none",
             "redirect_uris": ["https://z.example/cb"], "status": "active", "platform_product": null},
            {"client_id": "c-1", "display_name": "Alpha", "token_endpoint_auth_method": "private_key_jwt",
             "jwks_uri": "https://a.example/jwks", "redirect_uris": [], "status": "active", "platform_product": null},
            {"client_id": "c-0", "display_name": "Old", "status": "retired"}
        ]),
    );
    lists.insert(
        "groups".into(),
        json!([{"name": "ops", "display_name": "Ops", "membership_issuer": "admin", "status": "active"}]),
    );
    lists.insert(
        "upstream_idps".into(),
        json!([{"name": "corp", "issuer": "https://corp.example", "client_id": "access",
                "client_secret_ref": "secret://vault/corp", "jwks_uri": "https://corp.example/jwks",
                "ssf": null, "status": "active"}]),
    );
    Runtime {
        lists,
        settings: json!({
            "jose_alg": "ES256",
            "rp_id": "acme.example",
            "branding": {"display_name": "Acme", "logo_uri": null},
            "session_policy": {"absolute_ms": "43200000", "idle_ms": "900000", "binding": "asn"},
            "mappers": [{"claim": "z", "source": "a"}, {"claim": "b", "source": "c"}]
        }),
        etags: Map::new(),
    }
}

fn exported() -> Value {
    export(contract(), "acme", &runtime(), ExportOptions::default()).unwrap()
}

// TN-123 item 1: deterministic export (golden), generated members and retired resources left out
#[test]
fn the_export_is_deterministic_sorted_and_without_generated_members() {
    let text = yaml::to_string(&exported(), None);
    let golden = r#"clients:
  - client_id: "c-1"
    display_name: "Alpha"
    jwks_uri: "https://a.example/jwks"
    redirect_uris: []
    token_endpoint_auth_method: "private_key_jwt"
  - client_id: "c-2"
    display_name: "Zeta"
    redirect_uris:
      - "https://z.example/cb"
    token_endpoint_auth_method: "none"
groups:
  - display_name: "Ops"
    membership_issuer: "admin"
    name: "ops"
realm: "acme"
settings:
  branding:
    display_name: "Acme"
    logo_uri: null
  jose_alg: "ES256"
  mappers:
    - claim: "b"
      source: "c"
    - claim: "z"
      source: "a"
  rp_id: "acme.example"
  session_policy:
    absolute_ms: "43200000"
    binding: "asn"
    idle_ms: "900000"
upstream_idps:
  - client_id: "access"
    client_secret_ref: "secret://vault/corp"
    issuer: "https://corp.example"
    jwks_uri: "https://corp.example/jwks"
    name: "corp"
    ssf: null
"#;
    assert_eq!(text, golden);
    let mut shuffled = runtime();
    if let Some(Value::Array(c)) = shuffled.lists.get_mut("clients") {
        c.reverse();
    }
    let again = export(contract(), "acme", &shuffled, ExportOptions::default()).unwrap();
    assert_eq!(yaml::to_string(&again, None), golden);
    let all = export(
        contract(),
        "acme",
        &runtime(),
        ExportOptions { generated: true },
    )
    .unwrap();
    assert_eq!(all["clients"].as_array().unwrap().len(), 3);
    assert_eq!(all["clients"][0]["status"], "retired");
}

// TN-123 item 2: secrets by reference only, on export and on read
#[test]
fn a_secret_value_is_refused_and_a_reference_is_kept() {
    let mut r = runtime();
    if let Some(Value::Array(c)) = r.lists.get_mut("clients") {
        c[0]["client_secret"] = json!("s3cr3t");
    }
    assert!(matches!(
        export(contract(), "acme", &r, ExportOptions::default()),
        Err(DocError::Secret(_))
    ));
    let mut doc = exported();
    doc["upstream_idps"][0]["client_secret_ref"] = json!("plain-value");
    assert!(matches!(
        plan(
            contract(),
            "acme",
            &doc,
            &runtime(),
            &PlanOptions::default()
        ),
        Err(DocError::Secret(_))
    ));
}

// TN-123 item 4: the exported document is in sync; an unset member is never drift
#[test]
fn an_exported_document_has_no_drift_and_unset_members_are_not_drift() {
    let steps = plan(
        contract(),
        "acme",
        &exported(),
        &runtime(),
        &PlanOptions::default(),
    )
    .unwrap();
    assert!(steps.is_empty(), "{steps:?}");
    let sparse = json!({
        "realm": "acme",
        "clients": [{"client_id": "c-1", "display_name": "Alpha"}],
        "settings": {"branding": {"display_name": "Acme"}}
    });
    let steps = plan(
        contract(),
        "acme",
        &sparse,
        &runtime(),
        &PlanOptions::default(),
    )
    .unwrap();
    assert!(
        steps.iter().all(|s| matches!(s, Step::Unmanaged { .. })),
        "{steps:?}"
    );
}

// TN-123 item 3, TN-110: a change is one write, carrying the unmanaged members as they are
#[test]
fn a_changed_member_is_one_write_that_keeps_the_rest() {
    let mut doc = exported();
    doc["clients"][0]["display_name"] = json!("Alpha 2");
    doc["groups"] = json!([{"name": "ops", "display_name": "Ops"}, {"name": "dev", "display_name": "Dev", "membership_issuer": "admin"}]);
    doc["clients"]
        .as_array_mut()
        .unwrap()
        .push(json!({"display_name": "New", "redirect_uris": []}));
    let steps = plan(
        contract(),
        "acme",
        &doc,
        &runtime(),
        &PlanOptions::default(),
    )
    .unwrap();
    let writes: Vec<_> = steps
        .iter()
        .filter_map(|s| match s {
            Step::Write {
                operation,
                key,
                body,
                ..
            } => Some((operation.as_str(), key.clone(), body.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(writes.len(), 3, "{steps:?}");
    let (op, key, body) = &writes[0];
    assert_eq!((*op, key.as_deref()), ("putClient", Some("c-1")));
    assert_eq!(body["display_name"], "Alpha 2");
    assert_eq!(body["jwks_uri"], "https://a.example/jwks");
    assert!(body.get("status").is_none() && body.get("client_id").is_none());
    assert_eq!(writes[1].0, "createClient");
    assert_eq!(writes[2].0, "putGroup");
    assert_eq!(writes[2].1.as_deref(), Some("dev"));
}

// TN-122, E11: the reconciler's Grant has no reserved action; reserved changes are proposals
#[test]
fn a_reserved_change_is_only_proposed() {
    let mut doc = exported();
    doc["upstream_idps"][0]["issuer"] = json!("https://corp2.example");
    doc["settings"]["rp_id"] = json!("login.acme.example");
    doc["settings"]["branding"]["display_name"] = json!("Acme Inc");
    let steps = plan(
        contract(),
        "acme",
        &doc,
        &runtime(),
        &PlanOptions::default(),
    )
    .unwrap();
    let reserved: Vec<_> = steps.iter().filter(|s| s.reserved()).collect();
    let open: Vec<_> = steps.iter().filter(|s| !s.reserved()).collect();
    assert_eq!(reserved.len(), 2, "{steps:?}");
    assert_eq!(open.len(), 1);
    let p = proposal(reserved[0], "CT3", "reserved");
    assert_eq!(p["operation"], "putUpstreamIdp");
    assert_eq!(p["tier"], "CT3");
}

// TN-124: a resource retired at runtime is a restriction; the plan never brings it back
#[test]
fn the_reconciler_does_not_undo_a_retirement() {
    let mut doc = exported();
    doc["clients"]
        .as_array_mut()
        .unwrap()
        .push(json!({"client_id": "c-0", "display_name": "Old"}));
    let steps = plan(
        contract(),
        "acme",
        &doc,
        &runtime(),
        &PlanOptions::default(),
    )
    .unwrap();
    assert!(steps.iter().any(|s| matches!(s, Step::Conflict { at, reason } if at == "clients/c-0" && reason.contains("TN-124"))));
    assert!(!steps.iter().any(|s| matches!(s, Step::Write { .. })));
}

// TN-124: the emergency escape is the resource's retire (CT1), a proposal, not an unmanage flag
#[test]
fn a_release_is_a_restriction_exercise_proposal() {
    let step = release("clients/c-1").unwrap();
    assert!(
        matches!(&step, Step::Write { operation, key, .. } if operation == "retireClient" && key.as_deref() == Some("c-1"))
    );
    assert!(!step.reserved());
    let p = proposal(&step, "CT1", "emergency");
    assert_eq!(p["tier"], "CT1");
    assert!(release("clients").is_err());
    assert!(release("accounts/a-1").is_err());
}

// TN-123 item 3: full CRUD with --prune; without it, unnamed resources are left alone
#[test]
fn prune_retires_what_the_document_does_not_name() {
    let doc = json!({"realm": "acme", "clients": [{"client_id": "c-1"}]});
    let steps = plan(
        contract(),
        "acme",
        &doc,
        &runtime(),
        &PlanOptions {
            prune: true,
            managed_by: None,
        },
    )
    .unwrap();
    assert!(steps.iter().any(|s| matches!(s, Step::Write { operation, key, .. } if operation == "retireClient" && key.as_deref() == Some("c-2"))));
    assert!(
        !steps
            .iter()
            .any(|s| matches!(s, Step::Write { key, .. } if key.as_deref() == Some("c-0")))
    );
}

#[test]
fn another_realms_or_an_unknown_document_is_refused() {
    let mut doc = exported();
    doc["realm"] = json!("other");
    assert_eq!(
        plan(
            contract(),
            "acme",
            &doc,
            &runtime(),
            &PlanOptions::default()
        ),
        Err(DocError::Realm("other".into()))
    );
    let mut doc = exported();
    doc["accounts"] = json!([]);
    assert!(matches!(
        plan(
            contract(),
            "acme",
            &doc,
            &runtime(),
            &PlanOptions::default()
        ),
        Err(DocError::Shape(_))
    ));
    let mut doc = exported();
    doc["clients"]
        .as_array_mut()
        .unwrap()
        .push(json!({"client_id": "c-9"}));
    let steps = plan(
        contract(),
        "acme",
        &doc,
        &runtime(),
        &PlanOptions::default(),
    )
    .unwrap();
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, Step::Conflict { at, .. } if at == "clients/c-9"))
    );
}

// OP-151 m.3 (o): a protection mode change is planned and names its tier
#[test]
fn a_protection_mode_change_names_its_tier() {
    let mut r = runtime();
    r.settings["protection_mode"] = json!({"bot": "monitor", "suspicious_ip": "monitor",
        "breached_password": "monitor", "brute_force": "enforce", "sl2": "shadow", "denied_asns": []});
    let doc = json!({"realm": "acme", "settings": {"protection_mode": {"suspicious_ip": "enforce"}, "jose_alg": "Ed25519"}});
    let steps = plan(contract(), "acme", &doc, &r, &PlanOptions::default()).unwrap();
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, Step::Write { operation, what, .. }
        if operation == "putProtectionMode" && what.ends_with("(idp.realm.protection_mode)"))),
        "{steps:?}"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, Step::Write { operation, body, .. }
        if operation == "putJoseAlg" && body["alg"] == "Ed25519"))
    );
    let doc = json!({"realm": "acme", "settings": {"protection_mode": {"suspicious_ip": "monitor", "bot": "monitor", "sl2": "shadow"}}});
    r.settings["protection_mode"]["bot"] = json!("enforce");
    let steps = plan(contract(), "acme", &doc, &r, &PlanOptions::default()).unwrap();
    assert!(steps.iter().any(|s| matches!(s, Step::Write { what, .. } if what.ends_with("(idp.realm.protection_mode_loosen)"))), "{steps:?}");
}
