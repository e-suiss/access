//! The platform-admin surface (OP-151 m.2 M2): its own audience (TN-119), content-free reads
//! (INV-29, X31), no super-admin shortcut and no route that acts as a user (TN-110, TN-130), and
//! provisioning writes that compile to an Exercise (TN-110).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use access_http::api::domain::Surface;
use access_http::api::manifest::{Access, MANIFEST, Verb};
use access_http::api::platform::{CONTENT_FIELDS, ROWS};
use access_http::api::schema::openapi;
use access_kernel::json::b64url_encode;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};

use admin::{Harness, LEAKED, REALM, ais, platform_domain, read, realm_domain, send};

fn platform_rows() -> impl Iterator<Item = &'static access_http::api::manifest::Route> {
    MANIFEST.iter().filter(|r| r.surface == Surface::Platform)
}

// TN-119, OP-151 m.3 (a), m.6 (f): a realm-admin token never reads the platform surface; the
// answer is 401 before anything is looked up
#[tokio::test]
async fn a_realm_admin_token_is_refused_on_the_platform_surface() {
    let h = Harness::new();
    let router = h.router();
    let realm_token = h.token(
        "realm-admin",
        &format!("access-admin:realm:{REALM}"),
        &["realm.read", "platform.read"],
        600_000,
    );
    for path in [
        "/admin/v1/platform",
        "/admin/v1/platform/tenants",
        "/admin/v1/platform/tenants/t1",
        "/admin/v1/platform/tenants/t1/realms",
        "/admin/v1/platform/tenants/t1/sandbox-domains",
        "/admin/v1/platform/realms/acme",
        "/admin/v1/platform/operator/health",
    ] {
        let (r, body) = send(&router, read(path, &realm_token)).await;
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["code"], "wrong-audience", "{path}");
    }
    let platform_token = h.token(
        "platform-admin",
        "access-admin:platform",
        &["platform.read", "realm.read"],
        600_000,
    );
    let (r, body) = send(&router, read("/admin/v1/realms/acme", &platform_token)).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "wrong-audience");
}

fn resolve<'a>(doc: &'a Value, v: &'a Value) -> &'a Value {
    match v.get("$ref").and_then(Value::as_str) {
        Some(r) => {
            let name = r.rsplit('/').next().unwrap();
            &doc["components"]["schemas"][name]
        }
        None => v,
    }
}

/// Every property name reachable from `schema`, through refs, arrays and `oneOf`.
fn names(doc: &Value, schema: &Value, out: &mut Vec<String>, depth: usize) {
    assert!(depth < 16, "schema too deep");
    let s = resolve(doc, schema);
    if let Some(props) = s.get("properties").and_then(Value::as_object) {
        for (k, v) in props {
            out.push(k.clone());
            names(doc, v, out, depth + 1);
        }
    }
    if let Some(items) = s.get("items") {
        names(doc, items, out, depth + 1);
    }
    for key in ["oneOf", "anyOf", "allOf"] {
        if let Some(Value::Array(alts)) = s.get(key) {
            for a in alts {
                names(doc, a, out, depth + 1);
            }
        }
    }
}

// INV-29, X31: every platform route's response schema names no account, client, grant, record
// or claim member, at any depth; each object is closed
#[test]
fn platform_responses_are_content_free_by_contract() {
    let doc = openapi();
    for row in platform_rows() {
        let op = &doc["paths"][row.path][row.verb.name()];
        let ok = if row.verb == Verb::Get || row.access != Access::Write {
            &op["responses"]["200"]
        } else {
            &op["responses"]["201"]
        };
        let schema = &ok["content"]["application/json"]["schema"];
        assert!(
            schema.is_object(),
            "{}: no success schema",
            row.operation_id
        );
        let mut all = Vec::new();
        names(&doc, schema, &mut all, 0);
        assert!(!all.is_empty(), "{}", row.operation_id);
        for banned in CONTENT_FIELDS {
            assert!(
                !all.iter().any(|n| n == banned),
                "{}: {banned}",
                row.operation_id
            );
        }
        assert_eq!(
            resolve(&doc, schema)["additionalProperties"],
            json!(false),
            "{}",
            row.operation_id
        );
    }
}

fn keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                out.push(k.clone());
                keys(x, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| keys(x, out)),
        _ => {}
    }
}

// INV-29, X31: whatever the port returns, a platform answer shows only the kind's members
#[tokio::test]
async fn platform_reads_drop_what_the_kind_may_not_show() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("p", "access-admin:platform", &["platform.read"], 600_000);
    for path in [
        "/admin/v1/platform/tenants",
        "/admin/v1/platform/tenants/t1",
        "/admin/v1/platform/tenants/t1/realms",
        "/admin/v1/platform/tenants/t1/sandbox-domains",
        "/admin/v1/platform/realms/acme",
        "/admin/v1/platform/operator/health",
    ] {
        let (r, body) = send(&router, read(path, &token)).await;
        assert_eq!(r.status(), StatusCode::OK, "{path}: {body}");
        let mut all = Vec::new();
        keys(&body, &mut all);
        for banned in CONTENT_FIELDS.iter().chain([&LEAKED, &"genesis"]) {
            assert!(!all.iter().any(|k| k == banned), "{path}: {banned}");
        }
    }
}

// TN-110, TN-111, INV-29: a provisioning write is the caller's AIS compiled to one Exercise; the
// answer carries the Exercise, the created resource and the Genesis summary, no secret and no
// content
#[tokio::test]
async fn a_realm_creation_answers_with_its_exercise_and_genesis() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("p", "access-admin:platform", &["platform.read"], 600_000);
    let draft = Request::post("/admin/v1/platform/intents")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", admin::proof("POST", "/admin/v1/platform/intents"))
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "operation": "createRealm", "key": "t1",
                    "body": { "slug": "shop", "root": { "sole": "AQEBAQEBAQEBAQEBAQEBAQ" },
                              "acknowledge_no_recovery": true } })
            .to_string(),
        ))
        .unwrap();
    let (r, drafted) = send(&router, draft).await;
    assert_eq!(r.status(), StatusCode::OK, "{drafted}");
    assert_eq!(drafted["operation"], "createRealm");
    assert_eq!(drafted["domain"], b64url_encode(&platform_domain().0));
    assert_eq!(h.position(), 0, "drafting changes nothing");

    let me = h.instance(platform_domain());
    let nonce = [9; 16];
    let path = "/admin/v1/platform/tenants/t1/realms";
    let request = Request::post(path)
        .header("content-type", "application/json")
        .header("idempotency-key", b64url_encode(&nonce))
        .header("x-access-ais", ais(&me, platform_domain(), nonce, h.now()))
        .body(Body::from(drafted["body"].to_string()))
        .unwrap();
    let (r, body) = send(&router, request).await;
    assert_eq!(r.status(), StatusCode::CREATED, "{body}");
    assert_eq!(body["position"], "1");
    assert_eq!(body["genesis"]["recovery"], "not_available");
    assert_eq!(body["resource"]["slug"], "new");
    let mut all = Vec::new();
    keys(&body, &mut all);
    for banned in CONTENT_FIELDS.iter().chain([&"client_secret"]) {
        assert!(!all.iter().any(|k| k == banned), "{banned}");
    }
    assert_eq!(h.position(), 1);

    // TN-119: a realm surface's Instance does not write on the platform surface
    let other = h.instance(realm_domain());
    let nonce = [10; 16];
    let request = Request::post(path)
        .header("content-type", "application/json")
        .header("idempotency-key", b64url_encode(&nonce))
        .header(
            "x-access-ais",
            ais(&other, platform_domain(), nonce, h.now()),
        )
        .body(Body::from("{}"))
        .unwrap();
    let (r, body) = send(&router, request).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "ais-rejected");
    assert_eq!(h.position(), 1);
}

// TN-110, MD-14, CMP-15.5, Ek B "no super-admin shortcut": the platform surface covers tenants,
// realm metadata, sandbox domains, streams and the operator's health only; it has no route into
// a realm's resources, settings or authority state
#[test]
fn the_platform_surface_has_no_super_admin_shortcut() {
    let allowed = [
        "",
        "intents",
        "tenants",
        "realms",
        "sandbox-domains",
        "streams",
        "operator",
    ];
    for row in platform_rows() {
        let rest = row.path.strip_prefix("/admin/v1/platform").unwrap();
        let first = rest.trim_start_matches('/').split('/').next().unwrap_or("");
        assert!(allowed.contains(&first), "{}", row.operation_id);
        if first == "realms" {
            assert_eq!(row.path, "/admin/v1/platform/realms/{realm_slug}");
            assert_eq!(row.verb, Verb::Get, "{}", row.operation_id);
        }
        if first == "tenants" {
            let last = rest.rsplit('/').next().unwrap();
            assert!(
                ["tenants", "{tenant_id}", "realms", "sandbox-domains"].contains(&last),
                "{}",
                row.operation_id
            );
        }
        for word in [
            "settings", "accounts", "clients", "groups", "grants", "records", "claims", "audit",
            "explain", "search",
        ] {
            assert!(!row.path.contains(word), "{}: {word}", row.operation_id);
        }
    }
    assert_eq!(platform_rows().count(), ROWS.len() + 1);
}

// TN-130, MD-9, X37, must-never #19: nothing on either surface lets anyone act as a user
#[test]
fn no_route_acts_as_a_user() {
    for row in MANIFEST {
        let text = format!("{} {} {}", row.path, row.operation_id, row.summary).to_lowercase();
        for banned in [
            "impersonat",
            "log in as",
            "login-as",
            "login_as",
            "view as",
            "view-as",
            "act-as",
            "act_as",
            "as-user",
            "delegated-session",
            "sudo",
            "support-token",
        ] {
            assert!(!text.contains(banned), "{}: {banned}", row.operation_id);
        }
    }
}
