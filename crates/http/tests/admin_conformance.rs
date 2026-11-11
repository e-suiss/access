//! Admin API conformance (§9.7, TN-110, TN-130, OP-151 m.3 (s)): a management call without the
//! caller's actor proof changes nothing; there is no credential-setting route and no route that
//! acts as another user.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use access_http::api::manifest::{Access, MANIFEST};
use access_kernel::combinator::Mode;
use access_kernel::json::b64url_encode;
use axum::body::Body;
use axum::http::{Request, StatusCode};

use admin::{Harness, ais, ais_with, platform_domain, proof, realm_domain, send};

const PATH: &str = "/admin/v1/realms/acme/groups/staff/retire";

fn write(key: &str, ais: Option<&str>, token: Option<&str>) -> Request<Body> {
    let mut b = Request::post(PATH)
        .header("content-type", "application/json")
        .header("idempotency-key", key);
    if let Some(a) = ais {
        b = b.header("x-access-ais", a);
    }
    if let Some(t) = token {
        b = b
            .header("authorization", format!("DPoP {t}"))
            .header("dpop", proof("POST", PATH));
    }
    b.body(Body::from(r#"{"name":"x"}"#)).unwrap()
}

// §9.7, TN-110, OP-151 m.3 (s), TNI-12
#[tokio::test]
async fn a_write_without_actor_proof_changes_nothing() {
    let h = Harness::new();
    let router = h.router();
    let nonce = [5; 16];
    let key = b64url_encode(&nonce);
    let reader = h.token(
        "reader",
        "access-admin:realm:acme",
        &["realm.read", "realm.write"],
        600_000,
    );
    let wrong = h.instance(platform_domain());
    let stranger = suiss_crypto::signer::SoftSigner::generate_ed25519()
        .unwrap()
        .0;
    let own = h.instance(realm_domain());
    let refused = [
        write(&key, None, None),
        write(&key, None, Some(&reader)),
        write(
            &key,
            Some(&ais(&wrong, realm_domain(), nonce, h.now())),
            None,
        ),
        write(
            &key,
            Some(&ais(&stranger, realm_domain(), nonce, h.now())),
            None,
        ),
        write(
            &key,
            Some(&ais_with(&own, realm_domain(), nonce, h.now(), Mode::Check)),
            None,
        ),
        write(
            &key,
            Some(&ais(&own, realm_domain(), nonce, h.now() + 120_000)),
            None,
        ),
    ];
    for (i, request) in refused.into_iter().enumerate() {
        let (r, body) = send(&router, request).await;
        assert!(
            matches!(r.status(), StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
            "case {i}: {} {body}",
            r.status()
        );
        assert_eq!(h.position(), 0, "case {i}");
        assert_eq!(h.commits(), 0, "case {i}");
    }
    let (r, body) = send(
        &router,
        write(&key, Some(&ais(&own, realm_domain(), nonce, h.now())), None),
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK, "{body}");
    assert_eq!(body["position"], "1");
    assert_eq!(h.position(), 1);
}

// TN-61, TN-130, MD-14, X24
#[test]
fn no_credential_setting_or_acting_as_route_exists() {
    for row in MANIFEST {
        let text = format!("{} {} {}", row.path, row.operation_id, row.summary).to_lowercase();
        for banned in [
            "credential",
            "password",
            "set-secret",
            "impersonat",
            "log in as",
            "login-as",
            "act-as",
            "sudo",
            "token",
        ] {
            assert!(!text.contains(banned), "{}: {banned}", row.operation_id);
        }
        assert!(row.verb_fits(), "{}", row.operation_id);
        if row.verb.mutating() && row.access != Access::Write {
            assert!(
                matches!(row.operation_id, "draftIntent" | "draftPlatformIntent"),
                "{}",
                row.operation_id
            );
        }
    }
}

// IDI-1, MD-14, TN-110
#[test]
fn every_realm_write_is_an_idp_exercise() {
    use access_http::api::domain::Surface;
    use access_identity_admin::app::rest::Op;
    let mut writes = 0;
    for row in MANIFEST
        .iter()
        .filter(|r| r.surface == Surface::Realm && r.changes_state())
    {
        assert_eq!(row.access, Access::Write, "{}", row.operation_id);
        // OP-154 m.4
        // OP-154 m.3 (f)
        if matches!(row.operation_id, "createJob" | "revokeAllAgentInstances")
            || access_http::api::realm::planned(row.operation_id)
        {
            continue;
        }
        assert!(
            Op::from_operation(row.operation_id).is_some(),
            "{} compiles to no idp.* change",
            row.operation_id
        );
        writes += 1;
    }
    assert!(writes > 30, "{writes}");
}

// XI-3, C2, E27
#[test]
fn every_management_write_answers_with_its_committed_exercise() {
    let doc = access_http::api::schema::openapi();
    let schemas = doc["components"]["schemas"].as_object().unwrap();
    let mut writes = 0;
    for (path, ops) in doc["paths"].as_object().unwrap() {
        for (method, op) in ops.as_object().unwrap() {
            if !matches!(method.as_str(), "post" | "put" | "patch" | "delete") {
                continue;
            }
            let id = op["operationId"].as_str().unwrap();
            // PI-7
            if matches!(id, "draftIntent" | "draftPlatformIntent") {
                continue;
            }
            // OP-157 m.3 (w)
            if id == "keepReviewItem" {
                continue;
            }
            let responses = op["responses"].as_object().unwrap();
            assert!(!responses.contains_key("202"), "{method} {path}: 202");
            for (code, response) in responses.iter().filter(|(c, _)| c.starts_with('2')) {
                let reference = response["content"]["application/json"]["schema"]["$ref"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{method} {path} {code}: no schema"));
                let name = reference.rsplit('/').next().unwrap();
                let required = schemas[name]["required"].as_array().unwrap();
                for member in ["exercise_id", "position"] {
                    assert!(
                        required.iter().any(|r| r == member),
                        "{method} {path} {code}: {name} lacks {member}"
                    );
                }
                writes += 1;
            }
        }
    }
    assert!(writes > 40, "{writes}");
}

fn committed_contract(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdks/openapi")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

// XI-7, E30, E44
#[test]
fn no_contract_offers_an_inbox() {
    let banned = [
        "inbox",
        "task",
        "todo",
        "notification",
        "attention",
        "queue",
        "pending",
    ];
    let mut approval_entries = 0;
    for name in [
        "access-v1.json",
        "admin-v1.json",
        "frontend.json",
        "login.json",
    ] {
        let doc = committed_contract(name);
        for (path, ops) in doc["paths"].as_object().unwrap() {
            for (method, op) in ops.as_object().unwrap() {
                let id = op["operationId"].as_str().unwrap_or_default();
                let words = format!("{path} {id}").to_ascii_lowercase();
                for word in banned {
                    assert!(!words.contains(word), "{name}: {method} {path} ({id})");
                }
                if method != "get"
                    || !path.contains("approv")
                    || std::path::Path::new(path)
                        .extension()
                        .is_some_and(|e| e.eq_ignore_ascii_case("js"))
                {
                    continue;
                }
                let params = op["parameters"].as_array().cloned().unwrap_or_default();
                assert!(
                    params
                        .iter()
                        .any(|p| p["name"] == "request" && p["required"] == true),
                    "{name}: {method} {path} opens without the coordinator's request"
                );
                approval_entries += 1;
            }
        }
    }
    assert_eq!(approval_entries, 1);
}
