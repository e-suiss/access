//! The management API's common rules over HTTP (OP-65, TN-126, TN-127, OP-67 m.1): `Request-Id`,
//! `RateLimit` headers and throttling, `Idempotency-Key`, problem bodies.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

mod admin;

use std::sync::atomic::Ordering;

use access_http::api::domain::SurfaceScope;
use access_http::api::domain::idempotency;
use access_http::api::ports::{Begun, IdempotencyStore};
use access_kernel::json::b64url_encode;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use suiss_crypto::signer::{Signer, SoftSigner};

use admin::{Harness, ais, platform_domain, proof, read, realm_domain, send};

const REALM_WRITE: &str = "/admin/v1/realms/acme/groups/staff/retire";
const PLATFORM_WRITE: &str = "/admin/v1/platform/tenants";

fn post(path: &str, key: &str, ais: &str, body: &'static str) -> Request<Body> {
    Request::post(path)
        .header("idempotency-key", key)
        .header("x-access-ais", ais)
        .body(Body::from(body))
        .unwrap()
}

// OP-65, OP-67 m.1
#[tokio::test]
async fn every_response_carries_the_trace_id_as_request_id() {
    let h = Harness::new();
    let router = h.router();
    let sent = Request::get("/admin/v1/platform")
        .header(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        )
        .body(Body::empty())
        .unwrap();
    let (r, body) = send(&router, sent).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid-token");
    assert_eq!(
        r.headers()["request-id"],
        "4bf92f3577b34da6a3ce929d0e0e4736"
    );
    let mut seen = std::collections::BTreeSet::new();
    for traceparent in [
        None,
        Some("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
        Some("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"),
        Some("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        Some("garbage"),
    ] {
        let mut b = Request::get("/admin/v1/nope");
        if let Some(t) = traceparent {
            b = b.header("traceparent", t);
        }
        let (r, _) = send(&router, b.body(Body::empty()).unwrap()).await;
        assert_eq!(r.status(), StatusCode::NOT_FOUND);
        let id = r.headers()["request-id"].to_str().unwrap().to_owned();
        assert_eq!(id.len(), 32);
        assert_ne!(id, "4bf92f3577b34da6a3ce929d0e0e4736", "{traceparent:?}");
        assert!(seen.insert(id), "a fresh id per request");
    }
    let (r, _) = send(
        &router,
        Request::get("/admin/v1/../x").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(r.headers().contains_key("request-id"));
}

// TN-127, OP-151 m.3 (d)
#[tokio::test]
async fn reads_are_limited_per_token() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("t", "access-admin:platform", &["platform.read"], 600_000);
    for i in 0..60 {
        let (r, _) = send(&router, read("/admin/v1/platform", &token)).await;
        assert_eq!(r.status(), StatusCode::OK, "request {i}");
        let policy = r.headers()["ratelimit-policy"].to_str().unwrap();
        assert!(policy.contains("\"read\";q=60;w=60"), "{policy}");
        let left = r.headers()["ratelimit"].to_str().unwrap();
        assert!(left.contains(&format!("\"read\";r={}", 59 - i)), "{left}");
    }
    let (r, body) = send(&router, read("/admin/v1/platform", &token)).await;
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate-limited");
    assert_eq!(body["type"], "urn:suiss:access:problem:rate-limited");
    assert!(r.headers().contains_key("retry-after"));
    let other = h.token("u", "access-admin:platform", &["platform.read"], 600_000);
    let (r, _) = send(&router, read("/admin/v1/platform", &other)).await;
    assert_eq!(r.status(), StatusCode::OK);
    h.fake.now.fetch_add(60_000, Ordering::SeqCst);
    let fresh = h.token("t", "access-admin:platform", &["platform.read"], 600_000);
    let (r, _) = send(&router, read("/admin/v1/platform", &fresh)).await;
    assert_eq!(r.status(), StatusCode::OK);
}

// TN-127, OP-151 m.3 (d)
#[tokio::test]
async fn writes_are_limited_per_actor_instance() {
    for (path, domain, burst) in [
        (REALM_WRITE, realm_domain(), 50_u8),
        (PLATFORM_WRITE, platform_domain(), 20),
    ] {
        let h = Harness::new();
        let router = h.router();
        let actor = h.instance(domain);
        for i in 0..=burst {
            let nonce = [i; 16];
            let a = ais(&actor, domain, nonce, h.now());
            let (r, body) = send(&router, post(path, &b64url_encode(&nonce), &a, "{}")).await;
            if i < burst {
                assert!(r.status().is_success(), "{path} {i}: {body}");
            } else {
                assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS, "{path}");
                assert_eq!(body["code"], "rate-limited");
            }
        }
        let other = h.instance(domain);
        let nonce = [200; 16];
        let a = ais(&other, domain, nonce, h.now());
        let (r, _) = send(&router, post(path, &b64url_encode(&nonce), &a, "{}")).await;
        assert!(
            r.status().is_success(),
            "another Instance has its own budget"
        );
    }
}

// TN-126
#[tokio::test]
async fn a_write_needs_its_nonce_as_idempotency_key() {
    let h = Harness::new();
    let router = h.router();
    let actor = h.instance(realm_domain());
    let nonce = [1; 16];
    let a = ais(&actor, realm_domain(), nonce, h.now());
    let missing = Request::post(REALM_WRITE)
        .header("x-access-ais", &a)
        .body(Body::from("{}"))
        .unwrap();
    let (r, body) = send(&router, missing).await;
    assert_eq!(
        (r.status(), body["code"].as_str().unwrap()),
        (StatusCode::BAD_REQUEST, "idempotency-key-required")
    );
    for (key, code) in [
        ("k".repeat(256), "idempotency-key-invalid"),
        ("a b".to_owned(), "idempotency-key-invalid"),
        (b64url_encode(&[2; 16]), "idempotency-key-not-nonce"),
    ] {
        let (r, body) = send(&router, post(REALM_WRITE, &key, &a, "{}")).await;
        assert_eq!(
            (r.status(), body["code"].as_str().unwrap()),
            (StatusCode::BAD_REQUEST, code)
        );
    }
    assert_eq!(h.commits(), 0);
}

// TN-126, TI-8
#[tokio::test]
async fn a_repeated_write_replays_and_a_changed_one_is_refused() {
    let h = Harness::new();
    let router = h.router();
    let actor = h.instance(realm_domain());
    let nonce = [3; 16];
    let key = b64url_encode(&nonce);
    let a = ais(&actor, realm_domain(), nonce, h.now());
    let (first, body1) = send(&router, post(REALM_WRITE, &key, &a, "{\"x\":1}")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let (again, body2) = send(&router, post(REALM_WRITE, &key, &a, "{\"x\":1}")).await;
    assert_eq!(again.status(), StatusCode::OK);
    assert_eq!(body1, body2);
    assert_eq!(h.commits(), 1, "no second Exercise");
    let (changed, body) = send(&router, post(REALM_WRITE, &key, &a, "{\"x\":2}")).await;
    assert_eq!(changed.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "idempotency-key-reused");
    assert_eq!(h.commits(), 1);
}

// TN-126, SI-20
#[tokio::test]
async fn failures_are_not_kept() {
    let h = Harness::new();
    let router = h.router();
    let actor = h.instance(realm_domain());
    for (path, status, n) in [
        (
            "/admin/v1/realms/acme/groups/refuse/retire",
            StatusCode::BAD_REQUEST,
            6_u8,
        ),
        (
            "/admin/v1/realms/acme/groups/fail/retire",
            StatusCode::SERVICE_UNAVAILABLE,
            4,
        ),
    ] {
        let nonce = [n; 16];
        let key = b64url_encode(&nonce);
        let a = ais(&actor, realm_domain(), nonce, h.now());
        let before = h.commits();
        for _ in 0..2 {
            let (r, _) = send(&router, post(path, &key, &a, "{}")).await;
            assert_eq!(r.status(), status);
        }
        assert_eq!(h.commits(), before + 2, "{path}: ran again");
    }
}

// TN-126
#[tokio::test]
async fn a_running_key_is_in_use() {
    let h = Harness::new();
    let router = h.router();
    let actor = h.instance(realm_domain());
    let nonce = [9; 16];
    let key = b64url_encode(&nonce);
    let a = ais(&actor, realm_domain(), nonce, h.now());
    let kid = access_kernel::verify::key_scope::thumbprint(&actor.public_key());
    let scope = idempotency::scope(&SurfaceScope::Realm("acme".into()), &kid, key.as_bytes());
    let request = idempotency::request("POST", REALM_WRITE, b"{}");
    assert_eq!(
        h.fake
            .idempotency
            .begin(scope, request, h.now())
            .await
            .unwrap(),
        Begun::Run
    );
    let (r, body) = send(&router, post(REALM_WRITE, &key, &a, "{}")).await;
    assert_eq!(r.status(), StatusCode::CONFLICT);
    assert_eq!(body["code"], "idempotency-key-in-use");
    assert_eq!(h.commits(), 0);
}

// TN-126, OP-151 m.3 (c)
#[tokio::test]
async fn keys_are_scoped_to_the_caller() {
    let h = Harness::new();
    let router = h.router();
    let nonce = [4; 16];
    let key = b64url_encode(&nonce);
    for _ in 0..2 {
        let actor = h.instance(realm_domain());
        let a = ais(&actor, realm_domain(), nonce, h.now());
        let (r, _) = send(&router, post(REALM_WRITE, &key, &a, "{}")).await;
        assert_eq!(r.status(), StatusCode::OK);
    }
    assert_eq!(h.commits(), 2);
}

// TN-130
#[tokio::test]
async fn the_ais_may_travel_in_the_body() {
    let h = Harness::new();
    let router = h.router();
    let actor: SoftSigner = h.instance(realm_domain());
    let nonce = [6; 16];
    let a = ais(&actor, realm_domain(), nonce, h.now());
    let body = serde_json::json!({ "ais": a }).to_string();
    let request = Request::post(REALM_WRITE)
        .header("idempotency-key", b64url_encode(&nonce))
        .body(Body::from(body.clone()))
        .unwrap();
    let (r, _) = send(&router, request).await;
    assert_eq!(r.status(), StatusCode::OK);
    let both = Request::post(REALM_WRITE)
        .header("idempotency-key", b64url_encode(&nonce))
        .header("x-access-ais", &a)
        .body(Body::from(body))
        .unwrap();
    let (r, b) = send(&router, both).await;
    assert_eq!(
        (r.status(), b["code"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("ais-invalid"))
    );
}

// OP-65, TN-119
#[tokio::test]
async fn the_surface_roots_describe_their_surface() {
    let h = Harness::new();
    let router = h.router();
    let token = h.token("r", "access-admin:realm:acme", &["realm.read"], 600_000);
    let (r, body) = send(&router, read("/admin/v1/realms/acme", &token)).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body["surface"], "realm");
    assert_eq!(body["realm"], "acme");
    assert_eq!(body["audience"], "access-admin:realm:acme");
    assert_eq!(body["scope_namespace"], "realm.");
    let p = h.token("p", "access-admin:platform", &["platform.read"], 600_000);
    let req = Request::get("/admin/v1/platform")
        .header("authorization", format!("DPoP {p}"))
        .header("dpop", proof("GET", "/admin/v1/platform"))
        .body(Body::empty())
        .unwrap();
    let (r, body) = send(&router, req).await;
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body["audience"], "access-admin:platform");
    assert!(body.get("realm").is_none());
}
