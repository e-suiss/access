//! The internal listener's readiness, metrics and oracle watch, and request correlation
//! (OP-67 m.1, m.3, SA-22, §17.8.2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;

use access_http::api::app::{REQUEST_ID, RequestIds, request_id, request_id_of};
use access_http::api::ports::{Entropy, Unavailable};
use access_http::internal::{Probe, Readiness, SignerSocket, router as internal};
use access_http::{Health, Limits, SandboxHealth};
use access_telemetry::oracle::{Advisory, ORACLE};
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn health() -> Health {
    Health {
        status: "ok",
        sandbox: SandboxHealth {
            profile: "server",
            seccomp_phase: 2,
            landlock_required_abi: 4,
            landlock_kernel_abi: 6,
        },
    }
}

fn app(readiness: Readiness) -> Router {
    internal(health(), readiness, Limits::default(), || 42)
}

async fn get_path(app: &Router, path: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

fn failing(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).unwrap();
    v["errors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["code"].as_str().unwrap().to_owned())
        .collect()
}

// OP-67 m.3: the metric exposition is the SDK's, with no tenant or realm label
#[tokio::test]
async fn metrics_are_exposed() {
    access_telemetry::signals::HTTP_RESPONSES.incr(["2xx"]);
    let (status, body) = get_path(&app(Readiness::default()), "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("access_http_responses_total"), "{body}");
    assert!(!body.contains("tenant_id") && !body.contains("realm_id"));
}

// OP-67 m.3, MD-8, OP-53: unset start-up flags keep the process not ready, by name
#[tokio::test]
async fn readiness_fails_closed_during_start() {
    let readiness = Readiness::default();
    let jwks = readiness.flag("jwks");
    let app = app(readiness.clone());
    readiness.ready();
    let (status, body) = get_path(&app, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failing(&body), vec!["jwks"]);
    jwks.set(true);
    assert_eq!(get_path(&app, "/readyz").await.0, StatusCode::OK);
    readiness.unready();
    let (status, body) = get_path(&app, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failing(&body), vec!["started"]);
}

fn ping(pool: access_store::Pool) -> impl Fn() -> Probe + Send + Sync + 'static {
    move || {
        let pool = pool.clone();
        Box::pin(async move { access_store::connect::ping(&pool).await })
    }
}

// OP-67 m.3: a database pool that cannot hand out a connection and a signer whose socket is
// closed make the process not ready; the answer names the checks, never an address or secret
#[tokio::test]
async fn readiness_fails_when_a_dependency_is_down() {
    let db = access_store::testing::fresh().await.unwrap();
    let dir = std::env::temp_dir().join(format!("access-m8-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("signer.sock");
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();

    let readiness = Readiness::default();
    readiness.add_fn("db.app", ping(db.app.clone()));
    readiness.add(SignerSocket {
        name: "signer.identity",
        path: socket.clone(),
    });
    readiness.ready();
    let app = app(readiness);
    assert_eq!(get_path(&app, "/readyz").await.0, StatusCode::OK);

    drop(listener);
    std::fs::remove_file(&socket).unwrap();
    db.app.close().await;
    let (status, body) = get_path(&app, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(failing(&body), vec!["db.app", "signer.identity"]);
    assert!(!body.contains(socket.to_str().unwrap()));
    let _ = std::fs::remove_dir(&dir);
}

// §17.8.2, SEC31, OP-47: advisory volume per Instance is exported to security tooling from the
// internal listener
#[tokio::test]
async fn oracle_watch_is_exported() {
    ORACLE.record(&[0xab; 16], Advisory::Explain, 42);
    let (status, body) = get_path(&app(Readiness::default()), "/internal/v1/oracle-watch").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        v["current"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["instance"] == "ab".repeat(16) && r["explain"] == 1)
    );
}

struct Fixed;

impl Entropy for Fixed {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        out.fill(0x5a);
        Ok(())
    }
}

async fn echo(headers: HeaderMap) -> String {
    request_id_of(&headers).unwrap_or_default()
}

async fn call(traceparent: Option<&str>) -> (String, String) {
    let app = Router::new()
        .route("/x", get(echo))
        .layer(axum::middleware::from_fn_with_state(
            RequestIds::new(Arc::new(Fixed)),
            request_id,
        ));
    let mut req = Request::get("/x");
    if let Some(t) = traceparent {
        req = req.header("traceparent", t);
    }
    let response = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let id = response
        .headers()
        .get(REQUEST_ID)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (id, String::from_utf8(bytes.to_vec()).unwrap())
}

// OP-67 m.1, OP-65 m.4: a well-formed traceparent is continued, Request-Id is its trace id and
// the handler sees the same trace for what it calls next
#[tokio::test]
async fn traceparent_is_accepted_and_propagated() {
    let (id, seen) = call(Some(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    ))
    .await;
    assert_eq!(id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(seen, id);
}

// OP-67 m.1: without one, or with a malformed one, a trace is started from the RNG port and the
// handler continues it
#[tokio::test]
async fn traceparent_is_generated_when_absent_or_malformed() {
    let (a, seen) = call(None).await;
    assert_eq!(a, "5a".repeat(16));
    assert_eq!(seen, a);
    let before = access_telemetry::signals::TRACEPARENT_MALFORMED.get();
    let (b, _) = call(Some("00-zz-00f067aa0ba902b7-01")).await;
    assert_eq!(b, "5a".repeat(16));
    assert!(access_telemetry::signals::TRACEPARENT_MALFORMED.get() > before);
}
