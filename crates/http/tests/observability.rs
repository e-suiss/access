//! The internal listener and request correlation (OP-67 m.1, m.3, SA-22, §17.8.2).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Arc;

use access_http::internal::{Internal, Probe, Readiness, SignerSocket, router as internal};
use access_http::trace::{REQUEST_ID, correlate, request_id};
use access_http::{Health, SandboxHealth};
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
    internal(Internal {
        health: health(),
        readiness: Arc::new(readiness),
        now_ms: Arc::new(|| 42),
    })
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

// OP-67 m.3, SA-22: liveness, health with the Landlock ABI, and the metric exposition
#[tokio::test]
async fn liveness_health_and_metrics_are_served() {
    let app = app(Readiness::new());
    assert_eq!(
        get_path(&app, "/livez").await,
        (StatusCode::OK, "ok".into())
    );
    let (status, body) = get_path(&app, "/healthz").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["sandbox"]["landlock_required_abi"], 4);
    assert_eq!(v["sandbox"]["landlock_kernel_abi"], 6);
    access_telemetry::signals::HTTP_RESPONSES.incr(["2xx"]);
    let (status, body) = get_path(&app, "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("access_http_responses_total"), "{body}");
    assert!(!body.contains("tenant_id") && !body.contains("realm_id"));
}

// OP-67 m.3, MD-8, OP-53: no checks and unset start-up flags are not ready; ready once set
#[tokio::test]
async fn readiness_fails_closed_during_start() {
    let (status, body) = get_path(&app(Readiness::new()), "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("no_checks"));

    let mut readiness = Readiness::new();
    let jwks = readiness.flag("jwks");
    let caches = readiness.flag("realm_cache");
    let app = app(readiness);
    let (status, body) = get_path(&app, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["failing"], serde_json::json!(["jwks", "realm_cache"]));
    jwks.set(true);
    caches.set(true);
    let (status, body) = get_path(&app, "/readyz").await;
    assert_eq!(
        (status, body.as_str()),
        (StatusCode::OK, r#"{"status":"ready","failing":[]}"#)
    );
}

fn ping(pool: access_store::Pool) -> impl Fn() -> Probe + Send + Sync + 'static {
    move || {
        let pool = pool.clone();
        Box::pin(async move { access_store::connect::ping(&pool).await })
    }
}

// OP-67 m.3: a database pool that cannot hand out a connection and a signer whose socket is
// closed make the process not ready; the body names the checks, never an address or secret
#[tokio::test]
async fn readiness_fails_when_a_dependency_is_down() {
    let db = access_store::testing::fresh().await.unwrap();
    let dir = std::env::temp_dir().join(format!("access-m8-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("signer.sock");
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();

    let app = app(Readiness::new()
        .with_fn("db.app", ping(db.app.clone()))
        .with(SignerSocket {
            name: "signer.identity",
            path: socket.clone(),
        }));
    let (status, _) = get_path(&app, "/readyz").await;
    assert_eq!(status, StatusCode::OK);

    drop(listener);
    std::fs::remove_file(&socket).unwrap();
    db.app.close().await;
    let (status, body) = get_path(&app, "/readyz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        v["failing"],
        serde_json::json!(["db.app", "signer.identity"])
    );
    assert!(!body.contains(socket.to_str().unwrap()));
    let _ = std::fs::remove_dir(&dir);
}

// §17.8.2, SEC31, OP-47: advisory volume per Instance is exported to security tooling from the
// internal listener
#[tokio::test]
async fn oracle_watch_is_exported() {
    ORACLE.record(&[0xab; 16], Advisory::Explain, 42);
    let (status, body) = get_path(&app(Readiness::new()), "/internal/v1/oracle-watch").await;
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

async fn echo(headers: HeaderMap) -> String {
    request_id(&headers).unwrap_or_default()
}

fn correlated() -> Router {
    Router::new()
        .route("/x", get(echo))
        .layer(axum::middleware::from_fn(correlate))
}

async fn call(traceparent: Option<&str>) -> (String, String) {
    let mut req = Request::get("/x");
    if let Some(t) = traceparent {
        req = req.header("traceparent", t);
    }
    let response = correlated()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
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

// OP-67 m.1, OP-65 m.4: a well-formed traceparent is continued, Request-Id is its trace id
// and the handler sees the same trace
#[tokio::test]
async fn traceparent_is_accepted_and_propagated() {
    let (id, seen) = call(Some(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    ))
    .await;
    assert_eq!(id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(seen, id);
}

// OP-67 m.1: without one, or with a malformed one, a new trace is generated
#[tokio::test]
async fn traceparent_is_generated_when_absent_or_malformed() {
    let (a, seen) = call(None).await;
    assert_eq!(a.len(), 32);
    assert_eq!(seen, a);
    let before = access_telemetry::signals::TRACEPARENT_MALFORMED.get();
    let (b, _) = call(Some("00-zz-00f067aa0ba902b7-01")).await;
    assert_eq!(b.len(), 32);
    assert_ne!(a, b);
    assert!(access_telemetry::signals::TRACEPARENT_MALFORMED.get() > before);
}
