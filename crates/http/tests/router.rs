//! Behaviour of the shared HTTP stack.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use time::macros::datetime;
use tower::ServiceExt;

use access_http::{Health, Limits, SandboxHealth, SecurityTxt, harden, router};

fn security_txt() -> SecurityTxt {
    SecurityTxt {
        contacts: vec!["https://github.com/e-suiss/access/security/advisories/new".into()],
        expires: datetime!(2027-04-01 00:00 UTC),
        policy: Some("https://github.com/e-suiss/access/security/policy".into()),
        preferred_languages: Some("en, tr".into()),
    }
}

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

async fn boom() -> &'static str {
    panic!("boom with internal detail")
}

async fn body_string(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// SA-14
#[tokio::test]
async fn security_txt_has_required_fields() {
    let app = router(security_txt(), health(), Limits::default());
    let response = app
        .oneshot(
            Request::get("/.well-known/security.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(body.contains("Contact: https://github.com/e-suiss/access/security/advisories/new\n"));
    assert!(body.contains("Expires: 2027-04-01T00:00:00Z\n"));
}

// SA-21, R-3
#[tokio::test]
async fn panic_in_handler_becomes_500_problem_and_service_survives() {
    let app = harden(
        axum::Router::new()
            .route("/boom", get(boom))
            .route("/healthz", get(|| async { "ok" })),
        Limits::default(),
    );
    let response = app
        .clone()
        .oneshot(Request::get("/boom").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
    let body = body_string(response).await;
    assert!(
        !body.contains("internal detail"),
        "panic message leaked: {body}"
    );

    let health = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(health.status(), StatusCode::OK);
}

// R-5
#[tokio::test]
async fn oversized_body_is_rejected() {
    let limits = Limits {
        max_body_bytes: 16,
        ..Limits::default()
    };
    let app = harden(
        axum::Router::new().route(
            "/echo",
            axum::routing::post(|body: String| async move { body }),
        ),
        limits,
    );
    let response = app
        .oneshot(
            Request::post("/echo")
                .body(Body::from(vec![b'a'; 64]))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

// SA-22, OP-92
#[tokio::test]
async fn healthz_reports_landlock_abi() {
    let app = router(security_txt(), health(), Limits::default());
    let response = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(body.contains(r#""landlock_kernel_abi":6"#), "{body}");
    assert!(body.contains(r#""seccomp_phase":2"#), "{body}");
}

#[tokio::test]
async fn unknown_path_is_404_problem() {
    let app = router(security_txt(), health(), Limits::default());
    let response = app
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()["content-type"],
        "application/problem+json"
    );
}
