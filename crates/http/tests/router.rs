//! Behaviour of the shared HTTP stack.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use time::macros::datetime;
use tower::ServiceExt;

use access_http::internal::{Readiness, router as internal};
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
    let app = router(security_txt(), Limits::default(), Router::new());
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

// SA-21, R-3, RAUTHY-006
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
    let app = internal(health(), Readiness::default(), Limits::default(), || 0);
    let response = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_string(response).await;
    assert!(body.contains(r#""landlock_kernel_abi":6"#), "{body}");
    assert!(body.contains(r#""seccomp_phase":2"#), "{body}");
}

// U42, §14.5, OP-151 m.3 (b): /healthz on the internal listener names the lockdown in force:
// the profile, the seccomp phase, the Landlock ABI required (a hard minimum) and the one the
// kernel reports; the public listener does not serve it
#[tokio::test]
async fn healthz_names_the_required_and_the_kernel_landlock_abi() {
    let app = internal(health(), Readiness::default(), Limits::default(), || 0);
    let response = app
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
    let sandbox = &body["sandbox"];
    assert_eq!(sandbox["profile"], "server");
    assert_eq!(sandbox["seccomp_phase"], 2);
    assert_eq!(sandbox["landlock_required_abi"], 4);
    assert_eq!(sandbox["landlock_kernel_abi"], 6);
    let public = router(security_txt(), Limits::default(), Router::new());
    let response = public
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_path_is_404_problem() {
    let app = router(security_txt(), Limits::default(), Router::new());
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

// TN-113: a path reaches routing and path-based permissions only in its one canonical spelling;
// dot segments, empty segments and needless percent-encoding are refused before any route
#[tokio::test]
async fn non_canonical_paths_never_reach_a_route() {
    let app = router(security_txt(), Limits::default(), Router::new());
    let ok = app
        .clone()
        .oneshot(
            Request::get("/.well-known/security.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    for path in [
        "/x/../.well-known/security.txt",
        "/./.well-known/security.txt",
        "//.well-known/security.txt",
        "/%2Ewell-known/security.txt",
        "/x/%2E%2E/.well-known/security.txt",
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert!(body_string(response).await.contains("path-not-canonical"));
    }
}

// OP-67 m.3, OP-151 m.3 (b): health, liveness, readiness and metrics are on the internal
// listener only; the public router does not serve them
#[tokio::test]
async fn health_endpoints_are_internal_only() {
    let public = router(security_txt(), Limits::default(), Router::new());
    let ready = Readiness::default();
    let inside = internal(health(), ready.clone(), Limits::default(), || 0);
    for path in ["/healthz", "/livez", "/readyz", "/metrics"] {
        let r = public
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND, "{path}");
    }
    let get = |path: &'static str| {
        inside
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
    };
    assert_eq!(get("/livez").await.unwrap().status(), StatusCode::OK);
    assert_eq!(get("/metrics").await.unwrap().status(), StatusCode::OK);
    // MD-8: a process that is not ready takes no traffic
    assert_eq!(
        get("/readyz").await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    ready.ready();
    assert_eq!(get("/readyz").await.unwrap().status(), StatusCode::OK);
    assert_eq!(get("/nope").await.unwrap().status(), StatusCode::NOT_FOUND);
}

// SI-13, OP-150, CR-22: the provider declarations are served without authentication and state
// that no custodial key exists
#[tokio::test]
async fn the_provider_declarations_are_public() {
    use access_http::declarations::{Declarations, PATH, Stated};
    let app = harden(
        access_http::declarations::router(&Declarations::of(Stated::default())),
        Limits::default(),
    );
    let response = app
        .oneshot(Request::get(PATH).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    let body: serde_json::Value = serde_json::from_str(&body_string(response).await).unwrap();
    assert_eq!(body["custody"], "none");
    assert_eq!(body["version"], 1);
}
