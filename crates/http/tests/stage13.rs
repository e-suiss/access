//! OP-158 m.4 (a): the Stage 13 routes answer `501 not-yet-served` until their lanes serve them:
//! the realm-admin rows and the routes outside the realm-admin manifest.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_http::api::realm::{ROWS, planned, spec};
use access_http::stage13::{Method, PLANNED, router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

/// The Stage 13 realm-admin operations (OP-158 m.4 (a)).
const ADMIN: [&str; 8] = [
    "getPlacement",
    "getDurability",
    "putResidency",
    "putDrProfile",
    "putRateLimit",
    "putCryptoProfile",
    "putHashProfile",
    "putAuditTier",
];

/// The Stage 13 admin rows their lanes serve.
// OP-158 m.3 (w), (y)
const SERVED: [&str; 3] = ["putAuditTier", "putCryptoProfile", "putHashProfile"];

// OP-158 m.4 (a)
#[test]
fn every_stage_13_admin_row_is_declared_with_its_kind_and_planned() {
    for op in ADMIN {
        assert!(ROWS.iter().any(|r| r.operation_id == op), "{op}");
        assert!(spec(op).is_some(), "{op}");
        assert_eq!(planned(op), !SERVED.contains(&op), "{op}");
    }
    assert!(ROWS.iter().any(|r| r.operation_id == "rehomeRealm"));
}

// OP-158 m.4 (a)
#[tokio::test]
async fn every_declared_stage_13_route_is_not_yet_served() {
    assert_eq!(PLANNED.len(), 2);
    for p in PLANNED {
        let path = p
            .path
            .replace("{domain}", "ZG9tYWlu")
            .replace("{export}", "e1")
            .replace("{size}", "9")
            .replace("{position}", "3");
        let req = match p.method {
            Method::Get => Request::get(&path),
            Method::Post => Request::post(&path),
        };
        let res = router()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_IMPLEMENTED, "{path}");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "not-yet-served", "{path}");
    }
}
