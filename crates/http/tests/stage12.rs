//! OP-157 m.4 (a): the Stage 12 routes answer `501 not-yet-served` until their lanes serve them:
//! the realm-admin rows, the Frontend API rows and any route outside both.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_http::api::realm::{ROWS, planned, spec};
use access_http::stage12::{Method, PLANNED, router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

/// The Stage 12 realm-admin operations (OP-157 m.4 (a)).
const ADMIN: [&str; 22] = [
    "listCaseSystems",
    "registerCaseSystem",
    "retireCaseSystem",
    "listSupportGrants",
    "putSupportArtifactPolicy",
    "listBreakglassAccounts",
    "markBreakglassAccount",
    "clearBreakglassAccount",
    "listBreakglassDrills",
    "listBreakglassReviews",
    "listReviews",
    "scheduleReview",
    "getReview",
    "closeReview",
    "listReviewItems",
    "keepReviewItem",
    "previewOffboarding",
    "commitOffboarding",
    "putDelegatedAdmin",
    "putApprovalInline",
    "putApprovalBatch",
    "reviewBreakglassUse",
];

/// The Stage 12 admin rows their lanes serve.
const SERVED: [&str; 21] = [
    "listBreakglassAccounts",
    "markBreakglassAccount",
    "clearBreakglassAccount",
    "listBreakglassDrills",
    "listBreakglassReviews",
    "reviewBreakglassUse",
    "listCaseSystems",
    "registerCaseSystem",
    "retireCaseSystem",
    // OP-157 m.3 (v)
    "previewOffboarding",
    "commitOffboarding",
    "putSupportArtifactPolicy",
    // OP-157 m.3 (w)
    "listReviews",
    "scheduleReview",
    "getReview",
    "closeReview",
    "listReviewItems",
    "keepReviewItem",
    // OP-157 m.3 (t)
    "putDelegatedAdmin",
    // OP-157 m.3 (m)
    "putApprovalInline",
    "putApprovalBatch",
];

// OP-157 m.4 (a)
#[test]
fn every_stage_12_admin_row_is_declared_with_its_kind_and_planned() {
    for op in ADMIN {
        assert!(ROWS.iter().any(|r| r.operation_id == op), "{op}");
        assert!(spec(op).is_some(), "{op}");
        // OP-157 m.3 (h)
        assert_eq!(planned(op), !SERVED.contains(&op), "{op}");
    }
}

// OP-157 m.4 (a)
#[tokio::test]
async fn every_declared_stage_12_route_is_not_yet_served() {
    for p in PLANNED {
        let req = match p.method {
            Method::Get => Request::get(p.path),
            Method::Post => Request::post(p.path),
        };
        let res = router()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_IMPLEMENTED, "{}", p.path);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["code"], "not-yet-served", "{}", p.path);
    }
}
