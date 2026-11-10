//! OP-156 m.4: the Stage 11 routes outside the manifests answer `501 not-yet-served` until
//! their lanes serve them.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_http::stage11::{Method, PLANNED, PROXY_ENGINES, router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use tower::ServiceExt as _;

// OP-156 m.4, m.3 (c), (l), (t)
#[tokio::test]
async fn every_declared_stage_11_route_is_not_yet_served() {
    for p in PLANNED {
        let paths: Vec<String> = if p.path.contains("{engine}") {
            PROXY_ENGINES
                .iter()
                .map(|e| p.path.replace("{engine}", e))
                .collect()
        } else {
            vec![p.path.to_owned()]
        };
        for path in paths {
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
}

// OP-156 m.3 (c), (l)
#[test]
fn the_relay_callback_is_declared_and_the_forward_auth_checks_are_served() {
    let ops: Vec<_> = PLANNED.iter().map(|p| p.operation).collect();
    for op in ["proxyCheck", "proxyCheckPost", "relayIysStatus"] {
        assert!(!ops.contains(&op), "{op}");
    }
}
