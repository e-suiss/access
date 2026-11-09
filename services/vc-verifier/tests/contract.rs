//! OP-65, OP-155 m.3 (p), m.4: the committed verifier contract (`sdks/openapi/vc-verifier-v1.json`)
//! is what the route table produces, and every declared route answers `501 not-yet-served`
//! through the real router. `ACCESS_UPDATE_CONTRACTS=1` rewrites the document.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use access_vc_verifier::contract::{ROUTES, Verb, openapi};
use access_vc_verifier::router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/vc-verifier-v1.json")
}

// OP-65, OP-155 m.4
#[test]
fn committed_openapi_matches_the_code() {
    let doc = openapi();
    for r in ROUTES {
        let op = &doc["paths"][r.path][r.verb.name()];
        assert_eq!(op["operationId"], r.operation);
        assert_eq!(
            op["responses"].get("501").is_some(),
            !r.live,
            "{}",
            r.operation
        );
    }
    let ops: BTreeSet<_> = ROUTES.iter().map(|r| r.operation).collect();
    assert_eq!(ops.len(), ROUTES.len());
    let mut expected = serde_json::to_string_pretty(&doc).unwrap();
    expected.push('\n');
    let p = path();
    if std::env::var_os("ACCESS_UPDATE_CONTRACTS").is_some() {
        std::fs::write(&p, &expected).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(&p).unwrap_or_default();
    assert_eq!(
        serde_json::from_str::<Value>(&committed).ok(),
        serde_json::from_str::<Value>(&expected).ok(),
        "{} is stale; run `just vc-verifier-contract`",
        p.display()
    );
}

// OP-155 m.4
#[tokio::test]
async fn every_declared_route_answers_not_yet_served() {
    for r in ROUTES.iter().filter(|r| !r.live) {
        let uri = r.path.replace('{', "x").replace('}', "");
        let method = match r.verb {
            Verb::Get => "GET",
            Verb::Post => "POST",
        };
        let answer = router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            answer.status(),
            StatusCode::NOT_IMPLEMENTED,
            "{}",
            r.operation
        );
        assert_eq!(
            answer.headers()["content-type"],
            "application/problem+json",
            "{}",
            r.operation
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(answer.into_body(), 1 << 16).await.unwrap()).unwrap();
        assert_eq!(body["code"], "not-yet-served", "{}", r.operation);
    }
    let unknown = router()
        .oneshot(
            Request::builder()
                .uri("/vc-verifier/v1/other")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
}
