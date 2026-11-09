//! OP-65, OP-154 m.3 (u): the committed executor contract (`sdks/openapi/executor-v1.json`)
//! against the code, and every route answering `501 not-yet-served` until it is served.
//! `ACCESS_UPDATE_CONTRACTS=1` rewrites the contract.

#![allow(clippy::unwrap_used, clippy::panic, reason = "test code")]

use std::path::PathBuf;

use access_executor::contract::{ROUTES, Verb, openapi};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt as _;

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/executor-v1.json")
}

// OP-65
#[test]
fn committed_openapi_matches_the_code() {
    let mut expected = serde_json::to_string_pretty(&openapi()).unwrap();
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
        "{} is stale; run `just executor-contract`",
        p.display()
    );
}

// OP-154 m.4
#[tokio::test]
async fn every_declared_route_answers_not_yet_served() {
    for r in ROUTES {
        let uri = r.path.replace('{', "x").replace('}', "");
        let method = match r.verb {
            Verb::Get => "GET",
            Verb::Post => "POST",
        };
        let res = access_executor::router()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(&uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_IMPLEMENTED, "{}", r.operation);
    }
}

// OP-154 m.3 (u), B21
#[test]
fn the_executor_reports_and_never_decides() {
    let text = openapi().to_string();
    for forbidden in ["allow", "decision", "grant_issue", "approve"] {
        assert!(!text.contains(&format!("\"{forbidden}\"")), "{forbidden}");
    }
}
