//! The experience routes against a fake Access (CMP-16, OP-153 m.3 (v)): a read that is not a
//! hub read for the viewer never leaves the service, an unanswered domain is unknown, and the
//! stream carries `{kind, at_least}` only.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unused_async_trait_impl,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::{Arc, Mutex};

use access_experience::adapters::{Beacon, router};
use access_experience::app::Experience;
use access_experience::contract::{Kind, Plan};
use access_experience::ports::{Clock, Random, Upstream};
use access_kernel::json::b64url_encode;
use access_sdk::transport::{Answer, Fault, Response};
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

#[derive(Clone, Default)]
struct Fake(Arc<Mutex<Vec<(String, Kind)>>>);

impl Upstream for Fake {
    async fn search(&self, domain: &str, kind: Kind, _body: Vec<u8>) -> Answer {
        self.0.lock().unwrap().push((domain.to_owned(), kind));
        if domain == b64url_encode(&[2; 32]) {
            return Answer::Unanswered(Fault::Unreachable);
        }
        Answer::Response(Response::new(
            200,
            json!({ "results": [], "page": {}, "context": { "advisory": true } })
                .to_string()
                .into_bytes(),
        ))
    }
}

struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> u64 {
        1_000_000
    }
}

impl Random for Fixed {
    fn nonce(&self) -> Option<[u8; 16]> {
        Some([7; 16])
    }
}

async fn post(app: &axum::Router, path: &str, body: &Value) -> (StatusCode, Value) {
    let r = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let bytes = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn viewer() -> String {
    b64url_encode(&[1; 16])
}

// XI-22, XI-18, OP-153 m.3 (v), XI-16
#[tokio::test]
async fn only_hub_reads_for_the_viewer_are_forwarded() {
    let fake = Fake::default();
    let app = router(
        Experience::new(fake.clone(), Fixed, Fixed, "pep-x5t".to_owned()),
        Beacon::default(),
    );
    let reachable = b64url_encode(&[1; 32]);
    let unreachable = b64url_encode(&[2; 32]);
    let (status, plan) = post(
        &app,
        "/experience/v1/hub/plan",
        &json!({ "viewer": viewer(), "domains": [{ "domain": reachable }, { "domain": unreachable }], "kinds": ["inventory"] }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let plan: Plan = serde_json::from_value(plan).unwrap();
    assert_eq!(plan.pep, "pep-x5t");
    assert_eq!(plan.reads.len(), 2);
    let signed: Vec<Value> = plan
        .reads
        .iter()
        .map(|r| {
            let mut body = r.body.clone();
            body["context"]["ais"] = json!("c2lnbmVk");
            json!({ "domain": r.domain, "kind": r.kind, "body": body })
        })
        .collect();

    let mut commit = signed[0].clone();
    commit["body"]["context"]["mode"] = json!("commit");
    let mut other = signed[0].clone();
    other["body"]["context"]["query"]["party"] = json!(b64url_encode(&[9; 16]));
    for refused in [commit, other] {
        let (status, problem) = post(
            &app,
            "/experience/v1/hub",
            &json!({ "viewer": viewer(), "reads": [refused] }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(problem["type"], "urn:suiss:access:problem:invalid-request");
    }
    assert!(fake.0.lock().unwrap().is_empty(), "nothing was forwarded");

    let (status, hub) = post(
        &app,
        "/experience/v1/hub",
        &json!({ "viewer": viewer(), "reads": signed }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let domains = hub["domains"].as_array().unwrap();
    assert_eq!(domains[0]["freshness"], "current");
    assert_eq!(domains[0]["as_of"], 1_000_000);
    assert_eq!(domains[1]["freshness"], "unknown");
    assert!(domains[1].get("as_of").is_none());
    assert!(
        hub["notices"]
            .as_array()
            .unwrap()
            .contains(&json!("hub.not_shown_unconnected"))
    );
}

// OP-153 m.3 (v), §17.3.1, XI-3
#[tokio::test]
async fn the_stream_says_read_again_and_nothing_more() {
    let beacon = Beacon::default();
    let app = router(
        Experience::new(Fake::default(), Fixed, Fixed, "pep".to_owned()),
        beacon.clone(),
    );
    let r = app
        .oneshot(
            Request::get("/experience/v1/stream")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.headers()["content-type"], "text/event-stream");
    beacon.notify(41);
    beacon.notify(40);
    let mut body = r.into_body().into_data_stream();
    let first = futures_util::StreamExt::next(&mut body)
        .await
        .unwrap()
        .unwrap();
    let text = String::from_utf8(first.to_vec()).unwrap();
    assert!(text.contains("event: authority"), "{text}");
    let data: Value =
        serde_json::from_str(text.lines().find_map(|l| l.strip_prefix("data: ")).unwrap()).unwrap();
    assert_eq!(data, json!({ "kind": "authority", "at_least": 41 }));
}
