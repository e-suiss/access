//! §9.5.1, L1-ADP-1…15: the `AuthZEN` 1.0 PDP checklist against the ADP surface over HTTP.
//!
//! The decision point is scripted, so each item checks the carrier, not the evaluation.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Mutex;

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Response};
use access_authority_core::query::{Hit, Query};
use access_http::adp::adapters::{Discovery, Pep, router};
use access_http::adp::app::Service;
use access_http::adp::ports::{Page, Pdp};
use access_http::{Limits, harden};
use access_kernel::combinator::{Decision, Outcome};
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;

/// Answers with a fixed outcome and remembers what it was asked.
struct Scripted {
    outcome: Result<Outcome, fn() -> CoreError>,
    seen: Mutex<Vec<Incoming>>,
}

impl Pdp for Scripted {
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send {
        self.seen.lock().unwrap().push(inc);
        std::future::ready(self.outcome.map_err(|f| f()).map(|outcome| Response {
            decision: Decision {
                outcome,
                blockers: Vec::new(),
                unmet: Vec::new(),
                relied_on: Vec::new(),
            },
            exercise: (outcome == Outcome::Allow).then_some(Digest([8; 32])),
            record: Some(3),
            replayed: false,
            basis_ref: Some(String::from("ref")),
            consistency: Some(String::from("seen")),
        }))
    }

    fn search(
        &self,
        _inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> impl Future<Output = Result<Page, CoreError>> + Send {
        let hit = match query {
            Query::Subject { .. } => Hit::Party(access_kernel::model::Id([7; 16])),
            _ => Hit::Public,
        };
        std::future::ready(Ok((
            vec![hit],
            page.is_none().then(|| String::from("next")),
        )))
    }
}

const ISSUER: &str = "https://pdp.example";

fn app(outcome: Result<Outcome, fn() -> CoreError>, pep: Option<&str>) -> Router {
    let pdp = Scripted {
        outcome,
        seen: Mutex::new(Vec::new()),
    };
    let limits = Limits::default();
    let routes = router(
        Service::new(pdp, limits.max_body_bytes),
        Discovery {
            issuer: ISSUER.to_owned(),
        },
    );
    let routes = match pep {
        Some(p) => routes.layer(axum::Extension(Pep(p.to_owned()))),
        None => routes,
    };
    harden(routes, limits)
}

fn evaluation(mode: &str, extra: &str) -> String {
    let b = |bytes: &[u8]| b64url_encode(bytes);
    format!(
        r#"{{"subject": {{"type": "user", "id": "alice", "properties": {{"department": "x"}}}},
            "action": {{"name": "read", "properties": {{"vendor": true}}}},
            "resource": {{"type": "shop", "id": "item-1"}},
            "context": {{
                "domain": "{d}", "mode": "{mode}", "nonce": "{n}",
                "basis": {{"anchor": "{a}"}}, "capacity": "own",
                "intent": {{
                    "action": {{"namespace": "shop", "name": "read", "major": 1, "schema": "{s}"}},
                    "resources": [{{"namespace": "shop", "path": ["item-1"]}}],
                    "validity": {{"from": 0, "until": 100000}}
                }}{extra}
            }}}}"#,
        d = b(&[1; 32]),
        n = b(&[2; 16]),
        a = b(&[3; 16]),
        s = b(&[5; 32]),
    )
}

async fn post(
    app: Router,
    body: String,
    request_id: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    post_to(app, "/access/v1/evaluation", body, request_id).await
}

async fn post_to(
    app: Router,
    path: &str,
    body: String,
    request_id: Option<&str>,
) -> (StatusCode, Option<String>, Value) {
    let mut req = Request::post(path).header(header::CONTENT_TYPE, "application/json");
    if let Some(id) = request_id {
        req = req.header("x-request-id", id);
    }
    let resp = app
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let echoed = resp
        .headers()
        .get("x-request-id")
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        echoed,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

// #1
#[tokio::test]
async fn evaluation_answers_allow_with_true() {
    let (status, _, body) = post(
        app(Ok(Outcome::Allow), Some("pep-1")),
        evaluation("commit", ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["decision"], true);
    assert_eq!(body["context"]["outcome"], "allow");
    assert_eq!(body["context"]["exercise"], b64url_encode(&[8; 32]));
}

// #7, R2
#[tokio::test]
async fn deny_and_require_action_are_200_false() {
    for (o, word) in [
        (Outcome::Deny, "deny"),
        (Outcome::RequireAction, "require_action"),
    ] {
        let (status, _, body) =
            post(app(Ok(o), Some("pep-1")), evaluation("commit", ""), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["decision"], false);
        assert_eq!(body["context"]["outcome"], word);
    }
}

// #7: a protocol error is 400, never a decision
#[tokio::test]
async fn a_protocol_error_is_400_problem() {
    let broken =
        evaluation("commit", "").replace(r#""capacity": "own""#, r#""capacity": "theirs""#);
    let (status, _, body) = post(app(Ok(Outcome::Allow), Some("pep-1")), broken, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "capacity");
    assert!(body.get("decision").is_none());
}

// #7: core refusals keep their classes
#[tokio::test]
async fn core_refusals_map_to_their_status() {
    let cases: [(fn() -> CoreError, StatusCode); 3] = [
        (|| CoreError::Nonce, StatusCode::UNPROCESSABLE_ENTITY),
        (|| CoreError::Protocol("domain"), StatusCode::BAD_REQUEST),
        (|| CoreError::Passes, StatusCode::BAD_REQUEST),
    ];
    for (err, want) in cases {
        let (status, _, body) =
            post(app(Err(err), Some("pep-1")), evaluation("commit", ""), None).await;
        assert_eq!(status, want);
        assert!(body.get("decision").is_none());
    }
}

// #6
#[tokio::test]
async fn discovery_names_the_pdp_and_the_profile() {
    let resp = app(Ok(Outcome::Allow), None)
        .oneshot(
            Request::get("/.well-known/authzen-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["policy_decision_point"], ISSUER);
    assert_eq!(
        body["access_evaluation_endpoint"],
        format!("{ISSUER}/access/v1/evaluation")
    );
    assert!(
        body["capabilities"]
            .as_array()
            .unwrap()
            .contains(&Value::from("urn:esuiss:access:adp:1"))
    );
}

// #8
#[tokio::test]
async fn the_request_id_is_echoed() {
    let (_, echoed, _) = post(
        app(Ok(Outcome::Deny), Some("pep-1")),
        evaluation("commit", ""),
        Some("req-42"),
    )
    .await;
    assert_eq!(echoed.as_deref(), Some("req-42"));
}

// #9: carrier fields are forward compatible, Access members are must-understand
#[tokio::test]
async fn unknown_members_split_by_carrier() {
    let (status, _, _) = post(
        app(Ok(Outcome::Allow), Some("pep-1")),
        evaluation("commit", ""),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unknown subject/action properties are ignored"
    );
    let (status, _, body) = post(
        app(Ok(Outcome::Allow), Some("pep-1")),
        evaluation("commit", r#", "tenant_id": "acme""#),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "unknown-member");
}

// #10, L1-ADP-2
#[tokio::test]
async fn an_unauthenticated_pep_is_401_and_not_evaluated() {
    let (status, _, body) = post(
        app(Ok(Outcome::Allow), None),
        evaluation("commit", ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "pep-unauthenticated");
}

// #11
#[tokio::test]
async fn floats_and_duplicates_are_refused() {
    let float = evaluation("commit", "").replace(r#""until": 100000"#, r#""until": 1e5"#);
    let (status, _, _) = post(app(Ok(Outcome::Allow), Some("pep-1")), float, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let dup = evaluation("commit", "").replace(
        r#""mode": "commit""#,
        r#""mode": "check", "mode": "commit""#,
    );
    let (status, _, _) = post(app(Ok(Outcome::Allow), Some("pep-1")), dup, None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// #12
#[tokio::test]
async fn an_oversized_body_is_refused() {
    let big = evaluation(
        "commit",
        &format!(r#", "pad": "{}""#, "a".repeat(300 * 1024)),
    );
    let (status, _, _) = post(app(Ok(Outcome::Allow), Some("pep-1")), big, None).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

// §9.5 Decision Response: `check` is advisory
#[tokio::test]
async fn check_is_marked_advisory() {
    let (_, _, body) = post(
        app(Ok(Outcome::Allow), Some("pep-1")),
        evaluation("check", ""),
        None,
    )
    .await;
    assert_eq!(body["context"]["advisory"], true);
}

/// A batch whose items carry their own context and inherit the top-level carriers.
fn batch(modes: &[&str], semantic: &str) -> String {
    let items: Vec<String> = modes
        .iter()
        .map(|m| {
            let one: Value = serde_json::from_str(&evaluation(m, "")).unwrap();
            serde_json::json!({ "context": one["context"] }).to_string()
        })
        .collect();
    format!(
        r#"{{"subject": {{"type": "user", "id": "alice"}}, "action": {{"name": "read"}},
            "resource": {{"type": "shop", "id": "item-1"}},
            "options": {{"evaluations_semantic": "{semantic}"}},
            "evaluations": [{}]}}"#,
        items.join(",")
    )
}

// #3 (batch), OP-141 m.22 (a): each item is answered like a single evaluation
#[tokio::test]
async fn a_batch_answers_each_item() {
    let (status, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/evaluations",
        batch(&["commit", "check"], "execute_all"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["evaluations"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["decision"], true);
    assert_eq!(items[1]["context"]["advisory"], true);
}

// OP-141 m.22 (a): a short-circuit is check-only; skipped items are not denials
#[tokio::test]
async fn a_short_circuit_is_for_check_only() {
    let (status, _, body) = post_to(
        app(Ok(Outcome::Deny), Some("pep-1")),
        "/access/v1/evaluations",
        batch(&["check", "check"], "deny_on_first_deny"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["evaluations"][0]["decision"], false);
    assert_eq!(body["evaluations"][1]["evaluated"], false);
    let (status, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/evaluations",
        batch(&["check", "commit"], "permit_on_first_permit"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "evaluations_semantic");
}

// OP-141 m.22 (a): an item's protocol error stays with the item
#[tokio::test]
async fn an_item_error_stays_with_its_item() {
    let mut body: Value =
        serde_json::from_str(&batch(&["commit", "commit"], "execute_all")).unwrap();
    body["evaluations"][1]["context"]["hint"] = Value::from(1);
    let (status, _, out) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/evaluations",
        body.to_string(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(out["evaluations"][0]["decision"], true);
    assert_eq!(out["evaluations"][1]["error"], "unknown-member");
}

// OP-141 m.22 (h): a hypothetical explanation is a check labelled hypothetical; a recorded one
// is not offered yet
#[tokio::test]
async fn explain_is_hypothetical_check() {
    let (status, _, body) = post_to(
        app(Ok(Outcome::Deny), Some("pep-1")),
        "/access/v1/explain",
        evaluation("check", ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["context"]["kind"], "hypothetical");
    assert_eq!(body["context"]["advisory"], true);
    let (status, _, body) = post_to(
        app(Ok(Outcome::Deny), Some("pep-1")),
        "/access/v1/explain",
        evaluation("commit", ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "explain-mode");
}

fn search_body(query: &str, page: &str) -> String {
    let b = |bytes: &[u8]| b64url_encode(bytes);
    format!(
        r#"{{"subject": {{"type": "access_party"}}, "action": {{"name": "read"}},
            "context": {{
                "domain": "{d}", "mode": "check", "nonce": "{n}",
                "basis": {{"public": "{a}"}}, "capacity": "own",
                "intent": {{
                    "action": {{"namespace": "access", "name": "search", "major": 1, "schema": "{s}"}},
                    "resources": [{{"namespace": "access.search", "path": ["subject"]}}],
                    "validity": {{"from": 0, "until": 100000}}
                }},
                "query": {query}
            }}{page}}}"#,
        d = b(&[1; 32]),
        n = b(&[2; 16]),
        a = b(&[3; 16]),
        s = b(&[5; 32]),
    )
}

// #3–5 (search), L1-ADP-16, OP-141 m.22 (b): results with an opaque next page, advisory
#[tokio::test]
async fn search_pages_through_results() {
    let q = format!(
        r#"{{"action": {{"namespace": "shop", "name": "read", "major": 1, "schema": "{}"}},
            "resource": {{"namespace": "shop", "path": ["item-1"]}}}}"#,
        b64url_encode(&[5; 32])
    );
    let (status, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/search/subject",
        search_body(&q, ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["results"][0]["type"], "access_party");
    assert_eq!(body["page"]["next_token"], "next");
    assert_eq!(body["context"]["advisory"], true);
    let (_, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/search/subject",
        search_body(&q, r#", "page": {"token": "next"}"#),
        None,
    )
    .await;
    assert_eq!(body["page"]["next_token"], "");
    let (status, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/search/everything",
        search_body(&q, ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "search");
}
