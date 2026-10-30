//! §9.5.1, L1-ADP-1…11: the `AuthZEN` 1.0 PDP checklist against the ADP surface over HTTP.
//!
//! The decision point is scripted, so each item checks the carrier, not the evaluation.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::sync::Mutex;

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Response};
use access_http::adp::adapters::{Discovery, Pep, router};
use access_http::adp::app::Service;
use access_http::adp::ports::{Clock, Pdp};
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
    fn evaluate(
        &self,
        inc: Incoming,
        _now: u64,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send {
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
        }))
    }
}

struct Fixed;

impl Clock for Fixed {
    fn now(&self) -> u64 {
        10_000
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
        Service::new(pdp, Fixed, limits.max_body_bytes),
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
    let mut req =
        Request::post("/access/v1/evaluation").header(header::CONTENT_TYPE, "application/json");
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
