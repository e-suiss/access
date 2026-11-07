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

fn scripted(s: &Scripted, inc: Incoming) -> Result<Response, CoreError> {
    s.seen.lock().unwrap().push(inc);
    s.outcome.map_err(|f| f()).map(|outcome| Response {
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
        receipt: None,
        signed_receipt: None,
        pap: None,
        signed_pap: None,
        ended: Vec::new(),
        explained: None,
    })
}

/// Answers with a fixed outcome and remembers what it was asked.
struct Scripted {
    outcome: Result<Outcome, fn() -> CoreError>,
    seen: Mutex<Vec<Incoming>>,
}

impl Pdp for Scripted {
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send {
        std::future::ready(scripted(self, inc))
    }

    fn explain_recorded(
        &self,
        inc: Incoming,
        record: u64,
        _scope: access_authority_core::app::Scope,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send {
        let mut r = scripted(self, inc);
        if let Ok(resp) = &mut r {
            resp.record = Some(record);
        }
        std::future::ready(r)
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

    fn metadata(&self, domain: Digest) -> impl Future<Output = Option<Vec<u8>>> + Send {
        std::future::ready((domain == SIGNED).then(|| METADATA.to_vec()))
    }
}

/// The one domain whose signer has Domain Metadata, and its (opaque) `COSE_Sign1` bytes.
const SIGNED: Digest = Digest([1; 32]);
const METADATA: [u8; 4] = [0xd2, 0x84, 0x40, 0xa0];

fn domain_text(d: Digest) -> String {
    format!("sha-256:{}", b64url_encode(&d.0))
}

async fn get(path: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let resp = app(Ok(Outcome::Allow), None)
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
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
    // PI-5, G16
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
            .contains(&Value::from("urn:suiss:access:adp:1"))
    );
    assert!(body.get("signed_metadata").is_none());
}

// §9.15.1, OP-143 m.4, T29, TI-RT5, OP-150 m.3 (q): the signer's Domain Metadata is served as
// signed, with its media type and a cache lifetime that, stale copies included, never passes
// one hour
#[tokio::test]
async fn domain_metadata_is_served_as_signed() {
    let (status, headers, body) = get(&format!(
        "/.well-known/access-domain-metadata/{}",
        domain_text(SIGNED)
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers[header::CONTENT_TYPE],
        "application/access-domain-metadata+cbor"
    );
    let cache = headers[header::CACHE_CONTROL].to_str().unwrap();
    assert_eq!(cache, access_http::adp::adapters::METADATA_CACHE);
    let secs = |name: &str| -> u64 {
        cache
            .split(", ")
            .find_map(|d| d.strip_prefix(name)?.strip_prefix('='))
            .unwrap()
            .parse()
            .unwrap()
    };
    let fresh = secs("max-age");
    assert!(
        fresh + secs("stale-while-revalidate") <= access_http::adp::adapters::METADATA_MAX_AGE_S
    );
    assert!(fresh + secs("stale-if-error") <= access_http::adp::adapters::METADATA_MAX_AGE_S);
    assert_eq!(body, METADATA);
}

// §9.15.1, OP-143 m.4: no signed document, or no DomainID in its text form, is a 404, never an
// unsigned document
#[tokio::test]
async fn domain_metadata_without_a_signature_is_not_found() {
    let b = b64url_encode(&SIGNED.0);
    for domain in [
        domain_text(Digest([2; 32])),
        b.clone(),
        format!("sha-256:{b}="),
        format!("sha-256:{}", b64url_encode(&[1; 31])),
        format!("sha-512:{b}"),
    ] {
        for path in [
            format!("/.well-known/access-domain-metadata/{domain}"),
            format!("/.well-known/authzen-configuration/{domain}"),
        ] {
            let (status, headers, body) = get(&path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(headers[header::CONTENT_TYPE], "application/problem+json");
            let problem: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(problem["code"], "domain-metadata-unavailable");
            // OP-149 m.12
            assert_eq!(
                problem["type"],
                "urn:suiss:access:problem:domain-metadata-unavailable"
            );
        }
    }
}

// §9.5.1 #6, MD-3: a domain's discovery document names the domain's PDP identifier and carries
// its signed Domain Metadata
#[tokio::test]
async fn domain_discovery_carries_signed_metadata() {
    let domain = domain_text(SIGNED);
    let (status, _, body) = get(&format!("/.well-known/authzen-configuration/{domain}")).await;
    assert_eq!(status, StatusCode::OK);
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["policy_decision_point"], format!("{ISSUER}/{domain}"));
    assert_eq!(
        body["access_evaluation_endpoint"],
        format!("{ISSUER}/access/v1/evaluation")
    );
    assert_eq!(body["signed_metadata"], b64url_encode(&METADATA));
    assert!(
        body["capabilities"]
            .as_array()
            .unwrap()
            .contains(&Value::from("urn:suiss:access:adp:1"))
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
    // PI-23, G26
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
    // PI-23
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

// OP-141 m.22 (h), m.36: a hypothetical explanation is a check labelled hypothetical; with
// `record` it is the recorded decision, labelled recorded; `record` elsewhere is unknown
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
    let (status, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/explain",
        evaluation("commit", r#", "record": 7"#),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["context"]["kind"], "recorded");
    assert_eq!(body["context"]["record"], 7);
    let (status, _, body) = post_to(
        app(Ok(Outcome::Allow), Some("pep-1")),
        "/access/v1/explain",
        evaluation("check", r#", "scope": "viewer""#),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "scope");
    let (status, _, _) = post(
        app(Ok(Outcome::Allow), Some("pep-1")),
        evaluation("commit", r#", "record": 7"#),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

fn search_body(query: &str, page: &str) -> String {
    let b = |bytes: &[u8]| b64url_encode(bytes);
    format!(
        r#"{{"subject": {{"type": "access_party"}}, "action": {{"name": "read"}},
            "context": {{
                "domain": "{d}", "mode": "check", "nonce": "{n}",
                "basis": {{"public": "{a}"}}, "capacity": "own",
                "intent": {{
                    "action": {{"namespace": "access", "name": "read", "major": 1, "schema": "{s}"}},
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

// §13.7.4, OP-35, OP-141 m.23: over a rate limit is 429 with no decision
#[tokio::test]
async fn a_rate_limit_is_429() {
    let (status, _, body) = post(
        app(Err(|| CoreError::Limited), Some("pep-1")),
        evaluation("commit", ""),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate-limited");
}

// OP-141 m.25: a limit is the batch's answer, never an error inside a 200
#[tokio::test]
async fn a_rate_limited_batch_is_429() {
    let (status, _, body) = post_to(
        app(Err(|| CoreError::Limited), Some("pep-1")),
        "/access/v1/evaluations",
        batch(&["check", "check"], "execute_all"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "rate-limited");
}

// §9.15.1 k.2, P60, MD-5: Domain Metadata, the realm's AS metadata and the authzen
// configuration are three documents; none stands in for another, and the identity document's
// issuer is no authority claim
#[tokio::test]
async fn the_three_discovery_documents_stay_separate() {
    use access_identity_oauth::domain::issuer::Issuer;
    use access_identity_oauth::domain::metadata::{SERVED, authorization_server};
    let domain = domain_text(SIGNED);
    let (_, md_headers, md) = get(&format!("/.well-known/access-domain-metadata/{domain}")).await;
    let (_, az_headers, az) = get(&format!("/.well-known/authzen-configuration/{domain}")).await;
    assert_eq!(
        md_headers[header::CONTENT_TYPE],
        "application/access-domain-metadata+cbor"
    );
    assert_eq!(az_headers[header::CONTENT_TYPE], "application/json");
    assert!(serde_json::from_slice::<Value>(&md).is_err());
    let az: Value = serde_json::from_slice(&az).unwrap();
    let issuer = Issuer::parse("https://acme.id.example").unwrap();
    let as_meta: Value = serde_json::from_str(&authorization_server(&issuer, &SERVED)).unwrap();
    for authority in [
        "signed_metadata",
        "policy_decision_point",
        "operational_keys",
        "access_evaluation_endpoint",
    ] {
        assert!(as_meta.get(authority).is_none(), "{authority}");
    }
    for identity in [
        "issuer",
        "jwks_uri",
        "token_endpoint",
        "authorization_endpoint",
    ] {
        assert!(az.get(identity).is_none(), "{identity}");
    }
    assert_eq!(az["signed_metadata"], b64url_encode(&md));
}
