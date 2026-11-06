//! Harness self-test in process with paused time (OP-150 m.1 (a)): the fail-closed
//! reference passes every case, the negative control is flagged on every fault it ignores,
//! and timeouts land exactly on the deadline.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use access_pep_conformance::case::{Case, Dpop, Expect, Mode, Reply, TokenFault, TokenKind, load};
use access_pep_conformance::fixture::Fixture;
use access_pep_conformance::protocol::{CaseMessage, CaseResult, Outcome};
use access_pep_conformance::reference::{Fetch, Fetched, Leaky, Machine, Reference, Step};
use access_pep_conformance::run::{Adapter, AdapterError, CaseReport, run};
use access_pep_conformance::upstream::Upstream;
use access_pep_conformance::verdict::Verdict;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use tokio::time::{Instant, timeout};
use tower::ServiceExt;

const BASE: &str = "http://upstream.test";
const DEADLINE_MS: u64 = 500;

fn cases() -> Vec<Case> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/pep/cases");
    load(&dir).unwrap()
}

struct InProcess<M> {
    router: Router,
    new: fn(CaseMessage, u32) -> M,
}

async fn fetch(router: &Router, f: &Fetch, until: Instant) -> Fetched {
    let path = f.url.strip_prefix(BASE).unwrap();
    let builder = Request::builder().method(f.method).uri(path);
    let request = match &f.body {
        Some((content_type, body)) => builder
            .header("content-type", *content_type)
            .body(Body::from(body.clone())),
        None => builder.body(Body::empty()),
    }
    .unwrap();
    match tokio::time::timeout_at(until, router.clone().oneshot(request)).await {
        Err(_) => Fetched::Failed(String::from("deadline passed")),
        Ok(Err(e)) => Fetched::Failed(e.to_string()),
        Ok(Ok(response)) => Fetched::Response {
            status: response.status().as_u16(),
            body: response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        },
    }
}

impl<M: Machine> InProcess<M> {
    async fn present(&self, msg: &CaseMessage, attempt: u32) -> (Outcome, String) {
        let budget = Duration::from_millis(msg.deadline_ms);
        let until = Instant::now() + budget;
        let mut machine = (self.new)(msg.clone(), attempt);
        let mut fetched = None;
        loop {
            match machine.step(fetched.take()) {
                Step::Fetch(f) => fetched = Some(fetch(&self.router, &f, until).await),
                Step::Effect => {
                    let effect = Fetch {
                        method: "POST",
                        url: msg.upstream.effect.clone(),
                        body: None,
                    };
                    break match fetch(&self.router, &effect, Instant::now() + budget).await {
                        Fetched::Response { status: 204, .. } => (Outcome::Allow, String::new()),
                        other => (Outcome::Error, format!("{other:?}")),
                    };
                }
                Step::Deny(why) => break (Outcome::Deny, why),
                Step::Error(why) => break (Outcome::Error, why),
            }
        }
    }

    async fn drive(&self, msg: &CaseMessage) -> CaseResult {
        let mut allowed = false;
        let mut last = (Outcome::Error, String::new());
        for attempt in 0..msg.request.repeat.max(1) {
            last = self.present(msg, attempt).await;
            allowed |= last.0 == Outcome::Allow;
        }
        let (outcome, detail) = if allowed {
            (Outcome::Allow, String::new())
        } else {
            last
        };
        CaseResult {
            case: msg.case.clone(),
            outcome,
            detail: Some(detail),
        }
    }
}

impl<M: Machine> Adapter for InProcess<M> {
    async fn exchange(
        &mut self,
        msg: &CaseMessage,
        wait: Duration,
    ) -> Result<Option<CaseResult>, AdapterError> {
        Ok(timeout(wait, self.drive(msg)).await.ok())
    }
}

async fn run_with<M: Machine>(cases: &[Case], new: fn(CaseMessage, u32) -> M) -> Vec<CaseReport> {
    let upstream = Arc::new(Upstream::new(BASE, cases, Fixture::generate().unwrap()));
    let mut adapter = InProcess {
        router: Arc::clone(&upstream).router(),
        new,
    };
    run(
        &upstream,
        cases,
        &mut adapter,
        DEADLINE_MS,
        Duration::from_secs(2),
    )
    .await
    .unwrap()
}

// CMP-17, X21, TI-9, INV-26, L2-RCP-3, E25, E28
#[tokio::test(start_paused = true)]
async fn the_fail_closed_reference_passes_every_case() {
    let reports = run_with(&cases(), Reference::new).await;
    let failed: Vec<_> = reports.iter().filter(|r| !r.verdict.passed()).collect();
    assert!(failed.is_empty(), "{failed:#?}");
}

// CMP-17, X21, TI-9, INV-26
#[tokio::test(start_paused = true)]
async fn the_leaky_control_is_flagged_on_every_fault_it_ignores() {
    let reports = run_with(&cases(), Leaky::new).await;
    let leaked: BTreeSet<&str> = reports
        .iter()
        .filter(|r| matches!(r.verdict, Verdict::Leak { .. }))
        .map(|r| r.id.as_str())
        .collect();
    let expected: BTreeSet<&str> = [
        "adp-500",
        "adp-503",
        "adp-allow-without-receipt",
        "adp-malformed-body",
        "adp-receipt-other-audience",
        "adp-receipt-other-intent",
        "adp-timeout",
        "introspection-500",
        "introspection-503",
        "jwks-500",
        "jwks-timeout",
        "jwt-dpop-missing",
        "jwt-dpop-other-key",
        "jwt-dpop-replay",
        "jwt-exact-intent-reuse",
        "jwt-other-audience",
        "jwt-oversized",
        "status-list-503",
        "status-list-stale",
    ]
    .into_iter()
    .collect();
    assert_eq!(leaked, expected);
    let other: Vec<_> = reports
        .iter()
        .filter(|r| !leaked.contains(r.id.as_str()) && !r.verdict.passed())
        .collect();
    assert!(other.is_empty(), "{other:#?}");
}

// E25, E28, X21
#[tokio::test(start_paused = true)]
async fn a_hanging_upstream_ends_exactly_at_the_deadline() {
    let all = cases();
    let hang: Vec<Case> = all.into_iter().filter(|c| c.id == "adp-timeout").collect();
    let start = Instant::now();
    let reports = run_with(&hang, Reference::new).await;
    assert_eq!(start.elapsed(), Duration::from_millis(DEADLINE_MS));
    assert_eq!(reports[0].outcome, Some(Outcome::Error));
    assert_eq!(reports[0].effects, 0);
}

// CMP-17, X21, OP-150 m.1 (a)
#[test]
fn the_cases_cover_every_named_fault_and_a_control_per_mode() {
    let all = cases();
    let has = |f: &dyn Fn(&Case) -> bool| all.iter().any(f);
    let status_5xx =
        |r: &Option<Reply>| matches!(r, Some(Reply::Status { status }) if *status >= 500);
    assert!(has(&|c| matches!(
        c.adp,
        Some(Reply::Status { status: 503 })
    )));
    assert!(has(&|c| c.adp == Some(Reply::Hang)));
    assert!(has(&|c| matches!(c.adp, Some(Reply::Raw { .. }))));
    assert!(has(&|c| c.adp
        == Some(Reply::Decision {
            decision: true,
            receipt: false
        })));
    assert!(has(&|c| c.mode == Mode::Decision
        && c.intent.is_some()
        && c.expect == Expect::Deny));
    assert!(has(&|c| c.mode == Mode::Decision
        && c.audience.is_some()
        && c.expect == Expect::Deny));
    assert!(has(
        &|c| matches!(&c.introspection, Some(Reply::Json { body, .. }) if body["active"] == false)
    ));
    assert!(has(&|c| status_5xx(&c.introspection)));
    assert!(has(&|c| status_5xx(&c.jwks)));
    assert!(has(&|c| matches!(
        c.status_list,
        Some(Reply::List { stale: true, .. })
    )));
    // §9.9.3 k.2, §13.4 U55, §9.9.1, OP-150 m.3 (s): the token-side faults
    assert!(has(
        &|c| c.dpop == Some(Dpop::Missing) && c.expect == Expect::Deny
    ));
    assert!(has(
        &|c| c.dpop == Some(Dpop::OtherKey) && c.expect == Expect::Deny
    ));
    assert!(has(&|c| c.dpop == Some(Dpop::Replayed)
        && c.repeat == Some(2)
        && c.kind == Some(TokenKind::Bounds)
        && c.expect == Expect::Effect));
    assert!(has(&|c| c.dpop.is_none()
        && c.repeat == Some(2)
        && c.kind.is_none()
        && c.expect == Expect::Effect));
    assert!(has(&|c| c.token == Some(TokenFault::Oversized)));
    assert!(has(
        &|c| c.token == Some(TokenFault::OtherAudience) && c.expect == Expect::Deny
    ));
    for mode in [Mode::Decision, Mode::Introspection, Mode::Jwt] {
        assert_eq!(
            all.iter()
                .filter(|c| c.mode == mode
                    && c.expect == Expect::Effect
                    && c.repeat.is_none()
                    && c.kind.is_none())
                .count(),
            1,
            "{mode:?}"
        );
    }
}
