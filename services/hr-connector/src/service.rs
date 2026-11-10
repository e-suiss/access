//! The connector service (OP-156 m.3 (q)): one connector, run on its schedule or on request,
//! its runs recorded in its own database and served under `/hr-connector/v1/*`.

use std::sync::Arc;

use access_kernel::json::{b64url_decode, b64url_encode};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};

use crate::app::{Connector, Report, RunError, run};
use crate::ports::{Access, Clock, Pull, Random, Sign};
use crate::store::{Run, Store};

/// The service's parts.
pub struct Service<P, A, S, R, C> {
    /// The connector.
    pub connector: Connector,
    /// The HR system.
    pub pull: P,
    /// Access.
    pub access: A,
    /// The connector Instance's key.
    pub sign: S,
    /// Randomness.
    pub random: R,
    /// Time.
    pub clock: C,
    /// The run history.
    pub store: Store,
    /// One run at a time.
    pub running: tokio::sync::Mutex<()>,
}

fn reason(e: &RunError) -> &'static str {
    match e {
        RunError::Listing => "vendor-listing",
        RunError::Signature => "signature",
        RunError::Fault(crate::ports::Fault::Unreachable) => "unreachable",
        RunError::Fault(crate::ports::Fault::Malformed) => "malformed",
        RunError::Fault(crate::ports::Fault::Refused(..)) => "refused",
        RunError::Fault(crate::ports::Fault::Credential) => "credential",
    }
}

impl<P: Pull, A: Access, S: Sign, R: Random, C: Clock> Service<P, A, S, R, C> {
    /// Runs the connector once and records the run; `None` when the run could not be recorded.
    pub async fn run_once(&self) -> Option<Run> {
        let _one = self.running.lock().await;
        let started = self.clock.now()?;
        let id = self.random.bytes()?;
        let outcome = run(
            &self.connector,
            (&self.pull, &self.access, &self.sign, &self.random),
        )
        .await;
        let (report, outcome, why) = match &outcome {
            Ok(r) => (*r, "done", None),
            Err(e) => {
                tracing::warn!(
                    event = "hr.connector.failed",
                    vendor = self.connector.vendor.name(),
                    reason = reason(e),
                    "HR connector run failed"
                );
                (Report::default(), "failed", Some(String::from(reason(e))))
            }
        };
        let r = Run {
            run: id,
            connector: self.connector.name.clone(),
            started_ms: started,
            ended_ms: self.clock.now().unwrap_or(started).max(started),
            outcome: String::from(outcome),
            report,
            reason: why,
        };
        self.store.record(&r).await.ok()?;
        Some(r)
    }
}

fn run_json(r: &Run) -> Value {
    json!({
        "run": b64url_encode(&r.run),
        "connector": r.connector,
        "started_ms": r.started_ms,
        "ended_ms": r.ended_ms,
        "outcome": r.outcome,
        "report": r.report,
        "reason": r.reason,
    })
}

fn problem(status: StatusCode, code: &str) -> Response {
    (
        status,
        [("content-type", "application/problem+json")],
        json!({
            "type": format!("urn:suiss:access:problem:{code}"),
            "title": status.canonical_reason().unwrap_or(""),
            "status": status.as_u16(),
            "code": code,
        })
        .to_string(),
    )
        .into_response()
}

type Shared<P, A, S, R, C> = Arc<Service<P, A, S, R, C>>;

async fn connectors<P: Pull, A: Access, S: Sign, R: Random, C: Clock>(
    State(s): State<Shared<P, A, S, R, C>>,
) -> Response {
    let last = s
        .store
        .runs(&s.connector.name, 1)
        .await
        .ok()
        .and_then(|r| r.into_iter().next());
    axum::Json(json!({
        "connectors": [{
            "name": s.connector.name,
            "vendor": s.connector.vendor.name(),
            "realm": s.connector.realm,
            "source": s.connector.source,
            "last_run": last.as_ref().map(run_json),
        }],
    }))
    .into_response()
}

async fn start<P: Pull, A: Access, S: Sign, R: Random, C: Clock>(
    State(s): State<Shared<P, A, S, R, C>>,
    Path(name): Path<String>,
) -> Response {
    if name != s.connector.name {
        return problem(StatusCode::NOT_FOUND, "no-such-hr-connector");
    }
    match s.run_once().await {
        Some(r) => axum::Json(run_json(&r)).into_response(),
        None => problem(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

async fn one<P: Pull, A: Access, S: Sign, R: Random, C: Clock>(
    State(s): State<Shared<P, A, S, R, C>>,
    Path((name, run)): Path<(String, String)>,
) -> Response {
    let Some(id) = b64url_decode(&run)
        .ok()
        .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
    else {
        return problem(StatusCode::NOT_FOUND, "no-such-run");
    };
    if name != s.connector.name {
        return problem(StatusCode::NOT_FOUND, "no-such-hr-connector");
    }
    match s.store.run(&name, id).await {
        Ok(Some(r)) => axum::Json(run_json(&r)).into_response(),
        Ok(None) => problem(StatusCode::NOT_FOUND, "no-such-run"),
        Err(_) => problem(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}

async fn health<P: Pull, A: Access, S: Sign, R: Random, C: Clock>(
    State(s): State<Shared<P, A, S, R, C>>,
) -> Response {
    let db = s.store.healthy().await;
    let last = s
        .store
        .runs(&s.connector.name, 1)
        .await
        .ok()
        .and_then(|r| r.into_iter().next());
    let access = last
        .as_ref()
        .map(|r| r.reason.as_deref() != Some("unreachable"));
    let body = json!({ "database": db, "access": access });
    if db {
        axum::Json(body).into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, axum::Json(body)).into_response()
    }
}

/// The routes of `/hr-connector/v1/*` (`sdks/openapi/hr-connector-v1.json`).
pub fn router<P, A, S, R, C>(s: Shared<P, A, S, R, C>) -> Router
where
    P: Pull + 'static,
    A: Access + 'static,
    S: Sign + 'static,
    R: Random + 'static,
    C: Clock + 'static,
{
    Router::new()
        .route(
            "/hr-connector/v1/connectors",
            get(connectors::<P, A, S, R, C>),
        )
        .route(
            "/hr-connector/v1/connectors/{connector}/runs",
            post(start::<P, A, S, R, C>),
        )
        .route(
            "/hr-connector/v1/connectors/{connector}/runs/{run}",
            get(one::<P, A, S, R, C>),
        )
        .route("/hr-connector/v1/healthz", get(health::<P, A, S, R, C>))
        .with_state(s)
}
