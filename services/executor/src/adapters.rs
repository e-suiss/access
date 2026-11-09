//! The executor's HTTP surface, `/executor/v1/*` (OP-154 m.3 (u)), and the control state the
//! Authority hub renders: running, paused (confirmed or not), stopped (confirmed or not),
//! unknown or completed (U5). A job is named by its random 128-bit id; starting one needs the
//! actor's own signed statement, and every control call moves it only towards fewer effects
//! except `resume`, which needs the actor's new statements.

use std::sync::Arc;

use access_kernel::json::b64url_encode;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde_json::{Value, json};
use suiss_crypto::signer::Signer;

use crate::app::{ExecError, Executor, Start, bytes};
use crate::domain::history::{Confirmed, Job, Outcome};
use crate::domain::step::StepSpec;
use crate::ports::{Access, Clock, Random, Upstream};

/// An RFC 9457 problem.
#[must_use]
pub fn problem(status: StatusCode, code: &str) -> Response {
    let body = json!({
        "type": format!("urn:suiss:access:problem:{code}"),
        "title": status.canonical_reason().unwrap_or("Error"),
        "status": status.as_u16(),
        "code": code,
    });
    let mut r = (status, body.to_string()).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn failed(e: &ExecError) -> Response {
    let status = match e {
        ExecError::Malformed(_) => StatusCode::BAD_REQUEST,
        ExecError::NotAllowed(_) => StatusCode::FORBIDDEN,
        ExecError::Unknown => StatusCode::NOT_FOUND,
        ExecError::Conflict(_) | ExecError::Stale => StatusCode::CONFLICT,
        ExecError::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    problem(status, e.code())
}

fn set(v: &mut Value, key: &str, value: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(String::from(key), value);
    }
}

fn ok(v: Value) -> Response {
    let mut r = (StatusCode::OK, axum::Json(v)).into_response();
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The job's control state as the hub shows it (U5): a pause or stop counts once confirmed.
#[must_use]
pub fn state(job: &Job) -> (&'static str, bool) {
    let unknown = job
        .steps
        .iter()
        .any(|s| matches!(s.outcome, Some((Outcome::Unknown, _, _))));
    match (job.confirmed, &job.stop_requested) {
        (Some(Confirmed::Stopped), _) => ("stopped", true),
        (_, Some(_)) => ("stopped", false),
        _ if job.completed() => ("completed", false),
        _ if unknown && job.pause_requested => {
            ("unknown", job.confirmed == Some(Confirmed::Paused))
        }
        (Some(Confirmed::Paused), _) => ("paused", true),
        _ if job.pause_requested || job.handoff.is_some() => ("paused", false),
        _ => ("running", false),
    }
}

/// The job as the contract's `Job`.
#[must_use]
pub fn view(job: &Job) -> Value {
    let (state, confirmed) = state(job);
    let steps: Vec<Value> = job.steps.iter().map(step_view).collect();
    let mut v = json!({
        "job": b64url_encode(&job.started.job),
        "exercise": b64url_encode(&job.started.exercise),
        "kind": job.started.kind.name(),
        "state": state,
        "confirmed": confirmed,
        "steps": steps,
    });
    if let Some(reason) = &job.stop_requested {
        set(&mut v, "reason", Value::from(reason.as_str()));
    } else if let Some((_, reason, until)) = &job.handoff {
        set(&mut v, "reason", Value::from(reason.as_str()));
        set(&mut v, "handoff_until_ms", Value::from(*until));
    }
    v
}

fn step_view(s: &crate::domain::history::Step) -> Value {
    let mut v = json!({
        "step": b64url_encode(&s.step.0),
        "name": s.spec.name,
        "idempotency_key": b64url_encode(&s.key.0),
    });
    if let Some((o, e, _)) = &s.outcome {
        set(
            &mut v,
            "outcome",
            serde_json::to_value(o).unwrap_or(Value::Null),
        );
        set(
            &mut v,
            "evidence",
            serde_json::to_value(e).unwrap_or(Value::Null),
        );
    }
    if let Some(until) = s.window_until
        && s.outbox.is_none()
        && s.outcome.is_none()
    {
        set(&mut v, "commit_at_ms", Value::from(until));
    }
    if let Some((claim, refused)) = &s.attested {
        set(&mut v, "claim", Value::from(b64url_encode(claim)));
        if let Some(r) = refused {
            set(&mut v, "report_refused", Value::from(r.as_str()));
        }
    }
    v
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartBody {
    realm: String,
    connection: String,
    intent: String,
    ais: String,
    steps: Vec<StepSpec>,
    #[serde(default)]
    continuations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeBody {
    continuations: Vec<String>,
}

fn id(text: &str) -> Result<[u8; 16], ExecError> {
    <[u8; 16]>::try_from(bytes(text)?).map_err(|_| ExecError::Unknown)
}

fn list(items: &[String]) -> Result<Vec<Vec<u8>>, ExecError> {
    items.iter().map(|t| bytes(t)).collect()
}

/// The executor's routes over `exec`.
pub fn router<A, U, C, R, S>(exec: Arc<Executor<A, U, C, R, S>>) -> Router
where
    A: Access + 'static,
    U: Upstream + 'static,
    C: Clock + 'static,
    R: Random + 'static,
    S: Signer + Send + Sync + 'static,
{
    Router::new()
        .route("/executor/v1/jobs", post(start::<A, U, C, R, S>))
        .route("/executor/v1/jobs/{job}", get(one::<A, U, C, R, S>))
        .route("/executor/v1/jobs/{job}/steps", get(steps::<A, U, C, R, S>))
        .route(
            "/executor/v1/jobs/{job}/pause",
            post(pause::<A, U, C, R, S>),
        )
        .route(
            "/executor/v1/jobs/{job}/resume",
            post(resume::<A, U, C, R, S>),
        )
        .route("/executor/v1/jobs/{job}/stop", post(stop::<A, U, C, R, S>))
        .route(
            "/executor/v1/jobs/{job}/steps/{step}/cancel",
            post(cancel::<A, U, C, R, S>),
        )
        .with_state(exec)
}

type Shared<A, U, C, R, S> = State<Arc<Executor<A, U, C, R, S>>>;

async fn answer<A, U, C, R, S>(exec: &Executor<A, U, C, R, S>, job: [u8; 16]) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    match exec.job(job).await {
        Ok(j) => ok(view(&j)),
        Err(e) => failed(&e),
    }
}

async fn start<A, U, C, R, S>(
    State(exec): Shared<A, U, C, R, S>,
    body: axum::body::Bytes,
) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    let Ok(b) = serde_json::from_slice::<StartBody>(&body) else {
        return problem(StatusCode::BAD_REQUEST, "executor-malformed");
    };
    let req = match (bytes(&b.intent), bytes(&b.ais), list(&b.continuations)) {
        (Ok(intent), Ok(ais), Ok(continuations)) => Start {
            realm: b.realm,
            connection: b.connection,
            intent,
            ais,
            steps: b.steps,
            continuations,
        },
        _ => return problem(StatusCode::BAD_REQUEST, "executor-malformed"),
    };
    match exec.start(req).await {
        Ok(job) => answer(&exec, job).await,
        Err(e) => failed(&e),
    }
}

async fn one<A, U, C, R, S>(State(exec): Shared<A, U, C, R, S>, Path(job): Path<String>) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    match id(&job) {
        Ok(job) => answer(&exec, job).await,
        Err(e) => failed(&e),
    }
}

async fn steps<A, U, C, R, S>(
    State(exec): Shared<A, U, C, R, S>,
    Path(job): Path<String>,
) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    let job = match id(&job) {
        Ok(j) => j,
        Err(e) => return failed(&e),
    };
    match exec.job(job).await {
        Ok(j) => ok(json!({ "items": j.steps.iter().map(step_view).collect::<Vec<_>>() })),
        Err(e) => failed(&e),
    }
}

async fn control<A, U, C, R, S, F, Fut>(exec: &Executor<A, U, C, R, S>, job: &str, f: F) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
    F: FnOnce([u8; 16]) -> Fut,
    Fut: Future<Output = Result<(), ExecError>>,
{
    let job = match id(job) {
        Ok(j) => j,
        Err(e) => return failed(&e),
    };
    match f(job).await {
        Ok(()) => answer(exec, job).await,
        Err(e) => failed(&e),
    }
}

async fn pause<A, U, C, R, S>(
    State(exec): Shared<A, U, C, R, S>,
    Path(job): Path<String>,
) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    control(&exec, &job, |j| exec.pause(j)).await
}

async fn stop<A, U, C, R, S>(
    State(exec): Shared<A, U, C, R, S>,
    Path(job): Path<String>,
) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    control(&exec, &job, |j| exec.stop(j)).await
}

async fn resume<A, U, C, R, S>(
    State(exec): Shared<A, U, C, R, S>,
    Path(job): Path<String>,
    body: axum::body::Bytes,
) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    let Ok(Ok(continuations)) =
        serde_json::from_slice::<ResumeBody>(&body).map(|b| list(&b.continuations))
    else {
        return problem(StatusCode::BAD_REQUEST, "executor-malformed");
    };
    control(&exec, &job, |j| exec.resume(j, continuations)).await
}

async fn cancel<A, U, C, R, S>(
    State(exec): Shared<A, U, C, R, S>,
    Path((job, step)): Path<(String, String)>,
) -> Response
where
    A: Access,
    U: Upstream,
    C: Clock,
    R: Random,
    S: Signer + Send + Sync,
{
    let Ok(step) = bytes(&step) else {
        return problem(StatusCode::BAD_REQUEST, "executor-malformed");
    };
    let e = Arc::clone(&exec);
    control(&exec, &job, |j| async move { e.cancel(j, &step).await }).await
}
