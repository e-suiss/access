//! The experience over HTTP (OP-65): the plan and hub routes, the server-sent signal stream,
//! RFC 9457 problems, and an in-process signal beacon. The router has no route that writes
//! (OP-153 m.3 (v)).

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::stream::{self, Stream};
use tokio::sync::watch;

use crate::app::Experience;
use crate::contract::{
    HUB_PATH, HubRequest, PLAN_PATH, PlanRequest, STREAM_PATH, Signal, SignalKind,
};
use crate::domain::Malformed;
use crate::ports::{Clock, Random, Signals, Upstream};

/// Largest request body.
pub const MAX_BODY: usize = 256 * 1024;

/// The problem type prefix (OP-65).
pub const TYPE_PREFIX: &str = "urn:suiss:access:problem:";

/// How often the stream sends a keep-alive comment.
pub const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// An in-process signal feed: whoever learns that authority moved calls [`Beacon::notify`].
#[derive(Clone)]
pub struct Beacon(Arc<watch::Sender<u64>>);

impl Default for Beacon {
    fn default() -> Self {
        Self(Arc::new(watch::Sender::new(0)))
    }
}

impl Beacon {
    /// Authority moved to at least `position`; a lower position changes nothing.
    pub fn notify(&self, position: u64) {
        self.0.send_if_modified(|p| {
            if position > *p {
                *p = position;
                true
            } else {
                false
            }
        });
    }
}

impl Signals for Beacon {
    fn watch(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

fn problem(status: StatusCode, code: &str, title: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/problem+json")],
        serde_json::json!({
            "type": format!("{TYPE_PREFIX}{code}"),
            "title": title,
            "status": status.as_u16(),
            "code": code,
        })
        .to_string(),
    )
        .into_response()
}

fn malformed(Malformed(what): Malformed) -> Response {
    let _ = what;
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

fn json<T: serde::Serialize>(v: &T) -> Response {
    match serde_json::to_string(v) {
        Ok(s) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            s,
        )
            .into_response(),
        Err(_) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal Server Error",
        ),
    }
}

struct Shared<U, C, N, S> {
    experience: Experience<U, C, N>,
    signals: S,
}

/// The experience routes.
pub fn router<U, C, N, S>(experience: Experience<U, C, N>, signals: S) -> Router
where
    U: Upstream + 'static,
    C: Clock + 'static,
    N: Random + 'static,
    S: Signals + 'static,
{
    let shared = Arc::new(Shared {
        experience,
        signals,
    });
    Router::new()
        .route(PLAN_PATH, post(plan::<U, C, N, S>))
        .route(HUB_PATH, post(hub::<U, C, N, S>))
        .route(STREAM_PATH, get(stream::<U, C, N, S>))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(shared)
}

async fn plan<U: Upstream, C: Clock, N: Random, S: Signals>(
    State(shared): State<Arc<Shared<U, C, N, S>>>,
    body: Bytes,
) -> Response {
    let Ok(req) = serde_json::from_slice::<PlanRequest>(&body) else {
        return malformed(Malformed("body"));
    };
    match shared.experience.plan(&req) {
        Ok(p) => json(&p),
        Err(e) => malformed(e),
    }
}

async fn hub<U: Upstream, C: Clock, N: Random, S: Signals>(
    State(shared): State<Arc<Shared<U, C, N, S>>>,
    body: Bytes,
) -> Response {
    let Ok(req) = serde_json::from_slice::<HubRequest>(&body) else {
        return malformed(Malformed("body"));
    };
    match shared.experience.hub(&req).await {
        Ok(h) => json(&h),
        Err(e) => malformed(e),
    }
}

fn signals(rx: watch::Receiver<u64>) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold(rx, |mut rx| async move {
        rx.changed().await.ok()?;
        let at_least = *rx.borrow_and_update();
        let signal = Signal {
            kind: SignalKind::Authority,
            at_least,
        };
        let event = Event::default()
            .event("authority")
            .data(serde_json::to_string(&signal).ok()?);
        Some((Ok(event), rx))
    })
}

async fn stream<U: Upstream, C: Clock, N: Random, S: Signals>(
    State(shared): State<Arc<Shared<U, C, N, S>>>,
) -> impl IntoResponse {
    Sse::new(signals(shared.signals.watch())).keep_alive(KeepAlive::new().interval(KEEP_ALIVE))
}
