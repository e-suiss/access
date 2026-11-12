//! `Idempotency-Key` on the login surface (TN-126, OP-63 rule 3, OP-65): the same key with the
//! same request answers the first answer again; another request under the key is `422`; a
//! request still running under it is `409`. Validation failures (`400`) and server failures
//! (`5xx`) are not kept, so they run again.
//!
//! The first answers are kept in process memory only, never at rest: they can carry a session
//! cookie, a TOTP seed or recovery codes. The key is scoped to the realm host, the path and the
//! browser's flow and session cookies, so another browser cannot read an answer by its key; a
//! browser with neither cookie (starting its first flow) has nothing to bind an answer to, so
//! its request runs every time and creates nothing but an anonymous flow.
//! A retry that reaches another node runs again; the flow's compare-and-set keeps it from
//! consuming anything twice.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes, to_bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::Problem;

/// How long a first answer is kept (PD; published with the API).
pub const RETENTION: Duration = Duration::from_secs(600);

/// Most answers kept per process (PD).
pub const CAPACITY: usize = 10_000;

/// Longest key (TN-126).
pub(super) const MAX_KEY: usize = 255;

const KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// Largest body read here; the router's body limit applies first.
const MAX_BODY: usize = 256 * 1024;

#[derive(Clone)]
struct Stored {
    status: StatusCode,
    headers: Vec<(HeaderName, HeaderValue)>,
    body: Bytes,
}

enum Phase {
    Running,
    Done(Stored),
}

struct Entry {
    request: [u8; 32],
    at: Instant,
    state: Phase,
}

/// The first answers under each key.
#[derive(Default)]
pub(super) struct Cache {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<[u8; 32], Entry>,
    order: VecDeque<([u8; 32], Instant)>,
}

impl Inner {
    fn expire(&mut self, now: Instant) {
        while let Some(&(key, at)) = self.order.front() {
            let old = now.saturating_duration_since(at) >= RETENTION;
            if !old && self.entries.len() < CAPACITY {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&key).is_some_and(|e| e.at == at) {
                self.entries.remove(&key);
            }
        }
    }
}

enum Begin {
    Run,
    Replay(Stored),
    Reused,
    Running,
}

impl Cache {
    fn begin(&self, scope: [u8; 32], request: [u8; 32]) -> Begin {
        let Ok(mut inner) = self.inner.lock() else {
            return Begin::Run;
        };
        let now = Instant::now();
        inner.expire(now);
        match inner.entries.get(&scope) {
            Some(e) if e.request != request => Begin::Reused,
            Some(Entry {
                state: Phase::Running,
                ..
            }) => Begin::Running,
            Some(Entry {
                state: Phase::Done(s),
                ..
            }) => Begin::Replay(s.clone()),
            None => {
                inner.entries.insert(
                    scope,
                    Entry {
                        request,
                        at: now,
                        state: Phase::Running,
                    },
                );
                inner.order.push_back((scope, now));
                Begin::Run
            }
        }
    }

    fn finish(&self, scope: [u8; 32], stored: Option<Stored>) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        match stored {
            Some(s) => {
                if let Some(e) = inner.entries.get_mut(&scope) {
                    e.state = Phase::Done(s);
                }
            }
            None => {
                inner.entries.remove(&scope);
            }
        }
    }
}

/// Releases a running key if the request never finishes (cancellation, panic).
struct Guard<'a> {
    cache: &'a Cache,
    scope: [u8; 32],
    armed: bool,
}

impl Drop for Guard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.cache.finish(self.scope, None);
        }
    }
}

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(&u64::try_from(p.len()).unwrap_or(u64::MAX).to_be_bytes());
        buf.extend_from_slice(p);
    }
    suiss_crypto::digest::sha256(&buf)
}

fn key_problem(code: &'static str) -> Response {
    Problem::new(StatusCode::BAD_REQUEST, code, "Bad Request").into_response()
}

fn valid_key(v: &HeaderValue) -> Option<&[u8]> {
    let b = v.as_bytes();
    (!b.is_empty() && b.len() <= MAX_KEY && b.iter().all(|c| (0x21..=0x7e).contains(c)))
        .then_some(b)
}

/// The cookies that tie an answer to one browser; `None` when it has neither a flow nor a
/// session cookie, so nothing could keep another browser from reading the answer.
fn browser(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut flow = None;
    let mut session = None;
    for (name, value) in super::web::cookies(headers) {
        match name {
            n if n == access_identity_ui::app::FLOW_COOKIE => flow = flow.or(Some(value)),
            n if n == access_identity_ui::app::SESSION_COOKIE => {
                session = session.or(Some(value));
            }
            _ => {}
        }
    }
    if flow.is_none() && session.is_none() {
        return None;
    }
    Some(digest(&[
        flow.unwrap_or_default().as_bytes(),
        session.unwrap_or_default().as_bytes(),
    ]))
}

fn replay(s: Stored) -> Response {
    let mut response = (s.status, s.body).into_response();
    response.headers_mut().clear();
    for (name, value) in s.headers {
        response.headers_mut().append(name, value);
    }
    response
}

/// The request's `Idempotency-Key`, or the `400` that refuses it.
#[expect(
    clippy::result_large_err,
    reason = "the refusal is the response itself"
)]
pub(super) fn key(headers: &HeaderMap) -> Result<&[u8], Response> {
    let Some(value) = headers.get(&KEY) else {
        return Err(key_problem("idempotency-key-required"));
    };
    valid_key(value).ok_or_else(|| key_problem("idempotency-key-invalid"))
}

/// Runs `run` once per `Idempotency-Key` of a request whose body the caller streamed in under
/// its own limit and whose content digest it computed (OP-159 m.3 (mm)): the body is never
/// buffered here, and the same key with other content is `422`.
pub(super) async fn once(
    cache: &Cache,
    (method, uri, headers): (&axum::http::Method, &axum::http::Uri, &HeaderMap),
    content: [u8; 32],
    run: impl Future<Output = Response>,
) -> Response {
    let key = match key(headers) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let path = uri.path().as_bytes();
    let Some(owner) = browser(headers) else {
        return run.await;
    };
    let host = headers
        .get(header::HOST)
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    let query = uri.query().unwrap_or_default().as_bytes();
    let scope = digest(&[b"access/login-idempotency/v1", host, path, &owner, key]);
    let request = digest(&[
        b"access/login-idempotency/streamed/v1",
        method.as_str().as_bytes(),
        path,
        query,
        &content,
    ]);
    run_once(cache, scope, request, run).await
}

async fn run_once(
    cache: &Cache,
    scope: [u8; 32],
    request: [u8; 32],
    run: impl Future<Output = Response>,
) -> Response {
    match cache.begin(scope, request) {
        Begin::Run => {}
        Begin::Replay(s) => return replay(s),
        Begin::Reused => {
            return Problem::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                "idempotency-key-reused",
                "Idempotency-Key reused with another request",
            )
            .into_response();
        }
        Begin::Running => {
            return Problem::new(
                StatusCode::CONFLICT,
                "idempotency-key-in-use",
                "A request with this Idempotency-Key is still running",
            )
            .into_response();
        }
    }
    let mut guard = Guard {
        cache,
        scope,
        armed: true,
    };
    let response = run.await;
    let status = response.status();
    let keep = !(status == StatusCode::BAD_REQUEST || status.is_server_error());
    let (rparts, rbody) = response.into_parts();
    let Ok(body) = to_bytes(rbody, usize::MAX).await else {
        return Problem::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal Server Error",
        )
        .into_response();
    };
    let stored = Stored {
        status,
        headers: rparts
            .headers
            .iter()
            .map(|(n, v)| (n.clone(), v.clone()))
            .collect(),
        body: body.clone(),
    };
    guard.armed = false;
    cache.finish(scope, keep.then(|| stored.clone()));
    replay(stored)
}

/// The middleware over the login surface's `POST` routes.
pub(super) async fn layer(
    State(cache): State<std::sync::Arc<Cache>>,
    req: Request,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();
    let key = match key(&parts.headers) {
        Ok(k) => k,
        Err(r) => return r,
    };
    let Ok(bytes) = to_bytes(body, MAX_BODY).await else {
        return Problem::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body-too-large",
            "Payload Too Large",
        )
        .into_response();
    };
    let host = parts
        .headers
        .get(header::HOST)
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    let path = parts.uri.path().as_bytes();
    let Some(owner) = browser(&parts.headers) else {
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    };
    let scope = digest(&[b"access/login-idempotency/v1", host, path, &owner, key]);
    let request = digest(&[parts.method.as_str().as_bytes(), path, &bytes]);
    let run = next.run(Request::from_parts(parts, Body::from(bytes)));
    run_once(&cache, scope, request, run).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> Stored {
        Stored {
            status: StatusCode::OK,
            headers: Vec::new(),
            body: Bytes::from_static(b"x"),
        }
    }

    // TN-126
    #[test]
    fn a_key_answers_once_and_refuses_another_request() {
        let cache = Cache::default();
        assert!(matches!(cache.begin([1; 32], [2; 32]), Begin::Run));
        assert!(matches!(cache.begin([1; 32], [2; 32]), Begin::Running));
        assert!(matches!(cache.begin([1; 32], [3; 32]), Begin::Reused));
        cache.finish([1; 32], Some(stored()));
        assert!(matches!(cache.begin([1; 32], [2; 32]), Begin::Replay(_)));
        cache.finish([4; 32], None);
        assert!(matches!(cache.begin([5; 32], [2; 32]), Begin::Run));
        cache.finish([5; 32], None);
        assert!(matches!(cache.begin([5; 32], [9; 32]), Begin::Run));
    }

    // TN-126
    #[test]
    fn keys_are_bounded_visible_ascii() {
        assert!(valid_key(&HeaderValue::from_static("0f9c-ab")).is_some());
        assert!(valid_key(&HeaderValue::from_static("")).is_none());
        assert!(valid_key(&HeaderValue::from_static("a b")).is_none());
        let long = "k".repeat(MAX_KEY + 1);
        assert!(valid_key(&HeaderValue::from_str(&long).unwrap()).is_none());
    }
}
