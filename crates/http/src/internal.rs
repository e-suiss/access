//! The internal listener's routes (OP-67 m.3, OP-151 m.3 (b)): `/livez`, `/readyz`, `/healthz`,
//! `/metrics` and the security-tooling export `/internal/v1/oracle-watch` (§17.8.2, SEC31), on
//! the internal network only. None of them is on the public or management listener.
//!
//! Readiness fails closed: the process is ready only once it marked itself started and every
//! check and start-up flag passes, each within [`CHECK_BUDGET`] (MD-8, OP-53).

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use access_telemetry::metrics::{PROMETHEUS_CONTENT_TYPE, render_prometheus};
use access_telemetry::oracle::ORACLE;
use access_telemetry::signals::{READINESS_FAILURES, READY};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};

use crate::problem::{FieldError, codes};
use crate::{Health, Limits, harden};

/// Deadline of one readiness check (OP-67 m.3).
pub const CHECK_BUDGET: Duration = Duration::from_millis(500);

/// The `/metrics` content type (Prometheus text exposition).
pub const METRICS_CONTENT_TYPE: &str = PROMETHEUS_CONTENT_TYPE;

/// A readiness probe's future.
pub type Probe = Pin<Box<dyn Future<Output = bool> + Send + 'static>>;

/// One readiness check.
pub trait ReadyCheck: Send + Sync + 'static {
    /// The check's name in the `/readyz` answer; never carries a secret or an address.
    fn name(&self) -> &'static str;
    /// Whether the dependency answers now.
    fn probe(&self) -> Probe;
}

struct FnCheck<F> {
    name: &'static str,
    probe: F,
}

impl<F> ReadyCheck for FnCheck<F>
where
    F: Fn() -> Probe + Send + Sync + 'static,
{
    fn name(&self) -> &'static str {
        self.name
    }

    fn probe(&self) -> Probe {
        (self.probe)()
    }
}

/// A signer reachable on its Unix socket (CMP-22b, OP-143 m.5).
#[derive(Clone, Debug)]
pub struct SignerSocket {
    /// The check name, e.g. `signer.authority`.
    pub name: &'static str,
    /// The socket path.
    pub path: PathBuf,
}

impl ReadyCheck for SignerSocket {
    fn name(&self) -> &'static str {
        self.name
    }

    fn probe(&self) -> Probe {
        let path = self.path.clone();
        Box::pin(async move { tokio::net::UnixStream::connect(path).await.is_ok() })
    }
}

/// A start-up step that has to finish before traffic (JWKS loaded, caches warm, the outbox
/// consumer running). It starts unset.
#[derive(Clone, Debug)]
pub struct ReadyFlag {
    name: &'static str,
    set: Arc<AtomicBool>,
}

impl ReadyFlag {
    /// Marks the step done, or undone again.
    pub fn set(&self, ready: bool) {
        self.set.store(ready, Ordering::Release);
    }
}

impl ReadyCheck for ReadyFlag {
    fn name(&self) -> &'static str {
        self.name
    }

    fn probe(&self) -> Probe {
        Box::pin(std::future::ready(self.set.load(Ordering::Acquire)))
    }
}

#[derive(Default)]
struct Inner {
    started: AtomicBool,
    checks: Mutex<Vec<Arc<dyn ReadyCheck>>>,
    last: Mutex<Vec<&'static str>>,
}

/// Whether the process takes traffic: marked started once every listener is bound and the
/// background work started, and every registered check passing (OP-67 m.3, MD-8).
#[derive(Clone, Default)]
pub struct Readiness(Arc<Inner>);

impl std::fmt::Debug for Readiness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.checks().iter().map(|c| c.name()).collect();
        f.debug_struct("Readiness")
            .field("started", &self.is_ready())
            .field("checks", &names)
            .finish()
    }
}

/// The name of the started flag in the `/readyz` answer.
pub const STARTED: &str = "started";

impl Readiness {
    /// Marks the process started.
    pub fn ready(&self) {
        self.0.started.store(true, Ordering::Release);
    }

    /// Marks the process not started, as when it starts shutting down.
    pub fn unready(&self) {
        self.0.started.store(false, Ordering::Release);
    }

    /// Whether it was marked started.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.0.started.load(Ordering::Acquire)
    }

    fn checks(&self) -> Vec<Arc<dyn ReadyCheck>> {
        self.0
            .checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Adds a check.
    pub fn add(&self, check: impl ReadyCheck) {
        self.0
            .checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::new(check));
    }

    /// Adds a check from a probe function, e.g. a database pool ping.
    pub fn add_fn<F>(&self, name: &'static str, probe: F)
    where
        F: Fn() -> Probe + Send + Sync + 'static,
    {
        self.add(FnCheck { name, probe });
    }

    /// Adds a start-up flag, unset, and returns its handle.
    #[must_use]
    pub fn flag(&self, name: &'static str) -> ReadyFlag {
        let flag = ReadyFlag {
            name,
            set: Arc::new(AtomicBool::new(false)),
        };
        self.add(flag.clone());
        flag
    }

    /// The names of what is not ready now: [`STARTED`] when not marked started, then every
    /// check that failed or did not answer within [`CHECK_BUDGET`].
    pub async fn failing(&self) -> Vec<&'static str> {
        let checks = self.checks();
        let mut set = tokio::task::JoinSet::new();
        for (i, check) in checks.iter().enumerate() {
            let probe = check.probe();
            set.spawn(async move {
                (
                    i,
                    tokio::time::timeout(CHECK_BUDGET, probe)
                        .await
                        .unwrap_or(false),
                )
            });
        }
        let mut passed = vec![false; checks.len()];
        while let Some(joined) = set.join_next().await {
            if let Ok((i, ok)) = joined
                && let Some(slot) = passed.get_mut(i)
            {
                *slot = ok;
            }
        }
        let mut failing: Vec<&'static str> = Vec::new();
        if !self.is_ready() {
            failing.push(STARTED);
        }
        failing.extend(
            checks
                .iter()
                .zip(&passed)
                .filter(|(_, ok)| !**ok)
                .map(|(c, _)| c.name()),
        );
        self.observe(&failing);
        failing
    }

    fn observe(&self, failing: &[&'static str]) {
        READY.set(i64::from(failing.is_empty()), []);
        for name in failing {
            READINESS_FAILURES.incr([name]);
        }
        let mut last = self.0.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.as_slice() != failing {
            if !failing.is_empty() {
                tracing::warn!(
                    event = "readiness.failed",
                    outcome = "not_ready",
                    checks = ?failing,
                    "readiness checks failing (OP-67 m.3)"
                );
            }
            failing.clone_into(&mut last);
        }
    }
}

async fn livez() -> &'static str {
    "ok\n"
}

async fn readyz(ready: Readiness) -> Response {
    let failing = ready.failing().await;
    if failing.is_empty() {
        (StatusCode::OK, "ok\n").into_response()
    } else {
        codes::UNAVAILABLE
            .problem()
            .with_errors(
                failing
                    .into_iter()
                    .map(|code| FieldError {
                        pointer: None,
                        code,
                    })
                    .collect(),
            )
            .into_response()
    }
}

async fn metrics() -> Response {
    let mut r = (StatusCode::OK, render_prometheus()).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(METRICS_CONTENT_TYPE),
    );
    r
}

async fn not_found() -> Response {
    codes::NOT_FOUND.problem().into_response()
}

/// The internal router: liveness, readiness, health with the lockdown state (SA-22), the
/// metrics exposition and the oracle-watch export; `now_ms` is the clock port's Unix
/// milliseconds for the oracle-watch windows.
pub fn router(health: Health, ready: Readiness, limits: Limits, now_ms: fn() -> u64) -> Router {
    let routes = Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(move || readyz(ready.clone())))
        .route(
            "/healthz",
            get(move || std::future::ready(Json(health.clone()))),
        )
        .route("/metrics", get(metrics))
        // §17.8.2, SEC31
        .route(
            "/internal/v1/oracle-watch",
            get(move || std::future::ready(Json(ORACLE.snapshot(now_ms())))),
        )
        .fallback(not_found);
    harden(routes, limits)
}
