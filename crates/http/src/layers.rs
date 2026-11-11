//! The admission layers of a listener (SA-27, OP-35 layer A, OP-36, OP-53, OP-158 m.3 (v)): a
//! per-client-address token bucket in front of everything, and a lane of bounded in-flight
//! requests with a bounded queue in front of the routes. Neither ever admits on failure: a
//! full bucket is `429`, a full lane is `503` with `Retry-After`, and the queue depth is the
//! `access_pool_queue_depth` gauge of the lane, never labelled by the request.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;

use crate::login::Peer;
use crate::problem::{Problem, codes};

/// Most client addresses tracked at once; when full and none has refilled, a new address is
/// refused (fail closed).
pub const MAX_CLIENTS: usize = 65_536;

/// How long a request waits in a lane's queue before it is shed (OP-36, PD).
pub const QUEUE_WAIT: Duration = Duration::from_secs(1);

/// What one listener admits: its lane and its per-address rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The lane's name in `access_pool_queue_depth`: `critical` or `admin`.
    pub lane: &'static str,
    /// Requests running at once.
    pub in_flight: usize,
    /// Requests waiting at once; past it a request is shed.
    pub queue: usize,
    /// Requests per second per client address, sustained.
    pub per_second: u64,
    /// Requests per client address at once.
    pub burst: u64,
}

/// The public listener: token validation, sign-in, ADP (OP-53, PD).
pub const CRITICAL: Admission = Admission {
    lane: "critical",
    in_flight: 1_024,
    queue: 1_024,
    per_second: 1_000,
    burst: 5_000,
};

/// The management listener: admin and report requests, kept from starving sign-in (OP-53, PD).
pub const ADMIN: Admission = Admission {
    lane: "admin",
    in_flight: 64,
    queue: 64,
    per_second: 100,
    burst: 500,
};

#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens_milli: u64,
    at_ms: u64,
}

/// Token buckets per client address (OP-35 layer A): approximate, per process.
#[derive(Debug)]
pub struct ClientRate {
    per_second: u64,
    burst: u64,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

impl ClientRate {
    /// `burst` requests at once per address, refilled at `per_second`.
    #[must_use]
    pub fn new(per_second: u64, burst: u64) -> Self {
        Self {
            per_second,
            burst: burst.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn refill(&self, b: Bucket, now_ms: u64) -> Bucket {
        let gained = now_ms
            .saturating_sub(b.at_ms)
            .saturating_mul(self.per_second);
        Bucket {
            tokens_milli: b
                .tokens_milli
                .saturating_add(gained)
                .min(self.burst.saturating_mul(1_000)),
            at_ms: now_ms.max(b.at_ms),
        }
    }

    /// Whether one more request from `ip` is admitted at `now_ms`.
    #[must_use]
    pub fn admit(&self, ip: IpAddr, now_ms: u64) -> bool {
        let full = self.burst.saturating_mul(1_000);
        let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
        if !buckets.contains_key(&ip) && buckets.len() >= MAX_CLIENTS {
            buckets.retain(|_, b| self.refill(*b, now_ms).tokens_milli < full);
            if buckets.len() >= MAX_CLIENTS {
                return false;
            }
        }
        let b = buckets.get(&ip).copied().unwrap_or(Bucket {
            tokens_milli: full,
            at_ms: now_ms,
        });
        let b = self.refill(b, now_ms);
        let (admitted, tokens_milli) = match b.tokens_milli.checked_sub(1_000) {
            Some(left) => (true, left),
            None => (false, b.tokens_milli),
        };
        buckets.insert(
            ip,
            Bucket {
                tokens_milli,
                at_ms: b.at_ms,
            },
        );
        admitted
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The per-address rate, before the body is read (SA-27). A request without a client address
/// shares one bucket.
pub async fn client_rate(
    State(rate): State<Arc<ClientRate>>,
    request: Request,
    next: Next,
) -> Response {
    let ip = request
        .extensions()
        .get::<Peer>()
        .map_or(IpAddr::from([0, 0, 0, 0]), |Peer(ip)| *ip);
    if rate.admit(ip, now_ms()) {
        return next.run(request).await;
    }
    let mut r = codes::RATE_LIMITED.problem().into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    r
}

/// A lane: at most `in_flight` requests run, at most `queue` wait for a slot (OP-53).
#[derive(Clone, Debug)]
pub struct Lane {
    name: &'static str,
    slots: Arc<Semaphore>,
    waiting: Arc<AtomicI64>,
    queue: i64,
}

impl Lane {
    /// The lane of `admission`.
    #[must_use]
    pub fn new(admission: &Admission) -> Self {
        Self {
            name: admission.lane,
            slots: Arc::new(Semaphore::new(admission.in_flight.max(1))),
            waiting: Arc::new(AtomicI64::new(0)),
            queue: i64::try_from(admission.queue).unwrap_or(i64::MAX),
        }
    }

    /// Requests waiting now.
    #[must_use]
    pub fn waiting(&self) -> i64 {
        self.waiting.load(Ordering::SeqCst)
    }

    fn wait(&self, by: i64) {
        let n = self
            .waiting
            .fetch_add(by, Ordering::SeqCst)
            .saturating_add(by);
        access_telemetry::signals::POOL_QUEUE_DEPTH.set(n, [self.name]);
    }
}

fn shed() -> Response {
    let mut r = Problem::new(
        StatusCode::SERVICE_UNAVAILABLE,
        "unavailable",
        "Service Unavailable",
    )
    .with_reason(Some("shed"))
    .into_response();
    r.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    r
}

/// Load shedding and the concurrency limit (SA-27, OP-36): a request runs when a slot is free,
/// waits for one in the bounded queue up to [`QUEUE_WAIT`], or is shed with `503`; shedding
/// never admits.
pub async fn lane(State(lane): State<Lane>, request: Request, next: Next) -> Response {
    let permit = if let Ok(p) = lane.slots.clone().try_acquire_owned() {
        p
    } else {
        if lane.waiting() >= lane.queue {
            return shed();
        }
        lane.wait(1);
        let got = tokio::time::timeout(QUEUE_WAIT, lane.slots.clone().acquire_owned()).await;
        lane.wait(-1);
        match got {
            Ok(Ok(p)) => p,
            _ => return shed(),
        }
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-35
    #[test]
    fn an_address_bursts_then_refills_and_another_is_untouched() {
        let rate = ClientRate::new(10, 3);
        let a = IpAddr::from([192, 0, 2, 1]);
        for _ in 0..3 {
            assert!(rate.admit(a, 1_000));
        }
        assert!(!rate.admit(a, 1_000));
        assert!(rate.admit(IpAddr::from([192, 0, 2, 2]), 1_000));
        assert!(rate.admit(a, 1_100));
    }

    // OP-53, OP-36
    #[tokio::test]
    async fn a_waiting_request_is_the_lane_queue_depth() {
        use tower::ServiceExt as _;
        let lane = Lane::new(&Admission {
            lane: "critical",
            in_flight: 1,
            queue: 1,
            per_second: 1,
            burst: 1,
        });
        let gate = Arc::new(tokio::sync::Notify::new());
        let g = gate.clone();
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::get(move || {
                    let g = g.clone();
                    async move {
                        g.notified().await;
                        "done"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(
                lane.clone(),
                super::lane,
            ));
        let get = || {
            axum::http::Request::get("/")
                .body(axum::body::Body::empty())
                .unwrap_or_default()
        };
        let first = tokio::spawn(app.clone().oneshot(get()));
        let busy = tokio::time::timeout(Duration::from_secs(5), async {
            while lane.slots.available_permits() > 0 {
                tokio::task::yield_now().await;
            }
        });
        assert!(busy.await.is_ok());
        let second = tokio::spawn(app.clone().oneshot(get()));
        let queued = tokio::time::timeout(Duration::from_secs(5), async {
            while lane.waiting() == 0 {
                tokio::task::yield_now().await;
            }
        });
        assert!(queued.await.is_ok());
        assert_eq!(lane.waiting(), 1);
        let shed = app.clone().oneshot(get()).await.map(|r| r.status());
        assert_eq!(shed.ok(), Some(StatusCode::SERVICE_UNAVAILABLE));
        gate.notify_one();
        gate.notify_one();
        for h in [first, second] {
            let done = tokio::time::timeout(Duration::from_secs(5), h).await;
            assert!(matches!(done, Ok(Ok(Ok(r))) if r.status() == StatusCode::OK));
        }
        assert_eq!(lane.waiting(), 0);
    }
}
