//! A domain's algorithm allowlist and its post-quantum re-anchor on request (§15.16, CR-45
//! RA-6, OP-159 m.3 (e), (f), (g), m.9 (h)), for an authenticated PEP:
//! - `POST /access/v1/domains/{domain}/algorithms` `{"alg": <COSE id>}`: an algorithm joins
//!   the allowlist through `admit_algorithm` behind the CT3 time-lock. The first request opens
//!   it (`202`, `wait_until`); the same request after the lock and before it lapses admits the
//!   algorithm (`200`).
//! - `POST /access/v1/domains/{domain}/algorithms/retire`: the body is the ADP request of the
//!   root's `algorithm_retire` Exercise. A re-anchor runs first; without an anchored re-anchor
//!   that covers the head within the cadence the answer is `409 reanchor-required` and nothing
//!   is recorded. Then the Exercise is decided, and only an allowed one retires the algorithm
//!   from the signer's allowlist and notifies the roots and domain administrators.
//! - `POST /access/v1/domains/{domain}/reanchor`: one re-anchor of the latest witnessed
//!   checkpoint now.

use std::future::Future;
use std::sync::Arc;

use access_authority_core::app::Incoming;
use access_kernel::combinator::Outcome;
use access_kernel::digest::Digest;
use access_kernel::meta::Payload;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use suiss_crypto::cose::Algorithm;

use crate::Problem;
use crate::adp::adapters::{Pep, domain_id, respond};
use crate::adp::app::{Reply, bad, failed};
use crate::adp::domain::{Body as AdpBody, decode, encode};
use crate::adp::ports::Pdp;
use crate::problem::codes;

/// The admit route.
pub const ADMIT_PATH: &str = "/access/v1/domains/{domain}/algorithms";

/// The retirement route.
pub const RETIRE_PATH: &str = "/access/v1/domains/{domain}/algorithms/retire";

/// The re-anchor on request route.
pub const REANCHOR_PATH: &str = "/access/v1/domains/{domain}/reanchor";

/// Longest admit body.
const MAX_ADMIT: usize = 256;

/// Longest retirement body.
const MAX_RETIRE: usize = 1 << 16;

/// Why an allowlist change or a re-anchor is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AlgorithmError {
    /// No such domain.
    #[error("unknown domain")]
    Unknown,
    /// The domain declares the FIPS profile (CR-44, L0-SIG-82), or the algorithm is not one the
    /// change applies to.
    #[error("algorithm profile conflict")]
    Conflict,
    /// No anchored re-anchor covers the head within the cadence (RA-6).
    #[error("re-anchor required")]
    ReanchorRequired,
    /// No independent witness with a declared ML-DSA key (RB-0).
    #[error("no post-quantum witness")]
    NoPqWitness,
    /// No independently witnessed checkpoint to re-anchor yet (SEC23).
    #[error("checkpoint not witnessed")]
    NotWitnessed,
    /// No ML-DSA key or binding (CR-18, OP-159 m.3 (d)).
    #[error("post-quantum key unavailable")]
    PqKeyUnavailable,
    /// The signer or the store could not be reached.
    #[error("unavailable")]
    Unavailable,
}

/// Where an admission stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// The time-lock runs until this Unix ms.
    Locked(u64),
    /// The algorithm is in the allowlist.
    Admitted,
}

/// Where a re-anchor stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reanchored {
    /// No independent witness cosigned it yet; nothing is called anchored.
    Pending,
    /// Anchored at this size and time by these witnesses.
    Anchored {
        /// Tree size.
        size: u64,
        /// Unix ms.
        time: u64,
        /// The cosigning witnesses.
        witnesses: Vec<String>,
    },
}

/// The allowlist and re-anchor side of the signer and the store.
pub trait Algorithms: Send + Sync {
    /// Admits `alg` to `domain`'s allowlist behind the CT3 time-lock at `now`.
    fn admit(
        &self,
        domain: Digest,
        alg: Algorithm,
        now: u64,
    ) -> impl Future<Output = Result<Admission, AlgorithmError>> + Send;

    /// One re-anchor of `domain` at `now`, for a retirement or on request.
    fn reanchor(
        &self,
        domain: Digest,
        retirement: bool,
        now: u64,
    ) -> impl Future<Output = Result<Reanchored, AlgorithmError>> + Send;

    /// Whether `domain` may retire `alg` at `now`: the size of the re-anchor that covers it.
    fn retirable(
        &self,
        domain: Digest,
        alg: Algorithm,
        now: u64,
    ) -> impl Future<Output = Result<u64, AlgorithmError>> + Send;

    /// Retires `retired` = (alg, the allowed Exercise, the re-anchor size) from `domain`'s allowlist, and
    /// notifies the roots and domain administrators.
    fn retire(
        &self,
        domain: Digest,
        retired: (Algorithm, Digest, u64),
        now: u64,
    ) -> impl Future<Output = Result<(), AlgorithmError>> + Send;
}

struct Shared<A, P> {
    algorithms: A,
    pdp: P,
    now: fn() -> u64,
}

/// The routes over `algorithms` and the decision point `pdp`, with the clock `now`.
pub fn router<A: Algorithms + 'static, P: Pdp + 'static>(
    algorithms: A,
    pdp: P,
    now: fn() -> u64,
) -> Router {
    Router::new()
        .route(ADMIT_PATH, post(admit::<A, P>))
        .route(RETIRE_PATH, post(retire::<A, P>))
        .route(REANCHOR_PATH, post(reanchor::<A, P>))
        .with_state(Arc::new(Shared {
            algorithms,
            pdp,
            now,
        }))
}

fn refused(e: AlgorithmError) -> Response {
    match e {
        AlgorithmError::Unknown => codes::NOT_FOUND.problem().into_response(),
        AlgorithmError::Conflict => codes::assurance::ALGORITHM_PROFILE_CONFLICT
            .problem()
            .into_response(),
        AlgorithmError::ReanchorRequired => codes::assurance::REANCHOR_REQUIRED
            .problem()
            .into_response(),
        AlgorithmError::PqKeyUnavailable => codes::assurance::PQ_KEY_UNAVAILABLE
            .problem()
            .into_response(),
        AlgorithmError::NoPqWitness => {
            Problem::new(StatusCode::CONFLICT, "reanchor-no-pq-witness", "Conflict").into_response()
        }
        AlgorithmError::NotWitnessed => {
            Problem::new(StatusCode::CONFLICT, "checkpoint-not-witnessed", "Conflict")
                .into_response()
        }
        AlgorithmError::Unavailable => codes::UNAVAILABLE.problem().into_response(),
    }
}

fn unauthenticated() -> Response {
    Problem::new(StatusCode::UNAUTHORIZED, "pep-required", "Unauthorized").into_response()
}

fn invalid() -> Response {
    codes::INVALID_REQUEST.problem().into_response()
}

fn algorithm(body: &[u8]) -> Option<Algorithm> {
    let v = access_kernel::json::parse(body, MAX_ADMIT).ok()?;
    let id = v.get("alg")?.as_int()?;
    Algorithm::from_cose(id)
}

// OP-159 m.3 (e), m.9 (h)
async fn admit<A: Algorithms, P: Pdp>(
    State(s): State<Arc<Shared<A, P>>>,
    Path(domain): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    body: Bytes,
) -> Response {
    if pep.is_none() {
        return unauthenticated();
    }
    let Some(d) = domain_id(&domain) else {
        return refused(AlgorithmError::Unknown);
    };
    let Some(alg) = algorithm(&body) else {
        return invalid();
    };
    match s.algorithms.admit(d, alg, (s.now)()).await {
        Ok(Admission::Locked(until)) => (
            StatusCode::ACCEPTED,
            axum::Json(serde_json::json!({
                "status": "time-lock",
                "alg": alg.cose(),
                "wait_until": until,
            })),
        )
            .into_response(),
        Ok(Admission::Admitted) => axum::Json(serde_json::json!({
            "status": "admitted",
            "alg": alg.cose(),
        }))
        .into_response(),
        Err(e) => refused(e),
    }
}

fn anchored(r: &Reanchored) -> serde_json::Value {
    match r {
        Reanchored::Pending => serde_json::json!({ "status": "pending" }),
        Reanchored::Anchored {
            size,
            time,
            witnesses,
        } => serde_json::json!({
            "status": "anchored",
            "size": size,
            "time": time,
            "witnesses": witnesses,
        }),
    }
}

// CR-45 RA-6, OP-159 m.3 (g)
async fn reanchor<A: Algorithms, P: Pdp>(
    State(s): State<Arc<Shared<A, P>>>,
    Path(domain): Path<String>,
    pep: Option<axum::Extension<Pep>>,
) -> Response {
    if pep.is_none() {
        return unauthenticated();
    }
    let Some(d) = domain_id(&domain) else {
        return refused(AlgorithmError::Unknown);
    };
    match s.algorithms.reanchor(d, false, (s.now)()).await {
        Ok(r) => axum::Json(anchored(&r)).into_response(),
        Err(e) => refused(e),
    }
}

// §15.16, CR-45 RA-6, OP-159 m.3 (f)
async fn retire<A: Algorithms, P: Pdp>(
    State(s): State<Arc<Shared<A, P>>>,
    Path(domain): Path<String>,
    pep: Option<axum::Extension<Pep>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(axum::Extension(Pep(pep))) = pep else {
        return unauthenticated();
    };
    let Some(d) = domain_id(&domain) else {
        return refused(AlgorithmError::Unknown);
    };
    let decoded = match decode(&body, MAX_RETIRE) {
        Ok(x) => x,
        Err(e) => return respond(bad(e, AdpBody::Context), &headers),
    };
    let Some(Payload::AlgorithmRetire { algorithm }) = decoded.request.payload.as_ref() else {
        return invalid();
    };
    let alg = *algorithm;
    if decoded.request.domain != d {
        return invalid();
    }
    let now = (s.now)();
    // RA-6
    if let Err(e) = s.algorithms.reanchor(d, true, now).await
        && e == AlgorithmError::Unavailable
    {
        return refused(e);
    }
    let size = match s.algorithms.retirable(d, alg, now).await {
        Ok(size) => size,
        Err(e) => return refused(e),
    };
    let mode = decoded.request.mode;
    let inc = Incoming {
        request: decoded.request,
        ais: decoded.ais,
        pep,
        requester: None,
        explain: false,
        status: None,
        context: decoded.context,
    };
    let r = match s.pdp.evaluate(inc).await {
        Ok(r) => r,
        Err(e) => return respond(failed(e, AdpBody::Context), &headers),
    };
    let (Outcome::Allow, Some(exercise)) = (r.decision.outcome, r.exercise) else {
        return respond(Reply::Decision(encode(&r, mode)), &headers);
    };
    match s.algorithms.retire(d, (alg, exercise, size), now).await {
        Ok(()) => respond(Reply::Decision(encode(&r, mode)), &headers),
        Err(e) => refused(e),
    }
}

#[cfg(test)]
mod tests;
