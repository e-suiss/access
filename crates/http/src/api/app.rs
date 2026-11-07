//! The management API's request path: the request id, the per-row guard (rate limits, caller,
//! idempotency, lifecycle headers), the write helper and the router.

mod guard;
mod handlers;
mod request_id;
pub mod rest;

use std::sync::Arc;

use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use axum::Router;
use axum::body::Bytes;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

pub use request_id::{
    REQUEST_ID, RequestIds, TRACEPARENT, TRACESTATE, request_id, request_id_of, status_class,
};

use super::domain::SurfaceScope;
use super::domain::caller::{ReadCaller, WriteCaller};
use super::manifest::{Builder, MANIFEST, ManifestError, Route};
use super::ports::{Entropy, Env, Proposal, Proposals, Proposed, Unavailable};
use crate::Limits;
use crate::problem::{Code, codes};

/// The management API over its ports.
pub struct Api<E> {
    env: E,
    limits: Limits,
}

impl<E: Env> Api<E> {
    /// The API over `env`, reading bodies up to `limits`.
    #[must_use]
    pub fn new(env: E, limits: Limits) -> Arc<Self> {
        Arc::new(Self { env, limits })
    }

    /// The ports.
    pub const fn env(&self) -> &E {
        &self.env
    }
}

/// The verified caller of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A read token.
    Read(ReadCaller),
    /// An AIS.
    Write(WriteCaller),
}

/// What a guarded handler gets: the API, its manifest row, the surface and its domain, and the
/// verified caller.
pub struct Ctx<E> {
    /// The API.
    pub api: Arc<Api<E>>,
    /// The manifest row.
    pub row: &'static Route,
    /// The surface instance.
    pub scope: SurfaceScope,
    /// Its governing domain.
    pub domain: Digest,
    /// The caller.
    pub caller: Caller,
}

impl<E> Clone for Ctx<E> {
    fn clone(&self) -> Self {
        Self {
            api: self.api.clone(),
            row: self.row,
            scope: self.scope.clone(),
            domain: self.domain,
            caller: self.caller.clone(),
        }
    }
}

/// A committed write: the Exercise record a management write answers with (TN-110).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The `ExerciseID`.
    pub exercise_id: Digest,
    /// Its position in the domain's log.
    pub position: u64,
}

impl Committed {
    /// `{exercise_id, position}`; the position is a string (OP-65: 64-bit integers).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        json!({
            "exercise_id": b64url_encode(&self.exercise_id.0),
            "position": self.position.to_string(),
        })
    }
}

/// Compiles the guarded write into an Exercise through the [`super::ports::Proposals`] port and
/// submits it (TN-110): the only way a management write changes anything. A refusal or a
/// decision that does not allow it is the problem to answer with.
///
/// # Errors
/// `exercise-not-allowed` (403), `exercise-refused` (400), `ais-required` (401) for a read
/// caller, or `unavailable` (503).
pub async fn submit<E: Env>(ctx: &Ctx<E>, body: Bytes) -> Result<Committed, &'static Code> {
    let Caller::Write(caller) = &ctx.caller else {
        return Err(&codes::AIS_REQUIRED);
    };
    let proposal = Proposal {
        scope: ctx.scope.clone(),
        domain: ctx.domain,
        operation: ctx.row.operation_id,
        caller: caller.clone(),
        body,
    };
    match ctx.api.env.proposals().propose(proposal).await {
        Ok(Proposed::Committed {
            exercise_id,
            position,
        }) => Ok(Committed {
            exercise_id,
            position,
        }),
        Ok(Proposed::NotAllowed { .. }) => Err(&codes::EXERCISE_NOT_ALLOWED),
        Ok(Proposed::Refused) => Err(&codes::EXERCISE_REFUSED),
        Err(Unavailable) => Err(&codes::UNAVAILABLE),
    }
}

struct ApiEntropy<E>(Arc<Api<E>>);

impl<E: Env> Entropy for ApiEntropy<E> {
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable> {
        self.0.env.entropy().fill(out)
    }
}

async fn not_found() -> Response {
    codes::NOT_FOUND.problem().into_response()
}

async fn method_not_allowed() -> Response {
    codes::METHOD_NOT_ALLOWED.problem().into_response()
}

/// The management router (OP-151 m.3 (b)): `/admin/v1/*` built from [`MANIFEST`], with the
/// shared hardening and a `Request-Id` on every response. `/console/*` is reserved for the
/// console's BFF and answers `404` until it is served.
///
/// # Errors
/// [`ManifestError`] when a manifest row has no handler.
pub fn router<E: Env>(api: &Arc<Api<E>>) -> Result<Router, ManifestError> {
    router_for(api, MANIFEST, |b| {
        b.handle(
            super::manifest::PLATFORM_ROOT.operation_id,
            handlers::platform_root::<E>,
        )?
        .handle(
            super::manifest::REALM_ROOT.operation_id,
            handlers::realm_root::<E>,
        )
        .and_then(super::realm::register::<_, E>)
    })
}

/// [`router`] over other manifest rows and handlers, for tests of the guard itself.
///
/// # Errors
/// [`ManifestError`].
pub fn router_for<E: Env>(
    api: &Arc<Api<E>>,
    rows: &'static [Route],
    handlers: impl FnOnce(
        Builder<guard::RowGuard<E>>,
    ) -> Result<Builder<guard::RowGuard<E>>, ManifestError>,
) -> Result<Router, ManifestError> {
    let builder = Builder::new(rows, guard::RowGuard::new(api.clone()))?;
    let routes = handlers(builder)?
        .finish()?
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed);
    let ids = RequestIds::new(Arc::new(ApiEntropy(api.clone())));
    Ok(crate::harden(routes, api.limits)
        .layer(axum::middleware::from_fn_with_state(ids, request_id)))
}

/// A `200` JSON answer.
pub(crate) fn json_ok(value: &serde_json::Value) -> Response {
    (StatusCode::OK, axum::Json(value)).into_response()
}

pub use guard::RowGuard;
