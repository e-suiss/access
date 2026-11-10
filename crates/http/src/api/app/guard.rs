//! The guard every manifest row is served behind (TN-113, TN-126, TN-127, OP-151 m.3 (c), (d)):
//! the route group's rate limit and the surface's concurrency, the caller (read token or AIS),
//! the caller's rate limit and concurrency, `Idempotency-Key` on writes, and the lifecycle and
//! `RateLimit` headers. Every refusal is a problem from the catalogue; nothing reaches the
//! handler unless the row's requirement holds.

use std::sync::Arc;

use access_identity_oauth::domain::issuer::check_slug;
use axum::body::{Body, to_bytes};
use axum::extract::{FromRequestParts, RawPathParams, Request, State};
use axum::handler::Handler;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::routing::MethodRouter;

use super::{Api, Caller, Ctx};
use crate::api::domain::caller::{
    AIS_HEADER, Authorization, ReadCaller, Refusal, WriteCaller, ais_bytes, ais_kid, authorization,
    check_read, verify_ais,
};
use crate::api::domain::idempotency::{self, Answer as Kept};
use crate::api::domain::page::{QueryError, parameters};
use crate::api::domain::rate::{
    self, ACTOR_CONCURRENCY, BucketKey, Quota, SURFACE_CONCURRENCY, Take,
};
use crate::api::domain::{Surface, SurfaceScope};
use crate::api::manifest::{Access, Answer, GROUPS, Guard, Route, Visibility, method_router};
use crate::api::ports::{
    Begun, Env, IdempotencyStore, Presented, RateLimiter, ReadTokens, Surfaces, Unavailable,
};
use crate::problem::{Code, codes};

const IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");
const RATELIMIT_POLICY: HeaderName = HeaderName::from_static("ratelimit-policy");
const RATELIMIT: HeaderName = HeaderName::from_static("ratelimit");
const DPOP: HeaderName = HeaderName::from_static("dpop");

/// The guard of one API's rows.
pub struct RowGuard<E>(Arc<Api<E>>);

impl<E> Clone for RowGuard<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E: Env> RowGuard<E> {
    pub(crate) const fn new(api: Arc<Api<E>>) -> Self {
        Self(api)
    }
}

impl<E: Env> Guard for RowGuard<E> {
    fn wrap<H, T>(&self, row: &'static Route, handler: H) -> MethodRouter
    where
        H: Handler<T, ()>,
        T: 'static,
    {
        method_router(row, handler).route_layer(from_fn_with_state(
            Guarded {
                api: self.0.clone(),
                row,
            },
            guard::<E>,
        ))
    }
}

struct Guarded<E> {
    api: Arc<Api<E>>,
    row: &'static Route,
}

impl<E> Clone for Guarded<E> {
    fn clone(&self) -> Self {
        Self {
            api: self.api.clone(),
            row: self.row,
        }
    }
}

/// Releases a concurrency slot when the request ends, however it ends.
struct Slot<'a> {
    limiter: &'a dyn RateLimiter,
    key: String,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.limiter.leave(&self.key);
    }
}

/// The `RateLimit` items the response carries.
#[derive(Default)]
struct Limits(Vec<(Quota, Take)>);

impl Limits {
    fn stamp(&self, mut response: Response) -> Response {
        let policy = self
            .0
            .iter()
            .map(|(q, _)| q.policy_item())
            .collect::<Vec<_>>()
            .join(", ");
        let state = self
            .0
            .iter()
            .map(|(q, t)| rate::limit_item(*q, *t))
            .collect::<Vec<_>>()
            .join(", ");
        let headers = response.headers_mut();
        for (name, value) in [(RATELIMIT_POLICY, policy), (RATELIMIT, state)] {
            if let Ok(v) = HeaderValue::from_str(&value)
                && !value.is_empty()
            {
                headers.insert(name, v);
            }
        }
        response
    }
}

fn problem(code: &Code) -> Response {
    code.problem().into_response()
}

fn refusal(r: Refusal, visibility: Visibility) -> Response {
    let code = match r {
        Refusal::InvalidToken => &codes::INVALID_TOKEN,
        Refusal::WrongAudience => &codes::WRONG_AUDIENCE,
        Refusal::TokenLifetime => &codes::TOKEN_LIFETIME,
        Refusal::InsufficientScope if visibility == Visibility::Hidden => &codes::NOT_FOUND,
        Refusal::InsufficientScope => &codes::INSUFFICIENT_SCOPE,
        Refusal::AisRequired => &codes::AIS_REQUIRED,
        Refusal::AisInvalid => &codes::AIS_INVALID,
        Refusal::AisRejected => &codes::AIS_REJECTED,
    };
    let mut response = problem(code);
    if matches!(
        r,
        Refusal::InvalidToken | Refusal::WrongAudience | Refusal::TokenLifetime
    ) {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("DPoP error=\"invalid_token\""),
        );
    }
    response
}

fn throttled(surface: Surface, layer: &'static str, quota: Option<Quota>, wait_s: u64) -> Response {
    // TN-127, OP-151 m.3 (d)
    tracing::warn!(
        event = "api.throttled",
        outcome = "refused",
        surface = surface.name(),
        layer,
        policy = quota.map_or("concurrency", |q| q.name),
        "management API rate limit reached"
    );
    let mut response = problem(&codes::RATE_LIMITED);
    if let Ok(v) = HeaderValue::from_str(&wait_s.max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, v);
    }
    response
}

async fn scope_of(row: &Route, parts: &mut Parts) -> Option<SurfaceScope> {
    match row.surface {
        Surface::Platform => Some(SurfaceScope::Platform),
        Surface::Realm => {
            let params = RawPathParams::from_request_parts(parts, &()).await.ok()?;
            let slug = params.iter().find(|(k, _)| *k == "slug")?.1;
            check_slug(slug).ok()?;
            Some(SurfaceScope::Realm(slug.to_owned()))
        }
    }
}

fn values<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<Vec<&'a str>> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().ok())
        .collect()
}

async fn guard<E: Env>(State(g): State<Guarded<E>>, request: Request, next: Next) -> Response {
    let mut limits = Limits::default();
    let response = run(&g, request, next, &mut limits).await;
    limits.stamp(response)
}

#[expect(
    clippy::too_many_lines,
    reason = "one guard in the order the manifest row is enforced; splitting hides the order"
)]
async fn run<E: Env>(
    g: &Guarded<E>,
    request: Request,
    next: Next,
    limits: &mut Limits,
) -> Response {
    let (row, env) = (g.row, &g.api.env);
    let limiter = env.limiter();
    let Ok(now) = env.clock().now_ms() else {
        return problem(&codes::UNAVAILABLE);
    };
    let (mut parts, body) = request.into_parts();
    let Some(scope) = scope_of(row, &mut parts).await else {
        return problem(&codes::NOT_FOUND);
    };
    match parameters(parts.uri.query(), row.query) {
        Ok(_) => {}
        Err(QueryError::Unknown | QueryError::PageSize) => {
            return problem(&codes::UNKNOWN_QUERY_PARAMETER);
        }
    }
    let write = row.access == Access::Write;
    let surface = row.surface;
    let group = rate::group_of(row.path, GROUPS);
    // TN-127
    let quota = rate::group_quota(surface, write);
    let key = BucketKey {
        layer: "group",
        scope: scope.key(),
        method: parts.method.as_str().to_owned(),
        group,
        caller: None,
    };
    let take = limiter.take(&key, quota, now);
    if !take.allowed {
        return throttled(surface, "group", Some(quota), take.reset_s);
    }
    // TN-127
    let surface_slot = format!("surface:{}", scope.key());
    if !limiter.enter(&surface_slot, SURFACE_CONCURRENCY) {
        return throttled(surface, "concurrency", None, 1);
    }
    let _surface_slot = Slot {
        limiter,
        key: surface_slot,
    };
    // OP-156 m.3 (q)
    let limit = crate::api::realm::body_limit(row.operation_id)
        .map_or(g.api.limits.max_body_bytes, |l| {
            l.max(g.api.limits.max_body_bytes)
        });
    let Ok(body) = to_bytes(body, limit).await else {
        return problem(&codes::BODY_TOO_LARGE);
    };
    let auth = values(&parts.headers, &header::AUTHORIZATION).unwrap_or_else(|| vec!["\0"]);
    let (caller, caller_key, domain) = match row.access {
        Access::Read { scope: required } => {
            let Authorization::Dpop(token) = authorization(&auth) else {
                return refusal(Refusal::InvalidToken, row.visibility);
            };
            let proofs = values(&parts.headers, &DPOP).unwrap_or_default();
            let uri = format!("{}{}", env.origin(), parts.uri.path());
            let presented = Presented {
                token,
                proofs: &proofs,
                method: parts.method.as_str(),
                uri: &uri,
            };
            let token = match env.tokens().verify(presented).await {
                Ok(Some(t)) => t,
                Ok(None) => return refusal(Refusal::InvalidToken, row.visibility),
                Err(Unavailable) => return problem(&codes::UNAVAILABLE),
            };
            if let Err(r) = check_read(&token, &scope, required, now) {
                return refusal(r, row.visibility);
            }
            let domain = match env.surfaces().domain(&scope).await {
                Ok(Some(d)) => d,
                Ok(None) => return problem(&codes::NOT_FOUND),
                Err(Unavailable) => return problem(&codes::UNAVAILABLE),
            };
            let key = token.id;
            (
                Caller::Read(ReadCaller {
                    scope: scope.clone(),
                    token,
                }),
                key,
                domain,
            )
        }
        Access::Write => {
            // TN-110, TN-130
            let header_ais = values(&parts.headers, &HeaderName::from_static(AIS_HEADER))
                .unwrap_or_else(|| vec!["\0", "\0"]);
            let sign1 = match ais_bytes(&header_ais, &body) {
                Ok(b) => b,
                Err(r) => return refusal(r, row.visibility),
            };
            let kid = match ais_kid(&sign1) {
                Ok(k) => k,
                Err(r) => return refusal(r, row.visibility),
            };
            let domain = match env.surfaces().domain(&scope).await {
                Ok(Some(d)) => d,
                Ok(None) => return problem(&codes::NOT_FOUND),
                Err(Unavailable) => return problem(&codes::UNAVAILABLE),
            };
            let key = match env.surfaces().instance_key(domain, kid, now).await {
                Ok(Some(k)) => k,
                Ok(None) => return refusal(Refusal::AisRejected, row.visibility),
                Err(Unavailable) => return problem(&codes::UNAVAILABLE),
            };
            let caller = match verify_ais(sign1, kid, &key, &domain, now) {
                Ok(c) => c,
                Err(r) => return refusal(r, row.visibility),
            };
            (Caller::Write(caller), kid, domain)
        }
    };
    // TN-127
    let actor_quota = rate::actor_quota(surface, write);
    let actor = BucketKey {
        layer: "actor",
        scope: scope.key(),
        method: parts.method.as_str().to_owned(),
        group,
        caller: Some(caller_key),
    };
    let actor_take = limiter.take(&actor, actor_quota, now);
    if !actor_take.allowed {
        return throttled(surface, "actor", Some(actor_quota), actor_take.reset_s);
    }
    limits.0.push((quota, take));
    limits.0.push((actor_quota, actor_take));
    let actor_slot = format!("actor:{}", crate::api::domain::trace::to_hex(&caller_key));
    if !limiter.enter(&actor_slot, ACTOR_CONCURRENCY) {
        return throttled(surface, "concurrency", None, 1);
    }
    let _actor_slot = Slot {
        limiter,
        key: actor_slot,
    };
    let lifecycle = row.lifecycle.map(|l| l.headers()).unwrap_or_default();
    let ctx = Ctx {
        api: g.api.clone(),
        row,
        scope: scope.clone(),
        domain,
        caller: caller.clone(),
    };
    let response = match caller {
        Caller::Write(w) => idempotent(g, &scope, &w, (parts, body), next, ctx, now).await,
        Caller::Read(_) => {
            parts.extensions.insert(ctx);
            next.run(Request::from_parts(parts, Body::from(body))).await
        }
    };
    with_headers(response, &lifecycle)
}

fn with_headers(mut response: Response, extra: &[(&'static str, String)]) -> Response {
    for (name, value) in extra {
        if let Ok(v) = HeaderValue::from_str(value) {
            response
                .headers_mut()
                .append(HeaderName::from_static(name), v);
        }
    }
    response
}

/// `Idempotency-Key` on a write (TN-126, OP-151 m.3 (c)).
async fn idempotent<E: Env>(
    g: &Guarded<E>,
    scope: &SurfaceScope,
    caller: &WriteCaller,
    (mut parts, body): (Parts, axum::body::Bytes),
    next: Next,
    ctx: Ctx<E>,
    now: u64,
) -> Response {
    let store = g.api.env.idempotency();
    let mut keys = parts.headers.get_all(&IDEMPOTENCY_KEY).iter();
    let key = match (keys.next(), keys.next()) {
        (None, _) => return problem(&codes::IDEMPOTENCY_KEY_REQUIRED),
        (Some(k), None) if idempotency::valid_key(k.as_bytes()) => k.as_bytes().to_vec(),
        _ => return problem(&codes::IDEMPOTENCY_KEY_INVALID),
    };
    if key != caller.idempotency_key().as_bytes() {
        return problem(&codes::IDEMPOTENCY_KEY_NOT_NONCE);
    }
    let key_scope = idempotency::scope(scope, &caller.kid, &key);
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), |p| p.as_str().to_owned());
    let request = idempotency::request(parts.method.as_str(), &path, &body);
    match store.begin(key_scope, request, now).await {
        Ok(Begun::Run) => {}
        Ok(Begun::Replay(stored)) => {
            return Kept::decode(&stored).map_or_else(|| problem(&codes::INTERNAL), replay);
        }
        Ok(Begun::Reused) => return problem(&codes::IDEMPOTENCY_KEY_REUSED),
        Ok(Begun::Running) => return problem(&codes::IDEMPOTENCY_KEY_IN_USE),
        Err(Unavailable) => return problem(&codes::UNAVAILABLE),
    }
    parts.extensions.insert(ctx);
    let response = next.run(Request::from_parts(parts, Body::from(body))).await;
    let status = response.status();
    let (rparts, rbody) = response.into_parts();
    let Ok(rbody) = to_bytes(rbody, idempotency::MAX_ANSWER).await else {
        return problem(&codes::INTERNAL);
    };
    let kept = Kept {
        status: status.as_u16(),
        headers: rparts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect(),
        body: rbody.to_vec(),
    };
    let keep = g.row.answer == Answer::Replay
        && status != StatusCode::BAD_REQUEST
        && !status.is_server_error();
    let stored = if keep { kept.encode() } else { None };
    if store.finish(key_scope, request, stored).await.is_err() {
        tracing::warn!(
            event = "api.idempotency.unrecorded",
            outcome = "error",
            "an idempotency answer was not recorded"
        );
    }
    replay(kept)
}

fn replay(kept: Kept) -> Response {
    let status = StatusCode::from_u16(kept.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, kept.body).into_response();
    response.headers_mut().clear();
    for (name, value) in kept.headers {
        if let (Ok(n), Ok(v)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(&value),
        ) {
            response.headers_mut().append(n, v);
        }
    }
    response
}

impl<E> std::fmt::Debug for Guarded<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Guarded")
            .field("operation", &self.row.operation_id)
            .finish_non_exhaustive()
    }
}
