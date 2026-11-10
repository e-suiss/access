//! Enterprise upstream sign-in on axum (OP-155 m.3 (h)): `GET /v1/login/upstream/{connection}`
//! and its callback, at the realm's host and under `/realms/{slug}`. Realm selection, cookies
//! and replies are the login surface's.
//!
//! The connection's redirect back is a top-level navigation from another site, so it is not
//! held to the same-origin rule; the attempt it names is bound to this browser's flow cookie and
//! used once. `domain_hint` and `login_hint` are never read (TN-98).

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_federation::ports::{ProviderHttp, SocialSecrets};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::social::Social;
use access_identity_ui::app::upstream::{StartQuery, Upstreams};
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::Extension;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::Response;
use axum::routing::get;

use super::web::{Jar, problem, realm, send};
use super::{Peer, Shared};

struct Svc<D, K, KI, C, M, H, S> {
    login: Shared<D, K, KI, C, M>,
    social: Arc<Social<H, S>>,
    upstreams: Upstreams,
}

type St<D, K, KI, C, M, H, S> = State<Arc<Svc<D, K, KI, C, M, H, S>>>;
type Params0 = Path<HashMap<String, String>>;

/// Longest connection name.
const MAX_NAME: usize = 64;

/// Longest `code`, `state` or `iss`.
const MAX_CODE: usize = 2048;

/// The upstream routes, at the realm's host and under `/realms/{slug}`.
pub fn router<D, K, KI, C, M, H, S>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    social: impl Into<Arc<Social<H, S>>>,
    upstreams: Upstreams,
) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
    KI: Kits + 'static,
    C: Clock + Sync + Send + 'static,
    M: Messages + 'static,
    H: ProviderHttp + 'static,
    S: SocialSecrets + 'static,
{
    let svc = Arc::new(Svc {
        login: Shared {
            discovery,
            hosted: hosted.into(),
            assets: None,
        },
        social: social.into(),
        upstreams,
    });
    let mut r = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        r = r
            .route(
                &format!("{prefix}/v1/login/upstream/{{connection}}"),
                get(start::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/login/upstream/{{connection}}/callback"),
                get(callback::<D, K, KI, C, M, H, S>),
            );
    }
    r.with_state(svc)
}

fn bad() -> Response {
    problem(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request")
}

fn bounded(text: &str, max: usize) -> Result<&str, Response> {
    if text.is_empty() || text.len() > max || text.chars().any(char::is_control) {
        return Err(bad());
    }
    Ok(text)
}

fn connection(p: &HashMap<String, String>) -> Result<&str, Response> {
    let name = p.get("connection").map(String::as_str).unwrap_or_default();
    let ok = name
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_');
    if ok {
        bounded(name, MAX_NAME)
    } else {
        Err(bad())
    }
}

async fn start<D, K, KI, C, M, H, S>(
    State(s): St<D, K, KI, C, M, H, S>,
    Path(p): Params0,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    H: ProviderHttp,
    S: SocialSecrets,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let name = match connection(&p) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let Ok(params) = Params::parse(uri.query().unwrap_or_default()) else {
        return bad();
    };
    // TN-108; TN-98: no other parameter is read
    let ui_locales = params.get("ui_locales").filter(|l| l.len() <= 256);
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .start_upstream(
            &entry,
            &jar.browser(),
            name,
            StartQuery { ui_locales },
            &s.social,
        )
        .await;
    send(reply, &headers).await
}

async fn callback<D, K, KI, C, M, H, S>(
    State(s): St<D, K, KI, C, M, H, S>,
    Path(p): Params0,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
) -> Response
where
    D: Directory,
    K: Keys,
    KI: Kits,
    C: Clock + Sync,
    M: Messages,
    H: ProviderHttp,
    S: SocialSecrets,
{
    let entry = match realm(&s.login, &p, &uri, &headers).await {
        Ok(e) => e,
        Err(r) => return r,
    };
    let name = match connection(&p) {
        Ok(n) => n,
        Err(r) => return r,
    };
    let Ok(params) = Params::parse(uri.query().unwrap_or_default()) else {
        return bad();
    };
    let (Ok(code), Ok(state)) = (
        bounded(params.get("code").unwrap_or_default(), MAX_CODE),
        bounded(params.get("state").unwrap_or_default(), MAX_CODE),
    ) else {
        return bad();
    };
    let iss = match params.get("iss").map(|i| bounded(i, MAX_CODE)).transpose() {
        Ok(i) => i,
        Err(r) => return r,
    };
    let jar = Jar::of(&headers, peer);
    let reply = s
        .login
        .hosted
        .finish_upstream(
            &entry,
            &jar.browser(),
            name,
            (code, state, iss),
            &s.social,
            &s.upstreams,
        )
        .await;
    send(reply, &headers).await
}
