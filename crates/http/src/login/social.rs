//! Social sign-in, linked sign-ins and combined accounts on axum (IDP-31, OP-153 m.3 (l), (m)):
//! the `frontend-v1` routes of lane N4. Realm selection, cookies and replies are the login
//! surface's.
//!
//! The provider's redirect back is a top-level navigation from another site, so it is not held
//! to the same-origin rule; the attempt it names is bound to this browser's flow cookie and used
//! once. Apple's `form_post` answer is turned into the same `GET`.

#![allow(
    clippy::result_large_err,
    reason = "a refusal is the reply itself, built once per request"
)]

use std::collections::HashMap;
use std::sync::Arc;

use access_identity_federation::ports::{ProviderHttp, SocialSecrets};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::form_encode;
use access_identity_oauth::domain::request::Params;
use access_identity_oauth::ports::{Directory, Keys};
use access_identity_ui::app::Hosted;
use access_identity_ui::app::social::Social;
use access_identity_ui::ports::{Clock, Kits, Messages};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Extension, Router};
use serde::Deserialize;

use super::web::{Jar, json_only, problem, realm, same_origin, send};
use super::{Peer, Shared, idempotency};

struct Svc<D, K, KI, C, M, H, S> {
    login: Shared<D, K, KI, C, M>,
    social: Arc<Social<H, S>>,
}

type St<D, K, KI, C, M, H, S> = State<Arc<Svc<D, K, KI, C, M, H, S>>>;
type Params0 = Path<HashMap<String, String>>;

/// Longest provider name.
const MAX_PROVIDER: usize = 64;

/// Longest `code` or `state`.
const MAX_CODE: usize = 2048;

/// The routes of lane N4, at the realm's host and under `/realms/{slug}`.
pub fn router<D, K, KI, C, M, H, S>(
    discovery: Discovery<D, K>,
    hosted: impl Into<Arc<Hosted<KI, C, M>>>,
    social: impl Into<Arc<Social<H, S>>>,
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
    });
    let mut writes = Router::new();
    let mut reads = Router::new();
    for prefix in ["", "/realms/{slug}"] {
        writes = writes
            .route(
                &format!("{prefix}/v1/account/linked"),
                post(start_link::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/linked/{{link}}"),
                delete(unlink::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/combine"),
                post(combine::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/connected-apps"),
                post(share::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/connected-apps/preview"),
                post(share_preview::<D, K, KI, C, M, H, S>),
            )
            // OP-153 m.2 N5
            .route(
                &format!("{prefix}/v1/account/connected-apps/decline"),
                post(decline::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/connected-apps/{{client}}"),
                delete(stop_sharing::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/bindings"),
                post(offer_binding::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/connect/preview"),
                post(connect_preview::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/bindings/accept"),
                post(accept_binding::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/bindings/complete"),
                post(complete_binding::<D, K, KI, C, M, H, S>),
            );
        reads = reads
            .route(
                &format!("{prefix}/v1/login/social/{{provider}}"),
                get(start::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/login/social/{{provider}}/callback"),
                get(callback::<D, K, KI, C, M, H, S>).post(form_post),
            )
            .route(
                &format!("{prefix}/v1/account/linked"),
                get(linked::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/connected-apps"),
                get(connected::<D, K, KI, C, M, H, S>),
            )
            .route(
                &format!("{prefix}/v1/account/bindings"),
                get(bindings::<D, K, KI, C, M, H, S>),
            );
    }
    let cache = Arc::new(idempotency::Cache::default());
    writes
        .route_layer(axum::middleware::from_fn_with_state(
            cache,
            idempotency::layer,
        ))
        .merge(reads)
        .with_state(svc)
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

fn provider(p: &HashMap<String, String>) -> Result<&str, Response> {
    let name = p.get("provider").map(String::as_str).unwrap_or_default();
    let ok = name
        .bytes()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_');
    if ok {
        bounded(name, MAX_PROVIDER)
    } else {
        Err(bad())
    }
}

macro_rules! handler {
    (
        $(#[$doc:meta])*
        $name:ident($s:ident, $entry:ident, $jar:ident, $p:ident, $bytes:ident, $headers:ident, $uri:ident) $write:literal $body:block
    ) => {
        $(#[$doc])*
        async fn $name<D, K, KI, C, M, H, S>(
            State($s): St<D, K, KI, C, M, H, S>,
            Path($p): Params0,
            peer: Option<Extension<Peer>>,
            $uri: Uri,
            $headers: HeaderMap,
            $bytes: Bytes,
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
            let $entry = match realm(&$s.login, &$p, &$uri, &$headers).await {
                Ok(e) => e,
                Err(r) => return r,
            };
            if $write && let Err(r) = same_origin(&$headers) {
                return r;
            }
            if $write && !$bytes.is_empty() && let Err(r) = json_only(&$headers) {
                return r;
            }
            let $jar = Jar::of(&$headers, peer);
            let reply = async { $body }.await;
            match reply {
                Ok(r) => send(r, &$headers).await,
                Err(r) => r,
            }
        }
    };
}

handler! {
    /// `GET /v1/login/social/{provider}` (OP-153 m.3 (l)).
    start(s, entry, jar, p, bytes, headers, uri) false {
        let _ = (&bytes, &uri);
        let name = provider(&p)?;
        Ok(s.login.hosted.start_social(&entry, &jar.browser(), name, &s.social).await)
    }
}

handler! {
    /// `GET /v1/login/social/{provider}/callback` (§10.2.6).
    callback(s, entry, jar, p, bytes, headers, uri) false {
        let _ = &bytes;
        let name = provider(&p)?;
        let params = Params::parse(uri.query().unwrap_or_default()).map_err(|_| bad())?;
        let code = bounded(params.get("code").unwrap_or_default(), MAX_CODE)?;
        let state = bounded(params.get("state").unwrap_or_default(), MAX_CODE)?;
        Ok(s.login
            .hosted
            .finish_social(&entry, &jar.browser(), name, (code, state), &s.social)
            .await)
    }
}

/// `POST /v1/login/social/{provider}/callback`: a provider's `form_post` answer (Apple) comes
/// from another site without this browser's cookies; it becomes the `GET` above, which carries
/// them as a top-level navigation.
async fn form_post(Path(p): Params0, uri: Uri, bytes: Bytes) -> Response {
    let Ok(name) = provider(&p) else {
        return bad();
    };
    let Ok(form) = core::str::from_utf8(&bytes) else {
        return bad();
    };
    let Ok(params) = Params::parse(form) else {
        return bad();
    };
    let (Some(code), Some(state)) = (params.get("code"), params.get("state")) else {
        return bad();
    };
    let base = uri.path().trim_end_matches("/callback");
    let mut to = format!("{base}/callback?code=");
    form_encode(code, &mut to);
    to.push_str("&state=");
    form_encode(state, &mut to);
    let _ = name;
    let mut r = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(&to) {
        r.headers_mut().insert(header::LOCATION, v);
    }
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkBody {
    provider: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CombineBody {
    ticket: Option<String>,
}

handler! {
    /// `GET /v1/account/linked`.
    linked(s, entry, jar, p, bytes, headers, uri) false {
        let _ = (&p, &bytes, &uri);
        Ok(s.login.hosted.linked(&entry, &jar.browser()).await)
    }
}

handler! {
    /// `POST /v1/account/linked` (TN-65).
    start_link(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: LinkBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let mut m = HashMap::new();
        m.insert(String::from("provider"), req.provider);
        let name = provider(&m)?;
        Ok(s.login.hosted.start_link(&entry, &jar.browser(), name, &s.social).await)
    }
}

handler! {
    /// `DELETE /v1/account/linked/{link}`.
    unlink(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&bytes, &uri);
        let link = bounded(p.get("link").map(String::as_str).unwrap_or_default(), 64)?;
        Ok(s.login.hosted.unlink(&entry, &jar.browser(), link).await)
    }
}

handler! {
    /// `POST /v1/account/combine` (OP-153 m.3 (m)).
    combine(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: CombineBody = if bytes.is_empty() {
            CombineBody { ticket: None }
        } else {
            serde_json::from_slice(&bytes).map_err(|_| bad())?
        };
        let ticket = req.ticket.as_deref().map(|t| bounded(t, 64)).transpose()?;
        Ok(s.login.hosted.combine(&entry, &jar.browser(), ticket).await)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareBody {
    return_to: String,
}

/// Longest `return_to`.
const MAX_RETURN_TO: usize = 2048;

handler! {
    /// `GET /v1/account/connected-apps` (OP-153 m.3 (z)).
    connected(s, entry, jar, p, bytes, headers, uri) false {
        let _ = (&p, &bytes, &uri);
        Ok(s.login.hosted.connected_apps(&entry, &jar.browser()).await)
    }
}

handler! {
    /// `POST /v1/account/connected-apps/preview` (OP-153 m.3 (z)).
    share_preview(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: ShareBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let to = bounded(&req.return_to, MAX_RETURN_TO)?;
        Ok(s.login.hosted.share_preview(&entry, &jar.browser(), to).await)
    }
}

handler! {
    /// `POST /v1/account/connected-apps/decline` (OP-153 m.3 (z), X-L8).
    decline(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: ShareBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let to = bounded(&req.return_to, MAX_RETURN_TO)?;
        Ok(s.login.hosted.decline(&entry, &jar.browser(), to).await)
    }
}

handler! {
    /// `POST /v1/account/connected-apps` (OP-153 m.3 (z)).
    share(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: ShareBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let to = bounded(&req.return_to, MAX_RETURN_TO)?;
        Ok(s.login.hosted.share(&entry, &jar.browser(), to).await)
    }
}

handler! {
    /// `DELETE /v1/account/connected-apps/{client}` (OP-153 m.3 (z)).
    stop_sharing(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&bytes, &uri);
        let client = bounded(p.get("client").map(String::as_str).unwrap_or_default(), 255)?;
        Ok(s.login.hosted.stop_sharing(&entry, &jar.browser(), client).await)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenBody {
    token: String,
}

handler! {
    /// `GET /v1/account/bindings` (§12.1.3).
    bindings(s, entry, jar, p, bytes, headers, uri) false {
        let _ = (&p, &bytes, &uri);
        Ok(s.login.hosted.bindings(&entry, &jar.browser()).await)
    }
}

handler! {
    /// `POST /v1/account/bindings` (§12.1.3, TN-65).
    offer_binding(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &bytes, &uri);
        Ok(s.login.hosted.offer_binding(&entry, &jar.browser()).await)
    }
}

handler! {
    /// `POST /v1/account/bindings/accept` (§12.1.3).
    accept_binding(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: TokenBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let token = bounded(&req.token, 128)?;
        Ok(s.login.hosted.bind_half(&entry, &jar.browser(), token, true).await)
    }
}

handler! {
    /// `POST /v1/account/bindings/complete` (§12.1.3).
    complete_binding(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: TokenBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let token = bounded(&req.token, 128)?;
        Ok(s.login.hosted.bind_half(&entry, &jar.browser(), token, false).await)
    }
}

handler! {
    /// `POST /v1/account/connect/preview` (§8.17.4.3, X27).
    connect_preview(s, entry, jar, p, bytes, headers, uri) true {
        let _ = (&p, &uri);
        let req: ShareBody = serde_json::from_slice(&bytes).map_err(|_| bad())?;
        let to = bounded(&req.return_to, MAX_RETURN_TO)?;
        Ok(s.login.hosted.connect_preview(&entry, &jar.browser(), to).await)
    }
}
