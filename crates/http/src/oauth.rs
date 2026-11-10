//! The realm authorization server over HTTP (OP-146 I7, §11.4.5): `/authorize`, `/par`,
//! `/token`, `/userinfo`, `/revoke`, `/introspect` and `/end-session`, at the host root for a
//! subdomain issuer and under `/realms/{slug}` for a path issuer. Bodies are
//! `application/x-www-form-urlencoded` only (§11.4.5 #19); every answer is `no-store`; an
//! outage is `503 + Retry-After` (G50).

use std::sync::Arc;

use access_identity_oauth::app::oauth::{Env, OAuth, RETRY_AFTER_S, Realm, Reply, TokenHttp};
use access_identity_oauth::domain::metadata::Endpoint;
use access_identity_oauth::domain::request::Params;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::Problem;

pub mod approval;
mod ciba;
mod device;
mod register;

/// The session cookie of the hosted login (TN-17).
pub const SESSION_COOKIE: &str = "__Host-access-session";

const FORM: &str = "application/x-www-form-urlencoded";

type Shared<E> = State<Arc<OAuth<E>>>;

/// What a request brings, read once.
struct Incoming {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    slug: Option<String>,
    chain: Option<Arc<[Vec<u8>]>>,
    peer: Option<std::net::IpAddr>,
}

/// The authorization server routes.
pub fn router<E: Env>(service: OAuth<E>) -> Router {
    let shared = Arc::new(service);
    let mut r = Router::new();
    for e in [
        Endpoint::Authorize,
        Endpoint::Par,
        Endpoint::Token,
        Endpoint::Userinfo,
        Endpoint::Revoke,
        Endpoint::Introspect,
        Endpoint::EndSession,
        Endpoint::DeviceAuthorization,
        Endpoint::BackchannelAuthentication,
    ] {
        let root =
            move |s: Shared<E>,
                  m: Method,
                  u: Uri,
                  h: HeaderMap,
                  c: Chain,
                  peer: PeerOf,
                  b: Bytes| { handle(s, e, incoming(m, u, h, b, (None, c, peer))) };
        let under = move |s: Shared<E>,
                          p: Path<String>,
                          m: Method,
                          u: Uri,
                          h: HeaderMap,
                          c: Chain,
                          peer: PeerOf,
                          b: Bytes| {
            handle(s, e, incoming(m, u, h, b, (Some(p.0), c, peer)))
        };
        let path = e.path();
        let slugged = format!("/realms/{{slug}}{path}");
        let (a, b) = match e {
            Endpoint::Authorize | Endpoint::Userinfo | Endpoint::EndSession => {
                (get(root).post(root), get(under).post(under))
            }
            _ => (post(root), post(under)),
        };
        r = r.route(path, a).route(&slugged, b);
    }
    // §11.6, OP-154 m.3 (k)
    r.merge(approval::routes::<E>())
        .merge(register::routes::<E>())
        .merge(device::routes::<E>())
        .merge(ciba::routes::<E>())
        .with_state(shared)
}

/// The client certificate chain of the connection, leaf first: the mTLS listener's (RFC 8705
/// §2, OP-155 m.3 (k), (m)), else an X.509-SVID chain (OP-154 m.3 (r)). Only TLS that ends at
/// access-server sets either; a forwarded header never does.
struct Chain(Option<Arc<[Vec<u8>]>>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Chain {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> impl core::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        let mtls = parts
            .extensions
            .get::<crate::tls::MtlsChain>()
            .map(|c| c.0.clone());
        let chain = mtls.or_else(|| {
            parts
                .extensions
                .get::<crate::tls::ClientChain>()
                .map(|c| c.0.clone())
        });
        std::future::ready(Ok(Self(chain)))
    }
}

/// The peer address the listener saw (OP-154 m.3 (p), (j)).
type PeerOf = Option<axum::Extension<crate::login::Peer>>;

fn incoming(
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    (slug, chain, peer): (Option<String>, Chain, PeerOf),
) -> Incoming {
    Incoming {
        method,
        uri,
        headers,
        body,
        slug,
        chain: chain.0,
        peer: peer.map(|axum::Extension(crate::login::Peer(ip))| ip),
    }
}

fn authority<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> &'a str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default()
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// The session cookie's value, when sent once.
fn session_cookie(headers: &HeaderMap) -> Option<String> {
    let mut found = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .filter(|(k, _)| *k == SESSION_COOKIE)
        .map(|(_, v)| String::from(v));
    let first = found.next();
    if found.next().is_some() {
        return None;
    }
    // TN-33
    let bound = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == access_identity_session::domain::dbsc::BOUND_COOKIE)
        .map(|(_, v)| v);
    match (first, bound) {
        (Some(s), Some(b)) if !s.contains('.') && !b.contains('.') => Some(format!("{s}.{b}")),
        (first, _) => first,
    }
}

fn bad_request() -> Response {
    json_error(StatusCode::BAD_REQUEST, "invalid_request")
}

fn json_error(status: StatusCode, error: &str) -> Response {
    render(Reply::oauth_error(
        status.as_u16(),
        error,
        "the request is malformed",
    ))
}

/// §11.4.5 #19: a form-encoded body, or the query of a `GET`.
fn params(req: &Incoming) -> Option<Params> {
    let text = if req.method == Method::GET {
        String::from(req.uri.query().unwrap_or_default())
    } else {
        let form = header_text(&req.headers, header::CONTENT_TYPE.as_str())
            .and_then(|c| c.split(';').next())
            .is_some_and(|c| c.trim().eq_ignore_ascii_case(FORM));
        if !form {
            return None;
        }
        String::from_utf8(req.body.to_vec()).ok()?
    };
    Params::parse(&text).ok()
}

#[expect(
    clippy::too_many_lines,
    reason = "one dispatch over the authorization server endpoints"
)]
async fn handle<E: Env>(State(s): Shared<E>, endpoint: Endpoint, req: Incoming) -> Response {
    let realm: Realm = match s
        .realm(authority(&req.uri, &req.headers), req.slug.as_deref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return crate::not_found_problem().into_response(),
        Err(_) => return render(Reply::Unavailable),
    };
    // OP-154 m.4
    if !access_identity_oauth::domain::metadata::SERVED.has(endpoint) {
        return crate::problem::codes::NOT_YET_SERVED
            .problem()
            .into_response();
    }
    let authorization = header_text(&req.headers, header::AUTHORIZATION.as_str());
    if endpoint == Endpoint::Userinfo {
        let proofs: Vec<&str> = req
            .headers
            .get_all("dpop")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        // RFC 8705 §3
        return render(
            s.userinfo_mtls(
                &realm,
                req.method.as_str(),
                authorization,
                &proofs,
                req.chain.as_deref().unwrap_or(&[]),
            )
            .await,
        );
    }
    let Some(p) = params(&req) else {
        return if matches!(endpoint, Endpoint::Authorize | Endpoint::EndSession) {
            Problem::new(StatusCode::BAD_REQUEST, "invalid-request", "Bad Request").into_response()
        } else {
            bad_request()
        };
    };
    let cookie = session_cookie(&req.headers);
    let reply = match endpoint {
        Endpoint::Authorize => {
            let reply = s.authorize(&realm, &p, cookie.as_deref()).await;
            return render(error_page(&realm, &req.headers, reply));
        }
        Endpoint::Par => {
            let proofs: Vec<&str> = req
                .headers
                .get_all("dpop")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            s.par_mtls(
                &realm,
                &p,
                authorization,
                &proofs,
                req.chain.as_deref().unwrap_or(&[]),
            )
            .await
        }
        Endpoint::Token => {
            let proofs: Vec<&str> = req
                .headers
                .get_all("dpop")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            s.token(
                &realm,
                &p,
                TokenHttp {
                    authorization,
                    dpop: &proofs,
                    client_chain: req.chain.as_deref().unwrap_or(&[]),
                },
            )
            .await
        }
        Endpoint::Revoke => s.revoke(&realm, &p, authorization).await,
        // RFC 9701 §4, OP-155 m.3 (k)
        Endpoint::Introspect => {
            let jwt = header_text(&req.headers, header::ACCEPT.as_str())
                .is_some_and(|a| a.contains("application/token-introspection+jwt"));
            s.introspect_as(
                &realm,
                &p,
                authorization,
                jwt,
                req.chain.as_deref().unwrap_or(&[]),
            )
            .await
        }
        Endpoint::EndSession => s.end_session(&realm, &p, cookie.as_deref()).await,
        // OP-154 m.3 (p)
        Endpoint::DeviceAuthorization => {
            s.device_authorization(
                &realm,
                &p,
                TokenHttp {
                    authorization,
                    dpop: &[],
                    client_chain: req.chain.as_deref().unwrap_or(&[]),
                },
                req.peer,
            )
            .await
        }
        // OP-155 m.3 (l)
        Endpoint::BackchannelAuthentication => {
            s.backchannel_authentication(
                &realm,
                &p,
                TokenHttp {
                    authorization,
                    dpop: &[],
                    client_chain: req.chain.as_deref().unwrap_or(&[]),
                },
            )
            .await
        }
        _ => Reply::NotFound,
    };
    render(reply)
}

/// N5: a browser's authorization request that cannot go back to the app sees the hosted
/// error page, which names who can fix it and shows the request's reference, never the raw
/// code (§8.10, §8.15.2, X-L8, OP-153 m.3 (jj)). A client that does not ask for HTML keeps the
/// RFC 9457 problem.
fn error_page(realm: &Realm, headers: &HeaderMap, reply: Reply) -> Reply {
    use access_identity_ui::domain::error_page::{Owner, location};
    let html = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/html"));
    if !html {
        return reply;
    }
    let id = crate::api::app::request_id_of(headers)
        .or_else(|| header_text(headers, "x-request-id").map(String::from))
        .unwrap_or_default();
    let base = realm.issuer.as_str().trim_end_matches('/');
    match reply {
        Reply::Problem { code, .. } => Reply::Redirect(location(base, code, Owner::App, &id)),
        Reply::Unavailable => Reply::Redirect(location(
            base,
            "temporarily_unavailable",
            Owner::Access,
            &id,
        )),
        other => other,
    }
}

fn no_store(r: &mut Response) {
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

/// Renders a reply: redirects are `303`, JSON bodies `no-store` with their `DPoP-Nonce` and
/// `WWW-Authenticate`, an outage `503 + Retry-After`.
#[must_use]
pub fn render(reply: Reply) -> Response {
    let mut r = match reply {
        Reply::Redirect(to) => match HeaderValue::from_str(&to) {
            Ok(v) => (StatusCode::SEE_OTHER, [(header::LOCATION, v)]).into_response(),
            Err(_) => Problem::new(StatusCode::BAD_REQUEST, "invalid-redirect", "Bad Request")
                .into_response(),
        },
        Reply::Json {
            status,
            body,
            dpop_nonce,
            challenge,
        } => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            let mut r = (
                status,
                [(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )],
                body,
            )
                .into_response();
            if let Some(n) = dpop_nonce.and_then(|n| HeaderValue::from_str(&n).ok()) {
                r.headers_mut().insert("dpop-nonce", n);
            }
            if let Some(c) = challenge.and_then(|c| HeaderValue::from_str(&c).ok()) {
                r.headers_mut().insert(header::WWW_AUTHENTICATE, c);
            }
            r
        }
        Reply::Problem { status, code } => Problem::new(
            StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST),
            code,
            "Bad Request",
        )
        .into_response(),
        Reply::Unavailable => {
            let mut r = Problem::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "unavailable",
                "Service Unavailable",
            )
            .into_response();
            r.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_S));
            r
        }
        Reply::NotFound => crate::not_found_problem().into_response(),
        // OP-155 m.3 (k)
        Reply::FormPost { action, body } => form_post(&action, body),
        // IDP-24
        Reply::Page { body, frames } => page(&frames, body),
        Reply::Jwt {
            body,
            media,
            dpop_nonce,
        } => {
            let mut r = (
                StatusCode::OK,
                [(header::CONTENT_TYPE, HeaderValue::from_static(media))],
                body,
            )
                .into_response();
            if let Some(n) = dpop_nonce.and_then(|n| HeaderValue::from_str(&n).ok()) {
                r.headers_mut().insert("dpop-nonce", n);
            }
            r
        }
    };
    no_store(&mut r);
    r
}

/// The front-channel sign-out page: HTML that may only frame the clients' origins.
fn page(frames: &[String], body: String) -> Response {
    let csp = format!(
        "default-src 'none'; frame-src {}; frame-ancestors 'none'",
        frames.join(" ")
    );
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return Problem::new(StatusCode::BAD_REQUEST, "invalid-frame", "Bad Request")
            .into_response();
    };
    let mut r = (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response();
    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, csp);
    r
}

/// The `form_post.jwt` page (JARM §2.3.4): HTML that may only post to the client's origin.
fn form_post(action: &str, body: String) -> Response {
    let origin = action
        .split_once("://")
        .map(|(scheme, rest)| {
            let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
            format!("{scheme}://{host}")
        })
        .unwrap_or_default();
    let csp = format!("default-src 'none'; form-action {origin}; frame-ancestors 'none'");
    let Ok(csp) = HeaderValue::from_str(&csp) else {
        return Problem::new(StatusCode::BAD_REQUEST, "invalid-redirect", "Bad Request")
            .into_response();
    };
    let mut r = (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        )],
        body,
    )
        .into_response();
    r.headers_mut().insert(header::CONTENT_SECURITY_POLICY, csp);
    r
}
