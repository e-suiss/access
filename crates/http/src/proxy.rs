//! `/proxy/v1/check/{engine}` (IDP-30 (1), B22, OP-156 m.3 (l)): the forward-auth check of a
//! registered proxy for one request, in the engine's own protocol, GET or POST; the body is
//! never read. Envoy `ext_authz` in HTTP service mode keeps the original method and appends the
//! original path, so `/proxy/v1/check/envoy/{*path}` answers every method.
//!
//! The proxy is a PEP named by its transport: the client certificate on the mTLS listener
//! (the base64url of the SHA-256 of its DER), or a DPoP-bound PEP token (OP-155 m.3 (q)).
//! Nothing in the forwarded request names it.

use std::sync::Arc;

use access_identity_proxy::app::{Check, Proxy, Refusal};
use access_identity_proxy::domain::answer::render;
use access_identity_proxy::domain::engine::Engine;
use access_identity_proxy::ports::Ports;
use access_kernel::json::b64url_encode;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};

use crate::adp::adapters::Pep;
use crate::problem::codes;
use crate::tls::MtlsChain;

/// Seconds an engine waits before asking again after `503`.
pub const RETRY_AFTER_S: u64 = 1;

/// The proxy's transport identity: a PEP token's, else the mTLS client certificate's.
fn pep_of(pep: Option<&Pep>, chain: Option<&MtlsChain>) -> Option<String> {
    pep.map(|p| p.0.clone()).or_else(|| {
        chain
            .and_then(|c| c.0.first())
            .map(|leaf| b64url_encode(&suiss_crypto::digest::sha256(leaf)))
    })
}

fn refused(engine: Engine, r: Refusal) -> Response {
    // OP-67
    tracing::info!(
        event = "proxy.check.refused",
        engine = engine.word(),
        reason = %r,
        "forward-auth check refused"
    );
    match r {
        Refusal::Unregistered => codes::realm::PROXY_UNREGISTERED.problem().into_response(),
        Refusal::Malformed(_) => codes::realm::INVALID_FORWARDED_REQUEST
            .problem()
            .into_response(),
        Refusal::Unavailable => {
            let mut res = codes::UNAVAILABLE.problem().into_response();
            res.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_S));
            res
        }
    }
}

struct Asked<'a> {
    engine: Engine,
    suffix: Option<&'a str>,
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    pep: Option<String>,
}

async fn answer<P: Ports + 'static>(proxy: &Proxy<P>, a: Asked<'_>) -> Response {
    let headers = a.headers;
    let header = |name: &str| -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    };
    let check = Check {
        engine: a.engine,
        pep: a.pep.as_deref(),
        method: a.method.as_str(),
        suffix: a.suffix,
        query: a.uri.query(),
        header: &header,
    };
    match proxy.check(&check).await {
        Ok(answer) => {
            let r = render(a.engine, &answer);
            let mut res = (
                StatusCode::from_u16(r.status).unwrap_or(StatusCode::FORBIDDEN),
                r.body,
            )
                .into_response();
            let h = res.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            for (name, value) in r.headers {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(&value),
                ) {
                    h.append(n, v);
                }
            }
            res
        }
        Err(r) => refused(a.engine, r),
    }
}

struct Shared<P> {
    proxy: Arc<Proxy<P>>,
}

type Caller = (
    Option<axum::Extension<Pep>>,
    Option<axum::Extension<MtlsChain>>,
);

fn caller((pep, chain): &Caller) -> Option<String> {
    pep_of(
        pep.as_ref().map(|axum::Extension(p)| p),
        chain.as_ref().map(|axum::Extension(c)| c),
    )
}

async fn check<P: Ports + 'static>(
    State(s): State<Arc<Shared<P>>>,
    Path(engine): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    pep: Option<axum::Extension<Pep>>,
    chain: Option<axum::Extension<MtlsChain>>,
) -> Response {
    let Some(engine) = Engine::parse(&engine) else {
        return codes::NOT_FOUND.problem().into_response();
    };
    let pep = caller(&(pep, chain));
    answer(
        &s.proxy,
        Asked {
            engine,
            suffix: None,
            method: &method,
            uri: &uri,
            headers: &headers,
            pep,
        },
    )
    .await
}

/// The path Envoy appended to [`ENVOY_PREFIX`], as sent: never percent-decoded, so an encoded
/// slash or dot still reaches the ambiguity rules (OP-156 m.15 (d)); the application's root `/`
/// arrives as the prefix with a trailing `/` and is the empty suffix.
fn envoy_suffix(uri: &Uri) -> &str {
    uri.path().strip_prefix(ENVOY_PREFIX).unwrap_or_default()
}

/// The check path Envoy's `path_prefix` names, with the `/` every forwarded path starts with.
pub const ENVOY_PREFIX: &str = "/proxy/v1/check/envoy/";

async fn envoy<P: Ports + 'static>(
    State(s): State<Arc<Shared<P>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    pep: Option<axum::Extension<Pep>>,
    chain: Option<axum::Extension<MtlsChain>>,
) -> Response {
    let pep = caller(&(pep, chain));
    answer(
        &s.proxy,
        Asked {
            engine: Engine::Envoy,
            suffix: Some(envoy_suffix(&uri)),
            method: &method,
            uri: &uri,
            headers: &headers,
            pep,
        },
    )
    .await
}

/// The forward-auth routes over `proxy`.
pub fn router<P: Ports + 'static>(proxy: Arc<Proxy<P>>) -> Router {
    Router::new()
        .route("/proxy/v1/check/{engine}", get(check::<P>).post(check::<P>))
        .route(ENVOY_PREFIX, any(envoy::<P>))
        .route("/proxy/v1/check/envoy/{*path}", any(envoy::<P>))
        .with_state(Arc::new(Shared { proxy }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::assert_is_empty, reason = "test code")]

    use super::*;

    // IDP-30, B22, L1-ADP-2
    #[test]
    fn the_proxy_is_named_by_its_transport_only() {
        let chain = MtlsChain(Arc::from(vec![b"leaf".to_vec(), b"ca".to_vec()]));
        let by_cert = pep_of(None, Some(&chain)).unwrap();
        assert_eq!(
            by_cert,
            b64url_encode(&suiss_crypto::digest::sha256(b"leaf"))
        );
        assert_eq!(by_cert.len(), 43);
        let token = Pep(String::from("jkt"));
        assert_eq!(pep_of(Some(&token), Some(&chain)).as_deref(), Some("jkt"));
        assert_eq!(pep_of(None, None), None);
    }

    // IDP-30 (1), OP-156 m.15 (d), (f)
    #[test]
    fn envoy_paths_are_read_as_sent() {
        let suffix = |p: &str| String::from(envoy_suffix(&p.parse::<Uri>().unwrap()));
        assert_eq!(suffix("/proxy/v1/check/envoy/"), "");
        assert_eq!(suffix("/proxy/v1/check/envoy/a/b?x=1"), "a/b");
        assert_eq!(suffix("/proxy/v1/check/envoy/a%2fb"), "a%2fb");
        assert_eq!(suffix("/proxy/v1/check/envoy//etc"), "/etc");
    }
}
