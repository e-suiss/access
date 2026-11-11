//! The realm surface of the identity plane (CMP-15.1): OIDC Discovery, RFC 8414 and RFC 9728
//! metadata, the Suiss discovery document (OP-149 m.3) and the JWKS of the realm the request's
//! `Host` selects, at the host root for a subdomain issuer and under `/realms/{slug}` for a path
//! issuer (TN-10, §17.9.6).

use std::sync::Arc;

use access_identity_oauth::app::oidf::OidfReply;
use access_identity_oauth::app::{Discovery, Reply};
use access_identity_oauth::domain::metadata::{Document, JWKS_CACHE_CONTROL, JWKS_CONTENT_TYPE};
use access_identity_oauth::domain::suiss;
use access_identity_oauth::ports::{Directory, Keys};
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::Problem;

type Shared<D, K> = State<Arc<Discovery<D, K>>>;

/// The realm routes.
pub fn router<D, K>(service: Discovery<D, K>) -> Router
where
    D: Directory + 'static,
    K: Keys + 'static,
{
    let shared = Arc::new(service);
    let mut r = Router::new();
    for (doc, root, inserted, appended) in [
        (
            Document::OpenIdConfiguration,
            "/.well-known/openid-configuration",
            Some("/.well-known/openid-configuration/realms/{slug}"),
            Some("/realms/{slug}/.well-known/openid-configuration"),
        ),
        (
            Document::AuthorizationServer,
            "/.well-known/oauth-authorization-server",
            Some("/.well-known/oauth-authorization-server/realms/{slug}"),
            None,
        ),
        (
            Document::ProtectedResource,
            "/.well-known/oauth-protected-resource",
            Some("/.well-known/oauth-protected-resource/realms/{slug}"),
            None,
        ),
        (
            Document::Jwks,
            "/jwks.json",
            None,
            Some("/realms/{slug}/jwks.json"),
        ),
        // OP-149 m.3
        (
            Document::SuissConfiguration,
            "/.well-known/suiss-configuration",
            Some("/.well-known/suiss-configuration/realms/{slug}"),
            Some("/realms/{slug}/.well-known/suiss-configuration"),
        ),
    ] {
        r = r.route(
            root,
            get(move |s: Shared<D, K>, u: Uri, h: HeaderMap| at_root(s, u, h, doc)),
        );
        for path in [inserted, appended].into_iter().flatten() {
            r = r.route(
                path,
                get(
                    move |s: Shared<D, K>, p: Path<String>, u: Uri, h: HeaderMap| {
                        at_path(s, p, u, h, doc)
                    },
                ),
            );
        }
    }
    // OP-155 m.3 (j), IDP-19
    r = r
        .route(
            "/.well-known/openid-federation",
            get(|s: Shared<D, K>, u: Uri, h: HeaderMap| entity_configuration(s, None, u, h)),
        )
        .route(
            "/realms/{slug}/.well-known/openid-federation",
            get(
                |s: Shared<D, K>, Path(slug): Path<String>, u: Uri, h: HeaderMap| {
                    entity_configuration(s, Some(slug), u, h)
                },
            ),
        );
    for (path, list) in [("/federation/fetch", false), ("/federation/list", true)] {
        r = r
            .route(
                path,
                get(move |s: Shared<D, K>, u: Uri, h: HeaderMap| {
                    authority_role(s, None, u, h, list)
                }),
            )
            .route(
                &format!("/realms/{{slug}}{path}"),
                get(
                    move |s: Shared<D, K>, Path(slug): Path<String>, u: Uri, h: HeaderMap| {
                        authority_role(s, Some(slug), u, h, list)
                    },
                ),
            );
    }
    r.with_state(shared)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The fetch and list endpoints of the intermediate or trust anchor role (§10.7.1 rule 1): off
/// by default, and not found while off.
async fn authority_role<D: Directory, K: Keys>(
    State(s): Shared<D, K>,
    slug: Option<String>,
    uri: Uri,
    headers: HeaderMap,
    list: bool,
) -> Response {
    let host = authority(&uri, &headers);
    let reply = if list {
        s.federation_list(host, slug.as_deref()).await
    } else {
        let sub = uri
            .query()
            .and_then(|q| access_identity_oauth::domain::request::Params::parse(q).ok())
            .and_then(|p| p.get("sub").map(String::from));
        let Some(sub) = sub else {
            return federation_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "sub is required",
            );
        };
        s.federation_fetch(host, slug.as_deref(), &sub, now_ms())
            .await
    };
    // OP-155 m.3 (j)
    match reply {
        OidfReply::NotFound => federation_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "no subordinate statement is served for this sub",
        ),
        OidfReply::InvalidRequest => federation_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "sub must not be the issuer",
        ),
        OidfReply::Unavailable => federation_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "the federation role cannot answer now",
        ),
        other => oidf_reply(other),
    }
}

/// An error of a federation endpoint (OIDF §8.9): `application/json` with `error` and
/// `error_description`.
fn federation_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        serde_json::json!({ "error": error, "error_description": description }).to_string(),
    )
        .into_response()
}

fn oidf_reply(reply: OidfReply) -> Response {
    match reply {
        OidfReply::Statement(jwt) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static(access_identity_oidf::statement::CONTENT_TYPE),
            )],
            jwt,
        )
            .into_response(),
        OidfReply::List(doc) => respond(Reply::Metadata(doc)),
        OidfReply::NotFound | OidfReply::InvalidRequest => respond(Reply::NotFound),
        OidfReply::Unavailable => respond(Reply::Unavailable),
    }
}

/// The realm issuer's OpenID Federation entity configuration (§10.7.1 rule 1): a leaf serves
/// it, signed with the realm's `federation` key; a realm that is no leaf has none.
async fn entity_configuration<D: Directory, K: Keys>(
    State(s): Shared<D, K>,
    slug: Option<String>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    oidf_reply(
        s.entity_configuration(authority(&uri, &headers), slug.as_deref(), now_ms())
            .await,
    )
}

/// The request's authority: the `Host` header, or the HTTP/2 `:authority`. It only selects a
/// realm; the issuer is never built from it (§17.9.6).
fn authority<'a>(uri: &'a Uri, headers: &'a HeaderMap) -> &'a str {
    headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
        .unwrap_or_default()
}

async fn at_root<D: Directory, K: Keys>(
    State(s): Shared<D, K>,
    uri: Uri,
    headers: HeaderMap,
    doc: Document,
) -> Response {
    respond(s.serve(doc, authority(&uri, &headers), None).await)
}

async fn at_path<D: Directory, K: Keys>(
    State(s): Shared<D, K>,
    Path(slug): Path<String>,
    uri: Uri,
    headers: HeaderMap,
    doc: Document,
) -> Response {
    respond(s.serve(doc, authority(&uri, &headers), Some(&slug)).await)
}

fn respond(reply: Reply) -> Response {
    match reply {
        Reply::Metadata(doc) => (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            doc,
        )
            .into_response(),
        // CR-25
        Reply::Jwks(doc) => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static(JWKS_CONTENT_TYPE),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(JWKS_CACHE_CONTROL),
                ),
            ],
            doc,
        )
            .into_response(),
        Reply::Suiss(doc) => (
            [
                (
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                ),
                (
                    header::CACHE_CONTROL,
                    HeaderValue::from_static(suiss::CACHE_CONTROL),
                ),
            ],
            doc,
        )
            .into_response(),
        Reply::NotFound => crate::not_found_problem().into_response(),
        Reply::Unavailable => Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "unavailable",
            "Service Unavailable",
        )
        .into_response(),
    }
}
