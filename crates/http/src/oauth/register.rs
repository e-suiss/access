//! `POST /register` (RFC 7591) of the realm's DCR profile (OP-154 m.3 (j)): JSON only, an
//! initial access token in `Authorization`, the peer's address for the per-prefix limit; a
//! closed profile answers `404`.

use std::sync::Arc;

use access_identity_oauth::app::oauth::{Env, OAuth};
use axum::Extension;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use super::{authority, render};
use crate::login::Peer;

type Shared<E> = State<Arc<OAuth<E>>>;

/// The registration routes, at the host root and under `/realms/{slug}`.
pub(super) fn routes<E: Env>() -> Router<Arc<OAuth<E>>> {
    let path = access_identity_oauth::domain::metadata::REGISTER_PATH;
    Router::new()
        .route(path, post(register::<E>))
        .route(&format!("/realms/{{slug}}{path}"), post(register::<E>))
}

async fn register<E: Env>(
    State(s): Shared<E>,
    p: Option<Path<String>>,
    peer: Option<Extension<Peer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let realm = match s
        .realm(
            authority(&uri, &headers),
            p.as_ref().map(|Path(x)| x.as_str()),
        )
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return crate::not_found_problem().into_response(),
        Err(_) => return render(access_identity_oauth::app::oauth::Reply::Unavailable),
    };
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"));
    if !json {
        return render(access_identity_oauth::app::oauth::Reply::oauth_error(
            400,
            "invalid_client_metadata",
            "the registration is a JSON object",
        ));
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    render(
        s.register_client(
            &realm,
            authorization,
            &body,
            peer.map(|Extension(Peer(ip))| ip),
        )
        .await,
    )
}
