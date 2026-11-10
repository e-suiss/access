//! The gateway's HTTP surface: the MCP endpoint agents reach (`POST`, Streamable HTTP with
//! JSON answers). Every other method is `405`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;

use crate::app::Gateway;
use crate::ports::{Access, Clock, Upstream};

/// Largest request body read.
pub const MAX_REQUEST: usize = 1 << 20;

async fn mcp<A, U, C>(
    State(g): State<Arc<Gateway<A, U, C>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    A: Access + 'static,
    U: Upstream + 'static,
    C: Clock + 'static,
{
    let pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| {
            (
                String::from(k.as_str()),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let reply = g.handle(&refs, &body).await;
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::BAD_GATEWAY);
    if reply.body.is_empty() {
        return status.into_response();
    }
    let mut r = (status, reply.body).into_response();
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

/// The MCP endpoint at `path` over `gateway`.
pub fn router<A, U, C>(path: &str, gateway: Arc<Gateway<A, U, C>>) -> Router
where
    A: Access + 'static,
    U: Upstream + 'static,
    C: Clock + 'static,
{
    Router::new()
        .route(path, post(mcp::<A, U, C>))
        .with_state(gateway)
        .layer(axum::extract::DefaultBodyLimit::max(MAX_REQUEST))
}
