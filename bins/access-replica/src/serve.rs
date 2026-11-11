//! The replica's read endpoint (§9.7A.2 k.1, P43, OP-158 m.3 (f)): every answer says
//! `advisory: true`. A replica copy is never a source of ALLOW: it answers records and the
//! tree it holds, never a decision, and a PEP never takes it as commit input.
//! - `GET /v1/head`: the size and root held and the last accepted checkpoint.
//! - `GET /v1/records/{position}`: the record, or `redacted` with only its commitments.

use std::sync::{Arc, Mutex, PoisonError};

use access_kernel::json::b64url_encode;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use crate::state::{Held, Store};

type Shared = Arc<Mutex<Store>>;

/// The routes over `store`.
pub(crate) fn router(store: Shared) -> Router {
    Router::new()
        .route("/v1/head", get(head))
        .route("/v1/records/{position}", get(record))
        .with_state(store)
}

async fn head(State(store): State<Shared>) -> Response {
    let s = store.lock().unwrap_or_else(PoisonError::into_inner);
    let accepted = s.follower.accepted();
    axum::Json(json!({
        "advisory": true,
        "size": s.follower.size().to_string(),
        "checkpoint": accepted.map(|(size, root)| json!({
            "size": size.to_string(),
            "root": b64url_encode(&root),
        })),
    }))
    .into_response()
}

async fn record(State(store): State<Shared>, Path(position): Path<String>) -> Response {
    let Ok(pos) = position.parse::<u64>() else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let held = store
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .read(pos);
    match held {
        Ok(Some(Held::Open(bytes))) => axum::Json(json!({
            "advisory": true,
            "position": pos.to_string(),
            "record": b64url_encode(&bytes),
        }))
        .into_response(),
        Ok(Some(Held::Redacted(withheld))) => axum::Json(json!({
            "advisory": true,
            "position": pos.to_string(),
            "redacted": true,
            "withheld": b64url_encode(&withheld),
        }))
        .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
}
