//! RFC 9457 Problem Details (OP-64 rule 5). Internal details never reach the body.

use std::any::Any;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// An RFC 9457 problem response.
///
/// `type` stays `about:blank` until problem type URIs are published; the stable,
/// documented error code travels in the `code` extension member.
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    type_uri: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    #[serde(skip)]
    status_code: StatusCode,
}

impl Problem {
    /// Creates a problem with a stable `code` (used in the `type` URI) and a short title.
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        Self {
            type_uri: "about:blank",
            title,
            status: status.as_u16(),
            code,
            status_code: status,
        }
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut response = (self.status_code, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

/// Converts a caught panic into a 500 problem. The panic payload is logged, not returned.
#[allow(
    clippy::needless_pass_by_value,
    reason = "signature required by tower_http::catch_panic::ResponseForPanic"
)]
pub(crate) fn from_panic(payload: Box<dyn Any + Send + 'static>) -> Response {
    let message = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    tracing::error!(panic = %message, "request handler panicked");
    Problem::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal Server Error",
    )
    .into_response()
}
