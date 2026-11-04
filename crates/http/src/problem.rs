//! RFC 9457 Problem Details (OP-64 rule 5). Internal details never reach the body.

use std::any::Any;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// Prefix of every problem type URI (OP-149 m.12).
pub const TYPE_PREFIX: &str = "urn:suiss:access:problem:";

/// Codes whose response means no more than its HTTP status; their `type` stays
/// `about:blank` (OP-149 m.12).
pub const BARE: [&str; 3] = ["not_found", "internal", "unavailable"];

/// An RFC 9457 problem response.
///
/// `type` is `urn:suiss:access:problem:<code>` for the stable code, which also travels in the
/// `code` extension member; a [`BARE`] code keeps `about:blank` (OP-149 m.12).
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    type_uri: String,
    title: &'static str,
    status: u16,
    code: &'static str,
    #[serde(skip)]
    status_code: StatusCode,
}

impl Problem {
    /// Creates a problem with a stable `code` (named by the `type` URI) and a short title.
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        let type_uri = if BARE.contains(&code) {
            String::from("about:blank")
        } else {
            format!("{TYPE_PREFIX}{code}")
        };
        Self {
            type_uri,
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
