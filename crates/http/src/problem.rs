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

/// One part of a request a problem is about (RFC 9457 §3): the stable code of what is wrong
/// and, when the body names it, where.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldError {
    /// A JSON Pointer (RFC 6901) into the request body, as a URI fragment (`#/set/basis`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// The stable code of what is wrong there.
    pub code: &'static str,
}

/// An RFC 9457 problem response.
///
/// `type` is `urn:suiss:access:problem:<code>` for the stable code, which also travels in the
/// `code` extension member; a [`BARE`] code keeps `about:blank` (OP-149 m.12). The `reason`
/// extension member narrows the code with a stable, non-secret reason, and `errors` names the
/// parts of the request a protocol problem is about; neither carries request values.
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    type_uri: String,
    title: &'static str,
    status: u16,
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<FieldError>,
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
            reason: None,
            errors: Vec::new(),
            status_code: status,
        }
    }

    /// With a stable, non-secret `reason` that narrows the code.
    #[must_use]
    pub const fn with_reason(mut self, reason: Option<&'static str>) -> Self {
        self.reason = reason;
        self
    }

    /// With the parts of the request it is about.
    #[must_use]
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors;
        self
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
