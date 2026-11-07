//! `Request-Id` (OP-65, OP-67 m.1): the W3C trace id of the request, taken from a well-formed
//! `traceparent` or drawn from the RNG port, on every response of the router it wraps.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tracing::Instrument;

use crate::api::domain::trace::TraceContext;
use crate::api::ports::Entropy;
use crate::problem::codes;

/// The response header.
pub const REQUEST_ID: HeaderName = HeaderName::from_static("request-id");

/// The W3C trace context request header.
pub const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

/// The randomness new trace ids are drawn from.
#[derive(Clone)]
pub struct RequestIds(Arc<dyn Entropy>);

impl RequestIds {
    /// Draws from `entropy`.
    #[must_use]
    pub fn new(entropy: Arc<dyn Entropy>) -> Self {
        Self(entropy)
    }
}

fn context(request: &Request, ids: &RequestIds) -> Option<TraceContext> {
    let mut values = request.headers().get_all(&TRACEPARENT).iter();
    let sent = match (values.next(), values.next()) {
        (Some(v), None) => v.to_str().ok().and_then(TraceContext::parse),
        _ => None,
    };
    if sent.is_some() {
        return sent;
    }
    let mut id = [0_u8; 16];
    ids.0.fill(&mut id).ok()?;
    Some(TraceContext::start(id))
}

/// The middleware: the trace context goes into the request's extensions and the span, and its
/// trace id into `Request-Id`. Without randomness the request is refused (`503`), never served
/// without an id.
pub async fn request_id(
    State(ids): State<RequestIds>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(trace) = context(&request, &ids) else {
        return codes::UNAVAILABLE.problem().into_response();
    };
    let id = trace.request_id();
    request.extensions_mut().insert(trace);
    let span = tracing::info_span!("request", trace_id = %id);
    let mut response = next.run(request).instrument(span).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(REQUEST_ID, v);
    }
    response
}
