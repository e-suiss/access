//! `Request-Id` (OP-65, OP-67 m.1): the W3C trace id of the request, taken from a well-formed
//! `traceparent` or drawn from the RNG port, on every response of the router it wraps. The
//! request span continues that trace, so outbound calls, outbox rows and signer requests made
//! while serving it carry it on.

use std::sync::Arc;

use access_telemetry::signals::{HTTP_RESPONSES, TRACEPARENT_MALFORMED};
use access_telemetry::trace::{self as telemetry, TraceParent};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
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

/// The W3C trace state request header; passed on as received when short printable ASCII.
pub const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");

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
    if request.headers().contains_key(&TRACEPARENT) {
        TRACEPARENT_MALFORMED.incr([]);
        tracing::debug!(
            event = "traceparent.malformed",
            outcome = "restarted",
            "malformed traceparent; a new trace starts"
        );
    }
    let mut id = [0_u8; 16];
    ids.0.fill(&mut id).ok()?;
    Some(TraceContext::start(id))
}

/// The trace id of a request as this middleware left it: the `Request-Id` of its response.
#[must_use]
pub fn request_id_of(headers: &HeaderMap) -> Option<String> {
    headers
        .get(&TRACEPARENT)
        .and_then(|v| v.to_str().ok())
        .and_then(TraceParent::parse)
        .map(|t| t.trace_id())
}

/// The status class counted for the §17.8.2 503/429 rates: never a path or a request value.
#[must_use]
pub const fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() {
        429 => "429",
        503 => "503",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    }
}

/// The remote parent the request span continues: the caller's span, or, for a trace started
/// here, a parent named by the trace id's first half so the span keeps the drawn trace id.
fn parent_of(trace: &TraceContext) -> Option<TraceParent> {
    let mut parent = trace.parent_id;
    if parent == [0; 8] {
        parent.copy_from_slice(trace.trace_id.get(..8)?);
    }
    TraceParent::parse(&format!(
        "00-{}-{}-{:02x}",
        crate::api::domain::trace::to_hex(&trace.trace_id),
        crate::api::domain::trace::to_hex(&parent),
        trace.flags & 0x01
    ))
}

/// The middleware: the trace context goes into the request's extensions and the span, the
/// request continues with this server's own `traceparent`, and its trace id goes into
/// `Request-Id`. Without randomness the request is refused (`503`), never served without an id.
pub async fn request_id(
    State(ids): State<RequestIds>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(trace) = context(&request, &ids) else {
        return codes::UNAVAILABLE.problem().into_response();
    };
    let id = trace.request_id();
    let state = request
        .headers()
        .get(&TRACESTATE)
        .and_then(|v| v.to_str().ok())
        .and_then(telemetry::tracestate)
        .and_then(|s| HeaderValue::from_str(s).ok());
    let span = tracing::info_span!("request", trace_id = %id);
    let parent = parent_of(&trace);
    if let Some(p) = parent {
        telemetry::adopt(&span, p, state.as_ref().and_then(|s| s.to_str().ok()));
    }
    let own = telemetry::of(&span).or(parent);
    let headers = request.headers_mut();
    headers.remove(&TRACESTATE);
    if let Some(s) = state {
        headers.insert(TRACESTATE, s);
    }
    if let Some(v) = own.and_then(|t| HeaderValue::from_str(&t.header()).ok()) {
        headers.insert(TRACEPARENT, v);
    }
    request.extensions_mut().insert(trace);
    let mut response = next.run(request).instrument(span).await;
    HTTP_RESPONSES.incr([status_class(response.status())]);
    if let Ok(v) = HeaderValue::from_str(&id) {
        response.headers_mut().insert(REQUEST_ID, v);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    // §17.8.2: 429 and 503 are counted apart from their classes
    #[test]
    fn status_classes_are_fixed() {
        assert_eq!(status_class(StatusCode::TOO_MANY_REQUESTS), "429");
        assert_eq!(status_class(StatusCode::SERVICE_UNAVAILABLE), "503");
        assert_eq!(status_class(StatusCode::BAD_GATEWAY), "5xx");
        assert_eq!(status_class(StatusCode::NOT_FOUND), "4xx");
        assert_eq!(status_class(StatusCode::OK), "2xx");
    }

    // OP-67 m.1: a trace started here keeps its drawn trace id in the span's parent
    #[test]
    fn a_started_trace_keeps_its_id() {
        let trace = TraceContext::start([7; 16]);
        let parent = parent_of(&trace).unwrap_or_else(TraceParent::generate);
        assert_eq!(parent.trace_id(), "07".repeat(16));
    }
}
