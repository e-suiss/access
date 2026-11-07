//! Request correlation (OP-67 m.1, OP-65 m.4, OP-151 m.3 (p)): a well-formed W3C
//! `traceparent` is continued, anything else starts a new trace; the request span carries the
//! trace, the request continues with this server's own `traceparent` for what it calls next,
//! and the response's `Request-Id` is the trace id.

use access_telemetry::signals::{HTTP_RESPONSES, TRACEPARENT_MALFORMED};
use access_telemetry::trace::{self, TRACEPARENT, TRACESTATE, TraceParent};
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument as _;

/// The `Request-Id` response header (OP-65 m.4).
pub const REQUEST_ID: HeaderName = HeaderName::from_static("request-id");

/// The trace id a request carries after [`correlate`]: the `Request-Id` of its response.
#[must_use]
pub fn request_id(headers: &HeaderMap) -> Option<String> {
    incoming(headers).map(|t| t.trace_id())
}

fn incoming(headers: &HeaderMap) -> Option<TraceParent> {
    headers
        .get(TRACEPARENT)
        .and_then(|v| v.to_str().ok())
        .and_then(TraceParent::parse)
}

/// The response's status class for the §17.8.2 503/429 rates: never the path or a value from
/// the request.
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

/// The correlation middleware. Apply it outermost so every response, refusals included,
/// carries `Request-Id`.
pub async fn correlate(mut req: Request, next: Next) -> Response {
    let parent = match req.headers().get(TRACEPARENT) {
        None => None,
        Some(v) => {
            let parsed = v.to_str().ok().and_then(TraceParent::parse);
            if parsed.is_none() {
                TRACEPARENT_MALFORMED.incr([]);
                tracing::debug!(
                    event = "traceparent.malformed",
                    outcome = "restarted",
                    "malformed traceparent; a new trace starts"
                );
            }
            parsed
        }
    };
    let state = req
        .headers()
        .get(TRACESTATE)
        .and_then(|v| v.to_str().ok())
        .and_then(trace::tracestate)
        .map(str::to_owned);
    let span = tracing::info_span!("request", method = %req.method());
    if let Some(p) = parent {
        trace::adopt(&span, p, state.as_deref());
    }
    let own = trace::of(&span)
        .or(parent)
        .unwrap_or_else(TraceParent::generate);
    let headers = req.headers_mut();
    headers.remove(TRACESTATE);
    if let Some(s) = state.and_then(|s| HeaderValue::from_str(&s).ok()) {
        headers.insert(TRACESTATE, s);
    }
    if let Ok(v) = HeaderValue::from_str(&own.header()) {
        headers.insert(TRACEPARENT, v);
    }
    let mut response = next.run(req).instrument(span).await;
    HTTP_RESPONSES.incr([status_class(response.status())]);
    if let Ok(v) = HeaderValue::from_str(&own.trace_id()) {
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
}
