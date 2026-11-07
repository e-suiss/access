//! W3C Trace Context correlation (OP-67 m.1): one trace id per request, carried over HTTP,
//! internal RPC, the outbox and signer calls; `Request-Id` is that trace id (OP-65 m.4).

use std::fmt;

use opentelemetry::trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState};
use opentelemetry_sdk::trace::{IdGenerator, RandomIdGenerator};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// The `traceparent` header name.
pub const TRACEPARENT: &str = "traceparent";
/// The `tracestate` header name.
pub const TRACESTATE: &str = "tracestate";

/// Longest `tracestate` passed on; longer values are dropped (W3C: 512 bytes).
const TRACESTATE_MAX: usize = 512;

/// A well-formed version-00 `traceparent`: trace id, parent span id and the sampled flag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceParent {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    sampled: bool,
}

impl fmt::Debug for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.header())
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.header())
    }
}

fn hex_into(out: &mut [u8], text: &[u8]) -> Option<()> {
    if text.len() != out.len().checked_mul(2)? {
        return None;
    }
    for (slot, pair) in out.iter_mut().zip(text.as_chunks::<2>().0) {
        let [hi, lo] = *pair;
        *slot = nibble(hi)?.checked_mul(16)?.checked_add(nibble(lo)?)?;
    }
    Some(())
}

const fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => match c.checked_sub(b'a') {
            Some(v) => v.checked_add(10),
            None => None,
        },
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for n in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(n)) {
                out.push(char::from(*d));
            }
        }
    }
    out
}

impl TraceParent {
    /// Parses a `traceparent` value. Only version `00` in its exact 55-byte form with lowercase
    /// hex and non-zero ids is accepted; anything else is `None` and the caller starts a new
    /// trace (W3C Trace Context §4.3).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let b = value.as_bytes();
        if b.len() != 55 {
            return None;
        }
        let (version, rest) = b.split_at(2);
        let (dash1, rest) = rest.split_at(1);
        let (trace, rest) = rest.split_at(32);
        let (dash2, rest) = rest.split_at(1);
        let (span, rest) = rest.split_at(16);
        let (dash3, flags) = rest.split_at(1);
        if version != b"00" || dash1 != b"-" || dash2 != b"-" || dash3 != b"-" {
            return None;
        }
        let mut trace_id = [0u8; 16];
        let mut span_id = [0u8; 8];
        let mut flag = [0u8; 1];
        hex_into(&mut trace_id, trace)?;
        hex_into(&mut span_id, span)?;
        hex_into(&mut flag, flags)?;
        if trace_id == [0; 16] || span_id == [0; 8] {
            return None;
        }
        let [flags] = flag;
        Some(Self {
            trace_id,
            span_id,
            sampled: flags & 0x01 == 0x01,
        })
    }

    /// A new trace with a random trace id and root span id.
    #[must_use]
    pub fn generate() -> Self {
        let ids = RandomIdGenerator::default();
        Self {
            trace_id: ids.new_trace_id().to_bytes(),
            span_id: ids.new_span_id().to_bytes(),
            sampled: false,
        }
    }

    /// The header value, `00-<trace id>-<span id>-<flags>`.
    #[must_use]
    pub fn header(&self) -> String {
        format!(
            "00-{}-{}-{}",
            hex(&self.trace_id),
            hex(&self.span_id),
            if self.sampled { "01" } else { "00" }
        )
    }

    /// The trace id as 32 lowercase hex digits: the `Request-Id` (OP-65 m.4).
    #[must_use]
    pub fn trace_id(&self) -> String {
        hex(&self.trace_id)
    }

    /// The parent span id as 16 lowercase hex digits.
    #[must_use]
    pub fn span_id(&self) -> String {
        hex(&self.span_id)
    }

    /// Whether the sender sampled the trace. Only carried on: the sampler does not trust it.
    #[must_use]
    pub const fn sampled(&self) -> bool {
        self.sampled
    }

    fn span_context(&self, state: TraceState, remote: bool) -> SpanContext {
        SpanContext::new(
            TraceId::from_bytes(self.trace_id),
            SpanId::from_bytes(self.span_id),
            if self.sampled {
                TraceFlags::SAMPLED
            } else {
                TraceFlags::default()
            },
            remote,
            state,
        )
    }

    fn of(cx: &SpanContext) -> Option<Self> {
        if !cx.is_valid() {
            return None;
        }
        Some(Self {
            trace_id: cx.trace_id().to_bytes(),
            span_id: cx.span_id().to_bytes(),
            sampled: cx.is_sampled(),
        })
    }
}

/// A `tracestate` value passed on as received: never parsed for meaning, dropped when longer
/// than 512 bytes or not printable ASCII.
#[must_use]
pub fn tracestate(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= TRACESTATE_MAX
        && value.bytes().all(|b| (0x20..0x7f).contains(&b)))
    .then_some(value)
}

/// Makes `parent` the remote parent of `span` (incoming HTTP, an outbox row, a signer request).
/// Without the OpenTelemetry layer installed this does nothing.
pub fn adopt(span: &tracing::Span, parent: TraceParent, state: Option<&str>) {
    let state = state
        .and_then(tracestate)
        .and_then(|s| s.parse::<TraceState>().ok())
        .unwrap_or_default();
    let cx =
        opentelemetry::Context::new().with_remote_span_context(parent.span_context(state, true));
    let _ = span.set_parent(cx);
}

/// The trace context of `span`, if the OpenTelemetry layer gave it one.
#[must_use]
pub fn of(span: &tracing::Span) -> Option<TraceParent> {
    let cx = span.context();
    let span_ref = cx.span();
    TraceParent::of(span_ref.span_context())
}

/// The trace context of the current span, for outbound requests, outbox rows and signer
/// calls (OP-67 m.1).
#[must_use]
pub fn current() -> Option<TraceParent> {
    of(&tracing::Span::current())
}

/// The current `traceparent` header value, if there is a trace.
#[must_use]
pub fn current_header() -> Option<String> {
    current().map(|t| t.header())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    // OP-67 m.1: a well-formed W3C traceparent is accepted as is
    #[test]
    fn well_formed_traceparent_round_trips() {
        let t = TraceParent::parse(GOOD).unwrap_or_else(TraceParent::generate);
        assert_eq!(t.header(), GOOD);
        assert_eq!(t.trace_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(t.span_id(), "00f067aa0ba902b7");
        assert!(t.sampled());
    }

    // OP-67 m.1: malformed values are never trusted; the caller starts a new trace
    #[test]
    fn malformed_traceparent_is_refused() {
        for bad in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-",
        ] {
            assert!(TraceParent::parse(bad).is_none(), "{bad}");
        }
    }

    // OP-67 m.1: a generated trace is well formed and unique
    #[test]
    fn generated_traces_are_well_formed() {
        let a = TraceParent::generate();
        let b = TraceParent::generate();
        assert_ne!(a.trace_id(), b.trace_id());
        assert_eq!(TraceParent::parse(&a.header()), Some(a));
    }

    // OP-67 m.1: tracestate is passed on only when it is short printable ASCII
    #[test]
    fn tracestate_is_passed_not_trusted() {
        assert_eq!(tracestate("congo=t61rcWkgMzE"), Some("congo=t61rcWkgMzE"));
        assert_eq!(tracestate(""), None);
        assert_eq!(tracestate("a=\u{7}"), None);
        assert_eq!(tracestate(&"a".repeat(513)), None);
    }
}
