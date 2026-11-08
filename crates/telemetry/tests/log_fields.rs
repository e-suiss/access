//! OP-67 m.1, m.2: a log line inside a request span carries the request's trace.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use access_telemetry::trace::{self, TraceParent};
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

// OP-67 m.1, m.2
#[test]
fn log_lines_carry_the_common_fields() {
    let capture = Capture::default();
    let mut config = access_telemetry::Config::local("info");
    config.service = "access-test";
    config.version = "9.9.9";
    let _telemetry = access_telemetry::install(&config, capture.clone()).unwrap();

    let incoming =
        TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
    let span = tracing::info_span!("request");
    trace::adopt(&span, incoming, Some("congo=t61rcWkgMzE"));
    span.in_scope(|| {
        tracing::info!(event = "login.failed", outcome = "deny", "sign-in refused");
        let current = trace::current().unwrap();
        assert_eq!(current.trace_id(), incoming.trace_id());
        assert_ne!(current.span_id(), incoming.span_id());
    });

    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let line = output
        .lines()
        .find(|l| l.contains("login.failed"))
        .expect("the event was logged");
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["trace_id"], "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(v["span_id"].as_str().map(str::len), Some(16));
    assert_ne!(v["span_id"], "00f067aa0ba902b7");
    assert_eq!(v["service"], "access-test");
    assert_eq!(v["version"], "9.9.9");
    assert_eq!(v["event"], "login.failed");
    assert_eq!(v["outcome"], "deny");
    assert_eq!(v["message"], "sign-in refused");

    // OP-67 m.1
    let fresh = tracing::info_span!("request");
    let own = trace::of(&fresh).unwrap();
    assert_ne!(own.trace_id(), incoming.trace_id());
}
