//! OP-67 m.1: an outbound request carries the current trace as `traceparent`.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_identity_oauth::adapters::outbound::{Target, post_request};
use access_telemetry::trace::{TraceParent, adopt};

// OP-67 m.1
#[test]
fn outbound_requests_carry_the_trace() {
    let target = Target::parse("https://rp.example/logout").unwrap();
    let plain = post_request(&target, "application/json", &[], b"{}").unwrap();
    assert!(!String::from_utf8(plain).unwrap().contains("traceparent"));

    let _telemetry = access_telemetry::install(&access_telemetry::Config::local("info"), || {
        access_telemetry::Discard
    })
    .unwrap();
    let parent =
        TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
    let span = tracing::info_span!("request");
    adopt(&span, parent, None);
    let head = span.in_scope(|| post_request(&target, "application/json", &[], b"{}").unwrap());
    let head = String::from_utf8(head).unwrap();
    assert!(
        head.contains("\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-"),
        "{head}"
    );
}
