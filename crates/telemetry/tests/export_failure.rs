//! TI-18: telemetry is never a decision input; an export that fails changes nothing.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::{Duration, Instant};

use access_telemetry::signals::DECISIONS;

fn decide(amount: u64) -> &'static str {
    let outcome = if amount > 10 { "deny" } else { "allow" };
    DECISIONS.incr([outcome]);
    let _span = tracing::info_span!("decision").entered();
    tracing::info!(event = "decision.made", outcome, "decided");
    outcome
}

// TI-18, OP-47: with the collector unreachable, recording metrics and spans neither fails nor
// waits, and the same inputs give the same decisions
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_exporter_never_changes_a_decision() {
    let before: Vec<&str> = [1, 20, 5].into_iter().map(decide).collect();

    let mut config = access_telemetry::Config::local("info");
    config.otlp_endpoint = Some(String::from("http://127.0.0.1:9"));
    let telemetry = access_telemetry::install(&config, || access_telemetry::Discard).unwrap();
    let export = telemetry.start_export().unwrap();
    assert!(export.is_some());
    assert!(telemetry.start_export().is_err());

    let started = Instant::now();
    let after: Vec<&str> = [1, 20, 5].into_iter().map(decide).collect();
    for _ in 0..1000 {
        decide(3);
    }
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(before, after);
    assert!(DECISIONS.get() >= 1006);
    telemetry.shutdown();
}
