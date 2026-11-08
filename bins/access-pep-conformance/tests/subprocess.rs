//! The runner against the reference adapters as child processes over the JSON-lines
//! protocol (OP-150 m.1 (a)).

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::process::{Command, Output};

/// Real processes on a loaded machine: generous wall-clock limits, so only a wrong answer fails;
/// the exact deadline is checked under paused time in `selftest.rs`.
fn runner(sut: &str) -> Output {
    let cases = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/pep/cases");
    Command::new(env!("CARGO_BIN_EXE_access-pep-conformance"))
        .args([
            "--sut",
            sut,
            "--deadline-ms",
            "2000",
            "--grace-ms",
            "5000",
            "--cases",
        ])
        .arg(cases)
        .output()
        .unwrap()
}

// CMP-17, X21, TI-9, INV-26
#[test]
fn the_runner_passes_the_reference_and_flags_the_leaky_control() {
    let ok = runner(env!("CARGO_BIN_EXE_pep-reference"));
    let text = String::from_utf8_lossy(&ok.stdout);
    assert_eq!(ok.status.code(), Some(0), "{text}");
    assert!(text.contains("26/26 passed, 0 leaked"), "{text}");

    let leaky = runner(env!("CARGO_BIN_EXE_pep-reference-leaky"));
    let text = String::from_utf8_lossy(&leaky.stdout);
    assert_eq!(leaky.status.code(), Some(1), "{text}");
    assert!(text.contains("19 leaked an effect"), "{text}");
    assert!(text.contains("LEAK      adp-timeout"), "{text}");
}

// OP-150 m.2 L10, CMP-17, X21, TI-9
#[test]
fn the_runner_passes_the_sdk_adapter() {
    let ok = runner(env!("CARGO_BIN_EXE_pep-sdk"));
    let text = String::from_utf8_lossy(&ok.stdout);
    assert_eq!(ok.status.code(), Some(0), "{text}");
    assert!(text.contains("26/26 passed, 0 leaked"), "{text}");
}

// CMP-17
#[test]
fn an_adapter_that_breaks_the_protocol_stops_the_run() {
    let out = runner("echo not-json");
    assert_eq!(out.status.code(), Some(2));
    let out = runner("true");
    assert_eq!(out.status.code(), Some(2));
}
