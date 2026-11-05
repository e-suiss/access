//! The runner against the reference adapters as child processes over the JSON-lines
//! protocol (OP-150 m.1 (a)).

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn runner(sut: &str) -> Output {
    let cases = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/pep/cases");
    Command::new(env!("CARGO_BIN_EXE_access-pep-conformance"))
        .args(["--sut", sut, "--deadline-ms", "300", "--cases"])
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
    assert!(text.contains("19/19 passed, 0 leaked"), "{text}");

    let leaky = runner(env!("CARGO_BIN_EXE_pep-reference-leaky"));
    let text = String::from_utf8_lossy(&leaky.stdout);
    assert_eq!(leaky.status.code(), Some(1), "{text}");
    assert!(text.contains("13 leaked an effect"), "{text}");
    assert!(text.contains("LEAK      adp-timeout"), "{text}");
}

// CMP-17
#[test]
fn an_adapter_that_breaks_the_protocol_stops_the_run() {
    let out = runner("echo not-json");
    assert_eq!(out.status.code(), Some(2));
    let out = runner("true");
    assert_eq!(out.status.code(), Some(2));
}
