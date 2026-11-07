//! TI-18, IDP-36, OP-47: analytics and telemetry are never a decision, restriction or derived
//! authority input. No source file of a decision path names the analytics reads.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::{Path, PathBuf};

/// What reading analytics looks like in source.
const ANALYTICS: [&str; 7] = [
    "analytics_days",
    "aggregate_day",
    "surge_alerts",
    "analytics_daily",
    "analytics_alert",
    "app::analytics",
    "store::analytics",
];

/// The decision paths: the Kernel, the authority plane and the sign-in decision.
const DECISION_PATHS: [&str; 6] = [
    "kernel/src",
    "authority-core/src",
    "authority-ingest/src",
    "authority-sequencer/src",
    "identity-session/src",
    "suiss-restriction/src",
];

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

// TI-18, IDP-36: no decision path reads analytics
#[test]
fn no_decision_path_reads_analytics() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for d in DECISION_PATHS {
        let dir = crates.join(d);
        assert!(dir.is_dir(), "{}", dir.display());
        sources(&dir, &mut files);
    }
    assert!(files.len() > 20);
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        for token in ANALYTICS {
            assert!(
                !text.contains(token),
                "{} names {token}: analytics is never a decision input (TI-18)",
                f.display()
            );
        }
    }
}
