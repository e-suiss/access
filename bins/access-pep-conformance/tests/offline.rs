//! Conformance is not endorsement (P2, B9, §9.17, OP-159 m.3 (gg), Ek B 6292): the suite runs
//! with no Suiss account, no credentials and no configuration from the environment.

#![allow(
    clippy::unwrap_used,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::process::Command;

// P2, B9, OP-159 m.3 (gg)
#[test]
fn the_suite_runs_without_a_suiss_account_or_any_environment() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance");
    let home = std::env::temp_dir().join(format!("pep-offline-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_access-pep-conformance"))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .current_dir(&home)
        .args(["--profile", "decision-pep", "--root"])
        .arg(&root)
        .arg("--cases")
        .arg(root.join("pep/cases"))
        .args(["--deadline-ms", "2000", "--grace-ms", "5000", "--sut"])
        .arg(env!("CARGO_BIN_EXE_pep-sdk"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("0 leaked"), "{text}");
    assert!(text.contains("not endorsement"), "{text}");
    std::fs::remove_dir_all(&home).unwrap();
}
