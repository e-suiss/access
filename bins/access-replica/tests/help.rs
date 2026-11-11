//! The access-replica placeholder answers `--help` and refuses everything else (OP-158 m.4 (a)).

#![allow(clippy::unwrap_used, reason = "test code")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_access-replica");

// OP-158 m.4 (a)
#[test]
fn help_prints_the_usage_and_anything_else_is_refused() {
    let help = Command::new(BIN).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .starts_with("usage:")
    );
    let other = Command::new(BIN).output().unwrap();
    assert_eq!(other.status.code(), Some(2));
}
