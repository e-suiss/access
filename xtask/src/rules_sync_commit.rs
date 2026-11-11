//! `sync-commit` (OP-54-RL6, OP-24, OP-158 m.3 (n)): security writes run with `synchronous_commit = on`; only the OPERATIONAL telemetry connection uses `local`.
//!
//! - The security connections' startup options carry `synchronous_commit = on`
//!   (`crates/store/src/connect.rs`), so no role or database default can weaken them.
//! - No code, migration or deployment file sets `synchronous_commit` to `local`, `off` or
//!   `remote_write` outside [`OPERATIONAL`]; the deployment templates set it `on`.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "sync-commit";

const CONNECT: &str = "crates/store/src/connect.rs";

/// The files of the OPERATIONAL telemetry connection, the only place `local` is allowed. There
/// is none yet: telemetry is not written to the database.
const OPERATIONAL: [&str; 0] = [];

const SCANNED: [&str; 5] = ["crates/", "bins/", "services/", "deploy/", "scripts/"];

const WEAK: [&str; 3] = ["local", "off", "remote_write"];

/// The weakened setting on `line`, if any.
pub(crate) fn weakened(line: &str) -> Option<&'static str> {
    let lower = line.to_ascii_lowercase();
    let at = lower.find("synchronous_commit")?;
    let rest = lower.get(at.saturating_add("synchronous_commit".len())..)?;
    let value: String = rest
        .trim_start_matches(|c: char| {
            c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ':' | '=' | ')')
        })
        .trim_start_matches("to ")
        .trim_start_matches(|c: char| c.is_whitespace() || matches!(c, '"' | '\''))
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    WEAK.into_iter().find(|w| value == *w)
}

fn violation(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

/// Runs `sync-commit`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let connect = read(&root.join(CONNECT))?;
    if !connect.contains(r#"("synchronous_commit", "on")"#) {
        out.push(violation(
            CONNECT,
            String::from("the security connections' options do not set synchronous_commit = on"),
        ));
    }
    for path in walk(root)? {
        let r = rel(root, &path);
        if !SCANNED.iter().any(|s| r.starts_with(s)) || OPERATIONAL.contains(&r.as_str()) {
            continue;
        }
        let text_file = [".rs", ".sql", ".toml", ".yaml", ".yml", ".conf", ".sh"]
            .iter()
            .any(|e| r.ends_with(e));
        if !text_file
            || (std::path::Path::new(&r)
                .extension()
                .is_some_and(|e| e == "rs")
                && is_test_file(&r))
            || r.starts_with("xtask/")
        {
            continue;
        }
        let Ok(src) = read(&path) else { continue };
        for (i, line) in src.lines().enumerate() {
            if let Some(w) = weakened(line) {
                out.push(violation(
                    &r,
                    format!(
                        "line {}: synchronous_commit = {w}; security writes wait for the synchronous quorum (OP-24, OP-54-RL6)",
                        i.saturating_add(1)
                    ),
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-54-RL6, OP-24
    #[test]
    fn op_54_rl6_a_weakened_commit_setting_is_found_in_every_spelling() {
        assert_eq!(weakened("SET synchronous_commit = local"), Some("local"));
        assert_eq!(weakened("SET synchronous_commit TO off;"), Some("off"));
        assert_eq!(
            weakened(r#"("synchronous_commit", "remote_write")"#),
            Some("remote_write")
        );
        assert_eq!(weakened("  synchronous_commit: 'local'"), Some("local"));
        assert_eq!(weakened(r#"("synchronous_commit", "on")"#), None);
        assert_eq!(weakened("synchronous_commit = on"), None);
        assert_eq!(weakened("synchronous_commit: \"on\""), None);
        assert_eq!(weakened("nothing here"), None);
    }

    #[test]
    fn the_repository_has_no_weakened_commit() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check(root).unwrap();
        assert!(
            v.is_empty(),
            "{:?}",
            v.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }
}
