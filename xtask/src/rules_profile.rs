//! `panic-profile` (SA-21, OP-4, R-1): release builds keep overflow checks, and
//! network processes unwind so a panic fails one request, not the process.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::read;

const RULE: &str = "panic-profile";

/// Profiles used only to build `access-signer` and `access-parser-worker`.
const ISOLATED_ABORT_PROFILES: &[&str] = &[];

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

/// Checks the `[profile.*]` tables of a manifest or Cargo config.
pub(crate) fn profile_violations(
    path: &str,
    text: &str,
    require_release: bool,
) -> Result<Vec<Violation>, String> {
    let table: toml::Table = text.parse().map_err(|e| format!("{path}: {e}"))?;
    let mut out = Vec::new();
    let profiles = table.get("profile").and_then(toml::Value::as_table);
    if require_release {
        let overflow = profiles
            .and_then(|p| p.get("release"))
            .and_then(|r| r.get("overflow-checks"))
            .and_then(toml::Value::as_bool);
        if overflow != Some(true) {
            out.push(v(
                path,
                "[profile.release] must set overflow-checks = true (OP-4, R-1)".to_owned(),
            ));
        }
    }
    for (name, profile) in profiles.into_iter().flatten() {
        if profile
            .get("overflow-checks")
            .and_then(toml::Value::as_bool)
            == Some(false)
        {
            out.push(v(
                path,
                format!("[profile.{name}] disables overflow checks (OP-4, R-1)"),
            ));
        }
        let aborts = profile.get("panic").and_then(toml::Value::as_str) == Some("abort");
        if aborts && !ISOLATED_ABORT_PROFILES.contains(&name.as_str()) {
            out.push(v(
                path,
                format!(
                    "[profile.{name}] sets panic = \"abort\"; network processes must unwind (SA-21)"
                ),
            ));
        }
    }
    Ok(out)
}

/// Rejects `-C panic=abort` passed through rustflags in a Cargo config.
pub(crate) fn rustflag_violations(path: &str, text: &str) -> Vec<Violation> {
    let squeezed: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '"' && *c != '\'')
        .collect();
    if squeezed.contains("panic=abort") {
        vec![v(
            path,
            "rustflags set panic=abort; network processes must unwind (SA-21)".to_owned(),
        )]
    } else {
        Vec::new()
    }
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = profile_violations("Cargo.toml", &read(&root.join("Cargo.toml"))?, true)?;
    for config in [".cargo/config.toml", ".cargo/config"] {
        let path = root.join(config);
        if path.exists() {
            let text = read(&path)?;
            out.extend(profile_violations(config, &text, false)?);
            out.extend(rustflag_violations(config, &text));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_without_overflow_checks_is_rejected() {
        let v = profile_violations("Cargo.toml", "[profile.release]\nlto = true\n", true)
            .unwrap_or_default();
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn abort_in_release_profile_is_rejected() {
        let text = "[profile.release]\noverflow-checks = true\npanic = \"abort\"\n";
        assert_eq!(
            profile_violations("Cargo.toml", text, true)
                .unwrap_or_default()
                .len(),
            1
        );
    }

    #[test]
    fn unwinding_release_with_overflow_checks_is_accepted() {
        let text = "[profile.release]\noverflow-checks = true\npanic = \"unwind\"\n";
        assert!(
            profile_violations("Cargo.toml", text, true)
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[test]
    fn panic_abort_rustflag_is_rejected() {
        assert_eq!(
            rustflag_violations("c", "rustflags = [\"-C\", \"panic=abort\"]").len(),
            1
        );
    }
}
