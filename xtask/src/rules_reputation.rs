//! `no-reputation-score` (MUST-NEVER-8, §2.8, OP-157 m.3 (m)): Access computes no global
//! reputation or trust score and gives the coordinator no rank: only facts.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "no-reputation-score";

/// Identifier shapes of a global score, lower-cased with `_` and `-` removed.
const SCORES: [&str; 6] = [
    "reputationscore",
    "trustscore",
    "reputationrank",
    "approverrank",
    "userreputation",
    "approverreputation",
];

fn scope(p: &str) -> bool {
    ["crates/", "bins/", "services/", "sdks/rust/"]
        .iter()
        .any(|t| p.starts_with(t))
        && Path::new(p).extension().is_some_and(|e| e == "rs")
        && !is_test_file(p)
        && !p.starts_with("xtask/")
}

/// The lines of `text` naming a global score.
pub(crate) fn hits(text: &str) -> Vec<(usize, &'static str)> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let squeezed: String = line
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        for s in SCORES {
            if squeezed.contains(s) {
                out.push((n.saturating_add(1), s));
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let name = rel(root, &path);
        if scope(&name) {
            for (line, s) in hits(&read(&path)?) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(&name),
                    message: format!(
                        "line {line}: `{s}`: Access computes no global reputation or score (MUST-NEVER-8)"
                    ),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // MUST-NEVER-8
    #[test]
    fn must_never_8_a_global_score_identifier_is_refused() {
        assert_eq!(hits("let trust_score = 1;").len(), 1);
        assert_eq!(hits("fn approver_rank() {}").len(), 1);
        assert_eq!(hits("const REPUTATION_WINDOW_S: i64 = 1;"), Vec::new());
        assert_eq!(hits("let risk = signal.level();"), Vec::new());
    }
}
