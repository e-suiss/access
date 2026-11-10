//! `no-money-state` (MUST-NEVER-7, §7.9.9.4, OP-156 m.3 (u)): Access holds no money, writes no
//! ledger and coordinates no transaction. No migration under `crates/store/migrations/` or
//! `services/*/migrations/` may name a table or column for balances, ledgers, settlement, funds,
//! payouts, wallets or escrow, and no file under `crates/`, `bins/` or `services/` may run a
//! two-phase commit. Comments may name them.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "no-money-state";

/// Identifier parts that would make a table or column hold money state, lower case.
const MONEY: &[&str] = &[
    "balance",
    "ledger",
    "settlement",
    "funds",
    "payout",
    "wallet",
    "escrow",
];

/// Statements of a two-phase commit, lower case.
const COORDINATION: &[&str] = &[
    "prepare transaction",
    "commit prepared",
    "rollback prepared",
];

const CODE_ROOTS: &[&str] = &["crates/", "bins/", "services/"];

const CODE_EXTENSIONS: &[&str] = &["rs", "sql"];

fn migration(rel_path: &str) -> bool {
    let p = Path::new(rel_path);
    let parent = p
        .parent()
        .and_then(|d| d.file_name())
        .and_then(|d| d.to_str());
    let ext = p.extension().and_then(|e| e.to_str());
    ext == Some("sql")
        && parent == Some("migrations")
        && (rel_path.starts_with("crates/store/") || rel_path.starts_with("services/"))
}

fn code(line: &str) -> &str {
    line.split("--").next().unwrap_or_default()
}

/// The lines of a migration that name money state in an identifier.
pub(crate) fn money_hits(src: &str) -> Vec<usize> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            let l = code(l).to_ascii_lowercase();
            l.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| !w.is_empty())
                .any(|w| w == "money" || MONEY.iter().any(|m| w.contains(m)))
        })
        .map(|(i, _)| i.saturating_add(1))
        .collect()
}

/// The lines of a source file that run a two-phase commit.
pub(crate) fn coordination_hits(src: &str) -> Vec<usize> {
    src.lines()
        .enumerate()
        .filter(|(_, l)| {
            let l = l.trim_start();
            if l.starts_with("//") || l.starts_with("--") {
                return false;
            }
            let l = l.to_ascii_lowercase();
            let squeezed: String = l.split_whitespace().collect::<Vec<_>>().join(" ");
            COORDINATION.iter().any(|c| squeezed.contains(c))
        })
        .map(|(i, _)| i.saturating_add(1))
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if !CODE_ROOTS.iter().any(|r| rel_path.starts_with(r)) || !CODE_EXTENSIONS.contains(&ext) {
            continue;
        }
        let src = read(&path)?;
        if migration(&rel_path) {
            for line in money_hits(&src) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(format!("{rel_path}:{line}")),
                    message: "names money state; Access holds no money and writes no ledger \
                              (MUST-NEVER-7)"
                        .to_owned(),
                });
            }
        }
        for line in coordination_hits(&src) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: "runs a two-phase commit; Access coordinates no transaction \
                          (MUST-NEVER-7)"
                    .to_owned(),
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // MUST-NEVER-7
    #[test]
    fn money_state_and_two_phase_commit_are_found_and_comments_are_not() {
        assert_eq!(
            money_hits("create table access.account_balances (\n  id bytea\n);\n"),
            vec![1]
        );
        assert_eq!(money_hits("a int,\n  funds_held bigint,\n"), vec![2]);
        assert_eq!(money_hits("  amount money\n"), vec![1]);
        assert_eq!(
            money_hits("-- a ledger position, never a commit input\ncreate table x (id int);\n"),
            Vec::<usize>::new()
        );
        assert_eq!(
            coordination_hits("let q = \"prepare  transaction 'p1'\";\n"),
            vec![1]
        );
        assert_eq!(
            coordination_hits("// never PREPARE TRANSACTION here\n"),
            Vec::<usize>::new()
        );
        assert!(migration(
            "crates/store/migrations/20261117170000_q17_x.sql"
        ));
        assert!(migration("services/executor/migrations/1_x.sql"));
        assert!(!migration("crates/store/src/claims.rs"));
    }
}
