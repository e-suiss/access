//! `no-kill-switch` (CI-13, SI-4, §6.6, §8.17.9.4, OP-157 m.3 (i), Ek B 5542): nothing changes
//! authority without an Exercise. No code outside the store's authority module writes an
//! authority state table, and no route, handler, screen or command disables everything at once.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "no-kill-switch";

/// The tables that hold authority state; only the sequencer's commit writes them.
const AUTHORITY_TABLES: [&str; 11] = [
    "authority_log",
    "authority_state",
    "authority_version",
    "authority_domain",
    "authority_counter",
    "authority_nonce",
    "authority_outbox",
    "authority_receipt",
    "authority_single_use",
    "domain_head",
    "proof_store",
];

/// Where those tables may be written: the store's authority module, its test harness, the
/// migrations that create them, the cell move, which writes only the replayed records and
/// state another cell committed (OP-158 m.3 (n), m.4 (b) W7), and the handover's freeze and
/// adoption with their test.
const WRITERS: [&str; 6] = [
    "crates/store/src/authority.rs",
    "crates/store/src/testing.rs",
    "crates/store/migrations/",
    "crates/store/src/cells.rs",
    // OP-158 m.3 (l), HO-1, HO-8
    "crates/store/src/handover.rs",
    "crates/store/tests/handover.rs",
];

/// The statements that write a table, assembled so that this file holds none of them.
fn writes() -> [String; 5] {
    [
        ["INS", "ERT INTO"].concat(),
        ["UP", "DATE"].concat(),
        ["DEL", "ETE FROM"].concat(),
        ["CO", "PY"].concat(),
        ["TRUN", "CATE"].concat(),
    ]
}

/// Word sequences that name a switch over everything.
const SWITCHES: [&[&str]; 8] = [
    &["kill", "switch"],
    &["killswitch"],
    &["disable", "all"],
    &["stop", "all"],
    &["shutdown", "all"],
    &["panic", "button"],
    &["off", "switch"],
    &["revoke", "everything"],
];

fn ext(p: &str) -> &str {
    Path::new(p)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
}

fn in_tree(p: &str) -> bool {
    ["crates/", "bins/", "services/", "deploy/", "scripts/"]
        .iter()
        .any(|t| p.starts_with(t))
}

fn sql_scope(p: &str) -> bool {
    in_tree(p)
        && matches!(ext(p), "rs" | "sql" | "sh" | "py")
        && !WRITERS.iter().any(|w| p.starts_with(w))
}

fn switch_scope(p: &str) -> bool {
    let code = (matches!(ext(p), "rs") && in_tree(p) && !is_test_file(p))
        || (matches!(ext(p), "ts" | "tsx")
            && p.starts_with("web/")
            && p.contains("/src/")
            && !p.contains(".test."));
    let contract = ext(p) == "json" && p.starts_with("sdks/openapi/");
    code || contract
}

fn word_end(b: &[u8], at: usize) -> bool {
    b.get(at)
        .is_none_or(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
}

/// The authority tables `text` writes.
pub(crate) fn check_writes(text: &str) -> Vec<String> {
    let upper = text.to_ascii_uppercase();
    let squeezed = upper.split_whitespace().collect::<Vec<_>>().join(" ");
    let b = squeezed.as_bytes();
    let mut out = Vec::new();
    for verb in writes() {
        let needle = format!("{verb} ACCESS.");
        let mut from = 0;
        while let Some(i) = squeezed.get(from..).and_then(|s| s.find(&needle)) {
            let start = from.saturating_add(i).saturating_add(needle.len());
            for table in AUTHORITY_TABLES {
                let t = table.to_ascii_uppercase();
                if squeezed.get(start..).is_some_and(|s| s.starts_with(&t))
                    && word_end(b, start.saturating_add(t.len()))
                {
                    out.push(format!(
                        "`{verb} access.{table}` outside the sequencer's commit: authority state changes only by an Exercise (CI-13)"
                    ));
                }
            }
            from = start;
        }
    }
    out
}

fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in line.chars() {
        if c.is_ascii_alphanumeric() {
            if c.is_ascii_uppercase() && prev_lower && !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = c.is_ascii_lowercase() || c.is_ascii_digit();
            cur.push(c.to_ascii_lowercase());
        } else {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("/*") || t.starts_with('*') || t.starts_with('#')
}

/// The switches over everything `text` names outside comments.
pub(crate) fn check_switches(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !comment(l)) {
        let w = words(line);
        for s in SWITCHES {
            if w.windows(s.len())
                .any(|win| win.iter().zip(s.iter()).all(|(a, b)| a == b))
            {
                out.push(format!(
                    "`{}`: there is no switch over everything; containment is a narrowing Exercise (CI-13, SI-4)",
                    s.join(" ")
                ));
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        let (writes, switches) = (sql_scope(&r), switch_scope(&r));
        if !writes && !switches {
            continue;
        }
        let text = read(&path)?;
        let mut found = Vec::new();
        if writes {
            found.extend(check_writes(&text));
        }
        if switches {
            found.extend(check_switches(&text));
        }
        out.extend(found.into_iter().map(|message| Violation {
            rule: RULE,
            path: Path::new(&r).to_path_buf(),
            message,
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CI-13, §8.17.9.4, Ek B 5542
    #[test]
    fn ci_13_an_authority_write_outside_the_commit_is_refused() {
        let [insert, update, delete, ..] = writes();
        let select = ["SEL", "ECT * FROM"].concat();
        assert_eq!(
            check_writes(&format!("{select} access.authority_state")),
            Vec::<String>::new()
        );
        assert_eq!(
            check_writes(&format!("{update} access.authority_statement")),
            Vec::<String>::new()
        );
        assert_eq!(
            check_writes(&format!("{insert} access.identity_audit")),
            Vec::<String>::new()
        );
        let lower = update.to_ascii_lowercase();
        assert_eq!(
            check_writes(&format!("{lower}  access.authority_state")).len(),
            1
        );
        assert_eq!(
            check_writes(&format!("{delete} access.authority_log")).len(),
            1
        );
        assert_eq!(
            check_writes(&format!("{insert}\n access.domain_head")).len(),
            1
        );
        assert!(!sql_scope("crates/store/src/authority.rs"));
        assert!(!sql_scope("crates/store/migrations/20260101000000_x.sql"));
        assert!(sql_scope("crates/http/src/api/realm/handlers.rs"));
        assert!(sql_scope("deploy/breakglass/run.sh"));
    }

    // CI-13, SI-4, §6.6
    #[test]
    fn ci_13_a_switch_over_everything_is_refused() {
        for named in [
            r#".route("/admin/v1/kill-switch", post(h))"#,
            "fn disable_all(realm: &str) {}",
            "async function stopAll(): Promise<void> {}",
            r#""operationId": "panicButton""#,
            "const KILLSWITCH: bool = true;",
        ] {
            assert_eq!(check_switches(named).len(), 1, "{named}");
        }
        for fine in [
            "// there is no kill switch",
            " * no stop-all button either",
            "fn stop_allowed() {}",
            "let revoke_all_agent_instances = 1;",
            "disabled_at: allowance",
        ] {
            assert_eq!(check_switches(fine), Vec::<String>::new(), "{fine}");
        }
        assert!(switch_scope("web/console/src/screens/Audit.tsx"));
        assert!(switch_scope("sdks/openapi/admin-v1.json"));
        assert!(!switch_scope("crates/http/tests/router.rs"));
        assert!(!switch_scope("xtask/src/rules_kill_switch.rs"));
    }
}
