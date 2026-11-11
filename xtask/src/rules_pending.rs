//! `no-pending-queue` (X5, C26, §8.17.9.5, §12.5.2, OP-157 m.3 (u), Ek B 5558): Access has no
//! pending-change queue. Governance quorums live in the coordinator (a Work Gate or the
//! organization's IGA tool); the first admin's request returns `REQUIRE_ACTION` and nothing
//! waits here. No migration creates a pending-change table, and no route or operation names a
//! queue of pending changes or requests.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "no-pending-queue";

/// The names of a pending-change queue, in words.
const QUEUES: [&[&str]; 7] = [
    &["pending", "change"],
    &["pending", "changes"],
    &["pending", "approval"],
    &["pending", "approvals"],
    &["change", "queue"],
    &["approval", "queue"],
    &["request", "queue"],
];

fn words(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut last_lower = false;
    for c in line.chars() {
        if !c.is_ascii_alphanumeric() {
            if !word.is_empty() {
                out.push(std::mem::take(&mut word));
            }
            last_lower = false;
            continue;
        }
        if c.is_ascii_uppercase() && last_lower && !word.is_empty() {
            out.push(std::mem::take(&mut word));
        }
        last_lower = c.is_ascii_lowercase();
        word.push(c.to_ascii_lowercase());
    }
    if !word.is_empty() {
        out.push(word);
    }
    out
}

fn comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with("--") || t.starts_with('*') || t.starts_with('#')
}

/// Where the rule reads: migrations, the API routes and operations, the console's API client.
pub(crate) fn scope(rel: &str) -> bool {
    let sql = rel.ends_with(".sql")
        && (rel.starts_with("crates/store/migrations/") || rel.contains("/migrations/"));
    let api = rel.ends_with(".rs") && rel.starts_with("crates/http/src/api/");
    let spec = rel.ends_with(".json") && rel.contains("openapi");
    sql || api || spec
}

/// The queue names `text` uses outside comments.
pub(crate) fn scan(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().filter(|l| !comment(l)) {
        let w = words(line);
        for q in QUEUES {
            if w.windows(q.len())
                .any(|win| win.iter().zip(q.iter()).all(|(a, b)| a == b))
            {
                out.push(format!(
                    "`{}`: Access has no queue of pending changes; governance quorums live in the coordinator (X5, C26)",
                    q.join(" ")
                ));
            }
        }
    }
    out
}

/// Runs `no-pending-queue`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        if !scope(&r) {
            continue;
        }
        let text = read(&path)?;
        out.extend(scan(&text).into_iter().map(|message| Violation {
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

    // X5, C26, §8.17.9.5, OP-157 m.3 (u), Ek B 5558
    #[test]
    fn x5_a_pending_change_table_or_route_is_refused() {
        assert_eq!(
            scan("CREATE TABLE access.pending_changes (id uuid);").len(),
            1
        );
        assert_eq!(
            scan(r#".route("/admin/v1/pending-changes", get(h))"#).len(),
            1
        );
        assert_eq!(scan(r#""operationId": "listPendingApprovals""#).len(), 1);
        assert_eq!(
            scan("CREATE TABLE access.approval_queue (id uuid);").len(),
            1
        );
        assert!(scan("SELECT pending FROM access.relay_outbox").is_empty());
        assert!(scan("-- a pending change lives in the coordinator").is_empty());
        assert!(scan("// no pending change queue here").is_empty());
        assert!(scope("crates/store/migrations/20260101000000_x.sql"));
        assert!(scope("crates/http/src/api/realm.rs"));
        assert!(!scope("web/console/src/screens/Admin.tsx"));
    }
}
