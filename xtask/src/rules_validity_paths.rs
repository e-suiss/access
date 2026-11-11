//! `validity-paths` (SI-7, MD-7, EP-1…EP-10, OP-158 m.3 (t)): every validity path in
//! `conformance/catalog/validity-paths.toml` declares its cache-miss, partition and restart
//! behaviour and its staleness, names the code that implements it (which cites the path or one
//! of its rows), and never promises both validation while the database is down and revocation
//! within 250 ms. An `EP-n` cited in non-test code that the table does not declare is a
//! violation: an undeclared path does not pass.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "validity-paths";

const TABLE: &str = "conformance/catalog/validity-paths.toml";

/// The budget that may not be promised together with validation while the database is down.
const FAST_REVOCATION_MS: u64 = 250;

const SCANNED: &[&str] = &["crates/", "bins/", "sdks/rust/", "services/"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    version: u32,
    path: Vec<Row>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    path: String,
    rows: Vec<String>,
    cache_miss: String,
    partition: String,
    restart: String,
    staleness: String,
    db_down_validation: bool,
    revocation_ms: Option<u64>,
    code: Vec<String>,
}

fn violation(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

fn rows_of(t: &Table) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    if t.version != 1 {
        out.push(violation(TABLE, String::from("version must be 1")));
    }
    for r in &t.path {
        let at = format!("{TABLE} {}", r.id);
        if !seen.insert(r.id.clone()) {
            out.push(violation(&at, String::from("declared twice")));
        }
        for (name, v) in [
            ("path", &r.path),
            ("cache_miss", &r.cache_miss),
            ("partition", &r.partition),
            ("restart", &r.restart),
            ("staleness", &r.staleness),
        ] {
            if v.trim().is_empty() {
                out.push(violation(&at, format!("`{name}` is not declared (SI-7)")));
            }
        }
        if r.rows.is_empty() {
            out.push(violation(
                &at,
                String::from("names no guarantee row (MD-7)"),
            ));
        }
        if r.code.is_empty() {
            out.push(violation(&at, String::from("names no code (SI-7)")));
        }
        // MD-7, §13.11
        if r.db_down_validation && r.revocation_ms.is_some_and(|ms| ms <= FAST_REVOCATION_MS) {
            out.push(violation(
                &at,
                String::from(
                    "promises validation while the database is down and revocation within 250 ms on one path (MD-7)",
                ),
            ));
        }
    }
    for n in 1..=10 {
        let id = format!("EP-{n}");
        if !seen.contains(&id) {
            out.push(violation(TABLE, format!("{id} is not declared (§13.11)")));
        }
    }
    out
}

fn cites(text: &str, id: &str) -> bool {
    let b = text.as_bytes();
    text.match_indices(id).any(|(at, _)| {
        let before = at.checked_sub(1).and_then(|p| b.get(p)).copied();
        let after = b.get(at.saturating_add(id.len())).copied();
        !before.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-')
            && !after.is_some_and(|c| c.is_ascii_alphanumeric())
    })
}

fn code_of(root: &Path, t: &Table) -> Vec<Violation> {
    let mut out = Vec::new();
    for r in &t.path {
        for file in &r.code {
            let at = format!("{TABLE} {}", r.id);
            let Ok(text) = read(&root.join(file)) else {
                out.push(violation(&at, format!("`{file}` does not exist")));
                continue;
            };
            if !cites(&text, &r.id) && !r.rows.iter().any(|row| cites(&text, row)) {
                out.push(violation(
                    file,
                    format!("implements {} but cites neither it nor its rows", r.id),
                ));
            }
        }
    }
    out
}

/// The `EP-n` (n < 100) ids a text cites.
fn ep_ids(text: &str) -> BTreeSet<String> {
    let b = text.as_bytes();
    let mut out = BTreeSet::new();
    for (at, _) in text.match_indices("EP-") {
        let before = at.checked_sub(1).and_then(|p| b.get(p)).copied();
        if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            continue;
        }
        let digits: String = text
            .get(at.saturating_add(3)..)
            .unwrap_or_default()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if (1..=2).contains(&digits.len()) && !digits.starts_with('0') {
            out.insert(format!("EP-{digits}"));
        }
    }
    out
}

/// Runs `validity-paths`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read(&root.join(TABLE))?;
    let table: Table = toml::from_str(&text).map_err(|e| format!("{TABLE}: {e}"))?;
    let mut out = rows_of(&table);
    out.extend(code_of(root, &table));
    let declared: BTreeSet<&str> = table.path.iter().map(|r| r.id.as_str()).collect();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if path.extension().and_then(|e| e.to_str()) != Some("rs")
            || is_test_file(&rel_path)
            || !SCANNED.iter().any(|p| rel_path.starts_with(p))
        {
            continue;
        }
        for id in ep_ids(&read(&path)?) {
            if !declared.contains(id.as_str()) {
                out.push(violation(
                    &rel_path,
                    format!("cites {id}, which {TABLE} does not declare (SI-7)"),
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, db_down: bool, revocation: Option<u64>) -> Row {
        Row {
            id: String::from(id),
            path: String::from("p"),
            rows: vec![String::from("G49")],
            cache_miss: String::from("c"),
            partition: String::from("p"),
            restart: String::from("r"),
            staleness: String::from("s"),
            db_down_validation: db_down,
            revocation_ms: revocation,
            code: vec![String::from("a.rs")],
        }
    }

    fn table(extra: Row) -> Table {
        let mut path: Vec<Row> = (1..=10)
            .map(|n| row(&format!("EP-{n}"), false, None))
            .collect();
        path.retain(|r| r.id != extra.id);
        path.push(extra);
        Table { version: 1, path }
    }

    // MD-7, §13.11, OP-158 m.3 (t)
    #[test]
    fn a_path_never_promises_db_down_validation_with_fast_revocation() {
        assert!(rows_of(&table(row("EP-3", false, Some(250)))).is_empty());
        assert!(rows_of(&table(row("EP-4", true, None))).is_empty());
        assert_eq!(rows_of(&table(row("EP-4", true, Some(250)))).len(), 1);
    }

    // SI-7
    #[test]
    fn every_path_declares_its_behaviour_and_every_row_is_there() {
        let mut r = row("EP-6", true, None);
        r.partition = String::new();
        r.code.clear();
        assert_eq!(rows_of(&table(r)).len(), 2);
        let mut t = table(row("EP-1", false, None));
        t.path.retain(|r| r.id != "EP-9");
        assert_eq!(rows_of(&t).len(), 1);
    }

    // SI-7
    #[test]
    fn cited_paths_are_read_at_their_boundaries() {
        let ids = ep_ids("// EP-3, EP-10; ECDH-EP-256, SEP-2243, EP-256, EP-07");
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            vec![String::from("EP-10"), String::from("EP-3")]
        );
        assert!(cites("/// (G49, U35)", "U35"));
        assert!(!cites("/// U350", "U35"));
    }

    // SI-7
    #[test]
    fn the_shipped_table_parses() {
        let text = include_str!("../../conformance/catalog/validity-paths.toml");
        let t: Table = toml::from_str(text).unwrap();
        assert!(rows_of(&t).is_empty());
    }
}
