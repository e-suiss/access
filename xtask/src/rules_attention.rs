//! `attention-model` (§8.6, X23, OP-157 m.3 (m), Ek B 5619): the attention table is data in
//! `conformance/catalog/attention.toml`; no timer or job writes an action a `never` row names
//! (widening, acceptance, renewal, role transition, disposition, approval).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "attention-model";
const TABLE: &str = "conformance/catalog/attention.toml";

/// The automatic-column values §8.6 uses.
const AUTOMATIC: [&str; 3] = ["yes", "no", "never"];

/// Path parts that mark scheduled or job code.
const SCHEDULED: [&str; 6] = ["/jobs", "/job.", "sweep", "scheduler", "cron", "_timer"];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    row: Vec<Row>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    event: String,
    automatic: String,
    #[serde(default)]
    attention: Option<String>,
    owner: String,
    #[serde(default)]
    never_payloads: Vec<String>,
}

fn violation(file: &str, line: usize, message: &str) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(file),
        message: format!("line {line}: {message}"),
    }
}

fn scheduled(path: &str) -> bool {
    Path::new(path).extension().is_some_and(|e| e == "rs")
        && ["crates/", "bins/", "services/"]
            .iter()
            .any(|t| path.starts_with(t))
        && !is_test_file(path)
        && SCHEDULED.iter().any(|m| path.contains(m))
}

/// The table's own shape: known column values, and a payload named only on a `never` row.
pub(crate) fn table_violations(text: &str) -> Vec<Violation> {
    let table: Table = match toml::from_str(text) {
        Ok(t) => t,
        Err(e) => return vec![violation(TABLE, 1, &format!("{e}"))],
    };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for row in &table.row {
        if !seen.insert(row.id.as_str()) {
            out.push(violation(TABLE, 1, &format!("duplicate row `{}`", row.id)));
        }
        if !AUTOMATIC.contains(&row.automatic.as_str()) {
            out.push(violation(
                TABLE,
                1,
                &format!(
                    "row `{}`: unknown automatic value `{}`",
                    row.id, row.automatic
                ),
            ));
        }
        if row.automatic != "never" && row.automatic != "no" && !row.never_payloads.is_empty() {
            out.push(violation(
                TABLE,
                1,
                &format!("row `{}` names payloads but is automatic", row.id),
            ));
        }
        if row.event.is_empty() || row.owner.is_empty() {
            out.push(violation(
                TABLE,
                1,
                &format!("row `{}` is incomplete", row.id),
            ));
        }
        let _ = &row.attention;
    }
    out
}

/// The `Payload::` writes of `never` actions in one scheduled file.
pub(crate) fn file_violations(path: &str, text: &str, never: &BTreeSet<String>) -> Vec<Violation> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        for payload in never {
            if line.contains(&format!("Payload::{payload}")) {
                out.push(violation(
                    path,
                    n.saturating_add(1),
                    &format!(
                        "`Payload::{payload}` in scheduled code: this action is never automatic (§8.6, X23)"
                    ),
                ));
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read(&root.join(TABLE))?;
    let mut out = table_violations(&text);
    let table: Table = toml::from_str(&text).map_err(|e| e.to_string())?;
    let never: BTreeSet<String> = table
        .row
        .into_iter()
        .filter(|r| r.automatic == "never" || r.automatic == "no")
        .flat_map(|r| r.never_payloads)
        .collect();
    for path in walk(root)? {
        let name = rel(root, &path);
        if scheduled(&name) {
            out.extend(file_violations(&name, &read(&path)?, &never));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // X23, §8.6
    #[test]
    fn a_job_that_writes_a_never_automatic_action_is_refused() {
        let never = BTreeSet::from([String::from("GrantIssue")]);
        let v = file_violations(
            "bins/x/src/jobs.rs",
            "let p = Payload::GrantIssue(c);",
            &never,
        );
        assert_eq!(v.len(), 1);
        assert!(v[0].message.contains("never automatic"));
        assert!(
            file_violations(
                "bins/x/src/jobs.rs",
                "let p = Payload::GrantRevoke;",
                &never
            )
            .is_empty()
        );
    }

    #[test]
    fn scheduled_code_is_found_by_its_path() {
        assert!(scheduled("bins/access-server/src/jobs.rs"));
        assert!(scheduled("crates/x/src/hygiene_sweep.rs"));
        assert!(!scheduled("crates/x/src/grant.rs"));
        assert!(!scheduled("crates/x/tests/jobs.rs"));
    }

    #[test]
    fn the_table_rejects_unknown_columns_and_payloads_on_automatic_rows() {
        let good = r#"[[row]]
id = "a"
event = "e"
automatic = "never"
owner = "Access"
never_payloads = ["GrantIssue"]
"#;
        assert!(table_violations(good).is_empty());
        let bad = good.replace("automatic = \"never\"", "automatic = \"yes\"");
        assert!(!table_violations(&bad).is_empty());
        let unknown = good.replace("automatic = \"never\"", "automatic = \"maybe\"");
        assert!(!table_violations(&unknown).is_empty());
    }
}
