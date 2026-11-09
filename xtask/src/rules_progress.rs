//! `no-plan-progress` (MUST-NEVER-6, F10, OP-154 m.3 (b)): Access is not a workflow engine and
//! keeps no step state. A plan or step is only an opaque `PlanRef` or `StepRef` in an intent;
//! no table of an Access plane and no type of its non-test code names where a plan stands. The
//! Executor (`services/executor`) keeps its own job history by design (E62, E63) and is outside
//! this rule.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};

const RULE: &str = "no-plan-progress";

/// Identifiers that would hold where a plan stands.
const PROGRESS: &[&str] = &[
    "plan_progress",
    "step_progress",
    "current_step",
    "next_step",
    "completed_steps",
    "steps_done",
    "step_state",
    "plan_state",
    "step_status",
    "plan_status",
];

fn words(line: &str) -> impl Iterator<Item = String> + '_ {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
}

/// A migration's identifiers that name plan progress, outside `--` comments; a SQL table never
/// says `progress` at all.
pub(crate) fn sql_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let code = line.split("--").next().unwrap_or_default();
        for w in words(code) {
            if w == "progress" || PROGRESS.contains(&w.as_str()) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(format!("{rel_path}:{}", i.saturating_add(1))),
                    message: format!(
                        "`{w}`: Access keeps no plan or step state; a step is an opaque StepRef \
                         (MUST-NEVER-6)"
                    ),
                });
            }
        }
    }
    out
}

/// A Rust source's non-test identifiers that name plan progress.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        let n = i.saturating_add(1);
        if in_regions(&tests, n) {
            continue;
        }
        for w in words(line) {
            if PROGRESS.contains(&w.as_str()) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(format!("{rel_path}:{n}")),
                    message: format!(
                        "`{w}`: Access keeps no plan or step state; a step is an opaque StepRef \
                         (MUST-NEVER-6)"
                    ),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if !rel_path.starts_with("crates/") {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("sql") => out.extend(sql_violations(&rel_path, &read(&path)?)),
            Some("rs") if !is_test_file(&rel_path) => {
                out.extend(rust_violations(&rel_path, &read(&path)?));
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // MUST-NEVER-6, F10
    #[test]
    fn a_table_or_type_holding_plan_progress_is_refused() {
        let sql = "  id uuid,\n  current_step int,\n  progress int -- a\n";
        assert_eq!(
            sql_violations("crates/store/migrations/x.sql", sql).len(),
            2
        );
        let rs = "pub struct Job {\n    pub plan_state: u8,\n}\n";
        assert_eq!(
            rust_violations("crates/authority-core/src/a.rs", rs).len(),
            1
        );
    }

    // MUST-NEVER-6
    #[test]
    fn an_opaque_plan_reference_and_comments_are_accepted() {
        let sql = "-- the step's progress lives with the executor\n  plan_ref bytea,\n";
        assert!(sql_violations("crates/store/migrations/x.sql", sql).is_empty());
        let rs = "/// Not the current_step.\npub struct C {\n    pub plan: Option<Digest>,\n    pub step: Option<Digest>,\n}\n#[cfg(test)]\nmod tests { const next_step: u8 = 0; }\n";
        assert!(rust_violations("crates/kernel/src/intent.rs", rs).is_empty());
    }
}
