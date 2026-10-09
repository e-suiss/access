//! Source-level rules: Kernel and domain purity (OP-1, OP-3, OP-63), SQL only in
//! `store` (OP-66), no physical delete (OP-73), TODOs carry an issue (OP-64) and
//! the `unsafe` allowlist (R-2, OP-3, OP-64).

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{Lexed, find_token, in_regions, lex, line_at, test_regions};
use crate::supply_chain::metadata::{DepKind, Metadata};

fn violation(rule: &'static str, path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

/// Rust files of the repository with their relative paths.
fn rust_files(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    Ok(walk(root)?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| (rel(root, &p), p))
        .collect())
}

const PURITY: &str = "kernel-purity";

/// Pure code (OP-1 rule 1, OP-63 rule 1, TI-3): the Kernel, and the `domain`
/// layer of every component crate. A `*` matches one path segment.
pub(crate) const PURE_PATHS: &[&str] = &[
    "crates/kernel/src/",
    "crates/*/src/domain/",
    "crates/*/src/domain.rs",
];

/// I/O, async, clock and randomness are ports (OP-63); pure code never names them.
const IMPURE_PATTERNS: &[&str] = &[
    "async fn",
    "async move",
    ".await",
    "tokio::",
    "sqlx::",
    "reqwest::",
    "hyper::",
    "mio::",
    "std::fs",
    "std::net",
    "std::io",
    "std::env",
    "std::process",
    "std::thread",
    "std::time",
    "SystemTime",
    "rand::",
    "getrandom",
    "extern crate std",
];

/// Crates pure code must not depend on directly.
const IMPURE_CRATES: &[&str] = &[
    "tokio",
    "async-std",
    "sqlx",
    "tokio-postgres",
    "postgres",
    "reqwest",
    "hyper",
    "mio",
    "socket2",
    "rand",
    "rand_core",
    "getrandom",
];

/// True if `rel_path` is under one of [`PURE_PATHS`].
pub(crate) fn is_pure_path(rel_path: &str) -> bool {
    PURE_PATHS
        .iter()
        .any(|pattern| glob_prefix(pattern, rel_path))
}

/// Matches `path` against `pattern`, where `*` stands for one path segment and
/// a pattern ending in `/` matches everything below it.
fn glob_prefix(pattern: &str, path: &str) -> bool {
    let pat: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    let dir_pattern = pattern.ends_with('/');
    if segs.len() < pat.len() || (!dir_pattern && segs.len() != pat.len()) {
        return false;
    }
    pat.iter().zip(&segs).all(|(p, s)| *p == "*" || p == s)
}

/// Purity violations in one file's non-test code.
pub(crate) fn purity_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for pattern in IMPURE_PATTERNS {
        for at in find_token(&lexed.code, pattern) {
            let line = line_at(&lexed.code, at);
            if !in_regions(&tests, line) {
                out.push(violation(
                    PURITY,
                    rel_path,
                    line,
                    format!("`{pattern}` in pure code; clock, RNG and I/O are ports (OP-1, OP-63)"),
                ));
            }
        }
    }
    out
}

/// OP-1 rule 2: the Kernel root declares `no_std` and forbids `unsafe`.
pub(crate) fn kernel_root_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let code: String = lex(src).code.split_whitespace().collect();
    ["#![no_std]", "#![forbid(unsafe_code)]"]
        .iter()
        .filter(|attr| !code.contains(*attr))
        .map(|attr| {
            violation(
                PURITY,
                rel_path,
                1,
                format!("Kernel root must declare `{attr}` (OP-1)"),
            )
        })
        .collect()
}

fn purity_deps(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        if rel(root, pkg.dir()) != "crates/kernel" {
            continue;
        }
        for dep in pkg.deps.iter().filter(|d| d.kind == DepKind::Normal) {
            if IMPURE_CRATES.contains(&dep.name.as_str()) {
                out.push(Violation {
                    rule: PURITY,
                    path: PathBuf::from("crates/kernel/Cargo.toml"),
                    message: format!("the Kernel must not depend on `{}` (OP-1, OP-3)", dep.name),
                });
            }
        }
    }
    out
}

pub(crate) fn check_purity(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_files(root)? {
        if is_pure_path(&rel_path) && !is_test_file(&rel_path) {
            out.extend(purity_violations(&rel_path, &read(&path)?));
        }
    }
    let kernel_root = root.join("crates/kernel/src/lib.rs");
    if kernel_root.exists() {
        out.extend(kernel_root_violations(
            "crates/kernel/src/lib.rs",
            &read(&kernel_root)?,
        ));
    } else {
        out.push(violation(
            PURITY,
            "crates/kernel/src/lib.rs",
            0,
            "Kernel root is missing".to_owned(),
        ));
    }
    out.extend(purity_deps(
        root,
        &*crate::supply_chain::metadata::load(root)?,
    ));
    Ok(out)
}

const SQL: &str = "sql-only-in-store";

/// The only crate that talks to PostgreSQL (OP-66).
const STORE_DIR: &str = "crates/store/";

/// Code tokens that reach the database.
const SQL_TOKENS: &[&str] = &[
    "sqlx::",
    "tokio_postgres",
    "deadpool_postgres",
    "postgres::",
    "query!",
    "query_as!",
    "query_scalar!",
    "query_file!",
    "query_file_as!",
    "query_unchecked!",
];

/// Database driver crates only `store` may depend on.
const SQL_CRATES: &[&str] = &[
    "sqlx",
    "tokio-postgres",
    "postgres",
    "deadpool-postgres",
    "diesel",
    "sea-orm",
];

/// True if a string literal looks like a SQL statement. Keywords are matched in
/// upper case, the convention for SQL in this repository, so English text such
/// as "select a value from the list" does not match.
pub(crate) fn looks_like_sql(s: &str) -> bool {
    let words: Vec<&str> = s
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let has = |w: &str| words.contains(&w);
    let pair = |a: &str, b: &str| words.windows(2).any(|p| p == [a, b]);
    (has("SELECT") && has("FROM"))
        || pair("INSERT", "INTO")
        || (has("UPDATE") && has("SET"))
        || pair("DELETE", "FROM")
        || pair("CREATE", "TABLE")
        || pair("ALTER", "TABLE")
        || pair("DROP", "TABLE")
        || has("TRUNCATE")
}

/// SQL violations in one Rust file outside `store`.
pub(crate) fn sql_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let mut out = Vec::new();
    for token in SQL_TOKENS {
        for at in find_token(&lexed.code, token) {
            out.push(violation(
                SQL,
                rel_path,
                line_at(&lexed.code, at),
                format!("`{token}` outside crates/store (OP-66)"),
            ));
        }
    }
    for lit in lexed.strings.iter().filter(|l| looks_like_sql(&l.text)) {
        out.push(violation(
            SQL,
            rel_path,
            lit.line,
            "SQL statement outside crates/store (OP-66)".to_owned(),
        ));
    }
    out
}

/// Files that are part of the rule definitions themselves: their tests and
/// pattern tables necessarily spell out the forbidden text.
const RULE_DEFINITION_FILES: &[&str] =
    &["xtask/src/rules_source.rs", "xtask/src/rules_switches.rs"];

pub(crate) fn check_sql(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path.starts_with(STORE_DIR) || RULE_DEFINITION_FILES.contains(&rel_path.as_str()) {
            continue;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some("rs") => out.extend(sql_violations(&rel_path, &read(&path)?)),
            Some("sql") => out.push(violation(
                SQL,
                &rel_path,
                1,
                "SQL file outside crates/store (OP-66)".to_owned(),
            )),
            _ => {}
        }
    }
    let md = crate::supply_chain::metadata::load(root)?;
    for pkg in md.members() {
        if rel(root, pkg.dir()) == STORE_DIR.trim_end_matches('/') {
            continue;
        }
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            if SQL_CRATES.contains(&dep.name.as_str()) {
                out.push(Violation {
                    rule: SQL,
                    path: pkg
                        .manifest_path
                        .strip_prefix(root)
                        .unwrap_or(&pkg.manifest_path)
                        .to_path_buf(),
                    message: format!("only crates/store may depend on `{}` (OP-66)", dep.name),
                });
            }
        }
    }
    Ok(out)
}

const DELETE: &str = "no-physical-delete";

/// Tables that may be cleaned with `DELETE FROM`, one name per line (OP-73 rule
/// 7: identity-only job-queue tables, after the result is in the ledger).
pub(crate) const DELETE_ALLOWLIST_FILE: &str = "xtask/physical-delete-allowlist.txt";

/// Parses the allowlist: one table name per line, `#` starts a comment.
pub(crate) fn parse_list(text: &str) -> Vec<String> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Physical-delete statements in a piece of SQL text, as (byte offset, message).
pub(crate) fn delete_findings(sql: &str, allow: &[String]) -> Vec<(usize, String)> {
    let upper = sql.to_ascii_uppercase();
    let mut words: Vec<(usize, &str)> = Vec::new();
    let mut start = None;
    for (i, c) in upper.char_indices() {
        let word_char = c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"';
        match (word_char, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                words.push((s, upper.get(s..i).unwrap_or_default()));
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        words.push((s, upper.get(s..).unwrap_or_default()));
    }
    let mut out = Vec::new();
    for (k, &(at, w)) in words.iter().enumerate() {
        let next = words.get(k.saturating_add(1)).map(|&(_, n)| n);
        match (w, next) {
            ("DELETE", Some("FROM")) => {
                let mut t = k.saturating_add(2);
                if words.get(t).is_some_and(|&(_, x)| x == "ONLY") {
                    t = t.saturating_add(1);
                }
                let table = words.get(t).map_or("", |&(_, x)| x);
                let bare = table.rsplit('.').next().unwrap_or(table).trim_matches('"');
                if !allow.iter().any(|a| a.eq_ignore_ascii_case(bare)) {
                    out.push((
                        at,
                        format!(
                            "`DELETE FROM {bare}`: rows are never deleted; use soft delete (OP-73)"
                        ),
                    ));
                }
            }
            ("TRUNCATE", _) => out.push((at, "`TRUNCATE` is forbidden (OP-73)".to_owned())),
            ("DROP", Some("TABLE")) => out.push((
                at,
                "`DROP TABLE` is forbidden; archive instead (OP-73)".to_owned(),
            )),
            _ => {}
        }
    }
    out
}

/// Removes `--` and `/* */` comments from SQL, keeping line structure.
fn strip_sql_comments(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('-', Some('-')) => {
                for d in chars.by_ref() {
                    if d == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                let mut prev = ' ';
                for d in chars.by_ref() {
                    if d == '\n' {
                        out.push('\n');
                    }
                    if prev == '*' && d == '/' {
                        break;
                    }
                    prev = d;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

pub(crate) fn check_delete(root: &Path) -> Result<Vec<Violation>, String> {
    let allow_path = root.join(DELETE_ALLOWLIST_FILE);
    let allow = if allow_path.exists() {
        parse_list(&read(&allow_path)?)
    } else {
        Vec::new()
    };
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        match path.extension().and_then(|e| e.to_str()) {
            Some("sql") => {
                let sql = strip_sql_comments(&read(&path)?);
                for (at, msg) in delete_findings(&sql, &allow) {
                    out.push(violation(DELETE, &rel_path, line_at(&sql, at), msg));
                }
            }
            Some("rs")
                if !is_test_file(&rel_path)
                    && !RULE_DEFINITION_FILES.contains(&rel_path.as_str()) =>
            {
                let lexed = lex(&read(&path)?);
                let tests = test_regions(&lexed.code);
                for lit in lexed.strings.iter().filter(|l| !in_regions(&tests, l.line)) {
                    for (_, msg) in delete_findings(&lit.text, &allow) {
                        out.push(violation(DELETE, &rel_path, lit.line, msg));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

const TODO: &str = "todo-has-issue";

/// True if a to-do comment names its issue: `#123` or an issue URL.
pub(crate) fn todo_is_tracked(comment: &str) -> bool {
    let has_ref = comment.match_indices('#').any(|(at, _)| {
        comment
            .get(at.saturating_add(1)..)
            .and_then(|s| s.chars().next())
            .is_some_and(|c| c.is_ascii_digit())
    });
    has_ref || comment.contains("/issues/")
}

/// Lines of untracked to-do comments.
pub(crate) fn untracked_todos(comments: &[(usize, String)]) -> Vec<usize> {
    comments
        .iter()
        .filter(|(_, text)| !find_token(text, "TODO").is_empty() && !todo_is_tracked(text))
        .map(|(line, _)| *line)
        .collect()
}

/// Comment lines of non-Rust text files (`#` comments).
fn hash_comments(text: &str) -> Vec<(usize, String)> {
    text.lines()
        .enumerate()
        .filter_map(|(i, l)| {
            l.find('#').map(|at| {
                (
                    i.saturating_add(1),
                    l.get(at..).unwrap_or_default().to_owned(),
                )
            })
        })
        .collect()
}

pub(crate) fn check_todo(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let comments: Vec<(usize, String)> = match ext {
            "rs" => {
                let Lexed { comments, .. } = lex(&read(&path)?);
                comments.into_iter().map(|c| (c.line, c.text)).collect()
            }
            "toml" | "yml" | "yaml" | "sh" => hash_comments(&read(&path)?),
            _ if name == "justfile" || name == "pre-commit" => hash_comments(&read(&path)?),
            _ => continue,
        };
        for line in untracked_todos(&comments) {
            out.push(violation(
                TODO,
                &rel_path,
                line,
                "TODO without an issue reference (#N or issue URL) (OP-64)".to_owned(),
            ));
        }
    }
    Ok(out)
}

const UNSAFE: &str = "unsafe-allowlist";

/// Crates that may contain `unsafe` (R-2): the aws-lc and HSM/PKCS#11 wrapper,
/// the sandbox and the Kerberos gateway.
pub(crate) const UNSAFE_ALLOWED: &[&str] =
    &["crates/crypto", "crates/sandbox", "bins/access-gw-kerberos"];

/// R-2: total `unsafe` lines in the allowlisted crates.
pub(crate) const UNSAFE_LINE_BUDGET: usize = 500;

/// An `unsafe` use: its line and how many lines its block spans.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UnsafeUse {
    pub(crate) line: usize,
    pub(crate) lines: usize,
    pub(crate) justified: bool,
}

/// Finds every `unsafe` keyword in a file and whether a `// SAFETY:` comment (or a
/// `# Safety` doc section) sits on its line or in the comment and attribute lines
/// directly above.
pub(crate) fn unsafe_uses(src: &str) -> Vec<UnsafeUse> {
    let lexed = lex(src);
    let src_lines: Vec<&str> = src.lines().collect();
    let code_chars: Vec<char> = lexed.code.chars().collect();
    let mut out = Vec::new();
    for at in find_token(&lexed.code, "unsafe") {
        let line = line_at(&lexed.code, at);
        let justified_line = |n: usize| {
            src_lines
                .get(n.saturating_sub(1))
                .is_some_and(|l| l.contains("SAFETY:") || l.contains("# Safety"))
        };
        let mut justified = justified_line(line);
        let mut n = line.saturating_sub(1);
        while !justified && n >= 1 {
            let trimmed = src_lines
                .get(n.saturating_sub(1))
                .map_or("", |l| l.trim_start());
            let continues = ["//", "#[", "#!", "*", "/*"]
                .iter()
                .any(|p| trimmed.starts_with(p));
            if !continues {
                break;
            }
            justified = justified_line(n);
            n = n.saturating_sub(1);
        }
        let char_at = lexed.code.get(..at).map_or(0, |s| s.chars().count());
        let mut depth = 0_usize;
        let mut end_line = line;
        let mut cur_line = line;
        for &c in code_chars.iter().skip(char_at) {
            match c {
                '\n' => cur_line = cur_line.saturating_add(1),
                ';' if depth == 0 => break,
                '{' => depth = depth.saturating_add(1),
                '}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end_line = cur_line;
                        break;
                    }
                }
                _ => {}
            }
        }
        out.push(UnsafeUse {
            line,
            lines: end_line.saturating_sub(line).saturating_add(1),
            justified,
        });
    }
    out
}

/// True if a manifest inherits the workspace lints (`[lints] workspace = true`).
fn inherits_workspace_lints(manifest: &str) -> bool {
    manifest
        .parse::<toml::Table>()
        .ok()
        .and_then(|t| t.get("lints")?.get("workspace")?.as_bool())
        .unwrap_or(false)
}

fn workspace_forbids_unsafe(root_manifest: &str) -> bool {
    root_manifest
        .parse::<toml::Table>()
        .ok()
        .and_then(|t| {
            let v = t
                .get("workspace")?
                .get("lints")?
                .get("rust")?
                .get("unsafe_code")?;
            v.as_str()
                .or_else(|| v.get("level").and_then(toml::Value::as_str))
                .map(|s| s == "forbid")
        })
        .unwrap_or(false)
}

pub(crate) fn check_unsafe(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let ws_forbids = workspace_forbids_unsafe(&read(&root.join("Cargo.toml"))?);
    if !ws_forbids {
        out.push(violation(
            UNSAFE,
            "Cargo.toml",
            1,
            "[workspace.lints.rust] must set unsafe_code = \"forbid\" (R-2)".to_owned(),
        ));
    }
    let md = crate::supply_chain::metadata::load(root)?;
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        if UNSAFE_ALLOWED.contains(&dir.as_str()) {
            continue;
        }
        let manifest_ok = ws_forbids && inherits_workspace_lints(&read(&pkg.manifest_path)?);
        let mut roots_ok = !pkg.crate_roots.is_empty();
        for root_file in &pkg.crate_roots {
            let code: String = lex(&read(root_file)?).code.split_whitespace().collect();
            roots_ok &= code.contains("#![forbid(unsafe_code)]");
        }
        if !manifest_ok && !roots_ok {
            out.push(violation(
                UNSAFE,
                &format!("{dir}/Cargo.toml"),
                1,
                "crate must forbid unsafe: `[lints] workspace = true` or `#![forbid(unsafe_code)]` (R-2)".to_owned(),
            ));
        }
    }
    let mut budget_used = 0_usize;
    for (rel_path, path) in rust_files(root)? {
        let allowed = UNSAFE_ALLOWED
            .iter()
            .any(|d| rel_path.starts_with(&format!("{d}/")));
        for u in unsafe_uses(&read(&path)?) {
            if !u.justified {
                out.push(violation(
                    UNSAFE,
                    &rel_path,
                    u.line,
                    "`unsafe` without a preceding `// SAFETY:` comment (OP-64)".to_owned(),
                ));
            }
            if allowed {
                budget_used = budget_used.saturating_add(u.lines);
            } else if !RULE_DEFINITION_FILES.contains(&rel_path.as_str()) {
                out.push(violation(
                    UNSAFE,
                    &rel_path,
                    u.line,
                    "`unsafe` outside the allowlisted crates (R-2)".to_owned(),
                ));
            }
        }
    }
    if budget_used >= UNSAFE_LINE_BUDGET {
        out.push(violation(
            UNSAFE,
            "Cargo.toml",
            1,
            format!("{budget_used} unsafe lines in allowlisted crates; the budget is < {UNSAFE_LINE_BUDGET} (R-2)"),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_and_domain_layers_are_pure_paths() {
        assert!(is_pure_path("crates/kernel/src/lib.rs"));
        assert!(is_pure_path("crates/authority-core/src/domain/grant.rs"));
        assert!(is_pure_path("crates/identity-session/src/domain.rs"));
        assert!(!is_pure_path("crates/identity-session/src/adapters/pg.rs"));
        assert!(!is_pure_path("crates/identity-session/src/app/domain.rs"));
    }

    #[test]
    fn clock_in_kernel_is_rejected() {
        let v = purity_violations(
            "crates/kernel/src/a.rs",
            "fn now() { let t = std::time::SystemTime::now(); }",
        );
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn async_and_tokio_in_domain_layer_are_rejected() {
        let v = purity_violations(
            "crates/authority-core/src/domain/x.rs",
            "async fn f() { tokio::spawn(g()).await; }",
        );
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn impure_words_in_comments_strings_and_tests_are_ignored() {
        let src = "// no std::fs here\nconst S: &str = \"rand::\";\n#[cfg(test)]\nmod tests { fn t() { std::fs::read(\"x\"); } }\n";
        assert!(purity_violations("crates/kernel/src/a.rs", src).is_empty());
    }

    #[test]
    fn kernel_root_without_no_std_is_rejected() {
        let v = kernel_root_violations("lib.rs", "#![forbid(unsafe_code)]\n");
        assert_eq!(v.len(), 1);
        assert!(
            kernel_root_violations("lib.rs", "#![no_std]\n#![forbid(unsafe_code)]\n").is_empty()
        );
    }

    #[test]
    fn sqlx_macro_outside_store_is_rejected() {
        let v = sql_violations(
            "crates/identity-oauth/src/a.rs",
            "fn f() { sqlx::query!(\"SELECT 1 FROM t\"); }",
        );
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn english_text_is_not_mistaken_for_sql() {
        assert!(!looks_like_sql("select a value from the list"));
        assert!(!looks_like_sql("update the settings"));
        assert!(looks_like_sql("UPDATE users SET name = $1"));
    }

    #[test]
    fn physical_delete_statements_are_rejected() {
        let f = delete_findings(
            "DELETE FROM accounts WHERE id = 1; truncate x; drop table y;",
            &[],
        );
        assert_eq!(f.len(), 3);
    }

    #[test]
    fn allowlisted_job_queue_table_may_be_cleaned() {
        let allow = parse_list("# queue\njobs\n");
        assert_eq!(
            delete_findings("DELETE FROM public.\"jobs\" WHERE done", &allow),
            vec![]
        );
        assert_eq!(delete_findings("DELETE FROM accounts", &allow).len(), 1);
    }

    #[test]
    fn sql_comments_do_not_count() {
        let sql = strip_sql_comments("-- DELETE FROM a\n/* TRUNCATE b */ SELECT 1;");
        assert_eq!(delete_findings(&sql, &[]), vec![]);
    }

    #[test]
    fn todo_without_issue_is_rejected() {
        let comments = vec![
            (1, "// TODO: fix later".to_owned()),
            (2, "// TODO(#42): fix later".to_owned()),
            (
                3,
                "// TODO see https://github.com/e-suiss/access/issues/7".to_owned(),
            ),
            (4, "// TODOS are not TODO-tagged words".to_owned()),
        ];
        assert_eq!(untracked_todos(&comments), vec![1, 4]);
    }

    #[test]
    fn unsafe_block_without_safety_comment_is_rejected() {
        let uses = unsafe_uses("fn f() {\n    let x = unsafe { g() };\n}\n");
        assert_eq!(
            uses,
            vec![UnsafeUse {
                line: 2,
                lines: 1,
                justified: false
            }]
        );
    }

    #[test]
    fn unsafe_block_with_safety_comment_is_accepted_and_counted() {
        let src = "fn f() {\n    // SAFETY: g has no preconditions.\n    unsafe {\n        g();\n    }\n}\n";
        assert_eq!(
            unsafe_uses(src),
            vec![UnsafeUse {
                line: 3,
                lines: 3,
                justified: true
            }]
        );
    }

    #[test]
    fn forbid_unsafe_attribute_is_not_an_unsafe_use() {
        assert_eq!(unsafe_uses("#![forbid(unsafe_code)]\n"), vec![]);
    }

    #[test]
    fn manifest_inheriting_workspace_lints_forbids_unsafe() {
        assert!(inherits_workspace_lints("[lints]\nworkspace = true\n"));
        assert!(!inherits_workspace_lints(
            "[lints.rust]\nunsafe_code = \"allow\"\n"
        ));
        assert!(workspace_forbids_unsafe(
            "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n"
        ));
    }
}
