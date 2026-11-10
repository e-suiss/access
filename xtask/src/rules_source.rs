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

/// The Access Executor's, the VC verifier's and the HR connector's own SQL modules over their
/// own databases (OP-154 m.3 (u), OP-155 m.3 (p), OP-156 m.3 (q)): the only other places SQL is
/// written.
const EXECUTOR_SQL: &[&str] = &[
    "services/executor/src/store.rs",
    "services/executor/src/testing.rs",
    "services/executor/tests/store.rs",
    "services/executor/migrations/",
    // OP-155 m.3 (p)
    "services/vc-verifier/src/store.rs",
    "services/vc-verifier/src/testing.rs",
    "services/vc-verifier/migrations/",
    // OP-156 m.3 (q)
    "services/hr-connector/src/store.rs",
    "services/hr-connector/src/testing.rs",
    "services/hr-connector/tests/store.rs",
    "services/hr-connector/migrations/",
];

/// The packages outside `crates/store` that may depend on a database driver.
const SQL_PACKAGES: &[&str] = &[
    "services/executor",
    "services/vc-verifier",
    "services/hr-connector",
];

fn sql_allowed(rel_path: &str) -> bool {
    rel_path.starts_with(STORE_DIR)
        || EXECUTOR_SQL
            .iter()
            .any(|p| rel_path == *p || (p.ends_with('/') && rel_path.starts_with(p)))
}

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
        if sql_allowed(&rel_path) || RULE_DEFINITION_FILES.contains(&rel_path.as_str()) {
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
        let dir = rel(root, pkg.dir());
        if dir == STORE_DIR.trim_end_matches('/') || SQL_PACKAGES.contains(&dir.as_str()) {
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

/// The one file that may drop a database: the test harness's throwaway clones (OP-73).
pub(crate) const DROP_DATABASE_FILE: &str = "crates/store/src/testing.rs";

/// Physical-delete statements in a piece of SQL text, as (byte offset, message).
/// `DROP DATABASE` passes only when `drop_database` is set (the test harness, OP-73).
pub(crate) fn delete_findings(
    sql: &str,
    allow: &[String],
    drop_database: bool,
) -> Vec<(usize, String)> {
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
            ("TRUNCATE", _)
                if k.checked_sub(1)
                    .and_then(|p| words.get(p))
                    .is_some_and(|&(_, p)| matches!(p, "BEFORE" | "AFTER" | "OR")) => {}
            ("TRUNCATE", _) => out.push((at, "`TRUNCATE` is forbidden (OP-73)".to_owned())),
            ("DROP", Some("TABLE")) => out.push((
                at,
                "`DROP TABLE` is forbidden; archive instead (OP-73)".to_owned(),
            )),
            ("DROP", Some("SCHEMA")) => out.push((
                at,
                "`DROP SCHEMA` is forbidden; archive instead (OP-73)".to_owned(),
            )),
            ("DROP", Some("COLUMN")) => out.push((
                at,
                "`DROP COLUMN` destroys data; soft delete or crypto-shred instead (OP-73)"
                    .to_owned(),
            )),
            ("DROP", Some(col)) if col != "CONSTRAINT" && alter_table_target(&words, k) => {
                out.push((
                    at,
                    "`ALTER TABLE … DROP` destroys data; soft delete or crypto-shred instead (OP-73)"
                        .to_owned(),
                ));
            }
            ("DROP", Some("DATABASE")) if !drop_database => out.push((
                at,
                "`DROP DATABASE` is forbidden outside the test harness (OP-73)".to_owned(),
            )),
            ("THEN", Some("DELETE")) => out.push((
                at,
                "`MERGE … THEN DELETE` removes rows; use soft delete (OP-73)".to_owned(),
            )),
            _ => {}
        }
    }
    out
}

/// True when the words before `k` are an `ALTER TABLE [IF EXISTS] [ONLY] <name>` head, so the
/// `DROP` at `k` drops a column (`COLUMN` is optional in PostgreSQL).
fn alter_table_target(words: &[(usize, &str)], k: usize) -> bool {
    let back = |n: usize| k.checked_sub(n).and_then(|i| words.get(i)).map(|&(_, w)| w);
    let mut n = 2;
    while matches!(back(n), Some("ONLY" | "EXISTS" | "IF")) {
        n = n.saturating_add(1);
    }
    back(n) == Some("TABLE") && back(n.saturating_add(1)) == Some("ALTER")
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
                for (at, msg) in delete_findings(&sql, &allow, false) {
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
                    for (_, msg) in
                        delete_findings(&lit.text, &allow, rel_path == DROP_DATABASE_FILE)
                    {
                        out.push(violation(DELETE, &rel_path, lit.line, msg));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

const MIGRATION: &str = "migration-hygiene";

/// Words a migration never contains (OP-11, OP-16, OP-19, OP-55, §12.1.3 rules 9, 14).
const MIGRATION_BANS: &[(&str, &str)] = &[
    (
        "GEN_RANDOM_UUID",
        "internal ids are uuidv7() (§12.1.3 rule 14)",
    ),
    (
        "UNLOGGED",
        "canonical and SYNC-DERIVED data is never UNLOGGED (OP-16)",
    ),
    ("LISTEN", "LISTEN/NOTIFY is not a carrier (OP-19)"),
    ("NOTIFY", "LISTEN/NOTIFY is not a carrier (OP-19)"),
];

/// Findings in one migration: banned words, and any role switch other than the migration's
/// own `SET LOCAL ROLE access_migrator` / `RESET ROLE`.
pub(crate) fn migration_findings(sql: &str) -> Vec<(usize, String)> {
    let upper = sql.to_ascii_uppercase();
    let words: Vec<(usize, &str)> = upper
        .match_indices(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .scan(0, |start, (at, sep)| {
            let w = (*start, upper.get(*start..at).unwrap_or_default());
            *start = at.saturating_add(sep.len());
            Some(w)
        })
        .filter(|(_, w)| !w.is_empty())
        .collect();
    let mut out = Vec::new();
    for (k, &(at, w)) in words.iter().enumerate() {
        if let Some((_, why)) = MIGRATION_BANS.iter().find(|(b, _)| *b == w) {
            out.push((at, format!("`{w}`: {why}")));
        }
        let next = |n: usize| words.get(k.saturating_add(n)).map(|&(_, x)| x);
        if w == "SET" {
            let role_at = match next(1) {
                Some("ROLE") => Some(2),
                Some("LOCAL" | "SESSION") if next(2) == Some("ROLE") => Some(3),
                _ => None,
            };
            if let Some(r) = role_at {
                let allowed = next(1) == Some("LOCAL") && next(r) == Some("ACCESS_MIGRATOR");
                if !allowed {
                    out.push((
                        at,
                        "role switch: only `SET LOCAL ROLE access_migrator` (§12.1.3 rule 9)"
                            .to_owned(),
                    ));
                }
            }
        }
    }
    out
}

/// OP-138, OP-55: an index built `CONCURRENTLY` cannot run inside a transaction, so its
/// migration starts with sqlx's `-- no-transaction` directive and holds nothing else that needs
/// one. `None` when `raw` (the file as written) is fine.
pub(crate) fn concurrently_finding(raw: &str) -> Option<String> {
    let code = strip_sql_comments(raw).to_ascii_uppercase();
    let concurrent = code
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .any(|w| w == "CONCURRENTLY");
    let detached = raw.lines().next().map(str::trim) == Some("-- no-transaction");
    (concurrent && !detached).then(|| {
        "`CONCURRENTLY` runs outside a transaction: start the migration with `-- no-transaction` (OP-138)"
            .to_owned()
    })
}

/// OP-55: migrations from this version on are checked for locking DDL on existing tables;
/// earlier ones are released and never edited.
pub(crate) const ONLINE_DDL_FROM: u64 = 20_261_108_000_000;

/// The version prefix of a migration file name (`20261108120000_name.sql`).
pub(crate) fn migration_version(file_name: &str) -> Option<u64> {
    let digits: String = file_name.chars().take_while(char::is_ascii_digit).collect();
    (digits.len() == 14).then(|| digits.parse().ok()).flatten()
}

/// Blanks single-quoted strings and dollar-quoted bodies, keeping byte offsets and newlines.
fn blank_sql_literals(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut out = bytes.to_vec();
    let mut i = 0_usize;
    let blank = |out: &mut Vec<u8>, from: usize, to: usize| {
        for b in out.iter_mut().take(to).skip(from) {
            if *b != b'\n' {
                *b = b' ';
            }
        }
    };
    while let Some(&b) = bytes.get(i) {
        if b == b'\'' {
            let mut j = i.saturating_add(1);
            while let Some(&c) = bytes.get(j) {
                if c == b'\'' {
                    if bytes.get(j.saturating_add(1)) == Some(&b'\'') {
                        j = j.saturating_add(2);
                        continue;
                    }
                    break;
                }
                j = j.saturating_add(1);
            }
            blank(&mut out, i, j.saturating_add(1).min(bytes.len()));
            i = j.saturating_add(1);
        } else if b == b'$' {
            let tag_end = bytes
                .get(i.saturating_add(1)..)
                .and_then(|rest| {
                    rest.iter()
                        .position(|c| !(c.is_ascii_alphanumeric() || *c == b'_'))
                })
                .map(|n| i.saturating_add(1).saturating_add(n));
            match tag_end {
                Some(e) if bytes.get(e) == Some(&b'$') => {
                    let tag = bytes.get(i..=e).unwrap_or_default();
                    let body = e.saturating_add(1);
                    let close = bytes
                        .get(body..)
                        .and_then(|rest| rest.windows(tag.len()).position(|w| w == tag))
                        .map_or(bytes.len(), |n| {
                            body.saturating_add(n).saturating_add(tag.len())
                        });
                    blank(&mut out, i, close);
                    i = close;
                }
                _ => i = i.saturating_add(1),
            }
        } else {
            i = i.saturating_add(1);
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Upper-case words of `sql` (identifiers keep `.` and `"`), with their byte offsets.
fn sql_words(sql: &str, base: usize) -> Vec<(usize, String)> {
    let mut words = Vec::new();
    let mut start = None;
    for (i, c) in sql.char_indices().chain(std::iter::once((sql.len(), ' '))) {
        let word_char = c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '"';
        match (word_char, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                words.push((
                    base.saturating_add(s),
                    sql.get(s..i).unwrap_or_default().to_ascii_uppercase(),
                ));
                start = None;
            }
            _ => {}
        }
    }
    words
}

fn word(ws: &[(usize, String)], k: usize) -> &str {
    ws.get(k).map_or("", |(_, w)| w.as_str())
}

fn bare_table(name: &str) -> String {
    name.rsplit('.')
        .next()
        .unwrap_or(name)
        .trim_matches('"')
        .to_owned()
}

/// Splits `text` at commas outside parentheses, with each part's offset in `text`.
fn top_level_clauses(text: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0_usize;
    for (i, c) in text.char_indices() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push((start, text.get(start..i).unwrap_or_default()));
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    out.push((start, text.get(start..).unwrap_or_default()));
    out
}

/// OP-55: in a migration on a live database, an index on an existing table is built
/// `CONCURRENTLY` (or `ON ONLY` a partitioned parent), and a `CHECK` or `FOREIGN KEY` added to
/// an existing table is `NOT VALID` and validated later. Tables the same file creates are empty
/// and exempt. `sql` is the migration without comments.
pub(crate) fn online_ddl_findings(sql: &str) -> Vec<(usize, String)> {
    let code = blank_sql_literals(sql);
    let mut statements = Vec::new();
    let mut start = 0_usize;
    for (i, c) in code
        .char_indices()
        .chain(std::iter::once((code.len(), ';')))
    {
        if c == ';' {
            let text = code.get(start..i).unwrap_or_default();
            statements.push((start, text, sql_words(text, start)));
            start = i.saturating_add(1);
        }
    }
    let mut created = Vec::new();
    for (_, _, ws) in &statements {
        if word(ws, 0) != "CREATE" {
            continue;
        }
        let Some(t) = ws.iter().position(|(_, w)| w == "TABLE") else {
            continue;
        };
        if ws.iter().take(t).any(|(_, w)| w == "INDEX") {
            continue;
        }
        let mut n = t.saturating_add(1);
        while matches!(word(ws, n), "IF" | "NOT" | "EXISTS") {
            n = n.saturating_add(1);
        }
        created.push(bare_table(word(ws, n)));
    }
    let existing = |name: &str| !created.iter().any(|c| *c == bare_table(name));
    let mut out = Vec::new();
    for (offset, text, ws) in &statements {
        let at = ws.first().map_or(*offset, |(a, _)| *a);
        let head = (word(ws, 0), word(ws, 1), word(ws, 2));
        let index = matches!(head, ("CREATE", "INDEX", _) | ("CREATE", "UNIQUE", "INDEX"));
        if index && !ws.iter().any(|(_, w)| w == "CONCURRENTLY") {
            let on = ws.iter().position(|(_, w)| w == "ON");
            let target = on.map(|k| (word(ws, k.saturating_add(1)), word(ws, k.saturating_add(2))));
            match target {
                Some(("ONLY", _)) => {}
                Some((table, _)) if existing(table) => out.push((
                    at,
                    format!(
                        "`CREATE INDEX` on existing table `{}` without `CONCURRENTLY` locks writes (OP-55)",
                        bare_table(table).to_ascii_lowercase()
                    ),
                )),
                _ => {}
            }
        }
        if head.0 == "ALTER" && head.1 == "TABLE" {
            let mut n = 2_usize;
            while matches!(word(ws, n), "IF" | "EXISTS" | "ONLY") {
                n = n.saturating_add(1);
            }
            let table = word(ws, n);
            let Some((name_at, _)) = ws.get(n) else {
                continue;
            };
            if !existing(table) {
                continue;
            }
            let rest_from = name_at.saturating_sub(*offset).saturating_add(table.len());
            let rest = text.get(rest_from..).unwrap_or_default();
            for (clause_at, clause) in top_level_clauses(rest) {
                let cw = sql_words(
                    clause,
                    offset.saturating_add(rest_from).saturating_add(clause_at),
                );
                if word(&cw, 0) != "ADD" {
                    continue;
                }
                let mut k = 1_usize;
                if word(&cw, k) == "CONSTRAINT" {
                    k = k.saturating_add(2);
                }
                let kind = word(&cw, k);
                if !matches!(kind, "CHECK" | "FOREIGN") {
                    continue;
                }
                let not_valid = cw
                    .windows(2)
                    .any(|p| matches!(p, [(_, a), (_, b)] if a == "NOT" && b == "VALID"));
                if !not_valid {
                    out.push((
                        cw.first().map_or(at, |(a, _)| *a),
                        format!(
                            "`ADD {}` on existing table `{}` without `NOT VALID` scans it under lock; add it `NOT VALID` and `VALIDATE CONSTRAINT` later (OP-55)",
                            if kind == "CHECK" { "CHECK" } else { "FOREIGN KEY" },
                            bare_table(table).to_ascii_lowercase()
                        ),
                    ));
                }
            }
        }
    }
    out
}

pub(crate) fn check_migrations(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path.starts_with("crates/store/migrations/") {
            if rel_path.ends_with(".down.sql") {
                out.push(violation(
                    MIGRATION,
                    &rel_path,
                    1,
                    "no down migrations; rollback is PITR (OP-55)".to_owned(),
                ));
            }
            if path.extension().and_then(|e| e.to_str()) == Some("sql") {
                let raw = read(&path)?;
                let sql = strip_sql_comments(&raw);
                for (at, msg) in migration_findings(&sql) {
                    out.push(violation(MIGRATION, &rel_path, line_at(&sql, at), msg));
                }
                if let Some(msg) = concurrently_finding(&raw) {
                    out.push(violation(MIGRATION, &rel_path, 1, msg));
                }
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                if migration_version(name).is_some_and(|v| v >= ONLINE_DDL_FROM) {
                    for (at, msg) in online_ddl_findings(&sql) {
                        out.push(violation(MIGRATION, &rel_path, line_at(&sql, at), msg));
                    }
                }
            }
        } else if rel_path.starts_with("crates/store/src/")
            && rel_path != "crates/store/src/testing.rs"
            && path.extension().and_then(|e| e.to_str()) == Some("rs")
        {
            let lexed = lex(&read(&path)?);
            for lit in &lexed.strings {
                if lit.text.to_ascii_uppercase().contains("SET ROLE")
                    || lit.text.to_ascii_uppercase().contains("LOCAL ROLE")
                {
                    out.push(violation(
                        MIGRATION,
                        &rel_path,
                        lit.line,
                        "tenants are never switched with SET ROLE (§12.1.3 rule 9)".to_owned(),
                    ));
                }
            }
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
/// the sandbox, the Kerberos gateway and the Linux client's NSS and PAM shells (OP-156 m.3 (p)).
pub(crate) const UNSAFE_ALLOWED: &[&str] = &[
    "crates/crypto",
    "crates/suiss-crypto",
    "crates/suiss-sandbox",
    "bins/access-gw-kerberos",
    "services/linux-client/nss",
    "services/linux-client/pam",
];

/// R-2: total `unsafe` lines in the allowlisted crates (OP-156 m.3 (p): 500 → 650).
pub(crate) const UNSAFE_LINE_BUDGET: usize = 650;

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

/// R-2: a file may hold `unsafe` only inside an allowlisted crate.
fn unsafe_allowed(rel_path: &str) -> bool {
    UNSAFE_ALLOWED
        .iter()
        .any(|d| rel_path.starts_with(&format!("{d}/")))
}

/// OP-3, OP-4: the request-path lints the workspace denies.
const REQUEST_PATH_LINTS: &[&str] = &[
    "unwrap_used",
    "expect_used",
    "indexing_slicing",
    "panic",
    "arithmetic_side_effects",
];

/// The request-path lints `[workspace.lints.clippy]` does not set to `deny`.
fn undenied_request_path_lints(root_manifest: &str) -> Vec<&'static str> {
    let clippy = root_manifest.parse::<toml::Table>().ok().and_then(|t| {
        t.get("workspace")?
            .get("lints")?
            .get("clippy")?
            .as_table()
            .cloned()
    });
    REQUEST_PATH_LINTS
        .iter()
        .copied()
        .filter(|lint| {
            let level = clippy.as_ref().and_then(|c| c.get(*lint));
            let level = level.and_then(|v| {
                v.as_str()
                    .or_else(|| v.get("level").and_then(toml::Value::as_str))
            });
            level != Some("deny")
        })
        .collect()
}

pub(crate) fn check_unsafe(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let root_manifest = read(&root.join("Cargo.toml"))?;
    for lint in undenied_request_path_lints(&root_manifest) {
        out.push(violation(
            UNSAFE,
            "Cargo.toml",
            1,
            format!("[workspace.lints.clippy] must set {lint} = \"deny\" (OP-3, OP-4)"),
        ));
    }
    let ws_forbids = workspace_forbids_unsafe(&root_manifest);
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
        let allowed = unsafe_allowed(&rel_path);
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
            false,
        );
        assert_eq!(f.len(), 3);
    }

    // OP-73
    #[test]
    fn column_schema_and_merge_deletes_are_rejected() {
        for bad in [
            "ALTER TABLE access.users DROP COLUMN email;",
            "ALTER TABLE IF EXISTS ONLY access.users DROP email;",
            "ALTER TABLE access.users ADD COLUMN x int, DROP COLUMN y;",
            "DROP SCHEMA access CASCADE;",
            "DROP DATABASE access;",
            "MERGE INTO a USING b ON a.id = b.id WHEN MATCHED THEN DELETE;",
        ] {
            assert_eq!(delete_findings(bad, &[], false).len(), 1, "{bad}");
        }
        for ok in [
            "ALTER TABLE access.users DROP CONSTRAINT users_email_key;",
            "ALTER TABLE access.users ALTER COLUMN email DROP NOT NULL;",
            "ALTER TABLE access.users ALTER COLUMN email DROP DEFAULT;",
            "MERGE INTO a USING b ON a.id = b.id WHEN MATCHED THEN UPDATE SET x = b.x;",
            "DROP INDEX access.users_email;",
        ] {
            assert_eq!(delete_findings(ok, &[], false), vec![], "{ok}");
        }
        assert_eq!(
            delete_findings("DROP DATABASE IF EXISTS access_t_1 WITH (FORCE)", &[], true),
            vec![]
        );
        assert_eq!(delete_findings("DROP SCHEMA x", &[], true).len(), 1);
    }

    #[test]
    fn allowlisted_job_queue_table_may_be_cleaned() {
        let allow = parse_list("# queue\njobs\n");
        assert_eq!(
            delete_findings("DELETE FROM public.\"jobs\" WHERE done", &allow, false),
            vec![]
        );
        assert_eq!(
            delete_findings("DELETE FROM accounts", &allow, false).len(),
            1
        );
    }

    // OP-11, OP-16, OP-19, §12.1.3
    #[test]
    fn migrations_keep_their_hygiene() {
        let ok = "SET LOCAL ROLE access_migrator;\nCREATE TABLE a (id uuid DEFAULT uuidv7());\nRESET ROLE;";
        assert_eq!(migration_findings(ok), vec![]);
        for bad in [
            "CREATE TABLE a (id uuid DEFAULT gen_random_uuid());",
            "CREATE UNLOGGED TABLE a (x int);",
            "NOTIFY changes;",
            "SET ROLE access_app;",
            "SET LOCAL ROLE access_app;",
            "SET SESSION ROLE postgres;",
        ] {
            assert_eq!(migration_findings(bad).len(), 1, "{bad}");
        }
    }

    // OP-138, OP-55
    #[test]
    fn concurrent_indexes_run_outside_a_transaction() {
        let detached = "-- no-transaction\nCREATE INDEX CONCURRENTLY a_x ON access.a (x);\n";
        assert_eq!(concurrently_finding(detached), None);
        let plain = "SET LOCAL ROLE access_migrator;\nCREATE INDEX a_x ON access.a (x);\n";
        assert_eq!(concurrently_finding(plain), None);
        let commented = "-- builds it CONCURRENTLY later\nCREATE INDEX a_x ON access.a (x);\n";
        assert_eq!(concurrently_finding(commented), None);
        let inside =
            "SET LOCAL ROLE access_migrator;\nCREATE INDEX CONCURRENTLY a_x ON access.a (x);\n";
        assert!(concurrently_finding(inside).is_some());
        let late = "-- OP-138\n-- no-transaction\nCREATE INDEX CONCURRENTLY a_x ON access.a (x);\n";
        assert!(concurrently_finding(late).is_some());
    }

    // OP-55
    #[test]
    fn locking_ddl_on_existing_tables_is_rejected() {
        for bad in [
            "CREATE INDEX a_x ON access.a (x);",
            "CREATE UNIQUE INDEX IF NOT EXISTS a_x ON access.a (x);",
            "ALTER TABLE access.a ADD CONSTRAINT a_x CHECK (x > 0);",
            "ALTER TABLE IF EXISTS ONLY access.a ADD CHECK (x > 0);",
            "ALTER TABLE access.a ADD CONSTRAINT a_b FOREIGN KEY (b) REFERENCES access.b (id);",
            "ALTER TABLE access.a ADD COLUMN y int, ADD CONSTRAINT a_y CHECK (y IN (1, 2));",
        ] {
            assert_eq!(online_ddl_findings(bad).len(), 1, "{bad}");
        }
        for ok in [
            "CREATE INDEX CONCURRENTLY a_x ON access.a (x);",
            "CREATE INDEX a_x ON ONLY access.a (x);",
            "CREATE TABLE access.a (x int);\nCREATE INDEX a_x ON access.a (x);\n\
             ALTER TABLE access.a ADD CONSTRAINT a_x CHECK (x > 0);",
            "CREATE TABLE IF NOT EXISTS access.a (x int);\nCREATE UNIQUE INDEX a_x ON a (x);",
            "ALTER TABLE access.a ADD CONSTRAINT a_x CHECK (x > 0) NOT VALID;",
            "ALTER TABLE access.a VALIDATE CONSTRAINT a_x;",
            "ALTER TABLE access.a ADD COLUMN y int;",
            "CREATE FUNCTION f() RETURNS void AS $$ CREATE INDEX a_x ON access.a (x); $$ LANGUAGE sql;",
            "COMMENT ON TABLE access.a IS 'CREATE INDEX a_x ON access.a (x)';",
        ] {
            assert_eq!(online_ddl_findings(ok), vec![], "{ok}");
        }
        assert_eq!(
            migration_version("20261108120000_m1_x.sql"),
            Some(20_261_108_120_000)
        );
        assert_eq!(migration_version("README.md"), None);
        assert!(migration_version("20261107230200_m1c_admin_jobs.sql") < Some(ONLINE_DDL_FROM));
    }

    // OP-17, OP-73
    #[test]
    fn truncate_trigger_events_are_not_statements() {
        let sql = "CREATE TRIGGER t BEFORE TRUNCATE ON a FOR EACH STATEMENT EXECUTE FUNCTION f();\n\
                   CREATE TRIGGER u AFTER UPDATE OR TRUNCATE ON a EXECUTE FUNCTION f();";
        assert_eq!(delete_findings(sql, &[], false), vec![]);
        assert_eq!(delete_findings("TRUNCATE a;", &[], false).len(), 1);
        assert_eq!(
            delete_findings("BEGIN; TRUNCATE TABLE a;", &[], false).len(),
            1
        );
    }

    #[test]
    fn sql_comments_do_not_count() {
        let sql = strip_sql_comments("-- DELETE FROM a\n/* TRUNCATE b */ SELECT 1;");
        assert_eq!(delete_findings(&sql, &[], false), vec![]);
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

    // OP-3-G1, R-2
    #[test]
    fn unsafe_is_allowed_only_in_the_allowlisted_crates() {
        assert!(unsafe_allowed("crates/crypto/src/aws.rs"));
        assert!(unsafe_allowed("crates/suiss-sandbox/src/linux/mod.rs"));
        assert!(!unsafe_allowed("crates/kernel/src/lib.rs"));
        assert!(!unsafe_allowed("crates/crypto-extra/src/lib.rs"));
        assert!(!unsafe_allowed("crates/crypto"));
    }

    // OP-3-G2, OP-1
    #[test]
    fn pure_code_names_no_async_runtime_database_or_http_client() {
        for src in [
            "async fn f() {}",
            "fn f() { tokio::spawn(g()); }",
            "fn f() { sqlx::query(\"q\"); }",
            "fn f() { reqwest::get(\"u\"); }",
        ] {
            for path in [
                "crates/kernel/src/a.rs",
                "crates/authority-core/src/domain/a.rs",
            ] {
                assert!(!purity_violations(path, src).is_empty(), "{path}: {src}");
            }
        }
    }

    // OP-3-G6, OP-4, R-3
    #[test]
    fn the_workspace_denies_the_request_path_lints() {
        let all = "[workspace.lints.clippy]\nunwrap_used = \"deny\"\nexpect_used = \"deny\"\nindexing_slicing = \"deny\"\npanic = { level = \"deny\" }\narithmetic_side_effects = \"deny\"\n";
        assert_eq!(undenied_request_path_lints(all), Vec::<&str>::new());
        let warned = all.replace("panic = { level = \"deny\" }", "panic = \"warn\"");
        assert_eq!(undenied_request_path_lints(&warned), ["panic"]);
        assert_eq!(
            undenied_request_path_lints("[workspace]\n").len(),
            REQUEST_PATH_LINTS.len()
        );
    }
}

const SECRET_COMPARE: &str = "secret-compare";

/// CR-39 m.2: secrets are compared only with `ct_eq`; `*_vartime` functions never take a secret.
pub(crate) fn secret_compare_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let Lexed { code, .. } = lex(src);
    let mut out = Vec::new();
    for (i, line) in code.lines().enumerate() {
        let n = i.saturating_add(1);
        let exposed = line.contains(".expose()");
        if exposed
            && (line.contains("==")
                || line.contains("!=")
                || line.contains(".eq(")
                || line.contains(".cmp("))
        {
            out.push(violation(
                SECRET_COMPARE,
                rel_path,
                n,
                "an exposed secret is compared with ==, !=, eq or cmp; use ct_eq (CR-39 m.2)"
                    .to_owned(),
            ));
        }
        if let Some(pos) = line.find("_vartime(")
            && line.get(..pos).is_some_and(|head| head.contains("fn "))
            && line.get(pos..).is_some_and(|tail| tail.contains("Secret"))
        {
            out.push(violation(
                SECRET_COMPARE,
                rel_path,
                n,
                "a *_vartime function takes a Secret (CR-39 m.2)".to_owned(),
            ));
        }
    }
    out
}

pub(crate) fn check_secret_compare(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for (rel_path, path) in rust_files(root)? {
        if !is_test_file(&rel_path) && !rel_path.starts_with("xtask/") {
            out.extend(secret_compare_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod secret_compare_tests {
    use super::*;

    // CR-39 m.2
    #[test]
    fn comparing_an_exposed_secret_is_rejected() {
        // GHSA-53hj-r94p-8c8f
        let bad = "fn f(s: &Secret<[u8; 32]>, t: &[u8]) -> bool { s.expose() == t }\n";
        assert_eq!(
            secret_compare_violations("crates/x/src/lib.rs", bad).len(),
            1
        );
        let bad = "fn f(s: &Secret<[u8; 32]>, t: &[u8; 32]) -> bool { s.expose().eq(t) }\n";
        assert_eq!(
            secret_compare_violations("crates/x/src/lib.rs", bad).len(),
            1
        );
        let ok = "fn f(s: &Secret<[u8; 32]>, t: &[u8]) -> bool { s.ct_eq_bytes(t) }\n";
        assert!(secret_compare_violations("crates/x/src/lib.rs", ok).is_empty());
        let in_comment = "// s.expose() == t\nfn f() {}\n";
        assert!(secret_compare_violations("crates/x/src/lib.rs", in_comment).is_empty());
    }

    // CR-39 m.2
    #[test]
    fn vartime_functions_never_take_secrets() {
        let bad = "pub fn lookup_vartime(key: &Secret<[u8; 32]>) -> usize { 0 }\n";
        assert_eq!(
            secret_compare_violations("crates/x/src/lib.rs", bad).len(),
            1
        );
        let ok = "pub fn lookup_vartime(index: u32) -> usize { 0 }\n";
        assert!(secret_compare_violations("crates/x/src/lib.rs", ok).is_empty());
    }
}
