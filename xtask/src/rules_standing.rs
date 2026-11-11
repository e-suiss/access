//! `no-standing-admin` (OP-46, OP-54-RL10, OP-157 m.3 (j), Ek B 5654): there is no standing
//! emergency administrator in the database. Migrations, bootstrap SQL, seeds and deploy scripts
//! create no role that is a superuser, creates roles, bypasses row security or replicates, set no
//! literal password and seed no password hash; the server has no "emergency admin" path.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "no-standing-admin";

/// Role attributes a standing administrator would hold.
fn powers() -> [String; 4] {
    [
        String::from("SUPERUSER"),
        String::from("CREATEROLE"),
        ["BY", "PASSRLS"].concat(),
        String::from("REPLICATION"),
    ]
}

/// Names of an emergency administrator path in code.
const PATHS: [&str; 5] = [
    "emergency admin",
    "emergency_admin",
    "emergency-admin",
    "superadmin",
    "standing admin",
];

fn ext(p: &str) -> &str {
    Path::new(p)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
}

fn sql_scope(p: &str) -> bool {
    matches!(ext(p), "sql" | "sh")
        && (p.starts_with("crates/store/migrations/")
            || p.starts_with("crates/store/bootstrap/")
            || (p.starts_with("services/") && p.contains("/migrations/"))
            || p.starts_with("deploy/"))
}

fn code_scope(p: &str) -> bool {
    ext(p) == "rs" && (p.starts_with("bins/access-server/") || p.starts_with("crates/"))
}

fn word(text: &str, at: usize, len: usize) -> bool {
    let b = text.as_bytes();
    let before = at.checked_sub(1).and_then(|i| b.get(i)).copied();
    let after = b.get(at.saturating_add(len)).copied();
    let edge = |c: Option<u8>| c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == b'_'));
    edge(before) && edge(after)
}

/// The violations of one SQL or shell file.
pub(crate) fn check_sql(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let body: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("--") && !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let upper = body.to_ascii_uppercase();
    for stmt in upper.split(';') {
        if !(stmt.contains("CREATE ROLE")
            || stmt.contains("ALTER ROLE")
            || stmt.contains("CREATE USER"))
        {
            continue;
        }
        for power in powers() {
            let power = power.as_str();
            let mut from = 0;
            while let Some(i) = stmt.get(from..).and_then(|s| s.find(power)) {
                let at = from.saturating_add(i);
                if word(stmt, at, power.len()) {
                    out.push(format!(
                        "a role is granted {power}: no standing administrator (OP-54-RL10)"
                    ));
                }
                from = at.saturating_add(power.len());
            }
        }
        if stmt.contains("PASSWORD '") {
            out.push(String::from(
                "a role gets a literal password: no standing administrator (OP-54-RL10)",
            ));
        }
    }
    let seeded = upper.split(';').any(|stmt| {
        (stmt.contains("INSERT") || stmt.contains("COPY "))
            && (stmt.contains("$ARGON2") || stmt.contains("CRYPT("))
    });
    if seeded {
        out.push(String::from(
            "a password hash is seeded: no standing administrator (OP-54-RL10)",
        ));
    }
    out
}

/// The violations of one source file.
pub(crate) fn check_code(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    PATHS
        .iter()
        .filter(|p| lower.contains(*p))
        .map(|p| format!("`{p}`: there is no emergency administrator path (OP-46)"))
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        let found = if sql_scope(&r) {
            check_sql(&read(&path)?)
        } else if code_scope(&r) {
            check_code(&read(&path)?)
        } else {
            continue;
        };
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

    // OP-54-RL10, OP-46
    #[test]
    fn op_54_rl10_a_standing_admin_is_refused() {
        assert_eq!(
            check_sql(
                "CREATE ROLE a LOGIN NOSUPERUSER NOCREATEROLE NOBYPASSRLS NOREPLICATION PASSWORD :'p';"
            ),
            Vec::<String>::new()
        );
        assert_eq!(
            check_sql("-- SUPERUSER in a comment\nALTER ROLE a PASSWORD NULL;"),
            Vec::<String>::new()
        );
        assert_eq!(check_sql("CREATE ROLE root LOGIN SUPERUSER;").len(), 1);
        assert_eq!(check_sql("ALTER ROLE a BYPASSRLS CREATEROLE;").len(), 2);
        assert_eq!(check_sql("CREATE USER x PASSWORD 'hunter2';").len(), 1);
        assert_eq!(
            check_sql(&format!("{} INTO t VALUES ('$argon2id$v=19$x');", "INSERT")).len(),
            1
        );
        assert_eq!(check_code("fn emergency_admin_login() {}").len(), 1);
        assert_eq!(
            check_code("fn break_glass_grant() {}"),
            Vec::<String>::new()
        );
    }
}
