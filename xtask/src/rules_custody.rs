//! `no-custody-key` (OP-150 m.3 (e), SEC17, SEC19, SI-13, CR-31): Access has no custodial signing
//! mode; Instance keys are self-held (OP-149 m.16). No key label, seal context, configuration key
//! or code path may name a custody key until a custody signer is decided. Identifiers and string
//! literals of non-test Rust code, deployment configuration and scripts, and SQL migrations are
//! scanned; `non_custodial` (the assurance flag) is the one accepted use.
//!
//! OP-78, E59, Ek B 4631: nothing keeps a copy of a user-keyed DEK or KEK the operator could
//! open. No identifier, literal or configuration key names key escrow, and the content-free
//! records of user-keyed data (One's cloud key permissions) have no column for key material.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};
use crate::rules::switches::words;

const RULE: &str = "no-custody-key";

const WHY: &str = "no custodial key mode exists (OP-150 (e), SEC17, SEC19)";

/// The rule spells out the vocabulary it forbids.
const SELF_PATH: &str = "xtask/src/rules_custody.rs";

/// Reviewed exceptions: (relative path, reason). Each entry needs Adem's review.
const ALLOWLIST: &[(&str, &str)] = &[(
    "crates/http/src/declarations.rs",
    "the provider declaration that no custodial key exists (SI-13, OP-150 (e))",
)];

const DEPLOY_EXTENSIONS: &[&str] = &["toml", "yml", "yaml", "json", "sh", "conf", "env"];

/// The custody or escrow word in an atom, unless it is the `non_custodial` assurance flag.
pub(crate) fn custody_word(atom: &str) -> Option<String> {
    let w = words(atom);
    w.iter().enumerate().find_map(|(i, word)| {
        let non = i
            .checked_sub(1)
            .and_then(|p| w.get(p))
            .is_some_and(|p| p == "non");
        let hit = (word.starts_with("custod") && !(non && word == "custodial"))
            || word.starts_with("escrow");
        hit.then(|| word.clone())
    })
}

/// The statement that opens a table.
const CREATE: &str = concat!("CREATE", " TABLE ");

/// The tables that record user-keyed data without its content (E59 (2), OP-78).
const CONTENT_FREE_TABLES: &[&str] = &["access.cloud_key_"];

/// Column name words that would hold key material.
const KEY_MATERIAL: &[&str] = &["dek", "kek", "wrapped", "plaintext", "secret", "private"];

/// Columns of a content-free table whose names say they hold key material (Ek B 4631).
pub(crate) fn content_free_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut table: Option<String> = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(CREATE) {
            let name = rest.split_whitespace().next().unwrap_or_default();
            table = CONTENT_FREE_TABLES
                .iter()
                .any(|t| name.starts_with(t))
                .then(|| name.to_owned());
            continue;
        }
        if trimmed.starts_with(");") {
            table = None;
            continue;
        }
        let (Some(t), Some(column)) = (&table, trimmed.split_whitespace().next()) else {
            continue;
        };
        if column.starts_with("--") || column.chars().any(|c| c.is_ascii_uppercase()) {
            continue;
        }
        if let Some(w) = column.split('_').find(|w| KEY_MATERIAL.contains(w)) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{}", i.saturating_add(1))),
                message: format!(
                    "`{t}.{column}` (`{w}`): a content-free record of user-keyed data holds no key material (OP-78, E59)"
                ),
            });
        }
    }
    out
}

fn violation(rel_path: &str, line: usize, word: &str) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(format!("{rel_path}:{line}")),
        message: format!("`{word}`: {WHY}"),
    }
}

/// Custody words in a Rust file's non-test identifiers and string literals.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut atoms: Vec<(usize, String)> = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        for ident in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !ident.is_empty() {
                atoms.push((i.saturating_add(1), ident.to_owned()));
            }
        }
    }
    atoms.extend(lexed.strings.iter().map(|l| (l.line, l.text.clone())));
    atoms
        .into_iter()
        .filter(|(line, _)| !in_regions(&tests, *line))
        .filter_map(|(line, atom)| custody_word(&atom).map(|w| violation(rel_path, line, &w)))
        .collect()
}

/// Custody words in a configuration file, script or migration; `#` and `--` comments are
/// skipped.
pub(crate) fn text_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("--") {
            continue;
        }
        for atom in line
            .split(|c: char| c.is_whitespace() || "\"'=:,;[]{}()".contains(c))
            .filter(|a| !a.is_empty())
        {
            if let Some(w) = custody_word(atom) {
                out.push(violation(rel_path, i.saturating_add(1), &w));
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path == SELF_PATH || ALLOWLIST.iter().any(|(p, _)| *p == rel_path) {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let rust = ext == "rs" && !is_test_file(&rel_path) && !rel_path.starts_with("xtask/");
        let deploy = rel_path.starts_with("deploy/") && DEPLOY_EXTENSIONS.contains(&ext);
        let migration = (rel_path.starts_with("crates/store/migrations/")
            || (rel_path.starts_with("services/") && rel_path.contains("/migrations/")))
            && ext == "sql";
        if rust {
            out.extend(rust_violations(&rel_path, &read(&path)?));
        } else if deploy || migration {
            let text = read(&path)?;
            out.extend(text_violations(&rel_path, &text));
            if migration {
                out.extend(content_free_violations(&rel_path, &text));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-150, SEC17, SEC19, SI-13, CR-31
    // U14, U15
    #[test]
    fn custody_keys_are_refused() {
        for atom in [
            "access/identity/custody-kek",
            "CustodySigner",
            "custodian_key",
            "custodial",
            "CUSTODY_SIGNER_SOCKET",
        ] {
            assert!(custody_word(atom).is_some(), "{atom}");
        }
        assert_eq!(
            rust_violations("a.rs", "const L: &[u8] = b\"access/custody/seal\";").len(),
            1
        );
        assert_eq!(
            text_violations("deploy/a.toml", "[custody]\nkek = \"x\"\n").len(),
            1
        );
    }

    // OP-78, E59, Ek B 4631
    #[test]
    fn no_key_escrow_and_no_key_column_in_a_content_free_record() {
        for atom in ["KeyEscrow", "escrow_kek", "access/one/escrowed-dek"] {
            assert!(custody_word(atom).is_some(), "{atom}");
        }
        let sql = format!(
            "{CREATE}access.cloud_key_permissions (\n  tenant_id uuid NOT NULL,\n  job_key bytea NOT NULL,\n  wrapped_dek bytea,\n  PRIMARY KEY (tenant_id)\n);\n{CREATE}access.other (\n  wrapped_dek bytea\n);\n"
        );
        let v = content_free_violations("crates/store/migrations/x.sql", &sql);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].message.contains("wrapped_dek"));
    }

    // OP-150, SEC17
    #[test]
    fn the_non_custodial_flag_is_accepted() {
        for atom in ["non_custodial", "nonCustodial", "custom", "kek"] {
            assert!(custody_word(atom).is_none(), "{atom}");
        }
        let src = "// no custody signer\nconst F: &str = \"non_custodial\";\n#[cfg(test)]\nmod tests { fn custody_is_absent() {} }\n";
        assert!(rust_violations("a.rs", src).is_empty());
        assert!(text_violations("deploy/a.sh", "# no custody key\n").is_empty());
    }
}
