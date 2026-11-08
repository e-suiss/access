//! `personal-data` (OP-153 m.1 (c), m.3 (aa), OP-40, OP-74): every personal column is in
//! `conformance/catalog/personal-data.toml` with its vault class, Ek C retention class, legal
//! basis, portability and export flags. A migration from the PII vault on tags each personal
//! column with `-- pii:<vault>` on the line before it; the tag must match the catalog, every
//! catalog column must exist, and a column whose name says it is personal stops the merge
//! unless it is tagged.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "personal-data";

/// The catalog.
pub(crate) const CATALOG: &str = "conformance/catalog/personal-data.toml";

/// Where the Ek C class names live (`suiss_retention::Class`).
const CLASSES: &str = "crates/suiss-retention/src/class.rs";

/// Migrations from this version on carry `-- pii:` tags (the PII vault, OP-153 m.3 (aa)).
pub(crate) const TAGGED_FROM: u64 = 20_261_114_070_000;

/// Vault classes (OP-153 m.3 (aa)); `none` marks an unsealed pseudonym, index or code.
const VAULTS: &[&str] = &[
    "profile",
    "contact",
    "credential",
    "security_history",
    "none",
];

/// Column name parts that say a column holds personal data.
const PERSONAL: &[&str] = &[
    "email",
    "phone",
    "birth",
    "given_name",
    "family_name",
    "postal",
    "street",
    "national_id",
    "ip_address",
    "user_agent",
    "ciphertext",
    "granted",
    "document_digest",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Field {
    column: String,
    vault: String,
    retention: String,
    basis: String,
    portable: String,
    export: bool,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    #[serde(default)]
    field: Vec<Field>,
}

fn violation(path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(format!("{path}:{line}")),
        message,
    }
}

/// The Ek C class names `class.rs` maps its variants to.
pub(crate) fn class_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|l| {
            let (_, rest) = l.split_once("=> \"")?;
            let (name, _) = rest.split_once('"')?;
            Some(name.to_owned())
        })
        .collect()
}

/// A column of a migration: its table, name, line, and the `-- pii:` tag on the line before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Column {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) line: usize,
    pub(crate) tag: Option<String>,
}

fn is_ident(w: &str) -> bool {
    !w.is_empty()
        && w.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// The columns a migration creates or adds, with their tags.
pub(crate) fn columns(sql: &str) -> Vec<Column> {
    let mut out = Vec::new();
    let mut table: Option<String> = None;
    let mut tag: Option<String> = None;
    for (i, raw) in sql.lines().enumerate() {
        let line = raw.trim();
        if let Some(t) = line.strip_prefix("-- pii:") {
            tag = Some(t.trim().to_owned());
            continue;
        }
        if line.starts_with("--") || line.is_empty() {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        let mut head = upper.split_whitespace();
        let opens = matches!(
            (head.next(), head.next()),
            (Some("CREATE" | "ALTER"), Some("TABLE"))
        );
        if opens {
            let rest = upper
                .split_whitespace()
                .skip(2)
                .collect::<Vec<_>>()
                .join(" ");
            let name = rest
                .trim_start_matches("IF NOT EXISTS ")
                .split(|c: char| c.is_whitespace() || c == '(')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            table = (!line.ends_with(';')).then_some(name);
            tag = None;
            continue;
        }
        if line.starts_with(')') {
            table = None;
            tag = None;
            continue;
        }
        if let Some(t) = table.clone() {
            push_column(&mut out, &t, line, i, tag.take());
        }
        tag = None;
        if line.ends_with(';') {
            table = None;
        }
    }
    out
}

fn push_column(out: &mut Vec<Column>, table: &str, line: &str, i: usize, tag: Option<String>) {
    let body = line.strip_prefix("ADD COLUMN ").unwrap_or(line);
    let mut words = body.split_whitespace();
    let (Some(name), Some(kind)) = (words.next(), words.next()) else {
        return;
    };
    let keyword = matches!(
        name.to_ascii_uppercase().as_str(),
        "PRIMARY" | "FOREIGN" | "CHECK" | "UNIQUE" | "CONSTRAINT" | "ALTER" | "ADD" | "OR"
    );
    if keyword || !is_ident(name) || kind.starts_with('(') {
        return;
    }
    out.push(Column {
        table: table.to_owned(),
        name: name.to_owned(),
        line: i.saturating_add(1),
        tag,
    });
}

/// Whether a column name says it holds personal data.
pub(crate) fn personal_name(name: &str) -> bool {
    PERSONAL.iter().any(|p| name.contains(p))
}

fn migration_version(file_name: &str) -> Option<u64> {
    let digits: String = file_name.chars().take_while(char::is_ascii_digit).collect();
    (digits.len() == 14).then(|| digits.parse().ok()).flatten()
}

/// The check.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read(&root.join(CATALOG))?;
    let catalog: Catalog = toml::from_str(&text).map_err(|e| format!("{CATALOG}: {e}"))?;
    let classes = class_names(&read(&root.join(CLASSES))?);
    let mut out = Vec::new();
    let mut listed: BTreeMap<String, String> = BTreeMap::new();
    for f in &catalog.field {
        let bad = if !VAULTS.contains(&f.vault.as_str()) {
            Some(format!("unknown vault class `{}`", f.vault))
        } else if !classes.contains(&f.retention) {
            Some(format!("`{}` is not an Ek C class", f.retention))
        } else if !matches!(f.portable.as_str(), "observed" | "derived") {
            Some("portable is `observed` or `derived` (OP-43)".to_owned())
        } else if f.portable == "derived" && f.export {
            Some("derived data is not in the person export (OP-43)".to_owned())
        } else if f.vault == "credential" && f.export {
            Some("secret material is never exported (TN-79)".to_owned())
        } else if f.basis.trim().is_empty() || f.note.as_ref().is_some_and(|n| n.trim().is_empty())
        {
            Some("a legal basis label is required".to_owned())
        } else {
            None
        };
        if let Some(msg) = bad {
            out.push(violation(CATALOG, 1, format!("{}: {msg}", f.column)));
        }
        if listed.insert(f.column.clone(), f.vault.clone()).is_some() {
            out.push(violation(CATALOG, 1, format!("{}: listed twice", f.column)));
        }
    }
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if !rel_path.starts_with("crates/store/migrations/")
            || path.extension().and_then(|e| e.to_str()) != Some("sql")
        {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let tagged = migration_version(name).is_some_and(|v| v >= TAGGED_FROM);
        for c in columns(&read(&path)?) {
            let full = format!("{}.{}", c.table, c.name);
            seen.insert(full.clone());
            if !tagged {
                continue;
            }
            match (&c.tag, listed.get(&full)) {
                (Some(tag), Some(vault)) if tag == vault => {}
                (Some(tag), Some(vault)) => out.push(violation(
                    &rel_path,
                    c.line,
                    format!("`{full}` is tagged `pii:{tag}`, the catalog says `{vault}`"),
                )),
                (Some(tag), None) => out.push(violation(
                    &rel_path,
                    c.line,
                    format!("`{full}` is tagged `pii:{tag}` but missing from {CATALOG}"),
                )),
                (None, Some(_)) => out.push(violation(
                    &rel_path,
                    c.line,
                    format!("`{full}` is in {CATALOG}: tag it `-- pii:<vault>`"),
                )),
                (None, None) if personal_name(&c.name) => out.push(violation(
                    &rel_path,
                    c.line,
                    format!(
                        "`{full}` looks personal: tag it `-- pii:<vault>` and list it in {CATALOG}"
                    ),
                )),
                (None, None) => {}
            }
        }
    }
    for column in listed.keys() {
        if !seen.contains(column) {
            out.push(violation(
                CATALOG,
                1,
                format!("{column}: no migration defines this column"),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-153 m.1 (c)
    #[test]
    fn columns_carry_their_tags() {
        let sql = concat!(
            "CREATE",
            " TABLE access.t (\n  a uuid NOT NULL,\n  -- pii:contact\n  email_ct bytea,\n  CHECK (a IS NOT NULL),\n  PRIMARY KEY (a)\n);\n",
            "ALTER",
            " TABLE access.u\n  ADD COLUMN given_name text,\n  -- pii:profile\n  ADD COLUMN birth bytea;\n"
        );
        let c = columns(sql);
        assert_eq!(
            c.iter()
                .map(|c| (c.table.as_str(), c.name.as_str(), c.tag.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("access.t", "a", None),
                ("access.t", "email_ct", Some("contact")),
                ("access.u", "given_name", None),
                ("access.u", "birth", Some("profile")),
            ]
        );
        assert!(personal_name("given_name") && !personal_name("subject_id"));
    }

    // OP-153 m.1 (c)
    #[test]
    fn class_names_come_from_the_retention_crate() {
        let names =
            class_names("            Self::Profile => \"profile\",\n Self::Audit => \"audit\",");
        assert_eq!(names, vec!["profile".to_owned(), "audit".to_owned()]);
    }
}
