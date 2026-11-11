//! `conformance-profiles` (§9.1 L3, P2, OP-157 m.3 (s)): every profile under `conformance/profiles/` names only vector traces, PEP cases and CDDL files that exist.
//!
//! Each of the eight roles has exactly one profile, in the shape of
//! `conformance/cddl/conformance-profile.cddl`, named after its role.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::Violation;

/// Where the profiles live.
pub(crate) const DIR: &str = "conformance/profiles";

/// The eight roles (OP-157 m.3 (s)).
pub(crate) const ROLES: [&str; 8] = [
    "provider",
    "decision-pep",
    "offline-verifier",
    "approval-surface",
    "claim-issuer",
    "schema-publisher",
    "coordinator",
    "event-receiver",
];

const KEYS: [&str; 8] = [
    "v",
    "profile",
    "title",
    "shared_with",
    "vectors",
    "pep_cases",
    "cddl",
    "metadata_signature",
];

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: "conformance-profiles",
        path: PathBuf::from(path),
        message,
    }
}

fn texts(t: &toml::Table, key: &str) -> Option<Vec<String>> {
    t.get(key)?
        .as_array()?
        .iter()
        .map(|x| x.as_str().map(str::to_owned))
        .collect()
}

fn word(s: &str, first: fn(u8) -> bool, rest: fn(u8) -> bool, max: usize) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= max
        && b.first().is_some_and(|c| first(*c))
        && b.iter().all(|c| rest(*c))
}

fn lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}

fn name_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'_'
}

/// A `track/version` that has at least one vector file.
fn vector_exists(root: &Path, named: &str) -> bool {
    let Some((track, version)) = named.split_once('/') else {
        return false;
    };
    let shaped = word(track, lower, name_char, 63)
        && !version.is_empty()
        && version.len() <= 3
        && version.bytes().all(|c| c.is_ascii_digit());
    shaped
        && std::fs::read_dir(root.join("conformance/vectors").join(track).join(version)).is_ok_and(
            |mut it| it.any(|e| e.is_ok_and(|e| e.path().extension().is_some_and(|x| x == "json"))),
        )
}

/// Whether the `key` list's `item` names something in the repository.
fn exists(root: &Path, key: &str, item: &str) -> bool {
    match key {
        "vectors" => vector_exists(root, item),
        "pep_cases" => {
            word(item, |c| lower(c) || c.is_ascii_digit(), name_char, 128)
                && root
                    .join("conformance/pep/cases")
                    .join(format!("{item}.json"))
                    .is_file()
        }
        _ => {
            item.strip_suffix(".cddl").is_some_and(|n| {
                word(
                    n,
                    lower,
                    |c| lower(c) || c.is_ascii_digit() || c == b'-',
                    63,
                )
            }) && root.join("conformance/cddl").join(item).is_file()
        }
    }
}

/// The violations of one profile file.
pub(crate) fn profile(root: &Path, rel: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    let t: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => return vec![v(rel, format!("not TOML: {e}"))],
    };
    for k in t.keys() {
        if !KEYS.contains(&k.as_str()) {
            out.push(v(rel, format!("unknown key `{k}`")));
        }
    }
    if t.get("v").and_then(toml::Value::as_integer) != Some(1) {
        out.push(v(rel, String::from("`v` must be 1")));
    }
    let stem = Path::new(rel)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match t.get("profile").and_then(toml::Value::as_str) {
        Some(p) if ROLES.contains(&p) && p == stem => {}
        Some(p) => out.push(v(
            rel,
            format!("profile `{p}` must be one of the eight roles and match the file name"),
        )),
        None => out.push(v(rel, String::from("`profile` is missing"))),
    }
    match t.get("title").and_then(toml::Value::as_str) {
        Some(s) if (1..=128).contains(&s.len()) => {}
        _ => out.push(v(rel, String::from("`title` must be 1 to 128 bytes"))),
    }
    if let Some(products) = t.get("shared_with") {
        let ok = texts(&t, "shared_with").is_some_and(|ps| {
            !ps.is_empty()
                && ps.iter().all(|p| {
                    word(
                        p,
                        lower,
                        |c| lower(c) || c.is_ascii_digit() || c == b'-',
                        32,
                    )
                })
        });
        if !ok || !products.is_array() {
            out.push(v(rel, String::from("`shared_with` names other products")));
        }
    }
    if t.get("metadata_signature").is_some_and(|m| !m.is_bool()) {
        out.push(v(rel, String::from("`metadata_signature` is a boolean")));
    }
    for key in ["vectors", "pep_cases", "cddl"] {
        let Some(items) = texts(&t, key) else {
            out.push(v(rel, format!("`{key}` must be a list of names")));
            continue;
        };
        let mut seen = BTreeSet::new();
        for item in items {
            if !seen.insert(item.clone()) {
                out.push(v(rel, format!("`{key}` names `{item}` twice")));
            } else if !exists(root, key, &item) {
                out.push(v(
                    rel,
                    format!("`{key}` names `{item}`, which does not exist"),
                ));
            }
        }
    }
    out
}

/// Runs `conformance-profiles`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let dir = root.join(DIR);
    let mut out = Vec::new();
    let mut found = BTreeSet::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{DIR}: {e}"))?;
    let mut files: Vec<PathBuf> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
    files.sort();
    for path in files {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        let rel = format!("{DIR}/{name}");
        let Some(stem) = name.strip_suffix(".toml") else {
            out.push(v(&rel, String::from("only profile files belong here")));
            continue;
        };
        found.insert(stem.to_owned());
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))?;
        out.extend(profile(root, &rel, &text));
    }
    for role in ROLES {
        if !found.contains(role) {
            out.push(v(DIR, format!("no profile for `{role}`")));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
    }

    // P2, OP-157 m.3 (s), Ek B 5671
    #[test]
    fn the_repository_profiles_pass() {
        assert!(check(&root()).unwrap().is_empty());
    }

    // P2, OP-157 m.3 (s), Ek B 5671
    #[test]
    fn a_profile_that_names_a_missing_trace_fails() {
        let text = "v = 1\nprofile = \"coordinator\"\ntitle = \"Coordinator\"\nvectors = [\"core/9\", \"core/1\", \"core/1\"]\npep_cases = [\"no-such-case\"]\ncddl = [\"nothing.cddl\"]\nendorsed = true\n";
        let found = profile(&root(), "conformance/profiles/coordinator.toml", text);
        let messages: Vec<&str> = found.iter().map(|f| f.message.as_str()).collect();
        assert!(
            messages.iter().any(|m| m.contains("`core/9`")),
            "{messages:?}"
        );
        assert!(messages.iter().any(|m| m.contains("twice")), "{messages:?}");
        assert!(
            messages.iter().any(|m| m.contains("no-such-case")),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("nothing.cddl")),
            "{messages:?}"
        );
        assert!(
            messages.iter().any(|m| m.contains("endorsed")),
            "{messages:?}"
        );
        let wrong = "v = 1\nprofile = \"provider\"\ntitle = \"P\"\nvectors = []\npep_cases = []\ncddl = []\n";
        assert_eq!(
            profile(&root(), "conformance/profiles/coordinator.toml", wrong).len(),
            1
        );
    }
}
