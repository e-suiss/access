//! `witness-independence` (SI-12, B13, OP-158 m.3 (d)): independence is derived, never declared.
//! - No non-test code outside the Kernel's model sets `independent: true`; a witness is
//!   independent only when its operator is not the provider's (`same_operator`).
//! - A server configuration that declares witnesses names the provider operator, at least two
//!   witnesses, and at least one whose operator is not the provider's: Suiss does not count as an
//!   independent witness for a domain it hosts (Ek B 6082).

use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, test_regions};

const RULE: &str = "witness-independence";

fn code(rel_path: &str) -> bool {
    (rel_path.starts_with("crates/") || rel_path.starts_with("bins/"))
        && !rel_path.starts_with("crates/kernel/")
        && Path::new(rel_path).extension().is_some_and(|e| e == "rs")
}

fn same(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The violations of one server configuration's `[transparency]` table.
fn config(text: &str) -> Vec<String> {
    let Ok(doc) = text.parse::<toml::Table>() else {
        return Vec::new();
    };
    let Some(t) = doc.get("transparency").and_then(toml::Value::as_table) else {
        return Vec::new();
    };
    let witnesses = t
        .get("witnesses")
        .and_then(toml::Value::as_array)
        .cloned()
        .unwrap_or_default();
    if witnesses.is_empty() {
        return Vec::new();
    }
    let Some(provider) = t.get("operator").and_then(toml::Value::as_str) else {
        return vec!["witnesses without the provider `operator` (SI-12)".into()];
    };
    let mut out = Vec::new();
    if witnesses.len() < 2 {
        out.push("fewer than two witnesses: equivocation cannot be compared (U9, HL-7)".into());
    }
    let independent = witnesses.iter().any(|w| {
        w.get("operator")
            .and_then(toml::Value::as_str)
            .is_some_and(|o| !same(o, provider))
    });
    if !independent {
        out.push(format!(
            "no witness outside `{provider}`: its own witnesses are not independent (SI-12, B13)"
        ));
    }
    out
}

/// Runs `witness-independence`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        let toml_file = Path::new(&r)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("toml"));
        if toml_file && !r.starts_with("conformance/") && !r.contains("Cargo.toml") {
            for message in config(&read(&path)?) {
                out.push(Violation {
                    rule: RULE,
                    path: path.clone(),
                    message,
                });
            }
            continue;
        }
        if !code(&r) || is_test_file(&r) {
            continue;
        }
        let text = read(&path)?;
        let tests = test_regions(&text);
        for (i, line) in text.lines().enumerate() {
            let n = i.saturating_add(1);
            if line.contains("independent: true") && !in_regions(&tests, n) {
                out.push(Violation {
                    rule: RULE,
                    path: path.clone(),
                    message: format!(
                        "line {n}: independence is derived from the operators, never set (SI-12, B13)"
                    ),
                });
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SI-12, B13, U9
    #[test]
    fn a_configuration_needs_two_witnesses_and_one_outside_the_provider() {
        assert_eq!(config("listen = \"x\""), Vec::<String>::new());
        let own = "[transparency]\noperator = \"Suiss\"\n[[transparency.witnesses]]\nurl = \"http://a:1\"\nvkey = \"v\"\noperator = \"suiss\"\n[[transparency.witnesses]]\nurl = \"http://b:1\"\nvkey = \"v\"\noperator = \"Suiss \"\n";
        assert_eq!(config(own).len(), 1);
        let one = "[transparency]\noperator = \"Suiss\"\n[[transparency.witnesses]]\nurl = \"http://a:1\"\nvkey = \"v\"\noperator = \"Ex Ltd\"\n";
        assert_eq!(config(one).len(), 1);
        let ok = format!(
            "{one}[[transparency.witnesses]]\nurl = \"http://b:1\"\nvkey = \"v\"\noperator = \"Suiss\"\n"
        );
        assert_eq!(config(&ok), Vec::<String>::new());
        let unnamed = "[transparency]\n[[transparency.witnesses]]\nurl = \"http://a:1\"\nvkey = \"v\"\noperator = \"Ex\"\n";
        assert_eq!(config(unnamed).len(), 1);
    }
}
