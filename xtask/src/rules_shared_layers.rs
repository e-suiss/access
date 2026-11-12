//! `shared-layers` (PI-18, OP-70, OP-159 m.3 (kk)): normative text and vectors of the layers shared with Work live only under protocol and conformance.
//! Outside those two folders no file carries BCP 14 requirement keywords, no CDDL and no vector
//! data; the vectors shipped in the `suiss-crypto` package are byte-identical copies (`shared-vectors`).
//! A pull request that changes either folder carries the `decision` label (`ci.yml`).

use std::path::Path;

use super::files::{read, rel, walk};
use crate::Violation;

const RULE: &str = "shared-layers";

/// The single normative source of the layers shared with Work.
pub(crate) const SHARED: &[&str] = &["protocol/", "conformance/"];

/// Byte-identical copies `shared-vectors` checks.
const COPIES: &[&str] = &["crates/suiss-crypto/vectors/"];

const LABEL_SCRIPT: &str = ".github/scripts/decision-label.py";
const CI: &str = ".github/workflows/ci.yml";

const KEYWORDS: &[&str] = &[
    "MUST",
    "SHALL",
    "SHOULD",
    "REQUIRED",
    "RECOMMENDED",
    "MAY",
    "OPTIONAL",
];

const TEXT: &[&str] = &["md", "txt", "adoc", "rst"];
const DATA: &[&str] = &["json", "cbor", "toml", "txt", "hex", "diag", "bin", "cddl"];

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

fn extension(path: &str) -> &str {
    path.rsplit_once('.').map_or("", |(_, e)| e)
}

fn inside(path: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| path.starts_with(p))
}

/// Prose with fenced blocks and inline code spans removed.
fn prose(text: &str) -> String {
    let mut out = String::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let mut code = false;
        for c in line.chars() {
            if c == '`' {
                code = !code;
            } else if !code {
                out.push(c);
            }
        }
        out.push('\n');
    }
    out
}

/// The BCP 14 keywords a text uses as whole uppercase words.
pub(crate) fn keywords(text: &str) -> Vec<&'static str> {
    let prose = prose(text);
    let words: Vec<&str> = prose
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
        .collect();
    KEYWORDS
        .iter()
        .copied()
        .filter(|k| words.contains(k))
        .collect()
}

fn is_vector_data(path: &str) -> bool {
    if !DATA.contains(&extension(path)) {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    path.split('/').any(|s| s == "vectors") || name.contains("vector")
}

/// Findings for one repository file outside the shared folders.
pub(crate) fn file_findings(path: &str, text: Option<&str>) -> Vec<String> {
    if inside(path, SHARED) || inside(path, COPIES) {
        return Vec::new();
    }
    let mut out = Vec::new();
    if extension(path) == "cddl" {
        out.push(String::from(
            "CDDL of the shared layers lives only in conformance/cddl",
        ));
    } else if is_vector_data(path) {
        out.push(String::from(
            "vectors live only in conformance/vectors; a shipped copy is listed in shared-vectors",
        ));
    }
    if TEXT.contains(&extension(path))
        && let Some(text) = text
    {
        let found = keywords(text);
        if !found.is_empty() {
            out.push(format!(
                "normative keywords {} outside protocol/ and conformance/; the protocol text is written only there",
                found.join(", ")
            ));
        }
    }
    out
}

/// Findings for the CI step that asks for the `decision` label.
pub(crate) fn label_findings(
    script: Option<&str>,
    ci: Option<&str>,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    match script {
        None => out.push((LABEL_SCRIPT, String::from("missing"))),
        Some(s) => {
            for prefix in SHARED {
                if !s.contains(&format!("\"{prefix}\"")) {
                    out.push((
                        LABEL_SCRIPT,
                        format!("does not treat {prefix} as a shared layer"),
                    ));
                }
            }
            if !s.contains("\"decision\"") {
                out.push((
                    LABEL_SCRIPT,
                    String::from("does not ask for the decision label"),
                ));
            }
        }
    }
    let runs = ci.is_some_and(|c| {
        c.lines()
            .any(|l| l.contains("decision-label.py") && !l.trim_start().starts_with('#'))
    });
    if !runs {
        out.push((
            CI,
            String::from("no pull request step runs .github/scripts/decision-label.py"),
        ));
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in walk(root)? {
        let path = rel(root, &file);
        let text = if TEXT.contains(&extension(&path)) && !inside(&path, SHARED) {
            Some(read(&file)?)
        } else {
            None
        };
        for message in file_findings(&path, text.as_deref()) {
            out.push(v(&path, message));
        }
    }
    let script = std::fs::read_to_string(root.join(LABEL_SCRIPT)).ok();
    let ci = std::fs::read_to_string(root.join(CI)).ok();
    for (path, message) in label_findings(script.as_deref(), ci.as_deref()) {
        out.push(v(path, message));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap()
    }

    // PI-18
    #[test]
    fn normative_text_outside_protocol_and_conformance_fails() {
        let text = "# Notes\n\nA verifier MUST reject a stripped signature.\n";
        assert_eq!(file_findings("crates/kernel/NOTES.md", Some(text)).len(), 1);
        assert!(file_findings("protocol/l0/signatures.md", Some(text)).is_empty());
        assert!(file_findings("conformance/README.md", Some(text)).is_empty());
        let code = "Use `LandlockAbi::REQUIRED`.\n\n```rust\nlet x = MAY;\n```\n";
        assert!(file_findings("crates/suiss-sandbox/README.md", Some(code)).is_empty());
        assert!(file_findings("README.md", Some("You may run it.\n")).is_empty());
    }

    // PI-18
    #[test]
    fn vectors_or_cddl_outside_conformance_fail() {
        assert_eq!(
            file_findings("crates/kernel/tests/vectors/a.json", None).len(),
            1
        );
        assert_eq!(file_findings("bins/x/decision-vectors.cbor", None).len(), 1);
        assert_eq!(file_findings("crates/http/src/shape.cddl", None).len(), 1);
        assert!(file_findings("crates/kernel/tests/vectors.rs", None).is_empty());
        assert!(file_findings("conformance/vectors/core/1/cose.json", None).is_empty());
        assert!(file_findings("crates/suiss-crypto/vectors/core/1/cose.json", None).is_empty());
    }

    // PI-18, OP-70
    #[test]
    fn a_label_step_that_misses_a_shared_path_fails() {
        let script = "SHARED = (\"protocol/\", \"conformance/\")\nLABEL = \"decision\"\n";
        let ci = "      - run: python3 -I .github/scripts/decision-label.py a b\n";
        assert!(label_findings(Some(script), Some(ci)).is_empty());
        let partial = "SHARED = (\"protocol/\",)\nLABEL = \"decision\"\n";
        assert_eq!(label_findings(Some(partial), Some(ci)).len(), 1);
        assert_eq!(
            label_findings(Some(script), Some("# decision-label.py\n")).len(),
            1
        );
        assert_eq!(label_findings(None, None).len(), 2);
    }

    // PI-18
    #[test]
    fn the_repository_keeps_its_shared_layers_in_one_place() {
        assert!(check(&root()).unwrap().is_empty());
    }
}
