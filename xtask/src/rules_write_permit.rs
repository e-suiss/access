//! `write-permit` (OP-91, INV-12, OP-159 m.3 (ee)): only the authority core builds a write permit, and the permit has no public field.
//!
//! - `WritePermit` in [`DEFINITION`] has no `pub` field and is neither `Clone`, `Copy` nor
//!   `Default`.
//! - The sequencer's commit entries take a `WritePermit` first.
//! - `WritePermit::mint` is called only under [`MINTERS`]; the test constructor only in test
//!   files; the sequencer's `testing` feature is enabled only by dev-dependencies.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};

const RULE: &str = "write-permit";

/// The file that declares the permit.
pub(crate) const DEFINITION: &str = "crates/authority-sequencer/src/permit.rs";

/// The files whose commit entries spend a permit.
const ENTRIES: [(&str, &str); 2] = [
    (
        "crates/authority-sequencer/src/app.rs",
        "pub async fn commit(",
    ),
    (
        "crates/authority-sequencer/src/app/group.rs",
        "pub async fn commit_group(",
    ),
];

/// The only place a permit is minted.
pub(crate) const MINTERS: &str = "crates/authority-core/src/app/";

const SEQUENCER: &str = "access-authority-sequencer";

const SCANNED: [&str; 5] = ["crates/", "bins/", "services/", "fuzz/", "sdks/"];

fn violation(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

/// What is wrong with the permit's declaration in `src`.
pub(crate) fn declaration(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let lines: Vec<&str> = src.lines().collect();
    let Some(at) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("pub struct WritePermit"))
    else {
        out.push(String::from("no `pub struct WritePermit`"));
        return out;
    };
    let attrs = lines
        .get(..at)
        .unwrap_or_default()
        .iter()
        .rev()
        .take_while(|l| {
            let t = l.trim_start();
            t.starts_with("#[") || t.starts_with("///")
        })
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    for derived in ["Clone", "Copy", "Default"] {
        if attrs.contains("derive(") && attrs.contains(derived) {
            out.push(format!("WritePermit derives {derived}"));
        }
    }
    if lines.get(at).is_some_and(|l| l.contains('(')) {
        out.push(String::from("WritePermit is a tuple struct"));
    }
    for line in lines.iter().skip(at.saturating_add(1)) {
        let t = line.trim_start();
        if t.starts_with('}') {
            break;
        }
        if t.starts_with("pub") {
            out.push(format!("WritePermit has a public field: {}", t.trim_end()));
        }
    }
    for trait_ in ["Clone", "Copy", "Default"] {
        if src.contains(&format!("impl {trait_} for WritePermit")) {
            out.push(format!("WritePermit implements {trait_}"));
        }
    }
    out
}

/// Whether `src` names the entry `head` with a `WritePermit` as its first parameter.
pub(crate) fn entry_takes_permit(src: &str, head: &str) -> bool {
    let Some(at) = src.find(head) else {
        return false;
    };
    let rest = src.get(at.saturating_add(head.len())..).unwrap_or_default();
    let params: Vec<&str> = rest
        .split(')')
        .next()
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    params.first().is_some_and(|p| p.ends_with("self"))
        && params.get(1).is_some_and(|p| {
            p.split(':')
                .nth(1)
                .is_some_and(|t| t.trim() == "WritePermit")
        })
}

/// The lines of the Rust file `r` that build a permit where they may not.
pub(crate) fn forged(r: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    if r == DEFINITION {
        return out;
    }
    let names = src.contains("WritePermit");
    for (i, line) in src.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") {
            continue;
        }
        let n = i.saturating_add(1);
        let mint = line.contains("WritePermit::mint") || (names && line.contains("::mint("));
        if mint && !r.starts_with(MINTERS) {
            out.push(format!(
                "line {n}: a write permit is minted outside {MINTERS} (OP-91)"
            ));
        }
        if line.contains("WritePermit::for_tests") && !is_test_file(r) {
            out.push(format!(
                "line {n}: the test write permit is used outside a test file (OP-91)"
            ));
        }
        if literal(line) {
            out.push(format!(
                "line {n}: a write permit is built from a struct literal (OP-91)"
            ));
        }
    }
    out
}

/// Whether `line` builds a `WritePermit` from a struct literal (`WritePermit { field: … }`,
/// `WritePermit {}` or `WritePermit { .. }`), not a return type or an `impl` block.
fn literal(line: &str) -> bool {
    line.match_indices("WritePermit").any(|(at, _)| {
        let rest = line
            .get(at.saturating_add("WritePermit".len())..)
            .unwrap_or_default()
            .trim_start();
        let Some(body) = rest.strip_prefix('{') else {
            return false;
        };
        let body = body.trim_start();
        if body.starts_with('}') || body.starts_with("..") {
            return true;
        }
        let field: String = body
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        !field.is_empty()
            && body.get(field.len()..).is_some_and(|r| {
                r.trim_start().starts_with(':') && !r.trim_start().starts_with("::")
            })
    })
}

/// Whether the manifest `src` enables the sequencer's `testing` feature outside
/// `[dev-dependencies]`.
pub(crate) fn testing_outside_dev(src: &str) -> bool {
    let mut section = String::new();
    for line in src.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            t.clone_into(&mut section);
            continue;
        }
        if t.starts_with(SEQUENCER)
            && t.contains("\"testing\"")
            && !section.contains("dev-dependencies")
        {
            return true;
        }
    }
    false
}

/// Runs `write-permit`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let definition = read(&root.join(DEFINITION))?;
    out.extend(
        declaration(&definition)
            .into_iter()
            .map(|m| violation(DEFINITION, format!("{m} (OP-91, INV-12)"))),
    );
    for (file, head) in ENTRIES {
        let src = read(&root.join(file))?;
        if !entry_takes_permit(&src, head) {
            out.push(violation(
                file,
                format!("`{head}` does not take a WritePermit first (OP-159 m.3 (ee))"),
            ));
        }
    }
    for path in walk(root)? {
        let r = rel(root, &path);
        if !SCANNED.iter().any(|s| r.starts_with(s)) {
            continue;
        }
        if r.ends_with("Cargo.toml") {
            let src = read(&path)?;
            if testing_outside_dev(&src) {
                out.push(violation(
                    &r,
                    String::from(
                        "the sequencer's `testing` feature is enabled outside dev-dependencies (OP-91)",
                    ),
                ));
            }
            continue;
        }
        if Path::new(&r).extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let Ok(src) = read(&path) else { continue };
        out.extend(forged(&r, &src).into_iter().map(|m| violation(&r, m)));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // INV-12, OP-91: a public field, a derived copy or a default permit is refused
    #[test]
    fn inv_12_a_permit_with_a_public_field_or_a_copy_is_refused() {
        let good = "#[derive(Debug)]\npub struct WritePermit {\n    seal: (),\n}\n";
        assert_eq!(declaration(good), Vec::<String>::new());
        let public = "pub struct WritePermit {\n    pub seal: (),\n}\n";
        assert_eq!(declaration(public).len(), 1);
        let cloned = "#[derive(Debug, Clone)]\npub struct WritePermit {\n    seal: (),\n}\n";
        assert_eq!(declaration(cloned), ["WritePermit derives Clone"]);
        let tuple = "pub struct WritePermit(pub ());\n";
        assert_ne!(declaration(tuple), Vec::<String>::new());
        let defaulted = format!("{good}impl Default for WritePermit {{}}\n");
        assert_eq!(declaration(&defaulted), ["WritePermit implements Default"]);
        assert_eq!(
            declaration("struct Other;"),
            ["no `pub struct WritePermit`"]
        );
    }

    // INV-12, OP-91: only the core's app layer mints; tests use the test constructor
    #[test]
    fn inv_12_a_permit_minted_outside_the_core_app_layer_is_refused() {
        let mint = "let p = WritePermit::mint();\n";
        assert_eq!(
            forged("crates/authority-core/src/app/permit.rs", mint),
            Vec::<String>::new()
        );
        assert_eq!(forged("crates/identity-scim/src/app.rs", mint).len(), 1);
        assert_eq!(forged("bins/access-server/src/main.rs", mint).len(), 1);
        let alias = "use x::WritePermit as P;\nlet p = P::mint();\n";
        assert_eq!(forged("crates/http/src/lib.rs", alias).len(), 1);
        let test = "let p = WritePermit::for_tests();\n";
        assert_eq!(
            forged("crates/authority-sequencer/tests/dst.rs", test),
            Vec::<String>::new()
        );
        assert_eq!(forged("crates/http/src/lib.rs", test).len(), 1);
        let literal = "let p = WritePermit { seal: () };\n";
        assert_eq!(forged("crates/http/src/lib.rs", literal).len(), 1);
        assert_eq!(forged(DEFINITION, mint), Vec::<String>::new());
        let ret = "pub(crate) const fn issue() -> WritePermit {\n";
        assert_eq!(
            forged("crates/authority-core/src/app/permit.rs", ret),
            Vec::<String>::new()
        );
        assert_eq!(
            forged("crates/http/src/lib.rs", "let p = WritePermit {};\n").len(),
            1
        );
    }

    // OP-159 m.3 (ee): the commit entry asks for the permit first
    #[test]
    fn op_91_the_commit_entry_takes_the_permit_first() {
        let good = "pub async fn commit(\n        &mut self,\n        permit: WritePermit,\n        now: TrustedTime,\n    ) {";
        assert!(entry_takes_permit(good, "pub async fn commit("));
        let bad = "pub async fn commit(\n        &mut self,\n        now: TrustedTime,\n    ) {";
        assert!(!entry_takes_permit(bad, "pub async fn commit("));
        assert!(!entry_takes_permit("", "pub async fn commit("));
    }

    // OP-91: the test constructor is only reachable from dev-dependencies
    #[test]
    fn op_91_the_testing_feature_is_dev_only() {
        let dev = "[dependencies]\naccess-authority-sequencer = { path = \"x\" }\n[dev-dependencies]\naccess-authority-sequencer = { path = \"x\", features = [\"testing\"] }\n";
        assert!(!testing_outside_dev(dev));
        let prod = "[dependencies]\naccess-authority-sequencer = { path = \"x\", features = [\"testing\"] }\n";
        assert!(testing_outside_dev(prod));
    }

    #[test]
    fn the_repository_mints_permits_only_in_the_core() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check(root).unwrap();
        assert!(
            v.is_empty(),
            "{:?}",
            v.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }
}
