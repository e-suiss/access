//! `no-authority-to-identity-write` (§5.12, §10.1.1, TI-15, T31, E3, OP-150): the authority
//! plane never writes the identity plane. Identity reaches authority only as Claims through
//! Claim Ingest; authority reaches identity only by derived events and Decision Responses.
//! `dependency-direction` keeps `authority-*` off the `identity-*` crates; this rule keeps the
//! non-test code of the `authority-*` crates off the identity plane's store modules, so no
//! identity table can be written from the authority side.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};

const RULE: &str = "no-authority-to-identity-write";

/// The identity plane's store modules.
pub(crate) const IDENTITY_MODULES: &[&str] = &[
    "accounts",
    "audit",
    "backchannel",
    "dpop",
    "identity",
    "idp",
    "oauth",
    "passkeys",
    "sessions",
    "throttle",
];

/// The identity store modules a Rust source names outside its tests, with their lines.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        let n = i.saturating_add(1);
        if in_regions(&tests, n) {
            continue;
        }
        for (at, _) in line.match_indices("access_store::") {
            let rest = line.get(at.saturating_add(14)..).unwrap_or_default();
            let module: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if IDENTITY_MODULES.contains(&module.as_str()) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(format!("{rel_path}:{n}")),
                    message: format!(
                        "`access_store::{module}` from the authority plane: identity reaches \
                         authority only as Claims (§5.12, TI-15)"
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
        let authority = rel_path
            .strip_prefix("crates/")
            .is_some_and(|r| r.starts_with("authority-"));
        let rust = path.extension().and_then(|e| e.to_str()) == Some("rs");
        if authority && rust && !is_test_file(&rel_path) {
            out.extend(rust_violations(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // §5.12, TI-15, T31, E3: an authority crate naming an identity store module is refused
    #[test]
    fn identity_store_modules_are_refused_on_the_authority_side() {
        let src = "use access_store::accounts::Account;\nfn f() { access_store::idp::write(); }\n";
        assert_eq!(
            rust_violations("crates/authority-core/src/a.rs", src).len(),
            2
        );
        for m in IDENTITY_MODULES {
            let line = format!("use access_store::{m}::X;\n");
            assert_eq!(rust_violations("a.rs", &line).len(), 1, "{m}");
        }
    }

    // §5.12: the authority plane's own store modules, comments and test code are accepted
    #[test]
    fn authority_store_modules_are_accepted() {
        let src = "use access_store::authority::Draw;\nuse access_store::claims;\n// access_store::idp\n#[cfg(test)]\nmod tests { use access_store::identity::RealmId; }\n";
        assert!(rust_violations("crates/authority-core/src/a.rs", src).is_empty());
        assert!(rust_violations("a.rs", "use access_store::identityless::X;\n").is_empty());
    }
}
