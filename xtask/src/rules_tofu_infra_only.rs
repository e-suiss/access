//! `tofu-infra-only` (OP-158 m.3 (p), §12.5.3, T36): `deploy/tofu/**` provisions infrastructure only and makes no `idp.*` or ADP call.
//!
//! Realm and domain configuration is an Exercise through the management API, never
//! infrastructure: no file under `deploy/tofu/` names an `idp.*` action, the decision API
//! (`/access/v1/`), the management API (`/admin/v1/`), the Access CLI or the provider's own
//! write paths.

use std::path::Path;

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "tofu-infra-only";

const TOFU: &str = "deploy/tofu/";

/// What a configuration call looks like in an infrastructure file.
const CALLS: [&str; 5] = [
    "/access/v1/",
    "/admin/v1/",
    "/console/api/",
    "access-cli",
    "x-access-ais",
];

/// Whether `line` names an `idp.<namespace>.<action>` action label.
pub(crate) fn names_idp_action(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(at) = line.get(from..).and_then(|rest| rest.find("idp.")) {
        let start = from.saturating_add(at);
        let before = start
            .checked_sub(1)
            .and_then(|i| bytes.get(i))
            .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.');
        let rest = line.get(start.saturating_add(4)..).unwrap_or("");
        let mut parts = rest.splitn(3, '.');
        let ns = parts.next().unwrap_or("");
        let action: String = parts
            .next()
            .unwrap_or("")
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        let word = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
        if !before && word(ns) && !action.is_empty() {
            return true;
        }
        from = start.saturating_add(4);
    }
    false
}

/// The configuration call `line` makes, if any.
pub(crate) fn call(line: &str) -> Option<&'static str> {
    if names_idp_action(line) {
        return Some("an idp.* action");
    }
    CALLS.into_iter().find(|c| line.contains(c))
}

/// Runs `tofu-infra-only`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        if !r.starts_with(TOFU) {
            continue;
        }
        let Ok(src) = read(&path) else { continue };
        for (i, line) in src.lines().enumerate() {
            if let Some(what) = call(line) {
                out.push(Violation {
                    rule: RULE,
                    path: r.clone().into(),
                    message: format!(
                        "line {}: {what}; OpenTofu provisions infrastructure only, realm and domain configuration is an Exercise (OP-158 m.3 (p))",
                        i.saturating_add(1)
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

    // T36, OP-158 m.3 (p)
    #[test]
    fn t36_an_infrastructure_file_names_no_configuration_call() {
        assert!(names_idp_action(r#"action = "idp.realm.rehome""#));
        assert!(names_idp_action("idp.client.register"));
        assert!(!names_idp_action("var.idp.host"));
        assert!(!names_idp_action("cidp.realm.x"));
        assert!(!names_idp_action("the idp. namespace"));
        assert_eq!(
            call(r#"url = "https://a.example/admin/v1/realms/acme/clients""#),
            Some("/admin/v1/")
        );
        assert_eq!(
            call("command = \"access-cli realm create\""),
            Some("access-cli")
        );
        assert_eq!(call(r#"chart = "../helm/access""#), None);
    }

    #[test]
    fn the_repository_provisions_infrastructure_only() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check(root).unwrap();
        assert!(
            v.is_empty(),
            "{:?}",
            v.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }
}
