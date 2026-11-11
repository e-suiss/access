//! `support-template` (MD-9, TN-71, OP-157 m.3 (c)): a support Grant template names no reserved or support-protected `idp.account` action.
//! The templates' action lists in `app/templates/support.rs` are read against the catalog's
//! `reserved()` arms in `internal-api/src/idp.rs`: no eligible action is reserved or protected,
//! and the protected list holds every reserved `idp.account` action, the e-mail change and the
//! export.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Violation;

const RULE: &str = "support-template";
const TEMPLATES: &str = "crates/authority-core/src/app/templates/support.rs";
const CATALOG: &str = "crates/internal-api/src/idp.rs";

/// The `IdpAction::X` names in the block of `text` that starts at `head` and ends at `];`.
fn listed(text: &str, head: &str) -> Option<BTreeSet<String>> {
    let start = text.find(head)?;
    let rest = text.get(start..)?;
    let end = rest.find("];")?;
    Some(names(rest.get(..end)?, "IdpAction::"))
}

fn names(block: &str, prefix: &str) -> BTreeSet<String> {
    block
        .split(prefix)
        .skip(1)
        .filter_map(|s| {
            let n: String = s
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            (!n.is_empty()).then_some(n)
        })
        .collect()
}

/// The variants `reserved()` lists in the catalog.
fn reserved(text: &str) -> Option<BTreeSet<String>> {
    let start = text.find("pub const fn reserved(self) -> bool")?;
    let rest = text.get(start..)?;
    let end = rest.find("\n    }\n")?;
    Some(names(rest.get(..end)?, "Self::"))
}

/// The violations of the templates file `templates` against the catalog file `catalog`.
pub(crate) fn violations(templates: &str, catalog: &str) -> Vec<String> {
    let mut out = Vec::new();
    let (Some(eligible), Some(read_only), Some(protected), Some(reserved)) = (
        listed(templates, "pub const ELIGIBLE"),
        listed(templates, "pub const READ_ONLY"),
        listed(templates, "pub const PROTECTED"),
        reserved(catalog),
    ) else {
        return vec![String::from(
            "the support templates or the catalog's reserved() can no longer be read",
        )];
    };
    for a in eligible.iter().chain(read_only.iter()) {
        if reserved.contains(a) {
            out.push(format!("{a} is reserved and named by a support template"));
        }
        if protected.contains(a) {
            out.push(format!("{a} is protected and named by a support template"));
        }
    }
    if !read_only.is_subset(&eligible) {
        out.push(String::from("READ_ONLY names an action ELIGIBLE does not"));
    }
    for a in reserved.iter().filter(|a| a.starts_with("Account")) {
        if !protected.contains(a) {
            out.push(format!(
                "{a} is a reserved idp.account action missing from PROTECTED"
            ));
        }
    }
    for a in ["AccountEmailChange", "AccountExport"] {
        if !protected.contains(a) {
            out.push(format!("{a} is missing from PROTECTED"));
        }
    }
    out
}

/// Runs `support-template`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let read = |p: &str| fs::read_to_string(root.join(p)).map_err(|e| format!("{p}: {e}"));
    let (templates, catalog) = (read(TEMPLATES)?, read(CATALOG)?);
    Ok(violations(&templates, &catalog)
        .into_iter()
        .map(|message| Violation {
            rule: RULE,
            path: PathBuf::from(TEMPLATES),
            message,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG_TEXT: &str = "    pub const fn reserved(self) -> bool {\n        matches!(self, Self::AccountDelete | Self::AccountMfaChange | Self::RealmRpId)\n    }\n";

    // MD-9, TN-71, OP-157 m.3 (c)
    #[test]
    fn a_template_naming_a_reserved_or_protected_action_is_reported() {
        let good = "pub const ELIGIBLE: [IdpAction; 1] = [IdpAction::AccountRead];\npub const READ_ONLY: [IdpAction; 1] = [IdpAction::AccountRead];\npub const PROTECTED: [IdpAction; 4] = [IdpAction::AccountEmailChange, IdpAction::AccountExport, IdpAction::AccountDelete, IdpAction::AccountMfaChange];";
        assert!(violations(good, CATALOG_TEXT).is_empty());
        let reserved = good.replace(
            "ELIGIBLE: [IdpAction; 1] = [IdpAction::AccountRead]",
            "ELIGIBLE: [IdpAction; 2] = [IdpAction::AccountRead, IdpAction::AccountMfaChange]",
        );
        assert_eq!(violations(&reserved, CATALOG_TEXT).len(), 2);
        let uncovered = good.replace(", IdpAction::AccountDelete", "");
        assert_eq!(violations(&uncovered, CATALOG_TEXT).len(), 1);
        assert_eq!(violations("", CATALOG_TEXT).len(), 1);
    }

    // OP-157 m.3 (c)
    #[test]
    fn the_repository_templates_pass() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert!(check(&root).unwrap().is_empty());
    }
}
