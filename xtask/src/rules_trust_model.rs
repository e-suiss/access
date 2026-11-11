//! `trust-model`: the published trust model names every component of §13.2 and SA-7 with what it
//! is trusted with, what it never does and the lever that contains it (SEC5, OP-159 m.3 (gg)).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::catalog;

pub(crate) const FILE: &str = "conformance/catalog/trust-model.toml";

/// Components the trust model must name (§13.2, SA-7, Ek B 6250).
pub(crate) const REQUIRED: &[&str] = &[
    "anchor-root",
    "provider",
    "provider-operator",
    "identity-plane",
    "external-idp",
    "claim-issuer",
    "schema-publisher",
    "pep",
    "offline-verifier",
    "executor",
    "approval-surface",
    "witness",
    "legacy-gateway",
    "scim-client",
    "parser-worker",
    "co-tenant",
    "support-staff",
    "realm-signing-key",
    "operational-key",
    "binding-key",
];

/// One trust model row.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Component {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) trust: String,
    pub(crate) not_trusted: String,
    pub(crate) blast_radius: String,
    pub(crate) never: String,
    pub(crate) containment: String,
    #[serde(default)]
    pub(crate) rows: Vec<String>,
    #[serde(default)]
    pub(crate) tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TrustModel {
    #[serde(default)]
    pub(crate) component: Vec<Component>,
}

pub(crate) fn load(root: &Path) -> Result<TrustModel, String> {
    let path = root.join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn violation(message: String) -> Violation {
    Violation {
        rule: "SEC5",
        path: PathBuf::from(FILE),
        message,
    }
}

/// Pure validation, separated for tests: `ids` are the catalog IDs, `link_ok` resolves a test.
pub(crate) fn violations(
    model: &TrustModel,
    ids: &BTreeSet<String>,
    link_ok: &dyn Fn(&str) -> bool,
) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for c in &model.component {
        if !seen.insert(c.id.as_str()) {
            out.push(violation(format!("{}: duplicate component", c.id)));
        }
        for (field, value) in [
            ("name", &c.name),
            ("trust", &c.trust),
            ("not_trusted", &c.not_trusted),
            ("blast_radius", &c.blast_radius),
            ("never", &c.never),
            ("containment", &c.containment),
        ] {
            if value.trim().is_empty() {
                out.push(violation(format!("{}: `{field}` is empty", c.id)));
            }
        }
        if c.rows.is_empty() {
            out.push(violation(format!("{}: names no catalog row", c.id)));
        }
        for r in c.rows.iter().filter(|r| !ids.contains(*r)) {
            out.push(violation(format!(
                "{}: row {r} is not in the catalog",
                c.id
            )));
        }
        for t in c.tests.iter().filter(|t| !link_ok(t)) {
            out.push(violation(format!(
                "{}: test link {t:?} does not resolve",
                c.id
            )));
        }
    }
    for id in REQUIRED.iter().filter(|id| !seen.contains(**id)) {
        out.push(violation(format!(
            "component {id} is missing (§13.2, SA-7)"
        )));
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let model = load(root)?;
    let ids = catalog::load(root)?.ids();
    let out = violations(&model, &ids, &|l| catalog::link_exists(root, l));
    println!("      trust-model: {} components", model.component.len());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> TrustModel {
        TrustModel {
            component: REQUIRED
                .iter()
                .map(|id| Component {
                    id: (*id).to_owned(),
                    name: "c".into(),
                    trust: "t".into(),
                    not_trusted: "n".into(),
                    blast_radius: "b".into(),
                    never: "v".into(),
                    containment: "l".into(),
                    rows: vec!["INV-1".into()],
                    tests: vec![],
                })
                .collect(),
        }
    }

    fn ids() -> BTreeSet<String> {
        std::iter::once("INV-1".to_owned()).collect()
    }

    // SEC5, SA-7
    #[test]
    fn every_component_needs_its_never_boundary_and_a_known_row() {
        assert!(violations(&full(), &ids(), &|_| true).is_empty());
        let mut m = full();
        m.component.retain(|c| c.id != "co-tenant");
        if let Some(c) = m.component.first_mut() {
            c.never = String::new();
            c.rows = vec!["XX-9".into()];
            c.tests = vec!["nowhere.rs::f".into()];
        }
        let found: Vec<String> = violations(&m, &ids(), &|_| false)
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert!(
            found.iter().any(|m| m.contains("`never` is empty")),
            "{found:?}"
        );
        assert!(found.iter().any(|m| m.contains("XX-9")), "{found:?}");
        assert!(
            found.iter().any(|m| m.contains("does not resolve")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|m| m.contains("co-tenant is missing")),
            "{found:?}"
        );
    }

    // SEC5, OP-159 m.3 (gg)
    #[test]
    fn the_committed_trust_model_names_every_component() {
        let root = crate::workspace_root();
        let found = check(&root).unwrap_or_else(|e| vec![violation(e)]);
        assert!(found.is_empty(), "{found:?}");
    }
}
