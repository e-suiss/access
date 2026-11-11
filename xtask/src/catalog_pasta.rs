//! PASTA flows and attack trees for the high-impact flows (SA-5, OP-159 m.3 (ff)): each flow has
//! the seven PASTA stages and an attack tree; each leaf names a threat row and at least one test
//! or a declared limit; every abuse case names a test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::{Catalog, Threat};
use crate::Violation;

pub(crate) const PASTA_DIR: &str = "conformance/threat/pasta";
pub(crate) const TREE_DIR: &str = "conformance/threat/trees";

/// The flows §14.2 and OP-159 m.3 (ff) name.
pub(crate) const FLOWS: &[&str] = &[
    "handover",
    "recovery",
    "break-glass",
    "binding-re-anchor",
    "pq-re-anchor",
    "login-recovery",
    "saml",
];

/// The seven PASTA stages, in order.
pub(crate) const STAGES: &[&str] = &[
    "objectives",
    "technical-scope",
    "decomposition",
    "threat-analysis",
    "vulnerability-analysis",
    "attack-modeling",
    "risk-impact",
];

const LIMIT_FAMILIES: &[&str] = &["DL", "HL", "N", "RR"];

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Stage {
    pub(crate) name: String,
    pub(crate) summary: String,
    #[serde(default)]
    pub(crate) refs: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pasta {
    pub(crate) flow: String,
    pub(crate) title: String,
    pub(crate) tree: String,
    #[serde(default)]
    pub(crate) components: Vec<String>,
    #[serde(default)]
    pub(crate) stage: Vec<Stage>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Node {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) parent: Option<String>,
    /// `and`, `or` or `leaf`.
    pub(crate) gate: String,
    pub(crate) title: String,
    /// `TH-n`, or `<group> #<ordinal>` for an unnumbered row.
    #[serde(default)]
    pub(crate) threat: Option<String>,
    #[serde(default)]
    pub(crate) tests: Vec<String>,
    /// Declared limits (DL, HL, N, RR rows) the leaf rests on instead of, or besides, a test.
    #[serde(default)]
    pub(crate) limits: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tree {
    pub(crate) flow: String,
    pub(crate) goal: String,
    #[serde(default)]
    pub(crate) node: Vec<Node>,
}

fn read<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The PASTA flows and the attack trees, by flow name.
pub(crate) type Flows = (BTreeMap<String, Pasta>, BTreeMap<String, Tree>);

/// Every flow file and every tree file, by flow name.
pub(crate) fn load(root: &Path) -> Result<Flows, String> {
    let mut flows = BTreeMap::new();
    let mut trees = BTreeMap::new();
    for (dir, is_tree) in [(PASTA_DIR, false), (TREE_DIR, true)] {
        let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        paths.sort();
        for p in paths {
            let stem = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            if is_tree {
                trees.insert(stem, read::<Tree>(&p)?);
            } else {
                flows.insert(stem, read::<Pasta>(&p)?);
            }
        }
    }
    Ok((flows, trees))
}

/// Names a threat row may be cited by: `TH-n` and `<group> #<ordinal>`.
pub(crate) fn threat_names(threats: &[Threat]) -> BTreeSet<String> {
    threats
        .iter()
        .filter_map(|t| match (&t.id, &t.group, t.ordinal) {
            (Some(id), _, _) => Some(id.clone()),
            (None, Some(g), Some(o)) => Some(format!("{g} #{o}")),
            _ => None,
        })
        .collect()
}

fn violation(path: String, message: String) -> Violation {
    Violation {
        rule: "SA-5",
        path: PathBuf::from(path),
        message,
    }
}

/// Pure validation, separated for tests.
#[expect(clippy::too_many_lines, reason = "one linear pass per file kind")]
pub(crate) fn violations(
    flows: &BTreeMap<String, Pasta>,
    trees: &BTreeMap<String, Tree>,
    catalog: &Catalog,
    components: &BTreeSet<String>,
    link_ok: &dyn Fn(&str) -> bool,
) -> Vec<Violation> {
    let ids = catalog.ids();
    let threats = threat_names(&catalog.threats);
    let known = |r: &str| ids.contains(r) || threats.contains(r);
    let mut out = Vec::new();
    for f in FLOWS {
        if !flows.contains_key(*f) {
            out.push(violation(
                format!("{PASTA_DIR}/{f}.toml"),
                format!("PASTA flow {f} is missing"),
            ));
        }
    }
    for (name, p) in flows {
        let path = format!("{PASTA_DIR}/{name}.toml");
        let mut bad = |m: String| out.push(violation(path.clone(), m));
        if p.flow != *name {
            bad(format!("flow {:?} does not match the file name", p.flow));
        }
        if p.title.trim().is_empty() {
            bad("missing title".to_owned());
        }
        let names: Vec<&str> = p.stage.iter().map(|s| s.name.as_str()).collect();
        if names != STAGES {
            bad(format!(
                "stages must be the seven PASTA stages in order, found {names:?}"
            ));
        }
        for s in &p.stage {
            if s.summary.trim().is_empty() {
                bad(format!("stage {} has no summary", s.name));
            }
            for r in s.refs.iter().filter(|r| !known(r)) {
                bad(format!(
                    "stage {}: {r} is not a catalog or threat row",
                    s.name
                ));
            }
        }
        if !p
            .stage
            .iter()
            .any(|s| s.name == "threat-analysis" && s.refs.iter().any(|r| threats.contains(r)))
        {
            bad("threat-analysis names no threat row".to_owned());
        }
        for c in p.components.iter().filter(|c| !components.contains(*c)) {
            bad(format!("component {c} is not in the trust model"));
        }
        if p.tree != format!("{TREE_DIR}/{name}.toml") || !trees.contains_key(name) {
            bad(format!("attack tree {:?} is missing", p.tree));
        }
    }
    for (name, t) in trees {
        let path = format!("{TREE_DIR}/{name}.toml");
        let mut bad = |m: String| out.push(violation(path.clone(), m));
        if t.flow != *name || !flows.contains_key(name) {
            bad(format!("tree {:?} has no PASTA flow", t.flow));
        }
        if t.goal.trim().is_empty() {
            bad("missing goal".to_owned());
        }
        let node_ids: BTreeSet<&str> = t.node.iter().map(|n| n.id.as_str()).collect();
        if node_ids.len() != t.node.len() {
            bad("duplicate node ID".to_owned());
        }
        let roots = t.node.iter().filter(|n| n.parent.is_none()).count();
        if roots != 1 {
            bad(format!("needs exactly one root node, found {roots}"));
        }
        for n in &t.node {
            let children = t
                .node
                .iter()
                .filter(|c| c.parent.as_deref() == Some(n.id.as_str()))
                .count();
            if let Some(p) = &n.parent
                && !node_ids.contains(p.as_str())
            {
                bad(format!("{}: parent {p} does not exist", n.id));
            }
            if n.title.trim().is_empty() {
                bad(format!("{}: missing title", n.id));
            }
            match n.gate.as_str() {
                "and" | "or" if children == 0 => bad(format!("{}: gate without children", n.id)),
                "and" | "or" => {}
                "leaf" => {
                    if children > 0 {
                        bad(format!("{}: a leaf has children", n.id));
                    }
                    match &n.threat {
                        Some(th) if threats.contains(th) => {}
                        Some(th) => {
                            bad(format!("{}: threat {th} is not in the threat model", n.id));
                        }
                        None => bad(format!("{}: leaf names no threat row", n.id)),
                    }
                    if n.tests.is_empty() && n.limits.is_empty() {
                        bad(format!("{}: leaf needs a test or a declared limit", n.id));
                    }
                    for x in n.tests.iter().filter(|x| !link_ok(x)) {
                        bad(format!("{}: test link {x:?} does not resolve", n.id));
                    }
                    for l in &n.limits {
                        let fam = super::ids::family(l);
                        if !ids.contains(l) || !fam.is_some_and(|f| LIMIT_FAMILIES.contains(&f)) {
                            bad(format!("{}: {l} is not a declared limit row", n.id));
                        }
                    }
                }
                g => bad(format!("{}: unknown gate {g:?}", n.id)),
            }
        }
    }
    for a in &catalog.abuse_cases {
        if a.tests.is_empty() {
            out.push(violation(
                format!("{}/threat-model.toml", super::DIR),
                format!("{}: abuse case names no test (OP-159 m.3 (ff))", a.id),
            ));
        }
    }
    out
}

pub(crate) fn check(root: &Path, catalog: &Catalog) -> Result<Vec<Violation>, String> {
    let (flows, trees) = load(root)?;
    let components: BTreeSet<String> = crate::rules::trust_model::load(root)?
        .component
        .into_iter()
        .map(|c| c.id)
        .collect();
    let leaves = trees
        .values()
        .flat_map(|t| &t.node)
        .filter(|n| n.gate == "leaf")
        .count();
    println!(
        "      threat-model: {} PASTA flows, {} attack tree leaves",
        flows.len(),
        leaves
    );
    Ok(violations(&flows, &trees, catalog, &components, &|l| {
        super::scan::link_exists(root, l)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog {
            threats: vec![Threat {
                id: Some("TH-2".into()),
                title: "t".into(),
                stride: vec!["S".into()],
                rows: vec!["N-41".into()],
                ..Threat::default()
            }],
            rules: vec![super::super::Rule {
                id: "N-41".into(),
                family: "N".into(),
                ..super::super::Rule::default()
            }],
            abuse_cases: vec![super::super::Rule {
                id: "AB-1".into(),
                family: "AB".into(),
                tests: vec!["x.rs::f".into()],
                ..super::super::Rule::default()
            }],
        }
    }

    fn flow(name: &str) -> Pasta {
        Pasta {
            flow: name.into(),
            title: "t".into(),
            tree: format!("{TREE_DIR}/{name}.toml"),
            components: vec!["pep".into()],
            stage: STAGES
                .iter()
                .map(|s| Stage {
                    name: (*s).into(),
                    summary: "s".into(),
                    refs: vec!["TH-2".into()],
                })
                .collect(),
        }
    }

    fn tree(name: &str) -> Tree {
        Tree {
            flow: name.into(),
            goal: "g".into(),
            node: vec![
                Node {
                    id: "R".into(),
                    gate: "or".into(),
                    title: "r".into(),
                    ..Node::default()
                },
                Node {
                    id: "R.1".into(),
                    parent: Some("R".into()),
                    gate: "leaf".into(),
                    title: "l".into(),
                    threat: Some("TH-2".into()),
                    limits: vec!["N-41".into()],
                    ..Node::default()
                },
            ],
        }
    }

    fn all() -> (BTreeMap<String, Pasta>, BTreeMap<String, Tree>) {
        (
            FLOWS.iter().map(|f| ((*f).to_owned(), flow(f))).collect(),
            FLOWS.iter().map(|f| ((*f).to_owned(), tree(f))).collect(),
        )
    }

    fn comps() -> BTreeSet<String> {
        std::iter::once("pep".to_owned()).collect()
    }

    // SA-5, OP-159 m.3 (ff)
    #[test]
    fn every_flow_has_seven_stages_and_every_leaf_a_threat_and_a_test_or_limit() {
        let (flows, trees) = all();
        assert!(violations(&flows, &trees, &catalog(), &comps(), &|_| true).is_empty());

        let (mut flows, mut trees) = all();
        flows.remove("saml");
        if let Some(p) = flows.get_mut("handover") {
            p.stage.pop();
        }
        if let Some(t) = trees.get_mut("recovery") {
            t.node[1].threat = Some("TH-99".into());
            t.node[1].limits = vec![];
        }
        let mut cat = catalog();
        cat.abuse_cases[0].tests.clear();
        let found: Vec<String> = violations(&flows, &trees, &cat, &comps(), &|_| true)
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert!(
            found.iter().any(|m| m.contains("saml is missing")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|m| m.contains("seven PASTA stages")),
            "{found:?}"
        );
        assert!(found.iter().any(|m| m.contains("TH-99")), "{found:?}");
        assert!(
            found.iter().any(|m| m.contains("test or a declared limit")),
            "{found:?}"
        );
        assert!(found.iter().any(|m| m.contains("AB-1")), "{found:?}");
    }
}
