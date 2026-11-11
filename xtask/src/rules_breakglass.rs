//! `breakglass-isolation` (OP-46, CMP-25, G63, OP-157 m.3 (j)): the operator break-glass tool
//! (`bins/access-breakglass`) is a separate code path. Over the resolved graph of linked (normal)
//! dependencies it links only `access-crypto` among the workspace's own crates, besides what that
//! crate links itself, and nothing that reaches a database, Redis, the signer, Relay, the risk
//! engine or the MFA orchestrator.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::Metadata;

const RULE: &str = "breakglass-isolation";

/// The tool's directory.
const TOOL: &str = "bins/access-breakglass";

/// The workspace crates the tool may name as dependencies (OP-157 m.3 (j)).
const DIRECT: [&str; 2] = ["access-crypto", "access-telemetry"];

/// Crates the tool may never link, directly or through another crate.
fn forbidden(name: &str) -> bool {
    matches!(
        name,
        "access-store"
            | "access-http"
            | "access-internal-api"
            | "access-sdk"
            | "esuiss-access-sdk"
            | "sqlx"
            | "tokio-postgres"
            | "postgres"
            | "redis"
            | "async-nats"
            | "reqwest"
            | "hyper"
    ) || name.starts_with("sqlx-")
        || name.starts_with("access-authority-")
        || name.starts_with("access-identity-")
        || name.starts_with("redis-")
}

fn closure<'a>(linked: &'a BTreeMap<String, Vec<String>>, start: &str) -> BTreeSet<&'a str> {
    let mut seen = BTreeSet::new();
    let mut todo: Vec<&str> = linked
        .get(start)
        .map(|v| v.iter().map(String::as_str).collect())
        .unwrap_or_default();
    while let Some(id) = todo.pop() {
        if seen.insert(id) {
            todo.extend(linked.get(id).into_iter().flatten().map(String::as_str));
        }
    }
    seen
}

/// The violations in `md`.
pub(crate) fn check_metadata(root: &Path, md: &Metadata) -> Vec<Violation> {
    let names: BTreeMap<&str, &str> = md
        .packages
        .iter()
        .map(|p| (p.id.as_str(), p.name.as_str()))
        .collect();
    let members: BTreeSet<&str> = md.members().map(|p| p.id.as_str()).collect();
    let mut out = Vec::new();
    for pkg in md.members() {
        if rel(root, pkg.dir()) != TOOL {
            continue;
        }
        let manifest = pkg
            .manifest_path
            .strip_prefix(root)
            .unwrap_or(&pkg.manifest_path)
            .to_path_buf();
        for id in md.linked.get(&pkg.id).into_iter().flatten() {
            let name = names.get(id.as_str()).copied().unwrap_or_default();
            if members.contains(id.as_str()) && !DIRECT.contains(&name) {
                out.push(Violation {
                    rule: RULE,
                    path: manifest.clone(),
                    message: format!(
                        "the break-glass tool depends on `{name}`: it uses only access-crypto, access-telemetry and the standard library (OP-157 m.3 (j))"
                    ),
                });
            }
        }
        for id in closure(&md.linked, &pkg.id) {
            let name = names.get(id).copied().unwrap_or_default();
            if forbidden(name) {
                out.push(Violation {
                    rule: RULE,
                    path: manifest.clone(),
                    message: format!(
                        "the break-glass tool links `{name}`: it has no database, Redis, signer, Relay, risk or MFA dependency (OP-46, G63)"
                    ),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let mut out = check_metadata(root, &md);
    if !md.members().any(|p| rel(root, p.dir()) == TOOL) {
        out.push(Violation {
            rule: RULE,
            path: Path::new(TOOL).to_path_buf(),
            message: String::from("the operator break-glass tool is missing (OP-46)"),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::supply_chain::metadata::parse;

    fn id(dir: &str) -> String {
        let name = dir.rsplit('/').next().unwrap_or(dir);
        format!("path+file:///ws/{dir}#{name}@0.0.0")
    }

    fn pkg(dir: &str, name: &str) -> Value {
        json!({
            "id": id(dir), "name": name, "version": "0.0.0", "source": null,
            "manifest_path": format!("/ws/{dir}/Cargo.toml"), "dependencies": [],
            "targets": [{"kind": ["bin"], "src_path": format!("/ws/{dir}/src/main.rs")}],
        })
    }

    fn md(packages: &[Value], edges: &[(String, String)]) -> Metadata {
        let members: Vec<Value> = packages
            .iter()
            .filter_map(|p| p.get("id").cloned())
            .collect();
        let nodes: Vec<Value> = packages
            .iter()
            .filter_map(|p| p.get("id").and_then(Value::as_str))
            .map(|from| {
                let deps: Vec<Value> = edges
                    .iter()
                    .filter(|(f, _)| f == from)
                    .map(|(_, to)| json!({"pkg": to, "dep_kinds": [{"kind": null}]}))
                    .collect();
                json!({"id": from, "features": [], "deps": deps})
            })
            .collect();
        let doc = json!({"packages": packages, "workspace_members": members, "resolve": {"nodes": nodes}});
        parse(&doc.to_string()).unwrap_or_default()
    }

    // G63, OP-46, CMP-25
    #[test]
    fn g63_the_breakglass_tool_links_no_plane_or_database_crate() {
        let ok = md(
            &[
                pkg(TOOL, "access-breakglass"),
                pkg("crates/crypto", "access-crypto"),
                pkg("crates/kernel", "esuiss-access-kernel"),
            ],
            &[
                (id(TOOL), id("crates/crypto")),
                (id("crates/crypto"), id("crates/kernel")),
            ],
        );
        assert_eq!(check_metadata(Path::new("/ws"), &ok).len(), 0);
        let bad = md(
            &[
                pkg(TOOL, "access-breakglass"),
                pkg("crates/crypto", "access-crypto"),
                pkg("crates/store", "access-store"),
            ],
            &[
                (id(TOOL), id("crates/crypto")),
                (id("crates/crypto"), id("crates/store")),
            ],
        );
        assert_eq!(check_metadata(Path::new("/ws"), &bad).len(), 1);
        let direct = md(
            &[
                pkg(TOOL, "access-breakglass"),
                pkg("crates/parse", "access-parse"),
            ],
            &[(id(TOOL), id("crates/parse"))],
        );
        assert_eq!(check_metadata(Path::new("/ws"), &direct).len(), 1);
    }
}
