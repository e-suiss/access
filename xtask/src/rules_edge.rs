//! `edge-isolation` (OP-155 m.3 (c), (d), MD-1, MD-18, IDI-11, P-ID-5): what the edge processes
//! link, over the resolved graph of linked (normal) dependencies.
//!
//! - A gateway (`bins/access-gw-*`) and the edge core (`crates/edge-core`) link no store, no
//!   authority-plane crate and neither `identity-signer` nor `identity-account`, directly or
//!   through another crate: their only way out is the edge channel.
//! - XML and XML-signature crates (`quick-xml`, `bergshamra*`, `uppsala`, `kryptering`) are linked
//!   only by the parser worker (`bins/access-parser-worker`).
//! - The parser worker links no store and no plane crate: it holds no key and writes nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::Metadata;

const RULE: &str = "edge-isolation";

/// The one crate that may link the XML stack.
const WORKER: &str = "bins/access-parser-worker";

/// Crates no edge process may link (IDI-11).
fn plane_write(name: &str) -> bool {
    name == "access-store"
        || name.starts_with("access-authority-")
        || matches!(name, "access-identity-signer" | "access-identity-account")
}

/// Crates no process may link but the parser worker (OP-155 m.3 (d)).
fn xml_stack(name: &str) -> bool {
    matches!(name, "quick-xml" | "uppsala" | "kryptering") || name.starts_with("bergshamra")
}

fn edge(dir: &str) -> bool {
    dir == "crates/edge-core" || dir.starts_with("bins/access-gw-")
}

/// Every package id `start` links, itself excluded.
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
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let manifest = pkg
            .manifest_path
            .strip_prefix(root)
            .unwrap_or(&pkg.manifest_path)
            .to_path_buf();
        let linked: BTreeSet<&str> = closure(&md.linked, &pkg.id)
            .into_iter()
            .filter_map(|id| names.get(id).copied())
            .collect();
        for name in &linked {
            let message = if edge(&dir) && plane_write(name) {
                format!(
                    "edge process `{}` links `{name}`: gateways reach access-server only over the edge channel (IDI-11)",
                    pkg.name
                )
            } else if dir != WORKER && xml_stack(name) {
                format!(
                    "`{}` links `{name}`: XML is parsed only in the parser worker (OP-155 m.3 (d))",
                    pkg.name
                )
            } else if dir == WORKER && (plane_write(name) || name.starts_with("access-identity-")) {
                format!(
                    "the parser worker links `{name}`: it holds no key and writes nothing (MD-18)"
                )
            } else {
                continue;
            };
            out.push(Violation {
                rule: RULE,
                path: manifest.clone(),
                message,
            });
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    Ok(check_metadata(root, &md))
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
            "id": id(dir),
            "name": name,
            "version": "0.0.0",
            "source": null,
            "manifest_path": format!("/ws/{dir}/Cargo.toml"),
            "dependencies": [],
            "targets": [{"kind": ["lib"], "src_path": format!("/ws/{dir}/src/lib.rs")}],
        })
    }

    fn registry(name: &str) -> Value {
        json!({
            "id": format!("registry+https://github.com/rust-lang/crates.io-index#{name}@1.0.0"),
            "name": name,
            "version": "1.0.0",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": format!("/reg/{name}/Cargo.toml"),
            "dependencies": [],
            "targets": [{"kind": ["lib"], "src_path": "/reg/src/lib.rs"}],
        })
    }

    fn reg_id(name: &str) -> String {
        format!("registry+https://github.com/rust-lang/crates.io-index#{name}@1.0.0")
    }

    /// Metadata with `edges` as (from, to, kind) over package ids.
    fn md(packages: &[Value], edges: &[(String, String, Option<&str>)]) -> Metadata {
        let members: Vec<Value> = packages
            .iter()
            .filter(|p| p.get("source").is_some_and(Value::is_null))
            .filter_map(|p| p.get("id").cloned())
            .collect();
        let nodes: Vec<Value> = packages
            .iter()
            .filter_map(|p| p.get("id").and_then(Value::as_str))
            .map(|from| {
                let deps: Vec<Value> = edges
                    .iter()
                    .filter(|(f, _, _)| f == from)
                    .map(|(_, to, kind)| json!({"pkg": to, "dep_kinds": [{"kind": kind}]}))
                    .collect();
                json!({"id": from, "features": [], "deps": deps})
            })
            .collect();
        let doc = json!({
            "packages": packages,
            "workspace_members": members,
            "resolve": {"nodes": nodes},
        });
        parse(&doc.to_string()).unwrap_or_default()
    }

    // IDI-11, P-ID-5
    #[test]
    fn idi_11_a_gateway_reaching_the_store_through_a_crate_is_refused() {
        let m = md(
            &[
                pkg("bins/access-gw-ldap", "access-gw-ldap"),
                pkg("crates/identity-edge", "access-identity-edge"),
                pkg("crates/store", "access-store"),
            ],
            &[
                (id("bins/access-gw-ldap"), id("crates/identity-edge"), None),
                (id("crates/identity-edge"), id("crates/store"), None),
            ],
        );
        let v = check_metadata(Path::new("/ws"), &m);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].message.contains("access-store"));
    }

    // IDI-11
    #[test]
    fn idi_11_the_edge_core_links_no_plane_write_crate() {
        for name in [
            "access-authority-core",
            "access-identity-signer",
            "access-identity-account",
        ] {
            let m = md(
                &[
                    pkg("crates/edge-core", "access-edge-core"),
                    pkg("crates/x", name),
                ],
                &[(id("crates/edge-core"), id("crates/x"), None)],
            );
            assert_eq!(check_metadata(Path::new("/ws"), &m).len(), 1, "{name}");
        }
        let dev = md(
            &[
                pkg("crates/edge-core", "access-edge-core"),
                pkg("crates/store", "access-store"),
            ],
            &[(id("crates/edge-core"), id("crates/store"), Some("dev"))],
        );
        assert!(check_metadata(Path::new("/ws"), &dev).is_empty());
    }

    // OP-155 m.3 (d)
    #[test]
    fn only_the_parser_worker_links_xml() {
        let m = md(
            &[
                pkg(WORKER, "access-parser-worker"),
                pkg("bins/access-gw-saml", "access-gw-saml"),
                pkg("crates/identity-saml", "access-identity-saml"),
                registry("quick-xml"),
                registry("bergshamra-c14n"),
            ],
            &[
                (id(WORKER), reg_id("quick-xml"), None),
                (id(WORKER), reg_id("bergshamra-c14n"), None),
                (id("crates/identity-saml"), reg_id("quick-xml"), None),
                (id("bins/access-gw-saml"), reg_id("bergshamra-c14n"), None),
            ],
        );
        let v = check_metadata(Path::new("/ws"), &m);
        assert_eq!(v.len(), 2, "{v:?}");
        assert!(v.iter().all(|x| !x.path.starts_with(WORKER)));
    }

    // MD-18
    #[test]
    fn the_parser_worker_links_no_plane_crate() {
        let m = md(
            &[
                pkg(WORKER, "access-parser-worker"),
                pkg("crates/identity-oauth", "access-identity-oauth"),
            ],
            &[(id(WORKER), id("crates/identity-oauth"), None)],
        );
        assert_eq!(check_metadata(Path::new("/ws"), &m).len(), 1);
    }
}
