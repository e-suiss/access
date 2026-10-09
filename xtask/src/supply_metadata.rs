//! `cargo metadata` loading shared by the dependency and supply-chain checks.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

use serde_json::Value;

/// How a dependency is used. Dev-dependencies never reach a shipped artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DepKind {
    Normal,
    Dev,
    Build,
}

/// One declared dependency of a package.
#[derive(Debug, Clone)]
pub(crate) struct Dep {
    /// The depended-on package's name (not a rename).
    pub(crate) name: String,
    pub(crate) kind: DepKind,
    /// Set for path dependencies (workspace crates).
    pub(crate) path: Option<PathBuf>,
}

/// One package in the resolved graph.
#[derive(Debug, Clone)]
pub(crate) struct Package {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) manifest_path: PathBuf,
    pub(crate) deps: Vec<Dep>,
    pub(crate) has_build_script: bool,
    /// Source files of the package's lib and bin targets (crate roots).
    pub(crate) crate_roots: Vec<PathBuf>,
}

impl Package {
    /// The directory holding `Cargo.toml`.
    pub(crate) fn dir(&self) -> &Path {
        self.manifest_path.parent().unwrap_or(&self.manifest_path)
    }
}

/// The parts of `cargo metadata` the checks use.
#[derive(Debug, Default)]
pub(crate) struct Metadata {
    pub(crate) packages: Vec<Package>,
    pub(crate) workspace_members: Vec<String>,
    /// Enabled features per package id, over all platforms.
    pub(crate) features: BTreeMap<String, Vec<String>>,
}

impl Metadata {
    /// Workspace member packages.
    pub(crate) fn members(&self) -> impl Iterator<Item = &Package> {
        self.packages
            .iter()
            .filter(|p| self.workspace_members.contains(&p.id))
    }
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Parses `cargo metadata --format-version 1` output.
pub(crate) fn parse(json: &str) -> Result<Metadata, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("cargo metadata: {e}"))?;
    let mut md = Metadata::default();
    for p in v
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let deps = p
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|d| Dep {
                name: str_field(d, "name"),
                kind: match d.get("kind").and_then(Value::as_str) {
                    Some("dev") => DepKind::Dev,
                    Some("build") => DepKind::Build,
                    _ => DepKind::Normal,
                },
                path: d.get("path").and_then(Value::as_str).map(PathBuf::from),
            })
            .collect();
        let targets: Vec<&Value> = p
            .get("targets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .collect();
        let kinds = |t: &Value| -> Vec<String> {
            t.get("kind")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        let has_build_script = targets
            .iter()
            .any(|t| kinds(t).iter().any(|k| k == "custom-build"));
        let crate_roots = targets
            .iter()
            .filter(|t| {
                kinds(t).iter().any(|k| {
                    matches!(
                        k.as_str(),
                        "lib" | "bin" | "rlib" | "cdylib" | "staticlib" | "proc-macro"
                    )
                })
            })
            .map(|t| PathBuf::from(str_field(t, "src_path")))
            .collect();
        md.packages.push(Package {
            id: str_field(p, "id"),
            name: str_field(p, "name"),
            version: str_field(p, "version"),
            manifest_path: PathBuf::from(str_field(p, "manifest_path")),
            deps,
            has_build_script,
            crate_roots,
        });
    }
    md.workspace_members = v
        .get("workspace_members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let nodes = v
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(Value::as_array);
    for node in nodes.into_iter().flatten() {
        let features = node
            .get("features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        md.features.insert(str_field(node, "id"), features);
    }
    Ok(md)
}

static CACHE: OnceLock<Result<Arc<Metadata>, String>> = OnceLock::new();

/// Runs `cargo metadata` once per process (offline, locked) and caches it.
pub(crate) fn load(root: &Path) -> Result<Arc<Metadata>, String> {
    CACHE
        .get_or_init(|| {
            let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
            let output = Command::new(cargo)
                .args(["metadata", "--format-version", "1", "--locked", "--offline"])
                .current_dir(root)
                .output()
                .map_err(|e| format!("cargo metadata: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "cargo metadata failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            let json =
                String::from_utf8(output.stdout).map_err(|e| format!("cargo metadata: {e}"))?;
            parse(&json).map(Arc::new)
        })
        .clone()
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Builds fake `cargo metadata` JSON for the unit tests.

    use serde_json::{Value, json};

    /// A workspace member at `/ws/<dir>` with path dependencies on other members.
    pub(crate) fn member(dir: &str, deps: &[(&str, Option<&str>)]) -> Value {
        let name = dir.rsplit('/').next().unwrap_or(dir);
        let deps: Vec<Value> = deps
            .iter()
            .map(|(dep_dir, kind)| {
                json!({
                    "name": dep_dir.rsplit('/').next().unwrap_or(dep_dir),
                    "kind": kind,
                    "path": format!("/ws/{dep_dir}"),
                })
            })
            .collect();
        json!({
            "id": format!("path+file:///ws/{dir}#{name}@0.0.0"),
            "name": name,
            "version": "0.0.0",
            "source": null,
            "manifest_path": format!("/ws/{dir}/Cargo.toml"),
            "dependencies": deps,
            "targets": [{"kind": ["lib"], "src_path": format!("/ws/{dir}/src/lib.rs")}],
        })
    }

    /// A registry package depended on by name.
    pub(crate) fn external(name: &str, version: &str, build_rs: bool) -> Value {
        let mut targets = vec![json!({"kind": ["lib"], "src_path": "/reg/src/lib.rs"})];
        if build_rs {
            targets.push(json!({"kind": ["custom-build"], "src_path": "/reg/build.rs"}));
        }
        json!({
            "id": format!("registry+https://github.com/rust-lang/crates.io-index#{name}@{version}"),
            "name": name,
            "version": version,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": format!("/reg/{name}/Cargo.toml"),
            "dependencies": [],
            "targets": targets,
        })
    }

    /// A metadata document; every `/ws/` package is a workspace member.
    pub(crate) fn metadata(packages: &[Value], features: &[(&str, &[&str])]) -> String {
        let members: Vec<Value> = packages
            .iter()
            .filter(|p| p.get("source").is_some_and(Value::is_null))
            .filter_map(|p| p.get("id").cloned())
            .collect();
        let nodes: Vec<Value> = features
            .iter()
            .map(|(id, f)| json!({"id": id, "features": f}))
            .collect();
        json!({
            "packages": packages,
            "workspace_members": members,
            "resolve": {"nodes": nodes},
        })
        .to_string()
    }
}
