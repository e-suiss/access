//! Project policy checks: open-source and business-model boundaries, and the
//! structure rules that are not about code purity.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Check, Violation};

#[path = "policy_scan.rs"]
mod scan;

pub(crate) fn checks() -> Vec<Check> {
    let mut all = vec![
        Check {
            name: "no-paid-features",
            run: no_paid_features,
        },
        Check {
            name: "license",
            run: license,
        },
        Check {
            name: "no-adr-folder",
            run: no_adr_folder,
        },
        Check {
            name: "component-layers",
            run: component_layers,
        },
    ];
    all.extend(scan::checks());
    all
}

/// Words that would mark a paid or closed tier.
const PAID_MARKERS: &[&str] = &[
    "enterprise",
    "premium",
    "paid",
    "commercial",
    "license_key",
    "licence_key",
    "pro_only",
    "paywall",
];

/// Component crates that must follow the OP-63 layer split.
const COMPONENT_PREFIXES: &[&str] = &["authority-", "identity-"];

fn metadata(root: &Path) -> Result<serde_json::Value, String> {
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
        .args(["metadata", "--no-deps", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    serde_json::from_slice(&output.stdout).map_err(|e| format!("cargo metadata output: {e}"))
}

static NULL: serde_json::Value = serde_json::Value::Null;

/// `value[key]` without the panicking index operator (OP-3 lints).
fn field<'a>(value: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    value.get(key).unwrap_or(&NULL)
}

fn packages(metadata: &serde_json::Value) -> impl Iterator<Item = &serde_json::Value> {
    field(metadata, "packages").as_array().into_iter().flatten()
}

fn manifest_path(package: &serde_json::Value) -> PathBuf {
    PathBuf::from(field(package, "manifest_path").as_str().unwrap_or_default())
}

/// Returns the paid-tier marker contained in `name`, if any.
fn paid_marker(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase().replace('-', "_");
    PAID_MARKERS.iter().copied().find(|marker| {
        lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| {
                word == *marker
                    || word.starts_with(&format!("{marker}_"))
                    || word.ends_with(&format!("_{marker}"))
            })
    })
}

fn no_paid_features(root: &Path) -> Result<Vec<Violation>, String> {
    let metadata = metadata(root)?;
    let mut violations = Vec::new();
    for package in packages(&metadata) {
        let name = field(package, "name").as_str().unwrap_or_default();
        let path = manifest_path(package);
        if let Some(marker) = paid_marker(name) {
            violations.push(paid_violation(&path, &format!("package `{name}`"), marker));
        }
        for feature in field(package, "features")
            .as_object()
            .into_iter()
            .flat_map(|f| f.keys())
        {
            if let Some(marker) = paid_marker(feature) {
                violations.push(paid_violation(
                    &path,
                    &format!("feature `{feature}`"),
                    marker,
                ));
            }
        }
    }
    violations.extend(npm_packages_paid(root)?);
    Ok(violations)
}

/// OP-97: every npm package is independent; scan each `package.json` under `web/` and `sdks/`.
fn npm_packages_paid(root: &Path) -> Result<Vec<Violation>, String> {
    let mut violations = Vec::new();
    let mut manifests = Vec::new();
    for dir in ["web", "sdks"] {
        let base = root.join(dir);
        if !base.is_dir() {
            continue;
        }
        for entry in walk(&base) {
            if entry.file_name().is_some_and(|n| n == "package.json")
                && !entry.components().any(|c| c.as_os_str() == "node_modules")
            {
                manifests.push(entry);
            }
        }
    }
    for manifest in manifests {
        let text = std::fs::read_to_string(&manifest)
            .map_err(|e| format!("{}: {e}", manifest.display()))?;
        let json: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", manifest.display()))?;
        if let Some(name) = field(&json, "name").as_str()
            && let Some(marker) = paid_marker(name)
        {
            violations.push(paid_violation(
                &manifest,
                &format!("npm package `{name}`"),
                marker,
            ));
        }
    }
    Ok(violations)
}

fn paid_violation(path: &Path, what: &str, marker: &str) -> Violation {
    Violation {
        rule: "D4/B3",
        path: path.to_path_buf(),
        message: format!("{what} contains `{marker}`: Access has no closed or paid edition"),
    }
}

fn license(root: &Path) -> Result<Vec<Violation>, String> {
    let metadata = metadata(root)?;
    let mut violations = Vec::new();
    for package in packages(&metadata) {
        let license = field(package, "license").as_str().unwrap_or_default();
        if license != "Apache-2.0" {
            violations.push(Violation {
                rule: "D4",
                path: manifest_path(package),
                message: format!(
                    "package `{}` has license `{license}`; every package is Apache-2.0",
                    field(package, "name").as_str().unwrap_or_default()
                ),
            });
        }
    }
    let license_file = std::fs::read_to_string(root.join("LICENSE")).unwrap_or_default();
    if !license_file.contains("Apache License") || !license_file.contains("Version 2.0") {
        violations.push(Violation {
            rule: "D4",
            path: root.join("LICENSE"),
            message: "LICENSE must be the Apache License 2.0".to_owned(),
        });
    }
    Ok(violations)
}

fn no_adr_folder(root: &Path) -> Result<Vec<Violation>, String> {
    let files = scan::repo_files(root)?;
    Ok(adr_paths(files.iter().map(String::as_str))
        .into_iter()
        .map(|path| Violation {
            rule: "OP-70",
            path,
            message: "no ADR folder: the spec decision registers are the decision record"
                .to_owned(),
        })
        .collect())
}

fn adr_paths<'a>(files: impl Iterator<Item = &'a str>) -> Vec<PathBuf> {
    files
        .filter(|file| {
            Path::new(file).components().any(|c| {
                let part = c.as_os_str().to_string_lossy().to_ascii_lowercase();
                part == "adr" || part == "adrs" || part == "decisions"
            })
        })
        .map(PathBuf::from)
        .collect()
}

fn component_layers(root: &Path) -> Result<Vec<Violation>, String> {
    let crates_dir = root.join("crates");
    let mut violations = Vec::new();
    let entries =
        std::fs::read_dir(&crates_dir).map_err(|e| format!("{}: {e}", crates_dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !COMPONENT_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
        {
            continue;
        }
        let src = entry.path().join("src");
        for layer in missing_layers(&src) {
            violations.push(Violation {
                rule: "OP-63",
                path: src.clone(),
                message: format!("component crate `{name}` has no `{layer}` module"),
            });
        }
    }
    Ok(violations)
}

fn missing_layers(src: &Path) -> Vec<&'static str> {
    ["domain", "ports", "app"]
        .into_iter()
        .filter(|layer| {
            !src.join(format!("{layer}.rs")).exists() && !src.join(layer).join("mod.rs").exists()
        })
        .collect()
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n != "node_modules" && n != "target")
                {
                    stack.push(path);
                }
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // D4, B3
    #[test]
    fn enterprise_feature_name_is_rejected() {
        assert_eq!(paid_marker("enterprise"), Some("enterprise"));
        assert_eq!(paid_marker("enterprise-sso"), Some("enterprise"));
        assert_eq!(paid_marker("sso_premium"), Some("premium"));
        assert_eq!(paid_marker("license-key"), Some("license_key"));
    }

    #[test]
    fn ordinary_names_are_accepted() {
        for name in [
            "std",
            "verify",
            "access-server",
            "suiss-crypto",
            "prepaid_budget_view",
            "sso",
        ] {
            assert_eq!(paid_marker(name), None, "{name}");
        }
    }

    // OP-70
    #[test]
    fn adr_directory_is_rejected() {
        let found = adr_paths(
            [
                "README.md",
                "docs/adr/0001-x.md",
                "crates/kernel/src/lib.rs",
                "Decisions/x.md",
            ]
            .into_iter(),
        );
        assert_eq!(
            found,
            vec![
                PathBuf::from("docs/adr/0001-x.md"),
                PathBuf::from("Decisions/x.md")
            ]
        );
    }

    // OP-63
    #[test]
    fn component_crate_without_layers_is_reported() {
        let dir = std::env::temp_dir().join(format!("xtask-layers-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/domain.rs"), "").unwrap();
        assert_eq!(missing_layers(&dir.join("src")), vec!["ports", "app"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
