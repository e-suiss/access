//! Supply-chain checks (§14.7 F-1…F-3, SA-32, SA-34, OP-4, §14.6).

#[path = "supply_cooldown.rs"]
mod cooldown;
#[path = "supply_metadata.rs"]
pub(crate) mod metadata;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::rules::files::{read, rel, walk};
use crate::{Check, Violation};
use cooldown::parse_lock;

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "lockfiles",
            run: check_lockfiles,
        },
        Check {
            name: "no-backtracking-regex",
            run: check_backtracking_regex,
        },
        Check {
            name: "no-io-uring",
            run: check_io_uring,
        },
        Check {
            name: "serde-json-depth",
            run: check_serde_json_depth,
        },
        Check {
            name: "build-rs-allowlist",
            run: check_build_rs,
        },
        Check {
            name: "vendored-ide-files",
            run: check_vendored_ide_files,
        },
        Check {
            name: "actions-pinned",
            run: check_actions_pinned,
        },
        Check {
            name: "cooldown",
            run: cooldown::check,
        },
    ]
}

fn v(rule: &'static str, path: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

/// SA-32: only linear-time regex engines.
const BACKTRACKING_REGEX: &[&str] = &["fancy-regex", "pcre2", "pcre2-sys", "onig", "onig_sys"];

/// OP-4, SA-22: `io_uring` bypasses seccomp; it is not used.
const IO_URING: &[&str] = &["io-uring", "tokio-uring", "rio", "glommio", "monoio"];

/// Locked packages whose name is in `banned`.
pub(crate) fn banned_in_lock(
    lock: &str,
    banned: &[&str],
    rule: &'static str,
    why: &str,
) -> Result<Vec<Violation>, String> {
    Ok(parse_lock(lock)?
        .into_iter()
        .filter(|p| banned.contains(&p.name.as_str()))
        .map(|p| {
            v(
                rule,
                "Cargo.lock",
                format!("`{}` {} is banned: {why}", p.name, p.version),
            )
        })
        .collect())
}

fn check_backtracking_regex(root: &Path) -> Result<Vec<Violation>, String> {
    banned_in_lock(
        &read(&root.join("Cargo.lock"))?,
        BACKTRACKING_REGEX,
        "no-backtracking-regex",
        "backtracking regex engines allow ReDoS (SA-32)",
    )
}

fn check_io_uring(root: &Path) -> Result<Vec<Violation>, String> {
    banned_in_lock(
        &read(&root.join("Cargo.lock"))?,
        IO_URING,
        "no-io-uring",
        "io_uring is forbidden (OP-4, SA-22)",
    )
}

/// §14.6: JSON nesting stays bounded; `unbounded_depth` turns the limit off.
pub(crate) fn serde_json_depth(md: &metadata::Metadata) -> Vec<Violation> {
    md.packages
        .iter()
        .filter(|p| p.name == "serde_json")
        .filter(|p| {
            md.features
                .get(&p.id)
                .is_some_and(|f| f.iter().any(|x| x == "unbounded_depth"))
        })
        .map(|p| {
            v(
                "serde-json-depth",
                "Cargo.lock",
                format!(
                    "serde_json {} has `unbounded_depth` enabled (§14.6)",
                    p.version
                ),
            )
        })
        .collect()
}

fn check_serde_json_depth(root: &Path) -> Result<Vec<Violation>, String> {
    let md = metadata::load(root)?;
    Ok(serde_json_depth(&md))
}

/// F-2: every package with a build script is reviewed and listed here.
const BUILD_RS_ALLOWLIST: &str = "supply-chain/build-rs-allowlist.txt";

/// Compares packages with build scripts to the allowlist: new ones and stale
/// entries both fail, so the list always equals the reviewed set.
pub(crate) fn build_rs_diff(md: &metadata::Metadata, allowlist: &str) -> Vec<Violation> {
    let listed: BTreeSet<String> = allowlist
        .lines()
        .map(|l| l.split('#').next().unwrap_or_default().trim())
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    let actual: BTreeSet<String> = md
        .packages
        .iter()
        .filter(|p| p.has_build_script)
        .map(|p| p.name.clone())
        .collect();
    let new = actual.difference(&listed).map(|n| {
        v(
            "build-rs-allowlist",
            BUILD_RS_ALLOWLIST,
            format!("`{n}` has a build script that was not reviewed (F-2); review it and add it"),
        )
    });
    let stale = listed.difference(&actual).map(|n| {
        v(
            "build-rs-allowlist",
            BUILD_RS_ALLOWLIST,
            format!("`{n}` no longer has a build script; remove it"),
        )
    });
    new.chain(stale).collect()
}

fn check_build_rs(root: &Path) -> Result<Vec<Violation>, String> {
    let path = root.join(BUILD_RS_ALLOWLIST);
    let allowlist = if path.exists() {
        read(&path)?
    } else {
        String::new()
    };
    Ok(build_rs_diff(&*metadata::load(root)?, &allowlist))
}

/// F-2 (`PolinRider` class): editor and hook configuration inside vendored
/// sources can run code on a developer machine.
const IDE_DIRS: &[&str] = &[".vscode", ".devcontainer", ".githooks", ".idea"];

fn find_ide_dirs(dir: &Path, root: &Path, out: &mut Vec<Violation>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if IDE_DIRS.contains(&name.as_str()) {
                out.push(v(
                    "vendored-ide-files",
                    &rel(root, &path),
                    "IDE or hook directory in vendored sources (F-2)".to_owned(),
                ));
            }
            find_ide_dirs(&path, root, out)?;
        }
    }
    Ok(())
}

pub(crate) fn check_vendored_ide_files(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let vendor = root.join("vendor");
    if vendor.is_dir() {
        find_ide_dirs(&vendor, root, &mut out)?;
    }
    Ok(out)
}

/// Checks `uses:` lines of a workflow or action file: a 40-hex commit SHA and a
/// version comment, or a local `./` action.
pub(crate) fn unpinned_uses(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start().trim_start_matches("- ").trim_start();
        let Some(rest) = trimmed.strip_prefix("uses:") else {
            continue;
        };
        let (value, comment) = rest
            .split_once('#')
            .map_or((rest, ""), |(a, b)| (a, b.trim()));
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if value.starts_with("./") {
            continue;
        }
        let at = format!("{rel_path}:{}", i.saturating_add(1));
        let pinned = value.rsplit_once('@').is_some_and(|(_, r)| {
            r.len() == 40
                && r.chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        });
        let docker_pinned = value.starts_with("docker://") && value.contains("@sha256:");
        if !(pinned || docker_pinned) {
            out.push(v(
                "actions-pinned",
                &at,
                format!("`{value}` must be pinned to a full commit SHA (F-2)"),
            ));
        } else if comment.is_empty() {
            out.push(v(
                "actions-pinned",
                &at,
                format!("`{value}` needs a `# vX.Y.Z` version comment (F-2)"),
            ));
        }
    }
    out
}

fn check_actions_pinned(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        let in_scope =
            rel_path.starts_with(".github/workflows/") || rel_path.starts_with(".github/actions/");
        let yaml = path.extension().is_some_and(|e| e == "yml" || e == "yaml");
        if in_scope && yaml {
            out.extend(unpinned_uses(&rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

/// `Cargo.lock` is committed; every npm package has a `package-lock.json` in
/// its directory or an ancestor (npm workspaces keep one at the root, OP-83).
pub(crate) fn missing_lockfiles(files: &[String]) -> Vec<Violation> {
    let mut out = Vec::new();
    if !files.iter().any(|f| f == "Cargo.lock") {
        out.push(v(
            "lockfiles",
            "Cargo.lock",
            "Cargo.lock is missing (F-2)".to_owned(),
        ));
    }
    for pkg in files
        .iter()
        .filter(|f| f.rsplit('/').next() == Some("package.json"))
    {
        let mut dir = pkg.rsplit_once('/').map_or("", |(d, _)| d);
        let found = loop {
            let lock = if dir.is_empty() {
                "package-lock.json".to_owned()
            } else {
                format!("{dir}/package-lock.json")
            };
            if files.contains(&lock) {
                break true;
            }
            if dir.is_empty() {
                break false;
            }
            dir = dir.rsplit_once('/').map_or("", |(d, _)| d);
        };
        if !found {
            out.push(v(
                "lockfiles",
                pkg,
                "package.json without a package-lock.json (OP-83, F-1)".to_owned(),
            ));
        }
    }
    out
}

fn check_lockfiles(root: &Path) -> Result<Vec<Violation>, String> {
    let files: Vec<String> = walk(root)?.iter().map(|p| rel(root, p)).collect();
    Ok(missing_lockfiles(&files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use metadata::fixture::{external, member, metadata as md_json};
    use metadata::parse;

    #[test]
    fn backtracking_regex_engine_in_lockfile_is_rejected() {
        let lock = "[[package]]\nname = \"fancy-regex\"\nversion = \"0.14.0\"\n[[package]]\nname = \"regex\"\nversion = \"1.0.0\"\n";
        assert_eq!(
            banned_in_lock(lock, BACKTRACKING_REGEX, "r", "x")
                .unwrap_or_default()
                .len(),
            1
        );
    }

    #[test]
    fn io_uring_in_lockfile_is_rejected() {
        let lock = "[[package]]\nname = \"tokio-uring\"\nversion = \"0.5.0\"\n";
        assert_eq!(
            banned_in_lock(lock, IO_URING, "r", "x")
                .unwrap_or_default()
                .len(),
            1
        );
    }

    #[test]
    fn serde_json_with_unbounded_depth_is_rejected() {
        let pkg = external("serde_json", "1.0.0", false);
        let id = "registry+https://github.com/rust-lang/crates.io-index#serde_json@1.0.0";
        let md = parse(&md_json(
            std::slice::from_ref(&pkg),
            &[(id, &["std", "unbounded_depth"])],
        ))
        .unwrap_or_default();
        assert_eq!(serde_json_depth(&md).len(), 1);
        let md = parse(&md_json(&[pkg], &[(id, &["std"])])).unwrap_or_default();
        assert!(serde_json_depth(&md).is_empty());
    }

    #[test]
    fn new_build_script_and_stale_entry_are_both_reported() {
        let md = parse(&md_json(
            &[
                external("libc", "0.2.0", true),
                external("serde", "1.0.0", false),
                member("crates/kernel", &[]),
            ],
            &[],
        ))
        .unwrap_or_default();
        let diff = build_rs_diff(&md, "# reviewed\nproc-macro2\n");
        assert_eq!(diff.len(), 2);
        assert!(build_rs_diff(&md, "libc\n").is_empty());
    }

    #[test]
    fn action_pinned_to_tag_is_rejected() {
        let wf = "steps:\n  - uses: actions/checkout@v5\n  - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0\n  - uses: ./.github/actions/setup\n";
        let v = unpinned_uses("ci.yml", wf);
        assert_eq!(v.len(), 1);
        assert!(v.first().is_some_and(|x| x.path.ends_with("ci.yml:2")));
    }

    #[test]
    fn pinned_action_without_version_comment_is_rejected() {
        let wf = "- uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8\n";
        assert_eq!(unpinned_uses("ci.yml", wf).len(), 1);
    }

    #[test]
    fn npm_package_without_lockfile_is_rejected() {
        let files = vec![
            "Cargo.lock".to_owned(),
            "web/console/package.json".to_owned(),
        ];
        assert_eq!(missing_lockfiles(&files).len(), 1);
        let mut with_root_lock = files;
        with_root_lock.push("package-lock.json".to_owned());
        assert!(missing_lockfiles(&with_root_lock).is_empty());
    }

    #[test]
    fn missing_cargo_lock_is_rejected() {
        assert_eq!(missing_lockfiles(&[]).len(), 1);
    }
}
