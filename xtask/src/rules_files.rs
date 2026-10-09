//! Repository file walking shared by the rule checks.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories never scanned by the source rules: build output, VCS data,
/// local-only docs, third-party code and package caches.
const SKIP_DIRS: &[&str] = &["target", ".git", "docs", "node_modules", "vendor"];

/// Hidden directories that hold repository configuration and are scanned.
const SCANNED_HIDDEN_DIRS: &[&str] = &[".github", ".cargo", ".githooks", ".semgrep", ".config"];

/// Lists every file under `root` (sorted), skipping [`SKIP_DIRS`] and hidden
/// directories other than [`SCANNED_HIDDEN_DIRS`].
pub(crate) fn walk(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    walk_into(root, root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk_into(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if kind.is_dir() {
            let at_root = dir == root;
            let skipped = SKIP_DIRS.contains(&name.as_str())
                || (name.starts_with('.') && !SCANNED_HIDDEN_DIRS.contains(&name.as_str()));
            if skipped && (at_root || !matches!(name.as_str(), "docs" | "vendor")) {
                continue;
            }
            walk_into(root, &path, out)?;
        } else if kind.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

/// `path` relative to `root`, with `/` separators.
pub(crate) fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// True for Rust files that only build in test or bench configurations.
pub(crate) fn is_test_file(rel_path: &str) -> bool {
    let parts: Vec<&str> = rel_path.split('/').collect();
    parts.iter().any(|p| matches!(*p, "tests" | "benches"))
        || parts
            .last()
            .is_some_and(|f| *f == "tests.rs" || f.ends_with("_tests.rs"))
}

/// Reads a file as UTF-8.
pub(crate) fn read(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integration_tests_and_test_modules_count_as_test_files() {
        assert!(is_test_file("crates/http/tests/router.rs"));
        assert!(is_test_file("crates/kernel/src/tests.rs"));
        assert!(!is_test_file("crates/kernel/src/testkit.rs"));
    }
}
