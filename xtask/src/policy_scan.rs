//! Text scans over the repository's own files for boundaries that are configuration,
//! not code:

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::{Check, Violation};

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "no-nightly-hardening",
            run: no_nightly_hardening,
        },
        Check {
            name: "image-sources",
            run: image_sources,
        },
        Check {
            name: "no-flaky-retries",
            run: no_flaky_retries,
        },
        Check {
            name: "out-of-scope-owner",
            run: out_of_scope_owner,
        },
        Check {
            name: "normative-standards",
            run: normative_standards,
        },
    ]
}

/// Tracked and not-ignored files, relative to the root. `docs/` is excluded by
/// `.git/info/exclude`, so the local spec is never scanned.
pub(crate) fn repo_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|f| root.join(f).is_file())
        .map(str::to_owned)
        .collect())
}

fn read(root: &Path, file: &str) -> String {
    std::fs::read_to_string(root.join(file)).unwrap_or_default()
}

fn violation(rule: &'static str, file: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{file}:{}", line.saturating_add(1))),
        message,
    }
}

fn is_config(file: &str) -> bool {
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.starts_with("dockerfile")
        || name == "justfile"
        || [".toml", ".yml", ".yaml", ".sh", ".json"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

/// Files that may run sanitizers: the weekly job and the recipe it calls (SA-23).
const SANITIZER_FILES: &[&str] = &[".github/workflows/weekly.yml", "justfile"];

fn nightly_hardening_findings(file: &str, text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("stack-protector") || lower.contains("sanitizer=cfi") {
            found.push((
                n,
                "nightly stack protector / CFI is not used (SA-23)".to_owned(),
            ));
        } else if lower.contains("-zsanitizer") && !SANITIZER_FILES.contains(&file) {
            found.push((
                n,
                "sanitizers run only in the weekly job (SA-23)".to_owned(),
            ));
        }
        if (lower.contains("runtimeclassname") || lower.contains("runtime:"))
            && (lower.contains("gvisor") || lower.contains("runsc"))
        {
            found.push((n, "gVisor is not the default runtime (SA-24)".to_owned()));
        }
    }
    found
}

fn no_nightly_hardening(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)?.iter().filter(|f| is_config(f)) {
        for (n, message) in nightly_hardening_findings(file, &read(root, file)) {
            out.push(violation("SA-23", file, n, message));
        }
    }
    Ok(out)
}

/// Third-party image catalogs that OP-49 rules out.
const IMAGE_CATALOGS: &[&str] = &["bitnami/", "bitnamilegacy/", "bitnamicharts/"];

/// Prefix of images that `just dev` builds locally from Dockerfiles in this repository.
const LOCAL_IMAGE_PREFIX: &str = "access-dev/";

/// Returns the image reference on a `FROM` / `image:` line, if any.
fn image_reference(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("FROM ")
        .or_else(|| trimmed.strip_prefix("from "))
        .or_else(|| trimmed.strip_prefix("image:"))
        .or_else(|| trimmed.strip_prefix("- image:"))?;
    let reference = rest
        .split_whitespace()
        .find(|part| !part.starts_with("--"))?
        .trim_matches(|c| c == '"' || c == '\'');
    Some(reference)
}

fn image_findings(text: &str, is_dockerfile: bool) -> Vec<(usize, String)> {
    let mut stages: Vec<String> = Vec::new();
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let Some(reference) = image_reference(line) else {
            continue;
        };
        if is_dockerfile && let Some((_, alias)) = line.to_ascii_lowercase().split_once(" as ") {
            stages.push(alias.trim().to_owned());
        }
        let lower = reference.to_ascii_lowercase();
        if lower == "scratch"
            || stages.contains(&lower)
            || lower.starts_with('$')
            || lower.starts_with(LOCAL_IMAGE_PREFIX)
        {
            continue;
        }
        if IMAGE_CATALOGS.iter().any(|c| lower.contains(c)) {
            found.push((
                n,
                format!("`{reference}`: no third-party image catalogs (OP-49)"),
            ));
        } else if !reference.contains("@sha256:") {
            found.push((n, format!("`{reference}` is not pinned by digest (OP-49)")));
        }
    }
    found
}

fn image_sources(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let name = Path::new(&file)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_dockerfile = name.starts_with("dockerfile");
        let in_scope = is_dockerfile
            || (file.starts_with("deploy/")
                && Path::new(&name)
                    .extension()
                    .is_some_and(|e| e == "yaml" || e == "yml"))
            || file.starts_with(".github/");
        if !in_scope {
            continue;
        }
        for (n, message) in image_findings(&read(root, &file), is_dockerfile) {
            out.push(violation("OP-49", &file, n, message));
        }
    }
    Ok(out)
}

fn retry_findings(file: &str, text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = compact.to_ascii_lowercase();
        let nonzero_setting = lower
            .strip_prefix("retries=")
            .is_some_and(|value| value.trim_start_matches('"') != "0" && !value.starts_with('0'));
        let nonzero_flag = lower
            .split("--retries")
            .nth(1)
            .is_some_and(|value| !value.trim_start_matches('=').starts_with('0'));
        let retry_action =
            file.starts_with(".github/") && lower.contains("uses:") && lower.contains("retry");
        if nonzero_setting || nonzero_flag || retry_action {
            found.push((
                n,
                "flaky tests are quarantined, never retried until green (SA-59)".to_owned(),
            ));
        }
    }
    found
}

fn no_flaky_retries(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)?.iter().filter(|f| is_config(f)) {
        for (n, message) in retry_findings(file, &read(root, file)) {
            out.push(violation("SA-59", file, n, message));
        }
    }
    Ok(out)
}

fn out_of_scope_findings(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let lower = line.to_ascii_lowercase();
            (lower.contains("out of scope") || lower.contains("out-of-scope"))
                && !lower.contains("owned by")
        })
        .map(|(n, _)| n)
        .collect()
}

fn out_of_scope_owner(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let is_text = [".md", ".tsx", ".ts", ".rs", ".html"]
            .iter()
            .any(|ext| file.ends_with(ext));
        if !is_text || file.starts_with("xtask/") {
            continue;
        }
        for n in out_of_scope_findings(&read(root, &file)) {
            out.push(violation(
                "E33",
                &file,
                n,
                "\"out of scope\" only for a real external owner (say \"owned by …\"); otherwise name the plane or layer".to_owned(),
            ));
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Standards {
    standard: Vec<Standard>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Standard {
    id: String,
    title: String,
    status: String,
    normative: bool,
    used_by: Vec<String>,
}

const STANDARDS_FILE: &str = "conformance/catalog/standards.toml";

fn standards_findings(standards: &Standards) -> Vec<String> {
    let mut found = Vec::new();
    for s in &standards.standard {
        if s.id.is_empty() || s.title.is_empty() || s.used_by.is_empty() {
            found.push(format!("`{}`: id, title and used_by are required", s.id));
        }
        match s.status.as_str() {
            "published" => {}
            "draft" if !s.normative => {}
            "draft" => found.push(format!(
                "`{}` is a draft and must not be a normative dependency (§9.4.2, L27)",
                s.id
            )),
            other => found.push(format!("`{}`: unknown status `{other}`", s.id)),
        }
    }
    found
}

fn normative_standards(root: &Path) -> Result<Vec<Violation>, String> {
    let text = std::fs::read_to_string(root.join(STANDARDS_FILE))
        .map_err(|e| format!("{STANDARDS_FILE}: {e}"))?;
    let standards: Standards =
        toml::from_str(&text).map_err(|e| format!("{STANDARDS_FILE}: {e}"))?;
    Ok(standards_findings(&standards)
        .into_iter()
        .map(|message| Violation {
            rule: "L27",
            path: PathBuf::from(STANDARDS_FILE),
            message,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    // SA-23
    #[test]
    fn sa_23_stack_protector_flag_is_rejected() {
        let found = nightly_hardening_findings(
            ".cargo/config.toml",
            "rustflags = [\"-Zstack-protector=all\"]",
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn sa_23_sanitizer_outside_weekly_job_is_rejected() {
        let flag = "RUSTFLAGS=-Zsanitizer=address";
        assert_eq!(
            nightly_hardening_findings(".github/workflows/ci.yml", flag).len(),
            1
        );
        assert_eq!(
            nightly_hardening_findings(".github/workflows/weekly.yml", flag).len(),
            0
        );
    }

    // SA-24
    #[test]
    fn sa_24_gvisor_runtime_class_is_rejected() {
        assert_eq!(
            nightly_hardening_findings("deploy/k8s/x.yaml", "runtimeClassName: gvisor").len(),
            1
        );
    }

    // OP-49
    #[test]
    fn op_49_bitnami_image_is_rejected() {
        let found = image_findings("    image: bitnami/postgresql@sha256:abc", false);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn op_49_unpinned_image_is_rejected_but_build_stage_is_not() {
        let dockerfile = "FROM rust:1.99@sha256:abc AS build\nFROM build AS chef\nFROM gcr.io/distroless/cc:nonroot\n";
        let found = image_findings(dockerfile, true);
        assert_eq!(found.len(), 1);
        assert!(found[0].1.contains("distroless"));
    }

    // SA-59
    #[test]
    fn sa_59_nonzero_retries_are_rejected() {
        assert_eq!(
            retry_findings(".config/nextest.toml", "retries = 2").len(),
            1
        );
        assert_eq!(
            retry_findings(".config/nextest.toml", "retries = 0").len(),
            0
        );
        assert_eq!(
            retry_findings("justfile", "cargo nextest run --retries 3").len(),
            1
        );
        assert_eq!(
            retry_findings(".github/workflows/ci.yml", "uses: nick-fields/retry@abc").len(),
            1
        );
    }

    // E33
    #[test]
    fn e_33_out_of_scope_without_owner_is_rejected() {
        assert_eq!(out_of_scope_findings("Billing is out of scope.").len(), 1);
        assert_eq!(
            out_of_scope_findings("Payroll is out of scope (owned by the HR system).").len(),
            0
        );
    }

    // L27
    #[test]
    fn l_27_normative_draft_is_rejected() {
        let standards = Standards {
            standard: vec![
                Standard {
                    id: "draft-x".into(),
                    title: "X".into(),
                    status: "draft".into(),
                    normative: true,
                    used_by: vec!["kernel".into()],
                },
                Standard {
                    id: "draft-y".into(),
                    title: "Y".into(),
                    status: "draft".into(),
                    normative: false,
                    used_by: vec!["release".into()],
                },
            ],
        };
        let found = standards_findings(&standards);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("draft-x"));
    }
}
