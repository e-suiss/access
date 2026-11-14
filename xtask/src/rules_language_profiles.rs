//! `language-profiles` (MD-2, SA-20, OP-159 m.3 (dd)): every R-1…R-7 cell names an existing enforcing mechanism.
//!
//! - Every rule R-1…R-7 has exactly one cell for each of `rust`, `typescript` and `c-ffi`.
//! - A cell that applies names at least one mechanism, and every mechanism exists (see the
//!   kinds in the catalog's header); a cell that does not apply says why.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::test_layers;

pub(crate) const FILE: &str = "conformance/catalog/language-profiles.toml";

pub(crate) const LANGUAGES: [&str; 3] = ["rust", "typescript", "c-ffi"];

pub(crate) const RULES: u32 = 7;

/// The TypeScript projects an `eslint:`, `tsconfig:` or `npmrc:` mechanism must hold in: the
/// `web/` pnpm workspace, whose packages share its settings (OP-159 m.32), and the SDK, an
/// independent npm package (OP-97).
pub(crate) const TS_PACKAGES: [&str; 2] = ["web", "sdks/typescript"];

/// The `web/` workspace keeps the shared TypeScript settings in `tsconfig.base.json` and the
/// install settings in `pnpm-workspace.yaml`.
const WORKSPACE: &str = "web";

/// The `pnpm-workspace.yaml` lines that do what an `.npmrc` line does.
fn pnpm_lines(npmrc: &str) -> Option<&'static [&'static str]> {
    match npmrc {
        "ignore-scripts=true" => Some(&["strictDepBuilds: true", "allowBuilds: {}"]),
        "min-release-age=7" => Some(&["minimumReleaseAge: 10080"]),
        "save-exact=true" => Some(&["savePrefix: \"\""]),
        "engine-strict=true" => Some(&["engineStrict: true"]),
        _ => None,
    }
}

/// One cell of the profile table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cell {
    pub(crate) rule: String,
    pub(crate) language: String,
    #[serde(default)]
    pub(crate) mechanism: Vec<String>,
    #[serde(default = "yes")]
    pub(crate) applies: bool,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Profiles {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) cell: Vec<Cell>,
}

/// Answers whether a mechanism exists.
pub(crate) trait Mechanisms {
    /// `None` when `mechanism` exists, otherwise why not.
    fn missing(&self, mechanism: &str) -> Option<String>;
}

fn violation(message: String) -> Violation {
    Violation {
        rule: "MD-2",
        path: PathBuf::from(FILE),
        message,
    }
}

/// Pure validation, separated for tests.
pub(crate) fn violations(p: &Profiles, m: &dyn Mechanisms) -> Vec<Violation> {
    let mut out = Vec::new();
    if p.version != 1 {
        out.push(violation(format!("version {} is not 1", p.version)));
    }
    let mut seen: BTreeMap<(u32, &str), usize> = BTreeMap::new();
    for c in &p.cell {
        let name = format!("{} × {}", c.rule, c.language);
        let Some(n) = c
            .rule
            .strip_prefix("R-")
            .and_then(|n| n.parse::<u32>().ok())
            .filter(|n| (1..=RULES).contains(n))
        else {
            out.push(violation(format!("{name}: not a rule R-1…R-{RULES}")));
            continue;
        };
        let Some(lang) = LANGUAGES.iter().find(|l| **l == c.language) else {
            out.push(violation(format!(
                "{name}: language is not one of {LANGUAGES:?}"
            )));
            continue;
        };
        let k = seen.entry((n, lang)).or_default();
        *k = k.saturating_add(1);
        if c.applies {
            if c.mechanism.is_empty() {
                out.push(violation(format!("{name}: names no mechanism")));
            }
            if c.reason.is_some() {
                out.push(violation(format!(
                    "{name}: a reason only goes with applies = false"
                )));
            }
            for mech in &c.mechanism {
                if let Some(why) = m.missing(mech) {
                    out.push(violation(format!("{name}: {mech:?} {why}")));
                }
            }
        } else {
            if c.reason.as_deref().is_none_or(|r| r.trim().is_empty()) {
                out.push(violation(format!(
                    "{name}: does not apply but gives no reason"
                )));
            }
            if !c.mechanism.is_empty() {
                out.push(violation(format!(
                    "{name}: does not apply but names mechanisms"
                )));
            }
        }
    }
    for n in 1..=RULES {
        for lang in LANGUAGES {
            match seen.get(&(n, lang)).copied().unwrap_or(0) {
                0 => out.push(violation(format!("R-{n} × {lang} is missing"))),
                1 => {}
                k => out.push(violation(format!("R-{n} × {lang} appears {k} times"))),
            }
        }
    }
    out
}

/// The repository as the mechanisms see it.
pub(crate) struct Repo {
    pub(crate) root: PathBuf,
    manifest: toml::Table,
    xtask: String,
    semgrep: String,
    recipes: Vec<String>,
    workflows: BTreeMap<String, Vec<String>>,
}

fn level_denies(v: &toml::Value) -> bool {
    let level = v
        .as_str()
        .or_else(|| v.get("level").and_then(toml::Value::as_str));
    matches!(level, Some("deny" | "forbid"))
}

impl Repo {
    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.root.join(rel)).ok()
    }

    fn in_every_package(&self, file: &str, holds: &dyn Fn(&str) -> bool) -> Option<String> {
        let lacking: Vec<&str> = TS_PACKAGES
            .iter()
            .copied()
            .filter(|p| {
                let file = if *p == WORKSPACE && file == "tsconfig.json" {
                    "tsconfig.base.json"
                } else {
                    file
                };
                self.read(&format!("{p}/{file}"))
                    .is_none_or(|text| !holds(&text))
            })
            .collect();
        (!lacking.is_empty()).then(|| format!("is not in {file} of {lacking:?}"))
    }

    fn npmrc(&self, line: &str) -> Option<String> {
        let lacking: Vec<&str> = TS_PACKAGES
            .iter()
            .copied()
            .filter(|p| {
                if *p == WORKSPACE {
                    let Some(wanted) = pnpm_lines(line) else {
                        return true;
                    };
                    self.read(&format!("{p}/pnpm-workspace.yaml"))
                        .is_none_or(|t| !wanted.iter().all(|w| t.lines().any(|l| l.trim() == *w)))
                } else {
                    self.read(&format!("{p}/.npmrc"))
                        .is_none_or(|t| !t.lines().any(|l| l.trim() == line))
                }
            })
            .collect();
        (!lacking.is_empty())
            .then(|| format!("is not in .npmrc or pnpm-workspace.yaml of {lacking:?}"))
    }
}

impl Mechanisms for Repo {
    fn missing(&self, mechanism: &str) -> Option<String> {
        let Some((kind, what)) = mechanism.split_once(':') else {
            return Some(String::from("has no kind"));
        };
        let found = match kind {
            "lint" => what.split_once("::").is_some_and(|(table, lint)| {
                self.manifest
                    .get("workspace")
                    .and_then(|w| w.get("lints"))
                    .and_then(|l| l.get(table))
                    .and_then(|t| t.get(lint))
                    .is_some_and(level_denies)
            }),
            "profile" => what.split_once('.').is_some_and(|(profile, key)| {
                self.manifest
                    .get("profile")
                    .and_then(|p| p.get(profile))
                    .and_then(|p| p.get(key))
                    .is_some_and(|v| v.as_bool() != Some(false))
            }),
            "xtask" => self.xtask.contains(&format!("name: \"{what}\"")),
            "semgrep" => self.semgrep.contains(&format!("id: {what}\n")),
            "recipe" => self.recipes.iter().any(|r| r == what),
            "job" => what.split_once('/').is_some_and(|(w, j)| {
                self.workflows
                    .get(w)
                    .is_some_and(|jobs| jobs.iter().any(|n| n == j))
            }),
            "eslint" => return self.in_every_package("eslint.config.js", &|t| t.contains(what)),
            "tsconfig" => {
                let wanted = format!("\"{what}\": true");
                return self.in_every_package("tsconfig.json", &|t| t.contains(&wanted));
            }
            "npmrc" => return self.npmrc(what),
            "file" => self.root.join(what).is_file(),
            _ => return Some(format!("has an unknown kind {kind:?}")),
        };
        (!found).then(|| String::from("does not exist"))
    }
}

pub(crate) fn load(root: &Path) -> Result<Profiles, String> {
    let path = root.join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn repo(root: &Path) -> Result<Repo, String> {
    let read =
        |rel: &str| std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"));
    let manifest = read("Cargo.toml")?
        .parse::<toml::Table>()
        .map_err(|e| format!("Cargo.toml: {e}"))?;
    let mut xtask = String::new();
    let dir = root.join("xtask/src");
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "rs") {
            xtask.push_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?);
        }
    }
    let mut workflows = BTreeMap::new();
    let wf = root.join(".github/workflows");
    for entry in std::fs::read_dir(&wf).map_err(|e| format!("{}: {e}", wf.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "yml")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
            workflows.insert(stem.to_owned(), test_layers::jobs(&text));
        }
    }
    Ok(Repo {
        root: root.to_path_buf(),
        manifest,
        xtask,
        semgrep: read(".semgrep/rules.yml")?,
        recipes: test_layers::recipes(&read("justfile")?),
        workflows,
    })
}

/// Runs `language-profiles`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(violations(&load(root)?, &repo(root)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Known;

    impl Mechanisms for Known {
        fn missing(&self, mechanism: &str) -> Option<String> {
            (mechanism != "xtask:unsafe-allowlist").then(|| String::from("does not exist"))
        }
    }

    fn full() -> Profiles {
        let mut cell = Vec::new();
        for n in 1..=RULES {
            for lang in LANGUAGES {
                cell.push(Cell {
                    rule: format!("R-{n}"),
                    language: lang.to_owned(),
                    mechanism: vec![String::from("xtask:unsafe-allowlist")],
                    applies: true,
                    reason: None,
                });
            }
        }
        Profiles { version: 1, cell }
    }

    fn messages(v: &[Violation]) -> Vec<&str> {
        v.iter().map(|v| v.message.as_str()).collect()
    }

    // MD-2, SA-20
    #[test]
    fn md_2_a_cell_with_an_empty_or_missing_mechanism_is_refused() {
        assert_eq!(messages(&violations(&full(), &Known)), Vec::<&str>::new());
        let mut p = full();
        if let Some(c) = p.cell.get_mut(0) {
            c.mechanism.clear();
        }
        if let Some(c) = p.cell.get_mut(1) {
            c.mechanism = vec![String::from("lint:clippy::nothing")];
        }
        assert_eq!(
            messages(&violations(&p, &Known)),
            [
                "R-1 × rust: names no mechanism",
                "R-1 × typescript: \"lint:clippy::nothing\" does not exist",
            ]
        );
    }

    // MD-2
    #[test]
    fn md_2_every_rule_and_language_has_one_cell_and_exemptions_say_why() {
        let mut p = full();
        if let Some(c) = p.cell.get_mut(2) {
            c.applies = false;
            c.mechanism.clear();
        }
        p.cell.pop();
        assert_eq!(
            messages(&violations(&p, &Known)),
            [
                "R-1 × c-ffi: does not apply but gives no reason",
                "R-7 × c-ffi is missing",
            ]
        );
    }

    #[test]
    fn the_repository_mechanisms_exist() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let r = repo(root).unwrap();
        assert_eq!(r.missing("lint:clippy::unwrap_used"), None);
        assert!(r.missing("lint:clippy::no_such_lint").is_some());
        assert_eq!(r.missing("profile:release.overflow-checks"), None);
        assert_eq!(r.missing("xtask:unsafe-allowlist"), None);
        assert_eq!(r.missing("semgrep:unwrap-in-non-test-code"), None);
        assert_eq!(r.missing("job:weekly/sanitizers"), None);
        assert_eq!(r.missing("tsconfig:strict"), None);
        assert!(r.missing("other:x").is_some());
        let v = check(root).unwrap();
        assert_eq!(messages(&v), Vec::<&str>::new());
    }
}
