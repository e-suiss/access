//! `test-layers` (SA-59, OP-159 m.3 (bb)): every test layer names an existing recipe or CI job, and phase 0–1 layers are active.
//!
//! - Every layer SA-T1…SA-T18 appears exactly once.
//! - A `recipe` names a recipe of the `justfile`; a `job` is `<workflow>/<job>` and names a job of
//!   `.github/workflows/<workflow>.yml`.
//! - An `active` layer names a recipe or a job; a layer of phase 0 or 1 is `active` (SA-59: a
//!   layer whose phase has come is a gate, and earlier phases are not relaxed).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;

pub(crate) const FILE: &str = "conformance/catalog/test-layers.toml";

/// The layers of §14.8.
pub(crate) const LAYERS: u32 = 18;

/// The last phase whose layers are gates now (SA-59: 0 from the first line of code, 1 before
/// the first public release).
pub(crate) const ACTIVE_UP_TO: u32 = 1;

const CADENCES: [&str; 4] = ["pr", "nightly", "weekly", "release"];

/// One test layer.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Layer {
    pub(crate) id: String,
    pub(crate) content: String,
    pub(crate) cadence: String,
    pub(crate) phase: u32,
    #[serde(default)]
    pub(crate) recipe: Option<String>,
    #[serde(default)]
    pub(crate) job: Option<String>,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Catalog {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) layer: Vec<Layer>,
}

/// What exists in the repository for the layers to name.
pub(crate) trait Runners {
    /// Whether the `justfile` has `recipe`.
    fn recipe(&self, recipe: &str) -> bool;
    /// Whether `.github/workflows/<workflow>.yml` has `job`.
    fn job(&self, workflow: &str, job: &str) -> bool;
}

/// The recipes of a `justfile`.
pub(crate) fn recipes(justfile: &str) -> Vec<String> {
    justfile
        .lines()
        .filter(|l| {
            l.chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase() || c == '@')
        })
        .filter(|l| l.contains(':') && !l.contains(":="))
        .filter_map(|l| {
            l.trim_start_matches('@')
                .split([' ', ':'])
                .next()
                .map(str::to_owned)
        })
        .collect()
}

/// The jobs of a workflow file.
pub(crate) fn jobs(workflow: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for line in workflow.lines() {
        if line.starts_with("jobs:") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        if !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            break;
        }
        if let Some(name) = line.strip_prefix("  ")
            && !name.starts_with(' ')
            && !name.starts_with('#')
            && let Some(name) = name.trim_end().strip_suffix(':')
        {
            out.push(name.to_owned());
        }
    }
    out
}

struct Repo {
    recipes: Vec<String>,
    workflows: BTreeMap<String, Vec<String>>,
}

impl Runners for Repo {
    fn recipe(&self, recipe: &str) -> bool {
        self.recipes.iter().any(|r| r == recipe)
    }

    fn job(&self, workflow: &str, job: &str) -> bool {
        self.workflows
            .get(workflow)
            .is_some_and(|j| j.iter().any(|n| n == job))
    }
}

fn violation(message: String) -> Violation {
    Violation {
        rule: "SA-59",
        path: PathBuf::from(FILE),
        message,
    }
}

/// Pure validation, separated for tests.
pub(crate) fn violations(catalog: &Catalog, runners: &dyn Runners) -> Vec<Violation> {
    let mut out = Vec::new();
    if catalog.version != 1 {
        out.push(violation(format!("version {} is not 1", catalog.version)));
    }
    let mut seen: BTreeMap<u32, usize> = BTreeMap::new();
    for l in &catalog.layer {
        let id = &l.id;
        let Some(n) = id
            .strip_prefix("SA-T")
            .and_then(|n| n.parse::<u32>().ok())
            .filter(|n| (1..=LAYERS).contains(n))
        else {
            out.push(violation(format!("{id}: not a layer SA-T1…SA-T{LAYERS}")));
            continue;
        };
        let k = seen.entry(n).or_default();
        *k = k.saturating_add(1);
        if l.content.trim().is_empty() {
            out.push(violation(format!("{id}: no content")));
        }
        if !CADENCES.contains(&l.cadence.as_str()) {
            out.push(violation(format!(
                "{id}: cadence {:?} is unknown",
                l.cadence
            )));
        }
        if l.rules.is_empty() || l.rules.iter().any(|r| r.trim().is_empty()) {
            out.push(violation(format!("{id}: names no rule")));
        }
        if let Some(r) = &l.recipe
            && !runners.recipe(r)
        {
            out.push(violation(format!(
                "{id}: recipe {r:?} is not in the justfile"
            )));
        }
        if let Some(j) = &l.job {
            match j.split_once('/') {
                Some((w, name)) if runners.job(w, name) => {}
                _ => out.push(violation(format!(
                    "{id}: job {j:?} is not a job of .github/workflows/<workflow>.yml"
                ))),
            }
        }
        match l.status.as_str() {
            "active" if l.recipe.is_none() && l.job.is_none() => out.push(violation(format!(
                "{id}: active but names no recipe and no job"
            ))),
            "planned" if l.phase <= ACTIVE_UP_TO => out.push(violation(format!(
                "{id}: phase {} layers are gates now and must be active (SA-59)",
                l.phase
            ))),
            "active" | "planned" => {}
            other => out.push(violation(format!("{id}: status {other:?} is unknown"))),
        }
    }
    for n in 1..=LAYERS {
        match seen.get(&n).copied().unwrap_or(0) {
            0 => out.push(violation(format!("SA-T{n} is missing"))),
            1 => {}
            k => out.push(violation(format!("SA-T{n} appears {k} times"))),
        }
    }
    out
}

pub(crate) fn load(root: &Path) -> Result<Catalog, String> {
    let path = root.join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn repo(root: &Path) -> Result<Repo, String> {
    let justfile = std::fs::read_to_string(root.join("justfile")).map_err(|e| e.to_string())?;
    let dir = root.join(".github/workflows");
    let mut workflows = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "yml")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            workflows.insert(stem.to_owned(), jobs(&text));
        }
    }
    Ok(Repo {
        recipes: recipes(&justfile),
        workflows,
    })
}

/// Runs `test-layers`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(violations(&load(root)?, &repo(root)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed;

    impl Runners for Fixed {
        fn recipe(&self, recipe: &str) -> bool {
            recipe == "fuzz-regress"
        }

        fn job(&self, workflow: &str, job: &str) -> bool {
            workflow == "ci" && job == "test"
        }
    }

    fn full() -> Catalog {
        Catalog {
            version: 1,
            layer: (1..=LAYERS)
                .map(|n| Layer {
                    id: format!("SA-T{n}"),
                    content: String::from("layer"),
                    cadence: String::from("pr"),
                    phase: 0,
                    recipe: None,
                    job: Some(String::from("ci/test")),
                    status: String::from("active"),
                    rules: vec![String::from("SA-59")],
                })
                .collect(),
        }
    }

    fn messages(v: &[Violation]) -> Vec<&str> {
        v.iter().map(|v| v.message.as_str()).collect()
    }

    // SA-59
    #[test]
    fn sa_59_a_catalog_with_an_inactive_phase_one_layer_is_refused() {
        assert_eq!(messages(&violations(&full(), &Fixed)), Vec::<&str>::new());
        let mut c = full();
        if let Some(l) = c.layer.get_mut(8) {
            l.phase = 1;
            l.status = String::from("planned");
        }
        assert_eq!(
            messages(&violations(&c, &Fixed)),
            ["SA-T9: phase 1 layers are gates now and must be active (SA-59)"]
        );
        let mut later = full();
        if let Some(l) = later.layer.get_mut(13) {
            l.phase = 2;
            l.status = String::from("planned");
            l.job = None;
        }
        assert_eq!(messages(&violations(&later, &Fixed)), Vec::<&str>::new());
    }

    // SA-59, OP-159 m.3 (bb)
    #[test]
    fn sa_59_a_layer_naming_a_missing_recipe_or_job_is_refused() {
        let mut c = full();
        if let Some(l) = c.layer.get_mut(0) {
            l.recipe = Some(String::from("no-such-recipe"));
        }
        if let Some(l) = c.layer.get_mut(1) {
            l.job = Some(String::from("nightly/no-such-job"));
        }
        if let Some(l) = c.layer.get_mut(2) {
            l.job = None;
        }
        assert_eq!(
            messages(&violations(&c, &Fixed)),
            [
                "SA-T1: recipe \"no-such-recipe\" is not in the justfile",
                "SA-T2: job \"nightly/no-such-job\" is not a job of .github/workflows/<workflow>.yml",
                "SA-T3: active but names no recipe and no job",
            ]
        );
    }

    // SA-59
    #[test]
    fn sa_59_a_missing_or_repeated_layer_is_refused() {
        let mut c = full();
        let last = c.layer.pop();
        if let Some(first) = c.layer.first().cloned() {
            c.layer.push(first);
        }
        drop(last);
        assert_eq!(
            messages(&violations(&c, &Fixed)),
            ["SA-T1 appears 2 times", "SA-T18 is missing"]
        );
    }

    #[test]
    fn recipes_and_jobs_are_read_from_their_files() {
        let just = "# c\ntest:\n    x\nfuzz target seconds=\"60\":\n    y\nsanitizer_nightly := \"n\"\n@quiet:\n";
        assert_eq!(recipes(just), ["test", "fuzz", "quiet"]);
        let wf = "name: X\njobs:\n  fast:\n    name: fast\n    steps:\n      - run: x\n  # c\n  test-full:\n    name: y\n";
        assert_eq!(jobs(wf), ["fast", "test-full"]);
    }

    #[test]
    fn the_repository_catalog_is_complete() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let v = check(root).unwrap();
        assert_eq!(messages(&v), Vec::<&str>::new());
    }
}
