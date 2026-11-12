//! `formal-manifest` (CR-46, CR-50, MD-15, X41, OP-159 m.3 (y)): every formal target in the manifest names existing evidence for its status.
//!
//! A `proved` Lean target names theorems `proofs.toml` marks `proved`; a Kani target names an
//! existing `#[kani::proof]` harness whose unwind bounds and stubs its assumptions declare, run
//! per commit by the `formal` job when `proved`; a TLA+ target names definitions of an existing
//! model, listed in an existing `.cfg` whose constants its scope states; a `DRT-linked` target
//! names the nightly summary job; a `planned` target names no evidence. Every harness and model
//! is in the manifest, CR-K1…CR-K9 each have a target, the out-of-scope list declares HL-15,
//! HL-16 and HL-29, and no wording uses a forbidden claim.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;

const RULE: &str = "formal-manifest";
const FILE: &str = "conformance/formal/manifest.toml";
const PROOFS: &str = "conformance/lean/proofs.toml";
const HARNESSES: &str = "crates/kernel/src/proofs";
const MODELS: &str = "conformance/tla";
const CLAIMS: &str = "conformance/catalog/forbidden-claims.toml";
const JUSTFILE: &str = "justfile";
const STATUSES: [&str; 4] = ["planned", "modelled", "proved", "DRT-linked"];
const RUNTIME_LIMITS: [&str; 3] = ["HL-15", "HL-16", "HL-29"];

/// One formal target.
#[derive(Debug, Default, Clone, Deserialize)]
#[expect(
    clippy::struct_field_names,
    reason = "the field names are the manifest's keys (OP-159 m.3 (y))"
)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub(crate) target: String,
    pub(crate) tool: String,
    pub(crate) property: String,
    pub(crate) rules: Vec<String>,
    pub(crate) status: String,
    pub(crate) assumptions: Vec<String>,
    pub(crate) scope: String,
    pub(crate) semantic_version: String,
    pub(crate) evidence: Vec<String>,
}

/// A part outside every model.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutOfScope {
    pub(crate) part: String,
    pub(crate) limit: String,
    #[serde(default)]
    pub(crate) note: Option<String>,
}

/// `conformance/formal/manifest.toml`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) target: Vec<Target>,
    #[serde(default)]
    pub(crate) out_of_scope: Vec<OutOfScope>,
}

/// A Kani harness: its unwind bound and the paths it stubs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Harness {
    pub(crate) unwind: Option<String>,
    pub(crate) stubs: Vec<String>,
}

/// What the evidence can point at.
#[derive(Debug, Default)]
pub(crate) struct World {
    /// Lean theorem name → status.
    pub(crate) theorems: BTreeMap<String, String>,
    /// `crates/kernel/src/proofs/k<n>.rs#name` → harness.
    pub(crate) harnesses: BTreeMap<String, Harness>,
    /// Harnesses `just kani pr` runs.
    pub(crate) per_commit: BTreeSet<String>,
    /// Model path → its definitions.
    pub(crate) models: BTreeMap<String, BTreeSet<String>>,
    /// `.cfg` path → (its constant assignments, every name it lists).
    pub(crate) configs: BTreeMap<String, (Vec<String>, BTreeSet<String>)>,
    /// `<workflow>/<job>`.
    pub(crate) jobs: BTreeSet<String>,
    /// Forbidden phrases, lower case.
    pub(crate) phrases: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Theorem {
    name: String,
    status: String,
}

#[derive(Debug, Default, Deserialize)]
struct Proofs {
    #[serde(default)]
    theorem: Vec<Theorem>,
}

#[derive(Debug, Default, Deserialize)]
struct ClaimRow {
    #[serde(default)]
    phrases: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct Claims {
    #[serde(default)]
    claim: Vec<ClaimRow>,
}

fn violation(message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(FILE),
        message,
    }
}

fn has_ext(path: &str, ext: &str) -> bool {
    Path::new(path).extension().is_some_and(|e| e == ext)
}

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"))
}

/// Reads the manifest.
///
/// # Errors
/// The file is missing or not a manifest.
pub(crate) fn load(root: &Path) -> Result<Manifest, String> {
    toml::from_str(&read(root, FILE)?).map_err(|e| format!("{FILE}: {e}"))
}

fn files(root: &Path, dir: &str, ext: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(root.join(dir)) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|n| n.ends_with(ext))
        .map(|n| format!("{dir}/{n}"))
        .collect();
    out.sort();
    out
}

/// The `#[kani::proof]` harnesses of one source file, by function name.
pub(crate) fn harnesses_in(text: &str) -> BTreeMap<String, Harness> {
    let mut out = BTreeMap::new();
    let mut pending: Option<Harness> = None;
    for line in text.lines().map(str::trim) {
        if line == "#[kani::proof]" {
            pending = Some(Harness::default());
        } else if let Some(h) = pending.as_mut() {
            if let Some(n) = line
                .strip_prefix("#[kani::unwind(")
                .and_then(|r| r.strip_suffix(")]"))
            {
                h.unwind = Some(n.to_owned());
            } else if let Some(s) = line
                .strip_prefix("#[kani::stub(")
                .and_then(|r| r.split(',').next())
            {
                h.stubs.push(s.trim().to_owned());
            } else if let Some(rest) = line.strip_prefix("fn ") {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if let Some(h) = pending.take() {
                    out.insert(name, h);
                }
            }
        }
    }
    out
}

/// The definitions (`Name ==` at the start of a line) of a TLA+ module.
pub(crate) fn definitions(text: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| {
            let (head, _) = l.split_once("==")?;
            let name: String = head
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty() && !l.starts_with(' ')).then_some(name)
        })
        .collect()
}

/// A `.cfg`: its `NAME = value` constants and every bare name it lists.
pub(crate) fn config(text: &str) -> (Vec<String>, BTreeSet<String>) {
    let mut constants = Vec::new();
    let mut names = BTreeSet::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with("\\*") {
            continue;
        }
        if let Some((k, v)) = line.split_once(" = ") {
            constants.push(format!("{} = {}", k.trim(), v.trim()));
        } else {
            names.extend(line.split_whitespace().map(str::to_owned));
        }
    }
    (constants, names)
}

/// Harness names in the `pr=(…)` array of the `kani` recipe.
pub(crate) fn per_commit(justfile: &str) -> BTreeSet<String> {
    let Some((_, rest)) = justfile.split_once("    pr=(") else {
        return BTreeSet::new();
    };
    rest.split(')')
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

fn world(root: &Path) -> Result<World, String> {
    let proofs: Proofs =
        toml::from_str(&read(root, PROOFS)?).map_err(|e| format!("{PROOFS}: {e}"))?;
    let claims: Claims =
        toml::from_str(&read(root, CLAIMS)?).map_err(|e| format!("{CLAIMS}: {e}"))?;
    let mut w = World {
        theorems: proofs
            .theorem
            .into_iter()
            .map(|t| (t.name, t.status))
            .collect(),
        per_commit: per_commit(&read(root, JUSTFILE)?),
        jobs: super::security_model::signals(root)?.jobs,
        phrases: claims
            .claim
            .into_iter()
            .flat_map(|c| c.phrases)
            .filter(|p| !p.contains('{'))
            .map(|p| p.to_lowercase())
            .collect(),
        ..World::default()
    };
    for f in files(root, HARNESSES, ".rs") {
        for (name, h) in harnesses_in(&read(root, &f)?) {
            w.harnesses.insert(format!("{f}#{name}"), h);
        }
    }
    for f in files(root, MODELS, ".tla") {
        let defs = definitions(&read(root, &f)?);
        w.models.insert(f, defs);
    }
    for f in files(root, MODELS, ".cfg") {
        let c = config(&read(root, &f)?);
        w.configs.insert(f, c);
    }
    Ok(w)
}

fn check_target(t: &Target, w: &World, out: &mut Vec<String>) {
    let name = &t.target;
    for (field, value) in [
        ("target", &t.target),
        ("tool", &t.tool),
        ("property", &t.property),
        ("scope", &t.scope),
        ("semantic_version", &t.semantic_version),
    ] {
        if value.trim().is_empty() {
            out.push(format!("{name}: `{field}` is empty"));
        }
    }
    if t.rules.is_empty() {
        out.push(format!("{name}: names no rule"));
    }
    if !STATUSES.contains(&t.status.as_str()) {
        out.push(format!(
            "{name}: status {:?} is not one of {STATUSES:?}",
            t.status
        ));
        return;
    }
    let text = format!("{} {} {}", t.property, t.scope, t.assumptions.join(" ")).to_lowercase();
    for p in w.phrases.iter().filter(|p| text.contains(p.as_str())) {
        out.push(format!("{name}: uses the forbidden claim {p:?} (CR-50 R4)"));
    }
    for e in &t.evidence {
        if let Some(job) = e.strip_prefix("ci:")
            && !w.jobs.contains(job)
        {
            out.push(format!("{name}: CI job {job} does not exist"));
        }
    }
    let has = |e: &str| t.evidence.iter().any(|x| x == e);
    match (t.status.as_str(), t.tool.as_str()) {
        ("planned", _) => {
            if !t.evidence.is_empty() {
                out.push(format!("{name}: a planned target names no evidence"));
            }
        }
        ("DRT-linked", tool) => {
            if tool != "drt" || !t.evidence.iter().any(|e| e.starts_with("ci:nightly/")) {
                out.push(format!(
                    "{name}: DRT-linked needs tool `drt` and the nightly summary job"
                ));
            }
        }
        (status, "lean") => lean(t, status, w, out),
        (status, "kani") => kani(t, status, w, out),
        (status, "tla") => tla(t, status, w, out),
        (status, tool) => out.push(format!(
            "{name}: {tool} has no checked evidence; only `planned` is allowed for it ({status})"
        )),
    }
    if t.status == "proved" && t.tool != "lean" && !has("ci:ci/formal") {
        out.push(format!(
            "{name}: proved needs the per-commit `formal` job (CR-50 R2)"
        ));
    }
}

fn lean(t: &Target, status: &str, w: &World, out: &mut Vec<String>) {
    let names: Vec<&str> = t
        .evidence
        .iter()
        .filter_map(|e| e.strip_prefix(&format!("{PROOFS}#")))
        .collect();
    if names.is_empty() {
        out.push(format!("{}: names no theorem of {PROOFS}", t.target));
    }
    for n in names {
        match w.theorems.get(n) {
            None => out.push(format!("{}: theorem {n} is not in {PROOFS}", t.target)),
            Some(s) if status == "proved" && s != "proved" => out.push(format!(
                "{}: theorem {n} is {s} in {PROOFS}, not proved",
                t.target
            )),
            Some(_) => {}
        }
    }
}

fn kani(t: &Target, status: &str, w: &World, out: &mut Vec<String>) {
    let refs: Vec<&String> = t
        .evidence
        .iter()
        .filter(|e| e.starts_with(HARNESSES))
        .collect();
    if refs.is_empty() && status == "proved" {
        out.push(format!("{}: proved names no harness", t.target));
    }
    let declared = |s: &str| t.assumptions.iter().any(|a| a == s);
    for r in refs {
        let Some(h) = w.harnesses.get(r.as_str()) else {
            out.push(format!("{}: harness {r} does not exist", t.target));
            continue;
        };
        // CR-50 R3
        if let Some(n) = &h.unwind
            && !declared(&format!("unwind {n}"))
        {
            out.push(format!(
                "{}: the unwind bound {n} of {r} is not declared",
                t.target
            ));
        }
        for s in &h.stubs {
            if !declared(&format!("stub {s}")) {
                out.push(format!("{}: the stub {s} of {r} is not declared", t.target));
            }
        }
        let fn_name = r.rsplit('#').next().unwrap_or_default();
        if status == "proved" && !w.per_commit.contains(fn_name) {
            out.push(format!(
                "{}: proved, but `just kani pr` does not run {fn_name}",
                t.target
            ));
        }
    }
}

fn tla(t: &Target, status: &str, w: &World, out: &mut Vec<String>) {
    let cfgs: Vec<&(Vec<String>, BTreeSet<String>)> = t
        .evidence
        .iter()
        .filter(|e| has_ext(e, "cfg"))
        .filter_map(|e| {
            let c = w.configs.get(e.as_str());
            if c.is_none() {
                out.push(format!("{}: {e} does not exist", t.target));
            }
            c
        })
        .collect();
    if cfgs.is_empty() {
        out.push(format!("{}: names no model configuration", t.target));
    }
    // OP-159 m.3 (x)
    for (constants, _) in &cfgs {
        for c in constants {
            if !t.scope.contains(c.as_str()) {
                out.push(format!("{}: the bound `{c}` is not in its scope", t.target));
            }
        }
    }
    let props: Vec<(&str, &str)> = t
        .evidence
        .iter()
        .filter_map(|e| e.split_once('#'))
        .filter(|(m, _)| has_ext(m, "tla"))
        .collect();
    if props.is_empty() && status == "proved" {
        out.push(format!("{}: proved names no model property", t.target));
    }
    for (model, prop) in props {
        match w.models.get(model) {
            None => out.push(format!("{}: model {model} does not exist", t.target)),
            Some(defs) if !defs.contains(prop) => {
                out.push(format!("{}: {model} does not define {prop}", t.target));
            }
            Some(_) => {}
        }
        if !cfgs.iter().any(|(_, names)| names.contains(prop)) {
            out.push(format!("{}: no named .cfg checks {prop}", t.target));
        }
    }
}

/// The findings for `m` against `w`.
pub(crate) fn findings(m: &Manifest, w: &World) -> Vec<String> {
    let mut out = Vec::new();
    if m.version != 1 {
        out.push(format!("version {} is not 1", m.version));
    }
    for t in &m.target {
        check_target(t, w, &mut out);
    }
    let named: BTreeSet<&str> = m
        .target
        .iter()
        .flat_map(|t| t.evidence.iter())
        .map(|e| e.split('#').next().unwrap_or_default())
        .collect();
    let referenced: BTreeSet<&str> = m
        .target
        .iter()
        .flat_map(|t| t.evidence.iter())
        .map(String::as_str)
        .collect();
    for h in w.harnesses.keys() {
        if !referenced.contains(h.as_str()) {
            out.push(format!("harness {h} is not in the manifest"));
        }
    }
    for f in w.models.keys().chain(w.configs.keys()) {
        if !named.contains(f.as_str()) {
            out.push(format!("{f} is not in the manifest"));
        }
    }
    // CR-47
    for n in 1..=9 {
        let id = format!("CR-K{n}");
        if !m
            .target
            .iter()
            .any(|t| t.tool == "kani" && t.rules.contains(&id))
        {
            out.push(format!("{id} has no Kani target (CR-47)"));
        }
    }
    // HL-15, HL-16, HL-29
    for limit in RUNTIME_LIMITS {
        if !m.out_of_scope.iter().any(|o| o.limit == limit) {
            out.push(format!("no out_of_scope entry declares {limit}"));
        }
    }
    for (needle, limit) in [
        ("async runtime", "HL-15"),
        ("http", "HL-15"),
        ("compil", "HL-16"),
    ] {
        if !m
            .out_of_scope
            .iter()
            .any(|o| o.limit == limit && o.part.to_lowercase().contains(needle))
        {
            out.push(format!(
                "out_of_scope must declare the {needle} part under {limit}"
            ));
        }
    }
    for o in &m.out_of_scope {
        let text = format!("{} {}", o.part, o.note.as_deref().unwrap_or_default()).to_lowercase();
        for p in w.phrases.iter().filter(|p| text.contains(p.as_str())) {
            out.push(format!(
                "out_of_scope {:?} uses the forbidden claim {p:?}",
                o.part
            ));
        }
    }
    out
}

/// Runs `formal-manifest`.
///
/// # Errors
/// A file cannot be read or parsed.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let m = load(root)?;
    let w = world(root)?;
    Ok(findings(&m, &w).into_iter().map(violation).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(tool: &str, status: &str, evidence: &[&str]) -> Target {
        Target {
            target: "t".to_owned(),
            tool: tool.to_owned(),
            property: "p holds".to_owned(),
            rules: vec!["CR-K1".to_owned()],
            status: status.to_owned(),
            assumptions: Vec::new(),
            scope: "s".to_owned(),
            semantic_version: "kernel-v0.7.0".to_owned(),
            evidence: evidence.iter().map(|e| (*e).to_owned()).collect(),
        }
    }

    fn world() -> World {
        let mut w = World::default();
        w.theorems.insert("A.t".to_owned(), "proved".to_owned());
        w.theorems.insert("A.s".to_owned(), "stated".to_owned());
        w.harnesses.insert(
            format!("{HARNESSES}/k1.rs#k1_a"),
            Harness {
                unwind: Some("5".to_owned()),
                stubs: vec!["x::y".to_owned()],
            },
        );
        w.per_commit.insert("k1_a".to_owned());
        w.models.insert(
            format!("{MODELS}/M.tla"),
            BTreeSet::from(["Inv".to_owned()]),
        );
        w.configs.insert(
            format!("{MODELS}/M.cfg"),
            (vec!["N = 3".to_owned()], BTreeSet::from(["Inv".to_owned()])),
        );
        w.jobs = BTreeSet::from(["ci/formal".to_owned(), "ci/lean".to_owned()]);
        w.phrases = vec![
            "verified async runtime".to_owned(),
            "constant-time guaranteed".to_owned(),
        ];
        w
    }

    fn manifest(extra: Vec<Target>) -> Manifest {
        let mut kani = (1..=9)
            .map(|n| {
                let mut t = target_kani();
                t.rules = vec![format!("CR-K{n}")];
                t
            })
            .collect::<Vec<_>>();
        kani.extend(extra);
        kani.push({
            let mut t = target(
                "tla",
                "proved",
                &[
                    "conformance/tla/M.tla#Inv",
                    "conformance/tla/M.cfg",
                    "ci:ci/formal",
                ],
            );
            t.scope = "bounds N = 3".to_owned();
            t
        });
        Manifest {
            version: 1,
            target: kani,
            out_of_scope: vec![
                OutOfScope {
                    part: "the async runtime".to_owned(),
                    limit: "HL-15".to_owned(),
                    note: None,
                },
                OutOfScope {
                    part: "the HTTP layer".to_owned(),
                    limit: "HL-15".to_owned(),
                    note: None,
                },
                OutOfScope {
                    part: "the compiler".to_owned(),
                    limit: "HL-16".to_owned(),
                    note: None,
                },
                OutOfScope {
                    part: "the code against the model".to_owned(),
                    limit: "HL-29".to_owned(),
                    note: None,
                },
            ],
        }
    }

    fn target_kani() -> Target {
        let mut t = target(
            "kani",
            "proved",
            &["crates/kernel/src/proofs/k1.rs#k1_a", "ci:ci/formal"],
        );
        t.assumptions = vec!["unwind 5".to_owned(), "stub x::y".to_owned()];
        t
    }

    // CR-46, CR-50, OP-159 m.3 (y)
    #[test]
    fn a_status_needs_its_evidence() {
        let w = world();
        assert_eq!(findings(&manifest(Vec::new()), &w), Vec::<String>::new());

        let lean_ok = target(
            "lean",
            "proved",
            &["conformance/lean/proofs.toml#A.t", "ci:ci/lean"],
        );
        assert_eq!(findings(&manifest(vec![lean_ok]), &w), Vec::<String>::new());
        let stated = target("lean", "proved", &["conformance/lean/proofs.toml#A.s"]);
        let found = findings(&manifest(vec![stated]), &w);
        assert!(
            found.iter().any(|m| m.contains("A.s is stated")),
            "{found:?}"
        );

        let mut undeclared = target_kani();
        undeclared.assumptions.clear();
        let found = findings(&manifest(vec![undeclared]), &w);
        assert!(
            found.iter().any(|m| m.contains("unwind bound 5")),
            "{found:?}"
        );
        assert!(found.iter().any(|m| m.contains("stub x::y")), "{found:?}");

        let missing = target(
            "kani",
            "proved",
            &["crates/kernel/src/proofs/k2.rs#nope", "ci:ci/formal"],
        );
        let found = findings(&manifest(vec![missing]), &w);
        assert!(
            found.iter().any(|m| m.contains("does not exist")),
            "{found:?}"
        );

        let mut nightly = target_kani();
        nightly.evidence = vec![
            "crates/kernel/src/proofs/k1.rs#k1_a".to_owned(),
            "ci:nightly/test-full".to_owned(),
        ];
        let found = findings(&manifest(vec![nightly]), &w);
        assert!(
            found.iter().any(|m| m.contains("per-commit `formal` job")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|m| m.contains("nightly/test-full does not exist")),
            "{found:?}"
        );

        let mut tla = target(
            "tla",
            "proved",
            &[
                "conformance/tla/M.tla#Gone",
                "conformance/tla/M.cfg",
                "ci:ci/formal",
            ],
        );
        tla.scope = "no bounds".to_owned();
        let found = findings(&manifest(vec![tla]), &w);
        assert!(
            found.iter().any(|m| m.contains("does not define Gone")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|m| m.contains("`N = 3` is not in its scope")),
            "{found:?}"
        );

        let planned = target("Flux", "planned", &["ci:ci/formal"]);
        let found = findings(&manifest(vec![planned]), &w);
        assert!(
            found
                .iter()
                .any(|m| m.contains("planned target names no evidence")),
            "{found:?}"
        );
        let proved_flux = target("Flux", "proved", &["ci:ci/formal"]);
        let found = findings(&manifest(vec![proved_flux]), &w);
        assert!(
            found
                .iter()
                .any(|m| m.contains("Flux has no checked evidence")),
            "{found:?}"
        );
    }

    // CR-47
    #[test]
    fn every_harness_model_and_kani_target_is_listed() {
        let mut w = world();
        w.harnesses
            .insert(format!("{HARNESSES}/k9.rs#k9_x"), Harness::default());
        let mut m = manifest(Vec::new());
        m.target.retain(|t| !t.rules.contains(&"CR-K4".to_owned()));
        let found = findings(&m, &w);
        assert!(
            found
                .iter()
                .any(|f| f.contains("k9_x is not in the manifest")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|f| f.contains("CR-K4 has no Kani target")),
            "{found:?}"
        );
    }

    // HL-15, HL-29, OP-159 m.3 (y)
    #[test]
    fn the_runtime_and_http_layer_are_out_of_scope_and_verified_runtime_claims_are_refused() {
        let w = world();
        let mut m = manifest(Vec::new());
        m.out_of_scope.retain(|o| o.limit != "HL-15");
        let found = findings(&m, &w);
        assert!(
            found.iter().any(|f| f.contains("declares HL-15")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|f| f.contains("async runtime part")),
            "{found:?}"
        );
        assert!(found.iter().any(|f| f.contains("http part")), "{found:?}");

        let mut claim = target_kani();
        claim.property = "a verified async runtime".to_owned();
        let found = findings(&manifest(vec![claim]), &w);
        assert!(
            found.iter().any(|f| f.contains("verified async runtime")),
            "{found:?}"
        );
    }

    // HL-16, CR-50 R4
    #[test]
    fn the_compiler_boundary_is_declared_and_constant_time_guarantees_are_refused() {
        let w = world();
        let mut m = manifest(Vec::new());
        m.out_of_scope.retain(|o| o.limit != "HL-16");
        let found = findings(&m, &w);
        assert!(
            found.iter().any(|f| f.contains("declares HL-16")),
            "{found:?}"
        );
        assert!(found.iter().any(|f| f.contains("compil part")), "{found:?}");

        let mut claim = target_kani();
        claim.scope = "constant-time guaranteed".to_owned();
        let found = findings(&manifest(vec![claim]), &w);
        assert!(
            found.iter().any(|f| f.contains("constant-time guaranteed")),
            "{found:?}"
        );
    }

    #[test]
    fn harnesses_definitions_and_configs_are_read_from_source() {
        let src = "#[cfg(kani)]\nmod harness {\n    // CR-K1\n    #[kani::proof]\n    #[kani::unwind(5)]\n    #[kani::stub(a::b, s)]\n    fn k1_x() {}\n}\n";
        let h = harnesses_in(src);
        assert_eq!(
            h.get("k1_x"),
            Some(&Harness {
                unwind: Some("5".to_owned()),
                stubs: vec!["a::b".to_owned()]
            })
        );
        let defs = definitions("Init ==\n    /\\ x = 0\nInv == x >= 0\n  Nested == 1\n");
        assert_eq!(defs, BTreeSet::from(["Init".to_owned(), "Inv".to_owned()]));
        let (constants, names) = config("\\* SEC23\nCONSTANTS\n    N = 3\nINVARIANTS\n    Inv\n");
        assert_eq!(constants, vec!["N = 3".to_owned()]);
        assert!(names.contains("Inv") && names.contains("INVARIANTS"));
        assert_eq!(
            per_commit("x\n    pr=(a b\n        c)\n"),
            BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()])
        );
    }

    // CR-46, CR-50, MD-15, X41, OP-159 m.3 (y)
    #[test]
    fn the_committed_manifest_is_clean() {
        let found = check(&crate::workspace_root()).unwrap();
        assert!(
            found.is_empty(),
            "{:?}",
            found.iter().map(|v| &v.message).collect::<Vec<_>>()
        );
    }
}
