//! Tracked rule catalog and threat model (OP-81, OP-82; SAI-1, SA-6, SA-59).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{Check, Violation};
use ids::family;
use spec::{Spec, SpecRule};

#[path = "catalog_claims.rs"]
mod claims;
#[path = "catalog_ids.rs"]
mod ids;
#[path = "catalog_scan.rs"]
mod scan;
#[path = "catalog_spec.rs"]
mod spec;
#[path = "catalog_watchlist.rs"]
mod watchlist;

/// Catalog directory, relative to the workspace root.
pub(crate) const DIR: &str = "conformance/catalog";

/// Generated rule files and the families each one holds, in output order.
const RULE_FILES: &[(&str, &[&str])] = &[
    (
        "invariants.toml",
        &[
            "CI", "INV", "EI", "XI", "PI", "SI", "TI", "TI-RT", "SAI", "IDI", "AGI", "TNI", "OPI",
        ],
    ),
    ("guarantees.toml", &["G", "U", "N", "HL", "DL", "RR", "SEC"]),
    (
        "must-never.toml",
        &["MUST-NEVER", "OP-54-RL", "OP-3-G", "ADVISORY"],
    ),
    (
        "decisions.toml",
        &["SA", "CR", "R", "OP", "MD", "F", "IDP", "AG", "TN"],
    ),
];
const THREAT_FILE: &str = "threat-model.toml";
const CONFIG_FILE: &str = "catalog.toml";

const STATUSES: &[&str] = &[
    "canonical",
    "candidate",
    "retired",
    "frozen",
    "reference",
    "decision",
];
const CLASSES: &[&str] = &["BS", "UDC", "NG", "PU", "NG/PU"];
const STRIDE: &[&str] = &["S", "T", "R", "I", "D", "E"];
const LINDDUN: &[&str] = &[
    "Linking",
    "Identifying",
    "Non-repudiation",
    "Detecting",
    "Data disclosure",
    "Unawareness",
    "Non-compliance",
];
const TURKISH_LETTERS: &str = "çğıöşüÇĞİÖŞÜ";
const MAX_TITLE_WORDS: usize = 16;

/// `conformance/catalog/catalog.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// The Ek B stage under construction; rules with `stage <= current_stage` need tests.
    pub(crate) current_stage: u8,
    /// Families whose rules need tests once their stage is reached.
    pub(crate) enforced_families: Vec<String>,
    /// Directories scanned for Rust tests.
    pub(crate) test_roots: Vec<String>,
    /// Whole families required from a stage regardless of Ek B citations.
    #[serde(default)]
    pub(crate) stage_overrides: Vec<StageOverride>,
}

/// A family-wide stage decided outside the Ek B text (recorded with its reason).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StageOverride {
    pub(crate) family: String,
    pub(crate) stage: u8,
    pub(crate) reason: String,
}

/// One catalog entry.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) id: String,
    pub(crate) family: String,
    pub(crate) section: String,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) class: Option<String>,
    /// Earliest Ek B stage citing the ID; unset means report-only.
    #[serde(default)]
    pub(crate) stage: Option<u8>,
    pub(crate) title: String,
    /// Other spec IDs naming the same row (advisory aliases).
    #[serde(default)]
    pub(crate) aliases: Vec<String>,
    /// `path` or `path::function`, relative to the workspace root.
    #[serde(default)]
    pub(crate) tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

/// One threat-model row (OP-82, SA-5, SA-6).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Threat {
    /// `TH-n`; unset for the unnumbered identity-plane and hosting rows.
    #[serde(default)]
    pub(crate) id: Option<String>,
    /// For unnumbered rows: the group label and position within the group.
    #[serde(default)]
    pub(crate) group: Option<String>,
    #[serde(default)]
    pub(crate) ordinal: Option<u32>,
    pub(crate) title: String,
    pub(crate) stride: Vec<String>,
    pub(crate) linddun: Vec<String>,
    /// §13 (or invariant) rows that answer the threat; each must exist in the catalog.
    pub(crate) rows: Vec<String>,
    /// Other references (sections, red-team findings, decisions); informational.
    #[serde(default)]
    pub(crate) refs: Vec<String>,
    #[serde(default)]
    pub(crate) tests: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreatFile {
    #[serde(default)]
    threat: Vec<Threat>,
    #[serde(default)]
    abuse_case: Vec<Rule>,
}

/// The whole committed catalog.
#[derive(Debug, Default)]
pub(crate) struct Catalog {
    pub(crate) rules: Vec<Rule>,
    pub(crate) threats: Vec<Threat>,
    pub(crate) abuse_cases: Vec<Rule>,
}

impl Catalog {
    pub(crate) fn ids(&self) -> BTreeSet<String> {
        self.rules
            .iter()
            .chain(&self.abuse_cases)
            .flat_map(|r| std::iter::once(r.id.clone()).chain(r.aliases.iter().cloned()))
            .collect()
    }
}

fn read_toml<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub(crate) fn load_config(root: &Path) -> Result<Config, String> {
    let path = root.join(DIR).join(CONFIG_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn load(root: &Path) -> Result<Catalog, String> {
    let dir = root.join(DIR);
    let mut catalog = Catalog::default();
    for (file, _) in RULE_FILES {
        let parsed: RuleFile = read_toml(&dir.join(file))?;
        catalog.rules.extend(parsed.rule);
    }
    let threats: ThreatFile = read_toml(&dir.join(THREAT_FILE))?;
    catalog.threats = threats.threat;
    catalog.abuse_cases = threats.abuse_case;
    Ok(catalog)
}

/// A TOML basic string.
fn quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn list(items: &[String]) -> String {
    match items {
        [] => "[]".to_owned(),
        [one] if one.len() < 60 => format!("[{}]", quote(one)),
        many if many.iter().map(String::len).sum::<usize>() < 60 => {
            format!(
                "[{}]",
                many.iter().map(|s| quote(s)).collect::<Vec<_>>().join(", ")
            )
        }
        many => {
            let mut out = String::from("[\n");
            for s in many {
                let _ = writeln!(out, "  {},", quote(s));
            }
            out.push(']');
            out
        }
    }
}

const HEADER: &str = "# OP-81\n";

fn render_rules(_intro: &str, table: &str, rules: &[Rule]) -> String {
    format!("{HEADER}{}", render_entries(table, rules))
}

fn render_entries(table: &str, rules: &[Rule]) -> String {
    let mut out = String::new();
    for r in rules {
        let _ = write!(
            out,
            "\n[[{table}]]\nid = {}\nfamily = {}\nsection = {}\nstatus = {}\n",
            quote(&r.id),
            quote(&r.family),
            quote(&r.section),
            quote(&r.status)
        );
        if let Some(c) = &r.class {
            let _ = writeln!(out, "class = {}", quote(c));
        }
        if let Some(s) = r.stage {
            let _ = writeln!(out, "stage = {s}");
        }
        let _ = writeln!(out, "title = {}", quote(&r.title));
        if !r.aliases.is_empty() {
            let _ = writeln!(out, "aliases = {}", list(&r.aliases));
        }
        let _ = writeln!(out, "tests = {}", list(&r.tests));
    }
    out
}

fn render_threats(threats: &[Threat], abuse: &[Rule]) -> String {
    let mut out = format!("{HEADER}# OP-82, SA-5, SA-6\n");
    for t in threats {
        out.push_str("\n[[threat]]\n");
        if let Some(id) = &t.id {
            let _ = writeln!(out, "id = {}", quote(id));
        }
        if let Some(g) = &t.group {
            let _ = writeln!(out, "group = {}", quote(g));
        }
        if let Some(o) = t.ordinal {
            let _ = writeln!(out, "ordinal = {o}");
        }
        let _ = writeln!(out, "title = {}", quote(&t.title));
        let _ = writeln!(out, "stride = {}", list(&t.stride));
        let _ = writeln!(out, "linddun = {}", list(&t.linddun));
        let _ = writeln!(out, "rows = {}", list(&t.rows));
        if !t.refs.is_empty() {
            let _ = writeln!(out, "refs = {}", list(&t.refs));
        }
        let _ = writeln!(out, "tests = {}", list(&t.tests));
    }
    if !abuse.is_empty() {
        out.push_str("\n# §14.2\n");
        out.push_str(&render_entries("abuse_case", abuse));
    }
    out
}

/// Trailing number of an ID for natural ordering (`G9` < `G10`).
fn number(id: &str) -> u64 {
    let digits: String = id.chars().rev().take_while(char::is_ascii_digit).collect();
    digits
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

/// Merges spec rules with the existing catalog: spec decides IDs and metadata,
/// the catalog keeps curated titles and test links.
fn merge(
    spec_rules: &[SpecRule],
    existing: &BTreeMap<String, Rule>,
    stages: &BTreeMap<String, u8>,
    found: &BTreeMap<String, BTreeSet<String>>,
    link_ok: &dyn Fn(&str) -> bool,
) -> Vec<Rule> {
    spec_rules
        .iter()
        .map(|s| {
            let old = existing.get(&s.id);
            let title = old
                .map(|o| o.title.clone())
                .filter(|t| !t.is_empty())
                .or_else(|| s.english_lead.clone())
                .unwrap_or_default();
            let mut tests: BTreeSet<String> = old
                .map(|o| o.tests.iter().filter(|t| link_ok(t)).cloned().collect())
                .unwrap_or_default();
            for id in std::iter::once(&s.id).chain(&s.aliases) {
                tests.extend(found.get(id).into_iter().flatten().cloned());
            }
            let stage = std::iter::once(&s.id)
                .chain(&s.aliases)
                .filter_map(|id| stages.get(id))
                .min()
                .copied();
            Rule {
                id: s.id.clone(),
                family: s.family.clone(),
                section: s.section.clone(),
                status: s.status.clone(),
                class: s.class.clone(),
                stage: if s.status == "retired" { None } else { stage },
                title,
                aliases: s.aliases.clone(),
                tests: tests.into_iter().collect(),
            }
        })
        .collect()
}

/// Lowers `stage` to each family override (never raises it); retired rows stay unstaged.
fn apply_overrides(rules: &mut [Rule], overrides: &[StageOverride]) {
    for r in rules.iter_mut().filter(|r| r.status != "retired") {
        for o in overrides.iter().filter(|o| o.family == r.family) {
            r.stage = Some(r.stage.map_or(o.stage, |s| s.min(o.stage)));
        }
    }
}

fn sort_rules(rules: &mut [Rule], families: &[&str]) {
    let index = |f: &str| families.iter().position(|x| *x == f).unwrap_or(usize::MAX);
    rules.sort_by_key(|r| {
        (
            index(&r.family),
            if r.family == "ADVISORY" {
                0
            } else {
                number(&r.id)
            },
        )
    });
}

fn merge_threats(spec: &Spec, existing: &[Threat], link_ok: &dyn Fn(&str) -> bool) -> Vec<Threat> {
    let mut ordinals: BTreeMap<String, u32> = BTreeMap::new();
    let mut threats: Vec<Threat> = spec
        .threats
        .iter()
        .map(|t| {
            let (group, ordinal) = if t.id.is_some() {
                (None, None)
            } else {
                let g = t
                    .label
                    .split(')')
                    .next()
                    .unwrap_or_default()
                    .trim_start_matches('(')
                    .trim();
                let g = if g == "barındırma" { "hosting" } else { g }.to_owned();
                let n = ordinals.entry(g.clone()).or_insert(0);
                *n = n.saturating_add(1);
                (Some(g), Some(*n))
            };
            let old = existing.iter().find(|e| {
                if t.id.is_some() {
                    e.id == t.id
                } else {
                    e.group == group && e.ordinal == ordinal
                }
            });
            let default_title = if t.id.is_some() {
                t.label.clone()
            } else {
                String::new()
            };
            Threat {
                id: t.id.clone(),
                group,
                ordinal,
                title: old
                    .map(|o| o.title.clone())
                    .filter(|x| !x.is_empty())
                    .unwrap_or(default_title),
                stride: t.stride.clone(),
                linddun: t.linddun.clone(),
                rows: t.rows.clone(),
                refs: t.refs.clone(),
                tests: old
                    .map(|o| o.tests.iter().filter(|x| link_ok(x)).cloned().collect())
                    .unwrap_or_default(),
            }
        })
        .collect();
    threats.sort_by_key(|t| (t.id.is_none(), t.id.as_deref().map_or(0, number)));
    threats
}

/// `cargo xtask catalog`: regenerates the catalog from the local spec.
#[allow(
    clippy::too_many_lines,
    reason = "one linear regeneration pass; each step is a short, named block"
)]
pub(crate) fn generate(root: &Path) -> Result<(), String> {
    let spec_dir = root.join("docs/spec");
    if !spec_dir.is_dir() {
        return Err(format!(
            "{} not found. The catalog is generated from the local spec (OP-81); \
             CI only checks the committed catalog with `cargo xtask check`.",
            spec_dir.display()
        ));
    }
    let spec = spec::parse(&spec_dir)?;
    let config = load_config(root)?;
    let old = load(root)?;
    let existing: BTreeMap<String, Rule> = old
        .rules
        .iter()
        .chain(&old.abuse_cases)
        .map(|r| (r.id.clone(), r.clone()))
        .collect();

    let mut known: BTreeSet<String> = spec
        .rules
        .iter()
        .flat_map(|r| std::iter::once(r.id.clone()).chain(r.aliases.iter().cloned()))
        .collect();
    known.extend(spec.abuse_cases.iter().map(|r| r.id.clone()));
    known.extend(spec.decisions.keys().cloned());
    let found = scan::scan(root, &config.test_roots, &known);
    let link_ok = |l: &str| scan::link_exists(root, l);

    let cited: Vec<SpecRule> = spec
        .decisions
        .values()
        .filter(|d| found.contains_key(&d.id))
        .cloned()
        .collect();
    let mut all_spec = spec.rules.clone();
    all_spec.extend(cited);
    let mut rules = merge(&all_spec, &existing, &spec.stages, &found, &link_ok);
    apply_overrides(&mut rules, &config.stage_overrides);

    let dir = root.join(DIR);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let intros = [
        "Invariants and invariant candidates (§6, §7.8, §8.19, §10.11, §11.22.2, §12.9, §14.11, §15.22.1, §17.13).",
        "Guarantee matrix rows (§13.4 G/U/N, §13.5 HL), declared limits (§13.1), residual risks (§13.9), security decisions (§13.10).",
        "Must-never list (§2.8), OP-54 red lines (§17.9.8), OP-3 CI gates (§16.4.3) and advisory classes (§14.3, SA-10).",
        "Decision register rows cited by tests.",
    ];
    for ((file, families), intro) in RULE_FILES.iter().zip(intros) {
        let mut part: Vec<Rule> = rules
            .iter()
            .filter(|r| families.contains(&r.family.as_str()))
            .cloned()
            .collect();
        sort_rules(&mut part, families);
        write(&dir.join(file), &render_rules(intro, "rule", &part))?;
    }
    let threats = merge_threats(&spec, &old.threats, &link_ok);
    let abuse = merge(&spec.abuse_cases, &existing, &spec.stages, &found, &link_ok);
    write(&dir.join(THREAT_FILE), &render_threats(&threats, &abuse))?;

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &rules {
        let n = counts.entry(r.family.as_str()).or_default();
        *n = n.saturating_add(1);
    }
    let summary: Vec<String> = counts.iter().map(|(f, n)| format!("{f} {n}")).collect();
    println!(
        "catalog: {} rules ({}), {} threats, {} abuse cases",
        rules.len(),
        summary.join(", "),
        threats.len(),
        abuse.len()
    );
    let untitled: Vec<&SpecRule> = all_spec
        .iter()
        .chain(&spec.abuse_cases)
        .filter(|s| {
            rules
                .iter()
                .chain(&abuse)
                .any(|r| r.id == s.id && r.title.is_empty())
        })
        .collect();
    if !untitled.is_empty() {
        println!(
            "catalog: {} entries need an English title (catalog-format fails until curated)",
            untitled.len()
        );
    }
    if let Some(path) = std::env::var_os("XTASK_CATALOG_DUMP") {
        let mut dump = String::new();
        for s in &untitled {
            let _ = writeln!(dump, "{}\t{}", s.id, s.source.replace(['\n', '\t'], " "));
        }
        for t in threats.iter().filter(|t| t.title.is_empty()) {
            let label = spec
                .threats
                .iter()
                .find(|s| s.id.is_none() && s.label.contains(t.group.as_deref().unwrap_or("")));
            let _ = writeln!(
                dump,
                "threat:{}:{}\t{}",
                t.group.as_deref().unwrap_or(""),
                t.ordinal.unwrap_or(0),
                label.map_or("", |l| l.label.as_str())
            );
        }
        std::fs::write(PathBuf::from(&path), dump).map_err(|e| format!("dump: {e}"))?;
    }
    Ok(())
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "catalog-format",
            run: check_format,
        },
        Check {
            name: "rule-coverage",
            run: check_coverage,
        },
        Check {
            name: "threat-model",
            run: check_threat_model,
        },
        Check {
            name: "must-never",
            run: check_must_never,
        },
        Check {
            name: "forbidden-claims",
            run: claims::check_forbidden_claims,
        },
        Check {
            name: "benchmark-claims",
            run: claims::check_benchmark_claims,
        },
        Check {
            name: "maintainer-watchlist",
            run: watchlist::check,
        },
    ]
}

fn violation(rule: &'static str, file: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(DIR).join(file),
        message,
    }
}

fn file_of(family: &str) -> &'static str {
    RULE_FILES
        .iter()
        .find(|(_, f)| f.contains(&family))
        .map_or(THREAT_FILE, |(n, _)| n)
}

fn title_problem(title: &str) -> Option<String> {
    if title.trim().is_empty() {
        return Some("missing English title".to_owned());
    }
    if title.chars().any(|c| TURKISH_LETTERS.contains(c)) {
        return Some(format!("title is not English: {title:?}"));
    }
    let words = title.split_whitespace().count();
    (words > MAX_TITLE_WORDS).then(|| format!("title has {words} words (max {MAX_TITLE_WORDS})"))
}

/// Pure format validation, separated for tests.
pub(crate) fn format_violations(catalog: &Catalog, config: &Config) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for r in catalog.rules.iter().chain(&catalog.abuse_cases) {
        let file = file_of(&r.family);
        let mut bad = |m: String| out.push(violation("OP-81", file, format!("{}: {m}", r.id)));
        if !seen.insert(r.id.clone()) {
            bad("duplicate ID".to_owned());
        }
        if family(&r.id) != Some(r.family.as_str()) {
            bad(format!("family {:?} does not match the ID", r.family));
        }
        if !STATUSES.contains(&r.status.as_str()) {
            bad(format!("unknown status {:?}", r.status));
        }
        if let Some(c) = &r.class
            && !CLASSES.contains(&c.as_str())
        {
            bad(format!("unknown class {c:?}"));
        }
        if r.stage.is_some_and(|s| s > 14) {
            bad("stage outside Ek B stages 0–14".to_owned());
        }
        if let Some(p) = title_problem(&r.title) {
            bad(p);
        }
    }
    let mut threat_ids = BTreeSet::new();
    for t in &catalog.threats {
        let name = t.id.clone().unwrap_or_else(|| {
            format!(
                "{} #{}",
                t.group.as_deref().unwrap_or("?"),
                t.ordinal.unwrap_or(0)
            )
        });
        let mut bad = |m: String| out.push(violation("OP-82", THREAT_FILE, format!("{name}: {m}")));
        match &t.id {
            Some(id) if family(id) != Some("TH") => bad("not a TH ID".to_owned()),
            Some(id) if !threat_ids.insert(id.clone()) => bad("duplicate ID".to_owned()),
            None if t.group.is_none() || t.ordinal.is_none() => {
                bad("unnumbered threat needs group and ordinal".to_owned());
            }
            _ => {}
        }
        for s in t.stride.iter().filter(|s| !STRIDE.contains(&s.as_str())) {
            bad(format!("unknown STRIDE class {s:?}"));
        }
        for l in t.linddun.iter().filter(|l| !LINDDUN.contains(&l.as_str())) {
            bad(format!("unknown LINDDUN class {l:?}"));
        }
        if t.stride.is_empty() && t.linddun.is_empty() {
            bad("needs a STRIDE or LINDDUN class".to_owned());
        }
        if let Some(p) = title_problem(&t.title) {
            bad(p);
        }
    }
    for o in &config.stage_overrides {
        if o.reason.trim().is_empty()
            || o.stage > 14
            || family(&format!("{}-1", o.family)).is_none()
                && family(&format!("{}1", o.family)).is_none()
        {
            out.push(violation(
                "OP-81",
                CONFIG_FILE,
                format!(
                    "stage override for {:?} needs a known family, a stage 0–14 and a reason",
                    o.family
                ),
            ));
        }
    }
    for f in &config.enforced_families {
        if !RULE_FILES.iter().any(|(_, fs)| fs.contains(&f.as_str())) && f != "AB" {
            out.push(violation(
                "OP-81",
                CONFIG_FILE,
                format!("unknown enforced family {f:?}"),
            ));
        }
    }
    out
}

fn check_format(root: &Path) -> Result<Vec<Violation>, String> {
    let config = load_config(root)?;
    let catalog = load(root)?;
    if catalog.rules.is_empty() {
        return Ok(vec![violation(
            "OP-81",
            "invariants.toml",
            "catalog is empty; run `cargo xtask catalog`".to_owned(),
        )]);
    }
    Ok(format_violations(&catalog, &config))
}

/// Coverage per ID: scanned test citations, catalog links and honest-wording claims.
pub(crate) struct Coverage {
    pub(crate) by_id: BTreeMap<String, BTreeSet<String>>,
}

pub(crate) fn coverage(
    root: &Path,
    catalog: &Catalog,
    config: &Config,
) -> Result<Coverage, String> {
    let mut by_id = scan::scan(root, &config.test_roots, &catalog.ids());
    for r in &catalog.rules {
        for a in &r.aliases {
            if let Some(locs) = by_id.get(a).cloned() {
                by_id.entry(r.id.clone()).or_default().extend(locs);
            }
        }
    }
    // SAI-1
    for claim in claims::load(root)?.claim {
        for row in claim.rows {
            by_id
                .entry(row)
                .or_default()
                .insert(format!("forbidden-claims#{}", claim.id));
        }
    }
    for r in catalog.rules.iter().chain(&catalog.abuse_cases) {
        by_id
            .entry(r.id.clone())
            .or_default()
            .extend(r.tests.iter().cloned());
    }
    by_id.retain(|_, v| !v.is_empty());
    Ok(Coverage { by_id })
}

/// Rules that must have a test now and have none.
pub(crate) fn missing(catalog: &Catalog, config: &Config, cov: &Coverage) -> Vec<String> {
    catalog
        .rules
        .iter()
        .chain(&catalog.abuse_cases)
        .filter(|r| r.status != "retired")
        .filter(|r| config.enforced_families.contains(&r.family))
        .filter(|r| r.stage.is_some_and(|s| s <= config.current_stage))
        .filter(|r| !cov.by_id.contains_key(&r.id))
        .map(|r| r.id.clone())
        .collect()
}

fn stale_links(root: &Path, catalog: &Catalog) -> Vec<Violation> {
    let mut out = Vec::new();
    let rules = catalog
        .rules
        .iter()
        .chain(&catalog.abuse_cases)
        .map(|r| (r.id.clone(), &r.tests, file_of(&r.family)));
    let threats = catalog
        .threats
        .iter()
        .map(|t| (t.id.clone().unwrap_or_default(), &t.tests, THREAT_FILE));
    for (id, tests, file) in rules.chain(threats) {
        for t in tests.iter().filter(|t| !scan::link_exists(root, t)) {
            out.push(violation(
                "SA-59",
                file,
                format!("{id}: test link {t:?} does not resolve"),
            ));
        }
    }
    out
}

fn check_coverage(root: &Path) -> Result<Vec<Violation>, String> {
    let config = load_config(root)?;
    let catalog = load(root)?;
    let cov = coverage(root, &catalog, &config)?;
    let mut out = stale_links(root, &catalog);
    for id in missing(&catalog, &config, &cov) {
        let r = catalog
            .rules
            .iter()
            .chain(&catalog.abuse_cases)
            .find(|r| r.id == id);
        let file = r.map_or("invariants.toml", |r| file_of(&r.family));
        out.push(violation(
            "SAI-1",
            file,
            format!(
                "{id} is required from stage {} (current {}) and no test cites it",
                r.and_then(|r| r.stage).unwrap_or(0),
                config.current_stage
            ),
        ));
    }
    let enforced: Vec<&Rule> = catalog
        .rules
        .iter()
        .filter(|r| config.enforced_families.contains(&r.family) && r.status != "retired")
        .collect();
    let covered = enforced
        .iter()
        .filter(|r| cov.by_id.contains_key(&r.id))
        .count();
    println!(
        "      rule-coverage: {covered}/{} rules cited by tests; stage {} enforced",
        enforced.len(),
        config.current_stage
    );
    Ok(out)
}

/// Pure threat-model mapping validation (SA-6), separated for tests.
pub(crate) fn threat_violations(catalog: &Catalog) -> Vec<Violation> {
    let ids = catalog.ids();
    let mut out = Vec::new();
    let numbered: BTreeSet<u64> = catalog
        .threats
        .iter()
        .filter_map(|t| t.id.as_deref())
        .map(number)
        .collect();
    if let Some(max) = numbered.iter().max() {
        for n in (1..=*max).filter(|n| !numbered.contains(n)) {
            out.push(violation(
                "OP-82",
                THREAT_FILE,
                format!("TH-{n} is missing"),
            ));
        }
    } else {
        out.push(violation("OP-82", THREAT_FILE, "no TH rows".to_owned()));
    }
    for t in &catalog.threats {
        let name = t.id.clone().unwrap_or_else(|| t.title.clone());
        if t.rows.is_empty() {
            out.push(violation(
                "SA-6",
                THREAT_FILE,
                format!("{name}: maps to no §13 row"),
            ));
        }
        for row in t.rows.iter().filter(|r| !ids.contains(*r)) {
            out.push(violation(
                "SA-6",
                THREAT_FILE,
                format!("{name}: row {row} is not in the catalog"),
            ));
        }
    }
    out
}

fn check_threat_model(root: &Path) -> Result<Vec<Violation>, String> {
    let catalog = load(root)?;
    let mut out = threat_violations(&catalog);
    let covered = catalog
        .threats
        .iter()
        .filter(|t| !t.tests.is_empty())
        .count();
    println!(
        "      threat-model: {} threats, {covered} with tests",
        catalog.threats.len()
    );
    out.extend(stale_links(
        root,
        &Catalog {
            threats: catalog.threats,
            ..Catalog::default()
        },
    ));
    Ok(out)
}

/// Must-never regression catalog: every item #1…#n, red line and advisory class has an
/// entry, and the families are contiguous (Ek B stage 0; SA-10).
pub(crate) fn must_never_violations(catalog: &Catalog) -> Vec<Violation> {
    let mut out = Vec::new();
    for (fam, min) in [("MUST-NEVER", 19u64), ("OP-54-RL", 1), ("OP-3-G", 1)] {
        let nums: BTreeSet<u64> = catalog
            .rules
            .iter()
            .filter(|r| r.family == fam)
            .map(|r| number(&r.id))
            .collect();
        let max = nums.iter().max().copied().unwrap_or(0).max(min);
        for n in (1..=max).filter(|n| !nums.contains(n)) {
            let sep = if fam == "MUST-NEVER" { "-" } else { "" };
            out.push(violation(
                "OP-81",
                "must-never.toml",
                format!("{fam}{sep}{n} has no mapping entry"),
            ));
        }
    }
    if !catalog.rules.iter().any(|r| r.family == "ADVISORY") {
        out.push(violation(
            "SA-10",
            "must-never.toml",
            "no advisory classes".to_owned(),
        ));
    }
    out
}

fn check_must_never(root: &Path) -> Result<Vec<Violation>, String> {
    let config = load_config(root)?;
    let catalog = load(root)?;
    let cov = coverage(root, &catalog, &config)?;
    let mut out = must_never_violations(&catalog);
    for fam in ["MUST-NEVER", "OP-54-RL", "ADVISORY"] {
        let all: Vec<&Rule> = catalog.rules.iter().filter(|r| r.family == fam).collect();
        let covered = all.iter().filter(|r| cov.by_id.contains_key(&r.id)).count();
        println!("      must-never: {fam} {covered}/{} with tests", all.len());
    }
    let families = ["MUST-NEVER", "OP-54-RL", "OP-3-G", "ADVISORY"];
    let rules = catalog
        .rules
        .into_iter()
        .filter(|r| families.contains(&r.family.as_str()))
        .collect();
    out.extend(stale_links(
        root,
        &Catalog {
            rules,
            ..Catalog::default()
        },
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, title: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            family: family(id).unwrap_or_default().to_owned(),
            section: "6.2".to_owned(),
            status: "canonical".to_owned(),
            title: title.to_owned(),
            ..Rule::default()
        }
    }

    fn config(stage: u8) -> Config {
        Config {
            current_stage: stage,
            enforced_families: vec!["INV".into(), "N".into()],
            test_roots: vec![],
            stage_overrides: vec![],
        }
    }

    fn spec_rule(id: &str, lead: Option<&str>) -> SpecRule {
        SpecRule {
            id: id.to_owned(),
            family: family(id).unwrap_or_default().to_owned(),
            section: "6.2".to_owned(),
            status: "canonical".to_owned(),
            class: None,
            english_lead: lead.map(str::to_owned),
            aliases: vec![],
            source: String::new(),
        }
    }

    #[test]
    fn catalog_format_rejects_duplicates_unknown_status_and_non_english_titles() {
        let mut bad = rule("INV-2", "Tek yazım yolu");
        bad.status = "maybe".to_owned();
        let catalog = Catalog {
            rules: vec![rule("INV-2", "Single write path"), bad],
            ..Catalog::default()
        };
        let msgs: Vec<String> = format_violations(&catalog, &config(0))
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert!(msgs.iter().any(|m| m.contains("duplicate")), "{msgs:?}");
        assert!(
            msgs.iter().any(|m| m.contains("unknown status")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m.contains("not English")), "{msgs:?}");
    }

    #[test]
    fn catalog_format_rejects_family_mismatch_and_bad_stride() {
        let mut r = rule("INV-2", "Single write path");
        r.family = "SI".to_owned();
        let t = Threat {
            id: Some("TH-1".into()),
            title: "Malicious user".into(),
            stride: vec!["X".into()],
            rows: vec!["INV-2".into()],
            ..Threat::default()
        };
        let catalog = Catalog {
            rules: vec![r],
            threats: vec![t],
            ..Catalog::default()
        };
        let msgs: Vec<String> = format_violations(&catalog, &config(0))
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert!(
            msgs.iter().any(|m| m.contains("does not match")),
            "{msgs:?}"
        );
        assert!(msgs.iter().any(|m| m.contains("STRIDE")), "{msgs:?}");
    }

    // TI-RT12, OP-81, G38
    #[test]
    fn g38_ti_rt12_regeneration_follows_the_spec_and_keeps_curation() {
        let mut kept = rule("INV-2", "Curated title");
        kept.tests = vec!["a.rs::t".into(), "gone.rs::t".into()];
        let existing: BTreeMap<String, Rule> = [kept, rule("INV-99", "Removed from spec")]
            .into_iter()
            .map(|r| (r.id.clone(), r))
            .collect();
        let spec = [
            spec_rule("INV-2", Some("Spec lead")),
            spec_rule("INV-3", Some("Non-amplification")),
        ];
        let stages = BTreeMap::from([("INV-2".to_owned(), 3u8)]);
        let found = BTreeMap::from([(
            "INV-3".to_owned(),
            BTreeSet::from(["b.rs::inv_3_x".to_owned()]),
        )]);
        let merged = merge(&spec, &existing, &stages, &found, &|l| {
            !l.starts_with("gone")
        });
        let summary: Vec<_> = merged
            .iter()
            .map(|r| (r.id.as_str(), r.title.as_str(), r.stage, r.tests.clone()))
            .collect();
        assert_eq!(
            summary,
            [
                (
                    "INV-2",
                    "Curated title",
                    Some(3),
                    vec!["a.rs::t".to_owned()]
                ),
                (
                    "INV-3",
                    "Non-amplification",
                    None,
                    vec!["b.rs::inv_3_x".to_owned()]
                ),
            ]
        );
    }

    // SAI-1
    #[test]
    fn sai_1_uncovered_rule_of_the_current_stage_is_reported() {
        let mut now = rule("INV-2", "Single write path");
        now.stage = Some(0);
        let mut later = rule("INV-3", "Non-amplification");
        later.stage = Some(3);
        let unstaged = rule("INV-4", "Single basis");
        let mut covered = rule("N-41", "Passkeys do not stop token theft");
        covered.stage = Some(0);
        let catalog = Catalog {
            rules: vec![now, later, unstaged, covered],
            ..Catalog::default()
        };
        let cov = Coverage {
            by_id: BTreeMap::from([(
                "N-41".to_owned(),
                BTreeSet::from(["forbidden-claims#x".to_owned()]),
            )]),
        };
        assert_eq!(missing(&catalog, &config(0), &cov), ["INV-2"]);
        assert_eq!(missing(&catalog, &config(3), &cov), ["INV-2", "INV-3"]);
    }

    // SA-6
    #[test]
    fn sa_6_threat_without_known_row_is_reported() {
        let ok = Threat {
            id: Some("TH-1".into()),
            title: "Malicious user".into(),
            stride: vec!["E".into()],
            rows: vec!["INV-2".into()],
            ..Threat::default()
        };
        let unknown = Threat {
            id: Some("TH-3".into()),
            title: "Agent".into(),
            stride: vec!["S".into()],
            rows: vec!["G999".into()],
            ..Threat::default()
        };
        let catalog = Catalog {
            rules: vec![rule("INV-2", "x")],
            threats: vec![ok, unknown],
            ..Catalog::default()
        };
        let msgs: Vec<String> = threat_violations(&catalog)
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert_eq!(
            msgs,
            ["TH-2 is missing", "TH-3: row G999 is not in the catalog"]
        );
    }

    #[test]
    fn family_stage_override_lowers_but_never_raises_stage() {
        let mut later = rule("N-3", "x");
        later.stage = Some(5);
        let mut earlier = rule("N-4", "x");
        earlier.stage = None;
        let mut retired = rule("N-5", "x");
        retired.status = "retired".into();
        let mut rules = [later, earlier, retired, rule("INV-2", "x")];
        let o = StageOverride {
            family: "N".into(),
            stage: 0,
            reason: "test".into(),
        };
        apply_overrides(&mut rules, &[o]);
        let stages: Vec<_> = rules.iter().map(|r| r.stage).collect();
        assert_eq!(stages, [Some(0), Some(0), None, None]);
    }

    #[test]
    fn must_never_gaps_are_reported() {
        let rules = (1..=18)
            .filter(|n| *n != 7)
            .map(|n| rule(&format!("MUST-NEVER-{n}"), "x"))
            .collect();
        let msgs: Vec<String> = must_never_violations(&Catalog {
            rules,
            ..Catalog::default()
        })
        .into_iter()
        .map(|v| v.message)
        .collect();
        assert!(
            msgs.contains(&"MUST-NEVER-7 has no mapping entry".to_owned()),
            "{msgs:?}"
        );
        assert!(
            msgs.contains(&"MUST-NEVER-19 has no mapping entry".to_owned()),
            "{msgs:?}"
        );
    }

    #[test]
    fn rendered_rules_parse_back_identically() {
        let mut r = rule("INV-2", "Single \"write\" path");
        r.stage = Some(3);
        r.class = Some("BS".into());
        r.tests = vec![
            "crates/a/tests/x.rs::inv_2_one".into(),
            "crates/a/tests/x.rs::inv_2_two".into(),
        ];
        let text = render_rules("intro", "rule", std::slice::from_ref(&r));
        let parsed: RuleFile = toml::from_str(&text).unwrap();
        assert_eq!(parsed.rule, [r]);
    }

    #[test]
    fn rendered_threat_model_parses_back_identically() {
        let t = Threat {
            group: Some("identity plane".into()),
            ordinal: Some(1),
            title: "Credential stuffing".into(),
            stride: vec!["I".into()],
            linddun: vec!["Identifying".into()],
            rows: vec!["U44".into()],
            refs: vec!["§13.2".into()],
            ..Threat::default()
        };
        let mut ab = rule("AB-1", "Approval fatigue");
        ab.status = "frozen".into();
        let text = render_threats(std::slice::from_ref(&t), std::slice::from_ref(&ab));
        let parsed: ThreatFile = toml::from_str(&text).unwrap();
        assert_eq!((parsed.threat, parsed.abuse_case), (vec![t], vec![ab]));
    }
}
