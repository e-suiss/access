//! `compliance-map` (SA-53, SA-55, OP-159 m.3 (ii)): every compliance control cites catalog rows and existing tests, and makes no new claim.
//!
//! - One file per framework in `conformance/compliance/`; every framework of OP-159 m.3 (ii)
//!   has its file.
//! - A control's `status` is `met`, `partial`, `not-claimed` or `n/a`; a `met` control names at
//!   least one catalog row and one test, the others say in `note` what is missing.
//! - Every `rules` entry is a catalog row, every `tests` entry resolves to a function.
//! - A note makes no claim the catalog does not: no forbidden claim, and no guarantee word
//!   unless it is negated ("not guaranteed").
//! - `README.md` is generated from the files: `cargo xtask compliance-map`.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::catalog::{self, find_claims};

pub(crate) const DIR: &str = "conformance/compliance";
pub(crate) const README: &str = "conformance/compliance/README.md";

/// The frameworks of OP-159 m.3 (ii), by file stem.
pub(crate) const FRAMEWORKS: &[&str] = &[
    "pci-dss-4",
    "hipaa-security",
    "nist-800-53",
    "omb-m-22-09",
    "soc2",
    "iso-27001",
    "nis2",
    "dora",
    "eidas-2",
    "eudi-arf",
    "psd2-sca",
    "tr-payments",
    "owasp-asvs-5",
    "wcag-2-2",
    "residency",
    "nist-800-63-4",
];

const STATUSES: [&str; 4] = ["met", "partial", "not-claimed", "n/a"];

const GUARANTEE_WORDS: &[&str] = &[
    "guarantee",
    "guarantees",
    "guaranteed",
    "ensures",
    "compliant",
    "certified",
    "certifies",
    "conformant",
    "proves",
];

const NEGATIONS: &[&str] = &["not", "no", "never", "without", "nor"];

/// One dated milestone of a framework (OP-159 m.3 (ii), EUDI).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Milestone {
    pub(crate) date: String,
    pub(crate) what: String,
}

/// One control.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names, reason = "the schema's keys")]
pub(crate) struct Control {
    pub(crate) control: String,
    pub(crate) status: String,
    pub(crate) rules: Vec<String>,
    pub(crate) tests: Vec<String>,
    #[serde(default)]
    pub(crate) note: Option<String>,
}

/// One framework's mapping.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Mapping {
    pub(crate) version: u32,
    pub(crate) framework: String,
    #[serde(default)]
    pub(crate) edition: Option<String>,
    #[serde(default)]
    pub(crate) milestone: Vec<Milestone>,
    #[serde(default)]
    pub(crate) control: Vec<Control>,
}

/// What a mapping is checked against.
pub(crate) struct Known<'a> {
    pub(crate) rows: &'a BTreeSet<String>,
    pub(crate) link_ok: &'a dyn Fn(&str) -> bool,
    pub(crate) claims: &'a [catalog::ClaimRow],
}

fn violation(file: &str, rule: &'static str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{DIR}/{file}")),
        message,
    }
}

/// Guarantee words of `text` that no negation in the three words before qualifies.
pub(crate) fn unqualified_guarantees(text: &str) -> Vec<String> {
    let words: Vec<String> = text
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|w| !w.is_empty())
        .map(str::to_lowercase)
        .collect();
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if !GUARANTEE_WORDS.contains(&w.as_str()) {
            continue;
        }
        let negated = words
            .get(i.saturating_sub(3)..i)
            .unwrap_or_default()
            .iter()
            .any(|b| NEGATIONS.contains(&b.as_str()));
        if !negated {
            out.push(w.clone());
        }
    }
    out
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        })
}

/// Pure validation of one file, separated for tests.
pub(crate) fn violations(file: &str, m: &Mapping, known: &Known<'_>) -> Vec<Violation> {
    let mut out = Vec::new();
    let v = |msg: String| violation(file, "SA-53", msg);
    if m.version != 1 {
        out.push(v(format!("version {} is not 1", m.version)));
    }
    if m.framework.trim().is_empty() {
        out.push(v(String::from("names no framework")));
    }
    if m.control.is_empty() {
        out.push(v(String::from("maps no control")));
    }
    for ms in &m.milestone {
        if !is_date(&ms.date) || ms.what.trim().is_empty() {
            out.push(v(format!(
                "milestone {:?}: needs a YYYY-MM-DD date and what it is",
                ms.date
            )));
        }
    }
    let mut seen = BTreeSet::new();
    for c in &m.control {
        let id = &c.control;
        if id.trim().is_empty() {
            out.push(v(String::from("a control has no identifier")));
        }
        if !seen.insert(id.as_str()) {
            out.push(v(format!("{id}: mapped twice")));
        }
        if !STATUSES.contains(&c.status.as_str()) {
            out.push(v(format!("{id}: status {:?} is unknown", c.status)));
        }
        for r in c.rules.iter().filter(|r| !known.rows.contains(*r)) {
            out.push(v(format!("{id}: row {r} is not in the catalog")));
        }
        for t in c.tests.iter().filter(|t| !(known.link_ok)(t)) {
            out.push(v(format!("{id}: test {t:?} does not resolve")));
        }
        let note = c.note.as_deref().unwrap_or_default();
        match c.status.as_str() {
            "met" if c.rules.is_empty() => {
                out.push(v(format!("{id}: met but cites no catalog row")));
            }
            "met" if c.tests.is_empty() => {
                out.push(v(format!("{id}: met but names no test")));
            }
            "partial" | "not-claimed" | "n/a" if note.trim().is_empty() => {
                out.push(v(format!(
                    "{id}: {} needs a note saying what is missing or why",
                    c.status
                )));
            }
            _ => {}
        }
        for (_, claim, phrase) in find_claims(note, known.claims, false) {
            out.push(v(format!(
                "{id}: note makes the forbidden claim {claim} ({phrase:?})"
            )));
        }
        for w in unqualified_guarantees(note) {
            out.push(v(format!(
                "{id}: note says {w:?}; a mapping adds no claim of its own"
            )));
        }
    }
    out
}

/// Every mapping file, by file name.
pub(crate) fn load(root: &Path) -> Result<Vec<(String, Mapping)>, String> {
    let dir = root.join(DIR);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{DIR}: {e}"))?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().map(str::to_owned))
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
        })
        .collect();
    names.sort();
    let mut out = Vec::new();
    for n in names {
        let text = std::fs::read_to_string(dir.join(&n)).map_err(|e| format!("{DIR}/{n}: {e}"))?;
        let m: Mapping = toml::from_str(&text).map_err(|e| format!("{DIR}/{n}: {e}"))?;
        out.push((n, m));
    }
    Ok(out)
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// The counts of `m` by status, in [`STATUSES`] order.
fn counts(m: &Mapping) -> [usize; 4] {
    let mut out = [0_usize; 4];
    for c in &m.control {
        if let Some(i) = STATUSES.iter().position(|s| *s == c.status)
            && let Some(slot) = out.get_mut(i)
        {
            *slot = (*slot).saturating_add(1);
        }
    }
    out
}

/// `README.md` from the mappings.
pub(crate) fn render(files: &[(String, Mapping)]) -> String {
    let mut out = String::from(
        "# Compliance mappings\n\n\
One file per framework, `<framework>.toml`, maps each control to the guarantee rows and tests\n\
that already back it. A mapping adds no claim of its own: every row it cites is in\n\
[`catalog/`](../catalog), every test it names exists, and a control marked `met` names at least\n\
one row and one test. Statutory conformity is not guaranteed by any mapping; whether a\n\
deployment meets a regulation is the operator's own assessment.\n\n\
| Field | Meaning |\n|---|---|\n\
| `control` | the framework's control identifier |\n\
| `status` | `met`, `partial`, `not-claimed` or `n/a` |\n\
| `rules` | catalog rows that back it |\n\
| `tests` | tests that exercise it |\n\
| `note` | the scope of the mapping, or what is missing |\n\n\
The shape is [`compliance-map.schema.json`](../schemas/compliance-map.schema.json).\n\
`cargo xtask check` (`compliance-map`) checks every file here, and `cargo xtask compliance-map`\n\
writes this page from them.\n\n\
## Frameworks\n\n\
| Framework | File | Met | Partial | Not claimed | n/a |\n|---|---|---|---|---|---|\n",
    );
    for (name, m) in files {
        let [met, partial, not, na] = counts(m);
        let title = match &m.edition {
            Some(e) => format!("{} ({e})", m.framework),
            None => m.framework.clone(),
        };
        let _ = writeln!(
            out,
            "| {} | [`{name}`]({name}) | {met} | {partial} | {not} | {na} |",
            cell(&title)
        );
    }
    for (name, m) in files {
        let _ = write!(out, "\n## {}\n\n", cell(&m.framework));
        if let Some(e) = &m.edition {
            let _ = writeln!(out, "Edition: {}. Source: [`{name}`]({name}).\n", cell(e));
        } else {
            let _ = writeln!(out, "Source: [`{name}`]({name}).\n");
        }
        if !m.milestone.is_empty() {
            for ms in &m.milestone {
                let _ = writeln!(out, "- {}: {}", ms.date, cell(&ms.what));
            }
            out.push('\n');
        }
        out.push_str("| Control | Status | Rows | Tests | Note |\n|---|---|---|---|---|\n");
        for c in &m.control {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                cell(&c.control),
                c.status,
                cell(&c.rules.join(", ")),
                c.tests.len(),
                cell(c.note.as_deref().unwrap_or_default())
            );
        }
    }
    out
}

/// Runs `compliance-map`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let files = load(root)?;
    let rows = catalog::load(root)?.ids();
    let claims = catalog::forbidden_claims(root)?;
    let link_ok = |l: &str| catalog::link_exists(root, l);
    let known = Known {
        rows: &rows,
        link_ok: &link_ok,
        claims: &claims,
    };
    let mut out = Vec::new();
    for (name, m) in &files {
        out.extend(violations(name, m, &known));
    }
    for f in FRAMEWORKS {
        let name = format!("{f}.toml");
        if !files.iter().any(|(n, _)| *n == name) {
            out.push(violation(
                &name,
                "SA-53",
                String::from("missing; every framework of OP-159 m.3 (ii) has its mapping"),
            ));
        }
    }
    let want = render(&files);
    match std::fs::read_to_string(root.join(README)) {
        Ok(have) if have == want => {}
        _ => out.push(Violation {
            rule: "SA-53",
            path: PathBuf::from(README),
            message: String::from("out of date; run `cargo xtask compliance-map`"),
        }),
    }
    let controls: usize = files.iter().map(|(_, m)| m.control.len()).sum();
    println!(
        "      compliance-map: {} frameworks, {controls} controls",
        files.len()
    );
    Ok(out)
}

/// `cargo xtask compliance-map [--check]`.
pub(crate) fn write(root: &Path, check_only: bool) -> Result<(), String> {
    if check_only {
        let found = check(root)?;
        if found.is_empty() {
            return Ok(());
        }
        let lines: Vec<String> = found.into_iter().map(|v| v.message).collect();
        return Err(lines.join("\n"));
    }
    let text = render(&load(root)?);
    std::fs::write(root.join(README), text).map_err(|e| format!("{README}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows() -> BTreeSet<String> {
        ["G14", "U53"].iter().map(|s| (*s).to_owned()).collect()
    }

    fn control(id: &str, status: &str, rules: &[&str], tests: &[&str]) -> Control {
        Control {
            control: id.to_owned(),
            status: status.to_owned(),
            rules: rules.iter().map(|s| (*s).to_owned()).collect(),
            tests: tests.iter().map(|s| (*s).to_owned()).collect(),
            note: None,
        }
    }

    fn mapping(control: Vec<Control>) -> Mapping {
        Mapping {
            version: 1,
            framework: String::from("PCI DSS"),
            edition: Some(String::from("4.0.1")),
            milestone: Vec::new(),
            control,
        }
    }

    fn messages(m: &Mapping) -> Vec<String> {
        let rows = rows();
        let link_ok = |l: &str| l == "crates/x/tests/a.rs::real";
        let claims = vec![catalog::ClaimRow {
            id: String::from("j9-compliance-guaranteed"),
            scope: String::from("all"),
            phrases: vec![String::from("pci dss compliant")],
            negation: true,
            ..catalog::ClaimRow::default()
        }];
        let known = Known {
            rows: &rows,
            link_ok: &link_ok,
            claims: &claims,
        };
        violations("pci-dss-4.toml", m, &known)
            .into_iter()
            .map(|v| v.message)
            .collect()
    }

    // SA-53
    #[test]
    fn sa_53_a_mapping_that_marks_met_a_guarantee_not_in_the_catalog_is_refused() {
        let ok = mapping(vec![control(
            "8.4.2",
            "met",
            &["G14"],
            &["crates/x/tests/a.rs::real"],
        )]);
        assert_eq!(messages(&ok), Vec::<String>::new());
        let invented = mapping(vec![control(
            "8.4.2",
            "met",
            &["G999"],
            &["crates/x/tests/a.rs::real"],
        )]);
        assert_eq!(
            messages(&invented),
            ["8.4.2: row G999 is not in the catalog"]
        );
        let bare = mapping(vec![control("8.4.2", "met", &[], &[])]);
        assert_eq!(messages(&bare), ["8.4.2: met but cites no catalog row"]);
        let untested = mapping(vec![control("8.4.2", "met", &["G14"], &[])]);
        assert_eq!(messages(&untested), ["8.4.2: met but names no test"]);
        let ghost = mapping(vec![control(
            "8.4.2",
            "met",
            &["G14"],
            &["crates/x/tests/a.rs::imagined"],
        )]);
        assert_eq!(
            messages(&ghost),
            ["8.4.2: test \"crates/x/tests/a.rs::imagined\" does not resolve"]
        );
    }

    // SA-53, OP-159 m.3 (ii)
    #[test]
    fn sa_53_a_note_that_adds_a_claim_is_refused() {
        let mut c = control("10.2.1", "met", &["U53"], &["crates/x/tests/a.rs::real"]);
        c.note = Some(String::from("Access is PCI DSS compliant here."));
        let mut d = control("10.5.1", "partial", &[], &[]);
        d.note = Some(String::from("The export ensures retention."));
        let mut e = control("10.7.1", "not-claimed", &[], &[]);
        e.note = Some(String::from("Statutory conformity is not guaranteed."));
        let f = control("10.7.2", "n/a", &[], &[]);
        assert_eq!(
            messages(&mapping(vec![c, d, e, f])),
            [
                "10.2.1: note makes the forbidden claim j9-compliance-guaranteed (\"pci dss compliant\")",
                "10.2.1: note says \"compliant\"; a mapping adds no claim of its own",
                "10.5.1: note says \"ensures\"; a mapping adds no claim of its own",
                "10.7.2: n/a needs a note saying what is missing or why",
            ]
        );
    }

    // SA-53
    #[test]
    fn sa_53_an_unknown_status_a_repeated_control_and_a_bad_milestone_are_refused() {
        let mut m = mapping(vec![
            control("1", "done", &[], &[]),
            control("2", "met", &["G14"], &["crates/x/tests/a.rs::real"]),
            control("2", "met", &["G14"], &["crates/x/tests/a.rs::real"]),
        ]);
        m.milestone.push(Milestone {
            date: String::from("Dec 2026"),
            what: String::from("x"),
        });
        assert_eq!(
            messages(&m),
            [
                "milestone \"Dec 2026\": needs a YYYY-MM-DD date and what it is",
                "1: status \"done\" is unknown",
                "2: mapped twice",
            ]
        );
    }

    #[test]
    fn the_repository_mappings_are_complete_and_the_page_is_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let found: Vec<String> = check(root)
            .unwrap_or_default()
            .into_iter()
            .map(|v| format!("{}: {}", v.path.display(), v.message))
            .collect();
        assert_eq!(found, Vec::<String>::new());
    }
}
