//! `security-model`: `conformance/SECURITY-MODEL.md` is generated from the catalogs (the verdict,
//! DL-1…DL-10, the trust model, the hard limits with their honest wording, the residual risks
//! with owner, acceptance and signal, the threat model and the formal scope), and the catalog
//! rows it publishes are complete (SEC1, SEC5, RT28, §13.9, OP-159 m.3 (gg)).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::trust_model;
use crate::Violation;
use crate::catalog::{self, Catalog, Rule, pasta};

pub(crate) const FILE: &str = "conformance/SECURITY-MODEL.md";
const GUARANTEES: &str = "conformance/catalog/guarantees.toml";
const PROOFS: &str = "conformance/lean/proofs.toml";
const ALERTS: &str = "deploy/observability/alerts/access.yaml";
const EVENTS: &str = "conformance/catalog/events.toml";
const AUDIT: &str = "conformance/catalog/audit-taxonomy.toml";
const SOURCE_ROOTS: &[&str] = &["crates", "bins", "services"];
const NONE_DECLARED: &str = "none-declared";

/// §13.1, SEC1.
pub(crate) const VERDICT: &str = "SECURE WITH DECLARED LIMITS";

const VERDICT_TEXT: &str = "The model holds semantically under attack; there is no \
model-level vulnerability. No compromised issuer, IdP, publisher, provider operator, executor or \
verifier can mint positive authority beyond its own declared blast radius: positive authority \
arises only from a meta-Exercise in an Anchor lineage (INV-1, INV-2), every external input passes \
a use-typed Acceptance (INV-15), and every actor attribution rests on an Actor Intent Statement \
signed with the actor Instance's KeyBinding (PI-7). The remaining risks are declared limits, not \
hidden ones, and the product never states them as guarantees (XI-12).";

#[derive(Debug, Default, Deserialize)]
struct Theorem {
    name: String,
    #[serde(default)]
    rule: String,
    claim: String,
    status: String,
}

#[derive(Debug, Default, Deserialize)]
struct Proofs {
    #[serde(default)]
    theorem: Vec<Theorem>,
}

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"))
}

fn violation(path: &str, rule: &'static str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// What a signal may name: alert names, event and audit names, metric literals, CI jobs.
#[derive(Debug, Default)]
pub(crate) struct Signals {
    pub(crate) alerts: BTreeSet<String>,
    pub(crate) events: BTreeSet<String>,
    pub(crate) audit: BTreeSet<String>,
    pub(crate) metrics: BTreeSet<String>,
    pub(crate) jobs: BTreeSet<String>,
}

fn names_after(text: &str, key: &str) -> BTreeSet<String> {
    text.lines()
        .filter_map(|l| l.trim_start().strip_prefix(key))
        .filter_map(|rest| rest.trim().trim_matches('"').split('"').next().map(str::to_owned))
        .filter(|s| !s.is_empty())
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.filter_map(Result::ok) {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target" || n == "node_modules") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn metric_literals(root: &Path) -> BTreeSet<String> {
    let mut files = Vec::new();
    for r in SOURCE_ROOTS {
        rust_files(&root.join(r), &mut files);
    }
    let mut out = BTreeSet::new();
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        for part in text.split('"').skip(1).step_by(2) {
            if part.starts_with("access_")
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                out.insert(part.to_owned());
            }
        }
    }
    out
}

fn ci_jobs(root: &Path) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(root.join(".github/workflows")) else {
        return out;
    };
    for e in entries.filter_map(Result::ok) {
        let p = e.path();
        let Some(stem) = p
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".yml"))
            .map(str::to_owned)
        else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Some((_, jobs)) = text.split_once("\njobs:\n") else {
            continue;
        };
        for line in jobs.lines() {
            if let Some(name) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
                && !name.starts_with(' ')
                && !name.contains(' ')
            {
                out.insert(format!("{stem}/{name}"));
            }
        }
    }
    out
}

pub(crate) fn signals(root: &Path) -> Result<Signals, String> {
    Ok(Signals {
        alerts: names_after(&read(root, ALERTS)?, "- alert:"),
        events: names_after(&read(root, EVENTS)?, "name ="),
        audit: names_after(&read(root, AUDIT)?, "event ="),
        metrics: metric_literals(root),
        jobs: ci_jobs(root),
    })
}

/// Whether one RR signal names something that exists.
pub(crate) fn signal_ok(s: &str, known: &Signals) -> bool {
    if s == NONE_DECLARED {
        return true;
    }
    match s.split_once(':') {
        Some(("alert", n)) => known.alerts.contains(n),
        Some(("event", n)) => known.events.contains(n),
        Some(("audit", n)) => known.audit.contains(n),
        Some(("metric", n)) => known.metrics.contains(n),
        Some(("ci", n)) => known.jobs.contains(n),
        _ => false,
    }
}

fn live<'a>(catalog: &'a Catalog, family: &str) -> Vec<&'a Rule> {
    catalog
        .rules
        .iter()
        .filter(|r| r.family == family && r.status != "retired")
        .collect()
}

/// Pure validation of the published rows, separated for tests: `covered` holds the IDs a test
/// or a forbidden-claims row cites.
pub(crate) fn row_violations(
    catalog: &Catalog,
    covered: &BTreeSet<String>,
    known: &Signals,
) -> Vec<Violation> {
    let mut out = Vec::new();
    for n in 1..=10 {
        let id = format!("DL-{n}");
        if !catalog.rules.iter().any(|r| r.id == id) {
            out.push(violation(GUARANTEES, "SEC1", format!("{id} is missing (§13.1)")));
        }
    }
    // RT28
    for hl in live(catalog, "HL") {
        if !covered.contains(&hl.id) {
            out.push(violation(
                GUARANTEES,
                "RT28",
                format!(
                    "{}: no forbidden-claims row and no honest-wording test (OP-159 m.3 (gg))",
                    hl.id
                ),
            ));
        }
    }
    // §13.9
    for rr in live(catalog, "RR") {
        let mut bad = |m: &str| {
            out.push(violation(GUARANTEES, "SEC1", format!("{}: {m}", rr.id)));
        };
        if rr.owner.as_deref().is_none_or(|o| o.trim().is_empty()) {
            bad("needs an owner");
        }
        if rr.acceptance.as_deref().is_none_or(|a| a.trim().is_empty()) {
            bad("needs the reason it is accepted");
        }
        if rr.signal.is_empty() {
            bad("needs a signal or `none-declared`");
        }
        if rr.signal.len() > 1 && rr.signal.iter().any(|s| s == NONE_DECLARED) {
            bad("`none-declared` stands alone");
        }
        for s in rr.signal.iter().filter(|s| !signal_ok(s, known)) {
            bad(&format!("signal {s:?} names no existing alert, event, metric or CI job"));
        }
    }
    out
}

fn table(out: &mut String, head: &[&str], rows: &[Vec<String>]) {
    let _ = writeln!(out, "| {} |", head.join(" | "));
    let _ = writeln!(
        out,
        "|{}",
        head.iter().map(|_| "---|").collect::<String>()
    );
    for r in rows {
        let cells: Vec<String> = r.iter().map(|c| cell(c)).collect();
        let _ = writeln!(out, "| {} |", cells.join(" | "));
    }
}

fn class_name(c: Option<&str>) -> &'static str {
    match c {
        Some("BS") => "Guaranteed by semantics",
        Some("UDC") => "Under declared capability",
        Some("NG") => "Not guaranteed",
        Some("PU") => "Physically unsatisfiable",
        Some("NG/PU") => "Not guaranteed / physically unsatisfiable",
        _ => "Not guaranteed",
    }
}

/// The document, from the catalogs.
#[expect(clippy::too_many_lines, reason = "one section after another")]
pub(crate) fn render(root: &Path) -> Result<String, String> {
    let catalog = catalog::load(root)?;
    let model = trust_model::load(root)?;
    let claims = catalog::claims_rows(root)?;
    let proofs: Proofs = toml::from_str(&read(root, PROOFS)?).map_err(|e| format!("{PROOFS}: {e}"))?;
    let (flows, trees) = pasta::load(root)?;

    let mut out = String::new();
    out.push_str("# Access security model\n\n");
    out.push_str(
        "<!-- Generated by `cargo xtask security-model` from conformance/catalog; do not edit. -->\n\n",
    );
    out.push_str(
        "This page states what Access guarantees, what it does not, who owns each remaining \
risk and how it is watched. Every row comes from the machine-readable catalogs in \
[`catalog/`](catalog), and `cargo xtask check` fails when this page and the catalogs differ.\n\n",
    );
    let _ = writeln!(out, "## Verdict\n\n**{VERDICT}.** {VERDICT_TEXT}\n");

    out.push_str("## Declared limits\n\n");
    out.push_str("Each limit is classed in the guarantee matrix and owned as a residual risk below.\n\n");
    let dl: Vec<Vec<String>> = catalog
        .rules
        .iter()
        .filter(|r| r.family == "DL")
        .map(|r| vec![r.id.clone(), r.title.clone(), class_name(r.class.as_deref()).to_owned()])
        .collect();
    table(&mut out, &["ID", "Limit", "Class"], &dl);

    out.push_str("\n## Trust model\n\n");
    out.push_str(
        "For each component: what it is trusted with, what it is never trusted with, the widest \
result if it is fully malicious, what it can never do (a boundary guaranteed by semantics) and \
the attributable lever that contains it.\n\n",
    );
    let tm: Vec<Vec<String>> = model
        .component
        .iter()
        .map(|c| {
            vec![
                c.component.clone(),
                c.trust.clone(),
                c.not_trusted.clone(),
                c.blast_radius.clone(),
                c.never.clone(),
                c.containment.clone(),
            ]
        })
        .collect();
    table(
        &mut out,
        &["Component", "Trusted with", "Never trusted with", "Blast radius", "Never", "Containment"],
        &tm,
    );

    out.push_str("\n## Known hard limits\n\n");
    out.push_str(
        "No hard limit is ever part of a product promise. Each one names the honest wording that \
replaces a claim the product must not make.\n\n",
    );
    let hl: Vec<Vec<String>> = catalog
        .rules
        .iter()
        .filter(|r| r.family == "HL" && r.status != "retired")
        .map(|r| {
            let honest: Vec<&str> = claims
                .iter()
                .filter(|(_, rows, _)| rows.contains(&r.id))
                .map(|(_, _, h)| h.as_str())
                .collect();
            vec![r.id.clone(), r.title.clone(), honest.join(" ")]
        })
        .collect();
    table(&mut out, &["ID", "Hard limit", "Honest wording"], &hl);

    out.push_str("\n## Residual risks\n\n");
    let rr: Vec<Vec<String>> = catalog
        .rules
        .iter()
        .filter(|r| r.family == "RR" && r.status != "retired")
        .map(|r| {
            let signal = r
                .signal
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ");
            vec![
                r.id.clone(),
                r.title.clone(),
                r.owner.clone().unwrap_or_default(),
                r.acceptance.clone().unwrap_or_default(),
                signal,
            ]
        })
        .collect();
    table(&mut out, &["ID", "Risk", "Owner", "Why accepted", "Signal"], &rr);
    out.push_str(
        "\nA signal is an alert (`alert:`), a logged event (`event:`, `audit:`), a metric \
(`metric:`) or a CI job (`ci:<workflow>/<job>`); `none-declared` means no signal is declared yet.\n",
    );

    out.push_str("\n## Threat model\n\n");
    let _ = writeln!(
        out,
        "{} threat rows (STRIDE and LINDDUN) are in [`catalog/threat-model.toml`](catalog/threat-model.toml). \
The high-impact flows are analysed in the seven PASTA stages in [`threat/pasta/`](threat/pasta), each with an \
attack tree in [`threat/trees/`](threat/trees) whose every leaf names a threat row and a test or a declared limit.\n",
        catalog.threats.len()
    );
    let fl: Vec<Vec<String>> = flows
        .values()
        .map(|p| {
            let leaves = trees.get(&p.flow).map_or(0, |t| {
                t.node.iter().filter(|n| n.gate == "leaf").count()
            });
            vec![p.title.clone(), leaves.to_string()]
        })
        .collect();
    table(&mut out, &["Flow", "Attack tree leaves"], &fl);
    out.push('\n');
    let ab: Vec<Vec<String>> = catalog
        .abuse_cases
        .iter()
        .map(|a| vec![a.id.clone(), a.title.clone(), a.tests.len().to_string()])
        .collect();
    table(&mut out, &["Abuse case", "Title", "Tests"], &ab);

    out.push_str("\n## Formal scope\n\n");
    out.push_str(
        "Each line is a property of a model, machine-checked by the named tool; nothing outside \
the model is covered (HL-29). The async runtime, the HTTP layer, the compiler and the CPU are \
outside it (HL-15, HL-16).\n\n",
    );
    let fs: Vec<Vec<String>> = proofs
        .theorem
        .iter()
        .map(|t| {
            let status = if t.status == "proved" {
                "machine-checked (Lean)"
            } else {
                "stated, not yet proved"
            };
            vec![t.claim.clone(), format!("`{}`", t.name), t.rule.clone(), status.to_owned()]
        })
        .collect();
    table(&mut out, &["Property of AccessAlgebra", "Theorem", "Rule", "Status"], &fs);

    out.push_str("\n## Conformance and certification\n\n");
    out.push_str(
        "The conformance suite runs without a Suiss account and without network access to Suiss: \
the vectors, the reference evaluator and the PEP runner are in this folder, and the PEP runner \
only talks to fake upstreams on the loopback interface. Suiss-hosted Access is held to the same \
suite, which CI runs against our own server. Passing a profile is a published test result for \
named vectors; conformance is not endorsement. Suiss sells no certification or assessment \
service, and an audit of Access is never sold as a Suiss certificate.\n",
    );
    Ok(out)
}

fn covered(root: &Path, catalog: &Catalog) -> Result<BTreeSet<String>, String> {
    let config = catalog::load_config(root)?;
    let cov = catalog::coverage(root, catalog, &config)?;
    Ok(cov.by_id.into_keys().collect())
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let catalog = catalog::load(root)?;
    let mut out = row_violations(&catalog, &covered(root, &catalog)?, &signals(root)?);
    let want = render(root)?;
    match std::fs::read_to_string(root.join(FILE)) {
        Ok(have) if have == want => {}
        Ok(_) => out.push(violation(
            FILE,
            "SEC1",
            "out of date; run `cargo xtask security-model`".to_owned(),
        )),
        Err(_) => out.push(violation(
            FILE,
            "SEC1",
            "missing; run `cargo xtask security-model`".to_owned(),
        )),
    }
    Ok(out)
}

/// `cargo xtask security-model [--check]`.
pub(crate) fn write(root: &Path, check_only: bool) -> Result<(), String> {
    if check_only {
        let found = check(root)?;
        if found.is_empty() {
            return Ok(());
        }
        let lines: Vec<String> = found.into_iter().map(|v| v.message).collect();
        return Err(lines.join("\n"));
    }
    let text = render(root)?;
    std::fs::write(root.join(FILE), text).map_err(|e| format!("{FILE}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, family: &str) -> Rule {
        Rule {
            id: id.to_owned(),
            family: family.to_owned(),
            status: "canonical".to_owned(),
            ..Rule::default()
        }
    }

    fn known() -> Signals {
        Signals {
            alerts: std::iter::once("AccessSignerSlow".to_owned()).collect(),
            jobs: std::iter::once("nightly/dudect".to_owned()).collect(),
            ..Signals::default()
        }
    }

    // SEC1, RT28, §13.9, OP-159 m.3 (gg)
    #[test]
    fn rr_rows_need_owner_acceptance_and_a_real_signal_and_hl_rows_an_honest_wording() {
        let mut rules: Vec<Rule> = (1..=10).map(|n| rule(&format!("DL-{n}"), "DL")).collect();
        let mut rr = rule("RR-1", "RR");
        rr.owner = Some("o".into());
        rr.acceptance = Some("a".into());
        rr.signal = vec!["alert:AccessSignerSlow".into(), "ci:nightly/dudect".into()];
        rules.push(rr);
        rules.push(rule("HL-1", "HL"));
        let mut cat = Catalog {
            rules,
            ..Catalog::default()
        };
        let cov: BTreeSet<String> = std::iter::once("HL-1".to_owned()).collect();
        assert!(row_violations(&cat, &cov, &known()).is_empty());

        cat.rules.retain(|r| r.id != "DL-7");
        if let Some(r) = cat.rules.iter_mut().find(|r| r.id == "RR-1") {
            r.owner = None;
            r.signal = vec!["metric:access_made_up".into()];
        }
        let found: Vec<String> = row_violations(&cat, &BTreeSet::new(), &known())
            .into_iter()
            .map(|v| v.message)
            .collect();
        assert!(found.iter().any(|m| m.contains("DL-7 is missing")), "{found:?}");
        assert!(found.iter().any(|m| m.contains("needs an owner")), "{found:?}");
        assert!(found.iter().any(|m| m.contains("access_made_up")), "{found:?}");
        assert!(found.iter().any(|m| m.contains("HL-1: no forbidden-claims row")), "{found:?}");
    }

    // SEC1, SEC5, OP-159 m.3 (gg)
    #[test]
    fn the_published_model_carries_the_verdict_and_every_never_boundary() {
        let root = crate::workspace_root();
        let text = render(&root).unwrap_or_default();
        assert!(text.contains(&format!("**{VERDICT}.**")));
        for n in 1..=10 {
            assert!(text.contains(&format!("| DL-{n} |")), "DL-{n}");
        }
        let model = trust_model::load(&root).unwrap_or_default();
        assert!(!model.component.is_empty());
        for c in &model.component {
            assert!(text.contains(&cell(&c.never)), "{}", c.id);
        }
        let found = check(&root).unwrap_or_else(|e| vec![violation(FILE, "SEC1", e)]);
        assert!(found.is_empty(), "{found:?}");
    }
}
