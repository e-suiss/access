//! `support-policy` (OP-68, OP-159 m.3 (jj)): the supported versions table and the support policy come from the same data.
//! `conformance/catalog/support-policy.toml` holds the support period, the supported minors,
//! the disclosure and fix times, the CRA Art. 14 periods, the released minors and the CRA
//! technical obligations; SECURITY.md's "Supported versions" and "Fix times" sections are
//! generated from it, and the release gate tags only supported minors from main or their
//! maintenance branch (B20).

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::Violation;
use crate::catalog;
use crate::civil;

const RULE: &str = "support-policy";
pub(crate) const FILE: &str = "conformance/catalog/support-policy.toml";
const SECURITY_MD: &str = "SECURITY.md";
const RELEASE: &str = ".github/workflows/release.yml";
const CI: &str = ".github/workflows/ci.yml";
const BRANCH: &str = "release/v<major>.<minor>";
const MIN_YEARS: u32 = 5;
const MIN_MINORS: usize = 2;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names, reason = "the catalog's keys")]
pub(crate) struct Disclosure {
    pub(crate) embargo_days: u32,
    pub(crate) acknowledge_days: u32,
    pub(crate) assessment_days: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FixTarget {
    pub(crate) severity: String,
    pub(crate) cvss: String,
    pub(crate) days: u32,
}

/// CRA Art. 14 reporting periods (§18.11, SA-16).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cra {
    pub(crate) early_warning_hours: u32,
    pub(crate) notification_hours: u32,
    pub(crate) final_report_vulnerability_days: u32,
    pub(crate) final_report_incident_months: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names, reason = "the catalog's keys")]
pub(crate) struct Version {
    pub(crate) version: String,
    pub(crate) released: String,
    pub(crate) security_until: String,
    pub(crate) status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Obligation {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) source: String,
    pub(crate) status: String,
    pub(crate) artefacts: Vec<String>,
    pub(crate) tests: Vec<String>,
    #[serde(default)]
    pub(crate) needs: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Policy {
    pub(crate) version: u32,
    pub(crate) major_support_years: u32,
    pub(crate) supported_minors: usize,
    pub(crate) branch: String,
    pub(crate) disclosure: Disclosure,
    pub(crate) fix_target: Vec<FixTarget>,
    pub(crate) cra: Cra,
    pub(crate) versions: Vec<Version>,
    pub(crate) obligation: Vec<Obligation>,
}

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

pub(crate) fn parse(text: &str) -> Result<Policy, String> {
    toml::from_str(text).map_err(|e| format!("{FILE}: {e}"))
}

pub(crate) fn load(root: &Path) -> Result<Policy, String> {
    let text = std::fs::read_to_string(root.join(FILE)).map_err(|e| format!("{FILE}: {e}"))?;
    parse(&text)
}

fn major_minor(s: &str) -> Option<(u64, u64)> {
    let (a, b) = s.split_once('.')?;
    let ok = |x: &str| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit());
    if !ok(a)
        || !ok(b)
        || (a.len() > 1 && a.starts_with('0'))
        || (b.len() > 1 && b.starts_with('0'))
    {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn title_case(s: &str) -> String {
    let mut chars = s.chars();
    chars.next().map_or_else(String::new, |c| {
        c.to_uppercase().chain(chars).collect::<String>()
    })
}

/// Findings in the policy data on `today` (days since 1970-01-01).
pub(crate) fn policy_findings(p: &Policy, today: i64) -> Vec<String> {
    let mut out = Vec::new();
    if p.version != 1 {
        out.push(format!("version is {}, expected 1", p.version));
    }
    if p.major_support_years < MIN_YEARS {
        out.push(format!(
            "major_support_years is {}; each major receives security fixes for at least {MIN_YEARS} years (CRA Art. 13 (8))",
            p.major_support_years
        ));
    }
    if p.supported_minors < MIN_MINORS {
        out.push(format!(
            "supported_minors is {}; the {MIN_MINORS} newest minors of a major receive fixes (OP-68)",
            p.supported_minors
        ));
    }
    if p.branch != BRANCH {
        out.push(format!("branch is {:?}, expected {BRANCH:?}", p.branch));
    }
    if p.disclosure.embargo_days == 0 || p.disclosure.embargo_days > 90 {
        out.push(String::from("embargo_days is 1 to 90 (SA-14)"));
    }
    if p.disclosure.acknowledge_days > p.disclosure.assessment_days {
        out.push(String::from("acknowledge_days exceeds assessment_days"));
    }
    let order = ["critical", "high", "medium", "low"];
    let severities: Vec<&str> = p.fix_target.iter().map(|f| f.severity.as_str()).collect();
    if severities != order {
        out.push(format!(
            "fix_target lists {severities:?}; expected critical, high, medium, low in that order"
        ));
    }
    let mut last = 0;
    for f in &p.fix_target {
        if f.days < last {
            out.push(format!(
                "fix_target {}: fewer days than a more severe one",
                f.severity
            ));
        }
        if f.days > p.disclosure.embargo_days {
            out.push(format!("fix_target {}: past the embargo", f.severity));
        }
        last = f.days;
    }
    let c = &p.cra;
    if (c.early_warning_hours, c.notification_hours) != (24, 72)
        || c.final_report_vulnerability_days != 14
        || c.final_report_incident_months != 1
    {
        out.push(String::from(
            "cra periods are 24 h, 72 h, 14 days and 1 month (§18.11); a change is a spec decision first",
        ));
    }
    out.extend(version_findings(p, today));
    out
}

fn version_findings(p: &Policy, today: i64) -> Vec<String> {
    let mut out = Vec::new();
    let mut rows = Vec::new();
    for r in &p.versions {
        let (Some(mm), Some(released), Some(until)) = (
            major_minor(&r.version),
            civil::parse_date(&r.released),
            civil::parse_date(&r.security_until),
        ) else {
            out.push(format!(
                "{}: version is major.minor, released and security_until are YYYY-MM-DD",
                r.version
            ));
            continue;
        };
        if until < released {
            out.push(format!("{}: security_until precedes released", r.version));
        }
        if !matches!(r.status.as_str(), "supported" | "end-of-life") {
            out.push(format!("{}: status is supported or end-of-life", r.version));
        }
        rows.push((mm, released, until, r));
    }
    if rows.windows(2).any(|w| matches!(w, [a, b] if a.0 <= b.0)) {
        out.push(String::from("versions are listed newest first, each once"));
    }
    let mut rank = 0usize;
    let mut major = None;
    for (mm, _, until, r) in &rows {
        if major != Some(mm.0) {
            major = Some(mm.0);
            rank = 0;
        }
        let first = rows
            .iter()
            .filter(|x| x.0.0 == mm.0)
            .map(|x| x.1)
            .min()
            .unwrap_or(*until);
        let end = civil::add_years(first, p.major_support_years);
        let supported = rank < p.supported_minors && today <= end;
        let expected = if supported {
            "supported"
        } else {
            "end-of-life"
        };
        if r.status != expected {
            out.push(format!(
                "{}: status is {}, expected {expected} (the {} newest minors of a major, {} years from {})",
                r.version,
                r.status,
                p.supported_minors,
                p.major_support_years,
                civil::format_date(first)
            ));
        }
        if supported && *until < end {
            out.push(format!(
                "{}: security_until is {}, before the end of the major's support period {}",
                r.version,
                r.security_until,
                civil::format_date(end)
            ));
        }
        rank = rank.saturating_add(1);
    }
    out
}

/// Findings in the CRA technical obligations: a `met` obligation names tests that exist, a
/// `partial` one says what is missing.
pub(crate) fn obligation_findings(root: &Path, p: &Policy) -> Vec<String> {
    let mut out = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    for o in &p.obligation {
        if !ids.insert(o.id.as_str()) {
            out.push(format!("{}: listed twice", o.id));
        }
        if o.title.is_empty() || o.source.is_empty() {
            out.push(format!("{}: title and source are required", o.id));
        }
        match o.status.as_str() {
            "met" if o.tests.is_empty() => out.push(format!("{}: met names no test", o.id)),
            "met" if o.needs.is_some() => {
                out.push(format!("{}: met leaves nothing missing; drop needs", o.id));
            }
            "partial" if o.needs.as_deref().is_none_or(str::is_empty) => {
                out.push(format!("{}: partial says what is missing in needs", o.id));
            }
            "met" | "partial" => {}
            other => out.push(format!("{}: status {other:?} is met or partial", o.id)),
        }
        for t in o.tests.iter().filter(|t| !catalog::link_exists(root, t)) {
            out.push(format!("{}: test {t:?} does not exist", o.id));
        }
        for a in o.artefacts.iter().filter(|a| !root.join(a).exists()) {
            out.push(format!("{}: artefact {a:?} does not exist", o.id));
        }
    }
    out
}

/// The generated sections of SECURITY.md: heading and body.
pub(crate) fn sections(p: &Policy) -> Vec<(&'static str, String)> {
    let mut versions = format!(
        "Every major version receives security fixes for at least {} years from its first release. \
Within a major, the {} newest minor versions receive fixes. A fix for an older supported minor is \
released from its maintenance branch, `{}`. Versions before 1.0 form major 0.\n\n\
| Version | Released | Security fixes until | Status |\n|---|---|---|---|\n",
        p.major_support_years, p.supported_minors, p.branch
    );
    for r in &p.versions {
        let _ = writeln!(
            versions,
            "| {} | {} | {} | {} |",
            r.version, r.released, r.security_until, r.status
        );
    }
    let d = &p.disclosure;
    let mut fixes = format!(
        "We acknowledge a report within {} days and assess it with a CVSS v4 score within {} days. \
Disclosure is coordinated, with a default embargo of {} days that is shortened when a \
vulnerability is actively exploited. The target time from a confirmed report to a released fix:\n\n\
| Severity | CVSS v4 score | Fix released within |\n|---|---|---|\n",
        d.acknowledge_days, d.assessment_days, d.embargo_days
    );
    for f in &p.fix_target {
        let _ = writeln!(
            fixes,
            "| {} | {} | {} days |",
            title_case(&f.severity),
            f.cvss,
            f.days
        );
    }
    vec![("Supported versions", versions), ("Fix times", fixes)]
}

/// The body under `## heading` up to the next `## ` heading, and its byte range.
fn section_range(md: &str, heading: &str) -> Option<(usize, usize)> {
    let marker = format!("## {heading}\n\n");
    let start = if md.starts_with(&marker) {
        marker.len()
    } else {
        md.find(&format!("\n{marker}"))?
            .checked_add(marker.len())?
            .checked_add(1)?
    };
    let rest = md.get(start..)?;
    let end = rest
        .find("\n## ")
        .map_or(md.len(), |i| start.saturating_add(i).saturating_add(1));
    Some((start, end))
}

/// Findings when SECURITY.md's generated sections differ from the catalog.
pub(crate) fn markdown_findings(md: &str, p: &Policy) -> Vec<String> {
    let mut out = Vec::new();
    for (heading, body) in sections(p) {
        match section_range(md, heading).and_then(|(s, e)| md.get(s..e)) {
            None => out.push(format!("no \"## {heading}\" section")),
            Some(found) if found.trim_end() != body.trim_end() => out.push(format!(
                "\"## {heading}\" differs from {FILE}; run `cargo xtask support-policy`"
            )),
            Some(_) => {}
        }
    }
    out
}

/// Findings when the release gate does not keep releases open and on supported minors (B20).
pub(crate) fn workflow_findings(release: &str, ci: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (needle, what) in [
        (
            "cargo xtask release-tag \"$TAG\"",
            "check the tag against the support policy",
        ),
        (
            "--jq .visibility",
            "refuse a release from a repository that is not public",
        ),
        (
            "compare/$maintenance...$SHA",
            "accept the maintenance branch of the tagged minor",
        ),
        (
            "branch=$branch",
            "require the passed CI run on the branch the tag is on",
        ),
    ] {
        if !release.contains(needle) {
            out.push((
                RELEASE,
                format!("the release gate must {what} (`{needle}`)"),
            ));
        }
    }
    let pushes_branches = ci
        .lines()
        .any(|l| l.trim_start().starts_with("branches:") && l.contains("\"release/v*\""));
    if !pushes_branches {
        out.push((
            CI,
            String::from("CI runs on pushes to the maintenance branches (`\"release/v*\"`)"),
        ));
    }
    out
}

/// OP-68, B20: the maintenance branch of a release tag `v<major>.<minor>.<patch>` when the
/// workspace is at that version and the minor is supported on `today`.
pub(crate) fn release_branch(
    p: &Policy,
    tag: &str,
    workspace: &str,
    today: i64,
) -> Result<String, String> {
    let version = tag
        .strip_prefix('v')
        .ok_or_else(|| format!("{tag}: a release tag is v<major>.<minor>.<patch>"))?;
    let (series, patch) = version
        .rsplit_once('.')
        .ok_or_else(|| format!("{tag}: a release tag is v<major>.<minor>.<patch>"))?;
    let (major, minor) = major_minor(series)
        .filter(|_| major_minor(&format!("0.{patch}")).is_some())
        .ok_or_else(|| format!("{tag}: a release tag is v<major>.<minor>.<patch>"))?;
    if version != workspace {
        return Err(format!(
            "{tag}: the workspace version is {workspace}; tag the commit that sets it"
        ));
    }
    let row = p
        .versions
        .iter()
        .find(|r| major_minor(&r.version) == Some((major, minor)))
        .ok_or_else(|| {
            format!(
                "{tag}: {series} is not in {FILE}; add its row and regenerate SECURITY.md first"
            )
        })?;
    let until = civil::parse_date(&row.security_until).unwrap_or(i64::MIN);
    if row.status != "supported" || today > until {
        return Err(format!(
            "{tag}: {series} is {} (security fixes until {}); only supported minors are released",
            row.status, row.security_until
        ));
    }
    Ok(format!("release/v{major}.{minor}"))
}

fn workspace_version(root: &Path) -> Result<String, String> {
    let text =
        std::fs::read_to_string(root.join("Cargo.toml")).map_err(|e| format!("Cargo.toml: {e}"))?;
    let value: toml::Value = toml::from_str(&text).map_err(|e| format!("Cargo.toml: {e}"))?;
    value
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| String::from("Cargo.toml: no workspace.package.version"))
}

/// `cargo xtask release-tag <tag>`: prints the maintenance branch or fails.
pub(crate) fn release_tag(root: &Path, tag: &str) -> Result<String, String> {
    let p = load(root)?;
    let today = civil::now().div_euclid(86_400);
    release_branch(&p, tag, &workspace_version(root)?, today)
}

/// `cargo xtask support-policy [--check]`: regenerates SECURITY.md's sections from the catalog.
pub(crate) fn write(root: &Path, check_only: bool) -> Result<(), String> {
    let p = load(root)?;
    let path = root.join(SECURITY_MD);
    let mut md = std::fs::read_to_string(&path).map_err(|e| format!("{SECURITY_MD}: {e}"))?;
    for (heading, body) in sections(&p) {
        let (s, e) = section_range(&md, heading)
            .ok_or_else(|| format!("{SECURITY_MD}: no \"## {heading}\" section"))?;
        let tail = if e < md.len() { "\n" } else { "" };
        md.replace_range(s..e, &format!("{body}{tail}"));
    }
    if check_only {
        let findings = markdown_findings(&md, &p);
        let current = std::fs::read_to_string(&path).map_err(|e| format!("{SECURITY_MD}: {e}"))?;
        return if current == md && findings.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{SECURITY_MD} is out of date; run `cargo xtask support-policy`"
            ))
        };
    }
    std::fs::write(&path, md).map_err(|e| format!("{SECURITY_MD}: {e}"))
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let p = load(root)?;
    let today = civil::now().div_euclid(86_400);
    let mut out: Vec<Violation> = policy_findings(&p, today)
        .into_iter()
        .chain(obligation_findings(root, &p))
        .map(|m| v(FILE, m))
        .collect();
    match std::fs::read_to_string(root.join(SECURITY_MD)) {
        Ok(md) => out.extend(
            markdown_findings(&md, &p)
                .into_iter()
                .map(|m| v(SECURITY_MD, m)),
        ),
        Err(e) => out.push(v(SECURITY_MD, e.to_string())),
    }
    let release = std::fs::read_to_string(root.join(RELEASE)).unwrap_or_default();
    let ci = std::fs::read_to_string(root.join(CI)).unwrap_or_default();
    out.extend(
        workflow_findings(&release, &ci)
            .into_iter()
            .map(|(path, m)| v(path, m)),
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assert_is_empty, reason = "test code")]

    use super::*;

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap()
    }

    fn policy() -> Policy {
        load(&root()).unwrap()
    }

    fn day(s: &str) -> i64 {
        civil::parse_date(s).unwrap()
    }

    // OP-68, OP-159 m.3 (jj)
    #[test]
    fn the_catalog_and_security_md_agree() {
        let p = policy();
        assert_eq!(policy_findings(&p, day("2026-11-12")), Vec::<String>::new());
        assert_eq!(obligation_findings(&root(), &p), Vec::<String>::new());
        let md = std::fs::read_to_string(root().join(SECURITY_MD)).unwrap();
        assert_eq!(markdown_findings(&md, &p), Vec::<String>::new());
    }

    // OP-68
    #[test]
    fn a_table_that_drifts_from_the_catalog_fails() {
        let p = policy();
        let md = std::fs::read_to_string(root().join(SECURITY_MD)).unwrap();
        let drifted = md.replace(
            "| 0.3 | 2026-11-06 | 2031-10-29 | supported |",
            "| 0.3 | 2026-11-06 | 2027-11-06 | supported |",
        );
        assert_ne!(drifted, md);
        assert_eq!(markdown_findings(&drifted, &p).len(), 1);
        let slower = md.replace(
            "| Critical | 9.0-10.0 | 14 days |",
            "| Critical | 9.0-10.0 | 21 days |",
        );
        assert_eq!(markdown_findings(&slower, &p).len(), 1);
        let gone = md.replace("## Fix times", "## Timelines");
        assert_eq!(markdown_findings(&gone, &p).len(), 1);
        let mut later = policy();
        later.versions.remove(0);
        assert_eq!(markdown_findings(&md, &later).len(), 1);
    }

    // OP-68, OP-159 m.3 (jj)
    #[test]
    fn a_support_period_under_five_years_fails() {
        let mut p = policy();
        p.major_support_years = 3;
        assert!(
            policy_findings(&p, day("2026-11-12"))
                .iter()
                .any(|f| f.contains("at least 5 years"))
        );
        let mut p = policy();
        p.supported_minors = 1;
        assert!(!policy_findings(&p, day("2026-11-12")).is_empty());
        let mut p = policy();
        if let Some(r) = p.versions.first_mut() {
            r.security_until = String::from("2030-01-01");
        }
        assert!(
            policy_findings(&p, day("2026-11-12"))
                .iter()
                .any(|f| f.contains("before the end of the major's support period"))
        );
    }

    // OP-68
    #[test]
    fn only_the_two_newest_minors_are_supported() {
        let mut p = policy();
        if let Some(r) = p.versions.get_mut(2) {
            r.status = String::from("supported");
            r.security_until = String::from("2031-10-29");
        }
        assert!(
            policy_findings(&p, day("2026-11-12"))
                .iter()
                .any(|f| f.starts_with("0.2: status is supported, expected end-of-life"))
        );
        let after = day("2031-10-30");
        assert!(
            policy_findings(&policy(), after)
                .iter()
                .any(|f| f.starts_with("0.4: status is supported, expected end-of-life"))
        );
        let mut p = policy();
        p.versions.swap(0, 1);
        assert!(!policy_findings(&p, day("2026-11-12")).is_empty());
    }

    // B20, OP-68
    #[test]
    fn a_tag_outside_the_supported_minors_fails() {
        let p = policy();
        let today = day("2026-11-12");
        assert_eq!(
            release_branch(&p, "v0.4.1", "0.4.1", today),
            Ok(String::from("release/v0.4"))
        );
        assert_eq!(
            release_branch(&p, "v0.3.2", "0.3.2", today),
            Ok(String::from("release/v0.3"))
        );
        assert!(release_branch(&p, "v0.2.7", "0.2.7", today).is_err());
        assert!(release_branch(&p, "v0.7.0", "0.7.0", today).is_err());
        assert!(release_branch(&p, "v0.4.1", "0.4.2", today).is_err());
        assert!(release_branch(&p, "v0.4.1", "0.4.1", day("2031-10-30")).is_err());
        for bad in ["0.4.1", "v0.4", "v0.4.1-rc.1", "v0.04.1", "f0-v0.1.0"] {
            assert!(release_branch(&p, bad, "0.4.1", today).is_err(), "{bad}");
        }
    }

    // B20, OP-68
    #[test]
    fn release_tags_only_from_main_or_a_maintenance_branch() {
        let release = std::fs::read_to_string(root().join(RELEASE)).unwrap();
        let ci = std::fs::read_to_string(root().join(CI)).unwrap();
        assert_eq!(workflow_findings(&release, &ci), Vec::new());
        let public_only = release.replace("--jq .visibility", "--jq .name");
        assert_eq!(workflow_findings(&public_only, &ci).len(), 1);
        let main_only = ci.replace(", \"release/v*\"", "");
        assert_eq!(workflow_findings(&release, &main_only).len(), 1);
        let unchecked = release.replace("cargo xtask release-tag \"$TAG\"", "echo main");
        assert_eq!(workflow_findings(&unchecked, &ci).len(), 1);
    }

    // B3, OP-159 m.3 (jj)
    #[test]
    fn release_publishes_an_sbom_for_every_binary() {
        let release = std::fs::read_to_string(root().join(RELEASE)).unwrap();
        assert!(release.contains("just sbom \"$TARGET\""));
        for arch in ["amd64", "arm64"] {
            assert!(release.contains(&format!(
                "sbom-path: dist/access-server-linux-{arch}.cdx.json"
            )));
        }
    }

    // OP-159 m.3 (jj)
    #[test]
    fn an_obligation_marked_met_needs_a_test_that_exists() {
        let mut p = policy();
        if let Some(o) = p.obligation.first_mut() {
            o.tests = vec![String::from(
                "xtask/src/rules_support_policy.rs::no_such_test",
            )];
        }
        assert_eq!(obligation_findings(&root(), &p).len(), 1);
        let mut p = policy();
        if let Some(o) = p.obligation.first_mut() {
            o.tests.clear();
        }
        assert_eq!(obligation_findings(&root(), &p).len(), 1);
        let mut p = policy();
        if let Some(o) = p.obligation.last_mut() {
            o.needs = None;
        }
        assert_eq!(obligation_findings(&root(), &p).len(), 1);
    }
}
