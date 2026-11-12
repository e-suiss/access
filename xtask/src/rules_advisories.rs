//! `advisories` (OP-159 m.3 (jj)): every advisory record is OSV-shaped and carries a CVSS v4 vector.
//! Records live in `security/advisories/<id>.json`; `cargo xtask advisory new` writes one and
//! the GitHub Security Advisory and `RustSec` drafts made from it (SA-15). The Go vulnerability
//! database is not a channel (MD-1).

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};

use super::files::{rel, walk};
use crate::Violation;
use crate::civil;

const RULE: &str = "advisories";
const DIR: &str = "security/advisories";
const SCHEMA_VERSION: &str = "1.6.0";
const DRAFTS: &str = "target/advisories";
const REPOSITORY: &str = "https://github.com/e-suiss/access";

const FIELDS: &[&str] = &[
    "schema_version",
    "id",
    "modified",
    "published",
    "withdrawn",
    "aliases",
    "upstream",
    "related",
    "summary",
    "details",
    "severity",
    "affected",
    "references",
    "credits",
    "database_specific",
];

const ECOSYSTEMS: &[&str] = &["crates.io", "npm"];
const REFERENCE_TYPES: &[&str] = &[
    "ADVISORY",
    "ARTICLE",
    "DETECTION",
    "DISCUSSION",
    "REPORT",
    "FIX",
    "INTRODUCED",
    "PACKAGE",
    "EVIDENCE",
    "WEB",
];

const CVSS4_BASE: &[(&str, &str)] = &[
    ("AV", "NALP"),
    ("AC", "LH"),
    ("AT", "NP"),
    ("PR", "NLH"),
    ("UI", "NPA"),
    ("VC", "HLN"),
    ("VI", "HLN"),
    ("VA", "HLN"),
    ("SC", "HLN"),
    ("SI", "HLN"),
    ("SA", "HLN"),
];

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: path.into(),
        message,
    }
}

type Group = (usize, fn(u8) -> bool);

fn shaped(s: &str, prefix: &str, groups: &[Group]) -> bool {
    let Some(rest) = s.strip_prefix(prefix) else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == groups.len()
        && parts
            .iter()
            .zip(groups)
            .all(|(p, (n, f))| p.len() == *n && p.bytes().all(*f))
}

fn digit(b: u8) -> bool {
    b.is_ascii_digit()
}

fn ghsa_char(b: u8) -> bool {
    b"23456789cfghjmpqrvwx".contains(&b)
}

/// The local record id: `ACCESS-<year>-<four digits>`.
pub(crate) fn is_local_id(s: &str) -> bool {
    shaped(s, "ACCESS-", &[(4, digit), (4, digit)])
}

fn is_alias(s: &str) -> bool {
    shaped(
        s,
        "GHSA-",
        &[(4, ghsa_char), (4, ghsa_char), (4, ghsa_char)],
    ) || shaped(s, "RUSTSEC-", &[(4, digit), (4, digit)])
        || (s.starts_with("CVE-")
            && s.split('-').count() == 3
            && s.split('-')
                .nth(1)
                .is_some_and(|y| y.len() == 4 && y.bytes().all(digit))
            && s.split('-')
                .nth(2)
                .is_some_and(|n| n.len() >= 4 && n.bytes().all(digit)))
}

/// A CVSS v4.0 vector with every base metric, in order.
pub(crate) fn is_cvss4(vector: &str) -> bool {
    let Some(rest) = vector.strip_prefix("CVSS:4.0/") else {
        return false;
    };
    let metrics: Vec<(&str, &str)> = rest.split('/').filter_map(|m| m.split_once(':')).collect();
    if metrics.len() != rest.split('/').count() || metrics.len() < CVSS4_BASE.len() {
        return false;
    }
    let base = metrics
        .iter()
        .zip(CVSS4_BASE)
        .all(|((k, val), (name, allowed))| k == name && val.len() == 1 && allowed.contains(*val));
    let mut seen = BTreeSet::new();
    base && metrics.iter().all(|(k, val)| {
        seen.insert(*k) && !val.is_empty() && val.bytes().all(|b| b.is_ascii_uppercase())
    })
}

fn string<'a>(r: &'a Value, key: &str) -> Option<&'a str> {
    r.get(key).and_then(Value::as_str)
}

/// Findings in one record named `file_id`.json; `packages` are the workspace's package names.
pub(crate) fn record_findings(
    file_id: &str,
    r: &Value,
    packages: &BTreeSet<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(obj) = r.as_object() else {
        return vec![String::from("an advisory record is a JSON object")];
    };
    for k in obj.keys().filter(|k| !FIELDS.contains(&k.as_str())) {
        out.push(format!("{k}: not an OSV field"));
    }
    if !string(r, "schema_version").is_some_and(|s| s.starts_with("1.")) {
        out.push(String::from("schema_version is an OSV 1.x version"));
    }
    match string(r, "id") {
        Some(id) if id == file_id && is_local_id(id) => {}
        Some(id) => out.push(format!(
            "id {id}: ACCESS-<year>-<number>, matching the file name"
        )),
        None => out.push(String::from("id is required")),
    }
    let modified = string(r, "modified").and_then(civil::parse_rfc3339);
    let published = string(r, "published").and_then(civil::parse_rfc3339);
    match (published, modified) {
        (Some(p), Some(m)) if p <= m => {}
        (Some(_), Some(_)) => out.push(String::from("modified precedes published")),
        _ => out.push(String::from(
            "published and modified are RFC 3339 date-times",
        )),
    }
    for alias in r
        .get("aliases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        match alias.as_str() {
            Some(a) if a.starts_with("GO-") => {
                out.push(format!(
                    "alias {a}: the Go vulnerability database is not a channel (MD-1)"
                ));
            }
            Some(a) if is_alias(a) => {}
            _ => out.push(format!("alias {alias}: a GHSA, CVE or RUSTSEC id")),
        }
    }
    for key in ["summary", "details"] {
        if string(r, key).is_none_or(|s| s.trim().is_empty()) {
            out.push(format!("{key} is required"));
        }
    }
    if string(r, "summary").is_some_and(|s| s.chars().count() > 120) {
        out.push(String::from("summary is at most 120 characters"));
    }
    let severities = r.get("severity").and_then(Value::as_array);
    let cvss4: Vec<&str> = severities
        .into_iter()
        .flatten()
        .filter(|s| string(s, "type") == Some("CVSS_V4"))
        .filter_map(|s| string(s, "score"))
        .collect();
    match cvss4.as_slice() {
        [score] if is_cvss4(score) => {}
        [score] => out.push(format!(
            "severity CVSS_V4 {score:?} is not a CVSS v4.0 base vector"
        )),
        _ => out.push(String::from(
            "severity carries exactly one CVSS_V4 vector (OP-159 m.3 (jj))",
        )),
    }
    out.extend(affected_findings(r, packages));
    let references = r.get("references").and_then(Value::as_array);
    if references.is_none_or(Vec::is_empty) {
        out.push(String::from(
            "references names at least one advisory or fix",
        ));
    }
    for reference in references.into_iter().flatten() {
        let kind_ok = string(reference, "type").is_some_and(|t| REFERENCE_TYPES.contains(&t));
        let url_ok = string(reference, "url").is_some_and(|u| u.starts_with("https://"));
        if !kind_ok || !url_ok {
            out.push(format!(
                "reference {reference}: an OSV type and an https url"
            ));
        }
    }
    out
}

fn affected_findings(r: &Value, packages: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let affected = r.get("affected").and_then(Value::as_array);
    if affected.is_none_or(Vec::is_empty) {
        out.push(String::from("affected lists at least one package"));
    }
    for a in affected.into_iter().flatten() {
        let package = a.get("package");
        let ecosystem = package
            .and_then(|p| string(p, "ecosystem"))
            .unwrap_or_default();
        let name = package.and_then(|p| string(p, "name")).unwrap_or_default();
        if ecosystem == "Go" {
            out.push(String::from("ecosystem Go is not a channel (MD-1)"));
        } else if !ECOSYSTEMS.contains(&ecosystem) {
            out.push(format!(
                "{name}: ecosystem {ecosystem:?} is crates.io or npm"
            ));
        }
        if !packages.contains(name) {
            out.push(format!("{name:?} is not a package of this repository"));
        }
        let ranges = a.get("ranges").and_then(Value::as_array);
        if ranges.is_none_or(Vec::is_empty) {
            out.push(format!("{name}: ranges is required"));
        }
        for range in ranges.into_iter().flatten() {
            let events: Vec<&str> = range
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_object)
                .flat_map(|e| e.keys().map(String::as_str))
                .collect();
            let semver = string(range, "type") == Some("SEMVER");
            let closed = events.contains(&"fixed") || events.contains(&"last_affected");
            if !semver || !events.contains(&"introduced") || !closed {
                out.push(format!(
                    "{name}: a SEMVER range with introduced and fixed (or last_affected) events"
                ));
            }
        }
    }
    out
}

/// The names of the crates and npm packages in this repository.
pub(crate) fn packages(root: &Path) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for file in walk(root)? {
        let path = rel(root, &file);
        if path.ends_with("Cargo.toml") {
            let text = std::fs::read_to_string(&file).map_err(|e| format!("{path}: {e}"))?;
            if let Ok(value) = toml::from_str::<toml::Value>(&text)
                && let Some(name) = value
                    .get("package")
                    .and_then(|p| p.get("name"))
                    .and_then(toml::Value::as_str)
            {
                out.insert(name.to_owned());
            }
        } else if path.ends_with("package.json") {
            let text = std::fs::read_to_string(&file).map_err(|e| format!("{path}: {e}"))?;
            if let Ok(value) = serde_json::from_str::<Value>(&text)
                && let Some(name) = string(&value, "name")
            {
                out.insert(name.to_owned());
            }
        }
    }
    Ok(out)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let dir = root.join(DIR);
    let packages = packages(root)?;
    let mut out = Vec::new();
    for file in walk(&dir)? {
        let name = rel(&dir, &file);
        let path = format!("{DIR}/{name}");
        if name == "README.md" {
            continue;
        }
        let Some(id) = name.strip_suffix(".json").filter(|n| !n.contains('/')) else {
            out.push(v(
                &path,
                String::from("only <id>.json records and README.md live here"),
            ));
            continue;
        };
        let text = std::fs::read_to_string(&file).map_err(|e| format!("{path}: {e}"))?;
        match serde_json::from_str::<Value>(&text) {
            Ok(record) => out.extend(
                record_findings(id, &record, &packages)
                    .into_iter()
                    .map(|m| v(&path, m)),
            ),
            Err(e) => out.push(v(&path, format!("not JSON: {e}"))),
        }
    }
    Ok(out)
}

/// The arguments of `cargo xtask advisory new`.
#[derive(Debug, Default)]
pub(crate) struct New {
    pub(crate) id: String,
    pub(crate) ecosystem: String,
    pub(crate) package: String,
    pub(crate) introduced: String,
    pub(crate) fixed: String,
    pub(crate) cvss: String,
    pub(crate) summary: String,
    pub(crate) cwe: Vec<String>,
    pub(crate) out: Option<String>,
}

const USAGE: &str = "usage: cargo xtask advisory new <ACCESS-YYYY-NNNN> --package <crates.io|npm>:<name> \
--introduced <version> --fixed <version> --cvss <CVSS:4.0/...> --summary <text> [--cwe <CWE-n>]... [--out <dir>]";

fn parse_new(args: &[String]) -> Result<New, String> {
    let (id, rest) = args.split_first().ok_or_else(|| String::from(USAGE))?;
    let mut n = New {
        id: id.clone(),
        ..New::default()
    };
    let mut it = rest.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))?;
        match flag.as_str() {
            "--package" => {
                let (e, p) = value
                    .split_once(':')
                    .ok_or_else(|| String::from("--package is <ecosystem>:<name>"))?;
                n.ecosystem = e.to_owned();
                n.package = p.to_owned();
            }
            "--introduced" => n.introduced = value,
            "--fixed" => n.fixed = value,
            "--cvss" => n.cvss = value,
            "--summary" => n.summary = value,
            "--cwe" => n.cwe.push(value),
            "--out" => n.out = Some(value),
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    Ok(n)
}

/// The OSV record of a new advisory at `now`.
pub(crate) fn record(n: &New, now: i64) -> Value {
    let t = civil::format_rfc3339(now);
    let id = &n.id;
    json!({
        "schema_version": SCHEMA_VERSION,
        "id": id,
        "modified": t,
        "published": t,
        "aliases": [],
        "summary": n.summary,
        "details": n.summary,
        "severity": [{ "type": "CVSS_V4", "score": n.cvss }],
        "affected": [{
            "package": { "ecosystem": n.ecosystem, "name": n.package },
            "ranges": [{
                "type": "SEMVER",
                "events": [{ "introduced": n.introduced }, { "fixed": n.fixed }],
            }],
        }],
        "references": [{ "type": "ADVISORY", "url": format!("{REPOSITORY}/security/advisories") }],
        "database_specific": { "cwe_ids": n.cwe },
    })
}

/// The body of the GitHub repository security advisory draft.
pub(crate) fn ghsa_draft(n: &New) -> Value {
    let ecosystem = if n.ecosystem == "crates.io" {
        "rust"
    } else {
        "npm"
    };
    json!({
        "summary": n.summary,
        "description": n.summary,
        "cvss_vector_string": n.cvss,
        "cwe_ids": n.cwe,
        "vulnerabilities": [{
            "package": { "ecosystem": ecosystem, "name": n.package },
            "vulnerable_version_range": format!(">= {}, < {}", n.introduced, n.fixed),
            "patched_versions": n.fixed,
        }],
    })
}

/// The `RustSec` advisory database draft (crates only).
pub(crate) fn rustsec_draft(n: &New, now: i64) -> String {
    let date = civil::format_date(now.div_euclid(86_400));
    format!(
        "```toml\n[advisory]\nid = \"RUSTSEC-0000-0000\"\npackage = \"{}\"\ndate = \"{date}\"\n\
url = \"{REPOSITORY}/security/advisories\"\naliases = []\n\n[versions]\npatched = [\">= {}\"]\n\
unaffected = [\"< {}\"]\n```\n\n# {}\n\n{}\n",
        n.package, n.fixed, n.introduced, n.summary, n.summary
    )
}

/// `cargo xtask advisory new ...`: writes the record and the drafts; returns what was written.
pub(crate) fn new(root: &Path, args: &[String], now: i64) -> Result<Vec<String>, String> {
    let n = parse_new(args)?;
    if !is_local_id(&n.id) {
        return Err(format!("{}: the id is ACCESS-<year>-<four digits>", n.id));
    }
    let r = record(&n, now);
    let findings = record_findings(&n.id, &r, &packages(root)?);
    if !findings.is_empty() {
        return Err(findings.join("\n"));
    }
    let path = root.join(DIR).join(format!("{}.json", n.id));
    if path.exists() {
        return Err(format!("{DIR}/{}.json already exists", n.id));
    }
    let pretty = |v: &Value| {
        serde_json::to_string_pretty(v)
            .map(|s| s + "\n")
            .map_err(|e| e.to_string())
    };
    let out_dir = root.join(n.out.as_deref().unwrap_or(DRAFTS));
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let write =
        |p: &Path, body: &str| std::fs::write(p, body).map_err(|e| format!("{}: {e}", p.display()));
    write(&path, &pretty(&r)?)?;
    let ghsa = out_dir.join(format!("{}.ghsa.json", n.id));
    write(&ghsa, &pretty(&ghsa_draft(&n))?)?;
    let mut written = vec![path.display().to_string(), ghsa.display().to_string()];
    if n.ecosystem == "crates.io" {
        let rustsec = out_dir.join(format!("{}.rustsec.md", n.id));
        write(&rustsec, &rustsec_draft(&n, now))?;
        written.push(rustsec.display().to_string());
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assert_is_empty, reason = "test code")]

    use super::*;

    const CVSS: &str = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N";

    fn root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .map(Path::to_path_buf)
            .unwrap()
    }

    fn pkgs() -> BTreeSet<String> {
        ["esuiss-access-kernel", "@esuiss/access-login"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect()
    }

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    fn sample() -> Value {
        let n = parse_new(&args(&[
            "ACCESS-2026-0001",
            "--package",
            "crates.io:esuiss-access-kernel",
            "--introduced",
            "0.3.0",
            "--fixed",
            "0.4.1",
            "--cvss",
            CVSS,
            "--summary",
            "A stripped hybrid signature is accepted",
        ]))
        .unwrap();
        record(&n, civil::parse_rfc3339("2026-11-12T10:00:00Z").unwrap())
    }

    // OP-159 m.3 (jj)
    #[test]
    fn a_complete_osv_record_passes() {
        assert_eq!(
            record_findings("ACCESS-2026-0001", &sample(), &pkgs()),
            Vec::<String>::new()
        );
    }

    // OP-159 m.3 (jj)
    #[test]
    fn a_record_without_a_cvss_v4_vector_fails() {
        let mut r = sample();
        r["severity"] =
            json!([{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" }]);
        assert_eq!(record_findings("ACCESS-2026-0001", &r, &pkgs()).len(), 1);
        r["severity"] = json!([{ "type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L" }]);
        assert_eq!(record_findings("ACCESS-2026-0001", &r, &pkgs()).len(), 1);
        assert!(is_cvss4(&format!("{CVSS}/E:A")));
        assert!(!is_cvss4(&CVSS.replace("AV:N/AC:L", "AC:L/AV:N")));
        assert!(!is_cvss4(&format!("{CVSS}/AV:N")));
    }

    // OP-159 m.3 (jj), MD-1
    #[test]
    fn records_outside_the_osv_shape_fail() {
        let mut r = sample();
        r["affected"][0]["package"]["ecosystem"] = json!("Go");
        r["aliases"] = json!([
            "GO-2026-0001",
            "GHSA-2c3f-4g5h-6j7m",
            "CVE-2026-12345",
            "RUSTSEC-2026-0001"
        ]);
        assert_eq!(record_findings("ACCESS-2026-0001", &r, &pkgs()).len(), 2);
        let mut r = sample();
        r["affected"][0]["package"]["name"] = json!("some-other-crate");
        r["affected"][0]["ranges"][0]["events"] = json!([{ "introduced": "0" }]);
        r["vendor"] = json!(1);
        assert_eq!(record_findings("ACCESS-2026-0001", &r, &pkgs()).len(), 3);
        assert_eq!(
            record_findings("ACCESS-2026-0002", &sample(), &pkgs()).len(),
            1
        );
        let mut r = sample();
        r["published"] = json!("2026-11-13T00:00:00Z");
        r["references"] = json!([{ "type": "ADVISORY", "url": "http://example.org" }]);
        assert_eq!(record_findings("ACCESS-2026-0001", &r, &pkgs()).len(), 2);
    }

    // SA-15, OP-159 m.3 (jj)
    #[test]
    fn new_writes_an_osv_record_and_both_drafts() {
        let scratch = std::env::temp_dir().join(format!("xtask-advisory-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join(DIR)).unwrap();
        std::fs::write(
            scratch.join("Cargo.toml"),
            "[package]\nname = \"esuiss-access-kernel\"\n",
        )
        .unwrap();
        let now = civil::parse_rfc3339("2026-11-12T10:00:00Z").unwrap();
        let a = args(&[
            "ACCESS-2026-0001",
            "--package",
            "crates.io:esuiss-access-kernel",
            "--introduced",
            "0.3.0",
            "--fixed",
            "0.4.1",
            "--cvss",
            CVSS,
            "--summary",
            "A stripped hybrid signature is accepted",
            "--cwe",
            "CWE-347",
            "--out",
            "drafts",
        ]);
        let written = new(&scratch, &a, now).unwrap();
        assert_eq!(written.len(), 3);
        assert!(check(&scratch).unwrap().is_empty());
        let ghsa: Value = serde_json::from_str(
            &std::fs::read_to_string(scratch.join("drafts/ACCESS-2026-0001.ghsa.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(ghsa["cvss_vector_string"], json!(CVSS));
        assert_eq!(
            ghsa["vulnerabilities"][0]["package"]["ecosystem"],
            json!("rust")
        );
        let rustsec =
            std::fs::read_to_string(scratch.join("drafts/ACCESS-2026-0001.rustsec.md")).unwrap();
        assert!(rustsec.contains("patched = [\">= 0.4.1\"]"));
        assert!(new(&scratch, &a, now).is_err());
        let mut no_cvss = a.clone();
        if let Some(i) = no_cvss.iter().position(|x| x == CVSS) {
            no_cvss[i] = String::from("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
        }
        no_cvss[0] = String::from("ACCESS-2026-0002");
        assert!(new(&scratch, &no_cvss, now).is_err());
        std::fs::remove_dir_all(&scratch).unwrap();
    }

    // OP-159 m.3 (jj)
    #[test]
    fn the_published_records_are_valid() {
        assert!(check(&root()).unwrap().is_empty());
        assert!(packages(&root()).unwrap().contains("esuiss-access-kernel"));
    }
}
