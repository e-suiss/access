//! Forbidden product claims and unreproduced performance numbers in tracked docs and
//! UI strings (Ek B stage 0: "forbidden term and product claim scan", "benchmark
//! sub-condition"; §3.1d, §3.3a, §8.10, §13.8, §15.1.2, §18.2, B15, CR-50).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::Violation;
use crate::catalog::DIR;

const FILE: &str = "forbidden-claims.toml";

/// Which files the scans read.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Scan {
    /// Documentation globs; every `scope = "all"` claim applies.
    pub(crate) docs: Vec<String>,
    /// UI string globs; `scope = "ui"` claims apply here as well.
    pub(crate) ui: Vec<String>,
    pub(crate) exclude: Vec<String>,
    pub(crate) extensions: Vec<String>,
}

/// One forbidden claim.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claim {
    pub(crate) id: String,
    /// `all` (docs and UI) or `ui` (UI strings only).
    pub(crate) scope: String,
    pub(crate) phrases: Vec<String>,
    /// Qualified forms the spec allows; a paragraph containing one passes.
    #[serde(default)]
    pub(crate) allow: Vec<String>,
    /// Whether a negated mention ("not", "never", "no") is allowed.
    #[serde(default)]
    pub(crate) negation: bool,
    /// Spec IDs or sections the claim comes from.
    pub(crate) sources: Vec<String>,
    /// NG/PU guarantee rows this claim is the honest-wording test for (SAI-1).
    #[serde(default)]
    pub(crate) rows: Vec<String>,
    /// The honest form to use instead.
    pub(crate) honest: String,
}

/// Benchmark sub-condition (§3.1d).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Benchmark {
    /// Unit suffixes that make a number a performance figure.
    pub(crate) units: Vec<String>,
    /// A paragraph containing one of these passes (label or link to the bench code).
    pub(crate) markers: Vec<String>,
}

/// `forbidden-claims.toml`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimsFile {
    pub(crate) scan: Scan,
    #[serde(default)]
    pub(crate) vocab: BTreeMap<String, Vec<String>>,
    pub(crate) benchmark: Benchmark,
    #[serde(default)]
    pub(crate) claim: Vec<Claim>,
}

pub(crate) fn load(root: &Path) -> Result<ClaimsFile, String> {
    let path = root.join(DIR).join(FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut file: ClaimsFile =
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    for claim in &mut file.claim {
        let mut phrases = Vec::new();
        for p in &claim.phrases {
            match file
                .vocab
                .iter()
                .find(|(k, _)| p.contains(&format!("{{{k}}}")))
            {
                Some((k, words)) => {
                    phrases.extend(words.iter().map(|w| p.replace(&format!("{{{k}}}"), w)));
                }
                None => phrases.push(p.clone()),
            }
        }
        claim.phrases = phrases;
    }
    Ok(file)
}

/// Minimal glob: `**` spans directories, `*` stays within one segment. A pattern
/// without `/` matches the file name at any depth.
pub(crate) fn glob(pattern: &str, path: &str) -> bool {
    fn seg(p: &[u8], s: &[u8]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(b'*'), _) => {
                let rest = p.get(1..).unwrap_or_default();
                seg(rest, s) || (!s.is_empty() && seg(p, s.get(1..).unwrap_or_default()))
            }
            (Some(a), Some(b)) if a == b => seg(
                p.get(1..).unwrap_or_default(),
                s.get(1..).unwrap_or_default(),
            ),
            _ => false,
        }
    }
    fn parts(p: &[&str], s: &[&str]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some(&"**"), _) => {
                let rest = p.get(1..).unwrap_or_default();
                parts(rest, s) || (!s.is_empty() && parts(p, s.get(1..).unwrap_or_default()))
            }
            (Some(a), Some(b)) if seg(a.as_bytes(), b.as_bytes()) => parts(
                p.get(1..).unwrap_or_default(),
                s.get(1..).unwrap_or_default(),
            ),
            _ => false,
        }
    }
    if !pattern.contains('/') {
        let name = path.rsplit('/').next().unwrap_or(path);
        return seg(pattern.as_bytes(), name.as_bytes());
    }
    let p: Vec<&str> = pattern.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    parts(&p, &s)
}

/// Tracked and untracked-but-not-ignored files (`docs/` and local notes are ignored).
fn repo_files(root: &Path) -> Vec<String> {
    let output = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let mut files: Vec<String> = String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::to_owned)
                .collect();
            files.retain(|f| root.join(f).is_file());
            files
        }
        _ => Vec::new(),
    }
}

/// Files to scan and whether each is a UI string file.
fn targets(root: &Path, scan: &Scan) -> Vec<(String, bool)> {
    repo_files(root)
        .into_iter()
        .filter(|f| !scan.exclude.iter().any(|g| glob(g, f)))
        .filter(|f| {
            let ext = f.rsplit_once('.').map_or("", |(_, e)| e);
            scan.extensions.iter().any(|e| e == ext)
        })
        .filter_map(|f| {
            let ui = scan.ui.iter().any(|g| glob(g, &f));
            (ui || scan.docs.iter().any(|g| glob(g, &f))).then_some((f, ui))
        })
        .collect()
}

/// Lowercases and folds typography so phrases match: quotes, dashes, emphasis marks.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\u{2018}' | '\u{2019}' => out.push('\''),
            '\u{201C}' | '\u{201D}' => out.push('"'),
            '\u{2010}'..='\u{2015}' => out.push('-'),
            '*' | '`' => {}
            c if c.is_whitespace() => {
                if !out.ends_with(' ') {
                    out.push(' ');
                }
            }
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// Paragraphs (blank-line separated) with their first line number; fenced code
/// blocks are kept apart and flagged.
fn paragraphs(text: &str) -> Vec<(usize, String, bool)> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut start = 0;
    let mut fenced = false;
    let flush =
        |out: &mut Vec<(usize, String, bool)>, current: &mut String, start: usize, fenced: bool| {
            if !current.trim().is_empty() {
                out.push((start, std::mem::take(current), fenced));
            }
            current.clear();
        };
    for (n, line) in text.lines().enumerate() {
        let lineno = n.saturating_add(1);
        if line.trim_start().starts_with("```") {
            flush(&mut out, &mut current, start, fenced);
            fenced = !fenced;
            continue;
        }
        if line.trim().is_empty() && !fenced {
            flush(&mut out, &mut current, start, fenced);
            continue;
        }
        if current.is_empty() {
            start = lineno;
        }
        current.push_str(line);
        current.push('\n');
    }
    flush(&mut out, &mut current, start, fenced);
    out
}

fn is_word(c: char) -> bool {
    c.is_alphanumeric()
}

/// Byte offsets of whole-word occurrences of `phrase` in `text` (both normalized).
fn find_all(text: &str, phrase: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = text.get(from..).and_then(|t| t.find(phrase)) {
        let at = from.saturating_add(pos);
        let end = at.saturating_add(phrase.len());
        let before = text.get(..at).and_then(|t| t.chars().next_back());
        let after = text.get(end..).and_then(|t| t.chars().next());
        let starts_word = phrase.chars().next().is_some_and(is_word);
        let ends_word = phrase.chars().next_back().is_some_and(is_word);
        if !((starts_word && before.is_some_and(is_word))
            || (ends_word && after.is_some_and(is_word)))
        {
            out.push(at);
        }
        from = at.saturating_add(phrase.chars().next().map_or(1, char::len_utf8));
    }
    out
}

const NEGATIONS: &[&str] = &[
    "not", "never", "no", "don't", "doesn't", "isn't", "aren't", "cannot", "can't", "won't",
    "without", "nor", "neither", "nothing", "none",
];

/// Whether one of the five words before `at` negates the phrase.
fn negated(text: &str, at: usize) -> bool {
    let before = text.get(..at).unwrap_or_default();
    before
        .split(|c: char| !(c.is_alphanumeric() || c == '\''))
        .filter(|w| !w.is_empty())
        .rev()
        .take(5)
        .any(|w| NEGATIONS.contains(&w))
}

/// Claims found in one text: (line, claim id, phrase).
pub(crate) fn find_claims(text: &str, claims: &[Claim], ui: bool) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (start, para, _) in paragraphs(text) {
        let norm = normalize(&para);
        for claim in claims.iter().filter(|c| ui || c.scope == "all") {
            if claim.allow.iter().any(|a| norm.contains(&normalize(a))) {
                continue;
            }
            for phrase in &claim.phrases {
                let p = normalize(phrase);
                for at in find_all(&norm, &p) {
                    if claim.negation && negated(&norm, at) {
                        continue;
                    }
                    let line = start.saturating_add(para_line(&para, &norm, at));
                    out.push((line, claim.id.clone(), phrase.clone()));
                }
            }
        }
    }
    out
}

fn para_line(para: &str, norm: &str, at: usize) -> usize {
    let ratio = |n: usize, d: usize| n.saturating_mul(100).checked_div(d).unwrap_or(0);
    let lines = para.lines().count();
    let pct = ratio(at, norm.len().max(1));
    lines.saturating_sub(1).min(pct.saturating_mul(lines) / 100)
}

/// Performance figures without the §3.1d label: (line, figure).
pub(crate) fn find_benchmarks(text: &str, bench: &Benchmark) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let markers: Vec<String> = bench.markers.iter().map(|m| normalize(m)).collect();
    let units: Vec<String> = bench.units.iter().map(|u| normalize(u)).collect();
    for (start, para, fenced) in paragraphs(text) {
        if fenced {
            continue;
        }
        let norm = normalize(&para);
        if markers.iter().any(|m| norm.contains(m.as_str())) {
            continue;
        }
        let bytes = norm.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let prev_word = i > 0
                && bytes
                    .get(i.saturating_sub(1))
                    .is_some_and(u8::is_ascii_alphanumeric);
            if !bytes.get(i).is_some_and(u8::is_ascii_digit) || prev_word {
                i = i.saturating_add(1);
                continue;
            }
            let num_start = i;
            while bytes
                .get(i)
                .is_some_and(|b| b.is_ascii_digit() || *b == b'.' || *b == b',')
            {
                i = i.saturating_add(1);
            }
            let num_end = i;
            let rest = norm.get(i..).unwrap_or_default();
            let rest_trim = rest.trim_start();
            for u in &units {
                let Some(after) = rest_trim.strip_prefix(u.as_str()) else {
                    continue;
                };
                if after.chars().next().is_some_and(is_word) {
                    continue;
                }
                let figure = format!(
                    "{}{}",
                    norm.get(num_start..num_end).unwrap_or_default(),
                    rest.get(..rest.len().saturating_sub(after.len()))
                        .unwrap_or_default()
                );
                out.push((
                    start.saturating_add(para_line(&para, &norm, num_start)),
                    figure.trim().to_owned(),
                ));
                break;
            }
        }
    }
    out
}

fn scan_files<F>(root: &Path, scan: &Scan, mut f: F) -> Vec<Violation>
where
    F: FnMut(&str, &str, bool) -> Vec<Violation>,
{
    let mut out = Vec::new();
    for (file, ui) in targets(root, scan) {
        let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
            continue;
        };
        out.extend(f(&file, &text, ui));
    }
    out
}

fn validate(file: &ClaimsFile) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    let path = PathBuf::from(DIR).join(FILE);
    for c in &file.claim {
        let mut bad = |m: &str| {
            out.push(Violation {
                rule: "OP-81",
                path: path.clone(),
                message: format!("{}: {m}", c.id),
            });
        };
        if !ids.insert(c.id.clone()) {
            bad("duplicate claim id");
        }
        if !["all", "ui"].contains(&c.scope.as_str()) {
            bad("scope must be \"all\" or \"ui\"");
        }
        if c.phrases.iter().any(|p| p.trim().is_empty()) || c.phrases.is_empty() {
            bad("needs non-empty phrases");
        }
        if c.sources.is_empty() || c.honest.trim().is_empty() {
            bad("needs spec sources and an honest form");
        }
        if c.rows
            .iter()
            .any(|r| crate::catalog::ids::family(r).is_none())
        {
            bad("rows must be catalog IDs");
        }
    }
    out
}

pub(crate) fn check_forbidden_claims(root: &Path) -> Result<Vec<Violation>, String> {
    let file = load(root)?;
    let mut out = validate(&file);
    out.extend(scan_files(root, &file.scan, |path, text, ui| {
        find_claims(text, &file.claim, ui)
            .into_iter()
            .map(|(line, id, phrase)| {
                let honest = file
                    .claim
                    .iter()
                    .find(|c| c.id == id)
                    .map_or("", |c| c.honest.as_str());
                Violation {
                    rule: "B15",
                    path: PathBuf::from(format!("{path}:{line}")),
                    message: format!(
                        "forbidden claim `{id}` (\"{phrase}\"); say instead: {honest}"
                    ),
                }
            })
            .collect()
    }));
    Ok(out)
}

pub(crate) fn check_benchmark_claims(root: &Path) -> Result<Vec<Violation>, String> {
    let file = load(root)?;
    Ok(scan_files(root, &file.scan, |path, text, _| {
        find_benchmarks(text, &file.benchmark)
            .into_iter()
            .map(|(line, figure)| Violation {
                rule: "§3.1d",
                path: PathBuf::from(format!("{path}:{line}")),
                message: format!(
                    "performance figure `{figure}` needs \"pending reproduction\" or a link to its benches/ code"
                ),
            })
            .collect()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(id: &str, phrases: &[&str], allow: &[&str], negation: bool) -> Claim {
        Claim {
            id: id.to_owned(),
            scope: "all".to_owned(),
            phrases: phrases.iter().map(|s| (*s).to_owned()).collect(),
            allow: allow.iter().map(|s| (*s).to_owned()).collect(),
            negation,
            sources: vec!["B15".to_owned()],
            rows: vec![],
            honest: "x".to_owned(),
        }
    }

    #[test]
    fn unqualified_claim_is_found_case_insensitively_across_wrapped_lines() {
        let claims = [claim(
            "formally-verified",
            &["formally verified"],
            &[],
            true,
        )];
        let found = find_claims(
            "Intro.\n\nAccess is **Formally\nverified**.\n",
            &claims,
            false,
        );
        assert_eq!(
            found,
            [(
                3,
                "formally-verified".to_owned(),
                "formally verified".to_owned()
            )]
        );
    }

    #[test]
    fn negated_and_qualified_mentions_pass() {
        let claims = [
            claim("enterprise", &["paid-only features"], &[], true),
            claim("quantum", &["quantum-safe"], &["re-anchor"], false),
        ];
        assert_eq!(
            find_claims("Same code, no paid-only features.", &claims, false),
            Vec::<(usize, String, String)>::new()
        );
        assert_eq!(
            find_claims(
                "Re-anchored records stay quantum-safe at verifiers.",
                &claims,
                false
            ),
            Vec::<(usize, String, String)>::new()
        );
        assert_eq!(
            find_claims("Quantum-safe records.", &claims, false).len(),
            1
        );
    }

    #[test]
    fn phrases_match_whole_words_only() {
        let claims = [claim("dlp", &["dlp"], &[], false)];
        assert_eq!(
            find_claims("The dlpx module.", &claims, false),
            Vec::<(usize, String, String)>::new()
        );
        assert_eq!(find_claims("Access is a DLP.", &claims, false).len(), 1);
    }

    #[test]
    fn ui_only_claims_skip_documentation() {
        let mut c = claim("trusted-device", &["trusted device"], &[], false);
        c.scope = "ui".to_owned();
        let claims = [c];
        assert_eq!(
            find_claims("A trusted device.", &claims, false),
            Vec::<(usize, String, String)>::new()
        );
        assert_eq!(find_claims("A trusted device.", &claims, true).len(), 1);
    }

    #[test]
    fn performance_figures_need_the_reproduction_label() {
        let bench = Benchmark {
            units: vec!["ms".into(), "req/s".into(), "x faster".into()],
            markers: vec!["pending reproduction".into(), "benches/".into()],
        };
        let found = find_benchmarks(
            "Token issuance takes 1.5 ms.\n\nAbout 40000 req/s (pending reproduction).\n\n```\nsleep 5ms\n```\n\nIt is 3x faster.\n",
            &bench,
        );
        let figures: Vec<_> = found.iter().map(|(_, f)| f.as_str()).collect();
        assert_eq!(figures, ["1.5 ms", "3x faster"]);
        assert_eq!(
            find_benchmarks("Valid for 90 days; RFC 9116; 2 msgs.", &bench),
            Vec::<(usize, String)>::new()
        );
    }

    #[test]
    fn globs_match_names_anywhere_and_paths_by_segment() {
        assert!(glob("README*", "crates/kernel/README.md"));
        assert!(glob("docs/**", "docs/spec/a.md"));
        assert!(glob("web/**", "web/src/i18n/en.json"));
        assert!(!glob("docs/**", "xdocs/a.md"));
        assert!(glob(".github/*.md", ".github/pull_request_template.md"));
    }
}
