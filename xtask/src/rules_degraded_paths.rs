//! `degraded-paths` (TI-9, SEC27, SI-22, INV-26, MD-8, OP-45, OP-158 m.3 (s)): degraded mode is
//! only the TI-9/SEC27/SI-22 paths. Non-test Rust, configuration and web sources name no
//! fail-open, grace-window, stale-accept or allow-on-error switch, and no error branch of
//! non-test Rust returns ALLOW or an active introspection answer. A reviewed exception names
//! the declared path (TI-9, SEC27 or SI-22) it belongs to.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};
use crate::rules::switches::{fail_open_phrase, words};

const RULE: &str = "degraded-paths";

/// The declared degraded paths an exception may belong to (§17.7.1).
const DECLARED: &[&str] = &["TI-9", "SEC27", "SI-22"];

/// Reviewed exceptions: (relative path, matched phrase, declared path, reason).
const ALLOWLIST: &[(&str, &str, &str, &str)] = &[];

/// This file spells out the vocabulary it forbids.
const SELF_PATH: &str = "xtask/src/rules_degraded_paths.rs";

const CONFIG_EXTENSIONS: &[&str] = &["toml", "yml", "yaml", "json", "env", "ini", "conf", "cfg"];

const SCRIPT_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "js", "mjs"];

const SKIP_PREFIXES: &[&str] = &[
    "supply-chain/",
    "conformance/vectors/external/",
    "crates/suiss-crypto/vectors/external/",
    "sdks/typescript/wasm/",
];

const NEGATIONS: &[&str] = &[
    "no", "not", "never", "without", "refuse", "refused", "reject",
];

const ACCEPT: &[&str] = &[
    "allow", "allows", "permit", "accept", "accepts", "active", "ok", "pass",
];

/// MD-8, OP-45 rule 5: a degraded window, a grace window, a stale accept or a low-trust
/// active answer. Returns the phrase found in an atom, if any.
pub(crate) fn degraded_phrase(atom: &str) -> Option<String> {
    if let Some(hit) = fail_open_phrase(atom) {
        return Some(hit);
    }
    let w = words(atom);
    let at = |i: usize| w.get(i).map_or("", String::as_str);
    for i in 0..w.len() {
        let (a, b, c) = (at(i), at(i.saturating_add(1)), at(i.saturating_add(2)));
        let hit = match (a, b, c) {
            ("grace" | "degraded" | "outage", "window" | "allow" | "accept", _)
            | ("stale" | "cached" | "expired", _, _)
                if ACCEPT.contains(&b) =>
            {
                Some(format!("{a}_{b}"))
            }
            ("grace" | "degraded" | "outage", "window", _) => Some(format!("{a}_{b}")),
            ("allow" | "accept" | "accepts" | "serve" | "use", "stale" | "expired", _) => {
                Some(format!("{a}_{b}"))
            }
            ("x", "access", "degraded") => Some(String::from("x_access_degraded")),
            ("low", "confidence" | "trust", "active" | "allow") => Some(format!("{a}_{b}_{c}")),
            _ => None,
        };
        let negated = i
            .checked_sub(1)
            .and_then(|p| w.get(p))
            .is_some_and(|p| NEGATIONS.contains(&p.as_str()));
        if hit.is_some() && !negated {
            return hit;
        }
    }
    None
}

const ERROR_PATTERNS: &[&str] = &[
    "Err(",
    "Unavailable",
    "Timeout",
    "TimedOut",
    "Elapsed",
    "Unreachable",
];

const ALLOW_TOKENS: &[&str] = &["Allow", "Permit"];

const FALLBACKS: &[&str] = &[
    ".unwrap_or(",
    ".unwrap_or_else(",
    ".map_err(",
    ".or(",
    ".or_else(",
];

fn has_token(code: &str, token: &str) -> bool {
    crate::rules::lex::find_token(code, token)
        .into_iter()
        .any(|at| {
            code.get(..at)
                .is_none_or(|b| !b.ends_with(|c: char| c.is_alphanumeric() || c == '_'))
        })
}

fn yields_allow(code: &str, raw: &str) -> bool {
    ALLOW_TOKENS.iter().any(|t| has_token(code, t))
        || raw.contains("\"active\": true")
        || raw.contains("\"active\":true")
        || code.contains("active: true")
}

/// INV-26, MD-8: an error arm or fallback on one line that yields ALLOW.
fn error_branch_allow(code: &str, raw: &str) -> Option<&'static str> {
    for (at, _) in code.match_indices("=>") {
        let head = code.get(..at).unwrap_or_default();
        let pattern = head
            .rfind([',', '{', ';'])
            .and_then(|s| head.get(s.saturating_add(1)..))
            .unwrap_or(head);
        let tail = code.get(at.saturating_add(2)..).unwrap_or_default();
        let body = tail
            .find([',', '}', ';'])
            .map_or(tail, |e| tail.get(..e).unwrap_or(tail));
        let raw_tail = raw.get(at.saturating_add(2)..).unwrap_or(raw);
        if ERROR_PATTERNS.iter().any(|e| pattern.contains(e)) && yields_allow(body, raw_tail) {
            return Some("an error arm yields ALLOW");
        }
    }
    for f in FALLBACKS {
        if let Some(at) = code.find(f) {
            let rest = code.get(at..).unwrap_or_default();
            if yields_allow(rest, raw.get(at..).unwrap_or(raw)) {
                return Some("an error fallback yields ALLOW");
            }
        }
    }
    None
}

fn allowlisted(rel_path: &str, phrase: &str) -> bool {
    ALLOWLIST
        .iter()
        .any(|(p, w, _, _)| *p == rel_path && *w == phrase)
}

fn violation(rel_path: &str, line: usize, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(format!("{rel_path}:{line}")),
        message,
    }
}

const WHY: &str = "degraded mode is only the declared TI-9/SEC27/SI-22 paths; an error, an outage or a stale answer is DENY or 503, never ALLOW (OP-45, MD-8)";

fn scan_rust(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let raw: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        let n = i.saturating_add(1);
        if in_regions(&tests, n) {
            continue;
        }
        for ident in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if let Some(p) = degraded_phrase(ident).filter(|p| !allowlisted(rel_path, p)) {
                out.push(violation(rel_path, n, format!("`{p}`: {WHY}")));
            }
        }
        let source = raw.get(i).copied().unwrap_or_default();
        if let Some(why) = error_branch_allow(line, source)
            && !allowlisted(rel_path, "error-allow")
        {
            out.push(violation(rel_path, n, format!("{why}: {WHY}")));
        }
    }
    for l in &lexed.strings {
        if in_regions(&tests, l.line) {
            continue;
        }
        for atom in l
            .text
            .split(|c: char| c.is_whitespace() || "\"'=:,;[]{}()".contains(c))
        {
            if let Some(p) = degraded_phrase(atom).filter(|p| !allowlisted(rel_path, p)) {
                out.push(violation(rel_path, l.line, format!("`{p}`: {WHY}")));
            }
        }
    }
    out
}

fn scan_text(rel_path: &str, text: &str, comment: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let content = line
            .split_once(comment)
            .filter(|(b, _)| b.is_empty() || b.ends_with(char::is_whitespace))
            .map_or(line, |(b, _)| b);
        let mut prev = String::new();
        for atom in content
            .split(|c: char| c.is_whitespace() || "\"'=:,;[]{}()<>`".contains(c))
            .filter(|a| !a.is_empty())
        {
            let negated = NEGATIONS.contains(&prev.to_ascii_lowercase().as_str());
            atom.clone_into(&mut prev);
            if negated {
                continue;
            }
            if let Some(p) = degraded_phrase(atom).filter(|p| !allowlisted(rel_path, p)) {
                out.push(violation(
                    rel_path,
                    i.saturating_add(1),
                    format!("`{p}`: {WHY}"),
                ));
            }
        }
    }
    out
}

fn is_script_test(rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or_default();
    rel_path
        .split('/')
        .any(|p| matches!(p, "tests" | "test" | "__tests__" | "e2e"))
        || [".test.", ".spec."].iter().any(|t| name.contains(t))
}

/// The exceptions name a declared path and a file that cites it.
fn check_allowlist(root: &Path) -> Vec<Violation> {
    let mut out = Vec::new();
    for (path, phrase, declared, _) in ALLOWLIST {
        let cited = read(&root.join(path)).is_ok_and(|s| s.contains(declared));
        if !DECLARED.contains(declared) || !cited {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(*path),
                message: format!(
                    "the exception for `{phrase}` must name TI-9, SEC27 or SI-22 and the file must cite it"
                ),
            });
        }
    }
    out
}

/// Runs `degraded-paths`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = check_allowlist(root);
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path == SELF_PATH
            || rel_path.starts_with("xtask/")
            || SKIP_PREFIXES.iter().any(|p| rel_path.starts_with(p))
        {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        if ext == "rs" {
            if !is_test_file(&rel_path) {
                out.extend(scan_rust(&rel_path, &read(&path)?));
            }
        } else if SCRIPT_EXTENSIONS.contains(&ext) {
            if (rel_path.starts_with("web/") || rel_path.starts_with("sdks/"))
                && !is_script_test(&rel_path)
                && !rel_path.contains("/dist/")
            {
                out.extend(scan_text(&rel_path, &read(&path)?, "//"));
            }
        } else if CONFIG_EXTENSIONS.contains(&ext) || name.starts_with(".env") {
            out.extend(scan_text(&rel_path, &read(&path)?, "#"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-158 m.3 (s), MD-8, OP-45
    #[test]
    fn degraded_windows_and_stale_accepts_are_named() {
        for atom in [
            "fail_open",
            "grace_window_ms",
            "degradedWindow",
            "allow_on_error",
            "accept_stale",
            "stale_ok",
            "cached_allow",
            "serve_stale",
            "X-Access-Degraded",
            "low_confidence_active",
        ] {
            assert!(degraded_phrase(atom).is_some(), "{atom}");
        }
        for atom in [
            "grace_period",
            "no_grace_window",
            "degraded_alarm",
            "identity_degraded",
            "stale_status",
            "never_degraded_window",
            "ceremony-permit-expired",
        ] {
            assert!(degraded_phrase(atom).is_none(), "{atom}");
        }
    }

    // INV-26, TI-9
    #[test]
    fn an_error_branch_that_returns_allow_is_refused() {
        let bad = [
            "fn f(r: Result<D, E>) -> D { match r { Ok(d) => d, Err(_) => Decision::Allow } }",
            "fn f() -> Reply { match g() { Err(Unavailable) => json!({\"active\": true}), _ => x() } }",
            "fn f(r: Result<D, E>) -> D { r.unwrap_or(Decision::Allow) }",
            "fn f(r: Result<D, E>) -> D { r.unwrap_or_else(|_| Outcome::Allow) }",
        ];
        for src in bad {
            assert_eq!(scan_rust("a.rs", src).len(), 1, "{src}");
        }
        let good = [
            "fn f(r: Result<D, E>) -> D { match r { Ok(d) => d, Err(_) => Decision::Deny } }",
            "fn f() -> Reply { match g() { Err(Unavailable) => json!({\"active\": false}), _ => x() } }",
            "fn f(r: Option<D>) -> D { match r { Some(Allow) => Allow, None => Deny } }",
            "#[cfg(test)]\nmod tests { fn f() { let _ = r.unwrap_or(Decision::Allow); } }",
        ];
        for src in good {
            assert!(scan_rust("a.rs", src).is_empty(), "{src}");
        }
    }

    // OP-158 m.3 (s)
    #[test]
    fn configuration_and_web_text_name_no_window() {
        assert_eq!(
            scan_text("a.toml", "[identity]\ndegraded_window_s = 300\n", "#").len(),
            1
        );
        assert!(scan_text("a.toml", "# never a degraded window\nx = 1\n", "#").is_empty());
        assert!(scan_text("a.yaml", "note: no grace-window\n", "#").is_empty());
        assert_eq!(
            scan_text("a.ts", "const acceptStale = true;\n", "//").len(),
            1
        );
    }

    // TI-9, SEC27, SI-22
    #[test]
    fn exceptions_name_a_declared_path() {
        for (_, _, declared, _) in ALLOWLIST {
            assert!(DECLARED.contains(declared));
        }
    }
}
