//! `no-dev-mode` (TI-9, OP-48, OP-69 rule 2, X21, CR-34): there is no "dev mode",
//! "test mode" or security-weakening switch. `fail-closed` (INV-26, TI-9): no
//! switch turns an error, a timeout or a degraded dependency into ALLOW. Identifiers and string literals in
//! non-test Rust code, and keys and values in configuration files, must not name
//! one. Under `sdks/` (CMP-17, X21, OP-150 m.1 (a)) TypeScript and JavaScript sources are
//! scanned too, and the PEP vocabulary also covers default-allow and skipped checks.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};

const RULE: &str = "no-dev-mode";

/// Reviewed exceptions: (relative path, matched word, reason). Each entry needs
/// Adem's review.
const ALLOWLIST: &[(&str, &str, &str)] = &[
    (
        "crates/identity-webauthn/src/domain/mds.rs",
        "bypass",
        "FIDO MDS3 status name USER_VERIFICATION_BYPASS; it marks a model compromised (OP-146 m.4 (d))",
    ),
    (
        "xtask/src/rules_ui_terms.rs",
        "dangerously",
        "React's dangerouslySetInnerHTML, named only so `ui-text-nodes` can forbid it (TN-131)",
    ),
];

/// This file spells out the vocabulary it forbids.
const SELF_PATH: &str = "xtask/src/rules_switches.rs";

/// Script extensions scanned under [`SDK_PREFIX`].
const SCRIPT_EXTENSIONS: &[&str] = &["ts", "tsx", "mts", "cts", "js", "mjs", "cjs"];

/// SDK sources: the PEP and verifier packages (CMP-17).
const SDK_PREFIX: &str = "sdks/";

/// Generated SDK output that is not ours to name.
const SDK_SKIP_PREFIXES: &[&str] = &["sdks/typescript/wasm/"];

/// Configuration file extensions that are scanned.
const CONFIG_EXTENSIONS: &[&str] = &["toml", "yml", "yaml", "json", "env", "ini", "conf", "cfg"];

/// Directories whose configuration is third-party data, not our switches:
/// cargo-vet audit records quote other projects' notes.
const CONFIG_SKIP_PREFIXES: &[&str] = &[
    "supply-chain/",
    "conformance/vectors/external/",
    "crates/suiss-crypto/vectors/external/",
];

/// Splits an identifier or literal into lower-case words.
pub(crate) fn words(atom: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = atom.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_alphanumeric() {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            continue;
        }
        let prev = i.checked_sub(1).and_then(|p| chars.get(p)).copied();
        let next = chars.get(i.saturating_add(1)).copied();
        let boundary = c.is_uppercase()
            && prev.is_some_and(|p| {
                p.is_lowercase() || (p.is_uppercase() && next.is_some_and(char::is_lowercase))
            });
        if boundary && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        cur.extend(c.to_lowercase());
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Returns the forbidden phrase found in an atom, if any.
pub(crate) fn forbidden_phrase(atom: &str) -> Option<String> {
    let w = words(atom);
    for (i, word) in w.iter().enumerate() {
        let next = w.get(i.saturating_add(1)).map_or("", String::as_str);
        let hit = match word.as_str() {
            "dev" | "test" if next == "mode" => Some(format!("{word}_{next}")),
            "devmode" | "testmode" => Some(word.clone()),
            "skip" if next.starts_with("verif") => Some(format!("skip_{next}")),
            "disable" if next.starts_with("auth") => Some(format!("disable_{next}")),
            "allow" if next.starts_with("insecure") => Some(format!("allow_{next}")),
            w if w.starts_with("insecure")
                || w.starts_with("bypass")
                || w.starts_with("danger")
                || w.starts_with("skipverif")
                || w.starts_with("disableauth") =>
            {
                Some(w.to_owned())
            }
            _ => None,
        };
        let negated = i
            .checked_sub(1)
            .and_then(|p| w.get(p))
            .is_some_and(|p| p == "no");
        if hit.is_some() && !negated {
            return hit;
        }
    }
    None
}

fn allowlisted(rel_path: &str, phrase: &str) -> bool {
    ALLOWLIST
        .iter()
        .any(|(p, w, _)| *p == rel_path && *w == phrase)
}

/// INV-26, TI-9: a switch that turns an error, an unreachable state or a degraded
/// dependency into ALLOW. Returns the phrase found in an atom, if any.
pub(crate) fn fail_open_phrase(atom: &str) -> Option<String> {
    let w = words(atom);
    let at = |i: usize| w.get(i).map_or("", String::as_str);
    for i in 0..w.len() {
        let (a, b, c) = (at(i), at(i.saturating_add(1)), at(i.saturating_add(2)));
        let hit = match (a, b, c) {
            ("fail" | "fails", "open", _)
            | ("soft", "fail", _)
            | ("degraded", "allow" | "permit" | "accept", _)
            | ("allow" | "permit" | "accept", "degraded", _) => Some(format!("{a}_{b}")),
            ("failopen" | "softfail", _, _) => Some(a.to_owned()),
            (
                "allow" | "permit" | "accept" | "open",
                "on" | "if",
                "error" | "err" | "failure" | "fail" | "timeout" | "unavailable",
            ) => Some(format!("{a}_{b}_{c}")),
            ("ignore", "verify" | "verification" | "signature" | "signatures", _) => {
                Some(format!("{a}_{b}"))
            }
            _ => None,
        };
        let negated = i
            .checked_sub(1)
            .and_then(|p| w.get(p))
            .is_some_and(|p| p == "no");
        if hit.is_some() && !negated {
            return hit;
        }
    }
    None
}

/// Faults an SDK switch could turn into ALLOW.
const SDK_FAULT: &[&str] = &[
    "timeout",
    "timeouts",
    "error",
    "errors",
    "failure",
    "unavailable",
    "unreachable",
    "outage",
];
/// Allow words.
const SDK_ALLOW: &[&str] = &["allow", "allows", "permit", "accept", "open"];
/// Checks an SDK switch could skip.
const SDK_CHECK: &[&str] = &[
    "receipt",
    "receipts",
    "status",
    "revocation",
    "expiry",
    "exp",
    "audience",
    "aud",
    "signature",
    "signatures",
    "introspection",
    "verify",
    "verification",
    "pep",
    "enforcement",
    "check",
    "checks",
    "horizon",
    "freshness",
];

/// CMP-17, X21: the PEP SDK vocabulary on top of [`fail_open_phrase`]: an allow that
/// follows a fault or is the default, and a check the caller can skip.
pub(crate) fn fail_open_sdk_phrase(atom: &str) -> Option<String> {
    if let Some(hit) = fail_open_phrase(atom) {
        return Some(hit);
    }
    let w = words(atom);
    let at = |i: usize| w.get(i).map_or("", String::as_str);
    for i in 0..w.len() {
        let (a, b, c) = (at(i), at(i.saturating_add(1)), at(i.saturating_add(2)));
        let hit = if a == "on" && SDK_FAULT.contains(&b) && SDK_ALLOW.contains(&c) {
            Some(format!("{a}_{b}_{c}"))
        } else if (SDK_FAULT.contains(&a) || a == "default") && SDK_ALLOW.contains(&b) {
            Some(format!("{a}_{b}"))
        } else if SDK_ALLOW.contains(&a)
            && matches!(b, "on" | "if" | "by")
            && (SDK_FAULT.contains(&c) || c == "default")
        {
            Some(format!("{a}_{b}_{c}"))
        } else if matches!(a, "skip" | "ignore" | "disable" | "bypass") && SDK_CHECK.contains(&b) {
            Some(format!("{a}_{b}"))
        } else {
            None
        };
        let negated = i
            .checked_sub(1)
            .and_then(|p| w.get(p))
            .is_some_and(|p| p == "no");
        if hit.is_some() && !negated {
            return hit;
        }
    }
    None
}

const FAIL_CLOSED: &str = "fail-closed";

/// One scan: the rule name, how to find a phrase (everywhere, and under `sdks/`) and
/// how to explain it.
struct Scan {
    rule: &'static str,
    phrase: fn(&str) -> Option<String>,
    sdk_phrase: fn(&str) -> Option<String>,
    why: &'static str,
}

impl Scan {
    fn phrase_for(&self, rel_path: &str) -> fn(&str) -> Option<String> {
        if rel_path.starts_with(SDK_PREFIX) {
            self.sdk_phrase
        } else {
            self.phrase
        }
    }
}

const DEV_MODE: Scan = Scan {
    rule: RULE,
    phrase: forbidden_phrase,
    sdk_phrase: forbidden_phrase,
    why: "no dev/test mode or security-weakening switch (TI-9, OP-69)",
};

const FAIL_OPEN: Scan = Scan {
    rule: FAIL_CLOSED,
    phrase: fail_open_phrase,
    sdk_phrase: fail_open_sdk_phrase,
    why: "no fail-open path; errors and unknown states are DENY or REQUIRE_ACTION (INV-26, TI-9)",
};

/// Violations in a Rust file's non-test identifiers and string literals.
#[cfg(test)]
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    scan_rust(&DEV_MODE, rel_path, src)
}

/// Fail-open switches in a Rust file's non-test identifiers and string literals.
#[cfg(test)]
pub(crate) fn fail_open_rust(rel_path: &str, src: &str) -> Vec<Violation> {
    scan_rust(&FAIL_OPEN, rel_path, src)
}

fn scan_rust(scan: &Scan, rel_path: &str, src: &str) -> Vec<Violation> {
    let phrase = scan.phrase_for(rel_path);
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut atoms: Vec<(usize, String)> = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        let n = i.saturating_add(1);
        for ident in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !ident.is_empty() {
                atoms.push((n, ident.to_owned()));
            }
        }
    }
    atoms.extend(lexed.strings.iter().map(|l| (l.line, l.text.clone())));
    atoms
        .into_iter()
        .filter(|(line, _)| !in_regions(&tests, *line))
        .filter_map(|(line, atom)| phrase(&atom).map(|p| (line, p)))
        .filter(|(_, p)| !allowlisted(rel_path, p))
        .map(|(line, p)| Violation {
            rule: scan.rule,
            path: PathBuf::from(format!("{rel_path}:{line}")),
            message: format!("`{p}`: {}", scan.why),
        })
        .collect()
}

/// Identifiers in code and the contents of string and template literals of a
/// TypeScript or JavaScript source, with their lines; comments are dropped.
fn script_atoms(src: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut line = 1_usize;
    let mut i = 0_usize;
    let mut word = String::new();
    let mut word_line = 1_usize;
    let flush = |word: &mut String, at: usize, out: &mut Vec<(usize, String)>| {
        if !word.is_empty() {
            out.push((at, std::mem::take(word)));
        }
    };
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i.saturating_add(1)).copied();
        if c == '/' && next == Some('/') {
            flush(&mut word, word_line, &mut out);
            while chars.get(i).is_some_and(|&c| c != '\n') {
                i = i.saturating_add(1);
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            flush(&mut word, word_line, &mut out);
            i = i.saturating_add(2);
            while let Some(&c) = chars.get(i) {
                if c == '\n' {
                    line = line.saturating_add(1);
                }
                if c == '*' && chars.get(i.saturating_add(1)) == Some(&'/') {
                    i = i.saturating_add(2);
                    break;
                }
                i = i.saturating_add(1);
            }
            continue;
        }
        if matches!(c, '"' | '\'' | '`') {
            flush(&mut word, word_line, &mut out);
            let start = line;
            let mut text = String::new();
            i = i.saturating_add(1);
            while let Some(&s) = chars.get(i) {
                i = i.saturating_add(1);
                if s == '\\' {
                    if let Some(&escaped) = chars.get(i) {
                        text.push(escaped);
                        i = i.saturating_add(1);
                    }
                    continue;
                }
                if s == c {
                    break;
                }
                if s == '\n' {
                    line = line.saturating_add(1);
                }
                text.push(s);
            }
            out.push((start, text));
            continue;
        }
        if c.is_alphanumeric() || c == '_' || c == '$' {
            if word.is_empty() {
                word_line = line;
            }
            word.push(c);
        } else {
            flush(&mut word, word_line, &mut out);
            if c == '\n' {
                line = line.saturating_add(1);
            }
        }
        i = i.saturating_add(1);
    }
    flush(&mut word, word_line, &mut out);
    out
}

/// True for script files that only run as tests.
fn is_script_test(rel_path: &str) -> bool {
    let name = rel_path.rsplit('/').next().unwrap_or_default();
    rel_path
        .split('/')
        .any(|p| matches!(p, "tests" | "test" | "__tests__" | "e2e"))
        || [".test.", ".spec."].iter().any(|t| name.contains(t))
}

fn scan_script(scan: &Scan, rel_path: &str, src: &str) -> Vec<Violation> {
    let phrase = scan.phrase_for(rel_path);
    let mut out = Vec::new();
    for (line, atom) in script_atoms(src) {
        let hits = atom
            .split(|c: char| c.is_whitespace() || "\"'=:,;[]{}()".contains(c))
            .filter_map(phrase)
            .filter(|p| !allowlisted(rel_path, p))
            .collect::<Vec<_>>();
        for p in hits {
            out.push(Violation {
                rule: scan.rule,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: format!("`{p}`: {}", scan.why),
            });
        }
    }
    out
}

/// Violations in an SDK script's identifiers and string literals.
#[cfg(test)]
pub(crate) fn fail_open_script(rel_path: &str, src: &str) -> Vec<Violation> {
    scan_script(&FAIL_OPEN, rel_path, src)
}

/// Violations in a configuration file; `#` comments are skipped.
#[cfg(test)]
pub(crate) fn config_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    scan_config(&DEV_MODE, rel_path, text)
}

/// Fail-open switches in a configuration file.
#[cfg(test)]
pub(crate) fn fail_open_config(rel_path: &str, text: &str) -> Vec<Violation> {
    scan_config(&FAIL_OPEN, rel_path, text)
}

/// Prose in configuration ("never fail-open") negates the next word.
const NEGATIONS: &[&str] = &["no", "not", "never", "without"];

fn scan_config(scan: &Scan, rel_path: &str, text: &str) -> Vec<Violation> {
    let phrase = scan.phrase_for(rel_path);
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let content = match line.find('#') {
            Some(at)
                if line
                    .get(..at)
                    .is_some_and(|b| b.is_empty() || b.ends_with(char::is_whitespace)) =>
            {
                line.get(..at).unwrap_or_default()
            }
            _ => line,
        };
        let mut prev = "";
        for atom in content
            .split(|c: char| c.is_whitespace() || "\"'=:,[]{}()".contains(c))
            .filter(|a| !a.is_empty())
        {
            let negated = NEGATIONS.contains(&prev.to_ascii_lowercase().as_str());
            prev = atom;
            if negated {
                continue;
            }
            if let Some(p) = phrase(atom).filter(|p| !allowlisted(rel_path, p)) {
                out.push(Violation {
                    rule: scan.rule,
                    path: PathBuf::from(format!("{rel_path}:{}", i.saturating_add(1))),
                    message: format!("`{p}`: {}", scan.why),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    check_with(root, &DEV_MODE)
}

pub(crate) fn check_fail_closed(root: &Path) -> Result<Vec<Violation>, String> {
    check_with(root, &FAIL_OPEN)
}

fn check_with(root: &Path, scan: &Scan) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if rel_path == SELF_PATH {
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
                out.extend(scan_rust(scan, &rel_path, &read(&path)?));
            }
        } else if SCRIPT_EXTENSIONS.contains(&ext) {
            if rel_path.starts_with(SDK_PREFIX)
                && !is_script_test(&rel_path)
                && !SDK_SKIP_PREFIXES.iter().any(|p| rel_path.starts_with(p))
            {
                out.extend(scan_script(scan, &rel_path, &read(&path)?));
            }
        } else if (CONFIG_EXTENSIONS.contains(&ext) || name.starts_with(".env"))
            && !CONFIG_SKIP_PREFIXES.iter().any(|p| rel_path.starts_with(p))
        {
            out.extend(scan_config(scan, &rel_path, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_split_into_words() {
        assert_eq!(
            words("allowInsecureHTTPServer"),
            vec!["allow", "insecure", "http", "server"]
        );
        assert_eq!(words("SKIP_VERIFY"), vec!["skip", "verify"]);
    }

    #[test]
    fn dev_mode_flag_is_rejected() {
        assert_eq!(
            rust_violations("a.rs", "struct C { dev_mode: bool }").len(),
            1
        );
        assert_eq!(
            rust_violations("a.rs", "fn f() { env(\"ACCESS_TEST_MODE\"); }").len(),
            1
        );
    }

    #[test]
    fn security_weakening_names_are_rejected() {
        for atom in [
            "allow_insecure",
            "skipVerification",
            "bypass_mfa",
            "disable_auth",
            "dangerous_config",
            "DEVMODE",
        ] {
            assert!(forbidden_phrase(atom).is_some(), "{atom}");
        }
    }

    #[test]
    fn ordinary_words_are_accepted() {
        for atom in [
            "no-dev-mode",
            "secure_cookie",
            "verification",
            "mode",
            "developer",
            "test_vectors",
            "authentication",
        ] {
            assert!(forbidden_phrase(atom).is_none(), "{atom}");
        }
    }

    #[test]
    fn comments_and_test_code_are_not_checked() {
        let src = "// a bypass is rejected\n#[cfg(test)]\nmod tests { fn insecure_url_is_rejected() {} }\n";
        assert!(rust_violations("a.rs", src).is_empty());
    }

    // INV-26, TI-9
    #[test]
    fn fail_open_switches_are_rejected() {
        for atom in [
            "fail_open",
            "FAIL_OPEN_ON_TIMEOUT",
            "failOpen",
            "degraded_allow",
            "allowDegraded",
            "allow_on_error",
            "permit_if_unavailable",
            "skip_verify",
            "ocsp_soft_fail",
            "ignore_signature",
        ] {
            let hit = fail_open_phrase(atom).or_else(|| forbidden_phrase(atom));
            assert!(hit.is_some(), "{atom}");
        }
        for atom in [
            "fail_closed",
            "no_fail_open",
            "allow",
            "on_error",
            "open_session",
            "degraded_mode_banner",
        ] {
            assert!(fail_open_phrase(atom).is_none(), "{atom}");
        }
        assert_eq!(
            fail_open_rust("a.rs", "struct Config { fail_open: bool }").len(),
            1
        );
        assert_eq!(
            fail_open_config("deploy/a.yaml", "limiter:\n  degraded_allow: true\n").len(),
            1
        );
        let test_only = "#[cfg(test)]\nmod tests { fn allow_on_error_is_rejected() {} }\n";
        assert!(fail_open_config("a.toml", "title = \"never fail-open\"\n").is_empty());
        assert!(fail_open_rust("a.rs", test_only).is_empty());
    }

    // CMP-17, X21, TI-9, OP-150 m.1 (a)
    #[test]
    fn sdk_vocabulary_names_default_allow_and_skipped_checks() {
        for atom in [
            "defaultAllow",
            "allow_by_default",
            "timeoutAllow",
            "onUnavailableAllow",
            "ALLOW_IF_UNREACHABLE",
            "skipReceiptCheck",
            "ignore_status",
            "disableRevocation",
            "bypassPep",
            "failOpen",
        ] {
            assert!(fail_open_sdk_phrase(atom).is_some(), "{atom}");
        }
        for atom in [
            "allowed",
            "statusList",
            "receipt",
            "onError",
            "timeout_ms",
            "checkValidity",
            "no_default_allow",
            "verifyCoseSign1",
        ] {
            assert!(fail_open_sdk_phrase(atom).is_none(), "{atom}");
        }
        assert!(fail_open_phrase("defaultAllow").is_none());
    }

    // CMP-17, X21, TI-9, OP-150 m.1 (a)
    #[test]
    fn sdk_scripts_are_scanned_outside_comments_and_tests() {
        let src = "// a failOpen option is forbidden\n/* skipReceipt */\nexport interface Options {\n  failOpen?: boolean;\n}\nconst mode = \"degraded-allow\";\nconst ok = `checked ${x}`;\n";
        let v = fail_open_script("sdks/typescript/src/pep.ts", src);
        let lines: Vec<String> = v.iter().map(|v| v.path.display().to_string()).collect();
        assert_eq!(
            lines,
            [
                "sdks/typescript/src/pep.ts:4",
                "sdks/typescript/src/pep.ts:6"
            ]
        );
        assert!(is_script_test("sdks/typescript/src/pep.test.ts"));
        assert!(!is_script_test("sdks/typescript/src/pep.ts"));
        let rust = "pub struct Options { pub skip_receipt: bool }";
        assert_eq!(fail_open_rust("sdks/rust/access/src/a.rs", rust).len(), 1);
        assert!(fail_open_rust("crates/http/src/a.rs", rust).is_empty());
    }

    #[test]
    fn config_key_naming_insecure_switch_is_rejected() {
        let v = config_violations(
            "deploy/a.toml",
            "# insecure is not allowed\nallow_insecure = true\n",
        );
        assert_eq!(v.len(), 1);
    }
}
