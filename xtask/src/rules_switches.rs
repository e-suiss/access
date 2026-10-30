//! `no-dev-mode` (TI-9, OP-48, OP-69 rule 2, X21, CR-34): there is no "dev mode",
//! "test mode" or security-weakening switch. `fail-closed` (INV-26, TI-9): no
//! switch turns an error, a timeout or a degraded dependency into ALLOW. Identifiers and string literals in
//! non-test Rust code, and keys and values in configuration files, must not name
//! one.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};

const RULE: &str = "no-dev-mode";

/// Reviewed exceptions: (relative path, matched word, reason). Each entry needs
/// Adem's review. Empty on purpose.
const ALLOWLIST: &[(&str, &str, &str)] = &[];

/// This file spells out the vocabulary it forbids.
const SELF_PATH: &str = "xtask/src/rules_switches.rs";

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

const FAIL_CLOSED: &str = "fail-closed";

/// One scan: the rule name, how to find a phrase and how to explain it.
struct Scan {
    rule: &'static str,
    phrase: fn(&str) -> Option<String>,
    why: &'static str,
}

const DEV_MODE: Scan = Scan {
    rule: RULE,
    phrase: forbidden_phrase,
    why: "no dev/test mode or security-weakening switch (TI-9, OP-69)",
};

const FAIL_OPEN: Scan = Scan {
    rule: FAIL_CLOSED,
    phrase: fail_open_phrase,
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
        .filter_map(|(line, atom)| (scan.phrase)(&atom).map(|p| (line, p)))
        .filter(|(_, p)| !allowlisted(rel_path, p))
        .map(|(line, p)| Violation {
            rule: scan.rule,
            path: PathBuf::from(format!("{rel_path}:{line}")),
            message: format!("`{p}`: {}", scan.why),
        })
        .collect()
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
            if let Some(p) = (scan.phrase)(atom).filter(|p| !allowlisted(rel_path, p)) {
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

    #[test]
    fn config_key_naming_insecure_switch_is_rejected() {
        let v = config_violations(
            "deploy/a.toml",
            "# insecure is not allowed\nallow_insecure = true\n",
        );
        assert_eq!(v.len(), 1);
    }
}
