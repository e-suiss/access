//! `no-dev-mode` (TI-9, OP-48, OP-69 rule 2, X21, CR-34): there is no "dev mode",
//! "test mode" or security-weakening switch. Identifiers and string literals in
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
const CONFIG_SKIP_PREFIXES: &[&str] = &["supply-chain/"];

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

/// Violations in a Rust file's non-test identifiers and string literals.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
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
        .filter_map(|(line, atom)| forbidden_phrase(&atom).map(|p| (line, p)))
        .filter(|(_, p)| !allowlisted(rel_path, p))
        .map(|(line, p)| Violation {
            rule: RULE,
            path: PathBuf::from(format!("{rel_path}:{line}")),
            message: format!("`{p}`: no dev/test mode or security-weakening switch (TI-9, OP-69)"),
        })
        .collect()
}

/// Violations in a configuration file; `#` comments are skipped.
pub(crate) fn config_violations(rel_path: &str, text: &str) -> Vec<Violation> {
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
        for atom in content.split(|c: char| c.is_whitespace() || "\"'=:,[]{}()".contains(c)) {
            if let Some(p) = forbidden_phrase(atom).filter(|p| !allowlisted(rel_path, p)) {
                out.push(Violation {
                    rule: RULE,
                    path: PathBuf::from(format!("{rel_path}:{}", i.saturating_add(1))),
                    message: format!(
                        "`{p}`: no dev/test mode or security-weakening switch (TI-9, OP-69)"
                    ),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
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
                out.extend(rust_violations(&rel_path, &read(&path)?));
            }
        } else if (CONFIG_EXTENSIONS.contains(&ext) || name.starts_with(".env"))
            && !CONFIG_SKIP_PREFIXES.iter().any(|p| rel_path.starts_with(p))
        {
            out.extend(config_violations(&rel_path, &read(&path)?));
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

    #[test]
    fn config_key_naming_insecure_switch_is_rejected() {
        let v = config_violations(
            "deploy/a.toml",
            "# insecure is not allowed\nallow_insecure = true\n",
        );
        assert_eq!(v.len(), 1);
    }
}
