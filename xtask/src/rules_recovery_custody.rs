//! `recovery-custody` (SEC20, U16, OP-158 m.3 (m)): no Access signer, HSM label or configuration holds a recovery key; recovery keys stay outside the provider.
//!
//! The keys of a domain's rootTerms recovery entry live on the root Parties' own devices
//! (passkey or security key) or are offline ceremony keys. The provider never holds one, so its
//! operator can never recover a domain. The signer and HSM code (non-test identifiers and string
//! literals), the server and signer configuration, deployment files and SQL migrations must not
//! name a recovery key: an atom with a `recover` word next to a key-material word.

use std::path::{Path, PathBuf};

use crate::Violation;
use crate::rules::files::{is_test_file, read, rel, walk};
use crate::rules::lex::{in_regions, lex, test_regions};
use crate::rules::switches::words;

const RULE: &str = "recovery-custody";

const WHY: &str = "recovery keys stay outside the provider (SEC20, U16)";

/// The code that holds keys for the provider: the signers, their binaries and the HSM layer.
const KEY_HOLDERS: &[&str] = &[
    "crates/authority-signer/",
    "crates/identity-signer/",
    "crates/identity-vault/",
    "crates/crypto/",
    "bins/access-signer/",
    "bins/access-identity-signer/",
    "bins/access-server/src/config.rs",
    "bins/access-server/src/keys",
];

const CONFIG_EXTENSIONS: &[&str] = &["toml", "yml", "yaml", "json", "sh", "conf", "env"];

/// Words that name key material or where it is kept.
const KEY_WORDS: &[&str] = &[
    "key", "keys", "label", "labels", "seed", "secret", "private", "pkcs8", "sealed", "share",
    "shares", "kek", "slot",
];

/// The recovery-key word pair in an atom, or an HSM label under `access/recover`.
pub(crate) fn recovery_key_word(atom: &str) -> Option<String> {
    let lower = atom.to_ascii_lowercase();
    if lower.contains("access/recover") {
        return Some(lower);
    }
    let w = words(atom);
    let recover = w.iter().any(|x| x.starts_with("recover"));
    let key = w.iter().find(|x| KEY_WORDS.contains(&x.as_str()));
    match (recover, key) {
        (true, Some(k)) => Some(format!(
            "{}…{k}",
            w.iter()
                .find(|x| x.starts_with("recover"))
                .map_or("", |s| s)
        )),
        _ => None,
    }
}

fn violation(rel_path: &str, line: usize, word: &str) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(format!("{rel_path}:{line}")),
        message: format!("`{word}`: {WHY}"),
    }
}

/// Recovery-key names in a Rust file's non-test identifiers and string literals.
pub(crate) fn rust_violations(rel_path: &str, src: &str) -> Vec<Violation> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut atoms: Vec<(usize, String)> = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        for ident in line.split(|c: char| !(c.is_alphanumeric() || c == '_')) {
            if !ident.is_empty() {
                atoms.push((i.saturating_add(1), ident.to_owned()));
            }
        }
    }
    atoms.extend(lexed.strings.iter().map(|l| (l.line, l.text.clone())));
    atoms
        .into_iter()
        .filter(|(line, _)| !in_regions(&tests, *line))
        .filter_map(|(line, atom)| recovery_key_word(&atom).map(|w| violation(rel_path, line, &w)))
        .collect()
}

/// Recovery-key names in a configuration file, script or migration; `#` and `--` comments are
/// skipped.
pub(crate) fn text_violations(rel_path: &str, text: &str) -> Vec<Violation> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') || trimmed.starts_with("--") {
            continue;
        }
        for atom in line
            .split(|c: char| c.is_whitespace() || "\"'=:,;[]{}()".contains(c))
            .filter(|a| !a.is_empty())
        {
            if let Some(w) = recovery_key_word(atom) {
                out.push(violation(rel_path, i.saturating_add(1), &w));
            }
        }
    }
    out
}

/// Runs `recovery-custody`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for path in walk(root)? {
        let r = rel(root, &path);
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default();
        let holder = KEY_HOLDERS.iter().any(|p| r.starts_with(p));
        if ext == "rs" && holder && !is_test_file(&r) {
            out.extend(rust_violations(&r, &read(&path)?));
            continue;
        }
        let config = (r.starts_with("deploy/") || (holder && !r.contains("/tests/")))
            && CONFIG_EXTENSIONS.contains(&ext);
        let migration = (r.starts_with("crates/store/migrations/")
            || (r.starts_with("services/") && r.contains("/migrations/")))
            && ext == "sql";
        if config || migration {
            out.extend(text_violations(&r, &read(&path)?));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // SEC20, U16, CR-31, OP-144, OP-158 m.3 (m), Ek B 5908, 6140
    #[test]
    fn a_recovery_key_in_a_signer_label_or_config_is_refused() {
        for atom in [
            "access/recovery/root-1",
            "RecoveryKey",
            "recover_key_label",
            "RECOVERY_SEED_PATH",
            "recovery_shares",
        ] {
            assert!(recovery_key_word(atom).is_some(), "{atom}");
        }
        assert_eq!(
            rust_violations(
                "crates/authority-signer/src/x.rs",
                "const L: &str = \"access/recovery/entry\";"
            )
            .len(),
            1
        );
        assert_eq!(
            text_violations("deploy/a.toml", "[signer]\nrecovery_key = \"/k\"\n").len(),
            1
        );
    }

    // SEC20, U16
    #[test]
    fn recovery_words_without_key_material_are_accepted() {
        for atom in [
            "recovery_result",
            "domain_recover",
            "RecoveryEntry",
            "key",
            "pg_is_in_recovery",
        ] {
            assert!(recovery_key_word(atom).is_none(), "{atom}");
        }
        let src = "#[cfg(test)]\nmod tests { const K: &str = \"access/recovery/x\"; }\n";
        assert!(rust_violations("crates/crypto/src/a.rs", src).is_empty());
        assert!(text_violations("deploy/a.sh", "# recovery_key is never here\n").is_empty());
    }
}
