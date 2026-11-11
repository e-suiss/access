//! `forbidden-ui-terms` (X24, XI-13, §8.11, OP-151 m.3 (r)): the words a user of Access must
//! never read: "mandate", "pause", "transfer", "verified", "trusted", "full access", "forever",
//! "undo", and "session" for an Instance; nor "fail open", "test mode", "log in as" or
//! impersonation (MD-9, TI-9); nor an approver, approval, person or device called
//! "independent" (§8.17.6.3, OP-157 m.3 (l)). The string literals and JSX text of `web/*/src` and
//! `sdks/typescript/src` are scanned, tests excepted, and so are the message values of the
//! `locales/*/*.ftl` catalogues the hosted pages render; product claims are `forbidden-claims.toml`'s. Protocol phrases that must keep a
//! protocol's own words are allowed only through `conformance/catalog/ui-terms.toml`. The string
//! catalogues (Fluent values and `*/i18n/*` files) also never say "session" or "oturum" in any
//! sense (§8.11, X33, OP-153 m.25 (e)); API paths and code identifiers elsewhere keep the word.
//!
//! `ui-text-nodes` (TN-131): tenant-controlled strings render as text nodes only, so no web or
//! SDK source sets HTML from a string (`dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`,
//! `insertAdjacentHTML`, `document.write`).

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "forbidden-ui-terms";
const TEXT_RULE: &str = "ui-text-nodes";

/// The allowlist file.
pub(crate) const ALLOWLIST: &str = "conformance/catalog/ui-terms.toml";

/// Whole words that are never shown (X24, XI-13, §8.11).
const WORDS: &[&str] = &[
    "mandate",
    "mandates",
    "pause",
    "paused",
    "pausing",
    "transfer",
    "transferred",
    "transfers",
    "verified",
    "trusted",
    "forever",
    "undo",
];

/// Word sequences that are never shown.
const PHRASES: &[&[&str]] = &[
    &["full", "access"],
    &["fail", "open"],
    &["test", "mode"],
    &["log", "in", "as"],
    &["login", "as"],
    &["session", "instance"],
    &["instance", "session"],
    &["sessions", "instances"],
    &["instance", "sessions"],
    // §8.17.6.3, OP-157 m.3 (l)
    &["independent", "approver"],
    &["independent", "approvers"],
    &["independent", "approval"],
    &["independent", "approvals"],
    &["independently", "approved"],
    &["independent", "person"],
    &["independent", "people"],
    &["independent", "device"],
    &["independent", "devices"],
];

/// Word prefixes that are never shown (MD-9: no impersonation of any form).
const PREFIXES: &[&str] = &["impersonat"];

/// Whole words a string catalogue never shows: a sign-in is a sign-in (§8.11, X33).
const CATALOGUE_WORDS: &[&str] = &["session", "sessions"];

/// Word prefixes a string catalogue never shows: Turkish "oturum" and its inflections (X33).
const CATALOGUE_PREFIXES: &[&str] = &["oturum"];

/// Protocols whose own phrases an allowlist entry may keep.
const PROTOCOLS: &[&str] = &[
    "OAuth", "OIDC", "OpenID", "SAML", "SCIM", "WebAuthn", "DPoP", "SSF", "CAEP", "LDAP",
];

/// HTML sinks a string must never reach (TN-131).
const HTML_SINKS: &[&str] = &[
    "dangerouslySetInnerHTML",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
];

/// Source roots scanned.
const ROOTS: &[&str] = &["web/", "sdks/typescript/src/"];

/// Generated or built output that is not ours to word; the types generated from the `OpenAPI`
/// contracts carry protocol values, not UI text (OP-151 m.3 (g), (r)).
const SKIP: &[&str] = &[
    "/dist/",
    "/node_modules/",
    "/e2e/",
    "sdks/typescript/wasm/",
    "sdks/typescript/src/generated/",
];

const SCRIPT: &[&str] = &["ts", "tsx", "mts", "cts", "js", "jsx", "mjs", "cjs"];

/// One allowed protocol phrase.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Allowed {
    /// The phrase, as shown; it starts with the protocol's name.
    pub(crate) phrase: String,
    /// The standard that names it.
    pub(crate) standard: String,
    /// Why the protocol's word must stay.
    pub(crate) reason: String,
}

/// The allowlist file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Allowlist {
    /// Entries.
    #[serde(default)]
    pub(crate) allow: Vec<Allowed>,
}

/// Parses the allowlist and checks its entries are protocol phrases.
pub(crate) fn allowlist(text: &str) -> Result<Vec<String>, String> {
    let list: Allowlist = toml::from_str(text).map_err(|e| format!("{ALLOWLIST}: {e}"))?;
    let mut out = Vec::new();
    for a in list.allow {
        let protocol = a.phrase.split_whitespace().next().unwrap_or_default();
        if !PROTOCOLS.contains(&protocol)
            || a.standard.trim().is_empty()
            || a.reason.trim().is_empty()
        {
            return Err(format!(
                "{ALLOWLIST}: `{}` is not a protocol phrase with a standard and a reason",
                a.phrase
            ));
        }
        out.push(a.phrase.to_lowercase());
    }
    Ok(out)
}

/// Lower-case words of `text`.
fn words(text: &str) -> Vec<String> {
    crate::rules::switches::words(text)
}

/// The forbidden term in `text`, after removing the allowed phrases.
pub(crate) fn forbidden(text: &str, allowed: &[String]) -> Option<String> {
    let mut lower = text.to_lowercase();
    for a in allowed {
        lower = lower.replace(a.as_str(), " ");
    }
    let w = words(&lower);
    for (i, word) in w.iter().enumerate() {
        if WORDS.contains(&word.as_str()) {
            return Some(word.clone());
        }
        if let Some(p) = PREFIXES.iter().find(|p| word.starts_with(**p)) {
            return Some((*p).to_owned());
        }
        for phrase in PHRASES {
            let hit = phrase
                .iter()
                .enumerate()
                .all(|(k, p)| w.get(i.saturating_add(k)).is_some_and(|x| x == p));
            if hit {
                return Some(phrase.join(" "));
            }
        }
    }
    None
}

/// The forbidden term in a string catalogue's `text`: the UI terms and "session"/"oturum" in
/// any sense (§8.11, X33, OP-153 m.25 (e)).
pub(crate) fn forbidden_in_catalogue(text: &str, allowed: &[String]) -> Option<String> {
    if let Some(term) = forbidden(text, allowed) {
        return Some(term);
    }
    let mut lower = text.to_lowercase();
    for a in allowed {
        lower = lower.replace(a.as_str(), " ");
    }
    words(&lower).into_iter().find_map(|w| {
        if CATALOGUE_WORDS.contains(&w.as_str()) {
            return Some(w);
        }
        CATALOGUE_PREFIXES
            .iter()
            .find(|p| w.starts_with(**p))
            .map(|p| (*p).to_owned())
    })
}

/// Whether a script is a string catalogue: it lies under an `i18n` directory.
fn catalogue(rel_path: &str) -> bool {
    rel_path.split('/').any(|part| part == "i18n")
}

/// String and template literals of a script, with their lines; comments skipped.
pub(crate) fn literals(src: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let (mut i, mut line) = (0_usize, 1_usize);
    while let Some(&c) = chars.get(i) {
        let next = chars.get(i.saturating_add(1)).copied();
        if c == '\n' {
            line = line.saturating_add(1);
        }
        if c == '/' && next == Some('/') {
            while chars.get(i).is_some_and(|&c| c != '\n') {
                i = i.saturating_add(1);
            }
            continue;
        }
        if c == '/' && next == Some('*') {
            i = i.saturating_add(2);
            while let Some(&c) = chars.get(i) {
                if c == '\n' {
                    line = line.saturating_add(1);
                }
                i = i.saturating_add(1);
                if c == '*' && chars.get(i) == Some(&'/') {
                    i = i.saturating_add(1);
                    break;
                }
            }
            continue;
        }
        if matches!(c, '"' | '\'' | '`') {
            let start = line;
            let mut text = String::new();
            i = i.saturating_add(1);
            while let Some(&s) = chars.get(i) {
                i = i.saturating_add(1);
                if s == '\\' {
                    if let Some(&e) = chars.get(i) {
                        text.push(e);
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
        i = i.saturating_add(1);
    }
    out
}

/// JSX text: what stands between a tag's `>` and the next `<` or `{`, when it reads as words.
pub(crate) fn jsx_text(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (n, l) in src.lines().enumerate() {
        let mut rest = l;
        while let Some(at) = rest.find('>') {
            let after = rest.get(at.saturating_add(1)..).unwrap_or_default();
            let end = after.find(['<', '{']).unwrap_or(after.len());
            let text = after.get(..end).unwrap_or_default().trim();
            let wordy = text.chars().any(char::is_alphabetic)
                && text
                    .chars()
                    .all(|c| c.is_alphanumeric() || c.is_whitespace() || ".,!?'’…:-".contains(c));
            if wordy {
                out.push((n.saturating_add(1), text.to_owned()));
            }
            rest = after;
        }
    }
    out
}

/// Violations of one source file.
pub(crate) fn scan(rel_path: &str, src: &str, allowed: &[String]) -> Vec<Violation> {
    let mut texts = literals(src);
    let ext = rel_path.rsplit_once('.').map_or("", |(_, e)| e);
    if ext.eq_ignore_ascii_case("tsx") || ext.eq_ignore_ascii_case("jsx") {
        texts.extend(jsx_text(src));
    }
    let check = if catalogue(rel_path) {
        forbidden_in_catalogue
    } else {
        forbidden
    };
    let mut out = Vec::new();
    for (line, text) in texts {
        if let Some(term) = check(&text, allowed) {
            out.push(Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: format!(
                    "`{term}` is a forbidden UI term (X24, XI-13); say what happens instead"
                ),
            });
        }
    }
    let code: String = {
        let mut c = src.to_owned();
        for (_, text) in literals(src) {
            c = c.replacen(&text, "", 1);
        }
        c
    };
    for (n, l) in code.lines().enumerate() {
        let trimmed = l.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with('*') {
            continue;
        }
        if let Some(sink) = HTML_SINKS.iter().find(|s| l.contains(**s)) {
            out.push(Violation {
                rule: TEXT_RULE,
                path: PathBuf::from(format!("{rel_path}:{}", n.saturating_add(1))),
                message: format!(
                    "`{sink}`: tenant-controlled strings render as text nodes only (TN-131)"
                ),
            });
        }
    }
    out
}

/// Message values of a Fluent catalogue, with their lines; comments and ids skipped.
pub(crate) fn fluent_values(src: &str) -> Vec<(usize, String)> {
    src.lines()
        .enumerate()
        .filter_map(|(n, l)| {
            let t = l.trim_start();
            if t.is_empty() || t.starts_with('#') {
                return None;
            }
            let value = if l.starts_with(char::is_whitespace) {
                t.strip_prefix('.')
                    .map_or(t, |a| a.split_once('=').map_or(a, |(_, v)| v))
            } else {
                l.split_once('=').map_or("", |(_, v)| v)
            };
            Some((n.saturating_add(1), value.to_owned()))
        })
        .collect()
}

fn fluent(rel_path: &str) -> bool {
    rel_path.starts_with("locales/")
        && rel_path
            .rsplit_once('.')
            .is_some_and(|(_, e)| e.eq_ignore_ascii_case("ftl"))
}

fn scan_fluent(rel_path: &str, src: &str, allowed: &[String]) -> Vec<Violation> {
    fluent_values(src)
        .into_iter()
        .filter_map(|(line, text)| {
            forbidden_in_catalogue(&text, allowed).map(|term| Violation {
                rule: RULE,
                path: PathBuf::from(format!("{rel_path}:{line}")),
                message: format!(
                    "`{term}` is a forbidden UI term (X24, XI-13); say what happens instead"
                ),
            })
        })
        .collect()
}

fn scanned(rel_path: &str) -> bool {
    let ext = rel_path.rsplit_once('.').map_or("", |(_, e)| e);
    let name = rel_path.rsplit('/').next().unwrap_or_default();
    let in_root = ROOTS.iter().any(|r| rel_path.starts_with(r))
        && (rel_path.starts_with("sdks/") || rel_path.split('/').nth(2) == Some("src"));
    in_root
        && SCRIPT.contains(&ext)
        && !SKIP
            .iter()
            .any(|s| rel_path.contains(s) || rel_path.starts_with(s))
        && !name.contains(".test.")
        && !name.contains(".spec.")
}

fn run(root: &Path) -> Result<Vec<Violation>, String> {
    let allowed = allowlist(&read(&root.join(ALLOWLIST))?)?;
    let mut out = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        if scanned(&rel_path) {
            out.extend(scan(&rel_path, &read(&path)?, &allowed));
        } else if fluent(&rel_path) {
            out.extend(scan_fluent(&rel_path, &read(&path)?, &allowed));
        }
    }
    Ok(out)
}

/// `forbidden-ui-terms`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(run(root)?.into_iter().filter(|v| v.rule == RULE).collect())
}

/// `ui-text-nodes`.
pub(crate) fn check_text_nodes(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(run(root)?
        .into_iter()
        .filter(|v| v.rule == TEXT_RULE)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow() -> Vec<String> {
        allowlist(
            r#"
            [[allow]]
            phrase = "OAuth grant type"
            standard = "RFC 6749"
            reason = "protocol name"
            "#,
        )
        .unwrap_or_default()
    }

    // X24, XI-13, OP-151 m.3 (r)
    #[test]
    fn forbidden_terms_are_found() {
        let a = allow();
        for (text, term) in [
            ("Pause access", "pause"),
            ("Mandate", "mandate"),
            ("Transfer this grant", "transfer"),
            ("Verified account", "verified"),
            ("Trusted device", "trusted"),
            ("Give full access", "full access"),
            ("Valid forever", "forever"),
            ("Undo", "undo"),
            ("Your session instance", "session instance"),
            ("Log in as Ada", "log in as"),
            ("Impersonate user", "impersonat"),
            ("Needs 2 independent approvals", "independent approvals"),
            ("Independently approved", "independently approved"),
            ("Enable test mode", "test mode"),
            ("fail open", "fail open"),
        ] {
            assert_eq!(forbidden(text, &a).as_deref(), Some(term), "{text}");
        }
        for ok in [
            "Untrusted input",
            "Your sign-ins",
            "Instances",
            "Stop access",
            "End this sign-in",
        ] {
            assert_eq!(forbidden(ok, &a), None, "{ok}");
        }
    }

    // X33, §8.11, OP-153 m.25 (e)
    #[test]
    fn catalogues_never_say_session_in_any_sense() {
        let a = allow();
        for (text, term) in [
            ("Sessions", "sessions"),
            ("This session", "session"),
            ("They can only end sessions", "sessions"),
            ("Oturum açtığınız yerler", "oturum"),
            ("Bu oturum", "oturum"),
            ("Oturumu kapat", "oturum"),
            ("hesabınızın oturumları sonlandırıldı", "oturum"),
            ("Bu cihazda oturumumu açık tut", "oturum"),
            ("Pause access", "pause"),
        ] {
            assert_eq!(
                forbidden_in_catalogue(text, &a).as_deref(),
                Some(term),
                "{text}"
            );
        }
        for ok in [
            "Your sign-ins",
            "Sign-in on this device",
            "Girişleriniz",
            "Bu cihaz üzerinde giriş",
            "Oturma odası",
        ] {
            assert_eq!(forbidden_in_catalogue(ok, &a), None, "{ok}");
        }
        assert_eq!(forbidden("Sessions", &a), None);
    }

    // X33, OP-153 m.25 (e)
    #[test]
    fn session_is_refused_in_catalogues_only() {
        let src = "export const en = {\n  sessionsTitle: \"Your sessions\",\n};\n";
        let v = scan("web/console/src/i18n/en.ts", src, &[]);
        let lines: Vec<String> = v.iter().map(|v| v.path.display().to_string()).collect();
        assert_eq!(lines, ["web/console/src/i18n/en.ts:2"]);
        assert!(
            scan(
                "web/console/src/i18n/en.ts",
                "const k = { sessionsTitle: \"Your sign-ins\" };\n",
                &[]
            )
            .is_empty()
        );
        let code = "const r = await frontend(\"/v1/sessions/current\");\nconst s = \"session\";\n";
        assert!(scan("web/account/src/signins/index.tsx", code, &[]).is_empty());
        let v = scan_fluent(
            "locales/tr/login.ftl",
            "keep = Bu cihazda oturumumu açık tut\n",
            &[],
        );
        assert_eq!(v.len(), 1);
        assert!(catalogue("web/login/src/i18n/tr.ts"));
        assert!(!catalogue("web/console/src/screens/Own.tsx"));
    }

    // OP-151 m.3 (r)
    #[test]
    fn allowlist_holds_protocol_phrases_only() {
        assert!(
            allowlist("[[allow]]\nphrase = \"Verified badge\"\nstandard = \"x\"\nreason = \"y\"\n")
                .is_err()
        );
        assert!(
            allowlist("[[allow]]\nphrase = \"OAuth scope\"\nstandard = \"\"\nreason = \"y\"\n")
                .is_err()
        );
        let a = allowlist(
            "[[allow]]\nphrase = \"OAuth token transfer\"\nstandard = \"RFC 8693\"\nreason = \"name\"\n",
        )
        .unwrap_or_default();
        assert_eq!(forbidden("OAuth token transfer", &a), None);
        assert_eq!(forbidden("Transfer", &a).as_deref(), Some("transfer"));
    }

    // X24, TN-131
    #[test]
    fn literals_and_jsx_text_are_scanned() {
        let src = "// pause here is a comment\nconst a = \"Pause\";\nconst b = <p>Undo it</p>;\nconst c = `trusted ${x}`;\n";
        let v = scan("web/console/src/App.tsx", src, &[]);
        let lines: Vec<String> = v.iter().map(|v| v.path.display().to_string()).collect();
        assert_eq!(
            lines,
            [
                "web/console/src/App.tsx:2",
                "web/console/src/App.tsx:4",
                "web/console/src/App.tsx:3"
            ]
        );
    }

    // TN-131
    #[test]
    fn html_sinks_are_refused() {
        let v = scan(
            "web/console/src/x.tsx",
            "const a = <div dangerouslySetInnerHTML={{ __html: s }} />;\nel.innerHTML = s;\n// innerHTML in a comment\n",
            &[],
        );
        assert_eq!(v.len(), 2);
        assert!(v.iter().all(|v| v.rule == TEXT_RULE));
        assert!(scan("web/console/src/x.ts", "const s = \"innerHTML\";\n", &[]).is_empty());
    }

    #[test]
    fn scanned_paths() {
        assert!(scanned("web/console/src/App.tsx"));
        assert!(scanned("web/login/src/i18n/en.ts"));
        assert!(scanned("sdks/typescript/src/index.ts"));
        assert!(!scanned("web/console/e2e/a11y.spec.ts"));
        assert!(!scanned("web/console/dist/assets/x.js"));
        assert!(!scanned("web/console/vite.config.ts"));
        assert!(!scanned("sdks/typescript/src/index.test.ts"));
        assert!(!scanned("sdks/typescript/wasm/x.js"));
        assert!(!scanned("sdks/typescript/src/generated/access-v1.ts"));
    }

    // X24
    #[test]
    fn fluent_values_are_scanned_without_ids_or_comments() {
        let src =
            "# undo in a comment\nundo-id = Stop access\nbad = Undo it\n    .title = Verified\n";
        let v = scan_fluent("locales/en/x.ftl", src, &[]);
        let lines: Vec<String> = v.iter().map(|v| v.path.display().to_string()).collect();
        assert_eq!(lines, ["locales/en/x.ftl:3", "locales/en/x.ftl:4"]);
        assert!(fluent("locales/tr/login.ftl"));
        assert!(!fluent("web/login/src/x.ftl"));
    }
}
