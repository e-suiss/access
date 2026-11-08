//! `fluent-catalog` (OP-153 m.3 (s), TN-108, X35, X41, XI-25, SEC2, §8.8–§8.11): the message
//! catalog `conformance/catalog/messages.toml` and the Fluent files under `locales/` agree.
//! Every locale has every key of `en`, file by file; every key is catalogued with its §8.15.2
//! class and owner; the protected keys are exactly those of `protected-messages.toml`, and no
//! realm override file (`*.ftl` outside `locales/`) defines one; a guarantee-bearing text names
//! exactly one §3.3 class; and no end-user text says a word the glossary bans or a forbidden UI
//! term, in any language.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::Violation;
use crate::rules::files::{read, rel, walk};

const RULE: &str = "fluent-catalog";

const CATALOG: &str = "conformance/catalog/messages.toml";
const PROTECTED: &str = "conformance/catalog/protected-messages.toml";
const GLOSSARY: &str = "conformance/catalog/glossary.toml";
const LOCALES: &str = "locales/";
const BASE: &str = "en";

/// The surfaces an end user reads; the console is admin and developer UI.
const END_USER: &[&str] = &["login", "account", "hub", "mail"];

/// The §8.15.2 owners (E25).
const OWNERS: &[&str] = &[
    "identity_plane",
    "realm_admin",
    "access",
    "client_developer",
    "upstream_idp",
];

/// The §3.3 guarantee classes (SEC2).
const CLASSES: &[&str] = &["BS", "UDC", "NG", "PU"];

/// One catalogued message.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Message {
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) text_id: Option<String>,
    pub(crate) surface: String,
    pub(crate) class: String,
    pub(crate) owner: String,
    pub(crate) protected: bool,
    #[serde(default)]
    pub(crate) guarantee: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    message: Vec<Message>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Protected {
    keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Term {
    canonical: String,
    #[serde(flatten)]
    columns: BTreeMap<String, String>,
}

/// Words no end-user text says, per language.
#[derive(Debug, Deserialize)]
pub(crate) struct Banned {
    #[serde(flatten)]
    pub(crate) words: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub(crate) classes: Vec<String>,
    #[serde(default)]
    pub(crate) reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Glossary {
    term: Vec<Term>,
    banned: Vec<Banned>,
}

/// Key to text of one Fluent file; continuation lines join with a space.
pub(crate) fn ftl(src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in src.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            current = None;
        } else if line.starts_with(' ') {
            if let Some(v) = current.as_ref().and_then(|k| out.get_mut(k)) {
                let v: &mut String = v;
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once('=') {
            let k = k.trim().to_owned();
            out.insert(k.clone(), v.trim().to_owned());
            current = Some(k);
        }
    }
    out
}

fn violation(path: &str, message: String) -> Violation {
    Violation {
        rule: RULE,
        path: PathBuf::from(path),
        message,
    }
}

/// The word or phrase of `banned` that `text` says, whole words only.
pub(crate) fn says(text: &str, banned: &[String]) -> Option<String> {
    let words = crate::rules::switches::words(&text.to_lowercase());
    banned
        .iter()
        .find(|b| {
            let phrase = crate::rules::switches::words(&b.to_lowercase());
            !phrase.is_empty() && words.windows(phrase.len()).any(|w| w == phrase.as_slice())
        })
        .cloned()
}

/// Violations of the catalogs, given every Fluent file as (path, text).
#[expect(
    clippy::too_many_lines,
    reason = "one pass over the catalog, read top to bottom"
)]
pub(crate) fn check_texts(
    catalog: &[Message],
    protected: &[String],
    glossary_terms: &[(String, BTreeMap<String, String>)],
    banned: &[Banned],
    files: &[(String, String)],
) -> Vec<Violation> {
    let mut out = Vec::new();
    let by_key: BTreeMap<&str, &Message> = catalog.iter().map(|m| (m.key.as_str(), m)).collect();
    if by_key.len() != catalog.len() {
        out.push(violation(
            CATALOG,
            String::from("a key is catalogued twice"),
        ));
    }
    for m in catalog {
        if m.text_id
            .as_ref()
            .is_some_and(|t| t.replace('.', "-") != m.key)
        {
            out.push(violation(
                CATALOG,
                format!(
                    "{}: the key of a TextId is its wire id with `-` for `.`",
                    m.key
                ),
            ));
        }
        if !OWNERS.contains(&m.owner.as_str()) {
            out.push(violation(
                CATALOG,
                format!("{}: unknown owner `{}` (§8.15.2)", m.key, m.owner),
            ));
        }
        match &m.guarantee {
            Some(g) if !CLASSES.contains(&g.as_str()) => out.push(violation(
                CATALOG,
                format!("{}: `{g}` is not exactly one §3.3 class (SEC2)", m.key),
            )),
            Some(_) if !m.protected => out.push(violation(
                CATALOG,
                format!("{}: a guarantee-bearing text is protected (X35)", m.key),
            )),
            _ => {}
        }
    }
    let declared: BTreeSet<&str> = protected.iter().map(String::as_str).collect();
    let flagged: BTreeSet<&str> = catalog
        .iter()
        .filter(|m| m.protected)
        .map(|m| m.key.as_str())
        .collect();
    if declared != flagged {
        out.push(violation(
            PROTECTED,
            format!(
                "differs from the protected entries of {CATALOG}: {:?}",
                declared.symmetric_difference(&flagged).collect::<Vec<_>>()
            ),
        ));
    }
    for lang in glossary_terms
        .iter()
        .flat_map(|(_, c)| c.keys())
        .collect::<BTreeSet<_>>()
    {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for (canonical, columns) in glossary_terms {
            let Some(term) = columns.get(lang) else {
                out.push(violation(
                    GLOSSARY,
                    format!("{canonical}: no `{lang}` term"),
                ));
                continue;
            };
            if let Some(other) = seen.insert(term.as_str(), canonical.as_str()) {
                out.push(violation(
                    GLOSSARY,
                    format!("`{term}` names both {other} and {canonical} (one term, one concept)"),
                ));
            }
        }
    }
    let mut locales: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>> = BTreeMap::new();
    for (path, text) in files {
        let Some(rest) = path.strip_prefix(LOCALES) else {
            for k in ftl(text).keys() {
                if declared.contains(k.as_str()) {
                    out.push(violation(
                        path,
                        format!("`{k}` is protected; a realm cannot override it (X35, XI-25)"),
                    ));
                }
            }
            continue;
        };
        let Some((lang, file)) = rest.split_once('/') else {
            continue;
        };
        locales
            .entry(lang.to_owned())
            .or_default()
            .insert(file.to_owned(), ftl(text));
    }
    let Some(base) = locales.get(BASE) else {
        out.push(violation(LOCALES, String::from("no `en` catalog")));
        return out;
    };
    let mut in_base = BTreeSet::new();
    for (file, messages) in base {
        let surface = file.trim_end_matches(".ftl");
        for k in messages.keys() {
            in_base.insert(k.as_str());
            match by_key.get(k.as_str()) {
                None => out.push(violation(
                    &format!("{LOCALES}{BASE}/{file}"),
                    format!("`{k}` is not in {CATALOG}"),
                )),
                Some(m) if m.surface != surface => out.push(violation(
                    &format!("{LOCALES}{BASE}/{file}"),
                    format!("`{k}` belongs to the {} surface", m.surface),
                )),
                Some(_) => {}
            }
        }
    }
    for m in catalog {
        if !in_base.contains(m.key.as_str()) {
            out.push(violation(CATALOG, format!("`{}` has no `en` text", m.key)));
        }
    }
    for (lang, files) in &locales {
        for (file, base_messages) in base {
            let path = format!("{LOCALES}{lang}/{file}");
            let Some(messages) = files.get(file) else {
                out.push(violation(&path, String::from("missing")));
                continue;
            };
            let a: BTreeSet<_> = base_messages.keys().collect();
            let b: BTreeSet<_> = messages.keys().collect();
            if a != b {
                out.push(violation(
                    &path,
                    format!(
                        "keys differ from en: {:?}",
                        a.symmetric_difference(&b).collect::<Vec<_>>()
                    ),
                ));
            }
        }
        for (file, messages) in files {
            let path = format!("{LOCALES}{lang}/{file}");
            for (k, text) in messages {
                let Some(m) = by_key.get(k.as_str()) else {
                    continue;
                };
                if !END_USER.contains(&m.surface.as_str()) {
                    continue;
                }
                if let Some(term) = crate::rules::ui_terms::forbidden(text, &[]) {
                    out.push(violation(
                        &path,
                        format!("`{k}`: `{term}` is a forbidden UI term (X24, XI-13)"),
                    ));
                }
                for b in banned {
                    if !b.classes.is_empty() && !b.classes.contains(&m.class) {
                        continue;
                    }
                    let Some(words) = b
                        .words
                        .get(lang.as_str())
                        .or_else(|| lang.split('-').next().and_then(|l| b.words.get(l)))
                    else {
                        continue;
                    };
                    if let Some(w) = says(text, words) {
                        out.push(violation(&path, format!("`{k}` says `{w}`: {}", b.reason)));
                    }
                }
            }
        }
    }
    out
}

/// `fluent-catalog`.
pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let catalog: Catalog =
        toml::from_str(&read(&root.join(CATALOG))?).map_err(|e| format!("{CATALOG}: {e}"))?;
    let protected: Protected =
        toml::from_str(&read(&root.join(PROTECTED))?).map_err(|e| format!("{PROTECTED}: {e}"))?;
    let glossary: Glossary =
        toml::from_str(&read(&root.join(GLOSSARY))?).map_err(|e| format!("{GLOSSARY}: {e}"))?;
    let terms: Vec<(String, BTreeMap<String, String>)> = glossary
        .term
        .into_iter()
        .map(|t| (t.canonical, t.columns))
        .collect();
    let mut files = Vec::new();
    for path in walk(root)? {
        let rel_path = rel(root, &path);
        let skip = rel_path.contains("/node_modules/")
            || rel_path.starts_with("target/")
            || rel_path.starts_with("docs/");
        let ftl = Path::new(&rel_path)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("ftl"));
        if !skip && ftl {
            files.push((rel_path, read(&path)?));
        }
    }
    Ok(check_texts(
        &catalog.message,
        &protected.keys,
        &terms,
        &glossary.banned,
        &files,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(key: &str, surface: &str, class: &str, protected: bool) -> Message {
        Message {
            key: key.to_owned(),
            text_id: None,
            surface: surface.to_owned(),
            class: class.to_owned(),
            owner: String::from("identity_plane"),
            protected,
            guarantee: None,
        }
    }

    fn banned() -> Vec<Banned> {
        vec![
            Banned {
                words: BTreeMap::from([
                    (String::from("en"), vec![String::from("realm")]),
                    (String::from("tr"), vec![String::from("oturum")]),
                ]),
                classes: Vec::new(),
                reason: String::from("§8.9"),
            },
            Banned {
                words: BTreeMap::from([(String::from("en"), vec![String::from("allow")])]),
                classes: vec![String::from("consent")],
                reason: String::from("§8.8"),
            },
        ]
    }

    fn catalog() -> Vec<Message> {
        vec![
            message("login-failed", "login", "auth_failed", true),
            message("action-share", "login", "consent", false),
            message("blocker-ended", "hub", "remediation", false),
        ]
    }

    fn files(tr_login: &str) -> Vec<(String, String)> {
        vec![
            (
                String::from("locales/en/login.ftl"),
                String::from("login-failed = We couldn't sign you in.\naction-share = Share\n"),
            ),
            (
                String::from("locales/en/hub.ftl"),
                String::from("blocker-ended = Not allowed: the authority has ended.\n"),
            ),
            (String::from("locales/tr/login.ftl"), tr_login.to_owned()),
            (
                String::from("locales/tr/hub.ftl"),
                String::from("blocker-ended = İzin verilmedi.\n"),
            ),
        ]
    }

    fn run(files: &[(String, String)], catalog: &[Message]) -> Vec<String> {
        check_texts(
            catalog,
            &[String::from("login-failed")],
            &[],
            &banned(),
            files,
        )
        .into_iter()
        .map(|v| format!("{}: {}", v.path.display(), v.message))
        .collect()
    }

    const TR: &str = "login-failed = Giriş yapamadık.\naction-share = Paylaş\n";

    // OP-153 m.3 (s), TN-108
    #[test]
    fn a_consistent_catalog_passes() {
        assert_eq!(run(&files(TR), &catalog()), Vec::<String>::new());
    }

    // X35, XI-25
    #[test]
    fn a_protected_key_overridden_in_a_realm_file_fails() {
        let mut f = files(TR);
        f.push((
            String::from("deploy/realm-templates/acme/en.ftl"),
            String::from("login-failed = Wrong password.\n"),
        ));
        let v = run(&f, &catalog());
        assert!(v.iter().any(|m| m.contains("is protected")), "{v:?}");
    }

    // OP-153 m.3 (s), §8.10, §8.11
    #[test]
    fn a_forbidden_claim_in_the_turkish_catalog_fails() {
        let v = run(
            &files("login-failed = Oturum açılamadı.\naction-share = Paylaş\n"),
            &catalog(),
        );
        assert!(v.iter().any(|m| m.contains("says `oturum`")), "{v:?}");
        let v = run(
            &files("login-failed = Giriş yapamadık, undo.\naction-share = Paylaş\n"),
            &catalog(),
        );
        assert!(v.iter().any(|m| m.contains("forbidden UI term")), "{v:?}");
    }

    // TN-108
    #[test]
    fn a_locale_missing_a_key_fails() {
        let v = run(&files("login-failed = Giriş yapamadık.\n"), &catalog());
        assert!(v.iter().any(|m| m.contains("keys differ from en")), "{v:?}");
    }

    // §8.8, §8.11
    #[test]
    fn allow_is_banned_on_consent_only() {
        let mut f = files(TR);
        f[0].1 = String::from("login-failed = We couldn't sign you in.\naction-share = Allow\n");
        let v = run(&f, &catalog());
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("action-share"));
    }

    // SEC2, X35
    #[test]
    fn a_guarantee_names_exactly_one_class_and_is_protected() {
        let mut c = catalog();
        c[0].guarantee = Some(String::from("BS/UDC"));
        c[1].guarantee = Some(String::from("BS"));
        let v = run(&files(TR), &c);
        assert!(v.iter().any(|m| m.contains("not exactly one")), "{v:?}");
        assert!(v.iter().any(|m| m.contains("is protected (X35)")), "{v:?}");
    }
}
