//! Message catalogs (OP-153 m.3 (s), TN-108): Access's Fluent files under `locales/`, a realm's
//! overrides, and the five-step fallback chain. The canonical key of a login text is its
//! [`TextId`]; its Fluent key is the wire id with `-` for `.`.
//!
//! The files use the Fluent subset Access writes: comments, `key = text` messages, indented
//! continuation lines and `{ $name }` placeables. Selectors, terms and attributes are refused,
//! so a catalog cannot carry logic (TN-105).

use std::collections::{BTreeMap, BTreeSet};

use super::message::TextId;

/// The language every chain ends in.
pub const DEFAULT_LANGUAGE: &str = "en";

/// Access's own catalogs, by locale and surface.
const ACCESS: &[(&str, &str)] = &[
    ("en", include_str!("../../../../locales/en/login.ftl")),
    ("en", include_str!("../../../../locales/en/account.ftl")),
    ("en", include_str!("../../../../locales/en/hub.ftl")),
    ("en", include_str!("../../../../locales/en/mail.ftl")),
    ("tr", include_str!("../../../../locales/tr/login.ftl")),
    ("tr", include_str!("../../../../locales/tr/account.ftl")),
    ("tr", include_str!("../../../../locales/tr/hub.ftl")),
    ("tr", include_str!("../../../../locales/tr/mail.ftl")),
];

/// The keys no realm override may replace (X35, XI-25).
const PROTECTED: &str = include_str!("../../../../conformance/catalog/protected-messages.toml");

/// Why a catalog or an override is refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LocaleError {
    /// A line outside the Fluent subset.
    #[error("line {0}: outside the supported Fluent subset")]
    Syntax(usize),
    /// A key defined twice.
    #[error("key {0} defined twice")]
    Duplicate(String),
    /// A realm override of a protected key (X35).
    #[error("key {0} is protected")]
    Protected(String),
    /// A realm override of a key Access does not define.
    #[error("key {0} is unknown")]
    Unknown(String),
    /// A locale tag outside BCP 47's simple form.
    #[error("bad locale {0}")]
    Locale(String),
}

/// One parsed Fluent file: key to pattern.
pub type Messages = BTreeMap<String, String>;

fn key_ok(key: &str) -> bool {
    let mut chars = key.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

/// Parses a file of the supported Fluent subset.
///
/// # Errors
/// [`LocaleError::Syntax`] or [`LocaleError::Duplicate`].
pub fn parse(source: &str) -> Result<Messages, LocaleError> {
    let mut out = Messages::new();
    let mut current: Option<String> = None;
    for (n, line) in source.lines().enumerate() {
        let number = n.saturating_add(1);
        if line.trim().is_empty() || line.starts_with('#') {
            current = None;
            continue;
        }
        if line.starts_with(' ') {
            let Some(k) = &current else {
                return Err(LocaleError::Syntax(number));
            };
            let text = line.trim();
            if text.starts_with(['[', '*', '.', '}']) {
                return Err(LocaleError::Syntax(number));
            }
            if let Some(v) = out.get_mut(k) {
                if !v.is_empty() {
                    v.push(' ');
                }
                v.push_str(text);
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(LocaleError::Syntax(number));
        };
        let k = k.trim();
        if !key_ok(k) || v.contains("->") {
            return Err(LocaleError::Syntax(number));
        }
        if out
            .insert(String::from(k), String::from(v.trim()))
            .is_some()
        {
            return Err(LocaleError::Duplicate(String::from(k)));
        }
        current = Some(String::from(k));
    }
    Ok(out)
}

/// The Fluent key of a login text.
#[must_use]
pub fn key_of(id: TextId) -> String {
    id.as_str().replace('.', "-")
}

/// The keys of `protected-messages.toml`.
#[must_use]
pub fn protected() -> BTreeSet<String> {
    PROTECTED
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix('"'))
        .filter_map(|l| l.split_once('"').map(|(k, _)| String::from(k)))
        .collect()
}

/// A BCP 47 tag and its language, lower case: `tr-TR` is `("tr-tr", "tr")`.
///
/// # Errors
/// [`LocaleError::Locale`] for anything but letters, digits and `-`, 2 to 35 long.
pub fn tag(locale: &str) -> Result<(String, String), LocaleError> {
    let ok = (2..=35).contains(&locale.len())
        && locale
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !locale.starts_with('-');
    if !ok {
        return Err(LocaleError::Locale(String::from(locale)));
    }
    let full = locale.to_ascii_lowercase();
    let language = full
        .split('-')
        .next()
        .unwrap_or(DEFAULT_LANGUAGE)
        .to_owned();
    Ok((full, language))
}

/// Access's catalogs, by lower-case locale.
#[derive(Clone, Debug)]
pub struct Catalogs {
    access: BTreeMap<String, Messages>,
    protected: BTreeSet<String>,
}

/// A realm's overrides of unprotected keys, by lower-case locale (`idp.realm.locale_overrides`).
pub type Overrides = BTreeMap<String, Messages>;

impl Catalogs {
    /// Access's embedded catalogs.
    ///
    /// # Errors
    /// [`LocaleError`] when an embedded file is outside the subset.
    pub fn embedded() -> Result<Self, LocaleError> {
        let mut access: BTreeMap<String, Messages> = BTreeMap::new();
        for (locale, source) in ACCESS {
            let into = access.entry(String::from(*locale)).or_default();
            for (k, v) in parse(source)? {
                if into.insert(k.clone(), v).is_some() {
                    return Err(LocaleError::Duplicate(k));
                }
            }
        }
        Ok(Self {
            access,
            protected: protected(),
        })
    }

    /// Access's catalog of `locale`.
    #[must_use]
    pub fn access(&self, locale: &str) -> Option<&Messages> {
        self.access.get(locale)
    }

    /// Whether a realm may not override `key` (X35).
    #[must_use]
    pub fn is_protected(&self, key: &str) -> bool {
        self.protected.contains(key)
    }

    /// Checks a realm's overrides: known keys only, never a protected one; there is no
    /// "override plus validator" escape (X35).
    ///
    /// # Errors
    /// [`LocaleError::Protected`], [`LocaleError::Unknown`] or [`LocaleError::Locale`].
    pub fn check(&self, overrides: &Overrides) -> Result<(), LocaleError> {
        let en = self.access.get(DEFAULT_LANGUAGE);
        for (locale, messages) in overrides {
            tag(locale)?;
            for k in messages.keys() {
                if self.is_protected(k) {
                    return Err(LocaleError::Protected(k.clone()));
                }
                if !en.is_some_and(|m| m.contains_key(k)) {
                    return Err(LocaleError::Unknown(k.clone()));
                }
            }
        }
        Ok(())
    }

    /// The pattern of `key` for `locale`: realm (locale) → realm (language) → Access (locale)
    /// → Access (language) → `en`. A protected key skips the realm's layers.
    #[must_use]
    pub fn pattern<'a>(
        &'a self,
        key: &str,
        locale: &str,
        realm: Option<&'a Overrides>,
    ) -> Option<&'a str> {
        let (full, language) =
            tag(locale).unwrap_or_else(|_| (String::from(DEFAULT_LANGUAGE), String::from("en")));
        let realm = realm.filter(|_| !self.is_protected(key));
        let layers = [
            realm.and_then(|r| r.get(&full)),
            realm.and_then(|r| r.get(&language)),
            self.access.get(&full),
            self.access.get(&language),
            self.access.get(DEFAULT_LANGUAGE),
        ];
        layers
            .into_iter()
            .flatten()
            .find_map(|m| m.get(key))
            .map(String::as_str)
    }

    /// The text of `key` for `locale` with `args` placed as plain text (TN-131).
    #[must_use]
    pub fn format(
        &self,
        key: &str,
        locale: &str,
        realm: Option<&Overrides>,
        args: &[(&str, &str)],
    ) -> Option<String> {
        let mut text = String::from(self.pattern(key, locale, realm)?);
        for (name, value) in args {
            text = text.replace(&format!("{{ ${name} }}"), value);
        }
        Some(text)
    }
}

/// The realm's stored overrides (`idp.realm.locale_overrides`, deterministic CBOR) as the
/// hosted pages read them: `{locale: {key: text}}`, keeping only well-formed locales, known
/// unprotected keys and plain texts (X35, XI-25, OP-153 m.22 (k)); anything else is dropped.
#[must_use]
pub fn stored_overrides(bytes: Option<&[u8]>) -> serde_json::Value {
    use suiss_crypto::dcbor::{self, Limits, Value};
    let mut out = serde_json::Map::new();
    let (Some(Value::Map(locales)), Ok(catalogs)) = (
        bytes.and_then(|b| dcbor::decode(b, Limits::CEILING).ok()),
        Catalogs::embedded(),
    ) else {
        return serde_json::Value::Object(out);
    };
    let en = catalogs.access(DEFAULT_LANGUAGE);
    for (locale, texts) in &locales {
        let (Value::Text(locale), Value::Map(texts)) = (locale, texts) else {
            continue;
        };
        if tag(locale).is_err() {
            continue;
        }
        let mut kept = serde_json::Map::new();
        for (k, v) in texts {
            let (Value::Text(k), Value::Text(v)) = (k, v) else {
                continue;
            };
            let plain = !v
                .chars()
                .any(|c| c.is_control() || matches!(c, '{' | '}' | '<' | '>'));
            if plain && !catalogs.is_protected(k) && en.is_some_and(|m| m.contains_key(k)) {
                kept.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
        }
        if !kept.is_empty() {
            out.insert(locale.to_ascii_lowercase(), serde_json::Value::Object(kept));
        }
    }
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod tests;
