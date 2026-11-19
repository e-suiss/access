//! An environment's documents (TN-158 (5), (12)): the terms a person accepts, named by type,
//! version, title, address and the SHA-256 of the text. A required document is accepted at
//! sign-up; a new version of it is accepted again at the next sign-in.

use suiss_crypto::dcbor::Value;

/// The most documents an environment names.
pub const MAX_DOCUMENTS: usize = 8;
/// The most of them that are required.
pub const MAX_REQUIRED: usize = 4;
/// The longest title.
pub const TITLE_MAX_CHARS: usize = 120;
/// The longest address.
pub const URL_MAX_CHARS: usize = 2048;

/// One document of an environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    /// Its type, such as `terms` or `privacy`.
    pub kind: String,
    /// Its version label.
    pub version: String,
    /// Its title as shown.
    pub title: String,
    /// Where it is read: `https://`.
    pub url: String,
    /// SHA-256 of its text.
    pub digest: [u8; 32],
    /// Whether an account must accept it.
    pub required: bool,
}

fn word(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '+'))
}

impl Document {
    /// Whether every field is well formed.
    #[must_use]
    pub fn valid(&self) -> bool {
        let title = self.title.trim();
        word(&self.kind)
            && self.kind.starts_with(|c: char| c.is_ascii_lowercase())
            && word(&self.version)
            && !title.is_empty()
            && title.chars().count() <= TITLE_MAX_CHARS
            && !title.chars().any(char::is_control)
            && self.url.starts_with("https://")
            && self.url.len() <= URL_MAX_CHARS
            && !self
                .url
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
    }

    /// The written form.
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Map(vec![
            (Value::text("type"), Value::text(&self.kind)),
            (Value::text("version"), Value::text(&self.version)),
            (Value::text("title"), Value::text(&self.title)),
            (Value::text("url"), Value::text(&self.url)),
            (Value::text("sha256"), Value::Bytes(self.digest.to_vec())),
            (Value::text("required"), Value::Bool(self.required)),
        ])
    }

    /// From the written form; `None` when it is not one or not well formed.
    #[must_use]
    pub fn from_value(v: &Value) -> Option<Self> {
        let Value::Map(m) = v else {
            return None;
        };
        let get = |k: &str| {
            m.iter()
                .find(|(key, _)| matches!(key, Value::Text(t) if t == k))
                .map(|(_, v)| v)
        };
        let text = |k: &str| match get(k) {
            Some(Value::Text(t)) => Some(t.clone()),
            _ => None,
        };
        let digest = match get("sha256") {
            Some(Value::Bytes(b)) => <[u8; 32]>::try_from(b.as_slice()).ok()?,
            _ => return None,
        };
        let required = match get("required") {
            Some(Value::Bool(b)) => *b,
            _ => return None,
        };
        let d = Self {
            kind: text("type")?,
            version: text("version")?,
            title: text("title")?,
            url: text("url")?,
            digest,
            required,
        };
        d.valid().then_some(d)
    }
}

/// Whether a list of documents is well formed: at most [`MAX_DOCUMENTS`], of which at most
/// [`MAX_REQUIRED`] are required, each valid, one per type.
#[must_use]
pub fn valid_list(docs: &[Document]) -> bool {
    docs.len() <= MAX_DOCUMENTS
        && docs.iter().filter(|d| d.required).count() <= MAX_REQUIRED
        && docs.iter().all(Document::valid)
        && docs.iter().enumerate().all(|(i, d)| {
            docs.iter()
                .skip(i.saturating_add(1))
                .all(|e| e.kind != d.kind)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> Document {
        Document {
            kind: String::from("terms"),
            version: String::from("2026-11"),
            title: String::from("Terms of Service"),
            url: String::from("https://example.com/terms"),
            digest: [7; 32],
            required: true,
        }
    }

    // TN-158 (12)
    #[test]
    fn a_document_is_written_and_read_back_and_a_bad_one_is_refused() {
        let d = terms();
        assert_eq!(Document::from_value(&d.to_value()), Some(d.clone()));
        let mut http = d.clone();
        http.url = String::from("http://example.com/terms");
        assert!(!http.valid());
        let mut kind = d.clone();
        kind.kind = String::from("Terms");
        assert!(!kind.valid());
        let mut empty = d.clone();
        empty.title = String::from("  ");
        assert!(!empty.valid());
        assert!(valid_list(core::slice::from_ref(&d)));
        assert!(!valid_list(&[d.clone(), d]), "one per type");
    }
}
