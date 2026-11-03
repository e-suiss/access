//! Login identifiers (§17.2.2, MD-5, TN-2): realm-scoped and compared without letter case. An
//! e-mail address is one kind of identifier, never a key: nothing is authorized, linked or
//! merged by it (§12.3.3 m.6, E27).

use unicode_normalization::UnicodeNormalization;

/// Longest identifier, in characters (an e-mail address's limit).
pub const MAX_CHARS: usize = 320;

/// The identifier's kind; the kind never changes how it is matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentifierKind {
    /// A chosen user name.
    Username,
    /// An e-mail address.
    Email,
    /// A phone number.
    Phone,
}

impl IdentifierKind {
    /// The stored name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }
}

/// Why an identifier was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IdentifierError {
    /// Empty after normalization.
    #[error("empty identifier")]
    Empty,
    /// Longer than [`MAX_CHARS`].
    #[error("identifier too long")]
    TooLong,
    /// Contains a control character.
    #[error("control character in identifier")]
    Control,
}

/// A normalized login identifier: NFKC, without surrounding white space (OP-146 m.5 (j)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier {
    kind: IdentifierKind,
    value: String,
}

/// NFKC and trim.
#[must_use]
pub fn normalize(raw: &str) -> String {
    raw.nfkc().collect::<String>().trim().to_owned()
}

impl Identifier {
    /// Normalizes and checks `raw`.
    ///
    /// # Errors
    /// [`IdentifierError`].
    pub fn new(kind: IdentifierKind, raw: &str) -> Result<Self, IdentifierError> {
        let value = normalize(raw);
        if value.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if value.chars().count() > MAX_CHARS {
            return Err(IdentifierError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(IdentifierError::Control);
        }
        Ok(Self { kind, value })
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> IdentifierKind {
        self.kind
    }

    /// The normalized value, as stored.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// The case-folded form the realm's uniqueness and the login counters use.
    #[must_use]
    pub fn folded(&self) -> String {
        self.value.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-146, MD-5
    #[test]
    fn nfkc_trim_and_fold() {
        let a = Identifier::new(IdentifierKind::Email, "  Ａlice@Example.com ").unwrap();
        assert_eq!(a.value(), "Alice@Example.com");
        assert_eq!(a.folded(), "alice@example.com");
        assert_eq!(
            Identifier::new(IdentifierKind::Username, " \u{3000} "),
            Err(IdentifierError::Empty)
        );
        assert_eq!(
            Identifier::new(IdentifierKind::Username, "a\u{0}b"),
            Err(IdentifierError::Control)
        );
        assert_eq!(
            Identifier::new(IdentifierKind::Username, &"x".repeat(MAX_CHARS + 1)),
            Err(IdentifierError::TooLong)
        );
    }
}
