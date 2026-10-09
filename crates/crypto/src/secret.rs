//! `Secret<T>`: a value that must never be printed, logged, serialized or compared
//! in variable time.

use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// A secret value. Read it only through [`Secret::expose`], at the point of use.
pub struct Secret<T: Zeroize> {
    inner: SecretBox<T>,
}

impl<T: Zeroize> Secret<T> {
    /// Wraps a value. The caller's copy should not outlive this call.
    pub fn new(value: T) -> Self {
        Self {
            inner: SecretBox::new(Box::new(value)),
        }
    }

    /// Returns the plain value. Keep the borrow as short as possible.
    #[must_use]
    pub fn expose(&self) -> &T {
        self.inner.expose_secret()
    }
}

impl<T: Zeroize + AsRef<[u8]>> Secret<T> {
    /// Constant-time equality (§14.5: secrets are never compared with `==`).
    ///
    /// Lengths are not hidden: two secrets of different length compare unequal
    /// without inspecting their content.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.expose().as_ref().ct_eq(other.expose().as_ref()).into()
    }

    /// Constant-time comparison against a plain candidate (e.g. a presented token).
    #[must_use]
    pub fn ct_eq_bytes(&self, candidate: &[u8]) -> bool {
        self.expose().as_ref().ct_eq(candidate).into()
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self::new(self.expose().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    // SA-26
    assert_not_impl_any!(Secret<String>: core::fmt::Debug, core::fmt::Display, PartialEq, Eq);
    assert_not_impl_any!(Secret<Vec<u8>>: core::fmt::Debug, core::fmt::Display, PartialEq, Eq);
    assert_not_impl_any!(Secret<String>: serde::Serialize);

    #[test]
    fn ct_eq_is_true_for_equal_secrets() {
        let a = Secret::new(b"correct horse".to_vec());
        let b = Secret::new(b"correct horse".to_vec());
        assert!(a.ct_eq(&b));
    }

    #[test]
    fn ct_eq_is_false_for_different_content_or_length() {
        let a = Secret::new(b"correct horse".to_vec());
        assert!(!a.ct_eq(&Secret::new(b"correct horsf".to_vec())));
        assert!(!a.ct_eq(&Secret::new(b"correct".to_vec())));
        assert!(!a.ct_eq_bytes(b""));
    }

    #[test]
    fn expose_returns_the_wrapped_value() {
        let s = Secret::new(String::from("value"));
        assert_eq!(s.expose(), "value");
    }
}
