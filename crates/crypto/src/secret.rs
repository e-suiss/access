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

impl<const N: usize> Secret<[u8; N]> {
    /// Constant-time equality; only fixed-length secrets are compared (CR-39 m.2, m.3).
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.expose().ct_eq(other.expose()).into()
    }

    /// Constant-time comparison against a presented candidate. A candidate of another length
    /// is unequal; the length is public (CR-39 m.3).
    #[must_use]
    pub fn ct_eq_bytes(&self, candidate: &[u8]) -> bool {
        <&[u8; N]>::try_from(candidate).is_ok_and(|c| bool::from(self.expose().ct_eq(c)))
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
    assert_not_impl_any!(Secret<String>: core::fmt::Debug, core::fmt::Display, PartialEq, Eq, core::hash::Hash);
    assert_not_impl_any!(Secret<[u8; 32]>: core::fmt::Debug, core::fmt::Display, PartialEq, Eq, core::hash::Hash, PartialOrd);
    assert_not_impl_any!(Secret<Vec<u8>>: core::fmt::Debug, core::fmt::Display, PartialEq, Eq);
    assert_not_impl_any!(Secret<String>: serde::Serialize);

    // CR-39 m.2
    #[test]
    fn ct_eq_is_true_for_equal_secrets() {
        let a = Secret::new(*b"correct horse");
        let b = Secret::new(*b"correct horse");
        assert!(a.ct_eq(&b));
        assert!(a.ct_eq_bytes(b"correct horse"));
    }

    // CR-39 m.3
    #[test]
    fn ct_eq_is_false_for_different_content_or_length() {
        let a = Secret::new(*b"correct horse");
        assert!(!a.ct_eq(&Secret::new(*b"correct horsf")));
        assert!(!a.ct_eq_bytes(b"correct"));
        assert!(!a.ct_eq_bytes(b"correct horse!"));
        assert!(!a.ct_eq_bytes(b""));
    }

    #[test]
    fn expose_returns_the_wrapped_value() {
        let s = Secret::new(String::from("value"));
        assert_eq!(s.expose(), "value");
    }
}
