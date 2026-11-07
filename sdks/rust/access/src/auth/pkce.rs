//! PKCE with `S256` only (RFC 7636, RFC 9700 §2.1.1): `plain` is never offered.

use alloc::string::String;

use access_kernel::json::b64url_encode;
use suiss_crypto::digest::sha256;

use super::{Random, RandomUnavailable, random_text};

/// The only challenge method.
pub const METHOD: &str = "S256";

/// A code verifier: 32 random bytes, 43 base64url characters. Its `Debug` hides the value.
#[derive(Clone, PartialEq, Eq)]
pub struct Verifier(String);

impl core::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Verifier(..)")
    }
}

impl Verifier {
    /// A fresh verifier.
    ///
    /// # Errors
    /// [`RandomUnavailable`].
    pub fn generate(rng: &impl Random) -> Result<Self, RandomUnavailable> {
        random_text::<32>(rng).map(Self)
    }

    /// A verifier from its text, when it has the RFC 7636 §4.1 form (43 to 128 unreserved
    /// characters).
    #[must_use]
    pub fn from_text(text: &str) -> Option<Self> {
        let ok = (43..=128).contains(&text.len())
            && text
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
        ok.then(|| Self(String::from(text)))
    }

    /// The verifier, for the token request.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// `BASE64URL(SHA256(ASCII(verifier)))`.
    #[must_use]
    pub fn challenge(&self) -> String {
        b64url_encode(&sha256(self.0.as_bytes()))
    }
}
