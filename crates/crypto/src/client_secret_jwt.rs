//! `client_secret_jwt` (RFC 7523 §2.2, OIDC Core §9; CR-3, OP-148 m.16 (l), OP-155 m.3 (k)):
//! the HS256 client assertion of a legacy client registered with that method. It is two-party:
//! the secret is shared between the realm and that one client only, sealed under the realm's
//! KEK, and never verifies any other token.

use aws_lc_rs::hmac;

/// The JOSE `alg` of the assertion.
pub const ALG: &str = "HS256";

/// Shortest secret accepted, bytes: a 256-bit server-generated value (CR-38).
pub const MIN_SECRET: usize = 32;

/// Why an assertion's MAC did not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("client_secret_jwt rejected")]
pub struct Rejected;

/// Whether `signature` is the HS256 MAC of `input` under `secret`, compared in constant time.
///
/// # Errors
/// [`Rejected`], also for a secret shorter than [`MIN_SECRET`].
pub fn verify(secret: &[u8], input: &[u8], signature: &[u8]) -> Result<(), Rejected> {
    if secret.len() < MIN_SECRET {
        return Err(Rejected);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    // CR-39 m.6
    let _dit = crate::dit::DitGuard::new();
    hmac::verify(&key, input, signature).map_err(|_| Rejected)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // CR-3, OP-148 m.16 (l)
    #[test]
    fn verifies_its_own_secret_only() {
        let secret = crate::random::bytes::<32>().unwrap();
        let key = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let tag = hmac::sign(&key, b"h.p");
        verify(&secret, b"h.p", tag.as_ref()).unwrap();
        assert_eq!(verify(&secret, b"h.q", tag.as_ref()), Err(Rejected));
        let other = crate::random::bytes::<32>().unwrap();
        assert_eq!(verify(&other, b"h.p", tag.as_ref()), Err(Rejected));
        assert_eq!(verify(&secret[..16], b"h.p", tag.as_ref()), Err(Rejected));
    }
}
