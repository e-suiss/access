//! The key of an external identity (P-ID-9, TN-66): `(provider, provider_subject_id)`. The
//! provider is the preset's issuer as written (Entra's carries `{tid}`, and its subject is
//! `tid:oid`) or the upstream's registered issuer. The table keeps only its digest; an e-mail
//! address is never part of it (MD-5, TN-3).

use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::digest::context_digest;

/// Context of [`identity_key`].
pub const KEY_CONTEXT: &str = "access/federated-identity/v1";

/// `SHA-256(KEY_CONTEXT ‖ 0x00 ‖ dCBOR([provider, subject]))`.
#[must_use]
pub fn identity_key(provider: &str, subject: &str) -> [u8; 32] {
    let pair = Value::Array(vec![Value::text(provider), Value::text(subject)]);
    let bytes = dcbor::encode(&pair, Limits::CEILING).unwrap_or_default();
    context_digest(KEY_CONTEXT, &bytes).0
}

#[cfg(test)]
mod tests {
    use super::*;

    // P-ID-9, TN-66
    #[test]
    fn the_key_is_the_provider_and_subject_pair_only() {
        let a = identity_key("https://accounts.google.com", "1");
        assert_eq!(a, identity_key("https://accounts.google.com", "1"));
        assert_ne!(a, identity_key("https://accounts.google.com", "2"));
        assert_ne!(a, identity_key("https://appleid.apple.com", "1"));
        assert_ne!(
            identity_key("a", "b:c"),
            identity_key("a:b", "c"),
            "the pair is encoded, not concatenated"
        );
    }
}
