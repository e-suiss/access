//! The single-use secrets of account recovery (TN-59, TN-61, TN-62): an attempt's handle, the
//! rebind token, a reset intent, a temporary access pass and a cross-device link code. Only
//! their digests are stored; the identity plane's issuers (the hosted pages and the management
//! API's Exercises) and the redeeming side compute the same digest here.

use suiss_crypto::digest::context_digest;

/// The digest context.
const CONTEXT: &str = "access/recovery-token/v1";

/// The kind of a reset intent.
pub const RESET_INTENT: &str = "reset_intent";

/// The kind of a temporary access pass.
pub const TEMPORARY_ACCESS_PASS: &str = "temporary_access_pass";

/// The kind of an attempt's rebind token.
pub const REBIND: &str = "rebind";

/// The kind of a cross-device link code.
pub const LINK_CODE: &str = "link_code";

/// The stored digest of `token`, exactly as presented.
#[must_use]
pub fn digest(token: &str) -> [u8; 32] {
    context_digest(CONTEXT, token.as_bytes()).0
}

/// The stored digest of a code a person types: separators and spaces dropped, upper case.
#[must_use]
pub fn typed_digest(code: &str) -> [u8; 32] {
    let canonical: String = code
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    digest(&canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-59, TN-61
    #[test]
    fn tokens_are_stored_by_digest_and_typed_codes_canonically() {
        assert_ne!(digest("a"), digest("A"));
        assert_eq!(typed_digest("abcd-efgh"), typed_digest("ABCD EFGH"));
        assert_eq!(typed_digest("ABCDEFGH"), digest("ABCDEFGH"));
    }
}
