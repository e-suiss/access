//! An organization invitation's secrets (TN-89, OP-153 m.3 (o)): the link token and the magic
//! code exist only in the mail; the identity plane keeps and finds them by SHA-256.

/// The digest a link token is kept and found by: SHA-256 of its text.
#[must_use]
pub fn token_hash(token: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(token.trim().as_bytes())
}

/// The digest a magic code is kept and found by: SHA-256 of its text, trimmed and in upper
/// case, so a typed code matches however it was written.
#[must_use]
pub fn code_hash(code: &str) -> [u8; 32] {
    suiss_crypto::digest::sha256(code.trim().to_ascii_uppercase().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    // TN-89, OP-153 m.3 (o)
    #[test]
    fn a_typed_code_matches_however_it_was_written() {
        assert_eq!(code_hash(" abcd2345 "), code_hash("ABCD2345"));
        assert_ne!(token_hash("aBc"), token_hash("ABC"));
    }
}
