//! Privacy Pass redemption (RFC 9577, RFC 9578 §6, OP-153 m.1 (b)): a publicly verifiable token
//! (type `0x0002`, blind RSA, RSASSA-PSS-SHA384 with a 48-byte salt) proves only that some issuer
//! attested the client; its absence or failure is never held against the request.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{RSA_PSS_2048_8192_SHA384, UnparsedPublicKey};

/// The token type of publicly verifiable tokens (RFC 9578 §6).
pub const TOKEN_TYPE: u16 = 0x0002;

/// Length of a type `0x0002` token with a 2048-bit issuer key.
pub const TOKEN_LEN: usize = 2 + 32 + 32 + 32 + 256;

/// One issuer this deployment accepts tokens from.
#[derive(Clone, Debug)]
pub struct Issuer {
    /// The issuer's RSA public key, DER `RSAPublicKey` (PKCS#1) or `SubjectPublicKeyInfo`.
    pub key: Vec<u8>,
    /// `token_key_id`: SHA-256 of the issuer's published token key encoding.
    pub key_id: [u8; 32],
}

/// The `challenge_digest` of a `TokenChallenge` (RFC 9577 §2.1): SHA-256 of its encoding.
#[must_use]
pub fn challenge_digest(
    issuer_name: &str,
    redemption_context: &[u8],
    origin_info: &str,
) -> [u8; 32] {
    let mut c = TOKEN_TYPE.to_be_bytes().to_vec();
    let push16 = |c: &mut Vec<u8>, b: &[u8]| {
        c.extend_from_slice(&u16::try_from(b.len()).unwrap_or(u16::MAX).to_be_bytes());
        c.extend_from_slice(b);
    };
    push16(&mut c, issuer_name.as_bytes());
    c.push(u8::try_from(redemption_context.len()).unwrap_or(u8::MAX));
    c.extend_from_slice(redemption_context);
    push16(&mut c, origin_info.as_bytes());
    let mut out = [0; 32];
    out.copy_from_slice(digest(&SHA256, &c).as_ref());
    out
}

/// Whether `token` is a valid type `0x0002` token for `challenge` from one of `issuers`.
#[must_use]
pub fn verify(token: &[u8], challenge: &[u8; 32], issuers: &[Issuer]) -> bool {
    if token.len() != TOKEN_LEN {
        return false;
    }
    let (input, authenticator) = token.split_at(2 + 32 + 32 + 32);
    let Some(kind) = input.get(..2) else {
        return false;
    };
    if kind != TOKEN_TYPE.to_be_bytes() || input.get(34..66) != Some(challenge.as_slice()) {
        return false;
    }
    let Some(key_id) = input.get(66..98) else {
        return false;
    };
    issuers.iter().any(|i| {
        i.key_id.as_slice() == key_id
            && UnparsedPublicKey::new(&RSA_PSS_2048_8192_SHA384, &i.key)
                .verify(input, authenticator)
                .is_ok()
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, reason = "test code")]

    use super::*;

    // OP-153 m.1 (b)
    #[test]
    fn a_malformed_or_foreign_token_is_not_positive() {
        let challenge = challenge_digest("issuer.example", &[], "acme.example");
        assert!(!verify(&[], &challenge, &[]));
        let mut token = vec![0_u8; TOKEN_LEN];
        token[1] = 2;
        token[2 + 32..2 + 64].copy_from_slice(&challenge);
        let issuer = Issuer {
            key: vec![0x30, 0x00],
            key_id: [0; 32],
        };
        assert!(!verify(&token, &challenge, &[issuer]));
        token[1] = 1;
        assert!(!verify(&token, &challenge, &[]));
    }
}
