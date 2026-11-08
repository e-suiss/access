//! Authorization server primitives (OP-146 I7): digests of opaque values and client secrets
//! (CR-38), the PKCE S256 check (RFC 7636, CR-39) and client assertion signatures
//! (RFC 7523) under the CR-9 profile for external signatures.

use subtle::ConstantTimeEq as _;
use suiss_crypto::sig;

use crate::AwsLcBackend;
use crate::webauthn::{VerifyError, sha256, verify_rs256};

/// Context of a client secret's stored digest.
const SECRET_CONTEXT: &[u8] = b"access/client-secret/v1\0";

/// SHA-256 of `context ‖ 0x00 ‖ value`: the stored form of an opaque value (CR-38). Each kind
/// of value has its own context, so one kind never matches another.
#[must_use]
pub fn opaque_digest(context: &str, value: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(context.len().saturating_add(value.len()).saturating_add(1));
    m.extend_from_slice(context.as_bytes());
    m.push(0);
    m.extend_from_slice(value);
    sha256(&m)
}

/// The stored digest of a client secret: plain SHA-256, never Argon2; secrets are 256-bit
/// server-generated values (CR-38).
#[must_use]
pub fn secret_digest(secret: &[u8]) -> [u8; 32] {
    let mut m = SECRET_CONTEXT.to_vec();
    m.extend_from_slice(secret);
    sha256(&m)
}

/// Whether `presented` is the secret whose digest is `stored`, compared in constant time
/// (CR-38, CR-39).
#[must_use]
pub fn secret_matches(stored: &[u8; 32], presented: &[u8]) -> bool {
    bool::from(secret_digest(presented).ct_eq(stored))
}

/// Whether `verifier` is the PKCE verifier of the S256 `challenge` (RFC 7636 §4.6),
/// compared in constant time (CR-39).
#[must_use]
pub fn pkce_matches(challenge: &[u8; 32], verifier: &str) -> bool {
    bool::from(sha256(verifier.as_bytes()).ct_eq(challenge))
}

/// A client's public key, from its JWKS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientKey {
    /// P-256, SEC1 uncompressed.
    P256(Vec<u8>),
    /// Ed25519.
    Ed25519([u8; 32]),
    /// RSA modulus and exponent, big-endian.
    Rsa {
        /// Modulus.
        n: Vec<u8>,
        /// Exponent.
        e: Vec<u8>,
    },
}

/// A client assertion algorithm (§10.4.5, MD-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClientAlg {
    /// ECDSA P-256 SHA-256, `r ‖ s`.
    Es256,
    /// Ed25519.
    Ed25519,
    /// RSASSA-PKCS1-v1_5 SHA-256, 2048–8192 bits; identity plane only (CR-2).
    Rs256,
}

impl ClientAlg {
    /// From the JOSE name; `EdDSA` is never accepted (MD-3).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ES256" => Some(Self::Es256),
            "Ed25519" => Some(Self::Ed25519),
            "RS256" => Some(Self::Rs256),
            _ => None,
        }
    }

    /// The JOSE name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Ed25519 => "Ed25519",
            Self::Rs256 => "RS256",
        }
    }
}

/// Verifies a client's JWS signature over `input`. The key type must match the algorithm;
/// external ECDSA signatures may carry high S (CR-9 m.4).
///
/// # Errors
/// [`VerifyError`].
pub fn verify_client_signature(
    alg: ClientAlg,
    key: &ClientKey,
    input: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match (alg, key) {
        (ClientAlg::Es256, ClientKey::P256(sec1)) => {
            sig::p256(&AwsLcBackend, sec1, input, signature, false)?;
            Ok(())
        }
        (ClientAlg::Ed25519, ClientKey::Ed25519(pk)) => {
            sig::ed25519(&AwsLcBackend, pk, input, signature)?;
            Ok(())
        }
        (ClientAlg::Rs256, ClientKey::Rsa { n, e }) => verify_rs256(n, e, input, signature),
        _ => Err(VerifyError::Signature(sig::SignatureError::Invalid)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CR-38, U69
    #[test]
    fn secrets_match_their_digest_only() {
        let d = secret_digest(b"s3cret");
        assert!(secret_matches(&d, b"s3cret"));
        assert!(!secret_matches(&d, b"s3cres"));
        assert_ne!(opaque_digest("a", b"x"), opaque_digest("b", b"x"));
        assert_ne!(opaque_digest("ab", b""), opaque_digest("a", b"b"));
    }

    // CR-39
    #[test]
    fn pkce_s256_vector() {
        let challenge =
            access_kernel::json::b64url_decode("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .unwrap_or_default();
        let challenge: [u8; 32] = challenge.try_into().unwrap_or([0; 32]);
        assert!(pkce_matches(
            &challenge,
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        ));
        assert!(!pkce_matches(
            &challenge,
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXj"
        ));
    }

    // MD-3
    #[test]
    fn mismatched_key_type_is_rejected() {
        let key = ClientKey::Ed25519([0; 32]);
        assert!(verify_client_signature(ClientAlg::Es256, &key, b"x", &[0; 64]).is_err());
        assert_eq!(ClientAlg::from_name("EdDSA"), None);
        assert_eq!(ClientAlg::from_name("HS256"), None);
    }
}
