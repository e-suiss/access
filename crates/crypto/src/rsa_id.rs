//! RS256 in the identity plane only (CR-2, MD-3, MD-6, OP-155 m.3 (k)): the realm's RSA-3072
//! `rsa-id` key that signs identity assertions for clients that opted in, made on the first
//! opt-in, and the strict RS256 check of a client's signature. Authority artefacts are never
//! RSA (G46).

use access_kernel::json::b64url_encode;
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::{
    KeyPair as _, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaPublicKeyComponents,
};
use zeroize::Zeroizing;

use crate::webauthn::{VerifyError, rsa_key_valid, sha256};

/// The only size of a realm's `rsa-id` key (MD-6).
pub const BITS: usize = 3072;

/// The JOSE `alg` of the key.
pub const ALG: &str = "RS256";

/// Why an `rsa-id` key could not be made, loaded or used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RsaIdError {
    /// Not an RSA-3072 PKCS#8 key.
    #[error("key")]
    Key,
    /// `typ` or the payload is outside the JOSE profile.
    #[error("input")]
    Input,
    /// The primitive failed.
    #[error("sign")]
    Sign,
}

impl RsaIdError {
    /// Stable reason code for problem details (RFC 9457).
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Key => "rsa-id-key",
            Self::Input => "rsa-id-input",
            Self::Sign => "rsa-id-sign",
        }
    }
}

/// A realm's RSA-3072 identity assertion key.
pub struct RsaIdKey {
    pair: KeyPair,
    n: Vec<u8>,
    e: Vec<u8>,
    kid: [u8; 32],
}

impl core::fmt::Debug for RsaIdKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RsaIdKey")
            .field("kid", &b64url_encode(&self.kid))
            .finish_non_exhaustive()
    }
}

/// The RFC 7638 thumbprint of an RSA public key.
#[must_use]
pub fn thumbprint(n: &[u8], e: &[u8]) -> [u8; 32] {
    let members = format!(
        r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
        b64url_encode(e),
        b64url_encode(n)
    );
    sha256(members.as_bytes())
}

impl RsaIdKey {
    fn of(pair: KeyPair) -> Result<Self, RsaIdError> {
        if pair.public_modulus_len().saturating_mul(8) != BITS {
            return Err(RsaIdError::Key);
        }
        let (n, e) = pkcs1_parts(pair.public_key().as_ref()).ok_or(RsaIdError::Key)?;
        let kid = thumbprint(&n, &e);
        Ok(Self { pair, n, e, kid })
    }

    /// A new key and its PKCS#8 form, which the caller seals before it is stored (CR-21 m.3).
    ///
    /// # Errors
    /// [`RsaIdError`].
    pub fn generate() -> Result<(Self, Zeroizing<Vec<u8>>), RsaIdError> {
        let pair = KeyPair::generate(KeySize::Rsa3072).map_err(|_| RsaIdError::Sign)?;
        let der = Zeroizing::new(
            pair.as_der()
                .map_err(|_| RsaIdError::Key)?
                .as_ref()
                .to_vec(),
        );
        Ok((Self::of(pair)?, der))
    }

    /// The key a PKCS#8 form holds; anything but RSA-3072 is refused.
    ///
    /// # Errors
    /// [`RsaIdError::Key`].
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, RsaIdError> {
        Self::of(KeyPair::from_pkcs8(der).map_err(|_| RsaIdError::Key)?)
    }

    /// Its `kid`, the RFC 7638 thumbprint.
    #[must_use]
    pub const fn kid(&self) -> &[u8; 32] {
        &self.kid
    }

    /// The modulus and exponent, big-endian.
    #[must_use]
    pub fn public(&self) -> (&[u8], &[u8]) {
        (&self.n, &self.e)
    }

    /// The public JWK with `kid`, `alg: RS256` and `use: sig`.
    #[must_use]
    pub fn public_jwk(&self) -> String {
        format!(
            r#"{{"kty":"RSA","n":"{}","e":"{}","kid":"{}","alg":"{ALG}","use":"sig"}}"#,
            b64url_encode(&self.n),
            b64url_encode(&self.e),
            b64url_encode(&self.kid)
        )
    }

    /// A compact JWS with the protected header `{"alg":"RS256","kid","typ"}` over a JSON
    /// object `payload`.
    ///
    /// # Errors
    /// [`RsaIdError`].
    pub fn sign_compact(&self, typ: &str, payload: &[u8]) -> Result<String, RsaIdError> {
        let typ_ok = !typ.is_empty()
            && typ.len() <= 64
            && typ
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+/".contains(&b));
        if !typ_ok || payload.first() != Some(&b'{') {
            return Err(RsaIdError::Input);
        }
        let header = format!(
            r#"{{"alg":"{ALG}","kid":"{}","typ":"{typ}"}}"#,
            b64url_encode(&self.kid)
        );
        let mut out = b64url_encode(header.as_bytes());
        out.push('.');
        out.push_str(&b64url_encode(payload));
        let mut signature = vec![0; self.pair.public_modulus_len()];
        self.pair
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                out.as_bytes(),
                &mut signature,
            )
            .map_err(|_| RsaIdError::Sign)?;
        out.push('.');
        out.push_str(&b64url_encode(&signature));
        Ok(out)
    }
}

fn der_take(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let k = usize::from(first & 0x7f);
        if !(1..=2).contains(&k) {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(k)?;
        (
            bytes
                .iter()
                .fold(0_usize, |n, b| n.wrapping_shl(8) | usize::from(*b)),
            rest,
        )
    };
    let (body, rest) = rest.split_at_checked(len)?;
    Some((tag, body, rest))
}

/// The modulus and exponent of a PKCS#1 `RSAPublicKey` (RFC 8017 A.1.1), without leading
/// zeros.
#[must_use]
pub fn pkcs1_parts(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (0x30, seq, []) = der_take(der)? else {
        return None;
    };
    let (0x02, n, rest) = der_take(seq)? else {
        return None;
    };
    let (0x02, e, []) = der_take(rest)? else {
        return None;
    };
    Some((significant(n).to_vec(), significant(e).to_vec()))
}

fn significant(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes.get(start..).unwrap_or_default()
}

/// OP-125, OP-144: RS256 under the strict profile. The key is 2048–8192 bits with an odd
/// exponent ≥ 3; the signature is exactly the modulus length, never shorter or zero-padded
/// longer; the PKCS#1 v1.5 encoding is rebuilt and compared byte for byte, `DigestInfo`
/// included, by aws-lc-rs.
///
/// # Errors
/// [`VerifyError`].
pub fn verify_strict(
    n: &[u8],
    e: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    if !rsa_key_valid(n, e) {
        return Err(VerifyError::RsaKey);
    }
    let n = significant(n);
    if signature.len() != n.len() {
        return Err(VerifyError::Signature(
            suiss_crypto::sig::SignatureError::Invalid,
        ));
    }
    RsaPublicKeyComponents {
        n,
        e: significant(e),
    }
    .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
    .map_err(|_| VerifyError::Signature(suiss_crypto::sig::SignatureError::Invalid))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use access_kernel::json::b64url_decode;

    use super::*;

    fn parts(token: &str) -> (String, Vec<u8>) {
        let (input, sig) = token.rsplit_once('.').unwrap();
        (input.to_owned(), b64url_decode(sig).unwrap())
    }

    // MD-6, CR-2
    #[test]
    fn rsa_3072_signs_and_round_trips() {
        let (key, der) = RsaIdKey::generate().unwrap();
        let again = RsaIdKey::from_pkcs8(&der).unwrap();
        assert_eq!(key.kid(), again.kid());
        let token = key.sign_compact("JWT", br#"{"sub":"a"}"#).unwrap();
        let (input, sig) = parts(&token);
        assert_eq!(sig.len(), 384);
        let (n, e) = key.public();
        verify_strict(n, e, input.as_bytes(), &sig).unwrap();
        assert!(key.public_jwk().contains(r#""alg":"RS256""#));
        let header = b64url_decode(token.split('.').next().unwrap()).unwrap();
        assert!(
            String::from_utf8(header)
                .unwrap()
                .starts_with(r#"{"alg":"RS256","kid":""#)
        );
    }

    #[test]
    fn other_sizes_are_not_an_rsa_id_key() {
        let small = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = small.as_der().unwrap();
        assert_eq!(
            RsaIdKey::from_pkcs8(der.as_ref()).err(),
            Some(RsaIdError::Key)
        );
    }

    // OP-125, OP-144: exact length; no leading-zero padding, no truncation
    #[test]
    fn signature_length_is_exact() {
        let (key, _) = RsaIdKey::generate().unwrap();
        let token = key.sign_compact("JWT", b"{}").unwrap();
        let (input, sig) = parts(&token);
        let (n, e) = key.public();
        let mut padded = vec![0];
        padded.extend_from_slice(&sig);
        assert!(verify_strict(n, e, input.as_bytes(), &padded).is_err());
        assert!(verify_strict(n, e, input.as_bytes(), &sig[1..]).is_err());
        let mut flipped = sig.clone();
        flipped[10] ^= 1;
        assert!(verify_strict(n, e, input.as_bytes(), &flipped).is_err());
        assert!(verify_strict(n, e, b"other", &sig).is_err());
        assert_eq!(
            verify_strict(&n[..128], e, input.as_bytes(), &sig),
            Err(VerifyError::RsaKey)
        );
    }
}
