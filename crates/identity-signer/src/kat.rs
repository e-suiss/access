//! CMP-22b, OP-143 m.14 (a): the identity signer's start-up self-tests. It runs the authority
//! signer's known answers for Ed25519 and P-256 (CR-51 m.3), then a pairwise check of the
//! RSA-3072 PKCS#1 v1.5 path its SAML and RS256 keys sign with: a fresh key signs, the
//! signature verifies, and a flipped bit or another message does not.

use access_crypto::xmlsec::{self, Digest, RsaKey, Verify};

pub use access_crypto::kat::KatError;

/// Why a self-test refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SelfTestError {
    /// A known answer was wrong.
    #[error(transparent)]
    Known(#[from] KatError),
    /// The RSA pairwise check failed.
    #[error("rsa pairwise test failed")]
    Rsa,
}

impl SelfTestError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Known(e) => e.code(),
            Self::Rsa => "signer-kat-rsa",
        }
    }
}

const MESSAGE: &[u8] = b"access identity signer self-test";

fn flipped(signature: &[u8]) -> Vec<u8> {
    let mut out = signature.to_vec();
    if let Some(b) = out.last_mut() {
        *b ^= 1;
    }
    out
}

fn rsa_holds(key: &RsaKey, verify: impl Fn(&[u8], &[u8], &[u8]) -> bool) -> bool {
    let (Ok(spki), Ok(signature)) = (key.spki(), key.sign(Digest::Sha256, MESSAGE)) else {
        return false;
    };
    verify(&spki, MESSAGE, &signature)
        && !verify(&spki, MESSAGE, &flipped(&signature))
        && !verify(&spki, b"another message", &signature)
}

/// One DER element at the front of `der`: its tag, contents and what follows.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let (bytes, rest) = rest.split_at(n);
        let len = bytes.iter().try_fold(0_usize, |acc, b| {
            acc.checked_mul(256)?.checked_add(usize::from(*b))
        })?;
        (len, rest)
    };
    if rest.len() < len {
        return None;
    }
    let (contents, after) = rest.split_at(len);
    Some((tag, contents, after))
}

/// The PKCS#1 `RSAPublicKey` inside an RSA `subjectPublicKeyInfo`.
fn pkcs1_of_spki(spki: &[u8]) -> Option<&[u8]> {
    let (0x30, body, []) = element(spki)? else {
        return None;
    };
    let (0x30, _, rest) = element(body)? else {
        return None;
    };
    let (0x03, bits, []) = element(rest)? else {
        return None;
    };
    match bits.split_first()? {
        (0, key) => Some(key),
        _ => None,
    }
}

fn rsa_spki_verifies(spki: &[u8], message: &[u8], signature: &[u8]) -> bool {
    pkcs1_of_spki(spki)
        .is_some_and(|pkcs1| xmlsec::verify(Verify::RsaSha256, pkcs1, message, signature))
}

/// The RSA pairwise check with `verify` as the verifier.
fn rsa(verify: impl Fn(&[u8], &[u8], &[u8]) -> bool) -> Result<(), SelfTestError> {
    let (key, _doc) = RsaKey::generate().map_err(|_| SelfTestError::Rsa)?;
    rsa_holds(&key, verify)
        .then_some(())
        .ok_or(SelfTestError::Rsa)
}

/// Runs every self-test; the identity signer refuses to start on the first failure.
///
/// # Errors
/// The failed test.
pub fn run() -> Result<(), SelfTestError> {
    access_crypto::kat::run()?;
    rsa(rsa_spki_verifies)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CMP-22b, OP-143
    #[test]
    fn the_self_tests_pass() {
        assert_eq!(run(), Ok(()));
    }

    // CMP-22b, SAI-45
    #[test]
    fn a_verifier_that_accepts_everything_refuses() {
        assert_eq!(rsa(|_, _, _| true), Err(SelfTestError::Rsa));
    }

    // CMP-22b
    #[test]
    fn a_verifier_that_rejects_everything_refuses() {
        assert_eq!(rsa(|_, _, _| false), Err(SelfTestError::Rsa));
    }

    #[test]
    fn codes_are_stable() {
        assert_eq!(SelfTestError::Rsa.code(), "signer-kat-rsa");
        assert_eq!(
            SelfTestError::Known(KatError::P256).code(),
            "signer-kat-p256"
        );
    }
}
