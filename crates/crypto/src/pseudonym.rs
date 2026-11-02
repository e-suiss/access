//! Domain-pairwise party pseudonyms (P52, MD-10, OP-143 m.15 (d)): what a projection names a
//! Party by outside its domain. The key `K_d` lives in the PKCS#11 token and never leaves it.

use std::fmt::Write as _;

#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::hmac;
use suiss_crypto::pkcs11::{HsmError, HsmMac};

#[cfg(any(test, feature = "testing"))]
use crate::dit::DitGuard;
#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

const CONTEXT: &[u8] = b"access/party-ref/v1\0";

/// The token label of a domain's pseudonym key: `access/pseudonym/<DomainID hex>`.
#[must_use]
pub fn label(domain: &[u8; 32]) -> String {
    let mut out = String::from("access/pseudonym/");
    for b in domain {
        let _ = write!(out, "{b:02x}");
    }
    out
}

enum Key {
    Token(HsmMac),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// A domain's pseudonym key.
pub struct PseudonymKey(Key);

impl PseudonymKey {
    /// The key inside the token.
    #[must_use]
    pub const fn token(mac: HsmMac) -> Self {
        Self(Key::Token(mac))
    }

    /// An in-process key with the same output as the token's, for tests.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(Key::Memory(key))
    }

    /// The pseudonym of `party`: the first 16 bytes of
    /// `HMAC-SHA-256(K_d, "access/party-ref/v1" ‖ 0x00 ‖ PartyID)`.
    ///
    /// # Errors
    /// [`HsmError`] when the token refuses.
    pub fn party_ref(&self, party: &[u8; 16]) -> Result<[u8; 16], HsmError> {
        let mut message = CONTEXT.to_vec();
        message.extend_from_slice(party);
        let full = match &self.0 {
            Key::Token(mac) => mac.mac(&message)?,
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(key) => {
                // CR-39 m.6
                let _dit = DitGuard::new();
                let key = hmac::Key::new(hmac::HMAC_SHA256, key.expose());
                let mut out = [0; 32];
                out.copy_from_slice(hmac::sign(&key, &message).as_ref());
                out
            }
        };
        let mut out = [0; 16];
        out.copy_from_slice(&full[..16]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // P52, OP-143 m.15 (d): stable per key, different across keys and parties
    #[test]
    fn pseudonyms_are_pairwise() {
        let a = PseudonymKey::new(Secret::new([1; 32]));
        let b = PseudonymKey::new(Secret::new([2; 32]));
        let p = [7; 16];
        assert_eq!(a.party_ref(&p).unwrap(), a.party_ref(&p).unwrap());
        assert_ne!(a.party_ref(&p).unwrap(), b.party_ref(&p).unwrap());
        assert_ne!(a.party_ref(&p).unwrap(), a.party_ref(&[8; 16]).unwrap());
        assert_ne!(a.party_ref(&p).unwrap(), p);
        assert_eq!(label(&[0xab; 32]).len(), "access/pseudonym/".len() + 64);
    }
}
