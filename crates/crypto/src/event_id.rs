//! Keyed event id (OP-130 m.8, TI-RT10, T26): a per-domain MAC, so receivers can deduplicate
//! without the id revealing or linking anything. The key `K_D` lives in the PKCS#11 token
//! (OP-141 m.18 (d)).

use std::fmt::Write as _;

#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::hmac;
use suiss_crypto::pkcs11::{HsmError, HsmMac};

#[cfg(any(test, feature = "testing"))]
use crate::dit::DitGuard;
#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

const CONTEXT: &[u8] = b"access/event/v1\0";

/// The token label of a domain's event-id key: `access/event/<DomainID hex>`.
#[must_use]
pub fn label(domain: &[u8; 32]) -> String {
    let mut out = String::from("access/event/");
    for b in domain {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `"access/event/v1" ‖ 0x00 ‖ domain ‖ pos ‖ idx`, big-endian integers.
fn message(domain: &[u8; 32], pos: u64, idx: u32) -> [u8; 60] {
    let mut m = [0; 60];
    m[..16].copy_from_slice(CONTEXT);
    m[16..48].copy_from_slice(domain);
    m[48..56].copy_from_slice(&pos.to_be_bytes());
    m[56..].copy_from_slice(&idx.to_be_bytes());
    m
}

enum Key {
    Token(HsmMac),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// A domain's event-id key.
pub struct EventKey(Key);

impl EventKey {
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

    /// `HMAC-SHA-256(K_D, "access/event/v1" ‖ 0x00 ‖ domain ‖ pos ‖ idx)`.
    ///
    /// # Errors
    /// [`HsmError`] when the token refuses.
    pub fn event_id(&self, domain: &[u8; 32], pos: u64, idx: u32) -> Result<[u8; 32], HsmError> {
        let message = message(domain, pos, idx);
        match &self.0 {
            Key::Token(mac) => mac.mac(&message),
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(key) => {
                // CR-39 m.6
                let _dit = DitGuard::new();
                let key = hmac::Key::new(hmac::HMAC_SHA256, key.expose());
                let mut out = [0; 32];
                out.copy_from_slice(hmac::sign(&key, &message).as_ref());
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests;
