//! Keyed event id (OP-130 m.8, TI-RT10, T26): a per-domain MAC, so receivers can deduplicate
//! without the id revealing or linking anything.

use aws_lc_rs::hmac;

use crate::secret::Secret;

const CONTEXT: &[u8] = b"access/event/v1\0";

/// A domain's event-id key.
pub struct EventKey(Secret<[u8; 32]>);

impl EventKey {
    /// Wraps key material.
    #[must_use]
    pub fn new(key: Secret<[u8; 32]>) -> Self {
        Self(key)
    }

    /// `HMAC-SHA-256(K_D, "access/event/v1" ‖ 0x00 ‖ domain ‖ pos ‖ idx)`, big-endian integers.
    #[must_use]
    pub fn event_id(&self, domain: &[u8; 32], pos: u64, idx: u32) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.0.expose());
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(CONTEXT);
        ctx.update(domain);
        ctx.update(&pos.to_be_bytes());
        ctx.update(&idx.to_be_bytes());
        let mut out = [0; 32];
        out.copy_from_slice(ctx.sign().as_ref());
        out
    }
}

#[cfg(test)]
mod tests;
