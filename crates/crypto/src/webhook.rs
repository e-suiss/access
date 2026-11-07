//! Standard Webhooks signatures, the Suiss webhook profile shared with Relay (OP-149 m.4, m.7,
//! TN-135, TN-136, E42).
//!
//! - The signed content is `webhook-id ‖ "." ‖ webhook-timestamp ‖ "." ‖ body`.
//! - `webhook-signature` is a space-separated list of `<version>,<base64 signature>`; a
//!   receiver accepts the delivery when any entry verifies, so a rotated key can overlap.
//! - `v1a` is Ed25519, the default (TN-136): the signing key is a 32-byte seed written
//!   `whsk_<base64>`; the receiver holds its public key, written `whpk_<base64>`.
//! - `v1` is HMAC-SHA-256, for compatibility only: the secret is 32 random bytes written
//!   `whsec_<base64>`.

use aws_lc_rs::hmac;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair as _, UnparsedPublicKey};
use zeroize::Zeroizing;

use crate::dit::DitGuard;
use crate::secret::Secret;

/// Prefix of a written secret.
pub const SECRET_PREFIX: &str = "whsec_";

/// Version tag of an HMAC signature entry.
pub const SIGNATURE_VERSION: &str = "v1";

/// Version tag of an Ed25519 signature entry (TN-136).
pub const ED25519_VERSION: &str = "v1a";

/// Prefix of a written Ed25519 signing key.
pub const SIGNING_KEY_PREFIX: &str = "whsk_";

/// Prefix of a written Ed25519 public key.
pub const PUBLIC_KEY_PREFIX: &str = "whpk_";

/// Largest accepted clock skew of `webhook-timestamp`, seconds (PD).
pub const TOLERANCE_S: u64 = 300;

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 §4).
#[must_use]
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18_u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                out.push(char::from(STD.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes standard base64 with padding.
#[must_use]
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len());
    let last = bytes.len().saturating_sub(4);
    for (at, chunk) in bytes.chunks(4).enumerate() {
        let final_chunk = at.saturating_mul(4) == last;
        let mut n = 0_u32;
        let mut pad = 0_usize;
        for (i, c) in chunk.iter().enumerate() {
            let v = match c {
                b'A'..=b'Z' => c.checked_sub(b'A')?,
                b'a'..=b'z' => c.checked_sub(b'a')?.checked_add(26)?,
                b'0'..=b'9' => c.checked_sub(b'0')?.checked_add(52)?,
                b'+' => 62,
                b'/' => 63,
                b'=' if i >= 2 && final_chunk => {
                    pad = pad.checked_add(1)?;
                    0
                }
                _ => return None,
            };
            if pad > 0 && *c != b'=' {
                return None;
            }
            n = (n << 6) | u32::from(v);
        }
        let full = n.to_be_bytes();
        let keep = 3_usize.checked_sub(pad)?;
        out.extend_from_slice(full.get(1..1_usize.checked_add(keep)?)?);
    }
    Some(out)
}

/// A subscription's signing secret. It never appears in `Debug`.
pub struct WebhookSecret(Secret<Vec<u8>>);

impl core::fmt::Debug for WebhookSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WebhookSecret(<redacted>)")
    }
}

/// A written secret that is not `whsec_<base64>` of 24 to 64 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("malformed webhook secret")]
pub struct MalformedSecret;

impl WebhookSecret {
    /// A fresh secret of 32 random bytes.
    ///
    /// # Errors
    /// [`crate::random::RandomError`].
    pub fn generate() -> Result<Self, crate::random::RandomError> {
        let raw = Zeroizing::new(crate::random::bytes::<32>()?);
        Ok(Self(Secret::new(raw.to_vec())))
    }

    /// From raw key bytes, as stored sealed.
    ///
    /// # Errors
    /// [`MalformedSecret`] outside 24 to 64 bytes.
    pub fn from_bytes(raw: Vec<u8>) -> Result<Self, MalformedSecret> {
        if !(24..=64).contains(&raw.len()) {
            return Err(MalformedSecret);
        }
        Ok(Self(Secret::new(raw)))
    }

    /// The raw key bytes, to seal for storage.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8] {
        self.0.expose()
    }

    /// Reads `whsec_<base64>`.
    ///
    /// # Errors
    /// [`MalformedSecret`].
    pub fn parse(text: &str) -> Result<Self, MalformedSecret> {
        let b64 = text.strip_prefix(SECRET_PREFIX).ok_or(MalformedSecret)?;
        Self::from_bytes(b64_decode(b64).ok_or(MalformedSecret)?)
    }

    /// The written form, shown once to the subscriber.
    #[must_use]
    pub fn expose_text(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::from(SECRET_PREFIX));
        out.push_str(&b64_encode(self.0.expose()));
        out
    }

    fn key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, self.0.expose())
    }

    /// The `v1,<base64>` signature of one delivery.
    #[must_use]
    pub fn sign(&self, id: &str, timestamp_s: u64, body: &[u8]) -> String {
        let _dit = DitGuard::new();
        let tag = hmac::sign(&self.key(), &signed_content(id, timestamp_s, body));
        format!("{SIGNATURE_VERSION},{}", b64_encode(tag.as_ref()))
    }

    /// Whether `header` holds a `v1` signature of the delivery under this secret and the
    /// timestamp is within [`TOLERANCE_S`] of `now_s`.
    #[must_use]
    pub fn verify(
        &self,
        id: &str,
        timestamp_s: u64,
        body: &[u8],
        header: &str,
        now_s: u64,
    ) -> bool {
        if now_s.abs_diff(timestamp_s) > TOLERANCE_S {
            return false;
        }
        let content = signed_content(id, timestamp_s, body);
        let key = self.key();
        header.split(' ').any(|entry| {
            entry
                .strip_prefix("v1,")
                .and_then(b64_decode)
                .is_some_and(|sig| {
                    let _dit = DitGuard::new();
                    hmac::verify(&key, &content, &sig).is_ok()
                })
        })
    }
}

/// An Ed25519 webhook signing key (TN-136 `v1a`). It never appears in `Debug`.
pub struct WebhookSigningKey {
    seed: Secret<Vec<u8>>,
    pair: Ed25519KeyPair,
}

impl core::fmt::Debug for WebhookSigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("WebhookSigningKey(<redacted>)")
    }
}

impl WebhookSigningKey {
    /// A fresh key from 32 random bytes.
    ///
    /// # Errors
    /// [`crate::random::RandomError`].
    pub fn generate() -> Result<Self, crate::random::RandomError> {
        let seed = Zeroizing::new(crate::random::bytes::<32>()?);
        Self::from_seed(seed.as_slice()).map_err(|MalformedSecret| crate::random::RandomError)
    }

    /// From the 32-byte seed, as stored sealed.
    ///
    /// # Errors
    /// [`MalformedSecret`] for any other length.
    pub fn from_seed(seed: &[u8]) -> Result<Self, MalformedSecret> {
        if seed.len() != 32 {
            return Err(MalformedSecret);
        }
        let pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| MalformedSecret)?;
        Ok(Self {
            seed: Secret::new(seed.to_vec()),
            pair,
        })
    }

    /// Reads `whsk_<base64>`.
    ///
    /// # Errors
    /// [`MalformedSecret`].
    pub fn parse(text: &str) -> Result<Self, MalformedSecret> {
        let b64 = text
            .strip_prefix(SIGNING_KEY_PREFIX)
            .ok_or(MalformedSecret)?;
        let seed = Zeroizing::new(b64_decode(b64).ok_or(MalformedSecret)?);
        Self::from_seed(&seed)
    }

    /// The seed, to seal for storage.
    #[must_use]
    pub fn expose_seed(&self) -> &[u8] {
        self.seed.expose()
    }

    /// The public key the receiver verifies with.
    #[must_use]
    pub fn public_key(&self) -> WebhookPublicKey {
        let mut pk = [0_u8; 32];
        if let Some(src) = self.pair.public_key().as_ref().get(..32) {
            pk.copy_from_slice(src);
        }
        WebhookPublicKey(pk)
    }

    /// The `v1a,<base64>` signature of one delivery.
    #[must_use]
    pub fn sign(&self, id: &str, timestamp_s: u64, body: &[u8]) -> String {
        let sig = self.pair.sign(&signed_content(id, timestamp_s, body));
        format!("{ED25519_VERSION},{}", b64_encode(sig.as_ref()))
    }
}

/// An Ed25519 webhook public key, published to the receiver (TN-136).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebhookPublicKey([u8; 32]);

impl WebhookPublicKey {
    /// From its 32 bytes.
    #[must_use]
    pub const fn from_bytes(raw: [u8; 32]) -> Self {
        Self(raw)
    }

    /// Its 32 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Reads `whpk_<base64>`.
    ///
    /// # Errors
    /// [`MalformedSecret`].
    pub fn parse(text: &str) -> Result<Self, MalformedSecret> {
        let b64 = text.strip_prefix(PUBLIC_KEY_PREFIX).ok_or(MalformedSecret)?;
        let raw = b64_decode(b64).ok_or(MalformedSecret)?;
        Ok(Self(
            <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| MalformedSecret)?,
        ))
    }

    /// The written form, `whpk_<base64>`.
    #[must_use]
    pub fn text(&self) -> String {
        format!("{PUBLIC_KEY_PREFIX}{}", b64_encode(&self.0))
    }

    /// Whether `header` holds a `v1a` signature of the delivery under this key and the
    /// timestamp is within [`TOLERANCE_S`] of `now_s`.
    #[must_use]
    pub fn verify(
        &self,
        id: &str,
        timestamp_s: u64,
        body: &[u8],
        header: &str,
        now_s: u64,
    ) -> bool {
        if now_s.abs_diff(timestamp_s) > TOLERANCE_S {
            return false;
        }
        let content = signed_content(id, timestamp_s, body);
        let key = UnparsedPublicKey::new(&ED25519, &self.0);
        header.split(' ').any(|entry| {
            entry
                .strip_prefix("v1a,")
                .and_then(b64_decode)
                .is_some_and(|sig| key.verify(&content, &sig).is_ok())
        })
    }
}

fn signed_content(id: &str, timestamp_s: u64, body: &[u8]) -> Vec<u8> {
    let ts = timestamp_s.to_string();
    let mut out = Vec::with_capacity(
        id.len()
            .saturating_add(ts.len())
            .saturating_add(body.len())
            .saturating_add(2),
    );
    out.extend_from_slice(id.as_bytes());
    out.push(b'.');
    out.extend_from_slice(ts.as_bytes());
    out.push(b'.');
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests;
