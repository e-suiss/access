//! DPoP server state (§10.4.3 m.2–m.3, §12.2.1, MD-18): the fixed-length replay key (TN-30,
//! SHA-256 by OP-146 m.3) and the long-lived, shared, stateless server nonce (TN-29), a
//! time-window value MAC'd with a per-realm key that one component both issues and checks
//! (CR-3 (b)). Authorization server and resource server nonces use separate keys.

use std::fmt::Write as _;

use access_kernel::json::{b64url_decode, b64url_encode};
use aws_lc_rs::digest;
#[cfg(any(test, feature = "testing"))]
use aws_lc_rs::hmac;
use subtle::ConstantTimeEq as _;
use suiss_crypto::pkcs11::{HsmError, HsmMac};

#[cfg(any(test, feature = "testing"))]
use crate::dit::DitGuard;
#[cfg(any(test, feature = "testing"))]
use crate::secret::Secret;

const REPLAY_CONTEXT: &[u8] = b"access/dpop-replay/v1\0";
const NONCE_CONTEXT: &[u8] = b"access/dpop-nonce/v1\0";
const NONCE_VERSION: u8 = 1;
const NONCE_LEN: usize = 29;
const TAG_LEN: usize = 16;

/// Largest stale-nonce tolerance (TN-29: at most 5 minutes).
pub const MAX_STALE_MS: u64 = 5 * 60 * 1000;

/// The replay key of a proof: `SHA-256("access/dpop-replay/v1" ‖ 0x00 ‖ htm ‖ htu ‖ jti)`,
/// each part prefixed with its 32-bit big-endian length (TN-30, OP-146 m.3). `htu` is the
/// normalised form. Fixed length whatever the proof carries.
#[must_use]
pub fn replay_key(htm: &str, htu: &str, jti: &str) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(REPLAY_CONTEXT);
    for part in [htm, htu, jti] {
        let len = u32::try_from(part.len()).unwrap_or(u32::MAX);
        ctx.update(&len.to_be_bytes());
        ctx.update(part.as_bytes());
    }
    let mut out = [0; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Which side of the realm issues and checks the nonce; each has its own key (TN-29).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The authorization server: a missing or stale nonce is `400 use_dpop_nonce`.
    AuthorizationServer,
    /// A resource server of the realm: a missing or stale nonce is `401 use_dpop_nonce`.
    ResourceServer,
}

impl Role {
    const fn byte(self) -> u8 {
        match self {
            Self::AuthorizationServer => b'a',
            Self::ResourceServer => b'r',
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::AuthorizationServer => "as",
            Self::ResourceServer => "rs",
        }
    }
}

/// The token label of a realm's nonce key: `access/dpop-nonce/<RealmID hex>/<as|rs>/<generation>`.
#[must_use]
pub fn label(realm: &[u8; 16], role: Role, generation: u32) -> String {
    let mut out = String::from("access/dpop-nonce/");
    for b in realm {
        let _ = write!(out, "{b:02x}");
    }
    let _ = write!(out, "/{}/{generation}", role.name());
    out
}

enum Key {
    Token(HsmMac),
    #[cfg(any(test, feature = "testing"))]
    Memory(Secret<[u8; 32]>),
}

/// One generation of a realm's nonce key.
pub struct NonceKey(Key);

impl NonceKey {
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

    fn mac(&self, message: &[u8]) -> Result<[u8; 32], HsmError> {
        match &self.0 {
            Key::Token(mac) => mac.mac(message),
            #[cfg(any(test, feature = "testing"))]
            Key::Memory(key) => {
                // CR-39 m.6
                let _dit = DitGuard::new();
                let key = hmac::Key::new(hmac::HMAC_SHA256, key.expose());
                let mut out = [0; 32];
                out.copy_from_slice(hmac::sign(&key, message).as_ref());
                Ok(out)
            }
        }
    }
}

/// How long nonces live (TN-29, values PD): a nonce of window `w` is issued during
/// `[w·period, (w+1)·period)` and accepted until `(w+2)·period + stale`, a sliding window of
/// one extra period plus the stale tolerance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoncePolicy {
    period_ms: u64,
    stale_ms: u64,
}

impl NoncePolicy {
    /// Default rotation period: hours, not the 60 s model MD-18 rejects (PD).
    pub const DEFAULT_PERIOD_MS: u64 = 24 * 60 * 60 * 1000;

    /// A policy; the period is at least the stale tolerance and the tolerance at most 5 min.
    ///
    /// # Errors
    /// [`NonceError::Policy`].
    pub const fn new(period_ms: u64, stale_ms: u64) -> Result<Self, NonceError> {
        if period_ms == 0 || stale_ms > MAX_STALE_MS || period_ms < stale_ms {
            return Err(NonceError::Policy);
        }
        Ok(Self {
            period_ms,
            stale_ms,
        })
    }

    /// The rotation period.
    #[must_use]
    pub const fn period_ms(&self) -> u64 {
        self.period_ms
    }

    /// The stale tolerance.
    #[must_use]
    pub const fn stale_ms(&self) -> u64 {
        self.stale_ms
    }
}

impl Default for NoncePolicy {
    fn default() -> Self {
        Self {
            period_ms: Self::DEFAULT_PERIOD_MS,
            stale_ms: MAX_STALE_MS,
        }
    }
}

/// Why a nonce is not accepted; every case but [`NonceError::Unavailable`] and
/// [`NonceError::Policy`] is answered with `use_dpop_nonce` and a fresh nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum NonceError {
    /// The proof carries no nonce.
    #[error("missing")]
    Missing,
    /// Not a nonce of this format.
    #[error("malformed")]
    Malformed,
    /// Its key generation is neither the current nor the previous one.
    #[error("unknown key")]
    UnknownKey,
    /// Past the sliding window and stale tolerance.
    #[error("expired")]
    Expired,
    /// From a window that has not started.
    #[error("future")]
    Future,
    /// The MAC does not verify: another realm, role or key.
    #[error("mismatch")]
    Mismatch,
    /// The key store refused; the proof is rejected (MD-8).
    #[error("key unavailable")]
    Unavailable,
    /// The policy values are out of range.
    #[error("policy")]
    Policy,
}

impl NonceError {
    /// Stable reason code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "dpop-nonce-missing",
            Self::Malformed => "dpop-nonce-malformed",
            Self::UnknownKey => "dpop-nonce-unknown-key",
            Self::Expired => "dpop-nonce-expired",
            Self::Future => "dpop-nonce-future",
            Self::Mismatch => "dpop-nonce-mismatch",
            Self::Unavailable => "dpop-nonce-unavailable",
            Self::Policy => "dpop-nonce-policy",
        }
    }
}

/// A realm's nonce keys for one role: the current generation, which issues, and the previous
/// one, which is still accepted after a rotation.
pub struct NonceRing {
    realm: [u8; 16],
    role: Role,
    policy: NoncePolicy,
    current: (u32, NonceKey),
    previous: Option<(u32, NonceKey)>,
}

impl NonceRing {
    /// A ring with one key generation.
    #[must_use]
    pub const fn new(
        realm: [u8; 16],
        role: Role,
        policy: NoncePolicy,
        generation: u32,
        key: NonceKey,
    ) -> Self {
        Self {
            realm,
            role,
            policy,
            current: (generation, key),
            previous: None,
        }
    }

    /// The role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The policy.
    #[must_use]
    pub const fn policy(&self) -> NoncePolicy {
        self.policy
    }

    /// Makes `key` current; the old current generation stays accepted, the one before is
    /// dropped.
    pub fn rotate(&mut self, generation: u32, key: NonceKey) {
        let old = core::mem::replace(&mut self.current, (generation, key));
        self.previous = Some(old);
    }

    fn message(&self, generation: u32, window: u64) -> Vec<u8> {
        let mut m = Vec::with_capacity(NONCE_CONTEXT.len().saturating_add(29));
        m.extend_from_slice(NONCE_CONTEXT);
        m.push(self.role.byte());
        m.extend_from_slice(&self.realm);
        m.extend_from_slice(&generation.to_be_bytes());
        m.extend_from_slice(&window.to_be_bytes());
        m
    }

    fn window(&self, now: u64) -> u64 {
        now.checked_div(self.policy.period_ms).unwrap_or(0)
    }

    /// The nonce to send in `DPoP-Nonce` now: on every successful response and with every
    /// `use_dpop_nonce` error (TN-29).
    ///
    /// # Errors
    /// [`NonceError::Unavailable`].
    pub fn issue(&self, now: u64) -> Result<String, NonceError> {
        let (generation, key) = &self.current;
        let window = self.window(now);
        let tag = key
            .mac(&self.message(*generation, window))
            .map_err(|_| NonceError::Unavailable)?;
        let mut raw = Vec::with_capacity(NONCE_LEN);
        raw.push(NONCE_VERSION);
        raw.extend_from_slice(&generation.to_be_bytes());
        raw.extend_from_slice(&window.to_be_bytes());
        raw.extend_from_slice(tag.get(..TAG_LEN).unwrap_or_default());
        Ok(b64url_encode(&raw))
    }

    /// Checks a proof's nonce (IDP-11 step 9, TN-29). A missing nonce is rejected: the server
    /// sends one on every response, so a client without one has not yet been given it.
    ///
    /// # Errors
    /// [`NonceError`].
    pub fn check(&self, nonce: Option<&str>, now: u64) -> Result<(), NonceError> {
        let nonce = nonce.ok_or(NonceError::Missing)?;
        let raw = b64url_decode(nonce).map_err(|_| NonceError::Malformed)?;
        let raw: &[u8; NONCE_LEN] = raw
            .as_slice()
            .try_into()
            .map_err(|_| NonceError::Malformed)?;
        let (head, tag) = raw.split_at(13);
        let (version, rest) = head.split_at(1);
        let (generation, window) = rest.split_at(4);
        if version != [NONCE_VERSION] {
            return Err(NonceError::Malformed);
        }
        let generation =
            u32::from_be_bytes(generation.try_into().map_err(|_| NonceError::Malformed)?);
        let window = u64::from_be_bytes(window.try_into().map_err(|_| NonceError::Malformed)?);
        let key = if generation == self.current.0 {
            &self.current.1
        } else {
            match &self.previous {
                Some((g, key)) if *g == generation => key,
                _ => return Err(NonceError::UnknownKey),
            }
        };
        if window > self.window(now) {
            return Err(NonceError::Future);
        }
        let until = window
            .checked_add(2)
            .and_then(|w| w.checked_mul(self.policy.period_ms))
            .and_then(|t| t.checked_add(self.policy.stale_ms))
            .ok_or(NonceError::Expired)?;
        if now >= until {
            return Err(NonceError::Expired);
        }
        let expected = key
            .mac(&self.message(generation, window))
            .map_err(|_| NonceError::Unavailable)?;
        let expected = expected.get(..TAG_LEN).ok_or(NonceError::Mismatch)?;
        // CR-39 m.6
        let _dit = DitGuard::new();
        if bool::from(expected.ct_eq(tag)) {
            Ok(())
        } else {
            Err(NonceError::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests;
