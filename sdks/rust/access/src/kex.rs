//! The hybrid key exchange of the caller's TLS (CR-12 m.3, OP-159 m.3 (t)). The SDK does no
//! I/O, so it gives the caller's TLS stack the order of its key exchange groups for the realm's
//! `kex_share` policy and counts the handshakes the caller reports.
//!
//! - `optimistic` (the default) sends the `X25519MLKEM768` key share first.
//! - `advertise-only` sends an X25519 share first and lists `X25519MLKEM768` in
//!   `supported_groups`; Access answers with a `HelloRetryRequest` and the connection moves to the
//!   hybrid group. It suits networks whose middleboxes break a `ClientHello` larger than one
//!   segment.
//!
//! The hybrid group is never dropped in either mode.

use core::sync::atomic::{AtomicU64, Ordering};

use access_kernel::json;

/// The hybrid group (RFC 10024), its TLS code point.
pub const X25519MLKEM768: u16 = 0x11ec;
/// X25519.
pub const X25519: u16 = 0x001d;
/// P-256.
pub const SECP256R1: u16 = 0x0017;

/// Largest realm metadata document read for the policy (§14.6).
pub const MAX_METADATA: usize = 64 * 1024;

/// The realm's `kex_share` policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KexShare {
    /// The hybrid key share is sent in the first `ClientHello`.
    #[default]
    Optimistic,
    /// The hybrid group is listed, an X25519 share is sent; the server retries to the hybrid
    /// group.
    AdvertiseOnly,
}

impl KexShare {
    /// The policy named `text`; `None` for any other name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "optimistic" => Some(Self::Optimistic),
            "advertise-only" => Some(Self::AdvertiseOnly),
            _ => None,
        }
    }

    /// The policy a realm metadata document declares in `kex_share`. A document without it
    /// declares the default; an unknown value or a malformed document is refused, so the caller
    /// keeps the policy it has.
    ///
    /// # Errors
    /// [`KexError`].
    pub fn from_realm_metadata(body: &[u8]) -> Result<Self, KexError> {
        let doc = json::parse(body, MAX_METADATA).map_err(|_| KexError::Malformed)?;
        match doc.get("kex_share") {
            None => Ok(Self::default()),
            Some(v) => v.as_str().and_then(Self::parse).ok_or(KexError::Unknown),
        }
    }

    /// The policy's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Optimistic => "optimistic",
            Self::AdvertiseOnly => "advertise-only",
        }
    }

    /// The key exchange groups in the order the client offers them; the first gets the key
    /// share. Every mode lists the hybrid group.
    #[must_use]
    pub const fn groups(self) -> [u16; 3] {
        match self {
            Self::Optimistic => [X25519MLKEM768, X25519, SECP256R1],
            Self::AdvertiseOnly => [X25519, X25519MLKEM768, SECP256R1],
        }
    }
}

/// Why a realm metadata document gave no policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum KexError {
    /// Not a JSON document within [`MAX_METADATA`].
    #[error("malformed realm metadata")]
    Malformed,
    /// `kex_share` names no known policy.
    #[error("unknown kex_share")]
    Unknown,
}

/// The connections a client made under one policy: how many handshakes completed and how many
/// failed, all and with the hybrid key share. Telemetry only; it never decides anything.
#[derive(Debug, Default)]
pub struct Handshakes {
    mode: KexShare,
    completed: AtomicU64,
    failed: AtomicU64,
    hybrid_completed: AtomicU64,
    hybrid_failed: AtomicU64,
}

/// What the counters hold now.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// The policy the client runs under.
    pub mode: KexShare,
    /// Completed handshakes.
    pub completed: u64,
    /// Failed handshakes: connection errors before the handshake completed.
    pub failed: u64,
    /// Completed handshakes whose first key share was the hybrid one.
    pub hybrid_completed: u64,
    /// Failed handshakes whose first key share was the hybrid one.
    pub hybrid_failed: u64,
}

impl Handshakes {
    /// Counters for a client under `mode`.
    #[must_use]
    pub const fn new(mode: KexShare) -> Self {
        Self {
            mode,
            completed: AtomicU64::new(0),
            failed: AtomicU64::new(0),
            hybrid_completed: AtomicU64::new(0),
            hybrid_failed: AtomicU64::new(0),
        }
    }

    /// Records one handshake: whether it completed.
    pub fn record(&self, completed: bool) {
        let hybrid = self.mode == KexShare::Optimistic;
        let (all, pq) = if completed {
            (&self.completed, &self.hybrid_completed)
        } else {
            (&self.failed, &self.hybrid_failed)
        };
        all.fetch_add(1, Ordering::Relaxed);
        if hybrid {
            pq.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters now.
    #[must_use]
    pub fn counts(&self) -> Counts {
        Counts {
            mode: self.mode,
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            hybrid_completed: self.hybrid_completed.load(Ordering::Relaxed),
            hybrid_failed: self.hybrid_failed.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // CR-12 m.3, OP-159 m.3 (t)
    #[test]
    fn every_mode_lists_the_hybrid_group() {
        for mode in [KexShare::Optimistic, KexShare::AdvertiseOnly] {
            assert!(mode.groups().contains(&X25519MLKEM768), "{mode:?}");
            assert_eq!(KexShare::parse(mode.name()), Some(mode));
        }
        assert_eq!(KexShare::Optimistic.groups()[0], X25519MLKEM768);
        assert_eq!(KexShare::AdvertiseOnly.groups()[0], X25519);
        assert_eq!(KexShare::parse("classic-only"), None);
    }

    // CR-12 m.3, OP-159 m.3 (t)
    #[test]
    fn the_policy_is_read_from_realm_metadata() {
        assert_eq!(
            KexShare::from_realm_metadata(br#"{"slug":"acme","kex_share":"advertise-only"}"#),
            Ok(KexShare::AdvertiseOnly)
        );
        assert_eq!(
            KexShare::from_realm_metadata(br#"{"slug":"acme"}"#),
            Ok(KexShare::Optimistic)
        );
        assert_eq!(
            KexShare::from_realm_metadata(br#"{"kex_share":"none"}"#),
            Err(KexError::Unknown)
        );
        assert_eq!(
            KexShare::from_realm_metadata(br#"{"kex_share":1}"#),
            Err(KexError::Unknown)
        );
        assert_eq!(
            KexShare::from_realm_metadata(b"not json"),
            Err(KexError::Malformed)
        );
    }

    // CR-12 m.3
    #[test]
    fn handshakes_are_counted_by_outcome_and_share() {
        let optimistic = Handshakes::new(KexShare::Optimistic);
        optimistic.record(true);
        optimistic.record(false);
        optimistic.record(false);
        assert_eq!(
            optimistic.counts(),
            Counts {
                mode: KexShare::Optimistic,
                completed: 1,
                failed: 2,
                hybrid_completed: 1,
                hybrid_failed: 2,
            }
        );
        let advertise = Handshakes::new(KexShare::AdvertiseOnly);
        advertise.record(false);
        assert_eq!(advertise.counts().failed, 1);
        assert_eq!(advertise.counts().hybrid_failed, 0);
    }
}
