//! `requestState` of an MRTR answer (§11.5.5, RS-M12, RS-M13, AG-13, AGI-2, AGI-6, OP-154
//! m.3 (v)): AES-256-GCM under this server's key, valid for 120 s, opened once, and bound to
//! `(actor Instance, capacity, aud, intent digest)` as additional data, so a state moved to
//! another Instance, capacity, audience or intent does not open.
//!
//! The state carries no authority: at most the nonce of a `REQUIRE_ACTION` answer, which the
//! retry's own statement must repeat. A retry is a new request and gets a new decision; nothing
//! in the state is a decision input, and an ALLOW is never carried over (§9.9.5, P54).

use alloc::string::String;
use alloc::vec::Vec;
use std::sync::atomic::{AtomicU64, Ordering};

use access_kernel::digest::Digest;
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::TrustedTime;
use suiss_crypto::digest::context_digest;
use suiss_crypto::envelope::{Dek, MESSAGE_LIMIT, Sealed, open_body, seal_body};
use suiss_crypto::secret::Secret;

use crate::resource::{Replay, ReplayStore, TokenCapacity};

/// How long a state opens after it was sealed.
pub const STATE_TTL_MS: u64 = 120_000;

/// Digest context of the binding, the additional data of the seal.
pub const BINDING_CONTEXT: &str = "access/mcp-request-state/v1";

/// Digest context of the single-use key.
pub const USE_CONTEXT: &str = "access/mcp-request-state-use/v1";

/// Longest nonce a state carries (L1-ADP-7).
pub const MAX_NONCE: usize = 64;

const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const MAX_TEXT: usize = 512;

/// What a state is bound to (AG-13): the actor Instance's key binding (never `sub`: one
/// subject runs many Instances), the capacity, this server's audience and the original intent.
#[derive(Clone, Copy, Debug)]
pub struct Binding<'a> {
    /// The holder Instance's key thumbprint.
    pub instance: &'a [u8; 32],
    /// The capacity.
    pub capacity: &'a TokenCapacity,
    /// This server.
    pub audience: &'a str,
    /// The intent digest of the original request.
    pub intent: &'a Digest,
}

fn capacity_bytes(out: &mut Vec<u8>, capacity: &TokenCapacity) {
    match capacity {
        TokenCapacity::Own { subject } => {
            out.extend_from_slice(b"own\0");
            out.extend_from_slice(subject.as_bytes());
        }
        TokenCapacity::For { principal, actors } => {
            out.extend_from_slice(b"for\0");
            out.extend_from_slice(principal.as_bytes());
            for a in actors {
                out.push(0);
                out.extend_from_slice(a.sub.as_bytes());
                out.push(0);
                out.extend_from_slice(a.iss.as_deref().unwrap_or("").as_bytes());
            }
        }
    }
    out.push(0);
}

impl Binding<'_> {
    /// The binding digest.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut b = Vec::with_capacity(128);
        b.extend_from_slice(self.instance);
        capacity_bytes(&mut b, self.capacity);
        b.extend_from_slice(self.audience.as_bytes());
        b.push(0);
        b.extend_from_slice(&self.intent.0);
        context_digest(BINDING_CONTEXT, &b)
    }
}

/// Why a state was not sealed or does not open. Each is a refusal: the request is decided
/// without the state, never with a guess about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StateError {
    /// Not a state of this server, or bound to another Instance, capacity, audience or intent.
    #[error("request-state")]
    Invalid,
    /// Older than [`STATE_TTL_MS`].
    #[error("request-state-expired")]
    Expired,
    /// Opened before.
    #[error("request-state-replayed")]
    Replayed,
    /// The replay store did not answer.
    #[error("request-state-store")]
    Store,
    /// The key sealed its message limit; rotate it.
    #[error("request-state-exhausted")]
    Exhausted,
    /// The seal failed.
    #[error("request-state-seal")]
    Seal,
}

/// An opened state: only the nonce reference it carried (AGI-6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The `REQUIRE_ACTION` nonce the retry must repeat, when there was one.
    pub nonce: Option<Vec<u8>>,
}

/// The server's state key.
pub struct StateKey {
    key: Secret<[u8; 32]>,
    used: AtomicU64,
}

impl core::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StateKey").finish_non_exhaustive()
    }
}

impl StateKey {
    /// A key from 32 bytes of the caller's CSPRNG or key store.
    #[must_use]
    pub const fn new(key: Secret<[u8; 32]>) -> Self {
        Self {
            key,
            used: AtomicU64::new(0),
        }
    }

    fn dek(&self) -> Dek {
        Dek::from_secret(Secret::new(*self.key.expose()))
    }

    /// Seals a state for `binding` at `now`, carrying `nonce` when the answer was
    /// `REQUIRE_ACTION`.
    ///
    /// # Errors
    /// [`StateError::Exhausted`], [`StateError::Seal`], [`StateError::Invalid`] for a nonce
    /// over [`MAX_NONCE`].
    pub fn seal(
        &self,
        binding: &Binding<'_>,
        nonce: Option<&[u8]>,
        now: TrustedTime,
    ) -> Result<String, StateError> {
        // OP-135 m.3
        let n = self.used.fetch_add(1, Ordering::Relaxed);
        if n >= MESSAGE_LIMIT {
            return Err(StateError::Exhausted);
        }
        let nonce = nonce.unwrap_or_default();
        let len = u8::try_from(nonce.len())
            .ok()
            .filter(|l| usize::from(*l) <= MAX_NONCE)
            .ok_or(StateError::Invalid)?;
        let mut plain = Vec::with_capacity(nonce.len().saturating_add(10));
        plain.push(VERSION);
        plain.extend_from_slice(&now.to_be_bytes());
        plain.push(len);
        plain.extend_from_slice(nonce);
        let sealed =
            seal_body(self.dek(), &binding.digest().0, &plain).map_err(|_| StateError::Seal)?;
        let mut out = sealed.nonce.to_vec();
        out.extend_from_slice(&sealed.ciphertext);
        Ok(b64url_encode(&out))
    }

    /// Opens `state` for `binding` at `now`, once: an expired, foreign, rebound or replayed
    /// state is refused and never reaches a decision.
    ///
    /// # Errors
    /// [`StateError`].
    pub fn open(
        &self,
        state: &str,
        binding: &Binding<'_>,
        now: TrustedTime,
        replay: &impl ReplayStore,
    ) -> Result<Opened, StateError> {
        if state.len() > MAX_TEXT {
            return Err(StateError::Invalid);
        }
        let raw = b64url_decode(state).map_err(|_| StateError::Invalid)?;
        let (nonce, ciphertext) = raw.split_at_checked(NONCE_LEN).ok_or(StateError::Invalid)?;
        let sealed = Sealed {
            nonce: <[u8; NONCE_LEN]>::try_from(nonce).map_err(|_| StateError::Invalid)?,
            ciphertext: ciphertext.to_vec(),
        };
        let plain = open_body(&self.dek(), &binding.digest().0, &sealed)
            .map_err(|_| StateError::Invalid)?;
        let (head, rest) = plain.split_at_checked(10).ok_or(StateError::Invalid)?;
        let (version, issued) = head.split_first().ok_or(StateError::Invalid)?;
        let (issued, len) = issued.split_at_checked(8).ok_or(StateError::Invalid)?;
        if *version != VERSION {
            return Err(StateError::Invalid);
        }
        let issued =
            u64::from_be_bytes(<[u8; 8]>::try_from(issued).map_err(|_| StateError::Invalid)?);
        let len = usize::from(*len.first().ok_or(StateError::Invalid)?);
        if rest.len() != len {
            return Err(StateError::Invalid);
        }
        let until = issued
            .checked_add(STATE_TTL_MS)
            .ok_or(StateError::Invalid)?;
        if now > until || issued > now.saturating_add(STATE_TTL_MS) {
            return Err(StateError::Expired);
        }
        // AG-13
        match replay.record(&context_digest(USE_CONTEXT, &raw).0, until) {
            Replay::Fresh => {}
            Replay::Seen => return Err(StateError::Replayed),
            Replay::Unavailable => return Err(StateError::Store),
        }
        Ok(Opened {
            nonce: (!rest.is_empty()).then(|| rest.to_vec()),
        })
    }
}
