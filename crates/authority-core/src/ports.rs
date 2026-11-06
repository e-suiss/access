//! What the core needs from the outside (OP-63): state reads, actor-binding, salts, keys.

use std::future::Future;

use access_crypto::event_id::EventKey;
use access_crypto::token::TokenKey;
use access_kernel::digest::Digest;
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use access_store::authority::NonceRow;
use suiss_crypto::dcbor::Value;

use crate::CoreError;

/// One fetched state key: its value, `None` when absent, and its version.
pub type Row = (Vec<u8>, Option<Value>, u64);

/// Reads the state and the nonce table (the `StateView` read side).
pub trait Reader {
    /// Current values and versions of `keys`; an absent key comes back as `(key, None, 0)`.
    fn fetch(&self, keys: &[Vec<u8>]) -> impl Future<Output = Result<Vec<Row>, CoreError>> + Send;
    /// The live rows whose key starts with `prefix` (OP-141 m.20 (b)).
    fn scan(&self, prefix: &[u8]) -> impl Future<Output = Result<Vec<Row>, CoreError>> + Send;
    /// Live Grants on resources in `namespace` from the derived index, in id order after
    /// `after` (OP-141 m.22 (g)); candidates only, never a decision input.
    fn grants_in(
        &self,
        namespace: &str,
        after: Option<Id>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Id>, CoreError>> + Send;
    /// Live Grants `party` may hold, from the derived index, in id order after `after`.
    fn grants_for(
        &self,
        party: &Id,
        after: Option<Id>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Id>, CoreError>> + Send;
    /// The envelopes of the records `from..=to`, in order (OP-141 m.36 (d)).
    fn log(
        &self,
        from: u64,
        to: u64,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, CoreError>> + Send;
    /// The trusted time of the record at `pos`, if there is one.
    fn recorded_at(&self, pos: u64) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send;
    /// A SYNC-DERIVED counter's used amount; 0 when never drawn.
    fn counter(&self, key: &[u8]) -> impl Future<Output = Result<u64, CoreError>> + Send;
    /// The bytes a record kept as a proof under `digest` (a Claim, or a Claim body by its
    /// digest); none by default.
    fn proof(
        &self,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<Option<Vec<u8>>, CoreError>> + Send {
        let _ = digest;
        std::future::ready(Ok(None))
    }
    /// The position of the first decision of a nonce (OP-141 m.34 (c)).
    fn nonce_opened(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<u64>, CoreError>> + Send;
    /// The latest outcome of a nonce.
    fn nonce(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<NonceRow>, CoreError>> + Send;
    /// The first `projection.issue` of each live projection family `holder` holds (§9.9.3
    /// k.6, P50): the families that end with the holder Instance.
    fn live_families(
        &self,
        holder: &Id,
    ) -> impl Future<Output = Result<Vec<Digest>, CoreError>> + Send;
    /// What the latest `require_action` on `intent` left for its approval (§9.14.1 step 1,
    /// OP-150 L6): the render digest the decision point computed and the tier.
    fn opening(
        &self,
        intent: &Digest,
    ) -> impl Future<Output = Result<Option<Opening>, CoreError>> + Send;
}

/// What a decision point recorded when it asked for an approval (§9.14.1, §13.7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The render digest of the intent (§9.13.3, XI-8).
    pub render: Digest,
    /// The intent's consequence tier.
    pub tier: access_kernel::tier::Tier,
}

/// Confirms who a new key belongs to before it is an Instance: the actor-binding of
/// `party_register` and `instance_create` (§7.9.2.3). The identity plane provides it; without
/// a binding the request is anonymous.
pub trait Binding {
    /// The Party and key bound to `kid`, if any.
    fn bound(&self, kid: &[u8; 32]) -> Option<(Id, PublicKey)>;
}

/// Fresh field salts (OP-106 m.15).
pub trait Salts {
    /// A fresh salt.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when no randomness is available.
    fn salt(&mut self) -> Result<[u8; 32], CoreError>;
}

/// The domains' event-id keys `K_D` (OP-141 m.18 (d)).
pub trait Keys: Send + Sync {
    /// The key of `domain`.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the key is missing or the token fails.
    fn event_key(&self, domain: &Digest) -> Result<EventKey, CoreError>;
    /// The token key of `domain` (OP-141 m.22 (d)).
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the key is missing or the token fails.
    fn token_key(&self, domain: &Digest) -> Result<TokenKey, CoreError>;
    /// The pseudonym key of `domain` (P52, OP-143 m.15 (d)).
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the token fails.
    fn pseudonym_key(
        &self,
        domain: &Digest,
    ) -> Result<access_crypto::pseudonym::PseudonymKey, CoreError>;
    /// Makes the event-id and token keys of the new domain `domain` that are missing
    /// (OP-141 m.18 (d), m.22 (d)); a key that exists is kept.
    ///
    /// # Errors
    /// [`CoreError::Unavailable`] when the token fails.
    fn open_domain(&self, domain: &Digest) -> Result<(), CoreError>;
}
