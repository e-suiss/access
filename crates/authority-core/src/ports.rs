//! What the core needs from the outside (OP-63): state reads, actor-binding, salts, keys.

use std::future::Future;

use access_crypto::event_id::EventKey;
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
    /// The latest outcome of a nonce.
    fn nonce(
        &self,
        nonce: &[u8],
    ) -> impl Future<Output = Result<Option<NonceRow>, CoreError>> + Send;
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
}
