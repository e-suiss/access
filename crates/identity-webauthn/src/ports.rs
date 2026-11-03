//! What the domain needs from the outside world (OP-63).

use std::future::Future;

use crate::WebAuthnError;
use crate::domain::ceremony::Signal;
use crate::domain::credential::CredentialRecord;
use crate::domain::ids::{CredentialId, RealmId, UserHandle};
use crate::domain::mds::MdsBlob;

/// Trusted time.
pub trait Clock {
    /// Unix seconds.
    ///
    /// # Errors
    /// [`WebAuthnError::Clock`]: no trusted time, no ceremony.
    fn now(&self) -> Result<u64, WebAuthnError>;
}

/// Fresh randomness.
pub trait Random {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`WebAuthnError::Random`].
    fn fill(&self, out: &mut [u8]) -> Result<(), WebAuthnError>;
}

/// Whether an insert stored the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inserted {
    /// Stored.
    Stored,
    /// A live or deleted credential with this ID exists in the realm.
    Duplicate,
}

/// The realm-scoped passkey registry (CMP-15.7). Rows are never deleted (OP-73).
pub trait CredentialRegistry {
    /// Stores a new credential unless its ID is taken in the realm.
    fn insert(
        &self,
        record: &CredentialRecord,
    ) -> impl Future<Output = Result<Inserted, WebAuthnError>> + Send;

    /// A credential by ID, deleted ones included.
    fn find(
        &self,
        realm: RealmId,
        id: &CredentialId,
    ) -> impl Future<Output = Result<Option<CredentialRecord>, WebAuthnError>> + Send;

    /// The live credentials of an account.
    fn list(
        &self,
        realm: RealmId,
        user: &UserHandle,
    ) -> impl Future<Output = Result<Vec<CredentialRecord>, WebAuthnError>> + Send;

    /// Records a successful authentication: counter, BS and time.
    fn record_use(
        &self,
        realm: RealmId,
        id: &CredentialId,
        sign_count: u32,
        backup_state: bool,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send;

    /// Soft-deletes a credential (OP-73).
    fn soft_delete(
        &self,
        realm: RealmId,
        id: &CredentialId,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send;
}

/// The realm's keyed derivation for decoy credential IDs (TN-97, CR-3 (a)).
pub trait DecoySource {
    /// A keyed 32-byte derivation of `input` under the realm's key.
    ///
    /// # Errors
    /// [`WebAuthnError::Decoy`].
    fn derive(&self, realm: RealmId, input: &[u8]) -> Result<[u8; 32], WebAuthnError>;
}

/// Where passkey risk signals go (TN-63, K14). Stage 6 turns them into signal Claims.
pub trait SignalSink {
    /// Records one signal.
    fn emit(
        &self,
        realm: RealmId,
        credential: &CredentialId,
        signal: Signal,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send;
}

/// Where the raw metadata blob comes from: a file or a URL (OP-146 m.4 (d)).
pub trait MdsSource {
    /// The blob bytes.
    fn fetch(&self) -> impl Future<Output = Result<Vec<u8>, WebAuthnError>> + Send;
}

/// The cache of the last verified metadata blob.
pub trait MdsCache {
    /// The cached blob.
    fn current(&self) -> impl Future<Output = Result<Option<MdsBlob>, WebAuthnError>> + Send;

    /// Replaces the cached blob.
    fn replace(&self, blob: MdsBlob) -> impl Future<Output = Result<(), WebAuthnError>> + Send;
}
