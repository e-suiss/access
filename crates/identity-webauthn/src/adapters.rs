//! Port implementations (OP-63): system time and randomness, the HSM decoy key, a file
//! metadata source, and in-process registry, cache and signal sink.

use std::future::{Future, ready};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use access_crypto::webauthn::DecoyKey;

use crate::WebAuthnError;
use crate::domain::ceremony::Signal;
use crate::domain::credential::CredentialRecord;
use crate::domain::ids::{CredentialId, RealmId, UserHandle};
use crate::domain::mds::{MAX_BLOB, MdsBlob, MdsError};
use crate::ports::{
    Clock, CredentialRegistry, DecoySource, Inserted, MdsCache, MdsSource, Random, SignalSink,
};

/// The host clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, WebAuthnError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|_| WebAuthnError::Clock)
    }
}

/// The operating system's randomness through aws-lc-rs.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), WebAuthnError> {
        for chunk in out.chunks_mut(32) {
            let bytes = access_crypto::random::bytes::<32>().map_err(|_| WebAuthnError::Random)?;
            for (d, s) in chunk.iter_mut().zip(bytes) {
                *d = s;
            }
        }
        Ok(())
    }
}

/// Decoy keys per realm, each in the PKCS#11 token as `access/webauthn-decoy/<RealmID hex>`.
#[derive(Default)]
pub struct RealmDecoyKeys {
    keys: Vec<(RealmId, DecoyKey)>,
}

impl RealmDecoyKeys {
    /// Adds a realm's key.
    #[must_use]
    pub fn with(mut self, realm: RealmId, key: DecoyKey) -> Self {
        self.keys.push((realm, key));
        self
    }
}

impl DecoySource for RealmDecoyKeys {
    fn derive(&self, realm: RealmId, input: &[u8]) -> Result<[u8; 32], WebAuthnError> {
        let (_, key) = self
            .keys
            .iter()
            .find(|(r, _)| *r == realm)
            .ok_or(WebAuthnError::Decoy)?;
        key.derive(input).map_err(|_| WebAuthnError::Decoy)
    }
}

/// Reads the metadata blob from a file a fetch job or the operator keeps current.
#[derive(Clone, Debug)]
pub struct FileMdsSource {
    path: PathBuf,
}

impl FileMdsSource {
    /// A source reading `path`.
    #[must_use]
    pub const fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl FileMdsSource {
    fn read(&self) -> Result<Vec<u8>, WebAuthnError> {
        let len = std::fs::metadata(&self.path)
            .map_err(|e| WebAuthnError::MdsSource(e.kind().to_string()))?
            .len();
        if usize::try_from(len).map_or(true, |l| l > MAX_BLOB) {
            return Err(MdsError::Size.into());
        }
        std::fs::read(&self.path).map_err(|e| WebAuthnError::MdsSource(e.kind().to_string()))
    }
}

impl MdsSource for FileMdsSource {
    fn fetch(&self) -> impl Future<Output = Result<Vec<u8>, WebAuthnError>> + Send {
        ready(self.read())
    }
}

fn poisoned<T>(_: PoisonError<T>) -> WebAuthnError {
    WebAuthnError::MdsSource("lock poisoned".into())
}

/// An in-process metadata cache.
#[derive(Debug, Default)]
pub struct MemoryMdsCache {
    blob: RwLock<Option<MdsBlob>>,
}

impl MdsCache for MemoryMdsCache {
    fn current(&self) -> impl Future<Output = Result<Option<MdsBlob>, WebAuthnError>> + Send {
        ready(self.blob.read().map(|b| b.clone()).map_err(poisoned))
    }

    fn replace(&self, blob: MdsBlob) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        ready(
            self.blob
                .write()
                .map(|mut b| *b = Some(blob))
                .map_err(poisoned),
        )
    }
}

fn registry_poisoned<T>(_: PoisonError<T>) -> WebAuthnError {
    WebAuthnError::Registry("lock poisoned".into())
}

/// An in-process registry: realm-scoped, IDs unique per realm including deleted rows, soft
/// delete only (OP-73).
#[derive(Debug, Default)]
pub struct MemoryRegistry {
    rows: Mutex<Vec<CredentialRecord>>,
}

impl MemoryRegistry {
    fn with_rows<T>(
        &self,
        f: impl FnOnce(&mut Vec<CredentialRecord>) -> T,
    ) -> Result<T, WebAuthnError> {
        let mut rows = self.rows.lock().map_err(registry_poisoned)?;
        Ok(f(&mut rows))
    }
}

impl CredentialRegistry for MemoryRegistry {
    fn insert(
        &self,
        record: &CredentialRecord,
    ) -> impl Future<Output = Result<Inserted, WebAuthnError>> + Send {
        ready(self.with_rows(|rows| {
            if rows
                .iter()
                .any(|r| r.realm == record.realm && r.id == record.id)
            {
                Inserted::Duplicate
            } else {
                rows.push(record.clone());
                Inserted::Stored
            }
        }))
    }

    fn find(
        &self,
        realm: RealmId,
        id: &CredentialId,
    ) -> impl Future<Output = Result<Option<CredentialRecord>, WebAuthnError>> + Send {
        ready(self.with_rows(|rows| {
            rows.iter()
                .find(|r| r.realm == realm && r.id == *id)
                .cloned()
        }))
    }

    fn list(
        &self,
        realm: RealmId,
        user: &UserHandle,
    ) -> impl Future<Output = Result<Vec<CredentialRecord>, WebAuthnError>> + Send {
        ready(self.with_rows(|rows| {
            rows.iter()
                .filter(|r| r.realm == realm && r.user == *user && r.deleted_at.is_none())
                .cloned()
                .collect()
        }))
    }

    fn record_use(
        &self,
        realm: RealmId,
        id: &CredentialId,
        sign_count: u32,
        backup_state: bool,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        ready(self.with_rows(|rows| {
            if let Some(r) = rows.iter_mut().find(|r| r.realm == realm && r.id == *id) {
                r.sign_count = sign_count;
                r.backup_state = backup_state;
                r.last_used_at = Some(at);
            }
        }))
    }

    fn soft_delete(
        &self,
        realm: RealmId,
        id: &CredentialId,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        ready(self.with_rows(|rows| {
            if let Some(r) = rows.iter_mut().find(|r| r.realm == realm && r.id == *id) {
                r.deleted_at.get_or_insert(at);
            }
        }))
    }
}

/// An in-process signal sink.
#[derive(Debug, Default)]
pub struct MemorySignals {
    signals: Mutex<Vec<(CredentialId, Signal)>>,
}

fn signals_poisoned<T>(_: PoisonError<T>) -> WebAuthnError {
    WebAuthnError::Signals("lock poisoned".into())
}

impl MemorySignals {
    /// The signals raised so far.
    ///
    /// # Errors
    /// [`WebAuthnError::Signals`] if the lock is poisoned.
    pub fn taken(&self) -> Result<Vec<(CredentialId, Signal)>, WebAuthnError> {
        Ok(self.signals.lock().map_err(signals_poisoned)?.clone())
    }
}

impl SignalSink for MemorySignals {
    fn emit(
        &self,
        _realm: RealmId,
        credential: &CredentialId,
        signal: Signal,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        ready(
            self.signals
                .lock()
                .map(|mut s| s.push((credential.clone(), signal)))
                .map_err(signals_poisoned),
        )
    }
}
