//! The cell's opaque external ids (OP-137, MD-18): the id key is derived in the HSM on first use
//! and kept. Every product-facing surface names a tenant by it (OP-149 m.15 (i)).

use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_identity_events::ports::TenantIds;
use access_store::Pool;
use access_store::locks::cell_lock;
use suiss_crypto::pkcs11::KeyStore;

use crate::login::ID_KEY_ROOT;

/// Makes the cell's opaque-id root in the token when it has none (OP-137, OP-149 m.22 (g)):
/// once per cell, before anything uses opaque ids. Processes starting together take the cell
/// lock and look again under it, so the token ends with one root.
///
/// # Errors
/// The database or the token failed; a token holding two roots fails here too.
pub(crate) async fn open_root(app: &Pool, keys: &KeyStore) -> Result<(), String> {
    if keys.mac(ID_KEY_ROOT).is_ok() {
        return Ok(());
    }
    let lock = cell_lock(app, ID_KEY_ROOT)
        .await
        .map_err(|e| e.to_string())?;
    if keys.mac(ID_KEY_ROOT).is_err() {
        keys.generate_mac(ID_KEY_ROOT).map_err(|e| e.to_string())?;
    }
    lock.release().await.map_err(|e| e.to_string())
}

/// The cell's id key from the token.
pub(crate) struct CellIds {
    keys: Arc<KeyStore>,
    key: Mutex<Option<Arc<IdKey>>>,
}

impl CellIds {
    pub(crate) const fn new(keys: Arc<KeyStore>) -> Self {
        Self {
            keys,
            key: Mutex::new(None),
        }
    }

    fn key(&self) -> Option<Arc<IdKey>> {
        let mut slot = self.key.lock().ok()?;
        if slot.is_none() {
            let bytes = crate::login::id_key_bytes(&self.keys).ok()?;
            *slot = Some(Arc::new(IdKey::new(Secret::new(bytes))));
        }
        slot.clone()
    }

    /// `prefix_…` of `id`.
    pub(crate) fn encode(&self, prefix: &str, id: [u8; 16]) -> Option<String> {
        self.key()?.encode(prefix, id).ok()
    }

    /// The internal id of a `prefix_…` text.
    pub(crate) fn decode(&self, prefix: &str, text: &str) -> Option<[u8; 16]> {
        self.key()?.decode(prefix, text).ok()
    }
}

impl TenantIds for CellIds {
    fn external(&self, tenant: &[u8; 16]) -> Option<String> {
        self.encode(TENANT_PREFIX, *tenant)
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        self.decode(TENANT_PREFIX, text)
    }
}

#[cfg(test)]
mod tests;
