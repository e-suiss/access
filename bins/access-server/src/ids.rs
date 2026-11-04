//! The cell's opaque external ids (OP-137, MD-18): the id key is derived in the HSM on first use
//! and kept. Every product-facing surface names a tenant by it (OP-149 m.15 (i)).

use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_identity_events::ports::TenantIds;
use suiss_crypto::pkcs11::KeyStore;

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
