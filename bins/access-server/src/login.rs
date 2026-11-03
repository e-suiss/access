//! The hosted login's realm kits from the HSM (OP-94, OP-146 m.12): a realm's KEK and decoy key
//! live in the token under labels named by the realm; the cell's opaque-id key is derived in the
//! token from its root (OP-137). Kits are loaded on a realm's first sign-in and kept.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_crypto::webauthn::DecoyKey;
use access_identity_oauth::ports::{RealmEntry, Unavailable};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::ports::{Kits, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_store::Pool;
use access_store::tenancy::realm_tenant;
use suiss_crypto::envelope::{Dek, EnvelopeError, Kek};
use suiss_crypto::pkcs11::{HsmKek, KeyStore};

/// The root of the cell's opaque-id key in the token (OP-137).
const ID_KEY_ROOT: &str = "access/opaque-id";
/// The derivation context of the working id key.
const ID_KEY_CONTEXT: &[u8] = b"access/opaque-id/v1";

/// A token KEK behind a lock: a PKCS#11 session serves one caller at a time.
struct LockedKek {
    id: String,
    inner: Mutex<HsmKek>,
}

impl Kek for LockedKek {
    fn id(&self) -> &str {
        &self.id
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        self.inner
            .lock()
            .map_err(|_| EnvelopeError::Wrap)?
            .wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        self.inner
            .lock()
            .map_err(|_| EnvelopeError::Wrap)?
            .unwrap(wrapped)
    }
}

/// The realm kits of this process.
pub(crate) struct HsmKits {
    keys: KeyStore,
    router: Pool,
    lifetimes: SessionPolicy,
    loaded: Mutex<HashMap<[u8; 16], Arc<RealmKit>>>,
}

impl HsmKits {
    pub(crate) fn new(keys: KeyStore, router: Pool, lifetimes: SessionPolicy) -> Self {
        Self {
            keys,
            router,
            lifetimes,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    fn load(
        &self,
        entry: &RealmEntry,
        tenant: access_store::identity::TenantId,
    ) -> Result<RealmKit, String> {
        let mut hex = String::with_capacity(32);
        for b in entry.realm.as_bytes() {
            let _ = write!(hex, "{b:02x}");
        }
        let label = format!("access/realm-kek/{hex}");
        let kek = self.keys.kek(&label).map_err(|e| e.to_string())?;
        let decoy = self
            .keys
            .mac(&format!("access/webauthn-decoy/{hex}"))
            .map_err(|e| e.to_string())?;
        let ids = self
            .keys
            .mac(ID_KEY_ROOT)
            .and_then(|m| m.mac(ID_KEY_CONTEXT))
            .map_err(|e| e.to_string())?;
        let issuer = entry.issuer.as_str().to_owned();
        let host = entry
            .issuer
            .authority()
            .split(':')
            .next()
            .unwrap_or_default();
        let wa = WaRealm::from_bytes(*entry.realm.as_bytes());
        Ok(RealmKit {
            tenant,
            realm: entry.realm,
            issuer: issuer.clone(),
            name: entry.slug.clone(),
            kek: Box::new(LockedKek {
                id: label,
                inner: Mutex::new(kek),
            }),
            ids: IdKey::new(Secret::new(ids)),
            decoys: RealmDecoyKeys::default().with(wa, DecoyKey::token(decoy)),
            rp: RelyingParty {
                realm: wa,
                rp_id: RpId::parse(host).ok_or("rp id")?,
                name: entry.slug.clone(),
                pinned: true,
                related: Vec::new(),
            },
            webauthn: RealmPolicy::default(),
            auth: AuthPolicy::DEFAULT,
            lifetimes: self.lifetimes,
        })
    }
}

impl Kits for HsmKits {
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Unavailable> {
        let key = *entry.realm.as_bytes();
        if let Some(kit) = self.loaded.lock().map_err(|_| Unavailable)?.get(&key) {
            return Ok(kit.clone());
        }
        let tenant = realm_tenant(&self.router, entry.realm)
            .await
            .map_err(|_| Unavailable)?
            .ok_or(Unavailable)?;
        let kit = Arc::new(self.load(entry, tenant).map_err(|error| {
            tracing::error!(%error, realm = %entry.slug, "realm keys unavailable");
            Unavailable
        })?);
        self.loaded
            .lock()
            .map_err(|_| Unavailable)?
            .insert(key, kit.clone());
        Ok(kit)
    }
}
