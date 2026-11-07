//! The realm authorization server's environment in this process (OP-146 I7): the realm rows
//! over the application pool, the identity signer, clients' endpoints behind the SSRF guard,
//! the hosted login's pages, and the DPoP nonce keys in the HSM (OP-146 m.7 (b)).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use access_crypto::dpop::{NonceKey, NoncePolicy, NonceRing, Role, label};
use access_identity_hooks::ports::HookCaller;
use access_identity_oauth::adapters::clients::HttpClientKeys;
use access_identity_oauth::adapters::dpop::{PgReplayCache, SystemClock};
use access_identity_oauth::adapters::oauth::{HostedPages, OsRandom, PgOAuth};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::Env;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::ports::oauth::ManagementHolders;
use access_internal_api::projections::Projections;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::pkcs11::KeyStore;

/// The nonce key generation in use; rotation adds the next one (OP-146 m.7 (b)).
pub(crate) const NONCE_GENERATION: u32 = 1;

type Rings = HashMap<([u8; 16], Role), Arc<NonceRing>>;

/// The realms' DPoP nonce keys from the HSM, loaded on a realm's first request and kept. A
/// realm without its keys answers `503` for DPoP-bound requests; the server still starts.
pub(crate) struct HsmNonces {
    keys: Arc<KeyStore>,
    policy: NoncePolicy,
    loaded: Mutex<Rings>,
}

impl HsmNonces {
    pub(crate) fn new(keys: Arc<KeyStore>) -> Self {
        Self {
            keys,
            policy: NoncePolicy::default(),
            loaded: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn ring(&self, realm: RealmId, role: Role) -> Option<Arc<NonceRing>> {
        let key = (*realm.as_bytes(), role);
        if let Some(ring) = self.loaded.lock().ok()?.get(&key) {
            return Some(ring.clone());
        }
        let mac = match self
            .keys
            .mac(&label(realm.as_bytes(), role, NONCE_GENERATION))
        {
            Ok(m) => m,
            Err(error) => {
                tracing::error!(%error, "realm DPoP nonce key unavailable");
                return None;
            }
        };
        let ring = Arc::new(NonceRing::new(
            *realm.as_bytes(),
            role,
            self.policy,
            NONCE_GENERATION,
            NonceKey::token(mac),
        ));
        self.loaded.lock().ok()?.insert(key, ring.clone());
        Some(ring)
    }
}

/// What the authorization server reaches in this process; `P` is the authority plane's token
/// projections (OP-150 m.2).
pub(crate) struct ServerEnv<P> {
    pub(crate) db: PgOAuth,
    pub(crate) signer: SignerKeys,
    pub(crate) client_keys: HttpClientKeys,
    pub(crate) directory: PgDirectory,
    pub(crate) app: Pool,
    pub(crate) nonces: HsmNonces,
    pub(crate) dpop: DpopProfile,
    pub(crate) projections: P,
    pub(crate) tenant_ids: Arc<crate::ids::CellIds>,
    /// The realms' inline hooks (TN-135): `token_issuance`.
    pub(crate) hooks: Arc<dyn HookCaller + Sync>,
    /// The authority plane's live Instance keys, for management read tokens (TN-130).
    pub(crate) management: Arc<dyn ManagementHolders + Sync>,
}

impl<P: Projections + 'static> Env for ServerEnv<P> {
    type Db = PgOAuth;
    type Signer = SignerKeys;
    type ClientKeys = HttpClientKeys;
    type Pages = HostedPages;
    type Clock = SystemClock;
    type Random = OsRandom;
    type Directory = PgDirectory;
    type Replay = PgReplayCache;
    type Projections = P;
    type Tenants = Arc<crate::ids::CellIds>;

    fn db(&self) -> &PgOAuth {
        &self.db
    }

    fn signer(&self) -> &SignerKeys {
        &self.signer
    }

    fn client_keys(&self) -> &HttpClientKeys {
        &self.client_keys
    }

    fn pages(&self) -> &HostedPages {
        &HostedPages
    }

    fn clock(&self) -> &SystemClock {
        &SystemClock
    }

    fn random(&self) -> &OsRandom {
        &OsRandom
    }

    fn directory(&self) -> &PgDirectory {
        &self.directory
    }

    fn replay(&self, tenant: TenantId, realm: RealmId) -> PgReplayCache {
        PgReplayCache::new(self.app.clone(), tenant, realm)
    }

    fn nonces(&self, realm: RealmId, role: Role) -> Option<Arc<NonceRing>> {
        self.nonces.ring(realm, role)
    }

    fn dpop(&self) -> &DpopProfile {
        &self.dpop
    }

    fn projections(&self) -> &P {
        &self.projections
    }

    fn tenant_ids(&self) -> &Arc<crate::ids::CellIds> {
        &self.tenant_ids
    }
    fn hooks(&self) -> &(dyn HookCaller + Sync) {
        &*self.hooks
    }
    fn management(&self) -> &(dyn ManagementHolders + Sync) {
        &*self.management
    }
}

/// The realms' inline hooks as this process calls them (TN-135, OP-151 m.3 (j)): live hooks
/// from the realm tables, keys opened under the realm KEKs, calls through the SSRF-guarded
/// outbound client.
pub(crate) fn hooks(
    app: Pool,
    outbound: access_identity_oauth::adapters::outbound::Outbound,
    keks: crate::login::RealmKeks,
) -> Arc<dyn HookCaller + Sync> {
    Arc::new(access_identity_hooks::app::Hooks::new(
        access_identity_hooks::adapters::PgRegistry::new(
            app,
            access_identity_events::adapters::KekSealer(keks),
        ),
        access_identity_oauth::adapters::hooks::OutboundHooks(outbound),
        access_identity_hooks::adapters::SystemClock,
    ))
}
