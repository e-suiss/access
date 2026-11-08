//! The hosted login's realm kits from the HSM (OP-94, OP-146 m.12): a realm's KEK and decoy key
//! live in the token under labels named by the realm; the cell's opaque-id key is derived in the
//! token from its root (OP-137). Kits are loaded on a realm's first sign-in and kept. The same
//! realm KEKs seal event subscriptions' webhook secrets (OP-149 m.17 (b)).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_crypto::realm_index::{RealmIndexKey, label as index_label};
use access_crypto::webauthn::{DecoyKey, decoy_label};
use access_identity_account::app::vault::Vault;
use access_identity_events::adapters::RealmKek;
use access_identity_oauth::ports::{RealmEntry, Unavailable};
use access_identity_session::domain::realm_policy::RealmSignin;
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::ports::{Kits, RealmKit};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::tenancy::realm_tenant;
use suiss_crypto::envelope::{Dek, EnvelopeError, Kek};
use suiss_crypto::pkcs11::{HsmAead, HsmKek, KeyStore};
use zeroize::Zeroizing;

/// The root of the cell's opaque-id key in the token (OP-137).
pub(crate) const ID_KEY_ROOT: &str = "access/opaque-id";
/// The derivation context of the working id key.
const ID_KEY_CONTEXT: &[u8] = b"access/opaque-id/v1";

/// The cell's working opaque-id key material (OP-137).
pub(crate) fn id_key_bytes(keys: &KeyStore) -> Result<[u8; 32], String> {
    keys.mac(ID_KEY_ROOT)
        .and_then(|m| m.mac(ID_KEY_CONTEXT))
        .map_err(|e| e.to_string())
}

/// The token label of a realm's KEK: `access/realm-kek/<RealmID hex>` (OP-146 m.15 (e)).
pub(crate) fn kek_label(realm: &[u8; 16]) -> String {
    let mut out = String::from("access/realm-kek/");
    for b in realm {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The token label of a realm's password pepper: `access/realm-pepper/<RealmID hex>` (CR-37,
/// OP-150 m.3 (f)).
pub(crate) fn pepper_label(realm: &[u8; 16]) -> String {
    kek_label(realm).replacen("realm-kek", "realm-pepper", 1)
}

/// The pepper version the token's pepper key applies; rotation adds the next.
const PEPPER_VERSION: u16 = 1;

/// The id of a realm's KEK as sealed rows record it (`kek_id`): `access:realm-kek:<RealmID
/// hex>`, the label in the alphabet the tables' checks allow.
pub(crate) fn kek_id(realm: &[u8; 16]) -> String {
    kek_label(realm).replace('/', ":")
}

/// A token KEK behind a lock: a PKCS#11 session serves one caller at a time.
struct LockedKek {
    id: String,
    inner: Mutex<HsmKek>,
    pepper: HsmAead,
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

    fn pepper(&self, context: &[u8], plaintext: &[u8]) -> Result<(u16, Vec<u8>), EnvelopeError> {
        self.pepper
            .seal(context, plaintext)
            .map(|s| (PEPPER_VERSION, s))
            .map_err(|_| EnvelopeError::Seal)
    }

    fn unpepper(
        &self,
        version: u16,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        if version != PEPPER_VERSION {
            return Err(EnvelopeError::Open);
        }
        self.pepper
            .open(context, sealed)
            .map(Zeroizing::new)
            .map_err(|_| EnvelopeError::Open)
    }
}

/// A shared [`LockedKek`].
struct SharedKek(Arc<LockedKek>);

impl Kek for SharedKek {
    fn id(&self) -> &str {
        self.0.id()
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        self.0.wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        self.0.unwrap(wrapped)
    }

    fn pepper(&self, context: &[u8], plaintext: &[u8]) -> Result<(u16, Vec<u8>), EnvelopeError> {
        self.0.pepper(context, plaintext)
    }

    fn unpepper(
        &self,
        version: u16,
        context: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
        self.0.unpepper(version, context, sealed)
    }
}

/// The realms' KEKs from the token, opened once per realm and shared by the hosted login and
/// event delivery, with each realm's PII vault index key (OP-153 m.3 (aa)).
#[derive(Clone)]
pub(crate) struct RealmKeks {
    keys: Arc<KeyStore>,
    loaded: Arc<Mutex<HashMap<[u8; 16], Arc<LockedKek>>>>,
    indexes: Arc<Mutex<HashMap<[u8; 16], Arc<RealmIndexKey>>>>,
}

impl RealmKeks {
    pub(crate) fn new(keys: Arc<KeyStore>) -> Self {
        Self {
            keys,
            loaded: Arc::new(Mutex::new(HashMap::new())),
            indexes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The realm's blind index key, made in the token on first use (OP-153 m.3 (aa)).
    fn index(&self, realm: &[u8; 16]) -> Result<Arc<RealmIndexKey>, String> {
        let mut loaded = self.indexes.lock().map_err(|_| "index cache")?;
        if let Some(k) = loaded.get(realm) {
            return Ok(k.clone());
        }
        let label = index_label(realm);
        let mac = self
            .keys
            .mac(&label)
            .or_else(|_| {
                self.keys.generate_mac(&label)?;
                self.keys.mac(&label)
            })
            .map_err(|e| e.to_string())?;
        let key = Arc::new(RealmIndexKey::token(mac));
        loaded.insert(*realm, key.clone());
        Ok(key)
    }

    /// The realm's PII vault keys: its KEK and its index key (OP-153 m.3 (aa)). `None` when the
    /// token refuses either; nothing personal is read or written then (TI-9).
    pub(crate) fn vault(&self, realm: RealmId) -> Option<Vault> {
        let kek = self.get(realm.as_bytes());
        let index = self.index(realm.as_bytes());
        match (kek, index) {
            (Ok(k), Ok(i)) => Some(Vault {
                kek: Arc::new(SharedKek(k)),
                index: i,
            }),
            (Err(error), _) | (_, Err(error)) => {
                tracing::error!(%error, "PII vault keys unavailable");
                None
            }
        }
    }

    fn get(&self, realm: &[u8; 16]) -> Result<Arc<LockedKek>, String> {
        let mut loaded = self.loaded.lock().map_err(|_| "kek cache")?;
        if let Some(k) = loaded.get(realm) {
            return Ok(k.clone());
        }
        let label = kek_label(realm);
        let pepper = pepper_label(realm);
        let pepper = self
            .keys
            .aead(&pepper)
            .or_else(|_| self.keys.generate_aead(&pepper))
            .map_err(|e| e.to_string())?;
        let kek = Arc::new(LockedKek {
            inner: Mutex::new(self.keys.kek(&label).map_err(|e| e.to_string())?),
            id: kek_id(realm),
            pepper,
        });
        loaded.insert(*realm, kek.clone());
        Ok(kek)
    }
}

impl RealmKek for RealmKeks {
    fn kek(&self, _: TenantId, realm: RealmId) -> Option<Arc<dyn Kek + Send + Sync>> {
        match self.get(realm.as_bytes()) {
            Ok(k) => Some(Arc::new(SharedKek(k))),
            Err(error) => {
                tracing::error!(%error, "realm KEK unavailable");
                None
            }
        }
    }
}

/// What a realm's settings say about its sign-in (TN-132, Ek B carry-over 3379): the stored
/// sign-in policy and the pinned RP ID. A kit is rebuilt when either changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Settings {
    signin: Option<Vec<u8>>,
    rp_id: Option<String>,
    related: Vec<String>,
}

/// A kit and the settings it was built from.
type Loaded = (Settings, Arc<RealmKit>);

/// The realm kits of this process.
pub(crate) struct HsmKits {
    keys: Arc<KeyStore>,
    keks: RealmKeks,
    router: Pool,
    app: Pool,
    lifetimes: SessionPolicy,
    loaded: Mutex<HashMap<[u8; 16], Loaded>>,
}

impl HsmKits {
    pub(crate) fn new(keks: RealmKeks, router: Pool, app: Pool, lifetimes: SessionPolicy) -> Self {
        Self {
            keys: keks.keys.clone(),
            keks,
            router,
            app,
            lifetimes,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    /// The realm's sign-in settings as they are now, read in its own scope (TN-113).
    async fn settings(&self, tenant: TenantId, realm: RealmId) -> Result<Settings, Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(|_| Unavailable)?;
        let signin = access_store::idp::realm::policies(&mut t)
            .await
            .map_err(|_| Unavailable)?
            .signin;
        let rp_id = access_store::idp::settings(&mut t)
            .await
            .map_err(|_| Unavailable)?
            .and_then(|s| s.rp_id);
        // TN-18, OP-153 m.3 (u)
        let related = access_store::idp::related_origins(&mut t)
            .await
            .map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        Ok(Settings {
            signin,
            rp_id,
            related,
        })
    }

    fn load(
        &self,
        entry: &RealmEntry,
        tenant: TenantId,
        settings: &Settings,
    ) -> Result<RealmKit, String> {
        let kek = self.keks.get(entry.realm.as_bytes())?;
        let index = self.keks.index(entry.realm.as_bytes())?;
        let decoy = self
            .keys
            .mac(&decoy_label(entry.realm.as_bytes()))
            .map_err(|e| e.to_string())?;
        let ids = id_key_bytes(&self.keys)?;
        let issuer = entry.issuer.as_str().to_owned();
        let host = entry
            .issuer
            .authority()
            .split(':')
            .next()
            .unwrap_or_default();
        let wa = WaRealm::from_bytes(*entry.realm.as_bytes());
        // TN-132, MD-8
        let signin = match &settings.signin {
            Some(bytes) => RealmSignin::decode(bytes).ok_or("sign-in policy")?,
            None => RealmSignin::default(),
        };
        // IDP-5, IDI-4
        let rp_id = match &settings.rp_id {
            Some(pinned) => RpId::parse(pinned)
                .filter(|r| r.as_str() == host || host.ends_with(&format!(".{}", r.as_str())))
                .ok_or("pinned rp id")?,
            None => RpId::parse(host).ok_or("rp id")?,
        };
        Ok(RealmKit {
            tenant,
            realm: entry.realm,
            issuer: issuer.clone(),
            name: entry.slug.clone(),
            kek: Arc::new(SharedKek(kek)),
            index,
            ids: IdKey::new(Secret::new(ids)),
            decoys: RealmDecoyKeys::default().with(wa, DecoyKey::token(decoy)),
            rp: RelyingParty {
                realm: wa,
                rp_id,
                name: entry.slug.clone(),
                pinned: true,
                related: settings
                    .related
                    .iter()
                    .map(|o| {
                        access_identity_webauthn::domain::rp::Origin::parse(o)
                            .ok_or("related origin")
                    })
                    .collect::<Result<_, _>>()?,
            },
            webauthn: RealmPolicy::default(),
            auth: signin.apply(AuthPolicy::DEFAULT),
            lifetimes: self.lifetimes,
            signin,
        })
    }
}

impl Kits for HsmKits {
    /// The realm's kit with its sign-in settings as they are now: each request reads them, and
    /// a kit built from older ones is rebuilt (TN-132).
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Unavailable> {
        let key = *entry.realm.as_bytes();
        let tenant = realm_tenant(&self.router, entry.realm)
            .await
            .map_err(|_| Unavailable)?
            .ok_or(Unavailable)?;
        let settings = self.settings(tenant, entry.realm).await?;
        if let Some((seen, kit)) = self.loaded.lock().map_err(|_| Unavailable)?.get(&key)
            && *seen == settings
        {
            return Ok(kit.clone());
        }
        let kit = Arc::new(self.load(entry, tenant, &settings).map_err(|error| {
            tracing::error!(%error, realm = %entry.slug, "realm keys unavailable");
            Unavailable
        })?);
        self.loaded
            .lock()
            .map_err(|_| Unavailable)?
            .insert(key, (settings, kit.clone()));
        Ok(kit)
    }
}
