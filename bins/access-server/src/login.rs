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
use suiss_crypto::envelope::{Dek, DekCache, EnvelopeError, Kek};
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

/// The token label of generation `generation` of a realm's KEK (OP-138, OP-158 m.3 (y)): the
/// first is [`kek_label`], a rotation adds `/<generation>`.
pub(crate) fn kek_label_at(realm: &[u8; 16], generation: u32) -> String {
    if generation <= 1 {
        kek_label(realm)
    } else {
        format!("{}/{generation}", kek_label(realm))
    }
}

/// The `kek_id` of generation `generation` as sealed rows record it: `access:realm-kek:<RealmID
/// hex>[:<generation>]`, the label in the alphabet the tables' checks allow.
pub(crate) fn kek_id_at(realm: &[u8; 16], generation: u32) -> String {
    kek_label_at(realm, generation).replace('/', ":")
}

/// Most KEK generations probed in the token.
const MAX_GENERATIONS: u32 = 64;

/// How long a loaded KEK set is used before the token is probed again for a newer generation
/// another process made (OP-158 m.3 (y); PD).
const REPROBE_MS: u64 = 5 * 60 * 1000;

/// The KEKs of a realm in the token, newest first: generation and key.
pub(crate) fn realm_keks(keys: &KeyStore, realm: &[u8; 16]) -> Result<Vec<(u32, HsmKek)>, String> {
    let mut out = Vec::new();
    for generation in 1..=MAX_GENERATIONS {
        match keys.kek(&kek_label_at(realm, generation)) {
            Ok(k) => out.push((generation, k)),
            Err(_) if generation > 1 => break,
            Err(e) => return Err(e.to_string()),
        }
    }
    out.reverse();
    Ok(out)
}

/// A token KEK behind a lock: a PKCS#11 session serves one caller at a time. Unwrapped DEKs
/// are kept for [`DEK_CACHE_TTL_MS`], so a sign-in does not ask the token to unwrap the same
/// subject key again (CR-32 m.2, OP-135 m.5, OP-158 m.3 (y)).
struct LockedKek {
    id: String,
    inner: Mutex<HsmKek>,
    older: Mutex<Vec<HsmKek>>,
    older_ids: Vec<String>,
    pepper: HsmAead,
    cache: Mutex<DekCache>,
    clock: fn() -> u64,
    loaded_ms: u64,
}

/// A realm's current KEK with the generations before it: wraps with the current one, opens
/// with whichever wrapped the key (AES Key Wrap checks its own integrity), so rows a rotation
/// has not reached yet still open (OP-138).
struct Generations<'a> {
    current: &'a HsmKek,
    older: &'a [HsmKek],
}

impl Kek for Generations<'_> {
    fn id(&self) -> &str {
        self.current.id()
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        self.current.wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        self.current.unwrap(wrapped).or_else(|e| {
            self.older
                .iter()
                .find_map(|k| k.unwrap(wrapped).ok())
                .ok_or(e)
        })
    }
}

/// How long an unwrapped DEK stays cached (CR-32 m.2; PD 5 minutes): a shredded key's last
/// cached copy is gone at most this long after its row was shredded.
pub(crate) const DEK_CACHE_TTL_MS: u64 = suiss_crypto::envelope::CACHE_TTL_MS;

/// How many unwrapped DEKs one realm keeps at once (CR-32 m.2; PD).
pub(crate) const DEK_CACHE_MAX: usize = 4096;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl LockedKek {
    #[cfg(test)]
    fn new(id: String, kek: HsmKek, pepper: HsmAead, clock: fn() -> u64) -> Self {
        Self::with_older(id, kek, Vec::new(), pepper, clock)
    }

    fn with_older(
        id: String,
        kek: HsmKek,
        older: Vec<(String, HsmKek)>,
        pepper: HsmAead,
        clock: fn() -> u64,
    ) -> Self {
        let (older_ids, older) = older.into_iter().unzip();
        Self {
            id,
            inner: Mutex::new(kek),
            older: Mutex::new(older),
            older_ids,
            pepper,
            cache: Mutex::new(DekCache::new(DEK_CACHE_TTL_MS, DEK_CACHE_MAX)),
            loaded_ms: clock(),
            clock,
        }
    }
}

impl Kek for LockedKek {
    fn id(&self) -> &str {
        &self.id
    }

    fn opens(&self, kek_id: &str) -> bool {
        kek_id == self.id || self.older_ids.iter().any(|i| i == kek_id)
    }

    fn wrap(&self, dek: &Dek) -> Result<Vec<u8>, EnvelopeError> {
        self.inner
            .lock()
            .map_err(|_| EnvelopeError::Wrap)?
            .wrap(dek)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Dek, EnvelopeError> {
        let mut cache = self.cache.lock().map_err(|_| EnvelopeError::Wrap)?;
        let inner = self.inner.lock().map_err(|_| EnvelopeError::Wrap)?;
        let older = self.older.lock().map_err(|_| EnvelopeError::Wrap)?;
        let all = Generations {
            current: &inner,
            older: &older,
        };
        let dek = cache.get(&all, wrapped, (self.clock)())?;
        Ok(Dek::from_secret(Secret::new(*dek.secret().expose())))
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

    fn opens(&self, kek_id: &str) -> bool {
        self.0.opens(kek_id)
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

    /// Drops the loaded KEKs of `realm`, so the next use probes the token again: after a
    /// rotation made a new generation (OP-138).
    pub(crate) fn reload(&self, realm: &[u8; 16]) {
        if let Ok(mut loaded) = self.loaded.lock() {
            loaded.remove(realm);
        }
    }

    /// The token these KEKs live in.
    pub(crate) fn token(&self) -> &KeyStore {
        &self.keys
    }

    fn get(&self, realm: &[u8; 16]) -> Result<Arc<LockedKek>, String> {
        let mut loaded = self.loaded.lock().map_err(|_| "kek cache")?;
        if let Some(k) = loaded.get(realm)
            && now_ms().saturating_sub(k.loaded_ms) < REPROBE_MS
        {
            return Ok(k.clone());
        }
        let pepper = pepper_label(realm);
        let pepper = self
            .keys
            .aead(&pepper)
            .or_else(|_| self.keys.generate_aead(&pepper))
            .map_err(|e| e.to_string())?;
        let mut generations = realm_keks(&self.keys, realm)?.into_iter();
        let (generation, current) = generations.next().ok_or("realm KEK missing")?;
        let kek = Arc::new(LockedKek::with_older(
            kek_id_at(realm, generation),
            current,
            generations.map(|(g, k)| (kek_id_at(realm, g), k)).collect(),
            pepper,
            now_ms,
        ));
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
    verified: Vec<String>,
    push: bool,
    sms: bool,
    spc: bool,
    crypto: access_store::realm_crypto::RealmCrypto,
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
    base: Option<access_identity_domain::domain::host::Base>,
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
            base: None,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    /// These kits under the deployment's realm base host, which decides what a Suiss domain is
    /// for the RP ID rule (OP-156 m.3 (i)).
    #[must_use]
    pub(crate) fn with_base(mut self, base_host: &str) -> Self {
        self.base = Some(access_identity_domain::domain::host::Base::new(base_host));
        self
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
        // OP-156 m.3 (i)
        let verified = access_store::custom_domains::verified_hosts(&mut t)
            .await
            .map_err(|_| Unavailable)?;
        // OP-156 m.3 (d)
        let push = t.push_enabled().await.map_err(|_| Unavailable)?;
        // OP-156 m.3 (f), (g)
        let sms = t.sms_otp_enabled().await.map_err(|_| Unavailable)?;
        let spc = t.spc_enabled().await.map_err(|_| Unavailable)?;
        // OP-158 m.3 (y), m.6 (b)
        let crypto = t.realm_crypto().await.map_err(|_| Unavailable)?;
        t.commit().await.map_err(|_| Unavailable)?;
        Ok(Settings {
            signin,
            rp_id,
            related,
            verified,
            push,
            sms,
            spc,
            crypto,
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
        // IDP-5, IDI-4, OP-156 m.3 (i)
        let base = self.base.clone().unwrap_or_else(|| base_of(host));
        let effective = access_identity_domain::domain::rp::effective(
            settings.rp_id.as_deref(),
            &base,
            host,
            &settings.verified,
        );
        let pinned = effective.is_some();
        let rp_id = effective
            .or_else(|| settings.rp_id.clone())
            .and_then(|r| RpId::parse(&r))
            .or_else(|| RpId::parse(host))
            .ok_or("rp id")?;
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
                pinned,
                related: settings
                    .related
                    .iter()
                    .map(|o| {
                        access_identity_webauthn::domain::rp::Origin::parse(o)
                            .ok_or("related origin")
                    })
                    .collect::<Result<_, _>>()?,
            },
            // MD-11, OP-156 m.3 (e)
            webauthn: RealmPolicy {
                platform_uv_is_factor: signin.profile.platform_uv_is_factor(),
                ..RealmPolicy::default()
            },
            auth: AuthPolicy {
                push: settings.push,
                sms: settings.sms,
                spc: settings.spc,
                ..signin.apply(AuthPolicy::DEFAULT)
            },
            lifetimes: self.lifetimes,
            signin,
            hash: hash_policy(&settings.crypto)?,
        })
    }
}

/// CR-15, CR-36, OP-158 m.3 (y), m.6 (b): the realm's password hash policy; an unknown stored
/// profile refuses the kit rather than hashing weaker.
fn hash_policy(
    c: &access_store::realm_crypto::RealmCrypto,
) -> Result<access_identity_account::domain::password::HashPolicy, String> {
    use access_identity_account::domain::password::{HashPolicy, HashProfile};
    let profile = HashProfile::parse(&c.hash_profile).ok_or("hash profile")?;
    Ok(HashPolicy::of(profile, c.fips))
}

/// The base a realm issuer host sits under when the deployment's is not given: its parent for
/// a subdomain issuer, the host itself otherwise.
fn base_of(issuer_host: &str) -> access_identity_domain::domain::host::Base {
    let parent = issuer_host
        .split_once('.')
        .map(|(_, p)| p)
        .filter(|p| p.contains('.') || *p == "localhost" || *p == "test")
        .unwrap_or(issuer_host);
    access_identity_domain::domain::host::Base::new(parent)
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

#[cfg(test)]
mod dek_cache_tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NOW: AtomicU64 = AtomicU64::new(1_000);

    fn clock() -> u64 {
        NOW.load(Ordering::SeqCst)
    }

    // CR-32, OP-135, OP-158
    #[test]
    fn a_sign_in_unwraps_a_subject_key_once_until_it_expires() {
        let (module, token) = crate::testing::hsm("dek-cache");
        let keys = KeyStore::open(
            &module,
            &token,
            &Secret::new(String::from("1234-test-only")),
        )
        .unwrap();
        let kek = keys.generate_kek("access/realm-kek/test").unwrap();
        let pepper = keys.generate_aead("access/realm-pepper/test").unwrap();
        let locked = LockedKek::new("access:realm-kek:test".into(), kek, pepper, clock);
        let dek = Dek::generate().unwrap();
        let wrapped = locked.wrap(&dek).unwrap();
        assert!(
            locked
                .unwrap(&wrapped)
                .unwrap()
                .secret()
                .ct_eq(dek.secret())
        );
        keys.destroy_kek("access/realm-kek/test").unwrap();
        assert!(
            locked
                .unwrap(&wrapped)
                .unwrap()
                .secret()
                .ct_eq(dek.secret())
        );
        NOW.fetch_add(DEK_CACHE_TTL_MS, Ordering::SeqCst);
        assert!(locked.unwrap(&wrapped).is_err());
    }
}
