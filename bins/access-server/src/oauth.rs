//! The realm authorization server's environment in this process (OP-146 I7): the realm rows
//! over the application pool, the identity signer, clients' endpoints behind the SSRF guard,
//! the hosted login's pages, and the DPoP nonce keys in the HSM (OP-146 m.7 (b)).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use access_crypto::dpop::{NonceKey, NoncePolicy, NonceRing, Role, label};
use access_identity_hooks::ports::HookCaller;
use access_identity_oauth::adapters::cimd::HttpClientDocuments;
use access_identity_oauth::adapters::clients::HttpClientKeys;
use access_identity_oauth::adapters::dpop::{PgReplayCache, SystemClock};
use access_identity_oauth::adapters::oauth::{HostedPages, OsRandom, PgOAuth};
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::Env;
use access_identity_oauth::domain::dpop::DpopProfile;
use access_identity_oauth::ports::oauth::{ClaimSource, ClientDocuments, Held, ManagementHolders};
use access_internal_api::projections::Projections;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::pkcs11::KeyStore;

/// The nonce key generation a new realm is provisioned with (OP-146 m.7 (b)); later ones follow
/// the clock ([`NONCE_ROTATION_MS`]).
pub(crate) const NONCE_GENERATION: u32 = 1;

/// How long one nonce key generation issues (TN-29, MD-18, OP-158 m.3 (y); PD): every process
/// derives the generation from the clock, so all of them rotate together without talking.
pub(crate) const NONCE_ROTATION_MS: u64 = 24 * 60 * 60 * 1000;

type Rings = HashMap<([u8; 16], Role), (u32, Arc<NonceRing>)>;

/// The generation in force at `now_ms`; never below [`NONCE_GENERATION`].
pub(crate) fn nonce_generation(now_ms: u64) -> u32 {
    let g = now_ms.checked_div(NONCE_ROTATION_MS).unwrap_or(0);
    u32::try_from(g)
        .unwrap_or(u32::MAX)
        .max(NONCE_GENERATION.saturating_add(1))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The realms' DPoP nonce keys from the HSM, loaded on a realm's first request and kept. The
/// current generation issues and the previous one is still accepted, so a rotation never
/// rejects a nonce issued just before it (TN-29); older generations are retired. A realm
/// without its keys answers `503` for DPoP-bound requests; the server still starts.
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
        self.ring_at(realm, role, now_ms())
    }

    /// The ring of the generation in force at `now_ms`, rebuilt when the generation moved.
    pub(crate) fn ring_at(
        &self,
        realm: RealmId,
        role: Role,
        now_ms: u64,
    ) -> Option<Arc<NonceRing>> {
        let key = (*realm.as_bytes(), role);
        let generation = nonce_generation(now_ms);
        if let Some((g, ring)) = self.loaded.lock().ok()?.get(&key)
            && *g == generation
        {
            return Some(ring.clone());
        }
        let ring = match self.rotated(realm.as_bytes(), role, generation) {
            Ok(ring) => Arc::new(ring),
            Err(error) => {
                tracing::error!(%error, "realm DPoP nonce key unavailable");
                return None;
            }
        };
        self.loaded
            .lock()
            .ok()?
            .insert(key, (generation, ring.clone()));
        Some(ring)
    }

    /// TN-29, OP-158 m.3 (y): `generation` issues, the one before it is accepted, and older ones
    /// are retired from the token once no process at a neighbouring generation needs them.
    fn rotated(
        &self,
        realm: &[u8; 16],
        role: Role,
        generation: u32,
    ) -> Result<NonceRing, suiss_crypto::pkcs11::HsmError> {
        // OP-146 m.7 (b)
        drop(self.keys.mac(&label(realm, role, NONCE_GENERATION))?);
        let previous = generation.saturating_sub(1);
        let mut ring = NonceRing::new(
            *realm,
            role,
            self.policy,
            previous,
            NonceKey::token(self.keys.shared_mac(&label(realm, role, previous))?),
        );
        ring.rotate(
            generation,
            NonceKey::token(self.keys.shared_mac(&label(realm, role, generation))?),
        );
        if let Some(retired) = generation.checked_sub(3)
            && retired > NONCE_GENERATION
        {
            let _ = self.keys.retire_secret(&label(realm, role, retired));
        }
        Ok(ring)
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
    /// What accounts hold to release as identity claims, under the realms' PII vaults.
    pub(crate) claims: Arc<dyn ClaimSource + Sync>,
    /// CIMD documents and logos behind the SSRF guard (OP-154 m.3 (i)).
    pub(crate) documents: HttpClientDocuments,
    /// The authority plane's accepted assertion issuers (OP-154 m.3 (m), (q)).
    pub(crate) issuers: Arc<dyn access_identity_oauth::ports::oauth::AssertionIssuers + Sync>,
    /// The realms' SPIFFE bundles behind the SSRF guard (OP-154 m.3 (r)).
    pub(crate) bundles: Arc<dyn access_identity_attest::ports::Bundles + Sync>,
    /// Which trust domains the authority plane accepts (OP-154 m.3 (r)).
    pub(crate) workload_trust: Arc<dyn access_identity_oauth::ports::oauth::WorkloadTrust + Sync>,
    /// Whether a consent record's Grant stands, read from the authority plane (P58, EI-18).
    pub(crate) standing: Arc<dyn access_identity_oauth::ports::oauth::GrantStanding + Sync>,
    /// Mutual TLS client certificates: the realm's CAs, their Acceptance and revocation
    /// (RFC 8705 §2.1, OP-155 m.3 (k), (m)).
    pub(crate) client_certificates:
        Arc<dyn access_identity_oauth::ports::profile::ClientCertificates + Sync>,
    /// CIBA's invitations, openings, free hints and pings (OP-155 m.3 (l)).
    pub(crate) ciba: Arc<dyn access_identity_oauth::ports::oauth::CibaServices + Sync>,
    /// The operator's IP-range → country list for the device page, or none (OP-155 m.3 (l)).
    pub(crate) geo: Arc<dyn access_identity_oauth::ports::oauth::GeoLookup + Sync>,
    /// SAML 2.0 bearer assertions of accepted SAML upstreams, read in the parser worker (OP-155
    /// m.3 (h), (k)).
    pub(crate) saml: Arc<dyn access_identity_oauth::ports::profile::SamlAssertions + Sync>,
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

    fn saml_assertions(
        &self,
    ) -> &(dyn access_identity_oauth::ports::profile::SamlAssertions + Sync) {
        &*self.saml
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
    fn claims(&self) -> &(dyn ClaimSource + Sync) {
        &*self.claims
    }
    fn documents(&self) -> &(dyn ClientDocuments + Sync) {
        &self.documents
    }
    fn issuers(&self) -> &(dyn access_identity_oauth::ports::oauth::AssertionIssuers + Sync) {
        &*self.issuers
    }
    fn bundles(&self) -> &(dyn access_identity_attest::ports::Bundles + Sync) {
        &*self.bundles
    }
    fn workload_trust(&self) -> &(dyn access_identity_oauth::ports::oauth::WorkloadTrust + Sync) {
        &*self.workload_trust
    }
    fn ciba(&self) -> &(dyn access_identity_oauth::ports::oauth::CibaServices + Sync) {
        &*self.ciba
    }

    fn geo(&self) -> &(dyn access_identity_oauth::ports::oauth::GeoLookup + Sync) {
        &*self.geo
    }

    fn standing(&self) -> &(dyn access_identity_oauth::ports::oauth::GrantStanding + Sync) {
        &*self.standing
    }
    fn client_certificates(
        &self,
    ) -> &(dyn access_identity_oauth::ports::profile::ClientCertificates + Sync) {
        &*self.client_certificates
    }
}

/// The identity claims accounts hold (§10.4.6, OP-153 m.3 (l)), read under each realm's PII
/// vault; a realm whose vault keys are unavailable releases nothing and the token waits (TI-9).
pub(crate) struct VaultClaims {
    pub(crate) app: Pool,
    pub(crate) keks: crate::login::RealmKeks,
}

impl ClaimSource for VaultClaims {
    fn held(
        &self,
        tenant: TenantId,
        realm: RealmId,
        subject: [u8; 16],
    ) -> Held<'_, access_identity_oauth::domain::claims_request::Held> {
        Box::pin(async move {
            use access_identity_oauth::domain::claims_request::{Held as Claims, SUPPORTED};
            use access_identity_oauth::ports::Unavailable;
            let vault = self.keks.vault(realm).ok_or(Unavailable)?;
            let mut t = access_store::identity::TenantTx::begin(&self.app, tenant, realm)
                .await
                .map_err(|_| Unavailable)?;
            let (email, fields) =
                access_identity_account::app::vault::held_claims(&mut t, &vault, subject)
                    .await
                    .map_err(|_| Unavailable)?;
            t.commit().await.map_err(|_| Unavailable)?;
            let profile = fields
                .into_iter()
                .filter_map(|(name, value)| {
                    SUPPORTED
                        .iter()
                        .find(|s| **s == name.as_str())
                        .map(|s| (*s, value))
                })
                .collect();
            Ok(Claims {
                proven_email: email,
                profile,
            })
        })
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

#[cfg(test)]
mod nonce_tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;
    use access_crypto::Secret;
    use access_crypto::dpop::NonceError;

    fn store(module: &std::path::Path, label: &str) -> Arc<KeyStore> {
        Arc::new(
            KeyStore::open(module, label, &Secret::new(String::from("1234-test-only"))).unwrap(),
        )
    }

    // TN-29, MD-18, OP-158
    #[test]
    fn nonce_keys_rotate_with_the_clock_and_processes_agree() {
        let (module, token) = crate::testing::hsm("dpop-rotation");
        let keys = store(&module, &token);
        let (a, b) = (
            HsmNonces::new(keys.clone()),
            HsmNonces::new(store(&module, &token)),
        );
        let realm = RealmId::from_bytes([7; 16]);
        let role = Role::AuthorizationServer;
        assert!(a.ring_at(realm, role, 0).is_none());
        keys.generate_mac(&label(realm.as_bytes(), role, NONCE_GENERATION))
            .unwrap();
        let boundary = 20_000 * NONCE_ROTATION_MS;
        let before = boundary - 1_000;
        let after = boundary + 1_000;

        let old = a.ring_at(realm, role, before).unwrap();
        let issued = old.issue(before).unwrap();
        b.ring_at(realm, role, before)
            .unwrap()
            .check(Some(&issued), before)
            .unwrap();

        let new = b.ring_at(realm, role, after).unwrap();
        new.check(Some(&issued), after).unwrap();
        let fresh = new.issue(after).unwrap();
        assert_ne!(fresh, issued);
        a.ring_at(realm, role, after)
            .unwrap()
            .check(Some(&fresh), after)
            .unwrap();

        let later = boundary + NONCE_ROTATION_MS + 1_000;
        let ring = a.ring_at(realm, role, later).unwrap();
        let stale = ring.check(Some(&issued), later);
        assert!(matches!(
            stale,
            Err(NonceError::UnknownKey | NonceError::Expired)
        ));
        assert!(matches!(
            ring.check(Some(&issued), after),
            Err(NonceError::UnknownKey)
        ));

        let retired = label(realm.as_bytes(), role, nonce_generation(before) - 1);
        let _ = a
            .ring_at(realm, role, boundary + 2 * NONCE_ROTATION_MS + 1_000)
            .unwrap();
        assert_eq!(keys.retire_secret(&retired).unwrap(), 0);
    }

    // TN-29
    #[test]
    fn the_generation_follows_the_clock() {
        assert_eq!(nonce_generation(0), NONCE_GENERATION + 1);
        assert_eq!(nonce_generation(20_000 * NONCE_ROTATION_MS), 20_000);
        assert_eq!(nonce_generation(20_001 * NONCE_ROTATION_MS - 1), 20_000);
        assert_eq!(nonce_generation(u64::MAX), u32::MAX);
    }
}
