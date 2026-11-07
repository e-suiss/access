//! Adapters: live hooks from PostgreSQL through `access-store`, keys opened under the realm
//! KEK. The HTTPS transport is the identity plane's outbound client
//! (`access_identity_oauth::adapters::hooks`).

use access_crypto::webhook::{WebhookSecret, WebhookSigningKey};
use access_store::Pool;
use access_store::extensions::live_hook;
use access_store::identity::{RealmId, TenantId, TenantTx};

use crate::domain::{Disclosure, HookPoint, OnNoAnswer, Registration, Signing};
use crate::ports::{HookKey, HookRegistry, KeyVault, LiveHook, Unavailable};

/// The live hooks of `access_app`, with keys opened by `K`.
pub struct PgRegistry<K> {
    app: Pool,
    keys: K,
}

impl<K: KeyVault> PgRegistry<K> {
    /// A registry over the `access_app` pool.
    pub const fn new(app: Pool, keys: K) -> Self {
        Self { app, keys }
    }
}

fn down<E>(_: E) -> Unavailable {
    Unavailable
}

impl<K: KeyVault> HookRegistry for PgRegistry<K> {
    async fn live(
        &self,
        tenant: TenantId,
        realm: RealmId,
        point: HookPoint,
    ) -> Result<Option<LiveHook>, Unavailable> {
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        let row = live_hook(&mut t, point.name()).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let raw = self.keys.open(tenant, realm, &row.id, &row.key)?;
        let key = match Signing::from_name(&row.signing).ok_or(Unavailable)? {
            Signing::Ed25519 => HookKey::Ed25519(WebhookSigningKey::from_seed(&raw).map_err(down)?),
            Signing::Hmac => HookKey::Hmac(WebhookSecret::from_bytes(raw.to_vec()).map_err(down)?),
        };
        Ok(Some(LiveHook {
            registration: Registration {
                id: row.id,
                point,
                url: row.url,
                on_no_answer: OnNoAnswer::from_name(&row.on_no_answer).ok_or(Unavailable)?,
                disclose: row
                    .disclose
                    .iter()
                    .map(|d| Disclosure::from_name(d).ok_or(Unavailable))
                    .collect::<Result<_, _>>()?,
            },
            key,
            realm_allows_disclosure: false,
        }))
    }
}
