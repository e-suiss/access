//! The realm's replay cache in the cell's PostgreSQL (TN-30, OP-129 m.5, OP-146 m.5 (f)).

use std::future::Future;

use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};

use crate::ports::dpop::{CacheUnavailable, ReplayCache};

/// The replay cache of one realm; each key is committed before the request goes on, so a
/// later failure of the request does not free the proof for reuse.
#[derive(Clone)]
pub struct PgReplayCache {
    pool: Pool,
    tenant: TenantId,
    realm: RealmId,
}

impl PgReplayCache {
    /// The cache of `realm` in `tenant`, over the application pool.
    #[must_use]
    pub const fn new(pool: Pool, tenant: TenantId, realm: RealmId) -> Self {
        Self {
            pool,
            tenant,
            realm,
        }
    }
}

impl ReplayCache for PgReplayCache {
    fn first_use(
        &self,
        day: u32,
        key: [u8; 32],
    ) -> impl Future<Output = Result<bool, CacheUnavailable>> + Send {
        let pool = self.pool.clone();
        let (tenant, realm) = (self.tenant, self.realm);
        async move {
            let mut tx = TenantTx::begin(&pool, tenant, realm)
                .await
                .map_err(|_| CacheUnavailable)?;
            let fresh = tx
                .dpop_first_use(day, &key)
                .await
                .map_err(|_| CacheUnavailable)?;
            tx.commit().await.map_err(|_| CacheUnavailable)?;
            Ok(fresh)
        }
    }
}
