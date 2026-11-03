//! The realm's replay cache in the cell's PostgreSQL (TN-30, OP-129 m.5, OP-146 m.5 (f)), and
//! the host's clock.

use std::future::Future;
use std::time::{SystemTime, UNIX_EPOCH};

use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};

use crate::ports::dpop::{CacheUnavailable, Clock, ClockUnavailable, ReplayCache};

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

/// The host's clock; a clock before the Unix epoch is unavailable, never zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, ClockUnavailable> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| u64::try_from(d.as_millis()).ok())
            .ok_or(ClockUnavailable)
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
