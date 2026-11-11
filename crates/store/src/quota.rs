//! Layer B quota counters (OP-158 m.3 (v), T27, TN-24, OP-35, MD-8): exact GCRA counters per
//! tenant, realm and domain in PostgreSQL, drawn all or none under a row lock. A refusal writes
//! nothing; a failure is an error the caller refuses on, never an admission.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::idp::Bound;
use crate::scope::{DomainId, DomainTx};

/// A GCRA limit: units per second sustained and the burst.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rate {
    /// Units per second; at least 1 and at most 1 000 000.
    pub per_second: u32,
    /// Units at once; at least 1.
    pub burst: u32,
}

impl Rate {
    fn interval_us(self) -> Result<i64, StoreError> {
        let per_second = i64::from(self.per_second);
        if !(1..=1_000_000).contains(&per_second) || self.burst == 0 {
            return Err(StoreError::Range);
        }
        1_000_000_i64
            .checked_div(per_second)
            .ok_or(StoreError::Range)
    }
}

/// Which counter refused a widening commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitRefusal {
    /// The tenant is on billing hold (TN-1, B10).
    Suspended,
    /// The tenant's commit quota.
    Tenant,
    /// The domain's commit quota.
    Domain,
}

/// Which counter refused an identity request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestRefusal {
    /// The tenant's request quota.
    Tenant,
    /// The realm's `rate_limit_rps`.
    Realm,
}

fn micros(now_ms: u64) -> Result<i64, StoreError> {
    i64::try_from(now_ms)
        .ok()
        .and_then(|ms| ms.checked_mul(1_000))
        .ok_or(StoreError::Range)
}

/// Draws one widening commit of `domain` at `now_ms` from its tenant's and its own commit
/// quota; `None` when admitted.
///
/// # Errors
/// [`StoreError`]; the caller refuses the commit.
pub async fn take_commit(
    pool: &PgPool,
    domain: &DomainId,
    now_ms: u64,
    tenant: Rate,
    own: Rate,
) -> Result<Option<CommitRefusal>, StoreError> {
    let limit = |r: Rate| Ok::<_, StoreError>(vec![r.interval_us()?, i64::from(r.burst)]);
    let mut t = DomainTx::begin(pool, domain).await?;
    let refused = sqlx::query_scalar!(
        "SELECT access.commit_quota($1, $2, $3, $4)",
        domain.as_bytes().as_slice(),
        micros(now_ms)?,
        &limit(tenant)?,
        &limit(own)?,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    match refused.as_deref() {
        None => Ok(None),
        Some("suspended") => Ok(Some(CommitRefusal::Suspended)),
        Some("tenant") => Ok(Some(CommitRefusal::Tenant)),
        Some("domain") => Ok(Some(CommitRefusal::Domain)),
        Some(_) => Err(StoreError::Corrupt),
    }
}

/// What one identity request drew.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestTaken {
    /// The refusing counter; `None` when admitted.
    pub refused: Option<RequestRefusal>,
    /// The highest share of a burst in use after the draw, percent; 100 when refused.
    pub used_percent: u8,
}

/// Draws one identity request of `realm` at `now_ms` from its tenant's request quota and the
/// realm's `rate_limit_rps` (`default_rps` until one is set); bursts are `burst_s` seconds of
/// each rate.
///
/// # Errors
/// [`StoreError`]; the caller refuses the request.
pub async fn take_request(
    pool: &PgPool,
    (tenant, realm): (TenantId, RealmId),
    now_ms: u64,
    (default_rps, tenant_rps): (u32, u32),
    burst_s: u32,
) -> Result<RequestTaken, StoreError> {
    let int = |v: u32| i32::try_from(v).map_err(|_| StoreError::Range);
    let r = sqlx::query!(
        "SELECT refused, used FROM access.realm_quota($1, $2, $3, $4, $5, $6)",
        Uuid::from_bytes(*tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        micros(now_ms)?,
        int(default_rps)?,
        int(tenant_rps)?,
        int(burst_s)?,
    )
    .fetch_one(pool)
    .await?;
    let refused = match r.refused.as_deref() {
        None => None,
        Some("tenant") => Some(RequestRefusal::Tenant),
        Some("realm") => Some(RequestRefusal::Realm),
        Some(_) => return Err(StoreError::Corrupt),
    };
    let used = r.used.ok_or(StoreError::Corrupt)?;
    Ok(RequestTaken {
        refused,
        used_percent: u8::try_from(used.clamp(0, 100)).map_err(|_| StoreError::Corrupt)?,
    })
}

/// Writes the next version of the realm's `rate_limit_rps` (`idp.realm.rate_limit`).
///
/// # Errors
/// [`StoreError`].
pub async fn put_rate_limit(t: &mut TenantTx, bound: &Bound, rps: u32) -> Result<(), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.realm_rate_limits (tenant_id, realm_id, version, rps, domain_id, decision_pos)
         SELECT $1, $2,
                COALESCE((SELECT max(version) FROM access.realm_rate_limits
                           WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                $3, $4, $5",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        i32::try_from(rps).map_err(|_| StoreError::Range)?,
        bound.domain().as_bytes().as_slice(),
        bound.raw_position(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The realm's `rate_limit_rps` in force, `None` while the product default applies.
///
/// # Errors
/// [`StoreError`].
pub async fn rate_limit(t: &mut TenantTx) -> Result<Option<u32>, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let rps = sqlx::query_scalar!(
        "SELECT rps FROM access.realm_rate_limits
          WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    rps.map(|r| u32::try_from(r).map_err(|_| StoreError::Corrupt))
        .transpose()
}

/// Puts the tenant on billing hold or lifts it (TN-1, B10): a held tenant's widening commits are
/// refused as a protocol rejection; narrowing, export, handover and recovery stay open. A tenant
/// that is not active or held is left as it is.
///
/// # Errors
/// [`StoreError`].
pub async fn set_billing_hold(
    pool: &PgPool,
    tenant: TenantId,
    held: bool,
) -> Result<bool, StoreError> {
    let mut t = TenantTx::begin_tenant(pool, tenant).await?;
    let n = sqlx::query!(
        "UPDATE access.tenants SET status = CASE WHEN $2 THEN 'suspended' ELSE 'active' END
          WHERE tenant_id = $1 AND status IN ('active', 'suspended')",
        Uuid::from_bytes(*tenant.as_bytes()),
        held,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.tx.commit().await?;
    Ok(n == 1)
}
