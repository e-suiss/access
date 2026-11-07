//! Sandbox domains and the platform's metadata reads (OP-151 m.2 M2, m.3 (m), X21): which
//! governing domains are sandboxes with their template's fixed budget, and the tenant and realm
//! metadata the platform-admin surface reads across tenants. Nothing here reads realm content
//! (INV-29, X31).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::scope::DomainId;

/// A sandbox domain's fixed budget (OP-151 m.3 (m)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    /// Exercises per UTC day.
    pub exercises_per_day: u64,
    /// Projections per UTC day.
    pub projections_per_day: u64,
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// Marks the transaction realm's governing domain `domain` as a sandbox with `budget`; once
/// marked it stays so (OP-73).
///
/// # Errors
/// [`StoreError`].
pub async fn mark(t: &mut TenantTx, domain: &DomainId, budget: Budget) -> Result<(), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.sandbox_domains
           (domain_id, tenant_id, realm_id, exercises_per_day, projections_per_day)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (domain_id) DO NOTHING",
        domain.as_bytes().as_slice(),
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        signed(budget.exercises_per_day)?,
        signed(budget.projections_per_day)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The budget of the sandbox domain `domain`, read by the router role; `None` for a production
/// domain.
///
/// # Errors
/// [`StoreError`].
pub async fn budget(router: &PgPool, domain: &[u8; 32]) -> Result<Option<Budget>, StoreError> {
    let row = sqlx::query!(
        "SELECT exercises_per_day, projections_per_day FROM access.sandbox_domains
          WHERE domain_id = $1",
        domain.as_slice(),
    )
    .fetch_optional(router)
    .await?;
    row.map(|r| {
        Ok(Budget {
            exercises_per_day: unsigned(r.exercises_per_day)?,
            projections_per_day: unsigned(r.projections_per_day)?,
        })
    })
    .transpose()
}

/// A tenant's metadata (INV-29: no content).
#[derive(Clone)]
pub struct TenantMeta {
    /// The tenant.
    pub tenant: TenantId,
    /// `provisioning`, `active`, `suspended` or `deleted`.
    pub status: String,
    /// Its placement.
    pub placement: String,
    /// When it was created, Unix milliseconds.
    pub created_ms: u64,
}

/// At most `limit` tenants in id order after `after`, or the one `only`, read by the router role.
///
/// # Errors
/// [`StoreError`].
pub async fn tenants(
    router: &PgPool,
    only: Option<TenantId>,
    after: Option<TenantId>,
    limit: u32,
) -> Result<Vec<TenantMeta>, StoreError> {
    let after = Uuid::from_bytes(after.map_or([0; 16], |t| *t.as_bytes()));
    let only = only.map(|t| Uuid::from_bytes(*t.as_bytes()));
    let rows = sqlx::query!(
        r#"SELECT tenant_id, status, placement_id,
                  (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!" FROM access.tenants
            WHERE tenant_id > $1 AND ($2::uuid IS NULL OR tenant_id = $2)
            ORDER BY tenant_id LIMIT $3"#,
        after,
        only,
        i64::from(limit),
    )
    .fetch_all(router)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(TenantMeta {
                tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
                status: r.status,
                placement: r.placement_id,
                created_ms: unsigned(r.created_ms)?,
            })
        })
        .collect()
}

/// A realm's metadata (INV-29, X31: no settings, no accounts, no clients).
#[derive(Clone)]
pub struct RealmMeta {
    /// The tenant.
    pub tenant: TenantId,
    /// The realm.
    pub realm: RealmId,
    /// Its slug.
    pub slug: String,
    /// Its issuer, once set.
    pub issuer: Option<String>,
    /// Its placement.
    pub placement: String,
    /// Its governing domain.
    pub domain: [u8; 32],
    /// When it was created, Unix milliseconds.
    pub created_ms: u64,
    /// Its sandbox budget, for a sandbox realm.
    pub sandbox: Option<Budget>,
}

/// The live realms, read by the router role: the one with slug `slug`, or those of `tenant`
/// after the slug `after`, at most `limit`, in slug order; with `sandbox_only`, only sandboxes.
///
/// # Errors
/// [`StoreError`].
pub async fn realms(
    router: &PgPool,
    slug: Option<&str>,
    tenant: Option<TenantId>,
    after: Option<&str>,
    (limit, sandbox_only): (u32, bool),
) -> Result<Vec<RealmMeta>, StoreError> {
    let tenant = tenant.map(|t| Uuid::from_bytes(*t.as_bytes()));
    let rows = sqlx::query!(
        r#"SELECT r.tenant_id, r.realm_id, r.slug, r.issuer, r.placement_id, r.governing_domain_id,
                  (extract(epoch FROM r.created_at) * 1000)::bigint AS "created_ms!",
                  s.exercises_per_day AS "exercises_per_day?",
                  s.projections_per_day AS "projections_per_day?"
             FROM access.realms r
             LEFT JOIN access.sandbox_domains s ON s.domain_id = r.governing_domain_id
            WHERE r.status = 'active'
              AND ($1::text IS NULL OR r.slug = $1)
              AND ($2::uuid IS NULL OR r.tenant_id = $2)
              AND r.slug > coalesce($3, '')
              AND (NOT $4 OR s.domain_id IS NOT NULL)
            ORDER BY r.slug LIMIT $5"#,
        slug,
        tenant,
        after,
        sandbox_only,
        i64::from(limit),
    )
    .fetch_all(router)
    .await?;
    rows.into_iter()
        .map(|r| {
            let sandbox = match (r.exercises_per_day, r.projections_per_day) {
                (Some(e), Some(p)) => Some(Budget {
                    exercises_per_day: unsigned(e)?,
                    projections_per_day: unsigned(p)?,
                }),
                _ => None,
            };
            Ok(RealmMeta {
                tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
                realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
                slug: r.slug,
                issuer: r.issuer,
                placement: r.placement_id,
                domain: <[u8; 32]>::try_from(r.governing_domain_id.as_slice())
                    .map_err(|_| StoreError::Corrupt)?,
                created_ms: unsigned(r.created_ms)?,
                sandbox,
            })
        })
        .collect()
}

/// Creates the tenant `tenant` in `placement` when it does not exist; `false` when it did.
///
/// # Errors
/// [`StoreError`].
pub async fn create_tenant(
    app: &PgPool,
    tenant: TenantId,
    placement: &str,
) -> Result<bool, StoreError> {
    let mut t = TenantTx::begin_tenant(app, tenant).await?;
    let done = sqlx::query!(
        "INSERT INTO access.tenants (tenant_id, placement_id, status) VALUES ($1, $2, 'active')
         ON CONFLICT (tenant_id) DO NOTHING",
        Uuid::from_bytes(*tenant.as_bytes()),
        placement,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    t.commit().await?;
    Ok(done == 1)
}
