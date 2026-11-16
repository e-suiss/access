//! Sandbox domains and the platform's metadata reads (OP-151 m.2 M2, m.3 (m), X21): which
//! governing domains are sandboxes with their template's fixed budget, and the tenant and environment
//! metadata the platform-admin surface reads. The router role pages through the mapping only
//! (OP-132 m.3); each tenant's metadata is read by the app role in that tenant's scope. Nothing
//! here reads environment content (INV-29, X31).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{EnvironmentId, TenantId, TenantTx};
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

/// Marks the transaction environment's governing domain `domain` as a sandbox with `budget`; once
/// marked it stays so (OP-73).
///
/// # Errors
/// [`StoreError`].
pub async fn mark(t: &mut TenantTx, domain: &DomainId, budget: Budget) -> Result<(), StoreError> {
    let environment = t.environment().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.sandbox_domains
           (domain_id, tenant_id, environment_id, exercises_per_day, projections_per_day)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (domain_id) DO NOTHING",
        domain.as_bytes().as_slice(),
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*environment.as_bytes()),
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

/// At most `limit` tenants in id order after `after`, or the one `only`: the router role pages
/// through the ids (OP-132 m.3: the mapping only), and the app role reads each tenant's own
/// metadata in its scope.
///
/// # Errors
/// [`StoreError`].
pub async fn tenants(
    (router, app): (&PgPool, &PgPool),
    only: Option<TenantId>,
    after: Option<TenantId>,
    limit: u32,
) -> Result<Vec<TenantMeta>, StoreError> {
    let after = Uuid::from_bytes(after.map_or([0; 16], |t| *t.as_bytes()));
    let only = only.map(|t| Uuid::from_bytes(*t.as_bytes()));
    let ids = sqlx::query!(
        r#"SELECT tenant_id, status FROM access.tenants
            WHERE tenant_id > $1 AND ($2::uuid IS NULL OR tenant_id = $2)
            ORDER BY tenant_id LIMIT $3"#,
        after,
        only,
        i64::from(limit),
    )
    .fetch_all(router)
    .await?;
    let mut out = Vec::with_capacity(ids.len());
    for r in ids {
        let tenant = TenantId::from_bytes(*r.tenant_id.as_bytes());
        let mut t = TenantTx::begin_tenant(app, tenant).await?;
        let own = sqlx::query!(
            r#"SELECT placement_id, (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!"
                 FROM access.tenants WHERE tenant_id = $1"#,
            r.tenant_id,
        )
        .fetch_one(&mut *t.tx)
        .await?;
        t.commit().await?;
        out.push(TenantMeta {
            tenant,
            status: r.status,
            placement: own.placement_id,
            created_ms: unsigned(own.created_ms)?,
        });
    }
    Ok(out)
}

/// An environment's metadata (INV-29, X31: no settings, no accounts, no clients).
#[derive(Clone)]
pub struct EnvironmentMeta {
    /// The tenant.
    pub tenant: TenantId,
    /// The environment.
    pub environment: EnvironmentId,
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
    /// Its sandbox budget, for a sandbox environment.
    pub sandbox: Option<Budget>,
    /// Its hybrid key share policy, `optimistic` or `advertise-only` (CR-12 m.3, OP-159 m.3 (t)).
    pub kex_share: String,
    /// `standard` or `management` (TN-138).
    pub kind: String,
}

/// The live environments: the one with slug `slug`, or those of `tenant` after the slug `after`, at
/// most `limit`, in slug order; with `sandbox_only`, only the tenant's sandboxes. The router role
/// reads the mapping (OP-132 m.3); the app role reads each environment's metadata in its tenant's
/// scope.
///
/// # Errors
/// [`StoreError`]; [`StoreError::Range`] for `sandbox_only` without a tenant.
pub async fn environments(
    (router, app): (&PgPool, &PgPool),
    slug: Option<&str>,
    tenant: Option<TenantId>,
    after: Option<&str>,
    (limit, sandbox_only): (u32, bool),
) -> Result<Vec<EnvironmentMeta>, StoreError> {
    let only: Option<Vec<Uuid>> = if sandbox_only {
        let tenant = tenant.ok_or(StoreError::Range)?;
        let mut t = TenantTx::begin_tenant(app, tenant).await?;
        let ids = sqlx::query_scalar!(
            "SELECT environment_id FROM access.sandbox_domains WHERE tenant_id = $1",
            Uuid::from_bytes(*tenant.as_bytes()),
        )
        .fetch_all(&mut *t.tx)
        .await?;
        t.commit().await?;
        Some(ids)
    } else {
        None
    };
    let rows = sqlx::query!(
        r#"SELECT tenant_id, environment_id, slug, issuer FROM access.environments
            WHERE status = 'active'
              AND ($1::text IS NULL OR slug = $1)
              AND ($2::uuid IS NULL OR tenant_id = $2)
              AND slug > coalesce($3, '')
              AND ($4::uuid[] IS NULL OR environment_id = ANY($4))
            ORDER BY slug LIMIT $5"#,
        slug,
        tenant.map(|t| Uuid::from_bytes(*t.as_bytes())),
        after,
        only.as_deref(),
        i64::from(limit),
    )
    .fetch_all(router)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let tenant = TenantId::from_bytes(*r.tenant_id.as_bytes());
        let mut t = TenantTx::begin_tenant(app, tenant).await?;
        let own = sqlx::query!(
            r#"SELECT r.placement_id, r.governing_domain_id, r.kex_share, r.kind,
                      (extract(epoch FROM r.created_at) * 1000)::bigint AS "created_ms!",
                      s.exercises_per_day AS "exercises_per_day?",
                      s.projections_per_day AS "projections_per_day?"
                 FROM access.environments r
                 LEFT JOIN access.sandbox_domains s ON s.domain_id = r.governing_domain_id
                WHERE r.tenant_id = $1 AND r.environment_id = $2"#,
            r.tenant_id,
            r.environment_id,
        )
        .fetch_one(&mut *t.tx)
        .await?;
        t.commit().await?;
        let sandbox = match (own.exercises_per_day, own.projections_per_day) {
            (Some(e), Some(p)) => Some(Budget {
                exercises_per_day: unsigned(e)?,
                projections_per_day: unsigned(p)?,
            }),
            _ => None,
        };
        out.push(EnvironmentMeta {
            tenant,
            environment: EnvironmentId::from_bytes(*r.environment_id.as_bytes()),
            slug: r.slug,
            issuer: r.issuer,
            placement: own.placement_id,
            domain: <[u8; 32]>::try_from(own.governing_domain_id.as_slice())
                .map_err(|_| StoreError::Corrupt)?,
            created_ms: unsigned(own.created_ms)?,
            sandbox,
            kex_share: own.kex_share,
            kind: own.kind,
        });
    }
    Ok(out)
}

/// Creates `tenant` in `placement` awaiting its founder (OP-159 m.47 (c), TN-141): `false` when it
/// exists.
///
/// # Errors
/// [`StoreError`].
pub async fn create_tenant_provisioning(
    app: &PgPool,
    tenant: TenantId,
    placement: &str,
) -> Result<bool, StoreError> {
    let mut t = TenantTx::begin_tenant(app, tenant).await?;
    let done = sqlx::query!(
        "INSERT INTO access.tenants (tenant_id, placement_id, status) VALUES ($1, $2, 'provisioning')
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
