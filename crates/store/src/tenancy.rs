//! Tenants, realms and their hostnames (TN-1, TN-6, MD-5, OP-132): the identity plane's
//! scope rows. Internal ids are `UUIDv7` from the server (MD-18); nothing is deleted, deleted
//! rows keep their identifiers so they are never reused (INV-32, OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::scope::DomainId;

/// Hostname kind (§12.3.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostKind {
    /// Under the provider's domain.
    Subdomain,
    /// The customer's own domain.
    Custom,
}

impl HostKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Subdomain => "subdomain",
            Self::Custom => "custom",
        }
    }
}

/// Creates a tenant in `placement` and returns its id. The id is drawn first so the row is
/// inserted under its own scope (OP-12).
///
/// # Errors
/// [`StoreError`].
pub async fn create_tenant(app: &PgPool, placement: &str) -> Result<TenantId, StoreError> {
    let id = sqlx::query_scalar!(r#"SELECT uuidv7() AS "id!""#)
        .fetch_one(app)
        .await?;
    let tenant = TenantId::from_bytes(*id.as_bytes());
    let mut t = TenantTx::begin_tenant(app, tenant).await?;
    sqlx::query!(
        "INSERT INTO access.tenants (tenant_id, placement_id, status) VALUES ($1, $2, 'active')",
        id,
        placement,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(tenant)
}

/// Creates a realm governed by `domain`, which must belong to the same tenant (MD-5a).
///
/// # Errors
/// [`StoreError`]; a slug already taken, now or by a deleted realm, fails (TN-16, INV-32).
pub async fn create_realm(
    t: &mut TenantTx,
    domain: &DomainId,
    slug: &str,
    placement: &str,
) -> Result<RealmId, StoreError> {
    let id = sqlx::query_scalar!(
        r#"INSERT INTO access.realms (tenant_id, governing_domain_id, slug, placement_id)
           VALUES ($1, $2, $3, $4) RETURNING realm_id AS "id!""#,
        Uuid::from_bytes(*t.tenant.as_bytes()),
        domain.as_bytes().as_slice(),
        slug,
        placement,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(RealmId::from_bytes(*id.as_bytes()))
}

/// Soft-deletes a realm and its hostnames; the realm id and slug stay taken (INV-32).
///
/// # Errors
/// [`StoreError`].
pub async fn delete_realm(t: &mut TenantTx, realm: RealmId) -> Result<bool, StoreError> {
    let tenant = Uuid::from_bytes(*t.tenant.as_bytes());
    let realm = Uuid::from_bytes(*realm.as_bytes());
    let done = sqlx::query!(
        "UPDATE access.realms SET status = 'deleted', deleted_at = now()
          WHERE tenant_id = $1 AND realm_id = $2 AND status <> 'deleted'",
        tenant,
        realm,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Adds a hostname to the transaction's realm.
///
/// # Errors
/// [`StoreError`]; a hostname live elsewhere fails (TN-20).
pub async fn add_hostname(
    t: &mut TenantTx,
    hostname: &str,
    kind: HostKind,
) -> Result<(), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    sqlx::query!(
        "INSERT INTO access.realm_hostnames (tenant_id, realm_id, hostname, kind) VALUES ($1, $2, $3, $4)",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        hostname,
        kind.name(),
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Soft-deletes the transaction realm's hostname, freeing it for others (DNS is a lease,
/// §12.3.8).
///
/// # Errors
/// [`StoreError`].
pub async fn remove_hostname(t: &mut TenantTx, hostname: &str) -> Result<bool, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.realm_hostnames SET status = 'deleted', deleted_at = now()
          WHERE tenant_id = $1 AND realm_id = $2 AND hostname = $3 AND status = 'active'",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        hostname,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Sets the issuer of the transaction's realm, once: an issuer already set never changes
/// (TN-16, §17.9.6). Returns whether this call set it.
///
/// # Errors
/// [`StoreError`]; a malformed issuer, or a different one than already set, fails.
pub async fn set_issuer(t: &mut TenantTx, issuer: &str) -> Result<bool, StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.realms SET issuer = $3
          WHERE tenant_id = $1 AND realm_id = $2 AND issuer IS NULL",
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
        issuer,
    )
    .execute(&mut *t.tx)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// A live realm as the router serves it: its slug and the issuer stored on its row.
#[derive(Clone)]
pub struct RealmRoute {
    /// The realm.
    pub realm: RealmId,
    /// Its slug.
    pub slug: String,
    /// Its issuer.
    pub issuer: String,
}

/// The live realm with an issuer whose live hostname is `hostname`, read by the router role
/// (OP-132 m.3). The hostname is compared in lower case.
///
/// # Errors
/// [`StoreError`].
pub async fn route_by_host(
    router: &PgPool,
    hostname: &str,
) -> Result<Option<RealmRoute>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT r.realm_id, r.slug, r.issuer AS "issuer!" FROM access.realm_hostnames h
             JOIN access.realms r ON r.tenant_id = h.tenant_id AND r.realm_id = h.realm_id
            WHERE h.hostname = lower($1) AND h.status = 'active' AND r.status = 'active'
              AND r.issuer IS NOT NULL"#,
        hostname,
    )
    .fetch_optional(router)
    .await?;
    Ok(row.map(|r| RealmRoute {
        realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
        slug: r.slug,
        issuer: r.issuer,
    }))
}

/// The live realm with an issuer whose slug is `slug`, read by the router role (path
/// issuers, TN-10).
///
/// # Errors
/// [`StoreError`].
pub async fn route_by_slug(router: &PgPool, slug: &str) -> Result<Option<RealmRoute>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT realm_id, slug, issuer AS "issuer!" FROM access.realms
            WHERE slug = $1 AND status = 'active' AND issuer IS NOT NULL"#,
        slug,
    )
    .fetch_optional(router)
    .await?;
    Ok(row.map(|r| RealmRoute {
        realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
        slug: r.slug,
        issuer: r.issuer,
    }))
}

/// Every live realm with an issuer, read by the router role (start-up checks, §17.9.7).
///
/// # Errors
/// [`StoreError`].
pub async fn routes(router: &PgPool) -> Result<Vec<RealmRoute>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT realm_id, slug, issuer AS "issuer!" FROM access.realms
            WHERE status = 'active' AND issuer IS NOT NULL ORDER BY slug"#,
    )
    .fetch_all(router)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| RealmRoute {
            realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
            slug: r.slug,
            issuer: r.issuer,
        })
        .collect())
}

/// The tenant of the live realm `realm`, read by the router role (OP-132 m.3): the identity
/// plane loads a realm's keys after the router has resolved it.
///
/// # Errors
/// [`StoreError`].
pub async fn realm_tenant(router: &PgPool, realm: RealmId) -> Result<Option<TenantId>, StoreError> {
    let row = sqlx::query_scalar!(
        "SELECT tenant_id FROM access.realms WHERE realm_id = $1 AND status = 'active'",
        Uuid::from_bytes(*realm.as_bytes()),
    )
    .fetch_optional(router)
    .await?;
    Ok(row.map(|t| TenantId::from_bytes(*t.as_bytes())))
}

/// The live realm a request's `Host` names, read by the router role (OP-132 m.3). The
/// hostname is compared in lower case.
///
/// # Errors
/// [`StoreError`].
pub async fn resolve_host(
    router: &PgPool,
    hostname: &str,
) -> Result<Option<(TenantId, RealmId)>, StoreError> {
    let row = sqlx::query!(
        r#"SELECT h.tenant_id, h.realm_id FROM access.realm_hostnames h
             JOIN access.realms r ON r.tenant_id = h.tenant_id AND r.realm_id = h.realm_id
            WHERE h.hostname = lower($1) AND h.status = 'active' AND r.status = 'active'"#,
        hostname,
    )
    .fetch_optional(router)
    .await?;
    Ok(row.map(|r| {
        (
            TenantId::from_bytes(*r.tenant_id.as_bytes()),
            RealmId::from_bytes(*r.realm_id.as_bytes()),
        )
    }))
}
