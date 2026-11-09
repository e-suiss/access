//! The realm's protocol gateways (OP-155 m.3 (c), IDP-26, IDI-11). A gateway is registered and
//! retired by `idp.gateway.*` decisions only; the newest version is the gateway. The router role
//! names the realm of a gateway that connects with its client certificate. Nothing is deleted
//! (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId, TenantTx};
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// A live gateway as the edge channel sees it.
#[derive(Clone)]
pub struct GatewayRoute {
    /// The tenant that owns it.
    pub tenant: TenantId,
    /// Its realm.
    pub realm: RealmId,
    /// The realm's slug.
    pub slug: String,
    /// `saml`, `ldap`, `kerberos` or `radius`.
    pub kind: String,
    /// Its name.
    pub name: String,
}

/// Writes the next version of gateway `kind`/`name` under `bound`: live with `cert_sha256`, or
/// retired. Returns the version written.
///
/// # Errors
/// [`StoreError`].
pub async fn put_gateway(
    t: &mut TenantTx,
    bound: &Bound,
    kind: &str,
    name: &str,
    cert_sha256: &[u8; 32],
    live: bool,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let version = sqlx::query_scalar!(
        r#"INSERT INTO access.edge_gateways (tenant_id, realm_id, kind, name, version, state,
                cert_sha256, domain_id, decision_pos)
         SELECT $1, $2, $3, $4, COALESCE(MAX(version), 0) + 1, $5, $6, $7, $8
           FROM access.edge_gateways
          WHERE tenant_id = $1 AND realm_id = $2 AND kind = $3 AND name = $4
         RETURNING version AS "version!""#,
        tenant,
        realm,
        kind,
        name,
        if live { "live" } else { "retired" },
        cert_sha256.as_slice(),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u64::try_from(version).map_err(|_| StoreError::Corrupt)
}

/// The certificate digest of the live gateway `kind`/`name` of the realm; `None` when it was never
/// registered or is retired.
///
/// # Errors
/// [`StoreError`].
pub async fn live_gateway(
    t: &mut TenantTx,
    kind: &str,
    name: &str,
) -> Result<Option<[u8; 32]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT state, cert_sha256 FROM access.edge_gateways
          WHERE tenant_id = $1 AND realm_id = $2 AND kind = $3 AND name = $4
          ORDER BY version DESC LIMIT 1",
        tenant,
        realm,
        kind,
        name,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    match row {
        Some(r) if r.state == "live" => <[u8; 32]>::try_from(r.cert_sha256)
            .map(Some)
            .map_err(|_| StoreError::Corrupt),
        _ => Ok(None),
    }
}

/// Most gateways one certificate may name before the lookup fails closed.
const MAX_MATCHES: i64 = 2;

/// The live gateways `kind`/`name` whose newest version holds `cert_sha256`, in a live realm,
/// read by the router role. The caller accepts exactly one.
///
/// # Errors
/// [`StoreError`].
pub async fn gateway_routes(
    router: &PgPool,
    kind: &str,
    name: &str,
    cert_sha256: &[u8; 32],
) -> Result<Vec<GatewayRoute>, StoreError> {
    let rows = sqlx::query!(
        "SELECT g.tenant_id, g.realm_id, r.slug, g.kind, g.name
           FROM access.edge_gateways g
           JOIN access.realms r ON r.tenant_id = g.tenant_id AND r.realm_id = g.realm_id
          WHERE g.kind = $1 AND g.name = $2 AND g.cert_sha256 = $3 AND g.state = 'live'
            AND r.status = 'active'
            AND g.version = (SELECT MAX(n.version) FROM access.edge_gateways n
                              WHERE n.tenant_id = g.tenant_id AND n.realm_id = g.realm_id
                                AND n.kind = g.kind AND n.name = g.name)
          LIMIT $4",
        kind,
        name,
        cert_sha256.as_slice(),
        MAX_MATCHES,
    )
    .fetch_all(router)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| GatewayRoute {
            tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
            realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
            slug: r.slug,
            kind: r.kind,
            name: r.name,
        })
        .collect())
}
