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

/// Writes the next version of `RadSec` client `client` of RADIUS gateway `gateway` under
/// `bound`, with the SHA-256 of its TLS certificate (OP-155 m.3 (f)). Returns the version.
///
/// # Errors
/// [`StoreError`].
pub async fn put_radius_client(
    t: &mut TenantTx,
    bound: &Bound,
    gateway: &str,
    client: &str,
    cert_sha256: &[u8; 32],
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let version = sqlx::query_scalar!(
        r#"INSERT INTO access.edge_radius_clients (tenant_id, realm_id, gateway, client, version,
                cert_sha256, domain_id, decision_pos)
         SELECT $1, $2, $3, $4, COALESCE(MAX(version), 0) + 1, $5, $6, $7
           FROM access.edge_radius_clients
          WHERE tenant_id = $1 AND realm_id = $2 AND gateway = $3 AND client = $4
         RETURNING version AS "version!""#,
        tenant,
        realm,
        gateway,
        client,
        cert_sha256.as_slice(),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u64::try_from(version).map_err(|_| StoreError::Corrupt)
}

/// Whether a client of RADIUS gateway `gateway` holds, in its newest version, the certificate
/// whose SHA-256 is `cert_sha256`.
///
/// # Errors
/// [`StoreError`].
pub async fn radius_client_registered(
    t: &mut TenantTx,
    gateway: &str,
    cert_sha256: &[u8; 32],
) -> Result<bool, StoreError> {
    let (tenant, realm) = scope(t)?;
    let found = sqlx::query_scalar!(
        r#"SELECT EXISTS (
             SELECT 1 FROM access.edge_radius_clients c
              WHERE c.tenant_id = $1 AND c.realm_id = $2 AND c.gateway = $3 AND c.cert_sha256 = $4
                AND c.version = (SELECT MAX(n.version) FROM access.edge_radius_clients n
                                  WHERE n.tenant_id = c.tenant_id AND n.realm_id = c.realm_id
                                    AND n.gateway = c.gateway AND n.client = c.client)
           ) AS "found!""#,
        tenant,
        realm,
        gateway,
        cert_sha256.as_slice(),
    )
    .fetch_one(&mut *t.tx)
    .await?;
    Ok(found)
}

/// A Kerberos gateway's keytab policy (OP-155 m.3 (o)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeytabPolicy {
    /// The one service principal accepted, `service/host@REALM`.
    pub spn: String,
    /// Days between keytab rotations.
    pub rotate_days: u16,
    /// The lowest key version still accepted.
    pub kvno_floor: u32,
}

/// Writes the next version of gateway `gateway`'s keytab policy under `bound`.
///
/// # Errors
/// [`StoreError`].
pub async fn put_keytab_policy(
    t: &mut TenantTx,
    bound: &Bound,
    gateway: &str,
    p: &KeytabPolicy,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let version = sqlx::query_scalar!(
        r#"INSERT INTO access.edge_keytab_policies (tenant_id, realm_id, gateway, version, spn,
                rotate_days, kvno_floor, domain_id, decision_pos)
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8
           FROM access.edge_keytab_policies
          WHERE tenant_id = $1 AND realm_id = $2 AND gateway = $3
         RETURNING version AS "version!""#,
        tenant,
        realm,
        gateway,
        p.spn,
        i32::from(p.rotate_days),
        i64::from(p.kvno_floor),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u64::try_from(version).map_err(|_| StoreError::Corrupt)
}

/// The newest keytab policy of gateway `gateway`; `None` when it has none.
///
/// # Errors
/// [`StoreError`].
pub async fn keytab_policy(
    t: &mut TenantTx,
    gateway: &str,
) -> Result<Option<KeytabPolicy>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT spn, rotate_days, kvno_floor FROM access.edge_keytab_policies
          WHERE tenant_id = $1 AND realm_id = $2 AND gateway = $3
          ORDER BY version DESC LIMIT 1",
        tenant,
        realm,
        gateway,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(KeytabPolicy {
            spn: r.spn,
            rotate_days: u16::try_from(r.rotate_days).map_err(|_| StoreError::Corrupt)?,
            kvno_floor: u32::try_from(r.kvno_floor).map_err(|_| StoreError::Corrupt)?,
        })
    })
    .transpose()
}

/// Records that gateway `gateway` accepted a ticket under key version `kvno` at `at_ms`, once,
/// and returns every key version seen with when it was first seen, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn seen_kvno(
    t: &mut TenantTx,
    gateway: &str,
    kvno: u32,
    at_ms: u64,
) -> Result<Vec<(u32, u64)>, StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.edge_keytab_kvnos (tenant_id, realm_id, gateway, kvno, first_seen_ms)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (tenant_id, realm_id, gateway, kvno) DO NOTHING",
        tenant,
        realm,
        gateway,
        i64::from(kvno),
        i64::try_from(at_ms).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    let rows = sqlx::query!(
        "SELECT kvno, first_seen_ms FROM access.edge_keytab_kvnos
          WHERE tenant_id = $1 AND realm_id = $2 AND gateway = $3
          ORDER BY kvno",
        tenant,
        realm,
        gateway,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok((
                u32::try_from(r.kvno).map_err(|_| StoreError::Corrupt)?,
                u64::try_from(r.first_seen_ms).map_err(|_| StoreError::Corrupt)?,
            ))
        })
        .collect()
}
