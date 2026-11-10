//! The realm's forward-auth proxies and their browser sessions (OP-156 m.3 (l), IDP-30, B22).
//! A proxy is registered, changed and retired by `idp.proxy.*` decisions only; the newest
//! version is the proxy. The router role names the realm of a proxy by its transport identity
//! and application host. A sign-in is taken once; a session ends. Nothing is deleted (OP-73).

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

/// One version of a proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRow {
    /// Its name.
    pub name: String,
    /// The version.
    pub version: u64,
    /// Whether it is live.
    pub live: bool,
    /// The registration, as its JSON body.
    pub body: String,
    /// Whether the plain identity headers are on.
    pub plain_headers: bool,
    /// The decision that wrote it.
    pub position: u64,
}

/// What one version of a proxy says.
#[derive(Clone, Copy, Debug)]
pub struct NewProxy<'a> {
    /// Its name.
    pub name: &'a str,
    /// Whether it is live.
    pub live: bool,
    /// `nginx`, `traefik`, `caddy` or `envoy`.
    pub engine: &'a str,
    /// The application host.
    pub host: &'a str,
    /// The transport identity.
    pub pep: &'a str,
    /// The registration, as its JSON body.
    pub body: &'a str,
    /// Whether the plain identity headers are on.
    pub plain_headers: bool,
}

/// A proxy as the check finds it.
#[derive(Clone)]
pub struct ProxyRoute {
    /// The tenant that owns it.
    pub tenant: TenantId,
    /// Its realm.
    pub realm: RealmId,
    /// The realm's slug.
    pub slug: String,
    /// Its name.
    pub name: String,
}

/// Writes the next version of proxy `p.name` under `bound`. Returns the version written.
///
/// # Errors
/// [`StoreError`].
pub async fn put_proxy(
    t: &mut TenantTx,
    bound: &Bound,
    p: &NewProxy<'_>,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let version = sqlx::query_scalar!(
        r#"INSERT INTO access.proxy_registrations (tenant_id, realm_id, name, version, state,
                engine, host, pep, body, plain_headers, domain_id, decision_pos)
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9, $10, $11
           FROM access.proxy_registrations
          WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
         RETURNING version AS "version!""#,
        tenant,
        realm,
        p.name,
        if p.live { "live" } else { "retired" },
        p.engine,
        p.host,
        p.pep,
        p.body,
        p.plain_headers,
        bound.domain().as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u64::try_from(version).map_err(|_| StoreError::Corrupt)
}

/// The newest version of every proxy of the realm, by name.
///
/// # Errors
/// [`StoreError`].
pub async fn proxies(t: &mut TenantTx) -> Result<Vec<ProxyRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT DISTINCT ON (name) name, version, state, body, plain_headers, decision_pos
           FROM access.proxy_registrations
          WHERE tenant_id = $1 AND realm_id = $2
          ORDER BY name, version DESC",
        tenant,
        realm,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(ProxyRow {
                name: r.name,
                version: u64::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
                live: r.state == "live",
                body: r.body,
                plain_headers: r.plain_headers,
                position: u64::try_from(r.decision_pos).map_err(|_| StoreError::Corrupt)?,
            })
        })
        .collect()
}

/// The newest version of proxy `name`; `None` when it was never registered.
///
/// # Errors
/// [`StoreError`].
pub async fn proxy(t: &mut TenantTx, name: &str) -> Result<Option<ProxyRow>, StoreError> {
    Ok(proxies(t).await?.into_iter().find(|p| p.name == name))
}

/// Most proxies one transport identity and host may name before the lookup fails closed.
const MAX_MATCHES: i64 = 2;

/// The live proxies whose newest version holds transport identity `pep` for application host
/// `host`, in a live realm, read by the router role. The caller accepts exactly one.
///
/// # Errors
/// [`StoreError`].
pub async fn proxy_routes(
    router: &PgPool,
    pep: &str,
    host: &str,
) -> Result<Vec<ProxyRoute>, StoreError> {
    let rows = sqlx::query!(
        "SELECT p.tenant_id, p.realm_id, r.slug, p.name
           FROM access.proxy_registrations p
           JOIN access.realms r ON r.tenant_id = p.tenant_id AND r.realm_id = p.realm_id
          WHERE p.pep = $1 AND p.host = $2 AND p.state = 'live' AND r.status = 'active'
            AND p.version = (SELECT MAX(n.version) FROM access.proxy_registrations n
                              WHERE n.tenant_id = p.tenant_id AND n.realm_id = p.realm_id
                                AND n.name = p.name)
          LIMIT $3",
        pep,
        host,
        MAX_MATCHES,
    )
    .fetch_all(router)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| ProxyRoute {
            tenant: TenantId::from_bytes(*r.tenant_id.as_bytes()),
            realm: RealmId::from_bytes(*r.realm_id.as_bytes()),
            slug: r.slug,
            name: r.name,
        })
        .collect())
}

/// Keeps a sign-in of proxy `proxy` under the digest of its state.
///
/// # Errors
/// [`StoreError`].
pub async fn begin_sign_in(
    t: &mut TenantTx,
    proxy: &str,
    digest: &[u8; 32],
    (verifier, return_to): (&str, &str),
    (created_ms, expires_ms): (u64, u64),
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.proxy_sessions (tenant_id, realm_id, proxy, kind, digest, verifier,
                return_to, created_ms, expires_ms)
         VALUES ($1, $2, $3, 'sign_in', $4, $5, $6, $7, $8)",
        tenant,
        realm,
        proxy,
        digest.as_slice(),
        verifier,
        return_to,
        i64::try_from(created_ms).map_err(|_| StoreError::Range)?,
        i64::try_from(expires_ms).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// Takes the sign-in of `proxy` under `digest` at `now_ms`, once and before it expires: its PKCE
/// verifier and where the browser returns.
///
/// # Errors
/// [`StoreError`].
pub async fn take_sign_in(
    t: &mut TenantTx,
    proxy: &str,
    digest: &[u8; 32],
    now_ms: u64,
) -> Result<Option<(String, String)>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let now = i64::try_from(now_ms).map_err(|_| StoreError::Range)?;
    let row = sqlx::query!(
        r#"UPDATE access.proxy_sessions SET used_ms = $5
          WHERE tenant_id = $1 AND realm_id = $2 AND kind = 'sign_in' AND digest = $3
            AND proxy = $4 AND used_ms IS NULL AND ended_ms IS NULL AND expires_ms > $5
         RETURNING verifier AS "verifier!", return_to AS "return_to!""#,
        tenant,
        realm,
        digest.as_slice(),
        proxy,
        now,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|r| (r.verifier, r.return_to)))
}

/// Opens a session of `proxy` under the digest of its cookie, on the OAuth grant `sid`.
///
/// # Errors
/// [`StoreError`].
pub async fn open_session(
    t: &mut TenantTx,
    proxy: &str,
    digest: &[u8; 32],
    sid: &[u8; 16],
    (created_ms, expires_ms): (u64, u64),
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.proxy_sessions (tenant_id, realm_id, proxy, kind, digest, sid,
                created_ms, expires_ms)
         VALUES ($1, $2, $3, 'session', $4, $5, $6, $7)",
        tenant,
        realm,
        proxy,
        digest.as_slice(),
        sid.as_slice(),
        i64::try_from(created_ms).map_err(|_| StoreError::Range)?,
        i64::try_from(expires_ms).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The OAuth grant behind the live session of `proxy` under `digest` at `now_ms`.
///
/// # Errors
/// [`StoreError`].
pub async fn session(
    t: &mut TenantTx,
    proxy: &str,
    digest: &[u8; 32],
    now_ms: u64,
) -> Result<Option<[u8; 16]>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let now = i64::try_from(now_ms).map_err(|_| StoreError::Range)?;
    let sid = sqlx::query_scalar!(
        r#"SELECT sid AS "sid!" FROM access.proxy_sessions
          WHERE tenant_id = $1 AND realm_id = $2 AND kind = 'session' AND digest = $3
            AND proxy = $4 AND ended_ms IS NULL AND expires_ms > $5"#,
        tenant,
        realm,
        digest.as_slice(),
        proxy,
        now,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    sid.map(|s| <[u8; 16]>::try_from(s.as_slice()).map_err(|_| StoreError::Corrupt))
        .transpose()
}

/// Ends every live session of `proxy` at `now_ms`, as its retirement does; how many ended.
///
/// # Errors
/// [`StoreError`].
pub async fn end_sessions(t: &mut TenantTx, proxy: &str, now_ms: u64) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let now = i64::try_from(now_ms).map_err(|_| StoreError::Range)?;
    let done = sqlx::query!(
        "UPDATE access.proxy_sessions SET ended_ms = $4
          WHERE tenant_id = $1 AND realm_id = $2 AND proxy = $3 AND ended_ms IS NULL",
        tenant,
        realm,
        proxy,
        now,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(done.rows_affected())
}
