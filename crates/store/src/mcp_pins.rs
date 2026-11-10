//! The tool lists pinned for proxies in MCP mode (OP-156 m.3 (n), AG-42). A list is written by
//! `idp.proxy.mcp_pin` decisions only; the newest version is the list. Nothing is deleted
//! (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

/// The newest pinned list of a proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinsRow {
    /// The version.
    pub version: u64,
    /// The tools, as their JSON body.
    pub tools: String,
    /// The decision that wrote it.
    pub position: u64,
}

/// Writes the next pinned list of proxy `proxy` under `bound`. Returns the version written.
///
/// # Errors
/// [`StoreError`].
pub async fn put_pins(
    t: &mut TenantTx,
    bound: &Bound,
    proxy: &str,
    tools: &str,
) -> Result<u64, StoreError> {
    let (tenant, realm) = scope(t)?;
    let version = sqlx::query_scalar!(
        r#"INSERT INTO access.mcp_tool_pins (tenant_id, realm_id, proxy, version, tools,
                domain_id, decision_pos)
         SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6
           FROM access.mcp_tool_pins
          WHERE tenant_id = $1 AND realm_id = $2 AND proxy = $3
         RETURNING version AS "version!""#,
        tenant,
        realm,
        proxy,
        tools,
        bound.domain().as_bytes().as_slice(),
        bound.position,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    u64::try_from(version).map_err(|_| StoreError::Corrupt)
}

/// The newest pinned list of proxy `proxy`; `None` when none was ever pinned.
///
/// # Errors
/// [`StoreError`].
pub async fn pins(t: &mut TenantTx, proxy: &str) -> Result<Option<PinsRow>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT version, tools, decision_pos FROM access.mcp_tool_pins
          WHERE tenant_id = $1 AND realm_id = $2 AND proxy = $3
          ORDER BY version DESC LIMIT 1",
        tenant,
        realm,
        proxy,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(PinsRow {
            version: u64::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
            tools: r.tools,
            position: u64::try_from(r.decision_pos).map_err(|_| StoreError::Corrupt)?,
        })
    })
    .transpose()
}
