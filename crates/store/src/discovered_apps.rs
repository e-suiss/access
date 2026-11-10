//! What discovery connectors reported (OP-156 m.4 Q20, AG-39, AG-43): one row per admitted
//! `discovered_app` Claim whose disclosed body matched its value, appended once and never changed
//! (OP-73). The `discovery` search reads it.

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// One reported access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredRow {
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The connector's Party.
    pub issuer: [u8; 16],
    /// The Party the access belongs to.
    pub subject: [u8; 16],
    /// The connected service.
    pub connector: String,
    /// The application's client id there.
    pub app: String,
    /// Its display name.
    pub name: Option<String>,
    /// Its scopes.
    pub scopes: Vec<String>,
    /// Position of the Claim's record.
    pub pos: u64,
}

/// Records `row` (sequencer role, after its Claim record committed); a Claim recorded before is
/// left as it is.
///
/// # Errors
/// [`StoreError`].
pub async fn insert(
    sequencer: &PgPool,
    domain: &DomainId,
    row: &DiscoveredRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.discovered_apps
           (domain_id, claim_id, issuer_id, subject_id, connector, app, name, scopes, pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        row.claim.as_slice(),
        row.issuer.as_slice(),
        row.subject.as_slice(),
        row.connector,
        row.app,
        row.name,
        &row.scopes,
        i64::try_from(row.pos).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The newest `limit` reported accesses, in record order.
///
/// # Errors
/// [`StoreError`].
pub async fn list(
    pool: &PgPool,
    domain: &DomainId,
    limit: u32,
) -> Result<Vec<DiscoveredRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT claim_id, issuer_id, subject_id, connector, app, name, scopes, pos
           FROM access.discovered_apps WHERE domain_id = $1
          ORDER BY pos DESC, claim_id LIMIT $2",
        domain.as_bytes().as_slice(),
        i64::from(limit),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .rev()
        .map(|r| {
            Ok(DiscoveredRow {
                claim: <[u8; 16]>::try_from(r.claim_id).map_err(|_| StoreError::Corrupt)?,
                issuer: <[u8; 16]>::try_from(r.issuer_id).map_err(|_| StoreError::Corrupt)?,
                subject: <[u8; 16]>::try_from(r.subject_id).map_err(|_| StoreError::Corrupt)?,
                connector: r.connector,
                app: r.app,
                name: r.name,
                scopes: r.scopes,
                pos: u64::try_from(r.pos).map_err(|_| StoreError::Corrupt)?,
            })
        })
        .collect()
}
