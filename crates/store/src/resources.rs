//! Resource incarnations (OP-156 m.3 (k), INV-32, §7.9.10.4): the lifecycle facts a domain
//! product declared with admitted `resource_lifecycle` Claims, appended once and never changed
//! (OP-73). Claim Ingest refuses a create or reincarnate at or below the highest incarnation
//! seen for the resource.

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

/// One admitted lifecycle fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncarnationRow {
    /// The resource's namespace.
    pub namespace: String,
    /// Its path.
    pub path: Vec<String>,
    /// The incarnation the fact is about.
    pub incarnation: u64,
    /// `create`, `delete` or `reincarnate`.
    pub event: String,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The Claim's issuer, the domain product.
    pub issuer: [u8; 16],
    /// Position of its `claim` record.
    pub pos: u64,
}

/// Records an admitted lifecycle fact (sequencer role, after its Claim record committed); a
/// Claim recorded before is left as it is.
///
/// # Errors
/// [`StoreError`].
pub async fn insert_incarnation(
    sequencer: &PgPool,
    domain: &DomainId,
    row: &IncarnationRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.resource_incarnations
           (domain_id, namespace, path, incarnation, event, claim_id, issuer_id, pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        row.namespace,
        &row.path,
        signed(row.incarnation)?,
        row.event,
        row.claim.as_slice(),
        row.issuer.as_slice(),
        signed(row.pos)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The highest incarnation any recorded fact names for the resource; `None` when there is none.
///
/// # Errors
/// [`StoreError`].
pub async fn highest_incarnation(
    pool: &PgPool,
    domain: &DomainId,
    namespace: &str,
    path: &[String],
) -> Result<Option<u64>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let max = sqlx::query_scalar!(
        "SELECT max(incarnation) FROM access.resource_incarnations
          WHERE domain_id = $1 AND namespace = $2 AND path = $3",
        domain.as_bytes().as_slice(),
        namespace,
        path,
    )
    .fetch_one(&mut *t.tx)
    .await?;
    t.commit().await?;
    max.map(unsigned).transpose()
}

/// Every recorded fact of the resource, in record order.
///
/// # Errors
/// [`StoreError`].
pub async fn incarnations(
    pool: &PgPool,
    domain: &DomainId,
    namespace: &str,
    path: &[String],
) -> Result<Vec<IncarnationRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT namespace, path, incarnation, event, claim_id, issuer_id, pos
           FROM access.resource_incarnations
          WHERE domain_id = $1 AND namespace = $2 AND path = $3
          ORDER BY pos, claim_id",
        domain.as_bytes().as_slice(),
        namespace,
        path,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(IncarnationRow {
                namespace: r.namespace,
                path: r.path,
                incarnation: unsigned(r.incarnation)?,
                event: r.event,
                claim: <[u8; 16]>::try_from(r.claim_id.as_slice())
                    .map_err(|_| StoreError::Corrupt)?,
                issuer: <[u8; 16]>::try_from(r.issuer_id.as_slice())
                    .map_err(|_| StoreError::Corrupt)?,
                pos: unsigned(r.pos)?,
            })
        })
        .collect()
}
