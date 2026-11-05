//! Claim Ingest's tables (CMP-8, OP-150 m.2): the day's submission digests (protocol-ephemeral,
//! OP-146 m.5 (f)), the quarantined Claims by record, and the issuer quota notices (G44,
//! §16.7). The Claims themselves are `claim` records in the authority log.

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn day_of(day: u32) -> Result<i32, StoreError> {
    i32::try_from(day).map_err(|_| StoreError::Range)
}

/// Records the digest of a submission received on `day` (days since the Unix epoch): `true` the
/// first time, `false` for a resubmission. A day without an open partition is an error and the
/// submission is refused.
///
/// # Errors
/// [`StoreError`].
pub async fn first_submission(
    app: &PgPool,
    domain: &DomainId,
    day: u32,
    hash: &[u8; 32],
    carrier: &str,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.claim_ingest (domain_id, day, submission_hash, carrier)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        day_of(day)?,
        hash.as_slice(),
        carrier,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// Opens the submission partition of `day` (archive role); idempotent.
///
/// # Errors
/// [`StoreError`].
pub async fn open_claim_ingest_day(archive: &PgPool, day: u32) -> Result<String, StoreError> {
    Ok(sqlx::query_scalar!(
        r#"SELECT access.open_claim_ingest_day($1) AS "name!""#,
        day_of(day)?,
    )
    .fetch_one(archive)
    .await?)
}

/// A quarantined Claim (L2-CLM-3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineRow {
    /// Position of its `claim` record.
    pub pos: u64,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// Its issuer.
    pub issuer: [u8; 16],
    /// Its class.
    pub class: String,
    /// `source-not-accepted`, `future` or `quota`.
    pub reason: String,
}

/// Indexes a quarantined Claim (sequencer role, after its record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_quarantine(
    sequencer: &PgPool,
    domain: &DomainId,
    row: &QuarantineRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.claim_quarantine (domain_id, pos, claim_id, issuer_id, class, reason)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(row.pos)?,
        row.claim.as_slice(),
        row.issuer.as_slice(),
        row.class,
        row.reason,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

fn id16(v: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// The quarantine records of `claim`, oldest first.
///
/// # Errors
/// [`StoreError`].
pub async fn quarantined(
    pool: &PgPool,
    domain: &DomainId,
    claim: &[u8; 16],
) -> Result<Vec<QuarantineRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let rows = sqlx::query!(
        "SELECT pos, claim_id, issuer_id, class, reason FROM access.claim_quarantine
          WHERE domain_id = $1 AND claim_id = $2 ORDER BY pos",
        domain.as_bytes().as_slice(),
        claim.as_slice(),
    )
    .fetch_all(&mut *t.tx)
    .await?;
    t.commit().await?;
    rows.into_iter()
        .map(|r| {
            Ok(QuarantineRow {
                pos: u64::try_from(r.pos).map_err(|_| StoreError::Corrupt)?,
                claim: id16(&r.claim_id)?,
                issuer: id16(&r.issuer_id)?,
                class: r.class,
                reason: r.reason,
            })
        })
        .collect()
}

/// Records that `issuer` reached its quota in the window starting at `window_start_ms`
/// (sequencer role): `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn quota_reached(
    sequencer: &PgPool,
    domain: &DomainId,
    issuer: &[u8; 16],
    window_start_ms: u64,
    window_s: u32,
    pos: u64,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.issuer_quota (domain_id, issuer_id, window_start_ms, window_s, reached_pos)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        issuer.as_slice(),
        signed(window_start_ms)?,
        i32::try_from(window_s).map_err(|_| StoreError::Range)?,
        signed(pos)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// Marks the notice for the issuer's window as sent (§16.7): `true` the first time.
///
/// # Errors
/// [`StoreError`].
pub async fn quota_notified(
    app: &PgPool,
    domain: &DomainId,
    issuer: &[u8; 16],
    window_start_ms: u64,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(app, domain).await?;
    let done = sqlx::query!(
        "UPDATE access.issuer_quota SET notified_at = now()
          WHERE domain_id = $1 AND issuer_id = $2 AND window_start_ms = $3 AND notified_at IS NULL",
        domain.as_bytes().as_slice(),
        issuer.as_slice(),
        signed(window_start_ms)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The bytes a record kept as a proof under `digest` (§9.13): a Claim, or a Claim body by its
/// digest.
///
/// # Errors
/// [`StoreError`].
pub async fn proof(
    pool: &PgPool,
    domain: &DomainId,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let bytes = sqlx::query_scalar!(
        "SELECT bytes FROM access.proof_store WHERE domain_id = $1 AND digest = $2",
        domain.as_bytes().as_slice(),
        digest.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(bytes)
}
