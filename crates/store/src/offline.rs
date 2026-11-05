//! Offline verification records (§9.12.1, §9.12.2): recorded Offline Exercise Reports with
//! their chain, so the next report of a projection can be checked against the last head
//! (L2-RPT-2), and recorded Verifier Profile bodies by digest.

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn bytes<const N: usize>(v: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One recorded report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRow {
    /// Position of its `claim` record.
    pub pos: u64,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The projection's `ExerciseID`.
    pub exercise: [u8; 32],
    /// The head it continues; `None` for the first.
    pub previous: Option<[u8; 32]>,
    /// Its first sequence number.
    pub first_seq: u64,
    /// The next report's first sequence number.
    pub next_seq: u64,
    /// Its chain head.
    pub head: [u8; 32],
    /// Period start, milliseconds.
    pub period_from_ms: u64,
    /// Period end, milliseconds.
    pub period_until_ms: u64,
    /// The report body.
    pub body: Vec<u8>,
}

/// Records a report (sequencer role, after its Claim record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_report(
    sequencer: &PgPool,
    domain: &DomainId,
    r: &ReportRow,
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.offline_report
           (domain_id, pos, claim_id, exercise_id, previous, first_seq, next_seq, head,
            period_from_ms, period_until_ms, body)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(r.pos)?,
        r.claim.as_slice(),
        r.exercise.as_slice(),
        r.previous.as_ref().map(<[u8; 32]>::as_slice),
        signed(r.first_seq)?,
        signed(r.next_seq)?,
        r.head.as_slice(),
        signed(r.period_from_ms)?,
        signed(r.period_until_ms)?,
        r.body,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The report of the projection `exercise` with the highest first sequence number.
///
/// # Errors
/// [`StoreError`].
pub async fn last_report(
    pool: &PgPool,
    domain: &DomainId,
    exercise: &[u8; 32],
) -> Result<Option<ReportRow>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT pos, claim_id, exercise_id, previous, first_seq, next_seq, head, period_from_ms,
                period_until_ms, body
           FROM access.offline_report
          WHERE domain_id = $1 AND exercise_id = $2 ORDER BY first_seq DESC, pos DESC LIMIT 1",
        domain.as_bytes().as_slice(),
        exercise.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        Ok(ReportRow {
            pos: unsigned(r.pos)?,
            claim: bytes(&r.claim_id)?,
            exercise: bytes(&r.exercise_id)?,
            previous: r.previous.as_deref().map(bytes).transpose()?,
            first_seq: unsigned(r.first_seq)?,
            next_seq: unsigned(r.next_seq)?,
            head: bytes(&r.head)?,
            period_from_ms: unsigned(r.period_from_ms)?,
            period_until_ms: unsigned(r.period_until_ms)?,
            body: r.body,
        })
    })
    .transpose()
}

/// Records a Verifier Profile body (sequencer role, after its Claim record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn insert_profile(
    sequencer: &PgPool,
    domain: &DomainId,
    pos: u64,
    digest: &[u8; 32],
    claim: &[u8; 16],
    body: &[u8],
) -> Result<(), StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.verifier_profile (domain_id, pos, profile_digest, claim_id, body)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        signed(pos)?,
        digest.as_slice(),
        claim.as_slice(),
        body,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(())
}

/// The body of the profile whose digest a contract names (`verifier_profile_ref`).
///
/// # Errors
/// [`StoreError`].
pub async fn profile(
    pool: &PgPool,
    domain: &DomainId,
    digest: &[u8; 32],
) -> Result<Option<Vec<u8>>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let body = sqlx::query_scalar!(
        "SELECT body FROM access.verifier_profile
          WHERE domain_id = $1 AND profile_digest = $2 ORDER BY pos LIMIT 1",
        domain.as_bytes().as_slice(),
        digest.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(body)
}
