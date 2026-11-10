//! The commitments a coordinator ended, as Access saw them (OP-156 m.3 (t), EI-5, §8.17.7.2):
//! one row per commitment and issuer, appended after the `claim` record that ended it. The
//! decision path reads the authority log, never this table; it only lets the inventory say when
//! a commitment-scoped Grant ended with its commitment (OP-73: append-only).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

/// One ended commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Termination {
    /// The `CommitmentRef` digest.
    pub commitment: [u8; 32],
    /// Position of the `claim` record that ended it.
    pub pos: u64,
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The coordinator that issued it.
    pub issuer: [u8; 16],
    /// The Party it is about.
    pub subject: [u8; 16],
}

/// Records `t` once (sequencer role, after its Claim record committed); a second record of the
/// same commitment by the same issuer keeps the first.
///
/// # Errors
/// [`StoreError`].
pub async fn record_termination(
    sequencer: &PgPool,
    domain: &DomainId,
    t: &Termination,
) -> Result<(), StoreError> {
    let mut tx = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.commitment_terminations
           (domain_id, commitment, pos, claim_id, issuer_id, subject_id)
         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        t.commitment.as_slice(),
        i64::try_from(t.pos).map_err(|_| StoreError::Range)?,
        t.claim.as_slice(),
        t.issuer.as_slice(),
        t.subject.as_slice(),
    )
    .execute(&mut *tx.tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The first recorded end of `commitment`, by any issuer.
///
/// # Errors
/// [`StoreError`].
pub async fn termination(
    pool: &PgPool,
    domain: &DomainId,
    commitment: &[u8; 32],
) -> Result<Option<Termination>, StoreError> {
    let mut tx = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT commitment, pos, claim_id, issuer_id, subject_id
           FROM access.commitment_terminations
          WHERE domain_id = $1 AND commitment = $2 ORDER BY pos LIMIT 1",
        domain.as_bytes().as_slice(),
        commitment.as_slice(),
    )
    .fetch_optional(&mut *tx.tx)
    .await?;
    tx.commit().await?;
    let fixed = |v: &[u8]| v.try_into().map_err(|_| StoreError::Corrupt);
    row.map(|r| {
        Ok(Termination {
            commitment: fixed(&r.commitment)?,
            pos: u64::try_from(r.pos).map_err(|_| StoreError::Corrupt)?,
            claim: <[u8; 16]>::try_from(r.claim_id.as_slice()).map_err(|_| StoreError::Corrupt)?,
            issuer: <[u8; 16]>::try_from(r.issuer_id.as_slice())
                .map_err(|_| StoreError::Corrupt)?,
            subject: <[u8; 16]>::try_from(r.subject_id.as_slice())
                .map_err(|_| StoreError::Corrupt)?,
        })
    })
    .transpose()
}
