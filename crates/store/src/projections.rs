//! Authority token projection families (§9.9.3 k.6, P50, OP-150 m.2): a refresh family, its
//! holder and client, and its Token Status List entry. A family is revoked once, by the position
//! of the Exercise that ended it; the row stays (OP-73).

use sqlx::PgPool;

use crate::StoreError;
use crate::scope::{DomainId, DomainTx};

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn bytes<const N: usize>(v: &[u8]) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One family.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Family {
    /// The family.
    pub family: [u8; 16],
    /// The OAuth client.
    pub client_id: String,
    /// The holder Instance.
    pub holder: [u8; 16],
    /// The first `projection.issue` `ExerciseID`.
    pub root_exercise: [u8; 32],
    /// Its status list entry, `(uri, idx)`.
    pub status: Option<(String, u64)>,
    /// The position that revoked it.
    pub revoked_pos: Option<u64>,
}

/// Opens a family (sequencer role): `true` the first time. A status entry another family
/// holds is an error.
///
/// # Errors
/// [`StoreError`].
pub async fn open_family(
    sequencer: &PgPool,
    domain: &DomainId,
    f: &Family,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "INSERT INTO access.projection_family
           (domain_id, family_id, client_id, holder_id, root_exercise, status_uri, status_idx)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (domain_id, family_id) DO NOTHING",
        domain.as_bytes().as_slice(),
        f.family.as_slice(),
        f.client_id,
        f.holder.as_slice(),
        f.root_exercise.as_slice(),
        f.status.as_ref().map(|(uri, _)| uri.as_str()),
        f.status.as_ref().map(|(_, idx)| signed(*idx)).transpose()?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// Revokes a family at `pos` (sequencer role): `true` the first time; a revoked family stays
/// revoked.
///
/// # Errors
/// [`StoreError`].
pub async fn revoke_family(
    sequencer: &PgPool,
    domain: &DomainId,
    family: &[u8; 16],
    pos: u64,
) -> Result<bool, StoreError> {
    let mut t = DomainTx::begin(sequencer, domain).await?;
    let done = sqlx::query!(
        "UPDATE access.projection_family SET revoked_at = now(), revoked_pos = $3
          WHERE domain_id = $1 AND family_id = $2 AND revoked_at IS NULL",
        domain.as_bytes().as_slice(),
        family.as_slice(),
        signed(pos)?,
    )
    .execute(&mut *t.tx)
    .await?;
    t.commit().await?;
    Ok(done.rows_affected() == 1)
}

/// The family `family`.
///
/// # Errors
/// [`StoreError`].
pub async fn family(
    pool: &PgPool,
    domain: &DomainId,
    family: &[u8; 16],
) -> Result<Option<Family>, StoreError> {
    let mut t = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT family_id, client_id, holder_id, root_exercise, status_uri, status_idx, revoked_pos
           FROM access.projection_family WHERE domain_id = $1 AND family_id = $2",
        domain.as_bytes().as_slice(),
        family.as_slice(),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    t.commit().await?;
    row.map(|r| {
        let status = match (r.status_uri, r.status_idx) {
            (Some(uri), Some(idx)) => {
                Some((uri, u64::try_from(idx).map_err(|_| StoreError::Corrupt)?))
            }
            (None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Family {
            family: bytes(&r.family_id)?,
            client_id: r.client_id,
            holder: bytes(&r.holder_id)?,
            root_exercise: bytes(&r.root_exercise)?,
            status,
            revoked_pos: r
                .revoked_pos
                .map(|p| u64::try_from(p).map_err(|_| StoreError::Corrupt))
                .transpose()?,
        })
    })
    .transpose()
}
