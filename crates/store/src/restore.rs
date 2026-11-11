//! Restore and re-shred generations (OP-42, OP-57, OP-158 m.3 (r)): a restore generation above
//! the latest re-shred keeps the environment closed until the shred list is applied again.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn unsigned(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// Records a restore; returns its generation.
///
/// # Errors
/// [`StoreError`].
pub async fn mark_restored(app: &PgPool) -> Result<u64, StoreError> {
    let g = sqlx::query_scalar!(
        r#"INSERT INTO access_ops.restore_generations (kind, generation)
           SELECT 'restore', coalesce(max(generation), 0) + 1
             FROM access_ops.restore_generations WHERE kind = 'restore'
           RETURNING generation"#
    )
    .fetch_one(app)
    .await?;
    unsigned(g)
}

/// The restore generation no re-shred has caught up with, if any.
///
/// # Errors
/// [`StoreError`].
pub async fn pending_reshred(app: &PgPool) -> Result<Option<u64>, StoreError> {
    let r = sqlx::query!(
        r#"SELECT coalesce(max(generation) FILTER (WHERE kind = 'restore'), 0) AS "restore!",
                  coalesce(max(generation) FILTER (WHERE kind = 'reshred'), 0) AS "reshred!"
             FROM access_ops.restore_generations"#
    )
    .fetch_one(app)
    .await?;
    (r.restore > r.reshred)
        .then(|| unsigned(r.restore))
        .transpose()
}

/// Records that the shred list was applied after restore `generation`.
///
/// # Errors
/// [`StoreError`]; a generation is re-shredded once.
pub async fn mark_reshredded(app: &PgPool, generation: u64) -> Result<(), StoreError> {
    sqlx::query!(
        "INSERT INTO access_ops.restore_generations (kind, generation) VALUES ('reshred', $1)",
        i64::try_from(generation).map_err(|_| StoreError::Range)?,
    )
    .execute(app)
    .await?;
    Ok(())
}

/// How a subject stands against the shred list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shredded {
    /// Every key of the subject is destroyed.
    Yes,
    /// A key of the subject is still readable.
    No,
    /// The realm holds no such subject.
    Unknown,
}

impl TenantTx {
    /// Whether every key of `subject` is destroyed.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subject_shredded(&mut self, subject: [u8; 16]) -> Result<Shredded, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let (t, r, s) = (
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(subject),
        );
        let row = sqlx::query!(
            r#"SELECT s.wrapped_dek IS NULL AS "own!",
                      NOT EXISTS (SELECT FROM access.identity_subject_keys k
                                   WHERE k.tenant_id = s.tenant_id AND k.realm_id = s.realm_id
                                     AND k.subject_id = s.subject_id AND k.wrapped_dek IS NOT NULL) AS "classes!"
                 FROM access.identity_subjects s
                WHERE s.tenant_id = $1 AND s.realm_id = $2 AND s.subject_id = $3"#,
            t,
            r,
            s,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(match row {
            None => Shredded::Unknown,
            Some(r) if r.own && r.classes => Shredded::Yes,
            Some(_) => Shredded::No,
        })
    }

    /// Applies the shred list's entry for `subject` again (OP-42): the subject is moved along
    /// its TN-49 chain to `purging`, then every class key and its own key are destroyed. Returns
    /// how many keys were destroyed now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn reshred_subject(&mut self, subject: [u8; 16]) -> Result<u64, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let (t, r, s) = (
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(subject),
        );
        let classes = sqlx::query!(
            "UPDATE access.identity_subject_keys SET wrapped_dek = NULL, shredded_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND wrapped_dek IS NOT NULL",
            t,
            r,
            s,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        for (from, to) in [
            ("staged", "deactivated"),
            ("pending_user_action", "deactivated"),
            ("active", "deactivated"),
            ("locked", "deactivated"),
            ("suspended", "deactivated"),
            ("deactivated", "tombstone"),
            ("tombstone", "purging"),
        ] {
            sqlx::query!(
                "UPDATE access.identity_subjects SET status = $5
                  WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = $4",
                t,
                r,
                s,
                from,
                to,
            )
            .execute(&mut *self.tx)
            .await?;
        }
        let own = sqlx::query!(
            "UPDATE access.identity_subjects SET wrapped_dek = NULL, shredded_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'purging'
                AND wrapped_dek IS NOT NULL",
            t,
            r,
            s,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(classes.saturating_add(own))
    }
}
