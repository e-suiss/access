//! Realm KEK rotation (OP-138, OP-144, OP-158 m.3 (y)): the subject DEKs a KEK still wraps, their
//! re-wrap under the next KEK, and the counted, resumable rotation record. The DEK never comes
//! here in clear: the caller re-wraps inside the HSM and hands over the new wrapped bytes.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

/// A live subject DEK under a KEK: the subject's own (`class` none) or one of its vault classes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrapped {
    /// The subject.
    pub subject: [u8; 16],
    /// The vault class, or none for the subject's own DEK.
    pub class: Option<String>,
    /// The wrapped DEK.
    pub wrapped: Vec<u8>,
}

/// A realm's KEK rotation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rotation {
    /// The KEK being left.
    pub from_kek: String,
    /// The KEK being moved to.
    pub to_kek: String,
    /// DEKs moved so far.
    pub rewrapped: u64,
    /// Whether no DEK is left under `from_kek`.
    pub finished: bool,
}

impl TenantTx {
    fn kek_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Up to `limit` live subject DEKs of the realm still wrapped by `kek_id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn wrapped_by_kek(
        &mut self,
        kek_id: &str,
        limit: u32,
    ) -> Result<Vec<Wrapped>, StoreError> {
        let (tenant, realm) = self.kek_scope()?;
        let rows = sqlx::query!(
            r#"SELECT subject_id AS "subject!", class, wrapped_dek AS "wrapped!" FROM (
                 SELECT subject_id, NULL::text AS class, wrapped_dek FROM access.identity_subjects
                  WHERE tenant_id = $1 AND realm_id = $2 AND kek_id = $3 AND wrapped_dek IS NOT NULL
                 UNION ALL
                 SELECT subject_id, class, wrapped_dek FROM access.identity_subject_keys
                  WHERE tenant_id = $1 AND realm_id = $2 AND kek_id = $3 AND wrapped_dek IS NOT NULL
               ) k ORDER BY subject_id, class NULLS FIRST LIMIT $4"#,
            tenant,
            realm,
            kek_id,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| Wrapped {
                subject: *r.subject.as_bytes(),
                class: r.class,
                wrapped: r.wrapped,
            })
            .collect())
    }

    /// Replaces one subject DEK's wrap from `from_kek` to `to_kek`, only while it is still the
    /// wrap `old` and not shredded; false otherwise (a writer or a shred came first).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn rewrap_subject_dek(
        &mut self,
        key: &Wrapped,
        (from_kek, to_kek): (&str, &str),
        new: &[u8],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.kek_scope()?;
        let n = match &key.class {
            None => sqlx::query!(
                "UPDATE access.identity_subjects SET kek_id = $5, wrapped_dek = $6
                  WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND kek_id = $4
                    AND wrapped_dek = $7 AND shredded_at IS NULL",
                tenant,
                realm,
                uuid(key.subject),
                from_kek,
                to_kek,
                new,
                key.wrapped.as_slice(),
            )
            .execute(&mut *self.tx)
            .await?
            .rows_affected(),
            Some(class) => sqlx::query!(
                "UPDATE access.identity_subject_keys SET kek_id = $6, wrapped_dek = $7
                  WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND class = $4
                    AND kek_id = $5 AND wrapped_dek = $8 AND shredded_at IS NULL",
                tenant,
                realm,
                uuid(key.subject),
                class,
                from_kek,
                to_kek,
                new,
                key.wrapped.as_slice(),
            )
            .execute(&mut *self.tx)
            .await?
            .rows_affected(),
        };
        Ok(n == 1)
    }

    /// The realm's open rotation, else its last one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn kek_rotation(&mut self) -> Result<Option<Rotation>, StoreError> {
        let (tenant, realm) = self.kek_scope()?;
        let row = sqlx::query!(
            "SELECT from_kek, to_kek, rewrapped, finished_at IS NOT NULL AS \"finished!\"
               FROM access.kek_rotations WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY finished_at IS NULL DESC, started_at DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| Rotation {
            from_kek: r.from_kek,
            to_kek: r.to_kek,
            rewrapped: u64::try_from(r.rewrapped).unwrap_or(0),
            finished: r.finished,
        }))
    }

    /// Opens a rotation from `from_kek` to `to_kek`; false when the realm has one open already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_kek_rotation(
        &mut self,
        from_kek: &str,
        to_kek: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.kek_scope()?;
        let n = sqlx::query!(
            "INSERT INTO access.kek_rotations (tenant_id, realm_id, from_kek, to_kek)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            from_kek,
            to_kek,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Adds `moved` to the open rotation to `to_kek`, finishing it when `done`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn count_kek_rotation(
        &mut self,
        to_kek: &str,
        moved: u64,
        done: bool,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.kek_scope()?;
        let moved = i64::try_from(moved).map_err(|_| StoreError::Range)?;
        let n = sqlx::query!(
            "UPDATE access.kek_rotations SET rewrapped = rewrapped + $4,
                    finished_at = CASE WHEN $5 THEN clock_timestamp() ELSE NULL END
              WHERE tenant_id = $1 AND realm_id = $2 AND to_kek = $3 AND finished_at IS NULL",
            tenant,
            realm,
            to_kek,
            moved,
            done,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
