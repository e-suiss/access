//! The operator's side of the user-keyed domain (E52, E59, E66, OP-74, OP-78): where every
//! wrapped copy of a person's class DEKs and record keys is, the copies the operator holds, and
//! the `erasure_log`. The KEK never reaches it. Destroying a copy zeroes what is held and stamps
//! it; nothing returns and no row is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

/// One wrapped copy of a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyCopy {
    /// The One class.
    pub class: String,
    /// The record key, empty for the class DEK.
    pub record_key: String,
    /// `server`, `vault`, `tee` or `device`.
    pub holder: String,
    /// The TEE job or device; empty for the server and the vault.
    pub holder_id: String,
    /// What the operator holds (server, vault); `None` once destroyed or when held elsewhere.
    pub wrapped: Option<Vec<u8>>,
    /// Whether the copy is destroyed.
    pub destroyed: bool,
}

/// One `erasure_log` entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Erasure {
    /// The entry.
    pub id: [u8; 16],
    /// `record`, `class` or `account`.
    pub target: String,
    /// `applied`, `pending_devices` or `pending_hold`.
    pub state: String,
    /// The devices still to destroy their copy.
    pub waiting: Vec<String>,
}

impl TenantTx {
    fn scoped(&self, subject: [u8; 16]) -> Result<(Uuid, Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(subject),
        ))
    }

    /// Records a wrapped copy of one of `subject`'s keys.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn add_key_copy(
        &mut self,
        subject: [u8; 16],
        copy: &KeyCopy,
    ) -> Result<(), StoreError> {
        let (t, r, s) = self.scoped(subject)?;
        sqlx::query!(
            "INSERT INTO access.user_keyed_copies
               (tenant_id, realm_id, subject_id, class, record_key, holder, holder_id, wrapped)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            t,
            r,
            s,
            copy.class,
            copy.record_key,
            copy.holder,
            copy.holder_id,
            copy.wrapped.as_deref(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Every copy of `subject`'s keys.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn key_copies(&mut self, subject: [u8; 16]) -> Result<Vec<KeyCopy>, StoreError> {
        let (t, r, s) = self.scoped(subject)?;
        let rows = sqlx::query!(
            r#"SELECT class, record_key, holder, holder_id, wrapped,
                      destroyed_at IS NOT NULL AS "destroyed!"
                 FROM access.user_keyed_copies
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY class, record_key, holder, holder_id"#,
            t,
            r,
            s,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| KeyCopy {
                class: r.class,
                record_key: r.record_key,
                holder: r.holder,
                holder_id: r.holder_id,
                wrapped: r.wrapped,
                destroyed: r.destroyed,
            })
            .collect())
    }

    /// Destroys one copy: what is held is zeroed and the copy stamped. Returns whether it was
    /// live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn destroy_key_copy(
        &mut self,
        subject: [u8; 16],
        copy: &KeyCopy,
    ) -> Result<bool, StoreError> {
        let (t, r, s) = self.scoped(subject)?;
        let n = sqlx::query!(
            "UPDATE access.user_keyed_copies SET wrapped = NULL, destroyed_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND class = $4
                AND record_key = $5 AND holder = $6 AND holder_id = $7 AND destroyed_at IS NULL",
            t,
            r,
            s,
            copy.class,
            copy.record_key,
            copy.holder,
            copy.holder_id,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Opens an `erasure_log` entry; returns its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_erasure(
        &mut self,
        subject: [u8; 16],
        (target, class, record_key): (&str, Option<&str>, Option<&str>),
        (state, waiting): (&str, &[String]),
    ) -> Result<[u8; 16], StoreError> {
        let (t, r, s) = self.scoped(subject)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.user_keyed_erasures
               (tenant_id, realm_id, subject_id, target, class, record_key, state, waiting, closed_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, CASE WHEN $7 = 'applied' THEN clock_timestamp() END)
             RETURNING erasure_id",
            t,
            r,
            s,
            target,
            class,
            record_key,
            state,
            waiting,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// One `erasure_log` entry.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn erasure(&mut self, id: [u8; 16]) -> Result<Option<Erasure>, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let row = sqlx::query!(
            "SELECT erasure_id, target, state, waiting FROM access.user_keyed_erasures
              WHERE tenant_id = $1 AND realm_id = $2 AND erasure_id = $3",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| Erasure {
            id: *r.erasure_id.as_bytes(),
            target: r.target,
            state: r.state,
            waiting: r.waiting,
        }))
    }

    /// Moves an entry forward; `applied` closes it. Returns whether it moved.
    ///
    /// # Errors
    /// [`StoreError`]; the table refuses a step back.
    pub async fn advance_erasure(
        &mut self,
        id: [u8; 16],
        state: &str,
        waiting: &[String],
    ) -> Result<bool, StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        let n = sqlx::query!(
            "UPDATE access.user_keyed_erasures
                SET state = $4, waiting = $5,
                    closed_at = CASE WHEN $4 = 'applied' THEN clock_timestamp() END
              WHERE tenant_id = $1 AND realm_id = $2 AND erasure_id = $3",
            Uuid::from_bytes(*self.tenant.as_bytes()),
            Uuid::from_bytes(*realm.as_bytes()),
            Uuid::from_bytes(id),
            state,
            waiting,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
