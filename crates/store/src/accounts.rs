//! Identity subjects, login identifiers and the credential store (§10.1.7, IDP-2, TN-49, TN-68,
//! OP-145): realm-local rows under the transaction's scope. Nothing is deleted (OP-73); the
//! database enforces the TN-49 chain and keeps the last authentication method (TN-68).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

/// A stored subject.
pub struct SubjectRow {
    /// Internal `UUIDv7`.
    pub id: [u8; 16],
    /// TN-49 status name.
    pub status: String,
    /// Grows on every deactivation and revocation (TN-50, MD-7).
    pub session_epoch: i64,
    /// The KEK that wraps the subject's DEK.
    pub kek_id: String,
    /// The subject's wrapped DEK; `None` once shredded.
    pub wrapped_dek: Option<Vec<u8>>,
}

/// A credential to store: its secret sealed under its own DEK, wrapped by the subject's DEK.
pub struct NewCredential<'a> {
    /// Owner.
    pub subject: [u8; 16],
    /// `password`, `webauthn`, `totp` or `recovery_code`.
    pub kind: &'a str,
    /// Algorithm name (MD-3).
    pub algorithm: &'a str,
    /// Sealed secret.
    pub sealed: &'a SealedSecret,
}

/// A sealed credential secret and the key material to open it.
#[derive(Clone)]
pub struct SealedSecret {
    /// Id of the DEK that wraps this one.
    pub kek_id: String,
    /// The credential's wrapped DEK.
    pub wrapped_dek: Vec<u8>,
    /// AEAD nonce.
    pub nonce: [u8; 12],
    /// Ciphertext and tag.
    pub ciphertext: Vec<u8>,
    /// Pepper version, reserved (CR-37, OP-146 m.5 (l)).
    pub pepper_version: Option<i16>,
}

/// A stored, active credential.
pub struct CredentialRow {
    /// Internal id.
    pub id: [u8; 16],
    /// Owner.
    pub subject: [u8; 16],
    /// Kind.
    pub kind: String,
    /// Algorithm.
    pub algorithm: String,
    /// Sealed secret.
    pub sealed: SealedSecret,
}

/// Outcome of removing a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revoke {
    /// Revoked.
    Done,
    /// No such active credential.
    Missing,
    /// It is the subject's last method (TN-68); nothing changed.
    LastMethod,
}

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn nonce(v: Vec<u8>) -> Result<[u8; 12], StoreError> {
    <[u8; 12]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

impl TenantTx {
    fn scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Inserts a subject in `status` with its wrapped DEK; returns the new id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_subject(
        &mut self,
        status: &str,
        kek_id: &str,
        wrapped_dek: &[u8],
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.identity_subjects (tenant_id, realm_id, status, kek_id, wrapped_dek)
               VALUES ($1, $2, $3, $4, $5) RETURNING subject_id AS "id!""#,
            tenant,
            realm,
            status,
            kek_id,
            wrapped_dek,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The subject, locked for this transaction when `lock` is set.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subject(
        &mut self,
        id: [u8; 16],
        lock: bool,
    ) -> Result<Option<SubjectRow>, StoreError> {
        let (tenant, realm) = self.scope()?;
        let row = if lock {
            sqlx::query_as!(
                SubjectRecord,
                "SELECT subject_id, status, session_epoch, kek_id, wrapped_dek
                   FROM access.identity_subjects
                  WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 FOR UPDATE",
                tenant,
                realm,
                uuid(id),
            )
            .fetch_optional(&mut *self.tx)
            .await?
        } else {
            sqlx::query_as!(
                SubjectRecord,
                "SELECT subject_id, status, session_epoch, kek_id, wrapped_dek
                   FROM access.identity_subjects
                  WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
                tenant,
                realm,
                uuid(id),
            )
            .fetch_optional(&mut *self.tx)
            .await?
        };
        Ok(row.map(SubjectRecord::into_row))
    }

    /// Moves the subject from `from` to `to`; false when its status is not `from`. The
    /// database refuses a move outside the TN-49 chain.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_subject_status(
        &mut self,
        id: [u8; 16],
        from: &str,
        to: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_subjects SET status = $4, status_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = $5",
            tenant,
            realm,
            uuid(id),
            to,
            from,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Adds one to the subject's `session_epoch` and returns the new value (TN-50, MD-7).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn bump_session_epoch(&mut self, id: [u8; 16]) -> Result<Option<i64>, StoreError> {
        let (tenant, realm) = self.scope()?;
        Ok(sqlx::query_scalar!(
            "UPDATE access.identity_subjects SET session_epoch = session_epoch + 1, session_epoch_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 RETURNING session_epoch",
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Ends the subject's identity sessions and refresh families in this transaction
    /// (TN-50, OP-146 m.10 (a)): they carry the epoch they were issued under, so raising it
    /// ends them all; the login sessions behind it are marked ended in the same transaction.
    /// Grants of clients with a back-channel endpoint are queued for a logout notice
    /// (§10.4.6). Returns the new epoch.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_sessions(&mut self, id: [u8; 16]) -> Result<Option<i64>, StoreError> {
        let Some(epoch) = self.bump_session_epoch(id).await? else {
            return Ok(None);
        };
        let (tenant, realm) = self.scope()?;
        sqlx::query!(
            "UPDATE access.login_sessions
                SET ended_ms = (extract(epoch FROM clock_timestamp()) * 1000)::bigint, end_reason = 'epoch'
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND ended_ms IS NULL
                AND session_epoch < $4",
            tenant,
            realm,
            uuid(id),
            epoch,
        )
        .execute(&mut *self.tx)
        .await?;
        let notify = sqlx::query_scalar!(
            "WITH revoked AS (
               UPDATE access.oauth_grants
                  SET revoked_ms = (extract(epoch FROM clock_timestamp()) * 1000)::bigint, revoke_reason = 'epoch'
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND revoked_ms IS NULL
                  AND session_epoch < $4
               RETURNING grant_id, client_uuid)
             SELECT r.grant_id FROM revoked r
               JOIN access.idp_clients c
                 ON c.tenant_id = $1 AND c.realm_id = $2 AND c.client_uuid = r.client_uuid
              WHERE c.backchannel_logout_uri IS NOT NULL
              ORDER BY r.grant_id",
            tenant,
            realm,
            uuid(id),
            epoch,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        self.queue_backchannel_logout(&notify).await?;
        Ok(Some(epoch))
    }

    /// Adds a login identifier; false when the realm already has it in any letter case.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn add_identifier(
        &mut self,
        subject: [u8; 16],
        kind: &str,
        value: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.scope()?;
        let n = sqlx::query!(
            "INSERT INTO access.identity_identifiers (tenant_id, realm_id, subject_id, kind, value)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id, lower(value)) WHERE status = 'active' DO NOTHING",
            tenant,
            realm,
            uuid(subject),
            kind,
            value,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject holding `value` in this realm, compared without letter case.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subject_by_identifier(
        &mut self,
        value: &str,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.scope()?;
        let id = sqlx::query_scalar!(
            "SELECT subject_id FROM access.identity_identifiers
              WHERE tenant_id = $1 AND realm_id = $2 AND lower(value) = lower($3) AND status = 'active'",
            tenant,
            realm,
            value,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(id.map(|u| *u.as_bytes()))
    }

    /// Releases the subject's identifier `value` so it can be taken again.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn release_identifier(
        &mut self,
        subject: [u8; 16],
        value: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_identifiers SET status = 'released', released_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                AND lower(value) = lower($4) AND status = 'active'",
            tenant,
            realm,
            uuid(subject),
            value,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Stores a credential; returns its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_credential(
        &mut self,
        c: &NewCredential<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.identity_credentials
                 (tenant_id, realm_id, subject_id, kind, algorithm, kek_id, wrapped_dek, nonce, ciphertext, pepper_version)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING credential_id AS "id!""#,
            tenant,
            realm,
            uuid(c.subject),
            c.kind,
            c.algorithm,
            c.sealed.kek_id,
            c.sealed.wrapped_dek,
            c.sealed.nonce.as_slice(),
            c.sealed.ciphertext,
            c.sealed.pepper_version,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The subject's active credentials of `kind`, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn credentials(
        &mut self,
        subject: [u8; 16],
        kind: &str,
    ) -> Result<Vec<CredentialRow>, StoreError> {
        let (tenant, realm) = self.scope()?;
        let rows = sqlx::query!(
            "SELECT credential_id, subject_id, kind, algorithm, kek_id, wrapped_dek, nonce, ciphertext, pepper_version
               FROM access.identity_credentials
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND kind = $4 AND status = 'active'
              ORDER BY credential_id",
            tenant,
            realm,
            uuid(subject),
            kind,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(CredentialRow {
                    id: *r.credential_id.as_bytes(),
                    subject: *r.subject_id.as_bytes(),
                    kind: r.kind,
                    algorithm: r.algorithm,
                    sealed: SealedSecret {
                        kek_id: r.kek_id,
                        wrapped_dek: r.wrapped_dek,
                        nonce: nonce(r.nonce)?,
                        ciphertext: r.ciphertext,
                        pepper_version: r.pepper_version,
                    },
                })
            })
            .collect()
    }

    /// Replaces an active credential's sealed secret, as a rehash does (CR-37).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn reseal_credential(
        &mut self,
        id: [u8; 16],
        algorithm: &str,
        sealed: &SealedSecret,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_credentials
                SET algorithm = $4, kek_id = $5, wrapped_dek = $6, nonce = $7, ciphertext = $8, pepper_version = $9
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3 AND status = 'active'",
            tenant,
            realm,
            uuid(id),
            algorithm,
            sealed.kek_id,
            sealed.wrapped_dek,
            sealed.nonce.as_slice(),
            sealed.ciphertext,
            sealed.pepper_version,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Revokes a credential unless it is the subject's last method (TN-68). The subject row is
    /// locked first, so two removals cannot both pass the check; the database trigger is the
    /// backstop.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_credential(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> Result<Revoke, StoreError> {
        let (tenant, realm) = self.scope()?;
        let Some(live) = self.subject(subject, true).await? else {
            return Ok(Revoke::Missing);
        };
        let others = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM access.identity_credentials
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                  AND credential_id <> $4"#,
            tenant,
            realm,
            uuid(subject),
            uuid(id),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        let terminal = matches!(live.status.as_str(), "tombstone" | "purging");
        if others == 0 && !terminal {
            let exists = sqlx::query_scalar!(
                r#"SELECT EXISTS (SELECT 1 FROM access.identity_credentials
                    WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                      AND credential_id = $4 AND status = 'active') AS "e!""#,
                tenant,
                realm,
                uuid(subject),
                uuid(id),
            )
            .fetch_one(&mut *self.tx)
            .await?;
            return Ok(if exists {
                Revoke::LastMethod
            } else {
                Revoke::Missing
            });
        }
        let n = sqlx::query!(
            "UPDATE access.identity_credentials SET status = 'revoked', revoked_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND credential_id = $4
                AND status = 'active'",
            tenant,
            realm,
            uuid(subject),
            uuid(id),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(if n == 1 {
            Revoke::Done
        } else {
            Revoke::Missing
        })
    }

    /// Records a successful use of a credential.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn credential_used(&mut self, id: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = self.scope()?;
        sqlx::query!(
            "UPDATE access.identity_credentials SET last_used_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3",
            tenant,
            realm,
            uuid(id),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}

struct SubjectRecord {
    subject_id: Uuid,
    status: String,
    session_epoch: i64,
    kek_id: String,
    wrapped_dek: Option<Vec<u8>>,
}

impl SubjectRecord {
    fn into_row(self) -> SubjectRow {
        SubjectRow {
            id: *self.subject_id.as_bytes(),
            status: self.status,
            session_epoch: self.session_epoch,
            kek_id: self.kek_id,
            wrapped_dek: self.wrapped_dek,
        }
    }
}
