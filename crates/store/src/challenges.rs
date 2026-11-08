//! Address challenges, mailbox ownership and identifier tombstones (OP-153 m.3 (g), (i), TN-64,
//! TN-66, TN-76, TN-80): a pending registration or e-mail change before its code returns, since
//! when an account has owned each address it holds, and the identifiers it gave up. Every row
//! only grows or ends once (OP-73). Times are the caller's trusted clock, Unix milliseconds.

use sqlx::types::Uuid;

use crate::StoreError;
use crate::accounts::SubjectKeyRow;
use crate::identity::TenantTx;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn bytes32(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A new challenge.
pub struct NewChallenge<'a> {
    /// `registration` or `email_change`.
    pub purpose: &'a str,
    /// Digest of the flow handle.
    pub flow_hash: &'a [u8; 32],
    /// Digest of the browser's flow cookie.
    pub device_hash: &'a [u8; 32],
    /// The realm KEK's id.
    pub kek_id: &'a str,
    /// The challenge's own DEK, wrapped.
    pub wrapped_dek: &'a [u8],
    /// AEAD nonce of the sealed address.
    pub nonce: &'a [u8; 12],
    /// The address, sealed under the challenge's DEK.
    pub ciphertext: &'a [u8],
    /// The realm's blind index of the address.
    pub address_index: &'a [u8; 32],
    /// The realm's blind index of the canonical address.
    pub canonical_index: &'a [u8; 32],
    /// Digest of the code; `None` when no code can answer it.
    pub code_digest: Option<&'a [u8; 32]>,
    /// Wrong codes it takes.
    pub attempts: i16,
    /// The abuse score asked for step-up.
    pub step_up: bool,
    /// The abuse score.
    pub score: i16,
    /// The account an e-mail change is for.
    pub subject: Option<[u8; 16]>,
    /// Now.
    pub created_ms: i64,
    /// When it expires.
    pub expires_ms: i64,
}

/// A stored challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeRow {
    /// Its id, also the subject its code message is sealed for.
    pub id: [u8; 16],
    /// `registration` or `email_change`.
    pub purpose: String,
    /// Digest of the browser's flow cookie.
    pub device_hash: [u8; 32],
    /// The realm KEK's id.
    pub kek_id: String,
    /// The wrapped DEK; `None` once shredded.
    pub wrapped_dek: Option<Vec<u8>>,
    /// AEAD nonce of the address.
    pub nonce: [u8; 12],
    /// The sealed address.
    pub ciphertext: Vec<u8>,
    /// Blind index of the address.
    pub address_index: [u8; 32],
    /// Digest of the code.
    pub code_digest: Option<[u8; 32]>,
    /// Wrong codes left.
    pub attempts_left: i16,
    /// Whether the score asked for step-up.
    pub step_up: bool,
    /// The account it is for or became.
    pub subject: Option<[u8; 16]>,
    /// `open`, `completed`, `expired` or `failed`.
    pub status: String,
    /// When it expires.
    pub expires_ms: i64,
}

impl TenantTx {
    fn challenge_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Stores a new challenge; returns its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_challenge(&mut self, c: &NewChallenge<'_>) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.identity_address_challenges
               (tenant_id, realm_id, purpose, flow_hash, device_hash, kek_id, wrapped_dek, nonce,
                ciphertext, address_index, canonical_index, code_digest, attempts_left, step_up,
                score, subject_id, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
             RETURNING challenge_id",
            tenant,
            realm,
            c.purpose,
            c.flow_hash.as_slice(),
            c.device_hash.as_slice(),
            c.kek_id,
            c.wrapped_dek,
            c.nonce.as_slice(),
            c.ciphertext,
            c.address_index.as_slice(),
            c.canonical_index.as_slice(),
            c.code_digest.map(<[u8; 32]>::as_slice),
            c.attempts,
            c.step_up,
            c.score,
            c.subject.map(uuid),
            c.created_ms,
            c.expires_ms,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The challenge of flow handle digest `flow_hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn challenge_by_flow(
        &mut self,
        flow_hash: &[u8; 32],
    ) -> Result<Option<ChallengeRow>, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let row = sqlx::query!(
            "SELECT challenge_id, purpose, device_hash, kek_id, wrapped_dek, nonce, ciphertext,
                    address_index, code_digest, attempts_left, step_up, subject_id, status, expires_ms
               FROM access.identity_address_challenges
              WHERE tenant_id = $1 AND realm_id = $2 AND flow_hash = $3
              FOR UPDATE",
            tenant,
            realm,
            flow_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(ChallengeRow {
                id: *r.challenge_id.as_bytes(),
                purpose: r.purpose,
                device_hash: bytes32(r.device_hash)?,
                kek_id: r.kek_id,
                wrapped_dek: r.wrapped_dek,
                nonce: <[u8; 12]>::try_from(r.nonce).map_err(|_| StoreError::Corrupt)?,
                ciphertext: r.ciphertext,
                address_index: bytes32(r.address_index)?,
                code_digest: r.code_digest.map(bytes32).transpose()?,
                attempts_left: r.attempts_left,
                step_up: r.step_up,
                subject: r.subject_id.map(|u| *u.as_bytes()),
                status: r.status,
                expires_ms: r.expires_ms,
            })
        })
        .transpose()
    }

    /// Records one wrong code: `attempts_left` goes down to `left`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn challenge_attempt(&mut self, id: [u8; 16], left: i16) -> Result<(), StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        sqlx::query!(
            "UPDATE access.identity_address_challenges SET attempts_left = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_id = $3 AND status = 'open'",
            tenant,
            realm,
            uuid(id),
            left,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends an open challenge as `status` at `now_ms`, naming the account it became, and shreds
    /// its DEK; false when it was no longer open.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_challenge(
        &mut self,
        id: [u8; 16],
        status: &str,
        subject: Option<[u8; 16]>,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_address_challenges
                SET status = $4, ended_ms = $5, subject_id = COALESCE(subject_id, $6),
                    wrapped_dek = NULL, shredded_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_id = $3 AND status = 'open'",
            tenant,
            realm,
            uuid(id),
            status,
            now_ms,
            subject.map(uuid),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Ends up to `limit` open challenges past their expiry as `expired`, shredding their DEKs
    /// (OP-153 m.3 (g)); returns how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn expire_challenges(&mut self, now_ms: i64, limit: i64) -> Result<u64, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_address_challenges
                SET status = 'expired', ended_ms = $3, wrapped_dek = NULL, shredded_at = now()
              WHERE (tenant_id, realm_id, challenge_id) IN (
                SELECT tenant_id, realm_id, challenge_id FROM access.identity_address_challenges
                 WHERE tenant_id = $1 AND realm_id = $2 AND status = 'open' AND expires_ms <= $3
                 ORDER BY expires_ms LIMIT $4)",
            tenant,
            realm,
            now_ms,
            limit,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n)
    }

    /// The DEK of challenge `id`, as a subject's key row: what seals and opens its code message.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn challenge_key(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<SubjectKeyRow>, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let row = sqlx::query!(
            "SELECT kek_id, wrapped_dek FROM access.identity_address_challenges
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_id = $3",
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| SubjectKeyRow {
            kek_id: r.kek_id,
            wrapped_dek: r.wrapped_dek,
        }))
    }

    /// The id of the subject's live identifier with blind index `index`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn identifier_id(
        &mut self,
        subject: [u8; 16],
        index: &[u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let id = sqlx::query_scalar!(
            "SELECT identifier_id FROM access.identity_identifiers
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                AND value_index = $4",
            tenant,
            realm,
            uuid(subject),
            index.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(id.map(|u| *u.as_bytes()))
    }

    /// Records since when `subject` has owned the mailbox of identifier `identifier`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_mailbox(
        &mut self,
        identifier: [u8; 16],
        subject: [u8; 16],
        owner_since_ms: i64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        sqlx::query!(
            "INSERT INTO access.identity_mailboxes (tenant_id, realm_id, identifier_id, subject_id, owner_since_ms)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            uuid(identifier),
            uuid(subject),
            owner_since_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Since when the subject has owned the mailbox its messages go to (TN-66, OP-153 m.3 (i)):
    /// the proof of its oldest live e-mail identifier, or the time Access first recorded it.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn mailbox_since(&mut self, subject: [u8; 16]) -> Result<Option<i64>, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let since = sqlx::query_scalar!(
            r#"SELECT COALESCE(m.owner_since_ms, (extract(epoch FROM i.created_at) * 1000)::bigint) AS "since!"
                 FROM access.identity_identifiers i
                 LEFT JOIN access.identity_mailboxes m
                   ON m.tenant_id = i.tenant_id AND m.realm_id = i.realm_id
                  AND m.identifier_id = i.identifier_id
                WHERE i.tenant_id = $1 AND i.realm_id = $2 AND i.subject_id = $3
                  AND i.status = 'active' AND i.kind = 'email'
                ORDER BY i.identifier_id LIMIT 1"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(since)
    }

    /// Retires an identifier's blind index: it stays taken, until `reusable_ms` when set.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_tombstone(
        &mut self,
        index: &[u8; 32],
        subject: [u8; 16],
        retired_ms: i64,
        reusable_ms: Option<i64>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        sqlx::query!(
            "INSERT INTO access.identity_identifier_tombstones
               (tenant_id, realm_id, value_index, subject_id, retired_ms, reusable_ms)
             VALUES ($1, $2, $3, $4, $5, $6)",
            tenant,
            realm,
            index.as_slice(),
            uuid(subject),
            retired_ms,
            reusable_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Whether the blind index is retired and not yet reusable at `now_ms` (TN-76 m.3).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn identifier_retired(
        &mut self,
        index: &[u8; 32],
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let hit = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM access.identity_identifier_tombstones
                 WHERE tenant_id = $1 AND realm_id = $2 AND value_index = $3
                   AND (reusable_ms IS NULL OR reusable_ms > $4)) AS "hit!""#,
            tenant,
            realm,
            index.as_slice(),
            now_ms,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(hit)
    }

    /// Revokes every active credential of `subject`, the last one included: a proof of the
    /// mailbox outranks what was set before it (TN-64, TNI-5). Returns how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_all_credentials(&mut self, subject: [u8; 16]) -> Result<u64, StoreError> {
        let (tenant, realm) = self.challenge_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_credentials SET status = 'revoked', revoked_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'",
            tenant,
            realm,
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n)
    }
}
