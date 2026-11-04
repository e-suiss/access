//! The realm authorization server's state (OP-146 I7): pending authorization requests and
//! codes are ephemeral, digest-keyed and partitioned by day (OP-146 m.5 (f)); grants, their
//! refresh chains and pairwise subjects are identity records that are revoked or rotated, never
//! deleted (OP-73, CR-38, TN-31, MD-10).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn digest(v: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn bytes16(v: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A pending authorization request to store.
pub struct NewRequest<'a> {
    /// Partition day.
    pub day: i32,
    /// SHA-256 of the `request_uri` handle.
    pub hash: &'a [u8; 32],
    /// The client.
    pub client: [u8; 16],
    /// Pushed through `/par` (RFC 9126), else stored by `/authorize` while the user signs in.
    pub pushed: bool,
    /// Encoded, validated parameters.
    pub params: &'a [u8],
    /// Creation, Unix milliseconds.
    pub created_ms: i64,
    /// Absolute end, Unix milliseconds.
    pub expires_ms: i64,
}

/// A stored authorization request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestRow {
    /// Partition day.
    pub day: i32,
    /// The client.
    pub client: [u8; 16],
    /// Pushed through `/par`.
    pub pushed: bool,
    /// Encoded parameters.
    pub params: Vec<u8>,
    /// Creation.
    pub created_ms: i64,
    /// Absolute end.
    pub expires_ms: i64,
    /// When it was used.
    pub used_ms: Option<i64>,
}

/// An authorization code to store.
pub struct NewCode<'a> {
    /// Partition day.
    pub day: i32,
    /// SHA-256 of the code.
    pub hash: &'a [u8; 32],
    /// The client.
    pub client: [u8; 16],
    /// The login session it was issued from.
    pub session: [u8; 16],
    /// Encoded details: redirect URI, PKCE challenge, `dpop_jkt`, nonce, scope.
    pub details: &'a [u8],
    /// Issue time.
    pub created_ms: i64,
    /// Absolute end.
    pub expires_ms: i64,
}

/// A stored authorization code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeRow {
    /// Partition day.
    pub day: i32,
    /// The client.
    pub client: [u8; 16],
    /// The login session.
    pub session: [u8; 16],
    /// Encoded details.
    pub details: Vec<u8>,
    /// Absolute end.
    pub expires_ms: i64,
    /// The grant it was redeemed into, when redeemed.
    pub grant: Option<[u8; 16]>,
}

/// A grant to store.
pub struct NewGrant<'a> {
    /// The random `sid` of its tokens.
    pub sid: [u8; 16],
    /// The client.
    pub client: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// The login session.
    pub session: [u8; 16],
    /// The subject's epoch at issue (TN-50).
    pub session_epoch: i64,
    /// The key refresh tokens are bound to (TN-31).
    pub dpop_jkt: Option<&'a [u8; 32]>,
    /// Encoded details: scope, `auth_time`, `acr`.
    pub details: &'a [u8],
    /// Issue time.
    pub created_ms: i64,
    /// Absolute end of the refresh chain.
    pub expires_ms: i64,
}

/// A stored grant with its subject's current state (Δ = 0, MD-7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRow {
    /// Internal id.
    pub id: [u8; 16],
    /// The `sid` of its tokens.
    pub sid: [u8; 16],
    /// The client.
    pub client: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// The login session.
    pub session: [u8; 16],
    /// The epoch it was issued under.
    pub session_epoch: i64,
    /// The subject's epoch now.
    pub subject_epoch: i64,
    /// The subject's TN-49 status now.
    pub subject_status: String,
    /// The refresh binding key.
    pub dpop_jkt: Option<[u8; 32]>,
    /// Encoded details.
    pub details: Vec<u8>,
    /// Absolute end of the refresh chain.
    pub expires_ms: i64,
    /// When it was revoked.
    pub revoked_ms: Option<i64>,
}

/// A stored refresh token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshRow {
    /// Its grant.
    pub grant: [u8; 16],
    /// When it was rotated; a second use is reuse (TN-31).
    pub rotated_ms: Option<i64>,
}

struct GrantRecord {
    grant_id: Uuid,
    sid: Vec<u8>,
    client_uuid: Uuid,
    subject_id: Uuid,
    session_id: Uuid,
    session_epoch: i64,
    subject_epoch: i64,
    subject_status: String,
    dpop_jkt: Option<Vec<u8>>,
    details: Vec<u8>,
    expires_ms: i64,
    revoked_ms: Option<i64>,
}

impl GrantRecord {
    fn into_row(self) -> Result<GrantRow, StoreError> {
        Ok(GrantRow {
            id: *self.grant_id.as_bytes(),
            sid: bytes16(&self.sid)?,
            client: *self.client_uuid.as_bytes(),
            subject: *self.subject_id.as_bytes(),
            session: *self.session_id.as_bytes(),
            session_epoch: self.session_epoch,
            subject_epoch: self.subject_epoch,
            subject_status: self.subject_status,
            dpop_jkt: self.dpop_jkt.as_deref().map(digest).transpose()?,
            details: self.details,
            expires_ms: self.expires_ms,
            revoked_ms: self.revoked_ms,
        })
    }
}

impl TenantTx {
    fn oauth_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Stores a pending authorization request.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_oauth_request(&mut self, r: &NewRequest<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query!(
            "INSERT INTO access.oauth_requests (tenant_id, realm_id, day, request_hash, client_uuid,
                    pushed, params, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            tenant,
            realm,
            r.day,
            r.hash.as_slice(),
            uuid(r.client),
            r.pushed,
            r.params,
            r.created_ms,
            r.expires_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The request whose handle has digest `hash`, from day `from_day` on, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn oauth_request(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<RequestRow>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let row = sqlx::query!(
            "SELECT day, client_uuid, pushed, params, created_ms, expires_ms, used_ms
               FROM access.oauth_requests
              WHERE tenant_id = $1 AND realm_id = $2 AND day >= $3 AND request_hash = $4
              FOR UPDATE",
            tenant,
            realm,
            from_day,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| RequestRow {
            day: r.day,
            client: *r.client_uuid.as_bytes(),
            pushed: r.pushed,
            params: r.params,
            created_ms: r.created_ms,
            expires_ms: r.expires_ms,
            used_ms: r.used_ms,
        }))
    }

    /// Marks a request used; false when it already was (RFC 9126 §4: one use).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn use_oauth_request(
        &mut self,
        day: i32,
        hash: &[u8; 32],
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let n = sqlx::query!(
            "UPDATE access.oauth_requests SET used_ms = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND day = $3 AND request_hash = $4
                AND used_ms IS NULL",
            tenant,
            realm,
            day,
            hash.as_slice(),
            at_ms,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Stores an authorization code.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_code(&mut self, c: &NewCode<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query!(
            "INSERT INTO access.oauth_codes (tenant_id, realm_id, day, code_hash, client_uuid,
                    session_id, details, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            tenant,
            realm,
            c.day,
            c.hash.as_slice(),
            uuid(c.client),
            uuid(c.session),
            c.details,
            c.created_ms,
            c.expires_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The code with digest `hash`, from day `from_day` on, locked so that two exchanges of
    /// one code serialize.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn code(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<CodeRow>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let row = sqlx::query!(
            "SELECT day, client_uuid, session_id, details, expires_ms, grant_id
               FROM access.oauth_codes
              WHERE tenant_id = $1 AND realm_id = $2 AND day >= $3 AND code_hash = $4
              FOR UPDATE",
            tenant,
            realm,
            from_day,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| CodeRow {
            day: r.day,
            client: *r.client_uuid.as_bytes(),
            session: *r.session_id.as_bytes(),
            details: r.details,
            expires_ms: r.expires_ms,
            grant: r.grant_id.map(|g| *g.as_bytes()),
        }))
    }

    /// Redeems a code into `grant` by compare-and-set; false when it was redeemed already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn redeem_code(
        &mut self,
        day: i32,
        hash: &[u8; 32],
        at_ms: i64,
        grant: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let n = sqlx::query!(
            "UPDATE access.oauth_codes SET redeemed_ms = $5, grant_id = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND day = $3 AND code_hash = $4
                AND redeemed_ms IS NULL",
            tenant,
            realm,
            day,
            hash.as_slice(),
            at_ms,
            uuid(grant),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Records a client assertion's replay key for `day`; `true` the first time.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn assertion_first_use(
        &mut self,
        day: i32,
        key: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let n = sqlx::query!(
            "INSERT INTO access.client_assertion_replay (tenant_id, realm_id, day, key_hash)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            day,
            key.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Stores a grant; returns its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_grant(&mut self, g: &NewGrant<'_>) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.oauth_grants (tenant_id, realm_id, sid, client_uuid, subject_id,
                    session_id, session_epoch, dpop_jkt, details, created_ms, expires_ms)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               RETURNING grant_id AS "id!""#,
            tenant,
            realm,
            g.sid.as_slice(),
            uuid(g.client),
            uuid(g.subject),
            uuid(g.session),
            g.session_epoch,
            g.dpop_jkt.map(<[u8; 32]>::as_slice),
            g.details,
            g.created_ms,
            g.expires_ms,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The grant with `id`, with its subject's current epoch and status, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn grant(&mut self, id: [u8; 16]) -> Result<Option<GrantRow>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query_as!(
            GrantRecord,
            "SELECT g.grant_id, g.sid, g.client_uuid, g.subject_id, g.session_id, g.session_epoch,
                    s.session_epoch AS subject_epoch, s.status AS subject_status, g.dpop_jkt,
                    g.details, g.expires_ms, g.revoked_ms
               FROM access.oauth_grants g
               JOIN access.identity_subjects s
                 ON s.tenant_id = g.tenant_id AND s.realm_id = g.realm_id AND s.subject_id = g.subject_id
              WHERE g.tenant_id = $1 AND g.realm_id = $2 AND g.grant_id = $3
              FOR UPDATE OF g",
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(GrantRecord::into_row)
        .transpose()
    }

    /// The grant whose tokens carry `sid`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn grant_by_sid(&mut self, sid: &[u8; 16]) -> Result<Option<GrantRow>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query_as!(
            GrantRecord,
            "SELECT g.grant_id, g.sid, g.client_uuid, g.subject_id, g.session_id, g.session_epoch,
                    s.session_epoch AS subject_epoch, s.status AS subject_status, g.dpop_jkt,
                    g.details, g.expires_ms, g.revoked_ms
               FROM access.oauth_grants g
               JOIN access.identity_subjects s
                 ON s.tenant_id = g.tenant_id AND s.realm_id = g.realm_id AND s.subject_id = g.subject_id
              WHERE g.tenant_id = $1 AND g.realm_id = $2 AND g.sid = $3",
            tenant,
            realm,
            sid.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(GrantRecord::into_row)
        .transpose()
    }

    /// The grants of a login session that are not revoked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn session_grants(&mut self, session: [u8; 16]) -> Result<Vec<GrantRow>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query_as!(
            GrantRecord,
            "SELECT g.grant_id, g.sid, g.client_uuid, g.subject_id, g.session_id, g.session_epoch,
                    s.session_epoch AS subject_epoch, s.status AS subject_status, g.dpop_jkt,
                    g.details, g.expires_ms, g.revoked_ms
               FROM access.oauth_grants g
               JOIN access.identity_subjects s
                 ON s.tenant_id = g.tenant_id AND s.realm_id = g.realm_id AND s.subject_id = g.subject_id
              WHERE g.tenant_id = $1 AND g.realm_id = $2 AND g.session_id = $3 AND g.revoked_ms IS NULL
              ORDER BY g.grant_id",
            tenant,
            realm,
            uuid(session),
        )
        .fetch_all(&mut *self.tx)
        .await?
        .into_iter()
        .map(GrantRecord::into_row)
        .collect()
    }

    /// Revokes a grant; false when it already was.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_grant(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let n = sqlx::query!(
            "UPDATE access.oauth_grants SET revoked_ms = $4, revoke_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND grant_id = $3 AND revoked_ms IS NULL",
            tenant,
            realm,
            uuid(id),
            at_ms,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Stores a refresh token's digest under `grant`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_refresh(
        &mut self,
        hash: &[u8; 32],
        grant: [u8; 16],
        at_ms: i64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query!(
            "INSERT INTO access.oauth_refresh_tokens (tenant_id, realm_id, token_hash, grant_id, created_ms)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            hash.as_slice(),
            uuid(grant),
            at_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The refresh token with digest `hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn refresh(&mut self, hash: &[u8; 32]) -> Result<Option<RefreshRow>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let row = sqlx::query!(
            "SELECT grant_id, rotated_ms FROM access.oauth_refresh_tokens
              WHERE tenant_id = $1 AND realm_id = $2 AND token_hash = $3
              FOR UPDATE",
            tenant,
            realm,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| RefreshRow {
            grant: *r.grant_id.as_bytes(),
            rotated_ms: r.rotated_ms,
        }))
    }

    /// Rotates a refresh token by compare-and-set; false when it was rotated already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn rotate_refresh(
        &mut self,
        hash: &[u8; 32],
        at_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let n = sqlx::query!(
            "UPDATE access.oauth_refresh_tokens SET rotated_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND token_hash = $3 AND rotated_ms IS NULL",
            tenant,
            realm,
            hash.as_slice(),
            at_ms,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject whose pairwise value for `sector` is `value` (OP-149 A11).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn pairwise_subject(
        &mut self,
        sector: [u8; 16],
        value: &str,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        let row = sqlx::query_scalar!(
            "SELECT subject_id FROM access.pairwise_subjects
              WHERE tenant_id = $1 AND realm_id = $2 AND sector = $3 AND value = $4",
            tenant,
            realm,
            uuid(sector),
            value,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|s| *s.as_bytes()))
    }

    /// The subject's pairwise value for `sector`: the stored one, else `candidate`, stored now
    /// (MD-10: random, never derived).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn pairwise(
        &mut self,
        subject: [u8; 16],
        sector: [u8; 16],
        candidate: &str,
    ) -> Result<String, StoreError> {
        let (tenant, realm) = self.oauth_scope()?;
        sqlx::query!(
            "INSERT INTO access.pairwise_subjects (tenant_id, realm_id, subject_id, sector, value)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, realm_id, subject_id, sector) DO NOTHING",
            tenant,
            realm,
            uuid(subject),
            uuid(sector),
            candidate,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(sqlx::query_scalar!(
            "SELECT value FROM access.pairwise_subjects
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND sector = $4",
            tenant,
            realm,
            uuid(subject),
            uuid(sector),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }
}

/// Opens the authorization server's partitions of `day` (archive role); idempotent
/// (OP-146 m.5 (f)).
///
/// # Errors
/// [`StoreError`].
pub async fn open_oauth_day(archive: &PgPool, day: i32) -> Result<(), StoreError> {
    sqlx::query!("SELECT access.open_oauth_day($1)", day)
        .fetch_one(archive)
        .await?;
    Ok(())
}
