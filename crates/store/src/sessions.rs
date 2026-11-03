//! Authentication flows, login sessions, device markers and TOTP steps (TN-36, TN-50, TN-102,
//! MD-7, X33, RFC 6238). Flows are ephemeral and hash-only (OP-146 m.5 (f)); sessions and
//! markers are ended or revoked, never deleted (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

/// A flow to store.
pub struct NewFlow<'a> {
    /// Days since the Unix epoch of the flow's start; the partition.
    pub day: i32,
    /// SHA-256 of the flow handle.
    pub flow_hash: &'a [u8; 32],
    /// SHA-256 of the starting browser's device secret.
    pub device_hash: &'a [u8; 32],
    /// SHA-256 of a pending resume token, when one is out.
    pub resume_hash: Option<&'a [u8; 32]>,
    /// Absolute end, Unix milliseconds.
    pub expires_ms: i64,
    /// Encoded state.
    pub state: &'a [u8],
}

/// A stored flow.
#[derive(Clone, Debug)]
pub struct FlowRow {
    /// Partition day.
    pub day: i32,
    /// SHA-256 of the handle.
    pub flow_hash: [u8; 32],
    /// SHA-256 of the device secret.
    pub device_hash: [u8; 32],
    /// SHA-256 of the pending resume token.
    pub resume_hash: Option<[u8; 32]>,
    /// Compare-and-set version.
    pub version: i32,
    /// `open`, `done` or `abandoned`.
    pub status: String,
    /// Absolute end, Unix milliseconds.
    pub expires_ms: i64,
    /// Encoded state.
    pub state: Vec<u8>,
}

/// A flow change, applied only over `version`.
pub struct FlowUpdate<'a> {
    /// Partition day.
    pub day: i32,
    /// SHA-256 of the handle.
    pub flow_hash: &'a [u8; 32],
    /// The version that was read.
    pub version: i32,
    /// `open`, `done` or `abandoned`.
    pub status: &'a str,
    /// Encoded state.
    pub state: &'a [u8],
    /// The pending resume token's digest.
    pub resume_hash: Option<&'a [u8; 32]>,
}

/// A session to store.
pub struct NewSession<'a> {
    /// SHA-256 of the cookie value.
    pub cookie_hash: &'a [u8; 32],
    /// The subject.
    pub subject: [u8; 16],
    /// The subject's `session_epoch` at issue.
    pub session_epoch: i64,
    /// "Keep me signed in on this device".
    pub keep_signed_in: bool,
    /// Issue time, Unix milliseconds.
    pub created_ms: i64,
    /// Time of the authentication, Unix milliseconds.
    pub auth_time_ms: i64,
    /// Idle timeout.
    pub idle_ms: i64,
    /// Absolute end.
    pub expires_ms: i64,
    /// Encoded assurance.
    pub assurance: &'a [u8],
}

/// A stored session with its subject's current state (Δ = 0, MD-7).
#[derive(Clone, Debug)]
pub struct SessionRow {
    /// Internal id.
    pub id: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// The epoch the session carries.
    pub session_epoch: i64,
    /// The subject's epoch now.
    pub subject_epoch: i64,
    /// The subject's TN-49 status now.
    pub subject_status: String,
    /// "Keep me signed in".
    pub keep_signed_in: bool,
    /// Issue time.
    pub created_ms: i64,
    /// Authentication time.
    pub auth_time_ms: i64,
    /// Last use.
    pub last_seen_ms: i64,
    /// Idle timeout.
    pub idle_ms: i64,
    /// Absolute end.
    pub expires_ms: i64,
    /// Encoded assurance.
    pub assurance: Vec<u8>,
    /// End time, when ended.
    pub ended_ms: Option<i64>,
    /// `logout`, `epoch` or `admin`.
    pub end_reason: Option<String>,
}

/// A stored device marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MarkerRow {
    /// The subject.
    pub subject: [u8; 16],
    /// The epoch it was issued under.
    pub session_epoch: i64,
    /// Absolute end.
    pub expires_ms: i64,
    /// Revocation time.
    pub revoked_ms: Option<i64>,
}

/// A subject whose `session_epoch` moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochChange {
    /// The subject.
    pub subject: [u8; 16],
    /// The epoch now.
    pub session_epoch: i64,
    /// When it moved, Unix milliseconds of the database clock.
    pub at_ms: i64,
}

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn digest(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

struct SessionRecord {
    session_id: Uuid,
    subject_id: Uuid,
    session_epoch: i64,
    subject_epoch: i64,
    subject_status: String,
    keep_signed_in: bool,
    created_ms: i64,
    auth_time_ms: i64,
    last_seen_ms: i64,
    idle_ms: i64,
    expires_ms: i64,
    assurance: Vec<u8>,
    ended_ms: Option<i64>,
    end_reason: Option<String>,
}

impl SessionRecord {
    fn into_row(self) -> SessionRow {
        SessionRow {
            id: *self.session_id.as_bytes(),
            subject: *self.subject_id.as_bytes(),
            session_epoch: self.session_epoch,
            subject_epoch: self.subject_epoch,
            subject_status: self.subject_status,
            keep_signed_in: self.keep_signed_in,
            created_ms: self.created_ms,
            auth_time_ms: self.auth_time_ms,
            last_seen_ms: self.last_seen_ms,
            idle_ms: self.idle_ms,
            expires_ms: self.expires_ms,
            assurance: self.assurance,
            ended_ms: self.ended_ms,
            end_reason: self.end_reason,
        }
    }
}

struct FlowRecord {
    day: i32,
    flow_hash: Vec<u8>,
    device_hash: Vec<u8>,
    resume_hash: Option<Vec<u8>>,
    version: i32,
    status: String,
    expires_ms: i64,
    state: Vec<u8>,
}

impl FlowRecord {
    fn into_row(self) -> Result<FlowRow, StoreError> {
        Ok(FlowRow {
            day: self.day,
            flow_hash: digest(self.flow_hash)?,
            device_hash: digest(self.device_hash)?,
            resume_hash: self.resume_hash.map(digest).transpose()?,
            version: self.version,
            status: self.status,
            expires_ms: self.expires_ms,
            state: self.state,
        })
    }
}

impl TenantTx {
    fn realm_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Stores a new flow.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_flow(&mut self, f: &NewFlow<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        sqlx::query!(
            "INSERT INTO access.auth_flows
               (tenant_id, realm_id, day, flow_hash, device_hash, resume_hash, expires_ms, state)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            tenant,
            realm,
            f.day,
            f.flow_hash.as_slice(),
            f.device_hash.as_slice(),
            f.resume_hash.map(<[u8; 32]>::as_slice),
            f.expires_ms,
            f.state,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The flow with handle digest `hash` started on or after `from_day`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn flow(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<FlowRow>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        sqlx::query_as!(
            FlowRecord,
            "SELECT day, flow_hash, device_hash, resume_hash, version, status, expires_ms, state
               FROM access.auth_flows
              WHERE tenant_id = $1 AND realm_id = $2 AND day >= $3 AND flow_hash = $4
              FOR UPDATE",
            tenant,
            realm,
            from_day,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(FlowRecord::into_row)
        .transpose()
    }

    /// The open flow whose pending resume token has digest `hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn flow_by_resume(
        &mut self,
        from_day: i32,
        hash: &[u8; 32],
    ) -> Result<Option<FlowRow>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        sqlx::query_as!(
            FlowRecord,
            "SELECT day, flow_hash, device_hash, resume_hash, version, status, expires_ms, state
               FROM access.auth_flows
              WHERE tenant_id = $1 AND realm_id = $2 AND day >= $3 AND resume_hash = $4
              FOR UPDATE",
            tenant,
            realm,
            from_day,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(FlowRecord::into_row)
        .transpose()
    }

    /// Applies a flow change; false when the flow moved since it was read or is finished.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn update_flow(&mut self, u: &FlowUpdate<'_>) -> Result<bool, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let n = sqlx::query!(
            "UPDATE access.auth_flows
                SET version = version + 1, status = $6, state = $7, resume_hash = $8
              WHERE tenant_id = $1 AND realm_id = $2 AND day = $3 AND flow_hash = $4
                AND version = $5 AND status = 'open'",
            tenant,
            realm,
            u.day,
            u.flow_hash.as_slice(),
            u.version,
            u.status,
            u.state,
            u.resume_hash.map(<[u8; 32]>::as_slice),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Stores a session; returns its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_session(&mut self, s: &NewSession<'_>) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.login_sessions
                 (tenant_id, realm_id, cookie_hash, subject_id, session_epoch, keep_signed_in,
                  created_ms, auth_time_ms, last_seen_ms, idle_ms, expires_ms, assurance)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $7, $9, $10, $11)
               RETURNING session_id AS "id!""#,
            tenant,
            realm,
            s.cookie_hash.as_slice(),
            uuid(s.subject),
            s.session_epoch,
            s.keep_signed_in,
            s.created_ms,
            s.auth_time_ms,
            s.idle_ms,
            s.expires_ms,
            s.assurance,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The session whose cookie has digest `hash`, with its subject's current epoch and
    /// status, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn session_by_cookie(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<SessionRow>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        Ok(sqlx::query_as!(
            SessionRecord,
            "SELECT l.session_id, l.subject_id, l.session_epoch, s.session_epoch AS subject_epoch,
                    s.status AS subject_status, l.keep_signed_in, l.created_ms, l.auth_time_ms,
                    l.last_seen_ms, l.idle_ms, l.expires_ms, l.assurance, l.ended_ms, l.end_reason
               FROM access.login_sessions l
               JOIN access.identity_subjects s
                 ON s.tenant_id = l.tenant_id AND s.realm_id = l.realm_id AND s.subject_id = l.subject_id
              WHERE l.tenant_id = $1 AND l.realm_id = $2 AND l.cookie_hash = $3
              FOR UPDATE OF l",
            tenant,
            realm,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(SessionRecord::into_row))
    }

    /// The session with `id`, with its subject's current epoch and status, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn session_by_id(&mut self, id: [u8; 16]) -> Result<Option<SessionRow>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        Ok(sqlx::query_as!(
            SessionRecord,
            "SELECT l.session_id, l.subject_id, l.session_epoch, s.session_epoch AS subject_epoch,
                    s.status AS subject_status, l.keep_signed_in, l.created_ms, l.auth_time_ms,
                    l.last_seen_ms, l.idle_ms, l.expires_ms, l.assurance, l.ended_ms, l.end_reason
               FROM access.login_sessions l
               JOIN access.identity_subjects s
                 ON s.tenant_id = l.tenant_id AND s.realm_id = l.realm_id AND s.subject_id = l.subject_id
              WHERE l.tenant_id = $1 AND l.realm_id = $2 AND l.session_id = $3
              FOR UPDATE OF l",
            tenant,
            realm,
            uuid(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(SessionRecord::into_row))
    }

    /// The subject's sessions that are not ended, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn live_sessions(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<SessionRow>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        Ok(sqlx::query_as!(
            SessionRecord,
            "SELECT l.session_id, l.subject_id, l.session_epoch, s.session_epoch AS subject_epoch,
                    s.status AS subject_status, l.keep_signed_in, l.created_ms, l.auth_time_ms,
                    l.last_seen_ms, l.idle_ms, l.expires_ms, l.assurance, l.ended_ms, l.end_reason
               FROM access.login_sessions l
               JOIN access.identity_subjects s
                 ON s.tenant_id = l.tenant_id AND s.realm_id = l.realm_id AND s.subject_id = l.subject_id
              WHERE l.tenant_id = $1 AND l.realm_id = $2 AND l.subject_id = $3 AND l.ended_ms IS NULL
              ORDER BY l.session_id DESC",
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?
        .into_iter()
        .map(SessionRecord::into_row)
        .collect())
    }

    /// Records a use of a live session.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn touch_session(&mut self, id: [u8; 16], at_ms: i64) -> Result<(), StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        sqlx::query!(
            "UPDATE access.login_sessions SET last_seen_ms = greatest(last_seen_ms, $4)
              WHERE tenant_id = $1 AND realm_id = $2 AND session_id = $3 AND ended_ms IS NULL",
            tenant,
            realm,
            uuid(id),
            at_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends a session; false when it was already ended. Its live grants are revoked in the
    /// same transaction (G57) and those of clients with a back-channel endpoint are queued for
    /// a logout notice (§10.4.6).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_session(
        &mut self,
        id: [u8; 16],
        at_ms: i64,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let n = sqlx::query!(
            "UPDATE access.login_sessions SET ended_ms = $4, end_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND session_id = $3 AND ended_ms IS NULL",
            tenant,
            realm,
            uuid(id),
            at_ms,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if n != 1 {
            return Ok(false);
        }
        let grant_reason = if reason == "epoch" { "epoch" } else { "logout" };
        let notify = sqlx::query_scalar!(
            "WITH revoked AS (
               UPDATE access.oauth_grants SET revoked_ms = $4, revoke_reason = $5
                WHERE tenant_id = $1 AND realm_id = $2 AND session_id = $3 AND revoked_ms IS NULL
               RETURNING grant_id, client_uuid)
             SELECT r.grant_id FROM revoked r
               JOIN access.idp_clients c
                 ON c.tenant_id = $1 AND c.realm_id = $2 AND c.client_uuid = r.client_uuid
              WHERE c.backchannel_logout_uri IS NOT NULL
              ORDER BY r.grant_id",
            tenant,
            realm,
            uuid(id),
            at_ms,
            grant_reason,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        self.queue_backchannel_logout(&notify).await?;
        Ok(true)
    }

    /// Carries a live session from epoch `from` to epoch `to` with a new authentication
    /// (step-up, MFA enablement); false when it is ended or not at `from`, so a revoked
    /// session is never carried forward.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn restamp_session(
        &mut self,
        id: [u8; 16],
        from: i64,
        to: i64,
        auth_time_ms: i64,
        assurance: &[u8],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let n = sqlx::query!(
            "UPDATE access.login_sessions SET session_epoch = $5, auth_time_ms = $6, assurance = $7
              WHERE tenant_id = $1 AND realm_id = $2 AND session_id = $3 AND ended_ms IS NULL
                AND session_epoch = $4",
            tenant,
            realm,
            uuid(id),
            from,
            to,
            auth_time_ms,
            assurance,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Stores a device marker (X33).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_marker(
        &mut self,
        hash: &[u8; 32],
        subject: [u8; 16],
        session_epoch: i64,
        created_ms: i64,
        expires_ms: i64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        sqlx::query!(
            "INSERT INTO access.device_markers
               (tenant_id, realm_id, marker_hash, subject_id, session_epoch, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            tenant,
            realm,
            hash.as_slice(),
            uuid(subject),
            session_epoch,
            created_ms,
            expires_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The device marker with digest `hash`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn marker(&mut self, hash: &[u8; 32]) -> Result<Option<MarkerRow>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let row = sqlx::query!(
            "SELECT subject_id, session_epoch, expires_ms, revoked_ms FROM access.device_markers
              WHERE tenant_id = $1 AND realm_id = $2 AND marker_hash = $3",
            tenant,
            realm,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| MarkerRow {
            subject: *r.subject_id.as_bytes(),
            session_epoch: r.session_epoch,
            expires_ms: r.expires_ms,
            revoked_ms: r.revoked_ms,
        }))
    }

    /// Revokes the subject's live device markers; returns how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn revoke_markers(
        &mut self,
        subject: [u8; 16],
        at_ms: i64,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        Ok(sqlx::query!(
            "UPDATE access.device_markers SET revoked_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND revoked_ms IS NULL",
            tenant,
            realm,
            uuid(subject),
            at_ms,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected())
    }

    /// Records TOTP step `step` as used on an active credential; false when that step or a
    /// later one was already used (RFC 6238 §5.2).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn use_otp_step(
        &mut self,
        credential: [u8; 16],
        step: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_credentials SET otp_last_step = $4, last_used_at = now()
              WHERE tenant_id = $1 AND realm_id = $2 AND credential_id = $3 AND status = 'active'
                AND (otp_last_step IS NULL OR otp_last_step < $4)",
            tenant,
            realm,
            uuid(credential),
            step,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject's oldest active e-mail identifier, else its oldest phone identifier, as
    /// `(kind, value)`: where sign-in messages go (E42).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn contact(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<(String, String)>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let row = sqlx::query!(
            "SELECT kind, value FROM access.identity_identifiers
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                AND kind IN ('email', 'phone')
              ORDER BY kind = 'email' DESC, identifier_id LIMIT 1",
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| (r.kind, r.value)))
    }

    /// Subjects whose `session_epoch` moved after `since_ms` (database clock), oldest first,
    /// at most `limit` (MD-7 poll tier).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn epochs_since(
        &mut self,
        since_ms: i64,
        limit: i64,
    ) -> Result<Vec<EpochChange>, StoreError> {
        let (tenant, realm) = self.realm_scope()?;
        let rows = sqlx::query!(
            r#"SELECT subject_id, session_epoch,
                      (extract(epoch FROM session_epoch_at) * 1000)::bigint AS "at_ms!"
                 FROM access.identity_subjects
                WHERE tenant_id = $1 AND realm_id = $2
                  AND session_epoch_at > to_timestamp($3::bigint / 1000.0)
                ORDER BY session_epoch_at LIMIT $4"#,
            tenant,
            realm,
            since_ms,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| EpochChange {
                subject: *r.subject_id.as_bytes(),
                session_epoch: r.session_epoch,
                at_ms: r.at_ms,
            })
            .collect())
    }
}

/// Opens the flow partition of `day` (archive role); idempotent (OP-146 m.5 (f)).
///
/// # Errors
/// [`StoreError`].
pub async fn open_flow_day(archive: &PgPool, day: i32) -> Result<String, StoreError> {
    Ok(
        sqlx::query_scalar!(r#"SELECT access.open_auth_flow_day($1) AS "name!""#, day,)
            .fetch_one(archive)
            .await?,
    )
}
