//! CIBA as an invitation (OP-155 m.3 (l), IDP-14, §10.5.3): the realm's decided setting and the
//! backchannel requests by the SHA-256 of their `auth_req_id`, each carrying the `exercise_ref`
//! of the `REQUIRE_ACTION` it invites the person to answer. Scoped to the transaction's realm by
//! row-level security; nothing is deleted (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;

fn scope(t: &TenantTx) -> Result<(Uuid, Uuid), StoreError> {
    let realm = t.realm().ok_or(StoreError::Range)?;
    Ok((
        Uuid::from_bytes(*t.tenant.as_bytes()),
        Uuid::from_bytes(*realm.as_bytes()),
    ))
}

fn i64_of(v: u64) -> Result<i64, StoreError> {
    i64::try_from(v).map_err(|_| StoreError::Range)
}

fn u64_of(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// The realm's CIBA setting (`idp.realm.ciba`, `ciba_close`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CibaSettingsRow {
    /// Whether the realm offers CIBA.
    pub enabled: bool,
    /// Whether a free `login_hint` is accepted.
    pub login_hint: bool,
    /// The clients told by ping, each with its notification endpoint.
    pub ping: Vec<([u8; 16], String)>,
}

/// A backchannel request to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewCibaRequest<'a> {
    /// SHA-256 of the `auth_req_id`.
    pub handle_hash: [u8; 32],
    /// The client.
    pub client: [u8; 16],
    /// The person the hint names, when it names one.
    pub subject: Option<[u8; 16]>,
    /// The governing domain of the `exercise_ref`.
    pub domain: [u8; 32],
    /// The nonce of the `exercise_ref`.
    pub nonce: &'a [u8],
    /// The intent digest the `REQUIRE_ACTION` is about.
    pub intent: [u8; 32],
    /// The `authorization_details` as sent.
    pub details: &'a str,
    /// The scope asked for.
    pub scope: &'a str,
    /// The binding message.
    pub binding_message: Option<&'a str>,
    /// `poll` or `ping`.
    pub mode: &'a str,
    /// The ping mode's bearer token.
    pub notification_token: Option<&'a str>,
    /// The `auth_req_id` a ping names (CIBA Core §10.2).
    pub ping_handle: Option<&'a str>,
    /// Now.
    pub now_ms: u64,
    /// Its end.
    pub expires_ms: u64,
    /// The polling interval.
    pub interval_s: u32,
}

/// A backchannel request as stored.
#[derive(Clone, PartialEq, Eq)]
pub struct CibaRequestRow {
    /// Its id.
    pub id: [u8; 16],
    /// The client.
    pub client: [u8; 16],
    /// The person the hint named.
    pub subject: Option<[u8; 16]>,
    /// The governing domain of the `exercise_ref`.
    pub domain: [u8; 32],
    /// The nonce of the `exercise_ref`.
    pub nonce: Vec<u8>,
    /// The intent digest.
    pub intent: [u8; 32],
    /// The `authorization_details` as sent.
    pub details: String,
    /// The scope asked for.
    pub scope: String,
    /// The binding message.
    pub binding_message: Option<String>,
    /// `poll` or `ping`.
    pub mode: String,
    /// The ping mode's bearer token.
    pub notification_token: Option<String>,
    /// The `auth_req_id` a ping names.
    pub ping_handle: Option<String>,
    /// When it was made.
    pub created_ms: u64,
    /// Its end.
    pub expires_ms: u64,
    /// The polling interval now.
    pub interval_s: u32,
    /// The last poll.
    pub polled_ms: Option<u64>,
    /// `approved` or `denied`, once answered.
    pub decision: Option<String>,
    /// The approving session.
    pub session: Option<[u8; 16]>,
    /// The contribution Exercise the approval committed.
    pub contribution: Option<[u8; 32]>,
    /// When it was redeemed.
    pub used_ms: Option<u64>,
}

impl core::fmt::Debug for CibaRequestRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CibaRequestRow")
            .field("id", &self.id)
            .field("mode", &self.mode)
            .field("expires_ms", &self.expires_ms)
            .field("decision", &self.decision)
            .field("used_ms", &self.used_ms)
            .finish_non_exhaustive()
    }
}

fn fixed<const N: usize>(v: Vec<u8>) -> Result<[u8; N], StoreError> {
    <[u8; N]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

macro_rules! row_of {
    ($r:expr) => {
        CibaRequestRow {
            id: *$r.ciba_id.as_bytes(),
            client: *$r.client_uuid.as_bytes(),
            subject: $r.subject_id.map(|u| *u.as_bytes()),
            domain: fixed($r.domain_id)?,
            nonce: $r.nonce,
            intent: fixed($r.intent)?,
            details: $r.details,
            scope: $r.scope,
            binding_message: $r.binding_message,
            mode: $r.mode,
            notification_token: $r.notification_token,
            ping_handle: $r.ping_handle,
            created_ms: u64_of($r.created_ms),
            expires_ms: u64_of($r.expires_ms),
            interval_s: u32::try_from($r.interval_s).unwrap_or(600),
            polled_ms: $r.polled_ms.map(u64_of),
            decision: $r.decision,
            session: $r.session_id.map(|u| *u.as_bytes()),
            contribution: $r.contribution.map(fixed).transpose()?,
            used_ms: $r.used_ms.map(u64_of),
        }
    };
}

impl TenantTx {
    /// The realm's newest CIBA setting; off when never decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ciba_settings(&mut self) -> Result<CibaSettingsRow, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT enabled, login_hint, ping_clients, ping_endpoints FROM access.idp_ciba_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(
            r.map_or_else(CibaSettingsRow::default, |r| CibaSettingsRow {
                enabled: r.enabled,
                login_hint: r.login_hint,
                ping: r
                    .ping_clients
                    .iter()
                    .map(|c| *c.as_bytes())
                    .zip(r.ping_endpoints)
                    .collect(),
            }),
        )
    }

    /// Writes the next CIBA setting under `bound` (`idp.realm.ciba`, `ciba_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_ciba(&mut self, bound: &Bound, s: &CibaSettingsRow) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let clients: Vec<Uuid> = s.ping.iter().map(|(c, _)| Uuid::from_bytes(*c)).collect();
        let endpoints: Vec<String> = s.ping.iter().map(|(_, e)| e.clone()).collect();
        sqlx::query!(
            "INSERT INTO access.idp_ciba_settings
               (tenant_id, realm_id, version, enabled, login_hint, ping_clients, ping_endpoints,
                domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_ciba_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5, $6, $7, $8",
            tenant,
            realm,
            s.enabled,
            s.login_hint,
            &clients,
            &endpoints,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps a backchannel request; its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_ciba(&mut self, c: &NewCibaRequest<'_>) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.oauth_ciba_requests (tenant_id, realm_id, handle_hash, client_uuid,
                    subject_id, domain_id, nonce, intent, details, scope, binding_message, mode,
                    notification_token, ping_handle, created_ms, expires_ms, interval_s)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
             RETURNING ciba_id",
            tenant,
            realm,
            c.handle_hash.as_slice(),
            Uuid::from_bytes(c.client),
            c.subject.map(Uuid::from_bytes),
            c.domain.as_slice(),
            c.nonce,
            c.intent.as_slice(),
            c.details,
            c.scope,
            c.binding_message,
            c.mode,
            c.notification_token,
            c.ping_handle,
            i64_of(c.now_ms)?,
            i64_of(c.expires_ms)?,
            i32::try_from(c.interval_s).map_err(|_| StoreError::Range)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The backchannel request of `handle_hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ciba_by_handle(
        &mut self,
        handle_hash: &[u8; 32],
    ) -> Result<Option<CibaRequestRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT ciba_id, client_uuid, subject_id, domain_id, nonce, intent, details, scope,
                    binding_message, mode, notification_token, ping_handle, created_ms, expires_ms,
                    interval_s,
                    polled_ms, decision, session_id, contribution, used_ms
               FROM access.oauth_ciba_requests
              WHERE tenant_id = $1 AND realm_id = $2 AND handle_hash = $3 FOR UPDATE",
            tenant,
            realm,
            handle_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| Ok(row_of!(r))).transpose()
    }

    /// The backchannel request `id`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ciba(&mut self, id: [u8; 16]) -> Result<Option<CibaRequestRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT ciba_id, client_uuid, subject_id, domain_id, nonce, intent, details, scope,
                    binding_message, mode, notification_token, ping_handle, created_ms, expires_ms,
                    interval_s,
                    polled_ms, decision, session_id, contribution, used_ms
               FROM access.oauth_ciba_requests
              WHERE tenant_id = $1 AND realm_id = $2 AND ciba_id = $3 FOR UPDATE",
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| Ok(row_of!(r))).transpose()
    }

    /// Whether the nonce `nonce` of `domain`, or the contribution `contribution`, already answered
    /// an approved backchannel request (OP-154 m.13 (f)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ciba_answered(
        &mut self,
        domain: &[u8; 32],
        nonce: &[u8],
        contribution: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM access.oauth_ciba_requests
                WHERE tenant_id = $1 AND realm_id = $2
                  AND ((domain_id = $3 AND nonce = $4 AND decision = 'approved')
                       OR contribution = $5)) AS "answered!""#,
            tenant,
            realm,
            domain.as_slice(),
            nonce,
            contribution.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Notes a poll at `now_ms` with the interval it leaves (CIBA Core §11 `slow_down`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn poll_ciba(
        &mut self,
        id: [u8; 16],
        now_ms: u64,
        interval_s: u32,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.oauth_ciba_requests SET polled_ms = $4, interval_s = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND ciba_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(id),
            i64_of(now_ms)?,
            i32::try_from(interval_s).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Records the answer once: the approving session and the contribution when approved.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_ciba(
        &mut self,
        id: [u8; 16],
        approved: Option<([u8; 16], [u8; 32])>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let decision = if approved.is_some() {
            "approved"
        } else {
            "denied"
        };
        let n = sqlx::query!(
            "UPDATE access.oauth_ciba_requests
                SET decision = $4, decided_ms = $5, session_id = $6, contribution = $7
              WHERE tenant_id = $1 AND realm_id = $2 AND ciba_id = $3 AND decision IS NULL
                AND subject_id IS NOT NULL",
            tenant,
            realm,
            Uuid::from_bytes(id),
            decision,
            i64_of(now_ms)?,
            approved.map(|(s, _)| Uuid::from_bytes(s)),
            approved.as_ref().map(|(_, c)| c.as_slice()),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Notes that the client was pinged.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn ping_ciba(&mut self, id: [u8; 16], now_ms: u64) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.oauth_ciba_requests SET pinged_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND ciba_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(id),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Redeems an approved backchannel request once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn use_ciba(&mut self, id: [u8; 16], now_ms: u64) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.oauth_ciba_requests SET used_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND ciba_id = $3
                AND decision = 'approved' AND used_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(id),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
