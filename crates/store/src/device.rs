//! The device authorization grant (RFC 8628, OP-154 m.3 (p), CR-38): the realm's decided setting,
//! the device authorizations by the SHA-256 of their codes, and the wrong user codes the entry
//! limits count. Scoped to the transaction's realm by row-level security; nothing is deleted
//! (OP-73).

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

/// A device authorization to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDeviceCode<'a> {
    /// SHA-256 of the `device_code`.
    pub device_hash: [u8; 32],
    /// SHA-256 of the normalised `user_code`.
    pub user_hash: [u8; 32],
    /// The client.
    pub client: [u8; 16],
    /// The scope asked for.
    pub scope: &'a str,
    /// The IP prefix the request came from.
    pub ip_prefix: &'a str,
    /// Its country, when known.
    pub country: Option<&'a str>,
    /// Now.
    pub now_ms: u64,
    /// Its end.
    pub expires_ms: u64,
    /// The polling interval.
    pub interval_s: u32,
}

/// A device authorization as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCodeRow {
    /// Its id.
    pub device_id: [u8; 16],
    /// The client.
    pub client: [u8; 16],
    /// The scope asked for.
    pub scope: String,
    /// The IP prefix the request came from.
    pub ip_prefix: String,
    /// Its country, when known.
    pub country: Option<String>,
    /// Its end.
    pub expires_ms: u64,
    /// The polling interval now.
    pub interval_s: u32,
    /// The last poll.
    pub polled_ms: Option<u64>,
    /// `approved` or `denied`, once decided.
    pub decision: Option<String>,
    /// The person who approved it.
    pub subject: Option<[u8; 16]>,
    /// Their session.
    pub session: Option<[u8; 16]>,
    /// When it was redeemed.
    pub used_ms: Option<u64>,
}

macro_rules! row_of {
    ($r:expr) => {
        DeviceCodeRow {
            device_id: *$r.device_id.as_bytes(),
            client: *$r.client_uuid.as_bytes(),
            scope: $r.scope,
            ip_prefix: $r.ip_prefix,
            country: $r.country,
            expires_ms: u64_of($r.expires_ms),
            interval_s: u32::try_from($r.interval_s).unwrap_or(600),
            polled_ms: $r.polled_ms.map(u64_of),
            decision: $r.decision,
            subject: $r.subject_id.map(|u| *u.as_bytes()),
            session: $r.session_id.map(|u| *u.as_bytes()),
            used_ms: $r.used_ms.map(u64_of),
        }
    };
}

impl TenantTx {
    /// Whether the realm decided to offer the device authorization grant.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_code_enabled(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT enabled FROM access.idp_device_code_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }

    /// Writes the next device code setting under `bound` (`idp.realm.device_code`,
    /// `device_code_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_device_code(
        &mut self,
        bound: &Bound,
        enabled: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_device_code_settings
               (tenant_id, realm_id, version, enabled, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_device_code_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5",
            tenant,
            realm,
            enabled,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps a device authorization; `false` when its user code is already waiting.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_device_code(&mut self, d: &NewDeviceCode<'_>) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.oauth_device_codes (tenant_id, realm_id, device_hash, user_hash,
                    client_uuid, scope, ip_prefix, country, created_ms, expires_ms, interval_s)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (tenant_id, realm_id, user_hash) WHERE decision IS NULL DO NOTHING",
            tenant,
            realm,
            d.device_hash.as_slice(),
            d.user_hash.as_slice(),
            Uuid::from_bytes(d.client),
            d.scope,
            d.ip_prefix,
            d.country,
            i64_of(d.now_ms)?,
            i64_of(d.expires_ms)?,
            i32::try_from(d.interval_s).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The device authorization of `device_hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_code(
        &mut self,
        device_hash: &[u8; 32],
    ) -> Result<Option<DeviceCodeRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT device_id, client_uuid, scope, ip_prefix, country, expires_ms, interval_s,
                    polled_ms, decision, subject_id, session_id, used_ms
               FROM access.oauth_device_codes
              WHERE tenant_id = $1 AND realm_id = $2 AND device_hash = $3 FOR UPDATE",
            tenant,
            realm,
            device_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(r.map(|r| row_of!(r)))
    }

    /// The undecided device authorization of `user_hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_code_by_user(
        &mut self,
        user_hash: &[u8; 32],
    ) -> Result<Option<DeviceCodeRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT device_id, client_uuid, scope, ip_prefix, country, expires_ms, interval_s,
                    polled_ms, decision, subject_id, session_id, used_ms
               FROM access.oauth_device_codes
              WHERE tenant_id = $1 AND realm_id = $2 AND user_hash = $3 AND decision IS NULL
              FOR UPDATE",
            tenant,
            realm,
            user_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(r.map(|r| row_of!(r)))
    }

    /// Notes a poll at `now_ms` with the interval it leaves (RFC 8628 §3.5 `slow_down`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn poll_device_code(
        &mut self,
        device: [u8; 16],
        now_ms: u64,
        interval_s: u32,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.oauth_device_codes SET polled_ms = $4, interval_s = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(device),
            i64_of(now_ms)?,
            i32::try_from(interval_s).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Records the person's decision once: `subject` and `session` when approved.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_device_code(
        &mut self,
        device: [u8; 16],
        approved: Option<([u8; 16], [u8; 16])>,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let decision = if approved.is_some() {
            "approved"
        } else {
            "denied"
        };
        let n = sqlx::query!(
            "UPDATE access.oauth_device_codes
                SET decision = $4, decided_ms = $5, subject_id = $6, session_id = $7
              WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3 AND decision IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(device),
            decision,
            i64_of(now_ms)?,
            approved.map(|(s, _)| Uuid::from_bytes(s)),
            approved.map(|(_, s)| Uuid::from_bytes(s)),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Redeems an approved device authorization once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn use_device_code(
        &mut self,
        device: [u8; 16],
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.oauth_device_codes SET used_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3
                AND decision = 'approved' AND used_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(device),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Counts a wrong user code from `ip_prefix` by `subject`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn miss_device_code(
        &mut self,
        ip_prefix: &str,
        subject: [u8; 16],
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.oauth_device_misses (tenant_id, realm_id, ip_prefix, subject_id, at_ms)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            ip_prefix,
            Uuid::from_bytes(subject),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Wrong user codes from `ip_prefix` since `ip_since_ms`, and by `subject` since
    /// `subject_since_ms`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_misses(
        &mut self,
        ip_prefix: &str,
        ip_since_ms: u64,
        subject: [u8; 16],
        subject_since_ms: u64,
    ) -> Result<(u64, u64), StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            r#"SELECT
                 count(*) FILTER (WHERE ip_prefix = $3 AND at_ms >= $4) AS "ip!",
                 count(*) FILTER (WHERE subject_id = $5 AND at_ms >= $6) AS "subject!"
               FROM access.oauth_device_misses WHERE tenant_id = $1 AND realm_id = $2"#,
            tenant,
            realm,
            ip_prefix,
            i64_of(ip_since_ms)?,
            Uuid::from_bytes(subject),
            i64_of(subject_since_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok((u64_of(r.ip), u64_of(r.subject)))
    }
}
