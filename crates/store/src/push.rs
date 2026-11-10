//! Push verification (OP-156 m.3 (d), §10.1.3, §10.2.3): the realm's decided setting, the approver
//! device keys and the push challenges by the SHA-256 of their ids (CR-38). Scoped to the
//! transaction's realm by row-level security; a key is retired and a challenge ends, nothing is
//! deleted (OP-73).

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

fn u64_of(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn bytes32(v: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// An approver device key to keep (§10.1.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewDeviceKey<'a> {
    /// Its id.
    pub id: [u8; 16],
    /// Its subject.
    pub subject: [u8; 16],
    /// The RFC 7638 thumbprint of its public key.
    pub thumbprint: [u8; 32],
    /// The uncompressed SEC1 P-256 public key.
    pub public_key: &'a [u8],
    /// The name the person gave it.
    pub name: &'a str,
}

/// An active approver device key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceKeyRow {
    /// Its id.
    pub id: [u8; 16],
    /// Its subject.
    pub subject: [u8; 16],
    /// The RFC 7638 thumbprint of its public key.
    pub thumbprint: [u8; 32],
    /// The uncompressed SEC1 P-256 public key.
    pub public_key: Vec<u8>,
    /// The name the person gave it.
    pub name: String,
    /// When it was registered, Unix ms.
    pub created_ms: i64,
    /// When it last answered, Unix ms.
    pub last_seen_ms: Option<i64>,
}

/// A push challenge to keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewPushChallenge<'a> {
    /// The SHA-256 of the challenge id.
    pub hash: &'a [u8; 32],
    /// The subject it verifies.
    pub subject: [u8; 16],
    /// The digest of the flow handle it completes a step of.
    pub flow_hash: &'a [u8; 32],
    /// The number the sign-in page shows, 10 to 99.
    pub number: u8,
    /// The approver that started the flow itself, for the same-device exception.
    pub origin_device: Option<[u8; 16]>,
    /// Unix ms.
    pub created_ms: u64,
    /// Unix ms; 120 s after `created_ms`.
    pub expires_ms: u64,
}

/// A push challenge as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushChallengeRow {
    /// Its row id.
    pub id: [u8; 16],
    /// The subject it verifies.
    pub subject: [u8; 16],
    /// The digest of the flow handle.
    pub flow_hash: [u8; 32],
    /// The number the sign-in page shows.
    pub number: u8,
    /// The approver that started the flow itself.
    pub origin_device: Option<[u8; 16]>,
    /// Unix ms.
    pub created_ms: u64,
    /// Unix ms.
    pub expires_ms: u64,
    /// `approve`, `deny`, `not_me` or `wrong_number`, once answered.
    pub decision: Option<String>,
    /// Unix ms of the answer.
    pub decided_ms: Option<u64>,
    /// The approver that answered.
    pub device: Option<[u8; 16]>,
    /// Unix ms when the flow took the approval.
    pub used_ms: Option<u64>,
}

/// One past challenge of a subject, for the fatigue limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushHistoryRow {
    /// Unix ms.
    pub created_ms: u64,
    /// Unix ms.
    pub expires_ms: u64,
    /// The answer, if any.
    pub decision: Option<String>,
    /// Unix ms of the answer.
    pub decided_ms: Option<u64>,
}

impl TenantTx {
    /// Whether the realm decided to offer push verification (`idp.realm.push`); off by default.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn push_enabled(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT enabled FROM access.idp_push_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }

    /// Writes the next push setting under `bound` (`idp.realm.push`, `push_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_push(&mut self, bound: &Bound, enabled: bool) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_push_settings
               (tenant_id, realm_id, version, enabled, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_push_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5",
            tenant,
            realm,
            enabled,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps a new active approver key; `false` when a key with its thumbprint was ever kept.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_device_key(&mut self, k: &NewDeviceKey<'_>) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.identity_device_keys (tenant_id, realm_id, device_id,
                    identity_subject_id, thumbprint, public_key, key_type, algorithm, name)
             VALUES ($1, $2, $3, $4, $5, $6, 'EC-P256', 'ES256', $7)
             ON CONFLICT (tenant_id, realm_id, thumbprint) DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(k.id),
            Uuid::from_bytes(k.subject),
            k.thumbprint.as_slice(),
            k.public_key,
            k.name,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject's active approver keys, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_keys(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<DeviceKeyRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT device_id, identity_subject_id, thumbprint, public_key, name,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM last_seen) * 1000)::bigint AS last_seen_ms
                 FROM access.identity_device_keys
                WHERE tenant_id = $1 AND realm_id = $2 AND identity_subject_id = $3
                  AND status = 'active'
                ORDER BY created_at, device_id"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(DeviceKeyRow {
                    id: *r.device_id.as_bytes(),
                    subject: *r.identity_subject_id.as_bytes(),
                    thumbprint: bytes32(&r.thumbprint)?,
                    public_key: r.public_key,
                    name: r.name,
                    created_ms: r.created_ms,
                    last_seen_ms: r.last_seen_ms,
                })
            })
            .collect()
    }

    /// The active approver key with `thumbprint`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_key_by_thumbprint(
        &mut self,
        thumbprint: &[u8; 32],
    ) -> Result<Option<DeviceKeyRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            r#"SELECT device_id, identity_subject_id, thumbprint, public_key, name,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM last_seen) * 1000)::bigint AS last_seen_ms
                 FROM access.identity_device_keys
                WHERE tenant_id = $1 AND realm_id = $2 AND thumbprint = $3 AND status = 'active'
                FOR UPDATE"#,
            tenant,
            realm,
            thumbprint.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(DeviceKeyRow {
                id: *r.device_id.as_bytes(),
                subject: *r.identity_subject_id.as_bytes(),
                thumbprint: bytes32(&r.thumbprint)?,
                public_key: r.public_key,
                name: r.name,
                created_ms: r.created_ms,
                last_seen_ms: r.last_seen_ms,
            })
        })
        .transpose()
    }

    /// Retires the subject's active approver key `id`; the retired key when it was active.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn retire_device_key(
        &mut self,
        subject: [u8; 16],
        id: [u8; 16],
    ) -> Result<Option<DeviceKeyRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            r#"UPDATE access.identity_device_keys
                  SET status = 'retired', retired_at = clock_timestamp()
                WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3
                  AND identity_subject_id = $4 AND status = 'active'
            RETURNING device_id, identity_subject_id, thumbprint, public_key, name,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM last_seen) * 1000)::bigint AS last_seen_ms"#,
            tenant,
            realm,
            Uuid::from_bytes(id),
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(DeviceKeyRow {
                id: *r.device_id.as_bytes(),
                subject: *r.identity_subject_id.as_bytes(),
                thumbprint: bytes32(&r.thumbprint)?,
                public_key: r.public_key,
                name: r.name,
                created_ms: r.created_ms,
                last_seen_ms: r.last_seen_ms,
            })
        })
        .transpose()
    }

    /// Records that the approver key `id` answered.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn device_key_seen(&mut self, id: [u8; 16]) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "UPDATE access.identity_device_keys SET last_seen = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3 AND status = 'active'",
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps a push challenge.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_push_challenge(
        &mut self,
        c: &NewPushChallenge<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.push_challenges (tenant_id, realm_id, challenge_hash, subject_id,
                    flow_hash, number, origin_device, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            tenant,
            realm,
            c.hash.as_slice(),
            Uuid::from_bytes(c.subject),
            c.flow_hash.as_slice(),
            i16::from(c.number),
            c.origin_device.map(Uuid::from_bytes),
            i64_of(c.created_ms)?,
            i64_of(c.expires_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The push challenge of `hash`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn push_challenge(
        &mut self,
        hash: &[u8; 32],
    ) -> Result<Option<PushChallengeRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT challenge_id, subject_id, flow_hash, number, origin_device, created_ms,
                    expires_ms, decision, decided_ms, device_id, used_ms
               FROM access.push_challenges
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_hash = $3
              FOR UPDATE",
            tenant,
            realm,
            hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(PushChallengeRow {
                id: *r.challenge_id.as_bytes(),
                subject: *r.subject_id.as_bytes(),
                flow_hash: bytes32(&r.flow_hash)?,
                number: u8::try_from(r.number).map_err(|_| StoreError::Corrupt)?,
                origin_device: r.origin_device.map(|d| *d.as_bytes()),
                created_ms: u64_of(r.created_ms)?,
                expires_ms: u64_of(r.expires_ms)?,
                decision: r.decision,
                decided_ms: r.decided_ms.map(u64_of).transpose()?,
                device: r.device_id.map(|d| *d.as_bytes()),
                used_ms: r.used_ms.map(u64_of).transpose()?,
            })
        })
        .transpose()
    }

    /// Records the one answer of the challenge `id`; `false` when it was already answered.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_push_challenge(
        &mut self,
        id: [u8; 16],
        decision: &str,
        at_ms: u64,
        device: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.push_challenges SET decision = $4, decided_ms = $5, device_id = $6
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_id = $3 AND decision IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(id),
            decision,
            i64_of(at_ms)?,
            Uuid::from_bytes(device),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Marks the approved challenge `id` as taken by its flow; `false` when it was not an unused
    /// approval.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn use_push_challenge(
        &mut self,
        id: [u8; 16],
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.push_challenges SET used_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_id = $3
                AND decision = 'approve' AND used_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(id),
            i64_of(at_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject's challenges made since `since_ms`, newest first, at most 64.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn push_history(
        &mut self,
        subject: [u8; 16],
        since_ms: u64,
    ) -> Result<Vec<PushHistoryRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT created_ms, expires_ms, decision, decided_ms FROM access.push_challenges
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND created_ms >= $4
              ORDER BY created_ms DESC, challenge_id DESC LIMIT 64",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            i64_of(since_ms)?,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(PushHistoryRow {
                    created_ms: u64_of(r.created_ms)?,
                    expires_ms: u64_of(r.expires_ms)?,
                    decision: r.decision,
                    decided_ms: r.decided_ms.map(u64_of).transpose()?,
                })
            })
            .collect()
    }
}
