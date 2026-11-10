//! Payment-class authentication (OP-156 m.3 (e)–(h), MD-11, IDP-3, IDP-4, IDP-9): the realm's
//! decided SMS one-time code and Secure Payment Confirmation settings, SMS codes by their keyed
//! digest, the app-controlled factor's attestation and PIN declarations, the SIM change signals
//! of admitted `sim_change` Claims and the breach-range mirror's versions. Nothing is deleted
//! (OP-73): a code is spent, a version is archived.

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;
use crate::idp::Bound;
use crate::scope::{DomainId, DomainTx};

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

fn id16(v: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// An SMS code to keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NewSmsCode<'a> {
    /// The subject it verifies.
    pub subject: [u8; 16],
    /// `sign_in` or `activation`.
    pub purpose: &'a str,
    /// The flow or session digest it is bound to.
    pub binding: &'a [u8; 32],
    /// The keyed digest of the code.
    pub code_hash: &'a [u8; 32],
    /// Unix ms.
    pub created_ms: u64,
    /// Unix ms; 5 minutes after `created_ms`.
    pub expires_ms: u64,
}

/// An SMS code as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SmsCodeRow {
    /// Its row id.
    pub id: [u8; 16],
    /// The subject it verifies.
    pub subject: [u8; 16],
    /// `sign_in` or `activation`.
    pub purpose: String,
    /// The keyed digest of the code.
    pub code_hash: [u8; 32],
    /// Unix ms.
    pub created_ms: u64,
    /// Unix ms.
    pub expires_ms: u64,
    /// Tries so far, at most 3.
    pub attempts: u8,
    /// Unix ms when it was used.
    pub used_ms: Option<u64>,
}

/// What an approver key holds for the app-controlled factor (OP-156 m.3 (e)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppFactorKey {
    /// Hardware attestation verified at registration.
    pub hardware_attested: bool,
    /// The app asks for its own PIN before the key signs.
    pub app_pin: bool,
}

/// The last SIM change of a Party's line as an admitted `sim_change` Claim said it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimChange {
    /// The Party.
    pub subject: [u8; 16],
    /// The `ClaimID`.
    pub claim: [u8; 16],
    /// The operator or aggregator that issued it.
    pub issuer: [u8; 16],
    /// Position of its `claim` record.
    pub pos: u64,
    /// The last change, Unix ms.
    pub last_change_ms: u64,
    /// When the issuer checked the line, Unix ms.
    pub checked_ms: u64,
}

impl TenantTx {
    /// Whether the realm decided to offer SMS one-time codes (`idp.realm.sms_otp`); off by
    /// default.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sms_otp_enabled(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT enabled FROM access.idp_sms_otp_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }

    /// Writes the next SMS setting under `bound` (`idp.realm.sms_otp`, `sms_otp_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_sms_otp(&mut self, bound: &Bound, enabled: bool) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_sms_otp_settings
               (tenant_id, realm_id, version, enabled, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_sms_otp_settings
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

    /// Whether the realm opened Secure Payment Confirmation on its approval surface
    /// (`idp.realm.spc`); off by default.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn spc_enabled(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT enabled FROM access.idp_spc_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }

    /// Writes the next SPC setting under `bound` (`idp.realm.spc`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_spc(&mut self, bound: &Bound, enabled: bool) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_spc_settings
               (tenant_id, realm_id, version, enabled, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_spc_settings
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

    /// Keeps an SMS code.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_sms_code(&mut self, c: &NewSmsCode<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.sms_codes (tenant_id, realm_id, subject_id, purpose, binding,
                    code_hash, created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            tenant,
            realm,
            Uuid::from_bytes(c.subject),
            c.purpose,
            c.binding.as_slice(),
            c.code_hash.as_slice(),
            i64_of(c.created_ms)?,
            i64_of(c.expires_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest SMS code bound to `binding` for `purpose`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sms_code(
        &mut self,
        binding: &[u8; 32],
        purpose: &str,
    ) -> Result<Option<SmsCodeRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT code_id, subject_id, purpose, code_hash, created_ms, expires_ms, attempts,
                    used_ms
               FROM access.sms_codes
              WHERE tenant_id = $1 AND realm_id = $2 AND binding = $3 AND purpose = $4
              ORDER BY created_ms DESC, code_id DESC LIMIT 1
              FOR UPDATE",
            tenant,
            realm,
            binding.as_slice(),
            purpose,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(SmsCodeRow {
                id: *r.code_id.as_bytes(),
                subject: *r.subject_id.as_bytes(),
                purpose: r.purpose,
                code_hash: <[u8; 32]>::try_from(r.code_hash.as_slice())
                    .map_err(|_| StoreError::Corrupt)?,
                created_ms: u64_of(r.created_ms)?,
                expires_ms: u64_of(r.expires_ms)?,
                attempts: u8::try_from(r.attempts).map_err(|_| StoreError::Corrupt)?,
                used_ms: r.used_ms.map(u64_of).transpose()?,
            })
        })
        .transpose()
    }

    /// Counts one try of code `id`, and uses it when `used_ms` is given; `false` when it was used
    /// or out of tries already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn try_sms_code(
        &mut self,
        id: [u8; 16],
        used_ms: Option<u64>,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.sms_codes SET attempts = attempts + 1, used_ms = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND code_id = $3
                AND used_ms IS NULL AND attempts < 3",
            tenant,
            realm,
            Uuid::from_bytes(id),
            used_ms.map(i64_of).transpose()?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// How many SMS codes `subject` was sent since `since_ms`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sms_codes_since(
        &mut self,
        subject: [u8; 16],
        since_ms: u64,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM access.sms_codes
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND created_ms >= $4"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
            i64_of(since_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64_of(n)
    }

    /// What the active approver key `device` holds for the app-controlled factor; `None` when it
    /// is not active.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn app_factor_key(
        &mut self,
        device: [u8; 16],
    ) -> Result<Option<AppFactorKey>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT hardware_attested, pin_policy FROM access.identity_device_keys
              WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3 AND status = 'active'",
            tenant,
            realm,
            Uuid::from_bytes(device),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| AppFactorKey {
            hardware_attested: r.hardware_attested,
            app_pin: r.pin_policy.as_deref() == Some("app_pin"),
        }))
    }

    /// Records that the active approver key `device` of `subject` is in hardware and asks for
    /// the app PIN, from attestation verified now; `false` when it is not such a key.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn attest_app_factor_key(
        &mut self,
        subject: [u8; 16],
        device: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.identity_device_keys
                SET hardware_attested = true, pin_policy = 'app_pin', attested_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND device_id = $3
                AND identity_subject_id = $4 AND status = 'active'",
            tenant,
            realm,
            Uuid::from_bytes(device),
            Uuid::from_bytes(subject),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Keeps what the approver `device` declared about its PIN when it answered challenge
    /// `challenge`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_app_factor_answer(
        &mut self,
        challenge: [u8; 16],
        device: [u8; 16],
        pin_verified: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.app_factor_answers (tenant_id, realm_id, challenge_id, device_id,
                    pin_verified)
             VALUES ($1, $2, $3, $4, $5)",
            tenant,
            realm,
            Uuid::from_bytes(challenge),
            Uuid::from_bytes(device),
            pin_verified,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Whether the answer to challenge `challenge` declared the app PIN verified.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn app_factor_answer(&mut self, challenge: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT pin_verified FROM access.app_factor_answers
              WHERE tenant_id = $1 AND realm_id = $2 AND challenge_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(challenge),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }
}

impl TenantTx {
    /// The subject's active phone number as stored, for its SMS codes (OP-156 m.3 (f)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sms_line(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<crate::accounts::StoredValue>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT value, value_index, pii_class, nonce, ciphertext
               FROM access.identity_identifiers
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                AND kind = 'phone'
              ORDER BY identifier_id LIMIT 1",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            crate::accounts::stored(r.value, r.value_index, r.pii_class, r.nonce, r.ciphertext)
        })
        .transpose()
    }

    /// The SIM change signals about the Party of `subject` in the realm's governing domain: the
    /// latest change any of them names and the newest check, Unix ms; `None` when the subject
    /// has no Party or there is no signal. The domain scope is set for this read only.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn sim_signals(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<(u64, u64)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let found = sqlx::query!(
            "SELECT r.governing_domain_id, p.party_id
               FROM access.realms r
               JOIN access.subject_party p ON p.tenant_id = r.tenant_id AND p.realm_id = r.realm_id
              WHERE r.tenant_id = $1 AND r.realm_id = $2 AND r.status = 'active'
                AND p.subject_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(found) = found else {
            return Ok(None);
        };
        let domain = DomainId::from_bytes(
            <[u8; 32]>::try_from(found.governing_domain_id.as_slice())
                .map_err(|_| StoreError::Corrupt)?,
        );
        sqlx::query!("SELECT set_config('app.domain_id', $1, true)", domain.hex())
            .fetch_one(&mut *self.tx)
            .await?;
        let row = sqlx::query!(
            "SELECT max(last_change_ms) AS last_change, max(checked_ms) AS checked
               FROM access.sim_change_signals WHERE domain_id = $1 AND subject_id = $2",
            domain.as_bytes().as_slice(),
            found.party_id.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        sqlx::query!("SELECT set_config('app.domain_id', '', true)")
            .fetch_one(&mut *self.tx)
            .await?;
        match (row.last_change, row.checked) {
            (Some(l), Some(c)) => Ok(Some((u64_of(l)?, u64_of(c)?))),
            _ => Ok(None),
        }
    }
}

/// Records `s` once (sequencer role, after its Claim record committed).
///
/// # Errors
/// [`StoreError`].
pub async fn record_sim_change(
    sequencer: &PgPool,
    domain: &DomainId,
    s: &SimChange,
) -> Result<(), StoreError> {
    let mut tx = DomainTx::begin(sequencer, domain).await?;
    sqlx::query!(
        "INSERT INTO access.sim_change_signals
           (domain_id, subject_id, claim_id, issuer_id, pos, last_change_ms, checked_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        domain.as_bytes().as_slice(),
        s.subject.as_slice(),
        s.claim.as_slice(),
        s.issuer.as_slice(),
        i64_of(s.pos)?,
        i64_of(s.last_change_ms)?,
        i64_of(s.checked_ms)?,
    )
    .execute(&mut *tx.tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The signals about `subject` in `domain`: the newest check and the latest change any of them
/// names; `None` when there is none.
///
/// # Errors
/// [`StoreError`].
pub async fn sim_changes(
    pool: &PgPool,
    domain: &DomainId,
    subject: &[u8; 16],
) -> Result<Option<(u64, u64)>, StoreError> {
    let mut tx = DomainTx::begin(pool, domain).await?;
    let row = sqlx::query!(
        "SELECT max(last_change_ms) AS last_change, max(checked_ms) AS checked
           FROM access.sim_change_signals WHERE domain_id = $1 AND subject_id = $2",
        domain.as_bytes().as_slice(),
        subject.as_slice(),
    )
    .fetch_one(&mut *tx.tx)
    .await?;
    tx.commit().await?;
    match (row.last_change, row.checked) {
        (Some(l), Some(c)) => Ok(Some((u64_of(l)?, u64_of(c)?))),
        _ => Ok(None),
    }
}

/// One mirror version as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MirrorVersion {
    /// Its id.
    pub id: [u8; 16],
    /// The mirror directory it belongs to.
    pub directory: String,
    /// `staged`, `current`, `archived` or `failed`.
    pub status: String,
    /// Range files it holds, once complete.
    pub ranges: Option<u32>,
}

/// Starts a staged mirror version of `directory` from `source_host`.
///
/// # Errors
/// [`StoreError`].
pub async fn stage_mirror_version(
    pool: &PgPool,
    directory: &str,
    source_host: &str,
) -> Result<[u8; 16], StoreError> {
    let id = sqlx::query_scalar!(
        "INSERT INTO access.hibp_mirror_versions (directory, source_host) VALUES ($1, $2)
         RETURNING version_id",
        directory,
        source_host,
    )
    .fetch_one(pool)
    .await?;
    Ok(*id.as_bytes())
}

/// Marks the staged version `id` failed; the current version stays.
///
/// # Errors
/// [`StoreError`].
pub async fn fail_mirror_version(pool: &PgPool, id: [u8; 16]) -> Result<(), StoreError> {
    sqlx::query!(
        "UPDATE access.hibp_mirror_versions SET status = 'failed', ended_at = clock_timestamp()
          WHERE version_id = $1 AND status = 'staged'",
        Uuid::from_bytes(id),
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Makes the staged version `id` current with its count and digest, archiving the current one,
/// in one transaction; `false` when `id` is not staged.
///
/// # Errors
/// [`StoreError`].
pub async fn promote_mirror_version(
    pool: &PgPool,
    id: [u8; 16],
    ranges: u32,
    digest: &[u8; 32],
) -> Result<bool, StoreError> {
    let mut tx = pool.begin().await?;
    let directory = sqlx::query_scalar!(
        "SELECT directory FROM access.hibp_mirror_versions
          WHERE version_id = $1 AND status = 'staged' FOR UPDATE",
        Uuid::from_bytes(id),
    )
    .fetch_optional(&mut *tx)
    .await?;
    let Some(directory) = directory else {
        return Ok(false);
    };
    sqlx::query!(
        "UPDATE access.hibp_mirror_versions SET status = 'archived', archived_at = clock_timestamp()
          WHERE directory = $1 AND status = 'current'",
        directory,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        "UPDATE access.hibp_mirror_versions
            SET status = 'current', ranges = $2, digest = $3, promoted_at = clock_timestamp()
          WHERE version_id = $1",
        Uuid::from_bytes(id),
        i32::try_from(ranges).map_err(|_| StoreError::Range)?,
        digest.as_slice(),
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// The versions of `directory`, newest first, at most 64.
///
/// # Errors
/// [`StoreError`].
pub async fn mirror_versions(
    pool: &PgPool,
    directory: &str,
) -> Result<Vec<MirrorVersion>, StoreError> {
    let rows = sqlx::query!(
        "SELECT version_id, directory, status, ranges FROM access.hibp_mirror_versions
          WHERE directory = $1 ORDER BY started_at DESC, version_id DESC LIMIT 64",
        directory,
    )
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(MirrorVersion {
                id: id16(r.version_id.as_bytes())?,
                directory: r.directory,
                status: r.status,
                ranges: r
                    .ranges
                    .map(|n| u32::try_from(n).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
            })
        })
        .collect()
}
