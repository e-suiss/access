//! SL2 risk state of a realm (TN-46, OP-151 m.1 (b), m.3 (o)): the protection mode and canary
//! accounts, written only against a committed `idp.*` ALLOW (EI-25); each subject's last
//! sign-in as SL2 keeps it (pseudonym, prefix, coarse place, level); and the human review
//! queue. Every read and write is scoped to the transaction's realm.

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

fn ms(at: i64) -> Result<u64, StoreError> {
    u64::try_from(at).map_err(|_| StoreError::Corrupt)
}

/// The realm's protection mode as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionRow {
    /// `monitor` or `enforce`.
    pub bot: String,
    /// `monitor` or `enforce`.
    pub suspicious_ip: String,
    /// `monitor` or `enforce`.
    pub breached_password: String,
    /// `shadow`, `stepup` or `stepup_caep`.
    pub sl2: String,
    /// Denied ASNs.
    pub denied_asns: Vec<u32>,
}

/// What SL2 keeps of a subject's last sign-in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RiskSubjectRow {
    /// Unix milliseconds.
    pub last_at_ms: u64,
    /// Keyed pseudonym of the address.
    pub ip_pseudonym: Option<[u8; 32]>,
    /// `/24` or `/48` prefix.
    pub ip_prefix: Option<String>,
    /// ISO 3166-1 alpha-2.
    pub country: Option<String>,
    /// Autonomous system number.
    pub asn: Option<u32>,
    /// Hundredths of a degree.
    pub lat_cdeg: Option<i32>,
    /// Hundredths of a degree.
    pub lon_cdeg: Option<i32>,
    /// `low`, `medium` or `high`.
    pub level: Option<String>,
}

/// A new review item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewReview<'a> {
    /// The subject.
    pub subject: [u8; 16],
    /// The SL2 level.
    pub level: &'a str,
    /// Fired signal names.
    pub signals: &'a [String],
    /// The SL2 stage in force.
    pub mode: &'a str,
    /// `step_up`, `shadow_step_up`, `high` or `canary_hit`.
    pub reason: &'a str,
}

/// A review item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewRow {
    /// The item.
    pub review: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// The SL2 level.
    pub level: String,
    /// Fired signal names.
    pub signals: Vec<String>,
    /// The SL2 stage in force.
    pub mode: String,
    /// Why it was opened.
    pub reason: String,
    /// `open`, `confirmed`, `false_positive` or `dismissed`.
    pub state: String,
    /// Unix milliseconds.
    pub created_ms: u64,
}

impl TenantTx {
    /// The realm's protection mode; `None` when none was ever decided (defaults apply).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn protection(&mut self) -> Result<Option<ProtectionRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT bot, suspicious_ip, breached_password, sl2, denied_asns
               FROM access.realm_protection WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(ProtectionRow {
                bot: r.bot,
                suspicious_ip: r.suspicious_ip,
                breached_password: r.breached_password,
                sl2: r.sl2,
                denied_asns: r
                    .denied_asns
                    .into_iter()
                    .map(|a| u32::try_from(a).map_err(|_| StoreError::Corrupt))
                    .collect::<Result<_, _>>()?,
            })
        })
        .transpose()
    }

    /// Writes the realm's protection mode under `bound`, a committed `idp.realm.protection_mode`
    /// ALLOW of this transaction (EI-25).
    ///
    /// # Errors
    /// [`StoreError`]; an unbound decision fails in the database.
    pub async fn set_protection(
        &mut self,
        bound: &Bound,
        row: &ProtectionRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let asns: Vec<i64> = row.denied_asns.iter().map(|a| i64::from(*a)).collect();
        sqlx::query!(
            "INSERT INTO access.realm_protection (tenant_id, realm_id, bot, suspicious_ip,
                    breached_password, sl2, denied_asns, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (tenant_id, realm_id) DO UPDATE
                SET bot = EXCLUDED.bot, suspicious_ip = EXCLUDED.suspicious_ip,
                    breached_password = EXCLUDED.breached_password, sl2 = EXCLUDED.sl2,
                    denied_asns = EXCLUDED.denied_asns, domain_id = EXCLUDED.domain_id,
                    decision_pos = EXCLUDED.decision_pos, updated_at = now()",
            tenant,
            realm,
            row.bot,
            row.suspicious_ip,
            row.breached_password,
            row.sl2,
            &asns,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// When the transaction's realm was created, Unix milliseconds; `None` for no live realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn realm_created_ms(&mut self) -> Result<Option<u64>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let at = sqlx::query_scalar!(
            r#"SELECT (extract(epoch FROM created_at) * 1000)::bigint AS "ms!" FROM access.realms
              WHERE tenant_id = $1 AND realm_id = $2 AND status = 'active'"#,
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        at.map(ms).transpose()
    }

    /// Whether `subject` is a canary account (§4.4).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn is_canary(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM access.risk_canary
                 WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3) AS "e!""#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Makes `subject` a canary account under `bound`, a committed `idp.account.canary` ALLOW
    /// of this transaction; false when it already is one.
    ///
    /// # Errors
    /// [`StoreError`]; an unbound decision fails in the database.
    pub async fn mark_canary(
        &mut self,
        bound: &Bound,
        subject: [u8; 16],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.risk_canary (tenant_id, realm_id, subject_id, domain_id, decision_pos)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// What SL2 kept of `subject`'s last sign-in.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn risk_subject(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<RiskSubjectRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT last_at_ms, ip_pseudonym, ip_prefix, country, asn, lat_cdeg, lon_cdeg, level
               FROM access.risk_subject
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(RiskSubjectRow {
                last_at_ms: u64::try_from(r.last_at_ms).map_err(|_| StoreError::Corrupt)?,
                ip_pseudonym: r
                    .ip_pseudonym
                    .map(|p| <[u8; 32]>::try_from(p.as_slice()).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
                ip_prefix: r.ip_prefix,
                country: r.country,
                asn: r
                    .asn
                    .map(|a| u32::try_from(a).map_err(|_| StoreError::Corrupt))
                    .transpose()?,
                lat_cdeg: r.lat_cdeg,
                lon_cdeg: r.lon_cdeg,
                level: r.level,
            })
        })
        .transpose()
    }

    /// Replaces what SL2 keeps of `subject`'s last sign-in.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_risk_subject(
        &mut self,
        subject: [u8; 16],
        row: &RiskSubjectRow,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.risk_subject (tenant_id, realm_id, subject_id, last_at_ms,
                    ip_pseudonym, ip_prefix, country, asn, lat_cdeg, lon_cdeg, level)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (tenant_id, realm_id, subject_id) DO UPDATE
                SET last_at_ms = EXCLUDED.last_at_ms, ip_pseudonym = EXCLUDED.ip_pseudonym,
                    ip_prefix = EXCLUDED.ip_prefix, country = EXCLUDED.country,
                    asn = EXCLUDED.asn, lat_cdeg = EXCLUDED.lat_cdeg,
                    lon_cdeg = EXCLUDED.lon_cdeg,
                    level = coalesce(EXCLUDED.level, access.risk_subject.level),
                    updated_at = now()",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            i64::try_from(row.last_at_ms).map_err(|_| StoreError::Range)?,
            row.ip_pseudonym.as_ref().map(<[u8; 32]>::as_slice),
            row.ip_prefix.as_deref(),
            row.country.as_deref(),
            row.asn.map(i64::from),
            row.lat_cdeg,
            row.lon_cdeg,
            row.level.as_deref(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Records `subject`'s SL2 level without touching its last sign-in.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_risk_level(
        &mut self,
        subject: [u8; 16],
        level: &str,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.risk_subject (tenant_id, realm_id, subject_id, last_at_ms, level)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (tenant_id, realm_id, subject_id) DO UPDATE
                SET level = EXCLUDED.level, updated_at = now()",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            i64::try_from(at_ms.max(1)).map_err(|_| StoreError::Range)?,
            level,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Opens a review item.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_review(&mut self, review: &NewReview<'_>) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.risk_review (tenant_id, realm_id, subject_id, level, signals, mode,
                    reason)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING review_id",
            tenant,
            realm,
            Uuid::from_bytes(review.subject),
            review.level,
            review.signals,
            review.mode,
            review.reason,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Decides an open review item: `confirmed`, `false_positive` or `dismissed`; false when it
    /// is not open.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_review(
        &mut self,
        review: [u8; 16],
        state: &str,
        by: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "UPDATE access.risk_review SET state = $4, decided_at = now(), decided_by = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND review_id = $3 AND state = 'open'",
            tenant,
            realm,
            Uuid::from_bytes(review),
            state,
            by,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The realm's open review items, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_reviews(&mut self, limit: u32) -> Result<Vec<ReviewRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT review_id, subject_id, level, signals, mode, reason, state,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!"
                 FROM access.risk_review
                WHERE tenant_id = $1 AND realm_id = $2 AND state = 'open'
                ORDER BY created_at, review_id LIMIT $3"#,
            tenant,
            realm,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ReviewRow {
                    review: *r.review_id.as_bytes(),
                    subject: *r.subject_id.as_bytes(),
                    level: r.level,
                    signals: r.signals,
                    mode: r.mode,
                    reason: r.reason,
                    state: r.state,
                    created_ms: ms(r.created_ms)?,
                })
            })
            .collect()
    }
}
