//! The İYS rows of a realm (OP-156 m.3 (c), IDP-37 (4), B23, E42): the decided switch and the
//! realm's own preference topics, each consent record Access handed Relay and what Relay
//! reported back. Access never writes to İYS; nothing here is deleted (OP-73).

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

/// The realm's İYS switch as decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IysSetting {
    /// Whether consent records go to Relay.
    pub enabled: bool,
    /// `individual` or `merchant`: the İYS recipient type of the realm's accounts.
    pub recipient_type: String,
}

/// The latest consent record of one channel and Relay's latest report on it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IysState {
    /// `sms`, `email` or `call`.
    pub channel: String,
    /// Approved or rejected.
    pub consent: bool,
    /// When Access handed it to Relay, Unix ms.
    pub created_ms: i64,
    /// `recorded` or `failed`; none while Relay has not reported.
    pub status: Option<String>,
    /// When Relay says it happened, Unix ms.
    pub reported_ms: Option<i64>,
}

impl TenantTx {
    /// The subject's first active identifier of `kind` (`email` or `phone`): where an İYS
    /// consent record of that channel points.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn iys_contact(
        &mut self,
        subject: [u8; 16],
        kind: &str,
    ) -> Result<Option<crate::accounts::StoredValue>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT value, value_index, pii_class, nonce, ciphertext
               FROM access.identity_identifiers
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND status = 'active'
                AND kind = $4
              ORDER BY identifier_id LIMIT 1",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            kind,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            crate::accounts::stored(r.value, r.value_index, r.pii_class, r.nonce, r.ciphertext)
        })
        .transpose()
    }

    /// The realm's İYS switch; off when never decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn iys_setting(&mut self) -> Result<Option<IysSetting>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query!(
            "SELECT enabled, recipient_type FROM access.iys_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(|r| IysSetting {
            enabled: r.enabled,
            recipient_type: r.recipient_type,
        }))
    }

    /// Writes the next İYS switch under `bound` (`idp.realm.iys`, `iys_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_iys(
        &mut self,
        bound: &Bound,
        enabled: bool,
        recipient_type: &str,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.iys_settings
               (tenant_id, realm_id, version, enabled, recipient_type, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.iys_settings
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5, $6",
            tenant,
            realm,
            enabled,
            recipient_type,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The realm's own preference topics as decided; none when never decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn preference_topics(&mut self) -> Result<Vec<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT topics FROM access.preference_topics
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or_default())
    }

    /// Writes the realm's next topic list under `bound` (`idp.realm.preference_topics`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_preference_topics(
        &mut self,
        bound: &Bound,
        topics: &[String],
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.preference_topics
               (tenant_id, realm_id, version, topics, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.preference_topics
                               WHERE tenant_id = $1 AND realm_id = $2), 0) + 1,
                    $3, $4, $5",
            tenant,
            realm,
            topics,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps the consent record `record` (the Relay message's id) of `subject` on `channel`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_iys_record(
        &mut self,
        record: [u8; 16],
        subject: [u8; 16],
        channel: &str,
        consent: bool,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.iys_records (tenant_id, realm_id, record_id, subject_id, channel,
                                             consent)
             VALUES ($1, $2, $3, $4, $5, $6)",
            tenant,
            realm,
            Uuid::from_bytes(record),
            Uuid::from_bytes(subject),
            channel,
            consent,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Keeps Relay's report on `record`; `false` when the realm has no such record.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_iys_status(
        &mut self,
        record: [u8; 16],
        status: &str,
        reason: Option<&str>,
        reported_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.iys_status (tenant_id, realm_id, record_id, status, reason,
                                            reported_ms)
             SELECT $1, $2, record_id, $4, $5, $6 FROM access.iys_records
              WHERE tenant_id = $1 AND realm_id = $2 AND record_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(record),
            status,
            reason,
            i64_of(reported_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject's latest consent record per channel, with Relay's latest report on each.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn iys_state(&mut self, subject: [u8; 16]) -> Result<Vec<IysState>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT DISTINCT ON (r.channel)
                      r.channel, r.consent,
                      (extract(epoch FROM r.created_at) * 1000)::bigint AS "created_ms!",
                      s.status AS "status?", s.reported_ms AS "reported_ms?"
                 FROM access.iys_records r
                 LEFT JOIN LATERAL (
                   SELECT status, reported_ms FROM access.iys_status x
                    WHERE x.tenant_id = r.tenant_id AND x.realm_id = r.realm_id
                      AND x.record_id = r.record_id
                    ORDER BY x.status_id DESC LIMIT 1) s ON true
                WHERE r.tenant_id = $1 AND r.realm_id = $2 AND r.subject_id = $3
                ORDER BY r.channel, r.created_at DESC, r.record_id DESC"#,
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| IysState {
                channel: r.channel,
                consent: r.consent,
                created_ms: r.created_ms,
                status: r.status,
                reported_ms: r.reported_ms,
            })
            .collect())
    }
}
