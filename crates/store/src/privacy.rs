//! What the identity plane keeps about privacy itself (OP-153 m.3 (bb)–(ff), IDP-37, TN-78,
//! OP-42, OP-74, OP-147): preference and document acceptance history, deletion facts, data
//! subject requests, retention holds, and the reads of the user's security history and of the
//! inactivity sweep. Every table only grows (OP-73).

use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::TenantTx;

fn uuid(b: [u8; 16]) -> Uuid {
    Uuid::from_bytes(b)
}

fn digest(v: Vec<u8>) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// One preference change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferenceRow {
    /// `email`, `sms`, `call` or `push`.
    pub channel: String,
    /// The topic.
    pub topic: String,
    /// Granted or withdrawn.
    pub granted: bool,
    /// How it was given.
    pub method: String,
    /// The record digest the audit row binds.
    pub record_digest: [u8; 32],
    /// When, Unix milliseconds.
    pub changed_ms: i64,
}

/// One document acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceRow {
    /// Document type.
    pub document_type: String,
    /// Version label.
    pub version: String,
    /// Digest of the accepted text.
    pub document_digest: [u8; 32],
    /// Locale of the text.
    pub locale: String,
    /// How it was accepted.
    pub method: String,
    /// The client it was accepted in, if any.
    pub client: Option<String>,
    /// The record digest the audit row binds.
    pub record_digest: [u8; 32],
    /// When, Unix milliseconds.
    pub accepted_ms: i64,
}

/// A new document acceptance.
pub struct NewAcceptance<'a> {
    /// Document type.
    pub document_type: &'a str,
    /// Version label.
    pub version: &'a str,
    /// Digest of the accepted text.
    pub document_digest: &'a [u8; 32],
    /// Locale.
    pub locale: &'a str,
    /// Method.
    pub method: &'a str,
    /// Client.
    pub client: Option<&'a str>,
    /// Record digest.
    pub record_digest: &'a [u8; 32],
}

/// A deletion of a subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeletionRow {
    /// Its id.
    pub id: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// Who asked: `admin`, `self_service`, `scim` or `inactivity`.
    pub source: String,
    /// When it was asked, Unix milliseconds.
    pub requested_ms: i64,
    /// When the tombstone is due, Unix milliseconds.
    pub effective_ms: i64,
    /// When it was cancelled.
    pub cancelled_ms: Option<i64>,
    /// When the tombstone was written.
    pub deleted_ms: Option<i64>,
    /// When the keys may be destroyed.
    pub destroy_after_ms: Option<i64>,
    /// When the keys were destroyed.
    pub destroyed_ms: Option<i64>,
    /// The destruction proof.
    pub proof: Option<[u8; 32]>,
}

/// A data subject request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataRequestRow {
    /// Its id.
    pub id: [u8; 16],
    /// The subject.
    pub subject: [u8; 16],
    /// Kind.
    pub kind: String,
    /// When it arrived, Unix milliseconds.
    pub received_ms: i64,
    /// When it is due.
    pub due_ms: i64,
    /// When it was answered.
    pub answered_ms: Option<i64>,
    /// The answer.
    pub outcome: Option<String>,
}

/// A retention hold as stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldRow {
    /// Its id.
    pub id: [u8; 16],
    /// `subject`, `classes` or `tenant`.
    pub scope: String,
    /// The subject of a subject hold.
    pub subject: Option<[u8; 16]>,
    /// The classes of a class hold.
    pub classes: Vec<String>,
    /// `litigation`, `regulator` or `law_enforcement`.
    pub kind: String,
    /// It serves a suspicious-activity report.
    pub suspicious_activity: bool,
    /// When it was placed, Unix milliseconds.
    pub placed_ms: i64,
    /// When it ends.
    pub until_ms: Option<i64>,
}

/// A new hold.
pub struct NewHold<'a> {
    /// `subject`, `classes` or `tenant`.
    pub scope: &'a str,
    /// The subject of a subject hold (realm-scoped transaction).
    pub subject: Option<[u8; 16]>,
    /// The classes of a class hold.
    pub classes: &'a [String],
    /// Kind.
    pub kind: &'a str,
    /// It serves a suspicious-activity report.
    pub suspicious_activity: bool,
    /// When it ends, if known.
    pub until_ms: Option<i64>,
}

/// One security history entry: an audit row about the subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryRow {
    /// When, Unix milliseconds.
    pub at_ms: i64,
    /// The audit event type.
    pub event_type: String,
}

/// What the risk record keeps of the subject's last sign-in: already masked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastSignIn {
    /// When, Unix milliseconds.
    pub at_ms: i64,
    /// The /24 or /48 prefix.
    pub ip_prefix: Option<String>,
    /// The country code.
    pub country: Option<String>,
}

fn deletion(
    id: Uuid,
    subject: Uuid,
    source: String,
    times: [Option<i64>; 6],
    proof: Option<Vec<u8>>,
) -> Result<DeletionRow, StoreError> {
    let [
        requested,
        effective,
        cancelled,
        deleted,
        destroy_after,
        destroyed,
    ] = times;
    Ok(DeletionRow {
        id: *id.as_bytes(),
        subject: *subject.as_bytes(),
        source,
        requested_ms: requested.ok_or(StoreError::Corrupt)?,
        effective_ms: effective.ok_or(StoreError::Corrupt)?,
        cancelled_ms: cancelled,
        deleted_ms: deleted,
        destroy_after_ms: destroy_after,
        destroyed_ms: destroyed,
        proof: proof.map(digest).transpose()?,
    })
}

macro_rules! deletion_rows {
    ($rows:expr) => {
        $rows
            .into_iter()
            .map(|r| {
                deletion(
                    r.deletion_id,
                    r.subject_id,
                    r.source,
                    [
                        r.requested_ms,
                        r.effective_ms,
                        r.cancelled_ms,
                        r.deleted_ms,
                        r.destroy_after_ms,
                        r.destroyed_ms,
                    ],
                    r.destruction_proof,
                )
            })
            .collect::<Result<Vec<_>, StoreError>>()
    };
}

impl TenantTx {
    fn privacy_scope(&self) -> Result<(Uuid, Uuid), StoreError> {
        let realm = self.realm().ok_or(StoreError::Range)?;
        Ok((uuid(*self.tenant.as_bytes()), uuid(*realm.as_bytes())))
    }

    /// Records a preference change (IDP-37); returns its time, Unix milliseconds.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_preference(
        &mut self,
        subject: [u8; 16],
        channel: &str,
        topic: &str,
        granted: bool,
        method: &str,
        record_digest: &[u8; 32],
    ) -> Result<i64, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        Ok(sqlx::query_scalar!(
            r#"INSERT INTO access.identity_preferences
                 (tenant_id, realm_id, subject_id, channel, topic, granted, method, record_digest)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               RETURNING (extract(epoch FROM changed_at) * 1000)::bigint AS "ms!""#,
            tenant,
            realm,
            uuid(subject),
            channel,
            topic,
            granted,
            method,
            record_digest.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Every preference change of the subject, oldest first: the history (Ek B 3849).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn preferences(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<PreferenceRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT channel, topic, granted, method, record_digest,
                      (extract(epoch FROM changed_at) * 1000)::bigint AS "ms!"
                 FROM access.identity_preferences
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY change_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(PreferenceRow {
                    channel: r.channel,
                    topic: r.topic,
                    granted: r.granted,
                    method: r.method,
                    record_digest: digest(r.record_digest)?,
                    changed_ms: r.ms,
                })
            })
            .collect()
    }

    /// Records a document acceptance (IDP-37, E60); returns its time, Unix milliseconds.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_acceptance(
        &mut self,
        subject: [u8; 16],
        a: &NewAcceptance<'_>,
    ) -> Result<i64, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        Ok(sqlx::query_scalar!(
            r#"INSERT INTO access.identity_document_acceptances
                 (tenant_id, realm_id, subject_id, document_type, version, document_digest, locale,
                  method, client, record_digest)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               RETURNING (extract(epoch FROM accepted_at) * 1000)::bigint AS "ms!""#,
            tenant,
            realm,
            uuid(subject),
            a.document_type,
            a.version,
            a.document_digest.as_slice(),
            a.locale,
            a.method,
            a.client,
            a.record_digest.as_slice(),
        )
        .fetch_one(&mut *self.tx)
        .await?)
    }

    /// Every document acceptance of the subject, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn acceptances(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<AcceptanceRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT document_type, version, document_digest, locale, method, client, record_digest,
                      (extract(epoch FROM accepted_at) * 1000)::bigint AS "ms!"
                 FROM access.identity_document_acceptances
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY acceptance_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(AcceptanceRow {
                    document_type: r.document_type,
                    version: r.version,
                    document_digest: digest(r.document_digest)?,
                    locale: r.locale,
                    method: r.method,
                    client: r.client,
                    record_digest: digest(r.record_digest)?,
                    accepted_ms: r.ms,
                })
            })
            .collect()
    }

    /// Records a deletion request taking effect at `effective_ms`; `None` when the subject has
    /// an open one already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_deletion(
        &mut self,
        subject: [u8; 16],
        source: &str,
        requested_by: &str,
        exercise: Option<&[u8; 32]>,
        effective_ms: i64,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.identity_deletion_facts
                 (tenant_id, realm_id, subject_id, source, requested_by, exercise_id, effective_at)
               VALUES ($1, $2, $3, $4, $5, $6,
                       greatest(clock_timestamp(), to_timestamp($7::bigint / 1000.0)))
               ON CONFLICT (tenant_id, realm_id, subject_id) WHERE cancelled_at IS NULL DO NOTHING
               RETURNING deletion_id AS "id!""#,
            tenant,
            realm,
            uuid(subject),
            source,
            requested_by,
            exercise.map(<[u8; 32]>::as_slice),
            effective_ms,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(id.map(|u| *u.as_bytes()))
    }

    /// The subject's deletions, oldest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn deletions(&mut self, subject: [u8; 16]) -> Result<Vec<DeletionRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT deletion_id, subject_id, source, destruction_proof,
                      (extract(epoch FROM requested_at) * 1000)::bigint AS requested_ms,
                      (extract(epoch FROM effective_at) * 1000)::bigint AS effective_ms,
                      (extract(epoch FROM cancelled_at) * 1000)::bigint AS cancelled_ms,
                      (extract(epoch FROM deleted_at) * 1000)::bigint AS deleted_ms,
                      (extract(epoch FROM destroy_after) * 1000)::bigint AS destroy_after_ms,
                      (extract(epoch FROM destroyed_at) * 1000)::bigint AS destroyed_ms
                 FROM access.identity_deletion_facts
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY deletion_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        deletion_rows!(rows)
    }

    /// Cancels the subject's open deletion while its tombstone is not written yet.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cancel_deletion(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_deletion_facts SET cancelled_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                AND cancelled_at IS NULL AND deleted_at IS NULL",
            tenant,
            realm,
            uuid(subject),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Up to `limit` deletions whose tombstone is due by the database clock, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn due_tombstones(&mut self, limit: i64) -> Result<Vec<DeletionRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT deletion_id, subject_id, source, destruction_proof,
                      (extract(epoch FROM requested_at) * 1000)::bigint AS requested_ms,
                      (extract(epoch FROM effective_at) * 1000)::bigint AS effective_ms,
                      (extract(epoch FROM cancelled_at) * 1000)::bigint AS cancelled_ms,
                      (extract(epoch FROM deleted_at) * 1000)::bigint AS deleted_ms,
                      (extract(epoch FROM destroy_after) * 1000)::bigint AS destroy_after_ms,
                      (extract(epoch FROM destroyed_at) * 1000)::bigint AS destroyed_ms
                 FROM access.identity_deletion_facts
                WHERE tenant_id = $1 AND realm_id = $2 AND cancelled_at IS NULL AND deleted_at IS NULL
                  AND effective_at <= clock_timestamp()
                ORDER BY effective_at LIMIT $3 FOR UPDATE SKIP LOCKED"#,
            tenant,
            realm,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        deletion_rows!(rows)
    }

    /// Writes the tombstone time of a deletion and when its keys may go, `destroy_after_s` later.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn mark_deleted(
        &mut self,
        id: [u8; 16],
        destroy_after_s: i64,
    ) -> Result<Option<i64>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        Ok(sqlx::query_scalar!(
            r#"UPDATE access.identity_deletion_facts
                  SET deleted_at = clock_timestamp(),
                      destroy_after = clock_timestamp() + make_interval(secs => $4::bigint)
                WHERE tenant_id = $1 AND realm_id = $2 AND deletion_id = $3
                  AND deleted_at IS NULL AND cancelled_at IS NULL
                RETURNING (extract(epoch FROM destroy_after) * 1000)::bigint AS "ms!""#,
            tenant,
            realm,
            uuid(id),
            destroy_after_s,
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Up to `limit` tombstoned deletions whose destruction delay ran out, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn due_destructions(&mut self, limit: i64) -> Result<Vec<DeletionRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT deletion_id, subject_id, source, destruction_proof,
                      (extract(epoch FROM requested_at) * 1000)::bigint AS requested_ms,
                      (extract(epoch FROM effective_at) * 1000)::bigint AS effective_ms,
                      (extract(epoch FROM cancelled_at) * 1000)::bigint AS cancelled_ms,
                      (extract(epoch FROM deleted_at) * 1000)::bigint AS deleted_ms,
                      (extract(epoch FROM destroy_after) * 1000)::bigint AS destroy_after_ms,
                      (extract(epoch FROM destroyed_at) * 1000)::bigint AS destroyed_ms
                 FROM access.identity_deletion_facts
                WHERE tenant_id = $1 AND realm_id = $2 AND deleted_at IS NOT NULL AND destroyed_at IS NULL
                  AND destroy_after <= clock_timestamp()
                ORDER BY destroy_after LIMIT $3 FOR UPDATE SKIP LOCKED"#,
            tenant,
            realm,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        deletion_rows!(rows)
    }

    /// Completes a deletion with its destruction proof.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn mark_destroyed(
        &mut self,
        id: [u8; 16],
        proof: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_deletion_facts
                SET destroyed_at = clock_timestamp(), destruction_proof = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND deletion_id = $3
                AND deleted_at IS NOT NULL AND destroyed_at IS NULL",
            tenant,
            realm,
            uuid(id),
            proof.as_slice(),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Records a data subject request due `due_days` after now (KVKK m.13: at most 30).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_data_request(
        &mut self,
        subject: [u8; 16],
        kind: &str,
        due_days: i32,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.identity_data_requests (tenant_id, realm_id, subject_id, kind, due_at)
               VALUES ($1, $2, $3, $4, clock_timestamp() + make_interval(days => $5))
               RETURNING request_id AS "id!""#,
            tenant,
            realm,
            uuid(subject),
            kind,
            due_days,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Answers a data subject request once.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn answer_data_request(
        &mut self,
        id: [u8; 16],
        outcome: &str,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let n = sqlx::query!(
            "UPDATE access.identity_data_requests SET answered_at = clock_timestamp(), outcome = $4
              WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3 AND answered_at IS NULL",
            tenant,
            realm,
            uuid(id),
            outcome,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The realm's data subject requests after `after`, oldest first; only open ones when
    /// `open` is set.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn data_requests(
        &mut self,
        subject: Option<[u8; 16]>,
        open: bool,
        after: [u8; 16],
        limit: i64,
    ) -> Result<Vec<DataRequestRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT request_id, subject_id, kind, outcome,
                      (extract(epoch FROM received_at) * 1000)::bigint AS "received_ms!",
                      (extract(epoch FROM due_at) * 1000)::bigint AS "due_ms!",
                      (extract(epoch FROM answered_at) * 1000)::bigint AS answered_ms
                 FROM access.identity_data_requests
                WHERE tenant_id = $1 AND realm_id = $2 AND request_id > $3
                  AND ($4::uuid IS NULL OR subject_id = $4)
                  AND (NOT $5 OR answered_at IS NULL)
                ORDER BY request_id LIMIT $6"#,
            tenant,
            realm,
            uuid(after),
            subject.map(uuid),
            open,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| DataRequestRow {
                id: *r.request_id.as_bytes(),
                subject: *r.subject_id.as_bytes(),
                kind: r.kind,
                received_ms: r.received_ms,
                due_ms: r.due_ms,
                answered_ms: r.answered_ms,
                outcome: r.outcome,
            })
            .collect())
    }

    /// Places a hold (OP-74 m.3) in this transaction's tenant; a subject hold names a subject
    /// of this transaction's realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_hold(&mut self, h: &NewHold<'_>) -> Result<[u8; 16], StoreError> {
        let tenant = uuid(*self.tenant.as_bytes());
        let realm = self.realm().map(|r| uuid(*r.as_bytes()));
        let id = sqlx::query_scalar!(
            r#"INSERT INTO access.retention_holds
                 (tenant_id, scope, realm_id, subject_id, classes, kind, suspicious_activity, until)
               VALUES ($1, $2, CASE WHEN $2 = 'subject' THEN $3::uuid END, $4, $5, $6, $7,
                       CASE WHEN $8::bigint IS NULL THEN NULL ELSE to_timestamp($8::bigint / 1000.0) END)
               RETURNING hold_id AS "id!""#,
            tenant,
            h.scope,
            realm,
            h.subject.map(uuid),
            h.classes,
            h.kind,
            h.suspicious_activity,
            h.until_ms,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The holds that can cover this transaction's realm: the tenant's, and subject holds of
    /// this realm.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn holds(&mut self) -> Result<Vec<HoldRow>, StoreError> {
        let tenant = uuid(*self.tenant.as_bytes());
        let rows = sqlx::query!(
            r#"SELECT hold_id, scope, subject_id, classes, kind, suspicious_activity,
                      (extract(epoch FROM placed_at) * 1000)::bigint AS "placed_ms!",
                      (extract(epoch FROM until) * 1000)::bigint AS until_ms
                 FROM access.retention_holds
                WHERE tenant_id = $1
                ORDER BY hold_id"#,
            tenant,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| HoldRow {
                id: *r.hold_id.as_bytes(),
                scope: r.scope,
                subject: r.subject_id.map(|u| *u.as_bytes()),
                classes: r.classes,
                kind: r.kind,
                suspicious_activity: r.suspicious_activity,
                placed_ms: r.placed_ms,
                until_ms: r.until_ms,
            })
            .collect())
    }

    /// Audit rows naming `who` as actor or target since `since_ms`, newest first, at most
    /// `limit`: what the user's security history reads (OP-43).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn history(
        &mut self,
        who: &str,
        since_ms: i64,
        limit: i64,
    ) -> Result<Vec<HistoryRow>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT (extract(epoch FROM at) * 1000)::bigint AS "at_ms!", event_type
                 FROM access.identity_audit
                WHERE tenant_id = $1 AND realm_id = $2 AND (target = $3 OR actor = $3)
                  AND at >= to_timestamp($4::bigint / 1000.0)
                ORDER BY at DESC, id DESC LIMIT $5"#,
            tenant,
            realm,
            who,
            since_ms,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| HistoryRow {
                at_ms: r.at_ms,
                event_type: r.event_type,
            })
            .collect())
    }

    /// What the risk record keeps of the subject's last sign-in (OP-151 m.1 (b)).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn last_sign_in(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Option<LastSignIn>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let row = sqlx::query!(
            "SELECT last_at_ms, ip_prefix, country FROM access.risk_subject
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| LastSignIn {
            at_ms: r.last_at_ms,
            ip_prefix: r.ip_prefix,
            country: r.country,
        }))
    }

    /// Up to `limit` subjects in `statuses` whose last activity (a session, a credential use,
    /// else creation) is older than `idle_s` seconds by the database clock, oldest first: the
    /// inactivity sweep's candidates (TN-51). The sweep's clock is its own (TN-78).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn idle_subjects(
        &mut self,
        statuses: &[String],
        idle_s: i64,
        limit: i64,
    ) -> Result<Vec<([u8; 16], i64)>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"WITH seen AS (
                 SELECT s.subject_id,
                        greatest(
                          (extract(epoch FROM s.created_at) * 1000)::bigint,
                          coalesce((SELECT max(l.last_seen_ms) FROM access.login_sessions l
                                     WHERE l.tenant_id = s.tenant_id AND l.realm_id = s.realm_id
                                       AND l.subject_id = s.subject_id), 0),
                          coalesce((SELECT (extract(epoch FROM max(c.last_used_at)) * 1000)::bigint
                                      FROM access.identity_credentials c
                                     WHERE c.tenant_id = s.tenant_id AND c.realm_id = s.realm_id
                                       AND c.subject_id = s.subject_id), 0)) AS last_ms
                   FROM access.identity_subjects s
                  WHERE s.tenant_id = $1 AND s.realm_id = $2 AND s.status = ANY($3))
               SELECT subject_id, last_ms AS "last_ms!" FROM seen
                WHERE last_ms < (extract(epoch FROM clock_timestamp()) * 1000)::bigint - $4::bigint * 1000
                ORDER BY last_ms LIMIT $5"#,
            tenant,
            realm,
            statuses,
            idle_s,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (*r.subject_id.as_bytes(), r.last_ms))
            .collect())
    }
}

/// What a person export says about one authenticator: never its secret (TN-79).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorMeta {
    /// Kind.
    pub kind: String,
    /// Algorithm.
    pub algorithm: String,
    /// `active` or `revoked`.
    pub status: String,
    /// When it was added, Unix milliseconds.
    pub created_ms: i64,
    /// When it was last used.
    pub last_used_ms: Option<i64>,
}

/// One sign-in session as the person export lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionMeta {
    /// When it was created, Unix milliseconds.
    pub created_ms: i64,
    /// When it last authenticated.
    pub auth_time_ms: i64,
    /// When it ended, if it did.
    pub ended_ms: Option<i64>,
    /// Why it ended.
    pub end_reason: Option<String>,
}

impl TenantTx {
    /// The subject's authenticators' metadata, oldest first; no secret column is read (TN-79).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn authenticator_metadata(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<AuthenticatorMeta>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            r#"SELECT kind, algorithm, status,
                      (extract(epoch FROM created_at) * 1000)::bigint AS "created_ms!",
                      (extract(epoch FROM last_used_at) * 1000)::bigint AS last_used_ms
                 FROM access.identity_credentials
                WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
                ORDER BY credential_id"#,
            tenant,
            realm,
            uuid(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| AuthenticatorMeta {
                kind: r.kind,
                algorithm: r.algorithm,
                status: r.status,
                created_ms: r.created_ms,
                last_used_ms: r.last_used_ms,
            })
            .collect())
    }

    /// The subject's sign-in sessions, newest first, at most `limit`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn session_metadata(
        &mut self,
        subject: [u8; 16],
        limit: i64,
    ) -> Result<Vec<SessionMeta>, StoreError> {
        let (tenant, realm) = self.privacy_scope()?;
        let rows = sqlx::query!(
            "SELECT created_ms, auth_time_ms, ended_ms, end_reason FROM access.login_sessions
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
              ORDER BY session_id DESC LIMIT $4",
            tenant,
            realm,
            uuid(subject),
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SessionMeta {
                created_ms: r.created_ms,
                auth_time_ms: r.auth_time_ms,
                ended_ms: r.ended_ms,
                end_reason: r.end_reason,
            })
            .collect())
    }
}

impl TenantTx {
    /// Ends a hold now (`retention.hold.lift`, OP-147 m.3); false when it had ended already.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_hold(&mut self, id: [u8; 16]) -> Result<bool, StoreError> {
        let tenant = uuid(*self.tenant.as_bytes());
        let n = sqlx::query!(
            "UPDATE access.retention_holds SET until = clock_timestamp()
              WHERE tenant_id = $1 AND hold_id = $2 AND until IS NULL",
            tenant,
            uuid(id),
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }
}
