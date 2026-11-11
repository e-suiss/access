//! Support access as the identity plane keeps it (OP-157 m.3 (f), (g), TN-137, TN-74): operators'
//! requests and what became of each, the person's "Block support access" setting, the realm's
//! artifact policy and the sealed, redacted support artifacts. A request grants nothing; the
//! person's own `grant.issue` does. Nothing is deleted: an artifact is crypto-shredded (OP-73).

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

fn id16(b: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

fn id32(b: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(b).map_err(|_| StoreError::Corrupt)
}

fn ms(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

/// A request to record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSupportRequest<'a> {
    /// The operator's account.
    pub operator: [u8; 16],
    /// The operator's Party.
    pub operator_party: [u8; 16],
    /// The person's account.
    pub subject: [u8; 16],
    /// The person's Party.
    pub subject_party: [u8; 16],
    /// The case system's registered name.
    pub case_system: &'a str,
    /// The case as the case system shows it.
    pub case_label: &'a str,
    /// The `access/case-ref/v1` digest of `(case_system, case_label)`.
    pub case_ref: [u8; 32],
    /// `read` or `profile`.
    pub scope: &'a str,
    /// Minutes asked for.
    pub minutes: u32,
    /// When, Unix ms.
    pub created_ms: u64,
    /// When the invitation stops being answerable, Unix ms.
    pub expires_ms: u64,
}

/// How a request was answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The person declined it.
    Declined,
    /// The person's `grant.issue` committed.
    Granted {
        /// The Grant.
        grant: [u8; 16],
        /// The Exercise that issued it.
        exercise: [u8; 32],
        /// Its end, Unix ms.
        until_ms: u64,
        /// The position of the decision that issued it: where its holding opened.
        position: u64,
        /// `support.session`, `support.standing` or `support.artifacts`.
        template: String,
    },
}

/// How a granted request ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// Its Grant reached its end or its case closed.
    Ended,
    /// Its Grant was revoked.
    Revoked,
}

impl End {
    const fn name(self) -> &'static str {
        match self {
            Self::Ended => "ended",
            Self::Revoked => "revoked",
        }
    }
}

/// One request with what became of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportRequestRow {
    /// The request.
    pub id: [u8; 16],
    /// The operator's account.
    pub operator: [u8; 16],
    /// The operator's Party.
    pub operator_party: [u8; 16],
    /// The person's account.
    pub subject: [u8; 16],
    /// The person's Party.
    pub subject_party: [u8; 16],
    /// The case system.
    pub case_system: String,
    /// The case.
    pub case_label: String,
    /// The case digest.
    pub case_ref: [u8; 32],
    /// `read` or `profile`.
    pub scope: String,
    /// Minutes asked for.
    pub minutes: u32,
    /// When, Unix ms.
    pub created_ms: u64,
    /// When the invitation stops being answerable, Unix ms.
    pub expires_ms: u64,
    /// The answer and when it came.
    pub answer: Option<(Answer, u64)>,
    /// The end and when it came.
    pub end: Option<(End, u64)>,
}

struct Raw {
    request_id: Uuid,
    operator_id: Uuid,
    operator_party: Vec<u8>,
    subject_id: Uuid,
    subject_party: Vec<u8>,
    case_system: String,
    case_label: String,
    case_ref: Vec<u8>,
    scope: String,
    minutes: i32,
    created_ms: i64,
    expires_ms: i64,
    answer: Option<String>,
    grant_id: Option<Vec<u8>>,
    exercise: Option<Vec<u8>>,
    until_ms: Option<i64>,
    position: Option<i64>,
    template: Option<String>,
    answered_ms: Option<i64>,
    end_state: Option<String>,
    ended_ms: Option<i64>,
}

impl Raw {
    fn row(self) -> Result<SupportRequestRow, StoreError> {
        let answer = match (self.answer.as_deref(), self.answered_ms) {
            (Some("declined"), Some(at)) => Some((Answer::Declined, ms(at)?)),
            (Some("granted"), Some(at)) => Some((
                Answer::Granted {
                    grant: id16(self.grant_id.as_deref().ok_or(StoreError::Corrupt)?)?,
                    exercise: id32(self.exercise.as_deref().ok_or(StoreError::Corrupt)?)?,
                    until_ms: ms(self.until_ms.ok_or(StoreError::Corrupt)?)?,
                    position: ms(self.position.ok_or(StoreError::Corrupt)?)?,
                    template: self.template.ok_or(StoreError::Corrupt)?,
                },
                ms(at)?,
            )),
            (None, _) => None,
            _ => return Err(StoreError::Corrupt),
        };
        let end = match (self.end_state.as_deref(), self.ended_ms) {
            (Some("ended"), Some(at)) => Some((End::Ended, ms(at)?)),
            (Some("revoked"), Some(at)) => Some((End::Revoked, ms(at)?)),
            (None, _) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(SupportRequestRow {
            id: *self.request_id.as_bytes(),
            operator: *self.operator_id.as_bytes(),
            operator_party: id16(&self.operator_party)?,
            subject: *self.subject_id.as_bytes(),
            subject_party: id16(&self.subject_party)?,
            case_system: self.case_system,
            case_label: self.case_label,
            case_ref: id32(&self.case_ref)?,
            scope: self.scope,
            minutes: u32::try_from(self.minutes).map_err(|_| StoreError::Corrupt)?,
            created_ms: ms(self.created_ms)?,
            expires_ms: ms(self.expires_ms)?,
            answer,
            end,
        })
    }
}

/// The realm's open artifact policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactPolicy {
    /// Largest upload, bytes.
    pub max_bytes: u32,
    /// How long an artifact is kept, days.
    pub retention_days: u32,
}

/// An artifact to record: only its redacted, sealed text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSupportArtifact<'a> {
    /// The person's account.
    pub subject: [u8; 16],
    /// The person's Party.
    pub subject_party: [u8; 16],
    /// The case digest.
    pub case_ref: [u8; 32],
    /// `har`, `json` or `log`.
    pub format: &'a str,
    /// Size of the redacted text, bytes.
    pub size_bytes: u32,
    /// How many values were redacted.
    pub redactions: u32,
    /// SHA-256 of the redacted text (INV-30).
    pub digest: [u8; 32],
    /// The `idp.account.artifact_upload` Exercise.
    pub upload_exercise: [u8; 32],
    /// The realm KEK that wraps `wrapped_dek`.
    pub kek_id: &'a str,
    /// The artifact's own DEK, wrapped.
    pub wrapped_dek: &'a [u8],
    /// The AES-GCM nonce.
    pub nonce: [u8; 12],
    /// The sealed redacted text.
    pub ciphertext: &'a [u8],
    /// When, Unix ms.
    pub created_ms: u64,
    /// Until when it is kept, Unix ms.
    pub retain_until_ms: u64,
}

/// One stored artifact; the sealed parts are gone once it was shredded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportArtifactRow {
    /// The artifact.
    pub id: [u8; 16],
    /// The person's account.
    pub subject: [u8; 16],
    /// The person's Party.
    pub subject_party: [u8; 16],
    /// The case digest.
    pub case_ref: [u8; 32],
    /// `har`, `json` or `log`.
    pub format: String,
    /// Size, bytes.
    pub size_bytes: u32,
    /// Redacted values.
    pub redactions: u32,
    /// SHA-256 of the redacted text.
    pub digest: [u8; 32],
    /// The wrapping KEK.
    pub kek_id: String,
    /// `(wrapped DEK, nonce, ciphertext)` until shredded.
    pub sealed: Option<(Vec<u8>, [u8; 12], Vec<u8>)>,
    /// When, Unix ms.
    pub created_ms: u64,
}

impl TenantTx {
    /// Records request `r`; its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_support_request(
        &mut self,
        r: &NewSupportRequest<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.support_requests (tenant_id, realm_id, operator_id, operator_party,
                    subject_id, subject_party, case_system, case_label, case_ref, scope, minutes,
                    created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING request_id",
            tenant,
            realm,
            Uuid::from_bytes(r.operator),
            r.operator_party.as_slice(),
            Uuid::from_bytes(r.subject),
            r.subject_party.as_slice(),
            r.case_system,
            r.case_label,
            r.case_ref.as_slice(),
            r.scope,
            i32::try_from(r.minutes).map_err(|_| StoreError::Range)?,
            signed(r.created_ms)?,
            signed(r.expires_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// The requests made by `operator` (`by = true`) or made to `subject` (`by = false`) whose
    /// invitation ran out no earlier than `since_ms`, or that were granted and have not ended,
    /// newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_requests(
        &mut self,
        account: [u8; 16],
        by: bool,
        since_ms: u64,
        limit: i64,
    ) -> Result<Vec<SupportRequestRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query_as!(
            Raw,
            r#"SELECT r.request_id, r.operator_id, r.operator_party, r.subject_id, r.subject_party,
                      r.case_system, r.case_label, r.case_ref, r.scope, r.minutes, r.created_ms,
                      r.expires_ms,
                      a.state AS "answer?", a.grant_id AS "grant_id?", a.exercise AS "exercise?",
                      a.until_ms AS "until_ms?", a.position AS "position?", a.template AS "template?",
                      a.at_ms AS "answered_ms?",
                      e.state AS "end_state?", e.at_ms AS "ended_ms?"
                 FROM access.support_requests r
                 LEFT JOIN access.support_request_outcomes a
                   ON a.tenant_id = r.tenant_id AND a.realm_id = r.realm_id
                  AND a.request_id = r.request_id AND a.state IN ('declined', 'granted')
                 LEFT JOIN access.support_request_outcomes e
                   ON e.tenant_id = r.tenant_id AND e.realm_id = r.realm_id
                  AND e.request_id = r.request_id AND e.state IN ('ended', 'revoked')
                WHERE r.tenant_id = $1 AND r.realm_id = $2
                  AND (CASE WHEN $3 THEN r.operator_id ELSE r.subject_id END) = $4
                  AND (r.expires_ms >= $5 OR (a.state = 'granted' AND (e.state IS NULL OR e.at_ms >= $5)))
                ORDER BY r.request_id DESC
                LIMIT $6"#,
            tenant,
            realm,
            by,
            Uuid::from_bytes(account),
            signed(since_ms)?,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter().map(Raw::row).collect()
    }

    /// Request `id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_request(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<SupportRequestRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query_as!(
            Raw,
            r#"SELECT r.request_id, r.operator_id, r.operator_party, r.subject_id, r.subject_party,
                      r.case_system, r.case_label, r.case_ref, r.scope, r.minutes, r.created_ms,
                      r.expires_ms,
                      a.state AS "answer?", a.grant_id AS "grant_id?", a.exercise AS "exercise?",
                      a.until_ms AS "until_ms?", a.position AS "position?", a.template AS "template?",
                      a.at_ms AS "answered_ms?",
                      e.state AS "end_state?", e.at_ms AS "ended_ms?"
                 FROM access.support_requests r
                 LEFT JOIN access.support_request_outcomes a
                   ON a.tenant_id = r.tenant_id AND a.realm_id = r.realm_id
                  AND a.request_id = r.request_id AND a.state IN ('declined', 'granted')
                 LEFT JOIN access.support_request_outcomes e
                   ON e.tenant_id = r.tenant_id AND e.realm_id = r.realm_id
                  AND e.request_id = r.request_id AND e.state IN ('ended', 'revoked')
                WHERE r.tenant_id = $1 AND r.realm_id = $2 AND r.request_id = $3"#,
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(Raw::row).transpose()
    }

    /// The granted request whose Grant is `grant`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_request_by_grant(
        &mut self,
        grant: [u8; 16],
    ) -> Result<Option<SupportRequestRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "SELECT request_id FROM access.support_request_outcomes
              WHERE tenant_id = $1 AND realm_id = $2 AND grant_id = $3 AND state = 'granted'",
            tenant,
            realm,
            grant.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        match id {
            Some(id) => self.support_request(*id.as_bytes()).await,
            None => Ok(None),
        }
    }

    /// Records the answer to request `id`; whether it was the first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn answer_support_request(
        &mut self,
        id: [u8; 16],
        answer: &Answer,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let (state, grant, exercise, until, position, template) = match answer {
            Answer::Declined => ("declined", None, None, None, None, None),
            Answer::Granted {
                grant,
                exercise,
                until_ms,
                position,
                template,
            } => (
                "granted",
                Some(grant.to_vec()),
                Some(exercise.to_vec()),
                Some(signed(*until_ms)?),
                Some(signed(*position)?),
                Some(template.as_str()),
            ),
        };
        let done = sqlx::query!(
            "INSERT INTO access.support_request_outcomes (tenant_id, realm_id, request_id, state,
                    grant_id, exercise, until_ms, position, template, at_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(id),
            state,
            grant,
            exercise,
            until,
            position,
            template,
            signed(at_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Records that granted request `id` ended; whether it was the first end.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_support_request(
        &mut self,
        id: [u8; 16],
        end: End,
        at_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "INSERT INTO access.support_request_outcomes (tenant_id, realm_id, request_id, state, at_ms)
             SELECT $1, $2, $3, $4, $5
              WHERE EXISTS (SELECT 1 FROM access.support_request_outcomes
                             WHERE tenant_id = $1 AND realm_id = $2 AND request_id = $3
                               AND state = 'granted')
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(id),
            end.name(),
            signed(at_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// The granted requests whose Grant reached its end by `now_ms` and that have not ended yet.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_grants_past(
        &mut self,
        now_ms: u64,
        limit: i64,
    ) -> Result<Vec<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let ids = sqlx::query_scalar!(
            "SELECT a.request_id FROM access.support_request_outcomes a
              WHERE a.tenant_id = $1 AND a.realm_id = $2 AND a.state = 'granted'
                AND a.until_ms <= $3
                AND NOT EXISTS (SELECT 1 FROM access.support_request_outcomes e
                                 WHERE e.tenant_id = a.tenant_id AND e.realm_id = a.realm_id
                                   AND e.request_id = a.request_id
                                   AND e.state IN ('ended', 'revoked'))
              ORDER BY a.until_ms
              LIMIT $4",
            tenant,
            realm,
            signed(now_ms)?,
            limit,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(ids.into_iter().map(|u| *u.as_bytes()).collect())
    }

    /// Whether `subject` turned on Block support access.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_blocked(&mut self, subject: [u8; 16]) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let blocked = sqlx::query_scalar!(
            "SELECT blocked FROM access.support_blocks
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(blocked.unwrap_or(false))
    }

    /// Writes the next version of `subject`'s Block support access setting.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn set_support_block(
        &mut self,
        subject: [u8; 16],
        blocked: bool,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.support_blocks (tenant_id, realm_id, subject_id, version, blocked, at_ms)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5
               FROM access.support_blocks
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            blocked,
            signed(at_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The realm's artifact policy when uploads are open.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_artifact_policy(&mut self) -> Result<Option<ArtifactPolicy>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT open, max_bytes, retention_days FROM access.support_artifact_policies
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        match row {
            Some(r) if r.open => Ok(Some(ArtifactPolicy {
                max_bytes: u32::try_from(r.max_bytes.ok_or(StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)?,
                retention_days: u32::try_from(r.retention_days.ok_or(StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)?,
            })),
            _ => Ok(None),
        }
    }

    /// Writes the realm's next artifact policy under `bound`: open with `policy`, closed
    /// without one.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_support_artifact_policy(
        &mut self,
        bound: &Bound,
        policy: Option<ArtifactPolicy>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let max = policy
            .map(|p| i32::try_from(p.max_bytes))
            .transpose()
            .map_err(|_| StoreError::Range)?;
        let days = policy
            .map(|p| i32::try_from(p.retention_days))
            .transpose()
            .map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO access.support_artifact_policies (tenant_id, realm_id, version, open,
                    max_bytes, retention_days, domain_id, decision_pos)
             SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7
               FROM access.support_artifact_policies
              WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
            policy.is_some(),
            max,
            days,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Records artifact `a`; its id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_support_artifact(
        &mut self,
        a: &NewSupportArtifact<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.support_artifacts (tenant_id, realm_id, subject_id, subject_party,
                    case_ref, format, size_bytes, redactions, digest, upload_exercise, kek_id,
                    wrapped_dek, nonce, ciphertext, created_ms, retain_until_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
             RETURNING artifact_id",
            tenant,
            realm,
            Uuid::from_bytes(a.subject),
            a.subject_party.as_slice(),
            a.case_ref.as_slice(),
            a.format,
            i32::try_from(a.size_bytes).map_err(|_| StoreError::Range)?,
            i32::try_from(a.redactions).map_err(|_| StoreError::Range)?,
            a.digest.as_slice(),
            a.upload_exercise.as_slice(),
            a.kek_id,
            a.wrapped_dek,
            a.nonce.as_slice(),
            a.ciphertext,
            signed(a.created_ms)?,
            signed(a.retain_until_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Artifact `id`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn support_artifact(
        &mut self,
        id: [u8; 16],
    ) -> Result<Option<SupportArtifactRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT artifact_id, subject_id, subject_party, case_ref, format, size_bytes,
                    redactions, digest, kek_id, wrapped_dek, nonce, ciphertext, created_ms
               FROM access.support_artifacts
              WHERE tenant_id = $1 AND realm_id = $2 AND artifact_id = $3",
            tenant,
            realm,
            Uuid::from_bytes(id),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(r) = row else { return Ok(None) };
        let sealed = match (r.wrapped_dek, r.nonce, r.ciphertext) {
            (Some(w), Some(n), Some(c)) => Some((
                w,
                <[u8; 12]>::try_from(n.as_slice()).map_err(|_| StoreError::Corrupt)?,
                c,
            )),
            (None, None, None) => None,
            _ => return Err(StoreError::Corrupt),
        };
        Ok(Some(SupportArtifactRow {
            id: *r.artifact_id.as_bytes(),
            subject: *r.subject_id.as_bytes(),
            subject_party: id16(&r.subject_party)?,
            case_ref: id32(&r.case_ref)?,
            format: r.format,
            size_bytes: u32::try_from(r.size_bytes).map_err(|_| StoreError::Corrupt)?,
            redactions: u32::try_from(r.redactions).map_err(|_| StoreError::Corrupt)?,
            digest: id32(&r.digest)?,
            kek_id: r.kek_id,
            sealed,
            created_ms: ms(r.created_ms)?,
        }))
    }

    /// Crypto-shreds the artifacts kept past their retention at `now_ms` (OP-73): their key and
    /// ciphertext go, the row stays; how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn shred_support_artifacts(&mut self, now_ms: u64) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let done = sqlx::query!(
            "UPDATE access.support_artifacts
                SET wrapped_dek = NULL, nonce = NULL, ciphertext = NULL, shredded_at = clock_timestamp()
              WHERE tenant_id = $1 AND realm_id = $2 AND shredded_at IS NULL AND retain_until_ms <= $3",
            tenant,
            realm,
            signed(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(done.rows_affected())
    }
}
