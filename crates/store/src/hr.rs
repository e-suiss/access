//! The HR-sourced lifecycle's rows (OP-156 m.3 (q), IDP-35): HR sources and connectors under
//! `idp.hr.*` decisions, the imports, every version of a person's record under a source, which
//! record versions' Claims were answered, and the start and end dates still to apply. Nothing is
//! deleted (OP-73).

use sqlx::PgPool;
use sqlx::types::Uuid;

use crate::StoreError;
use crate::identity::{RealmId, TenantId, TenantTx};
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

fn unsigned(n: i64) -> Result<u64, StoreError> {
    u64::try_from(n).map_err(|_| StoreError::Corrupt)
}

fn signed(n: u64) -> Result<i64, StoreError> {
    i64::try_from(n).map_err(|_| StoreError::Range)
}

fn opt_unsigned(n: Option<i64>) -> Result<Option<u64>, StoreError> {
    n.map(unsigned).transpose()
}

fn opt_signed(n: Option<u64>) -> Result<Option<i64>, StoreError> {
    n.map(signed).transpose()
}

/// The newest version of one HR source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// Its issuer Party.
    pub issuer: [u8; 16],
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
}

/// The newest version of one HR connector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorRow {
    /// Its name.
    pub name: String,
    /// Whether it is live.
    pub live: bool,
    /// The HR source it pushes to.
    pub source: String,
    /// The HR system it reads.
    pub vendor: String,
    /// Its version.
    pub version: u64,
    /// The position of the decision that wrote it.
    pub position: u64,
}

/// A record version to write.
pub struct NewRecord<'a> {
    /// The source.
    pub source: &'a str,
    /// The blind index of the source's employee id.
    pub person: [u8; 32],
    /// The account.
    pub subject: [u8; 16],
    /// The `idp.hr.import` decision it came with.
    pub import: &'a Bound,
    /// The start date, Unix ms.
    pub start_ms: Option<u64>,
    /// The end date, Unix ms.
    pub end_ms: Option<u64>,
    /// The sealed values: nonce and ciphertext.
    pub sealed: (&'a [u8; 12], &'a [u8]),
    /// When its Claims may be issued, Unix ms.
    pub issue_after_ms: u64,
}

/// One version of a person's record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRow {
    /// The source.
    pub source: String,
    /// The blind index of the source's employee id.
    pub person: [u8; 32],
    /// Its version.
    pub version: u64,
    /// The account.
    pub subject: [u8; 16],
    /// The start date, Unix ms.
    pub start_ms: Option<u64>,
    /// The end date, Unix ms.
    pub end_ms: Option<u64>,
    /// The sealed values: nonce and ciphertext.
    pub sealed: ([u8; 12], Vec<u8>),
    /// When its Claims may be issued, Unix ms.
    pub issue_after_ms: u64,
    /// `issued` or `skipped` once its Claims were dealt with.
    pub claims: Option<String>,
}

/// The newest version of a start or end date.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DueRow {
    /// The source.
    pub source: String,
    /// The blind index of the source's employee id.
    pub person: [u8; 32],
    /// `start` or `end`.
    pub change: String,
    /// Its version.
    pub version: u64,
    /// The account.
    pub subject: [u8; 16],
    /// The date, Unix ms.
    pub due_ms: u64,
    /// `pending`, `applied` or `void`.
    pub state: String,
}

impl TenantTx {
    /// Writes the next version of HR source `name` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_hr_source(
        &mut self,
        bound: &Bound,
        name: &str,
        live: bool,
        issuer: &[u8; 16],
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.hr_sources (tenant_id, realm_id, name, version, state, issuer,
                    domain_id, decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7
               FROM access.hr_sources
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            name,
            if live { "live" } else { "retired" },
            issuer.as_slice(),
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every HR source, live and retired, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_sources(&mut self) -> Result<Vec<SourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (name) name, state, issuer, version, decision_pos
               FROM access.hr_sources
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY name, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SourceRow {
                    name: r.name,
                    live: r.state == "live",
                    issuer: id16(&r.issuer)?,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                })
            })
            .collect()
    }

    /// The newest version of HR source `name`, if it was ever registered.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_source(&mut self, name: &str) -> Result<Option<SourceRow>, StoreError> {
        Ok(self
            .hr_sources()
            .await?
            .into_iter()
            .find(|s| s.name == name))
    }

    /// Writes the next version of HR connector `name` under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_hr_connector(
        &mut self,
        bound: &Bound,
        name: &str,
        live: bool,
        (source, vendor): (&str, &str),
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.hr_connectors (tenant_id, realm_id, name, version, state, source,
                    vendor, domain_id, decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8
               FROM access.hr_connectors
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3",
            tenant,
            realm,
            name,
            if live { "live" } else { "retired" },
            source,
            vendor,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of every HR connector, live and retired, by name.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_connectors(&mut self) -> Result<Vec<ConnectorRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (name) name, state, source, vendor, version, decision_pos
               FROM access.hr_connectors
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY name, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ConnectorRow {
                    name: r.name,
                    live: r.state == "live",
                    source: r.source,
                    vendor: r.vendor,
                    version: unsigned(r.version)?,
                    position: unsigned(r.decision_pos)?,
                })
            })
            .collect()
    }

    /// Records the `idp.hr.import` bound by `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_hr_import(
        &mut self,
        bound: &Bound,
        source: &str,
        (format, file, records): (&str, &[u8; 32], u32),
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.hr_imports (tenant_id, realm_id, domain_id, decision_pos, source,
                    format, file, records)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            tenant,
            realm,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
            source,
            format,
            file.as_slice(),
            i32::try_from(records).map_err(|_| StoreError::Range)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Writes the next version of `r.person`'s record under `r.source`; returns its version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_hr_record(&mut self, r: &NewRecord<'_>) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let v = sqlx::query_scalar!(
            "INSERT INTO access.hr_records (tenant_id, realm_id, source, person, version,
                    subject_id, import_domain, import_pos, start_ms, end_ms, values_nonce,
                    values_ciphertext, issue_after_ms)
             SELECT $1, $2, $3, $4, COALESCE(MAX(version), 0) + 1, $5, $6, $7, $8, $9, $10, $11, $12
               FROM access.hr_records
              WHERE tenant_id = $1 AND realm_id = $2 AND source = $3 AND person = $4
             RETURNING version",
            tenant,
            realm,
            r.source,
            r.person.as_slice(),
            Uuid::from_bytes(r.subject),
            r.import.domain().as_bytes().as_slice(),
            r.import.raw_position(),
            opt_signed(r.start_ms)?,
            opt_signed(r.end_ms)?,
            r.sealed.0.as_slice(),
            r.sealed.1,
            signed(r.issue_after_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        unsigned(v)
    }

    /// Every version of `person`'s record under `source`, oldest first, with what became of
    /// its Claims.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_record_versions(
        &mut self,
        source: &str,
        person: &[u8; 32],
    ) -> Result<Vec<RecordRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            r#"SELECT r.source, r.person, r.version, r.subject_id, r.start_ms, r.end_ms,
                      r.values_nonce, r.values_ciphertext, r.issue_after_ms,
                      c.outcome AS "outcome?"
                 FROM access.hr_records r
                 LEFT JOIN access.hr_record_claims c
                   ON c.tenant_id = r.tenant_id AND c.realm_id = r.realm_id
                  AND c.source = r.source AND c.person = r.person AND c.version = r.version
                WHERE r.tenant_id = $1 AND r.realm_id = $2 AND r.source = $3 AND r.person = $4
                ORDER BY r.version"#,
            tenant,
            realm,
            source,
            person.as_slice(),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(RecordRow {
                    source: r.source,
                    person: id32(&r.person)?,
                    version: unsigned(r.version)?,
                    subject: *r.subject_id.as_bytes(),
                    start_ms: opt_unsigned(r.start_ms)?,
                    end_ms: opt_unsigned(r.end_ms)?,
                    sealed: (
                        <[u8; 12]>::try_from(r.values_nonce.as_slice())
                            .map_err(|_| StoreError::Corrupt)?,
                        r.values_ciphertext,
                    ),
                    issue_after_ms: unsigned(r.issue_after_ms)?,
                    claims: r.outcome,
                })
            })
            .collect()
    }

    /// The `(source, person)` pairs with a record version whose Claims were not dealt with,
    /// at most `limit`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_unissued(&mut self, limit: u32) -> Result<Vec<(String, [u8; 32])>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT r.source, r.person FROM access.hr_records r
              WHERE r.tenant_id = $1 AND r.realm_id = $2
                AND NOT EXISTS (SELECT 1 FROM access.hr_record_claims c
                                 WHERE c.tenant_id = r.tenant_id AND c.realm_id = r.realm_id
                                   AND c.source = r.source AND c.person = r.person
                                   AND c.version = r.version)
              ORDER BY r.source, r.person LIMIT $3",
            tenant,
            realm,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| Ok((r.source, id32(&r.person)?)))
            .collect()
    }

    /// Records what became of the Claims of a record version: `issued` or `skipped`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_record_dealt(
        &mut self,
        (source, person, version): (&str, &[u8; 32], u64),
        outcome: &str,
        at_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.hr_record_claims (tenant_id, realm_id, source, person, version,
                    outcome, issued_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            source,
            person.as_slice(),
            signed(version)?,
            outcome,
            signed(at_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest version of `person`'s `change` date under `source`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_due_of(
        &mut self,
        source: &str,
        person: &[u8; 32],
        change: &str,
    ) -> Result<Option<DueRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT source, person, change, version, subject_id, due_ms, state
               FROM access.hr_due
              WHERE tenant_id = $1 AND realm_id = $2 AND source = $3 AND person = $4
                AND change = $5
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
            source,
            person.as_slice(),
            change,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(DueRow {
                source: r.source,
                person: id32(&r.person)?,
                change: r.change,
                version: unsigned(r.version)?,
                subject: *r.subject_id.as_bytes(),
                due_ms: unsigned(r.due_ms)?,
                state: r.state,
            })
        })
        .transpose()
    }

    /// Writes the next version of `person`'s `change` date under `source`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_hr_due(
        &mut self,
        (source, person, change): (&str, &[u8; 32], &str),
        subject: [u8; 16],
        due_ms: u64,
        state: &str,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.hr_due (tenant_id, realm_id, source, person, change, version,
                    subject_id, due_ms, state)
             SELECT $1, $2, $3, $4, $5, COALESCE(MAX(version), 0) + 1, $6, $7, $8
               FROM access.hr_due
              WHERE tenant_id = $1 AND realm_id = $2 AND source = $3 AND person = $4
                AND change = $5",
            tenant,
            realm,
            source,
            person.as_slice(),
            change,
            Uuid::from_bytes(subject),
            signed(due_ms)?,
            state,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest pending start and end dates at or before `now_ms`, oldest first, at most
    /// `limit`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_due_now(&mut self, now_ms: u64, limit: u32) -> Result<Vec<DueRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT d.source, d.person, d.change, d.version, d.subject_id, d.due_ms, d.state
               FROM access.hr_due d
              WHERE d.tenant_id = $1 AND d.realm_id = $2 AND d.state = 'pending'
                AND d.due_ms <= $3
                AND NOT EXISTS (SELECT 1 FROM access.hr_due n
                                 WHERE n.tenant_id = d.tenant_id AND n.realm_id = d.realm_id
                                   AND n.source = d.source AND n.person = d.person
                                   AND n.change = d.change AND n.version > d.version)
              ORDER BY d.due_ms LIMIT $4",
            tenant,
            realm,
            signed(now_ms)?,
            i64::from(limit),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(DueRow {
                    source: r.source,
                    person: id32(&r.person)?,
                    change: r.change,
                    version: unsigned(r.version)?,
                    subject: *r.subject_id.as_bytes(),
                    due_ms: unsigned(r.due_ms)?,
                    state: r.state,
                })
            })
            .collect()
    }

    /// The live sources `subject` has a record under, with the record's newest version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_sources_of(&mut self, subject: [u8; 16]) -> Result<Vec<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query_scalar!(
            "SELECT DISTINCT source FROM access.hr_records
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
              ORDER BY source",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows)
    }

    /// How many people have a record under `source`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn hr_people(&mut self, source: &str) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query_scalar!(
            "SELECT COUNT(DISTINCT person) FROM access.hr_records
              WHERE tenant_id = $1 AND realm_id = $2 AND source = $3",
            tenant,
            realm,
            source,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        unsigned(n.unwrap_or(0))
    }
}

/// The realms with HR work at `now_ms`: a pending date that came, or a record version whose
/// Claims were not dealt with and may be issued. Read as `access_outbox_reader`.
///
/// # Errors
/// [`StoreError`].
pub async fn realms_with_work(
    reader: &PgPool,
    now_ms: u64,
    limit: u32,
) -> Result<Vec<(TenantId, RealmId)>, StoreError> {
    let rows = sqlx::query!(
        r#"SELECT tenant_id AS "tenant_id!", realm_id AS "realm_id!" FROM (
             SELECT d.tenant_id, d.realm_id FROM access.hr_due d
              WHERE d.state = 'pending' AND d.due_ms <= $1
                AND NOT EXISTS (SELECT 1 FROM access.hr_due n
                                 WHERE n.tenant_id = d.tenant_id AND n.realm_id = d.realm_id
                                   AND n.source = d.source AND n.person = d.person
                                   AND n.change = d.change AND n.version > d.version)
             UNION
             SELECT r.tenant_id, r.realm_id FROM access.hr_records r
              WHERE NOT EXISTS (SELECT 1 FROM access.hr_record_claims c
                                 WHERE c.tenant_id = r.tenant_id AND c.realm_id = r.realm_id
                                   AND c.source = r.source AND c.person = r.person
                                   AND c.version = r.version)
           ) w LIMIT $2"#,
        signed(now_ms)?,
        i64::from(limit),
    )
    .fetch_all(reader)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                TenantId::from_bytes(*r.tenant_id.as_bytes()),
                RealmId::from_bytes(*r.realm_id.as_bytes()),
            )
        })
        .collect())
}
