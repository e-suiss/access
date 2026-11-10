//! The upstream federation broker's rows (OP-155 m.3 (h), SEC9, TN-66, TN-98): the decided
//! assurance maps and home realm discovery switch, the sealed raw assertions, the subject
//! conflicts and the sessions a connection opened. Scoped to the transaction's realm by
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

fn u64_of(v: i64) -> Result<u64, StoreError> {
    u64::try_from(v).map_err(|_| StoreError::Range)
}

/// A raw upstream assertion to keep, sealed.
pub struct NewAssertion<'a> {
    /// The subject it signed in.
    pub subject: [u8; 16],
    /// The connection.
    pub connection: &'a str,
    /// Its digest, the evidence the Claims name.
    pub evidence: &'a [u8; 32],
    /// The AEAD nonce.
    pub nonce: &'a [u8; 12],
    /// The sealed assertion.
    pub ciphertext: &'a [u8],
    /// When, Unix milliseconds.
    pub now_ms: u64,
}

/// An open or resolved subject conflict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictRow {
    /// Its id.
    pub id: [u8; 16],
    /// The connection.
    pub connection: String,
    /// The account whose link holds the address.
    pub subject: [u8; 16],
    /// The digest of the new `(iss, sub)`.
    pub key: [u8; 32],
    /// When it was raised.
    pub created_ms: u64,
    /// When it was resolved.
    pub resolved_ms: Option<u64>,
}

impl TenantTx {
    /// The newest assurance map of connection `name`; `None` when none was decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn upstream_assurance_map(
        &mut self,
        name: &str,
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT map FROM access.idp_upstream_assurance_maps
              WHERE tenant_id = $1 AND realm_id = $2 AND name = $3
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
            name,
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// Writes the next assurance map of connection `name` under `bound`
    /// (`idp.upstream.assurance_map`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_upstream_assurance_map(
        &mut self,
        bound: &Bound,
        name: &str,
        map: &str,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_upstream_assurance_maps
               (tenant_id, realm_id, name, version, map, domain_id, decision_pos)
             SELECT $1, $2, $3,
                    COALESCE((SELECT max(version) FROM access.idp_upstream_assurance_maps
                               WHERE tenant_id = $1 AND realm_id = $2 AND name = $3), 0) + 1,
                    $4, $5, $6",
            tenant,
            realm,
            name,
            map,
            bound.domain().as_bytes().as_slice(),
            i64_of(bound.position())?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Whether home realm discovery is on; off until decided (TN-98).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn realm_hrd(&mut self) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT enabled FROM access.idp_realm_hrd_settings
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .unwrap_or(false))
    }

    /// Writes the next home realm discovery switch under `bound` (`idp.realm.hrd`,
    /// `idp.realm.hrd_close`).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_realm_hrd(&mut self, bound: &Bound, enabled: bool) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.idp_realm_hrd_settings
               (tenant_id, realm_id, version, enabled, domain_id, decision_pos)
             SELECT $1, $2,
                    COALESCE((SELECT max(version) FROM access.idp_realm_hrd_settings
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

    /// Keeps a sealed raw upstream assertion (§10.1.2 rule 1).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_upstream_assertion(
        &mut self,
        a: &NewAssertion<'_>,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.upstream_assertions
               (tenant_id, realm_id, subject_id, connection, evidence, nonce,
                assertion_ciphertext, created_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            tenant,
            realm,
            Uuid::from_bytes(a.subject),
            a.connection,
            a.evidence.as_slice(),
            a.nonce.as_slice(),
            a.ciphertext,
            i64_of(a.now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The sealed assertion whose digest is `evidence`, of `subject`: nonce and ciphertext.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn upstream_assertion(
        &mut self,
        subject: [u8; 16],
        evidence: &[u8; 32],
    ) -> Result<Option<([u8; 12], Vec<u8>)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let r = sqlx::query!(
            "SELECT nonce, assertion_ciphertext FROM access.upstream_assertions
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND evidence = $4
              ORDER BY assertion_id DESC LIMIT 1",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            evidence.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        r.map(|r| {
            let nonce = <[u8; 12]>::try_from(r.nonce.as_slice()).map_err(|_| StoreError::Range)?;
            Ok((nonce, r.assertion_ciphertext))
        })
        .transpose()
    }

    /// The account whose live link of `provider` holds the address with blind index `index`,
    /// if one does (TN-66).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn federated_by_address(
        &mut self,
        provider: &str,
        index: &[u8; 32],
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT subject_id FROM access.identity_federated
              WHERE tenant_id = $1 AND realm_id = $2 AND provider = $3 AND address_index = $4
                AND ended_ms IS NULL
              ORDER BY created_ms LIMIT 1",
            tenant,
            realm,
            provider,
            index.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?
        .map(|u| *u.as_bytes()))
    }

    /// Raises a subject conflict; false when the same one is already open.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_subject_conflict(
        &mut self,
        connection: &str,
        subject: [u8; 16],
        key: &[u8; 32],
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.upstream_subject_conflicts
               (tenant_id, realm_id, connection, subject_id, identity_key, created_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (tenant_id, realm_id, connection, identity_key)
               WHERE resolved_ms IS NULL DO NOTHING",
            tenant,
            realm,
            connection,
            Uuid::from_bytes(subject),
            key.as_slice(),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Resolves the open conflicts of `connection` naming `key` as linked; how many.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn resolve_subject_conflicts(
        &mut self,
        connection: &str,
        key: &[u8; 32],
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query!(
            "UPDATE access.upstream_subject_conflicts SET resolved_ms = $5, resolution = 'linked'
              WHERE tenant_id = $1 AND realm_id = $2 AND connection = $3 AND identity_key = $4
                AND resolved_ms IS NULL",
            tenant,
            realm,
            connection,
            key.as_slice(),
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected())
    }

    /// The subject conflicts of `subject`, newest first.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn subject_conflicts(
        &mut self,
        subject: [u8; 16],
    ) -> Result<Vec<ConflictRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT conflict_id, connection, subject_id, identity_key, created_ms, resolved_ms
               FROM access.upstream_subject_conflicts
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3
              ORDER BY conflict_id DESC",
            tenant,
            realm,
            Uuid::from_bytes(subject),
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(ConflictRow {
                    id: *r.conflict_id.as_bytes(),
                    connection: r.connection,
                    subject: *r.subject_id.as_bytes(),
                    key: <[u8; 32]>::try_from(r.identity_key.as_slice())
                        .map_err(|_| StoreError::Range)?,
                    created_ms: u64_of(r.created_ms)?,
                    resolved_ms: r.resolved_ms.map(u64_of).transpose()?,
                })
            })
            .collect()
    }

    /// Records that `connection` opened `session` (SEC9).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn record_upstream_session(
        &mut self,
        session: [u8; 16],
        connection: &str,
        now_ms: u64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.upstream_sessions (tenant_id, realm_id, session_id, connection,
                    created_ms)
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
            tenant,
            realm,
            Uuid::from_bytes(session),
            connection,
            i64_of(now_ms)?,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The live sessions `connection` opened, with their subjects (SEC9).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn upstream_live_sessions(
        &mut self,
        connection: &str,
    ) -> Result<Vec<([u8; 16], [u8; 16])>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT s.session_id, s.subject_id FROM access.upstream_sessions u
               JOIN access.login_sessions s
                 ON s.tenant_id = u.tenant_id AND s.realm_id = u.realm_id
                AND s.session_id = u.session_id
              WHERE u.tenant_id = $1 AND u.realm_id = $2 AND u.connection = $3
                AND s.ended_ms IS NULL
              ORDER BY s.session_id",
            tenant,
            realm,
            connection,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (*r.session_id.as_bytes(), *r.subject_id.as_bytes()))
            .collect())
    }
}
