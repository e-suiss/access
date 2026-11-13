//! The realm's protected resources, its CIMD clients and the server-side consent records
//! (OP-154 m.3 (i), (k), AG-3…AG-8, P58). Scoped to the transaction's realm by row-level
//! security; a CIMD client retires and a consent record ends, once (OP-73).

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

fn bytes32(v: &[u8]) -> Result<[u8; 32], StoreError> {
    <[u8; 32]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

fn bytes16(v: &[u8]) -> Result<[u8; 16], StoreError> {
    <[u8; 16]>::try_from(v).map_err(|_| StoreError::Corrupt)
}

/// A protected resource or MCP server of the realm (AG-8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRow {
    /// Its canonical URI.
    pub resource: String,
    /// Its display name.
    pub display_name: String,
    /// The algorithm its access tokens are signed with; `None` is the realm's (OP-159 m.21
    /// (g)).
    pub access_token_alg: Option<String>,
}

/// A CIMD client as stored: the snapshot of the document it was last seen with (AG-5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CimdRow {
    /// Internal id.
    pub client_uuid: [u8; 16],
    /// The Client Identifier URL.
    pub client_id: String,
    /// The document, as fetched.
    pub document: Vec<u8>,
    /// SHA-256 of the document.
    pub document_hash: [u8; 32],
    /// Digest of its authority fields.
    pub authority_hash: [u8; 32],
    /// Digest of its visual fields.
    pub visual_hash: [u8; 32],
    /// The prefetched logo and its media type.
    pub logo: Option<(Vec<u8>, String)>,
    /// When the realm first saw it.
    pub first_seen_ms: i64,
    /// When it was last fetched.
    pub fetched_ms: i64,
    /// Until when the snapshot is fresh.
    pub fresh_until_ms: i64,
    /// When its visual fields last changed.
    pub visual_changed_ms: Option<i64>,
}

/// A document fetched for a CIMD client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CimdSnapshot<'a> {
    /// The document.
    pub document: &'a [u8],
    /// SHA-256 of the document.
    pub document_hash: [u8; 32],
    /// Digest of its authority fields.
    pub authority_hash: [u8; 32],
    /// Digest of its visual fields.
    pub visual_hash: [u8; 32],
    /// The prefetched logo and its media type.
    pub logo: Option<(&'a [u8], &'a str)>,
    /// When it was fetched.
    pub fetched_ms: u64,
    /// Until when it is fresh.
    pub fresh_until_ms: u64,
}

/// A live consent record (P58).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsentRecordRow {
    /// Its id.
    pub consent_id: [u8; 16],
    /// The scopes it covers, sorted.
    pub scopes: Vec<String>,
    /// The client metadata hash it was given against.
    pub metadata_hash: [u8; 32],
    /// The domain of the Grant it names.
    pub grant_domain: [u8; 32],
    /// The Grant it names.
    pub grant_ref: [u8; 16],
    /// When it was given.
    pub created_ms: i64,
}

/// A consent record to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewConsentRecord<'a> {
    /// The person.
    pub subject: [u8; 16],
    /// The client.
    pub client: [u8; 16],
    /// `cimd` or `registered`.
    pub source: &'a str,
    /// The protected resource.
    pub resource: &'a str,
    /// The scopes, sorted.
    pub scopes: &'a [String],
    /// The client metadata hash.
    pub metadata_hash: [u8; 32],
    /// The Grant's domain.
    pub grant_domain: [u8; 32],
    /// The Grant.
    pub grant_ref: [u8; 16],
    /// The `grant.issue` Exercise that issued it.
    pub exercise: [u8; 32],
    /// Now.
    pub now_ms: u64,
}

/// Registers a protected resource under `bound` (`idp.client.resource_register`).
///
/// # Errors
/// [`StoreError`]; a resource registered before fails.
pub async fn insert_protected_resource(
    t: &mut TenantTx,
    bound: &Bound,
    resource: &str,
    display_name: &str,
    access_token_alg: Option<&str>,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_protected_resources (tenant_id, realm_id, resource, display_name,
                domain_id, decision_pos, access_token_alg)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
        tenant,
        realm,
        resource,
        display_name,
        bound.domain().as_bytes().as_slice(),
        i64_of(bound.position())?,
        access_token_alg,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

impl TenantTx {
    /// The registered protected resource `resource`, compared as an exact string.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn protected_resource(
        &mut self,
        resource: &str,
    ) -> Result<Option<ResourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT resource, display_name, access_token_alg FROM access.idp_protected_resources
              WHERE tenant_id = $1 AND realm_id = $2 AND resource = $3",
            tenant,
            realm,
            resource,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| ResourceRow {
            resource: r.resource,
            display_name: r.display_name,
            access_token_alg: r.access_token_alg,
        }))
    }

    /// The realm's protected resources, by URI.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn protected_resources(&mut self) -> Result<Vec<ResourceRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT resource, display_name, access_token_alg FROM access.idp_protected_resources
              WHERE tenant_id = $1 AND realm_id = $2 ORDER BY resource",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| ResourceRow {
                resource: r.resource,
                display_name: r.display_name,
                access_token_alg: r.access_token_alg,
            })
            .collect())
    }

    /// The live CIMD client of `client_id`, locked.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cimd_client(&mut self, client_id: &str) -> Result<Option<CimdRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT client_uuid, client_id, document, document_hash, authority_hash, visual_hash,
                    logo, logo_type, first_seen_ms, fetched_ms, fresh_until_ms, visual_changed_ms
               FROM access.oauth_cimd_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND client_id = $3 AND retired_ms IS NULL
              FOR UPDATE",
            tenant,
            realm,
            client_id,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(CimdRow {
                client_uuid: *r.client_uuid.as_bytes(),
                client_id: r.client_id,
                document: r.document,
                document_hash: bytes32(&r.document_hash)?,
                authority_hash: bytes32(&r.authority_hash)?,
                visual_hash: bytes32(&r.visual_hash)?,
                logo: r.logo.zip(r.logo_type),
                first_seen_ms: r.first_seen_ms,
                fetched_ms: r.fetched_ms,
                fresh_until_ms: r.fresh_until_ms,
                visual_changed_ms: r.visual_changed_ms,
            })
        })
        .transpose()
    }

    /// The live CIMD client with internal id `uuid`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cimd_client_by_uuid(
        &mut self,
        uuid: [u8; 16],
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT client_id FROM access.oauth_cimd_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(uuid),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }

    /// The live CIMD clients of the realm: internal id and URL.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn cimd_clients(&mut self) -> Result<Vec<([u8; 16], String)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT client_uuid, client_id FROM access.oauth_cimd_clients
              WHERE tenant_id = $1 AND realm_id = $2 AND retired_ms IS NULL ORDER BY client_id",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (*r.client_uuid.as_bytes(), r.client_id))
            .collect())
    }

    /// Records a CIMD client seen for the first time; returns its internal id.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn insert_cimd_client(
        &mut self,
        client_id: &str,
        s: &CimdSnapshot<'_>,
    ) -> Result<[u8; 16], StoreError> {
        let (tenant, realm) = scope(self)?;
        let id = sqlx::query_scalar!(
            "INSERT INTO access.oauth_cimd_clients (tenant_id, realm_id, client_id, document,
                    document_hash, authority_hash, visual_hash, logo, logo_type, first_seen_ms,
                    fetched_ms, fresh_until_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10, $11)
             RETURNING client_uuid",
            tenant,
            realm,
            client_id,
            s.document,
            s.document_hash.as_slice(),
            s.authority_hash.as_slice(),
            s.visual_hash.as_slice(),
            s.logo.map(|(b, _)| b),
            s.logo.map(|(_, t)| t),
            i64_of(s.fetched_ms)?,
            i64_of(s.fresh_until_ms)?,
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(*id.as_bytes())
    }

    /// Replaces a live CIMD client's snapshot; `visual_changed` records that its name or logo
    /// changed now.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn refresh_cimd_client(
        &mut self,
        uuid: [u8; 16],
        s: &CimdSnapshot<'_>,
        visual_changed: bool,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.oauth_cimd_clients
                SET document = $4, document_hash = $5, authority_hash = $6, visual_hash = $7,
                    logo = $8, logo_type = $9, fetched_ms = $10, fresh_until_ms = $11,
                    visual_changed_ms = CASE WHEN $12 THEN $10 ELSE visual_changed_ms END
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(uuid),
            s.document,
            s.document_hash.as_slice(),
            s.authority_hash.as_slice(),
            s.visual_hash.as_slice(),
            s.logo.map(|(b, _)| b),
            s.logo.map(|(_, t)| t),
            i64_of(s.fetched_ms)?,
            i64_of(s.fresh_until_ms)?,
            visual_changed,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Retires a live CIMD client (`domain_policy` or `disabled`): its consent records end as
    /// `client_retired` and its identity grants are revoked, so introspection answers
    /// `active: false` (AG-5, §11.3.6). Returns whether it was live.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn retire_cimd_client(
        &mut self,
        uuid: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(now_ms)?;
        let n = sqlx::query!(
            "UPDATE access.oauth_cimd_clients SET retired_ms = $4, retire_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND retired_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(uuid),
            now,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if n != 1 {
            return Ok(false);
        }
        self.end_client_consents(uuid, "client_retired", now_ms)
            .await?;
        sqlx::query!(
            "UPDATE access.oauth_grants SET revoked_ms = $4, revoke_reason = 'revoked'
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND revoked_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(uuid),
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(true)
    }

    /// The database's clock, Unix milliseconds: the time of a change no request clock names,
    /// such as a policy decision retiring clients.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn db_now_ms(&mut self) -> Result<u64, StoreError> {
        let ms = sqlx::query_scalar!(
            r#"SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint AS "ms!""#
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64::try_from(ms).map_err(|_| StoreError::Range)
    }

    /// The live consent record of `subject` for `client` at `resource`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn consent_record(
        &mut self,
        subject: [u8; 16],
        client: [u8; 16],
        resource: &str,
    ) -> Result<Option<ConsentRecordRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT consent_id, scopes, metadata_hash, grant_domain, grant_ref, created_ms
               FROM access.oauth_consent_records
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND client_uuid = $4
                AND resource = $5 AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            Uuid::from_bytes(client),
            resource,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(ConsentRecordRow {
                consent_id: *r.consent_id.as_bytes(),
                scopes: r.scopes,
                metadata_hash: bytes32(&r.metadata_hash)?,
                grant_domain: bytes32(&r.grant_domain)?,
                grant_ref: bytes16(&r.grant_ref)?,
                created_ms: r.created_ms,
            })
        })
        .transpose()
    }

    /// Keeps a consent record; the live one it replaces ends as `replaced`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_consent_record(&mut self, c: &NewConsentRecord<'_>) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        let now = i64_of(c.now_ms)?;
        sqlx::query!(
            "UPDATE access.oauth_consent_records SET ended_ms = $6, end_reason = 'replaced'
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND client_uuid = $4
                AND resource = $5 AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(c.subject),
            Uuid::from_bytes(c.client),
            c.resource,
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        let mut scopes = c.scopes.to_vec();
        scopes.sort();
        scopes.dedup();
        sqlx::query!(
            "INSERT INTO access.oauth_consent_records (tenant_id, realm_id, subject_id,
                    client_uuid, source, resource, scopes, metadata_hash, grant_domain,
                    grant_ref, exercise, created_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            tenant,
            realm,
            Uuid::from_bytes(c.subject),
            Uuid::from_bytes(c.client),
            c.source,
            c.resource,
            &scopes,
            c.metadata_hash.as_slice(),
            c.grant_domain.as_slice(),
            c.grant_ref.as_slice(),
            c.exercise.as_slice(),
            now,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Ends one live consent record with `reason`; false when it already ended.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_consent_record(
        &mut self,
        consent: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.oauth_consent_records SET ended_ms = $4, end_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND consent_id = $3 AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(consent),
            i64_of(now_ms)?,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Ends every live consent record of `client` with `reason`; returns how many ended.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn end_client_consents(
        &mut self,
        client: [u8; 16],
        reason: &str,
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query!(
            "UPDATE access.oauth_consent_records SET ended_ms = $4, end_reason = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3 AND ended_ms IS NULL",
            tenant,
            realm,
            Uuid::from_bytes(client),
            i64_of(now_ms)?,
            reason,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected())
    }
}
