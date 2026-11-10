//! The SAML identity provider's rows (OP-155 m.3 (a), (c), (e); §10.6.1; IDP-15; IDI-7):
//! service provider registrations and the certificate policy under `idp.saml.*` decisions,
//! request identifiers kept against replay, and the flows access-server forwards to the SAML
//! gateway and decides itself. Nothing is deleted (OP-73).

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

/// The newest version of one registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpRow {
    /// Its stable identifier.
    pub sp_id: [u8; 16],
    /// Its version.
    pub version: u64,
    /// The entity ID.
    pub entity_id: String,
    /// `saml2`, `wsfed-saml11` or `wsfed-saml2`.
    pub protocol: String,
    /// Whether it is live.
    pub live: bool,
    /// The registration document (JSON).
    pub definition: Vec<u8>,
    /// The position of the decision that wrote it.
    pub position: u64,
}

/// A registration to write.
pub struct NewSp<'a> {
    /// Its stable identifier.
    pub sp_id: [u8; 16],
    /// The entity ID.
    pub entity_id: &'a str,
    /// The protocol.
    pub protocol: &'a str,
    /// Live or retired.
    pub live: bool,
    /// The registration document.
    pub definition: &'a [u8],
}

/// A certificate policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertPolicy {
    /// Days between scheduled rotations.
    pub rotate_days: i32,
    /// Days a new certificate is published before use, and an old one after.
    pub overlap_days: i32,
    /// `true` for P-256, else RSA-3072.
    pub p256: bool,
    /// An emergency replacement.
    pub emergency: bool,
}

/// What a flow holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowRow {
    /// The binding.
    pub binding: String,
    /// `sso` or `slo`.
    pub kind: String,
    /// The raw binding values (CBOR).
    pub params: Vec<u8>,
    /// When it expires.
    pub expires_ms: i64,
    /// The attested session: session, subject, epoch, `auth_time`, AAL.
    pub session: Option<FlowSession>,
    /// When the handle expires, if one was issued.
    pub handle_expires_ms: Option<i64>,
    /// The decided outcome (CBOR).
    pub outcome: Option<Vec<u8>>,
}

/// The session a flow's handle attests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowSession {
    /// The session.
    pub session: [u8; 16],
    /// Its subject.
    pub subject: [u8; 16],
    /// The epoch it carries.
    pub epoch: i64,
    /// When the user authenticated.
    pub auth_time_ms: i64,
    /// The NIST AAL of that authentication.
    pub aal: i16,
}

fn bytes16(u: Uuid) -> [u8; 16] {
    *u.as_bytes()
}

impl TenantTx {
    /// Writes the next version of registration `sp_id` under `bound`; returns the version.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_saml_sp(&mut self, bound: &Bound, sp: &NewSp<'_>) -> Result<u64, StoreError> {
        let (tenant, realm) = scope(self)?;
        let version = sqlx::query_scalar!(
            r#"INSERT INTO access.saml_sps (tenant_id, realm_id, sp_id, version, entity_id, protocol,
                    state, definition, domain_id, decision_pos)
             SELECT $1, $2, $3, COALESCE(MAX(version), 0) + 1, $4, $5, $6, $7, $8, $9
               FROM access.saml_sps
              WHERE tenant_id = $1 AND realm_id = $2 AND sp_id = $3
             RETURNING version AS "version!""#,
            tenant,
            realm,
            Uuid::from_bytes(sp.sp_id),
            sp.entity_id,
            sp.protocol,
            if sp.live { "live" } else { "retired" },
            sp.definition,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .fetch_one(&mut *self.tx)
        .await?;
        u64::try_from(version).map_err(|_| StoreError::Corrupt)
    }

    /// The newest version of every registration of the realm, live and retired.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_sps(&mut self) -> Result<Vec<SpRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let rows = sqlx::query!(
            "SELECT DISTINCT ON (sp_id) sp_id, version, entity_id, protocol, state, definition,
                    decision_pos
               FROM access.saml_sps
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY sp_id, version DESC",
            tenant,
            realm,
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(SpRow {
                    sp_id: bytes16(r.sp_id),
                    version: u64::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
                    entity_id: r.entity_id,
                    protocol: r.protocol,
                    live: r.state == "live",
                    definition: r.definition,
                    position: u64::try_from(r.decision_pos).map_err(|_| StoreError::Corrupt)?,
                })
            })
            .collect()
    }

    /// The newest version of the registration whose entity ID is `entity_id`, if any ever was.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_sp_by_entity(
        &mut self,
        entity_id: &str,
    ) -> Result<Option<SpRow>, StoreError> {
        Ok(self
            .saml_sps()
            .await?
            .into_iter()
            .find(|r| r.entity_id == entity_id))
    }

    /// Writes the next certificate policy under `bound`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn put_saml_cert_policy(
        &mut self,
        bound: &Bound,
        p: &CertPolicy,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.saml_cert_policies (tenant_id, realm_id, version, rotate_days,
                    overlap_days, alg, emergency, domain_id, decision_pos)
             SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7, $8
               FROM access.saml_cert_policies
              WHERE tenant_id = $1 AND realm_id = $2",
            tenant,
            realm,
            p.rotate_days,
            p.overlap_days,
            if p.p256 { "p-256" } else { "rsa-3072" },
            p.emergency,
            bound.domain().as_bytes().as_slice(),
            bound.raw_position(),
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The newest certificate policy with its decision position.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_cert_policy(&mut self) -> Result<Option<(CertPolicy, u64)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT rotate_days, overlap_days, alg, emergency, decision_pos
               FROM access.saml_cert_policies
              WHERE tenant_id = $1 AND realm_id = $2
              ORDER BY version DESC LIMIT 1",
            tenant,
            realm,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok((
                CertPolicy {
                    rotate_days: r.rotate_days,
                    overlap_days: r.overlap_days,
                    p256: r.alg == "p-256",
                    emergency: r.emergency,
                },
                u64::try_from(r.decision_pos).map_err(|_| StoreError::Corrupt)?,
            ))
        })
        .transpose()
    }

    /// Records request `request_id` of `entity_id`; `false` when it was seen before (a replay).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_request_seen(
        &mut self,
        entity_id: &str,
        request_id: &str,
        logout: bool,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "INSERT INTO access.saml_request_ids (tenant_id, realm_id, entity_id, request_id, kind,
                    seen_ms)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT DO NOTHING",
            tenant,
            realm,
            entity_id,
            request_id,
            if logout { "logout" } else { "authn" },
            now_ms,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// Opens flow `flow_hash` with the raw binding values.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn open_saml_flow(
        &mut self,
        flow_hash: &[u8; 32],
        binding: &str,
        kind: &str,
        params: &[u8],
        now_ms: i64,
        expires_ms: i64,
    ) -> Result<(), StoreError> {
        let (tenant, realm) = scope(self)?;
        sqlx::query!(
            "INSERT INTO access.saml_flows (tenant_id, realm_id, flow_hash, binding, kind, params,
                    created_ms, expires_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            tenant,
            realm,
            flow_hash.as_slice(),
            binding,
            kind,
            params,
            now_ms,
            expires_ms,
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The flow `flow_hash`.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_flow(&mut self, flow_hash: &[u8; 32]) -> Result<Option<FlowRow>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT binding, kind, params, expires_ms, session_id, subject_id, session_epoch,
                    auth_time_ms, aal, handle_expires_ms, outcome
               FROM access.saml_flows
              WHERE tenant_id = $1 AND realm_id = $2 AND flow_hash = $3",
            tenant,
            realm,
            flow_hash.as_slice(),
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        Ok(row.map(|r| FlowRow {
            binding: r.binding,
            kind: r.kind,
            params: r.params,
            expires_ms: r.expires_ms,
            session: match (
                r.session_id,
                r.subject_id,
                r.session_epoch,
                r.auth_time_ms,
                r.aal,
            ) {
                (Some(session), Some(subject), Some(epoch), Some(auth), Some(aal)) => {
                    Some(FlowSession {
                        session: bytes16(session),
                        subject: bytes16(subject),
                        epoch,
                        auth_time_ms: auth,
                        aal,
                    })
                }
                _ => None,
            },
            handle_expires_ms: r.handle_expires_ms,
            outcome: r.outcome,
        }))
    }

    /// Gives undecided flow `flow_hash` a new one-use handle and the session it attests;
    /// `false` when the flow is unknown, expired or decided.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn attest_saml_flow(
        &mut self,
        flow_hash: &[u8; 32],
        handle_hash: &[u8; 32],
        handle_expires_ms: i64,
        session: Option<&FlowSession>,
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.saml_flows
                SET handle_hash = $4, handle_expires_ms = $5, session_id = $6, subject_id = $7,
                    session_epoch = $8, auth_time_ms = $9, aal = $10
              WHERE tenant_id = $1 AND realm_id = $2 AND flow_hash = $3
                AND decided_ms IS NULL AND expires_ms > $11",
            tenant,
            realm,
            flow_hash.as_slice(),
            handle_hash.as_slice(),
            handle_expires_ms,
            session.map(|s| Uuid::from_bytes(s.session)),
            session.map(|s| Uuid::from_bytes(s.subject)),
            session.map(|s| s.epoch),
            session.map(|s| s.auth_time_ms),
            session.map(|s| s.aal),
            now_ms,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The undecided flow whose live handle is `handle_hash`, locked for the decision.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_flow_by_handle(
        &mut self,
        handle_hash: &[u8; 32],
        now_ms: i64,
    ) -> Result<Option<([u8; 32], FlowRow)>, StoreError> {
        let (tenant, realm) = scope(self)?;
        let row = sqlx::query!(
            "SELECT flow_hash FROM access.saml_flows
              WHERE tenant_id = $1 AND realm_id = $2 AND handle_hash = $3
                AND decided_ms IS NULL AND handle_expires_ms > $4 AND expires_ms > $4
              FOR UPDATE",
            tenant,
            realm,
            handle_hash.as_slice(),
            now_ms,
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        let Some(r) = row else {
            return Ok(None);
        };
        let flow = <[u8; 32]>::try_from(r.flow_hash).map_err(|_| StoreError::Corrupt)?;
        Ok(self.saml_flow(&flow).await?.map(|f| (flow, f)))
    }

    /// Records the outcome of flow `flow_hash`; it is final.
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn decide_saml_flow(
        &mut self,
        flow_hash: &[u8; 32],
        outcome: &[u8],
        now_ms: i64,
    ) -> Result<bool, StoreError> {
        let (tenant, realm) = scope(self)?;
        let n = sqlx::query!(
            "UPDATE access.saml_flows SET decided_ms = $4, outcome = $5
              WHERE tenant_id = $1 AND realm_id = $2 AND flow_hash = $3 AND decided_ms IS NULL",
            tenant,
            realm,
            flow_hash.as_slice(),
            now_ms,
            outcome,
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(n == 1)
    }

    /// The subject's stored pairwise value for `sector`, without making one (`AllowCreate`
    /// false, §10.6.1).
    ///
    /// # Errors
    /// [`StoreError`].
    pub async fn saml_pairwise_existing(
        &mut self,
        subject: [u8; 16],
        sector: [u8; 16],
    ) -> Result<Option<String>, StoreError> {
        let (tenant, realm) = scope(self)?;
        Ok(sqlx::query_scalar!(
            "SELECT value FROM access.pairwise_subjects
              WHERE tenant_id = $1 AND realm_id = $2 AND subject_id = $3 AND sector = $4",
            tenant,
            realm,
            Uuid::from_bytes(subject),
            Uuid::from_bytes(sector),
        )
        .fetch_optional(&mut *self.tx)
        .await?)
    }
}
