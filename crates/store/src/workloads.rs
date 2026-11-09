//! Workload clients and the SPIFFE bundles a realm keeps (OP-154 m.3 (d), (r), AG-30, L25). A
//! workload client's selector, Bundle Endpoint and agent Party are realm configuration bound
//! to an `idp.client.*` decision; a kept bundle is a cache. Nothing is deleted (OP-73).

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

/// The workload facts of a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientWorkload {
    /// The client.
    pub client_uuid: [u8; 16],
    /// The SPIFFE ID selector: an identifier, or a whole-segment prefix written `…/*`.
    pub spiffe_id: String,
    /// The trust domain's Bundle Endpoint.
    pub bundle_endpoint: String,
    /// The agent Party whose Instances the workloads become.
    pub agent: [u8; 16],
}

/// An active workload client of the realm, with its `client_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadClient {
    /// The opaque `client_id`.
    pub client_id: String,
    /// `spiffe_jwt` or `spiffe_x509`.
    pub auth_method: String,
    /// Its workload facts.
    pub workload: ClientWorkload,
}

/// Writes the workload facts of a client under `bound`, replacing earlier ones.
///
/// # Errors
/// [`StoreError`].
pub async fn put_client_workload(
    t: &mut TenantTx,
    bound: &Bound,
    w: &ClientWorkload,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.idp_client_workloads (tenant_id, realm_id, client_uuid, spiffe_id,
                bundle_endpoint, agent_party, domain_id, decision_pos)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (tenant_id, realm_id, client_uuid) DO UPDATE
            SET spiffe_id = EXCLUDED.spiffe_id, bundle_endpoint = EXCLUDED.bundle_endpoint,
                agent_party = EXCLUDED.agent_party, domain_id = EXCLUDED.domain_id,
                decision_pos = EXCLUDED.decision_pos",
        tenant,
        realm,
        Uuid::from_bytes(w.client_uuid),
        w.spiffe_id,
        w.bundle_endpoint,
        w.agent.as_slice(),
        bound.domain.as_bytes().as_slice(),
        bound.position,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}

/// The workload facts of the client `client_uuid`, active or retired.
///
/// # Errors
/// [`StoreError`].
pub async fn client_workload(
    t: &mut TenantTx,
    client_uuid: [u8; 16],
) -> Result<Option<ClientWorkload>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT client_uuid, spiffe_id, bundle_endpoint, agent_party
           FROM access.idp_client_workloads
          WHERE tenant_id = $1 AND realm_id = $2 AND client_uuid = $3",
        tenant,
        realm,
        Uuid::from_bytes(client_uuid),
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    row.map(|r| {
        Ok(ClientWorkload {
            client_uuid: *r.client_uuid.as_bytes(),
            spiffe_id: r.spiffe_id,
            bundle_endpoint: r.bundle_endpoint,
            agent: <[u8; 16]>::try_from(r.agent_party).map_err(|_| StoreError::Corrupt)?,
        })
    })
    .transpose()
}

/// Most workload clients one realm is read with (PD).
pub const MAX_WORKLOAD_CLIENTS: i64 = 1_000;

/// The realm's active workload clients.
///
/// # Errors
/// [`StoreError`].
pub async fn workload_clients(t: &mut TenantTx) -> Result<Vec<WorkloadClient>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let rows = sqlx::query!(
        "SELECT c.client_id, c.auth_method, w.client_uuid, w.spiffe_id, w.bundle_endpoint,
                w.agent_party
           FROM access.idp_client_workloads w
           JOIN access.idp_clients c
             ON c.tenant_id = w.tenant_id AND c.realm_id = w.realm_id
            AND c.client_uuid = w.client_uuid
          WHERE w.tenant_id = $1 AND w.realm_id = $2 AND c.status = 'active'
            AND c.auth_method IN ('spiffe_jwt', 'spiffe_x509')
          ORDER BY c.client_id
          LIMIT $3",
        tenant,
        realm,
        MAX_WORKLOAD_CLIENTS,
    )
    .fetch_all(&mut *t.tx)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(WorkloadClient {
                client_id: r.client_id,
                auth_method: r.auth_method,
                workload: ClientWorkload {
                    client_uuid: *r.client_uuid.as_bytes(),
                    spiffe_id: r.spiffe_id,
                    bundle_endpoint: r.bundle_endpoint,
                    agent: <[u8; 16]>::try_from(r.agent_party).map_err(|_| StoreError::Corrupt)?,
                },
            })
        })
        .collect()
}

/// A bundle the realm keeps for one trust domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptBundle {
    /// The Bundle Endpoint it was fetched from.
    pub bundle_endpoint: String,
    /// The document.
    pub document: Vec<u8>,
    /// When it was fetched, Unix milliseconds.
    pub fetched_ms: u64,
}

/// The bundle kept for `trust_domain`.
///
/// # Errors
/// [`StoreError`].
pub async fn kept_bundle(
    t: &mut TenantTx,
    trust_domain: &str,
) -> Result<Option<KeptBundle>, StoreError> {
    let (tenant, realm) = scope(t)?;
    let row = sqlx::query!(
        "SELECT bundle_endpoint, document, fetched_ms FROM access.oauth_workload_bundles
          WHERE tenant_id = $1 AND realm_id = $2 AND trust_domain = $3",
        tenant,
        realm,
        trust_domain,
    )
    .fetch_optional(&mut *t.tx)
    .await?;
    Ok(row.map(|r| KeptBundle {
        bundle_endpoint: r.bundle_endpoint,
        document: r.document,
        fetched_ms: u64::try_from(r.fetched_ms).unwrap_or(0),
    }))
}

/// Keeps `bundle` for `trust_domain`, replacing the one kept.
///
/// # Errors
/// [`StoreError`].
pub async fn keep_bundle(
    t: &mut TenantTx,
    trust_domain: &str,
    bundle: &KeptBundle,
) -> Result<(), StoreError> {
    let (tenant, realm) = scope(t)?;
    sqlx::query!(
        "INSERT INTO access.oauth_workload_bundles (tenant_id, realm_id, trust_domain,
                bundle_endpoint, document, fetched_ms)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (tenant_id, realm_id, trust_domain) DO UPDATE
            SET bundle_endpoint = EXCLUDED.bundle_endpoint, document = EXCLUDED.document,
                fetched_ms = EXCLUDED.fetched_ms",
        tenant,
        realm,
        trust_domain,
        bundle.bundle_endpoint,
        bundle.document,
        i64::try_from(bundle.fetched_ms).map_err(|_| StoreError::Range)?,
    )
    .execute(&mut *t.tx)
    .await?;
    Ok(())
}
