//! The tenant directory of the product client API (OP-149 m.4): tenants read through the router
//! role, named outside by the cell's opaque ids (OP-137, MD-18), the same `tnt_` ids the events
//! carry (OP-149 m.15 (i)); and the resolution between a realm's Parties and a client's pairwise
//! `sub` (OP-149 A11).

use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::Domains;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::ports::Clock;
use access_http::product::adapters::router as product_router;
use access_http::product::app::Service;
use access_http::product::ports::{
    Exercises, KeyDirectory, Realm, Resolved, SubjectQuery, Subjects, Tenant, Tenants, Unavailable,
};
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_kernel::digest::Digest;
use access_kernel::json::b64url_encode;
use access_store::Pool;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp;
use access_store::tenancy::{RealmRoute, TenantRow, tenant, tenant_routes, tenants_after};

use crate::config::Config;
use crate::ids::CellIds;

/// The product client routes over the domains `keys`, the tenants the router role reads and
/// the realms' subjects (OP-149 m.4, m.5, m.9, A11).
pub(crate) fn routes<K>(
    config: &Config,
    keys: Arc<K>,
    pools: (Pool, Pool),
    ids: Arc<CellIds>,
) -> Result<axum::Router, String>
where
    K: KeyDirectory + Exercises + Consistency + access_authority_ingest::ports::Ledger + 'static,
{
    let (router, app) = pools;
    let region = config
        .suiss
        .as_ref()
        .ok_or("no suiss section")?
        .region
        .clone();
    // CMP-8
    let ingest = crate::ingest::routes(keys.clone(), app.clone());
    // OP-150 m.3 (a)
    let status = crate::status::routes(app.clone());
    Ok(product_router(Service::new(
        keys.clone(),
        PgTenants::new(router, ids),
        PgSubjects { app, domains: keys },
        region,
    ))
    .merge(ingest)
    .merge(status))
}

/// The head of a governing domain as a consistency token (OP-141 m.22 (f)).
pub(crate) trait Consistency: Send + Sync {
    /// The token of `domain`'s head now.
    fn consistency(
        &self,
        domain: Digest,
    ) -> impl std::future::Future<Output = Result<String, CoreError>> + Send;
}

impl<K, B, S, C> Consistency for Domains<K, B, S, C>
where
    K: Keys,
    B: Binding + Clone + Send + Sync,
    S: Salts + Clone + Send + Sync,
    C: Clock + Clone + Send + Sync,
{
    async fn consistency(&self, domain: Digest) -> Result<String, CoreError> {
        Domains::consistency(self, domain).await
    }
}

/// A realm's subjects (OP-149 A11): the Party a session subject's device Instances belong to
/// (`subject_party`) and the pairwise `sub` a client sees of that subject (MD-10).
pub(crate) struct PgSubjects<D> {
    pub(crate) app: Pool,
    pub(crate) domains: Arc<D>,
}

/// The pairwise value a client is shown first: 32 random bytes in base64url (MD-10).
fn candidate() -> Result<String, Unavailable> {
    access_crypto::random::bytes::<32>()
        .map(|b| b64url_encode(&b))
        .map_err(|_| Unavailable)
}

impl<D: Consistency> Subjects for PgSubjects<D> {
    async fn resolve(
        &self,
        tenant: [u8; 16],
        realm: [u8; 16],
        client_id: &str,
        lookup: SubjectQuery,
    ) -> Result<Option<Resolved>, Unavailable> {
        let down = |_| Unavailable;
        let (tenant, realm) = (TenantId::from_bytes(tenant), RealmId::from_bytes(realm));
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        let g = idp::governance(&mut t).await.map_err(down)?;
        let client = idp::client(&mut t, client_id).await.map_err(down)?;
        t.commit().await.map_err(down)?;
        let (Some(g), Some(client)) = (g, client.filter(|c| c.active)) else {
            return Ok(None);
        };
        // OP-141 m.22 (f)
        let consistency = self
            .domains
            .consistency(Digest(*g.domain.as_bytes()))
            .await
            .map_err(|_| Unavailable)?;
        let sector = client.client_uuid;
        let mut t = TenantTx::begin(&self.app, tenant, realm)
            .await
            .map_err(down)?;
        let mut pairs = Vec::new();
        let mut clients = Vec::new();
        // OP-149 m.31 (a): a platform product's service Party resolves like a user's, to the
        // pairwise value its service tokens carry
        match lookup {
            SubjectQuery::Parties(parties) => {
                for party in parties {
                    if let Some(subject) = idp::party_subject(&mut t, &party).await.map_err(down)? {
                        let sub = t
                            .pairwise(subject, sector, &candidate()?)
                            .await
                            .map_err(down)?;
                        pairs.push((party, sub));
                    } else if let Some(sub) = t
                        .platform_party_pairwise(&party, sector, &candidate()?)
                        .await
                        .map_err(down)?
                    {
                        pairs.push((party, sub));
                    }
                }
            }
            SubjectQuery::Subs(subs) => {
                for sub in subs {
                    if let Some(subject) = t.pairwise_subject(sector, &sub).await.map_err(down)? {
                        if let Some(party) =
                            idp::subject_party(&mut t, &subject).await.map_err(down)?
                        {
                            pairs.push((party, sub));
                        }
                    } else if let Some(party) = t
                        .platform_party_by_pairwise(sector, &sub)
                        .await
                        .map_err(down)?
                    {
                        pairs.push((party, sub));
                    } else if let Some(uuid) =
                        t.client_by_pairwise(sector, &sub).await.map_err(down)?
                        && let Some(c) = idp::client_by_uuid(&mut t, uuid).await.map_err(down)?
                    {
                        // OP-149 m.34 (b)
                        clients.push((c.client_id, sub));
                    }
                }
            }
        }
        t.commit().await.map_err(down)?;
        Ok(Some(Resolved {
            pairs,
            clients,
            consistency,
        }))
    }
}

/// Tenants from the database.
pub(crate) struct PgTenants {
    router: Pool,
    ids: Arc<CellIds>,
}

impl PgTenants {
    pub(crate) const fn new(router: Pool, ids: Arc<CellIds>) -> Self {
        Self { router, ids }
    }
}

/// The tenants of `rows` with their live realms (OP-149 m.4).
async fn with_realms(router: &Pool, rows: &[TenantRow]) -> Result<Vec<Tenant>, Unavailable> {
    let ids: Vec<TenantId> = rows.iter().map(|r| r.tenant).collect();
    let found = tenant_routes(router, &ids).await.map_err(|_| Unavailable)?;
    let realm = |r: &RealmRoute| Realm {
        id: *r.realm.as_bytes(),
        issuer: r.issuer.clone(),
        slug: r.slug.clone(),
    };
    Ok(rows
        .iter()
        .map(|row| Tenant {
            id: *row.tenant.as_bytes(),
            status: row.status.clone(),
            organizations: Vec::new(),
            realms: found
                .iter()
                .filter(|r| r.tenant == row.tenant)
                .map(realm)
                .collect(),
        })
        .collect())
}

impl Tenants for PgTenants {
    async fn tenant(&self, id: [u8; 16]) -> Result<Option<Tenant>, Unavailable> {
        let row = tenant(&self.router, TenantId::from_bytes(id))
            .await
            .map_err(|_| Unavailable)?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(with_realms(&self.router, &[row]).await?.pop())
    }

    async fn after(&self, after: Option<[u8; 16]>, limit: u32) -> Result<Vec<Tenant>, Unavailable> {
        let rows = tenants_after(&self.router, after.map(TenantId::from_bytes), limit)
            .await
            .map_err(|_| Unavailable)?;
        with_realms(&self.router, &rows).await
    }

    fn external(&self, id: [u8; 16]) -> Option<String> {
        self.ids.encode(TENANT_PREFIX, id)
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        self.ids.decode(TENANT_PREFIX, text)
    }
}
