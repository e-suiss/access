//! The tenant directory of the product client API (OP-149 m.4): tenants read through the router
//! role, named outside by the cell's opaque ids (OP-137, MD-18), the same `tnt_` ids the events
//! carry (OP-149 m.15 (i)).

use std::sync::Arc;

use access_http::product::adapters::router as product_router;
use access_http::product::app::Service;
use access_http::product::ports::{KeyDirectory, Realm, Tenant, Tenants, Unavailable};
use access_identity_events::domain::catalog::TENANT_PREFIX;
use access_store::Pool;
use access_store::identity::TenantId;
use access_store::tenancy::{RealmRoute, TenantRow, tenant, tenant_routes, tenants_after};

use crate::config::Config;
use crate::ids::CellIds;

/// The product client routes over `keys` and the tenants the router role reads (OP-149 m.4,
/// m.5).
pub(crate) fn routes<K: KeyDirectory + 'static>(
    config: &Config,
    keys: K,
    router: Pool,
    ids: Arc<CellIds>,
) -> Result<axum::Router, String> {
    let region = config
        .suiss
        .as_ref()
        .ok_or("no suiss section")?
        .region
        .clone();
    Ok(product_router(Service::new(
        keys,
        PgTenants::new(router, ids),
        region,
    )))
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
