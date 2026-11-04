//! The tenant directory of the product client API (OP-149 m.4): tenants read through the router
//! role, named outside by the cell's opaque ids (OP-137, MD-18). The id key is taken from the
//! token on first use, as the hosted login does.

use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::opaque_id::IdKey;
use access_http::product::adapters::router as product_router;
use access_http::product::app::Service;
use access_http::product::ports::{KeyDirectory, Tenant, Tenants, Unavailable};
use access_store::Pool;
use access_store::identity::TenantId;
use access_store::tenancy::{TenantRow, tenant, tenants_after};
use suiss_crypto::pkcs11::KeyStore;

use crate::config::Config;

/// The product client routes over `keys` and the tenants the router role reads (OP-149 m.4,
/// m.5).
pub(crate) fn routes<K: KeyDirectory + 'static>(
    config: &Config,
    keys: K,
    router: Pool,
    id_keys: Arc<KeyStore>,
) -> Result<axum::Router, String> {
    let region = config
        .suiss
        .as_ref()
        .ok_or("no suiss section")?
        .region
        .clone();
    Ok(product_router(Service::new(
        keys,
        PgTenants::new(router, id_keys),
        region,
    )))
}

/// The type prefix of a tenant's external id.
const PREFIX: &str = "tnt";

/// Tenants from the database.
pub(crate) struct PgTenants {
    router: Pool,
    keys: Arc<KeyStore>,
    ids: Mutex<Option<Arc<IdKey>>>,
}

impl PgTenants {
    pub(crate) const fn new(router: Pool, keys: Arc<KeyStore>) -> Self {
        Self {
            router,
            keys,
            ids: Mutex::new(None),
        }
    }

    fn ids(&self) -> Option<Arc<IdKey>> {
        let mut slot = self.ids.lock().ok()?;
        if slot.is_none() {
            let bytes = crate::login::id_key_bytes(&self.keys).ok()?;
            *slot = Some(Arc::new(IdKey::new(Secret::new(bytes))));
        }
        slot.clone()
    }
}

fn of(row: &TenantRow) -> Tenant {
    Tenant {
        id: *row.tenant.as_bytes(),
        status: row.status.clone(),
        organizations: Vec::new(),
    }
}

impl Tenants for PgTenants {
    async fn tenant(&self, id: [u8; 16]) -> Result<Option<Tenant>, Unavailable> {
        tenant(&self.router, TenantId::from_bytes(id))
            .await
            .map(|r| r.as_ref().map(of))
            .map_err(|_| Unavailable)
    }

    async fn after(&self, after: Option<[u8; 16]>, limit: u32) -> Result<Vec<Tenant>, Unavailable> {
        tenants_after(&self.router, after.map(TenantId::from_bytes), limit)
            .await
            .map(|rows| rows.iter().map(of).collect())
            .map_err(|_| Unavailable)
    }

    fn external(&self, id: [u8; 16]) -> Option<String> {
        self.ids()?.encode(PREFIX, id).ok()
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        self.ids()?.decode(PREFIX, text).ok()
    }
}
