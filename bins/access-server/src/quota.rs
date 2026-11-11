//! The realm request quota over PostgreSQL (OP-35, OP-158 m.3 (v), TN-24): `Host` (and the path
//! issuer's slug) selects the realm as the routes do, and the request draws from the realm's
//! `rate_limit_rps` and its tenant's request quota in layer B.

use access_http::quota::{BURST_S, DEFAULT_RPS, RequestQuotas, TENANT_RPS, Taken, Unavailable};
use access_identity_oauth::adapters::PgDirectory;
use access_store::Pool;
use access_store::quota::{RequestRefusal, take_request};

/// The request counters of the realms this process serves.
pub(crate) struct PgRequestQuotas {
    directory: PgDirectory,
    app: Pool,
    clock: fn() -> u64,
}

impl PgRequestQuotas {
    /// Counters resolving realms through `router` and drawing through `app` at `clock`.
    pub(crate) fn new(router: Pool, app: Pool, clock: fn() -> u64) -> Self {
        Self {
            directory: PgDirectory::new(router),
            app,
            clock,
        }
    }
}

impl RequestQuotas for PgRequestQuotas {
    async fn take(&self, authority: &str, slug: Option<&str>) -> Result<Taken, Unavailable> {
        let realm = access_identity_oauth::app::resolve_hosted(&self.directory, authority, slug)
            .await
            .map_err(|_| Unavailable)?;
        let Some(realm) = realm else {
            return Ok(Taken::NoRealm);
        };
        // MD-8
        match take_request(
            &self.app,
            (realm.tenant, realm.realm),
            (self.clock)(),
            (DEFAULT_RPS, TENANT_RPS),
            BURST_S,
        )
        .await
        {
            Ok(None) => Ok(Taken::Admitted),
            Ok(Some(RequestRefusal::Realm)) => Ok(Taken::Refused("realm")),
            Ok(Some(RequestRefusal::Tenant)) => Ok(Taken::Refused("tenant")),
            Err(_) => Err(Unavailable),
        }
    }
}
