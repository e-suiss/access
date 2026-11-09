//! The edge channel's gateway registry and the realms' vault keys (OP-155 m.3 (c), IDI-11).

use access_identity_account::app::vault::Vault;
use access_identity_edge::adapters::PgRegistry;
use access_identity_edge::app::{Edge, Vaults};
use access_store::Pool;
use access_store::identity::{RealmId, TenantId};

use crate::login::RealmKeks;

/// The realms' PII vault keys from the token.
pub(crate) struct EdgeVaults(pub(crate) RealmKeks);

impl Vaults for EdgeVaults {
    fn vault(&self, _: TenantId, realm: RealmId) -> Option<Vault> {
        self.0.vault(realm)
    }
}

/// The edge calls: the registry read by the router role, writes by the application role.
pub(crate) fn routes(router: Pool, app: Pool, keks: RealmKeks) -> axum::Router {
    access_http::edge::router(Edge::new(PgRegistry(router), EdgeVaults(keks), app))
}
