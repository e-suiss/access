//! The edge channel's gateway registry and the realms' vault keys (OP-155 m.3 (c), IDI-11), and
//! the LDAP, RADIUS and Kerberos gateways' calls (OP-155 m.3 (n), (f), (o)).

use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_identity_account::adapters::system::{
    SystemClock, SystemEntropy, cgroup_memory_budget, cores,
};
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::vault::Vault;
use access_identity_account::domain::password::Argon2Params;
use access_identity_edge::adapters::PgRegistry;
use access_identity_edge::app::kerberos::Kerberos;
use access_identity_edge::app::ldap::{Certificates, Ldap};
use access_identity_edge::app::radius::Radius;
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

/// The edge calls: the registry read by the router role, writes by the application role; the
/// SAML gateway's `session_attest` by the SAML identity provider (OP-155 m.3 (c)). LDAP binds and
/// RADIUS PAP hash on their own Argon2id service, sized to half the host, so that a directory or
/// network client cannot starve the hosted sign-in (CR-36).
pub(crate) fn routes(
    router: Pool,
    app: Pool,
    keks: RealmKeks,
    saml: Arc<crate::saml::Saml>,
    (ids, certificates): (Arc<IdKey>, Certificates),
) -> axum::Router {
    let hasher = Arc::new(Hasher::new(HasherConfig::sized(
        Argon2Params::CANONICAL,
        (cores() / 2).max(1),
        cgroup_memory_budget().map(|b| b / 2),
    )));
    let ldap = Ldap::new(
        EdgeVaults(keks.clone()),
        app.clone(),
        (
            hasher.clone(),
            Arc::new(SystemEntropy),
            Arc::new(SystemClock),
        ),
        ids,
        Some(certificates),
    );
    let radius = Radius::new(EdgeVaults(keks.clone()), app.clone(), hasher);
    let kerberos = Kerberos::new(EdgeVaults(keks.clone()), app.clone());
    access_http::edge::router_protocols(
        Edge::new(PgRegistry(router), EdgeVaults(keks), app),
        access_http::edge::Protocols {
            saml: Some(saml),
            ldap: Some(Arc::new(ldap)),
            radius: Some(Arc::new(radius)),
            kerberos: Some(Arc::new(kerberos)),
        },
    )
}
