//! The RADIUS gateway's edge call (§10.6.5, IDP-18, OP-155 m.3 (f)): `authenticate`, for RADIUS
//! gateways only.

use access_identity_edge::app::Vaults;
use access_identity_edge::app::radius::Radius;
use access_identity_edge::domain::Gateway;
use access_internal_api::edge::radius::{Authenticate, Authenticated};

use super::ldap::Answer;

/// The RADIUS call as the router serves it.
pub trait RadiusCalls: Send + Sync {
    /// `authenticate`.
    fn authenticate<'a>(&'a self, g: &'a Gateway, q: &'a Authenticate)
    -> Answer<'a, Authenticated>;
}

impl<V: Vaults + 'static> RadiusCalls for Radius<V> {
    fn authenticate<'a>(
        &'a self,
        g: &'a Gateway,
        q: &'a Authenticate,
    ) -> Answer<'a, Authenticated> {
        Box::pin(Radius::authenticate(self, g, q))
    }
}
