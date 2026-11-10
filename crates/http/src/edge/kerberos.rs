//! The Kerberos gateway's edge call (§10.6.4, IDP-17, OP-155 m.3 (o)): `authenticate`, for
//! Kerberos gateways only.

use access_identity_edge::app::Vaults;
use access_identity_edge::app::kerberos::Kerberos;
use access_identity_edge::domain::Gateway;
use access_internal_api::edge::kerberos::{Authenticate, Authenticated};

use super::ldap::Answer;

/// The Kerberos call as the router serves it.
pub trait KerberosCalls: Send + Sync {
    /// `authenticate`.
    fn authenticate<'a>(&'a self, g: &'a Gateway, q: &'a Authenticate)
    -> Answer<'a, Authenticated>;
}

impl<V: Vaults + 'static> KerberosCalls for Kerberos<V> {
    fn authenticate<'a>(
        &'a self,
        g: &'a Gateway,
        q: &'a Authenticate,
    ) -> Answer<'a, Authenticated> {
        Box::pin(Kerberos::authenticate(self, g, q))
    }
}
