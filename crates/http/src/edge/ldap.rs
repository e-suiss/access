//! The LDAP gateway's edge calls (§10.6.3, IDP-16, OP-155 m.3 (n)): `authenticate` and
//! `directory_read`, for LDAP gateways only.

use std::future::Future;
use std::pin::Pin;

use access_identity_edge::EdgeError;
use access_identity_edge::app::Vaults;
use access_identity_edge::app::ldap::Ldap;
use access_identity_edge::domain::{Gateway, Refusal};
use access_internal_api::edge::ldap::{Authenticate, Authenticated, DirectoryPage, DirectoryRead};
use access_internal_api::edge::{Call, GatewayKind};

/// A boxed answer of one call.
pub type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, EdgeError>> + Send + 'a>>;

/// The LDAP calls as the router serves them.
pub trait LdapCalls: Send + Sync {
    /// `authenticate`.
    fn authenticate<'a>(&'a self, g: &'a Gateway, q: &'a Authenticate)
    -> Answer<'a, Authenticated>;
    /// `directory_read`.
    fn directory_read<'a>(
        &'a self,
        g: &'a Gateway,
        q: &'a DirectoryRead,
    ) -> Answer<'a, DirectoryPage>;
}

impl<V: Vaults + 'static> LdapCalls for Ldap<V> {
    fn authenticate<'a>(
        &'a self,
        g: &'a Gateway,
        q: &'a Authenticate,
    ) -> Answer<'a, Authenticated> {
        Box::pin(Ldap::authenticate(self, g, q))
    }

    fn directory_read<'a>(
        &'a self,
        g: &'a Gateway,
        q: &'a DirectoryRead,
    ) -> Answer<'a, DirectoryPage> {
        Box::pin(Ldap::directory_read(self, g, q))
    }
}

/// The answer body of `call`, or `None` when it is not an LDAP call; a refusal is an
/// [`EdgeError`], a body that is not the call's is `Some(Err(None))`.
pub(super) async fn answer(
    ldap: &dyn LdapCalls,
    g: &Gateway,
    call: Call,
    body: &[u8],
) -> Option<Result<Vec<u8>, Option<EdgeError>>> {
    if !matches!(call, Call::Authenticate | Call::DirectoryRead) {
        return None;
    }
    if g.uri.kind != GatewayKind::Ldap {
        return Some(Err(Some(EdgeError::Refused(Refusal::Method))));
    }
    Some(match call {
        Call::Authenticate => match Authenticate::decode(body) {
            Ok(q) => ldap
                .authenticate(g, &q)
                .await
                .map(|a| a.encode())
                .map_err(Some),
            Err(_) => Err(None),
        },
        _ => match DirectoryRead::decode(body) {
            Ok(q) => ldap
                .directory_read(g, &q)
                .await
                .map(|p| p.encode())
                .map_err(Some),
            Err(_) => Err(None),
        },
    })
}
