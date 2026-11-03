//! What the domain needs from the outside world (OP-63): the realm directory the router role
//! reads (OP-132 m.3), and the realm keys the identity signer publishes (CMP-22b).

pub mod dpop;
pub mod oauth;

use std::future::Future;

use access_store::identity::{RealmId, TenantId};

use crate::domain::issuer::Issuer;

/// A live realm as the router sees it.
#[derive(Clone)]
pub struct RealmEntry {
    /// The tenant that owns it (routing context only, TN-1).
    pub tenant: TenantId,
    /// The realm.
    pub realm: RealmId,
    /// Its immutable slug (TN-16).
    pub slug: String,
    /// The issuer stored on its row (§17.9.6).
    pub issuer: Issuer,
}

/// The backing store could not answer; the caller answers 503 (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// The live realms, read across tenants by the router role (OP-132 m.3).
pub trait Directory: Send + Sync {
    /// The live realm with an issuer whose hostname is `host` (lower-cased, no port).
    fn by_host(
        &self,
        host: &str,
    ) -> impl Future<Output = Result<Option<RealmEntry>, Unavailable>> + Send;

    /// The live realm with an issuer whose slug is `slug`.
    fn by_slug(
        &self,
        slug: &str,
    ) -> impl Future<Output = Result<Option<RealmEntry>, Unavailable>> + Send;

    /// Every live realm with an issuer, for the start-up JWKS check (§17.9.7).
    fn all(&self) -> impl Future<Output = Result<Vec<RealmEntry>, Unavailable>> + Send;
}

/// The realm keys the identity signer holds (CMP-22b, OP-143 m.9).
pub trait Keys: Send + Sync {
    /// The signer answers.
    fn ping(&self) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// The current JWKS of `realm`, opening its key set on first use.
    fn jwks(&self, realm: RealmId) -> impl Future<Output = Result<String, Unavailable>> + Send;
}
