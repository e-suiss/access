//! What the product client API needs (OP-63): the domains' key lookup and the tenant directory.

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::KeyAnswer;
use access_authority_core::keys::AsOf;
use access_kernel::digest::Digest;

/// Answers key lookups on a domain (OP-149 m.5).
pub trait KeyDirectory: Send + Sync {
    /// The keys `kids` of `domain` at `as_of`; with `sign` the answer is signed.
    fn lookup(
        &self,
        domain: Digest,
        kids: Vec<[u8; 32]>,
        as_of: AsOf,
        sign: bool,
    ) -> impl Future<Output = Result<KeyAnswer, CoreError>> + Send;
}

impl<K: KeyDirectory> KeyDirectory for Arc<K> {
    fn lookup(
        &self,
        domain: Digest,
        kids: Vec<[u8; 32]>,
        as_of: AsOf,
        sign: bool,
    ) -> impl Future<Output = Result<KeyAnswer, CoreError>> + Send {
        (**self).lookup(domain, kids, as_of, sign)
    }
}

/// One tenant as its snapshot shows it (OP-149 m.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tenant {
    /// Internal id.
    pub id: [u8; 16],
    /// `provisioning`, `active`, `suspended` or `deleted`.
    pub status: String,
    /// Its organizations' external ids.
    pub organizations: Vec<String>,
    /// Its live realms, by slug.
    pub realms: Vec<Realm>,
}

/// A live realm of a tenant as its snapshot shows it (OP-149 m.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Realm {
    /// The realm's id, as events name it in `accessrealm`.
    pub id: [u8; 16],
    /// Its fixed issuer.
    pub issuer: String,
    /// Its immutable slug.
    pub slug: String,
}

/// The tenant directory could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("tenant directory unavailable")]
pub struct Unavailable;

/// Reads tenants and maps their ids (OP-149 m.4, MD-18).
pub trait Tenants: Send + Sync {
    /// The tenant `id`.
    fn tenant(
        &self,
        id: [u8; 16],
    ) -> impl Future<Output = Result<Option<Tenant>, Unavailable>> + Send;

    /// At most `limit` tenants in id order after `after`.
    fn after(
        &self,
        after: Option<[u8; 16]>,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<Tenant>, Unavailable>> + Send;

    /// The opaque external id of `id`.
    fn external(&self, id: [u8; 16]) -> Option<String>;

    /// The internal id of an external id.
    fn internal(&self, text: &str) -> Option<[u8; 16]>;
}
