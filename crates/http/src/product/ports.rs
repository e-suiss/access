//! What the product client API needs (OP-63): the domains' key and Party lookups and the
//! tenant directory.

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::adapters::{ExerciseRecord, KeyAnswer, PartyAnswer};
use access_authority_core::keys::AsOf;
use access_kernel::digest::Digest;
use access_kernel::model::Id;

/// Answers key lookups (OP-149 m.5) and Party status lookups (m.28 (c)) on a domain.
pub trait KeyDirectory: Send + Sync {
    /// The keys `kids` of `domain` at `as_of`; with `sign` the answer is signed.
    fn lookup(
        &self,
        domain: Digest,
        kids: Vec<[u8; 32]>,
        as_of: AsOf,
        sign: bool,
    ) -> impl Future<Output = Result<KeyAnswer, CoreError>> + Send;

    /// The Parties `parties` of `domain` at `as_of`; with `sign` the answer is signed.
    fn parties(
        &self,
        domain: Digest,
        parties: Vec<Id>,
        as_of: AsOf,
        sign: bool,
    ) -> impl Future<Output = Result<PartyAnswer, CoreError>> + Send;
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

    fn parties(
        &self,
        domain: Digest,
        parties: Vec<Id>,
        as_of: AsOf,
        sign: bool,
    ) -> impl Future<Output = Result<PartyAnswer, CoreError>> + Send {
        (**self).parties(domain, parties, as_of, sign)
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

/// Reads allowed Exercises of a domain (OP-149 m.9).
pub trait Exercises: Send + Sync {
    /// The allowed Exercise `exercise` of `domain`; `None` when the domain never allowed it.
    fn exercise(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> impl Future<Output = Result<Option<ExerciseRecord>, CoreError>> + Send;
}

impl<E: Exercises> Exercises for Arc<E> {
    fn exercise(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> impl Future<Output = Result<Option<ExerciseRecord>, CoreError>> + Send {
        (**self).exercise(domain, exercise)
    }
}

/// What a resolution asks for, one direction at a time (OP-149 A11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubjectQuery {
    /// `PartyID`s to their pairwise `sub`.
    Parties(Vec<[u8; 16]>),
    /// Pairwise `sub`s to their `PartyID`.
    Subs(Vec<String>),
}

/// The pairs a resolution found, read at or after `consistency`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// `(party, sub)` for every entry that resolved to a Party.
    pub pairs: Vec<([u8; 16], String)>,
    /// `(client_id, sub)` for every `sub` that is the pairwise pseudonym of a client of the realm
    /// without a Party: the `sub` of its service tokens (OP-149 m.34 (b)).
    pub clients: Vec<(String, String)>,
    /// The governing domain's head before the read, as an opaque token (OP-141 m.22 (f)).
    pub consistency: String,
}

/// Resolves between a realm's Parties and the pairwise `sub` a client of it sees (OP-149 A11,
/// MD-10).
pub trait Subjects: Send + Sync {
    /// The pairs of `lookup` in `realm` of `tenant` for the client `client_id`, its pairwise
    /// sector. `None` when the realm or an active client with that id is not there.
    fn resolve(
        &self,
        tenant: [u8; 16],
        realm: [u8; 16],
        client_id: &str,
        lookup: SubjectQuery,
    ) -> impl Future<Output = Result<Option<Resolved>, Unavailable>> + Send;
}
