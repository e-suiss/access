//! The revocation mechanisms each plane keeps, and how they meet (MD-7, OP-21, §17.3.4,
//! OP-150 m.2). The semantics is the `ValidityContract`; epochs are mechanism. `session_epoch`
//! revokes identity plane sessions and tokens only and never an authority decision (TI-15);
//! `key_epoch` is a key window; the authority plane has no `authz_epoch`, its place is taken by
//! the `AuthorityStateBasis` position a decision read (`applied_pos`). There is no global epoch.

use std::future::Future;

use access_kernel::digest::Digest;

use crate::idp::Unavailable;

/// Stable code of [`Unavailable`] while no epoch source is served.
pub const UNAVAILABLE: &str = "epochs-unavailable";

/// A position of a domain's authority log: what a decision, an introspection answer or a status
/// list reflects. It replaces `authz_epoch` (G51).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityPosition {
    /// The domain.
    pub domain: Digest,
    /// The position.
    pub position: u64,
    /// Its `recorded_at`, trusted time in milliseconds.
    pub recorded_at: u64,
}

/// An identity plane session epoch: monotonic per realm subject; a token's `rev` claim carries
/// the value it was issued under (OP-21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionEpoch {
    /// The realm.
    pub realm: [u8; 16],
    /// The realm subject.
    pub subject: [u8; 16],
    /// The epoch.
    pub epoch: u64,
}

/// Which key a `key_epoch` is the window of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyOwner {
    /// A domain operational key (Domain Metadata).
    Domain(Digest),
    /// A realm JOSE key (realm JWKS).
    Realm([u8; 16]),
}

/// A key window: the signing times a key's signatures are accepted for (MD-7, T20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyEpoch {
    /// Whose key.
    pub owner: KeyOwner,
    /// RFC 7638 thumbprint.
    pub kid: [u8; 32],
    /// First signing time, milliseconds.
    pub valid_from: u64,
    /// Last signing time, milliseconds.
    pub valid_until: u64,
}

impl KeyEpoch {
    /// Whether a signature made at `iat` falls in the window.
    #[must_use]
    pub const fn covers(&self, iat: u64) -> bool {
        self.valid_from <= iat && iat <= self.valid_until
    }
}

/// What the identity plane reads from the authority plane about its state: the head an
/// introspection answer must reach (`at_least`), and key windows.
pub trait Epochs: Send + Sync {
    /// The domain's latest committed position.
    fn head(
        &self,
        domain: Digest,
    ) -> impl Future<Output = Result<AuthorityPosition, Unavailable>> + Send;

    /// The window of the domain operational key `kid`, if the domain declared it.
    fn key_epoch(
        &self,
        domain: Digest,
        kid: [u8; 32],
    ) -> impl Future<Output = Result<Option<KeyEpoch>, Unavailable>> + Send;
}

/// The epochs of a process that does not serve them yet: every call is [`UNAVAILABLE`]. A
/// caller fails closed on it (OPI-3): an introspection answer is `active=false`.
#[derive(Clone, Copy, Debug, Default)]
pub struct Unserved;

impl Epochs for Unserved {
    fn head(
        &self,
        _domain: Digest,
    ) -> impl Future<Output = Result<AuthorityPosition, Unavailable>> + Send {
        std::future::ready(Err(Unavailable(String::from(UNAVAILABLE))))
    }

    fn key_epoch(
        &self,
        _domain: Digest,
        _kid: [u8; 32],
    ) -> impl Future<Output = Result<Option<KeyEpoch>, Unavailable>> + Send {
        std::future::ready(Err(Unavailable(String::from(UNAVAILABLE))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // MD-7, OPI-3, OP-150 m.2
    #[test]
    fn unserved_epochs_are_unavailable() {
        let d = Digest([1; 32]);
        assert_eq!(
            crate::block_on(Unserved.head(d)),
            Err(Unavailable(String::from(UNAVAILABLE)))
        );
        assert_eq!(
            crate::block_on(Unserved.key_epoch(d, [2; 32])),
            Err(Unavailable(String::from(UNAVAILABLE)))
        );
        let w = KeyEpoch {
            owner: KeyOwner::Domain(d),
            kid: [2; 32],
            valid_from: 10,
            valid_until: 20,
        };
        assert!(w.covers(10) && w.covers(20) && !w.covers(9) && !w.covers(21));
    }
}
