//! The authority reads of the realm's SSH certificate authority (OP-156 m.3 (o), IDP-32): the
//! live Grants a Party holds that cover `ssh.login`, which a certificate is drafted from and
//! held within, and whether an allowed projection's basis still stands, which decides whether
//! its certificate is in the KRL. Both are derived; neither records anything.

use std::future::Future;

use access_kernel::digest::Digest;
use access_kernel::meta::HoldingRef;
use access_kernel::model::{ActionRef, CanonicalAuthority, Id};

use crate::idp::Unavailable;

/// One live Grant of the Party: the `holding` basis that names it and what it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshHolding {
    /// The basis a `projection.issue` names.
    pub holding: HoldingRef,
    /// The Grant's canonical authority.
    pub authority: CanonicalAuthority,
}

/// What the authority plane answers about one allowed projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Its basis stands now.
    Stands,
    /// Its basis ended (a Grant revoked or expired, an Anchor retired, a Party departed).
    Ended,
    /// The domain holds no projection of that Exercise.
    Unknown,
}

/// The SSH certificate authority's reads (CMP-7).
pub trait SshGrants: Send + Sync {
    /// The live Grants of `party` in `domain` whose actions cover `action`, held by name or,
    /// for a rule-shaped Grant, as a member now; at most one page.
    fn holdings(
        &self,
        domain: Digest,
        party: Id,
        action: ActionRef,
    ) -> impl Future<Output = Result<Vec<SshHolding>, Unavailable>> + Send;

    /// Whether the basis of the projection the allowed `projection.issue` `exercise` of
    /// `domain` made still stands.
    fn standing(
        &self,
        domain: Digest,
        exercise: Digest,
    ) -> impl Future<Output = Result<Standing, Unavailable>> + Send;
}
