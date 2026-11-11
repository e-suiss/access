//! Support access as the identity plane forwards it (OP-157 m.3 (f), (g), OP-62): a person's own
//! `grant.issue` or `grant.revoke` of support access, the upload and the reading of a support
//! artifact, each committed with the identity plane as PEP; and what the identity plane needs to
//! draft a support Grant.

use std::future::Future;

use access_kernel::digest::Digest;
use access_kernel::model::Id;

use crate::idp::{Submission, Unavailable, Verdict};

/// What a support Grant is drafted with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SupportFacts {
    /// The self-anchor of the person, while the domain holds the Party.
    pub anchor: Option<Id>,
    /// The digest of the domain's `predicate-input` Acceptance of the case system's
    /// `support_case` Claims, when it has one.
    pub acceptance: Option<Digest>,
}

/// The authority plane behind support access.
pub trait SupportAuthority: Send + Sync {
    /// Commits `submission` as PEP after checking that a live Instance of its actor signed it.
    fn commit(
        &self,
        submission: Submission,
    ) -> impl Future<Output = Result<Verdict, Unavailable>> + Send;

    /// The [`SupportFacts`] of `party` and the case system `issuer` in `domain`.
    fn facts(
        &self,
        domain: Digest,
        party: Id,
        issuer: Id,
    ) -> impl Future<Output = Result<SupportFacts, Unavailable>> + Send;
}
