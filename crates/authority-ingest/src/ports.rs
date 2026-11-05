//! What the pipeline needs from the outside world (OP-63): the domain's ledger behind the
//! sequencer, the day's submission table and a clock.

use std::future::Future;
use std::sync::Arc;

use access_internal_api::claims::{ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::Unavailable;
use access_kernel::digest::Digest;

/// The domain's authority core: verifies a submission against the domain's state, records it
/// through the sequencer and answers its disposition (§9.13, L2-CLM-3, L2-CLM-4).
pub trait Ledger: Send + Sync {
    /// Records `submission`; `resubmitted` when the day's table had seen it.
    fn record(
        &self,
        submission: ClaimSubmission,
        resubmitted: bool,
    ) -> impl Future<Output = Result<ClaimVerdict, Unavailable>> + Send;
}

/// The day's submission digests (OP-146 m.5 (f), OP-150 m.6 (f)).
pub trait Submissions: Send + Sync {
    /// `true` the first time `hash` is seen in `domain` on `day`.
    fn first(
        &self,
        domain: Digest,
        day: u32,
        hash: [u8; 32],
        carrier: &'static str,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send;
}

/// Trusted time (OP-129 m.1).
pub trait Clock: Send + Sync {
    /// Now, in milliseconds.
    fn now(&self) -> impl Future<Output = Result<u64, Unavailable>> + Send;
}

impl<L: Ledger> Ledger for Arc<L> {
    fn record(
        &self,
        submission: ClaimSubmission,
        resubmitted: bool,
    ) -> impl Future<Output = Result<ClaimVerdict, Unavailable>> + Send {
        (**self).record(submission, resubmitted)
    }
}
