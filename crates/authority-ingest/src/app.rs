//! The ingest use case: from a submission to a recorded Claim and its disposition (CMP-8).

use access_internal_api::claims::{Carrier, ClaimIngest, ClaimSubmission, ClaimVerdict};
use access_internal_api::idp::Unavailable;

use crate::domain::{self, Refusal};
use crate::ports::{Clock, Ledger, Submissions};

/// The pipeline over its ports.
#[derive(Clone, Debug)]
pub struct Ingest<L, S, C> {
    ledger: L,
    submissions: S,
    clock: C,
}

impl<L, S, C> Ingest<L, S, C> {
    /// The pipeline.
    pub const fn new(ledger: L, submissions: S, clock: C) -> Self {
        Self {
            ledger,
            submissions,
            clock,
        }
    }
}

fn rejected(r: Refusal) -> ClaimVerdict {
    ClaimVerdict::Rejected {
        code: String::from(r.0),
    }
}

/// Checks what needs no state: sizes and, for a mapped carrier, its context (§9.13 rule 3).
///
/// # Errors
/// [`Refusal`].
pub fn precheck(s: &ClaimSubmission) -> Result<(), Refusal> {
    domain::check_size(&s.claim, s.body.as_deref())?;
    if matches!(s.carrier, Carrier::Oidc | Carrier::Set) {
        domain::carrier_context(s.body.as_deref())?;
    }
    Ok(())
}

impl<L: Ledger, S: Submissions, C: Clock> ClaimIngest for Ingest<L, S, C> {
    async fn ingest(&self, submission: ClaimSubmission) -> Result<ClaimVerdict, Unavailable> {
        if let Err(r) = precheck(&submission) {
            return Ok(rejected(r));
        }
        let now = self.clock.now().await?;
        let hash = domain::submission_hash(submission.carrier, &submission.claim);
        let first = self
            .submissions
            .first(
                submission.domain,
                domain::day_of(now),
                hash,
                submission.carrier.name(),
            )
            .await?;
        self.ledger.record(submission, !first).await
    }
}

#[cfg(test)]
mod tests;
