//! The human review queue (TN-46, GDPR art. 22, SCHUFA C-634/21): SL2 never locks an account; a
//! person reads the item and marks it. A false positive feeds the FP budget (OP-151 m.3 (o)).
//! Marking is an operational record, not authority or realm configuration; any containment is a
//! separate narrowing Exercise (SI-4, TN-48).

use access_store::identity::TenantTx;
use access_store::risk::ReviewRow;

use crate::RiskError;

/// A reviewer's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The risk was real.
    Confirmed,
    /// It was not: counts against the FP budget.
    FalsePositive,
    /// Nothing to do.
    Dismissed,
}

impl Verdict {
    /// The stored state.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::Dismissed => "dismissed",
        }
    }
}

/// Decides an open item; false when it is not open (decided items never change).
///
/// # Errors
/// [`RiskError`].
pub async fn decide(
    tx: &mut TenantTx,
    review: [u8; 16],
    verdict: Verdict,
    reviewer: &str,
) -> Result<bool, RiskError> {
    let done = tx.decide_review(review, verdict.name(), reviewer).await?;
    if done {
        tracing::info!(
            event = "risk.review.decided",
            verdict = verdict.name(),
            "risk review item decided"
        );
    }
    Ok(done)
}

/// The realm's open items, oldest first.
///
/// # Errors
/// [`RiskError`].
pub async fn open(tx: &mut TenantTx, limit: u32) -> Result<Vec<ReviewRow>, RiskError> {
    Ok(tx.open_reviews(limit).await?)
}
