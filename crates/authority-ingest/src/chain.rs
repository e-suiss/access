//! The chain gate of chain-constrained issuers (IDI-12, IDP-20, OP-155 m.3 (j), §10.7.1): a Claim
//! of an issuer whose OpenID Federation chain no longer resolves, was last checked longer ago
//! than the freshness window, has expired or has a metadata policy conflict is not ingested. The
//! gate never touches the Acceptance: the cut is a lapse, not a revocation, and input resumes on
//! its own once the chain resolves again.
//!
//! The issuer is read from the submission before it is verified. That only ever refuses more:
//! a Claim naming an issuer it was not signed by fails verification anyway.

use access_internal_api::claims::{Carrier, ClaimSubmission};
use access_kernel::claim::{self, Statement};
use access_kernel::codec::Canonical;
use access_kernel::model::Id;
use access_kernel::verify::cose;
use suiss_crypto::dcbor::{self, Limits};

use crate::domain::{Refusal, peek_iss};

/// How old a chain check may be before the issuer's Claims stop (Δ, OP-155 m.3 (j)).
pub const FRESHNESS_MS: u64 = 3_600_000;

/// The refusal of a Claim whose issuer's chain does not hold.
pub const REFUSAL: Refusal = Refusal("claim-issuer-chain");

/// The state of a tracked issuer's chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Tracked, never resolved yet.
    Pending,
    /// Resolved at the last check.
    Resolved,
    /// Did not resolve at the last check.
    Unresolved,
    /// The chain's metadata policies conflict.
    Conflict,
}

/// What the last chain check of a tracked issuer found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fact {
    /// The state.
    pub status: Status,
    /// When it was checked, Unix milliseconds.
    pub checked_ms: u64,
    /// When the chain expires, `min(exp)` over its statements.
    pub chain_exp_ms: u64,
}

/// Whether a tracked issuer's Claims are ingested at `now_ms`: its chain resolved, the check is
/// at most [`FRESHNESS_MS`] old and the chain has not expired.
#[must_use]
pub fn admits(f: &Fact, now_ms: u64) -> bool {
    // IDI-12
    f.status == Status::Resolved
        && now_ms <= f.checked_ms.saturating_add(FRESHNESS_MS)
        && now_ms < f.chain_exp_ms
}

/// Whether every tracked row that names the issuer admits it; an untracked issuer is not gated.
#[must_use]
pub fn gate(facts: &[Fact], now_ms: u64) -> Result<(), Refusal> {
    if facts.iter().all(|f| admits(f, now_ms)) {
        Ok(())
    } else {
        Err(REFUSAL)
    }
}

/// Who a submission says issued it, read without verifying it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Named {
    /// The issuer Party a signed or unsigned Claim names.
    pub party: Option<Id>,
    /// The `iss` an upstream carrier names.
    pub entity: Option<String>,
}

fn statement_of(sign1: &[u8]) -> Option<Statement> {
    let payload = cose::parse_sign1(sign1).ok()?.payload?;
    let value = dcbor::decode(&payload, Limits::CEILING).ok()?;
    Statement::from_value(&value).ok()
}

/// The issuer a submission names; nothing when it does not parse (verification refuses it).
#[must_use]
pub fn named(s: &ClaimSubmission) -> Named {
    match s.carrier {
        Carrier::Cose | Carrier::Webauthn => Named {
            party: statement_of(&s.claim).map(|st| st.issuer),
            entity: None,
        },
        Carrier::Unsigned(channel) => Named {
            party: claim::unsigned(&s.claim, &s.domain, &channel)
                .ok()
                .map(|u| u.statement.issuer),
            entity: None,
        },
        Carrier::Oidc | Carrier::Set => Named {
            party: None,
            entity: peek_iss(&s.claim).ok(),
        },
        _ => Named::default(),
    }
}

#[cfg(test)]
mod tests;
