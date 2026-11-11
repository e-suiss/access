//! The organization template's separation of duties (§2.4, §5.9, §13.7.3, SEC10, C26,
//! OP-157 m.3 (u)): a domain declares SoD by giving its `approve:<class>` Grants a term that
//! needs a contribution from another Party. Without it, the actor's own contribution or
//! assertion is enough: the rule is a requirement term, not a mode.

use access_kernel::model::{Binding, Consumption, Independence, ProofKind, RequirementTerm};

/// The term an org template's `approve:<class>` Grant carries when the domain declares SoD:
/// `count` contributions bound to the intent, each from a Party other than the actor
/// (`contributor ≠ actor principal`, Kernel L0-EVAL-26).
#[must_use]
pub fn approve_term(class: &str, count: u64) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: class.to_owned(),
        count,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctParty,
        consumption: Consumption::Reusable,
        source: None,
        assurance: std::collections::BTreeMap::new(),
    }
}
