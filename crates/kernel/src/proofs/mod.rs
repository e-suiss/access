//! Kani harnesses for the Kernel targets CR-K1…CR-K9 and their proptest mirrors (CR-47,
//! OP-159 m.3 (w)). Each `k<n>` module states its property once as a function; the `#[cfg(kani)]`
//! harness checks it for every input within the bounds, the `#[cfg(test)]` mirror for random
//! inputs. The module is compiled by `crates/kernel/tests/proofs.rs`.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Stored;
use access_kernel::combinator::{Basis, Capacity, Hop, HopStatus};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms,
    ResourceRef, ResourceSelector, Structural, TrustedTime, Window,
};
use access_kernel::validity::{
    ProfileClass, ProfileVariant, Revalidation, ValidityContract, VerifierContext,
};

mod k1;
mod k2;
mod k3;
mod k4;
mod k5;
mod k6;
mod k7;
mod k8;
mod k9;

/// A digest whose 32 bytes are all `n`.
pub(crate) const fn digest(n: u8) -> Digest {
    Digest([n; 32])
}

/// The one action every fixture uses.
pub(crate) fn action() -> ActionRef {
    ActionRef {
        namespace: String::from("pay"),
        name: String::from("refund"),
        major: 1,
        schema: digest(9),
    }
}

/// An authority set covering [`action`] on every `shop` resource.
pub(crate) fn authority() -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([action()]),
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from("shop"),
            prefix: Vec::new(),
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

/// An active hop covering [`intent`], valid on `[0, 100_000]`, without budgets.
pub(crate) fn hop() -> Hop {
    Hop {
        authority: CanonicalAuthority {
            authority: authority(),
            constraints: ConstraintSet {
                validity: Window {
                    from: 0,
                    until: 100_000,
                },
                conditions: BTreeSet::new(),
                budget: BTreeSet::new(),
            },
            delegation: DelegationTerms {
                depth: 1,
                downstream_holder_class: None,
            },
            requirements: BTreeSet::new(),
        },
        status: HopStatus::Active,
        conditions_hold: true,
        budgets: Vec::new(),
    }
}

/// A basis of `hops` for oneself.
pub(crate) fn basis(hops: Vec<Hop>) -> Basis {
    Basis {
        hops: hops.into_iter().map(Stored::Known).collect(),
        capacities: BTreeSet::from([Capacity::Own]),
    }
}

/// An intent for [`action`] on `shop/o1`, valid on `[0, 100_000]`.
pub(crate) fn intent() -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action(),
        resources: vec![ResourceRef {
            namespace: String::from("shop"),
            path: vec![String::from("o1")],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 100_000,
        },
    }
}

/// The audience every validity fixture names.
pub(crate) const AUDIENCE: &str = "verifier";

/// A contract for [`AUDIENCE`] with `horizon`, `variant`, Δ and skew, and nothing else to
/// understand.
pub(crate) fn contract(
    horizon: TrustedTime,
    variant: ProfileVariant,
    max_staleness_ms: Option<u64>,
    clock_skew_ms: u64,
) -> ValidityContract {
    ValidityContract {
        issuing_exercise: digest(1),
        basis_ref: Vec::new(),
        holder: digest(2),
        audience: BTreeSet::from([String::from(AUDIENCE)]),
        bounds: authority(),
        class: ProfileClass::Online,
        variant,
        profile_version: 1,
        params: BTreeMap::new(),
        horizon,
        max_staleness_ms,
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::new(),
        local_requirements: BTreeSet::new(),
        verifier_profile_ref: digest(3),
        clock_source: String::from("ntp"),
        clock_skew_ms,
        must_understand: BTreeSet::new(),
        status: None,
    }
}

/// What the verifier knows: `now`, the artefact's `iat`, the class skew and horizon ceiling,
/// whether it decides online and its last refresh.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Moment {
    pub(crate) now: TrustedTime,
    pub(crate) iat: TrustedTime,
    pub(crate) skew_ms: u64,
    pub(crate) horizon_cap_ms: u64,
    pub(crate) online: bool,
    pub(crate) last_refresh: Option<TrustedTime>,
}

impl Moment {
    /// The verifier context for this moment.
    pub(crate) const fn context<'a>(
        &self,
        understood: &'a BTreeSet<String>,
    ) -> VerifierContext<'a> {
        VerifierContext {
            now: self.now,
            audience: AUDIENCE,
            understood,
            last_refresh: self.last_refresh,
            online: self.online,
            skew_ms: self.skew_ms,
            iat: self.iat,
            horizon_cap_ms: self.horizon_cap_ms,
        }
    }
}

/// Times near zero, near `u64::MAX` and anywhere, so the mirrors reach the overflow edges.
#[cfg(all(test, not(kani)))]
pub(crate) fn edge() -> impl proptest::strategy::Strategy<Value = u64> {
    use proptest::prelude::*;
    prop_oneof![
        0..=1_000_000u64,
        (u64::MAX - 1_000_000)..=u64::MAX,
        (u64::MAX / 2 - 1_000_000)..=(u64::MAX / 2 + 1_000_000),
        any::<u64>(),
    ]
}

/// Evaluates one `commit` of [`intent`] at 50 000 on `basis` with `fuel` steps.
pub(crate) fn commit(
    basis: &access_kernel::combinator::Basis,
    fuel: u64,
) -> Result<access_kernel::combinator::Decision, access_kernel::combinator::Rejection> {
    use access_kernel::algebra::Catalog;
    use access_kernel::combinator::{EvaluationInput, Fuel, Mode, evaluate};
    use access_kernel::model::Id;

    let intent = intent();
    let catalog = Catalog::default();
    let candidates = core::slice::from_ref(basis);
    let input = EvaluationInput {
        mode: Mode::Commit,
        intent: &intent,
        intent_digest: digest(1),
        now: 50_000,
        actor_instance: Some(Id([1; 16])),
        actor_party: None,
        actor_is_agent: false,
        mandate: None,
        capacity: Capacity::Own,
        bases: candidates,
        restrictions: &[],
        proofs: &[],
        catalog: &catalog,
        mappings: &[],
    };
    evaluate(&input, &mut Fuel(fuel))
}
