//! Authentication and approval assurance per consequence tier (§13.7.3, the canonical table;
//! IDP-8 and §10.3.3 only narrow it): which authenticator class an `authentication` Claim must
//! come from, how fresh it must be and what it must be bound to, the `expires_at` ceiling of an
//! Approval Act Statement, and the cooling of a new authenticator binding (SEC18). CT0 takes the
//! CT1 values; a password, an OTP or a push alone satisfies no tier (N-45, SEC10, SEC26).

use alloc::collections::BTreeMap;
use alloc::string::String;

use crate::claim::body::Class;
use crate::model::{Binding, Consumption, Independence, ProofKind, RequirementTerm};
use crate::requirement::{HUMAN_PRESENCE, meets_floor};
use crate::tier::Tier;

/// Assurance dimension: proven by channel or verifier-name binding (§10.3.1).
pub const PHISHING_RESISTANT: &str = "phishing_resistant";
/// Assurance dimension: user verification that counts as a factor (MD-11).
pub const UV: &str = "uv";
/// Assurance dimension: a key that cannot leave its authenticator.
pub const HARDWARE_BOUND: &str = "hardware_bound";
/// Assurance dimension: a key held by the user, not a custodian.
pub const NON_CUSTODIAL: &str = "non_custodial";

/// Step-up freshness and AAS `expires_at` ceiling of CT0 and CT1 (§13.7.3, PD).
pub const CT1_FRESHNESS_MS: u64 = 15 * 60 * 1_000;
/// Step-up freshness and AAS `expires_at` ceiling of CT2 and CT3 (§13.7.3, PD).
pub const CT2_FRESHNESS_MS: u64 = 5 * 60 * 1_000;
/// How long a new authenticator binding or issuer designation satisfies no CT2+ requirement
/// (SEC18, PD).
pub const COOLING_MS: u64 = 24 * 3_600 * 1_000;

/// The longest an actor's authentication may be old for `tier` (§13.7.3 "Step-up freshness").
#[must_use]
pub const fn freshness_ceiling(tier: Tier) -> u64 {
    match tier {
        Tier::Ct0 | Tier::Ct1 => CT1_FRESHNESS_MS,
        Tier::Ct2 | Tier::Ct3 => CT2_FRESHNESS_MS,
    }
}

/// The longest an Approval Act Statement may be valid for `tier` (§13.7.3 "AAS `expires_at`").
#[must_use]
pub const fn aas_expiry_ceiling(tier: Tier) -> u64 {
    freshness_ceiling(tier)
}

/// What an actor's authentication of `tier` is bound to (§13.7.3): the actor Instance up to
/// CT1, the intent digest through H(AAS) from CT2.
#[must_use]
pub const fn binding(tier: Tier) -> Binding {
    match tier {
        Tier::Ct0 | Tier::Ct1 => Binding::ActorInstance,
        Tier::Ct2 | Tier::Ct3 => Binding::IntentDigest,
    }
}

/// The authenticator class `tier` needs, as assurance floors (§13.7.3 "Authenticator class"):
/// phishing-resistant for every tier, UV from CT2, hardware-bound and non-custodial at CT3.
#[must_use]
pub fn floors(tier: Tier) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::from([(String::from(PHISHING_RESISTANT), 1)]);
    if tier >= Tier::Ct2 {
        out.insert(String::from(UV), 1);
    }
    if tier == Tier::Ct3 {
        out.insert(String::from(HARDWARE_BOUND), 1);
        out.insert(String::from(NON_CUSTODIAL), 1);
    }
    out
}

/// The floors of an approval at `tier` (§13.7.3 "Human presence"): the authenticator class and
/// a present human, for every tier.
#[must_use]
pub fn approval_floors(tier: Tier) -> BTreeMap<String, u64> {
    let mut out = floors(tier);
    out.insert(String::from(HUMAN_PRESENCE), 1);
    out
}

/// Whether `levels` meet every floor.
#[must_use]
pub fn meets(floors: &BTreeMap<String, u64>, levels: &BTreeMap<String, u64>) -> bool {
    floors.iter().all(|(dim, floor)| {
        levels
            .get(dim)
            .is_some_and(|l| meets_floor(dim, *floor, *l))
    })
}

/// The highest tier whose authenticator class `levels` satisfy; `None` when they satisfy no
/// tier, CT0 included (§13.7.3 CT0 footnote: password, OTP and push alone).
#[must_use]
pub fn ceiling(levels: &BTreeMap<String, u64>) -> Option<Tier> {
    [Tier::Ct3, Tier::Ct2, Tier::Ct1]
        .into_iter()
        .find(|t| meets(&floors(*t), levels))
}

/// The `authentication` requirement an actor must meet at `tier` (§13.7.3; §8.5, §8.17.5.4):
/// one current Claim of that class, fresh within the tier's ceiling, bound as [`binding`] says,
/// from the tier's authenticator class and, for an approval, from a present human.
#[must_use]
pub fn authentication_term(tier: Tier, approval: bool) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: Class::Authentication.name(),
        count: 1,
        binding: binding(tier),
        freshness_ms: Some(freshness_ceiling(tier)),
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: if approval {
            approval_floors(tier)
        } else {
            floors(tier)
        },
    }
}

/// Whether an authentication at `auth_time` is fresh enough for `tier` at `now`.
#[must_use]
pub const fn fresh(tier: Tier, auth_time: u64, now: u64) -> bool {
    auth_time <= now && now.saturating_sub(auth_time) <= freshness_ceiling(tier)
}

/// Whether an AAS valid from `issued_at` to `expires_at` stays within the ceiling of `tier`.
#[must_use]
pub const fn aas_within_ceiling(tier: Tier, issued_at: u64, expires_at: u64) -> bool {
    expires_at >= issued_at && expires_at.saturating_sub(issued_at) <= aas_expiry_ceiling(tier)
}

/// SEC18: an authenticator binding or issuer designation made at `bound_at` satisfies a CT2+
/// requirement only from `bound_at + 24 h`. `Ok` when it may be used for `tier` at `now`;
/// `Err` carries when it becomes available, for the explanation ("available 14:00 tomorrow",
/// §8.13).
///
/// # Errors
/// The time the binding becomes usable.
pub const fn cooled(tier: Tier, bound_at: u64, now: u64) -> Result<(), u64> {
    let available = bound_at.saturating_add(COOLING_MS);
    if matches!(tier, Tier::Ct2 | Tier::Ct3) && now < available {
        Err(available)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
