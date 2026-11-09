//! What a projection needs from the core besides its `projection.issue` decision (§9.9.3 rule
//! 4, §9.9.4, §9.12.1, §13.7.2, §13.7.4, MD-10): the consequence tier of what it carries, the
//! domain-pairwise references of the parties it names, the audience's Verifier Profile, and the
//! issuance policy that denies a contract the connectivity ceilings, the profile or the
//! issuance limits do not admit.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::body::{Body, Class, VerifierProfile};
use access_kernel::combinator::{
    Blocker, BlockerClass, Decision, Outcome, Position, Remediation, Resolver,
};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::meta::{self, Actor, ExerciseBasis, InstanceState, Payload, SliceRequest, kind};
use access_kernel::model::{
    ActionRef, AuthoritySet, Binding as ProofBinding, CanonicalAuthority, Id, ProofKind,
    RequirementTerm, Window,
};
use access_kernel::tier::{self, Tier};
use access_kernel::validity::ceiling::{
    self, Ceiling, HOUR_MS, SECURE_CLOCK_CLASS, SLICE_SHARE_DIVISOR,
};
use access_kernel::validity::{ProfileClass, ProfileVariant};
use suiss_crypto::dcbor::{self, Limits};

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{Evaluation, Request};
use crate::ports::{Binding, Reader, Salts};

/// `projection.issue` per Instance and action class per hour (§13.7.4, PD).
pub const ISSUE_PER_HOUR: u64 = 30;
/// Open offline PAPs per Instance (§13.7.4, PD).
pub const OPEN_OFFLINE: u64 = 3;

/// The subcodes of a `restricted` DENY of the issuance policy, each `policy:<name>`
/// (§13.7.2, §13.7.4, §9.12.1).
pub mod policy {
    /// The bounds carry a meta-action, an action without an accepted schema or a catalog prefix
    /// the domain has not pinned: no tier, no projection.
    pub const TIER: &str = "policy:projection-tier";
    /// The variant does not belong to the class.
    pub const PROFILE: &str = "policy:projection-profile";
    /// The policy default allows no projection of this variant at this tier.
    pub const CLASS_CAP: &str = "policy:class-cap";
    /// The horizon exceeds the class ceiling or the verifier's declared one.
    pub const HORIZON: &str = "policy:class-cap-horizon";
    /// Δ or the checkpoint interval is missing or exceeds the class ceiling.
    pub const PARAMETER: &str = "policy:class-cap-parameter";
    /// The tier needs a verifier with a tamper-evident counter, a secure clock and attestation.
    pub const HARDWARE: &str = "policy:class-cap-hardware";
    /// An audience has no accepted Verifier Profile, the profiles differ, or the profile does
    /// not cover the contract.
    pub const VERIFIER_PROFILE: &str = "policy:verifier-profile";
    /// A slice goes to more than one verifier.
    pub const SLICE_AUDIENCE: &str = "policy:slice-audience";
    /// A slice takes more than a tenth of a lineage budget term.
    pub const SLICE_SHARE: &str = "policy:slice-share";
    /// A consumption-bearing action leaves the online class without a slice.
    pub const SLICE_REQUIRED: &str = "policy:slice-required";
    /// Over `projection.issue` per Instance × action class per hour.
    pub const RATE: &str = "policy:projection-rate";
    /// Over open offline PAPs per Instance.
    pub const OPEN_OFFLINE: &str = "policy:open-offline";
    /// An audience left a `checkpointed-offline` projection unreported past its deadline.
    pub const UNREPORTED: &str = "policy:unreported-contracts";
    /// The bounds carry a requirement the verifier cannot check itself.
    pub const LOCAL_REQUIREMENT: &str = "policy:local-requirement";
}

/// Whether a verifier checks `term` itself, without the authority plane: a local
/// authentication or a Claim presented to it, unbound or bound to the holder Instance. A
/// contribution, foreign authority, or a proof bound to an intent or a resource is never
/// local (§9.10 `local_requirements`).
#[must_use]
pub fn locally_verifiable(term: &RequirementTerm) -> bool {
    matches!(
        term.proof_kind,
        ProofKind::Authentication | ProofKind::Claim
    ) && matches!(
        term.binding,
        ProofBinding::None | ProofBinding::ActorInstance
    )
}

/// The class and variant words a contract is recorded under.
#[must_use]
pub fn class_word(class: ProfileClass) -> &'static str {
    match class {
        ProfileClass::Online => "online",
        ProfileClass::Intermittent => "intermittent",
        ProfileClass::Offline => "offline",
        ProfileClass::LongRunning => "long-running",
    }
}

/// The variant word a contract is recorded under.
#[must_use]
pub fn variant_word(variant: ProfileVariant) -> &'static str {
    match variant {
        ProfileVariant::OnlineStrict => "online-strict",
        ProfileVariant::BoundedStaleness => "bounded-staleness",
        ProfileVariant::RevalidateOnReconnect => "revalidate-on-reconnect",
        ProfileVariant::CheckpointedOffline => "checkpointed-offline",
        ProfileVariant::CheckpointContinuation => "checkpoint-continuation",
    }
}

/// The action namespaces of `bounds`, named and by prefix, sorted.
#[must_use]
pub fn namespaces(bounds: &AuthoritySet) -> Vec<String> {
    let actions = &bounds.actions;
    let mut out: Vec<String> = actions
        .exact
        .iter()
        .map(|a| a.namespace.clone())
        .chain(actions.prefix.iter().map(|(n, _)| n.clone()))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// A recorded Verifier Profile body, decoded.
fn decode_profile(body: &[u8]) -> Option<VerifierProfile> {
    let value = dcbor::decode(body, Limits::CEILING).ok()?;
    match Body::from_value(Class::VerifierProfile, &value).ok()? {
        Body::VerifierProfile(p) => Some(p),
        _ => None,
    }
}

/// Whether `profile` honours a contract of `variant` with `slice` at `ceiling` (§9.12.1,
/// §13.7.2, PI-12): it implements the variant, sends reports for an offline one, holds a counter
/// for a slice and, where the tier asks, the hardware triple.
fn profile_admits(
    profile: &VerifierProfile,
    variant: ProfileVariant,
    slice: bool,
    ceiling: &Ceiling,
) -> Result<(), &'static str> {
    if !profile.covers(variant, &BTreeMap::new()) {
        return Err(policy::VERIFIER_PROFILE);
    }
    if variant == ProfileVariant::CheckpointedOffline && !profile.offline_report {
        return Err(policy::VERIFIER_PROFILE);
    }
    if slice && !profile.tamper_evident_counter {
        return Err(policy::VERIFIER_PROFILE);
    }
    if ceiling.hardware
        && !(profile.tamper_evident_counter
            && profile.attestation.is_some()
            && profile.clock_source == SECURE_CLOCK_CLASS)
    {
        return Err(policy::HARDWARE);
    }
    Ok(())
}

/// Whether the slice stays within the verifier's declared slice ceilings by unit (§9.12.1).
fn slice_within(profile: &VerifierProfile, slice: &SliceRequest) -> bool {
    let fits = |unit: &str, amount: u64| {
        profile
            .slice_max
            .get(unit)
            .is_none_or(|max| i64::try_from(amount).is_ok_and(|a| a <= *max))
    };
    slice.count.is_none_or(|c| fits("count", c)) && slice.amounts.iter().all(|(u, a)| fits(u, *a))
}

/// A `restricted` DENY of the issuance policy at the domain's policy position.
fn policy_deny(code: &'static str, remediation: Remediation) -> Decision {
    Decision {
        outcome: Outcome::Deny,
        blockers: vec![Blocker {
            class: BlockerClass::Restricted,
            subcode: Some(String::from(code)),
            position: Position::DomainPolicy,
            resolver: Resolver::DomainAdmin,
            remediation,
        }],
        unmet: Vec::new(),
        relied_on: Vec::new(),
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The issuance policy of an allowed `projection.issue` (§9.12.1, §13.7.2, §13.7.4, PI-12,
    /// SEC13, SEC14): the connectivity ceilings of the variant at the bounds' tier, the
    /// audience's Verifier Profile, the slice rules and the issuance limits. A contract the
    /// policy does not admit is a recorded `restricted` DENY with the rule's subcode; nothing is
    /// projected and nothing is drawn.
    pub(crate) async fn projection_policy(
        &self,
        req: &Request,
        evaluation: &mut Evaluation,
        actor: Option<Actor>,
        now: u64,
    ) -> Result<(), CoreError> {
        let (Some(Payload::ProjectionIssue { .. }), Some(actor)) = (&req.payload, actor) else {
            return Ok(());
        };
        if evaluation.decision.outcome != Outcome::Allow {
            return Ok(());
        }
        if let Err((code, remediation)) = self.admit_projection(req, &actor, now).await? {
            evaluation.decision = policy_deny(code, remediation);
            evaluation.draws.clear();
            evaluation.effects.clear();
            evaluation.releases.clear();
        }
        Ok(())
    }

    /// Every action the bounds name, catalog prefixes expanded through the pinned catalogs;
    /// `None` for a prefix the domain has not pinned.
    fn bounded_actions(&self, bounds: &CanonicalAuthority) -> Option<BTreeSet<ActionRef>> {
        let actions = &bounds.authority.actions;
        let mut all = actions.exact.clone();
        for (namespace, version) in &actions.prefix {
            let listed = self.catalog.catalogs.get(version)?;
            all.extend(listed.iter().filter(|a| a.namespace == *namespace).cloned());
        }
        Some(all)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one rule table, read top to bottom in the order of §13.7.2"
    )]
    async fn admit_projection(
        &self,
        req: &Request,
        actor: &Actor,
        now: u64,
    ) -> Result<Result<(), (&'static str, Remediation)>, CoreError> {
        let Some(Payload::ProjectionIssue {
            bounds,
            audience,
            class,
            variant,
            max_staleness_ms,
            offline_slice,
        }) = &req.payload
        else {
            return Err(CoreError::Protocol("payload"));
        };
        let refuse = |code| Ok(Err((code, Remediation::NewRequestRequired)));
        // §9.10, Ek B 2517
        if !bounds.requirements.iter().all(locally_verifiable) {
            return refuse(policy::LOCAL_REQUIREMENT);
        }
        // §9.9.3 rule 4, OP-141 m.35 (g)
        let Some(actions) = self.bounded_actions(bounds) else {
            return refuse(policy::TIER);
        };
        let Some(tier) = self.projected_tier(&actions, None, now).await? else {
            return refuse(policy::TIER);
        };
        if variant.class() != *class {
            return refuse(policy::PROFILE);
        }
        // §13.7.2
        let Some(ceil) = ceiling::policy(*variant, tier) else {
            return refuse(policy::CLASS_CAP);
        };
        let horizon = bounds.constraints.validity.until;
        if horizon.saturating_sub(now) > ceil.horizon_ms {
            return refuse(policy::HORIZON);
        }
        match (variant, max_staleness_ms, ceil.staleness_ms) {
            (ProfileVariant::BoundedStaleness, Some(delta), Some(cap)) if *delta <= cap => {}
            (ProfileVariant::BoundedStaleness, _, _) | (_, Some(_), _) => {
                return refuse(policy::PARAMETER);
            }
            (_, None, _) => {}
        }
        // §13.7.2
        if ceil.checkpoint_ms.is_some() {
            return refuse(policy::PARAMETER);
        }
        let consuming = self
            .settled(|snap| {
                actions
                    .iter()
                    .filter_map(|a| crate::domain::accepted_schema(snap, a, now))
                    .any(|s| s.consumption_bearing)
            })
            .await?;
        // §5.10, §9.10 (2506, 2517)
        if *class != ProfileClass::Online && consuming && offline_slice.is_none() {
            return refuse(policy::SLICE_REQUIRED);
        }
        // §9.12.1, PI-12
        let mut profiles: Vec<(Digest, VerifierProfile)> = Vec::new();
        for a in audience {
            match self.reader.verifier_profile(a, now).await? {
                Some((digest, body)) => {
                    let Some(p) = decode_profile(&body) else {
                        return refuse(policy::VERIFIER_PROFILE);
                    };
                    profiles.push((Digest(digest), p));
                }
                None if *class == ProfileClass::Online && offline_slice.is_none() => {}
                None => return refuse(policy::VERIFIER_PROFILE),
            }
        }
        if let Some((first, _)) = profiles.first()
            && profiles.iter().any(|(d, _)| d != first)
        {
            return refuse(policy::VERIFIER_PROFILE);
        }
        for (_, p) in &profiles {
            if let Err(code) = profile_admits(p, *variant, offline_slice.is_some(), &ceil) {
                return refuse(code);
            }
            if p.cap_horizon(*variant, ceiling::ct(tier))
                .is_some_and(|cap| horizon.saturating_sub(now) > cap)
            {
                return refuse(policy::HORIZON);
            }
            if offline_slice.as_ref().is_some_and(|s| !slice_within(p, s)) {
                return refuse(policy::VERIFIER_PROFILE);
            }
        }
        if let Some(slice) = offline_slice {
            // SEC13, OP-150 m.3 (s)
            if audience.len() != 1 {
                return refuse(policy::SLICE_AUDIENCE);
            }
            // §13.7.2
            if *variant == ProfileVariant::CheckpointedOffline
                && tier == Tier::Ct1
                && let ExerciseBasis::Holding(h) = req.basis
            {
                let terms = self
                    .settled(|snap| crate::domain::slice_terms(snap, &h.grant, slice))
                    .await?
                    .unwrap_or_default();
                if terms.iter().any(|(_, _, term, demand)| {
                    *demand > term.capacity.checked_div(SLICE_SHARE_DIVISOR).unwrap_or(0)
                }) {
                    return refuse(policy::SLICE_SHARE);
                }
            }
        }
        // §13.7.4
        let names = namespaces(&bounds.authority);
        if self
            .reader
            .issued_since(&actor.instance, now.saturating_sub(HOUR_MS), &names)
            .await?
            >= ISSUE_PER_HOUR
        {
            return Ok(Err((
                policy::RATE,
                Remediation::WaitUntil(now.saturating_add(HOUR_MS)),
            )));
        }
        if *class == ProfileClass::Offline
            && self.reader.open_offline(&actor.instance, now).await? >= OPEN_OFFLINE
        {
            return refuse(policy::OPEN_OFFLINE);
        }
        // §13.7.2, SEC14
        for a in audience {
            if self.reader.unreported_overdue(a, now).await? {
                return Ok(Err((
                    policy::UNREPORTED,
                    Remediation::NotSatisfiableByActor,
                )));
            }
        }
        Ok(Ok(()))
    }

    /// The Verifier Profile the contract of a projection to `audience` is issued against
    /// (§9.12.1): its digest, the `verifier_profile_ref`, and its clock source class. Without
    /// a profile, an online contract names the audience set under `access/verifier-profile/v1`
    /// and the `trusted` clock class (OP-143 m.11).
    pub(crate) async fn contract_profile(
        &self,
        audience: &BTreeSet<String>,
        now: u64,
    ) -> Result<(Digest, String), CoreError> {
        for a in audience {
            if let Some((digest, body)) = self.reader.verifier_profile(a, now).await? {
                let Some(p) = decode_profile(&body) else {
                    return Err(CoreError::Protocol("verifier-profile"));
                };
                return Ok((Digest(digest), p.clock_source));
            }
        }
        let listed = suiss_crypto::dcbor::Value::Array(
            audience
                .iter()
                .map(|a| suiss_crypto::dcbor::Value::text(a))
                .collect(),
        );
        let bytes =
            dcbor::encode(&listed, Limits::CEILING).map_err(|_| CoreError::Protocol("pap"))?;
        Ok((
            Digest(suiss_crypto::digest::context_digest("access/verifier-profile/v1", &bytes).0),
            String::from("trusted"),
        ))
    }
}

fn bare(action: &ActionRef) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: action.clone(),
        resources: Vec::new(),
        params: BTreeMap::new(),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window { from: 0, until: 0 },
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The highest consequence tier among `actions`, each by its accepted Action Schema, and
    /// `intent` by its schema and amounts (§13.7.1, OP-141 m.35 (g)). `None` when one of them
    /// is a meta-action or has no accepted schema: such authority is never projected into a
    /// token (meta-actions go through AIS + `commit`, §9.9.3 rule 4).
    pub(crate) async fn projected_tier(
        &self,
        actions: &BTreeSet<ActionRef>,
        intent: Option<&IntentEnvelope>,
        now: u64,
    ) -> Result<Option<Tier>, CoreError> {
        let mut all: Vec<IntentEnvelope> = actions.iter().map(bare).collect();
        all.extend(intent.cloned());
        if all.iter().any(|i| i.action.namespace == meta::NAMESPACE) {
            return Ok(None);
        }
        let schemas = self
            .settled(|snap| {
                all.iter()
                    .map(|i| crate::domain::accepted_schema(snap, &i.action, now))
                    .collect::<Vec<_>>()
            })
            .await?;
        let mut top = Tier::Ct0;
        for (i, s) in all.iter().zip(schemas) {
            let Some(s) = s else {
                return Ok(None);
            };
            top = top.max(tier::of(i, None, false, Some(&s)));
        }
        Ok(Some(top))
    }

    /// The domain-pairwise reference of the Party of `instance` (P52, MD-10).
    pub(crate) async fn instance_ref(&self, instance: &Id) -> Result<Id, CoreError> {
        let party = self
            .settled(|snap| {
                crate::domain::read::<InstanceState>(snap, kind::INSTANCE, instance)
                    .map(|i| i.party)
            })
            .await?
            .ok_or(CoreError::Protocol("instance"))?;
        self.party_ref(&party)
    }

    /// Every Party `intent` names, with its domain-pairwise reference (P52, MD-10).
    pub(crate) fn intent_refs(
        &self,
        intent: &IntentEnvelope,
    ) -> Result<BTreeMap<Id, Id>, CoreError> {
        let mut out = BTreeMap::new();
        let named = intent
            .recipient
            .iter()
            .chain(intent.params.values().filter_map(|v| match v {
                ParamValue::Subject(p) => Some(p),
                _ => None,
            }));
        for p in named {
            out.insert(*p, self.party_ref(p)?);
        }
        Ok(out)
    }
}
