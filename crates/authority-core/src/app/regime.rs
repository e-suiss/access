//! Party Identity Regime and account status effects (§9.13, §10.1.5, E5): each reaches
//! authority only as a restriction overlay, an actor-binding input or an explicit Exercise;
//! none changes authority state by itself. Also the issuer order of qualifying Claims (TI-RT7,
//! G36) and the staleness of a membership carrier (§8.13: "Needs refresh — not removed").

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::body::{ACCOUNT_STATUSES, Class};
use access_kernel::claim::{self, ClaimState, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Decision, Outcome, Position, Unmet};
use access_kernel::meta::{self, Actor, ExerciseBasis, GrantState, InstanceState, kind};
use access_kernel::model::{
    Binding as ProofBinding, Conjunct, Consumption, EqValue, Id, Independence, ProofKind,
    RequirementTerm, SubjectSelector,
};

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{Evaluation, Request, Snapshot};
use crate::ports::{Binding, Reader, Salts};

/// The `account_status` values that narrow (§5.6, §12.3.1, TN-49).
const NARROWING_STATUSES: [&str; 3] = ["suspended", "deactivated", "tombstone"];

const fn current(s: &Statement, now: u64) -> bool {
    s.validity.from <= now && now <= s.validity.until
}

/// Whether two unordered Claims of one issuer line say otherwise of each other: their values
/// differ and are assertions about the subject. The value of a class with a body is the body's
/// digest, which names one event each (a sign-in, a binding), so such Claims stand side by side
/// (TI-RT7, OP-141 m.30 (e), OP-150 L6 (f)).
fn contradicts(a: &Statement, b: &Statement) -> bool {
    // OP-156 m.3 (r)
    if access_internal_api::signals::is_signal(&a.class) {
        return a.value != b.value
            && a.bound_resource == b.bound_resource
            && a.bound_instance == b.bound_instance;
    }
    a.value != b.value && !Class::parse(&a.class).is_some_and(Class::has_body)
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Whether Claim `id` asserts in its issuer line for a qualifying use: not superseded, and
    /// no current, unsuperseded Claim of the same line [`contradicts`] it without an order
    /// between them; when the order is not known the disqualifying side wins (TI-RT7, G36,
    /// §9.13 rule 6).
    pub(crate) async fn in_line(
        &self,
        snap: &mut Snapshot,
        id: &Id,
        s: &Statement,
        now: u64,
    ) -> Result<bool, CoreError> {
        if !self.unsuperseded(snap, id, s).await? {
            return Ok(false);
        }
        for (_, value, _) in self
            .scan(&claim::member_prefix(&s.class, &s.subject))
            .await?
        {
            let Some(other) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            if other == *id {
                continue;
            }
            let Some(o) = self
                .get(snap, &meta::key(kind::CLAIM, &other))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|o| {
                    o.ended.is_none()
                        && claim::same_line(s, &o.statement)
                        && contradicts(s, &o.statement)
                        && current(&o.statement, now)
                })
            else {
                continue;
            };
            if self.unsuperseded(snap, &other, &o.statement).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The accepted, current, unsuperseded Claims of `class` about `party`.
    async fn regime_claims(
        &self,
        snap: &mut Snapshot,
        class: &str,
        party: &Id,
        now: u64,
    ) -> Result<Vec<ClaimState>, CoreError> {
        let mut out = Vec::new();
        for (_, value, _) in self.scan(&claim::member_prefix(class, party)).await? {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|c| {
                    c.ended.is_none()
                        && c.statement.subject == *party
                        && c.statement.class == class
                        && current(&c.statement, now)
                })
            else {
                continue;
            };
            let gates = self.gates(snap, &state.statement.issuer).await?;
            let accepted = gates.iter().any(|g| {
                claim::ADMITTING_USES
                    .iter()
                    .any(|u| g.admits_for(u, &state.statement, now))
            });
            if accepted && self.unsuperseded(snap, &id, &state.statement).await? {
                out.push(state);
            }
        }
        Ok(out)
    }

    /// The overlay that denies `actor` by its subcode (§9.13, E5): its Party's narrowing
    /// account status from the ingest position on (TN-49, TN-50, SEC12, X36), its termination,
    /// or an identity break after its Instance was established (§10.1.5). A newer status in the
    /// issuer line lifts the first; two without an order keep it (TI-RT7).
    pub(crate) async fn overlaid(
        &self,
        actor: Actor,
        now: u64,
    ) -> Result<Option<&'static str>, CoreError> {
        let mut snap = Snapshot::default();
        let party = actor.party;
        let status = Class::AccountStatus.name();
        if self
            .regime_claims(&mut snap, &status, &party, now)
            .await?
            .iter()
            .any(|c| {
                matches!(&c.statement.value, Some(EqValue::Text(t))
                    if NARROWING_STATUSES.contains(&t.as_str()) && ACCOUNT_STATUSES.contains(&t.as_str()))
            })
        {
            return Ok(Some("account-status"));
        }
        let terminated = Class::PartyTerminated.name();
        if !self
            .regime_claims(&mut snap, &terminated, &party, now)
            .await?
            .is_empty()
        {
            return Ok(Some("party-terminated"));
        }
        let broken = Class::PartyIdentityBreak.name();
        let breaks = self.regime_claims(&mut snap, &broken, &party, now).await?;
        if !breaks.is_empty() {
            let since = self
                .get(&mut snap, &meta::key(kind::INSTANCE, &actor.instance))
                .await?
                .and_then(|v| InstanceState::from_value(&v).ok())
                .map(|i| i.since);
            // §10.1.5
            if breaks.iter().any(|b| since.is_none_or(|s| s < b.since)) {
                return Ok(Some("party-identity-break"));
            }
        }
        Ok(None)
    }

    /// Whether `party` recovered after its last compromise declaration and before the Instance
    /// established at `since` (§7.9.2.3, §7.9.2.4: Party recovery is an actor-binding input for
    /// a new Instance; it never carries an old one over).
    pub(crate) async fn recovered_before(
        &self,
        party: &Id,
        since: u64,
        now: u64,
    ) -> Result<bool, CoreError> {
        let declared = self
            .compromises(party, now)
            .await?
            .iter()
            .map(|c| c.declared)
            .max()
            .unwrap_or(0);
        let mut snap = Snapshot::default();
        let recovered = Class::PartyRecovered.name();
        Ok(self
            .regime_claims(&mut snap, &recovered, party, now)
            .await?
            .iter()
            .any(|r| r.since > declared && r.since < since))
    }

    /// A DENY on a holding of a Grant held by a predicate, where the actor's membership Claim
    /// has only gone stale, becomes `REQUIRE_ACTION` for a fresh Claim: "Needs refresh — not
    /// removed" (§8.13, §8.17.5.7, OP-142).
    pub(crate) async fn stale_holding(
        &self,
        req: &Request,
        actor: Option<Actor>,
        evaluation: &mut Evaluation,
        now: u64,
    ) -> Result<(), CoreError> {
        let (Outcome::Deny, ExerciseBasis::Holding(h), Some(actor)) =
            (evaluation.decision.outcome, &req.basis, actor)
        else {
            return Ok(());
        };
        if actor.party != h.holder {
            return Ok(());
        }
        let mut snap = Snapshot::default();
        let Some(SubjectSelector::Pred(conjuncts)) = self
            .get(&mut snap, &meta::key(kind::GRANT, &h.grant))
            .await?
            .and_then(|v| GrantState::from_value(&v).ok())
            .map(|g| g.content.holder)
        else {
            return Ok(());
        };
        let mut stale = Vec::new();
        for c in &conjuncts {
            if self
                .episode(&mut snap, &BTreeSet::from([c.clone()]), &h.holder, now)
                .await?
                .is_some()
            {
                continue;
            }
            match self.lapsed(&mut snap, c, &h.holder, now).await? {
                Some(term) => stale.push(term),
                None => return Ok(()),
            }
        }
        if stale.is_empty() {
            return Ok(());
        }
        evaluation.decision = Decision {
            outcome: Outcome::RequireAction,
            blockers: Vec::new(),
            unmet: stale
                .into_iter()
                .map(|term| Unmet {
                    term,
                    missing: 1,
                    position: Position::ActorSide,
                    satisfiable_by_actor: true,
                })
                .collect(),
            relied_on: Vec::new(),
        };
        evaluation.effects.clear();
        evaluation.draws.clear();
        evaluation.releases.clear();
        Ok(())
    }

    /// The fresh-Claim term for `c` when `party` holds a Claim that met it and has only run
    /// out of validity, from an issuer whose `subject-selection` Acceptance still stands.
    async fn lapsed(
        &self,
        snap: &mut Snapshot,
        c: &Conjunct,
        party: &Id,
        now: u64,
    ) -> Result<Option<RequirementTerm>, CoreError> {
        for (_, value, _) in self
            .scan(&claim::member_prefix(&c.claim_class, party))
            .await?
        {
            let Some(id) = value.and_then(|v| Id::from_value(&v).ok()) else {
                continue;
            };
            let Some(state) = self
                .get(snap, &meta::key(kind::CLAIM, &id))
                .await?
                .and_then(|v| ClaimState::from_value(&v).ok())
                .filter(|s| {
                    let st = &s.statement;
                    s.ended.is_none()
                        && st.subject == *party
                        && st.validity.until < now
                        && claim::satisfies(c, s, st.validity.until)
                })
            else {
                continue;
            };
            let gates = self.gates(snap, &state.statement.issuer).await?;
            let standing = gates.iter().any(|g| {
                g.admits_for(
                    claim::SUBJECT_SELECTION,
                    &state.statement,
                    state.statement.validity.until,
                ) && g.validity.from <= now
                    && now <= g.validity.until
            });
            if standing && self.unsuperseded(snap, &id, &state.statement).await? {
                return Ok(Some(RequirementTerm {
                    proof_kind: ProofKind::Claim,
                    class: c.claim_class.clone(),
                    count: 1,
                    binding: ProofBinding::None,
                    freshness_ms: None,
                    independence: Independence::None,
                    consumption: Consumption::Reusable,
                    source: Some(SubjectSelector::Party(state.statement.issuer)),
                    assurance: std::collections::BTreeMap::new(),
                }));
            }
        }
        Ok(None)
    }
}
