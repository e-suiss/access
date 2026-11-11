//! The `derived.*` values of a request and the `policy.set` analysis on the commit path
//! (§16.5, RT26, SI-8, OP-157 m.3 (n), (o)).

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical;
use access_kernel::meta::{self, Actor, ContentState, ExerciseBasis, InstanceState, Payload, kind};
use access_kernel::model::ProofKind;
use access_store::authority::Draw;
use suiss_crypto::dcbor::Value;

use super::proofs::Resolved;
use super::{Authority, Incoming};
use crate::CoreError;
use crate::ports::{Binding, PolicyRelation, Reader, Salts};
use crate::restrict::derived::{self, Counted, Derived, NONE, Window};

/// The values a recorded decision cites, read back for its explanation (SI-8).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Cited {
    /// The `derived` member of its `StateBasis`, if any.
    pub(crate) derived: Option<Derived>,
    /// The `policy_relation` member: the analysis raised the change (OP-157 m.3 (n)).
    pub(crate) raised: Option<PolicyRelation>,
}

/// The values of a request that read none (SI-8).
pub(crate) static EMPTY: Derived = Derived::empty();

/// The answer a cited word names.
#[must_use]
pub(crate) fn relation_of(word: &str) -> Option<PolicyRelation> {
    [
        PolicyRelation::Equivalent,
        PolicyRelation::Narrowing,
        PolicyRelation::Widening,
        PolicyRelation::Incomparable,
        PolicyRelation::MayError,
        PolicyRelation::Unknown,
    ]
    .into_iter()
    .find(|r| r.word() == word)
}

impl Cited {
    /// Reads the cited members of a recorded `StateBasis`.
    pub(crate) fn of(state_basis: Option<&Value>) -> Self {
        let derived = state_basis
            .and_then(|b| b.get("derived"))
            .and_then(Derived::from_cited);
        let raised = match state_basis.and_then(|b| b.get("policy_relation")) {
            Some(Value::Text(w)) => relation_of(w),
            _ => None,
        };
        Self { derived, raised }
    }
}

fn long(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The counter draws an ALLOW adds for the window values (§16.5, OP-157 m.3 (o)).
pub(crate) fn draws(window: &Window, allowed: bool) -> impl Iterator<Item = Draw> + '_ {
    window
        .increments
        .iter()
        .filter(move |_| allowed)
        .map(|(key, amount)| Draw {
            key: key.clone(),
            limit: u64::MAX >> 1,
            draw: *amount,
        })
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// What the decision being explained cited; `None` outside an explanation (SI-8).
    pub(crate) fn cited(&self) -> Option<&Cited> {
        self.past.as_ref().map(|p| &p.cited)
    }

    /// The `derived.*` values of `inc` and what an ALLOW of it adds to the window counters
    /// (§16.5 whitelist 1–11, OP-157 m.3 (o)). While a decision is explained, the values it
    /// cited, or none.
    pub(crate) async fn window_of(
        &self,
        inc: &Incoming,
        actor: Option<Actor>,
        resolved: &Resolved,
        now: u64,
    ) -> Result<Window, CoreError> {
        if let Some(cited) = self.cited() {
            return Ok(Window {
                values: cited.derived.clone().unwrap_or(Derived::empty()),
                increments: Vec::new(),
            });
        }
        let req = &inc.request;
        let party = actor.map(|a| a.party);
        let mut counted = Counted::default();
        if let Some(p) = &party {
            for b in derived::buckets(now) {
                counted.consumption = counted
                    .consumption
                    .saturating_add(self.counter(&derived::consumption_key(p, b)).await?);
                if let Some(t) = derived::target(&req.intent) {
                    counted.adjacent = counted
                        .adjacent
                        .saturating_add(self.counter(&derived::adjacent_key(p, &t, b)).await?);
                }
            }
            if let (ExerciseBasis::Holding(h), Some(since)) = (req.basis, resolved.held) {
                let started = self.reader.recorded_at(since).await?.unwrap_or(0);
                if started >= now.saturating_sub(derived::WINDOW_MS) {
                    let mut before = 0u64;
                    for b in derived::buckets(now) {
                        before = before.saturating_add(
                            self.counter(&derived::transitions_key(&h.grant, b)).await?,
                        );
                    }
                    let seen = self
                        .counter(&derived::transition_seen_key(&h.grant, p, since))
                        .await?
                        > 0;
                    counted.transitions = Some((h.grant, since, before, seen));
                }
            }
        }
        let mut window = derived::window(&req.intent, party.as_ref(), &counted, now);
        let v = &mut window.values;
        v.mapping_pin_age_s = NONE;
        v.claim_age_s = NONE;
        if let Some(a) = actor {
            let (len, _) = crate::rate::REQUEST_RATE[0];
            v.open_require_action = long(
                self.counter(&crate::rate::request_rate_key(&a.party, len, now))
                    .await?,
            );
            let names = vec![req.intent.action.namespace.clone()];
            v.projection_issue_count = long(
                self.reader
                    .issued_since(
                        &a.instance,
                        now.saturating_sub(derived::ISSUE_WINDOW_MS),
                        &names,
                    )
                    .await?,
            );
            v.open_offline_paps = long(self.reader.open_offline(&a.instance, now).await?);
        }
        v.unreported_contracts = i64::from(self.reader.unreported_overdue(&inc.pep, now).await?);
        let cited: Vec<Vec<u8>> = resolved
            .proofs
            .iter()
            .filter(|p| p.kind == ProofKind::Contribution)
            .map(|p| meta::key(kind::INSTANCE, &p.instance))
            .collect();
        if !cited.is_empty() {
            let ended = self.fetch(&cited).await?.into_iter().any(|(_, v, _)| {
                v.and_then(|v| InstanceState::from_value(&v).ok())
                    .is_none_or(|s| s.ended.is_some())
            });
            v.cited_instance_state = i64::from(ended);
        }
        let mut youngest: Option<u64> = None;
        for p in resolved
            .proofs
            .iter()
            .filter(|p| p.kind == ProofKind::Claim)
        {
            if let Some(at) = self.reader.recorded_at(p.position).await? {
                youngest = Some(youngest.map_or(at, |y| y.max(at)));
            }
        }
        if let Some(at) = youngest {
            v.claim_age_s = long(now.saturating_sub(at) / 1_000);
        }
        Ok(window)
    }

    /// Whether the control-plane analysis raises a structurally narrowing amendment of a
    /// restriction policy to expansion (OP-157 m.3 (n)): `None` when it does not, or when no
    /// solver is wired or the change is no such amendment. While a decision is explained, what
    /// it cited.
    pub(crate) async fn policy_raised(
        &self,
        payload: Option<&Payload>,
    ) -> Result<Option<PolicyRelation>, CoreError> {
        if let Some(cited) = self.cited() {
            return Ok(cited.raised);
        }
        let Some(Payload::PolicySet {
            policy: Some(p),
            content,
        }) = payload
        else {
            return Ok(None);
        };
        if !self.analysis.wired() {
            return Ok(None);
        }
        let old = self
            .fetch(&[meta::key(kind::POLICY, p)])
            .await?
            .into_iter()
            .find_map(|(_, v, _)| v.and_then(|v| ContentState::from_value(&v).ok()));
        let Some(old) = old.filter(|s| s.ended.is_none()) else {
            return Ok(None);
        };
        if !meta::policy_narrows(&old.content, content) {
            return Ok(None);
        }
        let source = |v: &Value| match v.get("source") {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let (Some(old), Some(new)) = (source(&old.content), source(content)) else {
            return Ok(None);
        };
        let relation = self
            .analysis
            .compare(crate::restrict::SCHEMA, &old, &new)
            .await;
        Ok(relation.raises(true).then_some(relation))
    }
}
