//! Impact previews (X20, TN-121, §5.4, §5.8, §16.5.1, SEC15, RR-13): what moving role
//! delegations to another version or setting a restriction policy would change, what a
//! revocation leaves exposed, and what a compromise may have touched. Every preview is DERIVED
//! and advisory: it reads state and the log and writes nothing. The move itself is an explicit
//! bulk `grant.amend`, one attributable Exercise per Grant, through the ADP like any other.

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, subsumes};
use access_kernel::claim::{self, ClaimState};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::meta::{
    self, ContentState, ExerciseBasis, GrantBasis, GrantState, NamedPin, View as _,
    authority_set_digest, authority_set_key, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Id, RequirementTerm, SubjectSelector, Window,
};
use access_kernel::record::{RecordEnvelope, RecordKind};
use access_kernel::tier::Tier;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Authority;
use crate::app::publishing::settle;
use crate::app::roles::{SetRelation, catalog_of, relation};
use crate::domain::{Snapshot, read};
use crate::ports::{Binding, PolicyAnalysis, PolicyRelation, Reader, Salts};

/// Most live Grants a preview looks at (PD).
pub const MAX_GRANTS: usize = 10_000;

/// Grants read from the index per page.
const PAGE: u32 = 500;

/// Most log records a compromise query walks (PD).
pub const MAX_RECORDS: u64 = 20_000;

/// Log records read per page.
const LOG_PAGE: u64 = 500;

/// Most member entries one rule-shaped holder count reads (the state scan ceiling).
const MAX_MEMBERS: usize = 256;

/// One ability: an action with the bounds it comes with.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ability {
    /// The action.
    pub action: ActionRef,
    /// The authority set limited to that action.
    pub bounds: AuthoritySet,
}

/// One line of a change preview (§8.17.9.2): "gives N people a new ability … removes 1 ability
/// from M people".
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbilityChange {
    /// The ability after the move when gained or widened, before it when lost or narrowed.
    pub ability: Ability,
    /// Holders who gain it or more of it.
    pub holders_gaining: u64,
    /// Holders who lose it or part of it.
    pub holders_losing: u64,
}

/// Who holds the Grants a preview looks at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Holders {
    /// Distinct Parties, named or selected by rule.
    pub parties: u64,
    /// A Grant is held by everyone.
    pub everyone: bool,
    /// The count may be lower: rule-shaped holders were counted by their first condition, or
    /// the member scan reached its ceiling.
    pub upper_bound: bool,
}

/// What a widening move needs (INV-10, XI-4): an expansion carries stricter requirements than
/// a narrowing, never looser ones.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Expansion {
    /// The tier of each `grant.amend` of the move.
    pub tier: Tier,
    /// Further `co_root` contributions a joint root needs (§13.7.3, SEC26).
    pub joint_root_quorum: u64,
    /// The CT3 time-lock, seconds.
    pub delay_s: u64,
    /// Requirement terms the moved Grants already carry; they stay.
    pub requirements: Vec<RequirementTerm>,
}

/// Rows a change would leave without meaning (TN-121).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Orphans {
    /// Grants whose action scope resolves to no action.
    pub empty_scopes: Vec<Id>,
    /// Rule-shaped Grants whose selector picks no holder now.
    pub unselecting: Vec<Id>,
}

/// The preview of moving the Grants pinned to role `name` v`from` to v`to` (X20, C28).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleChange {
    /// Role name.
    pub name: String,
    /// Version the Grants pin now.
    pub from: u64,
    /// Version they would pin.
    pub to: u64,
    /// The pin each `grant.amend` of the move carries.
    pub pin: NamedPin,
    /// The relation of v`to` to v`from`.
    pub relation: SetRelation,
    /// The Grants to amend, one Exercise each.
    pub moves: Vec<Id>,
    /// The `grant_amend` payload of each move, in the order of `moves`: the Grant's own
    /// constraints, delegation terms, requirements and agency kept, its authority set and pin
    /// those of v`to` (C28), as canonical payload bytes. Each is still its own attributable
    /// Exercise (§8.17.9.8).
    pub amends: Vec<Vec<u8>>,
    /// Who holds them.
    pub holders: Holders,
    /// Gained, widened, narrowed and lost abilities.
    pub abilities: Vec<AbilityChange>,
    /// What the move needs when it widens; `None` when it does not.
    pub expansion: Option<Expansion>,
    /// Orphan rows after the move.
    pub orphans: Orphans,
    /// More live Grants exist than the preview looked at.
    pub capped: bool,
}

/// The preview of a `policy.set` candidate (§5.8, OP-105).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyChange {
    /// The policy replaced, `None` for a new one.
    pub policy: Option<Id>,
    /// The relation of the candidate to the policy in force; [`PolicyRelation::Unknown`] when
    /// not proved.
    pub relation: PolicyRelation,
    /// The candidate's compile error, when it would be refused (OP-141 m.27 (e)).
    pub refused: Option<&'static str>,
}

/// What a revocation is of (§5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Revoked {
    /// A Grant and its lineage subtree.
    Grant(Id),
    /// An Instance.
    Instance(Id),
}

/// One projection that may still be honoured after a revocation (§5.4, §8.17.5.8).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Exposure {
    /// The projection's `ExerciseID`.
    pub exercise: Digest,
    /// Its holder Instance.
    pub holder: Id,
    /// Its profile class.
    pub class: String,
    /// Its horizon.
    pub horizon_ms: u64,
    /// How long after the revocation it may be honoured.
    pub window_ms: u64,
    /// The PEP that asked for it.
    pub pep: String,
    /// When that PEP says it applied the revocation, from its authority-state acknowledgement;
    /// `None` is unknown, not "not applied" (§9.12.3, E30).
    pub applied_at: Option<u64>,
}

/// A PEP's acknowledgement that it applied a revocation (§9.12.3, E30): an accepted
/// `authority_state_ack` Claim whose applied basis position is at or after the revocation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Acknowledged {
    /// The PEP.
    pub pep: String,
    /// PEP-local time it applied the state.
    pub applied_at: u64,
    /// The basis position it applied.
    pub basis: u64,
}

/// The aftermath summary of revoke, narrow, suspend and instance terminate (XI-3, §5.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aftermath {
    /// Grants that end with it.
    pub grants_ending: u64,
    /// Projections that may still be honoured, offline ones up to their horizon.
    pub projections_open: u64,
    /// The latest horizon among them.
    pub honoured_until_ms: Option<u64>,
    /// For an Instance: its running copies, the open projections it holds.
    pub running_copies: u64,
    /// Open projections whose PEP acknowledged applying the revocation (§9.12.3, E30).
    pub confirmed_applied: u64,
}

/// Revocation impact and staleness exposure (§5.4, §16.5.1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RevocationImpact {
    /// What is revoked.
    pub revoked: Revoked,
    /// When.
    pub at: u64,
    /// The Grants that end with it (the lineage subtree).
    pub subtree: Vec<Id>,
    /// Projections whose contract outlives it.
    pub exposed: Vec<Exposure>,
    /// The longest of their windows.
    pub max_exposure_ms: u64,
    /// How many positions the derived index is behind the log.
    pub index_lag: u64,
    /// Index rows that still say live for an ended Grant (§5.4 orphan tuple counter).
    pub orphan_tuples: u64,
    /// The PEPs that acknowledged applying it, one entry each, the latest application (E30).
    pub acknowledged: Vec<Acknowledged>,
    /// The aftermath summary.
    pub aftermath: Aftermath,
}

/// What a compromise is of (SEC15, RR-13).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Compromised {
    /// An Instance.
    Instance(Id),
    /// A Claim issuer Party.
    Issuer(Id),
    /// A key, by thumbprint; resolved to the Instance it is bound to now.
    Key([u8; 32]),
}

/// One Exercise in a compromise window.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WindowExercise {
    /// Position of its decision record.
    pub pos: u64,
    /// Its intent digest.
    pub intent: Digest,
    /// `allow`, `deny` or `require_action`.
    pub outcome: String,
}

/// What a compromise may have touched inside a window (SEC15, RR-13, §16.5.1): a derived list,
/// not a new object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompromiseImpact {
    /// What is compromised.
    pub compromised: Compromised,
    /// The window.
    pub window: Window,
    /// The Instance a key resolved to.
    pub instance: Option<Id>,
    /// Exercises decided in the window.
    pub exercises: Vec<WindowExercise>,
    /// Grants issued or changed by allowed ones.
    pub grants: Vec<Id>,
    /// Contributions they recorded.
    pub contributions: Vec<Id>,
    /// Projections they issued.
    pub projections: Vec<Digest>,
    /// Claims of the issuer recorded in the window.
    pub claims: Vec<Id>,
    /// The window held more records than the query walks.
    pub capped: bool,
}

/// `dCBOR(["member", class])` as a key prefix of the member index.
fn member_class_prefix(class: &str) -> Vec<u8> {
    let full = claim::member_key(class, &Id([0; 16]), &Id([0; 16]));
    let tail = 2 * 17;
    full.get(..full.len().saturating_sub(tail))
        .map(<[u8]>::to_vec)
        .unwrap_or_default()
}

/// The Parties rule `conjuncts` selects now, by its first condition; `true` when that is an
/// upper bound.
fn selected(
    view: &Snapshot,
    conjuncts: &BTreeSet<access_kernel::model::Conjunct>,
    now: u64,
) -> (BTreeSet<Id>, bool) {
    let Some(first) = conjuncts.iter().next() else {
        return (BTreeSet::new(), false);
    };
    let rows = view.scan(&member_class_prefix(&first.claim_class));
    let mut out = BTreeSet::new();
    for (_, v) in &rows {
        let Ok(id) = Id::from_value(v) else { continue };
        if let Some(c) = read::<ClaimState>(view, kind::CLAIM, &id)
            && claim::satisfies(first, &c, now)
        {
            out.insert(c.statement.subject);
        }
    }
    (out, conjuncts.len() > 1 || rows.len() >= MAX_MEMBERS)
}

fn count(
    holders: &mut Holders,
    parties: &mut BTreeSet<Id>,
    view: &Snapshot,
    sel: &SubjectSelector,
    now: u64,
) {
    match sel {
        SubjectSelector::Party(p) => {
            parties.insert(*p);
        }
        SubjectSelector::Public => holders.everyone = true,
        SubjectSelector::Pred(c) => {
            let (found, upper) = selected(view, c, now);
            parties.extend(found);
            holders.upper_bound |= upper;
        }
        SubjectSelector::Foreign { .. } => holders.upper_bound = true,
    }
}

fn only(set: &AuthoritySet, action: &ActionRef) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([action.clone()]),
            prefix: BTreeSet::new(),
        },
        ..set.clone()
    }
}

/// The abilities that change from `old` to `new`, each with `n` holders.
fn abilities(
    old: &AuthoritySet,
    new: &AuthoritySet,
    catalog: &Catalog,
    n: u64,
) -> Vec<AbilityChange> {
    let (before, after) = (catalog.covered(&old.actions), catalog.covered(&new.actions));
    let mut out = Vec::new();
    for action in before.union(&after) {
        let line = |set: &AuthoritySet, gaining: bool| AbilityChange {
            ability: Ability {
                action: action.clone(),
                bounds: only(set, action),
            },
            holders_gaining: if gaining { n } else { 0 },
            holders_losing: if gaining { 0 } else { n },
        };
        match (before.contains(action), after.contains(action)) {
            (false, true) => out.push(line(new, true)),
            (true, false) => out.push(line(old, false)),
            (true, true) => {
                let (o, w) = (only(old, action), only(new, action));
                let wider = !subsumes(&w, &o, catalog);
                let narrower = !subsumes(&o, &w, catalog);
                if wider {
                    out.push(line(new, true));
                }
                if narrower {
                    out.push(line(old, false));
                }
            }
            (false, false) => {}
        }
    }
    out
}

/// The CT3 time-lock of the domain (OP-141 m.34 (d)).
fn ct3_delay(view: &Snapshot) -> u64 {
    match view.get(&meta::policy_default_key(meta::CT3_DELAY)) {
        Some(Value::Unsigned(s)) => s,
        _ => meta::CT3_DELAY_DEFAULT_S,
    }
}

fn named_set(view: &Snapshot, name: &str, version: u64) -> Option<AuthoritySet> {
    view.get(&authority_set_key(name, Some(version)))
        .and_then(|v| v.get("authority").cloned())
        .and_then(|a| AuthoritySet::from_value(&a).ok())
}

/// The role change preview over the live Grants `grants` (X20, TN-121, INV-10): pure over the
/// snapshot, it never writes.
#[must_use]
pub fn role_change(
    view: &Snapshot,
    name: &str,
    (from, to): (u64, u64),
    grants: &[Id],
    capped: bool,
    now: u64,
) -> Option<RoleChange> {
    let old = named_set(view, name, from)?;
    let new = named_set(view, name, to)?;
    let catalog = catalog_of(view, &[&old, &new], now);
    let pinned: Vec<(Id, GrantState)> = grants
        .iter()
        .filter_map(|g| read::<GrantState>(view, kind::GRANT, g).map(|s| (*g, s)))
        .filter(|(_, s)| s.ended.is_none())
        .filter(|(_, s)| {
            s.content
                .named
                .as_ref()
                .is_some_and(|(n, v, _)| n == name && *v == from)
        })
        .collect();
    let mut holders = Holders::default();
    let mut parties = BTreeSet::new();
    let mut orphans = Orphans::default();
    let mut requirements = BTreeSet::new();
    for (id, s) in &pinned {
        count(&mut holders, &mut parties, view, &s.content.holder, now);
        if let SubjectSelector::Pred(c) = &s.content.holder
            && selected(view, c, now).0.is_empty()
        {
            orphans.unselecting.push(*id);
        }
        requirements.extend(s.content.authority.requirements.iter().cloned());
    }
    holders.parties = u64::try_from(parties.len()).unwrap_or(u64::MAX);
    // TN-121
    if !pinned.is_empty() && catalog.covered(&new.actions).is_empty() {
        orphans.empty_scopes = pinned.iter().map(|(g, _)| *g).collect();
    }
    let rel = relation(&old, &new, &catalog);
    // INV-10, XI-4
    let expansion = rel.widens().then(|| Expansion {
        tier: Tier::Ct3,
        joint_root_quorum: meta::CT3_QUORUM,
        delay_s: ct3_delay(view),
        requirements: requirements.into_iter().collect(),
    });
    Some(RoleChange {
        name: name.to_owned(),
        from,
        to,
        pin: (name.to_owned(), to, authority_set_digest(&new)),
        relation: rel,
        moves: pinned.iter().map(|(g, _)| *g).collect(),
        amends: pinned
            .iter()
            .map(|(g, s)| {
                let mut authority = s.content.authority.clone();
                authority.authority = new.clone();
                meta::Payload::GrantAmend {
                    grant: *g,
                    authority,
                    agency: s.content.agency.clone(),
                    named: Some((name.to_owned(), to, authority_set_digest(&new))),
                }
                .to_bytes()
                .unwrap_or_default()
            })
            .collect(),
        holders,
        abilities: abilities(&old, &new, &catalog, holders.parties),
        expansion,
        orphans,
        capped,
    })
}

/// The Grant ids of the lineage subtree under `root`, `root` first.
fn subtree(view: &Snapshot, root: &Id) -> Vec<Id> {
    let mut out = vec![*root];
    let mut frontier = vec![*root];
    for _ in 0..meta::MAX_LINEAGE {
        let mut next = Vec::new();
        for g in &frontier {
            if let Some(v) = view.get(&meta::key(kind::CHILDREN, g))
                && let Value::Array(kids) = v
            {
                for k in kids.iter().filter_map(|k| Id::from_value(k).ok()) {
                    if !out.contains(&k) {
                        out.push(k);
                        next.push(k);
                    }
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    out
}

/// The basis Grant of the projection `exercise`, from its state.
fn projection_grant(view: &Snapshot, exercise: &Digest) -> Option<Id> {
    let v = view.get(&meta::exercise_key(kind::PROJECTION, exercise))?;
    match meta::exercise_basis(v.get("basis")?).ok()? {
        ExerciseBasis::Holding(h) => Some(h.grant),
        ExerciseBasis::Public(g) => Some(g),
        ExerciseBasis::Anchor(_) => None,
    }
}

/// Whether Grant `g` is live: not ended, and every Grant above it live.
fn live_grant(view: &Snapshot, g: &Id) -> bool {
    let mut at = *g;
    for _ in 0..meta::MAX_LINEAGE {
        let Some(s) = read::<GrantState>(view, kind::GRANT, &at) else {
            return false;
        };
        if s.ended.is_some() {
            return false;
        }
        match s.content.basis {
            GrantBasis::Anchor(_) => return true,
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
    false
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

/// The `(kind, rest)` of an effect key.
fn effect_kind(key: &[u8]) -> Option<(String, Value)> {
    match dcbor::decode(key, Limits::CEILING).ok()? {
        Value::Array(mut items) if items.len() == 2 => {
            let rest = items.pop()?;
            match items.pop()? {
                Value::Text(k) => Some((k, rest)),
                _ => None,
            }
        }
        _ => None,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Every live Grant id in the derived index, at most [`MAX_GRANTS`], and whether there are
    /// more.
    async fn live_grant_ids(&self) -> Result<(Vec<Id>, bool, u64), CoreError> {
        let mut out = Vec::new();
        let mut after = None;
        let mut cursor = 0;
        loop {
            let (page, at) = self.reader.indexed_live(after, PAGE).await?;
            cursor = cursor.max(at);
            let full = page.len() == PAGE as usize;
            after = page.last().copied();
            out.extend(page);
            if out.len() >= MAX_GRANTS {
                out.truncate(MAX_GRANTS);
                return Ok((out, true, cursor));
            }
            if !full {
                return Ok((out, false, cursor));
            }
        }
    }

    /// Previews moving the Grants pinned to role `name` v`from` to v`to` (X20, C28, TN-121).
    /// Nothing is written; `None` when either version does not exist.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn change_role(
        &self,
        name: &str,
        from: u64,
        to: u64,
        now: u64,
    ) -> Result<Option<RoleChange>, CoreError> {
        let (grants, capped, _) = self.live_grant_ids().await?;
        settle(&self.reader, |snap| {
            role_change(snap, name, (from, to), &grants, capped, now)
        })
        .await
    }

    /// Previews setting `candidate` (a `policy_set` content) over `policy`, `None` for a new
    /// one (§5.8, OP-105). The relation comes from the control-plane analysis; nothing is
    /// written.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn change_policy(
        &self,
        policy: Option<Id>,
        candidate: &Value,
        analysis: &dyn PolicyAnalysis,
    ) -> Result<PolicyChange, CoreError> {
        let refused = crate::restrict::compile(candidate).err();
        let source = |v: &Value| match v.get("source") {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let old = match policy {
            None => Some(String::new()),
            Some(p) => {
                settle(&self.reader, |snap| {
                    read::<ContentState>(snap, kind::POLICY, &p)
                        .filter(|s| s.ended.is_none())
                        .and_then(|s| source(&s.content))
                })
                .await?
            }
        };
        let relation = match (refused, old, source(candidate)) {
            (None, Some(old), Some(new)) => {
                analysis.compare(crate::restrict::SCHEMA, &old, &new).await
            }
            _ => PolicyRelation::Unknown,
        };
        Ok(PolicyChange {
            policy,
            relation,
            refused,
        })
    }

    /// Revocation impact and staleness exposure of revoking `revoked` at `at` (§5.4, §16.5.1,
    /// XI-3): the lineage subtree, the projections whose contract outlives it, the derived index
    /// lag and the orphan tuple counter. Nothing is written.
    ///
    /// # Errors
    /// The reader's errors; [`CoreError::Unavailable`] when contracts or the index cannot be
    /// read.
    pub async fn revocation_impact(
        &self,
        revoked: Revoked,
        at: u64,
    ) -> Result<RevocationImpact, CoreError> {
        let contracts = self.reader.open_contracts(at).await?;
        let (live, _, cursor) = self.live_grant_ids().await?;
        let head = self.head();
        let acknowledged = self.acknowledged(revoked).await?;
        let applied = |pep: &str| {
            acknowledged
                .iter()
                .find(|a| a.pep == pep)
                .map(|a| a.applied_at)
        };
        let (subtree, exposed, orphan_tuples) = settle(&self.reader, |snap| {
            let subtree = match revoked {
                Revoked::Grant(g) => subtree(snap, &g),
                Revoked::Instance(_) => Vec::new(),
            };
            let exposed: Vec<Exposure> = contracts
                .iter()
                .filter(|c| match revoked {
                    Revoked::Instance(i) => c.holder == i,
                    Revoked::Grant(_) => {
                        projection_grant(snap, &c.exercise).is_some_and(|g| subtree.contains(&g))
                    }
                })
                .map(|c| Exposure {
                    exercise: c.exercise,
                    holder: c.holder,
                    class: c.class.clone(),
                    horizon_ms: c.horizon_ms,
                    window_ms: c.horizon_ms.saturating_sub(at),
                    pep: c.pep.clone(),
                    applied_at: applied(&c.pep),
                })
                .collect();
            let orphans = live.iter().filter(|g| !live_grant(snap, g)).count();
            (subtree, exposed, u64::try_from(orphans).unwrap_or(u64::MAX))
        })
        .await?;
        let n = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
        let aftermath = Aftermath {
            grants_ending: n(subtree.len()),
            projections_open: n(exposed.len()),
            honoured_until_ms: exposed.iter().map(|e| e.horizon_ms).max(),
            running_copies: match revoked {
                Revoked::Instance(_) => n(exposed.len()),
                Revoked::Grant(_) => 0,
            },
            confirmed_applied: n(exposed.iter().filter(|e| e.applied_at.is_some()).count()),
        };
        Ok(RevocationImpact {
            revoked,
            at,
            max_exposure_ms: exposed.iter().map(|e| e.window_ms).max().unwrap_or(0),
            subtree,
            exposed,
            index_lag: head.saturating_sub(cursor),
            orphan_tuples,
            acknowledged,
            aftermath,
        })
    }

    /// The authority-state acknowledgements of `revoked` once it is recorded (§9.12.3, E30):
    /// accepted, current `authority_state_ack` Claims whose applied basis position is at or after
    /// the ending record, the latest per PEP. Empty before the revocation is recorded. An ack
    /// changes no decision (INV-21); it only feeds this view.
    async fn acknowledged(&self, revoked: Revoked) -> Result<Vec<Acknowledged>, CoreError> {
        use access_kernel::claim::body::{self as claim_body, Body, Class};
        use access_kernel::model::EqValue;
        let class = Class::AuthorityStateAck.name();
        let mut prefix = claim::member_prefix(&class, &Id([0; 16]));
        prefix.truncate(prefix.len().saturating_sub(17));
        let (ended, acks) = settle(&self.reader, |snap| {
            let ended = match revoked {
                Revoked::Grant(g) => read::<GrantState>(snap, kind::GRANT, &g)
                    .and_then(|s| s.ended)
                    .map(|e| e.at),
                Revoked::Instance(i) => read::<meta::InstanceState>(snap, kind::INSTANCE, &i)
                    .and_then(|s| s.ended)
                    .map(|e| e.at),
            };
            let acks: Vec<access_kernel::claim::Statement> = snap
                .scan(&prefix)
                .into_iter()
                .filter_map(|(_, v)| Id::from_value(&v).ok())
                .filter_map(|id| {
                    snap.get(&meta::key(kind::CLAIM, &id))
                        .and_then(|v| ClaimState::from_value(&v).ok())
                })
                .filter(|s| s.ended.is_none())
                .map(|s| s.statement)
                .collect();
            (ended, acks)
        })
        .await?;
        let Some(ended) = ended else {
            return Ok(Vec::new());
        };
        let mut out: Vec<Acknowledged> = Vec::new();
        for s in acks {
            let Some(EqValue::Bytes(d)) = &s.value else {
                continue;
            };
            let Ok(d) = <[u8; 32]>::try_from(d.as_slice()) else {
                continue;
            };
            let Some(bytes) = self.reader.proof(&d).await? else {
                continue;
            };
            let Ok(Some(Body::AuthorityStateAck(a))) = claim_body::check(&s, Some(&bytes)) else {
                continue;
            };
            if a.basis < ended {
                continue;
            }
            match out.iter_mut().find(|o| o.pep == a.pep) {
                Some(o) if o.applied_at >= a.applied_at => {}
                Some(o) => {
                    o.applied_at = a.applied_at;
                    o.basis = a.basis;
                }
                None => out.push(Acknowledged {
                    pep: a.pep,
                    applied_at: a.applied_at,
                    basis: a.basis,
                }),
            }
        }
        out.sort();
        Ok(out)
    }

    /// What `compromised` may have touched inside `window` (SEC15, RR-13, §16.5.1): the
    /// Exercises its Instance decided there, the Grants, contributions and projections the
    /// allowed ones changed, and the issuer's Claims recorded there. A derived list; nothing is
    /// written.
    ///
    /// # Errors
    /// The reader's errors; [`CoreError::Unavailable`] when positions cannot be read.
    pub async fn compromise_impact(
        &self,
        compromised: Compromised,
        window: Window,
    ) -> Result<CompromiseImpact, CoreError> {
        let instance = match compromised {
            Compromised::Instance(i) => Some(i),
            Compromised::Issuer(_) => None,
            Compromised::Key(kid) => {
                settle(&self.reader, |snap| {
                    snap.get(&meta::key_index(&kid))
                        .and_then(|v| Id::from_value(&v).ok())
                })
                .await?
            }
        };
        let mut out = CompromiseImpact {
            compromised,
            window,
            instance,
            exercises: Vec::new(),
            grants: Vec::new(),
            contributions: Vec::new(),
            projections: Vec::new(),
            claims: Vec::new(),
            capped: false,
        };
        let first = match window.from.checked_sub(1) {
            None => 1,
            Some(before) => self
                .reader
                .position_at(before)
                .await?
                .map_or(1, |p| p.saturating_add(1)),
        };
        let Some(last) = self.reader.position_at(window.until).await? else {
            return Ok(out);
        };
        let last = if last.saturating_sub(first) >= MAX_RECORDS {
            out.capped = true;
            first.saturating_add(MAX_RECORDS).saturating_sub(1)
        } else {
            last
        };
        let issuer = match compromised {
            Compromised::Issuer(p) => Some(p),
            _ => None,
        };
        let mut nonces: BTreeSet<Vec<u8>> = BTreeSet::new();
        let mut from = first.max(1);
        while from <= last {
            let to = from.saturating_add(LOG_PAGE).saturating_sub(1).min(last);
            for bytes in self.reader.log(from, to).await? {
                let r = RecordEnvelope::from_bytes(&bytes)
                    .map_err(|_| CoreError::Protocol("record"))?;
                scan_record(&r, instance, issuer, &mut nonces, &mut out);
            }
            from = to.saturating_add(1);
        }
        for list in [&mut out.grants, &mut out.contributions, &mut out.claims] {
            list.sort();
            list.dedup();
        }
        out.projections.sort();
        out.projections.dedup();
        Ok(out)
    }
}

/// Folds one record into a compromise answer.
fn scan_record(
    r: &RecordEnvelope,
    instance: Option<Id>,
    issuer: Option<Id>,
    nonces: &mut BTreeSet<Vec<u8>>,
    out: &mut CompromiseImpact,
) {
    match r.header.kind {
        RecordKind::Opening => {
            if let (Some(i), Some(Value::Bytes(nonce))) = (instance, field(r, "nonce"))
                && field(r, "actor") == Some(&i.to_value())
            {
                nonces.insert(nonce.clone());
            }
        }
        RecordKind::Decision => {
            let Some(Value::Bytes(nonce)) = field(r, "nonce") else {
                return;
            };
            if !nonces.contains(nonce) {
                return;
            }
            let outcome = match field(r, "outcome").and_then(|o| o.get("outcome")) {
                Some(Value::Text(t)) => t.clone(),
                _ => String::from("unknown"),
            };
            let intent = field(r, "intent")
                .and_then(Digest::from_value)
                .unwrap_or(Digest([0; 32]));
            out.exercises.push(WindowExercise {
                pos: r.header.pos,
                intent,
                outcome,
            });
            let Some(Value::Array(effects)) = field(r, "effects") else {
                return;
            };
            for e in effects {
                let Value::Array(parts) = e else { continue };
                let Some(Value::Bytes(key)) = parts.first() else {
                    continue;
                };
                match effect_kind(key) {
                    Some((k, rest)) if k == kind::GRANT => {
                        out.grants.extend(Id::from_value(&rest).ok());
                    }
                    Some((k, rest)) if k == kind::CONTRIBUTION => {
                        out.contributions.extend(Id::from_value(&rest).ok());
                    }
                    Some((k, rest)) if k == kind::PROJECTION => {
                        out.projections.extend(Digest::from_value(&rest));
                    }
                    _ => {}
                }
            }
        }
        RecordKind::Claim => {
            if issuer.is_some_and(|p| field(r, "issuer") == Some(&p.to_value()))
                && let Some(id) = field(r, "id").and_then(|v| Id::from_value(v).ok())
            {
                out.claims.push(id);
            }
        }
        RecordKind::Genesis => {}
    }
}

#[cfg(test)]
mod tests;
