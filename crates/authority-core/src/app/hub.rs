//! The viewer's own slice of a domain for the Authority hub (§8.5 S2, S6, §8.17.7.1, §8.17.12,
//! X5, X6): the inventory grouped by agency and provenance and the uses of authority; the
//! changes are the management `changes` kind (IA-2). Each answer is
//! a derived read of the domain's own state and log: never recorded, never a credential (C30),
//! and only ever about the reading Party (XI-9, XI-22).

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::claim::body::{BindingKind, Class};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::meta::{
    self, Actor, AnchorState, ExerciseBasis, GrantBasis, GrantState, InstanceState, Root, kind,
};
use access_kernel::model::{ActionRef, BudgetTerm, Id, ResourceSelector, SubjectSelector, Window};
use access_kernel::record::{RecordEnvelope, RecordKind};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{Snapshot, read};
use crate::ports::{Binding, Reader, Salts};
use crate::query::{Found, Hit, PAGE};

/// Most log records one activity or changes page walks back (PD).
pub const LOG_WINDOW: u64 = 2_000;

/// Log records read per round trip.
const LOG_PAGE: u64 = 500;

/// The hub group a Grant shows in (§8.17.7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Group {
    /// Its agency names the viewer: someone may act for the viewer.
    ActingForYou,
    /// It derives from the viewer's holding or root and its agency does not name the viewer.
    SharedFromYou,
    /// The viewer holds it.
    YourAuthority,
}

impl Group {
    /// The wire word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::ActingForYou => "acting_for_you",
            Self::SharedFromYou => "shared_from_you",
            Self::YourAuthority => "your_authority",
        }
    }
}

/// Who holds a Grant, as far as the viewer may see.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Holder {
    /// A named Party.
    Party(Id),
    /// Everyone.
    Public,
    /// The members of the conjuncts' claim classes (rule-shaped, §8.17.5.7).
    Group(Vec<String>),
    /// A foreign selector the domain does not resolve.
    Foreign,
}

/// Where a Grant derives from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Source {
    /// An Anchor's root.
    Anchor(Id),
    /// A holding: the parent Grant and its holder.
    Holding {
        /// The parent Grant.
        grant: Id,
        /// Its holder.
        holder: Id,
    },
}

/// One Grant row of the inventory.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Holding {
    /// The Grant.
    pub grant: Id,
    /// The groups it shows in; never empty.
    pub groups: Vec<Group>,
    /// Its holder.
    pub holder: Holder,
    /// Where it derives from.
    pub source: Source,
    /// Its agency: the capacities it may be exercised in (XI-10).
    pub capacities: Vec<Capacity>,
    /// The actions it names exactly.
    pub actions: Vec<ActionRef>,
    /// The resources it covers.
    pub resource: ResourceSelector,
    /// Its validity window.
    pub validity: Window,
    /// Its budget terms: the authority limits (XI-14).
    pub budget: Vec<BudgetTerm>,
    /// How many while-conditions it carries.
    pub conditions: usize,
    /// The role it pins, as `(name, version)`.
    pub named: Option<(String, u64)>,
    /// Issuing position.
    pub since: u64,
    /// Revision, 0 at issue.
    pub revision: u64,
    /// Whether the viewer is a current member of a rule-shaped holder group; `None` when the
    /// holder is not a group (XI-15: a lapsed membership is "needs refresh", never "removed").
    pub member: Option<bool>,
}

/// An Anchor the viewer roots.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rooted {
    /// The Anchor.
    pub anchor: Id,
    /// Whether the viewer is its sole root (§13.8: a sole root confirms with a hardware key and
    /// waits out the delay).
    pub sole: bool,
    /// How many roots must act together.
    pub quorum: u64,
    /// Creating position.
    pub since: u64,
}

/// What a use rested on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Basis {
    /// An Anchor's root.
    Anchor(Id),
    /// A Grant, held or public.
    Grant(Id),
}

impl From<ExerciseBasis> for Basis {
    fn from(b: ExerciseBasis) -> Self {
        match b {
            ExerciseBasis::Anchor(a) => Self::Anchor(a),
            ExerciseBasis::Holding(h) => Self::Grant(h.grant),
            ExerciseBasis::Public(g) => Self::Grant(g),
        }
    }
}

/// One allowed use of authority by or for the viewer (S6): DENY and `REQUIRE_ACTION` are not
/// uses (§8.5, §8.17.12).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Use {
    /// The decision record's position.
    pub pos: u64,
    /// Its trusted time.
    pub at: Option<u64>,
    /// The intent digest.
    pub intent: Digest,
    /// The basis it rested on.
    pub basis: Basis,
    /// The capacity it was exercised in.
    pub capacity: Capacity,
    /// The acting Instance.
    pub instance: Id,
    /// Whether the viewer acted, rather than someone acting for the viewer.
    pub by_viewer: bool,
}

/// One hub entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Entry {
    /// A Grant row.
    Holding(Box<Holding>),
    /// An Anchor the viewer roots.
    Rooted(Rooted),
    /// A use.
    Use(Use),
}

/// The Claim classes that are regime key-events (SI-13, U26).
#[must_use]
pub fn key_event(class: &str) -> bool {
    matches!(
        Class::parse(class),
        Some(
            Class::PartyKeyState
                | Class::AuthenticatorBinding
                | Class::PartyRecovered
                | Class::IdentityBinding(BindingKind::Person)
        )
    )
}

/// A log position carried in a page token.
#[must_use]
pub fn position_token(pos: u64) -> Id {
    let mut out = [0; 16];
    for (o, b) in out.iter_mut().skip(8).zip(pos.to_be_bytes()) {
        *o = b;
    }
    Id(out)
}

/// The log position a page token carries.
#[must_use]
pub fn token_position(id: &Id) -> u64 {
    id.0.iter()
        .skip(8)
        .fold(0u64, |acc, b| (acc << 8) | u64::from(*b))
}

fn prefix_of(k: &str) -> Vec<u8> {
    let mut p = meta::key(k, &Id([0; 16]));
    p.truncate(p.len().saturating_sub(16));
    p
}

fn id_of_key(key: &[u8]) -> Option<Id> {
    match dcbor::decode(key, Limits::CEILING).ok()? {
        Value::Array(items) => Id::from_value(items.get(1)?).ok(),
        _ => None,
    }
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

fn roots(root: &Root, party: &Id) -> Option<(bool, u64)> {
    match root {
        Root::Sole(p) => (p == party).then_some((true, 1)),
        Root::Joint { parties, k } => parties.contains(party).then_some((false, *k)),
    }
}

/// Whether Grant `g` and every Grant above it are in force.
fn live(view: &Snapshot, g: &Id) -> Option<GrantState> {
    let state = read::<GrantState>(view, kind::GRANT, g)?;
    let mut at = state.clone();
    for _ in 0..meta::MAX_LINEAGE {
        if at.ended.is_some() {
            return None;
        }
        match at.content.basis {
            GrantBasis::Anchor(_) => return Some(state),
            GrantBasis::Holding(h) => at = read::<GrantState>(view, kind::GRANT, &h.grant)?,
        }
    }
    None
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// One page of the viewer's inventory after Grant `after` (§8.17.7.1): every live Grant held
    /// by the viewer, naming the viewer in its agency, or derived from the viewer's holding or
    /// root, each in at least one group (the completeness rule, XI-10); the Anchors the viewer
    /// roots on the first page.
    ///
    /// # Errors
    /// The reader's errors.
    pub(crate) async fn inventory(
        &self,
        actor: &Actor,
        after: Option<Id>,
        now: u64,
    ) -> Result<Found, CoreError> {
        let viewer = actor.party;
        let mut hits = Vec::new();
        if after.is_none() {
            for (key, value, _) in self.scan(&prefix_of(kind::ANCHOR)).await? {
                let (Some(anchor), Some(v)) = (id_of_key(&key), value) else {
                    continue;
                };
                let Ok(state) = AnchorState::from_value(&v) else {
                    continue;
                };
                if state.ended.is_some() {
                    continue;
                }
                if let Some((sole, quorum)) = roots(&state.root, &viewer) {
                    hits.push(Hit::Entry(Box::new(Entry::Rooted(Rooted {
                        anchor,
                        sole,
                        quorum,
                        since: state.since,
                    }))));
                }
            }
        }
        let mut next = None;
        let mut rows = 0usize;
        for (key, value, _) in self.scan(&prefix_of(kind::GRANT)).await? {
            let (Some(grant), Some(_)) = (id_of_key(&key), value) else {
                continue;
            };
            if after.is_some_and(|a| grant <= a) {
                continue;
            }
            let Some(state) = self.settled(|snap| live(snap, &grant)).await? else {
                continue;
            };
            let Some(row) = self.row(grant, &state, actor, now).await? else {
                continue;
            };
            if rows >= PAGE as usize {
                next = Some(grant);
                break;
            }
            rows = rows.saturating_add(1);
            hits.push(Hit::Entry(Box::new(Entry::Holding(Box::new(row)))));
        }
        Ok(Found {
            hits,
            next,
            audited: None,
        })
    }

    /// The inventory row of live Grant `grant` for `actor`, when it concerns the viewer.
    async fn row(
        &self,
        grant: Id,
        state: &GrantState,
        actor: &Actor,
        now: u64,
    ) -> Result<Option<Holding>, CoreError> {
        let viewer = actor.party;
        let c = &state.content;
        let (holder, member) = match &c.holder {
            SubjectSelector::Party(p) => (Holder::Party(*p), None),
            SubjectSelector::Public => (Holder::Public, None),
            SubjectSelector::Pred(conj) => (
                Holder::Group(conj.iter().map(|t| t.claim_class.clone()).collect()),
                Some(self.holds(&grant, actor, now).await?),
            ),
            SubjectSelector::Foreign { .. } => (Holder::Foreign, None),
        };
        let for_viewer = c.agency.contains(&Capacity::For(viewer));
        let from_viewer = match c.basis {
            GrantBasis::Holding(h) => h.holder == viewer,
            GrantBasis::Anchor(a) => {
                self.settled(|snap| {
                    read::<AnchorState>(snap, kind::ANCHOR, &a)
                        .is_some_and(|s| s.ended.is_none() && roots(&s.root, &viewer).is_some())
                })
                .await?
            }
        };
        let mut groups = Vec::new();
        if holder == Holder::Party(viewer) || member == Some(true) {
            groups.push(Group::YourAuthority);
        }
        if for_viewer && holder != Holder::Party(viewer) {
            groups.push(Group::ActingForYou);
        }
        // §8.17.7.1, X6
        if from_viewer && !for_viewer && holder != Holder::Party(viewer) {
            groups.push(Group::SharedFromYou);
        }
        if groups.is_empty() {
            return Ok(None);
        }
        let set = &c.authority;
        Ok(Some(Holding {
            grant,
            groups,
            holder,
            source: match c.basis {
                GrantBasis::Anchor(a) => Source::Anchor(a),
                GrantBasis::Holding(h) => Source::Holding {
                    grant: h.grant,
                    holder: h.holder,
                },
            },
            capacities: c.agency.iter().copied().collect(),
            actions: set.authority.actions.exact.iter().cloned().collect(),
            resource: set.authority.resource.clone(),
            validity: set.constraints.validity,
            budget: set.constraints.budget.iter().cloned().collect(),
            conditions: set.constraints.conditions.len(),
            named: c.named.as_ref().map(|(n, v, _)| (n.clone(), *v)),
            since: state.since,
            revision: state.revision,
            member,
        }))
    }

    /// The window of records one log page walks: up to [`LOG_WINDOW`] records ending before
    /// `before` (exclusive) or at the head.
    async fn window(&self, before: Option<Id>, now: u64) -> Result<Option<(u64, u64)>, CoreError> {
        let last = match before {
            Some(t) => token_position(&t).saturating_sub(1),
            None => self.reader.position_at(now).await?.unwrap_or(0),
        };
        if last == 0 {
            return Ok(None);
        }
        let first = last.saturating_sub(LOG_WINDOW.saturating_sub(1)).max(1);
        Ok(Some((first, last)))
    }

    async fn records(&self, first: u64, last: u64) -> Result<Vec<RecordEnvelope>, CoreError> {
        let mut out = Vec::new();
        let mut from = first;
        while from <= last {
            let to = from.saturating_add(LOG_PAGE).saturating_sub(1).min(last);
            for bytes in self.reader.log(from, to).await? {
                out.push(
                    RecordEnvelope::from_bytes(&bytes)
                        .map_err(|_| CoreError::Protocol("record"))?,
                );
            }
            from = to.saturating_add(1);
        }
        Ok(out)
    }

    /// The Party of Instance `instance`.
    async fn party_of(&self, instance: &Id) -> Result<Option<Id>, CoreError> {
        self.settled(|snap| read::<InstanceState>(snap, kind::INSTANCE, instance).map(|s| s.party))
            .await
    }

    /// One page of the viewer's activity (S6), newest first, walking back from `before`: the
    /// allowed decisions the viewer's Instances made, or that were made for the viewer.
    ///
    /// # Errors
    /// The reader's errors; [`CoreError::Protocol`] for a log record that does not decode.
    pub(crate) async fn activity(
        &self,
        actor: &Actor,
        before: Option<Id>,
        now: u64,
    ) -> Result<Found, CoreError> {
        let Some((first, last)) = self.window(before, now).await? else {
            return Ok(Found::default());
        };
        let viewer = actor.party;
        let mut opened: BTreeMap<Vec<u8>, (Id, Basis, Capacity)> = BTreeMap::new();
        let mut parties: BTreeMap<Id, Option<Id>> = BTreeMap::new();
        let mut uses = Vec::new();
        for r in self.records(first, last).await? {
            let Some(Value::Bytes(nonce)) = field(&r, "nonce") else {
                continue;
            };
            match r.header.kind {
                RecordKind::Opening => {
                    let (Some(instance), Some(basis), Some(capacity)) = (
                        field(&r, "actor").and_then(|v| Id::from_value(v).ok()),
                        field(&r, "basis").and_then(|v| meta::exercise_basis(v).ok()),
                        field(&r, "capacity").and_then(|v| meta::capacity(v).ok()),
                    ) else {
                        continue;
                    };
                    opened.insert(nonce.clone(), (instance, Basis::from(basis), capacity));
                }
                RecordKind::Decision => {
                    // §8.5, §8.17.12
                    let allowed = matches!(
                        field(&r, "outcome").and_then(|o| o.get("outcome")),
                        Some(Value::Text(t)) if t == "allow"
                    );
                    let Some((instance, basis, capacity)) = opened.get(nonce).copied() else {
                        continue;
                    };
                    if !allowed {
                        continue;
                    }
                    let party = if let Some(p) = parties.get(&instance) {
                        *p
                    } else {
                        let p = self.party_of(&instance).await?;
                        parties.insert(instance, p);
                        p
                    };
                    let by_viewer = party == Some(viewer);
                    if !by_viewer && capacity != Capacity::For(viewer) {
                        continue;
                    }
                    uses.push(Use {
                        pos: r.header.pos,
                        at: None,
                        intent: field(&r, "intent")
                            .and_then(Digest::from_value)
                            .unwrap_or(Digest([0; 32])),
                        basis,
                        capacity,
                        instance,
                        by_viewer,
                    });
                }
                _ => {}
            }
        }
        uses.reverse();
        uses.truncate(PAGE as usize);
        let mut hits = Vec::with_capacity(uses.len());
        for mut u in uses {
            u.at = self.reader.recorded_at(u.pos).await?;
            hits.push(Hit::Entry(Box::new(Entry::Use(u))));
        }
        Ok(Found {
            hits,
            next: (first > 1).then(|| position_token(first)),
            audited: None,
        })
    }
}

/// The set of hub kinds this module answers.
pub const KINDS: [&str; 2] = ["inventory", "activity"];

/// Distinct groups of a row, for tests and encoders.
#[must_use]
pub fn groups_of(rows: &[Holding]) -> BTreeSet<Group> {
    rows.iter().flat_map(|r| r.groups.iter().copied()).collect()
}
