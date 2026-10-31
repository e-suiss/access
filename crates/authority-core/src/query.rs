//! Search (CMP-11, OP-141 m.22 (b), (c), (g), (j)): who can act on a resource, and what a Party
//! may reach. The derived index only names candidates; each one is checked against the leader's
//! state. Never recorded, never a credential (C30).

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, resource_le};
use access_kernel::combinator::HopStatus;
use access_kernel::intent::intent_digest;
use access_kernel::meta::{self, Actor, AnchorState, GrantBasis, GrantState, View, kind};
use access_kernel::model::{ActionRef, Id, ResourceRef, ResourceSelector, SubjectSelector};

use crate::CoreError;
use crate::app::{Authority, Incoming};
use crate::domain::{Snapshot, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};

/// Results per page: the policy default and ceiling below the EA ceiling of 1000 (§13.7.4).
pub const PAGE: u32 = 100;

/// Namespace of the search intent's resource (OP-141 m.22 (j)).
pub const SEARCH_NAMESPACE: &str = "access.search";

/// What is searched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// Who can do `action` on `resource`.
    Subject {
        /// Action.
        action: ActionRef,
        /// Resource.
        resource: ResourceRef,
    },
    /// Which resources `party` reaches with `action`.
    Resource {
        /// Party searched.
        party: Id,
        /// Action.
        action: ActionRef,
    },
    /// Which actions `party` may take on `resource`.
    Action {
        /// Party searched.
        party: Id,
        /// Resource.
        resource: ResourceRef,
    },
}

impl Query {
    /// The path segment of the search intent's resource.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Subject { .. } => "subject",
            Self::Resource { .. } => "resource",
            Self::Action { .. } => "action",
        }
    }
}

/// One result.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hit {
    /// A Party.
    Party(Id),
    /// Everyone.
    Public,
    /// The members of a group: the conjuncts' claim classes.
    Group(Vec<String>),
    /// A reachable resource selector.
    Resource(ResourceSelector),
    /// An action.
    Action(ActionRef),
}

/// One page of results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Results of this page, without repeats.
    pub hits: Vec<Hit>,
    /// The last candidate looked at, when more may follow.
    pub next: Option<Id>,
}

/// The Anchor at the top of a Grant's lineage.
fn top_anchor(view: &dyn View, grant: &Id) -> Option<Id> {
    let mut at = *grant;
    for _ in 0..meta::MAX_LINEAGE {
        let g: GrantState = read(view, kind::GRANT, &at)?;
        match g.content.basis {
            GrantBasis::Anchor(a) => return Some(a),
            GrantBasis::Holding(h) => at = h.grant,
        }
    }
    None
}

/// Whether every hop of the lineage is live.
fn live(view: &dyn View, grant: &Id) -> Option<GrantState> {
    let (hops, _) = lineage_hops(view, grant)?;
    if hops.iter().all(|h| h.status == HopStatus::Active) {
        read(view, kind::GRANT, grant)
    } else {
        None
    }
}

fn holder_hit(sel: &SubjectSelector) -> Option<Hit> {
    match sel {
        SubjectSelector::Party(p) => Some(Hit::Party(*p)),
        SubjectSelector::Public => Some(Hit::Public),
        SubjectSelector::Pred(c) => Some(Hit::Group(
            c.iter().map(|c| c.claim_class.clone()).collect(),
        )),
        SubjectSelector::Foreign { .. } => None,
    }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Runs `f` over a snapshot, fetching what it asks for until it asks for nothing more.
    async fn settled<T>(&self, f: impl Fn(&Snapshot) -> T) -> Result<T, CoreError> {
        let mut snap = Snapshot::default();
        for _ in 0..crate::app::MAX_PASSES {
            snap.restart();
            let out = f(&snap);
            let missing = snap.missing();
            if missing.is_empty() {
                return Ok(out);
            }
            snap.fill(self.reader.fetch(&missing).await?);
        }
        Err(CoreError::Passes)
    }

    /// The reader of a search: the actor of a `check` AIS over the search intent, `None` when
    /// anonymous (OP-141 m.22 (c), (j)).
    async fn searcher(
        &self,
        inc: &Incoming,
        query: &Query,
        now: u64,
    ) -> Result<Option<Actor>, CoreError> {
        let req = &inc.request;
        let resource = req
            .intent
            .resources
            .first()
            .ok_or(CoreError::Protocol("intent"))?;
        if req.intent.action.namespace != meta::NAMESPACE
            || req.intent.action.name != "search"
            || resource.namespace != SEARCH_NAMESPACE
            || resource.path != [query.kind()]
            || req.mode != access_kernel::combinator::Mode::Check
        {
            return Err(CoreError::Protocol("search"));
        }
        let digest = intent_digest(&req.intent).map_err(|_| CoreError::Protocol("intent"))?;
        self.actor(inc, &digest, now).await
    }

    /// One page of `query` after `after`, as far as the reader may see (OP-141 m.22 (j)).
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for a request that is not a search; [`CoreError::Ais`].
    pub async fn search(
        &self,
        inc: &Incoming,
        query: &Query,
        after: Option<Id>,
        now: u64,
    ) -> Result<Found, CoreError> {
        let Some(actor) = self.searcher(inc, query, now).await? else {
            return Ok(Found::default());
        };
        let candidates = match query {
            Query::Subject { resource, .. } => {
                self.reader
                    .grants_in(&resource.namespace, after, PAGE)
                    .await?
            }
            Query::Resource { party, .. } | Query::Action { party, .. } => {
                if *party != actor.party {
                    return Ok(Found::default());
                }
                self.reader.grants_for(party, after, PAGE).await?
            }
        };
        let next = (candidates.len() == PAGE as usize)
            .then(|| candidates.last().copied())
            .flatten();
        let catalog = Catalog::default();
        let mut hits = BTreeSet::new();
        for g in &candidates {
            let hit = self
                .settled(|snap| Self::hit(snap, g, query, &actor, &catalog))
                .await?;
            if let Some(hit) = hit
                && (matches!(query, Query::Subject { .. }) || self.holds(g, &actor, now).await?)
            {
                hits.extend(hit);
            }
        }
        Ok(Found {
            hits: hits.into_iter().collect(),
            next,
        })
    }

    /// Whether `actor`'s Party holds Grant `g` now: by name, as `Public`, or as a group member.
    async fn holds(&self, g: &Id, actor: &Actor, now: u64) -> Result<bool, CoreError> {
        let holder = self
            .settled(|snap| read::<GrantState>(snap, kind::GRANT, g).map(|s| s.content.holder))
            .await?;
        Ok(match holder {
            Some(SubjectSelector::Party(p)) => p == actor.party,
            Some(SubjectSelector::Public) => true,
            Some(SubjectSelector::Pred(c)) => {
                let mut snap = Snapshot::default();
                self.episode(&mut snap, &c, &actor.party, now)
                    .await?
                    .is_some()
            }
            _ => false,
        })
    }

    /// What Grant `g` contributes to `query`, if it is live and covers it.
    fn hit(
        view: &Snapshot,
        g: &Id,
        query: &Query,
        actor: &Actor,
        catalog: &Catalog,
    ) -> Option<Vec<Hit>> {
        let grant = live(view, g)?;
        let set = &grant.content.authority.authority;
        let actions = catalog.covered(&set.actions);
        let on = |r: &ResourceRef| resource_le(&ResourceSelector::Exact(r.clone()), &set.resource);
        match query {
            Query::Subject { action, resource } => {
                // OP-141 m.22 (j): only within an Anchor the reader roots
                let anchor: AnchorState = read(view, kind::ANCHOR, &top_anchor(view, g)?)?;
                meta::root_requirements(&anchor, actor)?;
                (actions.contains(action) && on(resource))
                    .then(|| holder_hit(&grant.content.holder).into_iter().collect())
            }
            Query::Resource { action, .. } => actions
                .contains(action)
                .then(|| vec![Hit::Resource(set.resource.clone())]),
            Query::Action { resource, .. } => {
                on(resource).then(|| actions.iter().cloned().map(Hit::Action).collect())
            }
        }
    }
}

/// The page token's body: the last candidate.
#[must_use]
pub fn page_body(next: &Id) -> Vec<u8> {
    next.0.to_vec()
}

/// The last candidate a page token names.
#[must_use]
pub fn page_after(body: &[u8]) -> Option<Id> {
    <[u8; 16]>::try_from(body).ok().map(Id)
}
