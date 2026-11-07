//! Search (CMP-11, OP-141 m.22 (b), (c), (g), (j)): who can act on a resource, and what a Party
//! may reach. The derived index only names candidates; each one is checked against the leader's
//! state. Never recorded, never a credential (C30).

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, resource_le};
use access_kernel::combinator::HopStatus;
use access_kernel::intent::intent_digest;
use access_kernel::meta::{self, Actor, ExerciseBasis, GrantState, View, kind};
use access_kernel::model::{ActionRef, Id, ResourceRef, ResourceSelector, SubjectSelector, Window};

use crate::CoreError;
use crate::app::impact::{
    CompromiseImpact, Compromised, PolicyChange, RevocationImpact, Revoked, RoleChange,
};
use crate::app::publishing::Offer;
use crate::app::{Authority, Incoming};
use crate::domain::{Snapshot, accepted_catalog, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};
use crate::rate::Class;

/// Results per page: the policy default and ceiling below the EA ceiling of 1000 (§13.7.4).
pub const PAGE: u32 = 100;

/// Namespace of the search intent's resource; its action is `access:read` (OP-141 m.22 (j),
/// m.39 (b)).
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
    /// The published versions of `namespace` and where each stands here (§8.17.10.2).
    SchemaPublications {
        /// Namespace.
        namespace: String,
    },
    /// What a change would do (X20, TN-121, §5.8).
    ChangeImpact(Change),
    /// What revoking something at `at` leaves exposed (§5.4, §16.5.1).
    RevocationImpact {
        /// What is revoked.
        revoked: Revoked,
        /// When; now when absent.
        at: Option<u64>,
    },
    /// What a compromise may have touched in a window (SEC15, RR-13).
    CompromiseImpact {
        /// What is compromised.
        compromised: Compromised,
        /// The window.
        window: Window,
    },
}

/// The change a `change-impact` search previews.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// Moving the Grants pinned to role `name` v`from` to v`to`.
    Role {
        /// Role name.
        name: String,
        /// Version pinned now.
        from: u64,
        /// Version to move to.
        to: u64,
    },
    /// Setting a restriction policy: the candidate `policy_set` content as dCBOR.
    Policy {
        /// The policy replaced, `None` for a new one.
        policy: Option<Id>,
        /// The candidate content's dCBOR bytes.
        candidate: Vec<u8>,
    },
}

/// A developer-surface report (§8.17.10, §5.4, §16.5.1): advisory and never recorded.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Report {
    /// One published version as this domain sees it.
    Publication(Offer),
    /// A role change preview.
    RoleChange(RoleChange),
    /// A `policy.set` preview.
    PolicyChange(PolicyChange),
    /// A revocation impact.
    Revocation(RevocationImpact),
    /// A compromise impact.
    Compromise(CompromiseImpact),
}

impl Query {
    /// The path segment of the search intent's resource.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Subject { .. } => "subject",
            Self::Resource { .. } => "resource",
            Self::Action { .. } => "action",
            Self::SchemaPublications { .. } => "schema-publications",
            Self::ChangeImpact(_) => "change-impact",
            Self::RevocationImpact { .. } => "revocation-impact",
            Self::CompromiseImpact { .. } => "compromise-impact",
        }
    }

    /// Whether it is a developer-surface report rather than a graph search.
    #[must_use]
    pub const fn is_report(&self) -> bool {
        matches!(
            self,
            Self::SchemaPublications { .. }
                | Self::ChangeImpact(_)
                | Self::RevocationImpact { .. }
                | Self::CompromiseImpact { .. }
        )
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
    /// A developer-surface report.
    Report(Box<Report>),
}

/// One page of results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Results of this page, without repeats.
    pub hits: Vec<Hit>,
    /// The last candidate looked at, when more may follow.
    pub next: Option<Id>,
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
    pub(crate) async fn settled<T>(&self, f: impl Fn(&Snapshot) -> T) -> Result<T, CoreError> {
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
            || req.intent.action.name != "read"
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
        &mut self,
        inc: &Incoming,
        query: &Query,
        after: Option<Id>,
        now: u64,
    ) -> Result<Found, CoreError> {
        let actor = self.searcher(inc, query, now).await?;
        // §13.7.4, OP-141 m.23
        if !self
            .limiter
            .admit(Class::Search, crate::app::who(inc, actor), now)
        {
            return Err(CoreError::Limited);
        }
        let Some(actor) = actor else {
            return Ok(Found::default());
        };
        if query.is_report() {
            return self.report(&actor, query, now).await;
        }
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
            _ => return Ok(Found::default()),
        };
        let next = (candidates.len() == PAGE as usize)
            .then(|| candidates.last().copied())
            .flatten();
        // OP-141 m.39 (c)
        let namespace = match query {
            Query::Subject { action, .. } | Query::Resource { action, .. } => &action.namespace,
            Query::Action { resource, .. } => &resource.namespace,
            _ => return Ok(Found::default()),
        };
        let catalog = self
            .settled(|snap| accepted_catalog(snap, namespace, now, &Catalog::default()))
            .await?;
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
                // OP-141 m.22 (j), m.41 (c): only Grants the reader views
                if !crate::domain::views(view, &ExerciseBasis::Public(*g), &actor.party) {
                    return None;
                }
                (actions.contains(action) && on(resource))
                    .then(|| holder_hit(&grant.content.holder).into_iter().collect())
            }
            Query::Resource { action, .. } => actions
                .contains(action)
                .then(|| vec![Hit::Resource(set.resource.clone())]),
            Query::Action { resource, .. } => {
                on(resource).then(|| actions.iter().cloned().map(Hit::Action).collect())
            }
            _ => None,
        }
    }

    /// A developer-surface report for `actor` (§8.17.10, §5.4, §16.5.1, SEC15): only the
    /// domain's auditors (its meta-anchor root, or a holder of a live Grant naming
    /// `access:audit_export`) get one; anyone else gets nothing, as for a search they may not
    /// see. One page, never recorded.
    async fn report(&self, actor: &Actor, query: &Query, now: u64) -> Result<Found, CoreError> {
        if !self.audits(&actor.party).await? {
            return Ok(Found::default());
        }
        let reports: Vec<Report> = match query {
            Query::SchemaPublications { namespace } => self
                .publication_offers(namespace, now)
                .await?
                .into_iter()
                .map(Report::Publication)
                .collect(),
            Query::ChangeImpact(Change::Role { name, from, to }) => self
                .change_role(name, *from, *to, now)
                .await?
                .map(Report::RoleChange)
                .into_iter()
                .collect(),
            Query::ChangeImpact(Change::Policy { policy, candidate }) => {
                let content =
                    suiss_crypto::dcbor::decode(candidate, suiss_crypto::dcbor::Limits::CEILING)
                        .map_err(|_| CoreError::Protocol("candidate"))?;
                vec![Report::PolicyChange(
                    self.change_policy(*policy, &content, &crate::ports::NoAnalysis)
                        .await?,
                )]
            }
            Query::RevocationImpact { revoked, at } => vec![Report::Revocation(
                self.revocation_impact(*revoked, at.unwrap_or(now)).await?,
            )],
            Query::CompromiseImpact {
                compromised,
                window,
            } => vec![Report::Compromise(
                self.compromise_impact(*compromised, *window).await?,
            )],
            _ => Vec::new(),
        };
        Ok(Found {
            hits: reports
                .into_iter()
                .map(|r| Hit::Report(Box::new(r)))
                .collect(),
            next: None,
        })
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
