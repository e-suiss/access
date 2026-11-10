//! Search (CMP-11, OP-141 m.22 (b), (c), (g), (j)): who can act on a resource, and what a Party
//! may reach. The derived index only names candidates; each one is checked against the leader's
//! state. Never recorded, never a credential (C30).

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, resource_le};
use access_kernel::combinator::HopStatus;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, intent_digest};
use access_kernel::meta::{self, Actor, ExerciseBasis, GrantState, kind};
use access_kernel::model::{ActionRef, Id, ResourceRef, ResourceSelector, SubjectSelector, Window};

use crate::CoreError;
use crate::app::impact::{
    CompromiseImpact, Compromised, PolicyChange, RevocationImpact, Revoked, RoleChange,
};
use crate::app::management::{BulkImpact, Change as Changed, Holding};
use crate::app::publishing::Offer;
use crate::app::roles::{AdminGrant, RoleVersion};
use crate::app::sources::Sources;
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
    /// The domain's Named `AuthoritySet`s (C28).
    Roles,
    /// One role version with its "Not included" block (§8.17.9.2, E11).
    Role {
        /// Name.
        name: String,
        /// Version; the latest when absent.
        version: Option<u64>,
    },
    /// An admin Grant's meta-actions one by one (§8.17.9.2).
    AdminGrant {
        /// The Grant.
        grant: Id,
    },
    /// The reader's own holdings, each a usable basis (IA-5).
    Holdings,
    /// The Changes feed before a position (IA-2).
    Changes {
        /// Only changes recorded before it; the newest when absent.
        before: Option<u64>,
    },
    /// The domain's live Acceptances by use with their blast radius, and its partners
    /// (§8.17.9.3, §5.13).
    Sources,
    /// The preview of a bulk revoke (E17).
    BulkImpact {
        /// The Grants the job revokes.
        revoke: Vec<Id>,
    },
    /// The viewer's inventory (§8.17.7.1, X6): only ever `party`'s own.
    Inventory {
        /// The viewer.
        party: Id,
    },
    /// The viewer's uses of authority (S6).
    Activity {
        /// The viewer.
        party: Id,
    },
    /// An agent Instance's own summary (A-11, L8).
    AgentStatus,
    /// Who may approve a Gate of `gate_class` now: the holders of `approve:<class>`, that is
    /// of `access:contribute` on `access.contribution:[class]` (§7.9.5.3, E41, OP-156 m.3 (t)).
    /// Derived, never recorded, at most [`ELIGIBLE_MAX`] Parties.
    EligibleSet {
        /// The contribution class the Gate needs.
        gate_class: String,
        /// The resource the Gate is on, as the coordinator names it; opaque here.
        resource: String,
        /// The digest the approval binds, as the coordinator names it; opaque here.
        digest: Digest,
    },
    /// L6: what executors reported about one Exercise (OP-154 m.3 (u), EI-10).
    Outcome {
        /// The Exercise.
        exercise: Digest,
        /// The intent the viewer holds; it must be the Exercise's.
        envelope: Box<IntentEnvelope>,
    },
    /// The lifecycle facts declared for one resource and its highest incarnation (OP-156 m.3
    /// (k), INV-32); the domain's auditors only.
    ResourceIncarnation {
        /// The resource's namespace.
        namespace: String,
        /// Its path.
        path: Vec<String>,
    },
    /// The applications discovery connectors reported and the live agent or system Parties
    /// that account for each (AG-43, OP-156 m.4 Q20); the domain's auditors only, advisory.
    Discovery {
        /// Only those no one accounts for.
        unregistered: bool,
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
    /// The domain's roles and their latest versions.
    Roles(Vec<(String, u64)>),
    /// One role version.
    Role(RoleVersion),
    /// An admin Grant's meta-actions.
    AdminGrant(AdminGrant),
    /// One of the reader's holdings.
    Holding(Holding),
    /// One row of the Changes feed.
    Change(Changed),
    /// A bulk revoke preview.
    Bulk(BulkImpact),
    /// The Sources report.
    Sources(Sources),
    /// An agent Instance's own summary (A-11, L8).
    AgentStatus(crate::app::agent_status::AgentStatus),
    /// L6: an Exercise's reported outcome.
    Outcome(Box<crate::app::outcome::Outcome>),
    /// OP-156 m.3 (k): one resource's incarnations.
    Incarnations(crate::app::resources::Incarnations),
    /// AG-43: one discovered application.
    Shadow(crate::app::discovery::Shadow),
}

/// Search kinds declared and not served yet, each owned by its lane: `federation-chain` (Stage 10 P6, each OIDF
/// issuer's chain state and lapse, OP-155 m.3 (j)) and `scim-sync` (Stage 10 P3, inbound and
/// outbound SCIM provisioning results, OP-155 m.3 (g)). A search of one answers
/// `501 not-yet-served` (OP-154 m.4, OP-155 m.4, OP-156 m.4).
pub const RESERVED_KINDS: [&str; 2] = ["federation-chain", "scim-sync"];

/// The most Parties an eligible set names; more are marked truncated (OP-156 m.3 (t)).
pub const ELIGIBLE_MAX: usize = 1000;

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
            Self::Roles => "roles",
            Self::Role { .. } => "role",
            Self::AdminGrant { .. } => "admin-grant",
            Self::Holdings => "holdings",
            Self::Changes { .. } => "changes",
            Self::BulkImpact { .. } => "bulk-impact",
            Self::Sources => "sources",
            Self::Inventory { .. } => "inventory",
            Self::Activity { .. } => "activity",
            Self::AgentStatus => "agent-status",
            Self::Outcome { .. } => "outcome",
            Self::ResourceIncarnation { .. } => "resource-incarnation",
            Self::Discovery { .. } => "discovery",
            Self::EligibleSet { .. } => "eligible-set",
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
                | Self::Roles
                | Self::Role { .. }
                | Self::AdminGrant { .. }
                | Self::Holdings
                | Self::Changes { .. }
                | Self::BulkImpact { .. }
                | Self::Sources
                | Self::ResourceIncarnation { .. }
                | Self::Discovery { .. }
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
    /// An Authority hub entry of the viewer (§8.5 S2, S6).
    Entry(Box<crate::app::hub::Entry>),
}

/// One page of results.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Results of this page, without repeats.
    pub hits: Vec<Hit>,
    /// The last candidate looked at, when more may follow.
    pub next: Option<Id>,
    /// The Instance an audit-depth report was served to, which the stream records (OP-44).
    pub audited: Option<Id>,
}

/// Whether every hop of the lineage is live.
fn live(view: &Snapshot, grant: &Id) -> Option<GrantState> {
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
    /// The domain's accepted action `namespace`/`name` of `major` at `now`, with its pinned
    /// schema digest, as an intent names it (OP-141 m.35 (e), OP-151 m.20 (a)).
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn accepted_action(
        &self,
        namespace: &str,
        name: &str,
        major: u64,
        now: u64,
    ) -> Result<Option<access_kernel::model::ActionRef>, CoreError> {
        self.settled(|snap| crate::domain::accepted_action(snap, namespace, name, major, now))
            .await
    }

    /// Runs `f` over a snapshot, fetching the keys and prefix scans it asks for until it asks
    /// for nothing more.
    pub(crate) async fn settled<T>(&self, f: impl Fn(&Snapshot) -> T) -> Result<T, CoreError> {
        crate::app::publishing::settle(&self.reader, f).await
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
            if let (Query::Changes { .. }, Some(a)) = (query, after) {
                let before = u64::try_from(u128::from_be_bytes(a.0))
                    .map_err(|_| CoreError::Protocol("page"))?;
                let paged = Query::Changes {
                    before: Some(before),
                };
                return self.report(&actor, &paged, now).await;
            }
            return self.report(&actor, query, now).await;
        }
        // XI-9, XI-22
        match query {
            Query::Inventory { party } | Query::Activity { party } if *party != actor.party => {
                return Ok(Found::default());
            }
            Query::Inventory { .. } => return self.inventory(&actor, after, now).await,
            // A-11, E26
            Query::AgentStatus => {
                return Ok(Found {
                    hits: self
                        .agent_status(&actor, now)
                        .await?
                        .map(|s| Hit::Report(Box::new(Report::AgentStatus(s))))
                        .into_iter()
                        .collect(),
                    next: None,
                    audited: None,
                });
            }
            Query::Activity { .. } => return self.activity(&actor, after, now).await,
            Query::Outcome { exercise, envelope } => {
                return self.outcome(actor.party, *exercise, envelope, now).await;
            }
            Query::EligibleSet { gate_class, .. } => {
                return self.eligible_set(inc, &actor, gate_class, now).await;
            }
            _ => {}
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
            audited: None,
        })
    }

    /// The eligible set of a Gate of `class` (§7.9.5.3, E41, OP-156 m.3 (t)): the named holders of
    /// a live Grant covering `access:contribute` on `access.contribution:[class]` now, without
    /// repeats, at most [`ELIGIBLE_MAX`]; `next` is set when more were left out. Only the
    /// domain's auditors and a reader the domain allowed to read this kind (a `check` of the
    /// search intent itself is ALLOW) see one (E26); anyone else gets nothing. Rule-shaped and
    /// public holders are not listed: their members are asked one by one with
    /// `eligibility:check`. Nothing is recorded.
    async fn eligible_set(
        &mut self,
        inc: &Incoming,
        actor: &Actor,
        class: &str,
        now: u64,
    ) -> Result<Found, CoreError> {
        // E26
        let allowed = self.audits(&actor.party, now).await?
            || self.exercise(inc, now).await?.decision.outcome
                == access_kernel::combinator::Outcome::Allow;
        if !allowed {
            return Ok(Found::default());
        }
        let target = ResourceRef {
            namespace: String::from(crate::app::CONTRIBUTION_NAMESPACE),
            path: vec![String::from(class)],
            incarnation: 0,
        };
        let catalog = self
            .settled(|snap| accepted_catalog(snap, meta::NAMESPACE, now, &Catalog::default()))
            .await?;
        let mut parties = BTreeSet::new();
        let mut after = None;
        let mut truncated = false;
        loop {
            let page = self
                .reader
                .grants_in(&target.namespace, after, PAGE)
                .await?;
            for g in &page {
                let holder = self
                    .settled(|snap| eligible_holder(snap, g, &target, &catalog, now))
                    .await?;
                if let Some(p) = holder {
                    if parties.len() == ELIGIBLE_MAX && !parties.contains(&p) {
                        truncated = true;
                        break;
                    }
                    parties.insert(p);
                }
            }
            if truncated || page.len() < PAGE as usize {
                break;
            }
            after = page.last().copied();
        }
        Ok(Found {
            hits: parties.into_iter().map(Hit::Party).collect(),
            next: truncated.then_some(Id([0xff; 16])),
            audited: None,
        })
    }

    /// Whether `actor`'s Party holds Grant `g` now: by name, as `Public`, or as a group member.
    pub(crate) async fn holds(&self, g: &Id, actor: &Actor, now: u64) -> Result<bool, CoreError> {
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
                // OP-141 m.22 (j), m.41 (c)
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

    /// The management reads answered below the auditor line (IA-5, IA-2, OP-152 m.7 (b)): the
    /// reader's own holdings, the Changes feed at the reader's depth and an admin Grant for its
    /// holder; `None` for every other kind.
    async fn viewer_report(
        &self,
        actor: &Actor,
        query: &Query,
        auditor: bool,
        now: u64,
    ) -> Result<Option<Found>, CoreError> {
        match query {
            Query::Holdings => {
                let hits = self
                    .holdings(actor, now)
                    .await?
                    .into_iter()
                    .map(|h| Hit::Report(Box::new(Report::Holding(h))))
                    .collect();
                Ok(Some(Found {
                    hits,
                    next: None,
                    audited: None,
                }))
            }
            Query::Changes { before } => {
                let (rows, next) = self.changes(actor, auditor, *before).await?;
                Ok(Some(Found {
                    hits: rows
                        .into_iter()
                        .map(|c| Hit::Report(Box::new(Report::Change(c))))
                        .collect(),
                    next: next.map(|p| Id(u128::from(p).to_be_bytes())),
                    audited: auditor.then_some(actor.instance),
                }))
            }
            Query::AdminGrant { grant } => {
                let view = self.admin_grant(grant, now).await?;
                let holder = self
                    .settled(|snap| {
                        read::<GrantState>(snap, kind::GRANT, grant).is_some_and(|g| {
                            g.content.holder == SubjectSelector::Party(actor.party)
                        })
                    })
                    .await?;
                Ok(Some(Found {
                    hits: view
                        .filter(|_| auditor || holder)
                        .map(|v| Hit::Report(Box::new(Report::AdminGrant(v))))
                        .into_iter()
                        .collect(),
                    next: None,
                    audited: auditor.then_some(actor.instance),
                }))
            }
            _ => Ok(None),
        }
    }

    /// A developer-surface report for `actor` (§8.17.10, §5.4, §16.5.1, SEC15): only the
    /// domain's auditors (its meta-anchor root, or a holder of a live Grant naming
    /// `access:audit_export`) get one; anyone else gets nothing, as for a search they may not
    /// see. One page, never recorded as a decision; the stream records each one served.
    async fn report(&self, actor: &Actor, query: &Query, now: u64) -> Result<Found, CoreError> {
        let auditor = self.audits(&actor.party, now).await?;
        if let Some(found) = self.viewer_report(actor, query, auditor, now).await? {
            return Ok(found);
        }
        // XI-5, XI-9, §8.17.7.3
        let previews_own = match query {
            Query::RevocationImpact {
                revoked: Revoked::Grant(g),
                ..
            } => {
                self.settled(|snap| {
                    read::<GrantState>(snap, kind::GRANT, g).is_some_and(|s| {
                        let above = match s.content.basis {
                            access_kernel::meta::GrantBasis::Anchor(a) => ExerciseBasis::Anchor(a),
                            access_kernel::meta::GrantBasis::Holding(h) => {
                                ExerciseBasis::Holding(h)
                            }
                        };
                        crate::domain::views(snap, &above, &actor.party)
                    })
                })
                .await?
            }
            _ => false,
        };
        if !auditor && !previews_own {
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
                    self.change_policy(*policy, &content, self.analysis.as_ref())
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
            Query::Roles => vec![Report::Roles(self.roles().await?)],
            Query::Role { name, version } => self
                .role(name, *version, now)
                .await?
                .map(Report::Role)
                .into_iter()
                .collect(),
            Query::BulkImpact { revoke } => {
                vec![Report::Bulk(self.bulk_impact(revoke, now).await?)]
            }
            Query::Sources => vec![Report::Sources(self.sources(now).await?)],
            // OP-156 m.3 (k)
            Query::ResourceIncarnation { namespace, path } => {
                vec![Report::Incarnations(
                    self.incarnations(namespace, path).await?,
                )]
            }
            // AG-43, OP-156 m.4 Q20
            Query::Discovery { unregistered } => self
                .discovery(*unregistered)
                .await?
                .into_iter()
                .map(Report::Shadow)
                .collect(),
            _ => Vec::new(),
        };
        Ok(Found {
            hits: reports
                .into_iter()
                .map(|r| Hit::Report(Box::new(r)))
                .collect(),
            next: None,
            audited: Some(actor.instance),
        })
    }
}

/// The named holder of Grant `g` if it lets that Party contribute to `target` now: every hop
/// of its lineage live, in its validity window and with its while-conditions holding.
fn eligible_holder(
    view: &Snapshot,
    g: &Id,
    target: &ResourceRef,
    catalog: &Catalog,
    now: u64,
) -> Option<Id> {
    let grant: GrantState = read(view, kind::GRANT, g)?;
    let SubjectSelector::Party(party) = grant.content.holder else {
        return None;
    };
    let set = &grant.content.authority.authority;
    let contribute = meta::core_action(access_kernel::contribution::ACTION);
    if !catalog.covered(&set.actions).contains(&contribute)
        || !resource_le(&ResourceSelector::Exact(target.clone()), &set.resource)
    {
        return None;
    }
    let (hops, _) = crate::domain::lineage_hops_at(view, g, Some(now))?;
    let actor = Actor {
        party,
        instance: Id([0; 16]),
    };
    hops.iter()
        .all(|h| {
            let c = &h.authority.constraints;
            h.status == HopStatus::Active
                && c.validity.from <= now
                && now <= c.validity.until
                && crate::domain::conditions_hold(view, &c.conditions, Some(&actor), now)
        })
        .then_some(party)
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
