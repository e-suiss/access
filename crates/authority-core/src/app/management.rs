//! The management reads of the console (§8.17.9, IA-2, IA-5, E17): the domain's roles, the
//! viewer's own holdings as usable bases, the Changes feed and the preview of a bulk revoke.
//! Every one is derived and advisory: it reads state and the log and writes nothing.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::Catalog;
use access_kernel::codec::Canonical as _;
use access_kernel::combinator::HopStatus;
use access_kernel::meta::{self, Actor, GrantState, kind};
use access_kernel::model::{ActionRef, Id, ResourceSelector, SubjectSelector};
use access_kernel::record::{RecordEnvelope, RecordKind};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Authority;
use crate::app::impact::{Aftermath, RevocationImpact, Revoked};
use crate::app::publishing::settle;
use crate::domain::{Snapshot, accepted_catalog, lineage_hops, read};
use crate::ports::{Binding, Reader, Salts};

/// Most log records one Changes page walks back (PD).
pub const CHANGES_WINDOW: u64 = 2_000;

/// Most rows one Changes page holds.
pub const CHANGES_PAGE: usize = 100;

/// Most Grants one bulk job names (TN-125).
pub const MAX_BULK: usize = 100;

/// Log records read per page.
const LOG_PAGE: u64 = 500;

/// Most holdings one page lists.
const HOLDINGS_PAGE: u32 = 100;

/// One of the viewer's own holdings (IA-5): with `grant` and `holder` it is an ADP `holding`
/// basis the viewer may name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Holding {
    /// The Grant.
    pub grant: Id,
    /// The viewer's Party.
    pub holder: Id,
    /// The position that opened the episode.
    pub since: u64,
    /// The actions it covers now.
    pub actions: Vec<ActionRef>,
    /// The resource it covers.
    pub resource: ResourceSelector,
}

/// What kind of object a change touched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChangeKind {
    /// A Grant.
    Grant,
    /// An Anchor.
    Anchor,
    /// A Party.
    Party,
    /// An Instance.
    Instance,
    /// A Mandate.
    Mandate,
    /// An Acceptance.
    Acceptance,
    /// A restriction policy.
    Policy,
    /// A role version.
    AuthoritySet,
}

impl ChangeKind {
    const ALL: [(&'static str, Self); 8] = [
        (kind::GRANT, Self::Grant),
        (kind::ANCHOR, Self::Anchor),
        (kind::PARTY, Self::Party),
        (kind::INSTANCE, Self::Instance),
        (kind::MANDATE, Self::Mandate),
        (kind::ACCEPTANCE, Self::Acceptance),
        (kind::POLICY, Self::Policy),
        (kind::AUTHORITY_SET, Self::AuthoritySet),
    ];

    /// Its word.
    #[must_use]
    pub fn word(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, k)| *k == self)
            .map_or("grant", |(w, _)| w)
    }

    fn of(word: &str) -> Option<Self> {
        Self::ALL.iter().find(|(w, _)| *w == word).map(|(_, k)| *k)
    }
}

/// What a change's object is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Changed {
    /// An object by id.
    Object(Id),
    /// A role version.
    Role {
        /// Name.
        name: String,
        /// Version.
        version: u64,
    },
}

/// One row of the Changes feed (IA-2): information only, no item claims an action.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Change {
    /// The decision record's position.
    pub position: u64,
    /// Its trusted time.
    pub at: u64,
    /// The object's kind.
    pub kind: ChangeKind,
    /// The object.
    pub changed: Changed,
    /// The change ended it.
    pub ended: bool,
    /// The viewer's own Instance made it.
    pub own: bool,
}

/// The preview of a bulk revoke (E17, TN-125): each item's own revocation impact and their sum.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BulkImpact {
    /// The Grants of the job, in order.
    pub revoke: Vec<Id>,
    /// Each item's preview.
    pub items: Vec<RevocationImpact>,
    /// Every Grant that ends with the job, once.
    pub subtree: Vec<Id>,
    /// The aftermath over the job.
    pub aftermath: Aftermath,
    /// The longest window of any item.
    pub max_exposure_ms: u64,
}

fn field<'a>(r: &'a RecordEnvelope, name: &str) -> Option<&'a Value> {
    r.fields.get(name).map(|f| &f.value)
}

/// The kind and object of an effect key, for the kinds the feed shows.
fn changed(key: &[u8]) -> Option<(ChangeKind, Changed)> {
    let Value::Array(items) = dcbor::decode(key, Limits::CEILING).ok()? else {
        return None;
    };
    match items.as_slice() {
        [Value::Text(k), Value::Text(name), Value::Unsigned(v)] if k == kind::AUTHORITY_SET => {
            Some((
                ChangeKind::AuthoritySet,
                Changed::Role {
                    name: name.clone(),
                    version: *v,
                },
            ))
        }
        [Value::Text(k), id] if k != kind::AUTHORITY_SET => {
            let kind = ChangeKind::of(k)?;
            Some((kind, Changed::Object(Id::from_value(id).ok()?)))
        }
        _ => None,
    }
}

/// The changes one allowed decision record made, newest object order kept.
fn changes_of(r: &RecordEnvelope, actors: &BTreeMap<Vec<u8>, Value>, own: &Value) -> Vec<Change> {
    let allowed = matches!(
        field(r, "outcome").and_then(|o| o.get("outcome")),
        Some(Value::Text(t)) if t == "allow"
    );
    let Some(Value::Array(effects)) = field(r, "effects").filter(|_| allowed) else {
        return Vec::new();
    };
    let by_viewer = match field(r, "nonce") {
        Some(Value::Bytes(n)) => actors.get(n) == Some(own),
        _ => false,
    };
    effects
        .iter()
        .filter_map(|e| {
            let Value::Array(parts) = e else { return None };
            let Some(Value::Bytes(key)) = parts.first() else {
                return None;
            };
            let (kind, changed) = changed(key)?;
            let ended = parts.get(1).is_some_and(|v| v.get("ended").is_some());
            Some(Change {
                position: r.header.pos,
                at: r.header.recorded_at,
                kind,
                changed,
                ended,
                own: by_viewer,
            })
        })
        .collect()
}

/// Whether every hop of `grant`'s lineage is live.
fn live(view: &Snapshot, grant: &Id) -> Option<GrantState> {
    let (hops, _) = lineage_hops(view, grant)?;
    if hops.iter().all(|h| h.status == HopStatus::Active) {
        read(view, kind::GRANT, grant)
    } else {
        None
    }
}

/// `dCBOR(["authority_set", name])` keys share this prefix: a two-item array headed by the kind.
fn roles_prefix() -> Vec<u8> {
    let mut out = vec![0x82];
    out.extend(
        dcbor::encode(&Value::text(kind::AUTHORITY_SET), Limits::CEILING).unwrap_or_default(),
    );
    out
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Every Named `AuthoritySet` of the domain and its latest version (C28).
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn roles(&self) -> Result<Vec<(String, u64)>, CoreError> {
        let prefix = roles_prefix();
        settle(&self.reader, |snap| {
            snap.scan(&prefix)
                .into_iter()
                .filter_map(|(k, v)| {
                    let Value::Array(items) = dcbor::decode(&k, Limits::CEILING).ok()? else {
                        return None;
                    };
                    match (items.as_slice(), v) {
                        ([_, Value::Text(name)], Value::Unsigned(latest)) => {
                            Some((name.clone(), latest))
                        }
                        _ => None,
                    }
                })
                .collect()
        })
        .await
    }

    /// The live holdings of `actor`'s own Party (IA-5, OP-152 m.7 (b)): held by name or, for a
    /// rule-shaped Grant, as a member now; each names the episode a `holding` basis needs.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn holdings(&self, actor: &Actor, now: u64) -> Result<Vec<Holding>, CoreError> {
        let candidates = self
            .reader
            .grants_for(&actor.party, None, HOLDINGS_PAGE)
            .await?;
        let mut out = Vec::new();
        for g in candidates {
            let Some(state) = settle(&self.reader, |snap| live(snap, &g)).await? else {
                continue;
            };
            let since = match &state.content.holder {
                SubjectSelector::Party(p) if *p == actor.party => Some(state.since),
                SubjectSelector::Pred(c) => {
                    let mut snap = Snapshot::default();
                    self.episode(&mut snap, c, &actor.party, now).await?
                }
                _ => None,
            };
            let Some(since) = since else { continue };
            let set = &state.content.authority.authority;
            let namespaces: BTreeSet<String> = set
                .actions
                .exact
                .iter()
                .map(|a| a.namespace.clone())
                .chain(set.actions.prefix.iter().map(|(n, _)| n.clone()))
                .collect();
            let catalog = settle(&self.reader, |snap| {
                namespaces.iter().fold(Catalog::default(), |c, ns| {
                    accepted_catalog(snap, ns, now, &c)
                })
            })
            .await?;
            let mut actions: Vec<ActionRef> = catalog.covered(&set.actions).into_iter().collect();
            actions.extend(
                set.actions
                    .exact
                    .iter()
                    .filter(|a| a.namespace == meta::NAMESPACE)
                    .cloned(),
            );
            actions.sort();
            actions.dedup();
            out.push(Holding {
                grant: g,
                holder: actor.party,
                since,
                actions,
                resource: set.resource.clone(),
            });
        }
        Ok(out)
    }

    /// The Changes feed before `before` (IA-2): the objects allowed meta-Exercises changed,
    /// newest first, at most [`CHANGES_PAGE`] rows from the last [`CHANGES_WINDOW`] records.
    /// An auditor sees every row; anyone else only rows its own Instance made or that changed
    /// its own Party, its own Instance or a Grant it holds by name. Returns the rows and the
    /// position to continue before, when older records remain.
    ///
    /// # Errors
    /// The reader's errors; [`CoreError::Protocol`] for a record that does not decode.
    pub async fn changes(
        &self,
        actor: &Actor,
        auditor: bool,
        before: Option<u64>,
    ) -> Result<(Vec<Change>, Option<u64>), CoreError> {
        let last = before
            .unwrap_or_else(|| self.head().saturating_add(1))
            .saturating_sub(1);
        let first = last.saturating_sub(CHANGES_WINDOW).max(1);
        let mut rows = Vec::new();
        let mut actors: BTreeMap<Vec<u8>, Value> = BTreeMap::new();
        let own = actor.instance.to_value();
        let mut from = first;
        while from <= last {
            let to = from.saturating_add(LOG_PAGE).saturating_sub(1).min(last);
            for bytes in self.reader.log(from, to).await? {
                let r = RecordEnvelope::from_bytes(&bytes)
                    .map_err(|_| CoreError::Protocol("record"))?;
                match r.header.kind {
                    RecordKind::Opening => {
                        if let (Some(Value::Bytes(n)), Some(a)) =
                            (field(&r, "nonce"), field(&r, "actor"))
                        {
                            actors.insert(n.clone(), a.clone());
                        }
                    }
                    RecordKind::Decision => rows.extend(changes_of(&r, &actors, &own)),
                    RecordKind::Claim | RecordKind::Genesis => {}
                }
            }
            from = to.saturating_add(1);
        }
        if !auditor {
            let mine = settle(&self.reader, |snap| {
                rows.iter()
                    .map(|c| {
                        c.own
                            || match (&c.kind, &c.changed) {
                                (ChangeKind::Party, Changed::Object(p)) => *p == actor.party,
                                (ChangeKind::Instance, Changed::Object(i)) => *i == actor.instance,
                                (ChangeKind::Grant, Changed::Object(g)) => {
                                    read::<GrantState>(snap, kind::GRANT, g).is_some_and(|s| {
                                        s.content.holder == SubjectSelector::Party(actor.party)
                                    })
                                }
                                _ => false,
                            }
                    })
                    .collect::<Vec<bool>>()
            })
            .await?;
            rows = rows
                .into_iter()
                .zip(mine)
                .filter_map(|(c, keep)| keep.then_some(c))
                .collect();
        }
        rows.reverse();
        let more = rows.len() > CHANGES_PAGE || first > 1;
        rows.truncate(CHANGES_PAGE);
        let next = more
            .then(|| rows.last().map_or(first, |c| c.position))
            .filter(|p| *p > 1);
        Ok((rows, next))
    }

    /// The preview of a bulk revoke of `revoke` at `at` (E17, TN-125, XI-3): each Grant's own
    /// revocation impact, in order, and their sum. Nothing is written; the job's items are each
    /// their own Exercise.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] for an empty or oversized job; as
    /// [`Authority::revocation_impact`].
    pub async fn bulk_impact(&self, revoke: &[Id], at: u64) -> Result<BulkImpact, CoreError> {
        if revoke.is_empty() || revoke.len() > MAX_BULK {
            return Err(CoreError::Protocol("query"));
        }
        let mut items = Vec::with_capacity(revoke.len());
        for g in revoke {
            items.push(self.revocation_impact(Revoked::Grant(*g), at).await?);
        }
        let subtree: BTreeSet<Id> = items
            .iter()
            .flat_map(|i| i.subtree.iter().copied())
            .collect();
        let exposed: BTreeSet<_> = items
            .iter()
            .flat_map(|i| {
                i.exposed
                    .iter()
                    .map(|e| (e.exercise, e.horizon_ms, e.applied_at.is_some()))
            })
            .collect();
        let n = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
        let aftermath = Aftermath {
            grants_ending: n(subtree.len()),
            projections_open: n(exposed.len()),
            honoured_until_ms: exposed.iter().map(|(_, h, _)| *h).max(),
            running_copies: 0,
            confirmed_applied: n(exposed.iter().filter(|(_, _, a)| *a).count()),
        };
        Ok(BulkImpact {
            revoke: revoke.to_vec(),
            max_exposure_ms: items.iter().map(|i| i.max_exposure_ms).max().unwrap_or(0),
            subtree: subtree.into_iter().collect(),
            aftermath,
            items,
        })
    }
}
