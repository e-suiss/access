//! The Sources read of the console (§8.17.9.3, INV-15, X20, §5.13): every live Acceptance of the
//! domain by its use, with its blast radius, and the partners whose authority bridging Grants
//! recognize up to their ceilings. Derived and advisory: it reads state and writes nothing.

use std::collections::BTreeSet;

use access_authority_sequencer::ports::DomainLog;
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::foreign::ForeignIssuer;
use access_kernel::meta::{ContentState, GrantState, kind};
use access_kernel::model::{ActionRef, Id, ProofKind, ResourceSelector, SubjectSelector, Window};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::app::Authority;
use crate::app::publishing::settle;
use crate::domain::Snapshot;
use crate::ports::{Binding, Reader, Salts};

/// Who issues what a source admits.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Issuer {
    /// A Party of this domain or of a realm it accepts.
    Party(Id),
    /// A foreign domain (OP-143 m.13).
    Foreign(Digest),
}

/// One live Acceptance (§8.17.9.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Source {
    /// The Acceptance.
    pub acceptance: Id,
    /// Its canonical use.
    pub use_: String,
    /// Its issuer.
    pub issuer: Issuer,
    /// The claim classes it admits.
    pub classes: Vec<String>,
    /// For `schema-definition`, the namespace whose actions it defines.
    pub namespace: Option<String>,
    /// Position of its last change.
    pub since: u64,
    /// Whether changing it is a protected change (§8.17.9.3): every use but `actor-binding`
    /// and `predicate-input`.
    pub protected: bool,
    /// Blast radius: the live Grants that depend on it — by a holder condition or requirement
    /// on one of its classes, as the partner they recognize, or naming an action it defines.
    pub dependents: u64,
}

/// The ceiling one bridging Grant sets on a partner's authority (§5.13, C21).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ceiling {
    /// The bridging Grant.
    pub grant: Id,
    /// The partner's authority class it recognizes.
    pub class: String,
    /// The actions it allows at most.
    pub actions: Vec<ActionRef>,
    /// The resource it covers at most.
    pub resource: ResourceSelector,
    /// Until when.
    pub until: u64,
}

/// A partner domain whose authority is recognized here (§5.13, 3372).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Partner {
    /// The partner's `DomainID`.
    pub domain: Digest,
    /// The live `foreign-authority` Acceptances of it.
    pub acceptances: Vec<Id>,
    /// The ceilings of the live bridging Grants to it.
    pub ceilings: Vec<Ceiling>,
}

/// The Sources report.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sources {
    /// Every live Acceptance.
    pub sources: Vec<Source>,
    /// Every partner.
    pub partners: Vec<Partner>,
}

fn prefix(of: &str) -> Vec<u8> {
    let mut out = vec![0x82];
    out.extend(dcbor::encode(&Value::text(of), Limits::CEILING).unwrap_or_default());
    out
}

fn key_id(k: &[u8]) -> Option<Id> {
    let Value::Array(items) = dcbor::decode(k, Limits::CEILING).ok()? else {
        return None;
    };
    match items.as_slice() {
        [_, Value::Bytes(b)] => <[u8; 16]>::try_from(b.as_slice()).ok().map(Id),
        _ => None,
    }
}

fn texts(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| match i {
                Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn live_window(content: &Value, now: u64) -> bool {
    content
        .get("validity")
        .and_then(|w| Window::from_value(w).ok())
        .is_some_and(|w| w.from <= now && now < w.until)
}

fn source_of(id: Id, state: &ContentState, now: u64) -> Option<Source> {
    if state.ended.is_some() || !live_window(&state.content, now) {
        return None;
    }
    let use_ = match state.content.get("use") {
        Some(Value::Text(u)) => u.clone(),
        _ => return None,
    };
    let issuer = match state.content.get("issuer") {
        Some(Value::Bytes(b)) => Issuer::Party(Id(<[u8; 16]>::try_from(b.as_slice()).ok()?)),
        _ => Issuer::Foreign(ForeignIssuer::of(&state.content).ok()??.domain),
    };
    let namespace = state
        .content
        .get("spp")
        .and_then(|s| s.get("namespace"))
        .and_then(|n| match n {
            Value::Text(t) => Some(t.clone()),
            _ => None,
        });
    let protected = !matches!(use_.as_str(), "actor-binding" | "predicate-input");
    Some(Source {
        acceptance: id,
        use_,
        issuer,
        classes: texts(state.content.get("classes")),
        namespace,
        since: state.since,
        protected,
        dependents: 0,
    })
}

fn live_grants(snap: &Snapshot, now: u64) -> Vec<(Id, GrantState)> {
    snap.scan(&prefix(kind::GRANT))
        .into_iter()
        .filter_map(|(k, v)| {
            let g = GrantState::from_value(&v).ok()?;
            let c = &g.content.authority.constraints.validity;
            (g.ended.is_none() && c.from <= now && now < c.until)
                .then(|| key_id(&k).map(|id| (id, g)))
                .flatten()
        })
        .collect()
}

fn depends(source: &Source, g: &GrantState) -> bool {
    let a = &g.content.authority;
    match (&source.issuer, source.use_.as_str()) {
        (Issuer::Foreign(d), _) => {
            matches!(&g.content.holder, SubjectSelector::Foreign { domain, .. } if domain == d)
        }
        (_, "schema-definition") => source.namespace.as_ref().is_some_and(|ns| {
            a.authority.actions.exact.iter().any(|r| &r.namespace == ns)
                || a.authority.actions.prefix.iter().any(|(n, _)| n == ns)
        }),
        _ => {
            let held = match &g.content.holder {
                SubjectSelector::Pred(c) => {
                    c.iter().any(|c| source.classes.contains(&c.claim_class))
                }
                _ => false,
            };
            held || a
                .requirements
                .iter()
                .any(|t| t.proof_kind == ProofKind::Claim && source.classes.contains(&t.class))
        }
    }
}

fn report(snap: &Snapshot, now: u64) -> Sources {
    let mut sources: Vec<Source> = snap
        .scan(&prefix(kind::ACCEPTANCE))
        .into_iter()
        .filter_map(|(k, v)| {
            let state = ContentState::from_value(&v).ok()?;
            source_of(key_id(&k)?, &state, now)
        })
        .collect();
    let grants = live_grants(snap, now);
    for s in &mut sources {
        s.dependents =
            u64::try_from(grants.iter().filter(|(_, g)| depends(s, g)).count()).unwrap_or(u64::MAX);
    }
    let domains: BTreeSet<Digest> = sources
        .iter()
        .filter_map(|s| match s.issuer {
            Issuer::Foreign(d) => Some(d),
            Issuer::Party(_) => None,
        })
        .collect();
    let partners = domains
        .into_iter()
        .map(|d| Partner {
            domain: d,
            acceptances: sources
                .iter()
                .filter(|s| s.issuer == Issuer::Foreign(d))
                .map(|s| s.acceptance)
                .collect(),
            ceilings: grants
                .iter()
                .filter_map(|(id, g)| match &g.content.holder {
                    SubjectSelector::Foreign { domain, class } if *domain == d => Some(Ceiling {
                        grant: *id,
                        class: class.clone(),
                        actions: g
                            .content
                            .authority
                            .authority
                            .actions
                            .exact
                            .iter()
                            .cloned()
                            .collect(),
                        resource: g.content.authority.authority.resource.clone(),
                        until: g.content.authority.constraints.validity.until,
                    }),
                    _ => None,
                })
                .collect(),
        })
        .collect();
    sources.sort_by(|a, b| (&a.use_, a.since, a.acceptance).cmp(&(&b.use_, b.since, b.acceptance)));
    Sources { sources, partners }
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The domain's live Acceptances by use with their blast radius, and its partners with the
    /// ceilings of their bridging Grants (§8.17.9.3, §5.13).
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn sources(&self, now: u64) -> Result<Sources, CoreError> {
        settle(&self.reader, |snap| report(snap, now)).await
    }
}

#[cfg(test)]
mod tests;
