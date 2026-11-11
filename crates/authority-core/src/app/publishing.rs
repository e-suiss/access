//! Schema publishing (§8.17.10.2, §9.13, E10, E11, E12, X21): a publisher's typed Schema
//! Publication Package with its parameter classes and compatibility declaration. A package whose
//! authority-relevant parameter has no closed type is refused before it is kept (E12). A kept
//! package is a statement only: each domain accepts its exact fingerprint with its own reserved
//! `acceptance.amend` Exercise, and nothing in this module can do that for it (X21).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical as _;
use access_kernel::compat::{self, Mapping, MappingOp};
use access_kernel::digest::Digest;
use access_kernel::meta::{ContentState, View as _, kind};
use access_kernel::model::{ActionRef, Id, Window};
use access_kernel::schema::{ActionSchema, Spp, schemas_key};
use suiss_crypto::dcbor::{self, Limits, Value};

use access_authority_sequencer::ports::DomainLog;

use crate::CoreError;
use crate::app::{Authority, Incoming};
use crate::domain::{Snapshot, read};
use crate::ports::{Binding, Reader, Salts};

/// Digest context of a package fingerprint.
pub const FINGERPRINT_CONTEXT: &str = "access/schema-publication/v1";

/// Text key: a new version leaves every existing delegation on its accepted version (E10).
pub const EXISTING_GRANTS_UNCHANGED: &str = "publish.existing_grants_unchanged";

/// Text key: new actions are not in delegations whose catalog was pinned at issue (E11).
pub const NEW_ACTIONS_NOT_INCLUDED: &str = "publish.new_actions_not_included";

/// Text key: Access cannot verify what an action means; acceptance relies on the publisher.
pub const PUBLISHER_TRUST: &str = "publish.publisher_trust";

/// What an authority-relevant parameter decides (E12), and so which closed type it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Affects {
    /// Who receives the effect: a subject selector.
    Recipient,
    /// How much: an ordered numeric with a unit.
    Amount,
    /// How many: a count.
    Count,
    /// Which of a closed set: enum or equality.
    Choice,
    /// Whether: a boolean.
    Flag,
}

impl Affects {
    const ALL: [(&'static str, Self); 5] = [
        ("recipient", Self::Recipient),
        ("amount", Self::Amount),
        ("count", Self::Count),
        ("choice", Self::Choice),
        ("flag", Self::Flag),
    ];

    /// Its word.
    #[must_use]
    pub fn word(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, a)| *a == self)
            .map_or("choice", |(w, _)| w)
    }

    /// From its word.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.iter().find(|(w, _)| *w == word).map(|(_, a)| *a)
    }

    /// The Action Schema parameter types that map it to a closed type (§7.9.3.4).
    #[must_use]
    pub const fn types(self) -> &'static [&'static str] {
        match self {
            Self::Recipient => &["id"],
            Self::Amount => &["amount"],
            Self::Count => &["int"],
            Self::Choice => &["text", "int", "bool", "id"],
            Self::Flag => &["bool"],
        }
    }

    /// The warning reason when it is not mapped.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Recipient => "affects_recipient",
            Self::Amount => "affects_amount",
            Self::Count => "affects_count",
            Self::Choice => "affects_choice",
            Self::Flag => "affects_flag",
        }
    }
}

/// A parameter's class (§9.13.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamClass {
    /// Grants can bound it; it needs a closed type (E12).
    Relevant(Affects),
    /// Only in the intent digest, never in subsumption.
    Opaque,
}

/// A compatibility relation (§9.13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relation {
    /// Same meaning, other representation.
    RepresentationEquivalent,
    /// The new version allows less.
    Narrowing,
    /// The new version allows more; never applied automatically.
    Broadening,
    /// No mapping; never applied automatically.
    Incompatible,
}

impl Relation {
    const ALL: [(&'static str, Self); 4] = [
        ("representation-equivalent", Self::RepresentationEquivalent),
        ("narrowing", Self::Narrowing),
        ("broadening", Self::Broadening),
        ("incompatible", Self::Incompatible),
    ];

    /// Its word.
    #[must_use]
    pub fn word(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(_, r)| *r == self)
            .map_or("incompatible", |(w, _)| w)
    }

    /// From its word.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        Self::ALL.iter().find(|(w, _)| *w == word).map(|(_, r)| *r)
    }

    /// The Kernel's relation of the same word.
    #[must_use]
    pub const fn kernel(self) -> compat::Relation {
        match self {
            Self::RepresentationEquivalent => compat::Relation::RepresentationEquivalent,
            Self::Narrowing => compat::Relation::Narrowing,
            Self::Broadening => compat::Relation::Broadening,
            Self::Incompatible => compat::Relation::Incompatible,
        }
    }
}

/// Most mappings one compatibility declaration carries.
pub const MAX_MAPPINGS: usize = 64;

/// The publisher's compatibility declaration (§9.13.4): a Claim, never a mapping in force until
/// a domain pins it (E10). Its mappings turn a new-version intent into the old version; a domain
/// uses one only after pinning its digest, and only when it does not broaden (PI-19, OP-157
/// m.3 (r)).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Compatibility {
    /// The catalog version it relates to.
    pub from: u64,
    /// The declared relation.
    pub relation: Relation,
    /// The mappings, each from an action of `from` to the same action in this version.
    pub mappings: Vec<Mapping>,
}

/// What a publisher submits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// Namespace.
    pub namespace: String,
    /// Catalog version.
    pub catalog_version: u64,
    /// Action Schemas.
    pub actions: Vec<ActionSchema>,
    /// The class of each `(action, parameter)`.
    pub classes: BTreeMap<(String, String), ParamClass>,
    /// Retired actions.
    pub retirements: BTreeSet<ActionRef>,
    /// Lowest core spec version it needs.
    pub core_spec_min: Option<u64>,
    /// Compatibility declaration against an earlier version.
    pub compatibility: Option<Compatibility>,
}

/// An authority-relevant parameter without a closed type (§8.17.10.2, E12).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Warning {
    /// Action name.
    pub action: String,
    /// Parameter name.
    pub parameter: String,
    /// `affects_recipient`, `affects_amount`, …
    pub reason: &'static str,
    /// The parameter type to map it to.
    pub suggestion: &'static str,
}

/// Why a draft is not published.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublishError {
    /// Authority-relevant parameters without a closed type (E12).
    #[error("authority-relevant parameters without a closed type")]
    Unmappable(Vec<Warning>),
    /// A declared parameter without a class.
    #[error("parameter {action}.{parameter} has no class")]
    Unclassified {
        /// Action name.
        action: String,
        /// Parameter name.
        parameter: String,
    },
    /// A class for a parameter no action declares.
    #[error("class for undeclared parameter {action}.{parameter}")]
    Undeclared {
        /// Action name.
        action: String,
        /// Parameter name.
        parameter: String,
    },
    /// Not a valid Schema Publication Package.
    #[error("not a valid package")]
    Package,
    /// The version is not after the publisher's latest one (E10: published versions are
    /// immutable).
    #[error("catalog version must follow {latest}")]
    Version {
        /// The latest published version.
        latest: u64,
    },
    /// The compatibility declaration does not name an earlier published version.
    #[error("compatibility must name an earlier published version")]
    Compatibility,
    /// A mapping that does not fit its declaration (OP-157 m.3 (r)): another relation than the
    /// declared one, a mapping for an incompatible version, an action that is not in the two
    /// versions, a dropped field that is not authority-opaque, or one mapping twice.
    #[error("mapping does not fit the compatibility declaration")]
    Mapping,
}

/// A published package with what its publisher declares around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    /// The package.
    pub spp: Spp,
    /// Parameter classes.
    pub classes: BTreeMap<(String, String), ParamClass>,
    /// Compatibility declaration.
    pub compatibility: Option<Compatibility>,
    /// When it was published.
    pub published_ms: u64,
}

/// What every publish answer carries (E10, E11): the text the console shows next to it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Notes {
    /// Always `true`: no existing delegation changes until a domain accepts (E10).
    pub existing_grants_unchanged: bool,
    /// Actions new in this version: not in delegations whose catalog is pinned (E11).
    pub new_actions: Vec<String>,
    /// Text keys, in order.
    pub text: Vec<&'static str>,
}

/// A publish answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// The publication.
    pub publication: Publication,
    /// Its fingerprint.
    pub fingerprint: Digest,
    /// The notes.
    pub notes: Notes,
}

/// `SHA-256("access/schema-publication/v1" ‖ 0x00 ‖ dCBOR(spp))`: the exact digest a domain's
/// `schema-definition` Acceptance pins (E10).
#[must_use]
pub fn fingerprint(spp: &Spp) -> Digest {
    let bytes = dcbor::encode(&spp.to_value(), Limits::CEILING).unwrap_or_default();
    Digest(suiss_crypto::digest::context_digest(FINGERPRINT_CONTEXT, &bytes).0)
}

/// The warnings of `draft` (E12): each authority-relevant parameter whose type is not one its
/// effect maps to. A console shows these before publishing.
#[must_use]
pub fn warnings(draft: &Draft) -> Vec<Warning> {
    let mut out = Vec::new();
    for a in &draft.actions {
        for (param, ty) in &a.params {
            if let Some(ParamClass::Relevant(affects)) =
                draft.classes.get(&(a.name.clone(), param.clone()))
                && !affects.types().contains(&ty.as_str())
            {
                out.push(Warning {
                    action: a.name.clone(),
                    parameter: param.clone(),
                    reason: affects.reason(),
                    suggestion: affects.types().first().copied().unwrap_or("id"),
                });
            }
        }
    }
    out
}

fn classified(draft: &Draft) -> Result<(), PublishError> {
    let declared: BTreeSet<(String, String)> = draft
        .actions
        .iter()
        .flat_map(|a| a.params.keys().map(|p| (a.name.clone(), p.clone())))
        .collect();
    if let Some((action, parameter)) = declared.iter().find(|k| !draft.classes.contains_key(*k)) {
        return Err(PublishError::Unclassified {
            action: action.clone(),
            parameter: parameter.clone(),
        });
    }
    if let Some((action, parameter)) = draft.classes.keys().find(|k| !declared.contains(*k)) {
        return Err(PublishError::Undeclared {
            action: action.clone(),
            parameter: parameter.clone(),
        });
    }
    Ok(())
}

/// Validates `draft` as `publisher`'s next version after `previous` (its latest published one
/// of the namespace) and returns what is kept. Nothing is written and no domain is touched.
///
/// # Errors
/// [`PublishError`].
pub fn publish(
    publisher: Id,
    draft: Draft,
    previous: Option<&Publication>,
    now: u64,
) -> Result<Published, PublishError> {
    classified(&draft)?;
    // E12
    let w = warnings(&draft);
    if !w.is_empty() {
        return Err(PublishError::Unmappable(w));
    }
    // E10
    if let Some(p) = previous
        && p.spp.catalog_version >= draft.catalog_version
    {
        return Err(PublishError::Version {
            latest: p.spp.catalog_version,
        });
    }
    if let Some(c) = &draft.compatibility
        && previous.is_none_or(|p| p.spp.catalog_version != c.from)
    {
        return Err(PublishError::Compatibility);
    }
    let spp = Spp {
        publisher,
        namespace: draft.namespace,
        catalog_version: draft.catalog_version,
        actions: draft.actions,
        retirements: draft.retirements,
        core_spec_min: draft.core_spec_min,
    };
    let spp = Spp::from_value(&spp.to_value()).map_err(|_| PublishError::Package)?;
    // OP-157 m.3 (r)
    if let (Some(c), Some(p)) = (&draft.compatibility, previous) {
        mappings_fit(c, &p.spp, &spp, &draft.classes)?;
    }
    let publication = Publication {
        spp,
        classes: draft.classes,
        compatibility: draft.compatibility,
        published_ms: now,
    };
    let notes = notes(&publication, previous);
    Ok(Published {
        fingerprint: fingerprint(&publication.spp),
        publication,
        notes,
    })
}

/// Whether every mapping of `c` fits its declaration between `old` and `new` (OP-157 m.3 (r)).
fn mappings_fit(
    c: &Compatibility,
    old: &Spp,
    new: &Spp,
    classes: &BTreeMap<(String, String), ParamClass>,
) -> Result<(), PublishError> {
    if c.mappings.is_empty() {
        return Ok(());
    }
    if c.relation == Relation::Incompatible || c.mappings.len() > MAX_MAPPINGS {
        return Err(PublishError::Mapping);
    }
    let old_refs: BTreeSet<ActionRef> = old.refs().into_iter().map(|(r, _)| r).collect();
    let new_refs: BTreeSet<ActionRef> = new.refs().into_iter().map(|(r, _)| r).collect();
    let mut seen = BTreeSet::new();
    for m in &c.mappings {
        let digest = compat::mapping_digest(m).map_err(|_| PublishError::Mapping)?;
        let dropped_relevant = m.ops.iter().any(|op| match op {
            MappingOp::Drop { field } => {
                classes.get(&(m.to.name.clone(), field.clone())) != Some(&ParamClass::Opaque)
            }
            _ => false,
        });
        if m.relation != c.relation.kernel()
            || !old_refs.contains(&m.from)
            || !new_refs.contains(&m.to)
            || dropped_relevant
            || !seen.insert(digest)
        {
            return Err(PublishError::Mapping);
        }
    }
    Ok(())
}

/// The notes of `publication` after `previous` (E10, E11).
#[must_use]
pub fn notes(publication: &Publication, previous: Option<&Publication>) -> Notes {
    let before: BTreeSet<&str> = previous
        .map(|p| p.spp.actions.iter().map(|a| a.name.as_str()).collect())
        .unwrap_or_default();
    let new_actions: Vec<String> = publication
        .spp
        .actions
        .iter()
        .filter(|a| previous.is_some() && !before.contains(a.name.as_str()))
        .map(|a| a.name.clone())
        .collect();
    let mut text = vec![EXISTING_GRANTS_UNCHANGED];
    if !new_actions.is_empty() {
        text.push(NEW_ACTIONS_NOT_INCLUDED);
    }
    text.push(PUBLISHER_TRUST);
    Notes {
        existing_grants_unchanged: true,
        new_actions,
        text,
    }
}

impl Publication {
    /// Its fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> Digest {
        fingerprint(&self.spp)
    }

    fn value(&self) -> Value {
        let classes = self
            .classes
            .iter()
            .map(|((a, p), c)| {
                let class = match c {
                    ParamClass::Opaque => Value::text("opaque"),
                    ParamClass::Relevant(x) => Value::text(x.word()),
                };
                Value::Array(vec![Value::text(a), Value::text(p), class])
            })
            .collect();
        let mut fields = vec![
            (Value::text("spp"), self.spp.to_value()),
            (Value::text("classes"), Value::Array(classes)),
            (
                Value::text("published_ms"),
                Value::Unsigned(self.published_ms),
            ),
        ];
        if let Some(c) = &self.compatibility {
            let mut parts = vec![Value::Unsigned(c.from), Value::text(c.relation.word())];
            // OP-157 m.3 (r)
            if !c.mappings.is_empty() {
                parts.push(Value::Array(
                    c.mappings
                        .iter()
                        .map(access_kernel::codec::Canonical::to_value)
                        .collect(),
                ));
            }
            fields.push((Value::text("compatibility"), Value::Array(parts)));
        }
        Value::Map(fields)
    }

    /// Its canonical bytes, as kept.
    ///
    /// # Errors
    /// [`PublishError::Package`] when it does not encode.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PublishError> {
        dcbor::encode(&self.value(), Limits::CEILING).map_err(|_| PublishError::Package)
    }

    /// From its canonical bytes.
    ///
    /// # Errors
    /// [`PublishError::Package`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PublishError> {
        let bad = || PublishError::Package;
        let v = dcbor::decode(bytes, Limits::CEILING).map_err(|_| bad())?;
        let spp = Spp::from_value(v.get("spp").ok_or_else(bad)?).map_err(|_| bad())?;
        let mut classes = BTreeMap::new();
        if let Some(Value::Array(items)) = v.get("classes") {
            for item in items {
                let Value::Array(parts) = item else {
                    return Err(bad());
                };
                let [Value::Text(a), Value::Text(p), Value::Text(c)] = parts.as_slice() else {
                    return Err(bad());
                };
                let class = if c == "opaque" {
                    ParamClass::Opaque
                } else {
                    ParamClass::Relevant(Affects::parse(c).ok_or_else(bad)?)
                };
                classes.insert((a.clone(), p.clone()), class);
            }
        }
        let compatibility = match v.get("compatibility") {
            None => None,
            Some(Value::Array(parts)) => match parts.as_slice() {
                [Value::Unsigned(from), Value::Text(r)] => Some(Compatibility {
                    from: *from,
                    relation: Relation::parse(r).ok_or_else(bad)?,
                    mappings: Vec::new(),
                }),
                [Value::Unsigned(from), Value::Text(r), Value::Array(ms)] => Some(Compatibility {
                    from: *from,
                    relation: Relation::parse(r).ok_or_else(bad)?,
                    mappings: ms
                        .iter()
                        .map(Mapping::from_value)
                        .collect::<Result<_, _>>()
                        .map_err(|_| bad())?,
                }),
                _ => return Err(bad()),
            },
            Some(_) => return Err(bad()),
        };
        let published_ms = match v.get("published_ms") {
            Some(Value::Unsigned(ms)) => *ms,
            _ => return Err(bad()),
        };
        Ok(Self {
            spp,
            classes,
            compatibility,
            published_ms,
        })
    }
}

/// Where a publication stands in one domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Standing {
    /// A live `schema-definition` Acceptance pins this exact fingerprint.
    Accepted,
    /// The domain accepts this publisher for the namespace, but not this fingerprint; the
    /// version in force, if any.
    Pending {
        /// The catalog version the domain accepts now.
        accepted_version: Option<u64>,
    },
    /// The domain has no live Acceptance of this publisher for the namespace.
    Unreferenced,
}

impl Standing {
    /// Its word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Pending { .. } => "pending_acceptance",
            Self::Unreferenced => "unreferenced",
        }
    }
}

/// The SPPs of the live `schema-definition` Acceptances of `namespace` at `now`.
pub(crate) fn accepted_spps(view: &Snapshot, namespace: &str, now: u64) -> Vec<Spp> {
    let ids = match view.get(&schemas_key(namespace)) {
        Some(Value::Array(ids)) => ids,
        _ => Vec::new(),
    };
    ids.iter()
        .filter_map(|v| Id::from_value(v).ok())
        .filter_map(|id| read::<ContentState>(view, kind::ACCEPTANCE, &id))
        .filter(|a| a.ended.is_none())
        .filter(|a| {
            a.content
                .get("validity")
                .and_then(|w| Window::from_value(w).ok())
                .is_some_and(|w| w.from <= now && now <= w.until)
        })
        .filter_map(|a| a.content.get("spp").and_then(|v| Spp::from_value(v).ok()))
        .collect()
}

/// Where `publication` stands in the domain `view` reads (§8.17.10.2).
#[must_use]
pub fn standing(view: &Snapshot, publication: &Publication, now: u64) -> Standing {
    let mine: Vec<Spp> = accepted_spps(view, &publication.spp.namespace, now)
        .into_iter()
        .filter(|s| s.publisher == publication.spp.publisher)
        .collect();
    let target = publication.fingerprint();
    if mine.iter().any(|s| fingerprint(s) == target) {
        Standing::Accepted
    } else if mine.is_empty() {
        Standing::Unreferenced
    } else {
        Standing::Pending {
            accepted_version: mine.iter().map(|s| s.catalog_version).max(),
        }
    }
}

/// Runs `f` over a snapshot `reader` fills, keys and prefix scans alike, until it asks for
/// nothing more.
///
/// # Errors
/// [`CoreError::Passes`] and the reader's errors.
pub(crate) async fn settle<R: Reader, T>(
    reader: &R,
    f: impl Fn(&Snapshot) -> T,
) -> Result<T, CoreError> {
    let mut snap = Snapshot::default();
    for _ in 0..crate::app::MAX_PASSES {
        snap.restart();
        let out = f(&snap);
        let keys = snap.missing();
        let scans = snap.missing_scans();
        if keys.is_empty() && scans.is_empty() {
            return Ok(out);
        }
        if !keys.is_empty() {
            snap.fill(reader.fetch(&keys).await?);
        }
        for prefix in scans {
            let rows = reader.scan(&prefix).await?;
            snap.fill_scan(prefix, rows);
        }
    }
    Err(CoreError::Passes)
}

/// Where one publication stands across domains: the publisher's view (§8.17.10.2, X21).
/// Domains that never accepted this publisher for the namespace are left out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The fingerprint.
    pub fingerprint: Digest,
    /// Domains that accept the publisher for the namespace but not this fingerprint.
    pub pending_acceptance: Vec<Digest>,
    /// Domains that accept this fingerprint.
    pub accepted_in: Vec<Digest>,
    /// The notes.
    pub notes: Notes,
}

/// The status of `publication` in each of `domains`, read through their readers. There is no
/// accept here: a domain accepts only by its own `acceptance.amend` Exercise (X21).
///
/// # Errors
/// The readers' errors.
pub async fn status<R: Reader>(
    publication: &Publication,
    previous: Option<&Publication>,
    domains: Vec<(Digest, R)>,
    now: u64,
) -> Result<Status, CoreError> {
    let mut out = Status {
        fingerprint: publication.fingerprint(),
        pending_acceptance: Vec::new(),
        accepted_in: Vec::new(),
        notes: notes(publication, previous),
    };
    for (domain, reader) in domains {
        match settle(&reader, |snap| standing(snap, publication, now)).await? {
            Standing::Accepted => out.accepted_in.push(domain),
            Standing::Pending { .. } => out.pending_acceptance.push(domain),
            Standing::Unreferenced => {}
        }
    }
    Ok(out)
}

/// How a published version differs from the one a domain accepts now (§8.17.10.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Diff {
    /// Actions it adds.
    pub added: Vec<String>,
    /// Actions it no longer has.
    pub removed: Vec<String>,
    /// Actions whose schema changed.
    pub changed: Vec<String>,
    /// Actions it newly marks reserved.
    pub reserved_added: Vec<String>,
    /// Actions it no longer marks reserved: broadening (E11).
    pub reserved_removed: Vec<String>,
}

/// The difference from `from` to `to`.
#[must_use]
pub fn diff(from: Option<&Spp>, to: &Spp) -> Diff {
    let index = |s: Option<&Spp>| -> BTreeMap<String, ActionSchema> {
        s.map(|s| {
            s.actions
                .iter()
                .map(|a| (a.name.clone(), a.clone()))
                .collect()
        })
        .unwrap_or_default()
    };
    let (old, new) = (index(from), index(Some(to)));
    let mut d = Diff::default();
    for (name, a) in &new {
        match old.get(name) {
            None => d.added.push(name.clone()),
            Some(o) => {
                if o != a {
                    d.changed.push(name.clone());
                }
                if a.reserved && !o.reserved {
                    d.reserved_added.push(name.clone());
                }
                if o.reserved && !a.reserved {
                    d.reserved_removed.push(name.clone());
                }
            }
        }
    }
    d.removed = old
        .keys()
        .filter(|n| !new.contains_key(*n))
        .cloned()
        .collect();
    d
}

/// One published version as a domain's administrators see it in Sources ▸ Action definitions
/// (§8.17.10.2): its standing here, the typed diff from the version in force, its reserved
/// flags, parameter classes and the publisher's compatibility declaration. There is no accept in
/// it; acceptance is the domain's own `acceptance.amend` with this fingerprint (X21).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Offer {
    /// The fingerprint.
    pub fingerprint: Digest,
    /// The publisher.
    pub publisher: Id,
    /// The namespace.
    pub namespace: String,
    /// The catalog version.
    pub catalog_version: u64,
    /// Standing here.
    pub standing: Standing,
    /// Diff from the accepted version of the same publisher.
    pub diff: Diff,
    /// Reserved actions.
    pub reserved: Vec<String>,
    /// Parameter classes: `(action, parameter, class)`.
    pub classes: Vec<(String, String, ParamClass)>,
    /// The compatibility declaration.
    pub compatibility: Option<Compatibility>,
    /// Each declared mapping's digest and whether a live Acceptance here pins it (OP-157
    /// m.3 (r)): an unpinned mapping changes no coverage.
    pub pinned: Vec<(Digest, bool)>,
    /// The notes.
    pub notes: Notes,
}

/// The offers of `publications` (newest first) in the domain `view` reads.
#[must_use]
pub fn offers(view: &Snapshot, publications: &[Publication], now: u64) -> Vec<Offer> {
    let namespace = publications.first().map(|p| p.spp.namespace.clone());
    let pins = namespace
        .as_deref()
        .map(|ns| crate::app::compat::pins(view, ns, now))
        .unwrap_or_default();
    let accepted = namespace
        .map(|ns| accepted_spps(view, &ns, now))
        .unwrap_or_default();
    publications
        .iter()
        .map(|p| {
            let in_force = accepted
                .iter()
                .filter(|s| s.publisher == p.spp.publisher)
                .max_by_key(|s| s.catalog_version);
            let previous = publications.iter().find(|q| {
                q.spp.publisher == p.spp.publisher && q.spp.catalog_version < p.spp.catalog_version
            });
            Offer {
                fingerprint: p.fingerprint(),
                publisher: p.spp.publisher,
                namespace: p.spp.namespace.clone(),
                catalog_version: p.spp.catalog_version,
                standing: standing(view, p, now),
                diff: diff(in_force, &p.spp),
                reserved: p
                    .spp
                    .actions
                    .iter()
                    .filter(|a| a.reserved)
                    .map(|a| a.name.clone())
                    .collect(),
                classes: p
                    .classes
                    .iter()
                    .map(|((a, q), c)| (a.clone(), q.clone(), *c))
                    .collect(),
                compatibility: p.compatibility.clone(),
                pinned: p
                    .compatibility
                    .iter()
                    .flat_map(|c| c.mappings.iter())
                    .filter_map(|m| compat::mapping_digest(m).ok())
                    .map(|d| (d, pins.contains_key(&d)))
                    .collect(),
                notes: notes(p, previous),
            }
        })
        .collect()
}

/// Digest context of a publish request's package (L1-ADP-18).
pub const PACKAGE_CONTEXT: &str = "access/schema-package/v1";

/// The core action a publish request's intent names (L1-ADP-18).
pub const PUBLISH_ACTION: &str = "publish";

/// The core action a status request's intent names (L1-ADP-18).
pub const STATUS_ACTION: &str = "read";

/// The resource namespace of a publish or status intent; its path is `[namespace]`.
pub const PUBLICATION_NAMESPACE: &str = "access.publication";

/// The intent member of a publish request that carries the package digest.
pub const PACKAGE_PARAM: &str = "package";

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The publisher of a publish (`package` given) or status request (L1-ADP-18, §8.17.10.2):
    /// the Party of the actor of its `check` AIS over `access`/`publish` (or `access`/`read`)
    /// on `access.publication:[namespace]`, whose `opaque.package` is the package digest of a
    /// publish and absent from a status. `None` for an anonymous request.
    ///
    /// # Errors
    /// [`CoreError::Protocol`] `publication` for any other intent; [`CoreError::Ais`].
    pub async fn publisher(
        &self,
        inc: &Incoming,
        namespace: &str,
        package: Option<&Digest>,
        now: u64,
    ) -> Result<Option<Id>, CoreError> {
        let req = &inc.request;
        let action = if package.is_some() {
            PUBLISH_ACTION
        } else {
            STATUS_ACTION
        };
        let opaque_ok = match package {
            Some(d) => {
                req.intent.opaque.len() == 1 && req.intent.opaque.get(PACKAGE_PARAM) == Some(d)
            }
            None => req.intent.opaque.is_empty(),
        };
        let resource_ok = matches!(
            req.intent.resources.as_slice(),
            [r] if r.namespace == PUBLICATION_NAMESPACE && r.path == [namespace]
        );
        if req.mode != access_kernel::combinator::Mode::Check
            || req.payload.is_some()
            || req.intent.action != access_kernel::meta::core_action(action)
            || !resource_ok
            || !opaque_ok
        {
            return Err(CoreError::Protocol("publication"));
        }
        let digest = access_kernel::intent::intent_digest(&req.intent)
            .map_err(|_| CoreError::Protocol("intent"))?;
        Ok(self.actor(inc, &digest, now).await?.map(|a| a.party))
    }

    /// The published versions of `namespace` as this domain sees them (§8.17.10.2), newest
    /// first. A package that does not decode is left out.
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn publication_offers(
        &self,
        namespace: &str,
        now: u64,
    ) -> Result<Vec<Offer>, CoreError> {
        let publications: Vec<Publication> = self
            .reader
            .publications(namespace)
            .await?
            .iter()
            .filter_map(|b| Publication::from_bytes(b).ok())
            .filter(|p| p.spp.namespace == namespace)
            .collect();
        if publications.is_empty() {
            return Ok(Vec::new());
        }
        settle(&self.reader, |snap| offers(snap, &publications, now)).await
    }
}

#[cfg(test)]
mod tests;
