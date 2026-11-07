//! The role claim of an authority token (§5.3, §5.17, INV-33, S-1, OP-141 m.32): a role is the
//! Named `AuthoritySet` a Grant pins, and a token names it only as the projection of that
//! Grant, when the token's decided bounds cover the whole named version. A role claim therefore
//! never says more than the token's own authority ⊆ (`AuthoritySet` ∩ Mandate).
//!
//! The role editor's model (§8.17.9.2, C28, E11): a role version as a typed `AuthoritySet`
//! with its "Not included" block computed here (reserved actions in its prefix namespaces and
//! actions newer than its pinned catalog version), the relation of two versions decided by the
//! closed algebra, and an admin Grant's meta-actions listed one by one with reserved ones apart.

use std::collections::{BTreeMap, BTreeSet};

use access_authority_sequencer::ports::DomainLog;
use access_kernel::algebra::{Catalog, subsumes};
use access_kernel::codec::Canonical as _;
use access_kernel::digest::Digest;
use access_kernel::meta::{
    self, ExerciseBasis, GrantState, View as _, authority_set_digest, authority_set_key, kind,
};
use access_kernel::model::{ActionRef, AuthoritySet, Id, ProofKind};
use access_kernel::tier::Tier;
use suiss_crypto::dcbor::Value;

use crate::CoreError;
use crate::app::Authority;
use crate::domain::{Snapshot, accepted_catalog, read};
use crate::ports::{Binding, Reader, Salts};

/// The claim that carries a token's roles (RFC 9068 §2.2.3.1).
pub const ROLES_CLAIM: &str = "roles";

fn namespaces(set: &AuthoritySet) -> BTreeSet<String> {
    set.actions
        .exact
        .iter()
        .map(|a| a.namespace.clone())
        .chain(set.actions.prefix.iter().map(|(ns, _)| ns.clone()))
        .collect()
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// The roles a token of `bounds` decided on `basis` may name at `now`: the name of the
    /// Named `AuthoritySet` version the basis Grant pins, when that version lies within
    /// `bounds`; otherwise none.
    pub(crate) async fn projected_roles(
        &self,
        basis: &ExerciseBasis,
        bounds: &AuthoritySet,
        now: u64,
    ) -> Result<Vec<String>, CoreError> {
        let grant = match basis {
            ExerciseBasis::Holding(h) => h.grant,
            ExerciseBasis::Public(g) => *g,
            ExerciseBasis::Anchor(_) => return Ok(Vec::new()),
        };
        self.settled(|snap| {
            let Some((name, version, _)) =
                read::<GrantState>(snap, kind::GRANT, &grant).and_then(|g| g.content.named)
            else {
                return Vec::new();
            };
            let Some(named) = snap
                .get(&authority_set_key(&name, Some(version)))
                .and_then(|v| v.get("authority").cloned())
                .and_then(|a| AuthoritySet::from_value(&a).ok())
            else {
                return Vec::new();
            };
            let mut catalog = Catalog::default();
            for ns in namespaces(&named).union(&namespaces(bounds)) {
                catalog = accepted_catalog(snap, ns, now, &catalog);
            }
            if subsumes(&named, bounds, &catalog) {
                vec![name]
            } else {
                Vec::new()
            }
        })
        .await
    }
}

/// The core meta-actions (L0-META-1), in the Kernel's order.
pub const META_ACTIONS: [&str; 27] = [
    "anchor_create",
    "anchor_transfer",
    "anchor_amend",
    "anchor_retire",
    "party_register",
    "party_depart",
    "instance_create",
    "instance_rekey",
    "instance_terminate",
    "instance_recover",
    "mandate_bind",
    "mandate_rebind",
    "mandate_revoke",
    "grant_issue",
    "grant_amend",
    "grant_revoke",
    "grant_renounce",
    "acceptance_establish",
    "acceptance_amend",
    "acceptance_revoke",
    "policy_set",
    "policy_retire",
    "claim_issue",
    "contribute",
    "consumption_release",
    "authority_set_define",
    "projection_issue",
];

/// Whether a meta-action is reserved for the admin view (§8.17.9.2): `acceptance.*` and
/// `anchor.*`, shown apart and only ever covered by a Grant that names them.
#[must_use]
pub fn reserved_meta(name: &str) -> bool {
    name.starts_with("acceptance_") || name.starts_with("anchor_")
}

/// The tier a meta-action has when it widens authority (§13.7.1, OP-141 m.34 (a)).
#[must_use]
pub fn widening_tier(name: &str) -> Tier {
    match name {
        "contribute" | "projection_issue" => Tier::Ct1,
        "anchor_create"
        | "anchor_transfer"
        | "anchor_amend"
        | "anchor_retire"
        | "party_depart"
        | "instance_recover"
        | "grant_amend"
        | "acceptance_establish"
        | "acceptance_amend"
        | "policy_set"
        | "policy_retire" => Tier::Ct3,
        _ => Tier::Ct2,
    }
}

/// The word of a tier.
#[must_use]
pub const fn tier_word(tier: Tier) -> &'static str {
    match tier {
        Tier::Ct0 => "ct0",
        Tier::Ct1 => "ct1",
        Tier::Ct2 => "ct2",
        Tier::Ct3 => "ct3",
    }
}

/// The catalog of every namespace `set` names, as the domain accepts it at `now`.
pub(crate) fn catalog_of(view: &Snapshot, sets: &[&AuthoritySet], now: u64) -> Catalog {
    let mut catalog = Catalog::default();
    let all: BTreeSet<String> = sets.iter().flat_map(|s| namespaces(s)).collect();
    for ns in &all {
        catalog = accepted_catalog(view, ns, now, &catalog);
    }
    catalog
}

/// A catalog-pinned prefix and what the domain accepted after it (E11, §9.13.3): shown as "as
/// of catalog vN — future actions not included".
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedCatalog {
    /// The prefix namespace.
    pub namespace: String,
    /// The pinned catalog digest.
    pub catalog: Digest,
    /// Its catalog version, when a live Acceptance still names it.
    pub catalog_version: Option<u64>,
    /// Actions accepted in the namespace that the pinned catalog does not have.
    pub newer: Vec<ActionRef>,
}

/// The "Not included" block of a role version (§8.17.9.2, E11): computed, never typed in.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotIncluded {
    /// Reserved actions of its prefix namespaces it does not name: only a Grant that names one
    /// covers it.
    pub reserved: Vec<ActionRef>,
    /// Its pinned catalogs and the actions newer than each.
    pub catalogs: Vec<PinnedCatalog>,
}

/// The "Not included" block of `set` in the domain `view` reads.
#[must_use]
pub fn not_included(view: &Snapshot, set: &AuthoritySet, now: u64) -> NotIncluded {
    let mut out = NotIncluded::default();
    let mut reserved = BTreeSet::new();
    for (ns, cat) in &set.actions.prefix {
        let spps = crate::app::publishing::accepted_spps(view, ns, now);
        let pinned = spps.iter().find(|s| s.catalog_digest() == *cat);
        let pinned_refs: BTreeSet<ActionRef> = pinned
            .map(|s| s.refs().into_iter().map(|(r, _)| r).collect())
            .unwrap_or_default();
        let mut newer = BTreeSet::new();
        for spp in &spps {
            for (r, schema) in spp.refs() {
                if spp.retirements.contains(&r) {
                    continue;
                }
                if schema.reserved && !set.actions.exact.contains(&r) {
                    reserved.insert(r.clone());
                }
                if !pinned_refs.contains(&r) && !schema.reserved {
                    newer.insert(r);
                }
            }
        }
        out.catalogs.push(PinnedCatalog {
            namespace: ns.clone(),
            catalog: *cat,
            catalog_version: pinned.map(|s| s.catalog_version),
            newer: newer.into_iter().collect(),
        });
    }
    out.reserved = reserved.into_iter().collect();
    out
}

/// One version of a Named `AuthoritySet` as the role editor shows it (C28).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoleVersion {
    /// Name.
    pub name: String,
    /// This version.
    pub version: u64,
    /// The latest version of the name.
    pub latest: u64,
    /// The digest a Grant pins it by.
    pub digest: Digest,
    /// Position that defined it.
    pub since: u64,
    /// The typed authority set.
    pub authority: AuthoritySet,
    /// What it does not include.
    pub not_included: NotIncluded,
}

/// Version `version` of role `name` (the latest when `None`) in the domain `view` reads.
#[must_use]
pub fn role_version(
    view: &Snapshot,
    name: &str,
    version: Option<u64>,
    now: u64,
) -> Option<RoleVersion> {
    let Value::Unsigned(latest) = view.get(&authority_set_key(name, None))? else {
        return None;
    };
    let version = version.unwrap_or(latest);
    let state = view.get(&authority_set_key(name, Some(version)))?;
    let authority = AuthoritySet::from_value(state.get("authority")?).ok()?;
    let since = match state.get("since") {
        Some(Value::Unsigned(p)) => *p,
        _ => return None,
    };
    Some(RoleVersion {
        name: name.to_owned(),
        version,
        latest,
        digest: authority_set_digest(&authority),
        since,
        not_included: not_included(view, &authority, now),
        authority,
    })
}

/// How a new authority set relates to an old one (§5.8, C28): decided exactly by the closed
/// algebra (INV-8), no solver involved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SetRelation {
    /// The same authority.
    Equivalent,
    /// Strictly less.
    Narrowing,
    /// Strictly more.
    Widening,
    /// More somewhere, less elsewhere.
    Incomparable,
}

impl SetRelation {
    /// Its word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Equivalent => "equivalent",
            Self::Narrowing => "narrowing",
            Self::Widening => "widening",
            Self::Incomparable => "incomparable",
        }
    }

    /// Whether moving to the new set widens anything (XI-4).
    #[must_use]
    pub const fn widens(self) -> bool {
        matches!(self, Self::Widening | Self::Incomparable)
    }
}

/// The relation of `new` to `old` under `catalog`.
#[must_use]
pub fn relation(old: &AuthoritySet, new: &AuthoritySet, catalog: &Catalog) -> SetRelation {
    match (subsumes(new, old, catalog), subsumes(old, new, catalog)) {
        (true, true) => SetRelation::Equivalent,
        (true, false) => SetRelation::Narrowing,
        (false, true) => SetRelation::Widening,
        (false, false) => SetRelation::Incomparable,
    }
}

/// One meta-action an admin Grant covers (§8.17.9.2).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetaLine {
    /// The meta-action.
    pub action: &'static str,
    /// Reserved (`acceptance.*`, `anchor.*`).
    pub reserved: bool,
    /// Its tier when it widens authority.
    pub tier_when_widening: Tier,
    /// Contributions the Grant's own requirements ask for.
    pub grant_quorum: u64,
    /// Further `co_root` contributions a joint root needs for it at CT3 (§13.7.3, SEC26).
    pub joint_root_quorum: u64,
}

/// An admin Grant's meta-actions one by one, reserved ones apart (§8.17.9.2). Never "full
/// access": only what the Grant covers is listed.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdminGrant {
    /// The Grant.
    pub grant: Id,
    /// Its role pin, if any.
    pub role: Option<(String, u64)>,
    /// Covered meta-actions that are not reserved.
    pub actions: Vec<MetaLine>,
    /// Covered reserved meta-actions.
    pub reserved: Vec<MetaLine>,
}

/// The admin view of Grant `grant` in the domain `view` reads; `None` when it is not there.
#[must_use]
pub fn admin_grant(view: &Snapshot, grant: &Id, now: u64) -> Option<AdminGrant> {
    let state: GrantState = read(view, kind::GRANT, grant)?;
    let set = &state.content.authority.authority;
    let catalog = catalog_of(view, &[set], now);
    let covered = catalog.covered(&set.actions);
    let grant_quorum = state
        .content
        .authority
        .requirements
        .iter()
        .filter(|t| t.proof_kind == ProofKind::Contribution)
        .fold(0_u64, |n, t| n.saturating_add(t.count));
    let mut out = AdminGrant {
        grant: *grant,
        role: state
            .content
            .named
            .as_ref()
            .map(|(n, v, _)| (n.clone(), *v)),
        actions: Vec::new(),
        reserved: Vec::new(),
    };
    for name in META_ACTIONS {
        if !covered.contains(&meta::core_action(name)) {
            continue;
        }
        let tier = widening_tier(name);
        let line = MetaLine {
            action: name,
            reserved: reserved_meta(name),
            tier_when_widening: tier,
            grant_quorum,
            joint_root_quorum: if tier == Tier::Ct3 {
                meta::CT3_QUORUM
            } else {
                0
            },
        };
        if line.reserved {
            out.reserved.push(line);
        } else {
            out.actions.push(line);
        }
    }
    Some(out)
}

impl<L: DomainLog, R: Reader, B: Binding, S: Salts> Authority<L, R, B, S> {
    /// Version `version` of role `name`, the latest when `None` (C28).
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn role(
        &self,
        name: &str,
        version: Option<u64>,
        now: u64,
    ) -> Result<Option<RoleVersion>, CoreError> {
        crate::app::publishing::settle(&self.reader, |snap| role_version(snap, name, version, now))
            .await
    }

    /// The admin view of Grant `grant` (§8.17.9.2).
    ///
    /// # Errors
    /// The reader's errors.
    pub async fn admin_grant(&self, grant: &Id, now: u64) -> Result<Option<AdminGrant>, CoreError> {
        crate::app::publishing::settle(&self.reader, |snap| admin_grant(snap, grant, now)).await
    }
}

/// The current values of `names`' latest versions, by name.
#[must_use]
pub fn latest_versions(view: &Snapshot, names: &[&str]) -> BTreeMap<String, u64> {
    names
        .iter()
        .filter_map(|n| match view.get(&authority_set_key(n, None)) {
            Some(Value::Unsigned(v)) => Some(((*n).to_owned(), v)),
            _ => None,
        })
        .collect()
}
