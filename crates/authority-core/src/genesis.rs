//! The Genesis of a realm's governing domain (TN-111, §12.1.1 2a, §12.5.1, L0-META-7).
//!
//! A realm cannot exist without its governing domain, so creating a realm opens one. Its
//! Genesis roots the meta-anchor and the `idp` Anchor in the founding root, lets Parties
//! register and create their Instances under a Public bootstrap Grant, and accepts the `idp.*`
//! catalogs the identity plane publishes (E34, OP-141 m.35). The operator holds nothing in it
//! (INV-29); every later configuration change is an `idp.*` Exercise (MD-14).

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::idp::{GenesisOrder, NAMESPACES, RESOURCE_NAMESPACE, spp};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
pub use access_kernel::meta::core_action;
use access_kernel::meta::{self, Root};
use access_kernel::model::{
    ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, SubjectSelector, Window,
};
use access_kernel::record::Opened;
use access_kernel::schema::Spp;
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::CoreError;
use crate::ports::Salts;

/// Index of the `idp` Anchor among the Genesis Anchors; the meta-anchor is 0.
pub const IDP_ANCHOR: u64 = 1;

/// Index of the Public bootstrap Grant.
pub const BOOTSTRAP_GRANT: u64 = 0;

fn root_value(r: &Root) -> Value {
    match r {
        Root::Sole(p) => Value::Map(vec![(Value::text("sole"), p.to_value())]),
        Root::Joint { parties, k } => Value::Map(vec![(
            Value::text("joint"),
            Value::Map(vec![
                (Value::text("k"), Value::Unsigned(*k)),
                (
                    Value::text("parties"),
                    Value::Array(parties.iter().map(Canonical::to_value).collect()),
                ),
            ]),
        )]),
    }
}

/// The Party that publishes and accepts the catalogs: the founding root, or the first of a
/// joint root.
fn founder(r: &Root) -> Option<Id> {
    match r {
        Root::Sole(p) => Some(*p),
        Root::Joint { parties, .. } => parties.first().copied(),
    }
}

/// A set in canonical order (bytewise over the encodings).
fn set(items: Vec<Value>) -> Result<Value, CoreError> {
    let mut keyed = items
        .into_iter()
        .map(|v| {
            dcbor::encode(&v, Limits::CEILING)
                .map(|b| (b, v))
                .map_err(|_| CoreError::Protocol("genesis"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(Value::Array(keyed.into_iter().map(|(_, v)| v).collect()))
}

fn structural(namespace: &str, prefix: Vec<String>) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: String::from(namespace),
        prefix,
        kind: None,
        attrs: BTreeMap::new(),
    })
}

/// L0-META-7: anyone may register a Party and create its Instances; actor-binding decides who
/// the key belongs to (§7.9.2.3).
fn bootstrap() -> Value {
    let authority = CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([
                    core_action("party_register"),
                    core_action("instance_create"),
                ]),
                prefix: BTreeSet::new(),
            },
            resource: structural("access.party", Vec::new()),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth: 0,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::new(),
    };
    Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(0)),
        (Value::text("holder"), SubjectSelector::Public.to_value()),
        (Value::text("authority"), authority.to_value()),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ])
}

/// OP-141 m.35 (c): the `schema-definition` Acceptance of one `idp.*` namespace in its current
/// catalog: what a Genesis is born with, and what a root-signed `acceptance_establish` adds to a
/// domain opened with an older catalog (OP-151 m.18 (g)).
#[must_use]
pub fn schemas(namespace: &str, founder: Id) -> Value {
    published(&spp(namespace, founder), founder)
}

/// The `schema-definition` Acceptance of one `idp.*` namespace as catalog `version` declared
/// it: what a realm opened with that catalog was born with (OP-153 m.3 (a)).
#[must_use]
pub fn schemas_at(namespace: &str, founder: Id, version: u64) -> Value {
    published(
        &access_internal_api::idp::spp_at(namespace, founder, version),
        founder,
    )
}

/// OP-141 m.35 (c): the `schema-definition` Acceptance by `founder` of the catalog `package`.
fn published(package: &Spp, founder: Id) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), founder.to_value()),
        (Value::text("use"), Value::text("schema-definition")),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text("action_schema")]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
        (Value::text("spp"), package.to_value()),
    ])
}

/// The classes the realm issuer's default Acceptance covers: who acts, by which authenticator
/// and under which identity (§10.1.4 rule 3, §10.1.5), and whether that account still stands,
/// which only narrows (§12.3.1, TN-49, Ek B K04 default DENY overlay).
pub const REALM_ISSUER_CLASSES: [&str; 4] = [
    "account_status",
    "authentication",
    "authenticator_binding",
    "identity_binding_person",
];

/// The default Acceptance of the realm's identity issuer: `actor-binding` only; predicate
/// input and subject selection are added explicitly (§10.1.4 rule 3, E18, OP-142).
fn realm_issuer(issuer: Id) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::ACTOR_BINDING),
        ),
        (
            Value::text("classes"),
            Value::Array(
                REALM_ISSUER_CLASSES
                    .iter()
                    .map(|c| Value::text(c))
                    .collect(),
            ),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// The realm issuer's Acceptance for `classes` as predicate input (§10.1.4 rule 3, L2-CLM-3,
/// SI-5): what its `authentication` Claims prove with in an approval.
fn realm_issuer_predicates(issuer: Id, classes: &[String]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::PREDICATE_INPUT),
        ),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// The Genesis fields of a realm's new governing domain.
///
/// # Errors
/// [`CoreError::Unavailable`] without randomness; [`CoreError::Protocol`] for a root that
/// names no Party.
pub fn realm(
    order: &GenesisOrder,
    salts: &mut impl Salts,
) -> Result<BTreeMap<String, Opened>, CoreError> {
    let founder = founder(&order.root).ok_or(CoreError::Protocol("genesis-root"))?;
    // OP-141 m.35 (c)
    let mut namespaces: BTreeSet<&str> = NAMESPACES.iter().copied().collect();
    namespaces.insert(meta::NAMESPACE);
    for package in &order.schemas {
        if package.publisher != founder || !namespaces.insert(package.namespace.as_str()) {
            return Err(CoreError::Protocol("genesis-schema"));
        }
    }
    if order.slug.is_empty() {
        return Err(CoreError::Protocol("genesis-slug"));
    }
    // L0-META-5, L2-CLM-3
    if order
        .acceptances
        .iter()
        .any(|a| access_kernel::claim::Gate::of(a).is_err())
    {
        return Err(CoreError::Protocol("genesis-acceptance"));
    }
    let root = root_value(&order.root);
    // MD-5a, TN-1
    let idp = Value::Map(vec![
        (
            Value::text("scope"),
            Value::Map(vec![(
                Value::text("resource"),
                structural(RESOURCE_NAMESPACE, vec![order.slug.clone()]).to_value(),
            )]),
        ),
        (Value::text("root"), root.clone()),
    ]);
    let mut fields = vec![
        ("meta_anchor", Value::Map(vec![(Value::text("root"), root)])),
        ("anchors", set(vec![idp])?),
        ("grants", set(vec![bootstrap()])?),
        (
            "acceptances",
            set(NAMESPACES
                .iter()
                .map(|ns| schemas(ns, founder))
                .chain(order.schemas.iter().map(|p| published(p, founder)))
                .chain(order.issuer.map(realm_issuer))
                .chain(
                    order
                        .issuer
                        .filter(|_| !order.issuer_predicate_input.is_empty())
                        .map(|i| realm_issuer_predicates(i, &order.issuer_predicate_input)),
                )
                .chain(order.acceptances.iter().cloned())
                .collect())?,
        ),
        (
            "versions",
            Value::Map(vec![
                (Value::text("core"), Value::Unsigned(1)),
                (Value::text("meta_schema"), Value::Unsigned(1)),
            ]),
        ),
    ];
    // OP-141 m.34 (d), OP-152 m.7 (d) E11
    let mut policy = Vec::new();
    if let Some(delay) = order.ct3_delay_s {
        policy.push((Value::text(meta::CT3_DELAY), Value::Unsigned(delay)));
    }
    if order.causal_binding {
        policy.push((Value::text(meta::CAUSAL_BINDING), Value::Bool(true)));
    }
    if !policy.is_empty() {
        fields.push(("policy", Value::Map(policy)));
    }
    fields
        .into_iter()
        .map(|(k, value)| {
            Ok((
                String::from(k),
                Opened {
                    value,
                    salt: salts.salt()?,
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests;
