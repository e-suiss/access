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
use access_kernel::meta::{self, Root};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
    ResourceSelector, Structural, SubjectSelector, Window,
};
use access_kernel::record::Opened;
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

fn structural(namespace: &str) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: String::from(namespace),
        prefix: Vec::new(),
        kind: None,
        attrs: BTreeMap::new(),
    })
}

/// The reference of a core meta-action in Genesis Grants and in the intents that use them.
#[must_use]
pub fn core_action(name: &str) -> ActionRef {
    let schema = access_kernel::schema::ActionSchema {
        name: String::from(name),
        major: 1,
        effect: access_kernel::schema::EffectClass::Reversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::new(),
        resource_types: BTreeSet::new(),
        render: None,
    };
    ActionRef {
        namespace: String::from(meta::NAMESPACE),
        name: String::from(name),
        major: 1,
        schema: access_kernel::schema::action_digest(&schema),
    }
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
            resource: structural("access.party"),
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

/// OP-141 m.35 (c): the `schema-definition` Acceptance of one `idp.*` namespace.
fn schemas(namespace: &str, founder: Id) -> Value {
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
        (Value::text("spp"), spp(namespace, founder).to_value()),
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
    let root = root_value(&order.root);
    let idp = Value::Map(vec![
        (
            Value::text("scope"),
            Value::Map(vec![(
                Value::text("resource"),
                structural(RESOURCE_NAMESPACE).to_value(),
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
            set(NAMESPACES.iter().map(|ns| schemas(ns, founder)).collect())?,
        ),
        (
            "versions",
            Value::Map(vec![
                (Value::text("core"), Value::Unsigned(1)),
                (Value::text("meta_schema"), Value::Unsigned(1)),
            ]),
        ),
    ];
    // OP-141 m.34 (d)
    if let Some(delay) = order.ct3_delay_s {
        fields.push((
            "policy",
            Value::Map(vec![(Value::text("ct3_delay_s"), Value::Unsigned(delay))]),
        ));
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
