//! The Genesis of an environment's governing domain (TN-111, §12.1.1 2a, §12.5.1, L0-META-7).
//!
//! An environment cannot exist without its governing domain, so creating an environment opens one. Its
//! Genesis roots the meta-anchor and the `idp` Anchor in the founding root, lets Parties
//! register and create their Instances under a Public bootstrap Grant, and accepts the `idp.*`
//! catalogs the identity plane publishes (E34, OP-141 m.35). The operator holds nothing in it
//! (INV-29); every later configuration change is an `idp.*` Exercise (MD-14).

use std::collections::{BTreeMap, BTreeSet};

use access_internal_api::idp::{
    AdminRule, GenesisOrder, NAMESPACES, PRIMARY_BINDING_CLASSES, RESOURCE_NAMESPACE,
    TENANT_ADMINISTRATION, spp,
};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
pub use access_kernel::meta::core_action;
use access_kernel::meta::{self, Root};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, Conjunct, ConstraintSet,
    DelegationTerms, EqValue, Id, ResourceSelector, Structural, SubjectSelector, Window,
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

/// The core actions the Genesis bootstrap Grant covers: a new key registers its Party, creates
/// its Instance, or recovers one as the successor a `recovery_result` names (L0-META-7, OP-153
/// m.3 (c)).
pub const BOOTSTRAP_ACTIONS: [&str; 3] = ["party_register", "instance_create", "instance_recover"];

/// The bootstrap Grant's authority (L0-META-7): what a domain opened before `instance_recover`
/// joined it is amended to (OP-153 m.13 (e)).
#[must_use]
pub fn bootstrap_authority() -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: BOOTSTRAP_ACTIONS.iter().map(|a| core_action(a)).collect(),
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
    }
}

/// L0-META-7: anyone may register a Party and create its Instances; actor-binding decides who
/// the key belongs to (§7.9.2.3), and a `recovery_result` who may recover one (OP-153 m.3 (c)).
fn bootstrap() -> Value {
    let authority = bootstrap_authority();
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
/// it: what an environment opened with that catalog was born with (OP-153 m.3 (a)).
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

/// The classes the environment issuer's default Acceptance covers: who acts, by which authenticator
/// and under which identity (§10.1.4 rule 3, §10.1.5), whether that account still stands,
/// which only narrows (§12.3.1, TN-49, Ek B K04 default DENY overlay), and which key a recovery
/// named (OP-153 m.3 (c)). In deterministic CBOR order, as a Genesis set must be.
pub const ENVIRONMENT_ISSUER_CLASSES: [&str; 5] = [
    "account_status",
    "authentication",
    "recovery_result",
    "authenticator_binding",
    "identity_binding_person",
];

/// The environment issuer's Acceptance of `recovery_result` for actor-binding alone: what a domain
/// opened before the class joined [`ENVIRONMENT_ISSUER_CLASSES`] establishes (OP-153 m.3 (c),
/// m.13 (e)).
#[must_use]
pub fn recovery_acceptance(issuer: Id) -> Value {
    issuer_acceptance(issuer, &["recovery_result"])
}

/// The default Acceptance of the environment's identity issuer: `actor-binding` only; predicate
/// input and subject selection are added explicitly (§10.1.4 rule 3, E18, OP-142).
fn environment_issuer(issuer: Id) -> Value {
    issuer_acceptance(issuer, &ENVIRONMENT_ISSUER_CLASSES)
}

fn issuer_acceptance(issuer: Id, classes: &[&str]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (
            Value::text("use"),
            Value::text(access_kernel::claim::ACTOR_BINDING),
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

/// The environment issuer's Acceptance for `classes` as predicate input (§10.1.4 rule 3, L2-CLM-3,
/// SI-5): what its `authentication` Claims prove with in an approval.
fn environment_issuer_predicates(issuer: Id, classes: &[String]) -> Value {
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

/// The core meta-actions and reads the console's Admin, Developer and Audit screens ask about,
/// by the resource namespace their intents name (OP-159 m.43 (d), m.47 (d), (k) (2)): what a tenant
/// administrator rule covers on the meta-anchor. The writes among them stay the root's (OP-141
/// m.3); the rule makes them eligible, and the audit Grant makes its holders auditors.
pub const ADMIN_RULE_META: [(&str, &[&str]); 8] = [
    (
        "access.domain",
        &[
            "authority_set_define",
            "grant_issue",
            "grant_amend",
            "grant_revoke",
            "acceptance_establish",
            "acceptance_amend",
            "policy_set",
            "instance_terminate",
            "party_depart",
            "anchor_amend",
        ],
    ),
    ("access.role", &["authority_set_define"]),
    ("access.grant", &["grant_amend", "grant_revoke"]),
    ("access.acceptance", &["acceptance_amend"]),
    ("access.instance", &["instance_terminate"]),
    ("access.party", &["party_depart"]),
    ("access.policy", &["policy_set", "policy_retire"]),
    ("access.audit", &["read", "audit_export"]),
];

/// The holder of every Grant of a tenant administrator rule (OP-159 m.47 (d)): the Parties a
/// live `tenant_administration = true` Claim selects.
#[must_use]
pub fn admin_holder() -> SubjectSelector {
    SubjectSelector::Pred(BTreeSet::from([Conjunct {
        claim_class: String::from(TENANT_ADMINISTRATION),
        value: Some(EqValue::Bool(true)),
    }]))
}

fn unbounded(actions: BTreeSet<ActionRef>, resource: ResourceSelector) -> CanonicalAuthority {
    let mut a = bootstrap_authority();
    a.authority.actions = ActionSet {
        exact: actions,
        prefix: BTreeSet::new(),
    };
    a.authority.resource = resource;
    a
}

fn rule_grant(anchor: u64, authority: &CanonicalAuthority) -> Value {
    Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(anchor)),
        (Value::text("holder"), admin_holder().to_value()),
        (Value::text("authority"), authority.to_value()),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ])
}

/// The Grant set of a tenant administrator rule over the environment `slug` (OP-159 m.47 (d),
/// (k) (4)): one Grant per meta namespace on the meta-anchor and one of `rule.actions` on the
/// `idp` Anchor over `idp:[slug]`.
#[must_use]
pub fn admin_rule_grants(slug: &str, rule: &AdminRule) -> Vec<Value> {
    let mut out: Vec<Value> = ADMIN_RULE_META
        .iter()
        .map(|(ns, names)| {
            rule_grant(
                0,
                &unbounded(
                    names.iter().map(|n| core_action(n)).collect(),
                    structural(ns, Vec::new()),
                ),
            )
        })
        .collect();
    if !rule.actions.is_empty() {
        out.push(rule_grant(
            IDP_ANCHOR,
            &unbounded(
                rule.actions.iter().cloned().collect(),
                structural(RESOURCE_NAMESPACE, vec![String::from(slug)]),
            ),
        ));
    }
    out
}

fn issuer_use(issuer: Id, use_: &str, classes: &[&str]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(use_)),
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

/// The Acceptances of a tenant administrator rule (OP-159 m.47 (d)): `subject-selection` of
/// `tenant_administration` from the primary environment's issuer and, when that issuer is
/// another environment's, its `actor-binding` of who the administrator is and its
/// `authentication` Claims as predicate input.
#[must_use]
pub fn admin_rule_acceptances(rule: &AdminRule) -> Vec<Value> {
    let mut out = vec![issuer_use(
        rule.issuer,
        access_kernel::claim::SUBJECT_SELECTION,
        &[TENANT_ADMINISTRATION],
    )];
    if rule.foreign {
        out.push(issuer_use(
            rule.issuer,
            access_kernel::claim::ACTOR_BINDING,
            &PRIMARY_BINDING_CLASSES,
        ));
        out.push(issuer_use(
            rule.issuer,
            access_kernel::claim::PREDICATE_INPUT,
            &["authentication"],
        ));
    }
    out
}

/// The position, among the Genesis Acceptances in `fields`, of the rule's `subject-selection`
/// Acceptance (OP-159 m.47 (d)): its `AcceptanceID` is `object_id(domain, ACCEPTANCE, position)`.
#[must_use]
pub fn admin_acceptance_index(fields: &BTreeMap<String, Opened>, rule: &AdminRule) -> Option<u64> {
    let wanted = admin_rule_acceptances(rule).into_iter().next()?;
    let Some(Value::Array(list)) = fields.get("acceptances").map(|o| &o.value) else {
        return None;
    };
    let at = list.iter().position(|a| *a == wanted)?;
    u64::try_from(at).ok()
}

/// The Genesis fields of an environment's new governing domain.
///
/// # Errors
/// [`CoreError::Unavailable`] without randomness; [`CoreError::Protocol`] for a root that
/// names no Party.
pub fn environment(
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
    // §13.6, SEC20, OP-158 m.3 (m)
    let mut meta_anchor = vec![(Value::text("root"), root)];
    if let Some(e) = &order.recovery {
        meta_anchor.push((Value::text("recovery"), e.to_value()));
    }
    let mut fields = vec![
        ("meta_anchor", Value::Map(meta_anchor)),
        ("anchors", set(vec![idp])?),
        (
            "grants",
            set(std::iter::once(bootstrap())
                .chain(
                    order
                        .admin_rule
                        .iter()
                        .flat_map(|r| admin_rule_grants(&order.slug, r)),
                )
                .collect())?,
        ),
        (
            "acceptances",
            set(NAMESPACES
                .iter()
                .map(|ns| schemas(ns, founder))
                .chain(order.schemas.iter().map(|p| published(p, founder)))
                .chain(order.issuer.map(environment_issuer))
                .chain(
                    order
                        .issuer
                        .filter(|_| !order.issuer_predicate_input.is_empty())
                        .map(|i| environment_issuer_predicates(i, &order.issuer_predicate_input)),
                )
                .chain(order.acceptances.iter().cloned())
                .chain(order.admin_rule.iter().flat_map(admin_rule_acceptances))
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
