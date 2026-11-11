//! Restriction policies a domain opts into with its own `policy.set` (§13.7.6, OP-142, E54):
//! ready contents in Access's restriction schema. Each is a forbid-with-requirement, so it only
//! tightens; none applies until the domain's root commits it.
//!
//! - [`Pattern::Untrusted`]: a recipient, amount or URL whose value came from the web, mail, a
//!   document or another agent (`untrusted-external`) needs a person's approval (E54 (1)).
//! - [`Pattern::AdminApproval`]: an agent's action from a consequence tier on needs an
//!   approval from the enterprise's administrators (§11.19 enterprise row).
//! - [`Pattern::Disclosure`]: disclosing data through these actions needs the data owner's
//!   `disclose` contribution, lowering its label their `declassify` (IFC Option B, F11, SEC30).
//!   The label stays the owner's Claim; Access holds only the authority.
//! - [`Pattern::PartyTotal`], [`Pattern::ThresholdAdjacent`], [`Pattern::MassSelection`]: the
//!   structuring guards (§13.7.6, U18, OP-157 m.3 (q)), on the `derived.*` values.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::contribution::{APPROVE, DECLASSIFY, DISCLOSE};
use access_kernel::meta::RESTRICTION_SCHEMA;
use access_kernel::model::{
    Binding, Consumption, Independence, ProofKind, RequirementTerm, SubjectSelector,
};
use suiss_crypto::dcbor::{self, Limits, Value};

/// A ready policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pattern {
    /// An `untrusted-external` value in one of `params` needs `approval`.
    Untrusted {
        /// The typed parameters that name a recipient, an amount or a URL.
        params: BTreeSet<String>,
        /// The approval it needs.
        approval: RequirementTerm,
    },
    /// An agent's action of tier `min_tier` or above needs an approval from `approvers`.
    AdminApproval {
        /// The lowest tier it applies to.
        min_tier: u8,
        /// Who may approve.
        approvers: SubjectSelector,
    },
    /// Each of `actions` (`namespace:name`) needs a `disclose` contribution from `owner`, or a
    /// `declassify` one when `declassify`.
    Disclosure {
        /// The actions that disclose.
        actions: BTreeSet<String>,
        /// The data owner.
        owner: SubjectSelector,
        /// Whether the action lowers the label rather than discloses.
        declassify: bool,
    },
    /// The actor Party's consumption in the window above `limit` (in the threshold unit) needs
    /// `approval` (§13.7.6, U18).
    PartyTotal {
        /// The domain's limit.
        limit: u64,
        /// The approval it needs.
        approval: RequirementTerm,
    },
    /// The [`ADJACENT_REPEAT`]th Exercise to one target in the window within 80 % of a tier
    /// threshold needs `approval` (§13.7.6, U18).
    ThresholdAdjacent {
        /// The approval it needs.
        approval: RequirementTerm,
    },
    /// A new holder's CT2+ Exercise while more than [`MASS_NEW_HOLDERS`] Parties became holders
    /// of the same selector in the window needs `approval` (§13.7.6, U18).
    MassSelection {
        /// The approval it needs.
        approval: RequirementTerm,
    },
}

/// Threshold-adjacent Exercises to one target in the window that need an approval (§13.7.6,
/// U18, PD).
pub const ADJACENT_REPEAT: u64 = 3;

/// New holders of one selector in the window above which a new holder's CT2+ Exercise needs an
/// approval (§13.7.6, U18, PD).
pub const MASS_NEW_HOLDERS: u64 = 5;

/// A contribution of `class` bound to the exact intent, used once, from a Party other than the
/// actor's and, with `source`, from that selector only.
#[must_use]
pub fn contribution(class: &str, source: Option<SubjectSelector>) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from(class),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::DistinctParty,
        consumption: Consumption::SingleUse,
        source,
        assurance: BTreeMap::new(),
    }
}

fn ident(s: &str) -> bool {
    let mut b = s.bytes();
    b.next().is_some_and(|c| c.is_ascii_lowercase())
        && s.len() <= 63
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
}

fn action_name(s: &str) -> bool {
    s.split_once(':').is_some_and(|(ns, name)| {
        !ns.is_empty()
            && ns.len() <= 255
            && ns
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-".contains(&c))
            && ident(name)
    })
}

/// Most parameter or action names one pattern lists, within the policy cost ceiling (OP-104 m.3).
pub const MAX_NAMES: usize = 16;

fn list(items: &BTreeSet<String>) -> String {
    let quoted: Vec<String> = items.iter().map(|i| format!("\"{i}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

/// The `policy.set` content of `pattern`, in the domain's canonical form; `None` when a name
/// is not a typed parameter or action name, or a list is empty.
#[must_use]
pub fn content(pattern: &Pattern) -> Option<Value> {
    let (id, condition, term) = match pattern {
        Pattern::Untrusted { params, approval } => {
            if params.is_empty() || params.len() > MAX_NAMES || !params.iter().all(|p| ident(p)) {
                return None;
            }
            let any: Vec<String> = params
                .iter()
                .map(|p| format!("context.untrusted.contains(\"{p}\")"))
                .collect();
            ("untrusted-input", any.join(" || "), approval.clone())
        }
        Pattern::AdminApproval {
            min_tier,
            approvers,
        } => {
            if *min_tier > 3 {
                return None;
            }
            (
                "admin-approval",
                format!("context.actor == \"agent\" && context.tier >= {min_tier}"),
                contribution(APPROVE, Some(approvers.clone())),
            )
        }
        Pattern::Disclosure {
            actions,
            owner,
            declassify,
        } => {
            if actions.is_empty()
                || actions.len() > MAX_NAMES
                || !actions.iter().all(|a| action_name(a))
            {
                return None;
            }
            let class = if *declassify { DECLASSIFY } else { DISCLOSE };
            (
                class,
                format!("{}.contains(context.action)", list(actions)),
                contribution(class, Some(owner.clone())),
            )
        }
        // U18, OP-157 m.3 (q)
        Pattern::PartyTotal { limit, approval } => {
            let limit = i64::try_from(*limit).ok()?;
            (
                "party-total",
                format!("context.derived.party_consumption > {limit}"),
                approval.clone(),
            )
        }
        Pattern::ThresholdAdjacent { approval } => (
            "threshold-adjacent",
            format!("context.derived.threshold_adjacent >= {ADJACENT_REPEAT}"),
            approval.clone(),
        ),
        Pattern::MassSelection { approval } => (
            "mass-selection",
            format!(
                "context.derived.selector_transitions > {MASS_NEW_HOLDERS} && context.tier >= 2"
            ),
            approval.clone(),
        ),
    };
    let source = format!(
        "@id(\"{id}\") @require(\"rs-{id}\") forbid(principal, action, resource) when {{ {condition} }};"
    );
    let content = Value::Map(vec![
        (Value::text("schema"), Value::text(RESTRICTION_SCHEMA)),
        (Value::text("source"), Value::text(&source)),
        (Value::text("target"), Value::text("domain")),
        (
            Value::text("requirements"),
            Value::Map(vec![(
                Value::text(&format!("rs-{id}")),
                Value::Array(vec![term.to_value()]),
            )]),
        ),
    ]);
    dcbor::decode(
        &dcbor::encode(&content, Limits::CEILING).ok()?,
        Limits::CEILING,
    )
    .ok()
}

/// V1: `support-protected` (§8.16 #3, MD-9, OP-157 m.3 (c)): a forbid with no way through on
/// every `For` Exercise of a protected `idp.account` action, whatever its basis. A `For` Exercise
/// is someone acting on another's behalf; the e-mail change, the bulk export and every reserved
/// account action are the person's own. A break-glass basis passes only where a forbid rule
/// declares itself exempt. The domain installs it with its own `policy.set`.
#[must_use]
pub fn support_protected() -> Option<Value> {
    let actions: BTreeSet<String> = crate::app::templates::support::PROTECTED
        .iter()
        .map(|a| format!("{}:{}", a.namespace(), a.name()))
        .collect();
    let source = format!(
        "@id(\"support-protected\") forbid(principal, action, resource) when {{ context.capacity == \"for\" && {}.contains(context.action) }};",
        list(&actions)
    );
    let content = Value::Map(vec![
        (Value::text("schema"), Value::text(RESTRICTION_SCHEMA)),
        (Value::text("source"), Value::text(&source)),
        (Value::text("target"), Value::text("domain")),
    ]);
    dcbor::decode(
        &dcbor::encode(&content, Limits::CEILING).ok()?,
        Limits::CEILING,
    )
    .ok()
}

/// A containment or suspension, the ready restriction of a Party allowed to restrict (SI-4,
/// §6.6, §7.9.12.1, §11.9.2, OP-157 m.3 (i)). It is a blocking `forbid` without a requirement:
/// a new policy only narrows, so one `policy.set` contains at once and needs no quorum; lifting
/// it retires the policy, which widens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Containment {
    /// Every Exercise by an Instance of `party`.
    SuspendParty {
        /// The suspended Party.
        party: access_kernel::model::Id,
    },
    /// Every Exercise by `instance`.
    SuspendInstance {
        /// The suspended Instance.
        instance: access_kernel::model::Id,
    },
    /// Every Exercise of `actions` (`namespace:name`), whoever asks.
    ContainDomainAction {
        /// The contained actions.
        actions: BTreeSet<String>,
    },
}

impl Containment {
    /// Its name, the `@id` of its statement.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::SuspendParty { .. } => "suspend-party",
            Self::SuspendInstance { .. } => "suspend-instance",
            Self::ContainDomainAction { .. } => "contain-action",
        }
    }
}

fn hex(id: &access_kernel::model::Id) -> String {
    id.0.iter().fold(String::with_capacity(32), |mut out, b| {
        let _ = std::fmt::Write::write_fmt(&mut out, format_args!("{b:02x}"));
        out
    })
}

/// The `policy.set` content of `containment` on `target` (`domain`, or an Anchor's id); `None`
/// when an action is not an action name or the list is empty or too long.
#[must_use]
pub fn containment(
    containment: &Containment,
    target: Option<access_kernel::model::Id>,
) -> Option<Value> {
    let id = containment.name();
    let statement = match containment {
        Containment::SuspendParty { party } => format!(
            "@id(\"{id}\") forbid(principal is Instance, action, resource) when {{ principal.party == \"{}\" }};",
            hex(party)
        ),
        Containment::SuspendInstance { instance } => format!(
            "@id(\"{id}\") forbid(principal == Instance::\"{}\", action, resource);",
            hex(instance)
        ),
        Containment::ContainDomainAction { actions } => {
            if actions.is_empty()
                || actions.len() > MAX_NAMES
                || !actions.iter().all(|a| action_name(a))
            {
                return None;
            }
            format!(
                "@id(\"{id}\") forbid(principal, action, resource) when {{ {}.contains(context.action) }};",
                list(actions)
            )
        }
    };
    let target = match target {
        None => Value::text("domain"),
        Some(a) => Value::Map(vec![(Value::text("anchor"), a.to_value())]),
    };
    let content = Value::Map(vec![
        (Value::text("schema"), Value::text(RESTRICTION_SCHEMA)),
        (Value::text("source"), Value::text(&statement)),
        (Value::text("target"), target),
    ]);
    dcbor::decode(
        &dcbor::encode(&content, Limits::CEILING).ok()?,
        Limits::CEILING,
    )
    .ok()
}

/// V12: the object index the built-in `mapping-probation` policy takes its id from (SEC16,
/// OP-157 m.3 (r)); no Genesis or Exercise reaches it.
pub const PROBATION_SEQ: u64 = u64::MAX;

/// V12: `mapping-probation` (SEC16, §13.7.6, OP-157 m.3 (r)): a CT2+ Exercise covered only through
/// a compatibility mapping still in its probation needs an approval from another Party, bound to
/// the exact intent. `derived.mapping_pin_age_s` is −1 outside probation, so the rule reads only
/// that and the tier. Every domain has it: Kernel 0.4.1 Genesis has no policies, so the decision
/// path lays it over the domain's own.
#[must_use]
pub fn mapping_probation() -> Option<Value> {
    let source = "@id(\"mapping-probation\") @require(\"rs-mapping-probation\") forbid(principal, action, resource) when { context.derived.mapping_pin_age_s >= 0 && context.tier >= 2 };";
    let content = Value::Map(vec![
        (Value::text("schema"), Value::text(RESTRICTION_SCHEMA)),
        (Value::text("source"), Value::text(source)),
        (Value::text("target"), Value::text("domain")),
        (
            Value::text("requirements"),
            Value::Map(vec![(
                Value::text("rs-mapping-probation"),
                Value::Array(vec![contribution(APPROVE, None).to_value()]),
            )]),
        ),
    ]);
    dcbor::decode(
        &dcbor::encode(&content, Limits::CEILING).ok()?,
        Limits::CEILING,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // E54 (1), §13.7.6, OP-142, Ek B 4641, 4642, 4464
    #[test]
    fn every_pattern_compiles_against_the_restriction_schema() {
        let owner = SubjectSelector::Party(access_kernel::model::Id([4; 16]));
        for p in [
            Pattern::Untrusted {
                params: BTreeSet::from([String::from("recipient"), String::from("amount")]),
                approval: contribution(APPROVE, None),
            },
            Pattern::AdminApproval {
                min_tier: 2,
                approvers: owner.clone(),
            },
            Pattern::Disclosure {
                actions: BTreeSet::from([String::from("health.records:share")]),
                owner: owner.clone(),
                declassify: false,
            },
            Pattern::Disclosure {
                actions: BTreeSet::from([String::from("health.records:relabel")]),
                owner: owner.clone(),
                declassify: true,
            },
            Pattern::PartyTotal {
                limit: 500_000,
                approval: contribution(APPROVE, Some(owner.clone())),
            },
            Pattern::ThresholdAdjacent {
                approval: contribution(APPROVE, Some(owner.clone())),
            },
            Pattern::MassSelection {
                approval: contribution(APPROVE, Some(owner.clone())),
            },
        ] {
            let c = content(&p).unwrap();
            assert!(
                super::super::compile(&c).is_ok(),
                "{p:?} {:?}",
                super::super::compile(&c).err()
            );
        }
        assert!(
            content(&Pattern::Untrusted {
                params: BTreeSet::from([String::from("x\") || true || (\"")]),
                approval: contribution(APPROVE, None),
            })
            .is_none()
        );
        assert!(
            content(&Pattern::Disclosure {
                actions: BTreeSet::new(),
                owner: owner.clone(),
                declassify: false,
            })
            .is_none()
        );
        assert!(
            content(&Pattern::AdminApproval {
                min_tier: 4,
                approvers: owner,
            })
            .is_none()
        );
    }

    // §8.16, MD-9, OP-157 m.3 (c), Ek B 5510
    #[test]
    fn support_protected_compiles_and_names_every_protected_action() {
        let c = support_protected().unwrap();
        assert!(
            super::super::compile(&c).is_ok(),
            "{:?}",
            super::super::compile(&c).err()
        );
        let Some(Value::Text(source)) = c.get("source") else {
            panic!("source");
        };
        assert!(source.starts_with("@id(\"support-protected\") forbid"));
        assert!(!source.contains("@require"));
        for a in crate::app::templates::support::PROTECTED {
            assert!(
                source.contains(&format!("\"idp.account:{}\"", a.name())),
                "{}",
                a.name()
            );
        }
        assert!(crate::app::templates::support::PROTECTED.len() <= MAX_NAMES);
    }

    // SI-4, §6.6, §7.9.12.1, §11.9.2, OP-157 m.3 (i), Ek B 5581, 5659
    #[test]
    fn every_containment_compiles_and_only_blocks() {
        let id = access_kernel::model::Id([0xab; 16]);
        for (c, target) in [
            (Containment::SuspendParty { party: id }, None),
            (Containment::SuspendInstance { instance: id }, Some(id)),
            (
                Containment::ContainDomainAction {
                    actions: BTreeSet::from([String::from("pay.transfer:send")]),
                },
                None,
            ),
        ] {
            let v = containment(&c, target).unwrap();
            assert!(
                super::super::compile(&v).is_ok(),
                "{c:?} {:?}",
                super::super::compile(&v).err()
            );
            assert!(v.get("requirements").is_none());
            let Some(Value::Text(source)) = v.get("source") else {
                panic!("a source");
            };
            assert!(source.contains(&"ab".repeat(16)) || source.contains("pay.transfer:send"));
            assert!(!source.contains("@require") && !source.contains("@breakglass_exempt"));
        }
        assert!(
            containment(
                &Containment::ContainDomainAction {
                    actions: BTreeSet::from([String::from("x\"] || true || [\"")]),
                },
                None,
            )
            .is_none()
        );
        assert!(
            containment(
                &Containment::ContainDomainAction {
                    actions: BTreeSet::new(),
                },
                None,
            )
            .is_none()
        );
    }

    // SEC16, OP-157 m.3 (r), Ek B 5666
    #[test]
    fn mapping_probation_compiles_and_reads_only_the_pin_age_and_tier() {
        let c = mapping_probation().unwrap();
        assert!(
            super::super::compile(&c).is_ok(),
            "{:?}",
            super::super::compile(&c).err()
        );
        let Some(Value::Text(source)) = c.get("source") else {
            panic!("source");
        };
        assert!(source.contains("context.derived.mapping_pin_age_s >= 0"));
        assert!(source.contains("context.tier >= 2"));
    }
}
