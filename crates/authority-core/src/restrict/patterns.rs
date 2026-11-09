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
}

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
}
