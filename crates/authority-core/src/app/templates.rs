//! Regulatory templates (§10.3.4, §13.4 U62, MD-11, IDP-9, OP-156 m.3 (u)): the PSD2 SCA and
//! TR GKD rules as restriction policies a domain installs with its own `policy.set`. Each is a
//! forbid-with-requirement on the domain's payment actions, so it only tightens, and the
//! decision path enforces it like any other policy. A template is data, not a mode: no action is
//! a payment until the installer names it, and nothing applies until the root commits it.
//! Whether the rules meet the regulation is the tenant's legal assessment (N-52).
//!
//! - [`Template::Psd2Sca`]: a payment needs a fresh authentication with two independent factors,
//!   bound to the payment's own intent (dynamic linking: the intent names amount and payee).
//! - [`Template::TrGkd`]: a payment of tier CT2 or CT3 needs a fresh authentication that is
//!   phishing-resistant and carries the application-controlled factor, bound to the payment's
//!   own intent. Platform biometrics alone never set that factor.
//!
//! The realm settings of the TR template (SMS only at setup, the SIM-change rule, no platform
//! biometrics as a factor) belong to the identity plane; this is the authority half.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::codec::Canonical;
use access_kernel::meta::RESTRICTION_SCHEMA;
use access_kernel::model::{
    Binding, Consumption, Independence, ProofKind, RequirementTerm, SubjectSelector,
};
use suiss_crypto::dcbor::{self, Limits, Value};

use crate::restrict::patterns::MAX_NAMES;

pub mod support;

/// The Claim class an authentication proof has (§10.1.5).
pub const AUTHENTICATION: &str = "authentication";

/// How old the authentication may be, ms.
pub const FRESHNESS_MS: u64 = 5 * 60 * 1000;

/// A regulatory template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Template {
    /// PSD2 strong customer authentication with dynamic linking.
    Psd2Sca,
    /// Türkiye ÖHY ve BS Tebliği güçlü kimlik doğrulama (GKD), the TR payment template.
    TrGkd,
}

/// What an installer names: who issues the authentications the template asks for, and which of
/// the domain's actions are payments (`namespace:name`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Install {
    /// The issuer of the domain's `authentication` Claims: the realm's issuer Party.
    pub issuer: SubjectSelector,
    /// The payment actions.
    pub actions: BTreeSet<String>,
}

/// Every template.
pub const ALL: [Template; 2] = [Template::Psd2Sca, Template::TrGkd];

impl Template {
    /// Its name, the `@id` of its policy statement.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Psd2Sca => "psd2-sca",
            Self::TrGkd => "tr-gkd",
        }
    }

    /// The template of `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        ALL.into_iter().find(|t| t.name() == name)
    }

    /// The assurance floors the authentication must meet (§10.1.6).
    #[must_use]
    pub fn floors(self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::from([(String::from("aal"), 2)]);
        // MD-11, IDP-9
        if self == Self::TrGkd {
            out.insert(String::from("phishing_resistant"), 1);
            out.insert(String::from("app_controlled_factor"), 1);
        }
        out
    }

    /// The authentication the template asks for: from `issuer`, bound to the payment's intent,
    /// fresh and used once (§10.3.4 dynamic linking).
    #[must_use]
    pub fn requirement(self, issuer: SubjectSelector) -> RequirementTerm {
        RequirementTerm {
            proof_kind: ProofKind::Claim,
            class: String::from(AUTHENTICATION),
            count: 1,
            binding: Binding::IntentDigest,
            freshness_ms: Some(FRESHNESS_MS),
            independence: Independence::None,
            consumption: Consumption::SingleUse,
            source: Some(issuer),
            assurance: self.floors(),
        }
    }

    fn condition(self, list: &str) -> String {
        match self {
            Self::Psd2Sca => format!("{list}.contains(context.action)"),
            // MD-11
            Self::TrGkd => format!("context.tier >= 2 && {list}.contains(context.action)"),
        }
    }

    /// The `policy.set` content of the template for `install`, in the domain's canonical form;
    /// `None` when an action is not a `namespace:name`, or the list is empty or too long.
    #[must_use]
    pub fn content(self, install: &Install) -> Option<Value> {
        if install.actions.is_empty()
            || install.actions.len() > MAX_NAMES
            || !install.actions.iter().all(|a| action_name(a))
        {
            return None;
        }
        let quoted: Vec<String> = install.actions.iter().map(|a| format!("\"{a}\"")).collect();
        let list = format!("[{}]", quoted.join(", "));
        let id = self.name();
        let source = format!(
            "@id(\"{id}\") @require(\"rs-{id}\") forbid(principal, action, resource) when {{ {} }};",
            self.condition(&list)
        );
        let term = self.requirement(install.issuer.clone());
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

    /// The template a stored policy content was made from, read from its statement's `@id`; the
    /// policy record itself is the record of the installation.
    #[must_use]
    pub fn of(content: &Value) -> Option<Self> {
        let Some(Value::Text(source)) = content.get("source") else {
            return None;
        };
        ALL.into_iter()
            .find(|t| source.starts_with(&format!("@id(\"{}\") ", t.name())))
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
        ns.len() <= 255
            && !ns.is_empty()
            && ns.split('.').all(|p| {
                p.bytes().next().is_some_and(|c| c.is_ascii_lowercase())
                    && p.bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
            })
            && ident(name)
    })
}

pub mod legal;
pub mod sod;
pub mod transfer;

#[cfg(test)]
mod tests {
    use super::*;
    use access_kernel::model::Id;

    fn install() -> Install {
        Install {
            issuer: SubjectSelector::Party(Id([7; 16])),
            actions: BTreeSet::from([
                String::from("pay:initiate"),
                String::from("pay:approve"),
                String::from("pay:payout"),
            ]),
        }
    }

    // U62, MD-11, IDP-9, §10.3.4, Ek B 5266
    #[test]
    fn each_template_compiles_and_only_tightens() {
        for t in ALL {
            let c = t.content(&install()).unwrap();
            assert!(
                crate::restrict::compile(&c).is_ok(),
                "{t:?} {:?}",
                crate::restrict::compile(&c).err()
            );
            assert_eq!(Template::of(&c), Some(t));
            assert_eq!(Template::parse(t.name()), Some(t));
            let term = t.requirement(SubjectSelector::Party(Id([7; 16])));
            assert_eq!(term.binding, Binding::IntentDigest);
            assert_eq!(term.consumption, Consumption::SingleUse);
            assert!(term.freshness_ms.is_some());
        }
        let tr = Template::TrGkd.floors();
        assert_eq!(tr.get("app_controlled_factor"), Some(&1));
        assert_eq!(tr.get("phishing_resistant"), Some(&1));
        assert_eq!(
            Template::Psd2Sca.floors().get("app_controlled_factor"),
            None
        );
    }

    // U62
    #[test]
    fn an_action_list_that_is_not_names_is_refused() {
        let mut bad = install();
        bad.actions = BTreeSet::from([String::from("pay:x\"]) || true || ([\"")]);
        assert!(Template::TrGkd.content(&bad).is_none());
        bad.actions = BTreeSet::new();
        assert!(Template::Psd2Sca.content(&bad).is_none());
        bad.actions = (0..=MAX_NAMES).map(|i| format!("pay:a{i}")).collect();
        assert!(Template::Psd2Sca.content(&bad).is_none());
        assert_eq!(Template::of(&Value::text("x")), None);
    }
}
