//! The `idp.hook.*` and `idp.webhook.*` domain actions (TN-135, TN-136, MD-14, OP-151 m.3 (i),
//! (j), m.4): the rows the realm-admin catalogue merges. Registering a hook or a webhook widens
//! what leaves the realm, so it is irreversible and CT2; retiring narrows and is CT1.

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::model::{ActionRef, Id};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};

/// The namespaces of these actions.
pub const NAMESPACES: [&str; 2] = ["idp.hook", "idp.webhook"];

/// One extension point action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExtensionAction {
    /// Registers an inline hook at one call point (TN-135): CT2.
    HookRegister,
    /// Retires an inline hook; narrowing, CT1.
    HookRetire,
    /// Registers a webhook (TN-136): CT2.
    WebhookRegister,
    /// Changes a webhook's URL or events, or rotates its key: CT2.
    WebhookUpdate,
    /// Retires a webhook; narrowing, CT1.
    WebhookRetire,
}

impl ExtensionAction {
    /// Every action, in catalogue order.
    pub const ALL: [Self; 5] = [
        Self::HookRegister,
        Self::HookRetire,
        Self::WebhookRegister,
        Self::WebhookUpdate,
        Self::WebhookRetire,
    ];

    /// Its namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::HookRegister | Self::HookRetire => "idp.hook",
            Self::WebhookRegister | Self::WebhookUpdate | Self::WebhookRetire => "idp.webhook",
        }
    }

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HookRegister | Self::WebhookRegister => "register",
            Self::WebhookUpdate => "update",
            Self::HookRetire | Self::WebhookRetire => "retire",
        }
    }

    /// `namespace.name`, the label the identity plane records with its configuration.
    #[must_use]
    pub fn label(self) -> String {
        format!("{}.{}", self.namespace(), self.name())
    }

    /// The action with this label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.label() == label)
    }

    /// What it does to the world (§9.13.3).
    #[must_use]
    pub const fn effect(self) -> EffectClass {
        match self {
            Self::HookRetire | Self::WebhookRetire => EffectClass::Reversible,
            _ => EffectClass::Irreversible,
        }
    }

    /// None of these is reserved; registration is CT2, not CT3.
    #[must_use]
    pub const fn reserved(self) -> bool {
        false
    }

    /// Its Action Schema.
    #[must_use]
    pub fn schema(self) -> ActionSchema {
        ActionSchema {
            name: String::from(self.name()),
            major: 1,
            effect: self.effect(),
            reserved: self.reserved(),
            consumption_bearing: false,
            params: BTreeMap::new(),
            resource_types: BTreeSet::new(),
            render: None,
        }
    }

    /// The reference an intent names it by.
    #[must_use]
    pub fn action_ref(self) -> ActionRef {
        ActionRef {
            namespace: String::from(self.namespace()),
            name: String::from(self.name()),
            major: 1,
            schema: action_digest(&self.schema()),
        }
    }
}

/// The SPP of one of [`NAMESPACES`], published by `publisher` (OP-141 m.35 (a)).
#[must_use]
pub fn spp(namespace: &str, publisher: Id) -> Spp {
    Spp {
        publisher,
        namespace: String::from(namespace),
        catalog_version: access_internal_api::idp::CATALOG_VERSION,
        actions: ExtensionAction::ALL
            .into_iter()
            .filter(|a| a.namespace() == namespace)
            .map(ExtensionAction::schema)
            .collect(),
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.3 (i), (j), m.4: the names are exactly these; registration is CT2 and retiring
    // narrows
    #[test]
    fn extension_actions_are_named_and_tiered() {
        let labels: Vec<String> = ExtensionAction::ALL.iter().map(|a| a.label()).collect();
        assert_eq!(
            labels,
            [
                "idp.hook.register",
                "idp.hook.retire",
                "idp.webhook.register",
                "idp.webhook.update",
                "idp.webhook.retire",
            ]
        );
        for a in ExtensionAction::ALL {
            assert_eq!(ExtensionAction::from_label(&a.label()), Some(a));
            assert!(!a.reserved());
            assert!(NAMESPACES.contains(&a.namespace()));
            assert!(
                access_internal_api::idp::IdpAction::from_label(&a.label()).is_none(),
                "M1 merges the catalogue; no label is defined twice"
            );
        }
        assert_eq!(
            ExtensionAction::HookRegister.effect(),
            EffectClass::Irreversible
        );
        assert_eq!(
            ExtensionAction::WebhookRetire.effect(),
            EffectClass::Reversible
        );
        let s = spp("idp.webhook", Id([1; 16]));
        assert_eq!(s.actions.len(), 3);
    }
}
