//! The `idp.hook.*` and `idp.webhook.*` domain actions (TN-135, TN-136, MD-14, OP-151 m.3 (i),
//! (j), m.4): the rows the realm-admin catalogue merges. Registering a hook or a webhook widens
//! what leaves the realm, so it is irreversible and CT2; retiring narrows and is CT1.

use access_internal_api::idp::IdpAction;
use access_kernel::model::{ActionRef, Id};
use access_kernel::schema::{ActionSchema, EffectClass, Spp};

/// The namespaces of these actions, a part of the `idp.*` catalogue
/// ([`access_internal_api::idp::NAMESPACES`]).
pub const NAMESPACES: [&str; 2] = ["idp.hook", "idp.webhook"];

/// One extension point action: a view of its [`IdpAction`], which alone defines its name,
/// effect and schema (OP-151 m.4: the realm-admin catalogue holds every `idp.*` row).
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

    /// The catalogue action it is.
    #[must_use]
    pub const fn idp(self) -> IdpAction {
        match self {
            Self::HookRegister => IdpAction::HookRegister,
            Self::HookRetire => IdpAction::HookRetire,
            Self::WebhookRegister => IdpAction::WebhookRegister,
            Self::WebhookUpdate => IdpAction::WebhookUpdate,
            Self::WebhookRetire => IdpAction::WebhookRetire,
        }
    }

    /// Its namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        self.idp().namespace()
    }

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.idp().name()
    }

    /// `namespace.name`, the label the identity plane records with its configuration.
    #[must_use]
    pub fn label(self) -> String {
        self.idp().label()
    }

    /// The action with this label.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.label() == label)
    }

    /// What it does to the world (§9.13.3).
    #[must_use]
    pub const fn effect(self) -> EffectClass {
        self.idp().effect()
    }

    /// None of these is reserved; registration is CT2, not CT3.
    #[must_use]
    pub const fn reserved(self) -> bool {
        self.idp().reserved()
    }

    /// Its Action Schema.
    #[must_use]
    pub fn schema(self) -> ActionSchema {
        self.idp().schema()
    }

    /// The reference an intent names it by.
    #[must_use]
    pub fn action_ref(self) -> ActionRef {
        self.idp().action_ref()
    }
}

/// The SPP of one of [`NAMESPACES`], published by `publisher` (OP-141 m.35 (a)): the
/// catalogue's own.
#[must_use]
pub fn spp(namespace: &str, publisher: Id) -> Spp {
    access_internal_api::idp::spp(namespace, publisher)
}

#[cfg(test)]
mod tests {
    use super::*;

    // OP-151 m.3 (i), (j), m.4, m.10 (d)
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
            assert_eq!(
                IdpAction::from_label(&a.label()),
                Some(a.idp()),
                "the realm-admin catalogue defines every label once"
            );
            assert!(access_internal_api::idp::NAMESPACES.contains(&a.namespace()));
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
