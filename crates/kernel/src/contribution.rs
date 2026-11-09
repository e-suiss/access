//! The `contribute` meta-Exercise an approver's device signs (L0-META-30, §9.14.1 A step 4,
//! OP-149 m.9, m.29 (b)): the one intent a contribution of a class to a target intent is, so
//! the approver's Instance can pre-sign its AIS before the request is pushed to the Approval
//! Surface and the identity plane commits exactly that intent as PEP.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;

use crate::digest::Digest;
use crate::intent::{ContextRefs, IntentEnvelope};
use crate::meta::{self, AnchorScope, PAYLOAD_PARAM, Payload};
use crate::model::{Id, ResourceRef, Window};

/// The resource namespace a contribution names its class in (L0-META-30).
pub const NAMESPACE: &str = "access.contribution";

/// The name of the `contribute` meta-action.
pub const ACTION: &str = "contribute";

/// The `contribute` payload for `target`.
#[must_use]
pub fn contribute_payload(target: Digest, class: &str) -> Payload {
    Payload::Contribute {
        target,
        class: String::from(class),
    }
}

/// Whether root power over an Anchor of `scope` authorizes `party`'s contribution of `class`
/// without a Grant: only `accept_root`, under the Party's own self-anchor (L0-META-30, TN-91).
#[must_use]
pub fn self_authorized(class: &str, scope: &AnchorScope, party: &Id) -> bool {
    class == meta::ACCEPT_ROOT && *scope == AnchorScope::Party(*party)
}

/// The intent an approver Instance signs for a contribution of `class` to `target` over
/// `validity` (L0-META-30): `access/contribute` on `access.contribution:[class]`, incarnation 0,
/// with the payload digest in `opaque["payload"]` and nothing else.
///
/// `None` when the payload cannot be encoded.
#[must_use]
pub fn contribute_intent(target: Digest, class: &str, validity: Window) -> Option<IntentEnvelope> {
    let digest = contribute_payload(target, class).digest().ok()?;
    Some(IntentEnvelope {
        action: meta::core_action(ACTION),
        resources: vec![ResourceRef {
            namespace: String::from(NAMESPACE),
            path: vec![String::from(class)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(String::from(PAYLOAD_PARAM), digest)]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // L0-META-30, §9.14.1
    #[test]
    fn the_contribute_intent_is_deterministic() {
        let w = Window { from: 1, until: 2 };
        let a = contribute_intent(Digest([4; 32]), "approve", w).unwrap();
        let b = contribute_intent(Digest([4; 32]), "approve", w).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.action.name, ACTION);
        assert_eq!(a.action.namespace, meta::NAMESPACE);
        assert_eq!(a.resources[0].namespace, NAMESPACE);
        assert_eq!(a.resources[0].path, ["approve"]);
        assert_eq!(
            a.opaque[PAYLOAD_PARAM],
            contribute_payload(Digest([4; 32]), "approve")
                .digest()
                .unwrap()
        );
        assert_ne!(contribute_intent(Digest([5; 32]), "approve", w).unwrap(), a);
        assert_ne!(contribute_intent(Digest([4; 32]), "witness", w).unwrap(), a);
    }

    // L0-META-30, TN-91, OP-153 m.17 (b)
    #[test]
    fn only_a_root_acceptance_is_authorized_by_the_own_self_anchor() {
        let p = Id([2; 16]);
        let own = AnchorScope::Party(p);
        assert!(self_authorized(meta::ACCEPT_ROOT, &own, &p));
        assert!(!self_authorized("approve", &own, &p));
        assert!(!self_authorized(meta::ACCEPT_ROOT, &own, &Id([3; 16])));
        assert!(!self_authorized(
            meta::ACCEPT_ROOT,
            &AnchorScope::Domain,
            &p
        ));
    }
}
