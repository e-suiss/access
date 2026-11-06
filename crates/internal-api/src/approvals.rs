//! The approval behind a `contribute` Exercise between the planes (OP-62, §9.14.1 A, OP-150
//! L6): what a `REQUIRE_ACTION` left for the Approval Surface, and the contribution the surface
//! commits once the approver's single act is done. The identity plane shows the render the
//! decision point produced, never one of its own (§9.14.5 WYSIWYS, XI-8).

use std::collections::BTreeMap;

use access_kernel::combinator::Capacity;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{ExerciseBasis, Payload};
use access_kernel::model::{Id, ResourceRef, Window};

use crate::instances::{PAYLOAD_PARAM, core_action};

/// The resource namespace a contribution names its class in (L0-META-30).
pub const CONTRIBUTION_NAMESPACE: &str = "access.contribution";

/// What the decision point recorded when it asked for an approval of an intent (§9.14.1 step
/// 1, §13.7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The render digest it computed from the accepted Action Schema (§9.13.3).
    pub render_digest: Digest,
    /// The render itself, dCBOR (`access_kernel::render`), when the decision point kept it.
    pub render: Option<Vec<u8>>,
    /// The intent's consequence tier, 0 to 3.
    pub tier: u8,
}

/// A contribution the Approval Surface commits as PEP (§9.14.1 A step 4): the approver
/// Instance's AIS over [`contribute_intent`], the Approval Act Statement and the
/// `authentication` Claim bound to its digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contribution {
    /// The domain of the target request.
    pub domain: Digest,
    /// The contribution's nonce: the AAS `exercise_ref`.
    pub nonce: Vec<u8>,
    /// The target intent digest.
    pub target: Digest,
    /// The `contribute` class.
    pub class: String,
    /// The approver's basis for the class.
    pub basis: ExerciseBasis,
    /// Capacity.
    pub capacity: Capacity,
    /// The intent's validity.
    pub validity: Window,
    /// The approver Instance's AIS (`COSE_Sign1`) over the contribute intent.
    pub ais: Vec<u8>,
    /// The Approval Act Statement, dCBOR.
    pub aas: Vec<u8>,
    /// The recorded `authentication` Claim bound to H(AAS).
    pub claim: Id,
    /// The identity plane as PEP.
    pub pep: String,
}

/// The `contribute` payload for `target`.
#[must_use]
pub fn contribute_payload(target: Digest, class: &str) -> Payload {
    Payload::Contribute {
        target,
        class: String::from(class),
    }
}

/// The intent an approver Instance signs for a contribution of `class` to `target` over
/// `validity` (L0-META-30): `access/contribute` on `access.contribution:[class]` with the
/// payload digest in `opaque["payload"]`.
///
/// `None` when the payload cannot be encoded.
#[must_use]
pub fn contribute_intent(target: Digest, class: &str, validity: Window) -> Option<IntentEnvelope> {
    let digest = contribute_payload(target, class).digest().ok()?;
    Some(IntentEnvelope {
        action: core_action("contribute"),
        resources: vec![ResourceRef {
            namespace: String::from(CONTRIBUTION_NAMESPACE),
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

    // L0-META-30, §9.14.1: the contribute intent is a function of the target, the class and the
    // validity, so the approver's device and the identity plane sign and check the same digest
    #[test]
    fn the_contribute_intent_is_deterministic() {
        let w = Window { from: 1, until: 2 };
        let a = contribute_intent(Digest([4; 32]), "approve", w).unwrap();
        let b = contribute_intent(Digest([4; 32]), "approve", w).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.action.name, "contribute");
        assert_eq!(a.resources[0].namespace, CONTRIBUTION_NAMESPACE);
        assert_eq!(a.resources[0].path, ["approve"]);
        assert_eq!(
            a.opaque["payload"],
            contribute_payload(Digest([4; 32]), "approve")
                .digest()
                .unwrap()
        );
        assert_ne!(contribute_intent(Digest([5; 32]), "approve", w).unwrap(), a);
    }
}
