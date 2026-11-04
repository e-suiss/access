//! Instances the identity plane opens and ends in a governing domain (OP-62, OP-149 m.4, m.6):
//! a platform product's service Instance in each tenant, a user's device Instance from a
//! stepped-up session, and the termination of a device Instance by its own Party.

use std::collections::BTreeMap;

use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{ActorKind, ExerciseBasis, NAMESPACE, Payload};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::schema::{ActionSchema, EffectClass, action_digest};
use access_kernel::verify::cose::PublicKey;

/// The resource namespace an `instance_terminate` intent names its Instance in.
pub const INSTANCE_NAMESPACE: &str = "access.instance";

/// The intent parameter that carries the meta payload's digest.
pub const PAYLOAD_PARAM: &str = "payload";

/// A Suiss product that pairs with Access as a platform client (OP-149 m.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlatformProduct {
    /// Suiss Work.
    Work,
    /// Suiss Relay.
    Relay,
    /// Suiss One.
    One,
}

impl PlatformProduct {
    /// Every product.
    pub const ALL: [Self; 3] = [Self::Work, Self::Relay, Self::One];

    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Work => "work",
            Self::Relay => "relay",
            Self::One => "one",
        }
    }

    /// The product with this wire name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// Whose Instance is opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Registrant {
    /// A user's device, from a stepped-up session (OP-149 m.6): a human Party.
    Device {
        /// The realm.
        realm: [u8; 16],
        /// The session's subject.
        subject: [u8; 16],
    },
    /// A paired product's service in one tenant (OP-149 m.4): a system Party the identity plane
    /// service Party registers.
    Service {
        /// The product.
        product: PlatformProduct,
        /// The product's platform client.
        client: String,
    },
}

impl Registrant {
    /// The kind of actor its Party is (OP-149 m.8); fixed at `party_register`.
    #[must_use]
    pub const fn actor_kind(&self) -> ActorKind {
        match self {
            Self::Device { .. } => ActorKind::Human,
            Self::Service { .. } => ActorKind::System,
        }
    }
}

/// An Instance to open. Repeating the same registration opens nothing new: the answer is the
/// Instance the first one opened (idempotent by tenant, domain, registrant and key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The governing domain.
    pub domain: Digest,
    /// Whose Instance it is.
    pub registrant: Registrant,
    /// The Instance key: Ed25519 or P-256 (OP-149 m.14 (a)); its holder alone has the private
    /// key.
    pub key: PublicKey,
}

/// An opened Instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    /// Its Party.
    pub party: Id,
    /// The Instance.
    pub instance: Id,
    /// The key's RFC 7638 `kid` (CR-24).
    pub kid: [u8; 32],
    /// Whether an earlier identical registration had opened it.
    pub replayed: bool,
}

/// The authority plane's answer to a [`Registration`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationVerdict {
    /// Opened, now or before.
    Registered(Registered),
    /// Not opened, by stable reason code.
    Refused {
        /// Stable reason code.
        code: String,
    },
}

/// An `instance_terminate` Exercise a user's own Instance signed (OP-149 m.6, OP-146 m.4 (i)):
/// the identity plane forwards it as PEP once the session passes the step-up rule.
#[derive(Clone, Debug)]
pub struct Termination {
    /// The governing domain.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The Instance to end.
    pub instance: Id,
    /// The intent's validity.
    pub validity: Window,
    /// The basis: the actor Party's own self-anchor.
    pub basis: ExerciseBasis,
    /// The AIS over [`terminate_intent`].
    pub ais: Vec<u8>,
    /// The identity plane as PEP.
    pub pep: String,
}

/// The reference of a core meta-action (L0-META-1): the `access` namespace, major 1.
#[must_use]
pub fn core_action(name: &str) -> ActionRef {
    let schema = ActionSchema {
        name: String::from(name),
        major: 1,
        effect: EffectClass::Reversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::new(),
        resource_types: std::collections::BTreeSet::new(),
        render: None,
    };
    ActionRef {
        namespace: String::from(NAMESPACE),
        name: String::from(name),
        major: 1,
        schema: action_digest(&schema),
    }
}

/// The meta payload of a termination.
#[must_use]
pub const fn terminate_payload(instance: Id) -> Payload {
    Payload::InstanceTerminate { instance }
}

fn hex(id: &Id) -> String {
    use std::fmt::Write as _;
    id.0.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The intent a device signs to end `instance` over `validity`: `access/instance_terminate`
/// on `access.instance:[hex(instance)]`, the payload's digest in `opaque["payload"]`.
///
/// `None` when the payload cannot be encoded.
#[must_use]
pub fn terminate_intent(instance: Id, validity: Window) -> Option<IntentEnvelope> {
    let payload = terminate_payload(instance).digest().ok()?;
    Some(IntentEnvelope {
        action: core_action("instance_terminate"),
        resources: vec![ResourceRef {
            namespace: String::from(INSTANCE_NAMESPACE),
            path: vec![hex(&instance)],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: BTreeMap::from([(String::from(PAYLOAD_PARAM), payload)]),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity,
    })
}
