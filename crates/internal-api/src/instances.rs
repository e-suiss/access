//! Instances the identity plane opens and ends in a governing domain (OP-62, OP-149 m.4, m.6):
//! a platform product's service Instance in each tenant, a user's device Instance from a
//! stepped-up session, and the termination of a device Instance by its own Party.
//!
//! Registration is self-signed (OP-149 m.16 (a), L0-META-7): `party_register` and
//! `instance_create` are Exercises the new key signs itself under the Genesis bootstrap Grant,
//! so the signature is the proof of possession. The identity plane checks who may hold the
//! Party, binds the key to it for the commit and forwards the Exercises; Access never holds the
//! private key.

use std::collections::BTreeMap;

use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{self, ActorKind, ExerciseBasis, NAMESPACE, Payload, kind};
use access_kernel::model::{ActionRef, Id, ResourceRef, Window};
use access_kernel::schema::{ActionSchema, EffectClass, action_digest};
use access_kernel::verify::cose::PublicKey;

/// The resource namespace an `instance_terminate` intent names its Instance in.
pub const INSTANCE_NAMESPACE: &str = "access.instance";

/// The intent parameter that carries the meta payload's digest.
pub const PAYLOAD_PARAM: &str = "payload";

/// The resource namespace a self-signed registration intent names its Party in.
pub const PARTY_NAMESPACE: &str = "access.party";

/// Index of the Genesis bootstrap Grant among the Genesis objects (L0-META-7, TN-111).
pub const BOOTSTRAP_GRANT: u64 = 0;

/// Appended to a challenge to form the `party_register` nonce; `instance_create` uses the
/// challenge itself (OP-149 m.16 (a)).
pub const REGISTER_NONCE_SUFFIX: u8 = 0x01;

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
    /// A realm's identity Claim issuer (§10.1.7, OP-150 L2): a system Party whose Instance is
    /// the realm's Claim issuer key, the issuer the governing domain's default Acceptance names.
    ClaimIssuer {
        /// The realm.
        realm: [u8; 16],
    },
}

impl Registrant {
    /// The kind of actor its Party is (OP-149 m.8); fixed at `party_register`.
    #[must_use]
    pub const fn actor_kind(&self) -> ActorKind {
        match self {
            Self::Device { .. } => ActorKind::Human,
            Self::Service { .. } | Self::ClaimIssuer { .. } => ActorKind::System,
        }
    }
}

/// One meta Exercise the new key signed: commit mode, capacity `own`, the bootstrap basis of
/// the domain and the intent [`self_signed_intent`] forms (OP-149 m.16 (a)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfSigned {
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent's validity.
    pub validity: Window,
    /// The AIS (`COSE_Sign1`) by the new key.
    pub ais: Vec<u8>,
}

/// An Instance to open from Exercises its own key signed. Repeating the same registration opens
/// nothing new: the answer is the Instance the first one opened (the nonces replay).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registration {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The governing domain.
    pub domain: Digest,
    /// Whose Instance it is.
    pub registrant: Registrant,
    /// The Party the Instance belongs to.
    pub party: Id,
    /// The Instance key: Ed25519 or P-256 (OP-149 m.14 (a)); its holder alone has the private
    /// key.
    pub key: PublicKey,
    /// `party_register`, when the Party is new.
    pub register: Option<SelfSigned>,
    /// `instance_create`.
    pub create: SelfSigned,
    /// The identity plane as PEP.
    pub pep: String,
}

impl Registration {
    /// The `party_register` payload: the Party roots itself and is of the registrant's kind.
    #[must_use]
    pub fn register_payload(&self) -> Payload {
        Payload::PartyRegister {
            party: self.party,
            root: meta::Root::Sole(self.party),
            actor_kind: self.registrant.actor_kind(),
        }
    }

    /// The `instance_create` payload.
    #[must_use]
    pub fn create_payload(&self) -> Payload {
        Payload::InstanceCreate {
            party: self.party,
            key: self.key.clone(),
            mandate: None,
        }
    }

    /// The Instance `instance_create` opens: the first object of its Exercise.
    ///
    /// `None` when the nonce cannot be encoded.
    #[must_use]
    pub fn instance(&self) -> Option<Id> {
        let exercise = meta::exercise_id(&self.domain, &self.create.nonce).ok()?;
        Some(meta::object_id(&exercise, kind::INSTANCE, 0))
    }
}

/// The basis a self-signed registration names: the Genesis bootstrap Grant of `domain`, held
/// by the public (L0-META-7).
#[must_use]
pub fn bootstrap_basis(domain: &Digest) -> ExerciseBasis {
    ExerciseBasis::Public(meta::object_id(domain, kind::GRANT, BOOTSTRAP_GRANT))
}

/// The `party_register` nonce of a registration answering `challenge`.
#[must_use]
pub fn register_nonce(challenge: &[u8]) -> Vec<u8> {
    let mut n = challenge.to_vec();
    n.push(REGISTER_NONCE_SUFFIX);
    n
}

/// The intent the new key signs for `payload` (`party_register` or `instance_create`) of
/// `party` over `validity`: `access/<action>` on `access.party:[hex(party)]`, the payload's
/// digest in `opaque["payload"]`.
///
/// `None` when the payload cannot be encoded.
#[must_use]
pub fn self_signed_intent(
    payload: &Payload,
    party: Id,
    validity: Window,
) -> Option<IntentEnvelope> {
    let digest = payload.digest().ok()?;
    Some(IntentEnvelope {
        action: core_action(payload.action()),
        resources: vec![ResourceRef {
            namespace: String::from(PARTY_NAMESPACE),
            path: vec![hex(&party)],
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
