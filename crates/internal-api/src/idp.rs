//! The `idp.*` write path between the planes (MD-14, E34, EI-25, OP-146 I10): the actions the
//! identity plane publishes, the Exercise it sends as PEP, the committed decision it binds its
//! configuration to, and the Genesis a new realm's governing domain is opened with (TN-111).

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::combinator::{Capacity, Decision};
use access_kernel::digest::Digest;
use access_kernel::intent::IntentEnvelope;
use access_kernel::meta::{ExerciseBasis, Root};
use access_kernel::model::{ActionRef, Id};
use access_kernel::schema::{ActionSchema, EffectClass, Spp, action_digest};

/// The resource namespace every `idp.*` action addresses: `[slug, kind, …]` paths.
pub const RESOURCE_NAMESPACE: &str = "idp";

/// Version of every `idp.*` catalog.
pub const CATALOG_VERSION: u64 = 1;

/// The `idp.*` action namespaces, one SPP each (OP-141 m.35).
pub const NAMESPACES: [&str; 6] = [
    "idp.account",
    "idp.client",
    "idp.group",
    "idp.mapper",
    "idp.realm",
    "idp.upstream",
];

/// One `idp.*` domain action. Its Consequence Tier follows from its Action Schema (OP-141
/// m.34 (a), m.35 (g)): reserved is CT3, irreversible at least CT2, reversible CT1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IdpAction {
    /// Registers a client (TN-15, §12.1.2): CT2.
    ClientRegister,
    /// Replaces a client's name, authentication method and redirect URIs: CT2.
    ClientUpdate,
    /// Retires a client; narrowing, CT1.
    ClientRetire,
    /// Changes the realm's client and CIMD acceptance policy (§11.3, AG-4): CT2.
    CimdPolicy,
    /// Sets a token claim from a profile attribute (TN-117): CT2.
    MapperSet,
    /// Sets the realm's JOSE signing algorithm (OP-146 m.8 (e)): CT2.
    RealmJoseAlg,
    /// Raises the realm's Argon2id parameters (OP-33, §17.5.2); narrowing, CT1.
    RealmArgon2,
    /// Pins or changes the realm's RP ID (IDP-5, IDI-4): reserved, irreversible, CT3.
    RealmRpId,
    /// Moves the realm to another governing domain (§12.1.1 2a): reserved, CT3.
    RealmRehome,
    /// Registers an upstream identity provider (TN-95): reserved, CT3.
    UpstreamRegister,
    /// Maps upstream groups or claims onto realm membership (TN-117, L6): reserved, CT3.
    UpstreamMapping,
    /// Changes the realm's login branding: name, logo, colours and the hosted page's CSP
    /// origins (TN-106, §12.4.2): CT2.
    RealmBranding,
    /// Changes the realm's JOSE key rotation policy (TN-118, §12.1.2): reserved, CT3.
    RealmKeyPolicy,
    /// Rotates the realm's active JOSE key now, outside the schedule (TN-118): reserved, CT3.
    RealmKeyRotate,
    /// Drops a realm JOSE key at once, as on compromise (§13.2): narrowing, CT1 (§13.7.1).
    RealmKeyDrop,
    /// Erases an account for good by crypto-shredding (OP-73, TN-118): reserved, CT3.
    AccountDelete,
    /// Suspends an account: it cannot sign in until reactivated (§12.3.1); narrowing, CT1.
    AccountSuspend,
    /// Reactivates a suspended account (§12.3.1): CT2.
    AccountReactivate,
    /// Replaces a confidential client's secret; the old one stays valid for the overlap window
    /// (CR-38): CT2.
    ClientSecretRotate,
    /// Creates a group with its one membership issuer (TN-117): CT2.
    GroupCreate,
    /// Renames a group: CT2.
    GroupUpdate,
    /// Retires a group and ends its memberships; narrowing, CT1.
    GroupRetire,
    /// Adds members to a group whose membership issuer is the realm's administration (TN-117):
    /// CT2.
    GroupMembersAdd,
    /// Removes members from such a group; narrowing, CT1.
    GroupMembersRemove,
    /// Replaces an upstream identity provider's registration (TN-95): reserved, CT3.
    UpstreamUpdate,
    /// Retires an upstream identity provider; narrowing, CT1.
    UpstreamRetire,
    /// Sets the realm's sign-in requirements: methods, required fields, MFA, registration
    /// domain lists (TN-132): CT2.
    RealmSigninPolicy,
    /// Sets the realm's console session policy (TN-129, OP-151 m.3 (f)): CT2.
    RealmSessionPolicy,
    /// Tightens the realm's protection mode: monitor to enforce, a later SL2 stage, more denied
    /// ASNs (OP-151 m.3 (o), m.14 (f)); narrowing, CT1.
    RealmProtectionMode,
    /// Changes the realm's protection mode so that anything loosens (OP-151 m.14 (f)): CT2.
    RealmProtectionModeLoosen,
    /// Makes an account a canary: a credential the realm plants (§4.4, OP-151 m.14 (f)): CT2.
    AccountCanary,
}

impl IdpAction {
    /// Every action, in catalog order.
    pub const ALL: [Self; 31] = [
        Self::ClientRegister,
        Self::ClientUpdate,
        Self::ClientRetire,
        Self::CimdPolicy,
        Self::MapperSet,
        Self::RealmJoseAlg,
        Self::RealmArgon2,
        Self::RealmRpId,
        Self::RealmRehome,
        Self::UpstreamRegister,
        Self::UpstreamMapping,
        Self::RealmBranding,
        Self::RealmKeyPolicy,
        Self::RealmKeyRotate,
        Self::RealmKeyDrop,
        Self::AccountDelete,
        Self::AccountSuspend,
        Self::AccountReactivate,
        Self::ClientSecretRotate,
        Self::GroupCreate,
        Self::GroupUpdate,
        Self::GroupRetire,
        Self::GroupMembersAdd,
        Self::GroupMembersRemove,
        Self::UpstreamUpdate,
        Self::UpstreamRetire,
        Self::RealmSigninPolicy,
        Self::RealmSessionPolicy,
        Self::RealmProtectionMode,
        Self::RealmProtectionModeLoosen,
        Self::AccountCanary,
    ];

    /// Its namespace.
    #[must_use]
    pub const fn namespace(self) -> &'static str {
        match self {
            Self::ClientRegister
            | Self::ClientUpdate
            | Self::ClientRetire
            | Self::CimdPolicy
            | Self::ClientSecretRotate => "idp.client",
            Self::GroupCreate
            | Self::GroupUpdate
            | Self::GroupRetire
            | Self::GroupMembersAdd
            | Self::GroupMembersRemove => "idp.group",
            Self::MapperSet => "idp.mapper",
            Self::RealmJoseAlg
            | Self::RealmArgon2
            | Self::RealmRpId
            | Self::RealmRehome
            | Self::RealmBranding
            | Self::RealmKeyPolicy
            | Self::RealmKeyRotate
            | Self::RealmKeyDrop
            | Self::RealmSigninPolicy
            | Self::RealmSessionPolicy
            | Self::RealmProtectionMode
            | Self::RealmProtectionModeLoosen => "idp.realm",
            Self::UpstreamRegister
            | Self::UpstreamMapping
            | Self::UpstreamUpdate
            | Self::UpstreamRetire => "idp.upstream",
            Self::AccountDelete
            | Self::AccountSuspend
            | Self::AccountReactivate
            | Self::AccountCanary => "idp.account",
        }
    }

    /// Its name within the namespace.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ClientRegister | Self::UpstreamRegister => "register",
            Self::ClientUpdate | Self::GroupUpdate | Self::UpstreamUpdate => "update",
            Self::ClientRetire | Self::GroupRetire | Self::UpstreamRetire => "retire",
            Self::ClientSecretRotate => "secret_rotate",
            Self::GroupCreate => "create",
            Self::GroupMembersAdd => "members_add",
            Self::GroupMembersRemove => "members_remove",
            Self::AccountSuspend => "suspend",
            Self::AccountReactivate => "reactivate",
            Self::RealmSigninPolicy => "signin_policy",
            Self::RealmSessionPolicy => "session_policy",
            Self::CimdPolicy => "cimd_policy",
            Self::MapperSet => "set",
            Self::RealmJoseAlg => "jose_alg",
            Self::RealmArgon2 => "argon2",
            Self::RealmRpId => "rp_id",
            Self::RealmRehome => "rehome",
            Self::UpstreamMapping => "mapping",
            Self::RealmBranding => "branding",
            Self::RealmKeyPolicy => "key_policy",
            Self::RealmKeyRotate => "key_rotate",
            Self::RealmKeyDrop => "key_drop",
            Self::AccountDelete => "delete",
            Self::RealmProtectionMode => "protection_mode",
            Self::RealmProtectionModeLoosen => "protection_mode_loosen",
            Self::AccountCanary => "canary",
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
            Self::ClientRetire
            | Self::RealmArgon2
            | Self::RealmKeyDrop
            | Self::GroupRetire
            | Self::GroupMembersRemove
            | Self::AccountSuspend
            | Self::UpstreamRetire
            | Self::RealmProtectionMode => EffectClass::Reversible,
            _ => EffectClass::Irreversible,
        }
    }

    /// Reserved: only an express Grant covers it, and it is CT3 (§13.7.1).
    #[must_use]
    pub const fn reserved(self) -> bool {
        matches!(
            self,
            Self::RealmRpId
                | Self::RealmRehome
                | Self::UpstreamRegister
                | Self::UpstreamMapping
                | Self::UpstreamUpdate
                | Self::RealmKeyPolicy
                | Self::RealmKeyRotate
                | Self::AccountDelete
        )
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

/// The SPP of one `idp.*` namespace, published by `publisher` (OP-141 m.35 (a)).
#[must_use]
pub fn spp(namespace: &str, publisher: Id) -> Spp {
    Spp {
        publisher,
        namespace: String::from(namespace),
        catalog_version: CATALOG_VERSION,
        actions: IdpAction::ALL
            .into_iter()
            .filter(|a| a.namespace() == namespace)
            .map(IdpAction::schema)
            .collect(),
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// An `idp.*` Exercise the identity plane sends as PEP (MD-14): the intent it built from the
/// change and the actor's statement over it.
#[derive(Clone, Debug)]
pub struct Submission {
    /// The realm's governing domain.
    pub domain: Digest,
    /// The Exercise nonce.
    pub nonce: Vec<u8>,
    /// The intent; its `opaque["change"]` is the change digest (EI-25).
    pub intent: IntentEnvelope,
    /// Declared basis.
    pub basis: ExerciseBasis,
    /// Declared capacity.
    pub capacity: Capacity,
    /// The actor's AIS over the intent.
    pub ais: Vec<u8>,
    /// The identity plane as PEP.
    pub pep: String,
    /// The Party the identity plane bound the requesting session's subject to (§13.4 G54,
    /// OP-149 m.16 (a)): the Exercise is refused with [`ACTOR_BINDING`] unless a live Instance
    /// of that Party signed its AIS. `None` only for the operator's own root key, which has no
    /// session.
    pub actor: Option<Id>,
}

/// Stable code of an `idp.*` Exercise whose AIS no live Instance of the session's Party signed.
pub const ACTOR_BINDING: &str = "actor-binding";

/// A committed ALLOW of an `idp.*` action: what the identity plane binds its row to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The governing domain.
    pub domain: Digest,
    /// The nonce.
    pub nonce: Vec<u8>,
    /// Position of the decision record.
    pub position: u64,
    /// The intent digest the decision is about.
    pub intent: Digest,
    /// The `ExerciseID`.
    pub exercise: Digest,
    /// Whether the decision was already recorded before this request.
    pub replayed: bool,
}

/// The authority plane's answer to a [`Submission`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Allowed and committed.
    Committed(Committed),
    /// Denied or waiting on an action; nothing may be written.
    NotAllowed {
        /// The decision.
        decision: Decision,
        /// Position of its record, when recorded.
        position: Option<u64>,
    },
    /// No decision: the request is malformed, rejected or cannot be decided now.
    Refused {
        /// Stable reason code.
        code: String,
        /// Stable codes of what the refusal expected and did not find (RFC 9457 `errors[].code`,
        /// OP-149 m.24 (b), m.30 (b)); empty unless the plane can tell.
        errors: Vec<&'static str>,
    },
}

/// What a new realm's governing domain is opened with (TN-111, §12.5.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenesisOrder {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The realm's immutable slug: the domain's `idp` Anchor covers `idp:[slug, …]` only, so
    /// no other domain governs the realm (MD-5a, TN-1).
    pub slug: String,
    /// The founding root of the domain and of its `idp` Anchor.
    pub root: Root,
    /// The CT3 time-lock in seconds; `None` keeps the default (OP-141 m.34 (d)).
    pub ct3_delay_s: Option<u64>,
    /// Further catalogs the founder publishes in the Genesis besides the `idp.*` ones (OP-141
    /// m.35 (c)); each one's publisher is the founder.
    pub schemas: Vec<Spp>,
    /// The realm's identity Claim issuer Party, when it has one: the domain is born accepting
    /// it for `actor-binding` only (§10.1.4 rule 3, OP-142).
    pub issuer: Option<access_kernel::model::Id>,
    /// Further Acceptances the founder establishes at Genesis, each an `acceptance-content`
    /// (L0-META-5, L2-CLM-3); a local deployment's declarant is accepted this way (OP-149
    /// m.26 (c)).
    pub acceptances: Vec<suiss_crypto::dcbor::Value>,
    /// Classes of the realm issuer's Claims the domain is born accepting as predicate input
    /// too (§10.1.4 rule 3, L2-CLM-3): what a hosted approval's `authentication` Claim proves
    /// with (SI-5, OP-149 m.29 (b)). Empty keeps `actor-binding` alone.
    pub issuer_predicate_input: Vec<String>,
}

/// The domain a Genesis opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisOpened {
    /// The `DomainID`.
    pub domain: Digest,
}

/// The other plane could not be reached or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unavailable(pub String);
