//! What the domain needs from the outside world (OP-63): the authority plane, reached only
//! through `internal-api` messages (OP-62).

use std::future::Future;

pub use access_identity_signer::issuer::Registration as IssuerAis;
use access_internal_api::idp::{GenesisOpened, GenesisOrder, Submission, Unavailable, Verdict};
use access_internal_api::instances::{Registration, RegistrationVerdict, SelfSigned};
use access_kernel::digest::Digest;
use access_kernel::meta::ActorKind;
use access_kernel::model::Id;
use access_kernel::verify::cose::PublicKey;
use access_store::identity::RealmId;
use suiss_crypto::rotation::Policy;

use crate::domain::JoseAlg;

/// Decides `idp.*` Exercises: the identity plane is their PEP (MD-14, E34).
pub trait Decider: Send + Sync {
    /// Commits `submission` in its domain and returns the decision.
    fn decide(
        &self,
        submission: Submission,
    ) -> impl Future<Output = Result<Verdict, Unavailable>> + Send;

    /// The Party whose live Instance key in `domain` signed `ais` (§13.4 G54); `None` when no
    /// live Instance of the domain holds that key.
    fn signer(
        &self,
        domain: Digest,
        ais: &[u8],
    ) -> impl Future<Output = Result<Option<Id>, Unavailable>> + Send;
}

/// The keys of a realm that live outside the database (OP-146 m.16 (m), m.15 (e), m.7 (b)):
/// its JOSE key set in the identity signer, and its KEK, decoy key and DPoP nonce keys in the
/// HSM.
pub trait RealmKeys: Send + Sync {
    /// Opens what is missing and makes the realm's next JOSE keys use `alg`; repeating it
    /// changes nothing.
    fn open(
        &self,
        realm: RealmId,
        alg: JoseAlg,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Whether the identity signer can hold an ML-DSA key of `alg` (OP-159 m.3 (d)); without
    /// one the realm's post-quantum profile is refused.
    fn pq_ready(
        &self,
        alg: crate::domain::assurance::MlDsa,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
        let _ = alg;
        async { Ok(false) }
    }

    /// Opens the realm's post-quantum key set with `alg` (CR-41, OP-159 m.3 (o)); repeating it
    /// changes nothing.
    fn pq_open(
        &self,
        realm: RealmId,
        alg: crate::domain::assurance::MlDsa,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        let _ = (realm, alg);
        async { Err(Unavailable(String::from("no post-quantum keys"))) }
    }

    /// Drops every key of the realm's post-quantum key set (OP-159 m.3 (a)); repeating it
    /// changes nothing.
    fn pq_close(&self, realm: RealmId) -> impl Future<Output = Result<(), Unavailable>> + Send {
        let _ = realm;
        async { Ok(()) }
    }

    /// The realm's JWKS document as relying parties read it.
    fn jwks(&self, realm: RealmId) -> impl Future<Output = Result<String, Unavailable>> + Send;

    /// Rotates the realm's active key `retire` out now (TN-118); once it is no longer active,
    /// repeating it changes nothing.
    fn rotate(
        &self,
        realm: RealmId,
        retire: [u8; 32],
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Drops the realm key `kid` at once (§13.2); repeating it changes nothing.
    fn drop_key(
        &self,
        realm: RealmId,
        kid: [u8; 32],
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Replaces the realm's key rotation policy (TN-118).
    fn set_policy(
        &self,
        realm: RealmId,
        policy: Policy,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;

    /// Opens the realm's Claim issuer key for its issuer Party `party` and returns its public key
    /// (§10.1.7); repeating it changes nothing.
    fn open_issuer(
        &self,
        realm: RealmId,
        party: [u8; 16],
    ) -> impl Future<Output = Result<PublicKey, Unavailable>> + Send;

    /// Opens the realm's SAML signing key (P-256 when `p256`, else RSA-3072) on the first
    /// registration that needs it (MD-6, OP-155 m.3 (d)); repeating it changes nothing.
    fn saml_open(
        &self,
        realm: RealmId,
        p256: bool,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        let _ = (realm, p256);
        async { Err(Unavailable(String::from("no SAML keys"))) }
    }

    /// Replaces the realm's SAML signing key at once (`idp.saml.cert_emergency`).
    fn saml_emergency(
        &self,
        realm: RealmId,
        p256: bool,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send {
        let _ = (realm, p256);
        async { Err(Unavailable(String::from("no SAML keys"))) }
    }

    /// Signs the JSON `claims` as a compact JWS of `typ` with the realm's token key at `at`, Unix
    /// ms: a realm-signed binding offer (OP-153 m.18 (e)). Without a signer nothing is offered.
    fn sign_jws(
        &self,
        realm: RealmId,
        typ: &str,
        claims: &[u8],
        at: u64,
    ) -> impl Future<Output = Result<String, Unavailable>> + Send {
        let _ = (realm, typ, claims, at);
        std::future::ready(Err(Unavailable(String::from("identity-signer"))))
    }

    /// The realm's PII vault keys, its KEK and blind index key (OP-153 m.3 (aa)); `None` when
    /// the token refuses them, and nothing personal is written then (TI-9).
    fn vault(&self, realm: RealmId) -> Option<access_identity_account::app::vault::Vault> {
        let _ = realm;
        None
    }

    /// The AIS of one self-signed registration Exercise of the issuer Party, by the realm's
    /// Claim issuer key (OP-149 m.16 (a)).
    fn sign_issuer_registration(
        &self,
        realm: RealmId,
        registration: IssuerAis,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;
}

/// Opens the governing domain of a new realm (TN-111).
pub trait Governance: Send + Sync {
    /// Writes the Genesis of a new domain.
    fn open(
        &self,
        order: GenesisOrder,
    ) -> impl Future<Output = Result<GenesisOpened, Unavailable>> + Send;
}

/// Opens Instances in a governing domain (OP-149 m.4, m.16 (a)): the identity plane forwards a
/// paired product's self-signed `party_register` and `instance_create` there.
pub trait Instances: Send + Sync {
    /// Opens the Instance of `registration`, or answers with the one an identical earlier
    /// registration opened.
    fn register(
        &self,
        registration: Registration,
    ) -> impl Future<Output = Result<RegistrationVerdict, Unavailable>> + Send;

    /// The trusted time the domain judges a registration's intent and AIS by (OP-129 m.1).
    fn now(&self) -> impl Future<Output = Result<u64, Unavailable>> + Send;

    /// The actor kind of `party` in `domain` and whether it ended, from the domain's Party
    /// lookup (OP-149 m.28 (c), OP-153 m.10 (e)); `None` for a Party the domain does not know.
    fn party(
        &self,
        domain: Digest,
        party: Id,
    ) -> impl Future<Output = Result<Option<PartyKind>, Unavailable>> + Send {
        let _ = (domain, party);
        async { Err(Unavailable(String::from("party-lookup"))) }
    }

    /// Commits an organization's `party_register`, signed by the one-time key its founder's
    /// client made and dropped (OP-153 m.3 (b), L0-META-7).
    fn register_organization(
        &self,
        registration: OrgRegistration,
    ) -> impl Future<Output = Result<OrgRegistered, Unavailable>> + Send {
        let _ = registration;
        async { Err(Unavailable(String::from("organization-registration"))) }
    }

    /// Commits an agent's `party_register`, signed by the one-time key its operator's client
    /// made and dropped (OP-154 m.3 (c), L0-META-7).
    fn register_agent(
        &self,
        registration: AgentRegistration,
    ) -> impl Future<Output = Result<OrgRegistered, Unavailable>> + Send {
        let _ = registration;
        async { Err(Unavailable(String::from("agent-registration"))) }
    }

    /// Commits a workload's self-signed `instance_create` with no actor binding held: the
    /// authority plane takes the actor from the realm issuer's `identity_binding_workload`
    /// Claim that names the key (OP-154 m.3 (d)).
    fn register_workload(
        &self,
        registration: WorkloadInstance,
    ) -> impl Future<Output = Result<RegistrationVerdict, Unavailable>> + Send {
        let _ = registration;
        async { Err(Unavailable(String::from("workload-registration"))) }
    }

    /// The live Instances of `party` in `domain` at the head (AG-21, OP-154 m.3 (f)).
    fn instances(
        &self,
        domain: Digest,
        party: Id,
    ) -> impl Future<Output = Result<Vec<Id>, Unavailable>> + Send {
        let _ = (domain, party);
        async { Err(Unavailable(String::from("instance-lookup"))) }
    }

    /// What offboarding `party` in `domain` would touch now, channel by channel (OP-157 m.3
    /// (v)); `None` for a Party the domain does not know.
    fn offboarding(
        &self,
        domain: Digest,
        party: Id,
    ) -> impl Future<Output = Result<Option<Departing>, Unavailable>> + Send {
        let _ = (domain, party);
        async { Err(Unavailable(String::from("offboarding"))) }
    }

    /// V10, OP-157 m.4 (b): the live Grants in `reviewer`'s lineage in `domain`, a campaign's
    /// items (IDP-39 (3), OP-157 m.3 (w)).
    fn review_items(
        &self,
        domain: Digest,
        reviewer: Id,
    ) -> impl Future<Output = Result<Vec<TeamGrant>, Unavailable>> + Send {
        let _ = (domain, reviewer);
        async { Err(Unavailable(String::from("review"))) }
    }

    /// V10, OP-157 m.4 (b): the Party whose live Instance holds key `kid` in `domain` now;
    /// `None` when no live Instance holds it.
    fn key_party(
        &self,
        domain: Digest,
        kid: [u8; 32],
    ) -> impl Future<Output = Result<Option<Id>, Unavailable>> + Send {
        let _ = (domain, kid);
        async { Err(Unavailable(String::from("key-lookup"))) }
    }
}

/// A workload's first Instance (OP-154 m.3 (d)): the key the realm issuer's
/// `identity_binding_workload` Claim names signs its own `instance_create` under the bootstrap
/// basis; the Instance still acts only through a Grant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadInstance {
    /// The realm's governing domain.
    pub domain: Digest,
    /// The agent Party.
    pub party: Id,
    /// The workload's key, the one its DPoP proofs use.
    pub key: PublicKey,
    /// The self-signed `instance_create`.
    pub create: SelfSigned,
    /// The identity plane as PEP.
    pub pep: String,
}

impl WorkloadInstance {
    /// The `instance_create` payload.
    #[must_use]
    pub fn payload(&self) -> access_kernel::meta::Payload {
        access_kernel::meta::Payload::InstanceCreate {
            party: self.party,
            key: self.key.clone(),
            mandate: None,
        }
    }

    /// The Instance it opens: the first object of its Exercise.
    #[must_use]
    pub fn instance(&self) -> Option<Id> {
        let exercise = access_kernel::meta::exercise_id(&self.domain, &self.create.nonce).ok()?;
        Some(access_kernel::meta::object_id(
            &exercise,
            access_kernel::meta::kind::INSTANCE,
            0,
        ))
    }
}

/// An agent Party to register (OP-154 m.3 (c)): `party_register` with `actor_kind = agent`
/// and the operator Party as its sole root, signed by a key no Instance will ever hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRegistration {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The realm's governing domain.
    pub domain: Digest,
    /// The agent's Party.
    pub party: Id,
    /// Its root: the operator Party.
    pub operator: Id,
    /// The one-time key that signed the registration.
    pub key: PublicKey,
    /// The self-signed `party_register`.
    pub register: SelfSigned,
    /// The identity plane as PEP.
    pub pep: String,
}

impl AgentRegistration {
    /// The `party_register` payload.
    #[must_use]
    pub const fn payload(&self) -> access_kernel::meta::Payload {
        access_kernel::meta::Payload::PartyRegister {
            party: self.party,
            root: access_kernel::meta::Root::Sole(self.operator),
            actor_kind: ActorKind::Agent,
        }
    }
}

/// What an organization's registration came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrgRegistered {
    /// Recorded, now or by an identical earlier registration.
    Registered {
        /// An identical earlier registration recorded it.
        replayed: bool,
    },
    /// Not recorded, by stable reason code.
    Refused {
        /// Stable reason code.
        code: String,
    },
}

/// A Party as the domain's lookup answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PartyKind {
    /// Fixed at `party_register` (OP-149 m.8).
    pub actor_kind: ActorKind,
    /// It departed or was terminated.
    pub ended: bool,
}

/// An organization Party to register (OP-153 m.3 (b)): `party_register` with
/// `actor_kind = organization` and the founder's Party as its sole root, signed by a key no
/// Instance will ever hold (C6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrgRegistration {
    /// The tenant.
    pub tenant: [u8; 16],
    /// The realm's governing domain.
    pub domain: Digest,
    /// The organization's Party.
    pub party: Id,
    /// Its root: the founder's Party.
    pub founder: Id,
    /// The one-time key that signed the registration.
    pub key: PublicKey,
    /// The self-signed `party_register`.
    pub register: SelfSigned,
    /// The identity plane as PEP.
    pub pep: String,
    /// The pseudonymous context its bootstrap Exercise is counted under (§13.7.4, OP-152 m.5
    /// (b)); `None` counts it under the PEP alone.
    pub context: Option<access_internal_api::context::RateContext>,
}

impl OrgRegistration {
    /// The `party_register` payload.
    #[must_use]
    pub const fn payload(&self) -> access_kernel::meta::Payload {
        access_kernel::meta::Payload::PartyRegister {
            party: self.party,
            root: access_kernel::meta::Root::Sole(self.founder),
            actor_kind: ActorKind::Organization,
        }
    }
}

/// What a domain's verification and watch read from the outside world (TN-90, OP-153 m.3 (o)):
/// DNS TXT and MX records, the HTTPS challenge document, the registrar from RDAP, and what an
/// upstream identity provider asserted. Each answer is a fact or [`Unavailable`]; an
/// unavailable probe verifies nothing and lapses nothing by itself.
pub trait DomainProbe: Send + Sync {
    /// The TXT strings at `name`, each record's strings joined.
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, Unavailable>> + Send;

    /// The MX hosts of `domain`.
    fn mx(&self, domain: &str) -> impl Future<Output = Result<Vec<String>, Unavailable>> + Send;

    /// The body of the `https` document at `url` when it answers `200`, else `None`.
    fn https(&self, url: &str) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;

    /// The registrar RDAP names for `domain`, if any.
    fn registrar(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;
}

/// One conjunct of a rule-shaped holder as offboarding shows it: the Claim class and the value
/// it selects on, as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selects {
    /// The Claim class.
    pub class: String,
    /// The value, when the conjunct names one.
    pub value: Option<String>,
}

/// A rule-shaped holding that still selects the departing Party (C13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldByRule {
    /// The Grant.
    pub grant: Id,
    /// What its holder selects on.
    pub selects: Vec<Selects>,
    /// The episode's first position.
    pub since: u64,
    /// Whether it is stale (never removed).
    pub stale: bool,
}

/// A rule-shaped holding whose episode ended (INV-31).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndedByRule {
    /// The Grant.
    pub grant: Id,
    /// What its holder selects on.
    pub selects: Vec<Selects>,
    /// When it ended, Unix ms, when known.
    pub at: Option<u64>,
    /// The issuer of the last statement that selected the Party.
    pub issuer: Option<Id>,
}

/// What offboarding a Party would touch, from the authority plane (OP-157 m.3 (v), §8.17.9.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Departing {
    /// Its self-anchor.
    pub anchor: Option<Id>,
    /// The position of its departure, once it departed.
    pub departed: Option<u64>,
    /// Live Grants it holds by name.
    pub direct: Vec<Id>,
    /// Its live Instances.
    pub instances: Vec<Id>,
    /// Rule-shaped holdings that select it.
    pub holdings: Vec<HeldByRule>,
    /// Live Grants on its self-anchor.
    pub given: Vec<Id>,
    /// Live Grants derived from one of its holdings, with that holding's Grant.
    pub derived: Vec<(Id, Id)>,
    /// Rule-shaped holdings whose episode ended.
    pub ended: Vec<EndedByRule>,
}

/// One Grant of a reviewer's team (IDP-39 (3), OP-157 m.3 (w)): a live Grant in the reviewer's
/// lineage, as the campaign shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TeamGrant {
    /// The Grant.
    pub grant: Id,
    /// Who holds it.
    pub holder: access_kernel::model::SubjectSelector,
    /// What it allows.
    pub actions: Vec<access_kernel::model::ActionRef>,
    /// On what.
    pub resource: access_kernel::model::ResourceSelector,
    /// When.
    pub validity: access_kernel::model::Window,
    /// The position it was issued at.
    pub since: u64,
    /// The holding's holder it was issued from; `None` when issued under an Anchor.
    pub issued_by: Option<Id>,
    /// Whether it may be passed on.
    pub delegable: bool,
    /// How many live Grants derive from it.
    pub derived: u64,
    /// The basis the reviewer revokes it on.
    pub via: access_kernel::meta::ExerciseBasis,
}
