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
