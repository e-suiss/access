//! What the domain needs from the outside world (OP-63): the authority plane, reached only
//! through `internal-api` messages (OP-62).

use std::future::Future;

use access_internal_api::idp::{GenesisOpened, GenesisOrder, Submission, Unavailable, Verdict};
use access_internal_api::instances::{Registration, RegistrationVerdict};
use access_store::identity::RealmId;

use crate::domain::JoseAlg;

/// Decides `idp.*` Exercises: the identity plane is their PEP (MD-14, E34).
pub trait Decider: Send + Sync {
    /// Commits `submission` in its domain and returns the decision.
    fn decide(
        &self,
        submission: Submission,
    ) -> impl Future<Output = Result<Verdict, Unavailable>> + Send;
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
}
