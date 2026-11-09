//! What the hosted login needs from the outside world (OP-63): each realm's keys and sign-in
//! settings, the Relay seam that queues its messages, the identity signer for artifacts and the
//! authority plane's device Instances (OP-149 m.6, m.8).

use std::future::Future;
use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::Realm;
use access_identity_account::app::claims::Issued;
use access_identity_account::domain::claims::ClaimOrder;
use access_identity_account::notify::ports::Notifier;
use access_identity_oauth::ports::{RealmEntry, Unavailable};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::RelyingParty;
use access_internal_api::approvals::{Contribution, Opening};
use access_internal_api::idp::{Unavailable as InstancesUnavailable, Verdict};
use access_internal_api::instances::{Recovery, Registration, RegistrationVerdict, Termination};
use access_kernel::digest::Digest;
use access_store::identity::{RealmId, TenantId};
use suiss_crypto::envelope::Kek;

pub use access_identity_session::ports::Clock;

/// One realm's keys and sign-in settings.
pub struct RealmKit {
    /// Tenant.
    pub tenant: TenantId,
    /// Realm.
    pub realm: RealmId,
    /// The realm's stored issuer, without a trailing slash (§17.9.6).
    pub issuer: String,
    /// The name shown in authenticator apps (TOTP issuer, RP name).
    pub name: String,
    /// The realm KEK that wraps subject DEKs (OP-42, OP-135).
    pub kek: std::sync::Arc<dyn Kek + Send + Sync>,
    /// The realm's blind index key of the PII vault (OP-153 m.3 (aa)).
    pub index: std::sync::Arc<access_crypto::realm_index::RealmIndexKey>,
    /// The cell's id key (OP-137).
    pub ids: IdKey,
    /// The realm's decoy key (TN-97).
    pub decoys: RealmDecoyKeys,
    /// The relying party (MD-5).
    pub rp: RelyingParty,
    /// WebAuthn policy.
    pub webauthn: RealmPolicy,
    /// Sign-in requirements (TN-132).
    pub auth: AuthPolicy,
    /// Session lifetimes (TN-36).
    pub lifetimes: SessionPolicy,
    /// The realm's stored sign-in policy: registration rules, enumeration mode and e-mail reuse
    /// (TN-132, OP-153 m.3 (g), (i), (j)).
    pub signin: access_identity_session::domain::realm_policy::RealmSignin,
}

impl RealmKit {
    /// The realm as identity-account sees it.
    #[must_use]
    pub fn realm(&self) -> Realm<'_> {
        Realm {
            tenant: self.tenant,
            realm: self.realm,
            kek: &*self.kek,
            ids: &self.ids,
        }
    }

    /// The realm's PII vault keys (OP-153 m.3 (aa)).
    #[must_use]
    pub fn vault(&self) -> access_identity_account::app::vault::Vault {
        access_identity_account::app::vault::Vault {
            kek: self.kek.clone(),
            index: self.index.clone(),
        }
    }
}

/// The kits of the realms this process serves.
pub trait Kits: Send + Sync {
    /// The kit of the resolved realm `entry`.
    ///
    /// # Errors
    /// [`Unavailable`] when the keys or settings cannot be loaded now (fail-closed).
    fn kit(
        &self,
        entry: &RealmEntry,
    ) -> impl Future<Output = Result<Arc<RealmKit>, Unavailable>> + Send;
}

/// The Relay seam of a realm (E42 m.1): messages are queued in the sign-in's transaction.
pub trait Messages: Send + Sync {
    /// The notifier of one realm.
    type For<'a>: Notifier + Send + Sync
    where
        Self: 'a;

    /// A notifier for `realm`.
    fn notifier<'a>(&'a self, realm: &'a Realm<'a>) -> Self::For<'a>;
}

/// Signs identity plane artifacts as `COSE_Sign1` with the realm's identity signer key
/// (OP-149 m.8).
pub trait ArtifactSigner: Send + Sync {
    /// The tagged `COSE_Sign1` of `payload` with content type `content_type` at `at_ms`.
    fn sign_cose(
        &self,
        realm: RealmId,
        content_type: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;
}

/// A user's device Instances in the realm's governing domain, reached only through
/// `internal-api` (OP-62, OP-149 m.6).
pub trait DeviceInstances: Send + Sync {
    /// Opens the device Instance of `registration`, or answers with the one an identical
    /// earlier registration opened.
    fn register(
        &self,
        registration: Registration,
    ) -> impl Future<Output = Result<RegistrationVerdict, InstancesUnavailable>> + Send;

    /// Forwards a termination the user's own Instance signed, as PEP.
    fn terminate(
        &self,
        termination: Termination,
    ) -> impl Future<Output = Result<Verdict, InstancesUnavailable>> + Send;

    /// Forwards a self-signed `instance_recover` of a successor key, as PEP (OP-153 m.3 (c)).
    fn recover(
        &self,
        recovery: Recovery,
    ) -> impl Future<Output = Result<Verdict, InstancesUnavailable>> + Send;
}

/// The live Instance keys of a Party in the realm's governing domain, for its `did:web`
/// document (OP-154 m.3 (aa)): a read, never authority.
pub trait PartyKeys: Send + Sync {
    /// The keys of `party`'s live Instances in `domain`, in the order the domain created them.
    fn live_keys(
        &self,
        domain: Digest,
        party: [u8; 16],
    ) -> impl Future<
        Output = Result<Vec<access_kernel::verify::cose::PublicKey>, InstancesUnavailable>,
    > + Send;
}

/// A workload's first Instance (OP-154 m.3 (d)): its key's self-signed `instance_create`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadOpen {
    /// The realm's governing domain.
    pub domain: Digest,
    /// The agent Party.
    pub party: access_kernel::model::Id,
    /// The workload's key.
    pub key: access_kernel::verify::cose::PublicKey,
    /// The self-signed `instance_create`.
    pub create: access_internal_api::instances::SelfSigned,
    /// The identity plane as PEP.
    pub pep: String,
}

/// The authority plane's workload Instances, reached only through `internal-api` (OP-62).
pub trait WorkloadInstances: Send + Sync {
    /// Commits `open` with no actor binding held: the actor comes from the realm issuer's
    /// `identity_binding_workload` Claim that names the key.
    fn open_workload(
        &self,
        open: WorkloadOpen,
    ) -> impl Future<Output = Result<RegistrationVerdict, InstancesUnavailable>> + Send;
}

/// The authority plane behind the Approval Surface, reached only through `internal-api`
/// (OP-62, §9.14.1 A, OP-150 L6).
pub trait Approvals: Send + Sync {
    /// What the latest `REQUIRE_ACTION` on `intent` in `domain` left for its approval: the
    /// render the decision point kept and the tier; `None` when nothing waits.
    fn opening(
        &self,
        domain: Digest,
        intent: Digest,
    ) -> impl Future<Output = Result<Option<Opening>, InstancesUnavailable>> + Send;

    /// Commits the contribution as PEP, with the statement and the Claim as proofs.
    fn contribute(
        &self,
        contribution: Contribution,
    ) -> impl Future<Output = Result<Verdict, InstancesUnavailable>> + Send;
}

/// The realm's Claim courier, for the `authentication` Claim an approval needs at once (SI-5,
/// §9.14.1 step 3, OP-150 L2 (b)).
pub trait ApprovalClaims: Send + Sync {
    /// Issues `order` now: placed, signed, ingested and recorded.
    fn issue(
        &self,
        tenant: TenantId,
        realm: RealmId,
        order: &ClaimOrder,
    ) -> impl Future<Output = Result<Issued, InstancesUnavailable>> + Send;
}
