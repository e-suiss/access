//! What the hosted login needs from the outside world (OP-63): each environment's keys and sign-in
//! settings, the Relay seam that queues its messages, the identity signer for artifacts and the
//! authority plane's device Instances (OP-149 m.6, m.8).

use std::future::Future;
use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::Environment;
use access_identity_account::app::claims::Issued;
use access_identity_account::domain::claims::ClaimOrder;
use access_identity_account::notify::ports::Notifier;
use access_identity_oauth::ports::{EnvironmentEntry, Unavailable};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_webauthn::adapters::EnvironmentDecoyKeys;
use access_identity_webauthn::domain::policy::EnvironmentPolicy;
use access_identity_webauthn::domain::rp::RelyingParty;
use access_internal_api::approvals::{Contribution, Eligibility, Opening};
use access_internal_api::idp::{Unavailable as InstancesUnavailable, Verdict};
use access_internal_api::instances::{Recovery, Registration, RegistrationVerdict, Termination};
use access_kernel::digest::Digest;
use access_store::identity::{EnvironmentId, TenantId};
use suiss_crypto::envelope::Kek;

pub use access_identity_session::ports::Clock;

/// One environment's keys and sign-in settings.
pub struct EnvironmentKit {
    /// Tenant.
    pub tenant: TenantId,
    /// Environment.
    pub environment: EnvironmentId,
    /// The environment's stored issuer, without a trailing slash (§17.9.6).
    pub issuer: String,
    /// The name shown in authenticator apps (TOTP issuer, RP name).
    pub name: String,
    /// The environment KEK that wraps subject DEKs (OP-42, OP-135).
    pub kek: std::sync::Arc<dyn Kek + Send + Sync>,
    /// The environment's blind index key of the PII vault (OP-153 m.3 (aa)).
    pub index: std::sync::Arc<access_crypto::environment_index::EnvironmentIndexKey>,
    /// The cell's id key (OP-137).
    pub ids: IdKey,
    /// The environment's decoy key (TN-97).
    pub decoys: EnvironmentDecoyKeys,
    /// The relying party (MD-5).
    pub rp: RelyingParty,
    /// WebAuthn policy.
    pub webauthn: EnvironmentPolicy,
    /// What the environment's `direct` attestation policy verifies against: the FIDO metadata held
    /// now and the attestation chains' CRLs (OP-159 m.3 (ll)).
    pub attestation:
        std::sync::Arc<dyn access_identity_webauthn::ports::AttestationSources + Send + Sync>,
    /// Sign-in requirements (TN-132).
    pub auth: AuthPolicy,
    /// Session lifetimes (TN-36).
    pub lifetimes: SessionPolicy,
    /// The environment's stored sign-in policy: registration rules, enumeration mode and e-mail reuse
    /// (TN-132, OP-153 m.3 (g), (i), (j)).
    pub signin: access_identity_session::domain::environment_policy::EnvironmentSignin,
    /// What the environment hashes passwords and recovery secrets with: Argon2id at its profile, or
    /// PBKDF2 under the FIPS profile (OP-158 m.3 (y), m.6 (b)).
    pub hash: access_identity_account::domain::password::HashPolicy,
}

impl EnvironmentKit {
    /// The environment as identity-account sees it.
    #[must_use]
    pub fn environment(&self) -> Environment<'_> {
        Environment {
            tenant: self.tenant,
            environment: self.environment,
            kek: &*self.kek,
            ids: &self.ids,
        }
    }

    /// The environment's PII vault keys (OP-153 m.3 (aa)).
    #[must_use]
    pub fn vault(&self) -> access_identity_account::app::vault::Vault {
        access_identity_account::app::vault::Vault {
            kek: self.kek.clone(),
            index: self.index.clone(),
        }
    }
}

/// The kits of the environments this process serves.
pub trait Kits: Send + Sync {
    /// The kit of the resolved environment `entry`.
    ///
    /// # Errors
    /// [`Unavailable`] when the keys or settings cannot be loaded now (fail-closed).
    fn kit(
        &self,
        entry: &EnvironmentEntry,
    ) -> impl Future<Output = Result<Arc<EnvironmentKit>, Unavailable>> + Send;
}

/// The Relay seam of an environment (E42 m.1): messages are queued in the sign-in's transaction.
pub trait Messages: Send + Sync {
    /// The notifier of one environment.
    type For<'a>: Notifier + Send + Sync
    where
        Self: 'a;

    /// A notifier for `environment`.
    fn notifier<'a>(&'a self, environment: &'a Environment<'a>) -> Self::For<'a>;
}

/// Signs identity plane artifacts as `COSE_Sign1` with the environment's identity signer key
/// (OP-149 m.8).
pub trait ArtifactSigner: Send + Sync {
    /// The tagged `COSE_Sign1` of `payload` with content type `content_type` at `at_ms`.
    fn sign_cose(
        &self,
        environment: EnvironmentId,
        content_type: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send;
}

/// A user's device Instances in the environment's governing domain, reached only through
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

/// The live Instance keys of a Party in the environment's governing domain, for its `did:web`
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

    /// The Party and current key of the live Instance `instance` in `domain`; `None` for an
    /// ended or unknown one (L21).
    fn instance_key(
        &self,
        domain: Digest,
        instance: [u8; 16],
    ) -> impl Future<
        Output = Result<
            Option<(
                access_kernel::model::Id,
                access_kernel::verify::cose::PublicKey,
            )>,
            InstancesUnavailable,
        >,
    > + Send;
}

/// A workload's first Instance (OP-154 m.3 (d)): its key's self-signed `instance_create`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkloadOpen {
    /// The environment's governing domain.
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
    /// Commits `open` with no actor binding held: the actor comes from the environment issuer's
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

    /// Whether `viewer` may contribute `class` in `domain` now, the Grant its contribution
    /// names (`basis`) read first, and how many named holders may when the domain lets the
    /// viewer see that (§8.17.6.1, E26, OP-157 m.3 (l)).
    fn eligibility(
        &self,
        domain: Digest,
        class: &str,
        viewer: access_kernel::model::Id,
        basis: Option<access_kernel::model::Id>,
    ) -> impl Future<Output = Result<Eligibility, InstancesUnavailable>> + Send;

    /// Commits the contribution as PEP, with the statement and the Claim as proofs.
    fn contribute(
        &self,
        contribution: Contribution,
    ) -> impl Future<Output = Result<Verdict, InstancesUnavailable>> + Send;
}

/// The environment's Claim courier, for the `authentication` Claim an approval needs at once (SI-5,
/// §9.14.1 step 3, OP-150 L2 (b)).
pub trait ApprovalClaims: Send + Sync {
    /// Issues `order` now: placed, signed, ingested and recorded.
    fn issue(
        &self,
        tenant: TenantId,
        environment: EnvironmentId,
        order: &ClaimOrder,
    ) -> impl Future<Output = Result<Issued, InstancesUnavailable>> + Send;
}

/// The hosts of handles a person owns (E56 (2)): `GET https://<handle>/.well-known/access-handle`
/// over the public network, as Access fetches any outside document.
pub trait HandleHosts: Send + Sync {
    /// The body the handle's host answers, at most 512 bytes; `None` when it answers nothing
    /// usable.
    fn well_known(&self, handle: &str) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// Who a Suiss handle host points at (E56 (2)): read as the router, across tenants.
pub trait HandleDirectory: Send + Sync {
    /// The DID the verified, not retired Suiss handle `host` points at.
    fn did_of_host(
        &self,
        host: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send;
}
