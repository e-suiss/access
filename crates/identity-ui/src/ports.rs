//! What the hosted login needs from the outside world (OP-63): each realm's keys and sign-in
//! settings, the Relay seam that queues its messages, the identity signer for artifacts and the
//! authority plane's device Instances (OP-149 m.6, m.8).

use std::future::Future;
use std::sync::Arc;

use access_crypto::opaque_id::IdKey;
use access_identity_account::app::Realm;
use access_identity_account::notify::ports::Notifier;
use access_identity_oauth::ports::{RealmEntry, Unavailable};
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::RelyingParty;
use access_internal_api::idp::{Unavailable as InstancesUnavailable, Verdict};
use access_internal_api::instances::{Registration, RegistrationVerdict, Termination};
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
    pub kek: Box<dyn Kek + Send + Sync>,
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
}
