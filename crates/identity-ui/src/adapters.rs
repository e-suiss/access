//! Port implementations (OP-63): the outbox as the Relay seam, and passkey risk signals to
//! the log until Stage 6 turns them into Claims (TN-63).

use std::future::Future;

use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::Realm;
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_webauthn::WebAuthnError;
use access_identity_webauthn::domain::ceremony::Signal;
use access_identity_webauthn::domain::ids::{CredentialId, RealmId};
use access_identity_webauthn::ports::SignalSink;

use access_identity_oauth::adapters::SignerKeys;
use access_identity_oauth::ports::Unavailable;

use access_identity_account::app::claims::{ClaimSigner, Courier, Issued};
use access_identity_account::domain::claims::ClaimOrder;
use access_internal_api::claims::ClaimIngest;
use access_store::identity::{RealmId as StoreRealm, TenantId};

use crate::ports::{ApprovalClaims, ArtifactSigner, Messages};

impl<S, I, C> ApprovalClaims for Courier<S, I, C>
where
    S: ClaimSigner,
    I: ClaimIngest,
    C: access_identity_account::ports::Clock + Send + Sync,
{
    fn issue(
        &self,
        tenant: TenantId,
        realm: StoreRealm,
        order: &ClaimOrder,
    ) -> impl Future<Output = Result<Issued, access_internal_api::idp::Unavailable>> + Send {
        Self::issue(self, tenant, realm, order)
    }
}

impl<T: ApprovalClaims> ApprovalClaims for std::sync::Arc<T> {
    fn issue(
        &self,
        tenant: TenantId,
        realm: StoreRealm,
        order: &ClaimOrder,
    ) -> impl Future<Output = Result<Issued, access_internal_api::idp::Unavailable>> + Send {
        T::issue(self, tenant, realm, order)
    }
}

impl ArtifactSigner for SignerKeys {
    fn sign_cose(
        &self,
        realm: access_store::identity::RealmId,
        content_type: &str,
        payload: &[u8],
        at_ms: u64,
    ) -> impl Future<Output = Result<Vec<u8>, Unavailable>> + Send {
        Self::sign_cose(self, realm, content_type, payload, at_ms)
    }
}

/// The production Relay seam: messages sealed into `identity_outbox` (OP-146 m.11).
#[derive(Clone, Copy, Debug, Default)]
pub struct Outbox;

impl Messages for Outbox {
    type For<'a> = OutboxNotifier<'a>;

    fn notifier<'a>(&'a self, realm: &'a Realm<'a>) -> OutboxNotifier<'a> {
        OutboxNotifier::new(realm, &SystemEntropy, &SystemClock)
    }
}

/// Passkey risk signals, logged without the credential id (TN-63).
#[derive(Clone, Copy, Debug, Default)]
pub struct LogSignals;

impl SignalSink for LogSignals {
    fn emit(
        &self,
        _: RealmId,
        _: &CredentialId,
        signal: Signal,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        tracing::warn!(?signal, "passkey risk signal");
        std::future::ready(Ok(()))
    }
}
