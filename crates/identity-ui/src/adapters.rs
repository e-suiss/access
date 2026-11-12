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

/// What a realm's `direct` attestation policy verifies against in a server (§10.2.4, OP-159 m.3
/// (ll)): the FIDO metadata the refresh job holds, and each CRL distribution point of an
/// attestation chain, read from `access.attestation_crl_cache` while its `nextUpdate` has not
/// passed and otherwise fetched with [`Outbound::get_configured`] and cached. A point that
/// cannot be read gives nothing, so the registration is refused; nothing is fetched under the
/// `none` policy.
///
/// [`Outbound::get_configured`]: access_identity_oauth::adapters::outbound::Outbound::get_configured
pub struct CachedAttestationSources<C> {
    /// The metadata blob the refresh job keeps.
    pub metadata: std::sync::Arc<access_identity_webauthn::adapters::MemoryMdsCache>,
    /// The `access_app` pool.
    pub db: access_store::Pool,
    /// The guarded outbound client.
    pub outbound: access_identity_oauth::adapters::outbound::Outbound,
    /// Trusted time.
    pub clock: C,
}

impl<C: access_identity_webauthn::ports::Clock + Send + Sync> CachedAttestationSources<C> {
    async fn read(&self, url: &str) -> Option<Vec<u8>> {
        use access_identity_webauthn::domain::crl::{MAX_CRL, next_update};
        let now = self.clock.now().ok()?;
        let source = access_crypto::webauthn::sha256(url.as_bytes());
        match access_store::attestation_crl::latest(&self.db, &source).await {
            Ok(Some(c)) if now < c.next_update_s => return Some(c.crl),
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%error, "attestation CRL cache unreadable (OP-159 m.3 (ll))");
                return None;
            }
        }
        let answer = match self
            .outbound
            .get_configured(url, "application/pkix-crl", MAX_CRL)
            .await
        {
            Ok(a) if a.status == 200 => a,
            Ok(a) => {
                tracing::warn!(
                    status = a.status,
                    "attestation CRL not fetched (OP-159 m.3 (ll))"
                );
                return None;
            }
            Err(error) => {
                tracing::warn!(%error, "attestation CRL not fetched (OP-159 m.3 (ll))");
                return None;
            }
        };
        let next = next_update(&answer.body).filter(|n| now < *n)?;
        let digest = access_crypto::webauthn::sha256(&answer.body);
        if let Err(error) = access_store::attestation_crl::record(
            &self.db,
            &source,
            url,
            &digest,
            next,
            &answer.body,
        )
        .await
        {
            tracing::warn!(%error, "attestation CRL not cached (OP-159 m.3 (ll))");
        }
        Some(answer.body)
    }
}

impl<C: access_identity_webauthn::ports::Clock + Send + Sync>
    access_identity_webauthn::ports::AttestationSources for CachedAttestationSources<C>
{
    fn metadata(
        &self,
    ) -> access_identity_webauthn::ports::Pending<
        '_,
        Option<access_identity_webauthn::domain::mds::MdsBlob>,
    > {
        access_identity_webauthn::ports::AttestationSources::metadata(&*self.metadata)
    }

    fn crl<'a>(
        &'a self,
        url: &'a str,
    ) -> access_identity_webauthn::ports::Pending<'a, Option<Vec<u8>>> {
        Box::pin(self.read(url))
    }
}
