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

use crate::ports::Messages;

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
