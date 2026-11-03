//! The WebAuthn relying party over this service's ports, borrowed per call.

use access_identity_webauthn::WebAuthnError;
use access_identity_webauthn::app::WebAuthn;
use access_identity_webauthn::domain::ceremony::Signal;
use access_identity_webauthn::domain::credential::CredentialRecord;
use access_identity_webauthn::domain::ids::{CredentialId, RealmId, UserHandle};
use access_identity_webauthn::ports::{
    Clock as WaClockPort, CredentialRegistry, DecoySource, Inserted, Random as WaRandomPort,
    SignalSink,
};

use super::Auth;
use super::Notifier;
use crate::ports::{Clock, Random, SessionDb};

pub(crate) struct Registry<'a, P>(&'a P);
pub(crate) struct Signals<'a, S>(&'a S);
pub(crate) struct Decoys<'a>(&'a (dyn DecoySource + Sync));
pub(crate) struct Seconds<'a, C>(&'a C);
pub(crate) struct Bytes<'a, R>(&'a R);

impl<P: CredentialRegistry + Sync> CredentialRegistry for Registry<'_, P> {
    fn insert(
        &self,
        record: &CredentialRecord,
    ) -> impl Future<Output = Result<Inserted, WebAuthnError>> + Send {
        self.0.insert(record)
    }

    fn find(
        &self,
        realm: RealmId,
        id: &CredentialId,
    ) -> impl Future<Output = Result<Option<CredentialRecord>, WebAuthnError>> + Send {
        self.0.find(realm, id)
    }

    fn list(
        &self,
        realm: RealmId,
        user: &UserHandle,
    ) -> impl Future<Output = Result<Vec<CredentialRecord>, WebAuthnError>> + Send {
        self.0.list(realm, user)
    }

    fn record_use(
        &self,
        realm: RealmId,
        id: &CredentialId,
        sign_count: u32,
        backup_state: bool,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        self.0.record_use(realm, id, sign_count, backup_state, at)
    }

    fn soft_delete(
        &self,
        realm: RealmId,
        id: &CredentialId,
        at: u64,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        self.0.soft_delete(realm, id, at)
    }
}

impl<S: SignalSink + Sync> SignalSink for Signals<'_, S> {
    fn emit(
        &self,
        realm: RealmId,
        credential: &CredentialId,
        signal: Signal,
    ) -> impl Future<Output = Result<(), WebAuthnError>> + Send {
        self.0.emit(realm, credential, signal)
    }
}

impl DecoySource for Decoys<'_> {
    fn derive(&self, realm: RealmId, input: &[u8]) -> Result<[u8; 32], WebAuthnError> {
        self.0.derive(realm, input)
    }
}

impl<C: Clock> WaClockPort for Seconds<'_, C> {
    fn now(&self) -> Result<u64, WebAuthnError> {
        Ok(self.0.now_ms() / 1000)
    }
}

impl<R: Random> WaRandomPort for Bytes<'_, R> {
    fn fill(&self, out: &mut [u8]) -> Result<(), WebAuthnError> {
        self.0.fill(out).map_err(|_| WebAuthnError::Random)
    }
}

pub(crate) type Rp<'a, P, C, R, S> =
    WebAuthn<Registry<'a, P>, Seconds<'a, C>, Bytes<'a, R>, Decoys<'a>, Signals<'a, S>>;

impl<'a, D, C, R, N, P, S> Auth<'a, D, C, R, N, P, S>
where
    D: SessionDb,
    C: Clock,
    R: Random,
    N: Notifier + Sync,
    P: CredentialRegistry + Sync,
    S: SignalSink + Sync,
{
    pub(crate) fn webauthn(&self) -> Rp<'a, P, C, R, S> {
        WebAuthn {
            registry: Registry(self.passkeys.registry),
            clock: Seconds(self.clock),
            random: Bytes(self.random),
            decoys: Decoys(self.passkeys.decoys),
            signals: Signals(self.passkeys.signals),
        }
    }

    pub(crate) fn wa_realm(&self) -> RealmId {
        RealmId::from_bytes(*self.realm.realm.as_bytes())
    }
}
