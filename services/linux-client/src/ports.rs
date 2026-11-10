//! The daemon's ports (OP-63): Access's public routes, the clock, randomness, a local security
//! key and the kept state. Access answers or it does not; a missing answer is never a guess.

use std::future::Future;

use crate::domain::fido::Credential;
use crate::domain::state::State;

/// Access answered with this, or could not be reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reached<T> {
    /// Access answered.
    Answer(T),
    /// No answer within the timeout, or an answer outside the contract.
    Unreachable,
}

/// A device authorization Access started (RFC 8628 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceStart {
    /// The device code, polled by the daemon only.
    pub device_code: String,
    /// What the person enters.
    pub user_code: String,
    /// Where.
    pub verification_uri: String,
    /// Seconds until it ends.
    pub expires_in: u64,
    /// Seconds between polls.
    pub interval: u64,
}

/// One poll of a device authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DevicePoll {
    /// Not decided yet.
    Pending,
    /// Decided: the DPoP-bound access token of the person who approved it.
    Token(String),
    /// Refused, expired or spent.
    Ended,
}

/// What Access decided about a console sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignIn {
    /// Allowed.
    pub allow: bool,
    /// The person's security keys, for offline sign-in within 8 hours.
    pub credentials: Vec<Credential>,
}

/// Access's public Linux routes as this host reaches them with its client certificate.
pub trait Access: Send + Sync {
    /// `POST /linux/v1/nss`: the host's NSS snapshot.
    fn snapshot(&self) -> impl Future<Output = Reached<Vec<u8>>> + Send;

    /// `POST /device_authorization` as the host's client.
    fn device_start(&self) -> impl Future<Output = Reached<DeviceStart>> + Send;

    /// `POST /token` with the device code and a DPoP proof.
    fn device_poll(&self, device_code: &str) -> impl Future<Output = Reached<DevicePoll>> + Send;

    /// `POST /linux/v1/auth` for `user` with the person's token.
    fn sign_in(&self, token: &str, user: &str) -> impl Future<Output = Reached<SignIn>> + Send;

    /// `POST /linux/v1/sudo` for `user` and the command's digest with the person's token.
    fn sudo(
        &self,
        token: &str,
        user: &str,
        command: &[u8; 32],
    ) -> impl Future<Output = Reached<bool>> + Send;
}

/// The daemon's clock, Unix ms; `None` when it cannot be read.
pub trait Clock: Send + Sync {
    /// Now.
    fn now_ms(&self) -> Option<u64>;
}

/// Randomness; `None` when the source failed.
pub trait Random: Send + Sync {
    /// `N` random bytes.
    fn bytes<const N: usize>(&self) -> Option<[u8; N]>;
}

/// A local security key's `authenticatorGetAssertion`.
pub trait SecurityKey: Send + Sync {
    /// The key's answer (status byte and CBOR) to the CTAP2 command `request`; `None` when no
    /// key is present or it did not answer.
    fn get_assertion(&self, request: &[u8]) -> impl Future<Output = Option<Vec<u8>>> + Send;
}

/// The kept state.
pub trait Keep: Send + Sync {
    /// The state as last saved; an unreadable state is the empty state.
    fn load(&self) -> State;
    /// Saves the state; `false` when it could not.
    fn save(&self, state: &State) -> bool;
}
