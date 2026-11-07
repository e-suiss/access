//! What hooks need from the outside world (OP-63), and the one port the call sites use.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use access_crypto::webhook::{WebhookSecret, WebhookSigningKey};
use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};
use zeroize::Zeroizing;

use crate::domain::{Call, HookPoint, Outcome, Registration, Reply};

/// A port that could not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// The future a [`HookCaller`] returns.
pub type CallFuture<'a> = Pin<Box<dyn Future<Output = Outcome> + Send + 'a>>;

/// The call sites' port (TN-135): registration, token issuance and sign-in completion ask it
/// at their call point and act on the [`Outcome`]. It never fails: whatever goes wrong is a
/// refusal (MD-8), or, for `token_issuance` with `continue_without_claims`, no claims.
pub trait HookCaller: Send + Sync {
    /// Calls the realm's live hook at `call`'s point, if there is one.
    fn call(&self, tenant: TenantId, realm: RealmId, call: Call) -> CallFuture<'_>;
}

/// No hook anywhere: every call point goes on unchanged.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoHooks;

impl HookCaller for NoHooks {
    fn call(&self, _: TenantId, _: RealmId, _: Call) -> CallFuture<'_> {
        Box::pin(async { Outcome::proceed() })
    }
}

/// A hook's signing key, opened.
pub enum HookKey {
    /// `v1a`.
    Ed25519(WebhookSigningKey),
    /// `v1`.
    Hmac(WebhookSecret),
}

impl core::fmt::Debug for HookKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("HookKey(<redacted>)")
    }
}

impl HookKey {
    /// The Standard Webhooks signature entry of one request.
    #[must_use]
    pub fn sign(&self, id: &str, timestamp_s: u64, body: &[u8]) -> String {
        match self {
            Self::Ed25519(k) => k.sign(id, timestamp_s, body),
            Self::Hmac(k) => k.sign(id, timestamp_s, body),
        }
    }
}

/// A live hook with its opened key.
#[derive(Debug)]
pub struct LiveHook {
    /// The registration.
    pub registration: Registration,
    /// Its signing key.
    pub key: HookKey,
    /// Whether the realm's extension policy permits disclosing the e-mail (OP-151 m.10 (e)).
    pub realm_allows_disclosure: bool,
}

/// Where live hooks are found.
pub trait HookRegistry: Send + Sync {
    /// The realm's live hook at `point`.
    fn live(
        &self,
        tenant: TenantId,
        realm: RealmId,
        point: HookPoint,
    ) -> impl Future<Output = Result<Option<LiveHook>, Unavailable>> + Send;
}

/// The tenant's endpoint, behind the SSRF guard (§14.3).
pub trait HookTransport: Send + Sync {
    /// `POST url` with a JSON `body` and `headers`, answered within `deadline`; the answer
    /// body is read up to [`crate::domain::MAX_ANSWER`] bytes plus one.
    fn post(
        &self,
        url: &str,
        headers: &[(&'static str, String)],
        body: &[u8],
        deadline: Duration,
    ) -> impl Future<Output = Reply> + Send;
}

/// Trusted time.
pub trait HookClock: Send + Sync {
    /// Now, Unix ms; `None` when the clock cannot be trusted.
    fn now_ms(&self) -> Option<u64>;
}

/// Seals and opens hook and webhook keys under the realm KEK (OP-42, OP-135).
pub trait KeyVault: Send + Sync {
    /// Seals `plain` for registration `id`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn seal(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        plain: &[u8],
    ) -> Result<SealedKey, Unavailable>;

    /// Opens what was sealed for registration `id`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Result<Zeroizing<Vec<u8>>, Unavailable>;
}
