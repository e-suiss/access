//! What delivery needs from the outside world (OP-63). The realm's SET signer, the clock and
//! randomness are the identity plane's existing ports.

use std::future::Future;

use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};
use zeroize::Zeroizing;

pub use access_identity_oauth::ports::Unavailable;
pub use access_identity_oauth::ports::dpop::Clock;
pub use access_identity_oauth::ports::oauth::{Random, TenantIds, TokenSigner};

/// A receiver's HTTP answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    /// Status.
    pub status: u16,
    /// `Retry-After`, ms.
    pub retry_after_ms: Option<u64>,
}

/// Why a push got no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostError {
    /// Not sent: the URL or the address it resolves to is not one Access posts to (§14.3).
    Refused,
    /// No answer; worth trying again.
    Unreachable,
}

/// The receiver's endpoint, behind the SSRF guard.
pub trait Transport: Send + Sync {
    /// `POST url` with `content_type`, extra `headers` and `body`.
    fn post(
        &self,
        url: &str,
        content_type: &str,
        headers: &[(&str, String)],
        body: &[u8],
    ) -> impl Future<Output = Result<Reply, PostError>> + Send;
}

/// An RFC 8936 poll transmitter, behind the SSRF guard (OP-151 m.3 (l)).
pub trait PollClient: Send + Sync {
    /// `POST url` with the bearer credential and the JSON poll request `body`; the answer's
    /// status and body.
    fn poll(
        &self,
        url: &str,
        bearer: &str,
        body: &[u8],
    ) -> impl Future<Output = Result<(u16, Vec<u8>), PostError>> + Send;
}

/// Seals and opens a webhook subscription's secret under the realm KEK (OP-42, OP-135).
pub trait Sealer: Send + Sync {
    /// Seals `plain` for subscription `id`.
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

    /// Opens what [`Sealer::seal`] sealed.
    ///
    /// # Errors
    /// [`Unavailable`] for a missing KEK or bytes that do not open.
    fn open(
        &self,
        tenant: TenantId,
        realm: RealmId,
        id: &[u8; 16],
        sealed: &SealedKey,
    ) -> Result<Zeroizing<Vec<u8>>, Unavailable>;
}
