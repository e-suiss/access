//! What delivery needs from the outside world (OP-63). The realm's SET signer, the clock and
//! randomness are the identity plane's existing ports.

use std::future::Future;

use access_crypto::opaque_id::IdKey;
use access_store::events::SealedKey;
use access_store::identity::{RealmId, TenantId};
use zeroize::Zeroizing;

pub use access_identity_oauth::ports::Unavailable;
pub use access_identity_oauth::ports::dpop::Clock;
pub use access_identity_oauth::ports::oauth::{Random, TokenSigner};

/// Names tenants outside by their opaque `tnt_` id (OP-137, OP-149 m.15 (i)).
pub trait TenantIds: Send + Sync {
    /// The external id of `tenant`; `None` when the cell's id key cannot be used.
    fn external(&self, tenant: &[u8; 16]) -> Option<String>;

    /// The tenant an external id names; `None` for text that is not a `tnt_` id.
    fn internal(&self, text: &str) -> Option<[u8; 16]>;
}

impl TenantIds for IdKey {
    fn external(&self, tenant: &[u8; 16]) -> Option<String> {
        self.encode(crate::domain::catalog::TENANT_PREFIX, *tenant)
            .ok()
    }

    fn internal(&self, text: &str) -> Option<[u8; 16]> {
        self.decode(crate::domain::catalog::TENANT_PREFIX, text)
            .ok()
    }
}

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
