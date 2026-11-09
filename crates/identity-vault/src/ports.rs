//! What the vault needs from the outside world (OP-63): the authority plane's record of an
//! allowed Exercise, HTTPS to upstreams and the realm's client secrets (the federation ports,
//! through the SSRF-guarded outbound client), and randomness. Each fails closed (MD-8).

use std::future::Future;

use access_kernel::intent::IntentEnvelope;

use crate::domain::release::Allowed;

pub use access_identity_federation::ports::{Answer, ProviderHttp, SocialSecrets, Unreachable};

/// The authority plane did not answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("authority plane unavailable")]
pub struct Unavailable;

/// Reads allowed Exercises (OP-149 m.9) for a release.
pub trait Exercises: Send + Sync {
    /// What the domain `domain` kept of the allowed Exercise `exercise` when `intent` is the
    /// intent it was allowed for: the receipt's PEP, the Party acted for, the tier from the
    /// accepted Action Schema and whether its basis stands now. `None` for an Exercise the
    /// domain never allowed, one whose receipt was not kept, or another intent.
    fn allowed(
        &self,
        domain: [u8; 32],
        exercise: [u8; 32],
        intent: &IntentEnvelope,
    ) -> impl Future<Output = Result<Option<Allowed>, Unavailable>> + Send;
}

/// Randomness for `state` and PKCE verifiers (OP-63).
pub trait Random: Send + Sync {
    /// Fills `out`.
    ///
    /// # Errors
    /// [`Unavailable`].
    fn fill(&self, out: &mut [u8]) -> Result<(), Unavailable>;
}
