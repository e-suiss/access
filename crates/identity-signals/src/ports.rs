//! What a signal connector needs from outside (OP-63): a way to sign and send one Claim as the
//! source's own issuer.

use std::future::Future;

use access_internal_api::signals::Signal;

/// The connector could not send: nothing was claimed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("signal unavailable: {0}")]
pub struct Unavailable(pub String);

/// Signs one signal Claim as the source's issuer and sends it, body beside it, to Claim Ingest.
pub trait Issuer: Send + Sync {
    /// Issues `signal` about `subject`.
    fn issue(
        &self,
        subject: [u8; 16],
        signal: &Signal,
    ) -> impl Future<Output = Result<(), Unavailable>> + Send;
}
