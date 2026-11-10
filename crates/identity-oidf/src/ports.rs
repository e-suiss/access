//! What resolution needs from the outside world (OP-63): a fetch of one federation document
//! through the guarded outbound client (§10.7.1 item 8).

use std::future::Future;

/// The fetch could not be made: refused by the outbound guard or no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unreachable")]
pub struct Unreachable;

/// Fetches federation documents.
pub trait Fetch: Send + Sync {
    /// The status and body of a `GET` of `url`, asking for `accept`.
    fn fetch(
        &self,
        url: &str,
        accept: &str,
    ) -> impl Future<Output = Result<(u16, Vec<u8>), Unreachable>> + Send;
}
