//! What the export pass reaches outside the database (OP-63): the sinks over HTTPS or syslog TLS,
//! and the realm KEKs that open the sinks' secrets.

use std::future::Future;

pub use access_identity_events::adapters::RealmKek;

use crate::domain::collector::Request;

/// A sink did not accept: the code says why, without the secret or the sink's answer body
/// (OP-64).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Down(pub String);

/// The sinks' transports.
pub trait Wire: Send + Sync {
    /// Sends `request` and reads its answer's status and body, up to `max_body` bytes.
    fn http(
        &self,
        request: &Request,
        max_body: usize,
    ) -> impl Future<Output = Result<(u16, Vec<u8>), Down>> + Send;

    /// Writes `frames` to the syslog receiver at `host:port` over TLS and closes the stream.
    fn syslog(
        &self,
        endpoint: (&str, u16),
        frames: &[u8],
    ) -> impl Future<Output = Result<(), Down>> + Send;
}
