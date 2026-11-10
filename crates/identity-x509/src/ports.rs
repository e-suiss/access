//! What revocation needs from outside (OP-63): fetching an OCSP answer or a CRL over the
//! SSRF-guarded outbound client, which for these signed documents also reaches `http` on port
//! 80 (OP-155 m.3 (m)).

use core::future::Future;
use core::pin::Pin;

/// No answer: refused by the guard, unreachable, not `200`, or larger than allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unreachable")]
pub struct Unreachable;

/// A boxed future of the port.
pub type Fetched<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, Unreachable>> + Send + 'a>>;

/// One fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// `POST url` with an OCSP request.
    Ocsp {
        /// The responder.
        url: &'a str,
        /// The DER request.
        body: &'a [u8],
    },
    /// `GET url` of a CRL.
    Crl {
        /// The distribution point.
        url: &'a str,
    },
}

/// Fetches revocation documents.
pub trait Fetch: Send + Sync {
    /// The body of a `200` answer to `request`.
    fn fetch<'a>(&'a self, request: Request<'a>) -> Fetched<'a>;
}

/// No network: every certificate's status is unknown, so every certificate is refused (MD-8).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFetch;

impl Fetch for NoFetch {
    fn fetch<'a>(&'a self, _: Request<'a>) -> Fetched<'a> {
        Box::pin(async { Err(Unreachable) })
    }
}
