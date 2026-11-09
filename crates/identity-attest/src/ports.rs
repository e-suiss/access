//! What the workload checks need from outside (OP-63): a realm's kept SPIFFE bundles and the
//! guarded fetch of a Bundle Endpoint (OP-154 m.1 (d)).

use core::future::Future;
use core::pin::Pin;

/// The store or the network could not answer; the request is shed, never decided (G50).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unavailable")]
pub struct Unavailable;

/// A boxed future of the ports.
pub type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, Unavailable>> + Send + 'a>>;

/// A bundle as the realm keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kept {
    /// The Bundle Endpoint it was fetched from.
    pub endpoint: String,
    /// The document as fetched.
    pub document: Vec<u8>,
    /// When it was fetched, Unix milliseconds.
    pub fetched_ms: u64,
}

/// A realm's SPIFFE bundles, keyed by trust domain alone
/// (`draft-ietf-oauth-spiffe-client-auth` §6).
pub trait Bundles: Send + Sync {
    /// The bundle `realm` keeps for `trust_domain`, if any.
    fn kept<'a>(&'a self, realm: [u8; 16], trust_domain: &'a str) -> Pending<'a, Option<Kept>>;

    /// Keeps `kept` as `realm`'s bundle of `trust_domain`.
    fn keep<'a>(&'a self, realm: [u8; 16], trust_domain: &'a str, kept: Kept) -> Pending<'a, ()>;

    /// Fetches `endpoint` over the SSRF-guarded outbound client; `None` when the fetch is
    /// refused or fails, which keeps the bundle the realm has.
    fn fetch<'a>(&'a self, endpoint: &'a str) -> Pending<'a, Option<Vec<u8>>>;
}

/// No bundle source: every SVID is refused (fail closed).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoBundles;

impl Bundles for NoBundles {
    fn kept<'a>(&'a self, _: [u8; 16], _: &'a str) -> Pending<'a, Option<Kept>> {
        Box::pin(async { Ok(None) })
    }

    fn keep<'a>(&'a self, _: [u8; 16], _: &'a str, _: Kept) -> Pending<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn fetch<'a>(&'a self, _: &'a str) -> Pending<'a, Option<Vec<u8>>> {
        Box::pin(async { Ok(None) })
    }
}
