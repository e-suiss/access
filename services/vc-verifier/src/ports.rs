//! The verifier's ports (OP-63): Access's Claim Ingest over its public listener, outbound
//! fetches (DID documents, issuer metadata, status lists, trusted lists), time and randomness.
//! A port reports what came back; it never decides.

use std::future::Future;

pub use access_sdk::transport::{Answer, Fault, Response};

/// Trusted time.
pub trait Clock: Send + Sync {
    /// Unix milliseconds; `None` without trusted time, and then nothing is verified.
    fn now(&self) -> Option<u64>;
}

/// Randomness.
pub trait Random: Send + Sync {
    /// 16 fresh bytes; `None` when there are none.
    fn bytes(&self) -> Option<[u8; 16]>;
}

/// Access, reached as any third-party issuer reaches it: Claim Ingest on the public listener
/// with the verifier's client certificate (OP-62).
pub trait Access: Send + Sync {
    /// `POST /access/v1/claims:ingest` with `Idempotency-Key: key`.
    fn ingest(&self, key: String, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
}

/// The guarded outbound fetcher: `https` only, no redirect, no private or loopback address,
/// bounded size and time.
pub trait Fetch: Send + Sync {
    /// `GET url` with `Accept: accept`.
    fn get(&self, url: String, accept: &'static str) -> impl Future<Output = Answer> + Send;
}
