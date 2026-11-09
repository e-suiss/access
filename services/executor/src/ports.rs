//! The executor's ports (OP-63): Access over its public listener as this executor's PEP
//! identity, the upstreams, time and randomness. A port reports what came back; it never
//! decides.

use std::future::Future;

use access_sdk::transport::Answer;

use crate::drivers::HttpRequest;

/// Trusted time.
pub trait Clock: Send + Sync {
    /// Unix milliseconds; `None` without trusted time, and then nothing happens.
    fn now(&self) -> Option<u64>;
}

/// Randomness.
pub trait Random: Send + Sync {
    /// 16 fresh bytes; `None` when there are none.
    fn bytes(&self) -> Option<[u8; 16]>;
}

/// Access, reached as any third-party PEP reaches it: the public routes with this executor's
/// client certificate (OP-62, CMP-16 pattern).
pub trait Access: Send + Sync {
    /// `POST /access/v1/evaluation`.
    fn evaluate(&self, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
    /// `GET /.well-known/access-domain-metadata/sha-256:{domain}`.
    fn metadata(&self, domain: String) -> impl Future<Output = Answer> + Send;
    /// `POST /realms/{realm}/v1/vault/releases`.
    fn release(&self, realm: String, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
    /// `POST /access/v1/claims:ingest` with `Idempotency-Key: key`.
    fn ingest(&self, key: String, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
}

/// The upstreams a step calls.
pub trait Upstream: Send + Sync {
    /// Sends one request.
    fn send(&self, request: HttpRequest) -> impl Future<Output = Answer> + Send;
}
