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

/// A boxed future, for the ports an executor holds as trait objects.
pub type Boxed<'a, T> = std::pin::Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The cloud executor's isolation (E61, OP-156 m.3 (w)): one attested microVM per person, its
/// disk under a random key wrapped to the person's `one_browser_profile` DEK. There is no
/// default adapter; without one the cloud executor starts no job.
pub trait Isolation: Send + Sync {
    /// The person's own microVM, opened or found, and its TEE report; `None` when there is none.
    fn open(&self, person: [u8; 16]) -> Boxed<'_, Option<crate::domain::isolation::Report>>;

    /// Destroys the person's disk key and every wrapped DEK copy in the TEE (crypto-shred,
    /// E59 (3), E61 (4)); `true` once the TEE confirms it.
    fn destroy(&self, person: [u8; 16]) -> Boxed<'_, bool>;
}

/// The person's own coding tool on their device (E57 (2)), run by the local executor. It holds
/// its own sign-in in its own store; nothing here reads or carries it (E57 (3)).
pub trait LocalTool: Send + Sync {
    /// Runs one step: a tool call, a file write or a command.
    fn run(
        &self,
        step: &crate::domain::bridge::ToolStep,
    ) -> Boxed<'_, Option<crate::domain::bridge::ToolOutput>>;
}
