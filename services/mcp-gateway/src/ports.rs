//! The gateway's ports (OP-63): Access over its public listener as this gateway's PEP
//! identity, the MCP server behind it, and time. A port reports what came back; it never
//! decides.

use std::future::Future;

use access_sdk::transport::Answer;

/// Trusted time.
pub trait Clock: Send + Sync {
    /// Unix milliseconds; `None` without trusted time, and then nothing is called.
    fn now(&self) -> Option<u64>;
}

/// Access, reached as any registered proxy reaches it: the public routes with this gateway's
/// client certificate (OP-62, B22).
pub trait Access: Send + Sync {
    /// `POST /proxy/v1/mcp/tools`.
    fn tools(&self, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
    /// `POST /proxy/v1/mcp/calls`.
    fn calls(&self, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
    /// `GET /.well-known/access-domain-metadata/sha-256:{domain}`.
    fn metadata(&self, domain: String) -> impl Future<Output = Answer> + Send;
}

/// The MCP server the gateway stands in front of.
pub trait Upstream: Send + Sync {
    /// Sends one JSON-RPC request body to the MCP endpoint.
    fn send(&self, body: Vec<u8>) -> impl Future<Output = Answer> + Send;
}
