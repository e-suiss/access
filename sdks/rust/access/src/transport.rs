//! What the caller's I/O hands back to the SDK (§9.5 "Access-unavailable", §9.5.2 k.8, MD-8):
//! a response as received, or the fact that none came. The SDK decides; the transport only
//! reports.

use alloc::string::String;
use alloc::vec::Vec;

use access_kernel::model::TrustedTime;

/// Why no response came. Every variant is an unknown state for the PEP, never an ALLOW.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Fault {
    /// The deadline passed.
    #[error("timeout")]
    Timeout,
    /// The upstream could not be reached.
    #[error("unreachable")]
    Unreachable,
    /// The transport failed in another way.
    #[error("transport")]
    Transport,
}

/// An HTTP response as received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// `Content-Type`, when the transport saw one.
    pub content_type: Option<String>,
    /// The `access-key-excerpt` header, decoded, when present (OP-150 m.10 (e)).
    pub key_excerpt: Option<Vec<u8>>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A plain response without headers.
    #[must_use]
    pub const fn new(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: None,
            key_excerpt: None,
            body,
        }
    }
}

/// What came back from an upstream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// A response.
    Response(Response),
    /// No response.
    Unanswered(Fault),
}

/// The trusted clock port (T25): the time the SDK checks horizons and windows against. `None`
/// means the caller has no trusted time; every decision is then a DENY.
pub trait Clock {
    /// Trusted time, Unix milliseconds.
    fn now(&self) -> Option<TrustedTime>;
}

/// A clock fixed at one instant, for a request whose trusted time the caller already read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedClock(pub TrustedTime);

impl Clock for FixedClock {
    fn now(&self) -> Option<TrustedTime> {
        Some(self.0)
    }
}
