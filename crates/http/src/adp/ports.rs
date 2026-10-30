//! What the ADP surface needs (OP-63): a decision point and trusted time.

use std::future::Future;

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Response};

/// Evaluates one request (the authority core of the request's domain).
pub trait Pdp: Send + Sync {
    /// The decision for `inc` at `now`.
    fn evaluate(
        &self,
        inc: Incoming,
        now: u64,
    ) -> impl Future<Output = Result<Response, CoreError>> + Send;
}

/// Trusted time in milliseconds (OP-63: the clock is a port).
pub trait Clock: Send + Sync {
    /// Now.
    fn now(&self) -> u64;
}
