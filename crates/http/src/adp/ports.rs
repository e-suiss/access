//! What the ADP surface needs (OP-63): a decision point, which reads its own trusted time
//! under the domain's lock (OP-141 m.18 (c)).

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Response};

/// Evaluates one request (the authority core of the request's domain).
pub trait Pdp: Send + Sync {
    /// The decision for `inc`.
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send;
}

impl<P: Pdp> Pdp for Arc<P> {
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send {
        (**self).evaluate(inc)
    }
}
