//! What the ADP surface needs (OP-63): a decision point, which reads its own trusted time
//! under the domain's lock (OP-141 m.18 (c)).

use std::future::Future;
use std::sync::Arc;

use access_authority_core::CoreError;
use access_authority_core::app::{Incoming, Response};
use access_authority_core::query::{Hit, Query};

/// Evaluates one request (the authority core of the request's domain).
pub trait Pdp: Send + Sync {
    /// The decision for `inc`.
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send;

    /// One page of a search (OP-141 m.22); none by default.
    fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> impl Future<Output = Result<Page, CoreError>> + Send {
        let _ = (inc, query, page);
        std::future::ready(Err(CoreError::Protocol("search")))
    }
}

/// Results and the next page token.
pub type Page = (Vec<Hit>, Option<String>);

impl<P: Pdp> Pdp for Arc<P> {
    fn evaluate(&self, inc: Incoming) -> impl Future<Output = Result<Response, CoreError>> + Send {
        (**self).evaluate(inc)
    }

    fn search(
        &self,
        inc: Incoming,
        query: Query,
        page: Option<String>,
    ) -> impl Future<Output = Result<Page, CoreError>> + Send {
        (**self).search(inc, query, page)
    }
}
