//! Resolution over a [`Fetch`] port: drives the sans-I/O [`Resolver`] to a chain or a refusal
//! (IDP-19, OP-155 m.3 (j)).

use crate::domain::chain::{Chain, ChainError, Resolver, Step, TrustAnchor};
use crate::domain::statement::CONTENT_TYPE;
use crate::ports::Fetch;

/// Resolves the chain of `leaf` to one of `anchors` at `now_ms`; an unreachable document counts
/// as a refused path.
///
/// # Errors
/// [`ChainError`].
pub async fn resolve<F: Fetch>(
    fetch: &F,
    leaf: &str,
    anchors: Vec<TrustAnchor>,
    now_ms: u64,
) -> Result<Chain, ChainError> {
    let mut r = Resolver::new(leaf, anchors, now_ms);
    loop {
        match r.step() {
            Step::Fetch { url } => match fetch.fetch(&url, CONTENT_TYPE).await {
                Ok((status, body)) => r.feed(&url, status, &body),
                Err(_) => r.feed(&url, 0, &[]),
            },
            Step::Done(c) => return Ok(*c),
            Step::Failed(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests;
