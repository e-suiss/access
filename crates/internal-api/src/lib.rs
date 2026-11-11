//! The only contract between the identity and authority planes (OP-62): typed messages, no logic.

pub mod approvals;
pub mod claims;
pub mod context;
pub mod edge;
pub mod epochs;
pub mod events;
pub mod idp;
pub mod instances;
pub mod linux;
pub mod one;
pub mod projections;
pub mod saml;
pub mod signals;
pub mod ssh;
pub mod support;

#[cfg(test)]
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}
