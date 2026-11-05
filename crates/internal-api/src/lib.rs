//! The only contract between the identity and authority planes (OP-62): typed messages, no logic.

pub mod claims;
pub mod epochs;
pub mod events;
pub mod idp;
pub mod instances;
pub mod projections;

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
