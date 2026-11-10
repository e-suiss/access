//! One courier per outbox consumer (OP-156 m.3 (c), OP-31): a node sends only while it holds
//! the consumer's lease in `access_ops.courier_leases`, for [`TTL`] at a time, and its cursor
//! moves only under that lease's epoch. A node whose lease ran out stops after the send in
//! flight; another node takes over when the lease expires or is released.

use core::fmt::Write as _;
use std::time::Duration;

pub use access_store::relay::CourierLease;

/// How long a lease lasts unless renewed (PD).
pub const TTL: Duration = Duration::from_secs(10);

/// How long a node without the lease waits before it asks again (PD).
pub const RETRY: Duration = Duration::from_millis(3_000);

/// A lease and the local deadline before which this node may send under it. The deadline is
/// read before the lease is asked for, so it never passes the stored expiry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Term {
    /// The held lease.
    pub lease: CourierLease,
    /// Unix ms after which this node no longer sends under it.
    pub until_ms: u64,
}

impl Term {
    /// A term that began at `asked_ms`, when the lease was requested, for `ttl`.
    #[must_use]
    pub fn new(lease: CourierLease, asked_ms: u64, ttl: Duration) -> Self {
        let ttl_ms = u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        Self {
            lease,
            until_ms: asked_ms.saturating_add(ttl_ms),
        }
    }

    /// Whether this node may still send at `now_ms`.
    #[must_use]
    pub const fn live(&self, now_ms: u64) -> bool {
        now_ms < self.until_ms
    }

    /// Whether the lease should be renewed at `now_ms`: less than half of `ttl` is left.
    #[must_use]
    pub fn due(&self, now_ms: u64, ttl: Duration) -> bool {
        let half = u64::try_from(ttl.as_millis() / 2).unwrap_or(u64::MAX);
        self.until_ms.saturating_sub(now_ms) < half
    }
}

/// A holder name for this process: the host's name when it is set, and a random suffix, so two
/// processes on one host never share a lease.
#[must_use]
pub fn holder(host: Option<&str>, random: [u8; 8]) -> String {
    let host: String = host
        .unwrap_or("access")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
        .take(96)
        .collect();
    let mut out = if host.is_empty() {
        String::from("access")
    } else {
        host
    };
    out.push('/');
    for b in random {
        let _ = write!(out, "{b:02x}");
    }
    out
}
