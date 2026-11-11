//! How far each domain's declared replicas acknowledged (§16.6.1, T21, TI-13, SEC23, OP-158
//! m.3 (e), (f)). The replicas are the ones the domain's Domain Metadata declares; an
//! acknowledgement counts only when it verifies under the declared key and names a checkpoint
//! the domain signed. Without a declared replica nothing is ever acknowledged (fail closed).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use access_kernel::digest::Digest;
use tokio::sync::Notify;

pub use access_store::mirror::{ExportRun, RunKind};
pub use suiss_ledger::replica::mirror::{Frame, SignedReplicaAck};

/// What the answer to a SEC23-class commit says of its acknowledgement (SEC23, CL-2, OP-158
/// m.3 (e)). The record is committed and effective either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ack {
    /// A declared replica holds it and an independent witness cosigned it.
    Witnessed,
    /// Not yet: the client asks again with the same nonce.
    Pending,
}

impl Ack {
    /// The wire word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Witnessed => "witnessed",
            Self::Pending => "pending",
        }
    }
}

/// The meta-actions whose commit is acknowledged only once mirrored and witnessed besides
/// every CT3 commit and every `*revoke` action (SEC23, TI-6, OP-158 m.3 (e)): revocations,
/// Instance termination, restriction and Acceptance changes. A `policy.set` and an Acceptance
/// amendment count whichever way they go (fail closed).
pub const SEC23_META: [&str; 6] = [
    "grant_revoke",
    "mandate_revoke",
    "acceptance_revoke",
    "acceptance_amend",
    "instance_terminate",
    "policy_set",
];

/// Whether a commit of action `name` (meta-action or domain action) at consequence tier
/// `tier` is in the SEC23 class.
#[must_use]
pub fn sec23(name: &str, tier: Option<u8>) -> bool {
    tier == Some(3) || SEC23_META.contains(&name) || name.ends_with("revoke")
}

#[derive(Default)]
struct Slot {
    acked: u64,
}

/// What this process knows of each domain's replicas.
#[derive(Default)]
pub struct Replicas {
    slots: Mutex<HashMap<Digest, Slot>>,
    progress: Notify,
}

impl Replicas {
    fn with<T>(&self, f: impl FnOnce(&mut HashMap<Digest, Slot>) -> T) -> T {
        f(&mut self.slots.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// A declared replica holds `size` records of `domain` durably; waiters it covers return.
    pub fn set_acked(&self, domain: Digest, size: u64) {
        self.with(|s| {
            let slot = s.entry(domain).or_default();
            slot.acked = slot.acked.max(size);
        });
        self.progress.notify_waiters();
    }

    /// The largest size a declared replica of `domain` acknowledged, as this process saw it.
    #[must_use]
    pub fn acked(&self, domain: &Digest) -> u64 {
        self.with(|s| s.get(domain).map_or(0, |slot| slot.acked))
    }

    /// Waits until a declared replica holds `size` records of `domain`, at most `wait`,
    /// looking again every `every` in case the ack reached another process; `Err` with the
    /// size seen when it did not.
    ///
    /// # Errors
    /// The acknowledged size, below `size`.
    pub async fn wait<F, Fut>(
        &self,
        domain: Digest,
        size: u64,
        (wait, every): (Duration, Duration),
        mut look: F,
    ) -> Result<u64, u64>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = u64>,
    {
        let deadline = tokio::time::Instant::now()
            .checked_add(wait)
            .unwrap_or_else(tokio::time::Instant::now);
        loop {
            let progressed = self.progress.notified();
            let seen = self.acked(&domain).max(look().await);
            if seen >= size {
                self.set_acked(domain, seen);
                return Ok(seen);
            }
            let next = tokio::time::Instant::now()
                .checked_add(every)
                .unwrap_or(deadline)
                .min(deadline);
            let woken = tokio::time::timeout_at(next, progressed).await.is_ok();
            if !woken && tokio::time::Instant::now() >= deadline {
                let seen = self.acked(&domain).max(look().await);
                return if seen >= size { Ok(seen) } else { Err(seen) };
            }
        }
    }
}

/// The process's replicas.
#[must_use]
pub fn replicas() -> &'static Replicas {
    static REPLICAS: OnceLock<Replicas> = OnceLock::new();
    REPLICAS.get_or_init(Replicas::default)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    // TI-13, SEC23
    #[tokio::test]
    async fn a_wait_returns_when_an_ack_covers_it_and_says_pending_otherwise() {
        let r = Replicas::default();
        let d = Digest([0x51; 32]);
        let short = (Duration::from_millis(30), Duration::from_millis(10));
        assert_eq!(r.wait(d, 3, short, || async { 0 }).await, Err(0));
        assert_eq!(r.wait(d, 3, short, || async { 4 }).await, Ok(4));
        assert_eq!(r.acked(&d), 4);
        r.set_acked(d, 2);
        assert_eq!(r.acked(&d), 4);
        assert_eq!(r.wait(d, 4, short, || async { 0 }).await, Ok(4));
        assert_eq!(r.acked(&Digest([0x52; 32])), 0);
    }

    // SEC23, TI-6
    #[test]
    fn revocations_restrictions_and_ct3_commits_are_the_sec23_class() {
        for name in [
            "grant_revoke",
            "instance_terminate",
            "policy_set",
            "acceptance_amend",
        ] {
            assert!(sec23(name, Some(1)), "{name}");
        }
        assert!(sec23("idp.session.revoke", None));
        assert!(sec23("grant_issue", Some(3)));
        assert!(!sec23("grant_issue", Some(2)));
        assert!(!sec23("audit_export", None));
    }
}
