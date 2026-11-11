//! The replicas a provider declares for each domain and how far each acknowledged (§16.6.1,
//! T21, TI-13, SEC23, OP-158 m.3 (e), (f)). An acknowledgement counts only when it verifies
//! under the declared replica's key and names a checkpoint the domain signed; without a
//! declared replica nothing is ever acknowledged (fail closed).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};
use std::time::Duration;

use access_kernel::digest::Digest;
use tokio::sync::Notify;

/// One declared replica: its name, the Ed25519 key its acks are signed with, its operator and
/// whether that operator is outside the provider (CMP-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replica {
    /// The name its acks carry.
    pub name: String,
    /// Its Ed25519 public key.
    pub key: [u8; 32],
    /// Who runs it.
    pub operator: String,
    /// Not run by the provider's operator.
    pub independent: bool,
}

#[derive(Default)]
struct Slot {
    declared: Vec<Replica>,
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

    /// Declares `replicas` for `domain`, replacing what was declared.
    pub fn declare(&self, domain: Digest, replicas: Vec<Replica>) {
        self.with(|s| s.entry(domain).or_default().declared = replicas);
    }

    /// The replicas declared for `domain`.
    #[must_use]
    pub fn declared(&self, domain: &Digest) -> Vec<Replica> {
        self.with(|s| {
            s.get(domain)
                .map(|slot| slot.declared.clone())
                .unwrap_or_default()
        })
    }

    /// The declared replica named `name`.
    #[must_use]
    pub fn named(&self, domain: &Digest, name: &str) -> Option<Replica> {
        self.declared(domain).into_iter().find(|r| r.name == name)
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
        r.declare(
            d,
            vec![Replica {
                name: String::from("a"),
                key: access_crypto::random::bytes::<32>().unwrap(),
                operator: String::from("o"),
                independent: true,
            }],
        );
        assert!(r.named(&d, "a").is_some());
        assert!(r.named(&d, "b").is_none());
        assert_eq!(r.declared(&Digest([0x52; 32])), Vec::new());
    }
}
