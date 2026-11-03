//! Login throttling (OP-35, SA-30, TN-82, TN-83, §10.2.1 m.4): per-key rate and failure
//! penalties. Account keys are derived from the identifier, never from whether an account
//! exists, so a missing account is throttled exactly like a present one (CR-36 m.4).

use crate::domain::gcra::{Gcra, GcraDecision};

/// One day in milliseconds; the counter partitions are daily (OP-146 m.5 (f)).
pub const DAY_MS: u64 = 86_400_000;

/// What a counter key counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// One login identifier in a realm.
    Account,
    /// One identifier from one network (TN-82).
    AccountIp,
    /// One network (§10.2.1 m.4).
    Ip,
}

impl KeyKind {
    /// Domain separation byte of the key digest.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Account => 1,
            Self::AccountIp => 2,
            Self::Ip => 3,
        }
    }
}

/// How failures are punished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Penalty {
    /// A wait after each consecutive failure, `first_ms` doubling up to `cap_ms`; a hard lock
    /// at `lock_at` consecutive failures (SA-30). A success resets it.
    Doubling {
        /// First wait.
        first_ms: u64,
        /// Longest wait.
        cap_ms: u64,
        /// Consecutive failures that lock, if any.
        lock_at: Option<u32>,
    },
    /// An exponential blacklist by failure count; a quiet `decay_ms` restarts the count.
    Tiers {
        /// `(failures, ban)`, ascending.
        tiers: &'static [(u32, u64)],
        /// Quiet time after which the count restarts.
        decay_ms: u64,
    },
}

/// Rauthy's blacklist tiers (§10.2.1 m.4; PD): 7 → 60 s, 10 → 600 s, 15 → 900 s,
/// 20 → 3,600 s, 25 → 24 h.
pub const IP_TIERS: &[(u32, u64)] = &[
    (7, 60_000),
    (10, 600_000),
    (15, 900_000),
    (20, 3_600_000),
    (25, DAY_MS),
];

/// SA-30: consecutive failures that lock an account.
pub const HARD_LOCK_AT: u32 = 100;

/// One key class's rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPolicy {
    /// Attempt rate.
    pub rate: Gcra,
    /// Failure penalty.
    pub penalty: Penalty,
}

/// The realm's throttling rules (PD values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThrottlePolicy {
    /// Per identifier.
    pub account: KeyPolicy,
    /// Per identifier and network.
    pub account_ip: KeyPolicy,
    /// Per network.
    pub ip: KeyPolicy,
    /// Days a quiet key's state is kept.
    pub horizon_days: u32,
}

impl ThrottlePolicy {
    /// OP-146 m.5 (e): 1 s doubling to 30 s, hard lock at 100; the IP tiers above.
    pub const DEFAULT: Self = Self {
        account: KeyPolicy {
            rate: Gcra {
                interval_ms: 6_000,
                burst: 10,
            },
            penalty: Penalty::Doubling {
                first_ms: 1_000,
                cap_ms: 30_000,
                lock_at: Some(HARD_LOCK_AT),
            },
        },
        account_ip: KeyPolicy {
            rate: Gcra {
                interval_ms: 12_000,
                burst: 5,
            },
            penalty: Penalty::Doubling {
                first_ms: 1_000,
                cap_ms: 30_000,
                lock_at: None,
            },
        },
        ip: KeyPolicy {
            rate: Gcra {
                interval_ms: 2_000,
                burst: 30,
            },
            penalty: Penalty::Tiers {
                tiers: IP_TIERS,
                decay_ms: DAY_MS,
            },
        },
        horizon_days: 30,
    };

    /// The rules of `kind`.
    #[must_use]
    pub const fn of(&self, kind: KeyKind) -> &KeyPolicy {
        match kind {
            KeyKind::Account => &self.account,
            KeyKind::AccountIp => &self.account_ip,
            KeyKind::Ip => &self.ip,
        }
    }
}

/// One key's state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyState {
    /// GCRA arrival time.
    pub tat_ms: u64,
    /// Failures counted.
    pub failures: u32,
    /// Latest failure.
    pub last_failure_ms: u64,
    /// No attempt before this.
    pub blocked_until_ms: u64,
    /// Hard lock.
    pub locked: bool,
}

/// May an attempt go ahead?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// Yes; store the state.
    Open(KeyState),
    /// Not before `retry_after_ms` from now.
    Wait {
        /// Wait.
        retry_after_ms: u64,
    },
    /// Hard-locked: refused like a wrong password (TN-82).
    Locked,
}

impl KeyPolicy {
    /// Admits one attempt at `now_ms`, taking a slot of the rate.
    #[must_use]
    pub fn admit(&self, s: &KeyState, now_ms: u64) -> Gate {
        if s.locked {
            return Gate::Locked;
        }
        if now_ms < s.blocked_until_ms {
            return Gate::Wait {
                retry_after_ms: s.blocked_until_ms.saturating_sub(now_ms),
            };
        }
        match self.rate.check(s.tat_ms, now_ms) {
            GcraDecision::Allow { tat_ms } => Gate::Open(KeyState { tat_ms, ..*s }),
            GcraDecision::Deny { retry_after_ms } => Gate::Wait { retry_after_ms },
        }
    }

    /// The state after a failed attempt at `now_ms`.
    #[must_use]
    pub fn fail(&self, s: &KeyState, now_ms: u64) -> KeyState {
        match self.penalty {
            Penalty::Doubling {
                first_ms,
                cap_ms,
                lock_at,
            } => {
                let failures = s.failures.saturating_add(1);
                let shift = failures.saturating_sub(1).min(32);
                let wait = first_ms.checked_shl(shift).unwrap_or(cap_ms).min(cap_ms);
                KeyState {
                    failures,
                    last_failure_ms: now_ms,
                    blocked_until_ms: now_ms.saturating_add(wait),
                    locked: s.locked || lock_at.is_some_and(|n| failures >= n),
                    ..*s
                }
            }
            Penalty::Tiers { tiers, decay_ms } => {
                let quiet = now_ms.saturating_sub(s.last_failure_ms) > decay_ms;
                let failures = if quiet {
                    1
                } else {
                    s.failures.saturating_add(1)
                };
                let ban = tiers
                    .iter()
                    .rev()
                    .find(|(n, _)| failures >= *n)
                    .map_or(0, |(_, ban)| *ban);
                KeyState {
                    failures,
                    last_failure_ms: now_ms,
                    blocked_until_ms: s.blocked_until_ms.max(now_ms.saturating_add(ban)),
                    ..*s
                }
            }
        }
    }

    /// The state after a successful attempt: consecutive failures end; a network's count
    /// only decays.
    #[must_use]
    pub const fn succeed(&self, s: &KeyState) -> KeyState {
        match self.penalty {
            Penalty::Doubling { .. } => KeyState {
                failures: 0,
                blocked_until_ms: 0,
                ..*s
            },
            Penalty::Tiers { .. } => *s,
        }
    }
}

#[cfg(test)]
mod tests;
