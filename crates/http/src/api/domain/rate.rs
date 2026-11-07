//! Management API rate limits (TN-127, OP-151 m.3 (d), §13.7.4): three layers, each a token
//! bucket (GCRA) or a concurrency semaphore, announced with the IETF httpapi `RateLimit-Policy`
//! and `RateLimit` header fields. Keys come from the surface, the route group and the caller;
//! none of them is ever a metric label (OP-47).

use super::Surface;

/// A bucket's quota: `limit` requests per `window_s` seconds, at most `burst` at once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quota {
    /// The policy name in the headers.
    pub name: &'static str,
    /// Requests per window.
    pub limit: u32,
    /// Window, seconds.
    pub window_s: u32,
    /// Most requests at once.
    pub burst: u32,
}

impl Quota {
    /// Milliseconds between two requests at the sustained rate.
    #[must_use]
    pub fn interval_ms(self) -> u64 {
        u64::from(self.window_s)
            .saturating_mul(1000)
            .checked_div(u64::from(self.limit.max(1)))
            .unwrap_or(u64::MAX)
            .max(1)
    }

    /// The `RateLimit-Policy` item of this quota.
    #[must_use]
    pub fn policy_item(self) -> String {
        format!(
            "\"{}\";q={};w={}",
            self.name,
            self.burst.max(self.limit),
            self.window_s
        )
    }
}

/// Layer 3, per actor: realm-admin writes per actor Instance (OP-151 m.3 (d)).
pub const REALM_WRITE: Quota = Quota {
    name: "realm-write",
    limit: 10,
    window_s: 1,
    burst: 50,
};

/// Layer 3, per actor: platform-admin writes per client Instance (OP-151 m.3 (d)).
pub const PLATFORM_WRITE: Quota = Quota {
    name: "platform-write",
    limit: 5,
    window_s: 1,
    burst: 20,
};

/// Layer 3, per token: reads (OP-151 m.3 (d)).
pub const READ: Quota = Quota {
    name: "read",
    limit: 60,
    window_s: 60,
    burst: 60,
};

/// Layer 1, per surface instance, method and route group: realm-admin writes.
pub const REALM_GROUP_WRITE: Quota = Quota {
    name: "realm-group-write",
    limit: 50,
    window_s: 1,
    burst: 200,
};

/// Layer 1, per surface instance, method and route group: platform-admin writes.
pub const PLATFORM_GROUP_WRITE: Quota = Quota {
    name: "platform-group-write",
    limit: 20,
    window_s: 1,
    burst: 50,
};

/// Layer 1, per surface instance, method and route group: reads.
pub const GROUP_READ: Quota = Quota {
    name: "group-read",
    limit: 600,
    window_s: 60,
    burst: 600,
};

/// Layer 2: requests in flight per surface instance.
pub const SURFACE_CONCURRENCY: u32 = 64;

/// Layer 2: requests in flight per caller.
pub const ACTOR_CONCURRENCY: u32 = 8;

/// The layer 1 quota of a route.
#[must_use]
pub const fn group_quota(surface: Surface, write: bool) -> Quota {
    match (surface, write) {
        (_, false) => GROUP_READ,
        (Surface::Realm, true) => REALM_GROUP_WRITE,
        (Surface::Platform, true) => PLATFORM_GROUP_WRITE,
    }
}

/// The layer 3 quota of a caller.
#[must_use]
pub const fn actor_quota(surface: Surface, write: bool) -> Quota {
    match (surface, write) {
        (_, false) => READ,
        (Surface::Realm, true) => REALM_WRITE,
        (Surface::Platform, true) => PLATFORM_WRITE,
    }
}

/// What a bucket is keyed by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BucketKey {
    /// The layer: `group` or `actor`.
    pub layer: &'static str,
    /// The surface instance key.
    pub scope: String,
    /// The method.
    pub method: String,
    /// The longest-prefix route group.
    pub group: &'static str,
    /// The caller, for the actor layer: a digest, never a raw credential.
    pub caller: Option<[u8; 32]>,
}

/// One bucket's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Take {
    /// Admitted.
    pub allowed: bool,
    /// Requests left now.
    pub remaining: u32,
    /// Seconds until the bucket is full again, or until the next request is admitted when
    /// refused.
    pub reset_s: u64,
}

/// GCRA over a theoretical arrival time `tat_ms`: admits one request at `now_ms` or not, and
/// returns the new arrival time with the answer.
#[must_use]
pub fn gcra(tat_ms: u64, now_ms: u64, quota: Quota) -> (u64, Take) {
    let t = quota.interval_ms();
    let burst = u64::from(quota.burst.max(1));
    let tolerance = t.saturating_mul(burst.saturating_sub(1));
    let tat = tat_ms.max(now_ms);
    let next = tat.saturating_add(t);
    let allow_at = next.saturating_sub(tolerance.saturating_add(t));
    if now_ms < allow_at {
        let wait = allow_at.saturating_sub(now_ms);
        return (
            tat_ms,
            Take {
                allowed: false,
                remaining: 0,
                reset_s: wait.div_ceil(1000),
            },
        );
    }
    let used = next.saturating_sub(now_ms).div_ceil(t);
    let remaining = burst.saturating_sub(used);
    let full = next.saturating_sub(now_ms);
    (
        next,
        Take {
            allowed: true,
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
            reset_s: full.div_ceil(1000),
        },
    )
}

/// The `RateLimit` item of a bucket's answer.
#[must_use]
pub fn limit_item(quota: Quota, take: Take) -> String {
    format!("\"{}\";r={};t={}", quota.name, take.remaining, take.reset_s)
}

/// The longest prefix of `template` among `groups`, or the template itself (TN-127).
#[must_use]
pub fn group_of(template: &'static str, groups: &[&'static str]) -> &'static str {
    groups
        .iter()
        .filter(|g| {
            template
                .strip_prefix(**g)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
        .max_by_key(|g| g.len())
        .copied()
        .unwrap_or(template)
}
