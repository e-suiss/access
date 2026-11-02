//! Signing key rotation (CR-25, CR-26, CR-27): the key state machine, publish-before-use and the
//! schedule. Pure and deterministic; the caller brings the clock, the randomness and the keys.

use alloc::vec::Vec;

/// Where a key is in its life (CR-27).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum State {
    /// Created, not yet published.
    Pending,
    /// Published; verifies, does not sign yet.
    Published,
    /// The key that signs.
    Active,
    /// Replaced; verifies until it is dropped.
    Retiring,
    /// Gone from the publication; its private material is destroyed.
    Dropped,
}

/// Rotation policy; times in milliseconds (CR-19, CR-21, CR-23, CR-25, CR-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// How long a key signs before it is rotated.
    pub lifetime_ms: u64,
    /// The declared window `[valid_from, valid_until]`; it bounds the signing time and lets
    /// signing go on through a key-generation outage.
    pub window_ms: u64,
    /// `T_publish_lead`: how long a key is published before it may sign.
    pub publish_lead_ms: u64,
    /// How long a key stays published after its window ends.
    pub retain_ms: u64,
    /// Signatures after which a key is rotated.
    pub max_signatures: u64,
    /// Rotation jitter in thousandths of the lifetime, either way.
    pub jitter_permille: u16,
}

impl Policy {
    /// The authority plane's operational key defaults: 1 hour lifetime, 24 hour window, 65 minute
    /// lead (Δ of 1 hour and 5 minutes of margin), 72 hours kept after the window, 5 million
    /// signatures, ±20 % jitter (PD).
    pub const AUTHORITY: Self = Self {
        lifetime_ms: 3_600_000,
        window_ms: 86_400_000,
        publish_lead_ms: 3_900_000,
        retain_ms: 259_200_000,
        max_signatures: 5_000_000,
        jitter_permille: 200,
    };
}

/// One key's rotation record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    /// Key identifier.
    pub kid: [u8; 32],
    /// State.
    pub state: State,
    /// When it was published.
    pub published_at: Option<u64>,
    /// First instant it may sign.
    pub valid_from: u64,
    /// Last instant it may sign.
    pub valid_until: u64,
    /// When it became active.
    pub activated_at: Option<u64>,
    /// This key's jitter, in thousandths of the lifetime.
    pub jitter_permille: i32,
    /// Signatures made.
    pub signatures: u64,
}

/// What the schedule asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Create a key with this window and jitter.
    Generate {
        /// First instant it may sign.
        valid_from: u64,
        /// Last instant it may sign.
        valid_until: u64,
        /// Its jitter.
        jitter_permille: i32,
    },
    /// Publish a pending key.
    Publish([u8; 32]),
    /// Make a published key the signing key.
    Activate([u8; 32]),
    /// Stop a key signing.
    Retire([u8; 32]),
    /// Withdraw a key and destroy its private material.
    Drop([u8; 32]),
}

/// Whether `key` may sign at `now`: active, published at least the lead before, inside its
/// window and under its signature limit (SAI-46).
#[must_use]
pub fn usable(key: &Key, policy: &Policy, now: u64) -> bool {
    key.state == State::Active
        && key
            .published_at
            .is_some_and(|p| p.saturating_add(policy.publish_lead_ms) <= now)
        && key.valid_from <= now
        && now <= key.valid_until
        && key.signatures < policy.max_signatures
}

/// The key that signs at `now`, if any; without one, nothing is signed (CR-23).
#[must_use]
pub fn signing_key<'a>(keys: &'a [Key], policy: &Policy, now: u64) -> Option<&'a Key> {
    keys.iter()
        .filter(|k| usable(k, policy, now))
        .max_by_key(|k| (k.activated_at, k.valid_from))
}

/// When an active key is due for rotation: its lifetime from activation, moved by its jitter.
#[must_use]
pub fn rotate_at(key: &Key, policy: &Policy) -> Option<u64> {
    let start = key.activated_at?;
    let shift = i128::from(policy.lifetime_ms)
        .saturating_mul(i128::from(key.jitter_permille))
        .checked_div(1000)
        .unwrap_or(0);
    let at = i128::from(start)
        .saturating_add(i128::from(policy.lifetime_ms))
        .saturating_add(shift);
    u64::try_from(at.max(i128::from(start))).ok()
}

/// The jitter a new key takes from a random draw: uniform in `±policy.jitter_permille`.
#[must_use]
pub fn jitter(policy: &Policy, draw: u64) -> i32 {
    let span = u64::from(policy.jitter_permille);
    let pick = draw
        .checked_rem(span.saturating_mul(2).saturating_add(1))
        .unwrap_or(0);
    i32::try_from(pick)
        .unwrap_or(0)
        .saturating_sub(i32::from(policy.jitter_permille))
}

/// The steps that bring `keys` to the schedule at `now`; `draw` is a random value for the
/// jitter of a key to generate.
#[must_use]
pub fn plan(keys: &[Key], policy: &Policy, now: u64, draw: u64) -> Vec<Step> {
    let mut steps = Vec::new();
    for k in keys.iter().filter(|k| k.state == State::Pending) {
        steps.push(Step::Publish(k.kid));
    }
    let waiting = |k: &&Key| k.state == State::Published && now <= k.valid_until;
    let backup = keys.iter().filter(waiting).min_by_key(|k| k.valid_from);
    let active = keys
        .iter()
        .filter(|k| k.state == State::Active)
        .max_by_key(|k| (k.activated_at, k.valid_from));
    let due = active.is_none_or(|a| {
        rotate_at(a, policy).is_none_or(|t| now >= t)
            || a.signatures >= policy.max_signatures
            || now >= a.valid_until
    });
    let ready = backup.filter(|b| {
        b.published_at
            .is_some_and(|p| p.saturating_add(policy.publish_lead_ms) <= now)
            && b.valid_from <= now
    });
    let mut activated = None;
    if due && let Some(b) = ready {
        steps.push(Step::Activate(b.kid));
        activated = Some(b.kid);
    }
    for k in keys.iter().filter(|k| k.state == State::Active) {
        let replaced = activated.is_some() && Some(k.kid) != activated;
        if replaced || now > k.valid_until {
            steps.push(Step::Retire(k.kid));
        }
    }
    let has_backup = keys.iter().any(|k| {
        matches!(k.state, State::Pending | State::Published)
            && now <= k.valid_until
            && Some(k.kid) != activated
    });
    if !has_backup {
        let valid_from = now.saturating_add(policy.publish_lead_ms);
        steps.push(Step::Generate {
            valid_from,
            valid_until: valid_from.saturating_add(policy.window_ms),
            jitter_permille: jitter(policy, draw),
        });
    }
    for k in keys {
        let gone = match k.state {
            State::Retiring => now > k.valid_until.saturating_add(policy.retain_ms),
            State::Published => now > k.valid_until,
            _ => false,
        };
        if gone {
            steps.push(Step::Drop(k.kid));
        }
    }
    steps
}

/// Applies a step other than [`Step::Generate`] to `keys` at `now`; the caller adds generated
/// keys itself.
pub fn apply(keys: &mut [Key], step: &Step, now: u64) {
    let (kid, to) = match step {
        Step::Generate { .. } => return,
        Step::Publish(kid) => (kid, State::Published),
        Step::Activate(kid) => (kid, State::Active),
        Step::Retire(kid) => (kid, State::Retiring),
        Step::Drop(kid) => (kid, State::Dropped),
    };
    if let Some(k) = keys.iter_mut().find(|k| k.kid == *kid) {
        k.state = to;
        match to {
            State::Published => k.published_at = Some(now),
            State::Active => k.activated_at = Some(now),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
