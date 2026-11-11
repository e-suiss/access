//! The closed `derived.*` whitelist (§16.5, RT26, SI-8, OP-157 m.3 (o)): eleven values computed
//! from recorded state and SYNC-DERIVED window counters, given to the restriction context as its
//! `derived` record and cited in the decision record's `StateBasis`.
//!
//! The counters live in `access.authority_counter` and are drawn in the decision record's
//! `consumption.draws`, so the fold of the records before a decision rebuilds them. A window is
//! two fixed buckets of [`WINDOW_MS`] (the current and the previous one), so it always covers at
//! least the last 24 hours. A name outside [`NAMES`] is not in the schema and does not compile
//! (INV-36).

use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::intent::{IntentEnvelope, ParamValue};
use access_kernel::model::Id;
use access_kernel::tier::{CT1_MAX, CT2_MAX, THRESHOLD_UNIT};
use suiss_crypto::dcbor::{self, Limits, Value};

/// The whitelist, in the order of §16.5 (RT26).
pub const NAMES: [&str; 11] = [
    "party_consumption",
    "open_require_action",
    "selector_transitions",
    "cited_instance_state",
    "mapping_pin_age_s",
    "claim_age_s",
    "unreported_contracts",
    "rollback_guard",
    "projection_issue_count",
    "open_offline_paps",
    "threshold_adjacent",
];

/// The bucket length of the window counters, 24 hours (§13.7.6).
pub const WINDOW_MS: u64 = 86_400_000;

/// The window of `projection_issue_count`, one hour (§13.7.4).
pub const ISSUE_WINDOW_MS: u64 = 3_600_000;

/// The value of an age whose input is absent: no Claim relied on, no mapping used.
pub const NONE: i64 = -1;

/// The eleven values of one request (§16.5 whitelist 1–11).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Derived {
    /// 1. The actor Party's consumption in the window in the threshold unit, this request
    ///    included (§13.7.6).
    pub party_consumption: i64,
    /// 2. The requester's approval requests opened in the current hour (SEC28, §13.7.4).
    pub open_require_action: i64,
    /// 3. New holders of the basis Grant's selector in the window, this actor included, when the
    ///    actor is one of them; 0 otherwise (mass-selection guard, §13.7.6).
    pub selector_transitions: i64,
    /// 4. 1 when an Instance whose contribution the request cites has ended, else 0 (SEC11).
    pub cited_instance_state: i64,
    /// 5. Seconds since the compatibility mapping the request used was pinned; [`NONE`] when
    ///    no mapping was used (SEC16).
    pub mapping_pin_age_s: i64,
    /// 6. Seconds since the youngest relied-on Claim was recorded; [`NONE`] without one
    ///    (SEC18).
    pub claim_age_s: i64,
    /// 7. 1 when the requesting verifier left an offline contract unreported past its deadline,
    ///    else 0 (SEC14, §13.7.2).
    pub unreported_contracts: i64,
    /// 8. The rollback guard's input; only a recovery batch carries one, so 0 on the commit
    ///    path (SEC21, SEC22).
    pub rollback_guard: i64,
    /// 9. Projections the actor Instance was issued in the last hour for this namespace
    ///    (§13.7.4).
    pub projection_issue_count: i64,
    /// 10. Offline projections the actor Instance holds open (§13.7.4).
    pub open_offline_paps: i64,
    /// 11. Threshold-adjacent Exercises to this target in the window, this one included, when
    ///     this one is adjacent; 0 otherwise (§13.7.6).
    pub threshold_adjacent: i64,
}

fn long(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl Derived {
    /// The values of a request that reads none: every count 0, every age [`NONE`].
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            party_consumption: 0,
            open_require_action: 0,
            selector_transitions: 0,
            cited_instance_state: 0,
            mapping_pin_age_s: NONE,
            claim_age_s: NONE,
            unreported_contracts: 0,
            rollback_guard: 0,
            projection_issue_count: 0,
            open_offline_paps: 0,
            threshold_adjacent: 0,
        }
    }

    /// Name and value, in [`NAMES`] order.
    #[must_use]
    pub const fn entries(&self) -> [(&'static str, i64); 11] {
        [
            (NAMES[0], self.party_consumption),
            (NAMES[1], self.open_require_action),
            (NAMES[2], self.selector_transitions),
            (NAMES[3], self.cited_instance_state),
            (NAMES[4], self.mapping_pin_age_s),
            (NAMES[5], self.claim_age_s),
            (NAMES[6], self.unreported_contracts),
            (NAMES[7], self.rollback_guard),
            (NAMES[8], self.projection_issue_count),
            (NAMES[9], self.open_offline_paps),
            (NAMES[10], self.threshold_adjacent),
        ]
    }

    /// The restriction context's `derived` record.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::Value::Object(
            self.entries()
                .into_iter()
                .map(|(k, v)| (String::from(k), serde_json::Value::from(v)))
                .collect(),
        )
    }

    /// The `StateBasis` member that cites the values (SI-8).
    #[must_use]
    pub fn cited(&self) -> Value {
        Value::Map(
            self.entries()
                .into_iter()
                .map(|(k, v)| {
                    let n = if v < 0 {
                        Value::Negative(v.unsigned_abs().saturating_sub(1))
                    } else {
                        Value::Unsigned(v.unsigned_abs())
                    };
                    (Value::text(k), n)
                })
                .collect(),
        )
    }

    /// Reads values cited in a recorded `StateBasis`; `None` when the member is malformed or
    /// names anything outside [`NAMES`].
    #[must_use]
    pub fn from_cited(v: &Value) -> Option<Self> {
        let Value::Map(entries) = v else {
            return None;
        };
        let mut out = Self::default();
        for (k, n) in entries {
            let Value::Text(k) = k else { return None };
            let n = match n {
                Value::Unsigned(n) => i64::try_from(*n).ok()?,
                Value::Negative(n) => i64::try_from(*n).ok()?.checked_neg()?.checked_sub(1)?,
                _ => return None,
            };
            let slot = match NAMES.iter().position(|x| x == k)? {
                0 => &mut out.party_consumption,
                1 => &mut out.open_require_action,
                2 => &mut out.selector_transitions,
                3 => &mut out.cited_instance_state,
                4 => &mut out.mapping_pin_age_s,
                5 => &mut out.claim_age_s,
                6 => &mut out.unreported_contracts,
                7 => &mut out.rollback_guard,
                8 => &mut out.projection_issue_count,
                9 => &mut out.open_offline_paps,
                _ => &mut out.threshold_adjacent,
            };
            *slot = n;
        }
        Some(out)
    }
}

/// The start of the bucket holding `now`, then of the one before it when there is one.
#[must_use]
pub fn buckets(now: u64) -> Vec<u64> {
    let start = now.saturating_sub(now.checked_rem(WINDOW_MS).unwrap_or(0));
    std::iter::once(start)
        .chain(start.checked_sub(WINDOW_MS))
        .collect()
}

fn current(now: u64) -> u64 {
    now.saturating_sub(now.checked_rem(WINDOW_MS).unwrap_or(0))
}

fn key(parts: Vec<Value>) -> Vec<u8> {
    let mut all = vec![Value::text("derived")];
    all.extend(parts);
    dcbor::encode(&Value::Array(all), Limits::CEILING).unwrap_or_default()
}

/// Counter of the Party's consumption in the bucket starting at `bucket` (whitelist 1).
#[must_use]
pub fn consumption_key(party: &Id, bucket: u64) -> Vec<u8> {
    key(vec![
        Value::text(NAMES[0]),
        party.to_value(),
        Value::Unsigned(bucket),
    ])
}

/// Counter of new holders of `grant`'s selector in the bucket (whitelist 3).
#[must_use]
pub fn transitions_key(grant: &Id, bucket: u64) -> Vec<u8> {
    key(vec![
        Value::text(NAMES[2]),
        grant.to_value(),
        Value::Unsigned(bucket),
    ])
}

/// Marks that `party`'s episode from `since` already counted as a transition of `grant`.
#[must_use]
pub fn transition_seen_key(grant: &Id, party: &Id, since: u64) -> Vec<u8> {
    key(vec![
        Value::text("selector_seen"),
        grant.to_value(),
        party.to_value(),
        Value::Unsigned(since),
    ])
}

/// The version key of verifier `audience`'s contracts and reports, `contracts@verifier(V)`: an
/// offline or intermittent `projection.issue` to it and each report of one move it, and a
/// decision that reads `unreported_contracts` reads it (§16.5.2, whitelist 7, TI-4).
#[must_use]
pub fn verifier_contracts_key(audience: &str) -> Vec<u8> {
    key(vec![
        Value::text("contracts@verifier"),
        Value::text(audience),
    ])
}

/// Counter of threshold-adjacent Exercises of `party` to `target` in the bucket (whitelist 11).
#[must_use]
pub fn adjacent_key(party: &Id, target: &Digest, bucket: u64) -> Vec<u8> {
    key(vec![
        Value::text(NAMES[10]),
        party.to_value(),
        target.to_value(),
        Value::Unsigned(bucket),
    ])
}

/// The intent's amounts in the threshold unit: their sum and their largest.
#[must_use]
pub fn amounts(intent: &IntentEnvelope) -> (u64, u64) {
    intent
        .params
        .values()
        .filter_map(|v| match v {
            ParamValue::Amount { value, unit } if unit == THRESHOLD_UNIT => {
                u64::try_from(*value).ok()
            }
            _ => None,
        })
        .fold((0, 0), |(sum, max), a| (sum.saturating_add(a), max.max(a)))
}

/// Whether `amount` is within 80 % of the tier threshold just above it, up to that threshold
/// (§13.7.6, PD).
#[must_use]
pub fn adjacent(amount: u64) -> bool {
    [CT1_MAX, CT2_MAX].into_iter().any(|limit| {
        let limit = u64::try_from(limit).unwrap_or(u64::MAX);
        amount <= limit && amount.saturating_mul(5) >= limit.saturating_mul(4)
    })
}

/// The target a repetition is counted against: the recipient, else the first resource.
#[must_use]
pub fn target(intent: &IntentEnvelope) -> Option<Digest> {
    let bytes = match (&intent.recipient, intent.resources.first()) {
        (Some(r), _) => dcbor::encode(&r.to_value(), Limits::CEILING).ok()?,
        (None, Some(r)) => dcbor::encode(&r.to_value(), Limits::CEILING).ok()?,
        (None, None) => return None,
    };
    Some(Digest(
        suiss_crypto::digest::context_digest("access/derived-target/v1", &bytes).0,
    ))
}

/// What one request reads and, when it is allowed, adds to the window counters.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Window {
    /// The values the restriction context reads.
    pub values: Derived,
    /// Counter keys and amounts an ALLOW draws (`consumption.draws`).
    pub increments: Vec<(Vec<u8>, u64)>,
}

/// The counter inputs of the window values: what the counters held before this request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counted {
    /// Whitelist 1 over both buckets.
    pub consumption: u64,
    /// Whitelist 11 over both buckets, when the intent has a target.
    pub adjacent: u64,
    /// Whitelist 3 over both buckets, with whether this episode already counted, when the actor
    /// is a new holder of a predicate Grant.
    pub transitions: Option<(Id, u64, u64, bool)>,
}

/// The window values and increments of a request by `party` (whitelist 1, 3, 11).
#[must_use]
pub fn window(intent: &IntentEnvelope, party: Option<&Id>, counted: &Counted, now: u64) -> Window {
    let mut out = Window::default();
    let Some(party) = party else {
        return out;
    };
    let bucket = current(now);
    let (sum, max) = amounts(intent);
    out.values.party_consumption = long(counted.consumption.saturating_add(sum));
    if sum > 0 {
        out.increments.push((consumption_key(party, bucket), sum));
    }
    if let Some(t) = target(intent).filter(|_| adjacent(max)) {
        out.values.threshold_adjacent = long(counted.adjacent.saturating_add(1));
        out.increments.push((adjacent_key(party, &t, bucket), 1));
    }
    if let Some((grant, since, before, seen)) = counted.transitions {
        out.values.selector_transitions = long(before.saturating_add(u64::from(!seen)));
        if !seen {
            out.increments.push((transitions_key(&grant, bucket), 1));
            out.increments
                .push((transition_seen_key(&grant, party, since), 1));
        }
    }
    out
}

#[cfg(test)]
mod tests;
