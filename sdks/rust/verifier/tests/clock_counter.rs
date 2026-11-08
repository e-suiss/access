//! Trusted clock and tamper-evident counter through the `testing` emulator (OP-150 m.1 (b)).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};

use access_kernel::digest::Digest;
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, ResourceSelector, Structural, TrustedTime,
};
use access_kernel::validity::{
    ProfileVariant, Revalidation, ValidityContract, ValidityError, VerifierContext, check,
};
use access_verifier::counter::{
    CounterError, CounterId, CounterReading, Draw, SliceGuard, TamperEvidentCounter,
};
use access_verifier::testing::{EmulatedClock, EmulatedCounter};
use access_verifier::time::{
    ClockError, ClockGuard, ClockReading, DEFAULT_DRIFT_PPM, DEFAULT_TOLERANCE_MS, TrustedClock,
};

const HORIZON: TrustedTime = 10_000_000;
const SKEW: u64 = 60_000;
const IAT: TrustedTime = 9_000_000;

fn d(n: u8) -> Digest {
    Digest([n; 32])
}

fn contract() -> ValidityContract {
    let variant = ProfileVariant::CheckpointedOffline;
    ValidityContract {
        issuing_exercise: d(1),
        basis_ref: vec![9],
        holder: d(2),
        audience: ["pep:door".to_owned()].into_iter().collect(),
        bounds: AuthoritySet {
            actions: ActionSet {
                exact: [ActionRef {
                    namespace: "door".to_owned(),
                    name: "open".to_owned(),
                    major: 1,
                    schema: d(3),
                }]
                .into_iter()
                .collect(),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: "site".to_owned(),
                prefix: vec![],
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        class: variant.class(),
        variant,
        profile_version: 1,
        params: BTreeMap::new(),
        horizon: HORIZON,
        max_staleness_ms: None,
        freshness_sources: BTreeSet::new(),
        revalidation: Revalidation::default(),
        offline_slice: BTreeSet::new(),
        local_requirements: BTreeSet::new(),
        verifier_profile_ref: d(4),
        clock_source: "monotonic+signed".to_owned(),
        clock_skew_ms: SKEW,
        must_understand: BTreeSet::new(),
        status: None,
    }
}

/// The Kernel's horizon check with `now` taken from the guarded device clock.
fn use_at(guard: &mut ClockGuard, clock: &EmulatedClock) -> Result<(), String> {
    let now = guard.now(clock).map_err(|e| format!("clock: {e}"))?;
    let understood = BTreeSet::new();
    let ctx = VerifierContext {
        now,
        audience: "pep:door",
        understood: &understood,
        last_refresh: None,
        online: false,
        skew_ms: SKEW,
        iat: IAT,
        horizon_cap_ms: u64::MAX / 4,
    };
    check(&contract(), &ctx).map_err(|e| format!("validity: {e}"))
}

fn expired() -> Result<(), String> {
    Err(format!("validity: {}", ValidityError::Expired))
}

/// Advances the emulator so that true time becomes `to`.
fn advance_to(clock: &EmulatedClock, to: TrustedTime) {
    clock.advance(to.saturating_sub(clock.truth()));
}

// U2, T25, OP-118 m.4, OP-117 m.13
#[test]
fn horizon_boundaries_hold_on_the_device_clock() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    for at in [IAT, HORIZON - 1, HORIZON, HORIZON + SKEW] {
        advance_to(&clock, at);
        assert_eq!(use_at(&mut guard, &clock), Ok(()), "{at}");
    }
    advance_to(&clock, HORIZON + SKEW + 1);
    assert_eq!(use_at(&mut guard, &clock), expired());
}

// U2, T25, OP-117 m.13
#[test]
fn a_clock_ahead_ends_use_early_and_a_clock_behind_overshoots_by_its_skew_only() {
    let ahead = EmulatedClock::new(IAT);
    ahead.set_skew(30_000);
    let mut guard = ClockGuard::default();
    advance_to(&ahead, HORIZON + SKEW - 30_000);
    assert_eq!(use_at(&mut guard, &ahead), Ok(()));
    ahead.advance(1);
    assert_eq!(use_at(&mut guard, &ahead), expired());

    let behind = EmulatedClock::new(IAT);
    behind.set_skew(-30_000);
    let mut guard = ClockGuard::default();
    advance_to(&behind, HORIZON + SKEW + 30_000);
    assert_eq!(use_at(&mut guard, &behind), Ok(()));
    behind.advance(1);
    assert_eq!(use_at(&mut guard, &behind), expired());

    let far_behind = EmulatedClock::new(IAT);
    far_behind.set_skew(-i64::try_from(SKEW + 1).unwrap());
    let mut guard = ClockGuard::default();
    assert_eq!(
        use_at(&mut guard, &far_behind),
        Err(format!("validity: {}", ValidityError::NotYetValid))
    );
}

// U2, TI-RT2, T25
#[test]
fn a_backward_jump_is_refused_until_time_passes_the_anchor() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    assert_eq!(guard.now(&clock), Ok(IAT));
    clock.advance(1_000);
    clock.jump(-5_000);
    assert_eq!(guard.now(&clock), Err(ClockError::WentBack));
    assert_eq!(guard.last().map(|r| r.trusted), Some(IAT));
    assert_eq!(
        use_at(&mut guard, &clock),
        Err("clock: trusted time went back".to_owned())
    );
    clock.jump(5_000);
    assert_eq!(guard.now(&clock), Ok(IAT + 1_000));
}

// U2, TI-RT2, T25
#[test]
fn a_forward_jump_beyond_the_tolerance_is_refused() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    assert!(guard.now(&clock).is_ok());
    clock.advance(1_000);
    clock.jump(i64::try_from(DEFAULT_TOLERANCE_MS).unwrap());
    assert_eq!(guard.now(&clock), Ok(IAT + 1_000 + DEFAULT_TOLERANCE_MS));
    clock.advance(1_000);
    clock.jump(i64::try_from(DEFAULT_TOLERANCE_MS + 1).unwrap());
    assert_eq!(guard.now(&clock), Err(ClockError::JumpedAhead));
}

// U2, TI-RT2, T25
#[test]
fn a_frozen_clock_is_refused_once_monotonic_time_outruns_it() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    assert!(guard.now(&clock).is_ok());
    assert_eq!(clock.freeze(), Ok(()));
    clock.advance(DEFAULT_TOLERANCE_MS);
    assert_eq!(guard.now(&clock), Ok(IAT));
    clock.advance(DEFAULT_TOLERANCE_MS + 1);
    assert_eq!(guard.now(&clock), Err(ClockError::Frozen));
    clock.thaw();
    assert_eq!(guard.now(&clock), Ok(clock.truth()));
}

// U2, T25
#[test]
fn an_unavailable_clock_or_a_reset_monotonic_clock_gives_no_time() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    assert!(guard.now(&clock).is_ok());
    clock.set_unavailable(true);
    clock.advance(1_000);
    assert_eq!(guard.now(&clock), Err(ClockError::Unavailable));
    assert_eq!(
        use_at(&mut guard, &clock),
        Err("clock: trusted clock unavailable".to_owned())
    );
    clock.set_unavailable(false);
    assert_eq!(guard.now(&clock), Ok(IAT + 1_000));
    clock.reset_monotonic();
    clock.advance(10);
    assert_eq!(guard.now(&clock), Err(ClockError::MonotonicWentBack));
}

// TI-RT2, FA-3, U29
#[test]
fn small_steps_do_not_add_up_and_the_tolerance_grows_with_elapsed_time() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    assert!(guard.now(&clock).is_ok());
    let step = i64::try_from(DEFAULT_TOLERANCE_MS / 2).unwrap();
    clock.advance(1_000);
    clock.jump(step);
    assert!(guard.now(&clock).is_ok());
    clock.advance(1_000);
    clock.jump(step);
    assert!(guard.now(&clock).is_ok());
    clock.advance(1_000);
    clock.jump(step);
    assert_eq!(guard.now(&clock), Err(ClockError::JumpedAhead));
    let mut guard = ClockGuard::default();
    let base = ClockReading {
        trusted: IAT,
        monotonic_ms: 0,
    };
    assert!(guard.accept(base).is_ok());
    let day = 86_400_000;
    let allowed = DEFAULT_TOLERANCE_MS + day * DEFAULT_DRIFT_PPM / 1_000_000;
    assert_eq!(guard.allowance_ms(day), allowed);
    let ahead = ClockReading {
        trusted: IAT + day + allowed,
        monotonic_ms: day,
    };
    assert_eq!(guard.accept(ahead), Ok(IAT + day + allowed));
    let mut guard = ClockGuard::anchored(DEFAULT_TOLERANCE_MS, base).with_drift(0);
    assert_eq!(guard.accept(ahead), Err(ClockError::JumpedAhead));
}

// TI-RT2, TI-RT5, TI-19
#[test]
fn a_refusing_guard_re_anchors_only_on_an_attested_time() {
    let clock = EmulatedClock::new(IAT);
    let mut guard = ClockGuard::default();
    assert!(guard.now(&clock).is_ok());
    assert_eq!(clock.freeze(), Ok(()));
    clock.advance(10_000);
    assert_eq!(guard.now(&clock), Err(ClockError::Frozen));
    clock.thaw();
    clock.jump(60_000);
    assert_eq!(guard.now(&clock), Err(ClockError::JumpedAhead));
    assert_eq!(guard.now(&clock), Err(ClockError::JumpedAhead));
    let reading = clock.read().unwrap();
    assert_eq!(
        guard.reanchor(reading, reading.trusted - DEFAULT_TOLERANCE_MS - 1),
        Err(ClockError::Unattested)
    );
    assert_eq!(
        guard.reanchor(reading, reading.trusted),
        Ok(reading.trusted)
    );
    assert_eq!(guard.anchor(), Some(reading));
    clock.advance(1_000);
    assert_eq!(guard.now(&clock), Ok(reading.trusted + 1_000));
    clock.reset_monotonic();
    clock.advance(10);
    assert_eq!(guard.now(&clock), Err(ClockError::MonotonicWentBack));
    let rebooted = clock.read().unwrap();
    assert_eq!(
        guard.reanchor(rebooted, rebooted.trusted),
        Ok(rebooted.trusted)
    );
    clock.advance(10);
    assert!(guard.now(&clock).is_ok());
    let earlier = ClockReading {
        trusted: IAT,
        monotonic_ms: rebooted.monotonic_ms + 20,
    };
    assert_eq!(guard.reanchor(earlier, IAT), Err(ClockError::WentBack));
}

const ID: CounterId = CounterId([1; 16]);

fn slice(counter: &EmulatedCounter, units: u64) -> SliceGuard {
    SliceGuard::new(counter.read().unwrap(), units)
}

fn granted(value: u64) -> Draw {
    Draw::Granted(CounterReading { id: ID, value })
}

// U2, T25
#[test]
fn draws_step_the_counter_and_stop_at_the_slice() {
    let mut counter = EmulatedCounter::new(ID);
    let mut guard = slice(&counter, 5);
    assert_eq!(guard.draw(&mut counter, 1), Ok(granted(1)));
    assert_eq!(guard.draw(&mut counter, 3), Ok(granted(4)));
    assert_eq!(guard.draw(&mut counter, 2), Ok(Draw::Exhausted));
    assert_eq!(counter.read().map(|r| r.value), Ok(4));
    assert_eq!(guard.draw(&mut counter, 1), Ok(granted(5)));
    assert_eq!(guard.draw(&mut counter, 1), Ok(Draw::Exhausted));
    assert_eq!(guard.used(), 5);
}

// U2, T25
#[test]
fn a_rolled_back_counter_is_refused() {
    let mut counter = EmulatedCounter::new(ID);
    let mut guard = slice(&counter, 10);
    assert_eq!(guard.draw(&mut counter, 4), Ok(granted(4)));
    assert_eq!(counter.roll_back(1), Ok(()));
    assert_eq!(guard.draw(&mut counter, 1), Err(CounterError::RolledBack));
    assert_eq!(guard.last().value, 4);
}

// U2, T25
#[test]
fn a_wiped_counter_is_refused_even_at_a_higher_value() {
    let mut counter = EmulatedCounter::new(ID);
    let mut guard = slice(&counter, 10);
    assert_eq!(guard.draw(&mut counter, 2), Ok(granted(2)));
    assert_eq!(counter.wipe(CounterId([2; 16])), Ok(()));
    let mut other = counter.share();
    assert!(other.advance(7).is_ok());
    assert_eq!(guard.draw(&mut counter, 1), Err(CounterError::Wiped));
}

// U2, T25
#[test]
fn an_unavailable_counter_draws_nothing() {
    let mut counter = EmulatedCounter::new(ID);
    let mut guard = slice(&counter, 10);
    assert_eq!(counter.set_unavailable(true), Ok(()));
    assert_eq!(guard.draw(&mut counter, 1), Err(CounterError::Unavailable));
    assert_eq!(counter.set_unavailable(false), Ok(()));
    assert_eq!(guard.draw(&mut counter, 1), Ok(granted(1)));
}

// U3, SEC13, T25
#[test]
fn a_group_counter_bounds_the_sum_of_all_members() {
    let mut a = EmulatedCounter::new(ID);
    let mut b = a.share();
    let mut guard_a = slice(&a, 5);
    let mut guard_b = slice(&b, 5);
    assert_eq!(guard_a.draw(&mut a, 3), Ok(granted(3)));
    assert_eq!(guard_b.draw(&mut b, 2), Ok(granted(5)));
    assert_eq!(guard_b.draw(&mut b, 1), Ok(Draw::Exhausted));
    assert_eq!(guard_a.draw(&mut a, 1), Ok(Draw::Exhausted));
    assert_eq!(guard_a.used(), 5);
    assert_eq!(b.roll_back(3), Ok(()));
    assert_eq!(guard_a.draw(&mut a, 1), Err(CounterError::RolledBack));
    assert_eq!(guard_b.draw(&mut b, 1), Err(CounterError::RolledBack));
}
