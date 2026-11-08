#![allow(clippy::arithmetic_side_effects, reason = "test fixtures")]

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use proptest::prelude::*;

use super::{Decision, Defer, Occurrence, Record, Retain, SNAPSHOT_MAX_AGE, may_destroy};
use crate::class::Class;
use crate::hold::{Hold, HoldKind, HoldScope};
use crate::ids::{HoldId, SubjectId, TenantId};
use crate::schedule::{Basis, Event, Length, Period, PolicyVersion, Schedule};
use crate::time::Timestamp;

const DAY: u64 = 86_400_000;
const FRESH: Option<Duration> = Some(Duration::from_secs(60));

fn ts(ms: u64) -> Timestamp {
    Timestamp::from_unix_millis(ms)
}

fn schedule(length: Length, start: Event, max: Option<Period>) -> Schedule {
    Schedule {
        tenant: TenantId::new("t1"),
        class: Class::Kyc,
        basis: Basis::new("5549 m.8"),
        length,
        start,
        max,
        version: PolicyVersion::new(1),
    }
}

fn record(start: Occurrence, end: Occurrence) -> Record {
    Record {
        tenant: TenantId::new("t1"),
        class: Class::Kyc,
        subject: Some(SubjectId::new("s1")),
        start,
        end,
    }
}

fn hold(id: &str, scope: HoldScope, until: Option<u64>) -> Hold {
    Hold {
        id: HoldId::new(id),
        tenant: TenantId::new("t1"),
        scope,
        placed_at: ts(0),
        until: until.map(ts),
        kind: HoldKind::Regulator,
        suspicious_activity: false,
    }
}

fn ten_days() -> Schedule {
    schedule(Length::For(Period::Days(10)), Event::Recorded, None)
}

// OP-147 m.2, OP-74 m.2
#[test]
fn destroys_only_once_the_period_has_run() {
    let s = ten_days();
    let r = record(Occurrence::At(ts(DAY)), Occurrence::Unknown);
    let end = ts(11 * DAY);
    assert_eq!(
        may_destroy(&s, &r, &[], FRESH, ts(11 * DAY - 1)),
        Decision::Retain(Retain::Running { until: end })
    );
    assert_eq!(may_destroy(&s, &r, &[], FRESH, end), Decision::Destroy);
    assert!(may_destroy(&s, &r, &[], FRESH, ts(u64::MAX)).is_destroy());
}

// OP-147 m.2
#[test]
fn a_stale_or_missing_snapshot_defers() {
    assert_eq!(SNAPSHOT_MAX_AGE, Duration::from_hours(24));
    let s = ten_days();
    let r = record(Occurrence::At(ts(0)), Occurrence::Unknown);
    let now = ts(100 * DAY);
    assert_eq!(
        may_destroy(&s, &r, &[], None, now),
        Decision::Defer(Defer::NoSnapshot)
    );
    assert_eq!(
        may_destroy(&s, &r, &[], Some(SNAPSHOT_MAX_AGE), now),
        Decision::Defer(Defer::StaleSnapshot)
    );
    let just_fresh = Duration::from_millis(86_400_000 - 1);
    assert_eq!(
        may_destroy(&s, &r, &[], Some(just_fresh), now),
        Decision::Destroy
    );
}

// OP-74 m.3, OP-147 m.2, Ek C.5
#[test]
fn an_active_covering_hold_retains() {
    let s = schedule(
        Length::For(Period::Years(2)),
        Event::Recorded,
        Some(Period::Years(2)),
    );
    let r = record(Occurrence::At(ts(0)), Occurrence::Unknown);
    let now = ts(10_000 * DAY);
    let held = |h: Hold| may_destroy(&s, &r, &[h], FRESH, now);
    for scope in [
        HoldScope::Subject(SubjectId::new("s1")),
        HoldScope::Classes(vec![Class::Audit, Class::Kyc]),
        HoldScope::Tenant,
    ] {
        assert_eq!(
            held(hold("h", scope.clone(), None)),
            Decision::Retain(Retain::Held(HoldId::new("h")))
        );
        assert_eq!(
            held(hold("h", scope.clone(), Some(now.unix_millis() + 1))),
            Decision::Retain(Retain::Held(HoldId::new("h")))
        );
        assert_eq!(
            held(hold("h", scope, Some(now.unix_millis()))),
            Decision::Destroy
        );
    }
    assert_eq!(
        held(hold("h", HoldScope::Subject(SubjectId::new("s2")), None)),
        Decision::Destroy
    );
    assert_eq!(
        held(hold("h", HoldScope::Classes(vec![Class::Audit]), None)),
        Decision::Destroy
    );
    let mut other_tenant = hold("h", HoldScope::Tenant, None);
    other_tenant.tenant = TenantId::new("t2");
    assert_eq!(held(other_tenant), Decision::Destroy);
}

// OP-147 m.2
#[test]
fn unknown_state_defers() {
    let now = ts(1_000 * DAY);
    let s = ten_days();
    let unknown = record(Occurrence::Unknown, Occurrence::Unknown);
    assert_eq!(
        may_destroy(&s, &unknown, &[], FRESH, now),
        Decision::Defer(Defer::UnknownStart)
    );

    let mut other = record(Occurrence::At(ts(0)), Occurrence::Unknown);
    other.class = Class::Audit;
    assert_eq!(
        may_destroy(&s, &other, &[], FRESH, now),
        Decision::Defer(Defer::Mismatch)
    );
    other.class = Class::Kyc;
    other.tenant = TenantId::new("t2");
    assert_eq!(
        may_destroy(&s, &other, &[], FRESH, now),
        Decision::Defer(Defer::Mismatch)
    );

    let r = record(Occurrence::At(ts(0)), Occurrence::Unknown);
    let empty = hold("bad", HoldScope::Classes(Vec::new()), Some(1));
    assert_eq!(
        may_destroy(&s, &r, &[empty], FRESH, now),
        Decision::Defer(Defer::MalformedHold(HoldId::new("bad")))
    );

    let until = schedule(Length::Until(Event::TenantClosed), Event::Recorded, None);
    assert_eq!(
        may_destroy(&until, &r, &[], FRESH, now),
        Decision::Defer(Defer::UnknownEnd)
    );

    let capped_below = schedule(
        Length::For(Period::Years(5)),
        Event::Recorded,
        Some(Period::Years(2)),
    );
    assert_eq!(
        may_destroy(&capped_below, &r, &[], FRESH, now),
        Decision::Defer(Defer::InvalidSchedule)
    );

    let late = record(Occurrence::At(ts(u64::MAX - 1)), Occurrence::Unknown);
    assert_eq!(
        may_destroy(&s, &late, &[], FRESH, ts(u64::MAX)),
        Decision::Defer(Defer::OutOfRange)
    );
}

// Ek rule 4, OP-74 m.2
#[test]
fn the_period_waits_for_the_start_event() {
    let r = record(Occurrence::NotYet, Occurrence::Unknown);
    assert_eq!(
        may_destroy(&ten_days(), &r, &[], FRESH, ts(u64::MAX)),
        Decision::Retain(Retain::AwaitingStart)
    );
}

// OP-147 m.2, Ek C.3.6
#[test]
fn until_event_goes_when_the_event_is_recorded() {
    let s = schedule(Length::Until(Event::TenantClosed), Event::Recorded, None);
    let open = record(Occurrence::At(ts(0)), Occurrence::NotYet);
    assert_eq!(
        may_destroy(&s, &open, &[], FRESH, ts(u64::MAX)),
        Decision::Retain(Retain::AwaitingEnd)
    );
    let closed = record(Occurrence::At(ts(0)), Occurrence::At(ts(50 * DAY)));
    assert_eq!(
        may_destroy(&s, &closed, &[], FRESH, ts(50 * DAY - 1)),
        Decision::Retain(Retain::Running {
            until: ts(50 * DAY)
        })
    );
    assert_eq!(
        may_destroy(&s, &closed, &[], FRESH, ts(50 * DAY)),
        Decision::Destroy
    );
}

// OP-74 m.2, Ek C.5
#[test]
fn a_cap_ends_an_open_until_event_schedule() {
    let s = schedule(
        Length::Until(Event::MandateEnded),
        Event::Recorded,
        Some(Period::Days(3)),
    );
    let r = record(Occurrence::At(ts(0)), Occurrence::NotYet);
    assert_eq!(
        may_destroy(&s, &r, &[], FRESH, ts(3 * DAY - 1)),
        Decision::Retain(Retain::Running { until: ts(3 * DAY) })
    );
    assert_eq!(
        may_destroy(&s, &r, &[], FRESH, ts(3 * DAY)),
        Decision::Destroy
    );
    let ended_late = record(Occurrence::At(ts(0)), Occurrence::At(ts(9 * DAY)));
    assert_eq!(
        may_destroy(&s, &ended_late, &[], FRESH, ts(3 * DAY)),
        Decision::Destroy
    );
}

// Ek C.2.1 (TTK m.82), OP-147 m.2
#[test]
fn year_end_start_counts_from_the_next_year() {
    let s = schedule(Length::For(Period::Years(10)), Event::YearEnd, None);
    let jan_2026 = ts(20_454 * DAY);
    let r = record(Occurrence::At(jan_2026), Occurrence::Unknown);
    let jan_2037 = ts(24_472 * DAY);
    assert_eq!(
        may_destroy(&s, &r, &[], FRESH, ts(jan_2037.unix_millis() - 1)),
        Decision::Retain(Retain::Running { until: jan_2037 })
    );
    assert_eq!(may_destroy(&s, &r, &[], FRESH, jan_2037), Decision::Destroy);
}

fn period() -> impl Strategy<Value = Period> {
    prop_oneof![
        (0u32..5_000).prop_map(Period::Days),
        (0u32..200).prop_map(Period::Months),
        (0u32..30).prop_map(Period::Years),
    ]
}

fn event() -> impl Strategy<Value = Event> {
    prop_oneof![
        Just(Event::Recorded),
        Just(Event::YearEnd),
        Just(Event::TenantClosed),
        Just(Event::AccountClosed),
    ]
}

fn occurrence() -> impl Strategy<Value = Occurrence> {
    prop_oneof![
        (0u64..40_000 * DAY).prop_map(|ms| Occurrence::At(ts(ms))),
        Just(Occurrence::NotYet),
        Just(Occurrence::Unknown),
    ]
}

fn any_schedule() -> impl Strategy<Value = Schedule> {
    (
        prop_oneof![
            period().prop_map(Length::For),
            event().prop_map(Length::Until)
        ],
        event(),
        proptest::option::of(period()),
    )
        .prop_map(|(length, start, max)| schedule(length, start, max))
}

fn any_hold() -> impl Strategy<Value = Hold> {
    (
        prop_oneof![
            Just(HoldScope::Tenant),
            Just(HoldScope::Subject(SubjectId::new("s1"))),
            Just(HoldScope::Subject(SubjectId::new("s2"))),
            Just(HoldScope::Classes(vec![Class::Kyc])),
            Just(HoldScope::Classes(vec![Class::Audit])),
        ],
        proptest::option::of(0u64..40_000 * DAY),
        any::<bool>(),
    )
        .prop_map(|(scope, until, other_tenant)| {
            let mut h = hold("h", scope, until);
            if other_tenant {
                h.tenant = TenantId::new("t2");
            }
            h
        })
}

fn shortest_days(p: Period) -> u64 {
    match p {
        Period::Days(n) => u64::from(n),
        Period::Months(n) => 28 * u64::from(n),
        Period::Years(n) => 365 * u64::from(n),
    }
}

proptest! {
    // OP-147 m.2, OP-73 m.4
    #[test]
    fn never_destroys_early(
        s in any_schedule(),
        start in occurrence(),
        end in occurrence(),
        holds in proptest::collection::vec(any_hold(), 0..4),
        age_ms in proptest::option::of(0u64..2 * 86_400_000),
        now in 0u64..50_000 * DAY,
    ) {
        let r = record(start, end);
        let age = age_ms.map(Duration::from_millis);
        let now = ts(now);
        let d = may_destroy(&s, &r, &holds, age, now);
        if d.is_destroy() {
            prop_assert!(age.is_some_and(|a| a < SNAPSHOT_MAX_AGE));
            prop_assert!(!holds.iter().any(|h| h.is_active(now) && h.covers(&r)));
            match (s.length, r.start, r.end) {
                (Length::For(p), Occurrence::At(at), _) => {
                    prop_assert!(now.unix_millis() >= at.unix_millis() + shortest_days(p) * DAY);
                }
                (Length::Until(_), _, Occurrence::At(at)) => {
                    let by_event = now >= at;
                    let by_cap = match (r.start, s.max) {
                        (Occurrence::At(st), Some(max)) => {
                            now.unix_millis() >= st.unix_millis() + shortest_days(max) * DAY
                        }
                        _ => false,
                    };
                    prop_assert!(by_event || by_cap);
                }
                (Length::Until(_), Occurrence::At(st), Occurrence::NotYet) => {
                    let max = s.max.map(shortest_days);
                    prop_assert!(max.is_some_and(|m| now.unix_millis() >= st.unix_millis() + m * DAY));
                }
                _ => prop_assert!(false, "destroyed without a known start or end"),
            }
        }
    }

    // OP-147 m.2
    #[test]
    fn destroy_is_stable_over_time(
        s in any_schedule(),
        start in occurrence(),
        end in occurrence(),
        holds in proptest::collection::vec(any_hold(), 0..4),
        now in 0u64..50_000 * DAY,
        later in 0u64..50_000 * DAY,
    ) {
        let r = record(start, end);
        if may_destroy(&s, &r, &holds, FRESH, ts(now)).is_destroy() {
            prop_assert!(may_destroy(&s, &r, &holds, FRESH, ts(now + later)).is_destroy());
        }
    }

    // OP-74 m.3
    #[test]
    fn an_indefinite_covering_hold_always_retains(
        s in any_schedule(),
        start in occurrence(),
        end in occurrence(),
        now in 0u64..50_000 * DAY,
    ) {
        let r = record(start, end);
        let h = hold("h", HoldScope::Tenant, None);
        prop_assert!(!may_destroy(&s, &r, &[h], FRESH, ts(now)).is_destroy());
    }
}
