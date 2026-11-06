//! The rotation schedule run minute by minute over simulated days.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "simulated clocks and counters in test code"
)]

use alloc::vec::Vec;

use super::*;

const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;

/// Plan passes per minute, as a signer's round runs them: generate, publish, activate and
/// generate the backup, publish it.
const PASSES: usize = 4;

/// Runs the schedule every minute from `0` to `until`; `generate` says whether key generation
/// works at a given time. Returns the keys and, per minute, the signing key.
fn run(
    policy: &Policy,
    until: u64,
    generate: impl Fn(u64) -> bool,
) -> (Vec<Key>, Vec<Option<[u8; 32]>>) {
    let mut keys: Vec<Key> = Vec::new();
    let mut signing = Vec::new();
    let mut next: u8 = 0;
    let mut now = 0;
    while now <= until {
        for _ in 0..PASSES {
            let mut progressed = false;
            for step in plan(&keys, policy, now, u64::from(next).wrapping_mul(7919)) {
                match step {
                    Step::Generate {
                        valid_from,
                        valid_until,
                        jitter_permille,
                        founding,
                    } => {
                        if generate(now) {
                            next = next.wrapping_add(1);
                            keys.push(Key {
                                kid: [next; 32],
                                state: State::Pending,
                                published_at: None,
                                valid_from,
                                valid_until,
                                activated_at: None,
                                jitter_permille,
                                signatures: 0,
                                founding,
                            });
                            progressed = true;
                        }
                    }
                    other => {
                        apply(&mut keys, &other, now);
                        progressed = true;
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        let key = signing_key(&keys, policy, now).map(|k| k.kid);
        if let Some(kid) = key
            && let Some(k) = keys.iter_mut().find(|k| k.kid == kid)
        {
            k.signatures += 1;
        }
        signing.push(key);
        now += MINUTE;
    }
    (keys, signing)
}

fn key<'a>(keys: &'a [Key], kid: &[u8; 32]) -> &'a Key {
    keys.iter().find(|k| k.kid == *kid).unwrap()
}

// CR-25, CR-27, CR-59, SAI-46: from the first minute some key signs every minute; a key signs
// only once it has been published for the lead, unless it is the founding key, inside its
// window, and one key at a time
#[test]
fn keys_rotate_without_a_gap() {
    let p = Policy::AUTHORITY;
    let (keys, signing) = run(&p, 100 * HOUR, |_| true);
    assert!(signing.iter().all(Option::is_some));
    for (minute, kid) in signing.iter().enumerate() {
        let now = u64::try_from(minute).unwrap() * MINUTE;
        if let Some(kid) = kid {
            let k = key(&keys, kid);
            assert!(k.founding || k.published_at.unwrap() + p.publish_lead_ms <= now);
            assert!(k.valid_from <= now && now <= k.valid_until);
        }
    }
    let used: Vec<_> = keys.iter().filter(|k| k.activated_at.is_some()).collect();
    assert!(used.len() >= 75, "{}", used.len());
    assert!(keys.iter().any(|k| k.state == State::Dropped));
}

// CR-59, CR-25, SAI-46: the founding key signs the minute it is published; the set's second
// key signs no earlier than its full lead; once the founding key has rotated out no key ever
// signs before its lead, and exactly one key of the set is founding
#[test]
fn the_founding_key_signs_at_once_and_only_it() {
    let p = Policy::AUTHORITY;
    let (keys, signing) = run(&p, 100 * HOUR, |_| true);
    let founding: Vec<&Key> = keys.iter().filter(|k| k.founding).collect();
    assert_eq!(founding.len(), 1);
    let first = founding[0];
    assert_eq!(signing[0], Some(first.kid));
    assert_eq!(first.published_at, Some(0));
    assert_eq!(first.valid_from, 0);
    let second = keys
        .iter()
        .filter(|k| !k.founding)
        .min_by_key(|k| k.valid_from)
        .unwrap();
    assert_eq!(second.valid_from, p.publish_lead_ms);
    let second_signs = signing
        .iter()
        .position(|kid| *kid == Some(second.kid))
        .unwrap();
    assert!(
        u64::try_from(second_signs).unwrap() * MINUTE
            >= second.published_at.unwrap() + p.publish_lead_ms
    );
    let handover = signing
        .iter()
        .position(|kid| *kid != Some(first.kid))
        .unwrap();
    for (minute, kid) in signing.iter().enumerate().skip(handover) {
        let now = u64::try_from(minute).unwrap() * MINUTE;
        let k = key(&keys, &kid.unwrap());
        assert!(!k.founding, "minute {minute}");
        assert!(
            k.published_at.unwrap() + p.publish_lead_ms <= now,
            "minute {minute}"
        );
    }
}

// CR-19, CR-23: rotation follows the lifetime within the jitter
#[test]
fn rotation_follows_the_lifetime_within_the_jitter() {
    let p = Policy::AUTHORITY;
    let (keys, _) = run(&p, 24 * HOUR, |_| true);
    let mut starts: Vec<u64> = keys.iter().filter_map(|k| k.activated_at).collect();
    starts.sort_unstable();
    for pair in starts.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(gap >= p.lifetime_ms * 8 / 10, "{gap}");
        assert!(
            gap <= p.publish_lead_ms + p.lifetime_ms * 12 / 10 + MINUTE,
            "{gap}"
        );
    }
    let jitters: Vec<i32> = keys.iter().map(|k| k.jitter_permille).collect();
    assert!(jitters.iter().all(|j| j.abs() <= 200));
    assert!(jitters.iter().any(|j| *j != jitters[0]));
}

// CR-23: when keys cannot be generated, the active key signs to the end of its window and then
// nothing is signed
#[test]
fn an_outage_signs_to_the_end_of_the_window_then_nothing() {
    let p = Policy::AUTHORITY;
    let outage = 3 * HOUR;
    let (keys, signing) = run(&p, 48 * HOUR, |now| now < outage);
    let last_until = keys.iter().map(|k| k.valid_until).max().unwrap();
    for (minute, kid) in signing.iter().enumerate() {
        let now = u64::try_from(minute).unwrap() * MINUTE;
        if now <= last_until {
            assert!(kid.is_some(), "minute {minute}");
        } else {
            assert!(kid.is_none(), "minute {minute}");
        }
    }
}

// CR-23, OP-150: a round that keeps the schedule leaves no rotation overdue; a key-generation
// outage leaves the active key past its rotation time, which the delay alarm reports
#[test]
fn an_outage_makes_rotation_overdue() {
    let p = Policy::AUTHORITY;
    let (keys, _) = run(&p, 10 * HOUR, |_| true);
    assert_eq!(overdue(&keys, &p, 10 * HOUR), None);
    let (keys, _) = run(&p, 10 * HOUR, |now| now < 3 * HOUR);
    let late = overdue(&keys, &p, 10 * HOUR).unwrap();
    assert!(late > 0 && late < 10 * HOUR, "{late}");
    assert_eq!(overdue(&[], &p, 10 * HOUR), None);
}

// CR-21, CR-23, CR-59: a key that reaches its signature limit stops signing; the next signs
// once its lead has passed, and in between nothing is signed, the founding key's successor
// included
#[test]
fn the_signature_limit_rotates() {
    let p = Policy {
        max_signatures: 10,
        ..Policy::AUTHORITY
    };
    let (keys, signing) = run(&p, 6 * HOUR, |_| true);
    assert!(keys.iter().all(|k| k.signatures <= 10));
    let used = keys.iter().filter(|k| k.activated_at.is_some()).count();
    assert!(used >= 5, "{used}");
    let lead = usize::try_from(p.publish_lead_ms / MINUTE).unwrap();
    assert!(signing[..10].iter().all(Option::is_some));
    assert!(signing[10..lead].iter().all(Option::is_none));
    assert!(signing[lead].is_some());
}

// CR-23: jitter is uniform over ±jitter_permille
#[test]
fn jitter_stays_in_range() {
    let p = Policy::AUTHORITY;
    assert_eq!(jitter(&p, 0), -200);
    assert_eq!(jitter(&p, 400), 200);
    assert_eq!(jitter(&p, 401), -200);
    let none = Policy {
        jitter_permille: 0,
        ..p
    };
    assert_eq!(jitter(&none, 12345), 0);
}
