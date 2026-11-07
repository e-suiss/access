use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn facts(binding: Binding) -> ConsoleFacts {
    ConsoleFacts {
        created_ms: 0,
        last_seen_ms: 0,
        revoked: false,
        ended: false,
        binding,
    }
}

// TN-129, OP-151 m.3 (f): 12 hours absolute, 15 minutes idle
#[test]
fn lifetimes_are_twelve_hours_and_fifteen_minutes() {
    assert_eq!(ABSOLUTE_MS, 12 * HOUR);
    assert_eq!(IDLE_MS, 15 * MIN);
    let ip = v4(192, 0, 2, 10);
    let p = BindingPolicy::default();
    let f = facts(Binding::of(ip, None, p));
    assert_eq!(check(&f, ip, None, p, 15 * MIN - 1), ConsoleCheck::Valid);
    assert_eq!(check(&f, ip, None, p, 15 * MIN), ConsoleCheck::IdleExpired);
    let busy = ConsoleFacts {
        last_seen_ms: 12 * HOUR - MIN,
        ..f
    };
    assert_eq!(
        check(&busy, ip, None, p, 12 * HOUR - 1),
        ConsoleCheck::Valid
    );
    assert_eq!(check(&busy, ip, None, p, 12 * HOUR), ConsoleCheck::Expired);
    assert_eq!(ends_ms(&f), 15 * MIN);
    assert_eq!(ends_ms(&busy), 12 * HOUR);
}

// TN-129, OP-151 m.1 (b): without a `GeoResolver` source the binding is the /24 or /48 prefix
#[test]
fn prefix_binding_without_a_geoip_source() {
    let p = BindingPolicy::default();
    let b = Binding::of(v4(198, 51, 100, 7), None, p);
    assert_eq!(b, Binding::V4Prefix([198, 51, 100]));
    assert!(b.holds(v4(198, 51, 100, 200), None, p));
    assert!(!b.holds(v4(198, 51, 101, 7), None, p));
    let six: IpAddr = "2001:db8:abcd:12::1".parse().unwrap();
    let b6 = Binding::of(six, None, p);
    assert_eq!(b6, Binding::V6Prefix([0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd]));
    assert!(b6.holds("2001:db8:abcd:ffff::2".parse().unwrap(), None, p));
    assert!(!b6.holds("2001:db8:abce::1".parse().unwrap(), None, p));
    let mapped = IpAddr::V6(Ipv4Addr::new(198, 51, 100, 9).to_ipv6_mapped());
    assert!(b.holds(mapped, None, p));
}

// TN-129, OP-151 m.1 (b), TI-9: the ASN when a source answers; a source that appears or
// disappears never widens a session
#[test]
fn asn_binding_and_source_changes_end_the_session() {
    let p = BindingPolicy::default();
    let ip = v4(203, 0, 113, 4);
    let b = Binding::of(ip, Some(64_500), p);
    assert_eq!(b, Binding::Asn(64_500));
    assert!(b.holds(v4(192, 0, 2, 1), Some(64_500), p));
    assert!(!b.holds(ip, Some(64_501), p));
    assert!(!b.holds(ip, None, p));
    let prefix = Binding::of(ip, None, p);
    assert!(!prefix.holds(ip, Some(64_500), p));
    let f = facts(b);
    assert_eq!(
        check(&f, ip, Some(64_501), p, MIN),
        ConsoleCheck::BindingMismatch
    );
}

// TN-129: the realm's optional full address binding is the strictest
#[test]
fn full_address_binding_from_the_realm_policy() {
    let p = BindingPolicy { full_ip: true };
    let ip = v4(192, 0, 2, 10);
    let b = Binding::of(ip, Some(64_500), p);
    assert_eq!(b, Binding::Address(ip));
    assert!(b.holds(ip, Some(64_500), p));
    assert!(!b.holds(v4(192, 0, 2, 11), Some(64_500), p));
    let six = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert_eq!(Binding::of(six, None, p), Binding::Address(six));
}

// TN-129: the stored binding reads back; anything else is refused
#[test]
fn binding_encoding_round_trips() {
    let all = [
        Binding::Asn(7),
        Binding::V4Prefix([10, 0, 0]),
        Binding::V6Prefix([1, 2, 3, 4, 5, 6]),
        Binding::Address(v4(10, 0, 0, 1)),
        Binding::Address(IpAddr::V6(Ipv6Addr::LOCALHOST)),
    ];
    for b in all {
        assert_eq!(Binding::decode(&b.encode()), Some(b));
    }
    for bad in [
        &[][..],
        &[1, 0, 0],
        &[2, 1, 2, 3, 4],
        &[9, 0],
        &[5, 1, 2, 3, 4],
    ] {
        assert_eq!(Binding::decode(bad), None);
    }
}

// TN-50, G57: an ended or revoked session is never valid, whatever its age
#[test]
fn ended_and_revoked_sessions_serve_nothing() {
    let ip = v4(192, 0, 2, 10);
    let p = BindingPolicy::default();
    let f = facts(Binding::of(ip, None, p));
    let ended = ConsoleFacts { ended: true, ..f };
    assert_eq!(check(&ended, ip, None, p, 1), ConsoleCheck::Ended);
    let revoked = ConsoleFacts { revoked: true, ..f };
    assert_eq!(check(&revoked, ip, None, p, 1), ConsoleCheck::Revoked);
    assert_eq!(ConsoleCheck::BindingMismatch.code(), "binding-mismatch");
}

// TN-131: the CSRF token is the session's and both copies must match it
#[test]
fn csrf_token_is_bound_to_the_session() {
    let a = Secret::new([7u8; 32]);
    let b = Secret::new([8u8; 32]);
    let t = csrf_token(&a);
    assert!(csrf_ok(&a, &t, &t));
    assert!(!csrf_ok(&b, &t, &t));
    assert!(!csrf_ok(&a, &t, &csrf_token(&b)));
    assert!(!csrf_ok(&a, "", &t));
    assert!(!csrf_ok(&a, "not base64url!", &t));
}

// TN-128, TN-131, TN-33: host-only, Secure, HttpOnly, SameSite=Strict, no lifetime of its own
#[test]
fn cookies_are_strict_and_host_only() {
    let c = session_cookie("v");
    assert!(c.starts_with("__Host-access-console=v;"));
    for part in ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"] {
        assert!(c.contains(part), "{part}");
    }
    assert!(!c.contains("Domain") && !c.contains("Max-Age"));
    let x = csrf_cookie("t");
    assert!(x.contains("SameSite=Strict") && x.contains("Secure") && !x.contains("HttpOnly"));
    for clear in clear_cookies() {
        assert!(clear.ends_with("Max-Age=0"));
    }
}
