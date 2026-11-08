//! The management API's pure rules (OP-65, TN-112, TN-126, TN-127, OP-67 m.1): trace context,
//! GCRA buckets, route groups, idempotency answers, ETag/If-Match, listing, cursors, lifecycle
//! headers, JSON Merge Patch and the caller model.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;

use access_http::api::adapters::{MemoryLimiter, SivCursors};
use access_http::api::domain::SurfaceScope;
use access_http::api::domain::caller::{
    Authorization, MAX_TOKEN_LIFETIME_MS, Refusal, ais_bytes, authorization, check_read,
};
use access_http::api::domain::conditional::{Precondition, etag, if_match};
use access_http::api::domain::idempotency::{Answer, valid_key};
use access_http::api::domain::lifecycle::{Lifecycle, deprecation, sunset};
use access_http::api::domain::merge_patch::{PatchError, apply, check};
use access_http::api::domain::page::{
    DEFAULT_PAGE, QueryError, cursor_context, next_link, page_size, parameters,
};
use access_http::api::domain::rate::{self, Quota, gcra, group_of};
use access_http::api::domain::trace::TraceContext;
use access_http::api::manifest::GROUPS;
use access_http::api::ports::{CursorSeal, RateLimiter, ReadToken};
use serde_json::json;
use suiss_crypto::secret::Secret;

// OP-67 m.1: W3C traceparent parsing
#[test]
fn traceparent_is_read_strictly() {
    let t = TraceContext::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").unwrap();
    assert_eq!(t.request_id(), "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(t.flags, 1);
    assert!(
        TraceContext::parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-x").is_some()
    );
    for bad in [
        "",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e473-00f067aa0ba902b7-01",
    ] {
        assert!(TraceContext::parse(bad).is_none(), "{bad}");
    }
}

// TN-127: GCRA admits the burst, then the sustained rate
#[test]
fn buckets_admit_the_burst_then_the_rate() {
    let q = Quota {
        name: "q",
        limit: 10,
        window_s: 1,
        burst: 5,
    };
    let mut tat = 0;
    let now = 1_000_000;
    for i in 0..5 {
        let (next, take) = gcra(tat, now, q);
        assert!(take.allowed, "{i}");
        assert_eq!(take.remaining, 4 - i);
        tat = next;
    }
    let (_, take) = gcra(tat, now, q);
    assert!(!take.allowed);
    assert_eq!(take.reset_s, 1);
    let (_, take) = gcra(tat, now + 100, q);
    assert!(take.allowed, "one interval later");
    assert_eq!(rate::limit_item(q, take), "\"q\";r=0;t=1");
    assert_eq!(q.policy_item(), "\"q\";q=10;w=1");
}

// TN-127: three layers behind one port; concurrency slots are returned
#[test]
fn the_limiter_counts_concurrency_slots() {
    let l = MemoryLimiter::default();
    assert!(l.enter("a", 2));
    assert!(l.enter("a", 2));
    assert!(!l.enter("a", 2));
    assert!(l.enter("b", 2));
    l.leave("a");
    assert!(l.enter("a", 2));
}

// TN-127: longest-prefix route groups
#[test]
fn route_groups_are_longest_prefix() {
    assert_eq!(group_of("/admin/v1/platform", GROUPS), "/admin/v1/platform");
    assert_eq!(
        group_of("/admin/v1/realms/{slug}/clients/{id}", GROUPS),
        "/admin/v1/realms/{slug}"
    );
    assert_eq!(
        group_of("/admin/v1/platformx", GROUPS),
        "/admin/v1/platformx"
    );
    assert_eq!(
        rate::actor_quota(access_http::api::domain::Surface::Realm, true),
        rate::REALM_WRITE
    );
}

// TN-126: keys and kept answers
#[test]
fn keys_and_answers_round_trip() {
    assert!(valid_key(b"AAAAAAAAAAAAAAAAAAAAAA"));
    assert!(!valid_key(b""));
    assert!(!valid_key(&[b'k'; 256]));
    assert!(!valid_key(b"a\tb"));
    let a = Answer {
        status: 201,
        headers: vec![("content-type".into(), b"application/json".to_vec())],
        body: b"{}".to_vec(),
    };
    assert_eq!(Answer::decode(&a.encode().unwrap()).unwrap(), a);
    let mut bytes = a.encode().unwrap();
    bytes.push(0);
    assert!(Answer::decode(&bytes).is_none());
    assert!(Answer::decode(&[0, 1, 0xff, 0xff, 0xff, 0xff]).is_none());
}

// OP-65: strong ETags and If-Match (428 without, 412 on a mismatch, weak never matches)
#[test]
fn if_match_compares_strong_tags() {
    let v1 = etag("client", "cli_1", b"1");
    let v2 = etag("client", "cli_1", b"2");
    assert_ne!(v1, v2);
    assert_ne!(v1, etag("client", "cli_2", b"1"));
    assert!(v1.starts_with('"') && v1.ends_with('"'));
    assert_eq!(if_match([], Some(&v1)), Err(Precondition::Required));
    assert_eq!(if_match([v1.as_str()], Some(&v1)), Ok(()));
    assert_eq!(
        if_match([v2.as_str()], Some(&v1)),
        Err(Precondition::Failed)
    );
    let list = format!("{v2}, {v1}");
    assert_eq!(if_match([list.as_str()], Some(&v1)), Ok(()));
    let weak = format!("W/{v1}");
    assert_eq!(
        if_match([weak.as_str()], Some(&v1)),
        Err(Precondition::Failed)
    );
    assert_eq!(if_match(["*"], Some(&v1)), Ok(()));
    assert_eq!(if_match(["*"], None), Err(Precondition::Failed));
}

// OP-65, TN-112, §13.7.4, RAUTHY-004: only named parameters, page size 1 to 100, no offsets
#[test]
fn list_queries_are_closed() {
    let allowed = &["page[size]", "cursor", "filter"];
    let p = parameters(
        Some("page%5Bsize%5D=10&filter=userName+eq+%22a%22"),
        allowed,
    )
    .unwrap();
    assert_eq!(p["filter"], "userName eq \"a\"");
    assert_eq!(page_size(&p), Ok(10));
    assert_eq!(page_size(&BTreeMap::new()), Ok(DEFAULT_PAGE));
    for q in ["offset=10", "page=2", "cursor=a&cursor=b", "filter=%ZZ"] {
        assert_eq!(
            parameters(Some(q), allowed),
            Err(QueryError::Unknown),
            "{q}"
        );
    }
    for size in ["0", "101", "-1", "010", "x", ""] {
        let p = parameters(Some(&format!("page[size]={size}")), allowed).unwrap();
        assert_eq!(page_size(&p), Err(QueryError::PageSize), "{size}");
    }
}

// OP-65, RFC 8288: opaque cursors bound to their list, and the next link
#[test]
fn cursors_are_sealed_to_their_list() {
    let c = SivCursors::new(Secret::new([1; 32]));
    let params: BTreeMap<String, String> = [("filter".to_owned(), "active pr".to_owned())].into();
    let ctx = cursor_context("listClients", "realm:acme", &params);
    let cursor = c.seal(&ctx, b"position-42").unwrap();
    assert!(!cursor.contains("position"));
    assert_eq!(c.open(&ctx, &cursor).unwrap(), b"position-42");
    let other = cursor_context("listClients", "realm:other", &params);
    assert!(c.open(&other, &cursor).is_none(), "another realm's list");
    let refiltered = cursor_context("listClients", "realm:acme", &BTreeMap::new());
    assert!(c.open(&refiltered, &cursor).is_none(), "another filter");
    assert!(c.open(&ctx, "AAAA").is_none());
    let link = next_link("/admin/v1/realms/acme/clients", &params, &cursor);
    assert!(link.starts_with("</admin/v1/realms/acme/clients?filter=active%20pr&cursor="));
    assert!(link.ends_with(">; rel=\"next\""));
}

// OP-65 m.2: RFC 9745 Deprecation and RFC 8594 Sunset
#[test]
fn lifecycle_headers_are_well_formed() {
    assert_eq!(deprecation(1_688_169_599), "@1688169599");
    assert_eq!(
        sunset(1_782_864_000).unwrap(),
        "Wed, 01 Jul 2026 00:00:00 GMT"
    );
    let l = Lifecycle {
        deprecated_at: 1_688_169_599,
        sunset_at: Some(1_782_864_000),
        successor: Some("/admin/v1/realms/{slug}/clients/v2"),
    };
    let h = l.headers();
    assert_eq!(h[0], ("deprecation", "@1688169599".to_owned()));
    assert_eq!(h[1].0, "sunset");
    assert!(h[2].1.contains("rel=\"successor-version\""));
}

// TN-112 k.2, RFC 7396: merge patch with explicit null, and only the resource's members
#[test]
fn merge_patch_follows_rfc_7396() {
    let mut target = json!({ "a": "b", "c": { "d": "e", "f": "g" } });
    apply(&mut target, &json!({ "a": "z", "c": { "f": null } })).unwrap();
    assert_eq!(target, json!({ "a": "z", "c": { "d": "e" } }));
    let mut t = json!({ "a": [1] });
    apply(&mut t, &json!({ "a": { "b": "c" }, "n": null })).unwrap();
    assert_eq!(t, json!({ "a": { "b": "c" } }));
    let mut t = json!({ "a": "b" });
    apply(&mut t, &json!(["c"])).unwrap();
    assert_eq!(t, json!(["c"]));
    assert_eq!(check(&json!({ "name": "x" }), &["name"]), Ok(()));
    assert_eq!(
        check(&json!({ "name": "x", "owner": "y" }), &["name"]),
        Err(PatchError::Invalid)
    );
    assert_eq!(check(&json!([]), &["name"]), Err(PatchError::Invalid));
    let mut deep = json!(1);
    for _ in 0..40 {
        deep = json!({ "a": deep });
    }
    assert_eq!(apply(&mut json!({}), &deep), Err(PatchError::Invalid));
}

fn token(audience: &str, scopes: &[&str], iat: u64, exp: u64) -> ReadToken {
    ReadToken {
        audience: audience.into(),
        scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
        subject: "s".into(),
        issued_at_ms: iat,
        expires_at_ms: exp,
        id: [0; 32],
    }
}

// OP-151 m.3 (a), (c), TN-119, TN-130: audience per surface, scope, ≤ 60 min, not expired
#[test]
fn read_tokens_are_held_to_their_surface() {
    let realm = SurfaceScope::Realm("acme".into());
    let now = 1_000_000_000;
    let ok = token(
        "access-admin:realm:acme",
        &["realm.read"],
        now,
        now + 60_000,
    );
    assert_eq!(check_read(&ok, &realm, "realm.read", now), Ok(()));
    assert_eq!(
        check_read(&ok, &SurfaceScope::Platform, "platform.read", now),
        Err(Refusal::WrongAudience)
    );
    assert_eq!(
        check_read(&ok, &SurfaceScope::Realm("acme2".into()), "realm.read", now),
        Err(Refusal::WrongAudience)
    );
    assert_eq!(
        check_read(&ok, &realm, "realm.audit.read", now),
        Err(Refusal::InsufficientScope)
    );
    assert_eq!(
        check_read(&ok, &realm, "realm.read", now + 60_000),
        Err(Refusal::InvalidToken)
    );
    let long = token(
        "access-admin:realm:acme",
        &["realm.read"],
        now,
        now + MAX_TOKEN_LIFETIME_MS + 1,
    );
    assert_eq!(
        check_read(&long, &realm, "realm.read", now),
        Err(Refusal::TokenLifetime)
    );
    assert_eq!(authorization(&[]), Authorization::None);
    assert_eq!(authorization(&["DPoP abc"]), Authorization::Dpop("abc"));
    assert_eq!(authorization(&["Bearer abc"]), Authorization::Unusable);
    assert_eq!(
        authorization(&["DPoP a", "DPoP b"]),
        Authorization::Unusable
    );
    assert_eq!(ais_bytes(&[], b"{}"), Err(Refusal::AisRequired));
    assert_eq!(ais_bytes(&["!!"], b""), Err(Refusal::AisInvalid));
    assert_eq!(ais_bytes(&[], br#"{"ais": 1}"#), Err(Refusal::AisInvalid));
}
