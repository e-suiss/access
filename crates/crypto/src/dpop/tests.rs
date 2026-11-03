use super::*;

const REALM: [u8; 16] = [3; 16];
const HOUR: u64 = 60 * 60 * 1000;
const T0: u64 = 1_800_000_000_000;

fn key(n: u8) -> NonceKey {
    NonceKey::new(Secret::new([n; 32]))
}

fn ring(role: Role) -> NonceRing {
    NonceRing::new(
        REALM,
        role,
        NoncePolicy::new(HOUR, MAX_STALE_MS).unwrap(),
        1,
        key(1),
    )
}

// TN-30, OP-146 m.3: fixed-length SHA-256 replay key, unambiguous over its parts
#[test]
fn replay_key_is_sha256_and_unambiguous() {
    let k = replay_key("POST", "https://a.example/token", "j1");
    assert_eq!(k, replay_key("POST", "https://a.example/token", "j1"));
    assert_ne!(k, replay_key("GET", "https://a.example/token", "j1"));
    assert_ne!(k, replay_key("POST", "https://a.example/other", "j1"));
    assert_ne!(k, replay_key("POST", "https://a.example/token", "j2"));
    assert_ne!(replay_key("PO", "STx", "j"), replay_key("POST", "x", "j"));
    let long = "j".repeat(10_000);
    assert_eq!(replay_key("POST", "u", &long).len(), 32);
    let mut message = REPLAY_CONTEXT.to_vec();
    for part in ["POST", "u", "j"] {
        message.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
        message.extend_from_slice(part.as_bytes());
    }
    assert_eq!(
        replay_key("POST", "u", "j").as_slice(),
        digest::digest(&digest::SHA256, &message).as_ref()
    );
}

// TN-29, MD-18: an issued nonce is accepted for its window, the next one and the stale tolerance
#[test]
fn nonce_sliding_window_and_stale_tolerance() {
    let r = ring(Role::AuthorizationServer);
    let start = T0 - T0 % HOUR;
    let n = r.issue(start).unwrap();
    assert_eq!(r.issue(start + HOUR - 1).unwrap(), n);
    assert_ne!(r.issue(start + HOUR).unwrap(), n);
    for now in [
        start,
        start + HOUR,
        start + 2 * HOUR - 1,
        start + 2 * HOUR + MAX_STALE_MS - 1,
    ] {
        assert_eq!(r.check(Some(&n), now), Ok(()), "{now}");
    }
    assert_eq!(
        r.check(Some(&n), start + 2 * HOUR + MAX_STALE_MS),
        Err(NonceError::Expired)
    );
    assert_eq!(r.check(Some(&n), start - 1), Err(NonceError::Future));
}

// TN-29: a nonce-less proof is rejected; tampered or foreign nonces fail
#[test]
fn nonce_missing_malformed_or_forged() {
    let r = ring(Role::AuthorizationServer);
    let n = r.issue(T0).unwrap();
    assert_eq!(r.check(None, T0), Err(NonceError::Missing));
    assert_eq!(r.check(Some("abc"), T0), Err(NonceError::Malformed));
    assert_eq!(r.check(Some("!!!"), T0), Err(NonceError::Malformed));
    let mut raw = b64url_decode(&n).unwrap();
    raw[0] = 2;
    assert_eq!(
        r.check(Some(&b64url_encode(&raw)), T0),
        Err(NonceError::Malformed)
    );
    let mut raw = b64url_decode(&n).unwrap();
    raw[28] ^= 1;
    assert_eq!(
        r.check(Some(&b64url_encode(&raw)), T0),
        Err(NonceError::Mismatch)
    );
    let other_realm = NonceRing::new([4; 16], Role::AuthorizationServer, r.policy(), 1, key(1));
    assert_eq!(other_realm.check(Some(&n), T0), Err(NonceError::Mismatch));
}

// TN-29, CR-3 (b): authorization server and resource server nonces are separate
#[test]
fn as_and_rs_nonces_are_separate() {
    let a = ring(Role::AuthorizationServer);
    let same_key_rs = ring(Role::ResourceServer);
    let rs = NonceRing::new(REALM, Role::ResourceServer, a.policy(), 1, key(2));
    let n = a.issue(T0).unwrap();
    assert_eq!(same_key_rs.check(Some(&n), T0), Err(NonceError::Mismatch));
    assert_eq!(rs.check(Some(&n), T0), Err(NonceError::Mismatch));
    assert_eq!(rs.check(Some(&rs.issue(T0).unwrap()), T0), Ok(()));
    assert_ne!(
        label(&REALM, Role::AuthorizationServer, 1),
        label(&REALM, Role::ResourceServer, 1)
    );
    assert_eq!(
        label(&[0xab; 16], Role::ResourceServer, 7),
        format!("access/dpop-nonce/{}/rs/7", "ab".repeat(16))
    );
}

// TN-29: rotation keeps the previous generation accepted and drops the one before
#[test]
fn nonce_key_rotation() {
    let mut r = ring(Role::AuthorizationServer);
    let first = r.issue(T0).unwrap();
    r.rotate(2, key(2));
    let second = r.issue(T0).unwrap();
    assert_ne!(first, second);
    assert_eq!(r.check(Some(&first), T0), Ok(()));
    assert_eq!(r.check(Some(&second), T0), Ok(()));
    r.rotate(3, key(3));
    assert_eq!(r.check(Some(&first), T0), Err(NonceError::UnknownKey));
    assert_eq!(r.check(Some(&second), T0), Ok(()));
}

// TN-29, MD-18: the stale tolerance is at most 5 minutes; there is no 60 s nonce model
#[test]
fn nonce_policy_bounds() {
    assert_eq!(
        NoncePolicy::new(HOUR, MAX_STALE_MS + 1),
        Err(NonceError::Policy)
    );
    assert_eq!(NoncePolicy::new(0, 0), Err(NonceError::Policy));
    assert_eq!(NoncePolicy::new(1000, 2000), Err(NonceError::Policy));
    let d = NoncePolicy::default();
    assert!(d.period_ms() >= HOUR);
    assert_eq!(d.stale_ms(), MAX_STALE_MS);
    let codes: std::collections::BTreeSet<&str> = [
        NonceError::Missing,
        NonceError::Malformed,
        NonceError::UnknownKey,
        NonceError::Expired,
        NonceError::Future,
        NonceError::Mismatch,
        NonceError::Unavailable,
        NonceError::Policy,
    ]
    .iter()
    .map(|e| e.code())
    .collect();
    assert_eq!(codes.len(), 8);
}
