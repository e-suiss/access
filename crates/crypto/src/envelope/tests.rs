use super::{
    CACHE_TTL_MS, Dek, DekCache, EnvelopeError, Kek, Sealer, SoftKek, open_body, rewrap, seal_body,
};

fn kek(id: &str, b: u8) -> SoftKek {
    SoftKek::new(id, [b; 32])
}

// T39, CR-32: a body round-trips under its DEK and nothing else
#[test]
fn a_body_opens_only_with_its_key_and_context() {
    let k = kek("domain-kek-1", 1);
    let dek = Dek::generate().unwrap();
    let wrapped = k.wrap(&dek).unwrap();
    assert_eq!(wrapped.len(), 40, "RFC 3394 adds one 8-byte block");
    let sealed = seal_body(dek, b"dom|body", b"secret body").unwrap();
    let dek = k.unwrap(&wrapped).unwrap();
    assert_eq!(
        open_body(&dek, b"dom|body", &sealed).unwrap().as_slice(),
        b"secret body"
    );
    assert_eq!(
        open_body(&dek, b"dom|other", &sealed).unwrap_err(),
        EnvelopeError::Open
    );
    let mut tampered = sealed.clone();
    tampered.ciphertext[0] ^= 1;
    assert_eq!(
        open_body(&dek, b"dom|body", &tampered).unwrap_err(),
        EnvelopeError::Open
    );
    let other = Dek::generate().unwrap();
    assert_eq!(
        open_body(&other, b"dom|body", &sealed).unwrap_err(),
        EnvelopeError::Open
    );
}

// OP-135 m.1: a key wrapped by one KEK does not unwrap under another; rotation rewraps it
#[test]
fn wrapping_is_bound_to_the_kek_and_rotates() {
    let (old, new) = (kek("v1", 1), kek("v2", 2));
    let dek = Dek::generate().unwrap();
    let wrapped = old.wrap(&dek).unwrap();
    let sealed = seal_body(dek, b"c", b"x").unwrap();
    assert_eq!(new.unwrap(&wrapped).err(), Some(EnvelopeError::Wrap));
    let rotated = rewrap(&old, &new, &wrapped).unwrap();
    assert_ne!(rotated, wrapped);
    assert_eq!(
        open_body(&new.unwrap(&rotated).unwrap(), b"c", &sealed)
            .unwrap()
            .as_slice(),
        b"x"
    );
    let mut bad = wrapped.clone();
    bad[5] ^= 1;
    assert_eq!(old.unwrap(&bad).err(), Some(EnvelopeError::Wrap));
}

// V4 (CR-51.2): a long-lived DEK refuses past its message limit and on counter overflow
#[test]
fn a_long_lived_key_stops_at_its_limit() {
    let mut s = Sealer::with_limit(Dek::generate().unwrap(), 0, 2);
    let a = s.seal(b"c", b"1").unwrap();
    s.seal(b"c", b"2").unwrap();
    assert_eq!(s.seal(b"c", b"3").unwrap_err(), EnvelopeError::Exhausted);
    assert_eq!(s.used(), 2);
    assert_eq!(s.open(b"c", &a).unwrap().as_slice(), b"1");
    let mut full = Sealer::with_limit(Dek::generate().unwrap(), u64::MAX, u64::MAX);
    assert_eq!(full.seal(b"c", b"x").unwrap_err(), EnvelopeError::Exhausted);
    assert_eq!(
        Sealer::new(Dek::generate().unwrap(), super::MESSAGE_LIMIT)
            .seal(b"c", b"x")
            .unwrap_err(),
        EnvelopeError::Exhausted
    );
}

// fresh nonces: two encryptions of one message differ
#[test]
fn nonces_are_fresh() {
    let mut s = Sealer::new(Dek::generate().unwrap(), 0);
    let (a, b) = (s.seal(b"c", b"m").unwrap(), s.seal(b"c", b"m").unwrap());
    assert_ne!(a.nonce, b.nonce);
    assert_ne!(a.ciphertext, b.ciphertext);
}

// CR-32.2: cached keys expire, the cache is bounded, a shredded key is forgotten at once
#[test]
fn the_cache_expires_bounds_and_forgets() {
    let k = kek("v1", 1);
    let wrapped: Vec<Vec<u8>> = (0..3)
        .map(|_| k.wrap(&Dek::generate().unwrap()).unwrap())
        .collect();
    let mut c = DekCache::new(CACHE_TTL_MS, 2);
    c.get(&k, &wrapped[0], 0).unwrap();
    c.get(&k, &wrapped[1], 10).unwrap();
    c.get(&k, &wrapped[2], 20).unwrap();
    assert_eq!(c.len(), 2, "the oldest entry made room");
    c.forget(&wrapped[2]);
    assert_eq!(c.len(), 1);
    c.get(&k, &wrapped[1], CACHE_TTL_MS + 11).unwrap();
    assert_eq!(
        c.len(),
        1,
        "the expired entry was dropped and the key unwrapped again"
    );
    assert!(c.get(&kek("v2", 2), &wrapped[0], 0).is_err());
}
