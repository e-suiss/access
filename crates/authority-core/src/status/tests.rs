#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unused_async_trait_impl,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_kernel::digest::Digest;
use access_kernel::status::{ListToken, StatusRef, lookup};
use access_store::status::{List, Publication, Snapshot};

use super::*;

fn list() -> List {
    List {
        list_no: 0,
        uri: list_uri("https://api.example/", &Digest([7; 32]), 0),
        capacity: 64,
        allocated: 10,
    }
}

fn snapshot(pos: u64, recorded_at: u64, revoked: &[u64]) -> Snapshot {
    Snapshot {
        pos,
        recorded_at,
        revoked: revoked.to_vec(),
    }
}

fn last(seq: u64, applied_pos: u64, iat_ms: u64) -> Publication {
    Publication {
        uri: list().uri,
        seq,
        applied_pos,
        iat_ms,
        entries: 64,
        token: Vec::new(),
        excerpt: None,
    }
}

// OP-150 m.3 (a): a list is addressed under the API base by number and domain
#[test]
fn a_list_uri_names_its_number_and_domain() {
    let uri = list_uri("https://api.example/", &Digest([0; 32]), 3);
    assert_eq!(
        uri,
        format!(
            "https://api.example/access/v1/status-lists/3?domain=sha-256:{}",
            "A".repeat(43)
        )
    );
}

// L2-STL-3, OP-150 m.3 (s): one bit per entry, least significant first; an entry outside the
// list is refused
#[test]
fn bits_set_exactly_the_revoked_entries() {
    let b = bits(16, &[0, 9, 15]).unwrap();
    assert_eq!(b, vec![0b0000_0001, 0b1000_0010]);
    assert_eq!(bits(16, &[16]), Err(BuildError::Entry));
    assert_eq!(bits(0, &[]).unwrap(), vec![0]);
}

// T24, OP-150 m.3 (l), m.6 (d), L2-STL-2: the token's iat is the reflected position's
// recorded_at in seconds and as_of is that position; its compressed list reads back the bits
#[test]
fn a_token_reflects_its_position_and_bits() {
    let t = token(&list(), &snapshot(42, 1_700_000_123_999, &[3, 10])).unwrap();
    assert_eq!(t.iat, 1_700_000_123);
    assert_eq!(t.as_of, 42);
    assert_eq!(t.ttl, Some(TTL_S));
    let back = ListToken::from_bytes(&t.to_bytes().unwrap()).unwrap();
    assert_eq!(back, t);
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&t.lst).unwrap();
    let r = |idx| StatusRef {
        idx,
        uri: list().uri,
    };
    assert!(lookup(&t, &raw, &r(3)).unwrap());
    assert!(lookup(&t, &raw, &r(10)).unwrap());
    assert!(!lookup(&t, &raw, &r(4)).unwrap());
}

// G43, T24: a list never goes back to an earlier or the same position, so old content is never
// signed again with a fresh iat
#[test]
fn a_publication_never_goes_back() {
    let l = last(4, 20, 1_000);
    assert_eq!(
        plan(Some((&l, Some(0))), &snapshot(20, 900_000, &[1]), 900_000),
        Plan::Skip(Skip::NotNewer)
    );
    assert_eq!(
        plan(Some((&l, Some(0))), &snapshot(19, 900_000, &[1]), 900_000),
        Plan::Skip(Skip::NotNewer)
    );
    assert_eq!(
        plan(None, &snapshot(0, 0, &[]), 0),
        Plan::Publish { seq: 0 }
    );
}

// T24, §17.4.2: a revocation is published at once; an unchanged list only when its iat is a
// heartbeat old
#[test]
fn a_revocation_is_published_first_and_a_quiet_list_on_heartbeat() {
    let l = last(4, 20, 1_000_000);
    assert_eq!(
        plan(
            Some((&l, Some(1))),
            &snapshot(21, 1_000_100, &[1, 2]),
            1_000_200
        ),
        Plan::Publish { seq: 5 }
    );
    assert_eq!(
        plan(
            Some((&l, Some(2))),
            &snapshot(21, 1_000_100, &[1, 2]),
            1_000_200
        ),
        Plan::Skip(Skip::Unchanged)
    );
    assert_eq!(
        plan(
            Some((&l, Some(2))),
            &snapshot(30, 1_000_000 + HEARTBEAT_MS, &[1, 2]),
            1_000_000 + HEARTBEAT_MS
        ),
        Plan::Publish { seq: 5 }
    );
    assert_eq!(
        plan(Some((&l, None)), &snapshot(21, 1_000_100, &[]), 1_000_200),
        Plan::Publish { seq: 5 }
    );
}

struct Store {
    lists: Vec<List>,
    snapshot: Option<Snapshot>,
    recorded: std::sync::Mutex<Vec<Publication>>,
}

impl Lists for &Store {
    async fn lists(&self, _: Digest) -> Result<Vec<List>, CoreError> {
        Ok(self.lists.clone())
    }

    async fn snapshot(&self, _: Digest, _: &str) -> Result<Option<Snapshot>, CoreError> {
        Ok(self.snapshot.clone())
    }

    async fn latest(&self, _: Digest, _: &str) -> Result<Option<Publication>, CoreError> {
        Ok(self.recorded.lock().unwrap().last().cloned())
    }

    async fn record(&self, _: Digest, p: &Publication) -> Result<bool, CoreError> {
        self.recorded.lock().unwrap().push(p.clone());
        Ok(true)
    }
}

struct Refusing;

impl ListSigner for Refusing {
    async fn sign(
        &self,
        _: Digest,
        _: Vec<u8>,
        _: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
        Err("signer-unreachable")
    }
}

// T24, §17.4.2, PI-9: without a head to read, or without a signer, no list is published; the
// last one stays and ages, so a verifier's Δ decides
#[tokio::test]
async fn no_snapshot_or_no_signer_publishes_nothing() {
    let store = Store {
        lists: vec![list()],
        snapshot: None,
        recorded: std::sync::Mutex::new(Vec::new()),
    };
    let p = Publisher::new(&store, Refusing);
    assert!(matches!(
        p.publish(Digest([7; 32]), 5).await,
        Err(CoreError::Unavailable("status-head"))
    ));
    let store = Store {
        snapshot: Some(snapshot(3, 1_000, &[])),
        ..store
    };
    let p = Publisher::new(&store, Refusing);
    assert!(matches!(
        p.publish(Digest([7; 32]), 5).await,
        Err(CoreError::Unavailable("signer-unreachable"))
    ));
    assert!(store.recorded.lock().unwrap().is_empty());
}
