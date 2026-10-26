//! OP-130, TI-2, TI-6, TI-8, TI-19, L0-ENC-25: the sequencer against a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::time::Duration;

use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::{PgLog, create_genesis, verify_chain};
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::domain::{Draft, Item, NonceUse, Outcome};
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::codec::Canonical;
use access_kernel::digest::{self, Digest};
use access_kernel::record::{Opened, RecordEnvelope, RecordKind};
use access_store::StoreError;
use access_store::authority::{read_log, read_outbox};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};
use suiss_crypto::dcbor::Value;

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const TTL: Duration = Duration::from_secs(10);

fn fields(tag: &str) -> BTreeMap<String, Opened> {
    BTreeMap::from([(
        "note".to_owned(),
        Opened {
            value: Value::text(tag),
            salt: [3; 32],
        },
    )])
}

fn item(tag: &str, nonce: Option<(u8, u8)>) -> Item {
    Item {
        draft: Draft {
            kind: RecordKind::Decision,
            fields: fields(tag),
        },
        nonce: nonce.map(|(n, d)| NonceUse {
            nonce: vec![n; 16],
            actor: vec![1],
            intent_digest: [d; 32],
        }),
        events: vec![vec![0xa0]],
        proofs: vec![([9; 32], vec![1, 2, 3])],
    }
}

fn key() -> EventKey {
    EventKey::new(Secret::new([5; 32]))
}

async fn domain(db: &TestDb, tag: &str) -> Digest {
    create_genesis(&db.sequencer, TENANT, fields(tag), 1_000)
        .await
        .unwrap()
}

async fn lead(db: &TestDb, d: Digest, who: &str) -> Result<Leader<PgLog>, SequencerError> {
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, who.to_owned(), TTL);
    Leader::acquire(log, d, key()).await
}

#[tokio::test]
async fn domain_id_is_the_genesis_digest() {
    let db = fresh().await.unwrap();
    let d = domain(&db, "g").await;
    let log = read_log(&db.app, &DomainId::from_bytes(d.0), 0, 0)
        .await
        .unwrap();
    // L0-ENC-25
    assert_eq!(digest::domain_id(&log[0].envelope), d);
    assert_eq!(
        RecordEnvelope::from_bytes(&log[0].envelope)
            .unwrap()
            .domain()
            .unwrap(),
        d
    );
    // a second Genesis for the same content is the same domain and is refused
    assert!(
        create_genesis(&db.sequencer, TENANT, fields("g"), 1_000)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn records_chain_and_the_frontier_root_is_the_tree_head() {
    let db = fresh().await.unwrap();
    let d = domain(&db, "g").await;
    let mut l = lead(&db, d, "a").await.unwrap();
    for round in 0..4_u8 {
        let items: Vec<Item> = (0..=round)
            .map(|i| item(&format!("{round}-{i}"), None))
            .collect();
        assert!(matches!(
            l.commit(2_000 + u64::from(round), &items).await.unwrap(),
            Outcome::Appended(_)
        ));
    }
    let last = l.head().pos;
    assert_eq!(last, 10);
    verify_chain(&db.app, d, 0, last).await.unwrap();
    // RFC 9162 tree head over the stored leaf cores equals the frontier's root
    let log = read_log(&db.app, &DomainId::from_bytes(d.0), 0, last)
        .await
        .unwrap();
    let cores: Vec<Vec<u8>> = log
        .iter()
        .map(|r| {
            RecordEnvelope::from_bytes(&r.envelope)
                .unwrap()
                .leaf_core()
                .unwrap()
                .to_bytes()
                .unwrap()
        })
        .collect();
    let refs: Vec<&[u8]> = cores.iter().map(Vec::as_slice).collect();
    assert_eq!(l.head().frontier.root(), digest::root(&refs));
    // TI-19: time never goes back, even when the clock does
    l.commit(1, &[item("late", None)]).await.unwrap();
    let back = read_log(&db.app, &DomainId::from_bytes(d.0), last + 1, last + 1)
        .await
        .unwrap();
    assert_eq!(back[0].recorded_at, 2_003);
}

#[tokio::test]
async fn a_fenced_leader_steps_down_and_writes_nothing() {
    let db = fresh().await.unwrap();
    let d = domain(&db, "g").await;
    let mut old = lead(&db, d, "a").await.unwrap();
    old.commit(2_000, &[item("x", None)]).await.unwrap();
    assert!(matches!(
        lead(&db, d, "b").await,
        Err(SequencerError::Store(StoreError::LeaseHeld))
    ));
    // the old leader's lease lapses (simulated by a release it does not notice)
    let id = DomainId::from_bytes(d.0);
    access_store::authority::release_lease(
        &db.sequencer,
        &id,
        "a",
        access_store::authority::Lease { epoch: old.epoch() },
    )
    .await
    .unwrap();
    let mut new = lead(&db, d, "b").await.unwrap();
    assert!(new.epoch() > old.epoch());
    let err = old.commit(2_001, &[item("stale", None)]).await.unwrap_err();
    assert!(
        matches!(err, SequencerError::Store(StoreError::HeadMoved)),
        "{err}"
    );
    assert!(matches!(
        old.commit(2_002, &[item("again", None)]).await,
        Err(SequencerError::SteppedDown)
    ));
    new.commit(2_003, &[item("y", None)]).await.unwrap();
    verify_chain(&db.app, d, 0, new.head().pos).await.unwrap();
    assert_eq!(new.head().pos, 2);
}

#[tokio::test]
async fn a_nonce_retry_replays_and_a_reuse_conflicts() {
    let db = fresh().await.unwrap();
    let d = domain(&db, "g").await;
    let mut l = lead(&db, d, "a").await.unwrap();
    let Outcome::Appended(first) = l.commit(2_000, &[item("x", Some((1, 7)))]).await.unwrap()
    else {
        panic!()
    };
    // §9.5 k.5: same nonce, intent and actor
    assert_eq!(
        l.commit(2_001, &[item("x", Some((1, 7)))]).await.unwrap(),
        Outcome::Replayed(first[0])
    );
    // same nonce, other intent
    assert!(matches!(
        l.commit(2_002, &[item("x", Some((1, 8)))]).await,
        Err(SequencerError::NonceConflict)
    ));
    assert!(matches!(
        l.commit(2_003, &[item("a", Some((2, 1))), item("b", Some((2, 1)))])
            .await,
        Err(SequencerError::NonceRepeated)
    ));
    assert_eq!(l.head().pos, 1);
}

#[tokio::test]
async fn outbox_ids_are_keyed_per_domain_position_and_index() {
    let db = fresh().await.unwrap();
    let d = domain(&db, "g").await;
    let mut l = lead(&db, d, "a").await.unwrap();
    let mut it = item("x", None);
    it.events = vec![vec![1], vec![2]];
    l.commit(2_000, &[it]).await.unwrap();
    let id = DomainId::from_bytes(d.0);
    let rows = read_outbox(&db.app, &id, (0, 0), 10).await.unwrap();
    assert_eq!(
        rows.iter().map(|r| (r.pos, r.idx)).collect::<Vec<_>>(),
        [(1, 0), (1, 1)]
    );
    for r in rows {
        assert_eq!(r.event_id, key().event_id(id.as_bytes(), r.pos, r.idx));
    }
}

// OP-129 m.1: the process and server clocks of a local cluster agree within U
#[tokio::test]
async fn trusted_time_from_two_sources() {
    use access_authority_sequencer::adapters::SourcesClock;
    use access_authority_sequencer::ports::Clock;
    let db = fresh().await.unwrap();
    let mut clock = SourcesClock::new(db.app.clone());
    let a = clock.now().await.unwrap();
    let b = clock.now().await.unwrap();
    assert!(a > 1_700_000_000_000);
    assert!(b + 250 >= a);
}
