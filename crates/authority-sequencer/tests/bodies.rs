//! T39, CR-32, OP-73, OP-135: encrypted bodies, crypto-shredding and KEK rotation on a real
//! PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_crypto::envelope::{Dek, Kek, Sealed, SoftKek, open_body, rewrap, seal_body};
use access_store::authority::{LogRecord, create_domain};
use access_store::bodies::{get, put, shred, wrapped_by};
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};

async fn domain(db: &TestDb, seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, [1; 16], &g).await.unwrap();
    d
}

fn context(d: &DomainId, commit: &[u8; 32]) -> Vec<u8> {
    [d.as_bytes().as_slice(), commit.as_slice()].concat()
}

async fn store(db: &TestDb, d: &DomainId, kek: &SoftKek, commit: [u8; 32], body: &[u8]) {
    let dek = Dek::generate().unwrap();
    let wrapped = kek.wrap(&dek).unwrap();
    let sealed = seal_body(dek, &context(d, &commit), body).unwrap();
    put(
        &db.sequencer,
        d,
        &commit,
        kek.id(),
        &wrapped,
        &sealed.nonce,
        &sealed.ciphertext,
    )
    .await
    .unwrap();
}

async fn read(db: &TestDb, d: &DomainId, kek: &SoftKek, commit: [u8; 32]) -> Option<Vec<u8>> {
    let body = get(&db.app, d, &commit).await.unwrap().unwrap();
    let (wrapped, nonce, ciphertext) = body.sealed?;
    let dek = kek.unwrap(&wrapped).unwrap();
    Some(
        open_body(&dek, &context(d, &commit), &Sealed { nonce, ciphertext })
            .unwrap()
            .to_vec(),
    )
}

// T39: a body is stored encrypted and read back with the domain KEK
#[tokio::test]
async fn bodies_round_trip_encrypted() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 1).await;
    let kek = SoftKek::new("dom-kek-1", [7; 32]);
    store(&db, &d, &kek, [2; 32], b"intent body").await;
    assert_eq!(read(&db, &d, &kek, [2; 32]).await.unwrap(), b"intent body");
    let raw = get(&db.app, &d, &[2; 32])
        .await
        .unwrap()
        .unwrap()
        .sealed
        .unwrap();
    assert!(
        !raw.2.windows(6).any(|w| w == b"intent"),
        "the database holds ciphertext only"
    );
}

// OP-73, OP-74: shredding removes the key and the ciphertext; the row and commitment stay
#[tokio::test]
async fn a_shredded_body_cannot_be_read_or_revived() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 3).await;
    let kek = SoftKek::new("dom-kek-1", [7; 32]);
    store(&db, &d, &kek, [4; 32], b"personal data").await;
    assert!(shred(&db.sequencer, &d, &[4; 32]).await.unwrap());
    assert!(!shred(&db.sequencer, &d, &[4; 32]).await.unwrap());
    let body = get(&db.app, &d, &[4; 32]).await.unwrap().unwrap();
    assert!(body.sealed.is_none());
    assert!(read(&db, &d, &kek, [4; 32]).await.is_none());
    // the same commitment cannot be stored again to bring the body back
    store(&db, &d, &kek, [4; 32], b"personal data").await;
    assert!(
        get(&db.app, &d, &[4; 32])
            .await
            .unwrap()
            .unwrap()
            .sealed
            .is_none()
    );
}

// §17.10.4: every body moves to the new KEK; the old one is no longer needed
#[tokio::test]
async fn kek_rotation_rewraps_live_bodies() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 5).await;
    let (old, new) = (
        SoftKek::new("dom-kek-1", [7; 32]),
        SoftKek::new("dom-kek-2", [8; 32]),
    );
    for c in 10..13_u8 {
        store(&db, &d, &old, [c; 32], &[c]).await;
    }
    shred(&db.sequencer, &d, &[12; 32]).await.unwrap();
    let todo = wrapped_by(&db.app, &d, old.id(), 100).await.unwrap();
    assert_eq!(todo, [[10; 32], [11; 32]]);
    for commit in todo {
        let (wrapped, _, _) = get(&db.app, &d, &commit)
            .await
            .unwrap()
            .unwrap()
            .sealed
            .unwrap();
        let rotated = rewrap(&old, &new, &wrapped).unwrap();
        assert!(
            access_store::bodies::rewrap(&db.sequencer, &d, &commit, new.id(), &rotated)
                .await
                .unwrap()
        );
    }
    assert_eq!(
        wrapped_by(&db.app, &d, old.id(), 100).await.unwrap(),
        Vec::<[u8; 32]>::new()
    );
    assert_eq!(read(&db, &d, &new, [10; 32]).await.unwrap(), [10]);
}

// OP-73: the application cannot write bodies, and no role deletes them
#[tokio::test]
async fn only_the_sequencer_writes_bodies() {
    let db = fresh().await.unwrap();
    let d = domain(&db, 6).await;
    let err = put(&db.app, &d, &[1; 32], "k", &[0; 40], &[0; 12], &[0; 16])
        .await
        .unwrap_err();
    assert!(err.to_string().contains("permission denied"), "{err}");
}
