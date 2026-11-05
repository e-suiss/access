//! OP-150 m.2: the Stage 6 tables against a real PostgreSQL. Nothing is deleted, an end is
//! written once, and the Claim Ingest digests live in day partitions (OP-73, OP-146 m.5 (f)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::format_collect,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, acquire_lease, commit_batch, create_domain,
};
use access_store::claims::{
    QuarantineRow, first_submission, insert_quarantine, open_claim_ingest_day, quarantined,
    quota_notified, quota_reached,
};
use access_store::identity::TenantTx;
use access_store::offline::{ReportRow, insert_profile, insert_report, last_report, profile};
use access_store::projections::{Family, family, open_family, revoke_family};
use access_store::realm_binding::{Role, bind, domains, retire};
use access_store::scope::DomainId;
use access_store::status::{Publication, latest, publish};
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use sqlx::{Connection, Executor, PgConnection};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 6];

/// A domain whose log holds positions 0 to 3.
async fn domain(db: &TestDb, tenant: [u8; 16], seed: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let genesis = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1_000,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, tenant, &genesis, &[])
        .await
        .unwrap();
    let (lease, head) = acquire_lease(&db.sequencer, &d, "a", Duration::from_secs(10))
        .await
        .unwrap();
    let records = (1..=3)
        .map(|pos| LogRecord {
            pos,
            kind: "claim",
            recorded_at: 2_000,
            leaf_hash: [0x80 + u8::try_from(pos).unwrap(); 32],
            envelope: vec![0xa1, u8::try_from(pos).unwrap()],
        })
        .collect();
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records,
        head: HeadRow {
            pos: 3,
            epoch: lease.epoch,
            leaf_hash: [0x83; 32],
            recorded_at: 2_000,
            frontier: vec![[0x83; 32]],
        },
        nonces: vec![],
        outbox: vec![],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        effects: vec![],
    };
    commit_batch(&db.sequencer, &d, tenant, &batch)
        .await
        .unwrap();
    d
}

/// Runs `sql` as the owner inside `domain`'s scope and returns the error text, if any.
async fn as_owner(db: &TestDb, domain: &DomainId, sql: &str) -> Option<String> {
    let mut c = PgConnection::connect_with(&db.admin).await.unwrap();
    let hex: String = domain
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    c.execute("SET ROLE access_migrator").await.unwrap();
    c.execute(sqlx::AssertSqlSafe(format!(
        "SELECT set_config('app.domain_id', '{hex}', false)"
    )))
    .await
    .unwrap();
    c.execute(sqlx::AssertSqlSafe(sql.to_owned()))
        .await
        .err()
        .map(|e| e.to_string())
}

// OP-146 m.5 (f), CMP-8: a submission digest is recorded once per day; a day nobody opened
// refuses it
#[tokio::test]
async fn submission_digests_live_in_day_partitions() {
    let db = fresh().await.unwrap();
    let d = domain(&db, TENANT, 1).await;
    assert!(
        first_submission(&db.app, &d, 20_000, &[7; 32], "cose")
            .await
            .is_err()
    );
    open_claim_ingest_day(&db.archive, 20_000).await.unwrap();
    assert!(
        first_submission(&db.app, &d, 20_000, &[7; 32], "cose")
            .await
            .unwrap()
    );
    assert!(
        !first_submission(&db.app, &d, 20_000, &[7; 32], "pep")
            .await
            .unwrap()
    );
    assert!(
        first_submission(&db.app, &d, 20_000, &[7; 32], "fax")
            .await
            .is_err()
    );
    let err = as_owner(&db, &d, "DELETE FROM access.claim_ingest").await;
    assert!(err.is_some(), "OP-73");
}

// L2-CLM-3, G44, §16.7, OP-73: quarantine rows are kept as written; an issuer's quota notice
// is sent once
#[tokio::test]
async fn quarantine_and_quota_notices() {
    let db = fresh().await.unwrap();
    let d = domain(&db, TENANT, 2).await;
    let row = QuarantineRow {
        pos: 1,
        claim: [4; 16],
        issuer: [5; 16],
        class: String::from("authentication"),
        reason: String::from("source-not-accepted"),
    };
    insert_quarantine(&db.sequencer, &d, &row).await.unwrap();
    insert_quarantine(
        &db.sequencer,
        &d,
        &QuarantineRow {
            pos: 2,
            reason: String::from("quota"),
            ..row.clone()
        },
    )
    .await
    .unwrap();
    let held = quarantined(&db.app, &d, &[4; 16]).await.unwrap();
    assert_eq!(held.len(), 2);
    assert_eq!(held[0], row);
    assert!(
        as_owner(
            &db,
            &d,
            "UPDATE access.claim_quarantine SET reason = 'future'"
        )
        .await
        .is_some()
    );
    assert!(
        quota_reached(&db.sequencer, &d, &[5; 16], 0, 3_600, 2)
            .await
            .unwrap()
    );
    assert!(
        !quota_reached(&db.sequencer, &d, &[5; 16], 0, 3_600, 2)
            .await
            .unwrap()
    );
    assert!(quota_notified(&db.app, &d, &[5; 16], 0).await.unwrap());
    assert!(!quota_notified(&db.app, &d, &[5; 16], 0).await.unwrap());
}

// TN-4: a realm has one live governing domain and any number of consuming ones, each through an
// Acceptance; a retired binding stays
#[tokio::test]
async fn realms_bind_to_many_domains() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let governing = domain(&db, *t.as_bytes(), 3).await;
    let consuming = domain(&db, *t.as_bytes(), 4).await;
    let other = domain(&db, *t.as_bytes(), 5).await;
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &governing, "acme-bind", "pool-default")
        .await
        .unwrap();
    assert!(bind(&mut tx, r, &governing, Role::Governing).await.unwrap());
    assert!(
        bind(
            &mut tx,
            r,
            &consuming,
            Role::Consuming {
                acceptance: [9; 16]
            }
        )
        .await
        .unwrap()
    );
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    assert!(bind(&mut tx, r, &other, Role::Governing).await.is_err());
    drop(tx);
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    assert!(retire(&mut tx, r, &consuming).await.unwrap());
    assert!(!retire(&mut tx, r, &consuming).await.unwrap());
    let live = domains(&mut tx, r).await.unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].1, Role::Governing);
    tx.commit().await.unwrap();
}

// §9.12.1, §9.12.2, L2-RPT-2: reports keep their chain and profiles are found by digest
#[tokio::test]
async fn reports_and_profiles_are_recorded() {
    let db = fresh().await.unwrap();
    let d = domain(&db, TENANT, 6).await;
    let first = ReportRow {
        pos: 1,
        claim: [1; 16],
        exercise: [8; 32],
        previous: None,
        first_seq: 0,
        next_seq: 3,
        head: [9; 32],
        period_from_ms: 0,
        period_until_ms: 10,
        body: vec![0xa0],
    };
    insert_report(&db.sequencer, &d, &first).await.unwrap();
    let second = ReportRow {
        pos: 2,
        previous: Some([9; 32]),
        first_seq: 3,
        next_seq: 5,
        head: [10; 32],
        ..first.clone()
    };
    insert_report(&db.sequencer, &d, &second).await.unwrap();
    assert_eq!(
        last_report(&db.app, &d, &[8; 32]).await.unwrap(),
        Some(second)
    );
    let broken = ReportRow {
        pos: 3,
        previous: None,
        first_seq: 5,
        ..first
    };
    assert!(insert_report(&db.sequencer, &d, &broken).await.is_err());
    insert_profile(
        &db.sequencer,
        &d,
        3,
        &[6; 32],
        &[2; 16],
        &[0xa1, 0x01, 0x02],
    )
    .await
    .unwrap();
    assert_eq!(
        profile(&db.app, &d, &[6; 32]).await.unwrap(),
        Some(vec![0xa1, 0x01, 0x02])
    );
    assert_eq!(profile(&db.app, &d, &[7; 32]).await.unwrap(), None);
}

// OP-150 m.3 (a), T24, §9.9.3 k.6: status lists are published with the position they reflect;
// a family is revoked once and stays
#[tokio::test]
async fn status_lists_and_families() {
    let db = fresh().await.unwrap();
    let d = domain(&db, TENANT, 7).await;
    let uri = "https://access.example/status/1";
    for seq in 0..2 {
        let p = Publication {
            uri: String::from(uri),
            seq,
            applied_pos: seq + 1,
            iat_ms: 2_000,
            entries: 8,
            token: vec![0xd2],
            excerpt: None,
        };
        assert!(publish(&db.sequencer, &d, &p).await.unwrap());
    }
    assert_eq!(latest(&db.app, &d, uri).await.unwrap().unwrap().seq, 1);
    let f = Family {
        family: [3; 16],
        client_id: String::from("cli_x"),
        holder: [4; 16],
        root_exercise: [5; 32],
        status: Some((String::from(uri), 2)),
        revoked_pos: None,
    };
    assert!(open_family(&db.sequencer, &d, &f).await.unwrap());
    let twin = Family {
        family: [6; 16],
        ..f.clone()
    };
    assert!(open_family(&db.sequencer, &d, &twin).await.is_err());
    assert!(revoke_family(&db.sequencer, &d, &[3; 16], 3).await.unwrap());
    assert!(!revoke_family(&db.sequencer, &d, &[3; 16], 3).await.unwrap());
    assert_eq!(
        family(&db.app, &d, &[3; 16])
            .await
            .unwrap()
            .unwrap()
            .revoked_pos,
        Some(3)
    );
    assert!(
        as_owner(
            &db,
            &d,
            "UPDATE access.projection_family SET client_id = 'cli_y'"
        )
        .await
        .is_some()
    );
    assert!(
        as_owner(&db, &d, "DELETE FROM access.projection_family")
            .await
            .is_some()
    );
}
