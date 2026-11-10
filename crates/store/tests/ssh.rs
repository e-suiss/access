//! OP-156 m.3 (o), OP-73: the SSH certificate authority's rows on real Postgres. CA changes and
//! server groups are written only under a committed `idp.ssh.*` ALLOW; key phases, certificates
//! and revocations only grow; nothing is updated or deleted.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_store::authority::{
    CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
use access_store::ssh::NewCertificate;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

const TTL: Duration = Duration::from_secs(10);
const INTENT: [u8; 32] = [9; 32];

async fn domain(db: &TestDb, t: TenantId, seed: u8, allows: u8) -> DomainId {
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let (lease, mut head) = acquire_lease(&db.sequencer, &d, "a", TTL).await.unwrap();
    for i in 1..=allows {
        let pos = head.pos + 1;
        let leaf = [seed.wrapping_add(i); 32];
        let next = HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        };
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, i],
            }],
            head: next.clone(),
            nonces: vec![NonceRow {
                nonce: vec![i; 16],
                actor: vec![1],
                intent_digest: INTENT,
                decision_pos: pos,
                outcome: String::from("allow"),
                render_digest: None,
                tier: None,
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&db.sequencer, &d, *t.as_bytes(), &batch)
            .await
            .unwrap();
        head = next;
    }
    d
}

async fn realm(db: &TestDb, t: TenantId, d: &DomainId) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, "acme", "pool-default")
        .await
        .unwrap();
    tx.enter_realm(r).await.unwrap();
    create_settings(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    r
}

fn decision<'a>(d: &'a DomainId, position: u64, nonce: &'a [u8], action: &'a str) -> Decision<'a> {
    Decision {
        domain: d,
        position,
        nonce,
        intent: INTENT,
        change: [5; 32],
        action,
    }
}

fn certificate(serial: u64, valid_before: u64, principals: &[String]) -> NewCertificate<'_> {
    NewCertificate {
        ca_key: [7; 32],
        serial,
        key_id: "prj",
        domain: [1; 32],
        exercise: [u8::try_from(serial % 200).unwrap(); 32],
        position: 4,
        intent: &[0xa0],
        holder: "person",
        party: [2; 16],
        host_group: "prod-web",
        principals,
        public_key: [3; 32],
        valid_after: 10,
        valid_before,
        issued_ms: 100_000,
    }
}

// OP-156 m.3 (o), OP-73, MD-14
#[tokio::test]
async fn the_ca_rows_follow_decisions_and_only_grow() {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, tenant, 31, 3).await;
    let r = realm(&db, tenant, &d).await;
    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    tx.lock_ssh_ca().await.unwrap();
    assert_eq!(tx.ssh_ca_change().await.unwrap(), None);
    assert_eq!(tx.ssh_ca_applied().await.unwrap(), 0);
    let enable = bind(&mut tx, &decision(&d, 1, &[1; 16], "idp.ssh.ca_enable"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tx.put_ssh_ca_change(&enable, "enable").await.unwrap(), 1);
    tx.put_ssh_ca_key(&[7; 32], "active", 10, 1).await.unwrap();
    tx.put_ssh_ca_key(&[8; 32], "published", 20, 1)
        .await
        .unwrap();
    tx.put_ssh_ca_key(&[7; 32], "revoked", 30, 1).await.unwrap();
    let keys = tx.ssh_ca_keys().await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(
        keys.iter().find(|k| k.public_key == [7; 32]).unwrap().phase,
        "revoked"
    );
    assert_eq!(tx.ssh_ca_applied().await.unwrap(), 1);
    let group = bind(
        &mut tx,
        &decision(&d, 2, &[2; 16], "idp.ssh.host_group_register"),
    )
    .await
    .unwrap()
    .unwrap();
    tx.put_ssh_host_group(&group, "prod-web", true, "Web servers")
        .await
        .unwrap();
    let retire = bind(
        &mut tx,
        &decision(&d, 3, &[3; 16], "idp.ssh.host_group_retire"),
    )
    .await
    .unwrap()
    .unwrap();
    tx.put_ssh_host_group(&retire, "prod-web", false, "Web servers")
        .await
        .unwrap();
    let groups = tx.ssh_host_groups().await.unwrap();
    assert_eq!(groups.len(), 1);
    assert!(!groups[0].live);
    assert_eq!(groups[0].version, 2);
    let ayse = [String::from("ayse")];
    tx.insert_ssh_certificate(&certificate(u64::MAX, 1_000, &ayse))
        .await
        .unwrap();
    tx.insert_ssh_certificate(&certificate(5, 50, &ayse))
        .await
        .unwrap();
    assert!(
        tx.revoke_ssh_certificate(&[7; 32], u64::MAX, "basis-ended", 200_000)
            .await
            .unwrap()
    );
    assert!(
        !tx.revoke_ssh_certificate(&[7; 32], u64::MAX, "ca-off", 300_000)
            .await
            .unwrap()
    );
    let live = tx.ssh_certificates(60, 10).await.unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].serial, u64::MAX);
    assert_eq!(
        live[0].revoked,
        Some((String::from("basis-ended"), 200_000))
    );
    assert_eq!(tx.ssh_krl_version().await.unwrap(), 4);
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, tenant, r).await.unwrap();
    let unbound = bind(
        &mut tx,
        &decision(&d, 2, &[2; 16], "idp.ssh.host_group_register"),
    )
    .await;
    assert!(unbound.is_err() || unbound.unwrap().is_none());
    tx.rollback().await.unwrap();

    for sql in [
        "UPDATE access.ssh_certificates SET valid_before = 1",
        "DELETE FROM access.ssh_revocations",
        "DELETE FROM access.ssh_ca_keys",
        "UPDATE access.ssh_host_groups SET description = 'x'",
        "DELETE FROM access.ssh_ca_changes",
    ] {
        assert!(sqlx::query(sql).execute(&db.owner).await.is_err(), "{sql}");
    }
}
