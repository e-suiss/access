//! TN-135, TN-136, MD-14, EI-25, OP-73: inline hook and webhook registrations are written only
//! against a committed ALLOW of their own `idp.*` action; deliveries and their log are never
//! deleted and the log is never rewritten.

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
use access_store::events::SealedKey;
use access_store::extensions::{
    Attempt, HookRow, WebhookDelivery, WebhookKeyRow, WebhookRow, due_webhooks, insert_hook,
    insert_webhook, live_hook, live_webhooks, retire_hook, retire_webhook, update_webhook, webhook,
    webhook_keys,
};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{Decision, bind, create_settings};
use access_store::scope::DomainId;
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

async fn realm(db: &TestDb, t: TenantId, d: &DomainId, slug: &str) -> RealmId {
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, d, slug, "pool-default")
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

fn sealed(seed: u8) -> SealedKey {
    SealedKey {
        kek_id: String::from("kek-1"),
        wrapped_dek: vec![seed; 40],
        nonce: [seed; 12],
        ciphertext: vec![seed; 48],
    }
}

fn hook(seed: u8, point: &str) -> HookRow {
    HookRow {
        id: [seed; 16],
        point: String::from(point),
        url: String::from("https://hooks.shop.example/access"),
        on_no_answer: String::from("refuse"),
        disclose: Vec::new(),
        signing: String::from("ed25519"),
        key: sealed(seed),
        public_key: Some([seed; 32]),
        active: true,
    }
}

fn key(seed: u8) -> WebhookKeyRow {
    WebhookKeyRow {
        id: [seed; 16],
        signing: String::from("ed25519"),
        key: sealed(seed),
        public_key: Some([seed; 32]),
        not_after_ms: None,
    }
}

// TN-135, EI-25, MD-14: a hook is written only against idp.hook.register, one live hook per call
// point, retired against idp.hook.retire, and a registration never changes
#[tokio::test]
async fn tn_135_hooks_are_bound_realm_configuration() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 61, 5).await;
    let r = realm(&db, t, &d, "hooks").await;

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 1, &[1; 16], "idp.client.register"))
        .await
        .unwrap()
        .unwrap();
    assert!(
        insert_hook(&mut tx, &b, &hook(1, "post_login"))
            .await
            .is_err()
    );

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.hook.register"))
        .await
        .unwrap()
        .unwrap();
    insert_hook(&mut tx, &b, &hook(1, "post_login"))
        .await
        .unwrap();
    assert!(
        insert_hook(&mut tx, &b, &hook(2, "post_login"))
            .await
            .is_err()
    );
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.hook.register"))
        .await
        .unwrap()
        .unwrap();
    insert_hook(&mut tx, &b, &hook(1, "post_login"))
        .await
        .unwrap();
    let mut continue_on_login = hook(3, "pre_registration");
    continue_on_login.on_no_answer = String::from("continue_without_claims");
    assert!(
        insert_hook(&mut tx, &b, &continue_on_login).await.is_err(),
        "only token_issuance may continue without an answer"
    );
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.hook.register"))
        .await
        .unwrap()
        .unwrap();
    insert_hook(&mut tx, &b, &hook(1, "post_login"))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(
        live_hook(&mut tx, "post_login").await.unwrap(),
        Some(hook(1, "post_login"))
    );
    assert!(
        tx.raw_rows("UPDATE access.idp_hooks SET url = 'https://other.example/'")
            .await
            .is_err()
    );
    let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert!(
        tx.raw_rows("DELETE FROM access.idp_hooks").await.is_err(),
        "OP-73: no physical delete"
    );

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 3, &[3; 16], "idp.hook.retire"))
        .await
        .unwrap()
        .unwrap();
    assert!(retire_hook(&mut tx, &b, &[1; 16]).await.unwrap());
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(live_hook(&mut tx, "post_login").await.unwrap(), None);
}

// TN-136, EI-25: a webhook is registered, updated with a key rotation that keeps the old key for
// its overlap, and retired, each against its own idp.webhook.* ALLOW
#[tokio::test]
async fn tn_136_webhooks_are_bound_and_rotate_with_overlap() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 71, 4).await;
    let r = realm(&db, t, &d, "webhooks").await;
    let w = WebhookRow {
        realm: *r.as_bytes(),
        id: [7; 16],
        url: String::from("https://sync.shop.example/access"),
        events: vec![String::from("account.created")],
        signing: String::from("ed25519"),
        active: true,
    };

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 1, &[1; 16], "idp.hook.register"))
        .await
        .unwrap()
        .unwrap();
    assert!(insert_webhook(&mut tx, &b, &w, &key(1)).await.is_err());

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 2, &[2; 16], "idp.webhook.register"))
        .await
        .unwrap()
        .unwrap();
    insert_webhook(&mut tx, &b, &w, &key(1)).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let now = access_store::authority::server_time(&db.app).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 3, &[3; 16], "idp.webhook.update"))
        .await
        .unwrap()
        .unwrap();
    let mut changed = w.clone();
    changed.events.push(String::from("session.revoked"));
    let until = now + 86_400_000;
    assert!(
        update_webhook(&mut tx, &b, &changed, Some((&key(2), until)))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    assert_eq!(
        webhook(&mut tx, &w.id).await.unwrap(),
        Some(changed.clone())
    );
    let keys = webhook_keys(&mut tx, &w.id, now).await.unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0].id, [2; 16]);
    assert_eq!(keys[0].not_after_ms, None);
    assert!(keys[1].not_after_ms.is_some_and(|n| n.abs_diff(until) < 2));
    let later = webhook_keys(&mut tx, &w.id, until + 1).await.unwrap();
    assert_eq!(later.len(), 1, "the old key ends with its overlap");
    assert!(
        tx.raw_rows("UPDATE access.idp_webhooks SET url = 'https://x.example/'")
            .await
            .is_err()
    );

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 4, &[4; 16], "idp.webhook.retire"))
        .await
        .unwrap()
        .unwrap();
    assert!(retire_webhook(&mut tx, &b, &w.id).await.unwrap());
    tx.commit().await.unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    assert!(live_webhooks(&mut tx).await.unwrap().is_empty());
}

// TN-136, OP-73, OP-17: a delivery is queued once per event, each attempt is logged with status
// and latency and no body, the log is never rewritten and nothing is deleted
#[tokio::test]
async fn tn_136_deliveries_and_their_log_are_kept() {
    let db = fresh().await.unwrap();
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = domain(&db, t, 81, 1).await;
    let r = realm(&db, t, &d, "deliveries").await;
    let w = WebhookRow {
        realm: *r.as_bytes(),
        id: [8; 16],
        url: String::from("https://sync.shop.example/access"),
        events: vec![String::from("account.created")],
        signing: String::from("hmac"),
        active: true,
    };
    let mut k = key(1);
    k.signing = String::from("hmac");
    k.public_key = None;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let b = bind(&mut tx, &decision(&d, 1, &[1; 16], "idp.webhook.register"))
        .await
        .unwrap()
        .unwrap();
    insert_webhook(&mut tx, &b, &w, &k).await.unwrap();
    let delivery = WebhookDelivery {
        realm: *r.as_bytes(),
        webhook: w.id,
        event_id: String::from("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"),
        event_type: String::from("urn:suiss:access:event:account.created"),
        payload: b"{}".to_vec(),
        occurred_ms: 5,
        queued_ms: 0,
        attempts: 0,
        state: String::from("pending"),
    };
    assert!(tx.enqueue_webhook(&delivery, 10).await.unwrap());
    assert!(!tx.enqueue_webhook(&delivery, 10).await.unwrap());
    tx.commit().await.unwrap();

    let due = due_webhooks(&db.reader, 10, 10).await.unwrap();
    assert_eq!(due.len(), 1);
    assert!(due_webhooks(&db.reader, 9, 10).await.unwrap().is_empty());

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let retry = Attempt {
        outcome: "retry",
        status: Some(503),
        latency_ms: Some(42),
        reason: Some("status"),
        retry_at_ms: Some(60_010),
    };
    assert!(
        tx.record_webhook_attempt(&w.id, &delivery.event_id, &retry)
            .await
            .unwrap()
    );
    let done = Attempt {
        outcome: "delivered",
        status: Some(204),
        latency_ms: Some(7),
        reason: None,
        retry_at_ms: None,
    };
    assert!(
        tx.record_webhook_attempt(&w.id, &delivery.event_id, &done)
            .await
            .unwrap()
    );
    assert!(
        !tx.record_webhook_attempt(&w.id, &delivery.event_id, &done)
            .await
            .unwrap(),
        "a final delivery takes no further attempt"
    );
    let row = tx
        .webhook_delivery(&w.id, &delivery.event_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!((row.state.as_str(), row.attempts), ("delivered", 2));
    assert_eq!(
        tx.webhook_attempts(&w.id, &delivery.event_id)
            .await
            .unwrap(),
        vec![
            (String::from("retry"), Some(503), Some(42)),
            (String::from("delivered"), Some(204), Some(7)),
        ]
    );
    tx.commit().await.unwrap();

    for sql in [
        "UPDATE access.idp_webhook_attempts SET status = 200",
        "DELETE FROM access.idp_webhook_attempts",
        "DELETE FROM access.idp_webhook_deliveries",
        "DELETE FROM access.idp_webhooks",
        "DELETE FROM access.idp_webhook_keys",
    ] {
        let tx = TenantTx::begin(&db.app, t, r).await.unwrap();
        assert!(tx.raw_rows(sql).await.is_err(), "{sql}");
    }
}
