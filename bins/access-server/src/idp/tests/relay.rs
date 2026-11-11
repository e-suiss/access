//! `idp.relay.resend` through commit against real PostgreSQL and the authority plane (OP-156
//! m.3 (c)): an undelivered Relay message goes out again as a new outbox row citing the
//! original; a missing or shredded message is refused before anything is signed.

use std::sync::Arc;

use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::{SystemClock, SystemEntropy};
use access_identity_account::app::accounts::create;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::{Address, Body, Message, SignInMethod};
use access_identity_account::notify::notifier::OutboxNotifier;
use access_identity_account::notify::ports::Notifier as _;
use access_identity_admin::app::rest::{Op, compile};
use access_identity_admin::domain::Invalid;
use access_store::identity::Cursor;
use access_store::relay::Undelivered;
use serde_json::json;

use super::*;

const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

/// A fresh account of the realm with the e-mail address `who`.
pub(super) async fn account(w: &World, at: (TenantId, RealmId), who: &str) -> [u8; 16] {
    let kek = SoftKek::new("realm-kek", [9; 32]);
    let realm = Realm {
        tenant: at.0,
        realm: at.1,
        kek: &kek,
        ids: &w.ids,
    };
    let pg = PgAccounts::sealed(
        w.db.app.clone(),
        access_identity_account::app::vault::Vault::in_memory(
            Arc::new(SoftKek::new("realm-kek", [9; 32])),
            [9; 32],
        ),
    );
    create(
        &pg,
        &realm,
        &[Identifier::new(IdentifierKind::Email, who).unwrap()],
        &ADMIN,
    )
    .await
    .unwrap()
}

/// A message to a fresh account of the realm, recorded as undeliverable for `reason`.
async fn undelivered(w: &World, at: (TenantId, RealmId), reason: &str) -> EventId {
    let kek = SoftKek::new("realm-kek", [9; 32]);
    let realm = Realm {
        tenant: at.0,
        realm: at.1,
        kek: &kek,
        ids: &w.ids,
    };
    let who = format!("{}@example.com", reason.replace('_', "-"));
    let s = account(w, at, &who).await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let id = OutboxNotifier::new(&realm, &SystemEntropy, &SystemClock)
        .notify(
            &mut t,
            &Message {
                subject: s,
                to: Address::Email(who),
                locale: None,
                valid_since_ms: Some(1),
                body: Body::NewSignIn {
                    at_ms: 1_800_000_000_000,
                    method: SignInMethod::Passkey,
                },
            },
        )
        .await
        .unwrap();
    t.commit().await.unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let row = loop {
        let rows = access_store::identity::poll(&w.db.reader, Cursor::default(), 1000)
            .await
            .unwrap();
        if let Some(r) = rows
            .into_iter()
            .find(|r| r.kind == "relay.message.new_sign_in.v1" && r.realm == at.1)
        {
            break r;
        }
        assert!(std::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    t.relay_undelivered(&Undelivered {
        event_id: id.0,
        at: row.cursor(),
        kind: &row.kind,
        reason,
        relay_status: (reason == "rejected").then_some(422),
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    id
}

async fn refused(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
) -> Invalid {
    match w
        .admin()
        .prepare(&proposal(at, change, nonce, idp_anchor(d), 1))
        .await
    {
        Err(AdminError::Invalid(i)) => i,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("prepared"),
    }
}

// OP-156 m.3 (c), OP-73
#[tokio::test]
async fn an_undelivered_message_is_resent_through_commit() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("relay").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let at = (tenant, realm);
    let original = undelivered(&w, at, "rejected").await;
    let change = compile(
        Op::ResendRelay,
        Some(&original.to_string()),
        &json!({}),
        &w.ids,
    )
    .unwrap();
    assert_eq!(change, Change::RelayResend(original.0));
    written(
        &exercise(&w, &proposal(at, change, 1, idp_anchor(d), 1), ROOT_KEY)
            .await
            .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let again = t.relay_resends_of(original.0).await.unwrap();
    assert_eq!(again.len(), 1);
    assert_ne!(again[0], original.0, "a new CloudEvents id");
    assert_eq!(
        t.list_relay_undelivered(10).await.unwrap().len(),
        1,
        "the record stays"
    );
    t.commit().await.unwrap();

    let shredded = undelivered(&w, at, "shredded").await;
    assert_eq!(
        refused(&w, at, d, Change::RelayResend(shredded.0), 2).await,
        Invalid::RelayShredded
    );
    assert_eq!(
        refused(&w, at, d, Change::RelayResend([7; 16]), 3).await,
        Invalid::NoRelayMessage
    );
    assert!(compile(Op::ResendRelay, Some("../x"), &json!({}), &w.ids).is_err());
}

/// Commits one authority record with `event` in the governing domain's outbox.
pub(super) async fn authority_event(
    w: &World,
    tenant: TenantId,
    d: Digest,
    event: &access_internal_api::events::Event,
) {
    use access_store::authority::{
        CommitBatch, HeadRow, LogRecord, OutboxRow, acquire_lease, commit_batch,
    };
    let domain = access_store::scope::DomainId::from_bytes(d.0);
    let (lease, head) = acquire_lease(&w.db.sequencer, &domain, "t", Duration::from_secs(10))
        .await
        .unwrap();
    let pos = head.pos + 1;
    let leaf = access_crypto::random::bytes::<32>().unwrap();
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records: vec![LogRecord {
            pos,
            kind: "decision",
            recorded_at: 2,
            leaf_hash: leaf,
            envelope: vec![0xa1, 1],
        }],
        head: HeadRow {
            pos,
            epoch: lease.epoch,
            leaf_hash: leaf,
            recorded_at: 2,
            frontier: vec![leaf],
        },
        nonces: vec![],
        outbox: vec![OutboxRow {
            pos,
            idx: 0,
            event_id: access_crypto::random::bytes::<32>().unwrap(),
            event: event.to_bytes().unwrap(),
            trace_parent: None,
        }],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        beside: vec![],
        effects: vec![],
    };
    commit_batch(&w.db.sequencer, &domain, *tenant.as_bytes(), &batch)
        .await
        .unwrap();
}

/// A realm with one account bound to a fresh Party; returns the realm, its domain and the Party.
async fn notified(w: &World, slug: &str) -> ((TenantId, RealmId), Digest, [u8; 16]) {
    let (tenant, realm, d) = w.realm(slug).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let at = (tenant, realm);
    let s = account(w, at, &format!("{slug}@example.com")).await;
    let party = access_crypto::random::bytes::<16>().unwrap();
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(t.security_notices_enabled().await.unwrap(), "on by default");
    assert!(
        access_store::idp::bind_subject_party(&mut t, &s, &party)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    (at, d, party)
}

fn ended(d: Digest, party: [u8; 16]) -> access_internal_api::events::Event {
    use access_internal_api::events::{Detail, Event, Kind, Source, Subject};
    Event {
        kind: Kind::InstanceTerminated,
        domain: d,
        source: Source::Exercise(Digest([9; 32])),
        subject: Subject::Instance(Id([3; 16])),
        at: 1_800_000_000_000,
        detail: Detail::Instance { party: Id(party) },
    }
}

async fn switch(w: &World, at: (TenantId, RealmId), d: Digest, on: bool, nonce: u8) {
    let c = compile(
        Op::PutSecurityNotices,
        None,
        &json!({ "enabled": on }),
        &w.ids,
    )
    .unwrap();
    assert_eq!(c, Change::SecurityNotices(on));
    written(
        &exercise(w, &proposal(at, c, nonce, idp_anchor(d), 1), ROOT_KEY)
            .await
            .unwrap(),
    );
}

// OP-156 m.3 (c), Ek B 5294
#[tokio::test]
async fn closing_security_notices_stops_them_and_reopening_sends_them_again() {
    let w = World::new().await;
    let pools = crate::relay::NoticePools {
        app: w.db.app.clone(),
        router: w.db.router.clone(),
        reader: w.db.reader.clone(),
    };
    let (closed, cd, cparty) = notified(&w, "closed").await;
    let (reopened, rd, rparty) = notified(&w, "reopened").await;
    switch(&w, closed, cd, false, 1).await;
    switch(&w, reopened, rd, false, 1).await;
    switch(&w, reopened, rd, true, 2).await;
    let mut t = TenantTx::begin(&w.db.app, closed.0, closed.1)
        .await
        .unwrap();
    assert!(!t.security_notices_enabled().await.unwrap());
    t.commit().await.unwrap();
    authority_event(&w, closed.0, cd, &ended(cd, cparty)).await;
    authority_event(&w, reopened.0, rd, &ended(rd, rparty)).await;
    assert_eq!(
        crate::relay::notices_step(&pools, &w.vault.0, &w.ids)
            .await
            .unwrap(),
        1,
        "only the reopened realm sends"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rows = access_store::identity::poll(&w.db.reader, Cursor::default(), 1000)
            .await
            .unwrap();
        let sent = |r: RealmId| {
            rows.iter()
                .filter(|o| o.realm == r && o.kind == "relay.message.security_authority_notice.v1")
                .count()
        };
        if sent(reopened.1) == 1 {
            assert_eq!(sent(closed.1), 0, "closed: no notice");
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "reopened: the notice is sent again"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
