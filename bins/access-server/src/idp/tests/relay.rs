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

/// A message to a fresh account of the realm, recorded as undeliverable for `reason`.
async fn undelivered(w: &World, at: (TenantId, RealmId), reason: &str) -> EventId {
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
    let who = format!("{}@example.com", reason.replace('_', "-"));
    let s = create(
        &pg,
        &realm,
        &[Identifier::new(IdentifierKind::Email, &who).unwrap()],
        &ADMIN,
    )
    .await
    .unwrap();
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
