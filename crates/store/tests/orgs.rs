//! Organizations, memberships, invitations and domain claims on a real PostgreSQL (TN-5, TN-89,
//! TN-90, TN-91, OP-73, OP-153 m.3 (o), (p)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::orgs::{NewInvitation, Source, last_owner};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};

async fn realm(db: &TestDb) -> (TenantId, RealmId) {
    let t = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = DomainId::from_bytes([3; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [3; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *t.as_bytes(), &g, &[])
        .await
        .unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, t).await.unwrap();
    let r = create_realm(&mut tx, &d, "acme", "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (t, r)
}

async fn subject(tx: &mut TenantTx) -> [u8; 16] {
    tx.insert_subject("active", "realm-kek:1", &[9; 40])
        .await
        .unwrap()
}

// TN-91, OP-153 m.3 (p)
#[tokio::test]
async fn the_last_owner_cannot_be_removed_on_any_path() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let alice = subject(&mut tx).await;
    let bob = subject(&mut tx).await;
    let org = tx.insert_org([1; 16], "Acme", &[2; 32]).await.unwrap();
    tx.insert_membership(org, alice, Source::Invite, true, None)
        .await
        .unwrap();
    tx.insert_membership(org, bob, Source::Scim, false, Some(("member", 1)))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    for by in ["remove", "scim", "sweep", "delete"] {
        let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
        let e = tx.end_membership(org, alice, by).await.unwrap_err();
        assert!(last_owner(&e), "{by}: {e}");
        tx.rollback().await.unwrap();
    }
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let e = tx.end_memberships_of(alice, "delete").await.unwrap_err();
    assert!(last_owner(&e), "{e}");
    tx.rollback().await.unwrap();
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let e = tx.drop_ownership(org, alice).await.unwrap_err();
    assert!(last_owner(&e), "{e}");
    tx.rollback().await.unwrap();

    // TN-91
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let carol = subject(&mut tx).await;
    tx.insert_membership(org, carol, Source::Invite, true, None)
        .await
        .unwrap();
    assert!(tx.end_membership(org, alice, "leave").await.unwrap());
    assert!(tx.end_membership(org, bob, "scim").await.unwrap());
    let left = tx.memberships(org).await.unwrap();
    assert_eq!(left.len(), 1);
    assert!(left[0].owner && left[0].subject == carol);
    tx.commit().await.unwrap();

    // OP-73
    let deleted = sqlx::query("DELETE FROM access.org_memberships")
        .execute(&db.owner)
        .await;
    assert!(deleted.is_err());
}

fn invitation(org: [u8; 16], token: &[u8; 32], ttl_s: i64) -> NewInvitation<'_> {
    NewInvitation {
        org,
        token_hash: token,
        code_hash: &[5; 32],
        invitee_index: &[6; 32],
        invitee_domain: "example.com",
        inviter: [7; 16],
        role: ("member", 1),
        exercise: None,
        ttl_s,
    }
}

// TN-89, OP-153 m.3 (o), HL-39
#[tokio::test]
async fn an_invitation_is_accepted_once_and_a_click_consumes_nothing() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let alice = subject(&mut tx).await;
    let org = tx.insert_org([1; 16], "Acme", &[2; 32]).await.unwrap();
    let token = [4; 32];
    let id = tx
        .insert_invitation(&invitation(org, &token, 7 * 86_400))
        .await
        .unwrap();
    tx.count_scanner_click(id).await.unwrap();
    tx.count_scanner_click(id).await.unwrap();
    let found = tx.invitation_by_token(&token).await.unwrap().unwrap();
    assert!(found.open);
    assert_eq!(found.scanner_clicks, 2);
    assert_eq!(found.role, ("member".to_owned(), 1));
    assert_eq!(tx.invitations_since(org, 3_600).await.unwrap(), 1);
    assert!(tx.accept_invitation(id, alice).await.unwrap());
    assert!(!tx.accept_invitation(id, alice).await.unwrap());
    assert!(!tx.revoke_invitation(id).await.unwrap());
    assert!(!tx.invitation_by_token(&token).await.unwrap().unwrap().open);
    tx.commit().await.unwrap();

    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let e = tx
        .insert_invitation(&invitation(org, &[8; 32], 31 * 86_400))
        .await
        .unwrap_err();
    assert!(e.integrity(), "{e}");
}

// TN-90, OP-153 m.3 (o)
#[tokio::test]
async fn domain_claims_verify_lapse_and_show_contest() {
    let db = fresh().await.unwrap();
    let (t, r) = realm(&db).await;
    let mut tx = TenantTx::begin(&db.app, t, r).await.unwrap();
    let acme = tx.insert_org([1; 16], "Acme", &[2; 32]).await.unwrap();
    let other = tx.insert_org([9; 16], "Other", &[3; 32]).await.unwrap();
    let claim = tx
        .insert_domain_claim(acme, "acme.example", "dns_txt", &[1; 32])
        .await
        .unwrap();
    assert!(!tx.set_autojoin(claim, true).await.unwrap());
    assert!(
        tx.verify_domain(claim, 90 * 86_400, &[1; 32], &[2; 32])
            .await
            .unwrap()
    );
    assert!(tx.set_autojoin(claim, true).await.unwrap());
    assert!(!tx.watch_domain(claim, &[1; 32], &[2; 32]).await.unwrap());
    assert!(tx.watch_domain(claim, &[9; 32], &[2; 32]).await.unwrap());
    assert_eq!(
        tx.lapse_domains(72 * 3_600).await.unwrap(),
        Vec::<[u8; 16]>::new()
    );
    assert_eq!(tx.lapse_domains(0).await.unwrap(), vec![claim]);
    let rows = tx.domain_claims("acme.example").await.unwrap();
    assert!(!rows[0].verified && !rows[0].autojoin);

    tx.insert_domain_claim(other, "acme.example", "https", &[2; 32])
        .await
        .unwrap();
    let orgs: std::collections::BTreeSet<_> = tx
        .domain_claims("acme.example")
        .await
        .unwrap()
        .into_iter()
        .map(|d| d.org)
        .collect();
    assert_eq!(orgs.len(), 2);
    assert!(tx.release_domain(claim).await.unwrap());
    assert_eq!(tx.domain_claims("acme.example").await.unwrap().len(), 1);
    tx.commit().await.unwrap();
}
