//! Break-glass accounts, uses and reviews through commit against real PostgreSQL and the
//! authority plane (OP-157 m.3 (h), INV-28, §12.3.8): the mark is an `idp.org.*` Exercise that
//! carries no authority, a use's notice reaches its subject whatever the realm's notice setting,
//! and only another Party reviews a use.

use access_identity_admin::app::rest::{Kind as ReadKind, Op, compile};
use access_kernel::json::b64url_encode;
use access_store::breakglass::{BreakglassUse, ReviewState};
use access_store::identity::Cursor;
use access_store::orgs::Source;
use serde_json::json;

use super::orgs::{ORG, as_founder, create_org, ready};
use super::*;

fn mark(w: &World, member: [u8; 16], on: bool) -> Change {
    if on {
        compile(
            Op::MarkBreakglassAccount,
            None,
            &json!({ "organization": b64url_encode(&ORG), "member": b64url_encode(&member) }),
            &w.ids,
        )
        .unwrap()
    } else {
        compile(
            Op::ClearBreakglassAccount,
            Some(&b64url_encode(&member)),
            &json!({ "organization": b64url_encode(&ORG) }),
            &w.ids,
        )
        .unwrap()
    }
}

fn review(w: &World, exercise: [u8; 32], classification: &str) -> Change {
    compile(
        Op::ReviewBreakglassUse,
        Some(&b64url_encode(&exercise)),
        &json!({ "classification": classification }),
        &w.ids,
    )
    .unwrap()
}

async fn audited(w: &World, at: (TenantId, RealmId)) -> Vec<String> {
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let rows = t.audit_page(None, 1_000).await.unwrap();
    t.commit().await.unwrap();
    rows.into_iter().map(|r| r.event_type).collect()
}

fn used(exercise: [u8; 32], actor: [u8; 16]) -> BreakglassUse {
    BreakglassUse {
        exercise,
        drill: false,
        grant: [3; 16],
        actor,
        subject: Some(ROOT.0),
        used_at_ms: 1_000,
        due_at_ms: 1_000 + 72 * 3_600_000,
    }
}

// OP-157 m.3 (h), INV-28, §12.3.8 (4), Ek B 5442, 5537, 5653
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one realm through its break-glass admin rules"
)]
async fn a_mark_and_a_review_are_committed_exercises_that_grant_nothing() {
    let (w, at, d, founder) = Box::pin(ready("bg-admin")).await;
    let org = create_org(&w, at, d, founder).await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let alice = t.insert_subject("active", "kek-1", &[2; 40]).await.unwrap();
    t.insert_membership(org, alice, Source::Invite, false, None)
        .await
        .unwrap();
    t.commit().await.unwrap();

    written(
        &exercise(
            &w,
            &as_founder(at, d, mark(&w, alice, true), 10, founder),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(t.is_breakglass_account(&alice).await.unwrap());
    t.commit().await.unwrap();
    assert!(
        audited(&w, at)
            .await
            .iter()
            .any(|e| e == "breakglass.account_marked")
    );
    assert!(matches!(
        w.admin()
            .prepare(&as_founder(at, d, mark(&w, alice, true), 11, founder))
            .await,
        Err(AdminError::Conflict)
    ));
    let accounts = w
        .admin()
        .read(at.0, at.1, ReadKind::BreakglassAccounts, None, None, 10)
        .await
        .unwrap();
    assert_eq!(accounts.items.len(), 1);
    assert_eq!(
        accounts.items[0].0["account_id"],
        w.ids
            .encode(access_identity_account::app::SUBJECT_PREFIX, alice)
            .unwrap()
    );
    // INV-28
    assert!(accounts.items[0].0.get("grant").is_none());

    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        t.record_breakglass_use(&used([7; 32], [0x44; 16]))
            .await
            .unwrap()
    );
    assert!(
        t.record_breakglass_use(&used([8; 32], ROOT.0))
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    written(
        &exercise(
            &w,
            &as_founder(at, d, review(&w, [7; 32], "emergency"), 12, founder),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    // §12.3.8
    assert!(matches!(
        exercise(
            &w,
            &as_founder(at, d, review(&w, [8; 32], "drill"), 13, founder),
            ROOT_KEY
        )
        .await,
        Err(AdminError::Conflict)
    ));
    assert!(matches!(
        w.admin()
            .prepare(&as_founder(
                at,
                d,
                review(&w, [7; 32], "misuse"),
                14,
                founder
            ))
            .await,
        Err(AdminError::Conflict)
    ));
    let reviews = w
        .admin()
        .read(at.0, at.1, ReadKind::BreakglassReviews, None, None, 10)
        .await
        .unwrap();
    let seven = reviews
        .items
        .iter()
        .find(|(v, _)| v["exercise"] == b64url_encode(&[7; 32]))
        .unwrap();
    assert_eq!(seven.0["state"], ReviewState::Reviewed.name());
    assert_eq!(seven.0["classification"], "emergency");
    assert_eq!(seven.0["reviewer"], b64url_encode(&ROOT.0));
    assert!(
        audited(&w, at)
            .await
            .iter()
            .any(|e| e == "breakglass.reviewed")
    );

    written(
        &exercise(
            &w,
            &as_founder(at, d, mark(&w, alice, false), 15, founder),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(!t.is_breakglass_account(&alice).await.unwrap());
    t.commit().await.unwrap();
}

fn breakglass_used(d: Digest, subject: [u8; 16]) -> access_internal_api::events::Event {
    use access_internal_api::events::{Detail, Event, Kind, Source, Subject};
    Event {
        kind: Kind::BreakglassUsed,
        domain: d,
        source: Source::Exercise(Digest([0x5e; 32])),
        subject: Subject::Party(Id(subject)),
        at: 1_800_000_000_000,
        detail: Detail::Breakglass {
            grant: Id([3; 16]),
            actor: Id(ORG),
            approvals: 2,
            until: 1_800_014_400_000,
            drill: false,
        },
    }
}

// TN-71, OP-157 m.3 (h), (aa), §12.3.8 (4), Ek B 5539, 5537
#[tokio::test]
async fn a_use_reaches_its_subject_whatever_the_notice_setting_and_falls_overdue() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("bg-notice").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let at = (tenant, realm);
    let owner = super::relay::account(&w, at, "owner@bg.example").await;
    let subject = super::relay::account(&w, at, "subject@bg.example").await;
    let party = access_crypto::random::bytes::<16>().unwrap();
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &subject, &party)
            .await
            .unwrap()
    );
    let org = t.insert_org(ORG, "Acme Security", &[4; 32]).await.unwrap();
    t.insert_membership(org, owner, Source::Founder, true, None)
        .await
        .unwrap();
    let member = t.insert_subject("active", "kek-1", &[2; 40]).await.unwrap();
    t.insert_membership(org, member, Source::Invite, false, None)
        .await
        .unwrap();
    t.commit().await.unwrap();
    access_store::testing::mark_breakglass(&w.db, member)
        .await
        .unwrap();
    let off = compile(
        Op::PutSecurityNotices,
        None,
        &json!({ "enabled": false }),
        &w.ids,
    )
    .unwrap();
    written(
        &exercise(&w, &proposal(at, off, 20, idp_anchor(d), 1), ROOT_KEY)
            .await
            .unwrap(),
    );
    super::relay::authority_event(&w, at.0, d, &breakglass_used(d, party)).await;
    let pools = crate::relay::NoticePools {
        app: w.db.app.clone(),
        router: w.db.router.clone(),
        reader: w.db.reader.clone(),
    };
    assert_eq!(
        crate::relay::notices_step(&pools, &w.vault.0, &w.ids)
            .await
            .unwrap(),
        1,
        "the notice goes out with notices closed"
    );
    assert_eq!(
        crate::relay::notices_step(&pools, &w.vault.0, &w.ids)
            .await
            .unwrap(),
        0,
        "once"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let rows = access_store::identity::poll(&w.db.reader, Cursor::default(), 1000)
            .await
            .unwrap();
        let n = |k: &str| {
            rows.iter()
                .filter(|o| o.realm == at.1 && o.kind == k)
                .count()
        };
        if n("relay.message.breakglass_used.v1") == 1
            && n("relay.message.breakglass_alarm.v1") >= 1
            && n("event.breakglass.used") == 1
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "notice, alarm and webhook"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let pending = t.breakglass_reviews().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].state, ReviewState::Pending);
    let kek = access_identity_events::adapters::RealmKek::kek(&w.vault.0, at.0, at.1).unwrap();
    let late = 1_800_000_000_000 + 72 * 3_600_000 + 1;
    assert_eq!(
        access_identity_account::app::breakglass::sweep(
            &mut t,
            (&*kek, &w.ids),
            &access_identity_account::adapters::system::SystemEntropy,
            &access_identity_account::adapters::system::SystemClock,
            "https://bg-notice.example",
            late,
        )
        .await
        .unwrap(),
        1
    );
    t.commit().await.unwrap();
    let events = audited(&w, at).await;
    assert!(events.iter().any(|e| e == "breakglass.used"), "{events:?}");
    assert!(
        events.iter().any(|e| e == "breakglass.review_overdue"),
        "{events:?}"
    );
}
