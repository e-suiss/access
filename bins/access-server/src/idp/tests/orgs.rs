//! Organizations through commit against real PostgreSQL and the authority plane (TN-5, TN-91,
//! OP-153 m.3 (b), (p)): `idp.org.create` binds the organization to its Party with its founder
//! as first owner, and `idp.org.member_remove` never leaves it without an owner.

use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_admin::app::rest::{Op, compile};
use access_identity_admin::domain::Invalid;
use access_kernel::json::b64url_encode;
use access_store::orgs::Source;
use serde_json::json;

use super::*;

const ORG: [u8; 16] = [0x0a; 16];

async fn ready(slug: &str) -> (World, (TenantId, RealmId), Digest, [u8; 16]) {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm(slug).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let founder = t.insert_subject("active", "kek-1", &[1; 40]).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &founder, &ROOT.0)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    (w, (tenant, realm), d, founder)
}

fn as_founder(
    at: (TenantId, RealmId),
    d: Digest,
    change: Change,
    nonce: u8,
    founder: [u8; 16],
) -> Proposal {
    let mut p = proposal(at, change, nonce, idp_anchor(d), 1);
    p.subject = Some(founder);
    p
}

async fn refused(w: &World, p: &Proposal) -> Invalid {
    match w.admin().prepare(p).await {
        Err(AdminError::Invalid(i)) => i,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("prepared"),
    }
}

// TN-5, TN-3, OP-153 m.3 (b), TN-91, OP-153 m.3 (p), Ek B 3598, 3618, 4077
#[tokio::test]
async fn an_organization_is_created_through_commit_and_keeps_its_last_owner() {
    let (w, at, d, founder) = ready("orgs").await;
    let create = compile(
        Op::CreateOrganization,
        None,
        &json!({ "party": b64url_encode(&ORG), "display_name": "Acme" }),
        &w.ids,
    )
    .unwrap();
    let mut operator = proposal(at, create.clone(), 1, idp_anchor(d), 1);
    operator.subject = None;
    assert!(matches!(
        exercise(&w, &operator, ROOT_KEY).await,
        Err(AdminError::Refused(_))
    ));
    written(
        &exercise(&w, &as_founder(at, d, create.clone(), 2, founder), ROOT_KEY)
            .await
            .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let org = t.org_by_party(ORG).await.unwrap().unwrap();
    assert_eq!(org.display_name, "Acme");
    assert!(!org.hrd, "TN-98: home realm discovery is off by default");
    let members = t.memberships(org.id).await.unwrap();
    assert_eq!(members.len(), 1);
    assert!(members[0].owner && members[0].source == Source::Founder);
    let bob = t.insert_subject("active", "kek-1", &[2; 40]).await.unwrap();
    t.insert_membership(org.id, bob, Source::Invite, false, Some(("member", 1)))
        .await
        .unwrap();
    t.commit().await.unwrap();

    assert_eq!(
        refused(&w, &as_founder(at, d, create, 3, founder)).await,
        Invalid::OrgExists
    );

    let remove = |subject: [u8; 16]| {
        compile(
            Op::RemoveOrganizationMember,
            Some(&b64url_encode(&ORG)),
            &json!({ "account_id": w.ids.encode(SUBJECT_PREFIX, subject).unwrap() }),
            &w.ids,
        )
        .unwrap()
    };
    // TN-91
    assert_eq!(
        refused(&w, &as_founder(at, d, remove(founder), 4, founder)).await,
        Invalid::LastOwner
    );
    written(
        &exercise(&w, &as_founder(at, d, remove(bob), 5, founder), ROOT_KEY)
            .await
            .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert_eq!(t.memberships(org.id).await.unwrap().len(), 1);
    t.commit().await.unwrap();
    assert_eq!(
        refused(&w, &as_founder(at, d, remove(bob), 6, founder)).await,
        Invalid::NoMember
    );
}
