//! Organizations through commit against real PostgreSQL and the authority plane (TN-5, TN-91,
//! OP-153 m.3 (b), (p)): `idp.org.create` binds the organization to its Party with its founder
//! as first owner, and `idp.org.member_remove` never leaves it without an owner.

use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_admin::app::rest::{Op, compile};
use access_identity_admin::domain::Invalid;
use access_internal_api::instances::{RegistrationVerdict, SelfSigned};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{ActorKind, Payload, Root};
use access_store::orgs::Source;
use serde_json::json;

use super::*;

const ORG: [u8; 16] = [0x0a; 16];
const ORG_KEY: u8 = 0x3a;

/// The `party_register` of organization `party` its founder's client signs with the one-time
/// key `seed` (OP-153 m.3 (b)).
fn org_register(d: Digest, party: [u8; 16], founder: Id, seed: u8) -> SelfSigned {
    let payload = Payload::PartyRegister {
        party: Id(party),
        root: Root::Sole(founder),
        actor_kind: ActorKind::Organization,
    };
    let nonce = register_nonce(&challenge_of(seed));
    SelfSigned {
        ais: self_signed(d, &nonce, &payload, Id(party), seed),
        nonce,
        validity: Window {
            from: 0,
            until: HOUR,
        },
    }
}

async fn register_org(
    w: &World,
    at: (TenantId, RealmId),
    d: Digest,
    founder: [u8; 16],
    party: [u8; 16],
    seed: u8,
) -> Result<bool, AdminError> {
    w.admin()
        .register_organization(
            at,
            founder,
            Id(party),
            public(seed),
            org_register(d, party, ROOT, seed),
        )
        .await
}

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
    assert!(
        !register_org(&w, (tenant, realm), d, founder, ORG, ORG_KEY)
            .await
            .unwrap()
    );
    (w, (tenant, realm), d, founder)
}

// OP-153 m.3 (b), m.10 (e), C6, Ek B 4082, 3599
#[tokio::test]
async fn an_organization_party_is_self_registered_and_never_gets_an_instance() {
    let (w, at, d, founder) = ready("org-party").await;
    assert_eq!(
        Instances::party(&w.plane, d, Id(ORG)).await.unwrap(),
        Some(access_identity_admin::ports::PartyKind {
            actor_kind: ActorKind::Organization,
            ended: false,
        })
    );
    // C6: the organization's Party has no Instance, whatever key asks
    let mut r = registration(d, device(), Id(ORG), ORG_KEY, false);
    r.register = None;
    assert_eq!(
        Instances::register(&w.plane, r).await.unwrap(),
        RegistrationVerdict::Refused {
            code: String::from("denied")
        }
    );
    // OP-153 m.10 (e): a Party that is not an organization does not become one
    let create = |party: [u8; 16]| {
        compile(
            Op::CreateOrganization,
            None,
            &json!({ "party": b64url_encode(&party), "display_name": "Acme" }),
            &w.ids,
        )
        .unwrap()
    };
    assert_eq!(
        refused(&w, &as_founder(at, d, create(ROOT.0), 1, founder)).await,
        Invalid::NotOrganization
    );
    assert_eq!(
        refused(&w, &as_founder(at, d, create([0x0b; 16]), 2, founder)).await,
        Invalid::NotOrganization
    );
    // OP-153 m.3 (o), HL-41: a founder creates at most five organizations a day
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    for i in 0..5u8 {
        let org = t
            .insert_org([0x40 + i; 16], "Acme", &[i; 32])
            .await
            .unwrap();
        t.insert_membership(org, founder, Source::Founder, true, None)
            .await
            .unwrap();
    }
    t.commit().await.unwrap();
    assert_eq!(
        refused(&w, &as_founder(at, d, create(ORG), 3, founder)).await,
        Invalid::OrgLimit
    );
    assert!(matches!(
        register_org(&w, at, d, founder, [0x0c; 16], ORG_KEY + 1).await,
        Err(AdminError::Invalid(Invalid::OrgLimit))
    ));
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

/// Waits until the realm's identity outbox holds `n` events of `kind` (OP-153 m.4).
async fn realm_events(w: &World, realm: RealmId, kind: &str, n: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let seen = access_store::identity::poll(
            &w.db.reader,
            access_store::identity::Cursor::default(),
            1000,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.realm == realm && e.kind == kind)
        .count();
        if seen >= n {
            assert_eq!(seen, n, "{kind}");
            return;
        }
        assert!(std::time::Instant::now() < deadline, "{seen} of {n} {kind}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn refused(w: &World, p: &Proposal) -> Invalid {
    match w.admin().prepare(p).await {
        Err(AdminError::Invalid(i)) => i,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("prepared"),
    }
}

// TN-5, TN-3, OP-153 m.3 (b), TN-91, OP-153 m.3 (p), OP-153 m.4, Ek B 3598, 3618, 4077
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
        w.admin().prepare(&operator).await,
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
    // OP-153 m.4, OP-149 m.4
    realm_events(&w, at.1, "event.organization.created", 1).await;
    realm_events(&w, at.1, "event.membership.added", 1).await;
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
    realm_events(&w, at.1, "event.membership.removed", 1).await;
    assert_eq!(
        refused(&w, &as_founder(at, d, remove(bob), 6, founder)).await,
        Invalid::NoMember
    );
}
