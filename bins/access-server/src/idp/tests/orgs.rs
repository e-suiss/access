//! Organizations through commit against real PostgreSQL and the authority plane (TN-5, TN-91,
//! OP-153 m.3 (b), (p)): `idp.org.create` binds the organization to its Party with its founder
//! as first owner, and `idp.org.member_remove` never leaves it without an owner.

use access_identity_account::app::SUBJECT_PREFIX;
use access_identity_account::domain::claims::ClaimOrder;
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

/// The realm's vault keys as the test world's realm keys hand them out.
fn vault_of(w: &World, realm: RealmId) -> access_identity_account::app::vault::Vault {
    access_identity_admin::ports::RealmKeys::vault(&w.keys, realm).unwrap()
}

/// A real account of the realm with the e-mail `email`, sealed under the realm's vault.
async fn account(w: &World, (tenant, realm): (TenantId, RealmId), email: &str) -> [u8; 16] {
    use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
    let v = vault_of(w, realm);
    let named = access_identity_account::app::Realm {
        tenant,
        realm,
        kek: &*v.kek,
        ids: &w.ids,
    };
    let db = access_identity_account::adapters::pg::PgAccounts::sealed(w.db.app.clone(), v.clone());
    let who = access_identity_account::app::Actor {
        actor: "test",
        correlation: "test",
    };
    let email = Identifier::new(IdentifierKind::Email, email).unwrap();
    let subject = access_identity_account::app::accounts::create(&db, &named, &[email], &who)
        .await
        .unwrap();
    for to in [
        access_identity_account::domain::status::AccountStatus::PendingUserAction,
        access_identity_account::domain::status::AccountStatus::Active,
    ] {
        access_identity_account::app::accounts::change_status(&db, &named, subject, to, &who)
            .await
            .unwrap();
    }
    subject
}

async fn ready(slug: &str) -> (World, (TenantId, RealmId), Digest, [u8; 16]) {
    Box::pin(ready_with(slug, None)).await
}

async fn ready_with(
    slug: &str,
    ct3_delay_s: Option<u64>,
) -> (World, (TenantId, RealmId), Digest, [u8; 16]) {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm_with(slug, ct3_delay_s).await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let founder = account(&w, (tenant, realm), "founder@acme.example").await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
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
    let (w, at, d, founder) = Box::pin(ready("org-party")).await;
    assert_eq!(
        Instances::party(&w.plane, d, Id(ORG)).await.unwrap(),
        Some(access_identity_admin::ports::PartyKind {
            actor_kind: ActorKind::Organization,
            ended: false,
        })
    );
    // C6
    let mut r = registration(d, device(), Id(ORG), ORG_KEY, false);
    r.register = None;
    assert_eq!(
        Instances::register(&w.plane, r).await.unwrap(),
        RegistrationVerdict::Refused {
            code: String::from("denied")
        }
    );
    // OP-153 m.10 (e)
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
    // OP-153 m.3 (o), HL-41
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
    let (w, at, d, founder) = Box::pin(ready("orgs")).await;
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

fn invite(w: &World, body: &serde_json::Value) -> Change {
    compile(
        Op::CreateInvitation,
        Some(&b64url_encode(&ORG)),
        body,
        &w.ids,
    )
    .unwrap()
}

async fn create_org(w: &World, at: (TenantId, RealmId), d: Digest, founder: [u8; 16]) -> [u8; 16] {
    let create = compile(
        Op::CreateOrganization,
        None,
        &json!({ "party": b64url_encode(&ORG), "display_name": "Acme" }),
        &w.ids,
    )
    .unwrap();
    written(
        &exercise(w, &as_founder(at, d, create, 0xc0, founder), ROOT_KEY)
            .await
            .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let org = t.org_by_party(ORG).await.unwrap().unwrap().id;
    t.commit().await.unwrap();
    org
}

// TN-89, OP-153 m.3 (o), HL-39, Ek B 3606, 3607, 3829
#[tokio::test]
async fn an_invitation_is_committed_mailed_limited_and_revoked() {
    let (w, at, d, founder) = Box::pin(ready("org-invite")).await;
    let org = create_org(&w, at, d, founder).await;
    let body = json!({
        "email": "Bob@ACME.example",
        "inviter_name": "Ada from Acme",
        "role": "member",
        "role_version": 1,
    });
    // TN-89
    let change = invite(&w, &body);
    assert!(!format!("{change:?}").contains("acme.example"));
    written(
        &exercise(&w, &as_founder(at, d, change, 1, founder), ROOT_KEY)
            .await
            .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let listed = t.invitations(org).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(listed[0].open && !listed[0].accepted);
    assert_eq!(listed[0].invitee_domain, "acme.example");
    assert_eq!(listed[0].role, (String::from("member"), 1));
    t.commit().await.unwrap();
    // OP-153 m.3 (o)
    realm_events(&w, at.1, "relay.message.invitation.v1", 1).await;

    // TN-89
    for bad in [
        json!({ "email": "x@acme.example", "inviter_name": "A", "role": "member", "role_version": 1, "days": 31 }),
        json!({ "email": "x@acme.example", "inviter_name": "A", "role": "member", "role_version": 0 }),
        json!({ "email": "not-an-address", "inviter_name": "A", "role": "member", "role_version": 1 }),
    ] {
        assert_eq!(
            refused(&w, &as_founder(at, d, invite(&w, &bad), 2, founder)).await,
            Invalid::Invitation
        );
    }

    let revoke = compile(
        Op::RevokeInvitation,
        Some(&b64url_encode(&ORG)),
        &json!({ "invitation_id": w.ids.encode("inv", listed[0].id).unwrap() }),
        &w.ids,
    )
    .unwrap();
    written(
        &exercise(&w, &as_founder(at, d, revoke.clone(), 3, founder), ROOT_KEY)
            .await
            .unwrap(),
    );
    assert_eq!(
        refused(&w, &as_founder(at, d, revoke, 4, founder)).await,
        Invalid::NoInvitation
    );

    // HL-39, OP-153 m.3 (o)
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    for i in 0..49u8 {
        t.insert_invitation(&access_store::orgs::NewInvitation {
            org,
            token_hash: &[i; 32],
            code_hash: &[i; 32],
            invitee_index: &[i; 32],
            invitee_domain: "acme.example",
            inviter: ROOT.0,
            role: ("member", 1),
            exercise: None,
            ttl_s: 3_600,
        })
        .await
        .unwrap();
    }
    t.commit().await.unwrap();
    assert_eq!(
        refused(&w, &as_founder(at, d, invite(&w, &body), 5, founder)).await,
        Invalid::InviteLimit
    );
}

// TN-98, §10.2.6, TN-90, OP-149 m.4, Ek B 3436, 3454, 3611
#[tokio::test]
async fn home_realm_discovery_needs_a_verified_uncontested_domain() {
    let (w, at, d, founder) = Box::pin(ready("org-hrd")).await;
    let org = create_org(&w, at, d, founder).await;
    let patch = |body: serde_json::Value| {
        compile(
            Op::PatchOrganization,
            Some(&b64url_encode(&ORG)),
            &body,
            &w.ids,
        )
        .unwrap()
    };
    assert_eq!(
        refused(
            &w,
            &as_founder(at, d, patch(json!({ "hrd": true })), 1, founder)
        )
        .await,
        Invalid::HrdUnverified
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let claim = t
        .insert_domain_claim(org, "acme.example", "dns_txt", &[1; 32])
        .await
        .unwrap();
    assert!(
        t.verify_domain(claim, 86_400, &[2; 32], &[3; 32])
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    written(
        &exercise(
            &w,
            &as_founder(
                at,
                d,
                patch(json!({ "hrd": true, "display_name": "Acme Inc" })),
                2,
                founder,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let row = t.org(org).await.unwrap().unwrap();
    assert!(row.hrd);
    assert_eq!(row.display_name, "Acme Inc");
    assert_eq!(
        t.hrd_domains(org).await.unwrap(),
        vec![String::from("acme.example")]
    );
    // TN-90
    let other = t
        .insert_org([0x0d; 16], "Not Acme", &[4; 32])
        .await
        .unwrap();
    t.insert_domain_claim(other, "acme.example", "dns_txt", &[5; 32])
        .await
        .unwrap();
    assert_eq!(t.hrd_domains(org).await.unwrap(), Vec::<String>::new());
    t.commit().await.unwrap();
    realm_events(&w, at.1, "event.organization.updated", 1).await;
    assert_eq!(
        refused(
            &w,
            &as_founder(at, d, patch(json!({ "hrd": true })), 3, founder)
        )
        .await,
        Invalid::HrdUnverified
    );
}

/// The outside world a domain verification reads, as a test sets it.
#[derive(Default)]
struct Probe {
    txt: std::sync::Mutex<Vec<String>>,
    mx: std::sync::Mutex<Vec<String>>,
    registrar: std::sync::Mutex<Option<String>>,
    down: std::sync::atomic::AtomicBool,
}

impl access_identity_admin::ports::DomainProbe for Probe {
    fn txt(&self, name: &str) -> impl Future<Output = Result<Vec<String>, Unavailable>> + Send {
        assert!(name.starts_with("_suiss-access."));
        std::future::ready(if self.down.load(std::sync::atomic::Ordering::SeqCst) {
            Err(Unavailable(String::from("down")))
        } else {
            Ok(self.txt.lock().unwrap().clone())
        })
    }

    fn mx(&self, _: &str) -> impl Future<Output = Result<Vec<String>, Unavailable>> + Send {
        std::future::ready(Ok(self.mx.lock().unwrap().clone()))
    }

    fn https(&self, _: &str) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send {
        std::future::ready(Ok(None))
    }

    fn registrar(
        &self,
        _: &str,
    ) -> impl Future<Output = Result<Option<String>, Unavailable>> + Send {
        std::future::ready(Ok(self.registrar.lock().unwrap().clone()))
    }
}

async fn watch_pass(
    w: &World,
    at: (TenantId, RealmId),
    probe: &Probe,
) -> access_identity_admin::app::domains::WatchPass {
    access_identity_admin::app::domains::DomainWatch {
        app: &w.db.app,
        probe,
    }
    .realm(at)
    .await
    .unwrap()
}

async fn claims_of(
    w: &World,
    at: (TenantId, RealmId),
    org: [u8; 16],
) -> Vec<access_store::org_authority::DomainClaim> {
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let c = t.open_domain_claims(Some(org)).await.unwrap();
    t.commit().await.unwrap();
    c
}

fn orders(events: &[access_store::identity::OutboxEvent]) -> Vec<ClaimOrder> {
    events
        .iter()
        .filter_map(|e| ClaimOrder::from_bytes(&e.payload).ok())
        .collect()
}

async fn age(w: &World, at: (TenantId, RealmId), checked_s: i64, changed_s: i64) {
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    t.age_domain_watch(checked_s, changed_s).await.unwrap();
    t.commit().await.unwrap();
}

// TN-90, TN-98, §10.2.6, OP-153 m.3 (o), (gg), Ek B 3611, 3436, 3454, 3612, 4039
#[tokio::test]
async fn a_domain_is_verified_by_its_challenge_watched_contested_and_lapsed() {
    let (w, at, d, founder) = Box::pin(ready("org-domains")).await;
    let org = create_org(&w, at, d, founder).await;
    let claim = |domain: &str| {
        compile(
            Op::ClaimOrganizationDomain,
            Some(&b64url_encode(&ORG)),
            &json!({ "domain": domain, "method": "dns_txt" }),
            &w.ids,
        )
        .unwrap()
    };
    let patch = |body: serde_json::Value| {
        compile(
            Op::PatchOrganization,
            Some(&b64url_encode(&ORG)),
            &body,
            &w.ids,
        )
        .unwrap()
    };
    let founder_does = |change: Change, nonce: u8| as_founder(at, d, change, nonce, founder);
    let challenge = match exercise(&w, &founder_does(claim("acme.example"), 1), ROOT_KEY)
        .await
        .unwrap()
    {
        Applied::Written {
            secret: Some(s), ..
        } => s.expose().to_owned(),
        other => panic!("{other:?}"),
    };
    let probe = Probe::default();
    *probe.mx.lock().unwrap() = vec![String::from("mx1.acme.example")];
    *probe.registrar.lock().unwrap() = Some(String::from("1910"));

    // TN-90
    assert_eq!(watch_pass(&w, at, &probe).await.verified, 0);
    *probe.txt.lock().unwrap() = vec![format!("suiss-access-verify={challenge}")];
    probe.down.store(true, std::sync::atomic::Ordering::SeqCst);
    let p = watch_pass(&w, at, &probe).await;
    assert_eq!((p.verified, p.unavailable), (0, 1));
    probe.down.store(false, std::sync::atomic::Ordering::SeqCst);
    *probe.txt.lock().unwrap() = vec![String::from("suiss-access-verify=someone-else")];
    assert_eq!(watch_pass(&w, at, &probe).await.verified, 0);
    assert!(claims_of(&w, at, org).await[0].verified_ms.is_none());

    *probe.txt.lock().unwrap() = vec![format!("suiss-access-verify={challenge}")];
    assert_eq!(watch_pass(&w, at, &probe).await.verified, 1);
    let c = claims_of(&w, at, org).await;
    assert!(c[0].verified_ms.is_some() && c[0].claimed);
    let issued = orders(&identity_events(&w.db, "claim.domain_verification", 1).await);
    assert!(issued.iter().any(|o| o.party() == Some(ORG) && !o.retract));

    // TN-98, Ek B 3454
    written(
        &exercise(
            &w,
            &founder_does(patch(json!({ "hrd": true })), 2),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    // TN-90, OP-153 m.1 (d), Ek B 3612, 4039
    written(
        &exercise(&w, &founder_does(claim("gmail.com"), 3), ROOT_KEY)
            .await
            .unwrap(),
    );
    let autojoin = |domain: &str| patch(json!({ "autojoin": { "domain": domain, "on": true } }));
    assert_eq!(
        refused(&w, &founder_does(autojoin("gmail.com"), 4)).await,
        Invalid::ConsumerDomain
    );
    written(
        &exercise(&w, &founder_does(autojoin("acme.example"), 5), ROOT_KEY)
            .await
            .unwrap(),
    );

    // TN-90
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let other = t
        .insert_org([0x0d; 16], "Not Acme", &[4; 32])
        .await
        .unwrap();
    t.claim_domain(other, ("acme.example", "dns_txt"), &[5; 32], &[6; 32])
        .await
        .unwrap();
    t.commit().await.unwrap();
    assert_eq!(watch_pass(&w, at, &probe).await.contested, 2);
    let mine = claims_of(&w, at, org).await;
    let acme = mine.iter().find(|c| c.domain == "acme.example").unwrap();
    assert!(acme.contested_ms.is_some() && !acme.autojoin);
    assert_eq!(
        refused(&w, &founder_does(autojoin("acme.example"), 6)).await,
        Invalid::DomainContested
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert_eq!(t.hrd_domains(org).await.unwrap(), Vec::<String>::new());
    t.commit().await.unwrap();

    // TN-90
    *probe.txt.lock().unwrap() = Vec::new();
    *probe.mx.lock().unwrap() = vec![String::from("mx.elsewhere.example")];
    age(&w, at, 2 * 86_400, 0).await;
    assert_eq!(watch_pass(&w, at, &probe).await.changed, 1);
    assert_eq!(watch_pass(&w, at, &probe).await.lapsed, 0);
    age(&w, at, 0, 73 * 3_600).await;
    assert_eq!(watch_pass(&w, at, &probe).await.lapsed, 1);
    let acme = claims_of(&w, at, org)
        .await
        .into_iter()
        .find(|c| c.domain == "acme.example")
        .unwrap();
    assert!(acme.verified_ms.is_none() && !acme.claimed);
    let issued = orders(&identity_events(&w.db, "claim.domain_verification", 2).await);
    assert!(issued.iter().any(|o| o.retract && o.party() == Some(ORG)));
}

/// A core meta-action write `payload` on `basis`, signed by the key `seed`.
fn meta_write(
    d: Digest,
    nonce: u8,
    payload: Payload,
    basis: ExerciseBasis,
    seed: u8,
) -> access_internal_api::idp::Submission {
    let intent = access_kernel::intent::IntentEnvelope {
        provenance: std::collections::BTreeMap::new(),
        action: meta::core_action(payload.action()),
        resources: vec![access_kernel::model::ResourceRef {
            namespace: String::from("access.party"),
            path: vec![String::from("p")],
            incarnation: 0,
        }],
        params: std::collections::BTreeMap::new(),
        opaque: std::collections::BTreeMap::from([(
            String::from(meta::PAYLOAD_PARAM),
            payload.digest().unwrap(),
        )]),
        recipient: None,
        purpose: None,
        context: access_kernel::intent::ContextRefs::default(),
        validity: Window {
            from: NOW,
            until: NOW + HOUR,
        },
    };
    let digest = intent_digest(&intent).unwrap();
    access_internal_api::idp::Submission {
        domain: d,
        nonce: vec![nonce; 16],
        ais: sign(&statement(d, &[nonce; 16], digest, basis), seed),
        intent,
        payload: Some(Box::new(payload)),
        basis,
        capacity: Capacity::Own,
        contributions: Vec::new(),
        pep: String::from(PEP),
        actor: None,
    }
}

/// The `member` role: reading accounts in the realm `slug`.
fn member_set(slug: &str) -> access_kernel::model::AuthoritySet {
    use access_kernel::model::{ActionSet, AuthoritySet, ResourceSelector, Structural};
    AuthoritySet {
        actions: ActionSet {
            exact: std::collections::BTreeSet::from([
                access_internal_api::idp::IdpAction::AccountRead.action_ref(),
            ]),
            prefix: std::collections::BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: String::from(access_internal_api::idp::RESOURCE_NAMESPACE),
            prefix: vec![String::from(slug)],
            kind: None,
            attrs: std::collections::BTreeMap::new(),
        }),
        params: std::collections::BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

fn role_issue(d: Digest, holder: Id, (name, version): (&str, u64)) -> Payload {
    use access_kernel::model::{CanonicalAuthority, ConstraintSet, SubjectSelector};
    let set = member_set("org-role");
    Payload::GrantIssue(access_kernel::meta::GrantContent {
        basis: access_kernel::meta::GrantBasis::Anchor(meta::object_id(
            &d,
            kind::ANCHOR,
            IDP_ANCHOR,
        )),
        holder: SubjectSelector::Party(holder),
        authority: CanonicalAuthority {
            authority: set.clone(),
            constraints: ConstraintSet {
                validity: Window {
                    from: 0,
                    until: u64::MAX / 2,
                },
                conditions: std::collections::BTreeSet::new(),
                budget: std::collections::BTreeSet::new(),
            },
            delegation: access_kernel::model::DelegationTerms::default(),
            requirements: std::collections::BTreeSet::new(),
        },
        agency: std::collections::BTreeSet::from([Capacity::Own]),
        named: Some((name.to_owned(), version, meta::authority_set_digest(&set))),
    })
}

async fn role(
    w: &World,
    at: (TenantId, RealmId),
    member: ([u8; 16], [u8; 16]),
    sub: access_internal_api::idp::Submission,
) -> Result<Applied, AdminError> {
    Box::pin(w.admin().issue_role_grant(at, member, sub)).await
}

// TN-89, TN-5, §12.3.8, OP-153 m.3 (o), (gg), Ek B 3604, 3606
#[tokio::test]
async fn an_accepted_invitations_role_is_issued_by_the_inviters_current_authority() {
    let (w, at, d, founder) = Box::pin(ready("org-role")).await;
    let org = create_org(&w, at, d, founder).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let define = Payload::AuthoritySetDefine {
        name: String::from("member"),
        authority: member_set("org-role"),
    };
    let anchor = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    assert!(matches!(
        w.admin()
            .meta(at, meta_write(d, 0x50, define, anchor, ROOT_KEY))
            .await
            .unwrap(),
        Applied::Written { .. }
    ));
    let bob = account(&w, at, "bob@acme.example").await;
    let carol = account(&w, at, "carol@acme.example").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &bob, &ALICE.0)
            .await
            .unwrap()
    );
    assert!(
        access_store::idp::bind_subject_party(&mut t, &carol, &[0x0e; 16])
            .await
            .unwrap()
    );
    t.open_member(
        (org, bob),
        Source::Invite,
        Some(("member", 1)),
        Some(ROOT.0),
        None,
    )
    .await
    .unwrap();
    t.open_member(
        (org, carol),
        Source::Invite,
        Some(("member", 1)),
        Some(ALICE.0),
        None,
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    let idp = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, IDP_ANCHOR));
    let issue = |holder: Id, role: (&str, u64), nonce: u8, seed: u8| {
        meta_write(d, nonce, role_issue(d, holder, role), idp, seed)
    };

    // TN-89 (3)
    assert!(matches!(
        role(&w, at, (ORG, bob), issue(ALICE, ("member", 1), 0x51, ALICE_KEY)).await,
        Err(AdminError::Refused(c)) if c == "inviter-only"
    ));
    // TN-89 (2)
    assert!(matches!(
        role(&w, at, (ORG, bob), issue(ALICE, ("admin", 1), 0x52, ROOT_KEY)).await,
        Err(AdminError::Refused(c)) if c == "not-the-membership-role"
    ));
    assert!(matches!(
        role(&w, at, (ORG, bob), issue(ROOT, ("member", 1), 0x53, ROOT_KEY)).await,
        Err(AdminError::Refused(c)) if c == "not-the-membership-role"
    ));
    let applied = role(
        &w,
        at,
        (ORG, bob),
        issue(ALICE, ("member", 1), 0x54, ROOT_KEY),
    )
    .await
    .unwrap();
    assert!(matches!(applied, Applied::Written { .. }), "{applied:?}");
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let m = t.member(org, bob).await.unwrap().unwrap();
    assert_eq!(m.grant_state.as_deref(), Some("issued"));
    let origin = meta::exercise_id(&d, &[0x54; 16]).unwrap();
    assert_eq!(m.grant, Some(meta::object_id(&origin, kind::GRANT, 0).0));
    t.commit().await.unwrap();

    // TN-89 (3)
    let applied = role(
        &w,
        at,
        (ORG, carol),
        issue(Id([0x0e; 16]), ("member", 1), 0x55, ALICE_KEY),
    )
    .await
    .unwrap();
    assert!(matches!(applied, Applied::NotAllowed { .. }), "{applied:?}");
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let m = t.member(org, carol).await.unwrap().unwrap();
    assert_eq!(m.grant_state.as_deref(), Some("denied"));
    assert_eq!(m.grant, None);
    t.commit().await.unwrap();
    assert!(matches!(
        role(
            &w,
            at,
            (ORG, carol),
            issue(Id([0x0e; 16]), ("member", 1), 0x56, ALICE_KEY)
        )
        .await,
        Err(AdminError::Invalid(Invalid::NoMember))
    ));
}

// TN-109, TN-90, OP-153 m.3 (o), (p), (gg), Ek B 3613, 3604
#[tokio::test]
async fn membership_claims_wait_for_the_autojoin_cooling() {
    let (w, at, d, founder) = Box::pin(ready("org-cool")).await;
    let org = create_org(&w, at, d, founder).await;
    let bob = account(&w, at, "bob@acme.example").await;
    let carol = account(&w, at, "carol@acme.example").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &bob, &ALICE.0)
            .await
            .unwrap()
    );
    assert!(
        access_store::idp::bind_subject_party(&mut t, &carol, &[0x0e; 16])
            .await
            .unwrap()
    );
    t.open_member((org, bob), Source::DomainAutojoin, None, None, Some(86_400))
        .await
        .unwrap();
    t.open_member((org, carol), Source::DomainAutojoin, None, None, Some(-1))
        .await
        .unwrap();
    t.commit().await.unwrap();
    let probe = Probe::default();
    assert_eq!(watch_pass(&w, at, &probe).await.memberships, 2);
    assert_eq!(watch_pass(&w, at, &probe).await.memberships, 0);
    let issued = orders(&identity_events(&w.db, "claim.membership", 2).await);
    assert!(issued.iter().any(|o| o.subject == carol));
    assert!(issued.iter().any(|o| o.subject == founder));
    assert!(!issued.iter().any(|o| o.subject == bob));
    // OP-153 m.17 (c), m.25 (a)
    let scalar = orders(&identity_events(&w.db, "claim.org_member", 2).await);
    let org_party = access_kernel::model::EqValue::Bytes(ORG.to_vec());
    assert!(scalar.iter().all(|o| matches!(
        &o.content,
        access_identity_account::domain::claims::Content::Scalar(v) if *v == org_party
    )));
    assert!(scalar.iter().any(|o| o.subject == carol));
    assert!(!scalar.iter().any(|o| o.subject == bob));
}

/// An owner's `grant_issue` of the autojoin role on the organization's Anchor `anchor`, held
/// by `holder` (TN-90, OP-153 m.25 (i) (3)).
fn autojoin_issue(anchor: [u8; 16], holder: access_kernel::model::SubjectSelector) -> Payload {
    use access_kernel::model::{
        ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, ResourceSelector, Structural,
    };
    let hex = String::from("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
    Payload::GrantIssue(access_kernel::meta::GrantContent {
        basis: access_kernel::meta::GrantBasis::Anchor(Id(anchor)),
        holder,
        authority: CanonicalAuthority {
            authority: AuthoritySet {
                actions: ActionSet {
                    exact: std::collections::BTreeSet::from([
                        access_internal_api::idp::IdpAction::AccountRead.action_ref(),
                    ]),
                    prefix: std::collections::BTreeSet::new(),
                },
                resource: ResourceSelector::Structural(Structural {
                    namespace: String::from("access.party"),
                    prefix: vec![hex],
                    kind: None,
                    attrs: std::collections::BTreeMap::new(),
                }),
                params: std::collections::BTreeMap::new(),
                recipient: None,
                purpose: None,
            },
            constraints: ConstraintSet {
                validity: Window {
                    from: 0,
                    until: u64::MAX / 2,
                },
                conditions: std::collections::BTreeSet::new(),
                budget: std::collections::BTreeSet::new(),
            },
            delegation: access_kernel::model::DelegationTerms::default(),
            requirements: std::collections::BTreeSet::new(),
        },
        agency: std::collections::BTreeSet::from([Capacity::Own]),
        named: None,
    })
}

// TN-90, C13, E18, OP-153 m.17 (c), m.25 (i) (3), (gg), Ek B 3612
#[tokio::test]
async fn an_owner_issues_the_autojoin_role_to_the_organizations_org_member_claims() {
    use access_identity_admin::app::org_flows::NOT_THE_AUTOJOIN_GRANT;
    use access_identity_admin::app::transfers::OWNER_ONLY;
    use access_identity_admin::domain::org::org_members;
    let (w, at, d, founder) = Box::pin(ready("org-autojoin")).await;
    create_org(&w, at, d, founder).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let anchor = t.party_anchor(ORG).await.unwrap().unwrap();
    let issuer = access_store::issuer::realm_issuer(&mut t)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();

    // E18
    let index = access_store::authority::state_of(
        &w.db.app,
        &DomainId::from_bytes(d.0),
        &[meta::key(kind::ACCEPTANCES, &Id(issuer))],
    )
    .await
    .unwrap();
    let ids = match suiss_crypto::dcbor::decode(
        index[0].value.as_deref().unwrap(),
        suiss_crypto::dcbor::Limits::CEILING,
    )
    .unwrap()
    {
        suiss_crypto::dcbor::Value::Array(ids) => ids,
        other => panic!("{other:?}"),
    };
    let keys: Vec<Vec<u8>> = ids
        .iter()
        .map(|v| meta::key(kind::ACCEPTANCE, &Id::from_value(v).unwrap()))
        .collect();
    let selects = access_store::authority::state_of(&w.db.app, &DomainId::from_bytes(d.0), &keys)
        .await
        .unwrap()
        .iter()
        .filter_map(|r| r.value.as_deref())
        .filter_map(|v| suiss_crypto::dcbor::decode(v, suiss_crypto::dcbor::Limits::CEILING).ok())
        .filter_map(|v| meta::ContentState::from_value(&v).ok())
        .filter_map(|a| access_kernel::claim::Gate::of(&a.content).ok())
        .any(|g| g.use_ == access_kernel::claim::SUBJECT_SELECTION && g.classes == ["org_member"]);
    assert!(selects);

    let on_anchor = ExerciseBasis::Anchor(Id(anchor));
    let issue =
        |holder, nonce, seed| meta_write(d, nonce, autojoin_issue(anchor, holder), on_anchor, seed);
    // TN-90
    refusal(
        Box::pin(
            w.admin()
                .issue_autojoin_grant(at, ORG, issue(org_members(ORG), 0x70, ROOT_KEY)),
        )
        .await,
        NOT_THE_AUTOJOIN_GRANT,
    );
    let founder_does = |change: Change, nonce: u8| as_founder(at, d, change, nonce, founder);
    let claim = compile(
        Op::ClaimOrganizationDomain,
        Some(&b64url_encode(&ORG)),
        &json!({ "domain": "acme.example", "method": "dns_txt" }),
        &w.ids,
    )
    .unwrap();
    let challenge = match exercise(&w, &founder_does(claim, 0x60), ROOT_KEY)
        .await
        .unwrap()
    {
        Applied::Written {
            secret: Some(s), ..
        } => s.expose().to_owned(),
        other => panic!("{other:?}"),
    };
    let probe = Probe::default();
    *probe.mx.lock().unwrap() = vec![String::from("mx1.acme.example")];
    *probe.registrar.lock().unwrap() = Some(String::from("1910"));
    *probe.txt.lock().unwrap() = vec![format!("suiss-access-verify={challenge}")];
    assert_eq!(watch_pass(&w, at, &probe).await.verified, 1);
    let autojoin = compile(
        Op::PatchOrganization,
        Some(&b64url_encode(&ORG)),
        &json!({ "autojoin": { "domain": "acme.example", "on": true } }),
        &w.ids,
    )
    .unwrap();
    written(
        &exercise(&w, &founder_does(autojoin, 0x61), ROOT_KEY)
            .await
            .unwrap(),
    );

    refusal(
        Box::pin(w.admin().issue_autojoin_grant(
            at,
            ORG,
            issue(
                access_kernel::model::SubjectSelector::Party(ALICE),
                0x71,
                ROOT_KEY,
            ),
        ))
        .await,
        NOT_THE_AUTOJOIN_GRANT,
    );
    refusal(
        Box::pin(w.admin().issue_autojoin_grant(
            at,
            ORG,
            issue(org_members([0x0d; 16]), 0x72, ROOT_KEY),
        ))
        .await,
        NOT_THE_AUTOJOIN_GRANT,
    );
    refusal(
        Box::pin(
            w.admin()
                .issue_autojoin_grant(at, ORG, issue(org_members(ORG), 0x73, ALICE_KEY)),
        )
        .await,
        OWNER_ONLY,
    );
    let applied = Box::pin(w.admin().issue_autojoin_grant(
        at,
        ORG,
        issue(org_members(ORG), 0x74, ROOT_KEY),
    ))
    .await
    .unwrap();
    written(&applied);
    let origin = meta::exercise_id(&d, &[0x74; 16]).unwrap();
    let grant = meta::object_id(&origin, kind::GRANT, 0);
    let rows = access_store::authority::state_of(
        &w.db.app,
        &DomainId::from_bytes(d.0),
        &[meta::key(kind::GRANT, &grant)],
    )
    .await
    .unwrap();
    let state = meta::GrantState::from_value(
        &suiss_crypto::dcbor::decode(
            rows[0].value.as_deref().unwrap(),
            suiss_crypto::dcbor::Limits::CEILING,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(state.content.holder, org_members(ORG));
    assert_eq!(
        state.content.basis,
        access_kernel::meta::GrantBasis::Anchor(Id(anchor))
    );
}

// TN-120, OP-153 m.3 (p), (gg), OP-153 m.17 (h), Ek B 3625
#[tokio::test]
async fn the_connection_manager_template_only_drafts_for_seven_days_and_never_delegates() {
    use access_identity_admin::domain::org::{
        SSO_MANAGER_ROLE, sso_manager_grant, sso_manager_set,
    };
    let (w, at, d, founder) = Box::pin(ready("org-sso")).await;
    let org = create_org(&w, at, d, founder).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let bob = account(&w, at, "it@acme.example").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &bob, &ALICE.0)
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let define = Payload::AuthoritySetDefine {
        name: String::from(SSO_MANAGER_ROLE),
        authority: sso_manager_set("org-sso", ORG),
    };
    let meta_anchor = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    assert!(matches!(
        w.admin()
            .meta(at, meta_write(d, 0x70, define, meta_anchor, ROOT_KEY))
            .await
            .unwrap(),
        Applied::Written { .. }
    ));
    let idp = meta::object_id(&d, kind::ANCHOR, IDP_ANCHOR);
    let content = sso_manager_grant(
        ("org-sso", ORG),
        ALICE,
        access_kernel::meta::GrantBasis::Anchor(idp),
        1,
        0,
    );
    let validity = content.authority.constraints.validity;
    assert_eq!(validity.until - validity.from, 7 * 86_400_000);
    assert_eq!(content.authority.delegation.depth, 0);
    let issued = w
        .admin()
        .meta(
            at,
            meta_write(
                d,
                0x71,
                Payload::GrantIssue(content.clone()),
                ExerciseBasis::Anchor(idp),
                ROOT_KEY,
            ),
        )
        .await
        .unwrap();
    let Applied::Written { position, .. } = issued else {
        panic!("{issued:?}");
    };
    let holding = ExerciseBasis::Holding(access_kernel::meta::HoldingRef {
        grant: meta::object_id(&meta::exercise_id(&d, &[0x71; 16]).unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: position,
    });
    let draft = compile(
        Op::DraftOrganizationConnection,
        Some(&b64url_encode(&ORG)),
        &json!({ "issuer": "https://login.acme.example", "client_id": "access" }),
        &w.ids,
    )
    .unwrap();
    // OP-153 m.17 (h)
    let mut p = proposal(at, draft, 0x72, holding, 1);
    p.subject = Some(bob);
    written(&exercise(&w, &p, ALICE_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let drafts = t.sso_drafts(org).await.unwrap();
    assert_eq!(drafts.len(), 1);
    assert_eq!(
        drafts[0].issuer.as_deref(),
        Some("https://login.acme.example")
    );
    assert_eq!(drafts[0].drafted_by, ALICE.0);
    t.commit().await.unwrap();

    // TN-120
    let rename = compile(
        Op::PatchOrganization,
        Some(&b64url_encode(&ORG)),
        &json!({ "display_name": "Taken" }),
        &w.ids,
    )
    .unwrap();
    let mut p = proposal(at, rename, 0x73, holding, 1);
    p.subject = Some(bob);
    let Applied::NotAllowed { decision, .. } = exercise(&w, &p, ALICE_KEY).await.unwrap() else {
        panic!("renamed");
    };
    assert_eq!(
        decision.blockers[0].resolver,
        access_kernel::combinator::Resolver::GrantorOfHop(0)
    );
    let mut onward = content;
    onward.basis = access_kernel::meta::GrantBasis::Holding(access_kernel::meta::HoldingRef {
        grant: meta::object_id(&meta::exercise_id(&d, &[0x71; 16]).unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: position,
    });
    onward.holder = access_kernel::model::SubjectSelector::Party(Id([0x0e; 16]));
    let onward = w
        .admin()
        .meta(
            at,
            meta_write(d, 0x74, Payload::GrantIssue(onward), holding, ALICE_KEY),
        )
        .await
        .unwrap();
    // OP-153 m.17 (h)
    let Applied::NotAllowed { decision, .. } = onward else {
        panic!("{onward:?}");
    };
    assert_eq!(
        decision.blockers[0].subcode.as_deref(),
        Some("meta-not-within")
    );
    let bad = Payload::AuthoritySetDefine {
        name: String::from("enterprise-connection-manager"),
        authority: sso_manager_set("org-sso", ORG),
    };
    // OP-153 m.17 (h)
    assert!(matches!(
        w.admin()
            .meta(at, meta_write(d, 0x75, bad, meta_anchor, ROOT_KEY))
            .await,
        Err(AdminError::Refused(code)) if code == "payload"
    ));
}

// E53, E47, OP-153 m.3 (q), (gg), Ek B 3630, 3631, 3632, 3633
#[tokio::test]
async fn a_guardianship_ends_at_majority_and_a_parent_consent_is_never_silence() {
    use access_identity_account::domain::claim_classes::GuardianshipBasis;
    use access_identity_admin::app::household::Household;
    let w = World::new().await;
    let (tenant, realm, _d) = w.realm("household").await;
    let at = (tenant, realm);
    let parent = account(&w, at, "parent@family.example").await;
    let child = account(&w, at, "child@family.example").await;
    let adult = account(&w, at, "adult@family.example").await;
    let v = vault_of(&w, realm);
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &parent, &ROOT.0)
            .await
            .unwrap()
    );
    assert!(
        access_store::idp::bind_subject_party(&mut t, &child, &ALICE.0)
            .await
            .unwrap()
    );
    assert!(
        access_store::idp::bind_subject_party(&mut t, &adult, &[0x0e; 16])
            .await
            .unwrap()
    );
    let now = t.server_time().await.unwrap();
    let year_ms: u64 = 365 * 86_400_000;
    let born = |years_ago: u16| {
        let d = access_identity_admin::app::household::today(now);
        format!(
            "{:04}-{:02}-{:02}",
            d.year - years_ago,
            d.month,
            d.day.min(28)
        )
    };
    access_identity_account::app::vault::set_profile(&mut t, &v, child, "birthdate", &born(10))
        .await
        .unwrap();
    access_identity_account::app::vault::set_profile(&mut t, &v, adult, "birthdate", &born(30))
        .await
        .unwrap();
    t.commit().await.unwrap();
    let home = Household {
        app: &w.db.app,
        vault: &v,
    };

    // E53
    assert!(matches!(
        home.guardianship(at, (parent, adult), GuardianshipBasis::Parent, "TR")
            .await,
        Err(AdminError::Invalid(Invalid::AccountState))
    ));
    let g = home
        .guardianship(at, (parent, child), GuardianshipBasis::Parent, "TR")
        .await
        .unwrap();
    identity_events(&w.db, "claim.guardianship", 1).await;
    identity_events(&w.db, "claim.age_range", 1).await;
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let row = t.guardianship(g).await.unwrap().unwrap();
    assert!(row.majority_ms > i64::try_from(now + 7 * year_ms).unwrap());
    assert!(row.majority_ms < i64::try_from(now + 9 * year_ms).unwrap());
    t.commit().await.unwrap();
    assert_eq!(
        access_identity_admin::app::household::majorities(&w.db.app, at)
            .await
            .unwrap(),
        0
    );

    // E53, E47
    let consent = home.ask(at, g, &[7; 32]).await.unwrap();
    assert_eq!(
        home.outcome(at, consent).await.unwrap(),
        access_kernel::combinator::Outcome::RequireAction
    );
    assert!(matches!(
        home.decide(at, consent, child, true).await,
        Err(AdminError::Refused(c)) if c == "not-the-guardian"
    ));
    assert_eq!(
        home.decide(at, consent, parent, true).await.unwrap(),
        access_kernel::combinator::Outcome::Allow
    );
    let declined = home.ask(at, g, &[8; 32]).await.unwrap();
    assert_eq!(
        home.decide(at, declined, parent, false).await.unwrap(),
        access_kernel::combinator::Outcome::Deny
    );
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(t.insert_consent(g, &[9; 32], 73 * 3_600).await.is_err());
    t.rollback().await.unwrap();
}

fn refusal<T: std::fmt::Debug>(r: Result<T, AdminError>, code: &str) {
    match r {
        Err(AdminError::Refused(c)) => assert_eq!(c, code),
        other => panic!("{other:?}"),
    }
}

/// The organization Anchor's `anchor_transfer` to `to`, signed by the key `seed`.
fn handover(
    d: Digest,
    anchor: [u8; 16],
    to: Id,
    nonce: u8,
    seed: u8,
) -> access_internal_api::idp::Submission {
    let payload = Payload::AnchorTransfer {
        anchor: Id(anchor),
        root: Root::Sole(to),
        disposition: std::collections::BTreeMap::new(),
    };
    meta_write(d, nonce, payload, ExerciseBasis::Anchor(Id(anchor)), seed)
}

/// The root key's AIS over `p`'s prepared intent.
async fn root_signed(w: &World, p: &Proposal) -> Vec<u8> {
    let prepared = w.admin().prepare(p).await.unwrap();
    sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        ROOT_KEY,
    )
}

// E53, OP-153 m.20 (g), m.25 (b), (c), (gg), Ek B 3630, 3631
#[tokio::test]
async fn a_guardianship_is_recorded_under_its_decision_and_ends_at_majority_unsigned() {
    use access_identity_account::domain::claim_classes::GuardianshipBasis;
    use access_identity_admin::domain::accounts::GuardianshipRecord;
    let (w, at, d, founder) = Box::pin(ready("household-record")).await;
    let child = account(&w, at, "kid@family.example").await;
    let grown = account(&w, at, "grown@family.example").await;
    let v = vault_of(&w, at.1);
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &child, &ALICE.0)
            .await
            .unwrap()
    );
    assert!(
        access_store::idp::bind_subject_party(&mut t, &grown, &[0x0e; 16])
            .await
            .unwrap()
    );
    let now = t.server_time().await.unwrap();
    let today = access_identity_admin::app::household::today(now);
    let born = |years: u16| {
        format!(
            "{:04}-{:02}-{:02}",
            today.year - years,
            today.month,
            today.day.min(28)
        )
    };
    access_identity_account::app::vault::set_profile(&mut t, &v, child, "birthdate", &born(9))
        .await
        .unwrap();
    access_identity_account::app::vault::set_profile(&mut t, &v, grown, "birthdate", &born(40))
        .await
        .unwrap();
    t.commit().await.unwrap();
    let record = |ward, nonce| {
        proposal(
            at,
            Change::GuardianshipRecord(GuardianshipRecord {
                guardian: founder,
                ward,
                basis: GuardianshipBasis::Parent,
                country: String::from("TR"),
            }),
            nonce,
            idp_anchor(d),
            1,
        )
    };
    // E53
    let of_age = record(grown, 0xd0);
    let ais = root_signed(&w, &of_age).await;
    assert!(matches!(
        Box::pin(w.admin().record_guardianship(&of_age, ais)).await,
        Err(AdminError::Invalid(Invalid::AccountState))
    ));
    let p = record(child, 0xd1);
    let ais = root_signed(&w, &p).await;
    let (applied, id) = Box::pin(w.admin().record_guardianship(&p, ais.clone()))
        .await
        .unwrap();
    written(&applied);
    assert!(id.is_some());
    let again = Box::pin(w.admin().record_guardianship(&p, ais))
        .await
        .unwrap();
    assert_eq!(again.1, None, "a retry records nothing again");
    // OP-153 m.25 (c)
    let claims = orders(&identity_events(&w.db, "claim.guardianship", 1).await);
    let majority = u64::try_from(
        access_identity_admin::app::household::Date::parse(&born(9))
            .unwrap()
            .plus_years(18)
            .ms(),
    )
    .unwrap();
    assert!(
        claims
            .iter()
            .any(|o| o.subject == child && o.at.saturating_add(o.ttl_ms) == majority),
        "the Claim's validity ends at the ward's majority"
    );
}

// TN-91, TN-92, OP-153 m.3 (p), m.17 (b), (f), (gg), Ek B 3617, 3618, 3619, 3620, 3621
#[tokio::test]
async fn an_ownership_handover_waits_for_its_recipient_and_delay_and_any_party_can_cancel() {
    use access_identity_admin::app::transfers::{NOT_THE_TRANSFER, OWNER_ONLY, TRANSFER_WAITING};
    let (w, at, d, founder) = Box::pin(ready_with("org-handover", Some(0))).await;
    let org = create_org(&w, at, d, founder).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let bob = account(&w, at, "bob@acme.example").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &bob, &ALICE.0)
            .await
            .unwrap()
    );
    t.open_member((org, bob), Source::Invite, None, None, None)
        .await
        .unwrap();
    let anchor = t.party_anchor(ORG).await.unwrap().unwrap();
    t.commit().await.unwrap();

    // TN-91
    refusal(
        w.admin()
            .propose_transfer(
                at,
                ORG,
                (bob, founder),
                &handover(d, anchor, ROOT, 0x90, ALICE_KEY),
            )
            .await,
        OWNER_ONLY,
    );
    refusal(
        w.admin()
            .propose_transfer(
                at,
                ORG,
                (founder, bob),
                &handover(d, anchor, ALICE, 0x90, ALICE_KEY),
            )
            .await,
        OWNER_ONLY,
    );
    refusal(
        w.admin()
            .propose_transfer(
                at,
                ORG,
                (founder, bob),
                &handover(d, anchor, ROOT, 0x90, ROOT_KEY),
            )
            .await,
        NOT_THE_TRANSFER,
    );
    let first = w
        .admin()
        .propose_transfer(
            at,
            ORG,
            (founder, bob),
            &handover(d, anchor, ALICE, 0x90, ROOT_KEY),
        )
        .await
        .unwrap();
    // TN-91, OP-153 m.17 (f)
    realm_events(&w, at.1, "relay.message.ownership_handover.v1", 2).await;
    // OP-153 m.25 (i) (2)
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    assert_eq!(
        t.transfer(first.transfer)
            .await
            .unwrap()
            .unwrap()
            .intent_digest,
        Some(
            intent_digest(&handover(d, anchor, ALICE, 0x90, ROOT_KEY).intent)
                .unwrap()
                .0
        )
    );
    t.commit().await.unwrap();
    // L0-META-20, OP-153 m.17 (b), m.25 (a)
    let Applied::NotAllowed { decision, .. } = Box::pin(
        w.admin()
            .meta(at, handover(d, anchor, ALICE, 0x90, ROOT_KEY)),
    )
    .await
    .unwrap() else {
        panic!("the handover waits for its recipient");
    };
    assert!(
        decision.unmet.iter().any(|u| u.term
            == access_authority_core::requirements::with_ceiling(
                access_kernel::meta::accept_root(ALICE),
                &access_authority_core::requirements::ceiling(
                    access_kernel::tier::Tier::Ct3,
                    None,
                    false
                )
            )),
        "{decision:?}"
    );
    refusal(
        Box::pin(w.admin().complete_transfer(
            at,
            ORG,
            first.transfer,
            handover(d, anchor, ALICE, 0x90, ROOT_KEY),
        ))
        .await,
        TRANSFER_WAITING,
    );
    refusal(
        w.admin()
            .contribute_transfer(at, ORG, first.transfer, (founder, [0x77; 32]))
            .await,
        NOT_THE_TRANSFER,
    );
    w.admin()
        .contribute_transfer(at, ORG, first.transfer, (bob, [0x77; 32]))
        .await
        .unwrap();
    // TN-91
    refusal(
        Box::pin(w.admin().complete_transfer(
            at,
            ORG,
            first.transfer,
            handover(d, anchor, ALICE, 0x90, ROOT_KEY),
        ))
        .await,
        TRANSFER_WAITING,
    );
    // TN-91
    w.admin()
        .cancel_transfer(at, ORG, first.transfer, bob)
        .await
        .unwrap();
    assert!(matches!(
        w.admin()
            .contribute_transfer(at, ORG, first.transfer, (bob, [0x77; 32]))
            .await,
        Err(AdminError::Invalid(Invalid::NoMember))
    ));

    let second = handover(d, anchor, ALICE, 0x91, ROOT_KEY);
    let digest = second.payload.as_deref().unwrap().digest().unwrap().0;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let id = t
        .insert_transfer_ago(
            &access_store::org_authority::NewTransfer {
                org,
                from: founder,
                to: bob,
                to_party: ALICE.0,
                nonce: &second.nonce,
                payload_digest: &digest,
                intent_digest: None,
                effective_ms: 0,
                dns_recovery: false,
            },
            25 * 3_600,
        )
        .await
        .unwrap();
    t.commit().await.unwrap();
    w.admin()
        .contribute_transfer(at, ORG, id, (bob, [0x78; 32]))
        .await
        .unwrap();
    // L0-META-20, OP-153 m.25 (a)
    let unaccepted = Box::pin(w.admin().complete_transfer(at, ORG, id, second)).await;
    assert!(
        !matches!(
            unaccepted,
            Ok(Applied::Written { .. } | Applied::AlreadyWritten { .. })
        ),
        "{unaccepted:?}"
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let members = t.members(org).await.unwrap();
    assert!(!members.iter().any(|m| m.subject == bob && m.owner));
    assert!(members.iter().any(|m| m.subject == founder && m.owner));
    t.commit().await.unwrap();
    w.admin()
        .cancel_transfer(at, ORG, id, founder)
        .await
        .unwrap();

    // L0-META-20, L0-META-30, TN-91, §9.14.1, OP-153 m.25 (i) (2)
    let third = handover(d, anchor, ALICE, 0x92, ROOT_KEY);
    let target = intent_digest(&third.intent).unwrap();
    assert!(matches!(
        Box::pin(w.admin().meta(at, third.clone())).await.unwrap(),
        Applied::NotAllowed { .. }
    ));
    let digest = third.payload.as_deref().unwrap().digest().unwrap().0;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let id = t
        .insert_transfer_ago(
            &access_store::org_authority::NewTransfer {
                org,
                from: founder,
                to: bob,
                to_party: ALICE.0,
                nonce: &third.nonce,
                payload_digest: &digest,
                intent_digest: Some(&target.0),
                effective_ms: 0,
                dns_recovery: false,
            },
            25 * 3_600,
        )
        .await
        .unwrap();
    t.commit().await.unwrap();
    let exercise = Box::pin(accept_root(&w, at, d, (bob, ALICE, ALICE_KEY), target)).await;
    w.admin()
        .contribute_transfer(at, ORG, id, (bob, exercise.0))
        .await
        .unwrap();
    written(
        &Box::pin(w.admin().complete_transfer(at, ORG, id, third))
            .await
            .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let members = t.members(org).await.unwrap();
    assert!(members.iter().any(|m| m.subject == bob && m.owner));
    assert!(!members.iter().any(|m| m.subject == founder && m.owner));
    // TN-92
    assert!(
        t.transfers(org)
            .await
            .unwrap()
            .iter()
            .all(|h| !h.dns_recovery)
    );
    t.commit().await.unwrap();
}

/// The recipient's `accept_root` contribution to the handover whose `anchor_transfer` intent is
/// `target`, as the Approval Surface commits it (§9.14.1 A, L0-META-30): its device signs the
/// contribute intent on its Party's own self-anchor, the realm issuer states the
/// `authentication` Claim bound to the Approval Act Statement over the render the domain kept,
/// and the contribution goes to the domain with both as proofs.
async fn accept_root(
    w: &World,
    (tenant, realm): (TenantId, RealmId),
    d: Digest,
    (subject, party, seed): ([u8; 16], Id, u8),
    target: Digest,
) -> Digest {
    use access_identity_account::domain::claims::{AuthFacts, Bind, authentication};
    use access_identity_ui::ports::Approvals as _;
    use access_internal_api::approvals::Contribution;
    access_store::claims::open_claim_ingest_day(&w.db.archive, 0)
        .await
        .unwrap();
    let mut tx = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let issuer = access_store::issuer::realm_issuer(&mut tx)
        .await
        .unwrap()
        .unwrap();
    tx.commit().await.unwrap();
    w.keys.open_issuer(realm, issuer).await.unwrap();
    assert!(
        w.admin()
            .register_issuer(tenant, realm)
            .await
            .unwrap()
            .is_some()
    );
    let opening = w.plane.opening(d, target).await.unwrap().unwrap();
    let shown = access_kernel::render::decode(opening.render.as_deref().unwrap()).unwrap();
    let challenge = challenge_of(seed);
    let instance = meta::object_id(
        &meta::exercise_id(&d, &challenge).unwrap(),
        kind::INSTANCE,
        0,
    );
    let self_anchor = meta::object_id(
        &meta::exercise_id(&d, &register_nonce(&challenge)).unwrap(),
        kind::ANCHOR,
        0,
    );
    let nonce = vec![0x93; 16];
    let act = access_kernel::aas::ApprovalAct {
        evidence: Some(access_kernel::aas::EvidenceLevel::PhishingResistant),
        surface_class: Some(access_kernel::aas::SurfaceClass::Desktop),
        act: access_kernel::aas::Act::Contribution(String::from(meta::ACCEPT_ROOT)),
        instance,
        party,
        capacity: Capacity::Own,
        target,
        domain: d,
        nonce: nonce.clone(),
        work_gate: None,
        surface_profile: String::from(access_identity_ui::domain::approval::SURFACE_PROFILE),
        surface_version: access_identity_ui::domain::approval::SURFACE_VERSION,
        render_digest: opening.render_digest,
        material_fields: access_kernel::render::material_fields(&shown),
        issued_at: NOW - 1_000,
        expires_at: NOW + 60_000,
    };
    let aas = access_kernel::aas::digest(&act).unwrap();
    let order = authentication(AuthFacts {
        subject,
        method: access_kernel::claim::body::AuthMethod::Webauthn,
        auth_time: NOW - 1_000,
        assurance: [
            ("aal", 3),
            ("phishing_resistant", 1),
            ("uv", 1),
            ("human_presence", 1),
            ("hardware_bound", 1),
            ("non_custodial", 1),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), *v))
        .collect(),
        webauthn: None,
        evidence: None,
        bind: Bind::Statement {
            statement: aas.0,
            instance: instance.0,
        },
    });
    let claim = match super::claims::courier(w)
        .issue(tenant, realm, &order)
        .await
        .unwrap()
    {
        access_identity_account::app::claims::Issued::Answered {
            claim,
            verdict: access_internal_api::claims::ClaimVerdict::Admitted { .. },
        } => Id(claim),
        other => panic!("{other:?}"),
    };
    let validity = Window {
        from: NOW - 1_000,
        until: NOW + HOUR,
    };
    let intent =
        access_kernel::contribution::contribute_intent(target, meta::ACCEPT_ROOT, validity)
            .unwrap();
    let basis = ExerciseBasis::Anchor(self_anchor);
    let ais = sign(
        &statement(d, &nonce, intent_digest(&intent).unwrap(), basis),
        seed,
    );
    match w
        .plane
        .contribute(Contribution {
            domain: d,
            nonce,
            target,
            class: String::from(meta::ACCEPT_ROOT),
            basis,
            capacity: Capacity::Own,
            validity,
            ais,
            aas: act.to_bytes().unwrap(),
            claim,
            pep: String::from(PEP),
        })
        .await
        .unwrap()
    {
        access_internal_api::idp::Verdict::Committed(c) => c.exercise,
        other => panic!("{other:?}"),
    }
}

// OP-142, §8.17.12, C11, OP-153 m.3 (gg), Ek B 4082
#[tokio::test]
async fn members_delegate_only_to_the_apps_their_role_lists() {
    use access_kernel::model::{
        CanonicalAuthority, ConstraintSet, DelegationTerms, SubjectSelector,
    };
    const APP: Id = Id([0x5a; 16]);
    const OTHER: Id = Id([0x5b; 16]);
    let (w, at, d, founder) = Box::pin(ready("org-apps")).await;
    let _org = create_org(&w, at, d, founder).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let idp = meta::object_id(&d, kind::ANCHOR, IDP_ANCHOR);
    let role = |holder: SubjectSelector, depth: u64, class: Option<SubjectSelector>, basis| {
        access_kernel::meta::GrantContent {
            basis,
            holder,
            authority: CanonicalAuthority {
                authority: member_set("org-apps"),
                constraints: ConstraintSet {
                    validity: Window {
                        from: 0,
                        until: u64::MAX / 2,
                    },
                    conditions: std::collections::BTreeSet::new(),
                    budget: std::collections::BTreeSet::new(),
                },
                delegation: DelegationTerms {
                    depth,
                    downstream_holder_class: class,
                },
                requirements: std::collections::BTreeSet::new(),
            },
            agency: std::collections::BTreeSet::from([Capacity::Own]),
            named: None,
        }
    };
    let member = role(
        SubjectSelector::Party(ALICE),
        1,
        Some(SubjectSelector::Party(APP)),
        access_kernel::meta::GrantBasis::Anchor(idp),
    );
    let Applied::Written { position, .. } = w
        .admin()
        .meta(
            at,
            meta_write(
                d,
                0xa0,
                Payload::GrantIssue(member),
                ExerciseBasis::Anchor(idp),
                ROOT_KEY,
            ),
        )
        .await
        .unwrap()
    else {
        panic!("member role");
    };
    let held = access_kernel::meta::HoldingRef {
        grant: meta::object_id(&meta::exercise_id(&d, &[0xa0; 16]).unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: position,
    };
    let onward = |to: Id| {
        role(
            SubjectSelector::Party(to),
            0,
            Some(SubjectSelector::Party(APP)),
            access_kernel::meta::GrantBasis::Holding(held),
        )
    };
    let refused = w
        .admin()
        .meta(
            at,
            meta_write(
                d,
                0xa1,
                Payload::GrantIssue(onward(OTHER)),
                ExerciseBasis::Holding(held),
                ALICE_KEY,
            ),
        )
        .await
        .unwrap();
    let Applied::NotAllowed { decision, .. } = refused else {
        panic!("{refused:?}");
    };
    assert_eq!(
        decision.blockers[0].subcode.as_deref(),
        Some("meta-not-within")
    );
    written(
        &w.admin()
            .meta(
                at,
                meta_write(
                    d,
                    0xa2,
                    Payload::GrantIssue(onward(APP)),
                    ExerciseBasis::Holding(held),
                    ALICE_KEY,
                ),
            )
            .await
            .unwrap(),
    );
}

// TN-90, §12.3.8, OP-153 m.3 (gg), Ek B 3611
#[tokio::test]
async fn an_idp_domain_claim_is_verified_by_an_owners_upstream_assertion() {
    let (w, at, d, founder) = Box::pin(ready("org-idp")).await;
    let org = create_org(&w, at, d, founder).await;
    let claim = compile(
        Op::ClaimOrganizationDomain,
        Some(&b64url_encode(&ORG)),
        &json!({ "domain": "acme.example", "method": "idp" }),
        &w.ids,
    )
    .unwrap();
    written(
        &exercise(&w, &as_founder(at, d, claim, 0x61, founder), ROOT_KEY)
            .await
            .unwrap(),
    );
    let probe = Probe::default();
    *probe.mx.lock().unwrap() = vec![String::from("mx1.acme.example")];
    *probe.registrar.lock().unwrap() = Some(String::from("1910"));
    let member = account(&w, at, "member@acme.example").await;
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    t.open_member((org, member), Source::Invite, None, None, None)
        .await
        .unwrap();
    t.assert_upstream_domain(member, "https://accounts.google.com", "acme.example", None)
        .await
        .unwrap();
    t.assert_upstream_domain(
        founder,
        "https://accounts.google.com",
        "other.example",
        None,
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
    assert_eq!(watch_pass(&w, at, &probe).await.verified, 0);
    assert!(claims_of(&w, at, org).await[0].verified_ms.is_none());

    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    t.assert_upstream_domain(founder, "https://accounts.google.com", "acme.example", None)
        .await
        .unwrap();
    t.commit().await.unwrap();
    assert_eq!(watch_pass(&w, at, &probe).await.verified, 1);
    let c = claims_of(&w, at, org).await;
    assert!(c[0].verified_ms.is_some() && c[0].claimed);
    assert_eq!(c[0].method, "idp");
}

// OP-153 m.18 (e), m.19 (d), m.20 (g), m.25 (b), OP-141 m.35, §13.7.1
#[tokio::test]
async fn the_governing_domain_accepts_the_new_account_actions() {
    use access_identity_account::domain::claim_classes::GuardianshipBasis;
    use access_identity_admin::app::NOT_YET_SERVED;
    use access_identity_admin::domain::accounts::{
        AccountBind, AccountImport, GuardianshipRecord, MigrationExport,
    };
    let (w, at, d, founder) = Box::pin(ready_with("r1-catalog", Some(0))).await;
    let changes = [
        Change::AccountBind(AccountBind {
            subject: founder,
            peer_realm: [0x21; 16],
            peer_subject: [0x22; 16],
            offer: None,
        }),
        Change::AccountImport(AccountImport {
            file: [0x23; 32],
            accounts: 2,
        }),
        Change::MigrationExport(MigrationExport {
            recipient: [vec![4], vec![0x24; 64]].concat(),
        }),
        Change::GuardianshipRecord(GuardianshipRecord {
            guardian: founder,
            ward: [0x25; 16],
            basis: GuardianshipBasis::Parent,
            country: String::from("TR"),
        }),
    ];
    for (n, change) in (0xb0_u8..).zip(changes) {
        let label = change.action().label();
        let prepared = w
            .admin()
            .prepare(&proposal(at, change.clone(), n, idp_anchor(d), 1))
            .await;
        // TN-85, TN-86, OP-153 m.18 (e), m.19 (d)
        assert!(
            !matches!(&prepared, Err(AdminError::Refused(c)) if c == NOT_YET_SERVED),
            "{label}"
        );
        let intent = change
            .intent(
                "r1-catalog",
                Window {
                    from: NOW,
                    until: NOW + HOUR,
                },
            )
            .unwrap();
        let digest = intent_digest(&intent).unwrap();
        let basis = idp_anchor(d);
        let v = Decider::decide(
            &w.plane,
            Submission {
                domain: d,
                nonce: vec![n; 16],
                ais: sign(&statement(d, &[n; 16], digest, basis), ROOT_KEY),
                intent,
                payload: None,
                basis,
                capacity: Capacity::Own,
                contributions: Vec::new(),
                pep: String::from(PEP),
                actor: None,
            },
        )
        .await
        .unwrap();
        assert!(matches!(v, Verdict::Committed(_)), "{label}: {v:?}");
    }
}
