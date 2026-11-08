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
    let w = World::new().await;
    let (tenant, realm, d) = w.realm(slug).await;
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
    let (w, at, d, founder) = ready("org-party").await;
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
    let (w, at, d, founder) = ready("org-invite").await;
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
    let (w, at, d, founder) = ready("org-hrd").await;
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

    fn idp_asserts(
        &self,
        _: [u8; 16],
        _: &str,
    ) -> impl Future<Output = Result<bool, Unavailable>> + Send {
        std::future::ready(Ok(false))
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
    let (w, at, d, founder) = ready("org-domains").await;
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
    let (w, at, d, founder) = ready("org-role").await;
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
    let Applied::Written { exercise, .. } = applied else {
        panic!("{applied:?}");
    };
    let mut t = TenantTx::begin(&w.db.app, at.0, at.1).await.unwrap();
    let m = t.member(org, bob).await.unwrap().unwrap();
    assert_eq!(m.grant_state.as_deref(), Some("issued"));
    assert_eq!(m.grant, Some(meta::object_id(&exercise, kind::GRANT, 0).0));
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
    let (w, at, d, founder) = ready("org-cool").await;
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
}
