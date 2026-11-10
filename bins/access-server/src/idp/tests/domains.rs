//! Custom domains through commit against real PostgreSQL and the authority plane (OP-156 m.3 (a),
//! (i), TN-16, TN-17, §18.1): `idp.domain.register` is CT2 and names a host outside the base; the
//! DNS pass verifies it; `idp.domain.issuer_bind` is a reserved CT3 that needs a verified domain
//! and comes once; the issuer moves only before the realm's first activation; an RP ID on the
//! Suiss domain is refused and a verified custom domain is required.

use access_identity_admin::domain::custom_domain::{Binding, DomainChange};
use access_identity_domain::adapters::seal::{KeySeal, RealmKek};
use access_identity_domain::testing::{FakeDns, MemChallenges, NoPause, SoftAccount};
use access_internal_api::idp::IdpAction;
use access_store::custom_domains as cd;

use super::*;

const HOST: &str = "login.acme.example";

fn wall_s() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

struct NoKek;

impl RealmKek for NoKek {
    fn kek(
        &self,
        _: TenantId,
        _: RealmId,
    ) -> Option<Arc<dyn suiss_crypto::envelope::Kek + Send + Sync>> {
        None
    }
}

fn domain_change(at: (TenantId, RealmId), d: Digest, change: DomainChange, nonce: u8) -> Proposal {
    proposal(at, Change::Domain(change), nonce, idp_anchor(d), 1)
}

async fn row(w: &World, (tenant, realm): (TenantId, RealmId)) -> cd::DomainRow {
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let r = cd::live_by_host(&mut t, HOST).await.unwrap().unwrap();
    t.commit().await.unwrap();
    r
}

/// Runs the custom domain pass over the realm with both records published, no ACME.
async fn verify(w: &World, at: (TenantId, RealmId)) {
    let r = row(w, at).await;
    let dns = FakeDns::default();
    dns.publish(HOST, &r.challenge, &r.cname_target);
    let pass = access_identity_domain::app::pass::Pass::<
        _,
        access_identity_domain::testing::AcmeTwin,
        SoftAccount,
        NoPause,
        MemChallenges,
        NoKek,
    > {
        app: &w.db.app,
        dns: &dns,
        acme: None,
        challenges: &MemChallenges::default(),
        keys: &KeySeal(NoKek),
    };
    let now = wall_s();
    assert_eq!(pass.realm(at, now).await.unwrap().verified, 1);
}

// OP-156 m.3 (a), (i), TN-16, TN-20
#[tokio::test]
async fn a_custom_domain_is_registered_verified_and_bound_once() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("acme").await;
    let at = (tenant, realm);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    // §13.7.1, OP-141 m.35 (g)
    assert!(IdpAction::DomainIssuerBind.schema().reserved);
    assert!(!IdpAction::DomainRegister.schema().reserved);
    for bad in ["acme.id.test", "id.test", "acme.example", "acme.localhost"] {
        let p = domain_change(at, d, DomainChange::Register(String::from(bad)), 1);
        assert!(w.admin().prepare(&p).await.is_err(), "{bad}");
    }
    let register = domain_change(at, d, DomainChange::Register(String::from(HOST)), 2);
    written(&exercise(&w, &register, ROOT_KEY).await.unwrap());
    let r = row(&w, at).await;
    assert_eq!(r.status, "pending");
    assert_eq!(r.cname_target, "acme.id.test");
    assert_eq!(r.challenge.len(), 43);
    let again = domain_change(at, d, DomainChange::Register(String::from(HOST)), 3);
    assert!(w.admin().prepare(&again).await.is_err());

    // OP-156 m.3 (i)
    let early = domain_change(
        at,
        d,
        DomainChange::IssuerBind(String::from(HOST), Binding::RpId),
        4,
    );
    assert!(w.admin().prepare(&early).await.is_err());

    verify(&w, at).await;
    let bind = domain_change(
        at,
        d,
        DomainChange::IssuerBind(String::from(HOST), Binding::RpId),
        5,
    );
    written(&exercise(&w, &bind, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        settings(&mut t).await.unwrap().unwrap().rp_id.as_deref(),
        Some("acme.example")
    );
    assert!(t.last_rp_id_change().await.unwrap().is_some());
    t.commit().await.unwrap();
    assert_eq!(row(&w, at).await.bound_as.as_deref(), Some("rp_id"));
    let second = domain_change(
        at,
        d,
        DomainChange::IssuerBind(String::from(HOST), Binding::Issuer),
        6,
    );
    assert!(w.admin().prepare(&second).await.is_err());
    let retire = domain_change(at, d, DomainChange::Retire(String::from(HOST)), 7);
    assert!(w.admin().prepare(&retire).await.is_err());
}

// TN-16, OP-156 m.3 (i)
#[tokio::test]
async fn the_issuer_moves_to_a_verified_domain_only_before_the_first_activation() {
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("fresh").await;
    let at = (tenant, realm);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    written(
        &exercise(
            &w,
            &domain_change(at, d, DomainChange::Register(String::from(HOST)), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    verify(&w, at).await;
    written(
        &exercise(
            &w,
            &domain_change(
                at,
                d,
                DomainChange::IssuerBind(String::from(HOST), Binding::Issuer),
                2,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let route = access_store::custom_domains::route_by_custom_host(&w.db.router, HOST)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(route.route.issuer, format!("https://{HOST}"));
    assert_eq!(route.bound_as.as_deref(), Some("issuer"));
    let found = access_identity_oauth::app::resolve(
        &access_identity_oauth::adapters::PgDirectory::new(w.db.router.clone()),
        HOST,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(found.issuer.as_str(), format!("https://{HOST}"));
    assert!(
        access_identity_oauth::app::resolve(
            &access_identity_oauth::adapters::PgDirectory::new(w.db.router.clone()),
            "fresh.id.test",
            None,
        )
        .await
        .unwrap()
        .is_none()
    );

    let (tenant, realm, d) = w.realm("used").await;
    let at = (tenant, realm);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    written(
        &exercise(
            &w,
            &proposal(
                at,
                Change::ClientRegister(new_client(&w).await),
                1,
                idp_anchor(d),
                1,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    written(
        &exercise(
            &w,
            &domain_change(
                at,
                d,
                DomainChange::Register(String::from("id.used.example")),
                2,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let r = cd::live_by_host(&mut t, "id.used.example")
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    let dns = FakeDns::default();
    dns.publish("id.used.example", &r.challenge, &r.cname_target);
    let pass = access_identity_domain::app::pass::Pass::<
        _,
        access_identity_domain::testing::AcmeTwin,
        SoftAccount,
        NoPause,
        MemChallenges,
        NoKek,
    > {
        app: &w.db.app,
        dns: &dns,
        acme: None,
        challenges: &MemChallenges::default(),
        keys: &KeySeal(NoKek),
    };
    let now = wall_s();
    assert_eq!(pass.realm(at, now).await.unwrap().verified, 1);
    let late = domain_change(
        at,
        d,
        DomainChange::IssuerBind(String::from("id.used.example"), Binding::Issuer),
        3,
    );
    assert!(matches!(
        w.admin().prepare(&late).await,
        Err(AdminError::Invalid(Invalid::IssuerFixed))
    ));
}

// OP-156 m.3 (i), §18.1, TN-17
#[tokio::test]
async fn an_rp_id_on_the_suiss_domain_is_refused_and_a_verified_custom_domain_is_required() {
    let w = World {
        base: RealmBase::parse("https://suiss.example").unwrap(),
        ..World::new().await
    };
    let (tenant, realm, d) = w.realm("acme").await;
    let at = (tenant, realm);
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    for rp in ["acme.suiss.example", "suiss.example", "login.acme.example"] {
        let p = proposal(
            at,
            Change::RpId(RpId::parse(rp).unwrap()),
            1,
            idp_anchor(d),
            1,
        );
        assert!(
            matches!(
                w.admin().prepare(&p).await,
                Err(AdminError::Invalid(Invalid::RpId))
            ),
            "{rp}"
        );
    }
    written(
        &exercise(
            &w,
            &domain_change(at, d, DomainChange::Register(String::from(HOST)), 2),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    verify(&w, at).await;
    let pinned = proposal(
        at,
        Change::RpId(RpId::parse("acme.example").unwrap()),
        3,
        idp_anchor(d),
        1,
    );
    written(&exercise(&w, &pinned, ROOT_KEY).await.unwrap());
}
