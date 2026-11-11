//! The local deployment's Stage 12 fixtures on the real path (OP-157 m.6 (i), OP-153 m.3 (gg)):
//! the bootstrap makes a support operator in its organization with a registered case system and
//! the test user's open case, a marked break-glass account with its two pre-issued Grants, and
//! an access review whose manager sees the sample agent's Grant; a second run changes nothing.

use access_identity_account::app::SUBJECT_PREFIX;

use super::*;
use crate::bootstrap::agent::SampleAgentPlan;
use crate::bootstrap::governance::{BreakglassPlan, ReviewPlan, SupportOperatorPlan};

pub(super) fn fixtures_plan() -> Plan {
    Plan {
        sample_agent: Some(SampleAgentPlan {
            realm: String::from("acme"),
            display_name: String::from("Local sample agent"),
        }),
        support_operator: Some(SupportOperatorPlan {
            realm: String::from("acme"),
            display_name: String::from("Mehmet Y."),
            organisation: String::from("Acme Support"),
            identifier: String::from("support@acme.example"),
            password: Secret::new(String::from("operator horse battery staple")),
            case_system: String::from("local-desk"),
            case: String::from("4411"),
        }),
        breakglass_account: Some(BreakglassPlan {
            realm: String::from("acme"),
            identifier: String::from("oncall@acme.example"),
            organisation: String::from("Acme Security"),
        }),
        review_schedule: Some(ReviewPlan {
            realm: String::from("acme"),
            name: String::from("local-review"),
            period_days: 90,
        }),
        ..approve_plan(None)
    }
}

// OP-157 m.6 (i), m.3 (e), (f), (h), (w), m.10, TN-5, TN-73, CMP-8, OP-69, OP-153 m.3 (gg)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_bootstrap_makes_the_stage_twelve_fixtures_once_through_their_exercises() {
    let (w, signer) = World::open("bootstrap-fixtures", true).await;
    let signer = signer.unwrap();
    schedule(&signer);
    schedule(&signer);
    // OP-146 m.5 (f)
    crate::jobs::open_now(&w.db.app, &w.db.archive, "bootstrap-fixtures").await;
    let first = serde_json::to_value(w.run(&fixtures_plan()).await).unwrap();
    let support = &first["support_operator"];
    assert_eq!(support["created"], true, "{first}");
    assert_eq!(support["acceptance"], "accepted", "{support}");
    assert!(support["case_until"].as_u64().is_some(), "{support}");
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let operator = ids
        .decode(SUBJECT_PREFIX, support["subject"].as_str().unwrap())
        .unwrap();
    assert_eq!(
        idp::subject_party(&mut t, &operator).await.unwrap(),
        Some(id_of(support["party"].as_str().unwrap()).0)
    );
    // OP-157 m.3 (e)
    let systems = t.case_systems().await.unwrap();
    let system = systems.iter().find(|c| c.name == "local-desk").unwrap();
    assert!(system.live);
    assert_eq!(
        b64url_encode(&system.issuer),
        support["case_issuer"].as_str().unwrap()
    );
    // TN-5, OP-157 m.6 (f)
    let org = t
        .org_by_party(id_of(support["organisation_party"].as_str().unwrap()).0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(org.display_name, "Acme Support");
    assert!(
        t.memberships(org.id)
            .await
            .unwrap()
            .iter()
            .any(|m| m.subject == operator)
    );
    assert!(
        t.orgs_of(operator)
            .await
            .unwrap()
            .iter()
            .any(|(o, _)| !o.ended)
    );

    // OP-157 m.3 (h), m.10
    let breakglass = &first["breakglass_account"];
    assert_eq!(breakglass["created"], true, "{first}");
    let account = ids
        .decode(SUBJECT_PREFIX, breakglass["subject"].as_str().unwrap())
        .unwrap();
    let marked = t.breakglass_accounts().await.unwrap();
    assert!(
        marked.iter().any(|a| a.subject == account
            && b64url_encode(&a.org) == breakglass["organisation_party"].as_str().unwrap()),
        "{marked:?}"
    );
    let grants = breakglass["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 2, "{breakglass}");
    let holders: BTreeSet<&str> = grants
        .iter()
        .map(|g| g["holding"]["holder"].as_str().unwrap())
        .collect();
    assert!(holders.contains(breakglass["party"].as_str().unwrap()));
    assert!(holders.contains(first["test_user"]["party"].as_str().unwrap()));

    // OP-157 m.3 (w), IDP-39 (3)
    let review = &first["review_schedule"];
    assert_eq!(review["created"], true, "{first}");
    assert!(review["items"].as_u64().unwrap() >= 1, "{review}");
    assert_eq!(review["manager"], first["test_user"]["party"]);
    assert!(
        t.review_schedules()
            .await
            .unwrap()
            .iter()
            .any(|r| r.name == "local-review" && r.live && r.period_days == 90)
    );
    t.commit().await.unwrap();

    // OP-157 m.3 (w), m.18, Ek B 5565
    let keks = crate::login::RealmKeks::new(w.keys.clone());
    let inputs = crate::reviews::Inputs {
        app: &w.db.app,
        router: &w.db.router,
        keks: &keks,
        ids: &ids,
        console: Some("https://manage.access.test"),
    };
    let now = server_time(&w.db.app).await.unwrap();
    let sent = crate::reviews::step(&*w.domains, &inputs, "fixtures", now)
        .await
        .unwrap();
    assert_eq!(sent, 1, "the manager of one item is told once");
    let notices = identity_events_until(
        &w.db,
        "relay.message.review_campaign.v1",
        |q| !q.is_empty(),
        "the period's notice",
    )
    .await;
    assert_eq!(notices.len(), 1);
    assert_eq!(
        crate::reviews::step(&*w.domains, &inputs, "fixtures", now + 60_000)
            .await
            .unwrap(),
        0,
        "a period is announced once"
    );
    let next = now + 90 * 86_400_000;
    assert_eq!(
        crate::reviews::step(&*w.domains, &inputs, "fixtures", next)
            .await
            .unwrap(),
        1,
        "the next period is announced again"
    );
    w.domains.release().await;

    // OP-69
    schedule(&signer);
    let second = serde_json::to_value(w.run(&fixtures_plan()).await).unwrap();
    for section in ["support_operator", "breakglass_account", "review_schedule"] {
        assert_eq!(second[section]["created"], false, "{section}: {second}");
    }
    assert_eq!(second["support_operator"]["party"], support["party"]);
    assert_eq!(
        second["support_operator"]["case_until"],
        support["case_until"]
    );
    assert_eq!(second["breakglass_account"]["grants"], breakglass["grants"]);
    assert_eq!(second["review_schedule"]["items"], review["items"]);
}

// OP-157 m.6 (i), m.3 (f), TN-137, §8.16, Ek B 5524, 5613, OP-153 m.3 (gg)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_local_client_runs_a_support_episode_on_the_fixtures() {
    use access_http::adp::adapters::{Discovery, router as adp_router};
    use access_http::login::{me_router, router as login_router, support_router};
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
    use access_identity_account::app::claims::Courier;
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::app::local::LocalLimiter;
    use access_identity_account::app::login::LoginGate;
    use access_identity_account::domain::password::Argon2Params;
    use access_identity_account::domain::throttle::ThrottlePolicy;
    use access_identity_oauth::adapters::PgDirectory;
    use access_identity_oauth::app::Discovery as RealmDiscovery;
    use access_identity_session::domain::session::SessionPolicy;
    use access_identity_ui::adapters::Outbox;
    use access_identity_ui::app::{Devices, Hosted};
    use access_local_client::http::{Http, Identity, leaf_der};
    use access_local_client::login::{Credential, sign_in};
    use access_local_client::passkey::{Passkey, relying_party};
    use access_local_client::support::{Episode, episode};

    use crate::bootstrap::governance::SUPPORT_DEVICE_LABEL;
    use crate::login::{HsmKits, RealmKeks};

    let (w, signer) = World::open("bootstrap-support-episode", true).await;
    let signer = signer.unwrap();
    schedule(&signer);
    schedule(&signer);
    crate::jobs::open_now(&w.db.app, &w.db.archive, "bootstrap-support-episode").await;
    let plan = fixtures_plan();
    let first = serde_json::to_value(w.run(&plan).await).unwrap();
    schedule(&signer);
    schedule(&signer);
    let user = &first["test_user"];
    let support = &first["support_operator"];

    let tls = test_tls("access.test");
    let hosted = Arc::new(Hosted {
        kits: HsmKits::new(
            RealmKeks::new(Arc::clone(&w.keys)),
            w.db.router.clone(),
            w.db.app.clone(),
            SessionPolicy::DEFAULT,
        ),
        db: w.db.app.clone(),
        products: w.db.reader.clone(),
        clock: SystemClock,
        messages: Outbox,
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: Hasher::new(HasherConfig::sized(
            Argon2Params::CANONICAL,
            cores(),
            cgroup_memory_budget(),
        )),
        redirect_to: String::from("/"),
        hooks: Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
    });
    let discovery = || {
        RealmDiscovery::new(
            PgDirectory::new(w.db.router.clone()),
            SignerKeys::new(w.identity_signer.clone()),
        )
    };
    let courier = Arc::new(Courier {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        signer: SignerKeys::new(w.identity_signer.clone()),
        ingest: access_authority_ingest::app::Ingest::new(
            w.domains.clone(),
            crate::ingest::PgSubmissions(w.db.app.clone()),
            crate::ingest::Trusted(tokio::sync::Mutex::new(SourcesClock::new(w.db.app.clone()))),
        ),
        clock: SystemClock,
    });
    let app = login_router(discovery(), hosted.clone(), None)
        .merge(me_router(
            discovery(),
            hosted.clone(),
            Devices {
                signer: SignerKeys::new(w.identity_signer.clone()),
                instances: w.plane.clone(),
                approvals: w.plane.clone(),
                claims: Arc::clone(&courier),
                pep: String::from(IDENTITY_PEP),
            },
        ))
        .merge(support_router(
            discovery(),
            hosted,
            w.plane.clone(),
            String::from(IDENTITY_PEP),
        ))
        .merge(adp_router(
            access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        ));
    let config = access_http::tls::server_config(
        tls.server_cert.as_bytes(),
        tls.server_key.as_bytes(),
        Some(tls.ca.as_bytes()),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let served = tokio::spawn(access_http::tls::serve(listener, config, app, async {
        let _ = stopped.await;
    }));

    let pin = Secret::new(String::from(PIN));
    let token = KeyStore::open(&w.module, &w.label, &pin).unwrap();
    let device = token.signer(local::TEST_DEVICE_LABEL).unwrap();
    let operator_device = token.signer(SUPPORT_DEVICE_LABEL).unwrap();
    let passkey_key = token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let identity = Identity {
        chain_pem: tls.pep_cert.clone().into_bytes(),
        key_pem: tls.pep_key.clone().into_bytes(),
    };
    let leaf = leaf_der(&identity.chain_pem).unwrap();
    let http = Http::new(tls.ca.as_bytes(), Some(&identity), Some(addr)).unwrap();
    let issuer = user["issuer"].as_str().unwrap();
    let (rp_id, origin) = relying_party(issuer).unwrap();
    let passkey = Passkey {
        key: &passkey_key,
        rp_id: &rp_id,
        origin: &origin,
    };
    let operator = plan.support_operator.as_ref().unwrap();
    let domain = Digest(
        <[u8; 32]>::try_from(
            access_kernel::json::b64url_decode(first["sample"]["domain"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap(),
    );
    let done = episode(
        &http,
        &Episode {
            issuer,
            api_base: "https://access.test",
            pep_leaf_der: &leaf,
            domain,
            operator: &operator.identifier,
            operator_password: operator.password.expose(),
            operator_device: &operator_device,
            operator_party: id_of(support["party"].as_str().unwrap()),
            person: user["identifier"].as_str().unwrap(),
            person_subject: user["subject"].as_str().unwrap(),
            person_party: id_of(user["party"].as_str().unwrap()),
            person_passkey: &passkey,
            person_device: &device,
            case_system: &operator.case_system,
            case: &operator.case,
        },
    )
    .await
    .unwrap();
    assert!(done["exercise"].is_string(), "{done}");

    // §8.16, X37, Ek B 5613
    let mut jar = sign_in(
        &http,
        issuer,
        user["identifier"].as_str().unwrap(),
        Credential::Passkey(&passkey),
    )
    .await
    .unwrap();
    let r = http
        .request(
            "GET",
            &format!("{issuer}/v1/me/support-access"),
            &[("Cookie", jar.header().as_str())],
            None,
        )
        .await
        .unwrap();
    jar.take(&r);
    assert_eq!(r.status, 200, "{}", r.text());
    let access = r.json();
    let row = &access["access"][0];
    assert_eq!(row["state"], "active", "{access}");
    assert_eq!(row["operator"], "Mehmet Y.");
    assert_eq!(row["organization"], "Acme Support");
    assert_eq!(row["case"], "4411");
    assert_eq!(row["basis"]["holding"]["grant"], done["grant"]);
    assert!(row["revoke"].is_object(), "{row}");

    let _ = stop.send(());
    let _ = served.await;
    w.domains.release().await;
}
