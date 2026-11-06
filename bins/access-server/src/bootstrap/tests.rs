#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::large_futures,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use access_authority_core::adapters::{Domains, OsSalts, Setup};
use access_authority_sequencer::LEASE_TTL;
use access_authority_sequencer::adapters::SourcesClock;
use access_identity_oauth::adapters::SignerKeys;
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_identity_signer::adapters::{DirVault, SealedFactory, now_ms, serve};
use access_identity_signer::service::Service;
use access_store::tenancy::tenants_after;
use access_store::testing::{TestDb, fresh};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;
use tokio::net::UnixListener;

use super::*;
use crate::idp::{ActorBindings, Plane, RealmKeyring};
use crate::login::kek_label;
use crate::testing::hsm;

const PIN: &str = "1234-test-only";

type TestPlane = Plane<KeyStore, ActorBindings, OsSalts, SourcesClock>;

type AuthoritySigner = Arc<
    Mutex<
        access_authority_signer::service::Service<
            access_authority_signer::adapters::SealedFactory<SoftKek>,
            access_authority_signer::adapters::HsmBindings,
            access_authority_signer::adapters::DirVault,
        >,
    >,
>;

/// A real authority signer on a Unix socket, its binding keys in `store`, with the production
/// policy but a zero publish lead: the test runs the key schedule itself.
fn authority_signer(name: &str, store: KeyStore) -> (PathBuf, AuthoritySigner) {
    use access_authority_signer::adapters as signer;
    let dir = std::env::temp_dir().join(format!("abs-auth-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let policy = Policy {
        publish_lead_ms: 0,
        ..Policy::AUTHORITY
    };
    let service = Arc::new(Mutex::new(
        access_authority_signer::service::Service::start(
            signer::SealedFactory::new(SoftKek::new("authority-kek", [8; 32])),
            signer::HsmBindings::new(store),
            signer::DirVault::new(&dir),
            policy,
            signer::now_ms(),
        )
        .unwrap(),
    ));
    let path = dir.join("a.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(signer::serve(
        listener,
        Arc::clone(&service),
        vec![uid],
        signer::now_ms,
    ));
    (path, service)
}

/// One round of every keyring's schedule, as the signer runs it on its own.
fn schedule(signer: &AuthoritySigner) {
    let now = access_authority_signer::adapters::now_ms();
    assert_eq!(signer.lock().unwrap().tick(now, now), Vec::<Digest>::new());
}

/// A real identity signer on a Unix socket in a fresh directory.
fn identity_signer(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("abs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let service = Service::start(
        SealedFactory::new(SoftKek::new("realm-kek", [7; 32])),
        DirVault::new(&dir),
        Policy::REALM,
    )
    .unwrap();
    let path = dir.join("s.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        listener,
        Arc::new(Mutex::new(service)),
        vec![uid],
        now_ms,
    ));
    path
}

/// The bootstrap's world. Its token handles are never dropped: unloading `SoftHSM` after it
/// used OpenSSL leaves OpenSSL's exit handler behind in some hosts' loaders, and the test
/// process then crashes at exit.
struct World {
    db: TestDb,
    plane: TestPlane,
    domains: Arc<TestDomains>,
    keys: Arc<KeyStore>,
    keyring: RealmKeyring,
    base: RealmBase,
    module: PathBuf,
    label: String,
}

type TestDomains = Domains<KeyStore, ActorBindings, OsSalts, SourcesClock>;

/// One process's authority plane over `db`: its own lease holder name and actor bindings.
fn process(
    db: &TestDb,
    keys: KeyStore,
    holder: &str,
    signer: Option<PathBuf>,
) -> (Arc<TestDomains>, TestPlane) {
    let actors = ActorBindings::default();
    let domains = Arc::new(Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys,
        holder: String::from(holder),
        ttl: LEASE_TTL,
        binding: actors.clone(),
        salts: OsSalts,
        clock: SourcesClock::new(db.sequencer.clone()),
        deriver: db.deriver.clone(),
        signer,
        api_base: String::from("https://access.test"),
    }));
    let plane = Plane::new(
        domains.clone(),
        db.app.clone(),
        SourcesClock::new(db.sequencer.clone()),
        actors,
    );
    Box::leak(Box::new(domains.clone()));
    (domains, plane)
}

impl World {
    async fn new(name: &str) -> Self {
        Self::open(name, false).await.0
    }

    /// With an authority signer when `with_signer`.
    async fn open(name: &str, with_signer: bool) -> (Self, Option<AuthoritySigner>) {
        let db = fresh().await.unwrap();
        let (module, label) = hsm(name);
        let pin = Secret::new(String::from(PIN));
        let open = || KeyStore::open(&module, &label, &pin).unwrap();
        let (signer, service) = if with_signer {
            let (path, service) = authority_signer(name, open());
            (Some(path), Some(service))
        } else {
            (None, None)
        };
        let (domains, plane) = process(&db, open(), "bootstrap-test", signer);
        let keys = Arc::new(open());
        Box::leak(Box::new(keys.clone()));
        let keyring = RealmKeyring::new(SignerKeys::new(identity_signer(name)), keys.clone());
        let world = Self {
            db,
            plane,
            domains,
            keys,
            keyring,
            base: RealmBase::parse("https://access.test").unwrap(),
            module,
            label,
        };
        (world, service)
    }

    /// Another process over the same database and token, as `serve` beside a one-shot job.
    fn other_process(&self, holder: &str) -> (Arc<TestDomains>, TestPlane) {
        let pin = Secret::new(String::from(PIN));
        let keys = KeyStore::open(&self.module, &self.label, &pin).unwrap();
        process(&self.db, keys, holder, None)
    }

    /// A new tenant's realm `slug` with the bootstrap root as founder, created through the
    /// admin path alone.
    async fn admin_realm(
        &self,
        slug: &str,
    ) -> (TenantId, access_identity_admin::app::CreatedRealm) {
        let ids = cell_ids(&self.db.app, &self.keys).await.unwrap();
        let declared = DeclaredTargets::default();
        let bootstrap = Bootstrap {
            app: &self.db.app,
            router: &self.db.router,
            plane: &self.plane,
            realm_keys: &self.keyring,
            hsm: &self.keys,
            base: &self.base,
            declared: &declared,
        };
        let admin = bootstrap.admin(&ids, None);
        let tenant = create_tenant(&self.db.app, PLACEMENT).await.unwrap();
        let root = root_party(&root_key(&self.keys).unwrap().public_key());
        let created = admin
            .create_realm(&NewRealm {
                tenant,
                slug,
                style: IssuerStyle::Path,
                placement: PLACEMENT,
                root: Root::Sole(root),
                ct3_delay_s: None,
                schemas: Vec::new(),
                acceptances: Vec::new(),
            })
            .await
            .unwrap();
        (tenant, created)
    }

    async fn run(&self, plan: &Plan) -> Summary {
        let summary = Bootstrap {
            app: &self.db.app,
            router: &self.db.router,
            plane: &self.plane,
            realm_keys: &self.keyring,
            hsm: &self.keys,
            base: &self.base,
            declared: &DeclaredTargets::default(),
        }
        .run(plan)
        .await
        .unwrap();
        self.domains.release().await;
        summary
    }
}

fn client_key() -> PublicKey {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    PublicKey::P256(key.public_key().as_ref().to_vec())
}

fn plan() -> Plan {
    Plan {
        platform: String::from("platform"),
        tenants: vec![String::from("acme")],
        style: Style::Path,
        products: vec![ProductPlan {
            product: PlatformProduct::Work,
            display_name: String::from("Suiss Work"),
            client_key: client_key(),
            service_key: PublicKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            event_receiver: Some(String::from("https://work.test/ssf")),
            redirect_uri: RedirectUri::parse("https://work.test/cb").unwrap(),
        }],
        sample: None,
        test_user: None,
        compromise: None,
    }
}

/// The plan with the local fixtures of OP-149 m.26 (b), (c).
fn local_plan() -> Plan {
    Plan {
        test_user: Some(TestUserPlan {
            realm: String::from("acme"),
            identifier: String::from("Test.User@acme.example"),
            password: Secret::new(String::from("correct horse battery staple")),
            client_display_name: String::from("Local test client"),
            redirect_uri: RedirectUri::parse("http://127.0.0.1/cb").unwrap(),
            breach_ranges_dir: None,
        }),
        compromise: Some(CompromisePlan {
            realm: String::from("acme"),
        }),
        ..plan()
    }
}

/// The identity outbox events of `kind`, at least `n` of them, within a bounded wait.
/// The queued identity events of `kind` once `done` holds for them; the outbox reader only
/// shows rows below the cluster-wide snapshot horizon, so concurrent test databases delay
/// visibility and their order.
async fn identity_events_until(
    db: &TestDb,
    kind: &str,
    done: impl Fn(&[access_store::identity::OutboxEvent]) -> bool,
    what: &str,
) -> Vec<access_store::identity::OutboxEvent> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let queued: Vec<_> = access_store::identity::poll(
            &db.reader,
            access_store::identity::Cursor::default(),
            100,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind.starts_with(kind))
        .collect();
        if done(&queued) {
            return queued;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{} {kind}, not yet {what} after 20 s",
            queued.len()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

struct Now;

impl access_authority_ingest::ports::Clock for Now {
    fn now(&self) -> impl Future<Output = Result<u64, Unavailable>> + Send {
        std::future::ready(Ok(u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap()))
    }
}

// OP-149 m.26 (b), (c), TN-49, L2-CLM-5, MD-14: the bootstrap makes the test user with a
// password and the public client once, accepts the local declarant's party_compromise Claims so
// a PEP's unsigned declaration is admitted, and a second run finds all of it; the one-shot
// client changes commit idp.client.update and idp.client.retire and queue their events
#[tokio::test]
async fn local_fixtures_are_made_once_and_produce_events() {
    use access_identity_account::adapters::pg::PgAccounts;
    use access_identity_account::app::accounts::PASSWORD;
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    use access_internal_api::claims::{Carrier, ClaimIngest as _, ClaimSubmission, ClaimVerdict};
    use access_kernel::claim::Channel;

    let w = World::new("bootstrap-local").await;
    let plan = local_plan();
    let first = w.run(&plan).await;
    let user = first.test_user.clone().unwrap();
    let acme = first.realms.iter().find(|r| r.slug == "acme").unwrap();
    assert!(user.created);
    assert_eq!(user.identifier, "Test.User@acme.example");
    assert_eq!(user.issuer, acme.issuer);
    assert!(user.subject.starts_with("usr_"));
    assert_eq!(user.redirect_uri, "http://127.0.0.1/cb");
    let json = serde_json::to_value(&first).unwrap();
    assert!(json["test_user"].get("password").is_none());
    assert!(!format!("{plan:?}").contains("correct horse"));

    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let accounts = PgAccounts(w.db.app.clone());
    let mut tx = accounts.begin(route.tenant, route.realm).await.unwrap();
    let subject = tx
        .subject_by_identifier("Test.User@acme.example")
        .await
        .unwrap()
        .unwrap();
    let row = tx.subject(subject, false).await.unwrap().unwrap();
    assert_eq!(row.status, "active");
    assert_eq!(tx.credentials(subject, PASSWORD).await.unwrap().len(), 1);
    tx.commit().await.unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let client = idp::client(&mut t, &user.client_id).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert!(client.active);
    assert_eq!(client.auth_method, "none");
    assert_eq!(
        client.redirect_uris,
        vec![String::from("http://127.0.0.1/cb")]
    );
    assert_eq!(client.platform_product, None);

    // OP-149 m.26 (c): the declarant's unsigned Claim over a PEP channel is admitted
    let compromise = first.compromise.clone().unwrap();
    assert!(compromise.created);
    assert_eq!(compromise.domain, acme.domain);
    assert_eq!(compromise.class, "party_compromise");
    let domain = Digest(
        <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&compromise.domain).unwrap())
            .unwrap(),
    );
    let issuer = Id(<[u8; 16]>::try_from(
        access_kernel::json::b64url_decode(&compromise.issuer).unwrap(),
    )
    .unwrap());
    let now = server_time(&w.db.app).await.unwrap();
    for day in [now / 86_400_000 - 1, now / 86_400_000, now / 86_400_000 + 1] {
        access_store::claims::open_claim_ingest_day(&w.db.archive, u32::try_from(day).unwrap())
            .await
            .unwrap();
    }
    let channel = Channel::Pep([0x5a; 32]);
    let statement = access_kernel::claim::Statement {
        domain,
        issuer,
        subject: Id([0x77; 16]),
        class: String::from(access_kernel::claim::PARTY_COMPROMISE),
        value: None,
        issued_at: now,
        validity: Window {
            from: 0,
            until: u64::MAX,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    };
    let claim = access_kernel::claim::Unsigned {
        statement: statement.clone(),
        channel,
    }
    .to_bytes()
    .unwrap();
    let ingest = access_authority_ingest::app::Ingest::new(
        w.domains.clone(),
        crate::ingest::PgSubmissions(w.db.app.clone()),
        Now,
    );
    let submission = |claim: Vec<u8>| ClaimSubmission {
        domain,
        carrier: Carrier::Unsigned(channel),
        claim,
        body: None,
        evidence: None,
    };
    let verdict = ingest.ingest(submission(claim.clone())).await.unwrap();
    assert!(
        matches!(
            verdict,
            ClaimVerdict::Admitted {
                replayed: false,
                ..
            }
        ),
        "{verdict:?}"
    );
    // another issuer is not accepted
    let stranger = access_kernel::claim::Unsigned {
        statement: access_kernel::claim::Statement {
            issuer: Id([0x66; 16]),
            ..statement
        },
        channel,
    }
    .to_bytes()
    .unwrap();
    assert!(matches!(
        ingest.ingest(submission(stranger)).await.unwrap(),
        ClaimVerdict::Quarantined { .. }
    ));
    w.domains.release().await;

    let second = w.run(&plan).await;
    let again = second.test_user.unwrap();
    assert!(!again.created);
    assert_eq!(
        (again.subject, again.client_id),
        (user.subject, user.client_id)
    );
    let accepted = second.compromise.unwrap();
    assert!(!accepted.created);
    assert_eq!(accepted.issuer, compromise.issuer);

    // OP-149 m.26 (c), m.4: the platform client changes
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &DeclaredTargets::default(),
    };
    let updated = bootstrap
        .change_product_client(
            &plan,
            "work",
            local::ProductChange::Update {
                display_name: String::from("Suiss Work 2"),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.action, "idp.client.update");
    assert_eq!(updated.event, "api_client.updated");
    assert_eq!(updated.client_id, first.clients[0].client_id);
    let platform = route_by_slug(&w.db.router, "platform")
        .await
        .unwrap()
        .unwrap();
    let mut t = TenantTx::begin(&w.db.app, platform.tenant, platform.realm)
        .await
        .unwrap();
    let row = idp::client(&mut t, &updated.client_id)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        (row.display_name.as_str(), row.active),
        ("Suiss Work 2", true)
    );
    assert!(
        bootstrap
            .change_product_client(&plan, "relay", local::ProductChange::Retire)
            .await
            .is_err()
    );
    let retired = bootstrap
        .change_product_client(&plan, "work", local::ProductChange::Retire)
        .await
        .unwrap();
    assert_eq!(retired.event, "api_client.disabled");
    let mut t = TenantTx::begin(&w.db.app, platform.tenant, platform.realm)
        .await
        .unwrap();
    assert!(
        !idp::client(&mut t, &retired.client_id)
            .await
            .unwrap()
            .unwrap()
            .active
    );
    t.commit().await.unwrap();
    let has = |events: &[access_store::identity::OutboxEvent], kind: &str| {
        events.iter().any(|e| e.kind == kind)
    };
    let events = identity_events_until(
        &w.db,
        "event.api_client.",
        |q| has(q, "event.api_client.updated") && has(q, "event.api_client.disabled"),
        "updated and disabled",
    )
    .await;
    assert!(has(&events, "event.api_client.created"));
    // a retired client has no active row to change
    assert!(
        bootstrap
            .change_product_client(&plan, "work", local::ProductChange::Retire)
            .await
            .is_err()
    );
    w.domains.release().await;
}

// OP-149 m.28 (a), OP-31, TI-2: a one-shot client change commits while another process, as
// `serve`, leads the platform domain and renews its lease. The lease is not taken from the live
// leader: it hands the domain over at its next renewal, the one-shot leads it for its commit,
// and the leader leads again on its next request. A commit without the handoff is unavailable
// with the reason `lease-held`
#[tokio::test]
async fn a_one_shot_change_commits_while_another_process_leads() {
    use access_authority_core::CoreError;
    use access_internal_api::instances::{terminate_intent, terminate_payload};

    let w = World::new("bootstrap-handoff").await;
    let plan = plan();
    let first = w.run(&plan).await;
    let platform = first.realms.iter().find(|r| r.platform).unwrap();
    let domain = Digest(
        <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&platform.domain).unwrap())
            .unwrap(),
    );
    let (serve, _serve_plane) = w.other_process("serve");
    serve.consistency(domain).await.unwrap();
    let renewing = {
        let serve = Arc::clone(&serve);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                serve.renew().await;
            }
        })
    };
    assert!(matches!(
        w.domains.consistency(domain).await,
        Err(CoreError::Unavailable("lease-held"))
    ));
    let instance = Id([7; 16]);
    let validity = Window {
        from: 0,
        until: u64::MAX,
    };
    let request = Request {
        domain,
        mode: Mode::Commit,
        nonce: vec![9; 16],
        intent: terminate_intent(instance, validity).unwrap(),
        payload: Some(terminate_payload(instance)),
        basis: bootstrap_basis(&domain),
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    };
    let refused = MetaExercises::meta(&w.plane, request, vec![0xd2], String::from(IDENTITY_PEP))
        .await
        .unwrap_err();
    assert_eq!(refused.0, "lease-held");

    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &DeclaredTargets::default(),
    };
    let updated = bootstrap
        .change_product_client(
            &plan,
            "work",
            local::ProductChange::Update {
                display_name: String::from("Suiss Work 2"),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.event, "api_client.updated");
    assert_eq!(updated.client_id, first.clients[0].client_id);
    assert!(matches!(
        serve.consistency(domain).await,
        Err(CoreError::Unavailable("lease-held"))
    ));
    w.domains.release().await;
    serve.consistency(domain).await.unwrap();
    renewing.abort();
    serve.release().await;
}

// OP-69, OP-149 m.21, TN-111, L0-META-7, OP-149 m.4, MD-14, EI-25, OP-137: the bootstrap creates
// the platform tenant, a sample tenant and the Work client through the identity plane's paths,
// and a second run finds all of it and creates nothing
#[tokio::test]
async fn the_bootstrap_is_idempotent() {
    let w = World::new("bootstrap").await;
    let plan = plan();
    let first = w.run(&plan).await;
    assert_eq!(first.realms.len(), 2);
    let json = serde_json::to_value(&first).unwrap();
    assert_eq!(json["v"], 1);
    for key in [
        "tenant",
        "realm",
        "slug",
        "issuer",
        "discovery",
        "domain",
        "platform",
        "created",
    ] {
        assert!(json["realms"][0].get(key).is_some(), "{key}");
    }
    assert!(first.realms.iter().all(|r| r.created));
    let platform = &first.realms[0];
    assert!(platform.platform && !first.realms[1].platform);
    assert_eq!(platform.issuer, "https://access.test/realms/platform");
    assert_eq!(
        platform.discovery,
        "https://access.test/realms/platform/.well-known/suiss-configuration"
    );
    assert!(platform.tenant.starts_with("tnt_"));
    assert_eq!(platform.realm.len(), 36);
    assert_eq!(first.clients.len(), 1);
    assert!(first.clients[0].created);
    assert_eq!(first.clients[0].audience, platform.issuer);

    let second = w.run(&plan).await;
    assert!(second.realms.iter().all(|r| !r.created));
    assert!(second.clients.iter().all(|c| !c.created));
    assert_eq!(second.root.party, first.root.party);
    assert_eq!(second.clients[0].client_id, first.clients[0].client_id);
    for (a, b) in first.realms.iter().zip(&second.realms) {
        assert_eq!(
            (&a.tenant, &a.realm, &a.domain, &a.issuer),
            (&b.tenant, &b.realm, &b.domain, &b.issuer)
        );
    }
    assert_eq!(
        tenants_after(&w.db.router, None, 100).await.unwrap().len(),
        2
    );

    for r in &second.realms {
        let route = route_by_slug(&w.db.router, &r.slug).await.unwrap().unwrap();
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let g = idp::governance(&mut t).await.unwrap().unwrap();
        t.commit().await.unwrap();
        // L0-META-7: the root's Instance is registered once in each governing domain
        let challenge =
            root_challenge(&root_key(&w.keys).unwrap(), Digest(*g.domain.as_bytes())).unwrap();
        for nonce in [challenge.clone(), register_nonce(&challenge)] {
            let row = find_nonce(&w.db.app, &g.domain, &nonce)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(row.outcome, "allow");
        }
        // OP-146 m.16 (m)
        assert!(w.keys.kek(&kek_label(route.realm.as_bytes())).is_ok());
    }

    let route = route_by_slug(&w.db.router, "platform")
        .await
        .unwrap()
        .unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let row = idp::client(&mut t, &second.clients[0].client_id)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    assert!(row.active);
    assert_eq!(row.auth_method, "private_key_jwt");
    assert_eq!(row.platform_product.as_deref(), Some("work"));
    assert_eq!(row.event_receiver.as_deref(), Some("https://work.test/ssf"));
}

// OP-149 m.4: a product client is registered only in the platform tenant's realm, never in a
// sample tenant's
#[tokio::test]
async fn product_clients_live_in_the_platform_realm() {
    let w = World::new("bootstrap-platform").await;
    let summary = w.run(&plan()).await;
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let there = idp::client(&mut t, &summary.clients[0].client_id)
        .await
        .unwrap();
    t.commit().await.unwrap();
    assert!(there.is_none());
}

// OP-149 m.20: a plan names one public key per file, as a JWK or a one-key JWKS
#[test]
fn plan_keys_are_one_public_jwk() {
    let dir = std::env::temp_dir().join(format!("abs-jwk-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let okp = r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#;
    let one = dir.join("one.jwk");
    std::fs::write(&one, okp).unwrap();
    assert!(matches!(jwk(&one), Ok(PublicKey::Ed25519(_))));
    let set = dir.join("set.jwks");
    std::fs::write(&set, format!(r#"{{"keys":[{okp}]}}"#)).unwrap();
    assert!(matches!(jwk(&set), Ok(PublicKey::Ed25519(_))));
    let two = dir.join("two.jwks");
    std::fs::write(&two, format!(r#"{{"keys":[{okp},{okp}]}}"#)).unwrap();
    assert!(jwk(&two).is_err());
    let private = dir.join("private.jwk");
    std::fs::write(
        &private,
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}"#,
    )
    .unwrap();
    assert!(jwk(&private).is_err());
}

// OP-69, TI-9: a plan is checked whole; an unknown key is refused
#[test]
fn plans_refuse_unknown_settings() {
    let dir = std::env::temp_dir().join(format!("abs-plan-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ok = dir.join("ok.toml");
    std::fs::write(
        &ok,
        "platform = \"platform\"\ntenants = [\"acme\"]\nissuer_style = \"path\"\n",
    )
    .unwrap();
    let plan = Plan::load(&ok).unwrap();
    assert_eq!(plan.style, Style::Path);
    assert_eq!(plan.tenants, vec![String::from("acme")]);
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "platform = \"platform\"\nskip_signatures = true\n").unwrap();
    assert!(Plan::load(&bad).is_err());
    assert!(Plan::load(&dir.join("missing.toml")).is_err());
}

// OP-149 m.22 (g), OP-141 m.18 (d), m.22 (d), TN-111: a realm created through the admin path
// alone has its domain's event-id and token keys, and the domain can be led at once
#[tokio::test]
async fn admin_realm_creation_opens_the_domain_keys() {
    let w = World::new("bootstrap-admin-realm").await;
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let declared = DeclaredTargets::default();
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
    };
    let admin = bootstrap.admin(&ids, None);
    let tenant = create_tenant(&w.db.app, PLACEMENT).await.unwrap();
    let created = admin
        .create_realm(&NewRealm {
            tenant,
            slug: "keys",
            style: IssuerStyle::Path,
            placement: PLACEMENT,
            root: Root::Sole(Id([4; 16])),
            ct3_delay_s: None,
            schemas: Vec::new(),
            acceptances: Vec::new(),
        })
        .await
        .unwrap();
    let d = created.domain;
    assert!(w.keys.mac(&access_crypto::event_id::label(&d.0)).is_ok());
    assert!(w.keys.aead(&access_crypto::token::label(&d.0)).is_ok());
    assert!(w.domains.consistency(d).await.is_ok());
    w.domains.release().await;
}

// OP-149 m.5, SAI-46, CR-25, CR-59, OP-146 m.16 (m): a realm created through the admin path
// opens its domain's keyring at Genesis, where its founding operational key signs at once, so
// signed key lookups are answered from the realm's creation on, with no schedule round between
#[tokio::test]
async fn admin_realms_sign_key_lookups_from_genesis() {
    use access_authority_core::keys::AsOf;
    let (w, signer) = World::open("bootstrap-key-lookup", true).await;
    let signer = signer.unwrap();
    let (tenant, created) = w.admin_realm("lookups").await;
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    let kid = thumbprint(&root.public_key());
    let declared = DeclaredTargets::default();
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
    };

    schedule(&signer);
    schedule(&signer);
    bootstrap
        .onboard(tenant, created.realm, created.domain, &root, party)
        .await
        .unwrap();
    let answer = w
        .domains
        .lookup_keys(created.domain, &[kid], AsOf::Head, true)
        .await
        .unwrap();
    let (sign1, excerpt) = answer.signed.unwrap();
    assert!(!sign1.is_empty() && !excerpt.is_empty());
    assert_eq!(answer.lookup.keys.len(), 1);

    let (fresh_tenant, fresh) = w.admin_realm("fresh").await;
    bootstrap
        .onboard(fresh_tenant, fresh.realm, fresh.domain, &root, party)
        .await
        .unwrap();
    let at_once = w
        .domains
        .lookup_keys(fresh.domain, &[kid], AsOf::Head, true)
        .await
        .unwrap();
    let (sign1, excerpt) = at_once.signed.unwrap();
    assert!(!sign1.is_empty() && !excerpt.is_empty());
    w.domains.release().await;
}

/// The plan of the local deployment's Work sample.
fn sample_plan() -> Plan {
    Plan {
        sample: Some(SamplePlan {
            realm: String::from("acme"),
            namespace: String::from("work"),
            action: String::from("approve"),
        }),
        ..plan()
    }
}

/// The eligibility body a product sends for `subject` from a bootstrap summary's sample.
fn eligibility_body(sample: &serde_json::Value, subject: &str, now: u64) -> Vec<u8> {
    serde_json::json!({
        "subject": subject,
        "set": {
            "domain": sample["domain"],
            "intent": {
                "action": sample["action"],
                "resources": [sample["resource"]],
                "validity": { "from": now.saturating_sub(60_000), "until": now.saturating_add(60_000) },
            },
            "basis": sample["basis"],
            "capacity": "own",
        },
    })
    .to_string()
    .into_bytes()
}

// OP-149 m.10, OP-141 m.35 (c), OP-69: the sample realm's Genesis publishes the Work catalog,
// its root grants the sample action to the sample subject by a grant_issue Exercise, and the
// summary is what an eligibility check names: the subject is eligible, another Party is not,
// and a second run issues nothing new
#[tokio::test]
async fn the_bootstrapped_sample_is_eligible() {
    use access_http::adp::app::{Reply, Service};
    let w = World::new("bootstrap-sample").await;
    let plan = sample_plan();
    let first = w.run(&plan).await;
    let json = serde_json::to_value(&first).unwrap();
    let sample = &json["sample"];
    assert_eq!(sample["realm"], "acme");
    assert_eq!(sample["action"]["namespace"], "work");
    let acme = first.realms.iter().find(|r| r.slug == "acme").unwrap();
    assert_eq!(sample["domain"], acme.domain.as_str());

    let adp = Service::new(w.domains.clone(), 64 * 1024);
    let now = server_time(&w.db.app).await.unwrap();
    let subject = sample["subject"].as_str().unwrap();
    let pep = || Some(String::from("work"));
    let eligible = adp
        .eligibility(&eligibility_body(sample, subject, now), pep())
        .await;
    let Reply::Decision(v) = eligible else {
        panic!("{eligible:?}");
    };
    assert_eq!(v["eligible"], true, "{v}");
    let other = b64url_encode(&[0x5a; 16]);
    let refused = adp
        .eligibility(&eligibility_body(sample, &other, now), pep())
        .await;
    let Reply::Decision(v) = refused else {
        panic!("{refused:?}");
    };
    assert_eq!(v["eligible"], false);
    w.domains.release().await;

    let second = w.run(&plan).await;
    assert_eq!(serde_json::to_value(&second).unwrap()["sample"], *sample);
}

/// A plan file with its key paths moved under `keys`, where a P-256 client key and an Ed25519
/// service key are written for the products it names.
fn shipped(path: &Path, keys: &Path) -> Plan {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    let p256 = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let point = p256.public_key().as_ref();
    let client = serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(&point[1..33]),
        "y": b64url_encode(&point[33..65]),
    });
    let service = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": b64url_encode(
            ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .as_bytes()
        ),
    });
    std::fs::write(keys.join("work-client.jwk"), client.to_string()).unwrap();
    std::fs::write(keys.join("work-service.jwk"), service.to_string()).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    let local = keys.join(path.file_name().unwrap());
    // OP-149 m.26 (b): the shipped plans take the test password from the environment
    assert!(
        text.contains("password_env = \"BOOTSTRAP_TEST_PASSWORD\""),
        "{}",
        path.display()
    );
    assert!(!text.contains("\npassword = "), "{}", path.display());
    std::fs::write(
        &local,
        text.replace("/etc/access/products", keys.to_str().unwrap())
            .replace(
                "password_env = \"BOOTSTRAP_TEST_PASSWORD\"",
                "password = \"only for this test\"",
            ),
    )
    .unwrap();
    Plan::load(&local).unwrap()
}

// OP-69, OP-149 m.21, IDP-7, OP-149 m.23: every plan the local deployment ships loads, and each
// product client it registers passes the checks of idp.client.register
#[test]
fn every_shipped_plan_is_valid() {
    let dir = Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/compose/access"
    ));
    let keys = std::env::temp_dir().join(format!("abs-shipped-{}", std::process::id()));
    std::fs::create_dir_all(&keys).unwrap();
    let mut plans = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        if !(name.starts_with("bootstrap")
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("toml")))
        {
            continue;
        }
        plans += 1;
        let plan = shipped(&path, &keys);
        assert_eq!(plan.platform, "platform", "{name}");
        // OP-149 m.26 (b), (c): every shipped plan has the test user and the declarant
        let user = plan.test_user.as_ref().unwrap();
        assert_eq!(user.realm, "acme", "{name}");
        assert_eq!(plan.compromise.as_ref().unwrap().realm, "acme", "{name}");
        for p in &plan.products {
            let id = ClientId::parse("cli_0123456789abcdefghjkmnpqrs").unwrap();
            assert_eq!(
                p.client(id).check(&DeclaredTargets::default()),
                Ok(()),
                "{name}"
            );
        }
    }
    assert!(plans >= 2);
}

// OP-69, OP-141 m.35 (a): a sample names one of the plan's tenants and a catalog entry the
// kernel accepts, outside the namespaces Access publishes itself
#[test]
fn a_sample_names_a_tenant_and_a_valid_action() {
    let dir = std::env::temp_dir().join(format!("abs-sample-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let plan = |name: &str, realm: &str, namespace: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "platform = 'platform'\ntenants = ['acme']\n[sample]\nrealm = '{realm}'\nnamespace = '{namespace}'\naction = 'approve'\n"
            ),
        )
        .unwrap();
        Plan::load(&path)
    };
    assert!(plan("other", "other", "work").is_err());
    assert!(plan("access", "acme", "access").is_err());
    assert!(plan("idp", "acme", "idp.client").is_err());
    assert!(plan("upper", "acme", "Work").is_err());
    assert!(plan("ok", "acme", "work").unwrap().sample.is_some());
}

// OP-149 m.26 (b), TI-9: the test user names one of the plan's tenants and takes its password
// from exactly one place, the plan or a named environment variable that is set; never a default
#[test]
fn a_test_user_takes_its_password_from_one_named_place() {
    let dir = std::env::temp_dir().join(format!("abs-test-user-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let plan = |name: &str, realm: &str, password: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "platform = 'platform'\ntenants = ['acme']\n[test_user]\nrealm = '{realm}'\nidentifier = 'test@acme.example'\nredirect_uri = 'http://127.0.0.1/cb'\n{password}\n[compromise]\nrealm = '{realm}'\n"
            ),
        )
        .unwrap();
        Plan::load(&path)
    };
    let ok = plan("ok", "acme", "password = 'correct horse battery'").unwrap();
    assert_eq!(
        ok.test_user.as_ref().unwrap().identifier,
        "test@acme.example"
    );
    assert_eq!(ok.compromise.as_ref().unwrap().realm, "acme");
    assert!(plan("other", "other", "password = 'x'").is_err());
    assert!(plan("none", "acme", "").is_err());
    assert!(plan("empty", "acme", "password = ''").is_err());
    assert!(plan("both", "acme", "password = 'x'\npassword_env = 'Y'").is_err());
    assert!(
        plan(
            "unset",
            "acme",
            "password_env = 'ACCESS_TEST_UNSET_VARIABLE_A22'"
        )
        .is_err()
    );
    assert!(
        plan(
            "https",
            "acme",
            "password = 'x'\nredirect_uri = 'http://evil.example/cb'"
        )
        .is_err()
    );
}
