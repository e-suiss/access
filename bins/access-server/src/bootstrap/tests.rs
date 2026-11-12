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

/// The prefix of a world whose identity signer keeps the realm's post-quantum keys in the
/// HSM (OP-159 m.3 (d)); every other world seals them under the realm KEK.
pub(super) const PQ_IN_TOKEN: &str = "pq-token-";

/// A real identity signer on a Unix socket in a fresh directory.
fn identity_signer(name: &str, keys: &Arc<KeyStore>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("abs-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sealed = SealedFactory::new(SoftKek::new("realm-kek", [7; 32]));
    let factory: Box<dyn access_identity_signer::ports::KeyFactory + Send> =
        if name.starts_with(PQ_IN_TOKEN) {
            Box::new(access_identity_signer::adapters::token::TokenPq::new(
                sealed,
                keys.clone(),
            ))
        } else {
            Box::new(sealed)
        };
    let service = Service::start(factory, DirVault::new(&dir), Policy::REALM).unwrap();
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
    identity_signer: PathBuf,
}

type TestDomains = Domains<KeyStore, ActorBindings, OsSalts, SourcesClock>;

/// One process's authority plane over `db`: its own lease holder name and actor bindings.
fn process(
    db: &TestDb,
    keys: KeyStore,
    holder: &str,
    signer: Option<PathBuf>,
) -> (Arc<TestDomains>, TestPlane) {
    process_rung(db, keys, holder, signer, None)
}

/// [`process`], its leaders ringing `bell` after each durable commit (OP-156 m.3 (j)).
fn process_rung(
    db: &TestDb,
    keys: KeyStore,
    holder: &str,
    signer: Option<PathBuf>,
    bell: Option<Arc<dyn suiss_ledger::doorbell::Bell>>,
) -> (Arc<TestDomains>, TestPlane) {
    process_analysed(
        db,
        keys,
        holder,
        signer,
        bell,
        Arc::new(access_authority_core::ports::NoAnalysis),
    )
}

/// [`process_rung`] with `analysis` behind the `policy.set` analysis port (OP-159 m.3 (aa)).
fn process_analysed(
    db: &TestDb,
    keys: KeyStore,
    holder: &str,
    signer: Option<PathBuf>,
    bell: Option<Arc<dyn suiss_ledger::doorbell::Bell>>,
    analysis: Arc<dyn access_authority_core::ports::PolicyAnalysis>,
) -> (Arc<TestDomains>, TestPlane) {
    let actors = ActorBindings::default();
    let domains = Domains::new(Setup {
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
        analysis,
    });
    let domains = Arc::new(match bell {
        Some(b) => domains.with_bell(b),
        None => domains,
    });
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
        Self::open_rung(name, with_signer, None).await
    }

    /// [`World::open`], its leaders ringing `bell` (OP-156 m.3 (j)).
    async fn open_rung(
        name: &str,
        with_signer: bool,
        bell: Option<Arc<dyn suiss_ledger::doorbell::Bell>>,
    ) -> (Self, Option<AuthoritySigner>) {
        Self::open_on(name, with_signer, bell, fresh().await.unwrap())
    }

    /// [`World::open_rung`] over `db`, such as one on a replicated test cell (OP-158 m.3 (n)).
    fn open_on(
        name: &str,
        with_signer: bool,
        bell: Option<Arc<dyn suiss_ledger::doorbell::Bell>>,
        db: TestDb,
    ) -> (Self, Option<AuthoritySigner>) {
        Self::open_analysed(
            name,
            with_signer,
            bell,
            db,
            Arc::new(access_authority_core::ports::NoAnalysis),
        )
    }

    /// [`World::open_on`] with `analysis` behind the `policy.set` analysis port (OP-159 m.3 (aa)).
    fn open_analysed(
        name: &str,
        with_signer: bool,
        bell: Option<Arc<dyn suiss_ledger::doorbell::Bell>>,
        db: TestDb,
        analysis: Arc<dyn access_authority_core::ports::PolicyAnalysis>,
    ) -> (Self, Option<AuthoritySigner>) {
        let (module, label) = hsm(name);
        let pin = Secret::new(String::from(PIN));
        let open = || KeyStore::open(&module, &label, &pin).unwrap();
        let (signer, service) = if with_signer {
            let (path, service) = authority_signer(name, open());
            (Some(path), Some(service))
        } else {
            (None, None)
        };
        let (domains, plane) =
            process_analysed(&db, open(), "bootstrap-test", signer, bell, analysis);
        let keys = Arc::new(open());
        Box::leak(Box::new(keys.clone()));
        let identity_signer = identity_signer(name, &keys);
        let keyring = RealmKeyring::new(SignerKeys::new(identity_signer.clone()), keys.clone());
        let world = Self {
            db,
            plane,
            domains,
            keys,
            keyring,
            base: RealmBase::parse("https://access.test").unwrap(),
            module,
            label,
            identity_signer,
        };
        (world, service)
    }

    /// A second install in this process (OP-158 m.3 (l)): its own database, its own `SoftHSM`
    /// token `token` made before this process first opened the module (the module lists the
    /// tokens once), and its own authority signer.
    async fn open_install(name: &str, token: (PathBuf, String)) -> (Self, AuthoritySigner) {
        let db = fresh().await.unwrap();
        let (module, label) = token;
        let pin = Secret::new(String::from(PIN));
        let open = || KeyStore::open(&module, &label, &pin).unwrap();
        let (path, service) = authority_signer(name, open());
        let (domains, plane) = process_rung(&db, open(), "second-install", Some(path), None);
        let keys = Arc::new(open());
        Box::leak(Box::new(keys.clone()));
        let identity_signer = identity_signer(name, &keys);
        let keyring = RealmKeyring::new(SignerKeys::new(identity_signer.clone()), keys.clone());
        let world = Self {
            db,
            plane,
            domains,
            keys,
            keyring,
            base: RealmBase::parse("https://access.test").unwrap(),
            module,
            label,
            identity_signer,
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
        self.admin_realm_timed(slug, None).await
    }

    /// [`World::admin_realm`] with the CT3 time-lock `ct3_delay_s` (OP-141 m.34 (d)).
    async fn admin_realm_timed(
        &self,
        slug: &str,
        ct3_delay_s: Option<u64>,
    ) -> (TenantId, access_identity_admin::app::CreatedRealm) {
        self.admin_realm_with(slug, ct3_delay_s, None).await
    }

    /// [`World::admin_realm_timed`] whose meta-anchor carries `recovery` (OP-158 m.3 (m)).
    async fn admin_realm_with(
        &self,
        slug: &str,
        ct3_delay_s: Option<u64>,
        recovery: Option<access_kernel::recovery::RecoveryEntry>,
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
            console: None,
        };
        let admin = bootstrap.admin(&ids, None);
        let tenant = create_tenant(&self.db.app, PLACEMENT).await.unwrap();
        let root = root_party(&root_key(&self.keys).unwrap().public_key());
        let created = admin
            .create_realm_with(
                &NewRealm {
                    tenant,
                    slug,
                    style: IssuerStyle::Path,
                    placement: PLACEMENT,
                    root: Root::Sole(root),
                    ct3_delay_s,
                    causal_binding: false,
                    schemas: Vec::new(),
                    acceptances: Vec::new(),
                    issuer_predicate_input: Vec::new(),
                    provisioned_by: None,
                },
                recovery,
            )
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
            console: None,
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
            product: PlatformProduct::parse("work").unwrap(),
            display_name: String::from("Suiss Work"),
            client_key: client_key(),
            service_key: PublicKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            event_receiver: Some(String::from("https://work.test/ssf")),
            redirect_uris: vec![
                RedirectUri::parse("https://work.test/cb").unwrap(),
                RedirectUri::parse("http://127.0.0.1:8190/v1/access/approval").unwrap(),
            ],
        }],
        sample: None,
        test_user: None,
        compromise: None,
        sample_agent: None,
        support_operator: None,
        breakglass_account: None,
        review_schedule: None,
        pq_profile: None,
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
            totp: None,
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

// OP-149 m.26 (b), (c), TN-49, L2-CLM-5, MD-14
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
    let accounts = PgAccounts::sealed(
        w.db.app.clone(),
        crate::login::RealmKeks::new(w.keys.clone())
            .vault(route.realm)
            .unwrap(),
    );
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

    // OP-149 m.28 (b), m.16 (a), OP-150 m.12 (d)
    {
        use crate::product::PgSubjects;
        use access_http::product::ports::{Sector, SubjectQuery, Subjects as _};
        let party =
            <[u8; 16]>::try_from(access_kernel::json::b64url_decode(&user.party).unwrap()).unwrap();
        let instance =
            <[u8; 16]>::try_from(access_kernel::json::b64url_decode(&user.instance).unwrap())
                .unwrap();
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        assert_eq!(
            idp::subject_party(&mut t, &subject).await.unwrap(),
            Some(party)
        );
        assert_eq!(
            access_store::issuer::subject_instance(&mut t, &subject)
                .await
                .unwrap(),
            Some(instance)
        );
        let sub = t
            .pairwise(subject, client.client_uuid, &b64url_encode(&[1; 32]))
            .await
            .unwrap();
        t.commit().await.unwrap();
        let acme_domain = Digest(
            <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&acme.domain).unwrap())
                .unwrap(),
        );
        let status = w
            .domains
            .lookup_parties(
                acme_domain,
                &[Id(party)],
                access_authority_core::keys::AsOf::Head,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            status.lookup.parties[0].actor_kind,
            access_kernel::meta::ActorKind::Human
        );
        let subjects = PgSubjects {
            app: w.db.app.clone(),
            domains: w.domains.clone(),
        };
        let resolved = subjects
            .resolve(
                *route.tenant.as_bytes(),
                *route.realm.as_bytes(),
                Sector::RealmClient(&user.client_id),
                SubjectQuery::Subs(vec![sub.clone()]),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resolved.pairs, vec![(party, sub.clone())]);
        let back = subjects
            .resolve(
                *route.tenant.as_bytes(),
                *route.realm.as_bytes(),
                Sector::RealmClient(&user.client_id),
                SubjectQuery::Parties(vec![party]),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(back.pairs, vec![(party, sub)]);
        let has = |events: &[access_store::identity::OutboxEvent], kind: &str| {
            events.iter().any(|e| e.kind == kind)
        };
        identity_events_until(
            &w.db,
            "claim.",
            |q| has(q, "claim.identity_binding_person") && has(q, "claim.authenticator_binding"),
            "binding claims",
        )
        .await;
        w.domains.release().await;
    }

    // OP-149 m.26 (c)
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

    // OP-149 m.26 (c), m.4
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &DeclaredTargets::default(),
        console: None,
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
    assert!(
        bootstrap
            .change_product_client(&plan, "work", local::ProductChange::Retire)
            .await
            .is_err()
    );
    w.domains.release().await;
}

// OP-149 m.28 (a), OP-31, TI-2
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
        console: None,
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

// OP-69, OP-149 m.21, TN-111, L0-META-7, OP-149 m.4, MD-14, EI-25, OP-137
/// The test user's TOTP credentials and the seeds they hold, in base32.
async fn totp_seeds(w: &World, identifier: &str) -> Vec<String> {
    use access_identity_account::adapters::pg::PgAccounts;
    use access_identity_account::app::Realm;
    use access_identity_account::app::sealing::{open, subject_key};
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    use access_identity_events::adapters::RealmKek as _;
    use access_identity_session::app::TOTP;

    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let keks = crate::login::RealmKeks::new(w.keys.clone());
    let kek = keks.kek(route.tenant, route.realm).unwrap();
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let scope = Realm {
        tenant: route.tenant,
        realm: route.realm,
        kek: &*kek,
        ids: &ids,
    };
    let accounts = PgAccounts::sealed(w.db.app.clone(), keks.vault(route.realm).unwrap());
    let mut tx = accounts.begin(route.tenant, route.realm).await.unwrap();
    let subject = tx.subject_by_identifier(identifier).await.unwrap().unwrap();
    let row = tx.subject(subject, false).await.unwrap().unwrap();
    let dek = subject_key(&scope, &row).unwrap();
    let seeds = tx
        .credentials(subject, TOTP)
        .await
        .unwrap()
        .iter()
        .map(|c| {
            let hex = open(&scope, &dek, &subject, TOTP, &c.sealed).unwrap();
            let raw: Vec<u8> = (0..hex.expose().len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex.expose()[i..i + 2], 16).unwrap())
                .collect();
            access_identity_session::domain::codes::base32(&raw)
        })
        .collect();
    tx.commit().await.unwrap();
    seeds
}

// OP-149 m.26 (b), §10.2.2, TI-9
#[tokio::test]
async fn the_test_users_authenticator_app_is_enrolled_once_and_its_seed_kept_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;

    let w = World::new("bootstrap-totp").await;
    let dir = std::env::temp_dir().join(format!("abs-totp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("test-user-totp");
    std::fs::write(
        &path,
        "left over from somewhere else, and longer than a seed\n",
    )
    .unwrap();
    let mut plan = local_plan();
    let open = || TotpSeedFile::open(&path).unwrap();
    plan.test_user.as_mut().unwrap().totp = Some(open());
    assert!(!plan.test_user.as_ref().unwrap().totp.as_ref().unwrap().held);

    let first = w.run(&plan).await;
    let totp = first.test_user.as_ref().unwrap().totp.clone().unwrap();
    assert!(totp.created);
    assert_eq!(totp.seed_file, path.display().to_string());
    assert_eq!((totp.algorithm, totp.digits, totp.period), ("SHA1", 6, 30));
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    let text = std::fs::read_to_string(&path).unwrap();
    let seed = text.strip_suffix('\n').unwrap().to_owned();
    assert!(is_seed(&seed), "{text:?}");
    let summary = serde_json::to_string(&first).unwrap();
    assert!(!summary.contains(&seed));
    assert!(!format!("{plan:?}").contains(&seed));
    assert_eq!(
        totp_seeds(&w, "Test.User@acme.example").await,
        vec![seed.clone()]
    );

    plan.test_user.as_mut().unwrap().totp = Some(open());
    assert!(plan.test_user.as_ref().unwrap().totp.as_ref().unwrap().held);
    let second = w.run(&plan).await;
    assert!(!second.test_user.unwrap().totp.unwrap().created);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    assert_eq!(
        totp_seeds(&w, "Test.User@acme.example").await,
        vec![seed.clone()]
    );

    std::fs::write(&path, "").unwrap();
    plan.test_user.as_mut().unwrap().totp = Some(open());
    let third = w.run(&plan).await;
    assert!(third.test_user.unwrap().totp.unwrap().created);
    let renewed = std::fs::read_to_string(&path).unwrap();
    let renewed = renewed.strip_suffix('\n').unwrap();
    assert_ne!(renewed, seed);
    let mut seeds = totp_seeds(&w, "Test.User@acme.example").await;
    seeds.sort();
    let mut expected = vec![seed, renewed.to_owned()];
    expected.sort();
    assert_eq!(seeds, expected);
    std::fs::remove_dir_all(&dir).unwrap();
}

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
    // OP-149 m.35
    assert_eq!(
        first.clients[0].redirect_uris,
        [
            "https://work.test/cb",
            "http://127.0.0.1:8190/v1/access/approval"
        ]
    );
    assert_eq!(first.clients[0].redirect_uri, "https://work.test/cb");

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
        // L0-META-7
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
    // OP-149 m.35
    assert_eq!(
        row.redirect_uris,
        [
            "https://work.test/cb",
            "http://127.0.0.1:8190/v1/access/approval"
        ]
    );
}

// OP-149 m.4
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

// OP-149 m.20
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

// OP-69, TI-9
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

// OP-150 m.3 (m), MUST-NEVER-13, XI-18
#[test]
fn a_plan_registers_any_product_name() {
    // OP-149 m.4, OP-69
    let dir = std::env::temp_dir().join(format!("abs-product-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let key = dir.join("key.jwk");
    std::fs::write(
        &key,
        r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
    )
    .unwrap();
    let plan = |name: &str, product: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "platform = 'platform'\ntenants = ['acme']\n[[products]]\nproduct = '{product}'\nclient_key = '{k}'\nservice_key = '{k}'\nredirect_uri = 'https://product.example/cb'\n",
                k = key.display()
            ),
        )
        .unwrap();
        Plan::load(&path)
    };
    for ok in ["work", "relay", "one", "acme-ledger"] {
        let p = plan(ok, ok).unwrap();
        assert_eq!(p.products[0].product.name(), ok);
        assert_eq!(p.products[0].display_name, ok);
    }
    for bad in ["Work", "acme_ledger", "a", "urn:suiss:work"] {
        assert!(plan("bad", bad).is_err(), "{bad}");
    }
    // OP-149 m.35, RFC 6749 §3.1.2, RFC 8252
    let uris = |name: &str, keys: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "platform = 'platform'\ntenants = ['acme']\n[[products]]\nproduct = 'work'\nclient_key = '{k}'\nservice_key = '{k}'\n{keys}\n",
                k = key.display()
            ),
        )
        .unwrap();
        Plan::load(&path).map(|p| {
            p.products[0]
                .redirect_uris
                .iter()
                .map(|u| u.as_str().to_owned())
                .collect::<Vec<_>>()
        })
    };
    assert_eq!(
        uris(
            "list",
            "redirect_uris = ['https://work.localhost/v1/access/approval', 'http://127.0.0.1:8190/v1/access/approval']"
        )
        .unwrap(),
        [
            "https://work.localhost/v1/access/approval",
            "http://127.0.0.1:8190/v1/access/approval"
        ]
    );
    assert_eq!(
        uris(
            "one",
            "redirect_uri = 'https://work.localhost/v1/access/approval'"
        )
        .unwrap(),
        ["https://work.localhost/v1/access/approval"]
    );
    assert!(uris("none", "").is_err());
    assert!(uris("empty", "redirect_uris = []").is_err());
    assert!(
        uris(
            "both",
            "redirect_uri = 'https://a.example/cb'\nredirect_uris = ['https://b.example/cb']"
        )
        .is_err()
    );
    assert!(
        uris(
            "repeat",
            "redirect_uris = ['https://a.example/cb', 'https://a.example/cb']"
        )
        .is_err()
    );
    assert!(
        uris(
            "plain-http",
            "redirect_uris = ['https://a.example/cb', 'http://work.example/v1/access/approval']"
        )
        .is_err()
    );
}

// OP-149 m.22 (g), OP-141 m.18 (d), m.22 (d), TN-111
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
        console: None,
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
            causal_binding: false,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await
        .unwrap();
    let d = created.domain;
    assert!(w.keys.mac(&access_crypto::event_id::label(&d.0)).is_ok());
    assert!(w.keys.aead(&access_crypto::token::label(&d.0)).is_ok());
    assert!(w.domains.consistency(d).await.is_ok());
    w.domains.release().await;
}

// OP-152 m.5 (i), OP-149 m.29 (b), SI-5, §10.1.4 rule 3
#[tokio::test]
async fn admin_realms_accept_issuer_authentication_by_default() {
    let (w, _) = World::open("bs-predicate", false).await;
    let (_, created) = w.admin_realm("defaults").await;
    let gates: Vec<access_kernel::claim::Gate> =
        access_store::authority::state(&w.db.sequencer, &DomainId::from_bytes(created.domain.0))
            .await
            .unwrap()
            .into_iter()
            .filter_map(|r| r.value)
            .filter_map(|v| {
                suiss_crypto::dcbor::decode(&v, suiss_crypto::dcbor::Limits::CEILING).ok()
            })
            .filter_map(|v| meta::ContentState::from_value(&v).ok())
            .filter_map(|c| access_kernel::claim::Gate::of(&c.content).ok())
            .collect();
    let issuer = gates
        .iter()
        .find(|g| g.use_ == access_kernel::claim::ACTOR_BINDING && g.issuer.is_some())
        .and_then(|g| g.issuer)
        .unwrap();
    assert!(gates.iter().any(|g| g.issuer == Some(issuer)
        && g.use_ == access_kernel::claim::PREDICATE_INPUT
        && g.classes == [String::from("authentication")]));
    w.domains.release().await;
}

// OP-149 m.5, SAI-46, CR-25, CR-59, OP-146 m.16 (m)
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
        console: None,
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

// OP-149 m.28 (c), m.8, L0-META-7
#[tokio::test]
async fn admin_realms_answer_party_lookups() {
    use access_authority_core::keys::AsOf;
    use access_kernel::meta::ActorKind;
    let (w, signer) = World::open("bootstrap-party-lookup", true).await;
    let signer = signer.unwrap();
    let (tenant, created) = w.admin_realm("parties").await;
    let root = root_key(&w.keys).unwrap();
    let party = root_party(&root.public_key());
    let declared = DeclaredTargets::default();
    let bootstrap = Bootstrap {
        app: &w.db.app,
        router: &w.db.router,
        plane: &w.plane,
        realm_keys: &w.keyring,
        hsm: &w.keys,
        base: &w.base,
        declared: &declared,
        console: None,
    };
    schedule(&signer);
    let before = w
        .domains
        .lookup_parties(created.domain, &[party], AsOf::Head, false)
        .await
        .unwrap();
    assert_eq!(before.lookup.parties, Vec::new());
    assert_eq!(before.lookup.unknown, vec![party]);
    bootstrap
        .onboard(tenant, created.realm, created.domain, &root, party)
        .await
        .unwrap();
    let answer = w
        .domains
        .lookup_parties(created.domain, &[party, Id([0x42; 16])], AsOf::Head, true)
        .await
        .unwrap();
    let (sign1, excerpt) = answer.signed.clone().unwrap();
    assert!(!sign1.is_empty() && !excerpt.is_empty());
    assert_eq!(answer.lookup.unknown, vec![Id([0x42; 16])]);
    let [entry] = answer.lookup.parties.as_slice() else {
        panic!("{:?}", answer.lookup.parties);
    };
    assert_eq!((entry.party, entry.actor_kind), (party, ActorKind::Human));
    assert!(entry.ended.is_none());
    let register = register_nonce(&root_challenge(&root, created.domain).unwrap());
    let recorded = find_nonce(
        &w.db.app,
        &DomainId::from_bytes(created.domain.0),
        &register,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(entry.since.pos, recorded.decision_pos);
    let log = access_store::authority::read_log(
        &w.db.app,
        &DomainId::from_bytes(created.domain.0),
        entry.since.pos,
        entry.since.pos,
    )
    .await
    .unwrap();
    assert_eq!(entry.since.at, log[0].recorded_at);
    let earlier = w
        .domains
        .lookup_parties(
            created.domain,
            &[party],
            AsOf::Position(entry.since.pos - 1),
            false,
        )
        .await
        .unwrap();
    assert_eq!(earlier.lookup.unknown, vec![party]);
    assert!(matches!(
        w.domains
            .lookup_parties(created.domain, &[party], AsOf::Position(1_000), false)
            .await,
        Err(access_authority_core::CoreError::Unavailable("consistency"))
    ));
    w.domains.release().await;
}

/// The plan of the local deployment's Work sample.
fn sample_plan() -> Plan {
    Plan {
        sample: Some(SamplePlan {
            realm: String::from("acme"),
            namespace: String::from("work"),
            action: String::from("approve"),
            allowed: None,
            resource_namespace: String::from("work.ledger"),
            resource_path_prefix: String::from("led_"),
            step_up: None,
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

// OP-149 m.10, OP-141 m.35 (c), OP-69
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
        .eligibility(&eligibility_body(sample, subject, now), pep(), None)
        .await;
    let Reply::Decision(v) = eligible else {
        panic!("{eligible:?}");
    };
    assert_eq!(v["eligible"], true, "{v}");
    let other = b64url_encode(&[0x5a; 16]);
    let refused = adp
        .eligibility(&eligibility_body(sample, &other, now), pep(), None)
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
    // OP-149 m.26 (b)
    assert!(
        text.contains("password_env = \"BOOTSTRAP_TEST_PASSWORD\""),
        "{}",
        path.display()
    );
    assert!(!text.contains("\npassword = "), "{}", path.display());
    std::fs::write(
        &local,
        text.replace("/etc/access/products", keys.to_str().unwrap())
            .replace("/var/lib/access/bootstrap", keys.to_str().unwrap())
            .replace(
                "password_env = \"BOOTSTRAP_TEST_PASSWORD\"",
                "password = \"only for this test\"",
            ),
    )
    .unwrap();
    Plan::load(&local).unwrap()
}

// OP-69, OP-149 m.21, IDP-7, OP-149 m.23
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
        // OP-149 m.26 (b), (c)
        let user = plan.test_user.as_ref().unwrap();
        assert_eq!(user.realm, "acme", "{name}");
        assert_eq!(
            user.totp.as_ref().map(|t| t.path.clone()),
            Some(keys.join("test-user-totp")),
            "{name}"
        );
        assert_eq!(plan.compromise.as_ref().unwrap().realm, "acme", "{name}");
        // OP-157 m.6 (i)
        if name == "bootstrap.toml" {
            assert_eq!(plan.support_operator.as_ref().unwrap().realm, "acme");
            assert_eq!(plan.breakglass_account.as_ref().unwrap().realm, "acme");
            assert_eq!(plan.review_schedule.as_ref().unwrap().realm, "acme");
        }
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

// OP-69, OP-141 m.35 (a)
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
    let ok = plan("ok", "acme", "work").unwrap().sample.unwrap();
    // OP-149 m.30 (a)
    assert_eq!(ok.resource_namespace, "work.ledger");
    assert_eq!(ok.resource_path_prefix, "led_");
    let resource = |name: &str, namespace: &str, prefix: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "platform = 'platform'\ntenants = ['acme']\n[sample]\nrealm = 'acme'\nnamespace = 'work'\naction = 'approve'\nresource_namespace = '{namespace}'\nresource_path_prefix = '{prefix}'\n"
            ),
        )
        .unwrap();
        Plan::load(&path)
    };
    let named = resource("named", "shop.orders", "ord-")
        .unwrap()
        .sample
        .unwrap();
    assert_eq!(named.resource_namespace, "shop.orders");
    assert_eq!(named.resource_path_prefix, "ord-");
    assert!(resource("meta", "access", "led_").is_err());
    assert!(resource("idp", "idp.client", "led_").is_err());
    assert!(resource("upper-ns", "Work.ledger", "led_").is_err());
    assert!(resource("empty-prefix", "work.ledger", "").is_err());
    // OP-149 m.33 (c)
    assert_eq!(ok.step_up, None);
    let stepped = |name: &str, allowed: &str, step_up: &str| {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(
            &path,
            format!(
                "platform = 'platform'\ntenants = ['acme']\n[sample]\nrealm = 'acme'\nnamespace = 'work'\naction = 'approve'\n{allowed}step_up = '{step_up}'\n[test_user]\nrealm = 'acme'\nidentifier = 'test@acme.example'\nredirect_uri = 'http://127.0.0.1/cb'\npassword = 'correct horse battery staple'\n"
            ),
        )
        .unwrap();
        Plan::load(&path)
    };
    assert_eq!(
        stepped("aal2", "allowed = 'commit'\n", "aal2")
            .unwrap()
            .sample
            .unwrap()
            .step_up,
        Some(StepUp::Aal2)
    );
    assert!(stepped("aal3", "allowed = 'commit'\n", "aal3").is_err());
    assert!(stepped("no-allowed", "", "aal2").is_err());
}

// OP-149 m.26 (b), TI-9
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

/// The plan with the allowed Exercise of OP-149 m.29 (b): the test user may `work:commit` under
/// an approval it contributes itself.
fn approve_plan(step_up: Option<StepUp>) -> Plan {
    Plan {
        sample: Some(SamplePlan {
            realm: String::from("acme"),
            namespace: String::from("work"),
            action: String::from("approve"),
            allowed: Some(String::from("commit")),
            resource_namespace: String::from("work.ledger"),
            resource_path_prefix: String::from("led_"),
            step_up,
        }),
        ..local_plan()
    }
}

/// A test CA with a server leaf for `host` and a PEP client leaf, PEM.
struct TestTls {
    ca: String,
    server_cert: String,
    server_key: String,
    pep_cert: String,
    pep_key: String,
}

fn test_tls(host: &str) -> TestTls {
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca_pem = ca.self_signed(&ca_key).unwrap().pem();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let mut server = rcgen::CertificateParams::new(vec![host.to_owned()]).unwrap();
    server.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = rcgen::KeyPair::generate().unwrap();
    let server_cert = server.signed_by(&server_key, &issuer).unwrap();
    let mut pep = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    pep.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    pep.distinguished_name
        .push(rcgen::DnType::CommonName, "work-pep");
    let pep_key = rcgen::KeyPair::generate().unwrap();
    let pep_cert = pep.signed_by(&pep_key, &issuer).unwrap();
    TestTls {
        ca: ca_pem,
        server_cert: server_cert.pem(),
        server_key: server_key.serialize_pem(),
        pep_cert: pep_cert.pem(),
        pep_key: pep_key.serialize_pem(),
    }
}

/// A 16-byte id from the summary's base64url.
fn id_of(text: &str) -> Id {
    Id(<[u8; 16]>::try_from(access_kernel::json::b64url_decode(text).unwrap()).unwrap())
}

/// A holding from the summary's `basis`.
fn holding_of(basis: &serde_json::Value) -> HoldingRef {
    let h = &basis["holding"];
    HoldingRef {
        grant: id_of(h["grant"].as_str().unwrap()),
        holder: id_of(h["holder"].as_str().unwrap()),
        since: h["since"].as_u64().unwrap(),
    }
}

/// An intent of the allowed action over `ledger`, as a product writes it for the ADP: the
/// resource is `ledger` under the summary's path prefix (OP-149 m.30 (a)).
fn commit_intent(allowed: &serde_json::Value, ledger: &str, now: u64) -> serde_json::Value {
    let resource = &allowed["resource"];
    let prefix = resource["path_prefix"].as_str().unwrap();
    serde_json::json!({
        "action": allowed["action"],
        "resources": [{
            "namespace": resource["namespace"],
            "path": [format!("{prefix}{ledger}")],
        }],
        "params": {
            "ledger": { "eq": ledger },
            "declaration": { "eq": { "bytes": b64url_encode(&[0xd1; 32]) } },
        },
        "validity": { "from": now.saturating_sub(60_000), "until": now.saturating_add(600_000) },
    })
}

// OP-149 m.29 (b), m.26 (e), m.9, §9.14.1, §9.14.5, §9.8, §13.7.3
#[tokio::test]
async fn the_local_client_approves_an_allowed_exercise() {
    approval_through_the_local_client("bootstrap-approve", None).await;
}

// OP-149 m.33 (c), §13.7.3, §8.17.5.4
#[tokio::test]
async fn the_local_client_approves_an_allowed_exercise_with_a_step_up() {
    approval_through_the_local_client("bootstrap-approve-step-up", Some(StepUp::Aal2)).await;
}

async fn approval_through_the_local_client(world: &str, step_up: Option<StepUp>) {
    use access_http::adp::adapters::{Discovery, router as adp_router};
    use access_http::login::{me_router, router as login_router};
    use access_http::product::adapters::router as product_router;
    use access_http::product::ports::{AssertionRefused, ClientAssertions, PlatformClient};
    use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};

    /// This server has no platform clients: every assertion is refused.
    struct NoAssertions;

    impl ClientAssertions for NoAssertions {
        fn authenticate(
            &self,
            _: &str,
            _: &str,
        ) -> impl std::future::Future<Output = Result<PlatformClient, AssertionRefused>> + Send
        {
            std::future::ready(Err(AssertionRefused::Unauthenticated))
        }
    }
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
    use access_identity_ui::app::Devices;
    use access_identity_ui::app::Hosted;
    use access_local_client::approve::{Approve, approve};
    use access_local_client::claims::{Compromise, declare};
    use access_local_client::http::{Http, Identity, leaf_der};
    use access_local_client::login::{Credential, sign_in};
    use access_local_client::passkey::{Passkey, relying_party};
    use suiss_crypto::signer::SoftSigner;

    use crate::login::{HsmKits, RealmKeks};
    use crate::product::{PgSubjects, PgTenants};

    let (w, signer) = World::open(world, true).await;
    let signer = signer.unwrap();
    let plan = approve_plan(step_up);
    schedule(&signer);
    schedule(&signer);
    let first = w.run(&plan).await;
    schedule(&signer);
    schedule(&signer);
    // OP-146 m.5 (f)
    let today = i32::try_from(server_time(&w.db.app).await.unwrap() / 86_400_000).unwrap();
    for o in access_store::ephemeral::open_days(&w.db.archive, today, 1).await {
        o.result.unwrap();
    }
    let user = first.test_user.clone().unwrap();
    let allowed = serde_json::to_value(user.allowed.clone().unwrap()).unwrap();
    assert_eq!(allowed["action"]["name"], "commit");
    assert_eq!(allowed["params"]["ledger"], "text");
    // OP-149 m.30 (a)
    assert_eq!(allowed["resource"]["namespace"], "work.ledger");
    assert_eq!(allowed["resource"]["path_prefix"], "led_");
    assert_eq!(allowed["contribution"]["class"], "approve");
    // OP-149 m.33 (c)
    assert_eq!(
        allowed.get("step_up").and_then(serde_json::Value::as_str),
        step_up.map(StepUp::word)
    );
    assert_eq!(
        allowed["basis"]["holding"]["holder"],
        serde_json::Value::from(user.party.clone())
    );
    assert_eq!(
        access_kernel::json::b64url_decode(&user.passkey)
            .unwrap()
            .len(),
        32
    );
    let acme = first.realms.iter().find(|r| r.slug == "acme").unwrap();
    assert_eq!(allowed["domain"], acme.domain.as_str());

    let tls = test_tls("access.test");
    let keks = RealmKeks::new(Arc::clone(&w.keys));
    let hosted = Arc::new(Hosted {
        kits: HsmKits::new(
            keks,
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
        hooks: std::sync::Arc::new(access_identity_hooks::ports::NoHooks),
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
    let ids = Arc::new(crate::ids::CellIds::new(Arc::clone(&w.keys)));
    let app = login_router(discovery(), hosted.clone(), None)
        .merge(me_router(
            discovery(),
            hosted,
            Devices {
                signer: SignerKeys::new(w.identity_signer.clone()),
                instances: w.plane.clone(),
                approvals: w.plane.clone(),
                claims: Arc::clone(&courier),
                pep: String::from(IDENTITY_PEP),
            },
        ))
        .merge(adp_router(
            access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        ))
        .merge(product_router(access_http::product::app::Service::new(
            w.domains.clone(),
            PgTenants::new(w.db.router.clone(), ids),
            PgSubjects {
                app: w.db.app.clone(),
                domains: w.domains.clone(),
            },
            NoAssertions,
            String::from("local"),
            String::from("https://access.test"),
        )))
        .merge(crate::ingest::routes(w.domains.clone(), w.db.app.clone()));
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
    let passkey_key = token.signer(local::TEST_PASSKEY_LABEL).unwrap();
    let identity = Identity {
        chain_pem: tls.pep_cert.clone().into_bytes(),
        key_pem: tls.pep_key.clone().into_bytes(),
    };
    let leaf = leaf_der(&identity.chain_pem).unwrap();
    let http = Http::new(tls.ca.as_bytes(), Some(&identity), Some(addr)).unwrap();
    let (rp_id, origin) = relying_party(&user.issuer).unwrap();
    let passkey = Passkey {
        key: &passkey_key,
        rp_id: &rp_id,
        origin: &origin,
    };
    let domain = Digest(
        <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&acme.domain).unwrap()).unwrap(),
    );
    let now = server_time(&w.db.app).await.unwrap();
    let intent = commit_intent(&allowed, "main", now);
    let request = Approve {
        issuer: &user.issuer,
        api_base: "https://access.test",
        redirect_uri: &user.redirect_uri,
        identifier: &user.identifier,
        passkey: &passkey,
        device: &device,
        pep_leaf_der: &leaf,
        domain,
        party: id_of(&user.party),
        instance: Some(id_of(&user.instance)),
        intent: &intent,
        basis: holding_of(&allowed["basis"]),
        contribution: holding_of(&allowed["contribution"]["basis"]),
        reason: "Close the main ledger for the period.",
        request: None,
        work_gate: None,
    };
    // (OP-149 m.26 (b), (c), (e))
    let password = local_plan().test_user.unwrap().password;
    sign_in(
        &http,
        &user.issuer,
        &user.identifier,
        Credential::Password(password.expose(), Some(&passkey)),
    )
    .await
    .unwrap();
    sign_in(
        &http,
        &user.issuer,
        &user.identifier,
        Credential::Passkey(&passkey),
    )
    .await
    .unwrap();
    let sample = first.sample.clone().unwrap();
    let compromise = first.compromise.clone().unwrap();
    let declared = declare(
        &http,
        &Compromise {
            api_base: "https://access.test",
            domain: Digest(
                <[u8; 32]>::try_from(
                    access_kernel::json::b64url_decode(&compromise.domain).unwrap(),
                )
                .unwrap(),
            ),
            issuer: id_of(&compromise.issuer),
            party: id_of(&sample.subject),
            occurred_at: None,
            pep_leaf_der: &leaf,
        },
    )
    .await
    .unwrap();
    assert_eq!(declared["disposition"], "admit", "{declared}");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut answered = 0;
    loop {
        answered += courier.step().await.unwrap().answered;
        if answered >= 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{answered} sign-in Claims answered after 20 s"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let done = approve(&http, &request).await.unwrap();
    assert_eq!(done["receipt"]["verified"], true, "{done}");
    // OP-149 m.32
    assert_eq!(
        done["instance"],
        serde_json::Value::from(user.instance.clone())
    );
    assert_eq!(done["render_digest_verified"], true, "{done}");
    assert_eq!(
        access_kernel::json::b64url_decode(done["exercise"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    // OP-149 m.33 (c)
    assert_eq!(done["step_up"], step_up.is_some(), "{done}");
    assert_eq!(
        access_kernel::json::b64url_decode(done["claim"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    assert_eq!(done["receipt"]["exercise"], done["exercise"]);
    assert_ne!(done["contribution"], done["exercise"]);
    assert_eq!(
        done["receipt"]["audience"],
        access_local_client::adp::pep_name(&leaf)
    );

    // OP-157 m.6 (i)
    let live = commit_intent(&allowed, "live", now);
    let pushed = access_local_client::approve::push_request(
        &http,
        &Approve {
            intent: &live,
            ..request
        },
    )
    .await
    .unwrap();
    assert_eq!(pushed["redirect_uri"], user.redirect_uri.as_str());
    let encode = |v: &serde_json::Value| -> String {
        v.as_str()
            .unwrap()
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    };
    let page = http
        .request(
            "GET",
            &format!(
                "{}/v1/approve?request={}&redirect_uri={}&state={}",
                user.issuer,
                encode(&pushed["request_uri"]),
                encode(&pushed["redirect_uri"]),
                encode(&pushed["state"]),
            ),
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(page.status, 200, "{}", page.text());
    // OP-157 m.6 (i), OP-150 m.3 (r)
    assert!(page.text().contains("<script src=\"approve/app.js\">"));
    let script = http
        .request(
            "GET",
            &format!("{}/v1/approve/app.js", user.issuer),
            &[],
            None,
        )
        .await
        .unwrap();
    assert_eq!(script.status, 200);
    assert!(script.text().contains("call(\"approve/flows\""));

    // §9.14.2, XI-7
    let other = commit_intent(&allowed, "other", now);
    let other_digest =
        access_kernel::intent::intent_digest(&access_local_client::intent::parse(&other).unwrap())
            .unwrap();
    let pushed = serde_json::json!({
        "requester": { "party": user.party },
        "action": other["action"],
        "resource": other["resources"][0],
        "params": other["params"],
        "capacity": "own",
        "reason": "Nothing waits for this one.",
        "require_action": {
            "domain": acme.domain,
            "nonce": b64url_encode(&[0x77; 16]),
            "intent": b64url_encode(&other_digest.0),
        },
        "expires_at": now + 3_600_000,
    });
    let changed = approve(
        &http,
        &Approve {
            intent: &other,
            request: Some(&pushed),
            work_gate: None,
            ..request
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        changed.contains("approval-request-changed") && changed.contains("409"),
        "{changed}"
    );

    // §10.2.4, CR-40
    let (stranger, _) = SoftSigner::generate_ed25519().unwrap();
    let forged = Passkey {
        key: &stranger,
        rp_id: &rp_id,
        origin: &origin,
    };
    let refused = approve(
        &http,
        &Approve {
            passkey: &forged,
            ..request
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        refused.contains("passkey") && refused.contains("401"),
        "{refused}"
    );

    let _ = stop.send(());
    let _ = served.await;
    w.domains.release().await;

    let second = w.run(&plan).await;
    let again = second.test_user.unwrap();
    assert!(!again.created);
    assert_eq!(again.passkey, user.passkey);
    assert_eq!(
        serde_json::to_value(again.allowed.unwrap()).unwrap(),
        allowed
    );
}

mod provision {
    use access_identity_admin::app::provision::{
        Created, Order, Platform, ProvisionError, Provisioned,
    };
    use access_identity_admin::domain::provision::{
        NotAvailable, PlatformChange, ProvisionInvalid, RealmOrder, Recovery, RecoveryKey,
        RecoveryKeys, SANDBOX_BUDGET,
    };
    use access_store::sandbox;

    use super::*;

    /// Signs `change` as the platform root and has the platform realm's domain commit it.
    async fn provision(
        w: &World,
        admin: &Admin<'_, TestPlane, TestPlane, RealmKeyring>,
        platform: &Platform<'_>,
        change: &PlatformChange,
        nonce: [u8; 16],
    ) -> Result<Provisioned, ProvisionError> {
        let root = root_key(&w.keys).unwrap();
        let m = Moment::at(server_time(&w.db.app).await.unwrap());
        let prepared = admin
            .prepare_provision(platform, change, m.validity)
            .await?;
        MetaExercises::lead(&w.plane, prepared.domain)
            .await
            .unwrap();
        let basis =
            ExerciseBasis::Anchor(meta::object_id(&prepared.domain, kind::ANCHOR, IDP_ANCHOR));
        let ais = sign(
            &root,
            &m.statement(prepared.domain, &nonce, prepared.digest, basis),
        )
        .unwrap();
        let order = Order {
            change,
            nonce: nonce.to_vec(),
            validity: m.validity,
            basis,
            capacity: Capacity::Own,
        };
        Box::pin(admin.provision(platform, order, ais)).await
    }

    fn realm(tenant: TenantId, slug: &str, root: Root, ack: bool) -> RealmOrder {
        RealmOrder {
            tenant: *tenant.as_bytes(),
            slug: String::from(slug),
            style: IssuerStyle::Path,
            placement: String::from(PLACEMENT),
            root,
            ct3_delay_s: None,
            causal_binding: false,
            acknowledge_no_recovery: ack,
            recovery: None,
        }
    }

    // TN-110, TN-111, OP-151 m.2 M2, m.3 (m)
    #[tokio::test]
    async fn platform_provisioning_commits_then_opens_a_genesis() {
        let w = World::new("provision").await;
        w.run(&plan()).await;
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
            console: None,
        };
        let admin = bootstrap.admin(&ids, None);
        let route = route_by_slug(&w.db.router, "platform")
            .await
            .unwrap()
            .unwrap();
        let platform = Platform {
            tenant: route.tenant,
            realm: route.realm,
            router: &w.db.router,
        };
        let founder = root_party(&root_key(&w.keys).unwrap().public_key());

        let tenant = TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap());
        let change = PlatformChange::Tenant {
            tenant: *tenant.as_bytes(),
            placement: String::from(PLACEMENT),
        };
        let Provisioned::Done { created, .. } = provision(&w, &admin, &platform, &change, [1; 16])
            .await
            .unwrap()
        else {
            panic!("tenant creation not allowed");
        };
        assert!(created == Created::Tenant(tenant));
        assert!(
            access_store::tenancy::tenant(&w.db.router, tenant)
                .await
                .unwrap()
                .is_some()
        );

        // TN-111, §13.7.7
        let sole = PlatformChange::Realm(realm(tenant, "solo", Root::Sole(founder), false));
        assert!(matches!(
            provision(&w, &admin, &platform, &sole, [2; 16]).await,
            Err(ProvisionError::Invalid(
                ProvisionInvalid::RecoveryNotAcknowledged
            ))
        ));

        let joint = Root::Joint {
            parties: [founder, Id([0x42; 16])].into_iter().collect(),
            k: 2,
        };
        // §13.6, SEC20, OP-158 m.3 (m), Ek B 6030
        let mut with_keys = realm(tenant, "shop", joint.clone(), false);
        with_keys.recovery = Some(RecoveryKeys {
            held_on: access_kernel::recovery::KeyHolding::Device,
            keys: [
                (founder, b"a".as_slice()),
                (founder, b"b"),
                (Id([0x42; 16]), b"c"),
            ]
            .into_iter()
            .map(|(party, seed)| RecoveryKey {
                party,
                kid: suiss_crypto::digest::sha256(seed),
            })
            .collect(),
        });
        let shop = PlatformChange::Realm(with_keys);
        let Provisioned::Done {
            exercise, created, ..
        } = provision(&w, &admin, &platform, &shop, [3; 16])
            .await
            .unwrap()
        else {
            panic!("realm creation not allowed");
        };
        let Created::Realm {
            realm: shop_realm,
            domain,
            recovery,
            sandbox: None,
            ..
        } = created
        else {
            panic!("not a production realm");
        };
        assert_eq!(
            recovery,
            Recovery::Available {
                threshold: 2,
                keys: 3
            }
        );
        let entry = access_store::authority::state_of(
            &w.db.app,
            &DomainId::from_bytes(domain.0),
            &[access_kernel::recovery::entry_key()],
        )
        .await
        .unwrap()
        .into_iter()
        .find_map(|r| r.value)
        .map(|v| {
            access_kernel::recovery::RecoveryEntry::from_value(
                &suiss_crypto::dcbor::decode(&v, suiss_crypto::dcbor::Limits::CEILING).unwrap(),
            )
            .unwrap()
        })
        .unwrap();
        assert_eq!((entry.threshold, entry.keys.len()), (2, 3));

        assert_eq!(
            access_identity_admin::domain::provision::recovery(&joint, None).0,
            Recovery::NotAvailable(NotAvailable::NoKeys)
        );
        // OP-149 m.29 (b), SI-5, §10.1.4 rule 3
        let gates: Vec<access_kernel::claim::Gate> =
            access_store::authority::state(&w.db.sequencer, &DomainId::from_bytes(domain.0))
                .await
                .unwrap()
                .into_iter()
                .filter_map(|r| r.value)
                .filter_map(|v| {
                    suiss_crypto::dcbor::decode(&v, suiss_crypto::dcbor::Limits::CEILING).ok()
                })
                .filter_map(|v| meta::ContentState::from_value(&v).ok())
                .filter_map(|c| access_kernel::claim::Gate::of(&c.content).ok())
                .collect();
        let issuer = gates
            .iter()
            .find(|g| g.use_ == access_kernel::claim::ACTOR_BINDING && g.issuer.is_some())
            .and_then(|g| g.issuer)
            .unwrap();
        assert!(gates.iter().any(|g| g.issuer == Some(issuer)
            && g.use_ == access_kernel::claim::PREDICATE_INPUT
            && g.classes == [String::from("authentication")]));
        let shop_route = route_by_slug(&w.db.router, "shop").await.unwrap().unwrap();
        assert!(shop_route.tenant == tenant && shop_route.realm == shop_realm);
        assert_ne!(domain.0, [0; 32]);
        assert!(
            sandbox::budget(&w.db.router, &domain.0)
                .await
                .unwrap()
                .is_none()
        );

        // TN-16, INV-32
        let again = provision(&w, &admin, &platform, &shop, [3; 16]).await;
        assert!(matches!(
            again,
            Err(ProvisionError::Invalid(ProvisionInvalid::SlugTaken))
        ));

        // OP-151 m.3 (m)
        let play = PlatformChange::Sandbox(realm(tenant, "shop-sandbox", joint, false));
        let Provisioned::Done {
            exercise: sandbox_exercise,
            created,
            ..
        } = provision(&w, &admin, &platform, &play, [4; 16])
            .await
            .unwrap()
        else {
            panic!("sandbox creation not allowed");
        };
        let Created::Realm {
            domain: sandbox_domain,
            sandbox: Some(budget),
            ..
        } = created
        else {
            panic!("not a sandbox");
        };
        assert_ne!(sandbox_domain, domain);
        assert_ne!(sandbox_exercise, exercise);
        assert_eq!(budget.exercises_per_day, SANDBOX_BUDGET.exercises_per_day);
        assert_eq!(
            sandbox::budget(&w.db.router, &sandbox_domain.0)
                .await
                .unwrap(),
            Some(budget)
        );
        let listed = sandbox::realms(
            (&w.db.router, &w.db.app),
            None,
            Some(tenant),
            None,
            (10, true),
        )
        .await
        .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].slug, "shop-sandbox");
        w.domains.release().await;
    }

    /// The platform-admin surface of this process, governed by the platform realm.
    fn surface(w: &World) -> crate::admin::realm::Realms<TestPlane> {
        crate::admin::realm::Realms {
            app: w.db.app.clone(),
            reads: access_store::replica_reads::ReplicaReads::primary_only(w.db.app.clone()),
            checkpointer: w.db.checkpointer.clone(),
            router: w.db.router.clone(),
            ids: Arc::new(crate::ids::CellIds::new(w.keys.clone())),
            plane: w.plane.clone(),
            base: w.base.clone(),
            keys: Arc::new(RealmKeyring::new(
                SignerKeys::new(w.identity_signer.clone()),
                w.keys.clone(),
            )),
            declared: DeclaredTargets::default(),
            platform: Some(String::from("platform")),
            outbound: access_identity_oauth::adapters::outbound::Outbound::disabled(
                std::time::Duration::from_secs(5),
            ),
            vault: access_identity_events::adapters::KekSealer(crate::login::RealmKeks::new(
                w.keys.clone(),
            )),
            geo: Arc::new(access_identity_risk::adapters::NoGeoSource),
            ips: Arc::new(access_identity_risk::adapters::NoPseudonyms),
            authority_signer: None,
        }
    }

    /// A sandbox creation of `body` for the platform surface's commit, signed by the platform
    /// root: the intent is built here, never drafted (no `prepare_provision`).
    async fn signed_write(
        w: &World,
        (operation, tenant): (&'static str, &str),
        mut body: serde_json::Value,
        nonce: [u8; 16],
    ) -> (
        access_http::api::ports::PlatformWrite,
        access_http::api::domain::caller::WriteCaller,
    ) {
        use access_http::api::ports::PlatformWrite;
        let root = root_key(&w.keys).unwrap();
        let now = server_time(&w.db.app).await.unwrap();
        body["validity"] = access_identity_admin::app::rest::default_validity(now);
        let route = route_by_slug(&w.db.router, "platform")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let g = idp::governance(&mut t).await.unwrap().unwrap();
        t.commit().await.unwrap();
        let domain = Digest(*g.domain.as_bytes());
        let validity = access_identity_admin::app::rest::validity(&body).unwrap();
        let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
        let tenant = TenantId::from_bytes(
            ids.decode(
                access_identity_events::domain::catalog::TENANT_PREFIX,
                tenant,
            )
            .unwrap(),
        );
        let joint = Root::Joint {
            parties: [root_party(&root.public_key()), Id([0x42; 16])]
                .into_iter()
                .collect(),
            k: 2,
        };
        let slug = body["slug"].as_str().unwrap().to_owned();
        let change = PlatformChange::Sandbox(realm(tenant, &slug, joint, false));
        let intent = change.intent(&g.slug, validity).unwrap();
        let digest = access_kernel::intent::intent_digest(&intent).unwrap();
        MetaExercises::lead(&w.plane, domain).await.unwrap();
        let basis = ExerciseBasis::Anchor(meta::object_id(&domain, kind::ANCHOR, IDP_ANCHOR));
        let statement = Moment::at(now).statement(domain, &nonce, digest, basis);
        let ais = sign(&root, &statement).unwrap();
        let caller = access_http::api::domain::caller::WriteCaller {
            kid: thumbprint(&root.public_key()),
            statement,
            ais,
        };
        let write = PlatformWrite {
            domain,
            operation,
            tenant: Some(
                ids.encode(
                    access_identity_events::domain::catalog::TENANT_PREFIX,
                    *tenant.as_bytes(),
                )
                .unwrap(),
            ),
            body,
            now_ms: now,
        };
        (write, caller)
    }

    async fn commit_write(
        surface: &crate::admin::realm::Realms<TestPlane>,
        (write, caller): (
            access_http::api::ports::PlatformWrite,
            access_http::api::domain::caller::WriteCaller,
        ),
    ) -> access_http::api::ports::Written {
        use access_http::api::ports::PlatformResources as _;
        surface.commit(write, caller).await.unwrap()
    }

    // TN-110, TN-16, INV-32, OP-151 m.3 (m)
    #[tokio::test]
    async fn a_commit_without_a_draft_never_turns_a_taken_slug_into_a_sandbox() {
        use access_http::api::ports::Written;
        let w = World::new("provision-commit").await;
        w.run(&plan()).await;
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
            console: None,
        };
        let admin = bootstrap.admin(&ids, None);
        let route = route_by_slug(&w.db.router, "platform")
            .await
            .unwrap()
            .unwrap();
        let platform = Platform {
            tenant: route.tenant,
            realm: route.realm,
            router: &w.db.router,
        };
        let founder = root_party(&root_key(&w.keys).unwrap().public_key());
        let tenant = TenantId::from_bytes(idp::new_uuid(&w.db.app).await.unwrap());
        let change = PlatformChange::Tenant {
            tenant: *tenant.as_bytes(),
            placement: String::from(PLACEMENT),
        };
        assert!(matches!(
            provision(&w, &admin, &platform, &change, [1; 16]).await,
            Ok(Provisioned::Done { .. })
        ));
        let joint = Root::Joint {
            parties: [founder, Id([0x42; 16])].into_iter().collect(),
            k: 2,
        };
        let shop = PlatformChange::Realm(realm(tenant, "shop", joint, false));
        let Ok(Provisioned::Done {
            created: Created::Realm { domain, .. },
            ..
        }) = provision(&w, &admin, &platform, &shop, [2; 16]).await
        else {
            panic!("realm creation not allowed");
        };

        let surface = surface(&w);
        let tenant_text = ids
            .encode(
                access_identity_events::domain::catalog::TENANT_PREFIX,
                *tenant.as_bytes(),
            )
            .unwrap();
        let joint_body = serde_json::json!({
            "joint": {
                "k": 2,
                "parties": [b64url_encode(&founder.0), b64url_encode(&[0x42; 16])],
            }
        });
        let signed = signed_write(
            &w,
            ("createSandboxDomain", &tenant_text),
            serde_json::json!({ "slug": "shop", "root": joint_body, "issuer_style": "path", "placement": PLACEMENT }),
            [3; 16],
        )
        .await;
        let taken = commit_write(&surface, signed).await;
        assert!(
            matches!(taken, Written::Rejected(c) if c == &access_http::problem::codes::platform::SLUG_TAKEN),
            "{taken:?}"
        );
        assert!(
            sandbox::budget(&w.db.router, &domain.0)
                .await
                .unwrap()
                .is_none()
        );

        let signed = signed_write(
            &w,
            ("createSandboxDomain", &tenant_text),
            serde_json::json!({ "slug": "shop-play", "root": joint_body, "issuer_style": "path", "placement": PLACEMENT }),
            [4; 16],
        )
        .await;
        let first = commit_write(&surface, signed.clone()).await;
        let again = commit_write(&surface, signed).await;
        let (Written::Committed { exercise_id: a, .. }, Written::Committed { exercise_id: b, .. }) =
            (first, again)
        else {
            panic!("sandbox creation not committed");
        };
        assert_eq!(a, b);
        w.domains.release().await;
    }
}

mod account;
mod agent;
mod authzen;
mod catalog;
mod doorbell;
mod exchange;
mod executor;
mod experience;
mod first_contact;
mod management;
mod mcp;
mod mcp_gateway;
mod privacy;
mod product_twin;
mod proxy;
mod proxy_engines;
mod recovery;
mod recovery_authority;
mod sample_agent;
mod timing;
mod vault;
mod vc_verifier;
mod walkthrough;
// OP-157 m.4 (b)
mod operator_breakglass;
// OP-157 m.4 (b)
mod fixtures;
// OP-158 m.4 (a)
mod durability;
mod faults;
// OP-158 m.4 (b) (W12)
mod reshred;
// OP-158 m.4 (b)
mod kek_rotation;
// OP-158 m.4 (b)
mod realm_crypto;
// OP-158 m.4 (b)
mod read_path;
// OP-158 m.4 (b) (W9)
mod placement;
// OP-159 m.4 (b) (J8)
mod aitm;
// OP-159 m.4 (b) (J6)
mod solver;
// OP-159 m.4 (b) (J3)
mod pq_fixture;
