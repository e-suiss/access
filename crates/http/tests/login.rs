//! The hosted login surface end to end: an in-process server over a real PostgreSQL, a
//! software WebAuthn authenticator and a recording Relay seam (OP-146 m.4 (g), (h), m.12).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::unused_async_trait_impl,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "../../identity-webauthn/tests/support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use access_crypto::Secret;
use access_crypto::envelope::SoftKek;
use access_crypto::opaque_id::IdKey;
use access_crypto::totp::{TotpAlgorithm, hotp, step_of};
use access_crypto::webauthn::DecoyKey;
use access_http::login::{Assets, Peer, me_router, router};
use access_identity_account::adapters::pg::PgAccounts;
use access_identity_account::adapters::system::SystemEntropy;
use access_identity_account::app::accounts::{
    PasswordServices, change_status, create, deactivate, set_password,
};
use access_identity_account::app::claims::Issued;
use access_identity_account::app::hasher::{Hasher, HasherConfig};
use access_identity_account::app::local::LocalLimiter;
use access_identity_account::app::login::LoginGate;
use access_identity_account::app::{Actor, Realm};
use access_identity_account::domain::claims::ClaimOrder;
use access_identity_account::domain::identifier::{Identifier, IdentifierKind};
use access_identity_account::domain::password::Argon2Params;
use access_identity_account::domain::status::AccountStatus;
use access_identity_account::domain::throttle::ThrottlePolicy;
use access_identity_account::notify::NotifyError;
use access_identity_account::notify::envelope::EventId;
use access_identity_account::notify::message::{Body, Message};
use access_identity_account::notify::ports::Notifier;
use access_identity_account::ports::{BreachRanges, RangeUnavailable};
use access_identity_oauth::app::Discovery;
use access_identity_oauth::domain::issuer::Issuer;
use access_identity_oauth::ports::{Directory, Keys, RealmEntry, Unavailable};
use access_identity_session::domain::realm_policy::RealmSignin;
use access_identity_session::domain::requirement::AuthPolicy;
use access_identity_session::domain::session::SessionPolicy;
use access_identity_ui::app::{Devices, Hosted};
use access_identity_ui::ports::{
    ApprovalClaims, Approvals, ArtifactSigner, Clock, DeviceInstances, Kits, Messages, RealmKit,
};
use access_identity_webauthn::adapters::RealmDecoyKeys;
use access_identity_webauthn::domain::ids::RealmId as WaRealm;
use access_identity_webauthn::domain::policy::RealmPolicy;
use access_identity_webauthn::domain::rp::{RelyingParty, RpId};
use access_internal_api::approvals::{Contribution, Opening};
use access_internal_api::claims::ClaimVerdict;
use access_internal_api::idp::{Unavailable as PlaneUnavailable, Verdict};
use access_internal_api::instances::{Registered, Registration, RegistrationVerdict, Termination};
use access_kernel::json::{b64url_decode, b64url_encode};
use access_kernel::model::Id;
use access_store::authority::{LogRecord, create_domain};
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::scope::DomainId;
use access_store::tenancy::{create_realm, create_tenant};
use access_store::testing::{TestDb, fresh};
use axum::Router;
use axum::body::Body as HttpBody;
use axum::http::{HeaderMap, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use suiss_crypto::signer::{Signer, SoftSigner, sign_sign1};
use support::{Authenticator, Key, ORIGIN, RP_ID};
use tower::ServiceExt;

const HOST: &str = "acme.example";
const PW: &str = "correct horse battery";
const ADMIN: Actor<'static> = Actor {
    actor: "adm_test",
    correlation: "req_test",
};

/// A clock the test moves; a live one also follows real time, so measured durations are real
/// (TN-82 pads to the mean of measured successes).
#[derive(Clone)]
struct TestClock {
    at: Arc<AtomicU64>,
    live: Option<std::time::Instant>,
}

impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        let real = self
            .live
            .map_or(0, |s| u64::try_from(s.elapsed().as_millis()).unwrap());
        self.at.load(Ordering::SeqCst) + real
    }
}

struct Corpus;

impl BreachRanges for Corpus {
    fn range(&self, _: &str) -> impl Future<Output = Result<String, RangeUnavailable>> + Send {
        std::future::ready(Ok(String::new()))
    }
}

/// The Relay seam as a recorder: what would be queued, with its secret, and each message's
/// kind, `Require-Recipient-Valid-Since` and subject.
type Sent = Vec<(&'static str, Option<u64>, [u8; 16])>;

#[derive(Clone, Default)]
struct Outbox(Arc<Mutex<Vec<String>>>, Arc<Mutex<Sent>>);

struct Recording<'a>(&'a Outbox);

impl Notifier for Recording<'_> {
    fn notify(
        &self,
        _: &mut TenantTx,
        m: &Message,
    ) -> impl Future<Output = Result<EventId, NotifyError>> + Send {
        let secret = match &m.body {
            Body::Otp { code, .. } => code.expose().clone(),
            Body::MagicLink { link, .. } => link.expose().clone(),
            _ => String::new(),
        };
        self.0.0.lock().unwrap().push(secret);
        self.0
            .1
            .lock()
            .unwrap()
            .push((m.body.kind(), m.valid_since_ms, m.subject));
        let checked = m.validate().map_err(NotifyError::from);
        std::future::ready(checked.map(|()| EventId([1; 16])))
    }
}

impl Messages for Outbox {
    type For<'a> = Recording<'a>;

    fn notifier<'a>(&'a self, _: &'a Realm<'a>) -> Recording<'a> {
        Recording(self)
    }
}

impl Outbox {
    fn last(&self) -> String {
        self.0.lock().unwrap().last().cloned().unwrap()
    }
}

struct Dir(RealmEntry);

impl Directory for Dir {
    async fn by_host(&self, host: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok((host == HOST).then(|| self.0.clone()))
    }

    async fn by_slug(&self, _: &str) -> Result<Option<RealmEntry>, Unavailable> {
        Ok(None)
    }

    async fn all(&self) -> Result<Vec<RealmEntry>, Unavailable> {
        Ok(vec![self.0.clone()])
    }
}

struct NoKeys;

impl Keys for NoKeys {
    async fn ping(&self) -> Result<(), Unavailable> {
        Ok(())
    }

    async fn jwks(&self, _: RealmId) -> Result<String, Unavailable> {
        Err(Unavailable)
    }
}

/// The identity signer: one in-process key.
#[derive(Clone)]
struct ArtifactKey(Arc<SoftSigner>);

impl ArtifactSigner for ArtifactKey {
    async fn sign_cose(
        &self,
        _: RealmId,
        content_type: &str,
        payload: &[u8],
        _: u64,
    ) -> Result<Vec<u8>, Unavailable> {
        let kid = access_kernel::verify::key_scope::thumbprint(&self.0.public_key());
        sign_sign1(&*self.0, kid, content_type, payload).map_err(|_| Unavailable)
    }
}

/// The authority plane: opens every device Instance as `[9; 16]` and ends only that one.
struct Plane;

impl DeviceInstances for Plane {
    async fn register(&self, r: Registration) -> Result<RegistrationVerdict, PlaneUnavailable> {
        Ok(RegistrationVerdict::Registered(Registered {
            party: Id([8; 16]),
            instance: Id([9; 16]),
            kid: access_kernel::verify::key_scope::thumbprint(&r.key),
            replayed: false,
        }))
    }

    async fn terminate(&self, t: Termination) -> Result<Verdict, PlaneUnavailable> {
        if t.instance == Id([9; 16]) {
            return Ok(Verdict::Committed(access_internal_api::idp::Committed {
                domain: t.domain,
                nonce: t.nonce,
                position: 7,
                intent: access_kernel::digest::Digest([0xe1; 32]),
                exercise: access_kernel::digest::Digest([0xe2; 32]),
                replayed: false,
            }));
        }
        Ok(Verdict::Refused {
            code: String::from("protocol"),
            errors: Vec::new(),
        })
    }

    async fn recover(
        &self,
        _: access_internal_api::instances::Recovery,
    ) -> Result<Verdict, PlaneUnavailable> {
        Ok(Verdict::Refused {
            code: String::from("protocol"),
            errors: Vec::new(),
        })
    }
}

/// The authority plane behind the Approval Surface: one `REQUIRE_ACTION` on intent `[0x44; 32]`
/// with the render of a refund, at the tier the test sets; a contribution whose statement names
/// that render is committed as `[0xe3; 32]`, another is "the request changed"; with `unbound`
/// set, the Claim it finds is bound to another statement (`aas-binding`, OP-149 m.30 (b)).
#[derive(Clone, Default)]
struct Surface {
    tier: Arc<std::sync::atomic::AtomicU8>,
    gone: Arc<std::sync::atomic::AtomicBool>,
    shifted: Arc<std::sync::atomic::AtomicBool>,
    unbound: Arc<std::sync::atomic::AtomicBool>,
    contributions: Arc<Mutex<Vec<Contribution>>>,
}

const TARGET: access_kernel::digest::Digest = access_kernel::digest::Digest([0x44; 32]);

fn refund_render(shifted: bool) -> (access_kernel::digest::Digest, Vec<u8>) {
    use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
    use access_kernel::model::{ActionRef, ResourceRef, Window};
    use access_kernel::schema::{ActionSchema, EffectClass};
    let schema = ActionSchema {
        name: "refund".into(),
        major: 1,
        effect: EffectClass::Irreversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::from([("amount".to_owned(), "amount".to_owned())]),
        resource_types: std::collections::BTreeSet::new(),
        render: Some("Refund {amount} on {resource}".into()),
    };
    let intent = IntentEnvelope {
        action: ActionRef {
            namespace: "shop".into(),
            name: "refund".into(),
            major: 1,
            schema: access_kernel::schema::action_digest(&schema),
        },
        resources: vec![ResourceRef {
            namespace: "shop".into(),
            path: vec!["orders".into(), "o-1042".into()],
            incarnation: 0,
        }],
        params: BTreeMap::from([(
            "amount".to_owned(),
            ParamValue::Amount {
                value: if shifted { 4300 } else { 4200 },
                unit: "eur".into(),
            },
        )]),
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
    };
    let r = access_kernel::render::of(Some(&schema), &intent, "en").unwrap();
    (
        access_kernel::render::digest(&r).unwrap(),
        access_kernel::render::encode(&r).unwrap(),
    )
}

impl Approvals for Surface {
    async fn opening(
        &self,
        _: access_kernel::digest::Digest,
        intent: access_kernel::digest::Digest,
    ) -> Result<Option<Opening>, PlaneUnavailable> {
        if self.gone.load(Ordering::SeqCst) || intent != TARGET {
            return Ok(None);
        }
        let (render_digest, render) = refund_render(self.shifted.load(Ordering::SeqCst));
        Ok(Some(Opening {
            render_digest,
            render: Some(render),
            tier: self.tier.load(Ordering::SeqCst),
        }))
    }

    async fn contribute(&self, c: Contribution) -> Result<Verdict, PlaneUnavailable> {
        use access_kernel::codec::Canonical as _;
        let value =
            suiss_crypto::dcbor::decode(&c.aas, suiss_crypto::dcbor::Limits::CEILING).unwrap();
        let act = access_kernel::aas::ApprovalAct::from_value(&value).unwrap();
        let (render_digest, _) = refund_render(self.shifted.load(Ordering::SeqCst));
        if act.render_digest != render_digest {
            return Ok(Verdict::Refused {
                code: String::from("aas-render"),
                errors: Vec::new(),
            });
        }
        if self.unbound.load(Ordering::SeqCst) {
            return Ok(Verdict::Refused {
                code: String::from("aas-binding"),
                errors: vec!["bound-intent"],
            });
        }
        let (domain, nonce) = (c.domain, c.nonce.clone());
        self.contributions.lock().unwrap().push(c);
        Ok(Verdict::Committed(access_internal_api::idp::Committed {
            domain,
            nonce,
            position: 11,
            intent: TARGET,
            exercise: access_kernel::digest::Digest([0xe3; 32]),
            replayed: false,
        }))
    }
}

/// The realm's Claim courier: every order is admitted as Claim `[0xc1; 16]`.
#[derive(Clone, Default)]
struct Claims(Arc<Mutex<Vec<ClaimOrder>>>);

impl ApprovalClaims for Claims {
    async fn issue(
        &self,
        _: TenantId,
        _: RealmId,
        order: &ClaimOrder,
    ) -> Result<Issued, PlaneUnavailable> {
        self.0.lock().unwrap().push(order.clone());
        Ok(Issued::Answered {
            claim: [0xc1; 16],
            verdict: ClaimVerdict::Admitted {
                claim: Id([0xc1; 16]),
                position: 9,
                replayed: false,
            },
        })
    }
}

struct Kit(Arc<RealmKit>);

impl Kits for Kit {
    async fn kit(&self, entry: &RealmEntry) -> Result<Arc<RealmKit>, Unavailable> {
        if entry.realm == self.0.realm {
            Ok(self.0.clone())
        } else {
            Err(Unavailable)
        }
    }
}

struct Env {
    db: TestDb,
    tenant: TenantId,
    realm: RealmId,
    domain: DomainId,
    kit: Arc<RealmKit>,
    clock: TestClock,
    outbox: Outbox,
    app: Router,
    hasher: Arc<Hasher>,
    peers: AtomicU64,
    signer: ArtifactKey,
    surface: Surface,
    claims: Claims,
}

fn kit(tenant: TenantId, realm: RealmId, seed: u8, auth: AuthPolicy) -> RealmKit {
    let wa = WaRealm::from_bytes(*realm.as_bytes());
    RealmKit {
        tenant,
        realm,
        issuer: format!("https://{HOST}"),
        name: "Acme".into(),
        kek: std::sync::Arc::new(SoftKek::new("realm-kek:1", [seed; 32])),
        index: std::sync::Arc::new(access_crypto::realm_index::RealmIndexKey::new(Secret::new(
            [seed; 32],
        ))),
        ids: IdKey::new(Secret::new([seed.wrapping_add(1); 32])),
        decoys: RealmDecoyKeys::default().with(wa, DecoyKey::new(Secret::new([9; 32]))),
        rp: RelyingParty {
            realm: wa,
            rp_id: RpId::parse(RP_ID).unwrap(),
            name: "Acme".into(),
            pinned: true,
            related: Vec::new(),
        },
        webauthn: RealmPolicy::default(),
        auth,
        lifetimes: SessionPolicy::DEFAULT,
        signin: access_identity_session::domain::realm_policy::RealmSignin::default(),
    }
}

fn fixture() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "access-login-dist-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>Sign in</title><script type=module src=/assets/app.js></script>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app.js"), "export {};").unwrap();
    dir
}

async fn env(seed: u8, slug: &str, auth: AuthPolicy) -> Env {
    env_with(seed, slug, auth, false).await
}

async fn env_with(seed: u8, slug: &str, auth: AuthPolicy, live: bool) -> Env {
    env_full(seed, slug, auth, live, RealmSignin::default()).await
}

async fn env_full(seed: u8, slug: &str, auth: AuthPolicy, live: bool, signin: RealmSignin) -> Env {
    let signup = access_identity_ui::app::signup::Signup::without_providers().unwrap();
    env_core(seed, slug, auth, live, signin, signup).await
}

async fn env_core(
    seed: u8,
    slug: &str,
    auth: AuthPolicy,
    live: bool,
    signin: RealmSignin,
    signup: access_identity_ui::app::signup::Signup,
) -> Env {
    env_legacy(seed, slug, auth, live, signin, signup, None).await
}

async fn env_legacy(
    seed: u8,
    slug: &str,
    auth: AuthPolicy,
    live: bool,
    signin: RealmSignin,
    signup: access_identity_ui::app::signup::Signup,
    legacy: Option<Arc<dyn access_identity_account::ports::LegacyIdp>>,
) -> Env {
    let db = fresh().await.unwrap();
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let d = DomainId::from_bytes([seed; 32]);
    let g = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [seed; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &d, *tenant.as_bytes(), &g, &[])
        .await
        .unwrap();
    let mut tx = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let realm = create_realm(&mut tx, &d, slug, "pool-default")
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut built = kit(tenant, realm, seed, auth);
    built.signin = signin;
    let kit = Arc::new(built);
    let clock = TestClock {
        at: Arc::new(AtomicU64::new(1_800_000_000_000)),
        live: live.then(std::time::Instant::now),
    };
    let outbox = Outbox::default();
    let entry = RealmEntry {
        tenant,
        realm,
        slug: slug.to_owned(),
        issuer: Issuer::parse(&format!("https://{HOST}")).unwrap(),
    };
    let config = HasherConfig::sized(Argon2Params::CANONICAL, 4, None);
    let hosted = Arc::new(Hosted {
        kits: Kit(kit.clone()),
        db: db.app.clone(),
        products: db.reader.clone(),
        clock: clock.clone(),
        messages: outbox.clone(),
        gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
        hasher: match legacy {
            Some(idp) => Hasher::new(config).with_legacy_idp(idp),
            None => Hasher::new(config),
        },
        redirect_to: "/".into(),
        hooks: std::sync::Arc::new(access_identity_hooks::ports::NoHooks),
        risk: access_identity_session::app::RiskServices::without_sources(),
        signup,
    });
    let assets = Assets::load(&fixture()).unwrap();
    let signer = ArtifactKey(Arc::new(SoftSigner::generate_ed25519().unwrap().0));
    let surface = Surface::default();
    surface.tier.store(1, Ordering::SeqCst);
    let claims = Claims::default();
    let app = router(
        Discovery::new(Dir(entry.clone()), NoKeys),
        hosted.clone(),
        Some(assets),
    )
    .merge(me_router(
        Discovery::new(Dir(entry), NoKeys),
        hosted,
        Devices {
            signer: signer.clone(),
            instances: Plane,
            approvals: surface.clone(),
            claims: claims.clone(),
            pep: String::from("access-identity"),
        },
    ));
    Env {
        db,
        tenant,
        realm,
        domain: d,
        kit,
        clock,
        outbox,
        app,
        hasher: Arc::new(Hasher::new(config)),
        peers: AtomicU64::new(0),
        signer,
        surface,
        claims,
    }
}

impl Env {
    fn realm(&self) -> Realm<'_> {
        let _ = (self.tenant, self.realm);
        self.kit.realm()
    }

    async fn account(&self, who: &str) -> [u8; 16] {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.kit.vault());
        let id = Identifier::new(IdentifierKind::Email, who).unwrap();
        let s = create(&pg, &self.realm(), &[id], &ADMIN).await.unwrap();
        let services = PasswordServices {
            hasher: &self.hasher,
            ranges: &Corpus,
            entropy: &SystemEntropy,
        };
        set_password(&pg, &self.realm(), &services, s, PW, &ADMIN)
            .await
            .unwrap();
        for to in [AccountStatus::PendingUserAction, AccountStatus::Active] {
            change_status(&pg, &self.realm(), s, to, &ADMIN)
                .await
                .unwrap();
        }
        s
    }

    /// A client of the realm with `redirect` registered, under an idp.client.register ALLOW
    /// recorded in the governing domain (EI-25).
    async fn client(&self, redirect: &str) {
        self.register_client(
            (self.tenant, self.realm, self.domain),
            [0x5c; 16],
            format!("cli_{}4a", "0".repeat(24)),
            &[redirect],
            None,
        )
        .await;
    }

    /// A platform product client registered in another tenant's realm, the platform realm,
    /// with `redirects` as its return addresses (OP-149 m.4, m.33 (d), m.35).
    async fn platform_client(&self, redirects: &[&str]) {
        let tenant = create_tenant(&self.db.app, "pool-default").await.unwrap();
        let d = DomainId::from_bytes([0xd0; 32]);
        let g = LogRecord {
            pos: 0,
            kind: "genesis",
            recorded_at: 1,
            leaf_hash: [0xd0; 32],
            envelope: vec![0xa0],
        };
        create_domain(&self.db.sequencer, &d, *tenant.as_bytes(), &g, &[])
            .await
            .unwrap();
        let mut tx = TenantTx::begin_tenant(&self.db.app, tenant).await.unwrap();
        let realm = create_realm(&mut tx, &d, "platform", "pool-default")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        self.register_client(
            (tenant, realm, d),
            [0x7a; 16],
            format!("cli_{}7a", "0".repeat(24)),
            redirects,
            Some("work"),
        )
        .await;
    }

    /// Registers a client in `(tenant, realm, domain)` under an idp.client.register ALLOW
    /// recorded in that governing domain.
    async fn register_client(
        &self,
        (tenant, realm, domain): (TenantId, RealmId, DomainId),
        client_uuid: [u8; 16],
        client_id: String,
        redirects: &[&str],
        platform_product: Option<&str>,
    ) {
        use access_store::authority::{
            CommitBatch, HeadRow, NonceRow, acquire_lease, commit_batch,
        };
        use access_store::idp::{ClientRow, Decision, bind, insert_client};
        let (lease, head) = acquire_lease(
            &self.db.sequencer,
            &domain,
            "t",
            std::time::Duration::from_secs(10),
        )
        .await
        .unwrap();
        let pos = head.pos + 1;
        let leaf = [0x5c; 32];
        let batch = CommitBatch {
            epoch: lease.epoch,
            after: head.pos,
            records: vec![LogRecord {
                pos,
                kind: "decision",
                recorded_at: 2,
                leaf_hash: leaf,
                envelope: vec![0xa1, 1],
            }],
            head: HeadRow {
                pos,
                epoch: lease.epoch,
                leaf_hash: leaf,
                recorded_at: 2,
                frontier: vec![leaf],
            },
            nonces: vec![NonceRow {
                nonce: vec![1; 16],
                actor: vec![1],
                intent_digest: [9; 32],
                decision_pos: pos,
                outcome: String::from("allow"),
                render_digest: None,
                tier: None,
            }],
            outbox: vec![],
            proofs: vec![],
            reads: vec![],
            writes: vec![],
            draws: vec![],
            single_use: vec![],
            effects: vec![],
        };
        commit_batch(&self.db.sequencer, &domain, *tenant.as_bytes(), &batch)
            .await
            .unwrap();
        let mut tx = TenantTx::begin(&self.db.app, tenant, realm).await.unwrap();
        let bound = bind(
            &mut tx,
            &Decision {
                domain: &domain,
                position: pos,
                nonce: &[1; 16],
                intent: [9; 32],
                change: [5; 32],
                action: "idp.client.register",
            },
        )
        .await
        .unwrap()
        .unwrap();
        insert_client(
            &mut tx,
            &bound,
            &ClientRow {
                client_uuid,
                client_id,
                display_name: "Shop".into(),
                auth_method: if platform_product.is_some() {
                    "private_key_jwt".into()
                } else {
                    "none".into()
                },
                jwks_uri: None,
                redirect_uris: redirects.iter().map(|r| (*r).to_owned()).collect(),
                active: true,
                secret_hash: None,
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                jwks: platform_product.map(|_| {
                    String::from(
                        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"EREREREREREREREREREREREREREREREREREREREREREREQ"}]}"#,
                    )
                }),
                platform_product: platform_product.map(String::from),
                service_key: platform_product.map(|_| vec![0xa4, 1, 1, 0x20, 6]),
                event_receiver: None,
                require_par: false,
                public_sub: false,
                sector_identifier_uri: None,
                third_party: false,
            },
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    fn browser(&self, name: &str) -> Web {
        let ip = self.peers.fetch_add(1, Ordering::SeqCst);
        Web {
            ip: Ipv4Addr::new(
                10,
                u8::try_from(ip / 250 % 250).unwrap(),
                u8::try_from(ip % 250).unwrap() + 1,
                1,
            ),
            app: self.app.clone(),
            jar: BTreeMap::new(),
            name: name.to_owned(),
            n: 0,
            host: HOST.to_owned(),
        }
    }

    fn advance(&self, ms: u64) {
        self.clock.at.fetch_add(ms, Ordering::SeqCst);
    }

    fn totp(&self, seed: &[u8]) -> String {
        hotp(
            seed,
            TotpAlgorithm::Sha1,
            step_of(self.clock.now_ms() / 1000, 30),
            6,
        )
    }
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn step(&self) -> String {
        self.json()["step"].as_str().unwrap_or_default().to_owned()
    }

    fn messages(&self) -> Vec<String> {
        self.json()["messages"]
            .as_array()
            .map(|m| {
                m.iter()
                    .map(|x| x["id"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn action(&self) -> String {
        self.json()["action"].as_str().unwrap().to_owned()
    }
}

/// One browser: a cookie jar and fresh `Idempotency-Key`s.
struct Web {
    ip: Ipv4Addr,
    app: Router,
    jar: BTreeMap<String, String>,
    name: String,
    n: u64,
    host: String,
}

impl Web {
    fn key(&mut self) -> String {
        self.n += 1;
        format!("{}-{}", self.name, self.n)
    }

    async fn send(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        key: Option<&str>,
    ) -> Answer {
        self.send_with(method, path, body, key, &[]).await
    }

    async fn send_with(
        &mut self,
        method: &str,
        path: &str,
        body: Option<Value>,
        key: Option<&str>,
        extra: &[(&str, &str)],
    ) -> Answer {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, &self.host)
            .header("x-request-id", "req-1");
        for (name, value) in extra {
            req = req.header(*name, *value);
        }
        if !self.jar.is_empty() {
            let cookies: Vec<String> = self.jar.iter().map(|(k, v)| format!("{k}={v}")).collect();
            req = req.header(header::COOKIE, cookies.join("; "));
        }
        if method == "POST" || body.is_some() {
            req = req.header(header::CONTENT_TYPE, "application/json");
        }
        if let Some(k) = key {
            req = req.header("idempotency-key", k);
        }
        let body = body.map_or_else(HttpBody::empty, |b| HttpBody::from(b.to_string()));
        let mut req = req.body(body).unwrap();
        req.extensions_mut().insert(Peer(IpAddr::V4(self.ip)));
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        for c in headers.get_all(header::SET_COOKIE) {
            let c = c.to_str().unwrap();
            let (name, value) = c.split(';').next().unwrap().split_once('=').unwrap();
            if c.contains("Max-Age=0") {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        Answer {
            status,
            headers,
            body,
        }
    }

    async fn post(&mut self, path: &str, body: Option<Value>) -> Answer {
        let key = self.key();
        self.send("POST", path, body, Some(&key)).await
    }

    async fn get(&mut self, path: &str) -> Answer {
        self.send("GET", path, None, None).await
    }

    async fn start(&mut self) -> Answer {
        let a = self.post("/v1/login/flows", None).await;
        assert_eq!(
            a.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&a.body)
        );
        a
    }

    async fn submit(&mut self, at: &Answer, method: &str, fields: Value) -> Answer {
        self.post(
            &at.action(),
            Some(json!({ "method": method, "fields": fields })),
        )
        .await
    }

    async fn identify(&mut self, who: &str) -> Answer {
        let first = self.start().await;
        let a = self
            .submit(&first, "identifier", json!({ "identifier": who }))
            .await;
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(a.step(), "authenticate");
        a
    }

    async fn sign_in(&mut self, who: &str) -> Answer {
        let at = self.identify(who).await;
        self.submit(&at, "password", json!({ "password": PW }))
            .await
    }
}

fn base32_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0_u32, 0_u32);
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("base32"),
        };
        buf = (buf << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

fn passkey_node(a: &Answer) -> Value {
    a.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["type"] == "passkey_get")
        .unwrap()["options"]
        .clone()
}

// TN-96, TN-132, OP-146 m.12 (b)
#[tokio::test]
async fn identifier_then_password_signs_in_with_a_host_cookie() {
    let e = env(1, "lg-a", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut b = e.browser("b");
    let first = b.start().await;
    assert_eq!(first.step(), "identifier");
    assert!(b.jar.contains_key("__Host-access-flow"));
    assert_eq!(first.headers[header::CACHE_CONTROL], "no-store");
    let at = b
        .submit(
            &first,
            "identifier",
            json!({ "identifier": "alice@example.com" }),
        )
        .await;
    assert_eq!(at.step(), "authenticate");
    let echo = &at.json()["nodes"][0];
    assert_eq!(echo["value"], "alice@example.com");
    assert_eq!(echo["read_only"], true);
    let wrong = b
        .submit(&at, "password", json!({ "password": "nope nope nope" }))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.messages(), ["login.failed"]);
    let early = b
        .submit(&wrong, "password", json!({ "password": PW }))
        .await;
    assert_eq!(early.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(early.messages(), ["login.throttled"]);
    assert!(early.headers.contains_key(header::RETRY_AFTER));
    e.advance(2_000);
    let done = b
        .submit(&wrong, "password", json!({ "password": PW }))
        .await;
    assert_eq!(done.status, StatusCode::OK);
    assert_eq!(done.step(), "complete");
    assert_eq!(done.json()["redirect_to"], "/");
    let set: Vec<&str> = done
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    let session = set
        .iter()
        .find(|c| c.starts_with("__Host-access-session="))
        .unwrap();
    for attr in ["Path=/", "Secure", "HttpOnly", "SameSite=Lax"] {
        assert!(session.contains(attr), "{session}");
    }
    assert!(!session.contains("Domain="));
    let me = b.get("/v1/sessions/current").await;
    assert_eq!(me.status, StatusCode::OK);
    assert!(me.json()["subject"].as_str().unwrap().starts_with("usr_"));
    let again = b.submit(&done, "password", json!({ "password": PW })).await;
    assert_eq!(again.status, StatusCode::GONE);
}

// TN-106, X40
#[tokio::test]
async fn fabricated_submissions_are_refused() {
    let e = env(2, "lg-b", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    let first = b.start().await;
    for body in [
        json!({ "method": "password", "fields": { "password": "x" } }),
        json!({ "method": "identifier", "fields": { "identifier": "a", "role": "admin" } }),
        json!({ "method": "eval" }),
        json!({ "method": "identifier", "fields": { "identifier": "a" }, "extra": 1 }),
    ] {
        let a = b.post(&first.action(), Some(body)).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        assert_eq!(a.headers[header::CONTENT_TYPE], "application/problem+json");
    }
    let still = b.get(&first.action()).await;
    assert_eq!(still.status, StatusCode::OK);
    assert_eq!(still.step(), "identifier");
}

// TN-126, OP-65
#[tokio::test]
async fn idempotency_keys_replay_and_refuse() {
    let e = env(3, "lg-c", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    let missing = b.send("POST", "/v1/login/flows", None, None).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert!(String::from_utf8_lossy(&missing.body).contains("idempotency-key-required"));
    let first = b.start().await;
    let saved = b.jar.clone();
    let body = json!({ "method": "identifier", "fields": { "identifier": "ann@example.com" } });
    let one = b
        .send("POST", &first.action(), Some(body.clone()), Some("k1"))
        .await;
    assert_eq!(one.status, StatusCode::OK);
    b.jar.clone_from(&saved);
    let two = b
        .send("POST", &first.action(), Some(body.clone()), Some("k1"))
        .await;
    assert_eq!(two.body, one.body);
    assert_eq!(
        two.headers.get_all(header::SET_COOKIE).iter().count(),
        one.headers.get_all(header::SET_COOKIE).iter().count()
    );
    b.jar.clone_from(&saved);
    let other = b
        .send(
            "POST",
            &first.action(),
            Some(json!({ "method": "restart" })),
            Some("k1"),
        )
        .await;
    assert_eq!(other.status, StatusCode::UNPROCESSABLE_ENTITY);
    let mut c = e.browser("c");
    c.start().await;
    let theirs = c
        .send("POST", &first.action(), Some(body), Some("k1"))
        .await;
    assert_ne!(theirs.body, one.body);
    let fresh = c.send("POST", "/v1/login/flows", None, Some("k9")).await;
    c.jar.clear();
    let again = c.send("POST", "/v1/login/flows", None, Some("k9")).await;
    assert_eq!(again.status, StatusCode::CREATED);
    assert_ne!(again.body, fresh.body);
}

// §17.9.6
#[tokio::test]
async fn unknown_hosts_and_forms_are_refused() {
    let e = env(4, "lg-d", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    b.host = "evil.example".into();
    for (m, p) in [
        ("POST", "/v1/login/flows"),
        ("GET", "/login"),
        ("GET", "/.well-known/webauthn"),
        ("GET", "/v1/sessions"),
    ] {
        let a = b.send(m, p, None, Some("k")).await;
        assert_eq!(a.status, StatusCode::NOT_FOUND, "{p}");
        assert!(!String::from_utf8_lossy(&a.body).contains("lg-d"));
    }
    let mut b = e.browser("f");
    let req = Request::post("/v1/login/flows")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("idempotency-key", "k")
        .body(HttpBody::empty())
        .unwrap();
    let a = b.app.clone().oneshot(req).await.unwrap();
    assert_eq!(a.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    b.jar.clear();
}

// OP-153 m.4, §17.9.6
#[tokio::test]
async fn a_planned_frontend_route_answers_not_yet_served_only_for_a_known_realm() {
    use access_identity_ui::domain::frontend_v1::{ROUTES, Verb};
    let e = env(4, "lg-planned", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    for r in ROUTES.iter().filter(|r| !r.live) {
        let path = r.path.replace('{', "x").replace('}', "");
        let method = match r.verb {
            Verb::Get => "GET",
            Verb::Post => "POST",
            Verb::Put => "PUT",
            Verb::Delete => "DELETE",
        };
        let a = b.send(method, &path, None, Some("k")).await;
        assert_eq!(a.status, StatusCode::NOT_IMPLEMENTED, "{}", r.operation);
        let problem: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
        assert_eq!(problem["code"], "not-yet-served", "{}", r.operation);
    }
    b.host = "evil.example".into();
    let a = b.send("POST", "/v1/recovery", None, Some("k")).await;
    assert_eq!(a.status, StatusCode::NOT_FOUND);
}

// OP-146 m.12 (f), TN-18
#[tokio::test]
async fn the_login_app_carries_its_security_headers() {
    // GHSA-gpxg-fx2g-qxj2
    let e = env(5, "lg-e", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("b");
    let page = b.get("/login").await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(
        page.headers[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    let ts = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../web/login/security-headers.ts"),
    )
    .unwrap();
    let list = ts
        .split_once("contentSecurityPolicy = [")
        .and_then(|(_, rest)| rest.split_once("].join"))
        .unwrap()
        .0;
    let csp: Vec<&str> = list
        .lines()
        .filter_map(|l| l.trim().strip_prefix('"')?.strip_suffix("\","))
        .collect();
    assert_eq!(page.headers["content-security-policy"], csp.join("; "));
    for (name, value) in [
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        assert!(ts.contains(&format!("\"{value}\"")), "{name}");
        assert_eq!(page.headers[name], value);
    }
    assert!(ts.contains(page.headers["permissions-policy"].to_str().unwrap()));
    let js = b.get("/assets/app.js").await;
    assert_eq!(js.status, StatusCode::OK);
    assert_eq!(
        js.headers[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
    assert!(js.headers.contains_key("content-security-policy"));
    assert_eq!(
        b.get("/assets/../index.html").await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        b.get("/assets/missing.js").await.status,
        StatusCode::NOT_FOUND
    );
    let wk = b.get("/.well-known/webauthn").await;
    assert_eq!(wk.status, StatusCode::OK);
    assert_eq!(wk.json(), json!({ "origins": [ORIGIN] }));
}

// §10.2.2, TN-64, TN-59, TN-36, TN-50, S10
#[tokio::test]
async fn totp_recovery_codes_and_sign_out() {
    let e = env(6, "lg-f", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("alice@example.com").await.step(), "complete");
    let mut other = e.browser("o");
    assert_eq!(other.sign_in("alice@example.com").await.step(), "complete");
    let list = b.get("/v1/sessions").await;
    assert_eq!(list.json()["sessions"].as_array().unwrap().len(), 2);
    let started = b
        .post("/v1/account/totp", Some(json!({ "label": "alice" })))
        .await;
    assert_eq!(started.status, StatusCode::CREATED);
    let s = started.json();
    assert!(
        s["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Acme:alice?secret=")
    );
    let seed = base32_decode(s["secret"].as_str().unwrap());
    let path = format!("/v1/account/totp/{}", s["enrollment"].as_str().unwrap());
    let bad = b.post(&path, Some(json!({ "code": "000000" }))).await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    let ok = b.post(&path, Some(json!({ "code": e.totp(&seed) }))).await;
    assert_eq!(
        ok.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&ok.body)
    );
    let codes: Vec<String> = ok.json()["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(codes.len(), 10);
    assert_eq!(b.get("/v1/sessions/current").await.status, StatusCode::OK);
    assert_eq!(
        other.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );

    let mut c = e.browser("c");
    let second = c.sign_in("alice@example.com").await;
    assert_eq!(second.step(), "second_factor");
    let wrong = c
        .submit(&second, "totp", json!({ "totp_code": "000000" }))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.messages(), ["second_factor.failed"]);
    e.advance(30_000);
    let done = c
        .submit(&wrong, "totp", json!({ "totp_code": e.totp(&seed) }))
        .await;
    assert_eq!(done.step(), "complete");

    let mut d = e.browser("d");
    let second = d.sign_in("alice@example.com").await;
    let used = d
        .submit(
            &second,
            "recovery_code",
            json!({ "recovery_code": codes[0] }),
        )
        .await;
    assert_eq!(used.step(), "complete");
    let mut f = e.browser("f");
    let second = f.sign_in("alice@example.com").await;
    let again = f
        .submit(
            &second,
            "recovery_code",
            json!({ "recovery_code": codes[0] }),
        )
        .await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);

    let fresh = b.post("/v1/account/recovery-codes", None).await;
    assert_eq!(fresh.json()["recovery_codes"].as_array().unwrap().len(), 10);

    let out = c.post("/v1/sessions/current/sign-out", None).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT);
    assert!(!c.jar.contains_key("__Host-access-session"));
    assert_eq!(
        c.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );
    let all = b.post("/v1/sessions/sign-out-everywhere", None).await;
    assert_eq!(all.status, StatusCode::NO_CONTENT);
    assert_eq!(
        d.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );
}

// §10.2.4, TN-96, TN-97, OP-146 m.9, OP-149 m.16 (a)
#[tokio::test]
async fn a_passkey_registered_from_a_session_signs_in() {
    let e = env(7, "lg-g", AuthPolicy::DEFAULT).await;
    e.account("bob@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("bob@example.com").await.step(), "complete");
    let reg = b
        .post(
            "/v1/account/passkeys",
            Some(json!({ "name": "bob@example.com" })),
        )
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let r = reg.json();
    let challenge = b64url_decode(r["options"]["challenge"].as_str().unwrap()).unwrap();
    let user = r["options"]["user"]["id"].as_str().unwrap().to_owned();
    let mut key = Authenticator::new(Key::es256());
    let (cdj, att) = key.register(RP_ID, ORIGIN, &challenge);
    let id = b64url_encode(&key.credential_id);
    let credential = json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "attestationObject": b64url_encode(&att),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
    });
    let path = format!(
        "/v1/account/passkeys/{}",
        r["registration"].as_str().unwrap()
    );
    let done = b
        .post(&path, Some(json!({ "credential": credential })))
        .await;
    assert_eq!(
        done.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&done.body)
    );

    let mut c = e.browser("c");
    let first = c.start().await;
    let options = passkey_node(&first);
    assert_eq!(options["allowCredentials"], json!([]));
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let (cdj, ad, sig) = key.assert(RP_ID, ORIGIN, &challenge);
    let assertion = json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "authenticatorData": b64url_encode(&ad),
            "signature": b64url_encode(&sig),
            "userHandle": user,
        },
        "clientExtensionResults": {},
    });
    let signed = c
        .submit(
            &first,
            "passkey",
            json!({ "passkey_credential": assertion.to_string() }),
        )
        .await;
    assert_eq!(
        signed.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&signed.body)
    );
    assert!(c.jar.contains_key("__Host-access-session"));
    let replayed = c
        .submit(&first, "passkey", json!({ "passkey_credential": "{}" }))
        .await;
    assert_eq!(replayed.status, StatusCode::GONE);
    devices_bind_the_session_party(&e, &mut c).await;
}

/// OP-149 m.16 (a), L0-META-7: a stepped-up session's first device registers a new Party with
/// its own `party_register`; the identity plane binds the session's subject to that Party, names
/// it in later challenges and forwards later registrations for that Party only.
async fn devices_bind_the_session_party(e: &Env, c: &mut Web) {
    let party = b64url_encode(&[8; 16]);
    let mut register = async |party: &str, new: bool| {
        let ch = c.post("/v1/me/instances/challenges", None).await;
        assert_eq!(ch.status, StatusCode::CREATED);
        let mut body = json!({
            "challenge": ch.json()["challenge"],
            "party": party,
            "key": b64url_encode(&access_identity_session::domain::device::cose_key(
                &SoftSigner::generate_ed25519().unwrap().0.public_key(),
            )),
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_until": "2026-01-01T00:05:00Z",
            "ais": b64url_encode(&[0xd2; 40]),
        });
        if new {
            body["register_ais"] = json!(b64url_encode(&[0xd2; 40]));
        }
        (ch.json(), c.post("/v1/me/instances", Some(body)).await)
    };
    let (first, unbound) = register(&party, false).await;
    assert!(first.get("party").is_none());
    assert_eq!(unbound.status, StatusCode::BAD_REQUEST);
    assert_eq!(unbound.json()["code"], "invalid-party");
    let (_, created) = register(&party, true).await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.json()["party"], party.as_str());
    assert_eq!(
        b64url_decode(created.json()["instance"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    let (second, again) = register(&party, true).await;
    assert_eq!(second["party"], party.as_str());
    assert_eq!(again.json()["code"], "invalid-party");
    let (_, other) = register(&b64url_encode(&[6; 16]), false).await;
    assert_eq!(other.json()["code"], "invalid-party");
    // INV-13, §7.1, §12.12/7
    let (_, next) = register(&party, false).await;
    assert_eq!(next.status, StatusCode::CONFLICT);
    assert_eq!(next.json()["code"], "instance-exists");
    device_key_claims(e, c).await;
}

// OP-150 m.3 (r), §14.5, CSRF
#[tokio::test]
async fn the_frontend_api_is_same_origin_only() {
    let e = env(43, "lg-so", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut b = e.browser("b");
    let signed = b.sign_in("alice@example.com").await;
    assert_eq!(signed.status, StatusCode::OK);
    let set: Vec<String> = signed
        .headers
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    let session = set
        .iter()
        .find(|c| c.starts_with("__Host-access-session="))
        .unwrap();
    for attr in ["Secure", "HttpOnly", "SameSite=Lax", "Path=/"] {
        assert!(session.contains(attr), "{session}");
    }
    assert!(!session.contains("Domain="));

    for (name, value) in [
        ("origin", "https://evil.example"),
        ("origin", "http://acme.example"),
        ("origin", "null"),
        ("sec-fetch-site", "cross-site"),
        ("sec-fetch-site", "same-site"),
    ] {
        let key = b.key();
        for path in [
            "/v1/sessions/current/sign-out",
            "/v1/account/totp",
            "/v1/me/auth-context",
            "/v1/me/instances/challenges",
        ] {
            let r = b
                .send_with("POST", path, None, Some(&key), &[(name, value)])
                .await;
            assert_eq!(r.status, StatusCode::FORBIDDEN, "{name}: {value} {path}");
            assert_eq!(r.json()["code"], "cross-site");
            assert!(r.headers.get("access-control-allow-origin").is_none());
        }
    }
    assert_eq!(b.get("/v1/sessions/current").await.status, StatusCode::OK);
    for extra in [
        [("origin", "https://acme.example")],
        [("sec-fetch-site", "same-origin")],
        [("sec-fetch-site", "none")],
    ] {
        let key = b.key();
        let r = b
            .send_with("POST", "/v1/me/auth-context", None, Some(&key), &extra)
            .await;
        assert_eq!(r.status, StatusCode::OK, "{extra:?}");
    }
    let key = b.key();
    let preflight = b
        .send_with(
            "OPTIONS",
            "/v1/me/auth-context",
            None,
            Some(&key),
            &[
                ("origin", "https://evil.example"),
                ("access-control-request-method", "POST"),
            ],
        )
        .await;
    assert!(preflight.status.is_client_error(), "{}", preflight.status);
    assert!(
        preflight
            .headers
            .get("access-control-allow-origin")
            .is_none()
    );
    let page = b
        .send_with(
            "GET",
            "/v1/sessions/current",
            None,
            None,
            &[("origin", "https://evil.example")],
        )
        .await;
    assert!(page.headers.get("access-control-allow-origin").is_none());
}

/// The queued Claim orders once `ready` holds for them; the outbox shows a row only once every
/// older transaction in the cluster has ended.
async fn claim_orders(
    e: &Env,
    ready: impl Fn(&[access_identity_account::domain::claims::ClaimOrder]) -> bool,
) -> Vec<access_identity_account::domain::claims::ClaimOrder> {
    use access_identity_account::domain::claims::{ClaimOrder, OUTBOX_PREFIX};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let orders: Vec<ClaimOrder> = access_store::identity::poll(
            &e.db.reader,
            access_store::identity::Cursor::default(),
            1000,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|o| o.kind.starts_with(OUTBOX_PREFIX))
        .map(|o| ClaimOrder::from_bytes(&o.payload).unwrap())
        .collect();
        if ready(&orders) {
            return orders;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "claim orders: {:?}",
            orders.iter().map(|o| &o.class).collect::<Vec<_>>()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// §10.1.3 device key registration, §10.1.5, IDP-2, K16, OP-150 L2: the registered key is recorded
/// once for its Instance, and queues its `authenticator_binding` and the session's
/// `authentication`, both bound to that Instance, with the key only by digest; the first
/// registration's `party_register` binds the subject to its Party as `identity_binding_person`,
/// by digest; the user's termination of the Instance retires the key and ends its binding line.
async fn device_key_claims(e: &Env, c: &mut Web) {
    use access_identity_account::domain::claims::{Bind, ClaimOrder, Content};
    use access_kernel::claim::body::{AuthMethod, AuthenticatorKind, Body};
    let on_instance = |o: &&ClaimOrder| o.bind == Bind::Instance([9; 16]);
    let orders = claim_orders(e, |o| o.iter().filter(on_instance).count() >= 2).await;
    let bound: Vec<&ClaimOrder> = orders.iter().filter(on_instance).collect();
    assert_eq!(bound.len(), 2, "one key, one Instance, recorded once");
    assert!(bound.iter().any(|o| matches!(
        &o.content,
        Content::Body { body: Body::AuthenticatorBinding(b), .. } if b.kind == AuthenticatorKind::DeviceKey
    )));
    assert!(bound.iter().any(|o| matches!(
        &o.content,
        Content::Body { body: Body::Authentication(a), .. } if a.method == AuthMethod::DeviceKey
    )));
    let bindings: Vec<&ClaimOrder> = orders
        .iter()
        .filter(|o| o.class == "identity_binding_person")
        .collect();
    assert_eq!(bindings.len(), 1, "one Party, bound once");
    assert!(matches!(
        &bindings[0].content,
        Content::Body {
            body: Body::IdentityBinding(_),
            disclose: true
        }
    ));
    assert!(bindings[0].line.is_some() && bindings[0].bind == Bind::None);

    let termination = json!({
        "nonce": b64url_encode(&[1; 16]),
        "basis": b64url_encode(&[2; 16]),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:05:00Z",
        "ais": b64url_encode(&[0xd2; 8]),
    });
    let ended = c
        .send(
            "DELETE",
            &format!("/v1/me/instances/{}", b64url_encode(&[9; 16])),
            Some(termination),
            Some("del-9"),
        )
        .await;
    assert_eq!(ended.status, StatusCode::OK);
    let removed = |o: &ClaimOrder| {
        o.retract
            && matches!(
                &o.content,
                Content::Body { body: Body::AuthenticatorBinding(b), .. } if b.kind == AuthenticatorKind::DeviceKey
            )
    };
    let orders = claim_orders(e, |o| o.iter().any(removed)).await;
    let removal = orders.iter().find(|o| removed(o)).unwrap();
    let binding = bound
        .iter()
        .find(|o| o.class == "authenticator_binding")
        .unwrap();
    assert_eq!(removal.line, binding.line);
    assert_eq!(removal.bind, Bind::None);
}

/// A browser signed in with the passkey `key` (AAL2).
async fn passkey_session(
    e: &Env,
    name: &str,
    key: &mut Authenticator,
    id: &str,
    user: &str,
) -> Web {
    let mut w = e.browser(name);
    let first = w.start().await;
    let options = passkey_node(&first);
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let signed = w
        .submit(
            &first,
            "passkey",
            json!({ "passkey_credential": assertion_json(key, id, user, &challenge).to_string() }),
        )
        .await;
    assert_eq!(
        signed.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&signed.body)
    );
    w
}

/// `POST /v1/me/instances`: a new device `key` of Party `[8; 16]`, registering the Party too
/// when `new`.
async fn register_device(w: &mut Web, key: &SoftSigner, new: bool) -> Answer {
    let ch = w.post("/v1/me/instances/challenges", None).await;
    assert_eq!(ch.status, StatusCode::CREATED);
    let mut body = json!({
        "challenge": ch.json()["challenge"],
        "party": b64url_encode(&[8; 16]),
        "key": b64url_encode(&access_identity_session::domain::device::cose_key(&key.public_key())),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:05:00Z",
        "ais": b64url_encode(&[0xd2; 40]),
    });
    if new {
        body["register_ais"] = json!(b64url_encode(&[0xd2; 40]));
    }
    w.post("/v1/me/instances", Some(body)).await
}

/// `POST /v1/me/instances/bindings` (OP-149 m.32): `key` presented, the proof over the
/// challenge signed by `signer`.
async fn bind_device(w: &mut Web, key: &SoftSigner, signer: &SoftSigner) -> Answer {
    use access_identity_session::domain::device::{POP_CONTENT_TYPE, cose_key, kid};
    let ch = w.post("/v1/me/instances/challenges", None).await;
    assert_eq!(ch.status, StatusCode::CREATED);
    let challenge = b64url_decode(ch.json()["challenge"].as_str().unwrap()).unwrap();
    let public = key.public_key();
    let pop = sign_sign1(signer, kid(&public), POP_CONTENT_TYPE, &challenge).unwrap();
    w.post(
        "/v1/me/instances/bindings",
        Some(json!({
            "challenge": ch.json()["challenge"],
            "key": b64url_encode(&cose_key(&public)),
            "pop": b64url_encode(&pop),
        })),
    )
    .await
}

/// The `instance` the session's `auth_context` names, if any (OP-149 m.30 (c)).
async fn auth_context_instance(e: &Env, w: &mut Web) -> Option<Vec<u8>> {
    let issued = w.post("/v1/me/auth-context", None).await;
    assert_eq!(issued.status, StatusCode::OK);
    auth_context_fields(e, &issued.json())
        .into_iter()
        .find(|(k, _)| *k == suiss_crypto::dcbor::Value::text("instance"))
        .and_then(|(_, v)| match v {
            suiss_crypto::dcbor::Value::Bytes(b) => Some(b),
            _ => None,
        })
}

// OP-149 m.32, m.6, m.16 (a), INV-13, §5.1, OP-150 m.14 (f), m.12 (e), (f)
#[tokio::test]
async fn a_known_device_binds_a_later_session() {
    use access_identity_account::adapters::pg::PgTx;
    use access_identity_account::domain::claims::{Bind, ClaimOrder, Content};
    use access_identity_ui::app::devices::{DeviceKey, bind_party, record_device_key};
    use access_kernel::claim::body::{AuthMethod, Body};
    use access_kernel::verify::key_scope::thumbprint;
    let e = env(46, "lg-kd", AuthPolicy::DEFAULT).await;
    e.account("ann@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("ann@example.com").await.step(), "complete");
    let (mut key, id, user) = register_passkey(&mut b, "ann@example.com").await;
    let mut c = passkey_session(&e, "c", &mut key, &id, &user).await;
    let (device, _) = SoftSigner::generate_ed25519().unwrap();
    let registered = register_device(&mut c, &device, true).await;
    assert_eq!(registered.status, StatusCode::CREATED);
    assert_eq!(registered.json()["instance"], b64url_encode(&[9; 16]));

    let mut d = passkey_session(&e, "d", &mut key, &id, &user).await;
    assert_eq!(auth_context_instance(&e, &mut d).await, None);
    let bound = bind_device(&mut d, &device, &device).await;
    assert_eq!(
        bound.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&bound.body)
    );
    assert_eq!(bound.json()["instance"], b64url_encode(&[9; 16]));
    assert_eq!(bound.json()["party"], b64url_encode(&[8; 16]));
    assert_eq!(
        bound.json()["kid"],
        b64url_encode(&thumbprint(&device.public_key()))
    );
    assert_eq!(auth_context_instance(&e, &mut d).await, Some(vec![9; 16]));
    assert_eq!(auth_context_instance(&e, &mut c).await, Some(vec![9; 16]));
    // INV-13
    assert_eq!(
        bind_device(&mut d, &device, &device).await.json()["code"],
        "instance-exists"
    );
    let (other, _) = SoftSigner::generate_ed25519().unwrap();
    let second = register_device(&mut d, &other, false).await;
    assert_eq!(second.status, StatusCode::CONFLICT);
    assert_eq!(second.json()["code"], "instance-exists");
    let mut f = passkey_session(&e, "f", &mut key, &id, &user).await;
    let unknown = bind_device(&mut f, &other, &other).await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert_eq!(unknown.json()["code"], "invalid-party");
    let forged = bind_device(&mut f, &device, &other).await;
    assert_eq!(forged.status, StatusCode::BAD_REQUEST);
    assert_eq!(forged.json()["code"], "invalid-proof-of-possession");
    assert_eq!(auth_context_instance(&e, &mut f).await, None);

    // OP-149
    let bob = e.account("bob@example.com").await;
    let mut g = e.browser("g");
    assert_eq!(g.sign_in("bob@example.com").await.step(), "complete");
    let (mut bob_key, bob_id, bob_user) =
        register_passkey_with(&mut g, "bob@example.com", 0xc2).await;
    let (bob_device, _) = SoftSigner::generate_ed25519().unwrap();
    let mut tx = PgTx::new(TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap());
    assert!(
        bind_party(&mut tx, &bob, &[6; 16], &[0xd2; 40])
            .await
            .unwrap()
    );
    let recorded = record_device_key(
        &mut tx,
        &DeviceKey {
            subject: bob,
            key: bob_device.public_key(),
            instance: [7; 16],
            session: None,
        },
    )
    .await
    .unwrap();
    assert!(recorded.is_some());
    tx.0.commit().await.unwrap();
    let mut h = passkey_session(&e, "h", &mut bob_key, &bob_id, &bob_user).await;
    let anns = bind_device(&mut h, &device, &device).await;
    assert_eq!(anns.status, StatusCode::BAD_REQUEST);
    assert_eq!(anns.json()["code"], "invalid-party");
    let own = bind_device(&mut h, &bob_device, &bob_device).await;
    assert_eq!(own.status, StatusCode::CREATED);
    assert_eq!(own.json()["instance"], b64url_encode(&[7; 16]));
    assert_eq!(own.json()["party"], b64url_encode(&[6; 16]));
    assert_eq!(auth_context_instance(&e, &mut h).await, Some(vec![7; 16]));

    // OP-150 m.12 (f)
    let login_on = |instance: [u8; 16]| {
        move |o: &&ClaimOrder| {
            o.bind == Bind::Instance(instance)
                && matches!(
                    &o.content,
                    Content::Body { body: Body::Authentication(a), .. } if a.method == AuthMethod::DeviceKey
                )
        }
    };
    let orders = claim_orders(&e, |o| {
        o.iter().filter(login_on([9; 16])).count() >= 2
            && o.iter().filter(login_on([7; 16])).count() >= 1
    })
    .await;
    assert_eq!(
        orders.iter().filter(login_on([9; 16])).count(),
        2,
        "the registration's and the binding's"
    );
    assert_eq!(
        orders
            .iter()
            .filter(|o| o.class == "authenticator_binding" && o.bind == Bind::Instance([9; 16]))
            .count(),
        1,
        "the key was recorded once"
    );

    // OP-150 m.12 (e), m.14 (f)
    let ended = c
        .send(
            "DELETE",
            &format!("/v1/me/instances/{}", b64url_encode(&[9; 16])),
            Some(json!({
                "nonce": b64url_encode(&[1; 16]),
                "basis": b64url_encode(&[2; 16]),
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-01-01T00:05:00Z",
                "ais": b64url_encode(&[0xd2; 8]),
            })),
            Some("del-kd"),
        )
        .await;
    assert_eq!(ended.status, StatusCode::OK);
    assert_eq!(auth_context_instance(&e, &mut d).await, None);
    assert_eq!(auth_context_instance(&e, &mut c).await, None);
    assert_eq!(auth_context_instance(&e, &mut h).await, Some(vec![7; 16]));
    let retired = bind_device(&mut f, &device, &device).await;
    assert_eq!(retired.json()["code"], "invalid-party");
}

// §10.2.2, TN-102, OP-146 m.14 (h)
#[tokio::test]
async fn email_links_and_codes() {
    let e = env(8, "lg-h", AuthPolicy::DEFAULT).await;
    e.account("carol@example.com").await;
    let mut b = e.browser("b");
    let at = b.identify("carol@example.com").await;
    let methods: Vec<String> = at.json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["method"].as_str().map(str::to_owned))
        .collect();
    assert!(methods.contains(&"magic_link".to_owned()));
    let waiting = b.submit(&at, "magic_link", json!({})).await;
    assert_eq!(waiting.status, StatusCode::OK);
    assert_eq!(waiting.messages(), ["email.sent"]);
    let link = e.outbox.last();
    let token = link
        .strip_prefix(&format!("https://{HOST}/login/link#"))
        .unwrap();
    for _ in 0..2 {
        let preview = b
            .post("/v1/login/link/preview", Some(json!({ "token": token })))
            .await;
        assert_eq!(
            preview.json(),
            json!({ "state": "confirm", "same_device": true })
        );
    }
    let mut phone = e.browser("p");
    let other = phone
        .post("/v1/login/link/confirm", Some(json!({ "token": token })))
        .await;
    assert_eq!(other.json(), json!({ "state": "needs_confirmation" }));
    let polled = b.get(&waiting.action()).await;
    assert_eq!(polled.messages(), ["email.sent"]);
    let yes = phone
        .post(
            "/v1/login/link/confirm",
            Some(json!({ "token": token, "other_device": true })),
        )
        .await;
    assert_eq!(
        yes.json(),
        json!({ "state": "confirmed", "same_device": false })
    );
    assert!(!phone.jar.contains_key("__Host-access-session"));
    let done = b.get(&waiting.action()).await;
    assert_eq!(done.step(), "complete");
    assert!(b.jar.contains_key("__Host-access-session"));
    let used = phone
        .post(
            "/v1/login/link/confirm",
            Some(json!({ "token": token, "other_device": true })),
        )
        .await;
    assert_eq!(used.status, StatusCode::GONE);

    let mut c = e.browser("c");
    let at = c.identify("carol@example.com").await;
    let code_step = c.submit(&at, "email_code", json!({})).await;
    assert_eq!(code_step.messages(), ["email.sent"]);
    let code = e.outbox.last();
    let wrong = c
        .submit(
            &code_step,
            "email_code",
            json!({ "email_code": "00000000" }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let ok = c
        .submit(&code_step, "email_code", json!({ "email_code": code }))
        .await;
    assert_eq!(
        ok.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&ok.body)
    );
}

/// The answer with what differs between any two requests masked: the flow handle, the
/// passkey challenge and credential list (TN-97 makes those per identifier), the echoed
/// identifier, cookie values, `Date` and the request id.
fn masked(a: &Answer) -> (u16, Vec<(String, String)>, String) {
    let mut headers: Vec<(String, String)> = a
        .headers
        .iter()
        .filter(|(n, _)| *n != header::DATE && n.as_str() != "x-request-id")
        .map(|(n, v)| {
            let v = v.to_str().unwrap();
            let v = if *n == header::SET_COOKIE {
                let (name, rest) = v.split_once('=').unwrap();
                let attrs = rest.split_once(';').map_or("", |(_, a)| a);
                format!("{name}=*;{attrs}")
            } else if *n == header::CONTENT_LENGTH {
                "*".to_owned()
            } else {
                v.to_owned()
            };
            (n.as_str().to_owned(), v)
        })
        .collect();
    headers.sort();
    let mut body = a.json();
    if let Some(map) = body.as_object_mut() {
        map.insert("flow".into(), "*".into());
        map.insert("action".into(), "*".into());
    }
    if let Some(nodes) = body["nodes"].as_array_mut() {
        for n in nodes {
            if n.get("options").is_some() {
                n["options"]["challenge"] = "*".into();
                n["options"]["allowCredentials"] = "*".into();
            }
            if n["name"] == "identifier" && n.get("value").is_some() {
                n["value"] = "*".into();
            }
        }
    }
    (a.status.as_u16(), headers, body.to_string())
}

// OP-146 m.4 (h), CR-40, X34, TN-82, TN-96, TN-97, OP-146 m.10 (e)
#[tokio::test]
async fn enumeration_parity_on_login() {
    // CVE-2026-4633
    let e = env(9, "lg-i", AuthPolicy::DEFAULT).await;
    e.account("ann1@example.com").await;
    let locked = e.account("ann3@example.com").await;
    let gone = e.account("ann4@example.com").await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.kit.vault());
    change_status(&pg, &e.realm(), locked, AccountStatus::Locked, &ADMIN)
        .await
        .unwrap();
    deactivate(&pg, &e.realm(), gone, &ADMIN).await.unwrap();
    let who = [
        "ann1@example.com",
        "ann2@example.com",
        "ann3@example.com",
        "ann4@example.com",
    ];
    let mut identified = Vec::new();
    let mut wrong = Vec::new();
    let mut right = Vec::new();
    for (i, w) in who.iter().enumerate() {
        let mut b = e.browser(&format!("e{i}"));
        let at = b.identify(w).await;
        identified.push(masked(&at));
        let bad = b
            .submit(&at, "password", json!({ "password": "not the one" }))
            .await;
        assert!(!bad.headers.contains_key(header::LOCATION));
        wrong.push(masked(&bad));
        if i > 0 {
            e.advance(2_000);
            let good = b.submit(&bad, "password", json!({ "password": PW })).await;
            right.push(masked(&good));
        }
    }
    for set in [&identified, &wrong, &right] {
        for other in &set[1..] {
            assert_eq!(&set[0], other);
        }
    }
    assert_eq!(wrong[0].0, 401);
    assert!(wrong[0].2.contains("login.failed"));
    assert_eq!(right[0], wrong[0]);
}

// 3662, 4091, 4107, X-L11, X34, CR-40, TN-76, OP-153 m.11 (b)
#[tokio::test]
async fn a_deleted_account_cannot_be_told_from_one_that_never_existed() {
    use access_identity_account::app::privacy::{DeletionSource, request_deletion, tombstone_due};
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    let e = env(37, "del-a", AuthPolicy::DEFAULT).await;
    let gone = e.account("gone@example.com").await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.kit.vault());
    let mut tx = pg.begin(e.tenant, e.realm).await.unwrap();
    request_deletion(
        &mut tx,
        &e.realm(),
        gone,
        DeletionSource::SelfService,
        None,
        0,
        &ADMIN,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(tombstone_due(&pg, &e.realm(), &ADMIN).await.unwrap(), 1);
    let who = ["gone@example.com", "never@example.com"];
    let (mut identified, mut wrong, mut right) = (Vec::new(), Vec::new(), Vec::new());
    for (i, w) in who.iter().enumerate() {
        let mut b = e.browser(&format!("del{i}"));
        let at = b.identify(w).await;
        identified.push(masked(&at));
        let bad = b
            .submit(&at, "password", json!({ "password": "not the one" }))
            .await;
        wrong.push(masked(&bad));
        e.advance(2_000);
        let good = b.submit(&bad, "password", json!({ "password": PW })).await;
        right.push(masked(&good));
    }
    for set in [&identified, &wrong, &right] {
        assert_eq!(set[0], set[1]);
    }
    assert_eq!(right[0].0, 401);
    let mut signed_up = Vec::new();
    for (i, w) in who.iter().enumerate() {
        let mut b = e.browser(&format!("del-su{i}"));
        signed_up.push(masked(&b.register(w).await));
    }
    assert_eq!(signed_up[0], signed_up[1]);
    assert_eq!(signed_up[0].0, 200);
    // OP-153 m.11 (b)
    let sent = e.sent();
    assert_eq!(sent.len(), 1, "a retired address hears nothing: {sent:?}");
    assert_eq!(sent[0].0, "relay.message.otp.v1");
}

fn percentile(sorted: &[u128], p: usize) -> u128 {
    sorted[(sorted.len() - 1) * p / 100]
}

// OP-146 m.4 (h), SA-59, TN-82
#[tokio::test]
#[ignore = "nightly: login timing parity (OP-146 m.4 (h))"]
async fn enumeration_timing_parity_nightly() {
    const N: usize = 200;
    const PER_CLASS: usize = 4;
    let e = env_with(10, "lg-t", AuthPolicy::DEFAULT, true).await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.kit.vault());
    let mut classes: Vec<Vec<String>> = vec![Vec::new(); 4];
    for i in 0..PER_CLASS {
        let active = format!("act{i}@example.com");
        e.account(&active).await;
        classes[0].push(active);
        classes[1].push(format!("unk{i}@example.com"));
        let locked = format!("lck{i}@example.com");
        let s = e.account(&locked).await;
        change_status(&pg, &e.realm(), s, AccountStatus::Locked, &ADMIN)
            .await
            .unwrap();
        classes[2].push(locked);
        let gone = format!("off{i}@example.com");
        let s = e.account(&gone).await;
        deactivate(&pg, &e.realm(), s, &ADMIN).await.unwrap();
        classes[3].push(gone);
    }
    let warm = "warm@example.com";
    e.account(warm).await;
    for i in 0..30 {
        e.advance(61_000);
        let mut b = e.browser(&format!("w{i}"));
        assert_eq!(b.sign_in(warm).await.step(), "complete");
    }
    let mut times: Vec<Vec<u128>> = vec![Vec::new(); 4];
    for round in 0..N {
        for (class, names) in classes.iter().enumerate() {
            let mut b = e.browser(&format!("t{round}-{class}"));
            let at = b.identify(&names[round % PER_CLASS]).await;
            e.advance(61_000);
            let started = std::time::Instant::now();
            let a = b
                .submit(&at, "password", json!({ "password": "not the password" }))
                .await;
            times[class].push(started.elapsed().as_micros());
            assert_eq!(a.status, StatusCode::UNAUTHORIZED);
        }
    }
    for t in &mut times {
        t.sort_unstable();
    }
    let (p50, p95) = (percentile(&times[0], 50), percentile(&times[0], 95));
    for t in &times[1..] {
        let (q50, q95) = (percentile(t, 50), percentile(t, 95));
        assert!(
            q50.abs_diff(p50) <= (p50 / 4).max(10_000),
            "p50 {q50} vs {p50}"
        );
        assert!(
            q95.abs_diff(p95) <= (p95 / 2).max(20_000),
            "p95 {q95} vs {p95}"
        );
    }
}

// OP-149 m.6, m.8, m.9, m.16 (a), G57
/// The payload of a signed `auth_context` the realm key issued (OP-149 m.8): verified, its
/// digest checked, decoded to its map entries.
fn auth_context_fields(
    e: &Env,
    issued: &Value,
) -> Vec<(suiss_crypto::dcbor::Value, suiss_crypto::dcbor::Value)> {
    use access_identity_session::domain::auth_context::{CONTENT_TYPE, DIGEST_LABEL};
    use suiss_crypto::cose::{Algorithm, KeySet, verify_sign1};
    use suiss_crypto::dcbor::{self, Limits};
    use suiss_crypto::digest::context_digest;

    let sign1 = b64url_decode(issued["auth_context"].as_str().unwrap()).unwrap();
    let key = e.signer.0.public_key();
    let mut keys = KeySet::default();
    keys.insert(access_kernel::verify::key_scope::thumbprint(&key), key)
        .unwrap();
    keys.allowed.insert(Algorithm::Ed25519);
    let verified =
        verify_sign1(&suiss_crypto::sig::PureBackend, &sign1, &keys, CONTENT_TYPE).unwrap();
    assert_eq!(
        b64url_decode(issued["digest"].as_str().unwrap()).unwrap(),
        context_digest(DIGEST_LABEL, &verified.payload).0
    );
    let dcbor::Value::Map(fields) = dcbor::decode(&verified.payload, Limits::CEILING).unwrap()
    else {
        panic!("not a map");
    };
    fields
}

#[tokio::test]
async fn product_endpoints_follow_the_frontend_contract() {
    use suiss_crypto::dcbor::Value as Cbor;

    let e = env(41, "lg-me", AuthPolicy::DEFAULT).await;
    e.account("alice@example.com").await;
    let mut anon = e.browser("anon");
    assert_eq!(
        anon.post("/v1/me/instances/challenges", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        anon.post("/v1/me/auth-context", None).await.status,
        StatusCode::UNAUTHORIZED
    );

    let mut b = e.browser("b");
    b.sign_in("alice@example.com").await;
    let c = b.post("/v1/me/instances/challenges", None).await;
    assert_eq!(c.status, StatusCode::CREATED);
    assert_eq!(
        b64url_decode(c.json()["challenge"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    // OP-149 m.16 (a)
    assert_eq!(
        b64url_decode(c.json()["domain"].as_str().unwrap())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        b64url_decode(c.json()["basis"].as_str().unwrap())
            .unwrap()
            .len(),
        16
    );
    assert_eq!(c.json()["pep"], "access-identity");
    assert!(c.json().get("party").is_none());
    let registration = json!({
        "challenge": c.json()["challenge"],
        "party": b64url_encode(&[8; 16]),
        "key": "pQECIAEhWCA",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:05:00Z",
        "ais": "0oRD",
        "register_ais": "0oRD",
    });
    let weak = b.post("/v1/me/instances", Some(registration.clone())).await;
    assert_eq!(weak.status, StatusCode::FORBIDDEN);
    assert_eq!(weak.json()["code"], "step-up-required");
    let mut extra = registration;
    extra["pop"] = json!("b");
    let extra = b.post("/v1/me/instances", Some(extra)).await;
    assert_eq!(extra.status, StatusCode::BAD_REQUEST);
    // OP-149 m.16 (f)
    let termination = json!({
        "nonce": b64url_encode(&[1; 16]),
        "basis": b64url_encode(&[2; 16]),
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2026-01-01T00:05:00Z",
        "ais": b64url_encode(&[0xd2; 8]),
    });
    let prefixed = b
        .send(
            "DELETE",
            "/v1/me/instances/ins_0123456789abcdefghjkmnpqrs",
            Some(termination.clone()),
            Some("del-1"),
        )
        .await;
    assert_eq!(prefixed.status, StatusCode::BAD_REQUEST);
    let by_id = b
        .send(
            "DELETE",
            &format!("/v1/me/instances/{}", b64url_encode(&[9; 16])),
            Some(termination),
            Some("del-2"),
        )
        .await;
    assert_eq!(by_id.status, StatusCode::FORBIDDEN);
    assert_eq!(by_id.json()["code"], "step-up-required");

    let issued = b.post("/v1/me/auth-context", None).await;
    assert_eq!(issued.status, StatusCode::OK);
    let fields = auth_context_fields(&e, &issued.json());
    let aal = fields
        .iter()
        .find(|(k, _)| *k == Cbor::text("aal"))
        .map(|(_, v)| v.clone());
    assert_eq!(aal, Some(Cbor::text("aal1")));
    // OP-149 m.30 (c)
    assert!(fields.iter().all(|(k, _)| *k != Cbor::text("instance")));
    let bound = b
        .post(
            "/v1/me/auth-context",
            Some(json!({
                "content_type": "application/json; charset=utf-8",
                "content_digest": b64url_encode(&[1; 32]),
            })),
        )
        .await;
    assert_eq!(bound.status, StatusCode::BAD_REQUEST);
    assert_eq!(bound.json()["code"], "invalid-content");

    let digest = b64url_encode(&[3; 32]);
    let unregistered = b
        .get(&format!(
            "/v1/approve?request={digest}&redirect_uri=https%3A%2F%2Fnope.example%2Fcb&state=s1"
        ))
        .await;
    assert_eq!(unregistered.status, StatusCode::BAD_REQUEST);
    assert_eq!(unregistered.json()["code"], "invalid-redirect-uri");
    assert!(unregistered.headers.get(header::LOCATION).is_none());
    let no_state = b
        .get(&format!(
            "/v1/approve?request={digest}&redirect_uri=https%3A%2F%2Fnope.example%2Fcb"
        ))
        .await;
    assert_eq!(no_state.status, StatusCode::BAD_REQUEST);
}

// OP-149 m.33 (d), m.35, RFC 6749 §3.1.2, RFC 8252
#[tokio::test]
async fn a_products_platform_registration_is_its_approval_return_address() {
    use access_kernel::verify::key_scope::thumbprint;
    let e = env(46, "lg-pr", AuthPolicy::DEFAULT).await;
    e.platform_client(&[
        "https://work.example/v1/access/approval",
        "http://127.0.0.1:8190/v1/access/approval",
    ])
    .await;
    let (device, _) = SoftSigner::generate_ed25519().unwrap();
    let ais = sign_sign1(
        &device,
        thumbprint(&device.public_key()),
        "application/access-ais+cbor",
        b"contribute",
    )
    .unwrap();
    let mut coordinator = e.browser("work");
    let pushed = coordinator
        .post(
            "/v1/approve/requests",
            Some(json!({
                "request": {
                    "requester": { "party": b64url_encode(&[1; 16]) },
                    "action": { "namespace": "work", "name": "commit", "major": 1, "schema": b64url_encode(&[1; 32]) },
                    "resource": { "namespace": "work.ledger", "path": ["led_main"], "incarnation": 0 },
                    "params": { "ledger": { "eq": "main" } },
                    "capacity": "own",
                    "reason": "Close the main ledger for the period.",
                    "require_action": {
                        "domain": b64url_encode(&[46; 32]),
                        "nonce": b64url_encode(&[30; 16]),
                        "intent": b64url_encode(&[0x44; 32]),
                    },
                    "expires_at": e.clock.now_ms() + 3_600_000,
                },
                "contribution": {
                    "nonce": b64url_encode(&[30; 16]),
                    "basis": { "grant": b64url_encode(&[1; 16]), "holder": b64url_encode(&[8; 16]), "since": 0 },
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2026-01-01T00:05:00Z",
                    "ais": b64url_encode(&ais),
                },
            })),
        )
        .await;
    assert_eq!(
        pushed.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&pushed.body)
    );
    let digest = pushed.json()["digest"].as_str().unwrap().to_owned();
    let mut b = e.browser("b");
    let call =
        |redirect: &str| format!("/v1/approve?request={digest}&redirect_uri={redirect}&state=s1");
    for registered in [
        "https%3A%2F%2Fwork.example%2Fv1%2Faccess%2Fapproval",
        "http%3A%2F%2F127.0.0.1%3A8190%2Fv1%2Faccess%2Fapproval",
    ] {
        let accepted = b.get(&call(registered)).await;
        assert_eq!(
            accepted.status,
            StatusCode::OK,
            "{registered}: {}",
            String::from_utf8_lossy(&accepted.body)
        );
    }
    for other in [
        "https%3A%2F%2Fwork.example%2Fv1%2Faccess%2Fapproval%2F",
        "https%3A%2F%2Fwork.example%2Fv1%2Faccess%2Fapproval%3Fx%3D1",
        "https%3A%2F%2Fwork.example%2Fother",
        "https%3A%2F%2Fwork.example%2Fv1%2Faccess%2Fapproval%2Fthird",
        "http%3A%2F%2F127.0.0.1%3A8191%2Fv1%2Faccess%2Fapproval",
        "http%3A%2F%2Fwork.example%2Fv1%2Faccess%2Fapproval",
        "https%3A%2F%2Fnope.example%2Fcb",
    ] {
        let refused = b.get(&call(other)).await;
        assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{other}");
        assert_eq!(refused.json()["code"], "invalid-redirect-uri", "{other}");
        assert!(refused.headers.get(header::LOCATION).is_none());
    }
}

/// Registers a passkey from `b`'s signed-in session; returns the authenticator, its id and the
/// user handle.
// IDP-8, §10.2 AAL2, TN-96
#[tokio::test]
async fn a_passkey_is_the_second_factor_after_the_password() {
    let e = env(0x51, "lg-2f", AuthPolicy::DEFAULT).await;
    e.account("dora@example.com").await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("dora@example.com").await.step(), "complete");
    let (mut key, id, user) = register_passkey(&mut b, "dora@example.com").await;

    let mut c = e.browser("c");
    let second = c.sign_in("dora@example.com").await;
    assert_eq!(
        second.step(),
        "second_factor",
        "{} {}",
        second.status,
        String::from_utf8_lossy(&second.body)
    );
    let options = passkey_node(&second);
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let mut stranger = Authenticator::new(Key::es256());
    let stranger_id = b64url_encode(&stranger.credential_id);
    let bad = assertion_json(&mut stranger, &stranger_id, &user, &challenge);
    let refused = c
        .submit(
            &second,
            "passkey",
            json!({ "passkey_credential": bad.to_string() }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.step(), "second_factor");
    let options = passkey_node(&refused);
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let good = assertion_json(&mut key, &id, &user, &challenge);
    let done = c
        .submit(
            &refused,
            "passkey",
            json!({ "passkey_credential": good.to_string() }),
        )
        .await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(c.get("/v1/sessions/current").await.status, StatusCode::OK);
}

async fn register_passkey(b: &mut Web, who: &str) -> (Authenticator, String, String) {
    register_passkey_with(b, who, 0xc1).await
}

/// Registers a passkey whose credential id is 32 bytes of `credential`.
async fn register_passkey_with(
    b: &mut Web,
    who: &str,
    credential: u8,
) -> (Authenticator, String, String) {
    let reg = b
        .post("/v1/account/passkeys", Some(json!({ "name": who })))
        .await;
    assert_eq!(reg.status, StatusCode::CREATED);
    let r = reg.json();
    let challenge = b64url_decode(r["options"]["challenge"].as_str().unwrap()).unwrap();
    let user = r["options"]["user"]["id"].as_str().unwrap().to_owned();
    let mut key = Authenticator::new(Key::es256());
    key.credential_id = vec![credential; 32];
    let (cdj, att) = key.register(RP_ID, ORIGIN, &challenge);
    let id = b64url_encode(&key.credential_id);
    let credential = json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "attestationObject": b64url_encode(&att),
            "transports": ["internal"],
        },
        "clientExtensionResults": {},
    });
    let path = format!(
        "/v1/account/passkeys/{}",
        r["registration"].as_str().unwrap()
    );
    let done = b
        .post(&path, Some(json!({ "credential": credential })))
        .await;
    assert_eq!(done.status, StatusCode::CREATED);
    (key, id, user)
}

fn assertion_json(key: &mut Authenticator, id: &str, user: &str, challenge: &[u8]) -> Value {
    let (cdj, ad, sig) = key.assert(RP_ID, ORIGIN, challenge);
    json!({
        "id": id, "rawId": id, "type": "public-key",
        "response": {
            "clientDataJSON": b64url_encode(&cdj),
            "authenticatorData": b64url_encode(&ad),
            "signature": b64url_encode(&sig),
            "userHandle": user,
        },
        "clientExtensionResults": {},
    })
}

// OP-150 m.3 (r), OP-149 m.9, §9.14.1, §9.14.5, SI-5, §13.7.3, SEC18
#[tokio::test]
async fn an_approval_runs_on_the_hosted_surface() {
    use access_identity_account::domain::claims::Bind;
    use access_kernel::verify::key_scope::thumbprint;
    let e = env(45, "lg-ap", AuthPolicy::DEFAULT).await;
    e.account("ann@example.com").await;
    let redirect = "https://shop.example/approved";
    e.client(redirect).await;
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("ann@example.com").await.step(), "complete");
    let (mut key, id, user) = register_passkey(&mut b, "ann@example.com").await;
    let mut c = e.browser("c");
    let first = c.start().await;
    let options = passkey_node(&first);
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let signed = c
        .submit(
            &first,
            "passkey",
            json!({ "passkey_credential": assertion_json(&mut key, &id, &user, &challenge).to_string() }),
        )
        .await;
    assert_eq!(signed.step(), "complete");
    let (device, _) = SoftSigner::generate_ed25519().unwrap();
    let ch = c.post("/v1/me/instances/challenges", None).await;
    assert_eq!(ch.status, StatusCode::CREATED);
    let registered = c
        .post(
            "/v1/me/instances",
            Some(json!({
                "challenge": ch.json()["challenge"],
                "party": b64url_encode(&[8; 16]),
                "key": b64url_encode(&access_identity_session::domain::device::cose_key(&device.public_key())),
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-01-01T00:05:00Z",
                "ais": b64url_encode(&[0xd2; 40]),
                "register_ais": b64url_encode(&[0xd2; 40]),
            })),
        )
        .await;
    assert_eq!(registered.status, StatusCode::CREATED);
    // OP-149 m.30 (c)
    let issued = c.post("/v1/me/auth-context", None).await;
    assert_eq!(issued.status, StatusCode::OK);
    let instance = auth_context_fields(&e, &issued.json())
        .into_iter()
        .find(|(k, _)| *k == suiss_crypto::dcbor::Value::text("instance"))
        .map(|(_, v)| v);
    assert_eq!(
        instance,
        Some(suiss_crypto::dcbor::Value::Bytes(vec![9; 16]))
    );

    // §9.14.1 step 4
    let kid = thumbprint(&device.public_key());
    let ais = sign_sign1(&device, kid, "application/access-ais+cbor", b"contribute").unwrap();
    let push = |nonce: u8| {
        json!({
            "request": {
                "requester": { "party": b64url_encode(&[1; 16]), "instance": b64url_encode(&[2; 16]) },
                "action": { "namespace": "shop", "name": "refund", "major": 1, "schema": b64url_encode(&[1; 32]) },
                "resource": { "namespace": "shop", "path": ["orders", "o-1042"], "incarnation": 0 },
                "params": { "amount": { "amount": { "value": 4200, "unit": "eur" } } },
                "capacity": "own",
                "reason": "The customer reported that the parcel arrived damaged.",
                "require_action": {
                    "domain": b64url_encode(&[45; 32]),
                    "nonce": b64url_encode(&[nonce; 16]),
                    "intent": b64url_encode(&[0x44; 32]),
                },
                "expires_at": e.clock.now_ms() + 3_600_000,
            },
            "contribution": {
                "nonce": b64url_encode(&[nonce; 16]),
                "basis": { "grant": b64url_encode(&[1; 16]), "holder": b64url_encode(&[8; 16]), "since": 0 },
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2026-01-01T00:05:00Z",
                "ais": b64url_encode(&ais),
            },
        })
    };
    let mut coordinator = e.browser("work");
    let pushed = coordinator
        .post("/v1/approve/requests", Some(push(20)))
        .await;
    assert_eq!(
        pushed.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&pushed.body)
    );
    let uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
    assert!(uri.starts_with("urn:ietf:params:oauth:request_uri:"));
    let digest = pushed.json()["digest"].as_str().unwrap().to_owned();
    let call = |request: &str| {
        format!(
            "/v1/approve?request={request}&redirect_uri=https%3A%2F%2Fshop.example%2Fapproved&state=st-1"
        )
    };

    let page = c.get(&call(&uri)).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(page.headers.contains_key("content-security-policy"));
    assert!(String::from_utf8_lossy(&page.body).contains("/v1/approve/app.js"));
    assert_eq!(c.get(&call(&digest)).await.status, StatusCode::OK);
    let unknown = c.get(&call(&b64url_encode(&[0x77; 32]))).await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.json()["code"], "approval-request-unknown");
    let script = c.get("/v1/approve/app.js").await;
    assert_eq!(script.status, StatusCode::OK);
    assert!(
        script.headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );

    let start = json!({ "request": uri, "redirect_uri": redirect, "state": "st-1" });
    let mut anon = e.browser("anon");
    assert_eq!(
        anon.post("/v1/approve/flows", Some(start.clone()))
            .await
            .status,
        StatusCode::UNAUTHORIZED
    );
    let started = c.post("/v1/approve/flows", Some(start.clone())).await;
    assert_eq!(
        started.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    let s = started.json();
    let fields = s["render"]["fields"].as_array().unwrap();
    assert!(
        fields
            .iter()
            .any(|f| f["name"] == "amount" && f["text"] == "4200 eur" && f["material"] == true)
    );
    assert_eq!(s["render"]["tier"], 1);
    assert_eq!(
        s["render"]["reason"],
        "The customer reported that the parcel arrived damaged."
    );
    let statement = b64url_decode(s["options"]["challenge"].as_str().unwrap()).unwrap();
    assert_eq!(statement.len(), 32);
    assert_ne!(s["options"]["userVerification"], "required");
    let flow = s["flow"].as_str().unwrap().to_owned();
    let again = c.post("/v1/approve/flows", Some(start)).await;
    assert_eq!(again.status, StatusCode::CONFLICT);
    assert_eq!(again.json()["code"], "approval-started");

    let finish = |credential: Value| json!({ "credential": credential, "redirect_uri": redirect, "state": "st-1" });
    let done = c
        .post(
            &format!("/v1/approve/flows/{flow}"),
            Some(finish(assertion_json(&mut key, &id, &user, &statement))),
        )
        .await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    let location = done.json()["redirect"].as_str().unwrap().to_owned();
    assert!(location.starts_with("https://shop.example/approved?exercise="));
    assert!(location.contains(&format!("exercise={}", b64url_encode(&[0xe3; 32]))));
    assert!(location.contains("&render_digest="));
    // OP-149 m.33 (c)
    assert!(location.contains(&format!("&claim={}", b64url_encode(&[0xc1; 16]))));
    assert!(location.ends_with("&state=st-1"));
    assert_eq!(done.json()["claim"], b64url_encode(&[0xc1; 16]));
    let orders = e.claims.0.lock().unwrap().clone();
    assert_eq!(orders.len(), 1);
    assert_eq!(orders[0].class, "authentication");
    assert_eq!(
        orders[0].bind,
        Bind::Statement {
            statement: <[u8; 32]>::try_from(statement.as_slice()).unwrap(),
            instance: [9; 16],
        }
    );
    assert_eq!(orders[0].assurance.get("phishing_resistant"), Some(&1));
    assert_eq!(orders[0].assurance.get("human_presence"), Some(&1));
    let contributions = e.surface.contributions.lock().unwrap().clone();
    assert_eq!(contributions.len(), 1);
    assert_eq!(contributions[0].claim, Id([0xc1; 16]));
    assert_eq!(contributions[0].ais, ais);
    assert_eq!(contributions[0].nonce, vec![20; 16]);
    assert_eq!(contributions[0].class, "approve");
    assert_eq!(contributions[0].pep, "access-identity");
    let (render_digest, _) = refund_render(false);
    assert!(location.contains(&b64url_encode(&render_digest.0)));
    let twice = c
        .post(
            &format!("/v1/approve/flows/{flow}"),
            Some(finish(assertion_json(&mut key, &id, &user, &statement))),
        )
        .await;
    assert_eq!(twice.status, StatusCode::CONFLICT);
    assert_eq!(twice.json()["code"], "approval-finished");

    // §9.14.2, XI-7
    let pushed = coordinator
        .post("/v1/approve/requests", Some(push(21)))
        .await;
    let uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
    let start = json!({ "request": uri, "redirect_uri": redirect, "state": "st-1" });
    let s = c.post("/v1/approve/flows", Some(start)).await.json();
    let statement = b64url_decode(s["options"]["challenge"].as_str().unwrap()).unwrap();
    e.surface.shifted.store(true, Ordering::SeqCst);
    let changed = c
        .post(
            &format!("/v1/approve/flows/{}", s["flow"].as_str().unwrap()),
            Some(finish(assertion_json(&mut key, &id, &user, &statement))),
        )
        .await;
    assert_eq!(changed.status, StatusCode::CONFLICT);
    assert_eq!(changed.json()["code"], "approval-request-changed");
    assert_eq!(e.surface.contributions.lock().unwrap().len(), 1);
    e.surface.shifted.store(false, Ordering::SeqCst);

    // §13.7.3, SEC18
    e.surface.tier.store(2, Ordering::SeqCst);
    let pushed = coordinator
        .post("/v1/approve/requests", Some(push(22)))
        .await;
    let uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
    let start = json!({ "request": uri, "redirect_uri": redirect, "state": "st-1" });
    let s = c.post("/v1/approve/flows", Some(start)).await.json();
    assert_eq!(s["render"]["tier"], 2);
    assert_eq!(s["options"]["userVerification"], "required");
    let statement = b64url_decode(s["options"]["challenge"].as_str().unwrap()).unwrap();
    let cooling = c
        .post(
            &format!("/v1/approve/flows/{}", s["flow"].as_str().unwrap()),
            Some(finish(assertion_json(&mut key, &id, &user, &statement))),
        )
        .await;
    assert_eq!(
        cooling.status,
        StatusCode::FORBIDDEN,
        "{}",
        String::from_utf8_lossy(&cooling.body)
    );
    assert_eq!(cooling.json()["code"], "cooling");
    assert!(
        cooling.json()["title"]
            .as_str()
            .unwrap()
            .starts_with("Needs: a sign-in method added more than 24 h ago")
    );
    assert!(cooling.json()["available_at"].is_string());
    assert_eq!(e.claims.0.lock().unwrap().len(), 1);

    // SI-5, OP-149 m.30 (b)
    e.surface.tier.store(1, Ordering::SeqCst);
    e.surface.unbound.store(true, Ordering::SeqCst);
    let pushed = coordinator
        .post("/v1/approve/requests", Some(push(24)))
        .await;
    let uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
    let start = json!({ "request": uri, "redirect_uri": redirect, "state": "st-1" });
    let s = c.post("/v1/approve/flows", Some(start)).await.json();
    let statement = b64url_decode(s["options"]["challenge"].as_str().unwrap()).unwrap();
    let unbound = c
        .post(
            &format!("/v1/approve/flows/{}", s["flow"].as_str().unwrap()),
            Some(finish(assertion_json(&mut key, &id, &user, &statement))),
        )
        .await;
    assert_eq!(
        unbound.status,
        StatusCode::CONFLICT,
        "{}",
        String::from_utf8_lossy(&unbound.body)
    );
    assert_eq!(unbound.json()["code"], "approval-refused");
    assert_eq!(unbound.json()["reason"], "aas-binding");
    assert_eq!(
        unbound.json()["errors"],
        json!([{ "code": "bound-intent" }])
    );
    assert_eq!(
        unbound.json()["type"],
        "urn:suiss:access:problem:approval-refused"
    );
    assert_eq!(e.surface.contributions.lock().unwrap().len(), 1);
    e.surface.unbound.store(false, Ordering::SeqCst);

    e.surface.gone.store(true, Ordering::SeqCst);
    let pushed = coordinator
        .post("/v1/approve/requests", Some(push(23)))
        .await;
    let uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
    let gone = c
        .post(
            "/v1/approve/flows",
            Some(json!({ "request": uri, "redirect_uri": redirect, "state": "st-1" })),
        )
        .await;
    assert_eq!(gone.status, StatusCode::CONFLICT);
    assert_eq!(gone.json()["code"], "approval-request-changed");
}

// TN-44, RFC 9470, §8.17.5.4, X-L3
#[tokio::test]
async fn a_live_session_steps_up_in_place() {
    let e = env(47, "lg-su", AuthPolicy::DEFAULT).await;
    e.account("sue@example.com").await;
    let mut anon = e.browser("anon");
    let refused = anon
        .post("/v1/login/step-up", Some(json!({ "max_age": 0 })))
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    let mut b = e.browser("b");
    assert_eq!(b.sign_in("sue@example.com").await.step(), "complete");
    let (mut key, id, user) = register_passkey(&mut b, "sue@example.com").await;
    let before = b.get("/v1/sessions/current").await.json();
    assert_eq!(before["assurance"]["aal"], json!("Aal1"));
    let session = b.jar.get("__Host-access-session").cloned();
    let up = b
        .post(
            "/v1/login/step-up",
            Some(json!({
                "max_age": 0,
                "acr": "http://idmanagement.gov/ns/assurance/aal/2",
            })),
        )
        .await;
    assert_eq!(
        up.status,
        StatusCode::CREATED,
        "{}",
        String::from_utf8_lossy(&up.body)
    );
    let options = passkey_node(&up);
    let challenge = b64url_decode(options["challenge"].as_str().unwrap()).unwrap();
    let assertion = assertion_json(&mut key, &id, &user, &challenge).to_string();
    let done = b
        .submit(&up, "passkey", json!({ "passkey_credential": assertion }))
        .await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(b.jar.get("__Host-access-session").cloned(), session);
    let after = b.get("/v1/sessions/current").await.json();
    assert_eq!(after["id"], before["id"]);
    assert_ne!(after["assurance"]["aal"], json!("Aal1"));
}

impl Env {
    /// The subject an address belongs to now, through the realm's vault.
    async fn holder(&self, email: &str) -> Option<[u8; 16]> {
        use access_identity_account::ports::{AccountDb as _, AccountTx as _};
        let pg = PgAccounts::sealed(self.db.app.clone(), self.kit.vault());
        let mut tx = pg.begin(self.tenant, self.realm).await.unwrap();
        let s = tx.subject_by_identifier(email).await.unwrap();
        tx.commit().await.unwrap();
        s
    }

    fn sent(&self) -> Sent {
        self.outbox.1.lock().unwrap().clone()
    }
}

impl Web {
    async fn signup(&mut self) -> Answer {
        let a = self
            .post("/v1/login/flows", Some(json!({ "kind": "registration" })))
            .await;
        assert_eq!(
            a.status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&a.body)
        );
        assert_eq!(a.json()["kind"], "registration");
        a
    }

    async fn register(&mut self, email: &str) -> Answer {
        let at = self.signup().await;
        self.submit(&at, "register", json!({ "email": email }))
            .await
    }
}

// TN-80, TN-64, OP-153 m.3 (g), (i)
#[tokio::test]
async fn sign_up_creates_the_account_only_when_the_code_returns() {
    let e = env(31, "su-a", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("su-a");
    let code_step = b.register("New.Person@Example.com").await;
    assert_eq!(code_step.status, StatusCode::OK);
    assert_eq!(code_step.step(), "authenticate");
    assert_eq!(code_step.messages(), vec!["registration.code_sent"]);
    // TN-80
    assert_eq!(e.holder("new.person@example.com").await, None);
    let (kind, since, _) = *e.sent().last().unwrap();
    assert_eq!(kind, "relay.message.otp.v1");
    assert_eq!(since, Some(e.clock.now_ms()));
    let code = e.outbox.last();
    assert_eq!(code.len(), 8);
    let wrong = b
        .submit(
            &code_step,
            "email_code",
            json!({ "email_code": "00000000", "display_name": "N" }),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong.messages(), vec!["registration.failed"]);
    assert_eq!(e.holder("new.person@example.com").await, None);
    let done = b
        .submit(
            &code_step,
            "email_code",
            json!({ "email_code": code, "display_name": "New Person" }),
        )
        .await;
    assert_eq!(
        done.status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(done.step(), "complete");
    let subject = e.holder("NEW.PERSON@example.com").await.unwrap();
    let me = b.get("/v1/sessions/current").await;
    assert_eq!(me.status, StatusCode::OK);
    assert_eq!(me.json()["subject"], e.realm().external(subject).unwrap());
    // TN-66
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let since = t.mailbox_since(subject).await.unwrap();
    t.commit().await.unwrap();
    assert_eq!(
        since.and_then(|v| u64::try_from(v).ok()),
        Some(e.clock.now_ms())
    );
    let again = b
        .submit(
            &code_step,
            "email_code",
            json!({ "email_code": code, "display_name": "N" }),
        )
        .await;
    assert_eq!(again.status, StatusCode::GONE);
}

// CR-40, §10.2.1 m.6, TN-80, U44, SAI-5, X-L1
#[tokio::test]
async fn sign_up_answers_the_same_whether_or_not_the_address_has_an_account() {
    let e = env(32, "su-b", AuthPolicy::DEFAULT).await;
    let owner = e.account("taken@example.com").await;
    let mut answers = Vec::new();
    for (i, who) in ["taken@example.com", "free@example.com"].iter().enumerate() {
        let mut b = e.browser(&format!("su-b{i}"));
        let at = b.signup().await;
        let started = std::time::Instant::now();
        let a = b.submit(&at, "register", json!({ "email": who })).await;
        // TN-80
        assert!(started.elapsed() >= std::time::Duration::from_millis(250));
        answers.push(masked(&a));
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0].0, 200);
    let sent = e.sent();
    assert_eq!(sent.len(), 2);
    // §10.2.1 m.6
    assert_eq!(sent[0].0, "relay.message.signup_existing.v1");
    assert_eq!(sent[0].2, owner);
    assert!(sent[0].1.is_some());
    assert_eq!(sent[1].0, "relay.message.otp.v1");
}

// TN-80, TN-83, OP-153 m.3 (g)
#[tokio::test]
async fn the_cheap_gate_and_the_address_limits_answer_before_any_lookup() {
    let e = env(33, "su-c", AuthPolicy::DEFAULT).await;
    let mut statuses = Vec::new();
    for i in 0..6_u8 {
        let mut b = e.browser(&format!("su-c{i}"));
        b.ip = Ipv4Addr::new(10, 9, 9, i + 1);
        statuses.push(b.register(&format!("p{i}@example.com")).await.status);
    }
    assert_eq!(statuses[..5], [StatusCode::OK; 5]);
    assert_eq!(statuses[5], StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(e.sent().len(), 5);
    let mut statuses = Vec::new();
    for (i, who) in [
        "ann.lee@gmail.com",
        "annlee+a@gmail.com",
        "AnnLee@googlemail.com",
        "a.nnlee@gmail.com",
    ]
    .iter()
    .enumerate()
    {
        let mut b = e.browser(&format!("su-cc{i}"));
        statuses.push(b.register(who).await.status);
    }
    assert_eq!(statuses[..3], [StatusCode::OK; 3]);
    assert_eq!(statuses[3], StatusCode::TOO_MANY_REQUESTS);
}

// TN-81, OP-153 m.3 (h)
#[tokio::test]
async fn a_disposable_address_is_scored_and_never_refused() {
    let e = env(34, "su-d", AuthPolicy::DEFAULT).await;
    let mut b = e.browser("su-d");
    let a = b.register("someone@mailinator.com").await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(e.sent().last().unwrap().0, "relay.message.otp.v1");
    let mut r = e.browser("su-d2");
    assert_eq!(
        r.register("me@privaterelay.appleid.com").await.status,
        StatusCode::OK
    );
}

// TN-132, OP-153 m.3 (g)
#[tokio::test]
async fn the_realm_domain_lists_and_required_name_hold_at_sign_up() {
    let signin = RealmSignin {
        domain_deny: std::collections::BTreeSet::from([String::from("blocked.example")]),
        required_fields: std::collections::BTreeSet::from([
            String::from("email"),
            String::from("name"),
        ]),
        ..RealmSignin::default()
    };
    let e = env_full(35, "su-e", AuthPolicy::DEFAULT, false, signin).await;
    let mut b = e.browser("su-e");
    let refused = b.register("x@blocked.example").await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.messages(), vec!["registration.failed"]);
    assert_eq!(e.sent().len(), 0);
    let at = b.register("x@fine.example").await;
    let code = e.outbox.last();
    let nameless = b
        .submit(&at, "email_code", json!({ "email_code": code }))
        .await;
    assert_eq!(nameless.status, StatusCode::BAD_REQUEST);
    let done = b
        .submit(
            &at,
            "email_code",
            json!({ "email_code": code, "display_name": "X" }),
        )
        .await;
    assert_eq!(done.step(), "complete");
}

/// The previous identity provider of a lazy migration: knows one password, or is down.
struct OldIdp {
    up: bool,
    asked: Arc<AtomicU64>,
}

impl access_identity_account::ports::LegacyIdp for OldIdp {
    fn verify<'a>(
        &'a self,
        identifier: &'a str,
        password: &'a [u8],
        reference: &'a str,
    ) -> access_identity_account::ports::LegacyIdpFuture<'a> {
        Box::pin(async move {
            self.asked.fetch_add(1, Ordering::SeqCst);
            if !self.up {
                return Err(access_identity_account::ports::LegacyIdpUnavailable);
            }
            Ok(identifier == "old@example.com" && reference == "u-77" && password == PW.as_bytes())
        })
    }
}

impl Env {
    async fn import(
        &self,
        line: serde_json::Value,
    ) -> access_identity_account::app::import::Imported {
        let pg = PgAccounts::sealed(self.db.app.clone(), self.kit.vault());
        access_identity_account::app::import::import_line(
            &pg,
            &self.realm(),
            &line.to_string(),
            &ADMIN,
        )
        .await
        .unwrap()
    }

    async fn legacy_count(&self) -> u64 {
        let day = u32::try_from(self.clock.now_ms() / 86_400_000).unwrap();
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let (row, _) = t.aggregate_day(day).await.unwrap();
        t.commit().await.unwrap();
        row.legacy_password_accounts
    }

    async fn password_algorithm(&self, subject: [u8; 16]) -> Vec<String> {
        let mut t = TenantTx::begin(&self.db.app, self.tenant, self.realm)
            .await
            .unwrap();
        let c = t.credentials(subject, "password").await.unwrap();
        t.commit().await.unwrap();
        c.into_iter().map(|c| c.algorithm).collect()
    }
}

// 3567, 3568, 4049, 4089, TN-85, CR-37, OP-153 m.11 (h), (gg)
#[tokio::test]
async fn a_legacy_bcrypt_user_signs_in_and_is_stored_as_argon2id_after_one_login() {
    use access_identity_account::app::import::{Imported, Skipped};
    let e = env(38, "mig-a", AuthPolicy::DEFAULT).await;
    let hash = "$2y$05$pjDCtN..zgfjuaFwV5NMLeoCrLFlrr5.A2o2bXoe4BtTIrESvFIDe";
    let Imported::Created { subject, legacy } = e
        .import(json!({ "email": "ann@example.com", "password_hash": hash }))
        .await
    else {
        panic!("not imported");
    };
    assert!(legacy);
    assert_eq!(e.password_algorithm(subject).await, vec!["legacy-bcrypt"]);
    // 3569, 3894
    assert_eq!(e.legacy_count().await, 1);
    assert_eq!(
        e.import(json!({ "email": "ann@example.com", "password_hash": hash }))
            .await,
        Imported::Skipped(Skipped::Taken)
    );
    assert!(matches!(
        e.import(
            json!({ "email": "x@example.com", "password_hash": "d41d8cd98f00b204e9800998ecf8427e" })
        )
        .await,
        Imported::Skipped(Skipped::Hash(_))
    ));
    let mut wrong = e.browser("mig-a0");
    let at = wrong.identify("ann@example.com").await;
    let refused = wrong
        .submit(&at, "password", json!({ "password": "not the one" }))
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(e.password_algorithm(subject).await, vec!["legacy-bcrypt"]);
    e.advance(2_000);
    let mut b = e.browser("mig-a1");
    let done = b.sign_in("ann@example.com").await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(e.password_algorithm(subject).await, vec!["argon2id"]);
    assert_eq!(e.legacy_count().await, 0);
    e.advance(2_000);
    let mut again = e.browser("mig-a2");
    assert_eq!(again.sign_in("ann@example.com").await.step(), "complete");
}

// 3568, TN-85, MD-8, TI-9
#[tokio::test]
async fn a_legacy_idp_outage_fails_the_login_closed() {
    use access_identity_account::app::import::Imported;
    let asked = Arc::new(AtomicU64::new(0));
    let down = OldIdp {
        up: false,
        asked: asked.clone(),
    };
    let e = env_legacy(
        39,
        "mig-b",
        AuthPolicy::DEFAULT,
        false,
        RealmSignin::default(),
        access_identity_ui::app::signup::Signup::without_providers().unwrap(),
        Some(Arc::new(down)),
    )
    .await;
    let Imported::Created { subject, legacy } = e
        .import(json!({ "email": "old@example.com", "legacy_idp_reference": "u-77" }))
        .await
    else {
        panic!("not imported");
    };
    assert!(legacy);
    let mut b = e.browser("mig-b1");
    let at = b.identify("old@example.com").await;
    let r = b.submit(&at, "password", json!({ "password": PW })).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(asked.load(Ordering::SeqCst), 1);
    assert_eq!(e.password_algorithm(subject).await, vec!["legacy-idp"]);

    let up = env_legacy(
        40,
        "mig-c",
        AuthPolicy::DEFAULT,
        false,
        RealmSignin::default(),
        access_identity_ui::app::signup::Signup::without_providers().unwrap(),
        Some(Arc::new(OldIdp {
            up: true,
            asked: asked.clone(),
        })),
    )
    .await;
    let Imported::Created { subject, .. } = up
        .import(json!({ "email": "old@example.com", "legacy_idp_reference": "u-77" }))
        .await
    else {
        panic!("not imported");
    };
    let mut c = up.browser("mig-c1");
    assert_eq!(c.sign_in("old@example.com").await.step(), "complete");
    assert_eq!(up.password_algorithm(subject).await, vec!["argon2id"]);
    let without = env(41, "mig-d", AuthPolicy::DEFAULT).await;
    let Imported::Created { subject, .. } = without
        .import(json!({ "email": "old@example.com", "legacy_idp_reference": "u-77" }))
        .await
    else {
        panic!("not imported");
    };
    let mut d = without.browser("mig-d1");
    let at = d.identify("old@example.com").await;
    let r = d.submit(&at, "password", json!({ "password": PW })).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        without.password_algorithm(subject).await,
        vec!["legacy-idp"]
    );
}

/// A resolver with fixed answers (OP-153 m.11 (f)).
struct FakeDns;

impl access_identity_account::ports::MailDomains for FakeDns {
    fn deliverable<'a>(
        &'a self,
        domain: &'a str,
    ) -> access_identity_account::ports::MailFuture<'a> {
        use access_identity_account::ports::Deliverability;
        Box::pin(async move {
            match domain {
                "no-mail.example" | "null-mx.example" => Deliverability::Undeliverable,
                "slow-dns.example" => Deliverability::Unknown,
                _ => Deliverability::Deliverable,
            }
        })
    }
}

// TN-80, OP-153 m.11 (f), CR-40
#[tokio::test]
async fn an_address_whose_domain_takes_no_mail_is_refused_before_any_code() {
    let mut signup = access_identity_ui::app::signup::Signup::without_providers().unwrap();
    signup.mail = Arc::new(FakeDns);
    let e = env_core(
        36,
        "su-mx",
        AuthPolicy::DEFAULT,
        false,
        RealmSignin::default(),
        signup,
    )
    .await;
    let owner = e.account("held@null-mx.example").await;
    let mut answers = Vec::new();
    for (i, who) in ["held@null-mx.example", "free@no-mail.example"]
        .iter()
        .enumerate()
    {
        let mut b = e.browser(&format!("su-mx{i}"));
        let a = b.register(who).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        assert_eq!(a.messages(), vec!["registration.failed"]);
        answers.push(masked(&a));
    }
    // CR-40
    assert_eq!(answers[0], answers[1]);
    assert!(e.sent().is_empty());
    let _ = owner;
    let mut b = e.browser("su-mx-unknown");
    assert_eq!(
        b.register("someone@slow-dns.example").await.status,
        StatusCode::OK
    );
    assert_eq!(e.sent().last().unwrap().0, "relay.message.otp.v1");
    let mut b = e.browser("su-mx-ok");
    assert_eq!(
        b.register("someone@mail.example").await.status,
        StatusCode::OK
    );
}

// TN-64, TNI-5, §12.3.3 rule 1
#[tokio::test]
async fn the_mailbox_proof_kills_a_password_set_before_it() {
    use access_identity_account::ports::{AccountDb as _, AccountTx as _};
    let e = env(36, "su-f", AuthPolicy::DEFAULT).await;
    let pg = PgAccounts::sealed(e.db.app.clone(), e.kit.vault());
    let id = Identifier::new(IdentifierKind::Email, "victim@example.com").unwrap();
    let staged = create(&pg, &e.realm(), &[id], &ADMIN).await.unwrap();
    let services = PasswordServices {
        hasher: &e.hasher,
        ranges: &Corpus,
        entropy: &SystemEntropy,
    };
    set_password(
        &pg,
        &e.realm(),
        &services,
        staged,
        "attacker chose this",
        &ADMIN,
    )
    .await
    .unwrap();
    let mut b = e.browser("su-f");
    let at = b.register("victim@example.com").await;
    assert_eq!(e.sent().last().unwrap().0, "relay.message.otp.v1");
    let code = e.outbox.last();
    let done = b
        .submit(
            &at,
            "email_code",
            json!({ "email_code": code, "display_name": "V" }),
        )
        .await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(e.holder("victim@example.com").await, Some(staged));
    let mut tx = pg.begin(e.tenant, e.realm).await.unwrap();
    assert!(tx.credentials(staged, "password").await.unwrap().is_empty());
    let row = tx.subject(staged, false).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    assert_eq!(row.status, "active");
    let mut attacker = e.browser("su-f2");
    let at = attacker.identify("victim@example.com").await;
    let refused = attacker
        .submit(
            &at,
            "password",
            json!({ "password": "attacker chose this" }),
        )
        .await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
}

// OP-153 m.3 (i), TN-64, TN-66, TN-69, TN-76 m.5, §8.6
#[tokio::test]
async fn an_email_change_proves_the_new_address_and_tells_the_old_one() {
    let e = env(37, "su-g", AuthPolicy::DEFAULT).await;
    let subject = e.account("old@example.com").await;
    let mut b = e.browser("su-g");
    assert_eq!(b.sign_in("old@example.com").await.step(), "complete");
    let started = b
        .post(
            "/v1/account/email",
            Some(json!({ "email": "new@example.com" })),
        )
        .await;
    assert_eq!(
        started.status,
        StatusCode::ACCEPTED,
        "{}",
        String::from_utf8_lossy(&started.body)
    );
    let change = started.json()["change"].as_str().unwrap().to_owned();
    let (kind, since, _) = *e.sent().last().unwrap();
    assert_eq!(kind, "relay.message.otp.v1");
    assert_eq!(since, Some(e.clock.now_ms()));
    let code = e.outbox.last();
    let wrong = b
        .post(
            &format!("/v1/account/email/{change}"),
            Some(json!({ "code": "00000000" })),
        )
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    let done = b
        .post(
            &format!("/v1/account/email/{change}"),
            Some(json!({ "code": code })),
        )
        .await;
    assert_eq!(
        done.status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&done.body)
    );
    assert_eq!(e.holder("new@example.com").await, Some(subject));
    assert_eq!(e.holder("old@example.com").await, None);
    let notice = e.sent().last().copied().unwrap();
    assert_eq!(notice.0, "relay.message.email_changed.v1");
    assert_eq!(notice.2, subject);
    assert!(notice.1.is_some());
    assert_eq!(
        b.get("/v1/sessions/current").await.status,
        StatusCode::UNAUTHORIZED
    );
    // TN-76 m.5
    let before = e.sent().len();
    let mut other = e.browser("su-g2");
    assert_eq!(
        other.register("old@example.com").await.status,
        StatusCode::OK
    );
    assert_eq!(e.sent().len(), before);
}

// OP-153 m.3 (i), X29
#[tokio::test]
async fn an_email_change_needs_a_fresh_step_up() {
    let e = env(38, "su-h", AuthPolicy::DEFAULT).await;
    e.account("stale@example.com").await;
    let mut b = e.browser("su-h");
    b.sign_in("stale@example.com").await;
    e.advance(600_000);
    let a = b
        .post(
            "/v1/account/email",
            Some(json!({ "email": "n@example.com" })),
        )
        .await;
    assert_eq!(a.status, StatusCode::UNAUTHORIZED);
    assert_eq!(a.json()["code"], "step-up-required");
    let mut anon = e.browser("su-h2");
    let a = anon
        .post(
            "/v1/account/email",
            Some(json!({ "email": "n@example.com" })),
        )
        .await;
    assert_eq!(a.json()["code"], "session-required");
}

// OP-148, §7.9.8, E42, OP-153 m.3 (d), (i), m.9 (d)
#[tokio::test]
async fn a_second_step_and_new_recovery_codes_are_told_to_the_account() {
    let e = env(39, "su-i", AuthPolicy::DEFAULT).await;
    let subject = e.account("told@example.com").await;
    let mut b = e.browser("su-i");
    b.sign_in("told@example.com").await;
    let started = b
        .post("/v1/account/totp", Some(json!({ "label": "told" })))
        .await;
    let s = started.json();
    let seed = base32_decode(s["secret"].as_str().unwrap());
    let path = format!("/v1/account/totp/{}", s["enrollment"].as_str().unwrap());
    let ok = b.post(&path, Some(json!({ "code": e.totp(&seed) }))).await;
    assert_eq!(ok.status, StatusCode::OK);
    let enabled = *e.sent().last().unwrap();
    assert_eq!(enabled.0, "relay.message.second_factor_enabled.v1");
    assert_eq!(enabled.2, subject);
    assert!(enabled.1.is_some());
    let fresh = b.post("/v1/account/recovery-codes", None).await;
    assert_eq!(fresh.status, StatusCode::OK);
    let regenerated = *e.sent().last().unwrap();
    assert_eq!(regenerated.0, "relay.message.recovery_codes_regenerated.v1");
    assert_eq!(regenerated.2, subject);
}

// OP-153 m.3 (j), TN-96, TN-82, CR-40
#[tokio::test]
async fn strict_mode_takes_identifier_and_password_on_one_screen() {
    let signin = RealmSignin {
        strict: true,
        ..RealmSignin::default()
    };
    let e = env_full(40, "su-j", AuthPolicy::DEFAULT, false, signin).await;
    e.account("strict@example.com").await;
    let mut answers = Vec::new();
    for (i, (who, pw)) in [
        ("strict@example.com", "not the one"),
        ("nobody@example.com", "not the one"),
    ]
    .iter()
    .enumerate()
    {
        let mut b = e.browser(&format!("su-j{i}"));
        let first = b.start().await;
        let nodes = first.json()["nodes"].as_array().unwrap().clone();
        assert!(nodes.iter().any(|n| n["name"] == "password"));
        assert!(
            !nodes
                .iter()
                .any(|n| n["type"] == "submit" && n["method"] == "identifier")
        );
        assert!(nodes.iter().any(|n| n["type"] == "passkey_get"));
        let a = b
            .submit(
                &first,
                "password",
                json!({ "identifier": who, "password": pw }),
            )
            .await;
        answers.push(masked(&a));
    }
    assert_eq!(answers[0], answers[1]);
    assert_eq!(answers[0].0, 401);
    e.advance(2_000);
    let mut b = e.browser("su-j3");
    let first = b.start().await;
    let done = b
        .submit(
            &first,
            "password",
            json!({ "identifier": "strict@example.com", "password": PW }),
        )
        .await;
    assert_eq!(
        done.step(),
        "complete",
        "{}",
        String::from_utf8_lossy(&done.body)
    );
}

/// An organization with `owner` bound to Party `party` as its founder, and an invitation from
/// that Party to `invitee` with link token `token` and magic code `code` (TN-89).
async fn org_with_invitation(
    e: &Env,
    owner: [u8; 16],
    party: [u8; 16],
    invitee: &str,
    (token, code): (&str, &str),
) -> [u8; 16] {
    use access_identity_account::domain::invitation::{code_hash, token_hash};
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(
        access_store::idp::bind_subject_party(&mut t, &owner, &party)
            .await
            .unwrap()
    );
    let org = t.insert_org([0x0a; 16], "Acme", &[1; 32]).await.unwrap();
    t.insert_membership(org, owner, access_store::orgs::Source::Founder, true, None)
        .await
        .unwrap();
    let index = e
        .kit
        .vault()
        .index_of(e.tenant.as_bytes(), e.realm.as_bytes(), invitee)
        .unwrap();
    t.insert_invitation(&access_store::orgs::NewInvitation {
        org,
        token_hash: &token_hash(token),
        code_hash: &code_hash(code),
        invitee_index: &index,
        invitee_domain: &invitee.rsplit_once('@').unwrap().1.to_ascii_lowercase(),
        inviter: party,
        role: ("member", 1),
        exercise: None,
        ttl_s: 86_400,
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    org
}

// TN-89, OP-153 m.3 (o), (gg), HL-39, Ek B 3604, 3606, 4038
#[tokio::test]
async fn an_invitation_is_read_without_consuming_it_and_accepted_by_its_invitee() {
    let e = env(0x31, "lg-invite", AuthPolicy::DEFAULT).await;
    let owner = e.account("owner@acme.example").await;
    e.account("alice@acme.example").await;
    e.account("mallory@evil.example").await;
    let token = "tok-0123456789abcdefghijklmnopqrstuv";
    let org = org_with_invitation(
        &e,
        owner,
        [0x77; 16],
        "Alice@ACME.example",
        (token, "ABCD2345"),
    )
    .await;
    let path = format!("/v1/invitations/{token}");

    // TN-89 (8), (9)
    let mut scanner = e.browser("s");
    for _ in 0..2 {
        let a = scanner.get(&path).await;
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(a.headers["referrer-policy"], "no-referrer");
        assert_eq!(a.json()["organization"]["display_name"], "Acme");
        assert_eq!(a.json()["role"]["name"], "member");
    }
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let listed = t.invitations(org).await.unwrap();
    assert!(listed[0].open);
    assert_eq!(listed[0].scanner_clicks, 2);
    t.commit().await.unwrap();
    assert_eq!(
        scanner.post(&path, Some(json!({}))).await.status,
        StatusCode::UNAUTHORIZED
    );

    // TN-89 (5)
    let mut m = e.browser("m");
    assert_eq!(m.sign_in("mallory@evil.example").await.step(), "complete");
    let a = m.post(&path, Some(json!({ "confirm": true }))).await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    assert_eq!(a.json()["code"], "invitation-mismatch");

    // TN-89 (10)
    let mut b = e.browser("a");
    assert_eq!(b.sign_in("alice@acme.example").await.step(), "complete");
    let a = b.post(&path, Some(json!({}))).await;
    assert_eq!(a.status, StatusCode::CONFLICT);
    assert_eq!(a.json()["organization"]["display_name"], "Acme");
    let a = b.post(&path, Some(json!({ "confirm": true }))).await;
    assert_eq!(a.status, StatusCode::OK, "{:?}", a.json());
    // TN-89 (3), (10), OP-153 m.3 (o)
    assert_eq!(a.json()["owner"], false);
    assert_eq!(a.json()["role_grant"], "pending");
    let mine = b.get("/v1/account/organizations").await;
    assert_eq!(mine.status, StatusCode::OK);
    let items = mine.json()["items"].clone();
    assert_eq!(items.as_array().unwrap().len(), 1);
    assert_eq!(items[0]["source"], "invite");
    assert_eq!(items[0]["owner"], false);
    assert_eq!(items[0]["role"]["version"], 1);
    // §8.17.7.6, Ek B 3600
    assert_eq!(items[0]["roots"], 1);
    assert_eq!(items[0]["role_grant"], "pending");
    assert_eq!(
        b.post(&path, Some(json!({ "confirm": true }))).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(scanner.get(&path).await.status, StatusCode::NOT_FOUND);

    // TN-90
    let ask = format!(
        "/v1/organizations/{}/access-requests",
        b64url_encode(&[0x0a; 16])
    );
    assert_eq!(
        m.post(&ask, Some(json!({}))).await.status,
        StatusCode::ACCEPTED
    );
    assert_eq!(
        m.post(&ask, Some(json!({}))).await.status,
        StatusCode::CONFLICT
    );
    assert_eq!(
        b.post(&ask, Some(json!({}))).await.status,
        StatusCode::CONFLICT
    );
}

// TN-89 (3), OP-153 m.3 (o)
#[tokio::test]
async fn an_invitation_from_an_inviter_who_left_grants_nothing() {
    let e = env(0x32, "lg-invite-gone", AuthPolicy::DEFAULT).await;
    let owner = e.account("owner@acme.example").await;
    let other = e.account("carol@acme.example").await;
    e.account("alice@acme.example").await;
    let token = "tok-inviter-left-0123456789abcdefghij";
    let org = org_with_invitation(
        &e,
        owner,
        [0x78; 16],
        "alice@acme.example",
        (token, "WXYZ2345"),
    )
    .await;
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    t.insert_membership(org, other, access_store::orgs::Source::Invite, true, None)
        .await
        .unwrap();
    assert!(t.end_membership(org, owner, "remove").await.unwrap());
    t.commit().await.unwrap();
    let mut b = e.browser("a");
    assert_eq!(b.sign_in("alice@acme.example").await.step(), "complete");
    // TN-89
    let a = b
        .post("/v1/invitations/wxyz2345", Some(json!({ "confirm": true })))
        .await;
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    assert_eq!(a.json()["code"], "inviter-not-authorized");
}

// TN-3, TN-98, §10.2.6, OP-153 m.3 (gg), Ek B 3436, 3454, 3599
#[tokio::test]
async fn home_realm_discovery_routes_by_organization_id_only_when_turned_on() {
    let e = env(0x33, "lg-hrd", AuthPolicy::DEFAULT).await;
    let owner = e.account("owner@acme.example").await;
    let org = org_with_invitation(
        &e,
        owner,
        [0x79; 16],
        "x@acme.example",
        ("tok-hrd-0123456789abcdefghijklmnopq", "HRDC2345"),
    )
    .await;
    let path = format!("/v1/organizations/{}/sign-in", b64url_encode(&[0x0a; 16]));
    let mut b = e.browser("b");
    // TN-98
    assert_eq!(b.get(&path).await.status, StatusCode::NOT_FOUND);
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    assert!(t.set_org_hrd(org, true).await.unwrap());
    t.commit().await.unwrap();
    // §10.2.6
    assert_eq!(b.get(&path).await.status, StatusCode::NOT_FOUND);
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
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
    let a = b.get(&path).await;
    assert_eq!(a.status, StatusCode::OK);
    assert_eq!(a.json()["organization"]["display_name"], "Acme");
    assert_eq!(a.json()["domains"][0], "acme.example");
    assert_eq!(a.json()["confirm"], true);
    // TN-3
    assert_eq!(
        b.get("/v1/organizations/acme.example/sign-in").await.status,
        StatusCode::NOT_FOUND
    );
}

// TN-90, TN-109, OP-153 m.1 (d), m.3 (o), (gg), Ek B 3612, 3613, 4039
#[tokio::test]
async fn autojoin_admits_a_verified_domains_people_never_a_consumer_domains_and_cools() {
    let e = env(0x34, "lg-autojoin", AuthPolicy::DEFAULT).await;
    let owner = e.account("owner@acme.example").await;
    e.account("dave@acme.example").await;
    e.account("gina@gmail.com").await;
    e.account("erin@acme.example").await;
    let org = org_with_invitation(
        &e,
        owner,
        [0x7a; 16],
        "x@acme.example",
        ("tok-autojoin-0123456789abcdefghijklm", "AJNC2345"),
    )
    .await;
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    for domain in ["acme.example", "gmail.com"] {
        let claim = t
            .insert_domain_claim(org, domain, "dns_txt", &[1; 32])
            .await
            .unwrap();
        assert!(
            t.verify_domain(claim, 86_400, &[2; 32], &[3; 32])
                .await
                .unwrap()
        );
        assert!(t.set_autojoin(claim, true).await.unwrap());
    }
    t.commit().await.unwrap();
    let ask = format!(
        "/v1/organizations/{}/access-requests",
        b64url_encode(&[0x0a; 16])
    );

    // TN-90, TN-109
    let mut d = e.browser("d");
    assert_eq!(d.sign_in("dave@acme.example").await.step(), "complete");
    let a = d.post(&ask, Some(json!({}))).await;
    assert_eq!(a.status, StatusCode::CREATED, "{:?}", a.json());
    assert_eq!(a.json()["status"], "joined");
    assert_eq!(a.json()["cooling_s"], 86_400);
    let mine = d.get("/v1/account/organizations").await.json();
    assert_eq!(mine["items"][0]["source"], "domain_autojoin");
    assert_eq!(mine["items"][0]["owner"], false);
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let now = i64::try_from(t.server_time().await.unwrap()).unwrap();
    let cooled = t
        .members(org)
        .await
        .unwrap()
        .into_iter()
        .find(|m| m.source == access_store::orgs::Source::DomainAutojoin)
        .unwrap();
    assert!(cooled.cooling_until_ms.unwrap() > now + 23 * 3_600_000);
    t.commit().await.unwrap();

    // OP-153 m.1 (d), Ek B 4039
    let mut g = e.browser("g");
    assert_eq!(g.sign_in("gina@gmail.com").await.step(), "complete");
    assert_eq!(
        g.post(&ask, Some(json!({}))).await.status,
        StatusCode::ACCEPTED
    );

    // TN-90
    let mut t = TenantTx::begin(&e.db.app, e.tenant, e.realm).await.unwrap();
    let other = t
        .insert_org([0x0b; 16], "Not Acme", &[4; 32])
        .await
        .unwrap();
    t.insert_domain_claim(other, "acme.example", "dns_txt", &[5; 32])
        .await
        .unwrap();
    t.commit().await.unwrap();
    let mut r = e.browser("r");
    assert_eq!(r.sign_in("erin@acme.example").await.step(), "complete");
    assert_eq!(
        r.post(&ask, Some(json!({}))).await.status,
        StatusCode::ACCEPTED
    );
}
