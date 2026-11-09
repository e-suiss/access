//! The agent SDK against the real server (OP-154 m.3 (w), (y), OP-153 m.3 (gg)): a bootstrapped
//! realm with an agent Party its operator registered and an Instance its runtime key opened;
//! Grants the root issues to the agent; every request the agent SDK builds, signs and reads
//! goes through the real ADP router on the real sequencer, store and `SoftHSM`, with the agent
//! as its own transport-authenticated PEP.

use std::sync::atomic::{AtomicUsize, Ordering};

use access_http::adp::adapters::{Discovery, Pep as PepId, router as adp_router};
use access_identity_admin::ports::AgentRegistration;
use access_identity_oauth::adapters::PgDirectory;
use access_identity_oauth::app::Discovery as RealmDiscovery;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis, register_nonce,
    self_signed_intent,
};
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::{self as kjson, Json, b64url_decode};
use access_kernel::meta::{ActorKind, Root};
use access_kernel::model::{BudgetDimension, BudgetTerm, BudgetWindow};
use access_sdk::agent::a2a::{self, Inbound, TaskState, security_schemes, task_state};
use access_sdk::agent::contract::{Adp, AgentError, Change, Exercise, Plan, Proof, Signs, Step};
use access_sdk::agent::decision::Route;
use access_sdk::agent::request::{Requester, RequesterNote, WorkRefs, handoff};
use access_sdk::agent::status;
use access_sdk::transport::{Answer, Clock, Response as Answered};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequest, header};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::signer::{Signer, SoftSigner};
use tower::ServiceExt as _;

use super::*;

/// The agent's transport identity as the ADP's PEP.
pub(super) const AGENT_PEP: &str = "agent-runtime";
pub(super) const AGENT: Id = Id([0x0c; 16]);
const STRANGER: Id = Id([0x0d; 16]);

pub(super) struct Wall;

impl Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(now_ms())
    }
}

pub(super) fn nonce() -> Vec<u8> {
    access_crypto::random::bytes::<16>().unwrap().to_vec()
}

pub(super) fn block<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

/// The agent Instance's runtime key.
pub(super) struct Runtime(pub(super) SoftSigner);

pub(super) fn ais_by(key: &SoftSigner, s: &Statement) -> Option<Vec<u8>> {
    let payload = dcbor::encode(&s.to_value(), Limits::CEILING).ok()?;
    let kid = thumbprint(&key.public_key());
    sign_sign1(key as &dyn Signer, kid, CONTENT_TYPE, &payload).ok()
}

impl Signs for Runtime {
    fn sign(&self, s: &Statement) -> Option<Vec<u8>> {
        ais_by(&self.0, s)
    }
}

/// ADP in this process, reached as the agent's own PEP.
pub(super) struct Live {
    pub(super) adp: axum::Router,
    pub(super) asked: AtomicUsize,
}

impl Live {
    pub(super) fn post(&self, path: &str, body: &str) -> Answer {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let mut req = HttpRequest::post(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap();
        req.extensions_mut().insert(PepId(AGENT_PEP.to_owned()));
        let r = block(self.adp.clone().oneshot(req)).unwrap();
        let status = r.status().as_u16();
        let body = block(to_bytes(r.into_body(), 1 << 22)).unwrap().to_vec();
        Answer::Response(Answered::new(status, body))
    }
}

impl Adp for Live {
    fn evaluate(&self, body: &str) -> Answer {
        self.post("/access/v1/evaluation", body)
    }
}

fn body_of(a: &Answer) -> String {
    match a {
        Answer::Response(r) => String::from_utf8(r.body.clone()).unwrap(),
        Answer::Unanswered(f) => panic!("{f:?}"),
    }
}

/// A recording decision point: the raw answers the SDK read.
struct Recorded<'a> {
    live: &'a Live,
    bodies: std::cell::RefCell<Vec<String>>,
}

impl Adp for Recorded<'_> {
    fn evaluate(&self, body: &str) -> Answer {
        let a = self.live.evaluate(body);
        self.bodies.borrow_mut().push(body_of(&a));
        a
    }
}

/// A bootstrapped realm with the agent registered by its operator, the root, and one Instance.
struct Agents {
    w: World,
    domain: Digest,
    root: HsmSigner,
    root_party: Id,
    action: ActionRef,
    runtime: Runtime,
    instance: Id,
    live: Live,
    discovery: axum::Router,
}

fn window() -> Window {
    let now = now_ms();
    Window {
        from: now - 60_000,
        until: now + 600_000,
    }
}

fn self_signed(
    (domain, validity): (Digest, Window),
    by: &SoftSigner,
    nonce: &[u8],
    payload: &Payload,
    party: Id,
) -> Vec<u8> {
    let intent = self_signed_intent(payload, party, validity).unwrap();
    ais_by(
        by,
        &Statement {
            domain,
            nonce: nonce.to_vec(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis: bootstrap_basis(&domain),
            iat: now_ms(),
            exercise: None,
        },
    )
    .unwrap()
}

/// Registers [`AGENT`] with the root as its operator and opens an Instance for a fresh
/// runtime key under a sponsor's session (OP-154 m.3 (c)): the runtime key and the Instance.
pub(super) async fn enrol(w: &World, domain: Digest) -> (Runtime, Id) {
    enrol_with(w, domain, SoftSigner::generate_p256().unwrap().0).await
}

/// [`enrol`] with `runtime` as the Instance's key.
pub(super) async fn enrol_with(w: &World, domain: Digest, runtime: SoftSigner) -> (Runtime, Id) {
    let root_party = root_party(&root_key(&w.keys).unwrap().public_key());
    enrol_for_with(w, domain, (root_party, None), runtime).await
}

/// Registers [`AGENT`] with `operator` as its operator and opens an Instance for a fresh
/// runtime key under the session of `subject`, or of a new subject of `operator`.
pub(super) async fn enrol_for(
    w: &World,
    domain: Digest,
    operator: Id,
    subject: Option<[u8; 16]>,
) -> (Runtime, Id) {
    enrol_for_with(w, domain, (operator, subject), SoftSigner::generate_p256().unwrap().0).await
}

/// [`enrol_for`] with `runtime` as the Instance's key.
async fn enrol_for_with(
    w: &World,
    domain: Digest,
    (operator, subject): (Id, Option<[u8; 16]>),
    runtime: SoftSigner,
) -> (Runtime, Id) {
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let root_party = operator;
    let subject = if let Some(s) = subject {
        s
    } else {
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let subject = t
            .insert_subject("active", "realm-kek:1", &[9; 40])
            .await
            .unwrap();
        assert!(
            idp::bind_subject_party(&mut t, &subject, &root_party.0)
                .await
                .unwrap()
        );
        t.commit().await.unwrap();
        subject
    };
    // OP-154 m.3 (c)
    let one_time = SoftSigner::generate_p256().unwrap().0;
    let register = Payload::PartyRegister {
        party: AGENT,
        root: Root::Sole(root_party),
        actor_kind: ActorKind::Agent,
    };
    let reg_nonce = register_nonce(&access_crypto::random::bytes::<32>().unwrap());
    let validity = window();
    let registered = w
        .plane
        .register_agent(AgentRegistration {
            tenant: *route.tenant.as_bytes(),
            domain,
            party: AGENT,
            operator: root_party,
            key: one_time.public_key(),
            register: SelfSigned {
                ais: self_signed((domain, validity), &one_time, &reg_nonce, &register, AGENT),
                nonce: reg_nonce.clone(),
                validity,
            },
            pep: String::from(IDENTITY_PEP),
        })
        .await
        .unwrap();
    assert!(
        matches!(
            registered,
            access_identity_admin::ports::OrgRegistered::Registered { .. }
        ),
        "{registered:?}"
    );
    let challenge = access_crypto::random::bytes::<32>().unwrap().to_vec();
    let mut r = Registration {
        tenant: *route.tenant.as_bytes(),
        domain,
        registrant: Registrant::Device {
            realm: *route.realm.as_bytes(),
            subject,
        },
        party: AGENT,
        key: runtime.public_key(),
        register: None,
        create: SelfSigned {
            nonce: challenge.clone(),
            validity,
            ais: Vec::new(),
        },
        pep: String::from(IDENTITY_PEP),
        context: None,
    };
    r.create.ais = self_signed(
        (domain, validity),
        &runtime,
        &challenge,
        &r.create_payload(),
        AGENT,
    );
    let instance = match w.plane.register(r).await.unwrap() {
        RegistrationVerdict::Registered(done) => done.instance,
        other @ RegistrationVerdict::Refused { .. } => panic!("{other:?}"),
    };
    (Runtime(runtime), instance)
}

impl Agents {
    async fn open(name: &str) -> Self {
        Self::open_with(name, SoftSigner::generate_p256().unwrap().0).await
    }

    /// [`Self::open`] with `runtime` as the agent Instance's key.
    async fn open_with(name: &str, runtime: SoftSigner) -> Self {
        let (w, signer) = World::open(name, true).await;
        let signer = signer.unwrap();
        let summary = w.run(&sample_plan()).await;
        schedule(&signer);
        schedule(&signer);
        let json = serde_json::to_value(&summary).unwrap();
        let domain = Digest(
            <[u8; 32]>::try_from(
                b64url_decode(json["sample"]["domain"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        );
        let action = sample_plan().sample.unwrap().action_ref();
        let root = root_key(&w.keys).unwrap();
        let root_party = root_party(&root.public_key());
        let (runtime, instance) = enrol_with(&w, domain, runtime).await;
        let live = Live {
            adp: adp_router(
                access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
                Discovery {
                    issuer: String::from("https://access.test"),
                },
            ),
            asked: AtomicUsize::new(0),
        };
        let discovery = access_http::realm::router(RealmDiscovery::new(
            PgDirectory::new(w.db.router.clone()),
            access_identity_oauth::adapters::SignerKeys::new(w.identity_signer.clone()),
        ));
        Self {
            w,
            domain,
            root,
            root_party,
            action,
            runtime,
            instance,
            live,
            discovery,
        }
    }

    /// The root's `grant_issue` of `authority` to `holder` with `agency`, and its holding.
    async fn grant(
        &self,
        holder: Id,
        authority: CanonicalAuthority,
        agency: BTreeSet<Capacity>,
    ) -> HoldingRef {
        let payload = Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Anchor(meta::meta_anchor(&self.domain)),
            holder: SubjectSelector::Party(holder),
            authority,
            agency,
            named: None,
        });
        let now = server_time(&self.w.db.app).await.unwrap();
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, holder, validity).unwrap();
        let digest = intent_digest(&intent).unwrap();
        let n = nonce();
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.domain));
        let ais = sign(
            &self.root,
            &Statement {
                domain: self.domain,
                nonce: n.clone(),
                intent: digest,
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            },
        )
        .unwrap();
        MetaExercises::lead(&self.w.plane, self.domain)
            .await
            .unwrap();
        let verdict = MetaExercises::meta(
            &self.w.plane,
            Request {
                domain: self.domain,
                mode: Mode::Commit,
                nonce: n,
                intent,
                payload: Some(payload),
                basis,
                capacity: Capacity::Own,
                proofs: Vec::new(),
                exercise: None,
                consistency: None,
            },
            ais,
            String::from(IDENTITY_PEP),
        )
        .await
        .unwrap();
        let Verdict::Committed(c) = verdict else {
            panic!("{verdict:?}");
        };
        HoldingRef {
            grant: meta::object_id(&c.exercise, kind::GRANT, 0),
            holder,
            since: c.position,
        }
    }

    fn authority(
        &self,
        budget: Option<u64>,
        terms: BTreeSet<RequirementTerm>,
    ) -> CanonicalAuthority {
        let mut a = authority(BTreeSet::from([self.action.clone()]), "work", terms);
        if let Some(n) = budget {
            a.constraints.budget = BTreeSet::from([BudgetTerm {
                dimension: BudgetDimension::Count,
                capacity: n,
                window: BudgetWindow::RollingSeconds(86_400),
            }]);
        }
        a
    }

    fn plan(&self, path: &str, basis: HoldingRef, capacity: Option<Capacity>) -> Plan {
        Plan {
            intent: IntentEnvelope {
                provenance: BTreeMap::new(),
                action: self.action.clone(),
                resources: vec![ResourceRef {
                    namespace: String::from("work"),
                    path: vec![String::from(path)],
                    incarnation: 0,
                }],
                params: BTreeMap::new(),
                opaque: BTreeMap::new(),
                recipient: None,
                purpose: None,
                context: ContextRefs::default(),
                validity: window(),
            },
            basis: Some(ExerciseBasis::Holding(basis)),
            capacity,
        }
    }

    fn exercise(&self, plan: Plan) -> Exercise {
        Exercise::new(self.domain, AGENT_PEP, plan, nonce()).unwrap()
    }

    /// The identity plane's `operated_by` Claim naming the root as the agent's operator, as
    /// `idp.agent.register` emits it, carried to the domain by the realm issuer's courier.
    async fn operated_by(&self) {
        let order = access_identity_account::domain::claims::agent_claim(
            AGENT.0,
            access_kernel::claim::body::Class::OperatedBy,
            (
                access_kernel::model::EqValue::Bytes(self.root_party.0.to_vec()),
                &[],
            ),
            now_ms(),
            false,
        );
        self.issue(&order).await;
    }

    /// The realm issuer's Claim `order`, emitted by the identity plane and carried to the
    /// domain by the realm issuer's courier; the recorded Claim's id.
    async fn issue(&self, order: &access_identity_account::domain::claims::ClaimOrder) -> Id {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let t = TenantTx::begin(&self.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let mut pg = access_identity_account::adapters::pg::PgTx(t, None);
        access_identity_account::app::claims::emit(&mut pg, order)
            .await
            .unwrap();
        pg.0.commit().await.unwrap();
        self.delivered(order).await
    }

    /// Steps the realm issuer's courier until `order` is answered; the recorded Claim's id.
    async fn delivered(&self, order: &access_identity_account::domain::claims::ClaimOrder) -> Id {
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let w = &self.w;
        // OP-146 m.5 (f)
        let today = i32::try_from(server_time(&w.db.app).await.unwrap() / 86_400_000).unwrap();
        for o in access_store::ephemeral::open_days(&w.db.archive, today, 1).await {
            o.result.unwrap();
        }
        let courier = access_identity_account::app::claims::Courier {
            app: w.db.app.clone(),
            reader: w.db.reader.clone(),
            signer: access_identity_oauth::adapters::SignerKeys::new(w.identity_signer.clone()),
            ingest: access_authority_ingest::app::Ingest::new(
                w.domains.clone(),
                crate::ingest::PgSubmissions(w.db.app.clone()),
                crate::ingest::Trusted(tokio::sync::Mutex::new(
                    access_authority_sequencer::adapters::SourcesClock::new(w.db.app.clone()),
                )),
            ),
            clock: access_identity_account::adapters::system::SystemClock,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            let r = courier.step().await.unwrap();
            if r.answered > 0 {
                let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
                    .await
                    .unwrap();
                let id = access_store::issuer::last_in_line(
                    &mut t,
                    &order.subject,
                    &access_store::scope::DomainId::from_bytes(self.domain.0),
                    &order.line.unwrap(),
                )
                .await
                .unwrap()
                .unwrap();
                t.commit().await.unwrap();
                return Id(id);
            }
            assert!(std::time::Instant::now() < deadline, "{r:?}");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// One hub search of `kind` by the root, as the account pages sign it.
    async fn root_search(&self, kind: &str) -> Vec<serde_json::Value> {
        let now = now_ms();
        let search = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: meta::core_action("read"),
            resources: vec![ResourceRef {
                namespace: String::from("access.search"),
                path: vec![String::from(kind)],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: now - 60_000,
                until: now + 300_000,
            },
        };
        let n = nonce();
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.domain));
        let ais = sign(
            &self.root,
            &Statement {
                domain: self.domain,
                nonce: n.clone(),
                intent: intent_digest(&search).unwrap(),
                mode: Mode::Check,
                pep: String::from("access-hub-test"),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            },
        )
        .unwrap();
        let action = &search.action;
        let body = serde_json::json!({ "context": {
            "domain": b64url_encode(&self.domain.0),
            "mode": "check",
            "nonce": b64url_encode(&n),
            "intent": {
                "action": { "namespace": action.namespace, "name": action.name, "major": action.major, "schema": b64url_encode(&action.schema.0) },
                "resources": [{ "namespace": "access.search", "path": [kind] }],
                "validity": { "from": search.validity.from, "until": search.validity.until },
            },
            "basis": { "anchor": b64url_encode(&meta::meta_anchor(&self.domain).0) },
            "capacity": "own",
            "ais": b64url_encode(&ais),
            "query": { "party": b64url_encode(&self.root_party.0) },
        }});
        let mut req = HttpRequest::post(format!("/access/v1/search/{kind}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(PepId(String::from("access-hub-test")));
        let r = self.live.adp.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let out: serde_json::Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 1 << 22).await.unwrap()).unwrap();
        assert_eq!(status, 200, "{out}");
        out["results"].as_array().cloned().unwrap_or_default()
    }
}

/// A human-presence step-up bound to the actor's Instance (§8.18.3, AGI-4).
fn presence() -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Authentication,
        class: String::from("authentication"),
        count: 1,
        binding: Binding::ActorInstance,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::from([(String::from("human_presence"), 1)]),
    }
}

// A-1, A-2, A-3, A-4, A-6, A-7, A-10, AGI-4, SI-16, §8.17.5.2, §8.18.3, §9.9.5, AG-34,
// OP-153 m.3 (gg), Ek B 4121, 4345, 4346, 4347, 4348, 4351, 4354, 4357, 4362, 4363, 4444
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_on_the_real_server_follows_its_contract() {
    let a = Agents::open("l8-contract").await;
    let plain = a
        .grant(
            AGENT,
            a.authority(None, BTreeSet::new()),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let budget = a
        .grant(
            AGENT,
            a.authority(Some(1), BTreeSet::new()),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let human = a
        .grant(
            AGENT,
            a.authority(None, BTreeSet::from([presence()])),
            BTreeSet::from([Capacity::Own]),
        )
        .await;

    // A-1
    assert_eq!(
        Exercise::new(a.domain, AGENT_PEP, a.plan("l-1", plain, None), nonce()).err(),
        Some(AgentError::Capacity)
    );
    // A-2
    let mut ex = a.exercise(a.plan("l-1", plain, Some(Capacity::Own)));
    let Step::Proceed(allowed) = ex.ask(&a.live, &a.runtime, &Wall).unwrap() else {
        panic!("allow");
    };
    assert_eq!(Some(*allowed.exercise()), ex.exercise_ref());
    let changed = a.plan("l-2", plain, Some(Capacity::Own)).intent;
    assert_eq!(allowed.effect(&changed), Err(AgentError::EnvelopeChanged));
    assert_eq!(
        task_state(&Step::Proceed(allowed.clone())),
        TaskState::Working
    );

    // A-8, E31, Ek B 4352
    let horizon = now_ms() + 300_000;
    let mut long =
        access_sdk::agent::contract::Continuation::new(&allowed, now_ms(), horizon, Vec::new());
    assert!(long.ask(&ex, nonce(), &a.live, &a.runtime, &Wall).unwrap());
    assert!(long.may_start(now_ms()));
    let taken_over = Runtime(SoftSigner::generate_p256().unwrap().0);
    long.interrupted();
    assert!(!long.may_start(now_ms()));
    assert!(!long.ask(&ex, nonce(), &a.live, &taken_over, &Wall).unwrap());
    assert!(!long.may_start(now_ms()));
    assert_eq!(
        long.ask(&ex, nonce(), &a.live, &a.runtime, &Wall),
        Err(AgentError::Stopped)
    );

    // A-3, C30
    let mut first = a.exercise(a.plan("l-3", budget, Some(Capacity::Own)));
    assert!(matches!(
        first.ask(&a.live, &a.runtime, &Wall).unwrap(),
        Step::Proceed(_)
    ));
    let mut second = a.exercise(a.plan("l-4", budget, Some(Capacity::Own)));
    let Step::Stop(stopped) = second.ask(&a.live, &a.runtime, &Wall).unwrap() else {
        panic!("deny");
    };
    assert!(
        stopped
            .blockers
            .iter()
            .any(|b| b.class == access_kernel::combinator::BlockerClass::BudgetExhausted)
    );
    let before = a.live.asked.load(Ordering::SeqCst);
    assert_eq!(
        second.ask(&a.live, &a.runtime, &Wall),
        Err(AgentError::NonceClosed)
    );
    assert_eq!(
        second.renew(Change::BudgetReset, nonce(), now_ms()).err(),
        Some(AgentError::NoStateChange)
    );
    assert_eq!(a.live.asked.load(Ordering::SeqCst), before);
    let mut renewed = second
        .renew(
            Change::NewGrant(ExerciseBasis::Holding(plain)),
            nonce(),
            now_ms(),
        )
        .unwrap();
    assert!(matches!(
        renewed.ask(&a.live, &a.runtime, &Wall).unwrap(),
        Step::Proceed(_)
    ));

    // AGI-4, A-4, §8.18.3, Ek B 4121, 4363
    let recorded = Recorded {
        live: &a.live,
        bodies: std::cell::RefCell::new(Vec::new()),
    };
    let mut asks = a.exercise(a.plan("l-5", human, Some(Capacity::Own)));
    let step = asks.ask(&recorded, &a.runtime, &Wall).unwrap();
    let Step::Wait(wait) = &step else {
        panic!("{step:?} {:?}", recorded.bodies.borrow());
    };
    assert_eq!(wait.routes, [Route::PrincipalOwnAction]);
    assert!(!wait.unmet[0].satisfiable_by_actor);
    let raw = recorded.bodies.borrow()[0].clone();
    assert!(raw.contains("\"satisfiable_by_actor\":false"), "{raw}");
    assert!(!raw.contains("interaction_required"), "{raw}");
    let again = asks.ask(&recorded, &a.runtime, &Wall).unwrap();
    assert!(matches!(again, Step::Wait(_)));
    let sent = kjson::parse(recorded.bodies.borrow()[1].as_bytes(), 1 << 20).unwrap();
    assert!(sent.get("context").is_some());
    // §9.9.5, AG-34
    let (state, member) = a2a::require_action(&asks, &step).unwrap();
    assert_eq!(state, TaskState::InputRequired);
    assert!(member.contains("not-satisfiable-by-actor"));
    assert!(!member.contains("interaction_required"));
    // A-6, §8.17.5.2
    let note = RequesterNote::new("Needs the principal to confirm in person.").unwrap();
    let h = handoff(
        &asks,
        &step,
        Requester {
            party: AGENT,
            instance: Some(a.instance),
        },
        &note,
        WorkRefs::default(),
    )
    .unwrap();
    assert!(h.same_nonce);
    let request = kjson::parse(h.request.as_bytes(), 1 << 16).unwrap();
    assert_eq!(
        request.get("reason").and_then(Json::as_str),
        Some(note.as_str())
    );
    assert!(request.get("require_action").is_some());

    // A-10, L17
    let advisory = ex
        .check(nonce(), &a.live, &a.runtime, &Wall)
        .unwrap()
        .unwrap();
    assert!(advisory.allowed);

    // MUST-NEVER-14, §2.7, Ek B 4644
    let with_memory = Injecting {
        live: &a.live,
        answers: std::cell::RefCell::new(Vec::new()),
    };
    let mut private = a.exercise(a.plan("l-6", plain, Some(Capacity::Own)));
    let step = private.ask(&with_memory, &a.runtime, &Wall).unwrap();
    assert!(
        matches!(
            step,
            Step::Unknown(access_sdk::agent::decision::Unread::Status(400))
        ),
        "{step:?}"
    );
    assert!(with_memory.answers.borrow()[0].contains("unknown-member"));
    let mut clean = a.exercise(a.plan("l-6", plain, Some(Capacity::Own)));
    assert!(matches!(
        clean.ask(&a.live, &a.runtime, &Wall).unwrap(),
        Step::Proceed(_)
    ));
    a.w.domains.release().await;
}

/// A decision point the caller adds private context to (One memory, Work content): Access
/// reads none of it and refuses the request (MUST-NEVER-14).
struct Injecting<'a> {
    live: &'a Live,
    answers: std::cell::RefCell<Vec<String>>,
}

impl Adp for Injecting<'_> {
    fn evaluate(&self, body: &str) -> Answer {
        let injected = body.replacen(
            "\"context\":{",
            "\"context\":{\"memory\":{\"one\":\"the user said yes earlier\"},\"work_content\":\"draft\",",
            1,
        );
        let a = self.live.evaluate(&injected);
        self.answers.borrow_mut().push(body_of(&a));
        a
    }
}

// A-11, A-12, E26, AG-34, AGI-7, §11.15, OP-153 m.3 (gg), Ek B 4193, 4273, 4355, 4356,
// AG-34, Ek B 4443, 4448, 4549
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_reads_its_own_status_and_takes_no_authority_from_a_task() {
    let a = Agents::open("l8-status").await;
    let own = a
        .grant(
            AGENT,
            a.authority(Some(3), BTreeSet::new()),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let others = a
        .grant(
            STRANGER,
            a.authority(None, BTreeSet::new()),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let mut ex = a.exercise(a.plan("s-1", own, Some(Capacity::Own)));
    let Step::Proceed(allowed) = ex.ask(&a.live, &a.runtime, &Wall).unwrap() else {
        panic!("allow");
    };

    // A-11, E26
    assert!(a.w.domains.derive().await.is_empty());
    let body = status::body(&a.domain, AGENT_PEP, &nonce(), &a.runtime, &Wall).unwrap();
    let answer = a.live.post(status::PATH, &body);
    let s = status::read(&answer).unwrap_or_else(|e| panic!("{e:?} {}", body_of(&answer)));
    assert_eq!(s.instance, a.instance);
    assert_eq!(s.party, AGENT);
    assert!(s.live);
    let held = s
        .holdings
        .iter()
        .find(|h| h.grant == own.grant)
        .unwrap_or_else(|| panic!("{}", body_of(&answer)));
    assert_eq!(held.budgets[0].capacity, 3);
    assert_eq!(held.budgets[0].remaining, 2);
    assert!(held.until.is_none_or(|u| u > now_ms()));
    assert!(s.holdings.iter().all(|h| h.grant != others.grant));
    let raw = body_of(&answer);
    assert!(!raw.contains(&b64url_encode(&STRANGER.0)), "{raw}");
    assert!(!raw.contains(&b64url_encode(&a.root_party.0)), "{raw}");

    // A-12, XI-17
    let disclosure = access_sdk::agent::identity::Disclosure::new(
        a.instance,
        AGENT,
        a.root_party,
        Capacity::Own,
    );
    assert!(disclosure.json().contains("\"party_kind\":\"agent\""));

    // AG-34, AGI-7, Ek B 4448
    let inbound = a2a::inbound(
        format!(
            r#"{{"{}":{{"kind":"causal","exercise":"{}"}},"grant":"{}","access_token":"x"}}"#,
            a2a::EXTENSION,
            b64url_encode(&allowed.exercise().0),
            b64url_encode(&own.grant.0)
        )
        .as_bytes(),
    )
    .unwrap();
    assert_eq!(inbound, Inbound::Causal(*allowed.exercise()));
    let stranger = Runtime(SoftSigner::generate_p256().unwrap().0);
    let borrowed = a2a::separate_exercise(a.plan("s-2", own, Some(Capacity::Own)), &inbound);
    assert_eq!(
        borrowed.intent.context.upstream_exercise,
        Some(*allowed.exercise())
    );
    let mut taken = a.exercise(borrowed);
    let step = taken.ask(&a.live, &stranger, &Wall).unwrap();
    assert!(matches!(step, Step::Unknown(_) | Step::Stop(_)), "{step:?}");
    assert_eq!(task_state(&step), TaskState::Failed);

    // AG-34, Ek B 4193
    let r = a
        .discovery
        .clone()
        .oneshot(
            HttpRequest::get("/realms/acme/.well-known/openid-configuration")
                .header(header::HOST, "access.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let doc = to_bytes(r.into_body(), 1 << 20).await.unwrap();
    let schemes = security_schemes(&doc).unwrap();
    let j = kjson::parse(schemes.as_bytes(), 1 << 16).unwrap();
    let issuer = kjson::parse(&doc, 1 << 20)
        .unwrap()
        .get("issuer")
        .and_then(Json::as_str)
        .unwrap()
        .to_owned();
    assert_eq!(
        j.get("access_openid")
            .and_then(|o| o.get("openIdConnectUrl"))
            .and_then(Json::as_str),
        Some(format!("{issuer}/.well-known/openid-configuration").as_str())
    );
    let flows = j.get("access_oauth2").and_then(|o| o.get("flows")).unwrap();
    assert!(flows.get("authorizationCode").is_some(), "{schemes}");
    assert!(flows.get("deviceCode").is_none(), "{schemes}");
    a.w.domains.release().await;
}

// XI-17, A-12, §6.4, §8.10, §8.17.5.11, §8.17.7.1, OP-153 m.3 (gg), Ek B 4230
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hub_shows_an_agent_as_an_agent_with_its_operator() {
    let a = Agents::open("l9-faces").await;
    let acting = a
        .grant(
            AGENT,
            a.authority(None, BTreeSet::new()),
            BTreeSet::from([Capacity::For(a.root_party)]),
        )
        .await;
    let person = a
        .grant(
            a.root_party,
            a.authority(None, BTreeSet::new()),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let mut ex = a.exercise(a.plan("f-1", acting, Some(Capacity::For(a.root_party))));
    let Step::Proceed(_) = ex.ask(&a.live, &a.runtime, &Wall).unwrap() else {
        panic!("allow");
    };
    let before = a.root_search("inventory").await;
    let unnamed = before
        .iter()
        .find(|r| r["grant"] == b64url_encode(&acting.grant.0).as_str())
        .unwrap();
    assert_eq!(unnamed["agent"]["party_kind"], "agent", "{unnamed}");
    assert!(unnamed["agent"].get("operator").is_none(), "{unnamed}");
    a.operated_by().await;

    let inventory = a.root_search("inventory").await;
    let row = |g: Id| {
        inventory
            .iter()
            .find(|r| r["grant"] == b64url_encode(&g.0).as_str())
            .cloned()
            .unwrap_or_else(|| panic!("{inventory:?}"))
    };
    let agent = row(acting.grant);
    assert_eq!(agent["groups"][0], "acting_for_you", "{agent}");
    assert_eq!(agent["agent"]["party_kind"], "agent", "{agent}");
    assert_eq!(
        agent["agent"]["operator"],
        b64url_encode(&a.root_party.0),
        "{agent}"
    );
    let own = row(person.grant);
    assert!(own.get("agent").is_none(), "{own}");

    let activity = a.root_search("activity").await;
    let used = activity
        .iter()
        .find(|u| u["by_viewer"] == false)
        .unwrap_or_else(|| panic!("{activity:?}"));
    assert_eq!(used["agent"]["party_kind"], "agent", "{used}");
    assert_eq!(used["agent"]["party"], b64url_encode(&AGENT.0), "{used}");
    assert_eq!(
        used["agent"]["operator"],
        b64url_encode(&a.root_party.0),
        "{used}"
    );
    assert!(
        used["reports"]["attested"].as_array().unwrap().is_empty(),
        "{used}"
    );
    a.w.domains.release().await;
}

/// A runtime attestation of the actor's own Instance (§5.9, L21).
fn attested_runtime() -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: String::from("attestation_runtime"),
        count: 1,
        binding: Binding::ActorInstance,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    }
}

// §5.9, L21, U20, OP-154 m.3 (s), m.11 (l), OP-153 m.3 (gg), Ek B 4262
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_runtime_attestation_requirement_is_met_only_by_the_actors_attested_instance() {
    let a = Agents::open("l4-runtime").await;
    let attested = a
        .grant(
            AGENT,
            a.authority(None, BTreeSet::from([attested_runtime()])),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let mut ex = a.exercise(a.plan("r-1", attested, Some(Capacity::Own)));
    let step = ex.ask(&a.live, &a.runtime, &Wall).unwrap();
    let Step::Wait(wait) = &step else {
        panic!("{step:?}");
    };
    assert_eq!(wait.unmet[0].class.as_data(), "attestation_runtime");
    assert!(wait.unmet[0].satisfiable_by_actor);

    // L21
    let runtime = access_identity_attest::domain::runtime::RuntimeClass::Tpm.digest();
    let elsewhere = a
        .issue(
            &access_identity_account::domain::claims::runtime_attestation(
                AGENT.0,
                [0x5f; 16],
                runtime,
                now_ms(),
            ),
        )
        .await;
    ex.prove(Proof::ClaimRef(elsewhere)).unwrap();
    let step = ex.ask(&a.live, &a.runtime, &Wall).unwrap();
    assert!(matches!(step, Step::Wait(_)), "{step:?}");

    let here = a
        .issue(
            &access_identity_account::domain::claims::runtime_attestation(
                AGENT.0,
                a.instance.0,
                runtime,
                now_ms(),
            ),
        )
        .await;
    ex.prove(Proof::ClaimRef(here)).unwrap();
    let step = ex.ask(&a.live, &a.runtime, &Wall).unwrap();
    assert!(matches!(step, Step::Proceed(_)), "{step:?}");
    a.w.domains.release().await;
}

/// A DER TLV.
fn tlv(tag: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = tag.to_vec();
    let n = content.len();
    if n < 0x80 {
        out.push(u8::try_from(n).unwrap());
    } else {
        out.extend([0x81, u8::try_from(n).unwrap()]);
    }
    out.extend_from_slice(content);
    out
}

/// An Android `KeyDescription` of a TEE key generated in hardware on a verified, locked device
/// for `challenge`.
fn key_description(challenge: &[u8]) -> Vec<u8> {
    let root = tlv(
        &[0x30],
        &[
            tlv(&[0x04], &[7; 32]),
            tlv(&[0x01], &[0xff]),
            tlv(&[0x0a], &[0]),
            tlv(&[0x04], &[8; 32]),
        ]
        .concat(),
    );
    let hardware = [
        tlv(&[0xbf, 0x85, 0x3e], &tlv(&[0x02], &[0])),
        tlv(&[0xbf, 0x85, 0x40], &root),
    ]
    .concat();
    tlv(
        &[0x30],
        &[
            tlv(&[0x02], &[0, 200]),
            tlv(&[0x0a], &[1]),
            tlv(&[0x02], &[0, 200]),
            tlv(&[0x0a], &[1]),
            tlv(&[0x04], challenge),
            tlv(&[0x04], &[]),
            tlv(&[0x30], &[]),
            tlv(&[0x30], &hardware),
        ]
        .concat(),
    )
}

/// An attestation CA and the Android chain it issues for `key` and `challenge`.
fn android_chain(
    ca: &(rcgen::Issuer<'static, rcgen::KeyPair>, Vec<u8>),
    key: &rcgen::KeyPair,
    challenge: &[u8],
) -> Vec<Vec<u8>> {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17],
            key_description(challenge),
        ));
    let leaf = params.signed_by(key, &ca.0).unwrap().der().to_vec();
    vec![leaf, ca.1.clone()]
}

fn attestation_ca() -> (rcgen::Issuer<'static, rcgen::KeyPair>, Vec<u8>) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Test Attestation Root");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root = params.self_signed(&key).unwrap().der().to_vec();
    (rcgen::Issuer::new(params, key), root)
}

// §5.9, §10.1.2, §12.2.1, L21, AG-31, U20, OP-154 m.3 (s), m.11 (l), OP-153 m.3 (gg),
// Ek B 4125, 4262, 4524
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hardware_evidence_of_an_instance_key_becomes_its_runtime_attestation() {
    let (runtime, pkcs8) = SoftSigner::generate_p256().unwrap();
    let a = Agents::open_with("l4-evidence", runtime).await;
    let leaf_key = rcgen::KeyPair::try_from(pkcs8.expose().as_slice()).unwrap();
    let stranger = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca = attestation_ca();
    let route = route_by_slug(&a.w.db.router, "acme")
        .await
        .unwrap()
        .unwrap();
    let router = access_http::login::workloads_router(
        RealmDiscovery::new(
            PgDirectory::new(a.w.db.router.clone()),
            access_identity_oauth::adapters::SignerKeys::new(a.w.identity_signer.clone()),
        ),
        super::vault::Lab::hosted(&a.w),
        a.w.plane.clone(),
        access_identity_ui::app::workloads::AttestRoots {
            android: vec![ca.1.clone()],
            tpm: Vec::new(),
        },
    );
    let post = |body: serde_json::Value| {
        let router = router.clone();
        async move {
            let r = router
                .oneshot(
                    HttpRequest::post("/realms/acme/v1/workloads/attestations")
                        .header(header::HOST, "access.test")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = r.status().as_u16();
            let out: serde_json::Value =
                serde_json::from_slice(&to_bytes(r.into_body(), 1 << 20).await.unwrap())
                    .unwrap_or_default();
            (status, out)
        }
    };
    let rfc = access_identity_ui::domain::frontend::rfc3339;
    let at = server_time(&a.w.db.app).await.unwrap();
    let challenge =
        access_identity_attest::domain::runtime::challenge(&route.issuer, &a.instance.0, at);
    let body = |chain: &[Vec<u8>], at: u64, format: &str| {
        serde_json::json!({
            "instance": b64url_encode(&a.instance.0),
            "at": rfc(at),
            "format": format,
            "x5c": chain.iter().map(|c| b64url_encode(c)).collect::<Vec<_>>(),
        })
    };

    // L21
    let (status, r) = post(body(
        &android_chain(&ca, &stranger, &challenge),
        at,
        "android-key",
    ))
    .await;
    assert_eq!(
        (status, r["code"].as_str()),
        (400, Some("attestation-other-key")),
        "{r}"
    );
    let (status, r) = post(body(
        &android_chain(&ca, &leaf_key, &[9; 32]),
        at,
        "android-key",
    ))
    .await;
    assert_eq!(
        (status, r["code"].as_str()),
        (400, Some("attestation-refused")),
        "{r}"
    );
    let old = at - 600_000;
    let (status, r) = post(body(
        &android_chain(
            &ca,
            &leaf_key,
            &access_identity_attest::domain::runtime::challenge(&route.issuer, &a.instance.0, old),
        ),
        old,
        "android-key",
    ))
    .await;
    assert_eq!(
        (status, r["code"].as_str()),
        (400, Some("attestation-stale")),
        "{r}"
    );
    let (status, r) = post(body(&[vec![1]], at, "apple-app-attest")).await;
    assert_eq!(
        (status, r["code"].as_str()),
        (400, Some("attestation-format-unsupported")),
        "{r}"
    );

    // §12.2.1
    let (status, r) = post(body(
        &android_chain(&ca, &leaf_key, &challenge),
        at,
        "android-key",
    ))
    .await;
    assert_eq!(status, 202, "{r}");
    assert_eq!(r["runtime"], "android/tee/verified", "{r}");
    let class = access_identity_attest::domain::runtime::RuntimeClass::Android {
        level: access_identity_attest::domain::android::SecurityLevel::Tee,
        verified_locked: true,
    };
    let order = access_identity_account::domain::claims::runtime_attestation(
        AGENT.0,
        a.instance.0,
        class.digest(),
        at,
    );
    let claim = a.delivered(&order).await;

    // §5.9, Ek B 4262
    let basis = a
        .grant(
            AGENT,
            a.authority(None, BTreeSet::from([attested_runtime()])),
            BTreeSet::from([Capacity::Own]),
        )
        .await;
    let mut ex = a.exercise(a.plan("e-1", basis, Some(Capacity::Own)));
    assert!(matches!(
        ex.ask(&a.live, &a.runtime, &Wall).unwrap(),
        Step::Wait(_)
    ));
    ex.prove(Proof::ClaimRef(claim)).unwrap();
    let step = ex.ask(&a.live, &a.runtime, &Wall).unwrap();
    assert!(matches!(step, Step::Proceed(_)), "{step:?}");
    a.w.domains.release().await;
}
