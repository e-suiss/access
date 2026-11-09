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
use access_sdk::agent::contract::{Adp, AgentError, Change, Exercise, Plan, Signs, Step};
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
const AGENT_PEP: &str = "agent-runtime";
pub(super) const AGENT: Id = Id([0x0c; 16]);
const STRANGER: Id = Id([0x0d; 16]);

struct Wall;

impl Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(now_ms())
    }
}

fn nonce() -> Vec<u8> {
    access_crypto::random::bytes::<16>().unwrap().to_vec()
}

fn block<F: std::future::Future>(f: F) -> F::Output {
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
struct Live {
    adp: axum::Router,
    asked: AtomicUsize,
}

impl Live {
    fn post(&self, path: &str, body: &str) -> Answer {
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
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    let root_party = root_party(&root_key(&w.keys).unwrap().public_key());
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
    let runtime = SoftSigner::generate_p256().unwrap().0;
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
        let (runtime, instance) = enrol(&w, domain).await;
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
    a.w.domains.release().await;
}

// A-11, A-12, E26, AG-34, AGI-7, §11.15, OP-153 m.3 (gg), Ek B 4193, 4273, 4355, 4356,
// 4443, 4448, 4549
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
