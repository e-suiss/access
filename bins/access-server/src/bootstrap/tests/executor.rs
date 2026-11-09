//! The Access Executor against the real server path (OP-154 m.3 (u), OP-153 m.3 (gg)): the
//! token vault's bootstrapped realm, its Resource listing the executor's PEP name, and an
//! executor registered as an Instance of its own operator Party. The executor reaches Access
//! only through the public routes a third-party PEP uses (ADP evaluation and Domain Metadata,
//! the vault's release route, Claim Ingest), on the real sequencer and `SoftHSM`; its job
//! history is in its own database. The upstream API is a scripted stand-in.

#![allow(
    clippy::too_many_lines,
    reason = "test code: walks through the executor's rules"
)]

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use access_executor::app::{Config, ExecError, Executor, Start, Tokens};
use access_executor::domain::Kind;
use access_executor::domain::attest::Reporter;
use access_executor::domain::history::Outcome as Reported;
use access_executor::domain::machine::Next;
use access_executor::domain::step::{Call, Reversibility, StepSpec};
use access_executor::drivers::HttpRequest;
use access_executor::store::Store;
use access_http::adp::adapters::Pep as PepId;
use access_identity_vault::domain::resource::VaultChange;
use access_internal_api::instances::{
    PlatformProduct, Registrant, Registration, RegistrationVerdict, SelfSigned, bootstrap_basis,
    register_nonce, self_signed_intent,
};
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::b64url_decode;
use access_sdk::transport::{Answer, Fault, Response as Answered};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequestOf, header};
use suiss_crypto::signer::SoftSigner;
use tower::ServiceExt as _;

use super::vault::{EXECUTOR, Lab, revoke};
use super::*;

/// The executor's operator Party: its reports' issuer, never an actor.
const OPERATOR: Id = Id([0x0e; 16]);

const API: &str = "https://api.upstream.test/v1/messages";

/// Access's public routes as the executor's client certificate reaches them.
#[derive(Clone)]
struct Public {
    adp: axum::Router,
    pages: axum::Router,
    ingest: axum::Router,
}

async fn call(
    router: &axum::Router,
    req: axum::http::request::Builder,
    pep: bool,
    body: Vec<u8>,
) -> Answer {
    let mut req = req
        .header(header::HOST, "access.test")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    if pep {
        req.extensions_mut().insert(PepId(String::from(EXECUTOR)));
    }
    let r = router.clone().oneshot(req).await.unwrap();
    let status = r.status().as_u16();
    let key_excerpt = r
        .headers()
        .get("access-key-excerpt")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| b64url_decode(v).ok());
    let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
    Answer::Response(Answered {
        status,
        content_type: None,
        key_excerpt,
        body,
    })
}

impl access_executor::ports::Access for Public {
    async fn evaluate(&self, body: Vec<u8>) -> Answer {
        call(
            &self.adp,
            HttpRequestOf::post("/access/v1/evaluation"),
            true,
            body,
        )
        .await
    }

    async fn metadata(&self, domain: String) -> Answer {
        call(
            &self.adp,
            HttpRequestOf::get(format!(
                "/.well-known/access-domain-metadata/sha-256:{domain}"
            )),
            false,
            Vec::new(),
        )
        .await
    }

    async fn release(&self, realm: String, body: Vec<u8>) -> Answer {
        call(
            &self.pages,
            HttpRequestOf::post(format!("/realms/{realm}/v1/vault/releases")),
            true,
            body,
        )
        .await
    }

    async fn ingest(&self, key: String, body: Vec<u8>) -> Answer {
        call(
            &self.ingest,
            HttpRequestOf::post("/access/v1/claims:ingest").header("idempotency-key", key),
            true,
            body,
        )
        .await
    }
}

/// The upstream API: scripted answers in order, every request it was sent, and a switch that
/// leaves the next request hanging, as a crash mid-send would.
#[derive(Default)]
struct Api {
    answers: StdMutex<VecDeque<(u16, String)>>,
    seen: StdMutex<Vec<HttpRequest>>,
    hang: AtomicBool,
}

#[derive(Clone)]
struct Scripted(Arc<Api>);

impl access_executor::ports::Upstream for Scripted {
    async fn send(&self, request: HttpRequest) -> Answer {
        if self.0.hang.swap(false, Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
        self.0.seen.lock().unwrap().push(request);
        let next = self.0.answers.lock().unwrap().pop_front();
        next.map_or(Answer::Unanswered(Fault::Unreachable), |(status, body)| {
            Answer::Response(Answered::new(status, body.into_bytes()))
        })
    }
}

/// Wall time, moved on by the test where a window has to pass.
#[derive(Clone, Default)]
struct Wall(Arc<AtomicU64>);

impl access_executor::ports::Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(now_ms() + self.0.load(Ordering::SeqCst))
    }
}

struct Os;

impl access_executor::ports::Random for Os {
    fn bytes(&self) -> Option<[u8; 16]> {
        access_crypto::random::bytes().ok()
    }
}

type Exec = Executor<Public, Scripted, Wall, Os, SoftSigner>;

struct Rig {
    lab: Lab,
    public: Public,
    api: Arc<Api>,
    wall: Wall,
    store: Store,
    tokens: Arc<Tokens>,
    pkcs8: suiss_crypto::secret::Secret<Vec<u8>>,
    instance: Id,
    connection: String,
}

/// The executor key's self-signed registration Exercise of `payload`.
fn self_signed(domain: Digest, key: &SoftSigner, nonce: &[u8], payload: &Payload) -> SelfSigned {
    let now = now_ms();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(payload, OPERATOR, validity).unwrap();
    let statement = Statement {
        domain,
        nonce: nonce.to_vec(),
        intent: intent_digest(&intent).unwrap(),
        mode: Mode::Commit,
        pep: String::from(access_internal_api::instances::IDENTITY_PEP),
        capacity: Capacity::Own,
        basis: bootstrap_basis(&domain),
        iat: now,
        exercise: None,
    };
    SelfSigned {
        nonce: nonce.to_vec(),
        validity,
        ais: sign_sign1(
            key,
            thumbprint(&key.public_key()),
            access_kernel::ais::CONTENT_TYPE,
            &statement.to_bytes().unwrap(),
        )
        .unwrap(),
    }
}

impl Rig {
    async fn open(name: &str) -> Self {
        let mut lab = Lab::open(name).await;
        lab.change(VaultChange::Enable(Box::new(lab.resource())))
            .await;
        lab.consent().await;
        let connection = lab
            .connect(r#"{"access_token":"at-first","refresh_token":"rt-1","expires_in":120,"token_type":"Bearer"}"#)
            .await;
        let (key, pkcs8) = SoftSigner::generate_ed25519().unwrap();
        // AG-40, E57 (1), Ek B 4340, 4490
        let mut registration = Registration {
            tenant: *lab.route.tenant.as_bytes(),
            domain: lab.domain,
            registrant: Registrant::Service {
                product: PlatformProduct::parse("executor").unwrap(),
                client: String::from("executor"),
            },
            party: OPERATOR,
            key: key.public_key(),
            register: None,
            create: SelfSigned {
                nonce: Vec::new(),
                validity: Window { from: 0, until: 0 },
                ais: Vec::new(),
            },
            pep: String::from(access_internal_api::instances::IDENTITY_PEP),
            context: None,
        };
        let challenge = access_crypto::random::bytes::<32>().unwrap().to_vec();
        registration.register = Some(self_signed(
            lab.domain,
            &key,
            &register_nonce(&challenge),
            &registration.register_payload(),
        ));
        registration.create =
            self_signed(lab.domain, &key, &challenge, &registration.create_payload());
        let instance = match lab.w.plane.register(registration).await.unwrap() {
            RegistrationVerdict::Registered(r) => r.instance,
            other @ RegistrationVerdict::Refused { .. } => panic!("{other:?}"),
        };
        let public = Public {
            adp: lab.adp.clone(),
            pages: lab.pages.clone(),
            ingest: crate::ingest::routes(lab.w.domains.clone(), lab.w.db.app.clone()),
        };
        // CMP-8
        let today = server_time(&lab.w.db.app).await.unwrap() / 86_400_000;
        for day in [today - 1, today, today + 1] {
            access_store::claims::open_claim_ingest_day(
                &lab.w.db.archive,
                u32::try_from(day).unwrap(),
            )
            .await
            .unwrap();
        }
        let (store, _) = access_executor::testing::store().await.unwrap();
        Self {
            lab,
            public,
            api: Arc::new(Api::default()),
            wall: Wall::default(),
            store,
            tokens: Arc::new(Tokens::default()),
            pkcs8,
            instance,
            connection,
        }
    }

    /// A fresh executor process over the same database; `tokens` is its token memory.
    fn executor(&self, tokens: Arc<Tokens>) -> Exec {
        Executor::new(
            (
                self.store.clone(),
                self.public.clone(),
                Scripted(Arc::clone(&self.api)),
            ),
            (
                self.wall.clone(),
                Os,
                SoftSigner::ed25519_from_pkcs8(&self.pkcs8).unwrap(),
            ),
            Config {
                pep: String::from(EXECUTOR),
                kind: Kind::Customer,
                reporter: Reporter {
                    operator: OPERATOR,
                    executor: self.instance,
                },
                signature_agent: String::from(
                    "https://access.test/.well-known/http-message-signatures-directory",
                ),
            },
            tokens,
        )
    }

    /// The person's statement for the executor as PEP.
    fn ais(
        &self,
        intent: &IntentEnvelope,
        mode: Mode,
        exercise: Option<Digest>,
    ) -> (Vec<u8>, Vec<u8>) {
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let ais = sign(
            &self.lab.person,
            &Statement {
                domain: self.lab.domain,
                nonce: nonce.clone(),
                intent: intent_digest(intent).unwrap(),
                mode,
                pep: String::from(EXECUTOR),
                capacity: Capacity::Own,
                basis: ExerciseBasis::Holding(self.lab.holding),
                iat: now_ms(),
                exercise,
            },
        )
        .unwrap();
        (ais, nonce)
    }

    fn step(
        &self,
        name: &str,
        path: &str,
        reversibility: Reversibility,
        idempotent: bool,
    ) -> StepSpec {
        StepSpec {
            name: String::from(name),
            action: format!("{}/{}", self.lab.action.namespace, self.lab.action.name),
            resource: String::from("work:inbox"),
            reversibility,
            idempotent,
            call: Call::Http {
                method: String::from("POST"),
                url: format!("{API}/{path}"),
                body: Some(serde_json::json!({ "to": "someone@example.org" })),
            },
        }
    }

    /// Starts a job of `steps` under a fresh Exercise with `continuations` continue statements.
    async fn start(
        &self,
        exec: &Exec,
        intent: &IntentEnvelope,
        steps: Vec<StepSpec>,
        continuations: usize,
    ) -> Result<([u8; 16], Digest), ExecError> {
        let (ais, nonce) = self.ais(intent, Mode::Commit, None);
        let exercise = meta::exercise_id(&self.lab.domain, &nonce).unwrap();
        let continuations = (0..continuations)
            .map(|_| self.ais(intent, Mode::Continue, Some(exercise)).0)
            .collect();
        // U66
        self.lab.upstream.answers.lock().unwrap().push_back((
            200,
            String::from(r#"{"access_token":"at-second","expires_in":900}"#),
        ));
        let job = exec
            .start(Start {
                realm: String::from("acme"),
                connection: self.connection.clone(),
                intent: intent.to_bytes().unwrap(),
                ais,
                steps,
                continuations,
            })
            .await?;
        Ok((job, exercise))
    }

    fn answer(&self, status: u16, body: &str) {
        self.api
            .answers
            .lock()
            .unwrap()
            .push_back((status, String::from(body)));
    }

    /// The `outcome` search of `exercise` by the person, through the real ADP router.
    async fn outcome(&self, exercise: Digest, intent: &IntentEnvelope) -> serde_json::Value {
        let now = now_ms();
        let search = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: meta::core_action("read"),
            resources: vec![ResourceRef {
                namespace: String::from("access.search"),
                path: vec![String::from("outcome")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: access_kernel::intent::ContextRefs::default(),
            validity: Window {
                from: now - 60_000,
                until: now + 300_000,
            },
        };
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.lab.domain));
        let ais = sign(
            &self.lab.person,
            &Statement {
                domain: self.lab.domain,
                nonce: nonce.to_vec(),
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
            "domain": b64url_encode(&self.lab.domain.0),
            "mode": "check",
            "nonce": b64url_encode(&nonce),
            "intent": {
                "action": { "namespace": action.namespace, "name": action.name, "major": action.major, "schema": b64url_encode(&action.schema.0) },
                "resources": [{ "namespace": "access.search", "path": ["outcome"] }],
                "validity": { "from": search.validity.from, "until": search.validity.until },
            },
            "basis": { "anchor": b64url_encode(&meta::meta_anchor(&self.lab.domain).0) },
            "capacity": "own",
            "ais": b64url_encode(&ais),
            "query": { "exercise": b64url_encode(&exercise.0), "intent": b64url_encode(&intent.to_bytes().unwrap()) },
        }});
        let mut req = HttpRequestOf::post("/access/v1/search/outcome")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut()
            .insert(PepId(String::from("access-hub-test")));
        let r = self.lab.adp.clone().oneshot(req).await.unwrap();
        let status = r.status();
        let out: serde_json::Value =
            serde_json::from_slice(&to_bytes(r.into_body(), 1 << 22).await.unwrap()).unwrap();
        assert_eq!(status, axum::http::StatusCode::OK, "{out}");
        out["results"][0].clone()
    }
}

fn header_of<'a>(r: &'a HttpRequest, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

// AG-40, B21, F7, E64, INV-18, EI-10, E51, E62 (2), OP-154 m.3 (u), OP-153 m.3 (gg), Ek B 4277, 4279, 4280, 4327, 4417, 4481, 4486, 4497, 4600
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_executor_runs_an_allowed_exercise_and_its_reports_never_change_the_decision() {
    let rig = Rig::open("executor-run").await;
    let exec = rig.executor(Arc::clone(&rig.tokens));
    let intent = rig.lab.intent(1_200_000);
    let steps = vec![
        rig.step("send", "send", Reversibility::Reversible, true),
        rig.step("label", "label", Reversibility::Reversible, false),
    ];
    let (job, exercise) = rig.start(&exec, &intent, steps, 1).await.unwrap();
    rig.answer(200, r#"{"id":"m-1"}"#);
    rig.answer(422, r#"{"error":"unknown label"}"#);
    assert_eq!(exec.drive(job).await.unwrap(), Next::Done);

    let seen = rig.api.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 2);
    let j = exec.job(job).await.unwrap();
    // AG-40 (5), E62 (2)
    assert_eq!(
        header_of(&seen[0], "Authorization"),
        Some("Bearer at-second")
    );
    assert_eq!(
        header_of(&seen[0], "Idempotency-Key"),
        Some(b64url_encode(&j.steps[0].key.0).as_str())
    );
    // E51, Ek B 4327, 4328
    assert_eq!(
        header_of(&seen[0], "Signature-Agent"),
        Some("\"https://access.test/.well-known/http-message-signatures-directory\"")
    );
    assert!(
        header_of(&seen[0], "Signature-Input")
            .unwrap()
            .contains("tag=\"web-bot-auth\"")
    );
    assert_eq!(header_of(&seen[0], "User-Agent"), Some("access-executor/1"));
    let view = access_executor::adapters::view(&j);
    assert_eq!(view["state"], "completed");
    assert_eq!(view["steps"][0]["outcome"], "done");
    assert_eq!(view["steps"][0]["evidence"][0], "upstream-confirmation");
    assert_eq!(view["steps"][1]["outcome"], "not-done");
    assert!(view["steps"][1].get("report_refused").is_none(), "{view}");
    assert_eq!(j.checkpoints, 1);
    assert!(matches!(
        j.steps[1].outcome,
        Some((Reported::NotDone, _, _))
    ));

    // E64, INV-18, EI-10
    let report = rig.outcome(exercise, &intent).await;
    assert_eq!(report["type"], "outcome", "{report}");
    assert_eq!(report["status"], "attested");
    let allowed_at = report["allowed_at"].as_u64().unwrap();
    let attested = report["attested"].as_array().unwrap();
    assert_eq!(attested.len(), 2, "{report}");
    assert_eq!(attested[0]["outcome"], "done");
    assert_eq!(attested[0]["evidence"][0], "upstream-confirmation");
    assert_eq!(attested[0]["reporter"], b64url_encode(&OPERATOR.0));
    assert_eq!(attested[0]["executor"], b64url_encode(&rig.instance.0));
    assert_eq!(attested[0]["conformance"], "conforming");
    assert_eq!(attested[1]["outcome"], "not-done");
    assert_eq!(attested[1]["conformance"], "conforming");
    assert!(attested[1]["position"].as_u64().unwrap() > allowed_at);
    let again = rig.outcome(exercise, &intent).await;
    assert_eq!(again["allowed_at"].as_u64(), Some(allowed_at));

    // AG-40, F7, Ek B 4600
    let foreign = HoldingRef {
        holder: Id([0x5a; 16]),
        ..rig.lab.holding
    };
    let (ais, _) = {
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        (
            sign(
                &rig.lab.person,
                &Statement {
                    domain: rig.lab.domain,
                    nonce: nonce.clone(),
                    intent: intent_digest(&intent).unwrap(),
                    mode: Mode::Commit,
                    pep: String::from(EXECUTOR),
                    capacity: Capacity::Own,
                    basis: ExerciseBasis::Holding(foreign),
                    iat: now_ms(),
                    exercise: None,
                },
            )
            .unwrap(),
            nonce,
        )
    };
    let refused = exec
        .start(Start {
            realm: String::from("acme"),
            connection: rig.connection.clone(),
            intent: intent.to_bytes().unwrap(),
            ais,
            steps: vec![rig.step("send", "send", Reversibility::Reversible, true)],
            continuations: Vec::new(),
        })
        .await
        .unwrap_err();
    assert!(
        matches!(refused, ExecError::NotAllowed(ref c) if c == "deny"),
        "{refused:?}"
    );
    assert_eq!(rig.api.seen.lock().unwrap().len(), 2);
    // INV-19, AG-40, Ek B 4280
    let (other, _) = {
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        (
            sign(
                &rig.lab.person,
                &Statement {
                    domain: rig.lab.domain,
                    nonce,
                    intent: intent_digest(&intent).unwrap(),
                    mode: Mode::Commit,
                    pep: String::from("another-pep"),
                    capacity: Capacity::Own,
                    basis: ExerciseBasis::Holding(rig.lab.holding),
                    iat: now_ms(),
                    exercise: None,
                },
            )
            .unwrap(),
            0,
        )
    };
    let refused = exec
        .start(Start {
            realm: String::from("acme"),
            connection: rig.connection.clone(),
            intent: intent.to_bytes().unwrap(),
            ais: other,
            steps: vec![rig.step("send", "send", Reversibility::Reversible, true)],
            continuations: Vec::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(refused.code(), "executor-ais");
    rig.lab.w.domains.release().await;
}

// U5, AG-40, Ek B 4277, 4481, 4498, OP-154 m.3 (u)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revoked_grant_stops_the_job_at_its_next_check_and_the_stop_is_confirmed() {
    let rig = Rig::open("executor-stop").await;
    let exec = rig.executor(Arc::clone(&rig.tokens));
    let intent = rig.lab.intent(1_200_000);
    let steps = vec![
        rig.step("one", "one", Reversibility::Reversible, false),
        rig.step("two", "two", Reversibility::Reversible, false),
    ];
    let (job, exercise) = rig.start(&exec, &intent, steps, 2).await.unwrap();
    rig.answer(200, r#"{"id":"m-1"}"#);
    loop {
        let n = exec.advance(job).await.unwrap();
        if n == Next::Attest(0) {
            break;
        }
        assert!(
            !matches!(n, Next::Done | Next::Idle | Next::Wait(_)),
            "{n:?}"
        );
    }
    revoke(&rig.lab).await;
    assert_eq!(exec.drive(job).await.unwrap(), Next::Done);
    // U5
    assert_eq!(rig.api.seen.lock().unwrap().len(), 1);
    let j = exec.job(job).await.unwrap();
    let view = access_executor::adapters::view(&j);
    assert_eq!(view["state"], "stopped");
    assert_eq!(view["confirmed"], true);
    assert_eq!(view["reason"], "decision");
    assert_eq!(j.refused.as_deref(), Some("deny"));
    let report = rig.outcome(exercise, &intent).await;
    assert_eq!(
        report["control"][0]["state"], "stopped_confirmed",
        "{report}"
    );
    assert_eq!(report["attested"].as_array().unwrap().len(), 1);
    assert_eq!(exec.stop(job).await.map(|()| 0).unwrap(), 0);
    assert_eq!(exec.drive(job).await.unwrap(), Next::Done);
    assert_eq!(rig.api.seen.lock().unwrap().len(), 1);
    rig.lab.w.domains.release().await;
}

// U5, E47 (2), (3), Ek B 4493, OP-154 m.3 (u)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_confirms_and_an_irreversible_step_waits_out_its_window() {
    let rig = Rig::open("executor-window").await;
    let exec = rig.executor(Arc::clone(&rig.tokens));
    let intent = rig.lab.intent(1_200_000);
    let (job, _) = rig
        .start(
            &exec,
            &intent,
            vec![rig.step("send", "send", Reversibility::Irreversible, false)],
            0,
        )
        .await
        .unwrap();
    let Next::Wait(until) = exec.drive(job).await.unwrap() else {
        panic!()
    };
    let view = access_executor::adapters::view(&exec.job(job).await.unwrap());
    assert_eq!(view["steps"][0]["commit_at_ms"].as_u64(), Some(until));
    assert_eq!(rig.api.seen.lock().unwrap().len(), 0);
    rig.wall.0.store(16_000, Ordering::SeqCst);
    rig.answer(200, r#"{"id":"m-2"}"#);
    assert_eq!(exec.drive(job).await.unwrap(), Next::Done);
    assert_eq!(rig.api.seen.lock().unwrap().len(), 1);

    rig.wall.0.store(0, Ordering::SeqCst);
    let (cancelled, _) = rig
        .start(
            &exec,
            &intent,
            vec![rig.step("send", "send", Reversibility::Irreversible, false)],
            0,
        )
        .await
        .unwrap();
    assert!(matches!(
        exec.drive(cancelled).await.unwrap(),
        Next::Wait(_)
    ));
    let step = exec.job(cancelled).await.unwrap().steps[0].step;
    exec.cancel(cancelled, &step.0).await.unwrap();
    rig.wall.0.store(16_000, Ordering::SeqCst);
    assert_eq!(exec.drive(cancelled).await.unwrap(), Next::Done);
    let view = access_executor::adapters::view(&exec.job(cancelled).await.unwrap());
    assert_eq!(view["state"], "stopped", "{view}");
    assert_eq!(view["confirmed"], true);
    assert_eq!(view["steps"][0]["outcome"], "not-done");
    assert_eq!(rig.api.seen.lock().unwrap().len(), 1);
    rig.lab.w.domains.release().await;
}

// TI-6, E62 (1), (3), §7.9.7.2, Ek B 4496, 4497, OP-154 m.3 (u)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crash_after_the_outbox_sends_once_more_with_the_same_key_after_a_new_decision() {
    let rig = Rig::open("executor-crash").await;
    let first = rig.executor(Arc::clone(&rig.tokens));
    let intent = rig.lab.intent(1_200_000);
    let (job, _) = rig
        .start(
            &first,
            &intent,
            vec![rig.step("send", "send", Reversibility::Reversible, true)],
            1,
        )
        .await
        .unwrap();
    rig.api.hang.store(true, Ordering::SeqCst);
    let crashed =
        tokio::time::timeout(std::time::Duration::from_millis(500), first.drive(job)).await;
    assert!(crashed.is_err());
    drop(first);
    let j = rig
        .executor(Arc::new(Tokens::default()))
        .job(job)
        .await
        .unwrap();
    assert!(j.steps[0].outbox.is_some() && j.steps[0].answered.is_none());
    assert_eq!(rig.api.seen.lock().unwrap().len(), 0);

    // TI-6
    let second = rig.executor(Arc::clone(&rig.tokens));
    second.recover(job).await.unwrap();
    assert_eq!(second.advance(job).await.unwrap(), Next::Recheck);
    rig.answer(200, r#"{"id":"m-3"}"#);
    assert_eq!(second.drive(job).await.unwrap(), Next::Done);
    let seen = rig.api.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    let j = second.job(job).await.unwrap();
    assert!(j.steps[0].resent);
    assert_eq!(
        header_of(&seen[0], "Idempotency-Key"),
        Some(b64url_encode(&j.steps[0].key.0).as_str())
    );
    assert_eq!(
        access_executor::adapters::view(&j)["steps"][0]["outcome"],
        "done"
    );

    // E62 (3)
    let (lost, _) = rig
        .start(
            &second,
            &intent,
            vec![rig.step("send", "send", Reversibility::Reversible, true)],
            1,
        )
        .await
        .unwrap();
    rig.api.hang.store(true, Ordering::SeqCst);
    let crashed =
        tokio::time::timeout(std::time::Duration::from_millis(500), second.drive(lost)).await;
    assert!(crashed.is_err());
    let restarted = rig.executor(Arc::new(Tokens::default()));
    restarted.recover(lost).await.unwrap();
    assert_eq!(restarted.drive(lost).await.unwrap(), Next::Done);
    let view = access_executor::adapters::view(&restarted.job(lost).await.unwrap());
    assert_eq!(view["state"], "unknown", "{view}");
    assert_eq!(view["steps"][0]["outcome"], "unknown");
    assert_eq!(rig.api.seen.lock().unwrap().len(), 1);
    rig.lab.w.domains.release().await;
}
