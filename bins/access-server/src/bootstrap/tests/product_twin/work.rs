//! The Work seam on the real server path (§7.9.5, E7–E9, E41, EI-4, EI-5, EI-23, PI-14,
//! OP-156 m.3 (b), (t)). The coordinator is a product twin built on the public crates alone:
//! Suiss Work, and an "Other Coordinator" a third party runs, each with its own Party, issuer
//! key and Acceptance. Each one asks who may approve a Gate, asks whether one Party is eligible
//! now, and ends commitment-scoped authority with its `commitment_active` Claim; neither starts
//! any, and nothing it asks is recorded.

use access_kernel::claim::{PREDICATE_INPUT, acceptance_digest};
use access_kernel::contribution::{ACTION as CONTRIBUTE, NAMESPACE as CONTRIBUTIONS};
use access_kernel::model::WhileCondition;
use access_sdk::authorize::{Actor as SdkActor, ExerciseRequest, adp_body};
use access_store::authority::read_head;
use serde_json::{Value as Json, json};
use suiss_crypto::dcbor::{self, Limits};
use suiss_crypto::digest::context_digest;

use super::*;

/// A coordinator's product schema: a delivery its agents make, and its commitment Claim.
const WORK: &str = r#"
product = "Coordinator"
namespace = "deliver"
catalog_version = 1
truth = ["commitment", "gate", "autonomy", "accountability"]

[[actions]]
name = "submit"
major = 1
effect_class = "reversible"
resource_types = ["deliverable"]

[[claims]]
class = "commitment_active"
value = "bytes"
use = "predicate-input"
meaning = "The subject's commitment is active; false ends authority held while it is."
"#;

/// The contribution class the coordinator's Gates need.
const GATE_CLASS: &str = "finance_approve";

/// The public routes a coordinator calls beyond the kit's own (PI-14).
const ROUTES: [&str; 3] = [
    "/access/v1/eligibility:set",
    "/access/v1/eligibility:check",
    "/access/v1/claims:ingest",
];

/// `SHA-256("access/claim-body/v1" ‖ 0x00 ‖ dCBOR(["commitment_active", body]))`, as the
/// coordinator computes it (L2-CLB-1).
fn commitment_value(commitment: &Digest, active: bool) -> (Vec<u8>, Vec<u8>) {
    let body = Value::Map(vec![
        (Value::text("active"), Value::Bool(active)),
        (Value::text("commitment"), commitment.to_value()),
    ]);
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text("commitment_active"), body.clone()]),
        Limits::CEILING,
    )
    .unwrap();
    (
        context_digest("access/claim-body/v1", &tagged).0.to_vec(),
        dcbor::encode(&body, Limits::CEILING).unwrap(),
    )
}

/// A coordinator twin in its own deployment, and its own copy of its service key: what its
/// own code signs its reads with.
struct Coordinator {
    s: Seam,
    key: SoftSigner,
    schema: Schema,
}

impl Coordinator {
    async fn open(label: &str, product: &str) -> Self {
        let (w, signer) = World::open(label, true).await;
        let signer = signer.unwrap();
        schedule(&signer);
        let (service, pkcs8) = SoftSigner::generate_ed25519().unwrap();
        let key = SoftSigner::ed25519_from_pkcs8(&pkcs8).unwrap();
        let (client, _) = SoftSigner::generate_p256().unwrap();
        let plan = Plan {
            products: vec![ProductPlan {
                product: PlatformProduct::parse(product).unwrap(),
                display_name: format!("Coordinator {product}"),
                client_key: client.public_key(),
                service_key: service.public_key(),
                event_receiver: None,
                redirect_uris: vec![
                    RedirectUri::parse(&format!("https://{product}.test/cb")).unwrap(),
                ],
            }],
            ..plan()
        };
        let summary = serde_json::to_value(w.run(&plan).await).unwrap();
        let client_id = summary["clients"][0]["client_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let audience = summary["clients"][0]["audience"]
            .as_str()
            .unwrap()
            .to_owned();
        schedule(&signer);
        let (tenant, created_realm, domain) = realm(&w, SLUG).await;
        let root = root_key(&w.keys).unwrap();
        let root_party = root_party(&root.public_key());
        let declared = DeclaredTargets::default();
        Bootstrap {
            app: &w.db.app,
            router: &w.db.router,
            plane: &w.plane,
            realm_keys: &w.keyring,
            hsm: &w.keys,
            base: &w.base,
            declared: &declared,
            console: None,
        }
        .onboard(tenant, created_realm, domain, &root, root_party)
        .await
        .unwrap();
        schedule(&signer);
        let today = server_time(&w.db.app).await.unwrap() / 86_400_000;
        for day in [today - 1, today, today + 1] {
            access_store::claims::open_claim_ingest_day(&w.db.archive, u32::try_from(day).unwrap())
                .await
                .unwrap();
        }
        let ids: Arc<crate::ids::CellIds> = Arc::new(crate::ids::CellIds::new(w.keys.clone()));
        let pools = crate::events::EventPools {
            app: w.db.app.clone(),
            reader: w.db.reader.clone(),
            router: w.db.router.clone(),
            ids: ids.clone(),
            declared: DeclaredTargets::default(),
            outbound: None,
        };
        let (platform, _) = crate::platform::routes(
            &pools,
            Outbound::disabled(Duration::from_secs(5)),
            crate::login::RealmKeks::new(w.keys.clone()),
            w.plane.clone(),
            String::from("https://access.test"),
        );
        let adp = adp_router(
            access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        );
        let ingest = crate::ingest::routes(w.domains.clone(), w.db.app.clone());
        let listener = Listener {
            public: platform.merge(adp).merge(ingest),
            seen: Arc::new(StdMutex::new(Vec::new())),
        };
        let twin = Twin::new(
            Config {
                client_id,
                audience,
                pep: String::from(TWIN_PEP),
            },
            Keys { service, client },
            (listener.clone(), Wall, Os),
        );
        let tnt =
            access_identity_events::ports::TenantIds::external(&*ids, tenant.as_bytes()).unwrap();
        let paired = twin.register(&tnt).await.unwrap();
        assert_eq!(paired.len(), 1, "{paired:?}");
        let party = paired[0].party;
        schedule(&signer);
        let s = Seam {
            w,
            signer,
            domain,
            root,
            root_party,
            listener,
            twin,
            party,
        };
        let schema = Schema::parse(WORK).unwrap();
        s.twin.publish_schema(&s.domain, &schema).await.unwrap();
        s.accept_schema(&schema).await;
        Self { s, key, schema }
    }

    async fn head(&self) -> u64 {
        read_head(&self.s.w.db.sequencer, &DomainId::from_bytes(self.s.domain.0))
            .await
            .unwrap()
            .pos
    }

    /// The root accepts the coordinator's `commitment_active` Claims as predicate inputs and
    /// returns the Acceptance digest a `claim_held` condition names.
    async fn accept_commitments(&self) -> Digest {
        let content = Value::Map(vec![
            (Value::text("issuer"), self.s.party.to_value()),
            (Value::text("use"), Value::text(PREDICATE_INPUT)),
            (
                Value::text("classes"),
                Value::Array(vec![Value::text("commitment_active")]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
            ),
        ]);
        let digest = acceptance_digest(&content);
        self.s.root(Payload::AcceptanceEstablish(content)).await;
        digest
    }

    /// The coordinator says `commitment` is (or is no longer) active for `subject`, with its
    /// body beside the Claim.
    async fn commitment(&self, subject: Id, commitment: &Digest, active: bool) -> Json {
        let (value, body) = commitment_value(commitment, active);
        let claim = self
            .s
            .twin
            .sign_claim(
                &self.s.domain,
                Issue {
                    subject,
                    class: String::from("commitment_active"),
                    value: Some(EqValue::Bytes(value)),
                    for_ms: 3_600_000,
                    resource: None,
                },
            )
            .unwrap();
        let answer = self
            .post(
                ROUTES[2],
                json!({
                    "domain": format!("sha-256:{}", b64url_encode(&self.s.domain.0)),
                    "carrier": "cose",
                    "claim": b64url_encode(&claim),
                    "body": b64url_encode(&body),
                }),
            )
            .await;
        assert_eq!(answer["disposition"], "admit", "{answer}");
        schedule(&self.s.signer);
        answer
    }

    async fn post(&self, path: &str, body: Json) -> Json {
        assert!(ROUTES.contains(&path));
        let key = b64url_encode(&access_crypto::random::bytes::<16>().unwrap());
        let mut req = HttpRequestOf::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, "access.test")
            .header(header::CONTENT_TYPE, "application/json")
            .header("idempotency-key", key)
            .body(Body::from(body.to_string()))
            .unwrap();
        req.extensions_mut().insert(PepId(String::from(TWIN_PEP)));
        let r = self.s.listener.public.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let bytes = to_bytes(r.into_body(), 1 << 22).await.unwrap();
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&bytes));
        serde_json::from_slice(&bytes).unwrap()
    }

    /// The coordinator's own signed `check` context over `envelope` on `basis`.
    fn context(&self, envelope: &IntentEnvelope, basis: ExerciseBasis) -> Json {
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let digest = intent_digest(envelope).unwrap();
        let ais = Seam::ais(
            &self.key,
            &Statement {
                domain: self.s.domain,
                nonce: nonce.clone(),
                intent: digest,
                mode: Mode::Check,
                pep: String::from(TWIN_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now_ms(),
                exercise: None,
            },
        );
        let body = adp_body(&ExerciseRequest {
            domain: &self.s.domain,
            mode: Mode::Check,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(envelope),
            actor: &SdkActor::Statement(ais),
            basis: &basis,
            capacity: Capacity::Own,
            pep: TWIN_PEP,
            exercise: None,
        })
        .unwrap();
        serde_json::from_str::<Json>(&body).unwrap()["context"].clone()
    }

    /// `eligibility:set` for a Gate of `class` on `basis`: the Parties and `truncated`.
    async fn eligible_set(&self, class: &str, basis: ExerciseBasis) -> (Vec<Id>, bool) {
        let search = IntentEnvelope {
            provenance: BTreeMap::new(),
            action: meta::core_action("read"),
            resources: vec![ResourceRef {
                namespace: String::from("access.search"),
                path: vec![String::from("eligible-set")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: window(),
        };
        let mut context = self.context(&search, basis);
        context["query"] = json!({
            "gate_class": class,
            "resource": "deliver.deliverable:po-1182",
            "digest": b64url_encode(&[0x5a; 32]),
        });
        let answer = self.post(ROUTES[0], json!({ "context": context })).await;
        assert_eq!(answer["context"]["recorded"], false);
        let parties = answer["parties"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                Id(<[u8; 16]>::try_from(
                    access_kernel::json::b64url_decode(p.as_str().unwrap()).unwrap(),
                )
                .unwrap())
            })
            .collect();
        (parties, answer["truncated"].as_bool().unwrap())
    }

    /// `eligibility:check`: whether `who` may contribute `class` to `gate` now on `basis`.
    async fn eligible(&self, who: Id, class: &str, gate: Digest, basis: ExerciseBasis) -> bool {
        let intent =
            access_kernel::contribution::contribute_intent(gate, class, window()).unwrap();
        let digest = intent_digest(&intent).unwrap();
        let body = adp_body(&ExerciseRequest {
            domain: &self.s.domain,
            mode: Mode::Check,
            nonce: &[0; 16],
            intent: &digest,
            envelope: Some(&intent),
            actor: &SdkActor::Anonymous,
            basis: &basis,
            capacity: Capacity::Own,
            pep: TWIN_PEP,
            exercise: None,
        })
        .unwrap();
        let context = serde_json::from_str::<Json>(&body).unwrap()["context"].clone();
        let mut set = serde_json::Map::new();
        for k in ["domain", "intent", "basis", "capacity"] {
            set.insert(String::from(k), context[k].clone());
        }
        let answer = self
            .post(
                ROUTES[1],
                json!({ "subject": b64url_encode(&who.0), "set": Json::Object(set) }),
            )
            .await;
        answer["eligible"].as_bool().unwrap()
    }

    /// The root's Grant to `holder` to contribute `class`, valid over `validity`.
    async fn approver(&self, holder: SubjectSelector, class: &str, validity: Window) -> (Id, u64) {
        let mut authority = canonical(
            &[meta::core_action(CONTRIBUTE)],
            structural(CONTRIBUTIONS, &[class]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        authority.constraints.validity = validity;
        self.s.grant(holder, authority).await
    }

    /// `principal`'s commit of `payload` on its own self-anchor, its intent naming
    /// `commitment` as context (§7.9.5.1): the Exercise, its position, or the refusal.
    async fn scoped_commit(
        &self,
        principal: &Actor,
        payload: Payload,
        commitment: Option<Digest>,
    ) -> Result<(Digest, u64), Verdict> {
        let now = server_time(&self.s.w.db.app).await.unwrap();
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let mut intent = self_signed_intent(&payload, principal.party, validity).unwrap();
        intent.context.commitment = commitment;
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let basis = ExerciseBasis::Anchor(principal.anchor);
        let ais = Seam::ais(
            &principal.key,
            &Statement {
                domain: self.s.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now,
                exercise: None,
            },
        );
        MetaExercises::lead(&self.s.w.plane, self.s.domain)
            .await
            .unwrap();
        let verdict = MetaExercises::meta(
            &self.s.w.plane,
            Request {
                domain: self.s.domain,
                mode: Mode::Commit,
                nonce,
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
        schedule(&self.s.signer);
        match verdict {
            Verdict::Committed(c) => Ok((c.exercise, c.position)),
            other => Err(other),
        }
    }

    /// The agent's `deliver:submit` on `principal`'s deliverable, through the coordinator as
    /// its PEP.
    async fn submit(
        &self,
        agent: &Actor,
        principal: &Actor,
        basis: ExerciseBasis,
    ) -> Result<access_sdk::authorize::Authorized<(), ()>, Denied> {
        self.submit_of(agent, principal, basis).await.0
    }

    async fn submit_of(
        &self,
        agent: &Actor,
        principal: &Actor,
        basis: ExerciseBasis,
    ) -> (
        Result<access_sdk::authorize::Authorized<(), ()>, Denied>,
        IntentEnvelope,
    ) {
        let submit = self.schema.action("submit").unwrap();
        let envelope = envelope(
            submit,
            ("access.party", &[&hex(&principal.party), "po-1182"]),
            BTreeMap::new(),
        );
        let r = self
            .s
            .twin
            .ask(
                &self.s.domain,
                &self.s.request(agent, envelope.clone(), basis, Vec::new()),
            )
            .await;
        (r, envelope)
    }

    fn scoped(&self, principal: &Actor, agent: &Actor, acceptance: Digest) -> GrantContent {
        let submit = self.schema.action("submit").unwrap();
        let mut authority = canonical(
            std::slice::from_ref(&submit),
            structural("access.party", &[&hex(&principal.party)]),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        authority.constraints.conditions = BTreeSet::from([WhileCondition::ClaimHeld {
            class: String::from("commitment_active"),
            subject: SubjectSelector::Party(agent.party),
            acceptance,
        }]);
        GrantContent {
            basis: GrantBasis::Anchor(principal.anchor),
            holder: SubjectSelector::Party(agent.party),
            authority,
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        }
    }

    /// PI-14: every call went to a public route, as the coordinator itself.
    fn only_public(&self) {
        self.s.only_public();
        let contract: Json = serde_json::from_str(
            &std::fs::read_to_string(
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sdks/openapi/access-v1.json"),
            )
            .unwrap(),
        )
        .unwrap();
        for route in ROUTES {
            assert!(contract["paths"].get(route).is_some(), "{route}");
        }
    }
}

fn digest() -> Digest {
    Digest(access_crypto::random::bytes::<32>().unwrap())
}

/// EI-5, EI-23, E8, E14 for coordinator `product`.
async fn commitment_scoped(label: &str, product: &str) {
    let c = Coordinator::open(label, product).await;
    let acceptance = c.accept_commitments().await;
    let principal = c.s.actor().await;
    let agent = c.s.actor().await;
    let commitment = digest();
    let held = |exercise: Digest, since: u64| {
        holding(meta::object_id(&exercise, kind::GRANT, 0), agent.party, since)
    };

    // EI-5
    let missing = c
        .scoped_commit(
            &principal,
            Payload::GrantIssue(c.scoped(&principal, &agent, acceptance)),
            None,
        )
        .await;
    assert!(missing.is_err(), "{missing:?}");
    let (exercise, since) = c
        .scoped_commit(
            &principal,
            Payload::GrantIssue(c.scoped(&principal, &agent, acceptance)),
            Some(commitment),
        )
        .await
        .unwrap();
    let basis = held(exercise, since);

    // EI-23
    let r = c.submit(&agent, &principal, basis).await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");

    let other = digest();
    c.commitment(agent.party, &other, true).await;
    let r = c.submit(&agent, &principal, basis).await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");

    // §7.9.5.4
    c.commitment(agent.party, &commitment, true).await;
    let (allowed, delivery) = c.submit_of(&agent, &principal, basis).await;
    let mut delivered = Vec::new();
    ProductTwin::enforce(allowed.unwrap(), &delivery, || delivered.push("po-1182")).unwrap();
    assert_eq!(delivered, ["po-1182"]);

    // EI-23
    let stranger = c.s.actor().await;
    c.commitment(stranger.party, &digest(), true).await;
    let r = c.submit(&stranger, &principal, basis).await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");

    // E14
    let mut amended = c.scoped(&principal, &agent, acceptance);
    amended.authority.constraints.conditions.clear();
    let freed = c
        .scoped_commit(
            &principal,
            Payload::GrantAmend {
                grant: meta::object_id(&exercise, kind::GRANT, 0),
                authority: amended.authority,
                agency: amended.agency,
                named: None,
            },
            Some(commitment),
        )
        .await;
    assert!(freed.is_err(), "{freed:?}");

    // EI-5
    let before = c.head().await;
    let ended = c.commitment(agent.party, &commitment, false).await;
    assert!(c.head().await > before);
    let r = c.submit(&agent, &principal, basis).await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");
    c.commitment(agent.party, &commitment, true).await;
    let r = c.submit(&agent, &principal, basis).await;
    assert!(matches!(r, Err(Denied::Refused(_))), "{r:?}");
    let kept = access_store::commitments::termination(
        &c.s.w.db.app,
        &DomainId::from_bytes(c.s.domain.0),
        &commitment.0,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(kept.issuer, c.s.party.0);
    assert_eq!(kept.subject, agent.party.0);
    assert_eq!(
        kept.pos,
        ended["position"].as_str().unwrap().parse::<u64>().unwrap()
    );

    // EI-5
    let to_itself = c
        .s
        .twin
        .attempt(
            &c.s.domain,
            &Payload::GrantIssue(c.scoped(&principal, &agent, acceptance)),
            ExerciseBasis::Anchor(principal.anchor),
        )
        .await
        .unwrap();
    assert!(!to_itself.took_effect(), "{to_itself:?}");
    c.only_public();
}

/// E41, E26, §7.9.5.3 for coordinator `product`.
async fn eligible_set(label: &str, product: &str) {
    let c = Coordinator::open(label, product).await;
    let open = Window {
        from: 0,
        until: u64::MAX,
    };
    let first = c.s.actor().await;
    let second = c.s.actor().await;
    let other_class = c.s.actor().await;
    let (first_grant, first_since) = c
        .approver(SubjectSelector::Party(first.party), GATE_CLASS, open)
        .await;
    c.approver(SubjectSelector::Party(second.party), GATE_CLASS, open)
        .await;
    c.approver(pred("finance_team", EqValue::Bool(true)), GATE_CLASS, open)
        .await;
    c.approver(SubjectSelector::Party(other_class.party), "legal_approve", open)
        .await;
    let meta_anchor = ExerciseBasis::Anchor(meta::meta_anchor(&c.s.domain));

    // E26
    let before = c.head().await;
    assert_eq!(c.eligible_set(GATE_CLASS, meta_anchor).await, (Vec::new(), false));
    let (read, since) = c
        .s
        .grant(
            SubjectSelector::Party(c.s.party),
            canonical(
                &[meta::core_action("read")],
                structural("access.search", &["eligible-set"]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let reader = holding(read, c.s.party, since);
    assert!(c.s.w.domains.derive().await.is_empty());
    let at = c.head().await;
    let (parties, truncated) = c.eligible_set(GATE_CLASS, reader).await;
    let mut want = vec![first.party, second.party];
    want.sort();
    assert_eq!(parties, want);
    assert!(!truncated);
    assert_eq!(c.head().await, at);
    assert!(at > before);

    // E41 (2)
    let gate = digest();
    let at = c.head().await;
    assert!(
        c.eligible(
            first.party,
            GATE_CLASS,
            gate,
            holding(first_grant, first.party, first_since)
        )
        .await
    );
    assert!(
        !c.eligible(
            other_class.party,
            GATE_CLASS,
            gate,
            holding(first_grant, other_class.party, first_since)
        )
        .await
    );
    assert_eq!(c.head().await, at);

    // INV-5
    c.s.root(Payload::GrantRevoke { grant: first_grant }).await;
    assert!(c.s.w.domains.derive().await.is_empty());
    let (parties, _) = c.eligible_set(GATE_CLASS, reader).await;
    assert_eq!(parties, vec![second.party]);
    c.only_public();
}

// EI-5, EI-23, E8, E14, §7.9.5.4, §8.17.7.2, OP-156 m.3 (b), (t), Ek B 5175, 5252, 5260
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn work_ends_authority_with_its_commitment_and_never_starts_any() {
    commitment_scoped("q16-commitment", "work").await;
}

// E41, E26, §7.9.5.3, §8.17.6.1, OP-156 m.3 (t), Ek B 5223, 5252, 5258
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn work_asks_who_may_approve_and_nothing_is_recorded() {
    eligible_set("q16-eligible", "work").await;
}

// PI-14, E24, IA-7, X5, §7.9.5.8, OP-156 m.3 (t), Ek B 5255
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_coordinator_ends_authority_the_same_way() {
    commitment_scoped("q16-other-commit", "other-coordinator").await;
}

// PI-14, E24, IA-7, X5, §7.9.5.8, OP-156 m.3 (t), Ek B 5255
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_coordinator_asks_the_same_way() {
    eligible_set("q16-other-elig", "other-coordinator").await;
}
