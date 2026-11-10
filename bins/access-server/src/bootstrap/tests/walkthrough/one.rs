//! One's cloud key permission on the real server (OP-156 m.3 (w), E59, E46, OP-78, OP-153 m.3
//! (gg)): the realm root accepts One's `one` and `one.cloud_key` schemas and gives P the cloud
//! key actions; One binds the Mandate that covers its work while P is away; P's device Instance
//! grants the permission with its own signed Exercise through the account surface, on the real
//! router, sequencer, store and `SoftHSM`. The record holds no key or data, lasts at most a day,
//! ends with its Mandate or a tap, and every end tells the TEE to destroy its copies.

use std::collections::BTreeMap;

use access_kernel::combinator::Origins;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::meta::MandateEnvelope;
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, EqValue, ResourceRef,
    ResourceSelector, Structural,
};
use access_kernel::verify::key_scope::thumbprint;
use access_local_client::login::{Jar, post_json};
use access_product_twin::Schema;
use serde_json::{Value as JsonValue, json};
use suiss_crypto::dcbor::Value;
use suiss_crypto::signer::{Signer, sign_sign1};

use super::*;

const DAY: u64 = 86_400_000;

fn schema(name: &str) -> Schema {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/seams/schemas")
        .join(format!("{name}.toml"));
    Schema::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn data(person: Id) -> ResourceRef {
    ResourceRef {
        namespace: String::from("one.data"),
        path: vec![b64url_encode(&person.0)],
        incarnation: 0,
    }
}

fn over(actions: &[ActionRef], validity: Window) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: actions.iter().cloned().collect(),
                prefix: BTreeSet::new(),
            },
            resource: ResourceSelector::Structural(Structural {
                namespace: String::from("one.data"),
                prefix: Vec::new(),
                kind: None,
                attrs: BTreeMap::new(),
            }),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity,
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms::default(),
        requirements: BTreeSet::new(),
    }
}

fn hex_of(id: &Id) -> String {
    id.0.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    })
}

fn sign_ais<S: Signer>(key: &S, s: &Statement) -> Vec<u8> {
    sign_sign1(
        key,
        thumbprint(&key.public_key()),
        CONTENT_TYPE,
        &s.to_bytes().unwrap(),
    )
    .unwrap()
}

/// The root's commit of `payload` on the meta-anchor; a CT3 Exercise is sent again with the
/// same nonce once its time-lock has passed (SEC26).
async fn root_accept(d: &Desk, payload: Payload) {
    let root = root_key(&d.w.keys).unwrap();
    let now = server_time(&d.w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, AGENT, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&d.domain));
    let ais = sign_ais(
        &root,
        &Statement {
            domain: d.domain,
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
    let request = Request {
        domain: d.domain,
        mode: Mode::Commit,
        nonce,
        intent,
        payload: Some(payload),
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    };
    for attempt in 0..2 {
        MetaExercises::lead(&d.w.plane, d.domain).await.unwrap();
        let v = Box::pin(MetaExercises::meta(
            &d.w.plane,
            request.clone(),
            ais.clone(),
            String::from(IDENTITY_PEP),
        ))
        .await
        .unwrap();
        match v {
            Verdict::Committed(_) => return,
            other if attempt == 0 => {
                assert!(format!("{other:?}").contains("time-lock"), "{other:?}");
                access_store::testing::age_authority(&d.w.db, d.domain.0, 25 * 3_600_000)
                    .await
                    .unwrap();
            }
            other => panic!("{other:?}"),
        }
    }
}

struct Lab {
    d: Desk,
    grant: ActionRef,
    revoke: ActionRef,
    work: ActionRef,
    held: HoldingRef,
}

impl Lab {
    async fn open(name: &str) -> Self {
        let d = Box::pin(Desk::open(name, false)).await;
        let one = schema("one");
        let keys = schema("one.cloud_key");
        for s in [&one, &keys] {
            let accept = Payload::AcceptanceEstablish(Value::Map(vec![
                (Value::text("issuer"), AGENT.to_value()),
                (Value::text("use"), Value::text("schema-definition")),
                (
                    Value::text("classes"),
                    Value::Array(vec![Value::text("action_schema")]),
                ),
                (Value::text("subject"), SubjectSelector::Public.to_value()),
                (
                    Value::text("validity"),
                    Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
                ),
                (Value::text("spp"), s.spp(AGENT).unwrap().to_value()),
            ]));
            Box::pin(root_accept(&d, accept)).await;
        }
        let grant = keys.action("grant").unwrap();
        let revoke = keys.action("revoke").unwrap();
        let work = one.action("consolidate").unwrap();
        let held = Box::pin(root_grant(
            &d.w,
            d.domain,
            GrantContent {
                basis: GrantBasis::Anchor(meta::meta_anchor(&d.domain)),
                holder: SubjectSelector::Party(d.person),
                authority: over(
                    &[grant.clone(), revoke.clone()],
                    Window {
                        from: 0,
                        until: u64::MAX,
                    },
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            },
        ))
        .await;
        Self {
            d,
            grant,
            revoke,
            work,
            held,
        }
    }

    async fn now(&self) -> u64 {
        server_time(&self.d.w.db.app).await.unwrap()
    }

    /// One's own `payload` on its Instance, signed with its runtime key under the meta-anchor.
    async fn one_commit(&self, payload: Payload) -> Digest {
        let now = self.now().await;
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, AGENT, validity).unwrap();
        let nonce = nonce();
        let basis = ExerciseBasis::Anchor(meta::meta_anchor(&self.d.domain));
        let ais = sign_ais(
            &self.d.runtime.0,
            &Statement {
                domain: self.d.domain,
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
        MetaExercises::lead(&self.d.w.plane, self.d.domain)
            .await
            .unwrap();
        let verdict = Box::pin(MetaExercises::meta(
            &self.d.w.plane,
            Request {
                domain: self.d.domain,
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
        ))
        .await
        .unwrap();
        let Verdict::Committed(c) = verdict else {
            panic!("{verdict:?}");
        };
        c.exercise
    }

    /// One binds a Mandate covering `actions` on its own Party's resources, and ending itself, for
    /// two days on its Instance (E46).
    async fn mandate(&self, actions: &[ActionRef]) -> Id {
        let now = self.now().await;
        let mut actions = actions.to_vec();
        actions.push(meta::core_action("mandate_revoke"));
        let mut authority = over(
            &actions,
            Window {
                from: now - 60_000,
                until: now + 2 * DAY,
            },
        );
        authority.authority.resource = ResourceSelector::Structural(Structural {
            namespace: String::from(access_internal_api::instances::PARTY_NAMESPACE),
            prefix: vec![hex_of(&AGENT)],
            kind: None,
            attrs: BTreeMap::new(),
        });
        let exercise = self
            .one_commit(Payload::MandateBind {
                instance: self.d.instance,
                envelope: MandateEnvelope {
                    authority: authority.authority,
                    constraints: authority.constraints,
                    requirements: BTreeSet::new(),
                    pin: None,
                    origins: Origins::default(),
                },
            })
            .await;
        meta::object_id(&exercise, kind::MANDATE, 0)
    }

    async fn intent(
        &self,
        action: &ActionRef,
        params: BTreeMap<String, ParamValue>,
    ) -> IntentEnvelope {
        let now = self.now().await;
        IntentEnvelope {
            provenance: BTreeMap::new(),
            action: action.clone(),
            resources: vec![data(self.d.person)],
            params,
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: now - 60_000,
                until: now + 600_000,
            },
        }
    }

    async fn terms(&self, purpose: &str, (now, until): (u64, u64), mandate: Id) -> IntentEnvelope {
        let bytes = |b: Vec<u8>| ParamValue::Eq(EqValue::Bytes(b));
        let text = |t: &str| ParamValue::Eq(EqValue::Text(String::from(t)));
        self.intent(
            &self.grant,
            BTreeMap::from([
                (String::from("purpose"), text(purpose)),
                (String::from("classes"), text("one_memory,one_model")),
                (
                    String::from("window"),
                    ParamValue::Interval(Window { from: now, until }),
                ),
                (
                    String::from("tee_measurement"),
                    bytes(access_crypto::random::bytes::<32>().unwrap().to_vec()),
                ),
                (
                    String::from("job_key"),
                    bytes(access_crypto::random::bytes::<32>().unwrap().to_vec()),
                ),
                (String::from("mandate"), bytes(mandate.0.to_vec())),
            ]),
        )
        .await
    }

    /// P's device Instance's signed Exercise of `envelope`, as the route carries it.
    async fn signed(&self, envelope: &IntentEnvelope) -> JsonValue {
        let device = self.d.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let nonce = nonce();
        let ais = sign_ais(
            &device,
            &Statement {
                domain: self.d.domain,
                nonce: nonce.clone(),
                intent: intent_digest(envelope).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis: ExerciseBasis::Holding(self.held),
                iat: self.now().await,
                exercise: None,
            },
        );
        json!({
            "nonce": b64url_encode(&nonce),
            "intent": b64url_encode(&envelope.to_bytes().unwrap()),
            "basis": {
                "grant": b64url_encode(&self.held.grant.0),
                "holder": b64url_encode(&self.held.holder.0),
                "since": self.held.since,
            },
            "ais": b64url_encode(&ais),
        })
    }

    async fn post(&self, jar: &mut Jar, path: &str, body: Option<JsonValue>) -> (u16, JsonValue) {
        let r = post_json(
            &self.d.http,
            &format!("{}{path}", self.d.user.issuer),
            jar,
            body,
        )
        .await
        .unwrap();
        let v = serde_json::from_slice(&r.body).unwrap_or(JsonValue::Null);
        (r.status, v)
    }

    async fn list(&self, jar: &Jar) -> Vec<JsonValue> {
        let cookie = jar.header();
        let r = self
            .d
            .http
            .request(
                "GET",
                &format!("{}/v1/me/cloud-key-permissions", self.d.user.issuer),
                &[("Cookie", cookie.as_str())],
                None,
            )
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        let v: JsonValue = serde_json::from_slice(&r.body).unwrap();
        v["permissions"].as_array().unwrap().clone()
    }

    async fn audited(&self, event: &str) -> usize {
        let route = route_by_slug(&self.d.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let mut t = TenantTx::begin(&self.d.w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let rows = t.audit_page(None, 10_000).await.unwrap();
        t.commit().await.unwrap();
        rows.iter().filter(|r| r.event_type == event).count()
    }
}

fn find<'a>(rows: &'a [JsonValue], id: &JsonValue) -> &'a JsonValue {
    rows.iter().find(|r| r["id"] == *id).unwrap()
}

// OP-156 m.3 (w), E59, E46, OP-78, Ek B 4552, 4553, 4631
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cloud_key_permission_is_the_devices_exercise_and_ends_with_its_mandate() {
    Box::pin(cloud_key_walk()).await;
}

async fn cloud_key_walk() {
    let l = Box::pin(Lab::open("q20-cloud-key")).await;
    let mut jar = l.d.person().await;
    let mandate = l.mandate(std::slice::from_ref(&l.work)).await;
    let now = l.now().await;
    let path = "/v1/me/cloud-key-permissions";

    // E59, OP-156 m.3 (w)
    let long = l.terms("consolidate", (now, now + DAY + 1), mandate).await;
    let body = l.signed(&long).await;
    let (status, v) = Box::pin(l.post(&mut jar, path, Some(body))).await;
    assert_eq!(status, 400, "{v}");
    assert_eq!(v["code"], "cloud-key-window");

    // E46
    let other = l.terms("message", (now, now + DAY), mandate).await;
    let (status, v) = l.post(&mut jar, path, Some(l.signed(&other).await)).await;
    assert_eq!(status, 409, "{v}");
    assert_eq!(v["code"], "cloud-key-mandate");

    // E59 (2)
    let terms = l.terms("consolidate", (now, now + DAY), mandate).await;
    let (status, made) = l.post(&mut jar, path, Some(l.signed(&terms).await)).await;
    assert_eq!(status, 201, "{made}");
    assert_eq!(made["state"], "live");
    assert_eq!(made["classes"], json!(["one_memory", "one_model"]));
    let rows = l.list(&jar).await;
    let row = find(&rows, &made["id"]);
    assert_eq!(row["state"], "live", "{row}");
    assert_eq!(row["destroy"], false);
    assert_eq!(l.audited("cloud_key.granted").await, 1);

    // §13.4 G54
    let forged = {
        let mut s = l.signed(&terms).await;
        let other = suiss_crypto::signer::SoftSigner::generate_p256().unwrap().0;
        let ais = sign_ais(
            &other,
            &Statement {
                domain: l.d.domain,
                nonce: nonce(),
                intent: intent_digest(&terms).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis: ExerciseBasis::Holding(l.held),
                iat: now,
                exercise: None,
            },
        );
        s["ais"] = json!(b64url_encode(&ais));
        s
    };
    let (status, v) = l.post(&mut jar, path, Some(forged)).await;
    assert_eq!(status, 403, "{v}");

    // E59
    let first = l.terms("consolidate", (now, now + DAY), mandate).await;
    let (_, one) = l.post(&mut jar, path, Some(l.signed(&first).await)).await;
    let second = l.terms("consolidate", (now, now + DAY), mandate).await;
    let (_, two) = l.post(&mut jar, path, Some(l.signed(&second).await)).await;
    let (status, v) = l
        .post(
            &mut jar,
            &format!("{path}/{}/revoke", one["id"].as_str().unwrap()),
            None,
        )
        .await;
    assert_eq!(status, 204, "{v}");
    let id = kit_id(&l, &two).await;
    let revoke = l
        .intent(
            &l.revoke,
            BTreeMap::from([(
                String::from("permission"),
                ParamValue::Eq(EqValue::Bytes(id.to_vec())),
            )]),
        )
        .await;
    let (status, v) = l
        .post(
            &mut jar,
            &format!("{path}/{}/revoke", two["id"].as_str().unwrap()),
            Some(l.signed(&revoke).await),
        )
        .await;
    assert_eq!(status, 204, "{v}");
    let rows = l.list(&jar).await;
    for made in [&one, &two] {
        let row = find(&rows, &made["id"]);
        assert_eq!(row["state"], "revoked", "{row}");
        assert_eq!(row["destroy"], true);
    }
    assert_eq!(l.audited("cloud_key.revoked").await, 2);

    // E59, E46
    l.one_commit(Payload::MandateRevoke { mandate }).await;
    let rows = l.list(&jar).await;
    let row = find(&rows, &made["id"]);
    assert_eq!(row["state"], "mandate_ended", "{row}");
    assert_eq!(row["destroy"], true);

    l.d.close().await;
}

/// The raw id of the permission `made` names, read back from the store.
async fn kit_id(l: &Lab, made: &JsonValue) -> [u8; 16] {
    let route = route_by_slug(&l.d.w.db.router, "acme")
        .await
        .unwrap()
        .unwrap();
    let mut t = TenantTx::begin(&l.d.w.db.app, route.tenant, route.realm)
        .await
        .unwrap();
    let rows = t.cloud_keys(l.d.subject, 0, 50).await.unwrap();
    t.commit().await.unwrap();
    let exercise = access_kernel::json::b64url_decode(made["exercise"].as_str().unwrap()).unwrap();
    rows.into_iter()
        .find(|r| r.grant.exercise.as_slice() == exercise.as_slice())
        .unwrap()
        .id
}

/// What the hosts of handles people own answer at `/.well-known/access-handle` (E56).
#[derive(Clone, Default)]
pub(super) struct Hosts(Arc<std::sync::Mutex<BTreeMap<String, Vec<u8>>>>);

impl access_identity_ui::ports::HandleHosts for Hosts {
    fn well_known(
        &self,
        handle: &str,
    ) -> impl std::future::Future<Output = Option<Vec<u8>>> + Send {
        std::future::ready(self.0.lock().unwrap().get(handle).cloned())
    }
}

impl Desk {
    async fn me(&self, jar: &mut Jar, path: &str, body: Option<JsonValue>) -> (u16, JsonValue) {
        let r = post_json(
            &self.http,
            &format!("{}{path}", self.user.issuer),
            jar,
            body,
        )
        .await
        .unwrap();
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(JsonValue::Null),
        )
    }

    async fn get_json(&self, jar: &Jar, path: &str) -> (u16, JsonValue) {
        let cookie = jar.header();
        let r = self
            .http
            .request(
                "GET",
                &format!("{}{path}", self.user.issuer),
                &[("Cookie", cookie.as_str())],
                None,
            )
            .await
            .unwrap();
        (
            r.status,
            serde_json::from_slice(&r.body).unwrap_or(JsonValue::Null),
        )
    }

    /// `GET /.well-known/access-handle` with `host` as the request's host, on the real router.
    async fn handle_host(&self, host: &str) -> (u16, String) {
        use tower::ServiceExt as _;
        let router = access_http::login::handle_well_known_router(
            access_identity_ui::app::handle::RouterHandles(self.w.db.router.clone()),
        );
        let req = axum::http::Request::builder()
            .uri("/.well-known/access-handle")
            .header(axum::http::header::HOST, host)
            .body(axum::body::Body::empty())
            .unwrap();
        let r = router.oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let body = axum::body::to_bytes(r.into_body(), 4096).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }
}

// E56, OP-156 m.4 Q20, Ek B 4330
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handle_is_shown_only_once_both_directions_agree() {
    Box::pin(handle_walk()).await;
}

async fn handle_walk() {
    use access_identity_ui::app::handle::suiss_base;
    let d = Box::pin(Desk::open("q20-handles", false)).await;
    let mut jar = d.person().await;
    let base = suiss_base(&d.user.issuer).unwrap();
    let path = "/v1/me/handles";
    let did_path = format!("/u/{}/did.json", b64url_encode(&d.person.0));

    // E56 (2)
    let suiss = format!("ada.{base}");
    let (status, made) = d.me(&mut jar, path, Some(json!({ "handle": suiss }))).await;
    assert_eq!(status, 201, "{made}");
    assert_eq!(made["state"], "verified");
    let did = made["did"].as_str().unwrap().to_owned();
    assert_eq!(d.handle_host(&suiss).await, (200, did.clone()));
    assert_eq!(d.handle_host(&format!("eve.{base}")).await.0, 404);

    // E56 (2)
    let own = String::from("ada.example.org");
    let (status, pending) = d.me(&mut jar, path, Some(json!({ "handle": own }))).await;
    assert_eq!(status, 201, "{pending}");
    assert_eq!(pending["state"], "pending");
    assert_eq!(pending["shown"], false);
    let verify = format!("{path}/{}/verify", pending["id"].as_str().unwrap());
    let (status, v) = d.me(&mut jar, &verify, None).await;
    assert_eq!(status, 409, "{v}");
    d.handle_hosts
        .0
        .lock()
        .unwrap()
        .insert(own.clone(), b"did:web:someone.else:u:x".to_vec());
    let (status, _) = d.me(&mut jar, &verify, None).await;
    assert_eq!(status, 409);
    let (_, doc) = d.get_json(&jar, &did_path).await;
    let aka = doc["alsoKnownAs"].as_array().unwrap().clone();
    assert_eq!(aka, [json!(format!("https://{suiss}"))], "{doc}");
    d.handle_hosts
        .0
        .lock()
        .unwrap()
        .insert(own.clone(), format!("{did}\n").into_bytes());
    let (status, v) = d.me(&mut jar, &verify, None).await;
    assert_eq!(status, 200, "{v}");
    let (_, doc) = d.get_json(&jar, &did_path).await;
    assert_eq!(doc["alsoKnownAs"].as_array().unwrap().len(), 2, "{doc}");
    assert_eq!(d.handle_host(&own).await.0, 404);

    // E56
    let (_, list) = d.get_json(&jar, path).await;
    let id = list["handles"][0]["id"].as_str().unwrap().to_owned();
    let (status, _) = d.me(&mut jar, &format!("{path}/{id}/retire"), None).await;
    assert_eq!(status, 204);
    assert_eq!(d.handle_host(&suiss).await.0, 404);
    let (status, again) = d.me(&mut jar, path, Some(json!({ "handle": suiss }))).await;
    assert_eq!(status, 409, "{again}");
    let (status, bad) = d
        .me(
            &mut jar,
            path,
            Some(json!({ "handle": format!("a.b.{base}") })),
        )
        .await;
    assert_eq!(status, 400, "{bad}");
    let (_, doc) = d.get_json(&jar, &did_path).await;
    assert_eq!(
        doc["alsoKnownAs"],
        json!(["https://ada.example.org"]),
        "{doc}"
    );
    d.close().await;
}
