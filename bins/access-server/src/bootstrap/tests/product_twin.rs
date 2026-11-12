//! The Generic Domain Product contract on the real server path (§7.9.10.3, E16, E24, PI-14,
//! OP-156 m.2 Q1, OP-153 m.3 (gg)). Each product is a twin of `access-product-twin`, built on the
//! public crates alone: it pairs as a platform product and so registers its own Party and
//! Instance key, publishes its action namespace, issues its Claims through Claim Ingest and asks
//! Access as its own PEP, all over the public routes on the real sequencer, store and `SoftHSM`.
//! The domain's root accepts, or not, with its own Exercises; the product never writes an
//! Anchor, a Grant or an Acceptance.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use access_http::adp::adapters::{Discovery, Pep as PepId, router as adp_router};
use access_identity_oauth::adapters::outbound::Outbound;
use access_internal_api::instances::{
    Registrant, Registration, RegistrationVerdict, SelfSigned, register_nonce, self_signed_intent,
};
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::model::{Bound, BudgetDimension, BudgetTerm, BudgetWindow, Conjunct, EqValue};
use access_product_twin::twin::Random as TwinRandom;
use access_product_twin::{Call, Config, Issue, Keys, Proof, Schema, Twin, Wire};
use access_sdk::authorize::{Denied, Refusal};
use access_sdk::transport::{Answer, Response as Answered};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequestOf, header};
use suiss_crypto::dcbor::Value;
use suiss_crypto::signer::SoftSigner;
use tower::ServiceExt as _;

use super::*;

mod breakglass;
mod critical_interrupt;
mod discovery;
mod governance;
mod one;

/// The PEP name the twin's client certificate authenticates as (L1-ADP-2).
const TWIN_PEP: &str = "cHJvZHVjdC10d2luLWNlcnRpZmljYXRlLXRodW1icHJpbnQ";

/// The realm the twins pair with; its CT3 time-lock is zero so the root's Acceptances apply
/// at once.
const SLUG: &str = "seams";

/// Access's public listener as the twin's client certificate reaches it: the platform, ADP and
/// Claim Ingest routes, and every call it was sent.
#[derive(Clone)]
struct Listener {
    public: axum::Router,
    seen: Arc<StdMutex<Vec<Call>>>,
}

impl Listener {
    async fn raw(&self, method: &str, path: &str, body: Vec<u8>) -> Answer {
        let mut req = HttpRequestOf::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, "access.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(PepId(String::from(TWIN_PEP)));
        let r = self.public.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
        Answer::Response(Answered::new(status, body))
    }
}

impl Wire for Listener {
    async fn send(&self, call: Call) -> Answer {
        self.seen.lock().unwrap().push(call.clone());
        let mut req = HttpRequestOf::builder()
            .method(call.method.name())
            .uri(&call.path)
            .header(header::HOST, "access.test")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(b) = &call.bearer {
            req = req.header(header::AUTHORIZATION, format!("Bearer {b}"));
        }
        if let Some(k) = &call.idempotency_key {
            req = req.header("idempotency-key", k);
        }
        let mut req = req.body(Body::from(call.body)).unwrap();
        req.extensions_mut().insert(PepId(String::from(TWIN_PEP)));
        let r = self.public.clone().oneshot(req).await.unwrap();
        let status = r.status().as_u16();
        let body = to_bytes(r.into_body(), 1 << 22).await.unwrap().to_vec();
        Answer::Response(Answered::new(status, body))
    }
}

/// Wall time.
struct Wall;

impl access_sdk::transport::Clock for Wall {
    fn now(&self) -> Option<u64> {
        Some(now_ms())
    }
}

struct Os;

impl TwinRandom for Os {
    fn bytes(&self, n: usize) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            out.extend_from_slice(&access_crypto::random::bytes::<16>().ok()?);
        }
        out.truncate(n);
        Some(out)
    }
}

type ProductTwin = Twin<Listener, Wall, Os>;

/// A Party of the domain with its own Instance key: a person, an agent or a clinic using a
/// product.
struct Actor {
    party: Id,
    key: SoftSigner,
    /// Its self-anchor (§7.9.2.3).
    anchor: Id,
}

/// A bootstrapped deployment with one platform product client, the realm `seams` and the
/// twin of that product paired with it.
struct Seam {
    w: World,
    signer: AuthoritySigner,
    domain: Digest,
    root: HsmSigner,
    root_party: Id,
    listener: Listener,
    twin: ProductTwin,
    party: Id,
}

fn schema(name: &str) -> Schema {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/seams/schemas")
        .join(format!("{name}.toml"));
    Schema::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The realm `slug` in a new tenant with the bootstrap root as founder and a zero CT3
/// time-lock, through the admin path alone.
async fn realm(w: &World, slug: &str) -> (TenantId, RealmId, Digest) {
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
    let root = root_party(&root_key(&w.keys).unwrap().public_key());
    let created = admin
        .create_realm(&NewRealm {
            tenant,
            slug,
            style: IssuerStyle::Path,
            placement: PLACEMENT,
            root: Root::Sole(root),
            ct3_delay_s: Some(0),
            causal_binding: false,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
            provisioned_by: None,
        })
        .await
        .unwrap();
    (tenant, created.realm, created.domain)
}

impl Seam {
    /// The deployment with the platform product `product`, its twin paired with `seams`.
    async fn open(label: &str, product: &str) -> Self {
        Self::open_many(label, &[product]).await.0
    }

    /// The deployment with the platform products `products`, each a twin paired with `seams`;
    /// the first is the seam's own, the others come back with their Parties.
    async fn open_many(label: &str, products: &[&str]) -> (Self, Vec<(ProductTwin, Id)>) {
        let (seam, others, _) = Self::open_with(label, products).await;
        (seam, others)
    }

    /// [`Self::open`], and the product's own copy of its service key: what its own code signs
    /// its own statements with.
    async fn open_keyed(label: &str, product: &str) -> (Self, SoftSigner) {
        let (seam, _, own) = Self::open_with(label, &[product]).await;
        (seam, own)
    }

    async fn open_with(
        label: &str,
        products: &[&str],
    ) -> (Self, Vec<(ProductTwin, Id)>, SoftSigner) {
        let (w, signer) = Box::pin(World::open(label, true)).await;
        let signer = signer.unwrap();
        schedule(&signer);
        let mut own = None;
        let keys: Vec<(SoftSigner, SoftSigner)> = products
            .iter()
            .map(|_| {
                let (service, pkcs8) = SoftSigner::generate_ed25519().unwrap();
                own.get_or_insert_with(|| SoftSigner::ed25519_from_pkcs8(&pkcs8).unwrap());
                (service, SoftSigner::generate_p256().unwrap().0)
            })
            .collect();
        let own = own.unwrap();
        let plan = Plan {
            products: products
                .iter()
                .zip(&keys)
                .map(|(product, (service, client))| ProductPlan {
                    product: PlatformProduct::parse(product).unwrap(),
                    display_name: format!("Suiss {product}"),
                    client_key: client.public_key(),
                    service_key: service.public_key(),
                    event_receiver: None,
                    redirect_uris: vec![
                        RedirectUri::parse(&format!("https://{product}.test/cb")).unwrap(),
                    ],
                })
                .collect(),
            ..plan()
        };
        let summary = serde_json::to_value(Box::pin(w.run(&plan)).await).unwrap();
        schedule(&signer);
        let (tenant, created_realm, domain) = Box::pin(realm(&w, SLUG)).await;
        let root = root_key(&w.keys).unwrap();
        let root_party = root_party(&root.public_key());
        let declared = DeclaredTargets::default();
        Box::pin(
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
            .onboard(tenant, created_realm, domain, &root, root_party),
        )
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
            wake: None,
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
        let tnt =
            access_identity_events::ports::TenantIds::external(&*ids, tenant.as_bytes()).unwrap();
        let mut twins = Vec::new();
        for (i, (service, client)) in keys.into_iter().enumerate() {
            let client_id = summary["clients"][i]["client_id"]
                .as_str()
                .unwrap()
                .to_owned();
            let audience = summary["clients"][i]["audience"]
                .as_str()
                .unwrap()
                .to_owned();
            let twin = Twin::new(
                Config {
                    client_id,
                    audience,
                    pep: String::from(TWIN_PEP),
                },
                Keys { service, client },
                (listener.clone(), Wall, Os),
            );
            let paired = Box::pin(twin.register(&tnt)).await.unwrap();
            assert_eq!(paired.len(), 1, "{paired:?}");
            assert_eq!(paired[0].domain, domain);
            let party = paired[0].party;
            schedule(&signer);
            twins.push((twin, party));
        }
        let (twin, party) = twins.remove(0);
        (
            Self {
                w,
                signer,
                domain,
                root,
                root_party,
                listener,
                twin,
                party,
            },
            twins,
            own,
        )
    }

    fn bootstrap<'a>(
        &'a self,
        declared: &'a DeclaredTargets,
    ) -> Bootstrap<'a, TestPlane, RealmKeyring> {
        Bootstrap {
            app: &self.w.db.app,
            router: &self.w.db.router,
            plane: &self.w.plane,
            realm_keys: &self.w.keyring,
            hsm: &self.w.keys,
            base: &self.w.base,
            declared,
            console: None,
        }
    }

    /// The root's commit of `payload` on the meta-anchor: its Exercise and position.
    async fn root(&self, payload: Payload) -> (Digest, u64) {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let declared = DeclaredTargets::default();
        let position = Box::pin(self.bootstrap(&declared).commit_meta(
            self.domain,
            &self.root,
            &nonce,
            payload,
            self.root_party,
        ))
        .await
        .unwrap();
        schedule(&self.signer);
        (meta::exercise_id(&self.domain, &nonce).unwrap(), position)
    }

    /// The root accepts the product's published `schema` (`schema-definition`, OP-141 m.35).
    async fn accept_schema(&self, schema: &Schema) {
        let spp = schema.spp(self.party).unwrap();
        self.root(Payload::AcceptanceEstablish(Value::Map(vec![
            (Value::text("issuer"), self.party.to_value()),
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
            (Value::text("spp"), spp.to_value()),
        ])))
        .await;
    }

    /// The root accepts the product's Claims of `classes` for `use_`.
    async fn accept_claims(&self, use_: &str, classes: &[&str]) {
        let mut classes = classes.to_vec();
        classes.sort_by_key(|c| (c.len(), *c));
        self.root(Payload::AcceptanceEstablish(Value::Map(vec![
            (Value::text("issuer"), self.party.to_value()),
            (Value::text("use"), Value::text(use_)),
            (
                Value::text("classes"),
                Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
            ),
        ])))
        .await;
    }

    /// The root's Grant of `authority` to `holder` on the meta-anchor, and its id.
    async fn grant(&self, holder: SubjectSelector, authority: CanonicalAuthority) -> (Id, u64) {
        let (exercise, position) = self
            .root(Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta::meta_anchor(&self.domain)),
                holder,
                authority,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }))
            .await;
        (meta::object_id(&exercise, kind::GRANT, 0), position)
    }

    /// A new Party with its own Ed25519 Instance key, registered by its own self-signed
    /// Exercises (L0-META-7).
    async fn actor(&self) -> Actor {
        let (key, _) = SoftSigner::generate_ed25519().unwrap();
        let party = Id(access_crypto::random::bytes::<16>().unwrap());
        let challenge = access_crypto::random::bytes::<32>().unwrap().to_vec();
        let now = server_time(&self.w.db.app).await.unwrap();
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let mut r = Registration {
            tenant: [0; 16],
            domain: self.domain,
            registrant: Registrant::Device {
                realm: [0; 16],
                subject: [0; 16],
            },
            party,
            key: key.public_key(),
            register: None,
            create: SelfSigned {
                nonce: challenge.clone(),
                validity,
                ais: Vec::new(),
            },
            pep: String::from(IDENTITY_PEP),
            context: None,
        };
        let signed = |nonce: &[u8], payload: &Payload| {
            let intent = self_signed_intent(payload, party, validity).unwrap();
            Self::ais(
                &key,
                &Statement {
                    domain: self.domain,
                    nonce: nonce.to_vec(),
                    intent: intent_digest(&intent).unwrap(),
                    mode: Mode::Commit,
                    pep: String::from(IDENTITY_PEP),
                    capacity: Capacity::Own,
                    basis: access_internal_api::instances::bootstrap_basis(&self.domain),
                    iat: now,
                    exercise: None,
                },
            )
        };
        let register = register_nonce(&challenge);
        r.register = Some(SelfSigned {
            ais: signed(&register, &r.register_payload()),
            nonce: register.clone(),
            validity,
        });
        r.create.ais = signed(&challenge, &r.create_payload());
        match Box::pin(self.w.plane.register(r)).await.unwrap() {
            RegistrationVerdict::Registered(_) => {}
            other @ RegistrationVerdict::Refused { .. } => panic!("{other:?}"),
        }
        schedule(&self.signer);
        Actor {
            party,
            key,
            anchor: meta::object_id(
                &meta::exercise_id(&self.domain, &register).unwrap(),
                kind::ANCHOR,
                0,
            ),
        }
    }

    fn ais(key: &SoftSigner, s: &Statement) -> Vec<u8> {
        sign_sign1(
            key,
            thumbprint(&key.public_key()),
            CONTENT_TYPE,
            &s.to_bytes().unwrap(),
        )
        .unwrap()
    }

    /// `actor`'s own commit of the meta-action `payload` on `basis`, with the identity plane as
    /// PEP (EI-25): a Party acting as root of its own self-anchor.
    async fn own_commit(
        &self,
        actor: &Actor,
        basis: ExerciseBasis,
        payload: Payload,
    ) -> (Digest, u64) {
        let now = server_time(&self.w.db.app).await.unwrap();
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, actor.party, validity).unwrap();
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let ais = Self::ais(
            &actor.key,
            &Statement {
                domain: self.domain,
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
        MetaExercises::lead(&self.w.plane, self.domain)
            .await
            .unwrap();
        let verdict = Box::pin(MetaExercises::meta(
            &self.w.plane,
            Request {
                domain: self.domain,
                mode: Mode::Commit,
                nonce: nonce.clone(),
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
        schedule(&self.signer);
        (c.exercise, c.position)
    }

    /// `actor`'s statement for `envelope` on `basis`, with the twin as PEP, and the twin's
    /// request carrying it with `proofs`.
    fn request(
        &self,
        actor: &Actor,
        envelope: IntentEnvelope,
        basis: ExerciseBasis,
        proofs: Vec<Proof>,
    ) -> access_product_twin::Request {
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let ais = Self::ais(
            &actor.key,
            &Statement {
                domain: self.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&envelope).unwrap(),
                mode: Mode::Commit,
                pep: String::from(TWIN_PEP),
                capacity: Capacity::Own,
                basis,
                iat: now_ms(),
                exercise: None,
            },
        );
        access_product_twin::Request {
            ais,
            envelope,
            nonce,
            basis,
            capacity: Capacity::Own,
            proofs,
        }
    }

    /// PI-14: every call the twin made named a listed public endpoint and was sent as itself.
    fn only_public(&self) {
        let seen = self.listener.seen.lock().unwrap();
        assert!(!seen.is_empty());
        for c in seen.iter() {
            assert!(
                access_product_twin::wire::ENDPOINTS
                    .iter()
                    .any(|e| e.method == c.method && e.path == c.endpoint),
                "{} {}",
                c.method.name(),
                c.path
            );
        }
    }
}

fn window() -> Window {
    let now = now_ms();
    Window {
        from: now - 60_000,
        until: now + 600_000,
    }
}

fn envelope(
    action: ActionRef,
    resource: (&str, &[&str]),
    params: BTreeMap<String, ParamValue>,
) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action,
        resources: vec![ResourceRef {
            namespace: String::from(resource.0),
            path: resource.1.iter().map(|p| String::from(*p)).collect(),
            incarnation: 0,
        }],
        params,
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: window(),
    }
}

fn structural(namespace: &str, prefix: &[&str]) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: String::from(namespace),
        prefix: prefix.iter().map(|p| String::from(*p)).collect(),
        kind: None,
        attrs: BTreeMap::new(),
    })
}

fn canonical(
    actions: &[ActionRef],
    resource: ResourceSelector,
    params: BTreeMap<String, Bound>,
    budget: BTreeSet<BudgetTerm>,
    requirements: BTreeSet<RequirementTerm>,
) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: actions.iter().cloned().collect(),
                prefix: BTreeSet::new(),
            },
            resource,
            params,
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: u64::MAX,
            },
            conditions: BTreeSet::new(),
            budget,
        },
        delegation: DelegationTerms::default(),
        requirements,
    }
}

fn hex(id: &Id) -> String {
    id.0.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn pred(class: &str, value: EqValue) -> SubjectSelector {
    SubjectSelector::Pred(BTreeSet::from([Conjunct {
        claim_class: String::from(class),
        value: Some(value),
    }]))
}

fn holding(grant: Id, holder: Id, since: u64) -> ExerciseBasis {
    ExerciseBasis::Holding(HoldingRef {
        grant,
        holder,
        since,
    })
}

/// Whether `r` is a refusal of class `refusal`.
fn refused(
    r: &Result<access_sdk::authorize::Authorized<(), ()>, Denied>,
    refusal: Refusal,
) -> bool {
    matches!(r, Err(Denied::Refused(x)) if *x == refusal)
}

// §7.9.10.3, E16, PI-3, PI-14, B21, E24, OP-156 m.2 Q1, OP-153 m.3 (gg), Ek B 5244, 5248
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_product_publishes_issues_and_enforces_but_writes_no_authority() {
    let s = Seam::open("seam-contract", "ride").await;
    let ride = schema("ride");
    assert_ne!(s.party, s.root_party);

    let published = s.twin.publish_schema(&s.domain, &ride).await.unwrap();
    assert!(published.new);
    assert!(
        !s.twin
            .accepted(&s.domain, "ride", &published.fingerprint)
            .await
            .unwrap()
    );

    // §7.9.10.3
    let meta_anchor = ExerciseBasis::Anchor(meta::meta_anchor(&s.domain));
    let accept = s
        .twin
        .attempt(
            &s.domain,
            &Payload::AcceptanceEstablish(Value::Map(vec![
                (Value::text("issuer"), s.party.to_value()),
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
                (Value::text("spp"), ride.spp(s.party).unwrap().to_value()),
            ])),
            meta_anchor,
        )
        .await
        .unwrap();
    assert!(!accept.took_effect(), "{accept:?}");
    assert_eq!(
        (accept.status, accept.decision, accept.outcome.as_deref()),
        (200, Some(false), Some("deny")),
        "{accept:?}"
    );
    let accept_action = ride.action("accept").unwrap();
    let to_itself = s
        .twin
        .attempt(
            &s.domain,
            &Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta::meta_anchor(&s.domain)),
                holder: SubjectSelector::Party(s.party),
                authority: canonical(
                    std::slice::from_ref(&accept_action),
                    structural("ride.trip", &[]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
            meta_anchor,
        )
        .await
        .unwrap();
    assert!(!to_itself.took_effect(), "{to_itself:?}");
    assert_eq!(
        (
            to_itself.status,
            to_itself.decision,
            to_itself.outcome.as_deref()
        ),
        (200, Some(false), Some("deny")),
        "{to_itself:?}"
    );
    let anchor = s
        .twin
        .attempt(
            &s.domain,
            &Payload::AnchorCreate {
                scope: meta::AnchorScope::Resource(structural("ride.trip", &[])),
                root: Root::Sole(s.party),
                root_terms: BTreeSet::new(),
                sets: access_kernel::meta::RootSets::default(),
            },
            meta_anchor,
        )
        .await
        .unwrap();
    assert!(!anchor.took_effect(), "{anchor:?}");
    assert_eq!(
        (anchor.status, anchor.decision, anchor.outcome.as_deref()),
        (200, Some(false), Some("deny")),
        "{anchor:?}"
    );
    assert!(
        !s.twin
            .accepted(&s.domain, "ride", &published.fingerprint)
            .await
            .unwrap()
    );

    // E16
    s.accept_schema(&ride).await;
    assert!(
        s.twin
            .accepted(&s.domain, "ride", &published.fingerprint)
            .await
            .unwrap()
    );

    // PI-3
    let driver = s.actor().await;
    let (grant, _) = s
        .grant(
            pred("ride_driver", EqValue::Bool(true)),
            canonical(
                std::slice::from_ref(&accept_action),
                structural("ride.trip", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let trip = || {
        envelope(
            accept_action.clone(),
            ("ride.trip", &["t-1"]),
            BTreeMap::new(),
        )
    };
    let before = s
        .twin
        .ask(
            &s.domain,
            &s.request(&driver, trip(), holding(grant, driver.party, 0), Vec::new()),
        )
        .await;
    assert!(
        matches!(before, Err(Denied::Refused(Refusal::Deny))),
        "{before:?}"
    );
    let issue = || Issue {
        subject: driver.party,
        class: String::from("ride_driver"),
        value: Some(EqValue::Bool(true)),
        for_ms: 3_600_000,
        resource: None,
    };
    let unaccepted = s.twin.issue_claim(&s.domain, issue()).await.unwrap();
    assert_eq!(unaccepted.disposition, "quarantine", "{unaccepted:?}");
    assert_eq!(unaccepted.reason.as_deref(), Some("source-not-accepted"));
    s.accept_claims(access_kernel::claim::SUBJECT_SELECTION, &["ride_driver"])
        .await;
    let admitted = s.twin.issue_claim(&s.domain, issue()).await.unwrap();
    assert_eq!(admitted.disposition, "admit", "{admitted:?}");
    schedule(&s.signer);
    let episode = admitted.position.unwrap();
    let envelope = trip();
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &driver,
                envelope.clone(),
                holding(grant, driver.party, episode),
                Vec::new(),
            ),
        )
        .await
        .unwrap();
    let mut accepted_trips = Vec::new();
    ProductTwin::enforce(allowed, &envelope, || accepted_trips.push("t-1")).unwrap();
    assert_eq!(accepted_trips, ["t-1"]);

    // PI-14
    s.only_public();
    let internal = s.listener.raw("GET", "/readyz", Vec::new()).await;
    let management = s
        .listener
        .raw("GET", "/admin/v1/platform", Vec::new())
        .await;
    for a in [internal, management] {
        let Answer::Response(r) = a else {
            panic!("no answer");
        };
        assert!(matches!(r.status, 403 | 404), "{}", r.status);
    }
}

// §7.9.10.3, Ek B 5245
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suiss_ride_needs_no_new_ontology() {
    let s = Seam::open("seam-ride", "ride").await;
    let ride = schema("ride");
    s.twin.publish_schema(&s.domain, &ride).await.unwrap();
    s.accept_schema(&ride).await;
    let request = ride.action("request").unwrap();
    let agent = s.actor().await;
    let fare = |kurus: i64| {
        BTreeMap::from([(
            String::from("fare"),
            ParamValue::Amount {
                value: kurus,
                unit: String::from("try"),
            },
        )])
    };
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&request),
                structural("ride.trip", &[]),
                BTreeMap::from([(
                    String::from("fare"),
                    Bound::Range {
                        min: Some(0),
                        max: Some(30_000),
                        unit: String::from("try"),
                    },
                )]),
                BTreeSet::from([BudgetTerm {
                    dimension: BudgetDimension::Amount(String::from("try")),
                    capacity: 30_000,
                    window: BudgetWindow::Total,
                }]),
                BTreeSet::new(),
            ),
        )
        .await;
    let basis = holding(grant, agent.party, since);
    let mut booked = Vec::new();
    let first = envelope(request.clone(), ("ride.trip", &["t-1"]), fare(20_000));
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(&agent, first.clone(), basis, Vec::new()),
        )
        .await
        .unwrap();
    ProductTwin::enforce(allowed, &first, || booked.push("t-1")).unwrap();
    schedule(&s.signer);
    // L0-EVAL-15
    let over_budget = envelope(request.clone(), ("ride.trip", &["t-2"]), fare(20_000));
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(&agent, over_budget, basis, Vec::new()),
        )
        .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    let over_bound = envelope(request.clone(), ("ride.trip", &["t-3"]), fare(40_000));
    let r = s
        .twin
        .ask(&s.domain, &s.request(&agent, over_bound, basis, Vec::new()))
        .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    assert_eq!(booked, ["t-1"]);
    s.only_public();
}

// §7.9.10.3, §7.9.15, Ek B 5245
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn suiss_health_needs_no_new_ontology() {
    let s = Seam::open("seam-health", "health").await;
    let health = schema("health");
    s.twin.publish_schema(&s.domain, &health).await.unwrap();
    s.accept_schema(&health).await;
    s.accept_claims(
        access_kernel::claim::SUBJECT_SELECTION,
        &["health_guardian"],
    )
    .await;
    let read = health.action("read").unwrap();
    let share = health.action("share").unwrap();
    let patient = s.actor().await;
    let guardian = s.actor().await;
    let clinic = s.actor().await;
    let records = hex(&patient.party);
    // §7.9.2.3
    let (exercise, _) = s
        .own_commit(
            &patient,
            ExerciseBasis::Anchor(patient.anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(patient.anchor),
                holder: pred("health_guardian", EqValue::Text(records.clone())),
                authority: canonical(
                    std::slice::from_ref(&read),
                    structural("access.party", &[&records]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .await;
    let guardian_grant = meta::object_id(&exercise, kind::GRANT, 0);
    let record = || {
        envelope(
            read.clone(),
            ("access.party", &[&records, "record-1"]),
            BTreeMap::new(),
        )
    };
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &guardian,
                record(),
                holding(guardian_grant, guardian.party, 0),
                Vec::new(),
            ),
        )
        .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    let admitted = s
        .twin
        .issue_claim(
            &s.domain,
            Issue {
                subject: guardian.party,
                class: String::from("health_guardian"),
                value: Some(EqValue::Text(records.clone())),
                for_ms: 3_600_000,
                resource: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(admitted.disposition, "admit", "{admitted:?}");
    schedule(&s.signer);
    let read_it = record();
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &guardian,
                read_it.clone(),
                holding(guardian_grant, guardian.party, admitted.position.unwrap()),
                Vec::new(),
            ),
        )
        .await
        .unwrap();
    let mut shown = Vec::new();
    ProductTwin::enforce(allowed, &read_it, || shown.push("record-1")).unwrap();
    assert_eq!(shown, ["record-1"]);

    // §7.9.3.1
    let (exercise, since) = s
        .own_commit(
            &patient,
            ExerciseBasis::Anchor(patient.anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(patient.anchor),
                holder: SubjectSelector::Party(clinic.party),
                authority: canonical(
                    std::slice::from_ref(&share),
                    structural("access.party", &[&records]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::from([RequirementTerm {
                        proof_kind: ProofKind::Contribution,
                        class: String::from(access_kernel::contribution::DISCLOSE),
                        count: 1,
                        binding: Binding::IntentDigest,
                        freshness_ms: None,
                        independence: Independence::None,
                        consumption: Consumption::SingleUse,
                        source: Some(SubjectSelector::Party(patient.party)),
                        assurance: BTreeMap::new(),
                    }]),
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .await;
    let share_it = envelope(
        share.clone(),
        ("access.party", &[&records, "record-1"]),
        BTreeMap::from([(String::from("recipient"), ParamValue::Subject(clinic.party))]),
    );
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &clinic,
                share_it,
                holding(
                    meta::object_id(&exercise, kind::GRANT, 0),
                    clinic.party,
                    since,
                ),
                Vec::new(),
            ),
        )
        .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");
    s.only_public();
}

/// A shop product for the predicate seam: its `refund` needs its own `order_refundable`
/// predicate, and its `shop_staff` Claim is only ever a predicate input.
const SHOP: &str = r#"
product = "Seam Shop"
namespace = "seamshop"
catalog_version = 1
truth = ["order", "refund window"]

[[actions]]
name = "refund"
major = 1
effect_class = "irreversible"
reversibility = "compensable"
resource_types = ["order"]

[[claims]]
class = "order_refundable"
value = "bool"
use = "predicate-input"
meaning = "The order can be refunded now."

[[claims]]
class = "shop_staff"
value = "bool"
use = "predicate-input"
meaning = "The subject works in the shop."
"#;

// §2.6, §2.7, §7.9.10.5, INV-16, Ek B 5246
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_domain_predicate_is_consumed_and_never_recomputed() {
    let s = Seam::open("seam-predicate", "shop").await;
    let shop = Schema::parse(SHOP).unwrap();
    s.twin.publish_schema(&s.domain, &shop).await.unwrap();
    s.accept_schema(&shop).await;
    let refund = shop.action("refund").unwrap();
    let agent = s.actor().await;
    let order = ResourceRef {
        namespace: String::from("seamshop.order"),
        path: vec![String::from("o-1")],
        incarnation: 0,
    };
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&refund),
                structural("seamshop.order", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::from([RequirementTerm {
                    proof_kind: ProofKind::Claim,
                    class: String::from("order_refundable"),
                    count: 1,
                    binding: Binding::Resource,
                    freshness_ms: Some(600_000),
                    independence: Independence::None,
                    consumption: Consumption::Reusable,
                    source: Some(SubjectSelector::Party(s.party)),
                    assurance: BTreeMap::new(),
                }]),
            ),
        )
        .await;
    let basis = holding(grant, agent.party, since);
    let refund_it = || {
        envelope(
            refund.clone(),
            ("seamshop.order", &["o-1"]),
            BTreeMap::new(),
        )
    };

    // §2.6
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(&agent, refund_it(), basis, Vec::new()),
        )
        .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");

    let issue = || Issue {
        subject: agent.party,
        class: String::from("order_refundable"),
        value: Some(EqValue::Bool(true)),
        for_ms: 600_000,
        resource: Some(order.clone()),
    };
    let unaccepted = s.twin.issue_claim(&s.domain, issue()).await.unwrap();
    assert_eq!(unaccepted.disposition, "quarantine", "{unaccepted:?}");
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &agent,
                refund_it(),
                basis,
                vec![Proof::Carried(unaccepted.sign1.clone())],
            ),
        )
        .await;
    assert!(refused(&r, Refusal::RequireAction), "{r:?}");

    // §7.9.10.5
    s.accept_claims(
        access_kernel::claim::PREDICATE_INPUT,
        &["order_refundable", "shop_staff"],
    )
    .await;
    let admitted = s.twin.issue_claim(&s.domain, issue()).await.unwrap();
    assert_eq!(admitted.disposition, "admit", "{admitted:?}");
    schedule(&s.signer);
    let envelope = refund_it();
    let allowed = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &agent,
                envelope.clone(),
                basis,
                vec![Proof::Recorded(admitted.claim)],
            ),
        )
        .await
        .unwrap();
    let mut refunded = Vec::new();
    ProductTwin::enforce(allowed, &envelope, || refunded.push("o-1")).unwrap();
    assert_eq!(refunded, ["o-1"]);

    // INV-16
    let staff = s.actor().await;
    let (staff_grant, _) = s
        .grant(
            pred("shop_staff", EqValue::Bool(true)),
            canonical(
                std::slice::from_ref(&refund),
                structural("seamshop.order", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let member = s
        .twin
        .issue_claim(
            &s.domain,
            Issue {
                subject: staff.party,
                class: String::from("shop_staff"),
                value: Some(EqValue::Bool(true)),
                for_ms: 600_000,
                resource: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(member.disposition, "admit", "{member:?}");
    schedule(&s.signer);
    let r = s
        .twin
        .ask(
            &s.domain,
            &s.request(
                &staff,
                refund_it(),
                holding(staff_grant, staff.party, member.position.unwrap()),
                Vec::new(),
            ),
        )
        .await;
    assert!(matches!(r, Err(Denied::Refused(Refusal::Deny))), "{r:?}");
    s.only_public();
}

mod review;
mod seams;
mod security;
mod signals;
mod support;
mod work;
