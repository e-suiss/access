//! Agent token exchange and identity assertions at the realm's real token endpoint (OP-154
//! m.3 (m), (n), (o), (q), OP-153 m.3 (gg)): a bootstrapped realm whose sample subject P
//! delegates to an agent A1, which delegates on to an agent A2, all on the real sequencer;
//! tokens decided and signed by the authority plane and its signer over `SoftHSM`; an issuer
//! pinned by an `actor-binding` Acceptance at Genesis; every request through the real OAuth
//! router with DPoP proofs by the agents' own Instance keys.

#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    reason = "test code: the parties are P, A1 and A2"
)]

use std::collections::BTreeSet;
use std::time::Duration;

use access_identity_admin::domain::Change;
use access_identity_oauth::adapters::clients::{CachePolicy, HttpClientKeys};
use access_identity_oauth::adapters::oauth::PgOAuth;
use access_identity_oauth::adapters::outbound::Outbound;
use access_identity_oauth::adapters::{PgDirectory, SignerKeys};
use access_identity_oauth::app::oauth::OAuth;
use access_identity_oauth::domain::authority::{TokenExercise, encode_exercise};
use access_identity_oauth::domain::dpop::DpopProfile;
use access_internal_api::projections::{
    Confirmation, Projections as _, TokenKind, TokenProfile, TokenProjection,
    TokenProjectionRequest,
};
use access_kernel::json::b64url_decode;
use access_kernel::validity::{ProfileClass, ProfileVariant};
use access_kernel::verify::projection::digest_text;
use access_sdk::auth::dpop::{ProofFor, ProofKey, proof};
use access_sdk::auth::{Random, RandomUnavailable};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use axum::body::{Body, to_bytes};
use axum::http::{Request as HttpRequest, StatusCode, header};
use serde_json::{Value as JsonValue, json};
use suiss_crypto::dcbor::Value;
use tower::ServiceExt as _;

use super::*;

pub(super) const ISSUER: &str = "https://access.test/realms/acme";
const TOKEN: &str = "/realms/acme/token";
const RS: &str = "https://mcp.access.test/mcp";
pub(super) const UPSTREAM: &str = "https://upstream.access.test/api";
pub(super) const IDP: &str = "https://idp.l2.test";

struct Csprng;

impl Random for Csprng {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomUnavailable> {
        for chunk in out.chunks_mut(16) {
            let b: [u8; 16] = access_crypto::random::bytes().map_err(|_| RandomUnavailable)?;
            chunk.copy_from_slice(&b[..chunk.len()]);
        }
        Ok(())
    }
}

/// An agent Instance's key in the token: its AIS key and its DPoP key.
pub(super) struct Agent {
    key: HsmSigner,
    public: PublicKey,
    pub(super) party: Id,
}

impl Agent {
    fn jkt(&self) -> [u8; 32] {
        thumbprint(&self.public)
    }
}

impl ProofKey for Agent {
    fn public_key(&self) -> &PublicKey {
        &self.public
    }

    fn sign(&self, input: &[u8]) -> Option<Vec<u8>> {
        suiss_crypto::signer::Signer::sign(&self.key, input).ok()
    }
}

fn nonce16() -> Vec<u8> {
    access_crypto::random::bytes::<16>().unwrap().to_vec()
}

fn form(pairs: &[(&str, &str)]) -> String {
    let enc = |s: &str| {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect::<String>()
    };
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

pub(super) fn claims_of(token: &str) -> JsonValue {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64url_decode(payload).unwrap()).unwrap()
}

fn header_of(token: &str) -> JsonValue {
    let h = token.split('.').next().unwrap();
    serde_json::from_slice(&b64url_decode(h).unwrap()).unwrap()
}

pub(super) fn act_chain(claims: &JsonValue) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = claims.get("act");
    while let Some(a) = at {
        out.push(String::from(a["sub"].as_str().unwrap()));
        at = a.get("act");
    }
    out
}

/// An ES256 JWT of the test issuer.
pub(super) fn idp_jwt(key: &EcdsaKeyPair, typ: &str, claims: &JsonValue) -> String {
    let public = PublicKey::P256(key.public_key().as_ref().to_vec());
    let header = json!({ "alg": "ES256", "kid": b64url_encode(&thumbprint(&public)), "typ": typ });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", b64url_encode(sig.as_ref()))
}

pub(super) struct Realm {
    pub(super) w: World,
    oauth: axum::Router,
    pub(super) domain: Digest,
    action: ActionRef,
    pub(super) client: String,
    pub(super) p: Agent,
    a1: Agent,
    pub(super) a2: Agent,
    pub(super) stranger: Agent,
    g0: HoldingRef,
    g1: HoldingRef,
    pub(super) g2: HoldingRef,
    pub(super) stranger_own: HoldingRef,
    pub(super) idp: EcdsaKeyPair,
    confidential: (String, EcdsaKeyPair),
    nonce: std::sync::Mutex<Option<String>>,
}

/// Commits `payload` as the key's `commit` on `basis` in `capacity`.
async fn commit(
    w: &World,
    domain: Digest,
    key: &HsmSigner,
    about: Id,
    (basis, capacity): (ExerciseBasis, Capacity),
    payload: Payload,
) -> (Digest, u64) {
    let now = server_time(&w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, about, validity).unwrap();
    let nonce = nonce16();
    let ais = sign(
        key,
        &Statement {
            domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity,
            basis,
            iat: now,
            exercise: None,
        },
    )
    .unwrap();
    MetaExercises::lead(&w.plane, domain).await.unwrap();
    let verdict = MetaExercises::meta(
        &w.plane,
        Request {
            domain,
            mode: Mode::Commit,
            nonce,
            intent,
            payload: Some(payload),
            basis,
            capacity,
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
    (c.exercise, c.position)
}

pub(super) fn delegated(action: &ActionRef, depth: u64, to: Option<Id>) -> CanonicalAuthority {
    let mut a = authority(BTreeSet::from([action.clone()]), "work", BTreeSet::new());
    a.delegation = DelegationTerms {
        depth,
        downstream_holder_class: to.map(SubjectSelector::Party),
    };
    a
}

/// `holder`'s Grant from `grantor`'s holding (or the meta-anchor), committed by `grantor`.
pub(super) async fn issue(
    w: &World,
    domain: Digest,
    grantor: &HsmSigner,
    from: Option<HoldingRef>,
    holder: Id,
    authority: CanonicalAuthority,
    (agency, capacity): (BTreeSet<Capacity>, Capacity),
) -> HoldingRef {
    let anchor = meta::meta_anchor(&domain);
    let (grant_basis, basis) = from.map_or(
        (GrantBasis::Anchor(anchor), ExerciseBasis::Anchor(anchor)),
        |h| (GrantBasis::Holding(h), ExerciseBasis::Holding(h)),
    );
    let (exercise, since) = commit(
        w,
        domain,
        grantor,
        holder,
        (basis, capacity),
        Payload::GrantIssue(GrantContent {
            basis: grant_basis,
            holder: SubjectSelector::Party(holder),
            authority,
            agency,
            named: None,
        }),
    )
    .await;
    HoldingRef {
        grant: meta::object_id(&exercise, kind::GRANT, 0),
        holder,
        since,
    }
}

/// `agent`'s Party and Instance, self-registered under the bootstrap Grant from its own
/// address context, as an agent runtime on its own host would (§13.7.4).
async fn enroll(
    w: &World,
    (tenant, realm): (TenantId, RealmId),
    domain: Digest,
    a: &Agent,
    n: usize,
) {
    let challenge = root_challenge(&a.key, domain).unwrap();
    let m = Moment::at(server_time(&w.db.app).await.unwrap());
    let mut r = Registration {
        tenant: *tenant.as_bytes(),
        domain,
        registrant: Registrant::Device {
            realm: *realm.as_bytes(),
            subject: [0; 16],
        },
        party: a.party,
        key: a.public.clone(),
        register: None,
        create: SelfSigned {
            nonce: challenge.clone(),
            validity: m.validity,
            ais: Vec::new(),
        },
        pep: String::from(IDENTITY_PEP),
        context: Some(access_internal_api::context::RateContext::address(
            &[u8::try_from(n).unwrap().wrapping_add(0x51); 32],
        )),
    };
    let signed = |nonce: &[u8], payload: &Payload| {
        let intent = self_signed_intent(payload, a.party, m.validity).unwrap();
        sign(
            &a.key,
            &m.statement(
                domain,
                nonce,
                intent_digest(&intent).unwrap(),
                bootstrap_basis(&domain),
            ),
        )
        .unwrap()
    };
    let register = register_nonce(&challenge);
    r.create.ais = signed(&challenge, &r.create_payload());
    r.register = Some(SelfSigned {
        nonce: register.clone(),
        validity: m.validity,
        ais: signed(&register, &r.register_payload()),
    });
    MetaExercises::lead(&w.plane, domain).await.unwrap();
    let verdict = Instances::register(&w.plane, r).await.unwrap();
    assert!(
        matches!(verdict, RegistrationVerdict::Registered(_)),
        "{verdict:?}"
    );
}

fn sorted(mut m: Vec<(Value, Value)>) -> Value {
    m.sort_by(|a, b| {
        let ka = suiss_crypto::dcbor::encode(&a.0, suiss_crypto::dcbor::Limits::CEILING).unwrap();
        let kb = suiss_crypto::dcbor::encode(&b.0, suiss_crypto::dcbor::Limits::CEILING).unwrap();
        ka.cmp(&kb)
    });
    Value::Map(m)
}

impl Realm {
    #[allow(clippy::too_many_lines, reason = "one realm and its delegation chain")]
    pub(super) async fn open(name: &str) -> Self {
        let (w, signer) = World::open(name, true).await;
        let signer = signer.unwrap();
        let declared = DeclaredTargets::default();
        let b = Bootstrap {
            app: &w.db.app,
            router: &w.db.router,
            plane: &w.plane,
            realm_keys: &w.keyring,
            hsm: &w.keys,
            base: &w.base,
            declared: &declared,
            console: None,
        };
        // AG-29, §9.13
        let idp = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let accepted = sorted(vec![
            (Value::text("issuer"), Id([0x1d; 16]).to_value()),
            (Value::text("use"), Value::text("actor-binding")),
            (
                Value::text("classes"),
                Value::Array(vec![Value::text("identity_binding_person")]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX / 2)]),
            ),
            (
                Value::text("pinned"),
                sorted(vec![
                    (Value::text("iss"), Value::text(IDP)),
                    (Value::text("aud"), Value::text(ISSUER)),
                    (
                        Value::text("keys"),
                        Value::Array(vec![
                            PublicKey::P256(idp.public_key().as_ref().to_vec()).to_value(),
                        ]),
                    ),
                ]),
            ),
        ]);
        let sample = sample_plan().sample.unwrap();
        let founder = root_party(&root_key(&w.keys).unwrap().public_key());
        let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
        let (mut acceptances, predicate) = genesis_acceptances(Some(&sample), None);
        acceptances.push(accepted);
        b.realm(
            &b.admin(&ids, None),
            "acme",
            issuer_style(Style::Path),
            founder,
            vec![sample.catalog(founder)],
            (acceptances, predicate),
        )
        .await
        .unwrap();
        let plan = Plan {
            sample: Some(sample.clone()),
            compromise: None,
            ..local_plan()
        };
        let summary = w.run(&plan).await;
        schedule(&signer);
        schedule(&signer);
        let json = serde_json::to_value(&summary).unwrap();
        let domain = Digest(
            <[u8; 32]>::try_from(
                b64url_decode(json["sample"]["domain"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        );
        let client = String::from(json["test_user"]["client_id"].as_str().unwrap());
        let action = sample.action_ref();
        let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
        // §11.11.2 (e)
        let confidential_key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
        let admin = b.admin(&ids, None);
        let confidential_id = admin.new_client_id().await.unwrap();
        let confidential = String::from(confidential_id.as_str());
        b.change(
            &admin,
            (route.tenant, route.realm),
            domain,
            &root_key(&w.keys).unwrap(),
            Change::ClientRegister(access_identity_admin::domain::Client {
                id: confidential_id,
                display_name: String::from("Agent client"),
                auth: AuthMethod::PrivateKeyJwtKey {
                    key: PublicKey::P256(confidential_key.public_key().as_ref().to_vec()),
                },
                redirect_uris: vec![RedirectUri::parse("https://agent.access.test/cb").unwrap()],
                post_logout_redirect_uris: Vec::new(),
                backchannel_logout_uri: None,
                require_par: false,
                platform: None,
                subject: access_identity_admin::domain::Subject::default(),
                third_party: false,
            }),
        )
        .await
        .unwrap();
        let agent = |label: &str| {
            let key = token_key(&w.keys, label).unwrap();
            let public = key.public_key();
            Agent {
                party: root_party(&public),
                key,
                public,
            }
        };
        let p = agent(SUBJECT_LABEL);
        let (a1, a2, stranger) = (
            agent("l2-agent-1"),
            agent("l2-agent-2"),
            agent("l2-stranger"),
        );
        for (n, a) in [&a1, &a2, &stranger].into_iter().enumerate() {
            enroll(&w, (route.tenant, route.realm), domain, a, n).await;
        }
        let root = root_key(&w.keys).unwrap();
        // §9.9.4, AG-26
        let g0 = issue(
            &w,
            domain,
            &root,
            None,
            p.party,
            delegated(&action, 2, None),
            (BTreeSet::from([Capacity::Own]), Capacity::Own),
        )
        .await;
        let g1 = issue(
            &w,
            domain,
            &p.key,
            Some(g0),
            a1.party,
            delegated(&action, 1, Some(a2.party)),
            (BTreeSet::from([Capacity::For(p.party)]), Capacity::Own),
        )
        .await;
        let g2 = issue(
            &w,
            domain,
            &a1.key,
            Some(g1),
            a2.party,
            delegated(&action, 0, Some(a2.party)),
            (
                BTreeSet::from([Capacity::For(p.party)]),
                Capacity::For(p.party),
            ),
        )
        .await;
        let stranger_own = issue(
            &w,
            domain,
            &root,
            None,
            stranger.party,
            delegated(&action, 0, None),
            (BTreeSet::from([Capacity::Own]), Capacity::Own),
        )
        .await;
        w.domains.release().await;
        crate::jobs::open_now(&w.db.app, &w.db.archive, name).await;
        let day = u32::try_from(now_ms() / 86_400_000).unwrap();
        for d in [day - 1, day, day + 1] {
            access_store::dpop::open_dpop_replay_day(&w.db.archive, d)
                .await
                .unwrap();
        }
        let ids = std::sync::Arc::new(crate::ids::CellIds::new(w.keys.clone()));
        let oauth = access_http::oauth::router(OAuth::new(crate::oauth::ServerEnv {
            client_certificates: Arc::new(
                access_identity_oauth::ports::profile::NoClientCertificates,
            ),
            db: PgOAuth::with_reader(w.db.app.clone(), w.db.reader.clone()),
            signer: SignerKeys::new(w.identity_signer.clone()),
            client_keys: HttpClientKeys::new(
                Outbound::disabled(Duration::from_secs(5)),
                CachePolicy::default(),
            ),
            documents: access_identity_oauth::adapters::cimd::HttpClientDocuments::new(
                Outbound::disabled(Duration::from_secs(5)),
            ),
            directory: PgDirectory::new(w.db.router.clone()),
            app: w.db.app.clone(),
            nonces: crate::oauth::HsmNonces::new(w.keys.clone()),
            dpop: DpopProfile::default(),
            projections: w.plane.clone(),
            issuers: std::sync::Arc::new(w.plane.clone()),
            bundles: std::sync::Arc::new(access_identity_attest::ports::NoBundles),
            workload_trust: std::sync::Arc::new(w.plane.clone()),
            standing: std::sync::Arc::new(w.plane.clone()),
            tenant_ids: ids,
            hooks: std::sync::Arc::new(access_identity_hooks::ports::NoHooks),
            management: std::sync::Arc::new(crate::admin::tokens::PlaneHolders(
                w.plane.clone(),
                None,
            )),
            claims: std::sync::Arc::new(access_identity_oauth::ports::oauth::NoClaims),
            ciba: std::sync::Arc::new(access_identity_oauth::ports::oauth::NoCiba),
            geo: std::sync::Arc::new(access_identity_oauth::ports::oauth::NoGeo),
        }));
        Self {
            w,
            oauth,
            domain,
            action,
            client,
            p,
            a1,
            a2,
            stranger,
            g0,
            g1,
            g2,
            stranger_own,
            idp,
            confidential: (confidential, confidential_key),
            nonce: std::sync::Mutex::new(None),
        }
    }

    fn details(&self) -> String {
        format!(
            r#"[{{"type":"{}:{}:{}","kind":"bounds","schema":"{}"}}]"#,
            self.action.namespace,
            self.action.name,
            self.action.major,
            digest_text(&self.action.schema)
        )
    }

    /// `agent`'s signed `projection.issue` of the sample action for `audience` on `basis` in
    /// `capacity`, the AS as PEP, living `life_ms`.
    async fn exercise(
        &self,
        agent: &Agent,
        audience: &str,
        basis: HoldingRef,
        capacity: Capacity,
        life_ms: u64,
    ) -> (TokenExercise, Payload) {
        let now = server_time(&self.w.db.app).await.unwrap();
        let mut bounds = authority(
            BTreeSet::from([self.action.clone()]),
            "work",
            BTreeSet::new(),
        );
        bounds.constraints.validity = Window {
            from: now - 1_000,
            until: now + life_ms,
        };
        let payload = Payload::ProjectionIssue {
            bounds,
            audience: BTreeSet::from([audience.to_owned()]),
            class: ProfileClass::Online,
            variant: ProfileVariant::OnlineStrict,
            max_staleness_ms: None,
            offline_slice: None,
        };
        let validity = Window {
            from: now - 60_000,
            until: now + 600_000,
        };
        let intent = self_signed_intent(&payload, agent.party, validity).unwrap();
        let nonce = nonce16();
        let basis = ExerciseBasis::Holding(basis);
        let ais = sign(
            &agent.key,
            &Statement {
                domain: self.domain,
                nonce: nonce.clone(),
                intent: intent_digest(&intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(ISSUER),
                capacity,
                basis,
                iat: now,
                exercise: None,
            },
        )
        .unwrap();
        let e = TokenExercise {
            domain: self.domain,
            nonce,
            intent,
            payload_bytes: payload.to_bytes().unwrap(),
            payload: payload.clone(),
            basis,
            capacity,
            ais,
            target: None,
        };
        (e, payload)
    }

    /// P's own bounds token for the MCP server, decided and signed by the authority plane:
    /// the token P's client presents to the MCP server (A2).
    pub(super) async fn subject_token(&self, issuer: &str) -> String {
        let (e, payload) = self
            .exercise(&self.p, RS, self.g0, Capacity::Own, 240_000)
            .await;
        let mut e = e;
        e.ais = sign(
            &self.p.key,
            &Statement {
                domain: self.domain,
                nonce: e.nonce.clone(),
                intent: intent_digest(&e.intent).unwrap(),
                mode: Mode::Commit,
                pep: String::from(IDENTITY_PEP),
                capacity: Capacity::Own,
                basis: e.basis,
                iat: server_time(&self.w.db.app).await.unwrap(),
                exercise: None,
            },
        )
        .unwrap();
        let issued = self
            .w
            .plane
            .issue(TokenProjectionRequest {
                domain: self.domain,
                nonce: e.nonce,
                intent: e.intent,
                payload: payload.to_bytes().unwrap(),
                basis: e.basis,
                capacity: Capacity::Own,
                ais: e.ais,
                pep: String::from(IDENTITY_PEP),
                issuer: String::from(issuer),
                client_id: self.client.clone(),
                kind: TokenKind::Bounds,
                target: None,
                confirmation: Confirmation::DpopJkt(self.p.jkt()),
                resources: vec![String::from(RS)],
                family: None,
                profile: TokenProfile::default(),
            })
            .await
            .unwrap();
        let TokenProjection::Issued(t) = issued else {
            panic!("{issued:?}");
        };
        t.token
    }

    /// One `POST /token` by `agent` with `pairs`, a DPoP proof and the nonce retry.
    async fn token(&self, agent: &Agent, pairs: &[(&str, &str)]) -> (StatusCode, JsonValue) {
        let mut nonce: Option<String> = self.nonce.lock().unwrap().clone();
        for _ in 0..2 {
            let p = proof(
                agent,
                &ProofFor {
                    method: "POST",
                    uri: &format!("{ISSUER}/token"),
                    access_token: None,
                    nonce: nonce.as_deref(),
                },
                now_ms(),
                &Csprng,
            )
            .unwrap();
            let req = HttpRequest::post(TOKEN)
                .header(header::HOST, "access.test")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header("dpop", p)
                .body(Body::from(form(pairs)))
                .unwrap();
            let r = self.oauth.clone().oneshot(req).await.unwrap();
            let status = r.status();
            let fresh = r
                .headers()
                .get("dpop-nonce")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let bytes = to_bytes(r.into_body(), 1 << 20).await.unwrap();
            let body: JsonValue = serde_json::from_slice(&bytes).unwrap_or(JsonValue::Null);
            if let Some(f) = &fresh {
                *self.nonce.lock().unwrap() = Some(f.clone());
            }
            if body["error"] == "use_dpop_nonce" && fresh.is_some() {
                nonce = fresh;
                continue;
            }
            return (status, body);
        }
        panic!("no nonce accepted");
    }

    /// `agent`'s token exchange of `subject` (of `subject_type`) for `audience` on `basis` in
    /// `capacity`, with `extra` pairs.
    pub(super) async fn exchange(
        &self,
        agent: &Agent,
        (subject, subject_type): (&str, &str),
        audience: &str,
        (basis, capacity): (HoldingRef, Capacity),
        extra: &[(&str, &str)],
    ) -> (StatusCode, JsonValue) {
        let (e, _) = self
            .exercise(agent, audience, basis, capacity, 200_000)
            .await;
        let exercise = encode_exercise(&e).unwrap();
        let details = self.details();
        let mut pairs = vec![
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", self.client.as_str()),
            ("subject_token", subject),
            ("subject_token_type", subject_type),
            ("resource", audience),
            ("authorization_details", details.as_str()),
            ("access_exercise", exercise.as_str()),
        ];
        pairs.extend_from_slice(extra);
        self.token(agent, &pairs).await
    }

    /// A `jwt-bearer` request with `assertion` for the upstream, with the Exercise of
    /// `with` when given (by A2 otherwise).
    pub(super) async fn bearer(
        &self,
        assertion: String,
        with: Option<(&Agent, HoldingRef, Capacity)>,
    ) -> (StatusCode, JsonValue) {
        let details = self.details();
        let exercise = match with {
            Some((a, h, c)) => {
                Some(encode_exercise(&self.exercise(a, UPSTREAM, h, c, 200_000).await.0).unwrap())
            }
            None => None,
        };
        let mut pairs = vec![
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("client_id", self.client.as_str()),
            ("assertion", assertion.as_str()),
            ("resource", UPSTREAM),
        ];
        if let Some(e) = &exercise {
            pairs.push(("authorization_details", details.as_str()));
            pairs.push(("access_exercise", e.as_str()));
        }
        let agent = with.map_or(&self.a2, |(a, _, _)| a);
        self.token(agent, &pairs).await
    }
}

pub(super) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const JWT_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";

// AGI-1, AGI-7, P53, AG-23, AG-25, L22, L24, P48, INV-5, §9.9.3 k.9, §9.9.4, §11.10.2, §12.1.3 k.11,
// OP-154 m.3 (m), Ek B 4150, 4151, 4152, 4153, 4211, 4213, 4215, 4302, 4323, 4395, 4429, 4608
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exchange_writes_act_from_the_lineage_only() {
    let r = Realm::open("l2-exchange").await;
    let subject = r.subject_token(ISSUER).await;
    let held = claims_of(&subject);
    assert!(held.get("act").is_none());

    let (status, body) = r
        .exchange(
            &r.a2,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["issued_token_type"], ACCESS_TOKEN_TYPE);
    assert_eq!(body["token_type"], "DPoP");
    let token = body["access_token"].as_str().unwrap();
    // L24, P48
    assert_ne!(token, subject);
    let c = claims_of(token);
    assert_eq!(c["aud"], UPSTREAM);
    assert_eq!(c["cnf"]["jkt"], b64url_encode(&r.a2.jkt()));
    assert_eq!(c["client_id"], r.client.as_str());
    assert_eq!(c["sub"], held["sub"]);
    let chain = act_chain(&c);
    assert_eq!(chain.len(), 2, "{c}");
    assert_ne!(chain[0], chain[1]);
    assert!(c.get("may_act").is_none());
    assert!(c.get("agent_instance_id").is_none());
    // §9.9.4
    let (status, body) = r
        .exchange(
            &r.a1,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g1, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let first = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(act_chain(&first), [chain[1].clone()]);
    assert_eq!(first["may_act"]["sub"].as_str(), Some(chain[0].as_str()));

    // AGI-1, AG-29
    let now_s = now_ms() / 1000;
    let forged = idp_jwt(
        &r.idp,
        "JWT",
        &json!({
            "iss": IDP, "aud": ISSUER, "sub": "u-1", "jti": "forged-1",
            "iat": now_s, "exp": now_s + 120,
            "act": { "sub": "mallory", "act": { "sub": "eve", "act": { "sub": "trent" } } },
        }),
    );
    let (status, body) = r
        .exchange(
            &r.a2,
            (&forged, JWT_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let out = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(act_chain(&out), chain);
    assert!(!out.to_string().contains("mallory"));

    // AG-22, §11.9.4, OP-154 m.3 (h), Ek B 4207
    let (e, _) = r
        .exercise(&r.a2, UPSTREAM, r.g2, Capacity::For(r.p.party), 16 * 60_000)
        .await;
    let long = encode_exercise(&e).unwrap();
    let details = r.details();
    let (_, body) = r
        .token(
            &r.a2,
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("client_id", r.client.as_str()),
                ("subject_token", forged.as_str()),
                ("subject_token_type", JWT_TYPE),
                ("resource", UPSTREAM),
                ("authorization_details", details.as_str()),
                ("access_exercise", long.as_str()),
            ],
        )
        .await;
    assert_eq!(body["access_error"], "projection-horizon", "{body}");

    // AG-18, PI-11, P48, Ek B 4432
    let (e, _) = r
        .exercise(&r.a2, UPSTREAM, r.g2, Capacity::For(r.p.party), 200_000)
        .await;
    let bearer = HttpRequest::post(TOKEN)
        .header(header::HOST, "access.test")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(form(&[
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:token-exchange",
            ),
            ("client_id", r.client.as_str()),
            ("subject_token", subject.as_str()),
            ("subject_token_type", ACCESS_TOKEN_TYPE),
            ("resource", UPSTREAM),
            ("authorization_details", details.as_str()),
            ("access_exercise", encode_exercise(&e).unwrap().as_str()),
        ])))
        .unwrap();
    let answer = r.oauth.clone().oneshot(bearer).await.unwrap();
    assert_eq!(answer.status(), StatusCode::BAD_REQUEST);
    let refused: JsonValue =
        serde_json::from_slice(&to_bytes(answer.into_body(), 1 << 20).await.unwrap()).unwrap();
    assert_eq!(refused["error"], "invalid_dpop_proof", "{refused}");

    // §11.10.2, Ek B 4395
    let other = r.subject_token(ISSUER).await;
    let (status, body) = r
        .exchange(
            &r.stranger,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.stranger_own, Capacity::For(r.p.party)),
            &[
                ("actor_token", other.as_str()),
                ("actor_token_type", ACCESS_TOKEN_TYPE),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_grant", "{body}");

    // AG-26
    let (e, _) = r
        .exercise(&r.a2, UPSTREAM, r.g2, Capacity::For(r.p.party), 600_000)
        .await;
    let long = encode_exercise(&e).unwrap();
    let details = r.details();
    let (status, body) = r
        .token(
            &r.a2,
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                ("client_id", r.client.as_str()),
                ("subject_token", subject.as_str()),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                ("resource", UPSTREAM),
                ("authorization_details", details.as_str()),
                ("access_exercise", long.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_scope");

    // §12.1.3 k.11
    let foreign = r.subject_token("https://access.test/realms/other").await;
    let (_, body) = r
        .exchange(
            &r.a2,
            (&foreign, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // OP-154 m.3 (m), OP-155 m.3 (k)
    let (_, body) = r
        .exchange(
            &r.a2,
            ("PHNhbWw+", "urn:ietf:params:oauth:token-type:saml2"),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    assert_eq!(body["error"], "unauthorized_client", "{body}");

    // INV-5
    let exchanged = String::from(token);
    let plane_active = |t: String| {
        let plane = r.w.plane.clone();
        let domain = r.domain;
        async move { plane.introspect(domain, t).await.unwrap().active }
    };
    assert!(plane_active(exchanged.clone()).await);
    commit(
        &r.w,
        r.domain,
        &r.p.key,
        r.a1.party,
        (ExerciseBasis::Holding(r.g0), Capacity::Own),
        Payload::GrantRevoke { grant: r.g1.grant },
    )
    .await;
    r.w.domains.release().await;
    assert!(!plane_active(exchanged).await);
    let (_, body) = r
        .exchange(
            &r.a2,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[],
        )
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

// EI-6, AGI-7, AG-29, MD-18, L25, E26, §11.11.3, §11.11.4, Ek B 4135, 4189, 4190, 4551, 4563
// OP-154 m.3 (n), (q), Ek B 4635, 4652
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_assertion_is_claim_input_used_once_and_never_a_grant() {
    let r = Realm::open("l2-jwt-bearer").await;
    let now_s = now_ms() / 1000;
    let jag = |jti: &str| {
        idp_jwt(
            &r.idp,
            "oauth-id-jag+jwt",
            &json!({
                "iss": IDP, "aud": ISSUER, "sub": "U019488227", "client_id": r.client,
                "jti": jti, "iat": now_s, "exp": now_s + 240, "resource": UPSTREAM,
                "email": "user@example.com", "scope": "work.approve",
            }),
        )
    };
    // EI-6, Ek B 4635
    let (status, body) = r.bearer(jag("j-1"), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // AG-29
    let (_, body) = r
        .bearer(jag("j-1"), Some((&r.a2, r.g2, Capacity::For(r.p.party))))
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // EI-6
    let (_, body) = r
        .bearer(
            jag("j-2"),
            Some((&r.stranger, r.stranger_own, Capacity::For(r.p.party))),
        )
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    let (status, body) = r
        .bearer(jag("j-3"), Some((&r.a2, r.g2, Capacity::For(r.p.party))))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let c = claims_of(body["access_token"].as_str().unwrap());
    assert_eq!(c["aud"], UPSTREAM);
    assert_eq!(act_chain(&c).len(), 2);
    // E26
    assert!(!c.to_string().contains("user@example.com"));
    assert!(!c.to_string().contains("U019488227"));
    let (_, body) = r
        .bearer(jag("j-3"), Some((&r.a2, r.g2, Capacity::For(r.p.party))))
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // AG-29
    let theirs = idp_jwt(
        &r.idp,
        "oauth-id-jag+jwt",
        &json!({
            "iss": IDP, "aud": ISSUER, "sub": "U1", "client_id": "cli_someone_else",
            "jti": "j-4", "iat": now_s, "exp": now_s + 240,
        }),
    );
    let (_, body) = r
        .bearer(theirs, Some((&r.a2, r.g2, Capacity::For(r.p.party))))
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
    // §11.11.4
    let (_, body) = {
        let a = jag("j-5");
        let details = r.details();
        let e = encode_exercise(
            &r.exercise(&r.a2, RS, r.g2, Capacity::For(r.p.party), 200_000)
                .await
                .0,
        )
        .unwrap();
        r.token(
            &r.a2,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("client_id", r.client.as_str()),
                ("assertion", a.as_str()),
                ("resource", RS),
                ("authorization_details", details.as_str()),
                ("access_exercise", e.as_str()),
            ],
        )
        .await
    };
    assert_eq!(body["error"], "invalid_target", "{body}");
    // L25, Ek B 4135, 4652
    let workload = idp_jwt(
        &r.idp,
        "JWT",
        &json!({
            "iss": IDP, "aud": ISSUER, "sub": "arn:aws:iam::123456789012:role/agent",
            "jti": "w-1", "iat": now_s, "exp": now_s + 240,
        }),
    );
    let (status, body) = r
        .bearer(workload, Some((&r.a2, r.g2, Capacity::For(r.p.party))))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let stranger = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    let unknown = idp_jwt(
        &stranger,
        "JWT",
        &json!({
            "iss": "https://unknown.example", "aud": ISSUER, "sub": "x",
            "jti": "u-1", "iat": now_s, "exp": now_s + 240,
        }),
    );
    let (_, body) = r
        .bearer(unknown, Some((&r.a2, r.g2, Capacity::For(r.p.party))))
        .await;
    assert_eq!(body["error"], "invalid_grant", "{body}");
}

// OP-154 m.3 (n), (o), §11.11.2 (e), §11.12.3, Ek B 4155, 4401, 4653
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_tokens_are_audit_context_and_id_jags_need_a_strong_client() {
    let r = Realm::open("l2-txn").await;
    let subject = r.subject_token(ISSUER).await;
    let (status, body) = r
        .exchange(
            &r.a2,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[(
                "requested_token_type",
                "urn:ietf:params:oauth:token-type:txn_token",
            )],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["token_type"], "N_A");
    assert_eq!(body["expires_in"], 60);
    let txn = String::from(body["access_token"].as_str().unwrap());
    assert_eq!(header_of(&txn)["typ"], "txntoken+jwt");
    let c = claims_of(&txn);
    assert_eq!(c["tctx"]["exercise"], claims_of(&subject)["jti"]);
    assert!(c.get("authorization_details").is_none() && c.get("cnf").is_none());
    for kind in [
        JWT_TYPE,
        ACCESS_TOKEN_TYPE,
        "urn:ietf:params:oauth:token-type:txn_token",
    ] {
        let (status, body) = r
            .exchange(
                &r.a2,
                (&txn, kind),
                UPSTREAM,
                (r.g2, Capacity::For(r.p.party)),
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{kind} {body}");
    }
    // §11.11.2 (e)
    let (_, body) = r
        .exchange(
            &r.a2,
            (&subject, ACCESS_TOKEN_TYPE),
            UPSTREAM,
            (r.g2, Capacity::For(r.p.party)),
            &[
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:id-jag",
                ),
                ("audience", "https://as.upstream.access.test"),
            ],
        )
        .await;
    assert_eq!(body["error"], "unauthorized_client", "{body}");

    // MD-18, L6, §11.11.2, Ek B 4188, 4402
    let (id, key) = &r.confidential;
    let now_s = now_ms() / 1000;
    let header = json!({ "alg": "ES256", "typ": "JWT" });
    let claims = json!({
        "iss": id, "sub": id, "aud": ISSUER, "iat": now_s, "exp": now_s + 60,
        "jti": b64url_encode(&nonce16()),
    });
    let input = format!(
        "{}.{}",
        b64url_encode(header.to_string().as_bytes()),
        b64url_encode(claims.to_string().as_bytes())
    );
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    let assertion = format!("{input}.{}", b64url_encode(sig.as_ref()));
    let fresh = || {
        let claims = json!({
            "iss": id, "sub": id, "aud": ISSUER, "iat": now_s, "exp": now_s + 60,
            "jti": b64url_encode(&nonce16()),
        });
        let input = format!(
            "{}.{}",
            b64url_encode(header.to_string().as_bytes()),
            b64url_encode(claims.to_string().as_bytes())
        );
        let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        format!("{input}.{}", b64url_encode(sig.as_ref()))
    };
    let (e, _) = r
        .exercise(&r.a2, UPSTREAM, r.g2, Capacity::For(r.p.party), 200_000)
        .await;
    let exercise = encode_exercise(&e).unwrap();
    let details = r.details();
    let resource_as = "https://as.upstream.access.test";
    let ask = |exercise: String, assertion: String| {
        let (id, details, subject) = (id.clone(), details.clone(), subject.clone());
        let r = &r;
        async move {
            r.token(
                &r.a2,
                &[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    (
                        "client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    ),
                    ("client_assertion", assertion.as_str()),
                    ("client_id", id.as_str()),
                    ("subject_token", subject.as_str()),
                    ("subject_token_type", ACCESS_TOKEN_TYPE),
                    (
                        "requested_token_type",
                        "urn:ietf:params:oauth:token-type:id-jag",
                    ),
                    ("audience", resource_as),
                    ("resource", UPSTREAM),
                    ("scope", "work.approve"),
                    ("authorization_details", details.as_str()),
                    ("access_exercise", exercise.as_str()),
                ],
            )
            .await
        }
    };
    // AG-28, OP-154 m.3 (n), Ek B 4191
    let (status, refused) = ask(exercise.clone(), fresh()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "invalid_target", "{refused}");
    r.cross_app(Change::CrossAppConnection(
        access_identity_admin::domain::CrossAppConnection {
            name: String::from("upstream"),
            client_id: id.clone(),
            audience: String::from("https://as.upstream.access.test/other"),
            resource: String::from(UPSTREAM),
            scopes: vec![String::from("work.approve")],
        },
    ))
    .await;
    let (status, refused) = ask(exercise.clone(), fresh()).await;
    assert_eq!(refused["error"], "invalid_target", "{status} {refused}");
    r.cross_app(Change::CrossAppConnectionRetire(String::from("upstream")))
        .await;
    r.cross_app(Change::CrossAppConnection(
        access_identity_admin::domain::CrossAppConnection {
            name: String::from("upstream"),
            client_id: id.clone(),
            audience: String::from(resource_as),
            resource: String::from(UPSTREAM),
            scopes: vec![String::from("work.approve")],
        },
    ))
    .await;
    let (status, body) = r
        .token(
            &r.a2,
            &[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:token-exchange",
                ),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
                ("client_id", id.as_str()),
                ("subject_token", subject.as_str()),
                ("subject_token_type", ACCESS_TOKEN_TYPE),
                (
                    "requested_token_type",
                    "urn:ietf:params:oauth:token-type:id-jag",
                ),
                ("audience", resource_as),
                ("resource", UPSTREAM),
                ("scope", "work.approve"),
                ("authorization_details", details.as_str()),
                ("access_exercise", exercise.as_str()),
            ],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["issued_token_type"],
        "urn:ietf:params:oauth:token-type:id-jag"
    );
    assert_eq!(body["token_type"], "N_A");
    let jag = body["access_token"].as_str().unwrap();
    assert_eq!(header_of(jag)["typ"], "oauth-id-jag+jwt");
    let c = claims_of(jag);
    assert_eq!(c["iss"], ISSUER);
    assert_eq!(c["aud"], resource_as);
    assert_eq!(c["client_id"], id.as_str());
    assert_eq!(c["resource"], UPSTREAM);
    assert_eq!(c["sub"], claims_of(&subject)["sub"]);
    assert!(c["exp"].as_u64().unwrap() - c["iat"].as_u64().unwrap() <= 300);
    for authority in ["authorization_details", "act", "cnf", "access_contract"] {
        assert!(c.get(authority).is_none(), "{authority} in {c}");
    }

    // OP-73, Ek B 4191
    r.cross_app(Change::CrossAppConnectionRetire(String::from("upstream")))
        .await;
    let (e, _) = r
        .exercise(&r.a2, UPSTREAM, r.g2, Capacity::For(r.p.party), 200_000)
        .await;
    let (status, refused) = ask(encode_exercise(&e).unwrap(), fresh()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    assert_eq!(refused["error"], "invalid_target", "{refused}");
}

impl Realm {
    /// Commits an `idp.client.cross_app_connection*` change as the realm's root.
    async fn cross_app(&self, change: Change) {
        let declared = DeclaredTargets::default();
        let b = Bootstrap {
            app: &self.w.db.app,
            router: &self.w.db.router,
            plane: &self.w.plane,
            realm_keys: &self.w.keyring,
            hsm: &self.w.keys,
            base: &self.w.base,
            declared: &declared,
            console: None,
        };
        let route = route_by_slug(&self.w.db.router, "acme")
            .await
            .unwrap()
            .unwrap();
        let ids = cell_ids(&self.w.db.app, &self.w.keys).await.unwrap();
        b.change(
            &b.admin(&ids, None),
            (route.tenant, route.realm),
            self.domain,
            &root_key(&self.w.keys).unwrap(),
            change,
        )
        .await
        .unwrap();
    }
}
