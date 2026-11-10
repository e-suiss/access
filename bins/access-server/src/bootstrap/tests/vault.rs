//! The token vault against the real server path (OP-154 m.3 (t), OP-153 m.3 (gg)): a
//! bootstrapped realm whose Resource is enabled by a committed `idp.vault.resource_enable`; a
//! person connects an account through the real frontend router with their session, after a
//! consent record for the agent client; the upstream's token endpoint is a scripted stand-in
//! behind the provider port. Exercises are committed through the real ADP router with the
//! executor as transport-authenticated PEP, on the real sequencer and `SoftHSM`, and every
//! release goes through `POST /v1/vault/releases`.

#![allow(
    clippy::too_many_lines,
    reason = "test code: one walk through the vault's rules"
)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Mutex as StdMutex;

use access_crypto::Secret;
use access_http::adp::adapters::{Discovery, Pep as PepId, router as adp_router};
use access_identity_account::app::sealing::new_subject_key;
use access_identity_admin::domain::Change;
use access_identity_federation::ports::{Answer, ProviderHttp, SocialSecrets, Unreachable};
use access_identity_vault::app::Vault;
use access_identity_vault::domain::catalog::Catalog;
use access_identity_vault::domain::resource::{MappedAction, Origin, Resource, VaultChange};
use access_kernel::intent::IntentEnvelope;
use access_kernel::json::b64url_decode;
use access_sdk::authorize::{Actor as SdkActor, ExerciseRequest, adp_body};
use access_store::clients::NewConsentRecord;
use access_store::identity::TenantTx;
use axum::body::Body;
use axum::http::{Method, Request as HttpRequest, StatusCode, header};

use super::management::send;
use super::recovery::Recording;
use super::*;

/// The registered executor's PEP identity, as its client certificate names it.
pub(super) const EXECUTOR: &str = "ZXhlY3V0b3ItY2VydGlmaWNhdGUtdGh1bWJwcmludDA";
/// A PEP that is not this Resource's executor.
const OTHER_PEP: &str = "b3RoZXItcGVwLWNlcnRpZmljYXRlLXRodW1icHJpbnQ";
const GMAIL_SEND: &str = "https://www.googleapis.com/auth/gmail.send";

/// The upstream's token endpoint: scripted answers, in order, and the forms it was sent.
#[derive(Default)]
pub(super) struct Upstream {
    pub(super) answers: StdMutex<VecDeque<(u16, String)>>,
    forms: StdMutex<Vec<String>>,
}

/// The provider port over the shared script.
struct Scripted(Arc<Upstream>);

impl ProviderHttp for Scripted {
    fn get_json(
        &self,
        _: &str,
        _: Option<&str>,
    ) -> impl Future<Output = Result<Answer, Unreachable>> + Send {
        std::future::ready(Err(Unreachable))
    }

    fn post_form(
        &self,
        url: &str,
        form: &str,
    ) -> impl Future<Output = Result<Answer, Unreachable>> + Send {
        self.0.forms.lock().unwrap().push(format!("{url} {form}"));
        let next = self.0.answers.lock().unwrap().pop_front();
        std::future::ready(next.map(|(s, b)| (s, b.into_bytes())).ok_or(Unreachable))
    }
}

struct Secrets;

impl SocialSecrets for Secrets {
    fn secret(&self, _: &str) -> impl Future<Output = Result<Secret<String>, Unreachable>> + Send {
        std::future::ready(Ok(Secret::new(String::from("upstream-client-secret"))))
    }
}

/// The breach corpus lists nothing.
struct Clean;

impl access_identity_risk::ports::BreachProbe for Clean {
    fn check<'a>(
        &'a self,
        _: &'a access_identity_account::domain::password::Password,
    ) -> access_identity_risk::ports::BoxFuture<'a, access_identity_risk::domain::assess::Breach>
    {
        Box::pin(async { access_identity_risk::domain::assess::Breach::Clean })
    }
}

fn hasher() -> access_identity_account::app::hasher::Hasher {
    use access_identity_account::adapters::system::{cgroup_memory_budget, cores};
    use access_identity_account::app::hasher::{Hasher, HasherConfig};
    use access_identity_account::domain::password::Argon2Params;
    Hasher::new(HasherConfig::sized(
        Argon2Params::CANONICAL,
        cores(),
        cgroup_memory_budget(),
    ))
}

fn work(path: &str) -> ResourceRef {
    ResourceRef {
        namespace: String::from("work"),
        path: vec![String::from(path)],
        incarnation: 0,
    }
}

pub(super) struct Lab {
    pub(super) w: World,
    pub(super) pages: axum::Router,
    pub(super) adp: axum::Router,
    pub(super) upstream: Arc<Upstream>,
    pub(super) domain: Digest,
    pub(super) route: access_store::tenancy::RealmRoute,
    pub(super) action: ActionRef,
    pub(super) person: HsmSigner,
    pub(super) party: Id,
    pub(super) holding: HoldingRef,
    pub(super) subject: [u8; 16],
    pub(super) client: String,
    cookies: BTreeMap<String, String>,
}

/// Commits the root's `grant_issue` of `authority` to `holder` on the meta-anchor.
async fn grant(w: &World, domain: Digest, holder: Id, authority: CanonicalAuthority) -> HoldingRef {
    let root = root_key(&w.keys).unwrap();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&domain));
    grant_content(
        w,
        (domain, &root, basis),
        holder,
        grant_of(&domain, holder, authority),
    )
    .await
}

/// Commits `grantor`'s `grant_issue` of `content` to `holder` on `basis`.
async fn grant_content(
    w: &World,
    (domain, grantor, basis): (Digest, &HsmSigner, ExerciseBasis),
    holder: Id,
    content: GrantContent,
) -> HoldingRef {
    let payload = Payload::GrantIssue(content);
    let now = server_time(&w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, holder, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let ais = sign(
        grantor,
        &Statement {
            domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
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

impl Lab {
    pub(super) async fn open(name: &str) -> Self {
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
        let person = token_key(&w.keys, SUBJECT_LABEL).unwrap();
        let party = root_party(&person.public_key());
        let holding = grant(
            &w,
            domain,
            party,
            authority(BTreeSet::from([action.clone()]), "work", BTreeSet::new()),
        )
        .await;
        let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
        let client = register_client(&w, (route.tenant, route.realm), domain).await;
        let keks = crate::login::RealmKeks::new(Arc::clone(&w.keys));
        let kek = keks.vault(route.realm).unwrap().kek;
        let ids = crate::ids::CellIds::new(w.keys.clone()).key().unwrap();
        let realm = access_identity_account::app::Realm {
            tenant: route.tenant,
            realm: route.realm,
            kek: &*kek,
            ids: &ids,
        };
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let subject = t
            .insert_subject("active", kek.id(), &new_subject_key(&realm).unwrap())
            .await
            .unwrap();
        let bound = access_store::idp::bind_subject_party(&mut t, &subject, &party.0)
            .await
            .unwrap();
        assert!(bound);
        t.commit().await.unwrap();
        let upstream = Arc::new(Upstream::default());
        let pages = Self::pages(&w, Arc::clone(&upstream));
        let adp = adp_router(
            access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
            Discovery {
                issuer: String::from("https://access.test"),
            },
        );
        let mut lab = Self {
            w,
            pages,
            adp,
            upstream,
            domain,
            route,
            action,
            person,
            party,
            holding,
            subject,
            client,
            cookies: BTreeMap::new(),
        };
        lab.sign_in().await;
        lab
    }

    fn pages(w: &World, upstream: Arc<Upstream>) -> axum::Router {
        access_http::login::vault_router(
            access_identity_oauth::app::Discovery::new(
                access_identity_oauth::adapters::PgDirectory::new(w.db.router.clone()),
                SignerKeys::new(w.identity_signer.clone()),
            ),
            Self::hosted(w),
            Vault {
                catalog: Catalog::shipped().unwrap(),
                http: Scripted(upstream),
                secrets: Secrets,
                exercises: w.plane.clone(),
                random: crate::idp::vault::OsRandom,
            },
        )
    }

    /// The realm's hosted pages, as the server builds them.
    pub(super) fn hosted(
        w: &World,
    ) -> Arc<
        access_identity_ui::app::Hosted<
            crate::login::HsmKits,
            access_identity_account::adapters::system::SystemClock,
            Recording,
        >,
    > {
        use access_identity_account::adapters::system::SystemClock;
        use access_identity_account::app::local::LocalLimiter;
        use access_identity_account::app::login::LoginGate;
        use access_identity_account::domain::throttle::ThrottlePolicy;
        use access_identity_session::domain::session::SessionPolicy;
        use access_identity_ui::app::Hosted;
        let mut risk = access_identity_session::app::RiskServices::without_sources();
        risk.breach = Arc::new(Clean);
        Arc::new(Hosted {
            kits: crate::login::HsmKits::new(
                crate::login::RealmKeks::new(Arc::clone(&w.keys)),
                w.db.router.clone(),
                w.db.app.clone(),
                SessionPolicy::DEFAULT,
            ),
            db: w.db.app.clone(),
            products: w.db.reader.clone(),
            clock: SystemClock,
            messages: Recording::default(),
            gate: LoginGate::new(LocalLimiter::default(), ThrottlePolicy::DEFAULT, 0),
            hasher: hasher(),
            redirect_to: String::from("/"),
            hooks: Arc::new(access_identity_hooks::ports::NoHooks),
            risk,
            signup: access_identity_ui::app::signup::Signup::without_providers().unwrap(),
        })
    }

    /// A live session of the person, as a sign-in leaves it.
    async fn sign_in(&mut self) {
        let value: [u8; 32] = access_crypto::random::bytes().unwrap();
        let at = now_ms();
        let mut t = TenantTx::begin(&self.w.db.app, self.route.tenant, self.route.realm)
            .await
            .unwrap();
        let epoch = t
            .subject(self.subject, false)
            .await
            .unwrap()
            .unwrap()
            .session_epoch;
        t.insert_session(&access_store::sessions::NewSession {
            cookie_hash: &access_identity_session::domain::session::cookie_digest(&value),
            subject: self.subject,
            session_epoch: epoch,
            keep_signed_in: false,
            created_ms: i64::try_from(at).unwrap(),
            auth_time_ms: i64::try_from(at).unwrap(),
            idle_ms: 3_600_000,
            expires_ms: i64::try_from(at + 3_600_000).unwrap(),
            assurance: &serde_json::to_vec(&access_identity_session::domain::assurance::vector(&[
                access_identity_session::domain::assurance::Factor::password(at),
            ]))
            .unwrap(),
        })
        .await
        .unwrap();
        t.commit().await.unwrap();
        self.cookies
            .insert(String::from("__Host-access-session"), b64url_encode(&value));
    }

    /// The person's live consent record for the test client: their AAS for it (AS-M15).
    pub(super) async fn consent(&self) {
        let mut t = TenantTx::begin(&self.w.db.app, self.route.tenant, self.route.realm)
            .await
            .unwrap();
        let c = access_store::idp::client(&mut t, &self.client)
            .await
            .unwrap()
            .unwrap();
        t.put_consent_record(&NewConsentRecord {
            subject: self.subject,
            client: c.client_uuid,
            source: "registered",
            resource: "https://agent.access.test/mcp",
            scopes: &[],
            metadata_hash: [1; 32],
            grant_domain: self.domain.0,
            grant_ref: self.holding.grant.0,
            exercise: [2; 32],
            now_ms: now_ms(),
        })
        .await
        .unwrap();
        t.commit().await.unwrap();
    }

    /// One request of the person's browser to the realm's pages.
    pub(super) async fn page(
        &mut self,
        method: &Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value, axum::http::HeaderMap) {
        let mut b = HttpRequest::builder()
            .method(method.clone())
            .uri(format!("/realms/acme{path}"))
            .header(header::HOST, "access.test");
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        b = b.header(header::COOKIE, cookie);
        if *method != Method::GET {
            b = b
                .header(header::ORIGIN, "https://access.test")
                .header("sec-fetch-site", "same-origin")
                .header(
                    "idempotency-key",
                    b64url_encode(&access_crypto::random::bytes::<16>().unwrap()),
                )
                .header(header::CONTENT_TYPE, "application/json");
        }
        let body = body.map_or_else(Body::empty, |v| Body::from(v.to_string()));
        let (r, bytes) = send(&self.pages, b.body(body).unwrap()).await;
        for c in r.headers().get_all(header::SET_COOKIE) {
            let c = c.to_str().unwrap();
            let (name, value) = c.split(';').next().unwrap().split_once('=').unwrap();
            self.cookies.insert(name.to_owned(), value.to_owned());
        }
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (r.status(), json, r.headers().clone())
    }

    /// `POST /v1/vault/releases`, by `pep` when the transport named one.
    pub(super) async fn release(
        &self,
        pep: Option<&str>,
        body: &serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = HttpRequest::post("/realms/acme/v1/vault/releases")
            .header(header::HOST, "access.test")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        if let Some(p) = pep {
            req.extensions_mut().insert(PepId(p.to_owned()));
        }
        let (r, bytes) = send(&self.pages, req).await;
        (
            r.status(),
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The `work.approve` intent on `work:inbox`, valid for `ms` from now.
    pub(super) fn intent(&self, ms: u64) -> IntentEnvelope {
        let now = now_ms();
        IntentEnvelope {
            provenance: BTreeMap::new(),
            action: self.action.clone(),
            resources: vec![work("inbox")],
            params: BTreeMap::new(),
            opaque: BTreeMap::new(),
            recipient: None,
            purpose: None,
            context: access_kernel::intent::ContextRefs::default(),
            validity: Window {
                from: now - 1_000,
                until: now + ms,
            },
        }
    }

    /// Commits `intent` through the real ADP router with `pep` as the PEP and the person's key as
    /// the actor on `basis`; the Exercise and whether it was allowed.
    async fn commit(
        &self,
        intent: &IntentEnvelope,
        pep: &str,
        basis: HoldingRef,
    ) -> (Digest, bool) {
        self.commit_by(intent, pep, (basis, Capacity::Own), |s| {
            sign(&self.person, s).unwrap()
        })
        .await
    }

    /// [`Self::commit`] by the actor whose key `by` signs, in `capacity`.
    async fn commit_by(
        &self,
        intent: &IntentEnvelope,
        pep: &str,
        (basis, capacity): (HoldingRef, Capacity),
        by: impl Fn(&Statement) -> Vec<u8>,
    ) -> (Digest, bool) {
        let nonce = access_crypto::random::bytes::<16>().unwrap();
        let digest = intent_digest(intent).unwrap();
        let ais = by(&Statement {
            domain: self.domain,
            nonce: nonce.to_vec(),
            intent: digest,
            mode: Mode::Commit,
            pep: String::from(pep),
            capacity,
            basis: ExerciseBasis::Holding(basis),
            iat: now_ms(),
            exercise: None,
        });
        let basis = ExerciseBasis::Holding(basis);
        let body = adp_body(&ExerciseRequest {
            domain: &self.domain,
            mode: Mode::Commit,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(intent),
            actor: &SdkActor::Statement(ais),
            basis: &basis,
            capacity,
            pep,
            exercise: None,
        })
        .unwrap();
        let mut req = HttpRequest::post("/access/v1/evaluation")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(PepId(pep.to_owned()));
        let (r, bytes) = send(&self.adp, req).await;
        let out: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        assert_eq!(r.status(), StatusCode::OK, "{out}");
        let exercise = meta::exercise_id(&self.domain, &nonce).unwrap();
        (exercise, out["decision"] == true)
    }

    pub(super) fn body(
        &self,
        exercise: &Digest,
        intent: &IntentEnvelope,
        connection: &str,
        delivery: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "domain": b64url_encode(&self.domain.0),
            "exercise": b64url_encode(&exercise.0),
            "intent": b64url_encode(&intent.to_bytes().unwrap()),
            "connection": connection,
            "delivery": delivery,
        })
    }

    /// Commits an `idp.vault.*` change as the realm's root.
    pub(super) async fn change(&self, change: VaultChange) {
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
        let ids = cell_ids(&self.w.db.app, &self.w.keys).await.unwrap();
        b.change(
            &b.admin(&ids, None),
            (self.route.tenant, self.route.realm),
            self.domain,
            &root_key(&self.w.keys).unwrap(),
            Change::Vault(change),
        )
        .await
        .unwrap();
    }

    pub(super) fn resource(&self) -> Resource {
        Resource {
            name: String::from("google"),
            origin: Origin::Catalog,
            upstream: Catalog::shipped().unwrap().get("google").unwrap().clone(),
            client_id: String::from("google-client"),
            client_secret_ref: String::from("secret://vault/google"),
            scopes: BTreeSet::from([String::from(GMAIL_SEND)]),
            actions: vec![MappedAction {
                namespace: self.action.namespace.clone(),
                name: self.action.name.clone(),
                major: self.action.major,
                schema: b64url_encode(&self.action.schema.0),
                scopes: BTreeSet::from([String::from(GMAIL_SEND)]),
            }],
            executors: BTreeSet::from([String::from(EXECUTOR)]),
        }
    }

    /// Connects the person's account through the real pages: start, then the upstream's
    /// redirect back with `code`, answered by `answer`.
    pub(super) async fn connect(&mut self, answer: &str) -> String {
        let (status, started, _) = self
            .page(
                &Method::POST,
                "/v1/account/vault/connections",
                Some(serde_json::json!({ "resource": "google", "client_id": self.client })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{started}");
        let to = started["redirect_to"].as_str().unwrap();
        assert!(
            to.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"),
            "{to}"
        );
        assert!(to.contains("code_challenge_method=S256") && to.contains("access_type=offline"));
        let state = to
            .split(['?', '&'])
            .find_map(|p| p.strip_prefix("state="))
            .unwrap()
            .to_owned();
        self.upstream
            .answers
            .lock()
            .unwrap()
            .push_back((200, String::from(answer)));
        let (status, _, headers) = self
            .page(
                &Method::GET,
                &format!("/v1/account/vault/connections?code=the-code&state={state}"),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let location = headers[header::LOCATION].to_str().unwrap();
        assert!(location.contains("/account?connected="), "{location}");
        let form = self.upstream.forms.lock().unwrap().last().cloned().unwrap();
        assert!(
            form.starts_with("https://oauth2.googleapis.com/token "),
            "{form}"
        );
        assert!(form.contains("code_verifier=") && form.contains("code=the-code"));
        String::from(started["connection"].as_str().unwrap())
    }
}

// G59, U65, U66, EI-26, AGI-2, AS-M15, E36, AG-32, AG-40, OP-154 m.3 (t), OP-153 m.3 (gg),
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_leaves_the_vault_only_for_an_allowed_exercise_of_its_executor() {
    let mut l = Lab::open("vault-release").await;
    l.change(VaultChange::Enable(Box::new(l.resource()))).await;

    // AS-M15
    let (status, body, _) = l
        .page(
            &Method::POST,
            "/v1/account/vault/connections",
            Some(serde_json::json!({ "resource": "google", "client_id": l.client })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "vault-consent-required");
    l.consent().await;
    // AG-40 (5)
    let connection = l
        .connect(r#"{"access_token":"at-first","refresh_token":"rt-1","expires_in":120,"token_type":"Bearer"}"#)
        .await;
    let (status, listed, _) = l
        .page(&Method::GET, "/v1/account/vault/connections", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(listed["connections"][0]["status"], "active");
    assert_eq!(listed["connections"][0]["client_id"], l.client.as_str());
    let shown = listed.to_string();
    assert!(
        !shown.contains("at-first") && !shown.contains("rt-1"),
        "{shown}"
    );

    let intent = l.intent(1_200_000);
    let (allowed, ok) = l.commit(&intent, EXECUTOR, l.holding).await;
    assert!(ok);
    let body = l.body(&allowed, &intent, &connection, "executor");

    // AG-40 (3), §11.13
    let (status, r) = l.release(None, &body).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{r}");
    assert_eq!(r["code"], "release-unauthenticated");
    // G59, EI-26
    let unknown = l.body(&Digest([0x42; 32]), &intent, &connection, "executor");
    let (status, r) = l.release(Some(EXECUTOR), &unknown).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-without-exercise");
    // G59
    let other_intent = l.intent(1_100_000);
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(&allowed, &other_intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-without-exercise");
    // EI-26
    let (status, r) = l.release(Some(OTHER_PEP), &body).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-foreign-exercise");
    // G59
    let foreign = HoldingRef {
        holder: Id([0x5a; 16]),
        ..l.holding
    };
    let (denied, ok) = l.commit(&intent, EXECUTOR, foreign).await;
    assert!(!ok);
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(&denied, &intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-without-exercise");
    // AGI-2
    let (theirs, ok) = l.commit(&intent, OTHER_PEP, l.holding).await;
    assert!(ok);
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(&theirs, &intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-foreign-exercise");

    // U66, AG-40 (5)
    l.upstream.answers.lock().unwrap().push_back((
        200,
        String::from(r#"{"access_token":"at-second","expires_in":900}"#),
    ));
    let (status, r) = l.release(Some(EXECUTOR), &body).await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["access_token"], "at-second");
    assert_eq!(r["delivery"], "executor");
    assert_eq!(r["content"], "not-guaranteed");
    assert_eq!(r["tier"], "ct1");
    assert!(r["use_until_ms"].as_u64().unwrap() <= intent.validity.until);
    let refresh = l.upstream.forms.lock().unwrap().last().cloned().unwrap();
    assert!(refresh.contains("grant_type=refresh_token") && refresh.contains("refresh_token=rt-1"));
    let (status, r) = l.release(Some(EXECUTOR), &body).await;
    assert_eq!(status, StatusCode::CONFLICT, "{r}");
    assert_eq!(r["code"], "release-already-used");
    // §11.13 step 4, Ek B 4504, 4219
    let (_, listed, _) = l
        .page(&Method::GET, "/v1/account/vault/connections", None)
        .await;
    assert_eq!(
        listed["connections"][0]["used"][0]["exercise"],
        b64url_encode(&allowed.0)
    );
    assert_eq!(
        listed["connections"][0]["used"][0]["agent"],
        b64url_encode(&l.party.0)
    );

    // U65, AG-40 (4)
    let i2 = l.intent(1_200_000);
    let (e2, _) = l.commit(&i2, EXECUTOR, l.holding).await;
    let (status, r) = l
        .release(Some(EXECUTOR), &l.body(&e2, &i2, &connection, "agent"))
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["delivery"], "executor");
    l.change(VaultChange::ReleaseMode(true)).await;
    let i3 = l.intent(1_200_000);
    let (e3, _) = l.commit(&i3, EXECUTOR, l.holding).await;
    let (status, r) = l
        .release(Some(EXECUTOR), &l.body(&e3, &i3, &connection, "agent"))
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["delivery"], "agent");
    let until = r["use_until_ms"].as_u64().unwrap();
    assert!(until <= i3.validity.until && until <= now_ms() + 3_600_000);
    // U65
    let short = l.intent(300_000);
    let (e4, _) = l.commit(&short, EXECUTOR, l.holding).await;
    let (status, r) = l
        .release(Some(EXECUTOR), &l.body(&e4, &short, &connection, "agent"))
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    assert_eq!(r["delivery"], "executor");
    assert!(r["use_until_ms"].as_u64().unwrap() <= short.validity.until);

    // INV-5, AGI-2
    let i5 = l.intent(1_200_000);
    let (e5, ok) = l.commit(&i5, EXECUTOR, l.holding).await;
    assert!(ok);
    revoke(&l).await;
    let (status, r) = l
        .release(Some(EXECUTOR), &l.body(&e5, &i5, &connection, "executor"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{r}");
    assert_eq!(r["code"], "release-basis-ended");

    // OP-73
    let (status, r, _) = l
        .page(
            &Method::DELETE,
            &format!("/v1/account/vault/connections/{connection}"),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    let id = <[u8; 16]>::try_from(b64url_decode(&connection).unwrap()).unwrap();
    assert!(t.vault_token_set(id).await.unwrap().is_none());
    assert_eq!(
        t.vault_connection(id).await.unwrap().unwrap().status,
        "disconnected"
    );
    t.commit().await.unwrap();
    l.w.domains.release().await;
}

/// Registers the agent client the person consents to.
async fn register_client(
    w: &World,
    (tenant, realm): (TenantId, RealmId),
    domain: Digest,
) -> String {
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
    let ids = cell_ids(&w.db.app, &w.keys).await.unwrap();
    let admin = b.admin(&ids, None);
    let id = admin.new_client_id().await.unwrap();
    let key = suiss_crypto::signer::SoftSigner::generate_p256().unwrap().0;
    b.change(
        &admin,
        (tenant, realm),
        domain,
        &root_key(&w.keys).unwrap(),
        Change::ClientRegister(access_identity_admin::domain::Client {
            id: id.clone(),
            display_name: String::from("Mail agent"),
            auth: AuthMethod::PrivateKeyJwtKey {
                key: suiss_crypto::signer::Signer::public_key(&key),
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
    String::from(id.as_str())
}

/// Revokes the person's Grant as the realm's root.
pub(super) async fn revoke(l: &Lab) {
    revoke_grant(l, l.holding.grant).await;
}

/// Revokes `grant` as the realm's root.
pub(super) async fn revoke_grant(l: &Lab, grant: Id) {
    let root = root_key(&l.w.keys).unwrap();
    let payload = Payload::GrantRevoke { grant };
    let now = server_time(&l.w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, l.party, validity).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&l.domain));
    let ais = sign(
        &root,
        &Statement {
            domain: l.domain,
            nonce: nonce.clone(),
            intent: intent_digest(&intent).unwrap(),
            mode: Mode::Commit,
            pep: String::from(IDENTITY_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now,
            exercise: None,
        },
    )
    .unwrap();
    MetaExercises::lead(&l.w.plane, l.domain).await.unwrap();
    let verdict = MetaExercises::meta(
        &l.w.plane,
        Request {
            domain: l.domain,
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
    assert!(matches!(verdict, Verdict::Committed(_)), "{verdict:?}");
}

// OP-154 m.3 (t), Ek B 4414
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_refresh_needs_the_person_again() {
    let mut l = Lab::open("vault-reconnect").await;
    l.change(VaultChange::Enable(Box::new(l.resource()))).await;
    l.consent().await;
    let connection = l
        .connect(r#"{"access_token":"at-old","refresh_token":"rt-old","expires_in":60}"#)
        .await;
    l.upstream
        .answers
        .lock()
        .unwrap()
        .push_back((400, String::from(r#"{"error":"invalid_grant"}"#)));
    let intent = l.intent(1_200_000);
    let (e, ok) = l.commit(&intent, EXECUTOR, l.holding).await;
    assert!(ok);
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(&e, &intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{r}");
    assert_eq!(r["code"], "release-needs-reconnect");
    let (_, listed, _) = l
        .page(&Method::GET, "/v1/account/vault/connections", None)
        .await;
    assert_eq!(listed["connections"][0]["status"], "needs_reconnect");
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    let id = <[u8; 16]>::try_from(b64url_decode(&connection).unwrap()).unwrap();
    assert!(t.vault_token_set(id).await.unwrap().is_none());
    t.commit().await.unwrap();
    l.w.domains.release().await;
}

// S11, §12.4.1, AG-21, AG-41, AGI-2, OP-154 m.3 (e), (t), OP-153 m.3 (gg), Ek B 4219
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_person_sees_which_agent_used_which_of_their_accounts() {
    let mut l = Lab::open("vault-agents").await;
    l.change(VaultChange::Enable(Box::new(l.resource()))).await;
    l.consent().await;
    let connection = l
        .connect(r#"{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"token_type":"Bearer"}"#)
        .await;
    let (status, empty, _) = l
        .page(&Method::GET, "/v1/account/agent-connections", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{empty}");
    assert_eq!(empty["agents"], serde_json::json!([]), "{empty}");
    assert_eq!(empty["connections"][0]["connection"], connection.as_str());

    let (runtime, _) = super::agent::enrol(&l.w, l.domain).await;
    // OP-154 m.3 (c)
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    t.insert_agent(&access_store::agents::NewAgent {
        party: super::agent::AGENT.0,
        operator: root_party(&root_key(&l.w.keys).unwrap().public_key()).0,
        kind: "cloud",
        display_name: "Mail helper",
        description: None,
        exercise: &[6; 32],
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    // §9.9.4
    let root = root_key(&l.w.keys).unwrap();
    let work = |depth: u64| {
        let mut a = authority(BTreeSet::from([l.action.clone()]), "work", BTreeSet::new());
        a.delegation = DelegationTerms {
            depth,
            downstream_holder_class: Some(SubjectSelector::Party(super::agent::AGENT)),
        };
        a
    };
    let mine = grant_content(
        &l.w,
        (
            l.domain,
            &root,
            ExerciseBasis::Anchor(meta::meta_anchor(&l.domain)),
        ),
        l.party,
        grant_of(&l.domain, l.party, work(1)),
    )
    .await;
    let acting = grant_content(
        &l.w,
        (l.domain, &l.person, ExerciseBasis::Holding(mine)),
        super::agent::AGENT,
        GrantContent {
            basis: GrantBasis::Holding(mine),
            holder: SubjectSelector::Party(super::agent::AGENT),
            authority: work(0),
            agency: BTreeSet::from([Capacity::For(l.party)]),
            named: None,
        },
    )
    .await;
    let intent = l.intent(1_200_000);
    let (allowed, ok) = l
        .commit_by(&intent, EXECUTOR, (acting, Capacity::For(l.party)), |s| {
            super::agent::ais_by(&runtime.0, s).unwrap()
        })
        .await;
    assert!(ok);
    let (status, r) = l
        .release(
            Some(EXECUTOR),
            &l.body(&allowed, &intent, &connection, "executor"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{r}");

    let (status, listed, _) = l
        .page(&Method::GET, "/v1/account/agent-connections", None)
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let agent = &listed["agents"][0];
    assert_eq!(
        agent["agent"],
        b64url_encode(&super::agent::AGENT.0),
        "{listed}"
    );
    assert_eq!(agent["status"], "active", "{listed}");
    assert_eq!(agent["sponsor"], false, "{listed}");
    assert_eq!(
        agent["connections"],
        serde_json::json!([connection]),
        "{listed}"
    );
    assert!(agent["last_used_ms"].as_u64().is_some(), "{listed}");
    assert_eq!(agent["name"], "Mail helper", "{listed}");
    assert_eq!(agent["kind"], "cloud", "{listed}");
    assert_eq!(
        listed["connections"][0]["used"][0]["agent"],
        b64url_encode(&super::agent::AGENT.0)
    );
    let shown = listed.to_string();
    assert!(
        !shown.contains("at-1") && !shown.contains("rt-1"),
        "{shown}"
    );

    // AG-41
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    t.open_sponsorship(super::agent::AGENT.0, l.subject, &[7; 32])
        .await
        .unwrap();
    t.commit().await.unwrap();
    let (_, listed, _) = l
        .page(&Method::GET, "/v1/account/agent-connections", None)
        .await;
    assert_eq!(listed["agents"][0]["sponsor"], true, "{listed}");
    assert_eq!(listed["agents"].as_array().unwrap().len(), 1, "{listed}");

    l.cookies.clear();
    let (status, _, _) = l
        .page(&Method::GET, "/v1/account/agent-connections", None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    l.w.domains.release().await;
}

// E56, MD-10, OP-154 m.3 (aa), OP-153 m.3 (gg), Ek B 4329
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_did_web_document_names_the_live_keys_of_a_bound_party_only() {
    let l = Lab::open("did-web").await;
    let did = access_http::login::did_router(
        access_identity_oauth::app::Discovery::new(
            access_identity_oauth::adapters::PgDirectory::new(l.w.db.router.clone()),
            SignerKeys::new(l.w.identity_signer.clone()),
        ),
        Lab::hosted(&l.w),
        l.w.plane.clone(),
    );
    let get = |party: String| {
        let did = did.clone();
        async move {
            let req = HttpRequest::get(format!("/realms/acme/u/{party}/did.json"))
                .header(header::HOST, "access.test")
                .body(Body::empty())
                .unwrap();
            let (r, bytes) = send(&did, req).await;
            (
                r.status(),
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap_or_default(),
            )
        }
    };
    let agent = b64url_encode(&super::agent::AGENT.0);
    let (status, _) = get(agent.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (runtime, _) = super::agent::enrol(&l.w, l.domain).await;
    let (status, _) = get(agent.clone()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    t.insert_agent(&access_store::agents::NewAgent {
        party: super::agent::AGENT.0,
        operator: root_party(&root_key(&l.w.keys).unwrap().public_key()).0,
        kind: "cloud",
        display_name: "Mail helper",
        description: None,
        exercise: &[6; 32],
    })
    .await
    .unwrap();
    t.commit().await.unwrap();
    let (status, doc) = get(agent.clone()).await;
    assert_eq!(status, StatusCode::OK, "{doc}");
    let id = doc["id"].as_str().unwrap();
    assert!(id.starts_with("did:web:"), "{doc}");
    assert!(id.ends_with(&format!(":realms:acme:u:{agent}")), "{doc}");
    let kid = b64url_encode(&access_kernel::verify::key_scope::thumbprint(
        &runtime.0.public_key(),
    ));
    let methods = doc["verificationMethod"].as_array().unwrap();
    assert_eq!(methods.len(), 1, "{doc}");
    assert_eq!(methods[0]["id"], format!("{id}#{kid}"), "{doc}");
    assert_eq!(methods[0]["controller"], id, "{doc}");
    assert_eq!(methods[0]["publicKeyJwk"]["kid"], kid.as_str(), "{doc}");
    assert_eq!(doc["authentication"][0], methods[0]["id"], "{doc}");
    assert!(doc.get("service").is_none(), "{doc}");
    let shown = doc.to_string();
    assert!(
        !shown.contains("Mail helper") && !shown.contains("\"d\""),
        "{shown}"
    );

    // MD-10
    let (status, person) = get(b64url_encode(&l.party.0)).await;
    assert_eq!(status, StatusCode::OK, "{person}");
    assert!(
        person["id"]
            .as_str()
            .unwrap()
            .ends_with(&format!(":u:{}", b64url_encode(&l.party.0)))
    );

    // OP-73
    let mut t = TenantTx::begin(&l.w.db.app, l.route.tenant, l.route.realm)
        .await
        .unwrap();
    assert!(
        t.set_agent_status(super::agent::AGENT.0, "retired")
            .await
            .unwrap()
    );
    t.commit().await.unwrap();
    let (status, _) = get(agent).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get(b64url_encode(&[0x77; 16])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get(String::from("not-a-party")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    l.w.domains.release().await;
}
