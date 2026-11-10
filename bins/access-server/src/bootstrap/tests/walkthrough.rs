//! The third-party walkthroughs of §11.19 on the real server (OP-154 m.3 (ff), OP-153 m.3
//! (gg)): each scenario answers the same five questions (Party and Instance, the source of
//! authority, the decision path, what triggers an approval, how revocation is learned) through
//! the merged pieces on the real router, sequencer, store and `SoftHSM`. The third party in each
//! one speaks only the standard bindings (PI-13): `AuthZEN` evaluation, OAuth 2.0 and its
//! extensions, and `.well-known` discovery.

mod ciba;
mod cloud;
mod cross_org;
mod local_agent;
mod mcp_proxy;
mod ssh;
mod work_gate;

use std::sync::atomic::AtomicUsize;

use access_http::adp::adapters::{Discovery, router as adp_router};
use access_kernel::combinator::Capacity;
use access_local_client::http::{Http, Identity, leaf_der};
use access_sdk::agent::contract::{Exercise, Plan as AgentPlan, Step};

use super::agent::{AGENT, AGENT_PEP, Live, Runtime, Wall, enrol_for, nonce};
use super::exchange::{delegated, issue};
use super::*;

/// Whether `path` is one of the standard bindings a third party may need (PI-13): `AuthZEN`
/// evaluation and search, OAuth 2.0 endpoints, and `.well-known` discovery documents.
pub(super) fn standard(path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    let realm = path
        .strip_prefix("/realms/acme")
        .or_else(|| path.strip_prefix("/realms/platform"));
    path.starts_with("/access/v1/evaluation")
        || path.starts_with("/access/v1/search/")
        || path.contains("/.well-known/")
        || realm.is_some_and(|r| {
            matches!(
                r,
                "/token"
                    | "/authorize"
                    | "/par"
                    | "/introspect"
                    | "/revoke"
                    | "/jwks"
                    | "/bc-authorize"
            )
        })
}

/// A decision point the third party reaches as its own PEP, recording every path it asked.
pub(super) struct Recorded {
    pub(super) live: Live,
    pub(super) paths: std::sync::Mutex<Vec<String>>,
}

impl access_sdk::agent::contract::Adp for Recorded {
    fn evaluate(&self, body: &str) -> access_sdk::transport::Answer {
        let path = "/access/v1/evaluation";
        self.paths.lock().unwrap().push(String::from(path));
        self.live.post(path, body)
    }
}

impl Recorded {
    pub(super) fn new(w: &World) -> Self {
        Self {
            live: Live {
                adp: adp_router(
                    access_http::adp::app::Service::new(w.domains.clone(), 64 * 1024),
                    Discovery {
                        issuer: String::from("https://access.test"),
                    },
                ),
                asked: AtomicUsize::new(0),
            },
            paths: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// PI-13: every path the third party reached is a standard binding.
    pub(super) fn only_standard(&self) {
        let paths = self.paths.lock().unwrap();
        assert!(!paths.is_empty());
        for p in paths.iter() {
            assert!(standard(p), "{p}");
        }
    }
}

/// Commits the root's `payload` about `about` on the meta-anchor of `domain`: the Exercise and
/// its position.
pub(super) async fn root_commit(
    w: &World,
    domain: Digest,
    about: Id,
    payload: Payload,
) -> (Digest, u64) {
    let root = root_key(&w.keys).unwrap();
    let now = server_time(&w.db.app).await.unwrap();
    let validity = Window {
        from: now - 60_000,
        until: now + 600_000,
    };
    let intent = self_signed_intent(&payload, about, validity).unwrap();
    let n = nonce();
    let basis = ExerciseBasis::Anchor(meta::meta_anchor(&domain));
    let ais = sign(
        &root,
        &Statement {
            domain,
            nonce: n.clone(),
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
    (c.exercise, c.position)
}

/// The root's Grant of `content`, and its holding.
pub(super) async fn root_grant(w: &World, domain: Digest, content: GrantContent) -> HoldingRef {
    let SubjectSelector::Party(holder) = content.holder.clone() else {
        panic!("a Party holder");
    };
    let (exercise, since) = root_commit(w, domain, holder, Payload::GrantIssue(content)).await;
    HoldingRef {
        grant: meta::object_id(&exercise, kind::GRANT, 0),
        holder,
        since,
    }
}

/// The root revokes `grant`.
pub(super) async fn root_revoke(w: &World, domain: Digest, grant: Id, about: Id) {
    root_commit(w, domain, about, Payload::GrantRevoke { grant }).await;
}

/// The local deployment's realm with the test user P (password, software passkey, device
/// Instance and a Grant to contribute approvals), its hosted Approval Surface behind TLS, and
/// an agent Party with one Instance.
pub(super) struct Desk {
    pub(super) w: World,
    pub(super) domain: Digest,
    pub(super) user: TestUserOut,
    pub(super) allowed: serde_json::Value,
    pub(super) person: Id,
    pub(super) subject: [u8; 16],
    pub(super) http: Http,
    pub(super) leaf: Vec<u8>,
    pub(super) runtime: Runtime,
    pub(super) instance: Id,
    pub(super) adp: Recorded,
    /// A client of the deployment without a client certificate: the agent's OAuth client.
    pub(super) agent_http: Http,
    /// The CIBA pings the realm sent (OP-155 m.3 (l)).
    pub(super) pings: ciba::Pings,
    token: KeyStore,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Desk {
    /// `operator` names who operates the agent: the realm root (a hosted agent) or P (an
    /// agent on P's own device, its Instance opened under P's session).
    pub(super) async fn open(name: &str, on_the_persons_device: bool) -> Self {
        use access_http::login::{me_router, router as login_router};
        use access_identity_account::adapters::system::{SystemClock, cgroup_memory_budget, cores};
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
        use access_identity_ui::app::{Devices, Hosted};
        use access_local_client::login::{Credential, sign_in};
        use access_local_client::passkey::{Passkey, relying_party};

        use crate::login::{HsmKits, RealmKeks};

        let (w, signer) = World::open(name, true).await;
        let signer = signer.unwrap();
        let plan = approve_plan(None);
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
        let acme = first.realms.iter().find(|r| r.slug == "acme").unwrap();
        let domain = Digest(
            <[u8; 32]>::try_from(access_kernel::json::b64url_decode(&acme.domain).unwrap())
                .unwrap(),
        );
        let person = id_of(&user.party);
        let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
        let mut t = TenantTx::begin(&w.db.app, route.tenant, route.realm)
            .await
            .unwrap();
        let subject = idp::party_subject(&mut t, &person.0)
            .await
            .unwrap()
            .unwrap();
        t.commit().await.unwrap();

        let tls = test_tls("access.test");
        let hosted = Arc::new(Hosted {
            kits: HsmKits::new(
                RealmKeks::new(Arc::clone(&w.keys)),
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
            hooks: Arc::new(access_identity_hooks::ports::NoHooks),
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
                crate::ingest::Trusted(tokio::sync::Mutex::new(SourcesClock::new(
                    w.db.app.clone(),
                ))),
            ),
            clock: SystemClock,
        });
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
            ));
        // OP-155 m.3 (l)
        let (oauth, pings) = ciba::oauth_router(&w);
        let app = app.merge(oauth);
        let config = access_http::tls::server_config(
            tls.server_cert.as_bytes(),
            tls.server_key.as_bytes(),
            Some(tls.ca.as_bytes()),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(access_http::tls::serve(listener, config, app, async {
            let _ = stopped.await;
        }));
        let pin = Secret::new(String::from(PIN));
        let token = KeyStore::open(&w.module, &w.label, &pin).unwrap();
        let identity = Identity {
            chain_pem: tls.pep_cert.clone().into_bytes(),
            key_pem: tls.pep_key.clone().into_bytes(),
        };
        let leaf = leaf_der(&identity.chain_pem).unwrap();
        let http = Http::new(tls.ca.as_bytes(), Some(&identity), Some(addr)).unwrap();
        let agent_http = Http::new(tls.ca.as_bytes(), None, Some(addr)).unwrap();
        {
            let passkey_key = token.signer(local::TEST_PASSKEY_LABEL).unwrap();
            let (rp_id, origin) = relying_party(&user.issuer).unwrap();
            let passkey = Passkey {
                key: &passkey_key,
                rp_id: &rp_id,
                origin: &origin,
            };
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
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut answered = 0;
        while answered < 2 {
            answered += courier.step().await.unwrap().answered;
            assert!(
                std::time::Instant::now() < deadline,
                "{answered} sign-in Claims answered after 20 s"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let root = root_party(&root_key(&w.keys).unwrap().public_key());
        let (runtime, instance) = if on_the_persons_device {
            enrol_for(&w, domain, person, Some(subject)).await
        } else {
            enrol_for(&w, domain, root, None).await
        };
        let adp = Recorded::new(&w);
        Self {
            w,
            domain,
            user,
            allowed,
            person,
            subject,
            http,
            leaf,
            runtime,
            instance,
            adp,
            agent_http,
            pings,
            token,
            stop: Some(stop),
        }
    }

    /// The allowed action's intent over the ledger `ledger`, in the ADP JSON encoding.
    pub(super) async fn intent_json(&self, ledger: &str) -> serde_json::Value {
        let now = server_time(&self.w.db.app).await.unwrap();
        commit_intent(&self.allowed, ledger, now)
    }

    /// P's Grant of the allowed action to the agent, for P (INV-4), with the approval term of
    /// the sample (one `approve` contribution bound to the intent), signed by P's device on the
    /// root's delegable Grant to P: the root's Grant and P's.
    pub(super) async fn agent_grant(&self) -> (HoldingRef, HoldingRef) {
        let mut to_person = approve_plan(None)
            .sample
            .unwrap()
            .allowed_grant(&self.domain, self.person)
            .unwrap();
        to_person.authority.delegation = DelegationTerms {
            depth: 1,
            downstream_holder_class: Some(SubjectSelector::Party(AGENT)),
        };
        let mut onward = to_person.authority.clone();
        onward.delegation.depth = 0;
        let parent = root_grant(&self.w, self.domain, to_person).await;
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let held = issue(
            &self.w,
            self.domain,
            &device,
            Some(parent),
            AGENT,
            onward,
            (BTreeSet::from([Capacity::For(self.person)]), Capacity::Own),
        )
        .await;
        (parent, held)
    }

    /// The agent's Exercise of `intent` on `basis` for P.
    pub(super) fn exercise(&self, intent: &serde_json::Value, basis: HoldingRef) -> Exercise {
        let envelope = access_local_client::intent::parse(intent).unwrap();
        Exercise::new(
            self.domain,
            AGENT_PEP,
            AgentPlan {
                intent: envelope,
                basis: Some(ExerciseBasis::Holding(basis)),
                capacity: Some(Capacity::For(self.person)),
            },
            nonce(),
        )
        .unwrap()
    }

    /// The agent asks the decision point.
    pub(super) fn ask(&self, ex: &mut Exercise) -> Step {
        ex.ask(&self.adp, &self.runtime, &Wall).unwrap()
    }

    /// P approves the agent's waiting `ex` on the hosted Approval Surface with the software
    /// passkey, bound to P's device Instance: the `contribute` Exercise P's device signed
    /// (§9.14.1 A, §9.14.5).
    pub(super) async fn approve(&self, ex: &Exercise, intent: &serde_json::Value) -> Digest {
        use access_local_client::approve::{Approve, approve};
        use access_local_client::passkey::{Passkey, relying_party};
        let envelope = access_local_client::intent::parse(intent).unwrap();
        let digest = intent_digest(&envelope).unwrap();
        let now = server_time(&self.w.db.app).await.unwrap();
        let request = serde_json::json!({
            "requester": {
                "party": b64url_encode(&AGENT.0),
                "instance": b64url_encode(&self.instance.0),
            },
            "action": intent["action"],
            "resource": intent["resources"][0],
            "params": intent["params"],
            "capacity": { "for": b64url_encode(&self.person.0) },
            "reason": "The mail agent wants to close the main ledger for you.",
            "require_action": {
                "domain": b64url_encode(&self.domain.0),
                "nonce": b64url_encode(ex.nonce()),
                "intent": b64url_encode(&digest.0),
            },
            "expires_at": now + 3_600_000,
        });
        let device = self.token.signer(local::TEST_DEVICE_LABEL).unwrap();
        let passkey_key = self.token.signer(local::TEST_PASSKEY_LABEL).unwrap();
        let (rp_id, origin) = relying_party(&self.user.issuer).unwrap();
        let passkey = Passkey {
            key: &passkey_key,
            rp_id: &rp_id,
            origin: &origin,
        };
        let done = approve(
            &self.http,
            &Approve {
                issuer: &self.user.issuer,
                api_base: "https://access.test",
                redirect_uri: &self.user.redirect_uri,
                identifier: &self.user.identifier,
                passkey: &passkey,
                device: &device,
                pep_leaf_der: &self.leaf,
                domain: self.domain,
                party: self.person,
                instance: Some(id_of(&self.user.instance)),
                intent,
                basis: holding_of(&self.allowed["basis"]),
                contribution: holding_of(&self.allowed["contribution"]["basis"]),
                reason: "The mail agent wants to close the main ledger for you.",
                request: Some(&request),
                work_gate: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(done["render_digest_verified"], true, "{done}");
        assert!(done.get("exercise").is_none(), "{done}");
        Digest(
            <[u8; 32]>::try_from(
                access_kernel::json::b64url_decode(done["contribution"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        )
    }

    pub(super) async fn close(mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
        self.w.domains.release().await;
    }
}
