//! The security ecosystem on the real server path (E22, E36, IDP-39, §7.9.12, OP-156 m.3 (x), Ek B
//! 5227, 5247, 5273, 5274): a PAM product, a secret store and an IGA product are twins of the
//! public crates. Access decides the authority part and emits its events; the PAM opens a
//! session, the store releases a secret and the IGA's "remove" takes effect only through an
//! Exercise Access allowed. None of them writes a Grant.

use access_kernel::meta::HoldingRef;
use access_kernel::model::DelegationTerms;
use access_product_twin::twin::meta_intent;
use access_product_twin::wire;
use access_sdk::auth::replay::MemoryReplay;
use access_sdk::authorize::{Actor as SdkActor, ExerciseRequest, Intent, adp_body};
use access_sdk::resource::release::{Refused, Releases, SecretRef};
use figment::Figment;
use figment::providers::Toml;
use serde_json::{Value as Json, json};

use super::*;

/// The public routes the IGA twin calls beyond the kit's own (PI-14).
const ROUTES: [&str; 1] = ["/access/v1/search/{kind}"];

fn seam_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/seams/pam")
}

/// A schema of `conformance/seams/pam/`.
fn seam(name: &str) -> Schema {
    Schema::parse(&std::fs::read_to_string(seam_dir().join(format!("{name}.toml"))).unwrap())
        .unwrap()
}

/// How one PAM product's request maps to an Access intent and its answer back (`teleport.toml`,
/// `cyberark.toml`).
#[derive(serde::Deserialize)]
struct Mapping {
    vendor: String,
    recorded: String,
    action: String,
    resource_namespace: String,
    resource_path: Vec<String>,
    user: String,
    allow: Reply,
    refuse: Reply,
}

#[derive(serde::Deserialize)]
struct Reply {
    set: String,
    to: String,
    exercise: Option<String>,
}

impl Mapping {
    fn load(name: &str) -> Self {
        Figment::from(Toml::file(seam_dir().join(format!("{name}.toml"))))
            .extract()
            .unwrap()
    }

    fn recorded(&self) -> Json {
        serde_json::from_slice(&std::fs::read(seam_dir().join(&self.recorded)).unwrap()).unwrap()
    }

    /// The host the recorded request asks a session on.
    fn host(&self, request: &Json) -> Vec<String> {
        self.resource_path
            .iter()
            .map(|p| request.pointer(p).unwrap().as_str().unwrap().to_owned())
            .collect()
    }

    /// Writes Access's answer into the request the way the product reads it.
    fn answer(&self, request: &mut Json, exercise: Option<&Digest>) {
        let a = if exercise.is_some() {
            &self.allow
        } else {
            &self.refuse
        };
        *request.pointer_mut(&a.set).unwrap() = Json::from(a.to.as_str());
        if let (Some(at), Some(e)) = (&a.exercise, exercise) {
            let (parent, key) = at.rsplit_once('/').unwrap();
            let key = key.replace("~1", "/").replace("~0", "~");
            let slot = if parent.is_empty() {
                request.as_object_mut().unwrap()
            } else {
                request
                    .pointer_mut(parent)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
            };
            slot.insert(key, Json::from(hex32(e)));
        }
    }
}

/// The PAM twin's sessions: each one opened for the Exercise it records, never without one.
#[derive(Default)]
struct Sessions(Vec<(Vec<String>, Digest)>);

impl Sessions {
    /// Opens a session on `host` for `request`, only under Access's verified ALLOW.
    async fn open(&mut self, s: &Seam, request: &access_product_twin::Request) -> Option<Digest> {
        let allowed = s.twin.ask(&s.domain, request).await.ok()?;
        let exercise = *allowed.exercise();
        let host = request.envelope.resources[0].path.clone();
        ProductTwin::enforce(allowed, &request.envelope, || {
            self.0.push((host, exercise));
        })
        .ok()?;
        Some(exercise)
    }
}

// E22, IDP-39 (1), §7.9.12.4, OP-156 m.3 (x), OP-153 m.3 (gg), Ek B 5273, 5247
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pam_opens_a_session_only_for_a_just_in_time_exercise() {
    let s = Seam::open("seam-pam", "pam").await;
    let pam = seam("pam");
    s.twin.publish_schema(&s.domain, &pam).await.unwrap();
    s.accept_schema(&pam).await;
    let open = pam.action("open").unwrap();
    let alice = s.actor().await;
    let stranger = s.actor().await;
    let now = server_time(&s.w.db.app).await.unwrap();
    let mut jit = canonical(
        std::slice::from_ref(&open),
        structural("pam.host", &["prod"]),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    jit.constraints.validity = Window {
        from: now - 60_000,
        until: now + 3_600_000,
    };
    let (grant, since) = s.grant(SubjectSelector::Party(alice.party), jit).await;
    let basis = holding(grant, alice.party, since);
    let mut sessions = Sessions::default();

    for vendor in ["teleport", "cyberark"] {
        let m = Mapping::load(vendor);
        assert_eq!(m.action, "pam.session.open", "{}", m.vendor);
        let mut recorded = m.recorded();
        assert_eq!(recorded.pointer(&m.user).unwrap(), "alice");
        let host = m.host(&recorded);
        let path: Vec<&str> = host.iter().map(String::as_str).collect();
        let session = || {
            envelope(
                open.clone(),
                (m.resource_namespace.as_str(), path.as_slice()),
                BTreeMap::new(),
            )
        };

        // IDP-39 (1)
        let foreign = s.request(&stranger, session(), basis, Vec::new());
        assert_eq!(sessions.open(&s, &foreign).await, None, "{}", m.vendor);
        m.answer(&mut recorded, None);
        assert_eq!(recorded.pointer(&m.refuse.set).unwrap(), &*m.refuse.to);

        let exercise = sessions
            .open(&s, &s.request(&alice, session(), basis, Vec::new()))
            .await
            .unwrap();
        schedule(&s.signer);
        m.answer(&mut recorded, Some(&exercise));
        assert_eq!(recorded.pointer(&m.allow.set).unwrap(), &*m.allow.to);
        let at = m.allow.exercise.as_deref().unwrap();
        assert_eq!(
            recorded.pointer(at).unwrap(),
            &Json::from(hex32(&exercise)),
            "{}",
            m.vendor
        );
    }
    assert_eq!(sessions.0.len(), 2);
    assert!(sessions.0.iter().all(|(h, _)| h[0] == "prod"));

    // E22
    let staging = envelope(
        open.clone(),
        ("pam.host", &["staging", "db-1"]),
        BTreeMap::new(),
    );
    assert_eq!(
        sessions
            .open(&s, &s.request(&alice, staging, basis, Vec::new()))
            .await,
        None
    );
    let to_itself = s
        .twin
        .attempt(
            &s.domain,
            &Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta::meta_anchor(&s.domain)),
                holder: SubjectSelector::Party(s.party),
                authority: canonical(
                    std::slice::from_ref(&open),
                    structural("pam.host", &[]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
            ExerciseBasis::Anchor(meta::meta_anchor(&s.domain)),
        )
        .await
        .unwrap();
    assert!(!to_itself.took_effect(), "{to_itself:?}");

    // INV-5, L28
    s.root(Payload::GrantRevoke { grant }).await;
    let after = envelope(
        open.clone(),
        ("pam.host", &["prod", "db-1"]),
        BTreeMap::new(),
    );
    assert_eq!(
        sessions
            .open(&s, &s.request(&alice, after, basis, Vec::new()))
            .await,
        None
    );
    assert_eq!(sessions.0.len(), 2);
    assert!(
        revoked_event(&s, grant).await,
        "the PAM learns of the revocation"
    );
    s.only_public();
}

/// Whether the domain's outbox carries the `AuthorityRevoked` event of `grant`: the signal a PAM,
/// a SIEM or an IGA consumes (E22).
async fn revoked_event(s: &Seam, grant: Id) -> bool {
    access_store::authority::read_outbox(
        &s.w.db.app,
        &access_store::scope::DomainId::from_bytes(s.domain.0),
        (0, 0),
        1_000,
    )
    .await
    .unwrap()
    .iter()
    .map(|r| access_internal_api::events::Event::from_bytes(&r.event).unwrap())
    .any(|e| {
        e.kind == access_internal_api::events::Kind::AuthorityRevoked
            && e.subject == access_internal_api::events::Subject::Grant(grant)
    })
}

/// The secret store twin: it keeps its secrets, is its own PEP and releases one only through the
/// SDK's release gate.
struct Store<S> {
    secrets: BTreeMap<Vec<String>, String>,
    gate: Releases<S>,
}

impl<S: access_sdk::resource::ReplayStore> Store<S> {
    /// Releases `asked` for `request`: Access's verified ALLOW, then the release gate.
    async fn release(
        &self,
        s: &Seam,
        request: &access_product_twin::Request,
        asked: &SecretRef,
    ) -> Result<String, String> {
        let allowed = s
            .twin
            .ask(&s.domain, request)
            .await
            .map_err(|d| d.code().to_owned())?;
        let intent = Intent::named(request.envelope.clone()).unwrap();
        self.gate
            .release(allowed, &intent, asked, &Wall, |_| {
                self.secrets.get(&asked.resource().path).cloned()
            })
            .map_err(|r| r.code().to_owned())?
            .value
            .ok_or_else(|| String::from("absent"))
    }
}

fn hex32(d: &Digest) -> String {
    d.0.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn secret(mount: &str, path: &[&str]) -> SecretRef {
    SecretRef {
        mount: String::from(mount),
        path: path.iter().map(|p| String::from(*p)).collect(),
    }
}

fn random_value() -> String {
    hex(&Id(access_crypto::random::bytes::<16>().unwrap()))
}

// E36, §7.9.12.4, IDP-39, OP-156 m.3 (x), OP-153 m.3 (gg), Ek B 5274, 5247
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_secret_store_releases_nothing_without_the_release_exercise() {
    let s = Seam::open("seam-vault", "vault").await;
    let schema = seam("secret");
    s.twin.publish_schema(&s.domain, &schema).await.unwrap();
    s.accept_schema(&schema).await;
    let release = schema.action("release").unwrap();
    let agent = s.actor().await;
    let stranger = s.actor().await;
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&release),
                structural("secret", &["kv", "payroll"]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let basis = holding(grant, agent.party, since);
    let db = secret("kv", &["payroll", "db"]);
    let billing = secret("kv", &["billing", "key"]);
    let value = random_value();
    let store = Store {
        secrets: BTreeMap::from([
            (db.resource().path, value.clone()),
            (billing.resource().path, random_value()),
        ]),
        gate: Releases::new(MemoryReplay::new(Wall, 1_024)),
    };
    let ask = |who: &Actor, of: &SecretRef| {
        s.request(
            who,
            envelope(
                release.clone(),
                (
                    "secret",
                    &of.resource()
                        .path
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ),
                BTreeMap::new(),
            ),
            basis,
            Vec::new(),
        )
    };

    // E36
    assert_eq!(
        store.release(&s, &ask(&stranger, &db), &db).await,
        Err(String::from("refused"))
    );
    assert_eq!(
        store.release(&s, &ask(&agent, &billing), &billing).await,
        Err(String::from("refused"))
    );
    assert_eq!(
        store.release(&s, &ask(&agent, &db), &billing).await,
        Err(String::from(Refused::OtherSecret.code()))
    );
    let once = ask(&agent, &db);
    assert_eq!(store.release(&s, &once, &db).await, Ok(value));
    schedule(&s.signer);
    let again = store.release(&s, &once, &db).await;
    assert!(again.is_err(), "an Exercise releases once: {again:?}");

    // INV-5
    s.root(Payload::GrantRevoke { grant }).await;
    assert_eq!(
        store.release(&s, &ask(&agent, &db), &db).await,
        Err(String::from("refused"))
    );
    assert!(revoked_event(&s, grant).await);
    s.only_public();
}

/// One HTTP/1.1 exchange with the `OpenBao` server `scripts/ci/openbao-env.sh` started: its status
/// and JSON body.
async fn openbao(method: &str, path: &str, body: Option<&Json>) -> (u16, Json) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let env = |n: &str| {
        std::env::var(n).unwrap_or_else(|_| panic!("{n} is set by scripts/ci/openbao-env.sh"))
    };
    let addr = env("ACCESS_TEST_OPENBAO_ADDR");
    let token = env("ACCESS_TEST_OPENBAO_TOKEN");
    let body = body.map(Json::to_string).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nX-Vault-Token: {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let exchange = async {
        let mut stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        out
    };
    let out = tokio::time::timeout(Duration::from_secs(10), exchange)
        .await
        .unwrap();
    let text = String::from_utf8(out).unwrap();
    let (head, rest) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let json = if rest.trim().is_empty() {
        Json::Null
    } else {
        serde_json::from_str(rest.trim()).unwrap()
    };
    (status, json)
}

/// `OpenBao`'s KV v2 path of `secret`.
fn kv_path(secret: &SecretRef) -> String {
    format!("/v1/{}/data/{}", secret.mount, secret.path.join("/"))
}

// E36, §7.9.12.4, OP-156 m.3 (x), m.5, Ek B 5274
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "CI only: scripts/ci/openbao-env.sh up starts OpenBao"]
async fn openbao_keeps_the_secret_and_the_store_releases_it_only_for_the_exercise() {
    let s = Seam::open("seam-openbao", "openbao").await;
    let schema = seam("secret");
    s.twin.publish_schema(&s.domain, &schema).await.unwrap();
    s.accept_schema(&schema).await;
    let release = schema.action("release").unwrap();
    let agent = s.actor().await;
    let stranger = s.actor().await;
    let (grant, since) = s
        .grant(
            SubjectSelector::Party(agent.party),
            canonical(
                std::slice::from_ref(&release),
                structural("secret", &["secret", "payroll"]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let basis = holding(grant, agent.party, since);
    let db = secret("secret", &["payroll", "db"]);
    let value = random_value();
    let (status, written) = openbao(
        "POST",
        &kv_path(&db),
        Some(&json!({ "data": { "value": value } })),
    )
    .await;
    assert_eq!(status, 200, "{written}");
    let gate = Releases::new(MemoryReplay::new(Wall, 1_024));
    let ask = |who: &Actor| {
        s.request(
            who,
            envelope(
                release.clone(),
                ("secret", &["secret", "payroll", "db"]),
                BTreeMap::new(),
            ),
            basis,
            Vec::new(),
        )
    };
    let path = kv_path(&db);
    let mut reads = 0_u32;
    let mut from_openbao = async |request: &access_product_twin::Request| {
        let allowed = s.twin.ask(&s.domain, request).await.ok()?;
        let intent = Intent::named(request.envelope.clone()).unwrap();
        let released = gate
            .release(allowed, &intent, &db, &Wall, |e| *e.exercise)
            .ok()?;
        reads += 1;
        let (status, read) = openbao("GET", &path, None).await;
        assert_eq!(status, 200, "{read}");
        Some((
            released.exercise,
            read["data"]["data"]["value"].as_str()?.to_owned(),
        ))
    };

    // E36
    assert_eq!(from_openbao(&ask(&stranger)).await, None);
    let (exercise, got) = from_openbao(&ask(&agent)).await.unwrap();
    assert_eq!(got, value);
    assert_eq!(exercise.0.len(), 32);
    schedule(&s.signer);

    // INV-5
    s.root(Payload::GrantRevoke { grant }).await;
    assert_eq!(from_openbao(&ask(&agent)).await, None);
    assert_eq!(
        reads, 1,
        "OpenBao was read once, for the one allowed release"
    );
    s.only_public();
}

/// A small application whose reads the IGA reviews.
const PAYROLL: &str = r#"
product = "Payroll"
namespace = "payroll"
catalog_version = 1
truth = ["payslip"]

[[actions]]
name = "read"
major = 1
effect_class = "none"
resource_types = ["record"]
"#;

fn action_json(a: &ActionRef) -> Json {
    json!({
        "namespace": a.namespace,
        "name": a.name,
        "major": a.major,
        "schema": b64url_encode(&a.schema.0),
    })
}

/// Who the IGA reads for: the reviewer whose statement it forwards, on the reviewer's read-only
/// Grant over the searches. Access shows each reviewer only the Grants in its own lineage.
struct Reader<'a> {
    actor: &'a Actor,
    basis: ExerciseBasis,
}

impl Reader<'_> {
    /// The reader's search of `kind` with `query`, answered by Access's derived index (§7.9.12.3).
    async fn search(&self, s: &Seam, kind: &str, query: Json) -> Json {
        let path = ROUTES[0].replace("{kind}", kind);
        let envelope = IntentEnvelope {
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
            validity: window(),
        };
        let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
        let digest = intent_digest(&envelope).unwrap();
        let ais = Seam::ais(
            &self.actor.key,
            &Statement {
                domain: s.domain,
                nonce: nonce.clone(),
                intent: digest,
                mode: Mode::Check,
                pep: String::from(TWIN_PEP),
                capacity: Capacity::Own,
                basis: self.basis,
                iat: now_ms(),
                exercise: None,
            },
        );
        let body = adp_body(&ExerciseRequest {
            domain: &s.domain,
            mode: Mode::Check,
            nonce: &nonce,
            intent: &digest,
            envelope: Some(&envelope),
            actor: &SdkActor::Statement(ais),
            basis: &self.basis,
            capacity: Capacity::Own,
            pep: TWIN_PEP,
            exercise: None,
        })
        .unwrap();
        let mut body: Json = serde_json::from_str(&body).unwrap();
        body["context"]["query"] = query;
        let Answer::Response(r) = s
            .listener
            .raw("POST", &path, body.to_string().into_bytes())
            .await
        else {
            panic!("no answer");
        };
        assert_eq!(
            r.status,
            200,
            "{kind}: {}",
            String::from_utf8_lossy(&r.body)
        );
        serde_json::from_slice(&r.body).unwrap()
    }
}

/// `actor`'s own commit of `payload` on `basis`, forwarded by the twin as its PEP over the `AuthZEN`
/// evaluation endpoint: how an IGA hands Access a reviewer's decision (§7.9.12.3).
async fn forward(s: &Seam, actor: &Actor, basis: ExerciseBasis, payload: &Payload) -> Option<bool> {
    let envelope = meta_intent(payload, actor.party, window()).unwrap();
    let nonce = access_crypto::random::bytes::<16>().unwrap().to_vec();
    let digest = intent_digest(&envelope).unwrap();
    let ais = Seam::ais(
        &actor.key,
        &Statement {
            domain: s.domain,
            nonce: nonce.clone(),
            intent: digest,
            mode: Mode::Commit,
            pep: String::from(TWIN_PEP),
            capacity: Capacity::Own,
            basis,
            iat: now_ms(),
            exercise: None,
        },
    );
    let body = adp_body(&ExerciseRequest {
        domain: &s.domain,
        mode: Mode::Commit,
        nonce: &nonce,
        intent: &digest,
        envelope: Some(&envelope),
        actor: &SdkActor::Statement(ais),
        basis: &basis,
        capacity: Capacity::Own,
        pep: TWIN_PEP,
        exercise: None,
    })
    .unwrap();
    let mut body: Json = serde_json::from_str(&body).unwrap();
    body["context"]["payload"] = Json::from(b64url_encode(&payload.to_bytes().unwrap()));
    let call = wire::call(
        wire::Method::Post,
        wire::EVALUATION,
        &[],
        body.to_string().into_bytes(),
    )
    .unwrap();
    let Answer::Response(r) = s.listener.send(call).await else {
        return None;
    };
    schedule(&s.signer);
    let v: Json = serde_json::from_slice(&r.body).ok()?;
    v.get("decision").and_then(Json::as_bool)
}

// E22, IDP-39 (3), §7.9.12.3, INV-2, OP-156 m.3 (x), OP-153 m.3 (gg), Ek B 5227, 5247
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_iga_removal_takes_effect_only_as_the_reviewers_grant_revoke() {
    let s = Seam::open("seam-iga", "iga").await;
    let app = Schema::parse(PAYROLL).unwrap();
    s.twin.publish_schema(&s.domain, &app).await.unwrap();
    s.accept_schema(&app).await;
    let read = app.action("read").unwrap();
    let manager = s.actor().await;
    let member = s.actor().await;
    let mut to_manager = canonical(
        std::slice::from_ref(&read),
        structural("payroll.record", &[]),
        BTreeMap::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    to_manager.delegation = DelegationTerms {
        depth: 1,
        downstream_holder_class: None,
    };
    let (team, team_since) = s
        .grant(SubjectSelector::Party(manager.party), to_manager)
        .await;
    let manager_basis = holding(team, manager.party, team_since);
    let (issued, member_since) = s
        .own_commit(
            &manager,
            manager_basis,
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Holding(HoldingRef {
                    grant: team,
                    holder: manager.party,
                    since: team_since,
                }),
                holder: SubjectSelector::Party(member.party),
                authority: canonical(
                    std::slice::from_ref(&read),
                    structural("payroll.record", &[]),
                    BTreeMap::new(),
                    BTreeSet::new(),
                    BTreeSet::new(),
                ),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .await;
    let grant = meta::object_id(&issued, kind::GRANT, 0);
    let member_basis = holding(grant, member.party, member_since);
    let payslip = || envelope(read.clone(), ("payroll.record", &["r-1"]), BTreeMap::new());
    let reads = |s: &Seam| s.request(&member, payslip(), member_basis, Vec::new());
    assert!(s.twin.ask(&s.domain, &reads(&s)).await.is_ok());
    schedule(&s.signer);

    let (searches, searches_since) = s
        .grant(
            SubjectSelector::Party(manager.party),
            canonical(
                &[meta::core_action("read")],
                structural("access.search", &[]),
                BTreeMap::new(),
                BTreeSet::new(),
                BTreeSet::new(),
            ),
        )
        .await;
    let reviewer = Reader {
        actor: &manager,
        basis: holding(searches, manager.party, searches_since),
    };

    // §7.9.12.3
    assert!(s.w.domains.derive().await.is_empty());
    let who = reviewer
        .search(
            &s,
            "subject",
            json!({
                "action": action_json(&read),
                "resource": { "namespace": "payroll.record", "path": ["r-1"] },
            }),
        )
        .await;
    for p in [&member.party, &manager.party] {
        assert!(who.to_string().contains(&b64url_encode(&p.0)), "{who}");
    }
    let impact = reviewer
        .search(
            &s,
            "revocation-impact",
            json!({ "grant": b64url_encode(&grant.0) }),
        )
        .await;
    assert_eq!(
        impact["results"][0]["type"], "revocation_impact",
        "{impact}"
    );
    assert!(
        impact["results"][0]["subtree"]
            .to_string()
            .contains(&b64url_encode(&grant.0)),
        "{impact}"
    );
    let iga = s.actor().await;

    // IDP-39 (3), INV-2
    let by_itself = s
        .twin
        .attempt(
            &s.domain,
            &Payload::GrantRevoke { grant },
            ExerciseBasis::Anchor(meta::meta_anchor(&s.domain)),
        )
        .await
        .unwrap();
    assert!(!by_itself.took_effect(), "{by_itself:?}");
    let by_its_instance = forward(
        &s,
        &iga,
        ExerciseBasis::Anchor(meta::meta_anchor(&s.domain)),
        &Payload::GrantRevoke { grant },
    )
    .await;
    assert_ne!(by_its_instance, Some(true));
    assert!(s.twin.ask(&s.domain, &reads(&s)).await.is_ok());
    schedule(&s.signer);

    // §7.9.12.3
    assert_eq!(
        forward(&s, &manager, manager_basis, &Payload::GrantRevoke { grant }).await,
        Some(true)
    );
    let after = s.twin.ask(&s.domain, &reads(&s)).await;
    assert!(
        matches!(after, Err(Denied::Refused(Refusal::Deny))),
        "{after:?}"
    );
    assert!(revoked_event(&s, grant).await);
    s.only_public();
}
