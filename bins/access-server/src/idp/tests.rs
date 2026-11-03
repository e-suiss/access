#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::BTreeMap;
use std::time::Duration;

use access_authority_core::adapters::Setup;
use access_authority_core::app::Response;
use access_authority_core::genesis::{BOOTSTRAP_GRANT, IDP_ANCHOR, core_action};
use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::fold_check;
use access_crypto::event_id::EventKey;
use access_crypto::opaque_id::IdKey;
use access_crypto::secret::Secret;
use access_identity_admin::app::{Admin, Applied, NewRealm, Proposal};
use access_identity_admin::domain::{AuthMethod, Change, Client, ClientId, RedirectUri, RpId};
use access_identity_oauth::domain::issuer::{IssuerStyle, RealmBase};
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::intent::{ContextRefs, IntentEnvelope, intent_digest};
use access_kernel::meta::{self, ExerciseBasis, Payload, Root, kind};
use access_kernel::model::{Id, ResourceRef, Window};
use access_kernel::verify::cose::{ALG, CONTENT_TYPE as CT, KID, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{client, settings};
use access_store::tenancy::{create_tenant, route_by_slug};
use access_store::testing::{TestDb, fresh};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};

use super::*;

const NOW: u64 = 10_000;
const ROOT: Id = Id([1; 16]);
const ROOT_KEY: u8 = 11;
const ALICE: Id = Id([2; 16]);
const ALICE_KEY: u8 = 12;
const PEP: &str = "identity-admin";
const HOUR: u64 = 3_600_000;

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

/// Event-id, token and pseudonym keys for every domain.
struct AnyKeys;

impl Keys for AnyKeys {
    fn event_key(&self, _: &Digest) -> Result<EventKey, CoreError> {
        Ok(EventKey::new(Secret::new([5; 32])))
    }

    fn token_key(&self, _: &Digest) -> Result<access_crypto::token::TokenKey, CoreError> {
        Ok(access_crypto::token::TokenKey::new(Secret::new([6; 32])))
    }

    fn pseudonym_key(
        &self,
        _: &Digest,
    ) -> Result<access_crypto::pseudonym::PseudonymKey, CoreError> {
        Ok(access_crypto::pseudonym::PseudonymKey::new(Secret::new(
            [7; 32],
        )))
    }
}

/// The identity plane's actor-binding, fixed for the test.
#[derive(Clone)]
struct Bound;

impl Binding for Bound {
    fn bound(&self, kid: &[u8; 32]) -> Option<(Id, PublicKey)> {
        [(ROOT, ROOT_KEY), (ALICE, ALICE_KEY)]
            .into_iter()
            .find(|(_, k)| thumbprint(&public(*k)) == *kid)
            .map(|(p, k)| (p, public(k)))
    }
}

#[derive(Clone)]
struct Fixed;

impl Clock for Fixed {
    fn now(&mut self) -> impl Future<Output = Result<u64, SequencerError>> + Send {
        std::future::ready(Ok(NOW))
    }
}

type TestPlane = Plane<AnyKeys, Bound, OsSalts, Fixed>;

fn plane(db: &TestDb) -> TestPlane {
    let domains = Arc::new(Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: AnyKeys,
        holder: String::from("t"),
        ttl: Duration::from_secs(10),
        binding: Bound,
        salts: OsSalts,
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: None,
    }));
    Plane::new(domains, db.sequencer.clone(), db.app.clone(), Fixed)
}

/// The realm keys opened, in order.
#[derive(Default)]
struct Opened(std::sync::Mutex<Vec<([u8; 16], JoseAlg)>>);

impl RealmKeys for Opened {
    fn open(
        &self,
        realm: RealmId,
        alg: JoseAlg,
    ) -> impl std::future::Future<Output = Result<(), Unavailable>> + Send {
        self.0.lock().unwrap().push((*realm.as_bytes(), alg));
        std::future::ready(Ok(()))
    }
}

struct World {
    db: TestDb,
    plane: TestPlane,
    ids: IdKey,
    base: RealmBase,
    keys: Opened,
}

impl World {
    async fn new() -> Self {
        let db = fresh().await.unwrap();
        let plane = plane(&db);
        Self {
            db,
            plane,
            ids: IdKey::new(Secret::new([8; 32])),
            base: RealmBase::parse("https://id.test").unwrap(),
            keys: Opened::default(),
        }
    }

    fn admin(&self) -> Admin<'_, TestPlane, TestPlane, Opened> {
        Admin {
            app: &self.db.app,
            ids: &self.ids,
            decider: &self.plane,
            governance: &self.plane,
            pep: PEP,
            base: &self.base,
            keys: &self.keys,
        }
    }

    fn opened(&self) -> Vec<([u8; 16], JoseAlg)> {
        self.keys.0.lock().unwrap().clone()
    }

    async fn realm(&self, slug: &str) -> (TenantId, RealmId, Digest) {
        let tenant = create_tenant(&self.db.app, "pool-default").await.unwrap();
        let created = self
            .admin()
            .create_realm(&NewRealm {
                tenant,
                slug,
                style: IssuerStyle::Subdomain,
                placement: "pool-default",
                root: Root::Sole(ROOT),
                ct3_delay_s: None,
            })
            .await
            .unwrap();
        (tenant, created.realm, created.domain)
    }
}

fn sign(s: &Statement, seed: u8) -> Vec<u8> {
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(CT), Value::text(CONTENT_TYPE)),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public(seed)).to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let payload = s.to_bytes().unwrap();
    let sig = signing(seed)
        .sign(&to_be_signed(&prot, &payload))
        .to_bytes();
    let body = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(sig.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    [vec![0xd2], body].concat()
}

fn statement(domain: Digest, nonce: &[u8], intent: Digest, basis: ExerciseBasis) -> Statement {
    Statement {
        domain,
        nonce: nonce.to_vec(),
        intent,
        mode: Mode::Commit,
        pep: String::from(PEP),
        capacity: Capacity::Own,
        basis,
        iat: NOW,
        exercise: None,
    }
}

/// Registers `party` with the key `seed` under the Genesis bootstrap Grant (L0-META-7).
async fn onboard(plane: &TestPlane, d: Digest, party: Id, seed: u8) {
    let basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, BOOTSTRAP_GRANT));
    let payloads = [
        Payload::PartyRegister {
            party,
            root: Root::Sole(party),
        },
        Payload::InstanceCreate {
            party,
            key: public(seed),
            mandate: None,
        },
    ];
    for (i, payload) in payloads.into_iter().enumerate() {
        let intent = IntentEnvelope {
            action: core_action(payload.action()),
            resources: vec![ResourceRef {
                namespace: String::from("access.party"),
                path: vec![String::from("p")],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([(String::from("payload"), payload.digest().unwrap())]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: 0,
                until: HOUR,
            },
        };
        let mut nonce = vec![seed; 16];
        nonce[0] = 0xe0 + u8::try_from(i).unwrap();
        let digest = intent_digest(&intent).unwrap();
        let inc = Incoming {
            ais: Some(sign(&statement(d, &nonce, digest, basis), seed)),
            request: Request {
                domain: d,
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
            pep: String::from(PEP),
            explain: false,
        };
        let r: Response = plane.domains.exercise(&inc).await.unwrap();
        assert_eq!(r.decision.outcome, Outcome::Allow, "{r:?}");
    }
}

fn idp_anchor(d: Digest) -> ExerciseBasis {
    ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, IDP_ANCHOR))
}

fn proposal(
    (tenant, realm): (TenantId, RealmId),
    change: Change,
    nonce: u8,
    basis: ExerciseBasis,
    hours: u64,
) -> Proposal {
    Proposal {
        tenant,
        realm,
        change,
        nonce: vec![nonce; 16],
        validity: Window {
            from: NOW,
            until: NOW + hours * HOUR,
        },
        basis,
        capacity: Capacity::Own,
    }
}

/// Prepares `p`, has the actor `seed` sign it and applies it.
async fn exercise(
    w: &World,
    p: &Proposal,
    seed: u8,
) -> Result<Applied, access_identity_admin::AdminError> {
    let prepared = w.admin().prepare(p).await.unwrap();
    let ais = sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        seed,
    );
    w.admin().apply(p, ais).await
}

async fn new_client(w: &World) -> Client {
    Client {
        id: w.admin().new_client_id().await.unwrap(),
        display_name: String::from("Shop"),
        auth: AuthMethod::None,
        redirect_uris: vec![
            RedirectUri::parse("https://shop.example/cb").unwrap(),
            RedirectUri::parse("http://127.0.0.1/cb").unwrap(),
        ],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
    }
}

fn written(a: &Applied) -> u64 {
    match a {
        Applied::Written { position, .. } => *position,
        other => panic!("{other:?}"),
    }
}

// TN-111, TN-16, TN-10, OP-146 m.8 (c), §12.1.1 2a: creating a realm opens its governing
// domain with a Genesis, fixes the issuer on the realm row and starts the realm on the
// Genesis defaults; there is no master realm
#[tokio::test]
async fn realm_creation_opens_genesis_and_fixes_the_issuer() {
    // MD-5a, INV-2, INV-29, L0-META-7, CMP-26
    let w = World::new().await;
    assert!(
        access_store::tenancy::routes(&w.db.router)
            .await
            .unwrap()
            .is_empty()
    );
    let (tenant, realm, d) = w.realm("acme").await;
    let route = route_by_slug(&w.db.router, "acme").await.unwrap().unwrap();
    assert_eq!(route.issuer, "https://acme.id.test");
    let log = access_store::authority::read_log(&w.db.app, &DomainId::from_bytes(d.0), 0, 0)
        .await
        .unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].kind, "genesis");
    fold_check(&w.db.sequencer, d).await.unwrap();
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let s = settings(&mut t).await.unwrap().unwrap();
    assert_eq!(
        (s.jose_alg.as_str(), s.argon2_m_kib, s.rp_id),
        ("ES256", 7 * 1024, None)
    );
    // OP-146 m.16 (m)
    assert_eq!(w.opened(), vec![(*realm.as_bytes(), JoseAlg::Es256)]);
    let taken = w
        .admin()
        .create_realm(&NewRealm {
            tenant,
            slug: "acme",
            style: IssuerStyle::Subdomain,
            placement: "pool-default",
            root: Root::Sole(ROOT),
            ct3_delay_s: None,
        })
        .await;
    assert!(taken.is_err());
}

// MD-14, EI-25, TN-15, TN-110, IDP-7: a client is registered by an idp.* Exercise committed in
// the governing domain; its row is bound to that ALLOW, its client_id is opaque and its
// redirect URIs are kept as exact strings; a retry writes nothing twice
#[tokio::test]
async fn a_client_is_registered_through_commit() {
    // E34, OP-137, TN-20, CMP-15.5
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("shop").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let c = new_client(&w).await;
    let p = proposal(
        (tenant, realm),
        Change::ClientRegister(c.clone()),
        1,
        idp_anchor(d),
        1,
    );
    let prepared = w.admin().prepare(&p).await.unwrap();
    let ais = sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        ROOT_KEY,
    );
    let pos = written(&w.admin().apply(&p, ais.clone()).await.unwrap());
    assert!(pos > 0);
    assert!(matches!(
        w.admin().apply(&p, ais).await.unwrap(),
        Applied::AlreadyWritten { position, .. } if position == pos
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    let row = client(&mut t, c.id.as_str()).await.unwrap().unwrap();
    assert!(row.client_id.starts_with("cli_") && row.display_name == "Shop");
    assert_eq!(
        row.redirect_uris,
        ["https://shop.example/cb", "http://127.0.0.1/cb"]
    );
    t.commit().await.unwrap();
    fold_check(&w.db.sequencer, d).await.unwrap();
}

// MD-14, TN-110, INV-2: nothing reaches the configuration without its own committed ALLOW: an
// actor without authority is denied, and a statement over another change is not accepted
#[tokio::test]
async fn no_write_bypasses_the_commit() {
    // EI-25, PI-7, MUST-NEVER-1
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("shop-b").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let c = new_client(&w).await;
    let p = proposal(
        (tenant, realm),
        Change::ClientRegister(c.clone()),
        1,
        idp_anchor(d),
        1,
    );
    assert!(!matches!(
        exercise(&w, &p, ALICE_KEY).await,
        Ok(Applied::Written { .. } | Applied::AlreadyWritten { .. })
    ));
    let other = proposal(
        (tenant, realm),
        Change::ClientRegister(new_client(&w).await),
        2,
        idp_anchor(d),
        1,
    );
    let signed_other = w.admin().prepare(&other).await.unwrap();
    let ais = sign(
        &statement(signed_other.domain, &p.nonce, signed_other.digest, p.basis),
        ROOT_KEY,
    );
    assert!(!matches!(
        w.admin().apply(&p, ais).await,
        Ok(Applied::Written { .. } | Applied::AlreadyWritten { .. })
    ));
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert!(client(&mut t, c.id.as_str()).await.unwrap().is_none());
}

// IDP-5, IDI-4, OP-141 m.34 (b): the RP ID change is reserved and CT3, so its intent may stay
// valid up to the CT3 ceiling; a CT1 retire may not
#[tokio::test]
async fn an_rp_id_change_is_a_ct3_exercise() {
    // §13.7.1, §13.7.3, TI-RT3, K15
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("pass").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let c = new_client(&w).await;
    written(
        &exercise(
            &w,
            &proposal(
                (tenant, realm),
                Change::ClientRegister(c.clone()),
                1,
                idp_anchor(d),
                1,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let long_retire = proposal(
        (tenant, realm),
        Change::ClientRetire(ClientId::parse(c.id.as_str()).unwrap()),
        2,
        idp_anchor(d),
        48,
    );
    assert!(matches!(
        exercise(&w, &long_retire, ROOT_KEY).await,
        Err(access_identity_admin::AdminError::Refused(code)) if code == "protocol"
    ));
    let rp = proposal(
        (tenant, realm),
        Change::RpId(RpId::parse("id.test").unwrap()),
        3,
        idp_anchor(d),
        48,
    );
    written(&exercise(&w, &rp, ROOT_KEY).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, tenant, realm).await.unwrap();
    assert_eq!(
        settings(&mut t).await.unwrap().unwrap().rp_id.as_deref(),
        Some("id.test")
    );
    t.commit().await.unwrap();
    let foreign = proposal(
        (tenant, realm),
        Change::RpId(RpId::parse("other.test").unwrap()),
        4,
        idp_anchor(d),
        1,
    );
    assert!(w.admin().prepare(&foreign).await.is_err());
}

// OP-33, OP-146 m.4 (f), m.8 (e): realm Argon2 parameters rise and the JOSE algorithm changes
// only through commit
#[tokio::test]
async fn realm_settings_change_through_commit() {
    // CR-36, §17.5.2, K05
    use access_identity_account::domain::password::Argon2Params;
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("tune").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    let raise = Argon2Params {
        m_kib: 19 * 1024,
        t: 5,
        p: 1,
    };
    written(
        &exercise(
            &w,
            &proposal((tenant, realm), Change::Argon2(raise), 1, idp_anchor(d), 1),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    written(
        &exercise(
            &w,
            &proposal(
                (tenant, realm),
                Change::JoseAlg(JoseAlg::Ed25519),
                2,
                idp_anchor(d),
                1,
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let lower = proposal(
        (tenant, realm),
        Change::Argon2(Argon2Params::CANONICAL),
        3,
        idp_anchor(d),
        1,
    );
    assert!(w.admin().prepare(&lower).await.is_err());
    assert_eq!(
        access_identity_admin::app::jose_alg(&w.db.app, tenant, realm)
            .await
            .unwrap(),
        JoseAlg::Ed25519
    );
    // OP-146 m.16 (m), m.8 (e)
    assert_eq!(
        w.opened(),
        vec![
            (*realm.as_bytes(), JoseAlg::Es256),
            (*realm.as_bytes(), JoseAlg::Ed25519)
        ]
    );
}

/// A fresh token in the `SoftHSM` store `just test` prepares (`SOFTHSM2_CONF`, OP-69).
fn hsm(name: &str) -> (std::path::PathBuf, String) {
    assert!(
        std::env::var_os("SOFTHSM2_CONF").is_some(),
        "run the PKCS#11 tests through `just test`, which sets SOFTHSM2_CONF (OP-69)"
    );
    let module = [
        std::env::var("SUISS_PKCS11_MODULE").unwrap_or_default(),
        String::from("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        String::from("/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so"),
    ]
    .iter()
    .map(std::path::PathBuf::from)
    .find(|p| p.is_file())
    .unwrap();
    let label = format!("{name}-{}", std::process::id());
    let out = std::process::Command::new("softhsm2-util")
        .args([
            "--init-token",
            "--free",
            "--label",
            &label,
            "--pin",
            "1234-test-only",
            "--so-pin",
            "5678-test-only",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    (module, label)
}

// OP-146 m.16 (m), m.15 (e), m.7 (b), OP-94: a new realm's KEK, decoy key and DPoP nonce keys
// are made in the HSM once under their labels; the authorization server loads the nonce
// rings from them, and a realm without keys has none
#[test]
fn realm_keys_are_made_once_in_the_hsm() {
    static STORE: std::sync::OnceLock<Arc<KeyStore>> = std::sync::OnceLock::new();
    let store = STORE
        .get_or_init(|| {
            let (module, label) = hsm("realm-keys");
            let pin = Secret::new(String::from("1234-test-only"));
            Arc::new(KeyStore::open(&module, &label, &pin).unwrap())
        })
        .clone();
    let keyring = RealmKeyring::new(SignerKeys::new("/nonexistent.sock".into()), store.clone());
    let realm = [7; 16];
    keyring.hsm(&realm).unwrap();
    keyring.hsm(&realm).unwrap();
    store.kek(&kek_label(&realm)).unwrap();
    store.mac(&decoy_label(&realm)).unwrap();
    let nonces = crate::oauth::HsmNonces::new(store);
    for role in [NonceRole::AuthorizationServer, NonceRole::ResourceServer] {
        let ring = nonces.ring(RealmId::from_bytes(realm), role).unwrap();
        let n = ring.issue(NOW).unwrap();
        ring.check(Some(&n), NOW).unwrap();
    }
    assert!(
        nonces
            .ring(RealmId::from_bytes([8; 16]), NonceRole::AuthorizationServer)
            .is_none()
    );
}
