#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::time::Duration;

use access_authority_core::adapters::Setup;
use access_authority_core::genesis::{BOOTSTRAP_GRANT, IDP_ANCHOR};
use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::fold_check;
use access_crypto::event_id::EventKey;
use access_crypto::opaque_id::IdKey;
use access_crypto::secret::Secret;
use access_identity_admin::AdminError;
use access_identity_admin::app::{Admin, Applied, NewRealm, Proposal};
use access_identity_admin::domain::{
    AuthMethod, Change, Client, ClientId, Invalid, Platform, RedirectUri, RpId,
};
use access_identity_oauth::adapters::outbound::DeclaredTargets;
use access_identity_oauth::domain::issuer::{IssuerStyle, RealmBase};
use access_identity_signer::adapters::SealedFactory;
use access_identity_signer::ports::{Vault, VaultError};
use access_identity_signer::protocol::{
    Realm as SignerRealm, Request as SignerRequest, Response as SignerResponse,
};
use access_identity_signer::service::Service;
use access_internal_api::instances::{PlatformProduct, Registrant, register_nonce};
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::Capacity;
use access_kernel::intent::intent_digest;
use access_kernel::meta::{self, ActorKind, ExerciseBasis, Payload, Root, kind};
use access_kernel::model::{Id, Window};
use access_kernel::verify::cose::{ALG, CONTENT_TYPE as CT, KID, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::thumbprint;
use access_store::identity::{RealmId, TenantId, TenantTx};
use access_store::idp::{client, settings};
use access_store::tenancy::{create_tenant, route_by_slug};
use access_store::testing::{TestDb, fresh};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};
use suiss_crypto::envelope::SoftKek;
use suiss_crypto::rotation::Policy;

use super::*;
use crate::testing::hsm;

mod claims;
mod extensions;
mod governance;
mod platform;
mod records;
mod resources;

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

/// A fresh P-256 client key (MD-3, OP-149 m.20).
fn client_key() -> PublicKey {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).unwrap();
    PublicKey::P256(key.public_key().as_ref().to_vec())
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
    fn open_domain(&self, _: &Digest) -> Result<(), CoreError> {
        Ok(())
    }
}

#[derive(Clone)]
struct Fixed;

impl Clock for Fixed {
    fn now(&mut self) -> impl Future<Output = Result<u64, SequencerError>> + Send {
        std::future::ready(Ok(NOW))
    }
}

type TestPlane = Plane<AnyKeys, ActorBindings, OsSalts, Fixed>;

fn plane(db: &TestDb) -> TestPlane {
    let actors = ActorBindings::default();
    let domains = Arc::new(Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: AnyKeys,
        holder: String::from("t"),
        ttl: Duration::from_secs(10),
        binding: actors.clone(),
        salts: OsSalts,
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: None,
        api_base: String::from("https://access.test"),
    }));
    Plane::new(domains, db.app.clone(), Fixed, actors)
}

/// Realm key sets and Claim issuer keys, in memory.
#[derive(Default)]
struct MemVault(
    std::collections::BTreeMap<SignerRealm, Vec<u8>>,
    std::collections::BTreeMap<SignerRealm, Vec<u8>>,
);

impl Vault for MemVault {
    fn all(&mut self) -> Result<Vec<Vec<u8>>, VaultError> {
        Ok(self.0.values().cloned().collect())
    }

    fn put(&mut self, realm: &SignerRealm, bytes: &[u8]) -> Result<(), VaultError> {
        self.0.insert(*realm, bytes.to_vec());
        Ok(())
    }

    fn cell(&mut self) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(None)
    }

    fn put_cell(&mut self, _bytes: &[u8]) -> Result<(), VaultError> {
        Ok(())
    }

    fn issuer(&mut self, realm: &SignerRealm) -> Result<Option<Vec<u8>>, VaultError> {
        Ok(self.1.get(realm).cloned())
    }

    fn put_issuer(&mut self, realm: &SignerRealm, bytes: &[u8]) -> Result<(), VaultError> {
        self.1.insert(*realm, bytes.to_vec());
        Ok(())
    }
}

type TestSigner = Service<SealedFactory<SoftKek>, MemVault>;

/// The realm keys opened, in order, over an identity signer whose clock the test moves.
struct Opened {
    log: std::sync::Mutex<Vec<([u8; 16], JoseAlg)>>,
    signer: std::sync::Mutex<TestSigner>,
    now: std::sync::atomic::AtomicU64,
}

impl Default for Opened {
    fn default() -> Self {
        let factory = SealedFactory::new(SoftKek::new("realm-kek", [5; 32]));
        Self {
            log: std::sync::Mutex::default(),
            signer: std::sync::Mutex::new(
                Service::start(factory, MemVault::default(), Policy::REALM).unwrap(),
            ),
            now: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Opened {
    fn ask(&self, request: SignerRequest) -> SignerResponse {
        let now = self.now.load(std::sync::atomic::Ordering::SeqCst);
        self.signer.lock().unwrap().handle(request, now, 7)
    }

    /// Moves the signer's clock to `now` and runs its schedule.
    fn at(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            self.signer.lock().unwrap().tick(now, 7),
            Vec::<SignerRealm>::new()
        );
    }

    fn rekeyed(&self, request: SignerRequest) -> Result<(), Unavailable> {
        match self.ask(request) {
            SignerResponse::Rekeyed(_) => Ok(()),
            other => Err(Unavailable(format!("{other:?}"))),
        }
    }

    fn sign_claim(&self, realm: RealmId, payload: &[u8], at: u64) -> Result<Vec<u8>, Unavailable> {
        match self.ask(SignerRequest::SignClaim {
            realm: SignerRealm(*realm.as_bytes()),
            payload: payload.to_vec(),
            at,
        }) {
            SignerResponse::SignedCose { sign1, .. } => Ok(sign1),
            other => Err(Unavailable(format!("{other:?}"))),
        }
    }
}

impl RealmKeys for Opened {
    fn open(
        &self,
        realm: RealmId,
        alg: JoseAlg,
    ) -> impl std::future::Future<Output = Result<(), Unavailable>> + Send {
        self.log.lock().unwrap().push((*realm.as_bytes(), alg));
        let alg = match alg {
            JoseAlg::Es256 => JwsAlg::Es256,
            JoseAlg::Ed25519 => JwsAlg::Ed25519,
        };
        let r = self.ask(SignerRequest::Open {
            realm: SignerRealm(*realm.as_bytes()),
            alg,
        });
        std::future::ready(if r == SignerResponse::Opened {
            Ok(())
        } else {
            Err(Unavailable(format!("{r:?}")))
        })
    }

    fn jwks(
        &self,
        realm: RealmId,
    ) -> impl std::future::Future<Output = Result<String, Unavailable>> + Send {
        std::future::ready(
            match self.ask(SignerRequest::Jwks(SignerRealm(*realm.as_bytes()))) {
                SignerResponse::Jwks(doc) => Ok(doc),
                other => Err(Unavailable(format!("{other:?}"))),
            },
        )
    }

    fn rotate(
        &self,
        realm: RealmId,
        retire: [u8; 32],
    ) -> impl std::future::Future<Output = Result<(), Unavailable>> + Send {
        std::future::ready(self.rekeyed(SignerRequest::Rotate {
            realm: SignerRealm(*realm.as_bytes()),
            retire,
        }))
    }

    fn drop_key(
        &self,
        realm: RealmId,
        kid: [u8; 32],
    ) -> impl std::future::Future<Output = Result<(), Unavailable>> + Send {
        std::future::ready(self.rekeyed(SignerRequest::DropKey {
            realm: SignerRealm(*realm.as_bytes()),
            kid,
        }))
    }

    fn set_policy(
        &self,
        realm: RealmId,
        policy: Policy,
    ) -> impl std::future::Future<Output = Result<(), Unavailable>> + Send {
        std::future::ready(self.rekeyed(SignerRequest::SetPolicy {
            realm: SignerRealm(*realm.as_bytes()),
            policy,
        }))
    }

    fn open_issuer(
        &self,
        realm: RealmId,
        party: [u8; 16],
    ) -> impl std::future::Future<Output = Result<PublicKey, Unavailable>> + Send {
        std::future::ready(
            match self.ask(SignerRequest::OpenIssuer {
                realm: SignerRealm(*realm.as_bytes()),
                party,
            }) {
                SignerResponse::Issuer { key, .. } => Ok(PublicKey::Ed25519(key)),
                other => Err(Unavailable(format!("{other:?}"))),
            },
        )
    }

    fn sign_issuer_registration(
        &self,
        realm: RealmId,
        registration: access_identity_admin::ports::IssuerAis,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, Unavailable>> + Send {
        std::future::ready(
            match self.ask(SignerRequest::SignIssuerRegistration {
                realm: SignerRealm(*realm.as_bytes()),
                registration,
            }) {
                SignerResponse::SignedCose { sign1, .. } => Ok(sign1),
                other => Err(Unavailable(format!("{other:?}"))),
            },
        )
    }
}

/// One soft KEK for every realm, sealing hook and webhook keys (OP-42, OP-135).
struct TestKek(Arc<SoftKek>);

impl access_identity_events::adapters::RealmKek for TestKek {
    fn kek(
        &self,
        _: TenantId,
        _: RealmId,
    ) -> Option<Arc<dyn suiss_crypto::envelope::Kek + Send + Sync>> {
        Some(self.0.clone())
    }
}

struct World {
    db: TestDb,
    plane: TestPlane,
    ids: IdKey,
    base: RealmBase,
    keys: Opened,
    vault: access_identity_events::adapters::KekSealer<TestKek>,
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
            vault: access_identity_events::adapters::KekSealer(TestKek(Arc::new(SoftKek::new(
                "realm-kek",
                [9; 32],
            )))),
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
            platform_tenant: None,
            declared: DeclaredTargets::default(),
            vault: Some(&self.vault),
        }
    }

    fn opened(&self) -> Vec<([u8; 16], JoseAlg)> {
        self.keys.log.lock().unwrap().clone()
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
                schemas: Vec::new(),
                acceptances: Vec::new(),
                issuer_predicate_input: Vec::new(),
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
        .sign(&to_be_signed(&prot, &payload).unwrap())
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

/// The challenge a registration by the key `seed` answers: the `instance_create` nonce.
fn challenge_of(seed: u8) -> Vec<u8> {
    let mut c = vec![seed; 32];
    c[0] = 0xe1;
    c
}

/// The AIS by the key `seed` over the self-signed `payload` of `party` (OP-149 m.16 (a)).
fn self_signed(d: Digest, nonce: &[u8], payload: &Payload, party: Id, seed: u8) -> Vec<u8> {
    let validity = Window {
        from: 0,
        until: HOUR,
    };
    let intent = self_signed_intent(payload, party, validity).unwrap();
    sign(
        &statement(
            d,
            nonce,
            intent_digest(&intent).unwrap(),
            bootstrap_basis(&d),
        ),
        seed,
    )
}

/// The registration of `party` by `registrant` with the key `seed`, both Exercises signed by
/// that key: `party_register` when `new`, then `instance_create`.
fn registration(d: Digest, registrant: Registrant, party: Id, seed: u8, new: bool) -> Registration {
    let validity = Window {
        from: 0,
        until: HOUR,
    };
    let challenge = challenge_of(seed);
    let mut r = Registration {
        tenant: [0; 16],
        domain: d,
        registrant,
        party,
        key: public(seed),
        register: None,
        create: SelfSigned {
            nonce: challenge.clone(),
            validity,
            ais: Vec::new(),
        },
        pep: String::from(PEP),
    };
    r.create.ais = self_signed(d, &challenge, &r.create_payload(), party, seed);
    if new {
        let nonce = register_nonce(&challenge);
        r.register = Some(SelfSigned {
            ais: self_signed(d, &nonce, &r.register_payload(), party, seed),
            nonce,
            validity,
        });
    }
    r
}

fn device() -> Registrant {
    Registrant::Device {
        realm: [0; 16],
        subject: [0; 16],
    }
}

// L0-META-7, TN-111: the basis a self-signed registration names is the Genesis bootstrap Grant
#[test]
fn the_registration_basis_is_the_bootstrap_grant() {
    assert_eq!(
        access_internal_api::instances::BOOTSTRAP_GRANT,
        BOOTSTRAP_GRANT
    );
}

/// Registers `party` with the key `seed` through the identity plane's self-signed path
/// (L0-META-7, OP-149 m.16 (a)).
async fn onboard(plane: &TestPlane, d: Digest, party: Id, seed: u8) {
    let v = Instances::register(plane, registration(d, device(), party, seed, true))
        .await
        .unwrap();
    assert!(matches!(v, RegistrationVerdict::Registered(_)), "{v:?}");
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
        subject: None,
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
        require_par: false,
        subject: access_identity_admin::domain::Subject::default(),
        platform: None,
    }
}

/// The identity outbox's events of a kind that starts with `kind` once at least `n` are visible. The outbox watermark is
/// cluster-wide, so another test's open transaction delays an event, never loses it.
async fn identity_events(
    db: &TestDb,
    kind: &str,
    n: usize,
) -> Vec<access_store::identity::OutboxEvent> {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let queued: Vec<_> = access_store::identity::poll(
            &db.reader,
            access_store::identity::Cursor::default(),
            100,
        )
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind.starts_with(kind))
        .collect();
        if queued.len() >= n {
            return queued;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{} of {n} after 20 s",
            queued.len()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
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
    // OP-149 m.4, m.17 (e)
    let created = identity_events(&w.db, "event.tenant.", 1).await;
    assert_eq!(created.len(), 1);
    let event = access_identity_events::domain::catalog::IdentityEvent::from_outbox(
        &created[0].kind,
        &created[0].payload,
    )
    .unwrap();
    assert_eq!(event.payload["placement"], "pool-default");
    let taken = w
        .admin()
        .create_realm(&NewRealm {
            tenant,
            slug: "acme",
            style: IssuerStyle::Subdomain,
            placement: "pool-default",
            root: Root::Sole(ROOT),
            ct3_delay_s: None,
            schemas: Vec::new(),
            acceptances: Vec::new(),
            issuer_predicate_input: Vec::new(),
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
    // OP-149 m.4: the write queued one api_client.created in its transaction; the retry none
    let queued = identity_events(&w.db, "event.api_client.", 1).await;
    assert_eq!(queued.len(), 1);
    assert_eq!(queued[0].kind, "event.api_client.created");
    let event = access_identity_events::domain::catalog::IdentityEvent::from_outbox(
        &queued[0].kind,
        &queued[0].payload,
    )
    .unwrap();
    assert_eq!(event.payload["client_id"], c.id.as_str());
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

// MD-5a, TN-1, INV-37, F21: a realm has one governing domain; an idp.* commit about it in a
// domain that only consumes its Claims, even by that domain's own root, finds no covering
// authority, and the identity plane binds only its governing domain's decision
#[tokio::test]
async fn only_the_governing_domain_commits_a_realm_change() {
    // MD-14, CI-15, EI-25, E34
    let w = World::new().await;
    let (tenant, realm, d) = w.realm("gov-a").await;
    let (_, _, other) = w.realm("gov-b").await;
    onboard(&w.plane, d, ROOT, ROOT_KEY).await;
    onboard(&w.plane, other, ROOT, ROOT_KEY).await;
    let c = new_client(&w).await;
    let p = proposal(
        (tenant, realm),
        Change::ClientRegister(c.clone()),
        3,
        idp_anchor(other),
        1,
    );
    let intent = p.change.intent("gov-a", p.validity).unwrap();
    let digest = intent_digest(&intent).unwrap();
    let v = Decider::decide(
        &w.plane,
        Submission {
            domain: other,
            nonce: p.nonce.clone(),
            intent,
            basis: p.basis,
            capacity: p.capacity,
            ais: sign(&statement(other, &p.nonce, digest, p.basis), ROOT_KEY),
            pep: String::from(PEP),
            actor: None,
        },
    )
    .await
    .unwrap();
    let Verdict::NotAllowed { decision, .. } = v else {
        panic!("{v:?}");
    };
    assert!(
        decision
            .blockers
            .iter()
            .any(|b| b.class == access_kernel::combinator::BlockerClass::NoCoveringAuthority),
        "{decision:?}"
    );
    let ais = sign(&statement(other, &p.nonce, digest, p.basis), ROOT_KEY);
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
        Err(access_identity_admin::AdminError::Refused(code)) if code == "intent-validity"
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

fn platform_client(id: ClientId, product: PlatformProduct, seed: u8) -> Client {
    Client {
        id,
        display_name: String::from("Suiss Work"),
        auth: AuthMethod::PrivateKeyJwtKey { key: client_key() },
        redirect_uris: vec![RedirectUri::parse("https://work.suiss.example/cb").unwrap()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        subject: access_identity_admin::domain::Subject::default(),
        platform: Some(Platform {
            product,
            service_key: public(seed.wrapping_add(1)),
            event_receiver: Some(String::from("https://work.suiss.example/ssf")),
        }),
    }
}

// OP-149 m.4, CT2: only the platform tenant registers a platform product client; it uses
// private_key_jwt with one registered key and names its service key and event receiver
#[tokio::test]
async fn a_platform_client_is_registered_in_the_platform_tenant() {
    // MD-14, EI-25, RFC 7523, OP-62
    let w = World::new().await;
    let (pt, pr, pd) = w.realm("platform").await;
    let (t2, _, _) = w.realm("acme").await;
    onboard(&w.plane, pd, ROOT, ROOT_KEY).await;
    let c = platform_client(
        w.admin().new_client_id().await.unwrap(),
        PlatformProduct::parse("work").unwrap(),
        40,
    );
    let p = proposal(
        (pt, pr),
        Change::ClientRegister(c.clone()),
        3,
        idp_anchor(pd),
        1,
    );
    assert!(matches!(
        w.admin().prepare(&p).await,
        Err(AdminError::Invalid(Invalid::PlatformTenant))
    ));
    let elsewhere = Admin {
        platform_tenant: Some(t2),
        ..w.admin()
    };
    assert!(matches!(
        elsewhere.prepare(&p).await,
        Err(AdminError::Invalid(Invalid::PlatformTenant))
    ));
    let platform = Admin {
        platform_tenant: Some(pt),
        ..w.admin()
    };
    let public_client = Client {
        auth: AuthMethod::None,
        ..c.clone()
    };
    assert_eq!(
        Change::ClientRegister(public_client).check(&DeclaredTargets::default()),
        Err(Invalid::PlatformAuth)
    );
    let prepared = platform.prepare(&p).await.unwrap();
    let ais = sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        ROOT_KEY,
    );
    written(&platform.apply(&p, ais).await.unwrap());
    let mut t = TenantTx::begin(&w.db.app, pt, pr).await.unwrap();
    let row = client(&mut t, c.id.as_str()).await.unwrap().unwrap();
    t.commit().await.unwrap();
    assert_eq!(row.auth_method, "private_key_jwt");
    assert_eq!(row.jwks_uri, None);
    assert!(row.jwks.unwrap().contains(r#""crv":"P-256""#));
    assert_eq!(row.platform_product.as_deref(), Some("work"));
    assert_eq!(
        row.event_receiver.as_deref(),
        Some("https://work.suiss.example/ssf")
    );
    // OP-149 m.4, m.17a
    let created = identity_events(&w.db, "event.api_client.", 1).await;
    let event = access_identity_events::domain::catalog::IdentityEvent::from_outbox(
        &created[0].kind,
        &created[0].payload,
    )
    .unwrap();
    assert_eq!(event.payload["platform_product"], "work");
    // CR-24
    let key = client_key();
    assert!(
        AuthMethod::PrivateKeyJwtKey { key: key.clone() }
            .jwks()
            .unwrap()
            .contains(&access_kernel::json::b64url_encode(&thumbprint(&key)))
    );

    // OP-149 m.17a
    let retire = proposal(
        (pt, pr),
        Change::ClientRetire(c.id.clone()),
        4,
        idp_anchor(pd),
        1,
    );
    let prepared = platform.prepare(&retire).await.unwrap();
    let ais = sign(
        &statement(
            prepared.domain,
            &retire.nonce,
            prepared.digest,
            retire.basis,
        ),
        ROOT_KEY,
    );
    written(&platform.apply(&retire, ais).await.unwrap());
    let events = identity_events(&w.db, "event.api_client.", 2).await;
    assert_eq!(events[1].kind, "event.api_client.disabled");
    let disabled = access_identity_events::domain::catalog::IdentityEvent::from_outbox(
        &events[1].kind,
        &events[1].payload,
    )
    .unwrap();
    assert_eq!(disabled.payload["platform_product"], "work");
}

// OP-149 m.6, OP-146 m.4 (i): a device Instance is ended by an instance_terminate its own Party
// signed, forwarded as the identity plane's PEP
#[tokio::test]
async fn a_party_terminates_its_own_instance_through_the_identity_plane() {
    // L0-META-1, TN-50
    let w = World::new().await;
    let (_, _, d) = w.realm("acme").await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let create = challenge_of(ALICE_KEY);
    let register = register_nonce(&create);
    let anchor = meta::object_id(&meta::exercise_id(&d, &register).unwrap(), kind::ANCHOR, 0);
    let instance = meta::object_id(&meta::exercise_id(&d, &create).unwrap(), kind::INSTANCE, 0);
    let validity = Window {
        from: 0,
        until: HOUR,
    };
    let intent = terminate_intent(instance, validity).unwrap();
    let nonce = vec![0x5a; 16];
    let basis = ExerciseBasis::Anchor(anchor);
    let mut s = statement(d, &nonce, intent_digest(&intent).unwrap(), basis);
    s.pep = String::from("access-identity");
    let t = Termination {
        domain: d,
        nonce: nonce.clone(),
        instance,
        validity,
        basis,
        ais: sign(&s, ALICE_KEY),
        pep: String::from("access-identity"),
    };
    let wrong_pep = Termination {
        pep: String::from("someone-else"),
        ..t.clone()
    };
    assert!(!matches!(
        w.plane.terminate(wrong_pep).await.unwrap(),
        Verdict::Committed(_)
    ));
    let Verdict::Committed(c) = w.plane.terminate(t.clone()).await.unwrap() else {
        panic!("not committed");
    };
    assert_eq!(c.nonce, nonce);
    let again = w.plane.terminate(t).await.unwrap();
    assert_eq!(
        again,
        Verdict::Refused {
            code: String::from("ais-mismatch"),
            errors: Vec::new(),
        },
        "the ended Instance signs nothing more"
    );
}

/// Seals nothing: the test's streams push SETs and hold no webhook secret.
struct NoSeal;

impl access_identity_events::ports::Sealer for NoSeal {
    fn seal(
        &self,
        _: TenantId,
        _: RealmId,
        _: &[u8; 16],
        _: &[u8],
    ) -> Result<access_store::events::SealedKey, access_identity_events::Unavailable> {
        Err(access_identity_events::Unavailable)
    }

    fn open(
        &self,
        _: TenantId,
        _: RealmId,
        _: &[u8; 16],
        _: &access_store::events::SealedKey,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, access_identity_events::Unavailable> {
        Err(access_identity_events::Unavailable)
    }
}

// OP-149 m.17 (e), m.26 (d), m.4: a stream owned by a platform product client receives the
// events of every tenant, tenant.created among them, each SET naming the tenant it happened in
// (the platform tenant's own too); a tenant's own stream receives only its tenant's events
// without the claim, and only a platform client may own such a stream
#[tokio::test]
async fn a_platform_subscription_receives_every_tenant() {
    // OP-131, TN-1, OP-132 m.3
    use access_identity_events::app::Db;
    use access_identity_events::app::fanout::Fanout;
    use access_identity_events::app::streams::{StreamError, Streams};
    use access_identity_events::domain::catalog::{IdentityEvent, urn};
    use access_identity_events::domain::stream::parse_stream;
    use access_identity_oauth::adapters::dpop::SystemClock as OAuthClock;
    use access_identity_oauth::adapters::oauth::OsRandom;

    let w = World::new().await;
    let (pt, pr, pd) = w.realm("platform").await;
    onboard(&w.plane, pd, ROOT, ROOT_KEY).await;
    let platform = Admin {
        platform_tenant: Some(pt),
        ..w.admin()
    };
    let c = platform_client(
        w.admin().new_client_id().await.unwrap(),
        PlatformProduct::parse("work").unwrap(),
        40,
    );
    let p = proposal(
        (pt, pr),
        Change::ClientRegister(c.clone()),
        3,
        idp_anchor(pd),
        1,
    );
    let prepared = platform.prepare(&p).await.unwrap();
    let ais = sign(
        &statement(prepared.domain, &p.nonce, prepared.digest, p.basis),
        ROOT_KEY,
    );
    written(&platform.apply(&p, ais).await.unwrap());

    let db = Db {
        app: w.db.app.clone(),
        reader: w.db.reader.clone(),
        ids: Arc::new(IdKey::new(Secret::new([8; 32]))),
    };
    let streams = Streams::new(db.clone(), NoSeal, OsRandom);
    let request = |aud: &str| {
        parse_stream(
            &serde_json::to_vec(&serde_json::json!({
                "delivery": {"method": "urn:ietf:rfc:8935", "endpoint_url": "https://work.example/ssf"},
                "aud": aud,
                "events_requested": [urn("tenant.created"), urn("api_client.created")],
            }))
            .unwrap(),
        )
        .unwrap()
    };
    let shop = new_client(&w).await;
    assert!(matches!(
        streams
            .create_for_platform(pt, pr, &request("work"), shop.id.as_str())
            .await,
        Err(StreamError::NotFound)
    ));
    let work = streams
        .create_for_platform(pt, pr, &request("work"), c.id.as_str())
        .await
        .unwrap();

    let (t2, r2, _) = w.realm("acme").await;
    let own = streams.create(t2, r2, &request("acme")).await.unwrap();
    let listed = access_store::events::platform_subscriptions(&w.db.reader)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, work.id);

    let created = identity_events(&w.db, "event.tenant.", 2).await;
    let ids: Vec<(String, String)> = created
        .iter()
        .map(|e| {
            let e = IdentityEvent::from_outbox(&e.kind, &e.payload).unwrap();
            (
                e.ready().id,
                e.payload["tenant"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let fanout = Fanout::new(db, OAuthClock);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut queued = 0;
    while queued < 4 {
        queued += fanout.identity_step().await.unwrap();
        assert!(
            std::time::Instant::now() < deadline,
            "{queued} of 4 after 20 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // OP-149 m.15 (i)
    let uuid = |t: TenantId| {
        use access_identity_events::ports::TenantIds as _;
        w.ids.external(t.as_bytes()).unwrap()
    };
    let (acme_event, _) = ids.iter().find(|(_, t)| *t == uuid(t2)).unwrap();
    let (platform_event, _) = ids.iter().find(|(_, t)| *t == uuid(pt)).unwrap();
    let mut t = TenantTx::begin(&w.db.app, pt, pr).await.unwrap();
    let across = t.delivery(pr, work.id, acme_event).await.unwrap().unwrap();
    let home = t
        .delivery(pr, work.id, platform_event)
        .await
        .unwrap()
        .unwrap();
    t.commit().await.unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&across.payload).unwrap();
    assert_eq!(claims["access_tenant"], uuid(t2));
    assert_eq!(claims["aud"], "work");
    assert!(claims["events"].get(urn("tenant.created")).is_some());
    let claims: serde_json::Value = serde_json::from_slice(&home.payload).unwrap();
    assert_eq!(claims["access_tenant"], uuid(pt));
    assert_eq!(claims["events"][urn("tenant.created")]["tenant"], uuid(pt));
    let mut t = TenantTx::begin(&w.db.app, t2, r2).await.unwrap();
    let mine = t.delivery(r2, own.id, acme_event).await.unwrap().unwrap();
    let claims: serde_json::Value = serde_json::from_slice(&mine.payload).unwrap();
    assert!(claims.get("access_tenant").is_none());
    assert!(
        t.delivery(r2, own.id, platform_event)
            .await
            .unwrap()
            .is_none()
    );
    t.commit().await.unwrap();
}

// OP-149 m.16 (a), L0-META-7, §7.9.2.3: a registration commits only with Exercises the new key
// itself signed while the identity plane binds it to the checked Party; another key's
// signature, someone else's Party or a Party that was never registered gets nothing, and the
// binding ends with the request
#[tokio::test]
async fn self_signed_registration_binds_only_the_signing_key() {
    // E6, OP-141 m.2
    let w = World::new().await;
    let (_, _, d) = w.realm("acme").await;
    onboard(&w.plane, d, ALICE, ALICE_KEY).await;
    let registered = |v: &RegistrationVerdict| matches!(v, RegistrationVerdict::Registered(_));

    let mut forged = registration(d, device(), Id([4; 16]), 13, true);
    let other = registration(d, device(), Id([4; 16]), 14, true);
    forged.create.ais = other.create.ais;
    forged.register = other.register;
    let v = Instances::register(&w.plane, forged).await.unwrap();
    assert!(!registered(&v), "{v:?}");

    let taken = registration(d, device(), ALICE, 15, true);
    let v = Instances::register(&w.plane, taken).await.unwrap();
    assert!(!registered(&v), "{v:?}");

    let never = registration(d, device(), Id([5; 16]), 16, false);
    let v = Instances::register(&w.plane, never).await.unwrap();
    assert!(!registered(&v), "{v:?}");

    let second = registration(d, device(), ALICE, 17, false);
    let v = Instances::register(&w.plane, second.clone()).await.unwrap();
    let RegistrationVerdict::Registered(r) = v else {
        panic!("{v:?}");
    };
    assert_eq!((r.party, r.instance), (ALICE, second.instance().unwrap()));
    for seed in [13, 14, 15, 16, 17] {
        assert!(w.plane.actors.bound(&thumbprint(&public(seed))).is_none());
    }
}
