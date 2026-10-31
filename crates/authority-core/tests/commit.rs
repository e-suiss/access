//! §17.1.1, OP-141, L2-REC-5: the commit path end to end on a real PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, PgReader, Setup};
use access_authority_core::app::{Authority, Incoming, Response};
use access_authority_core::domain::{ProofRef, Request};
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::{PgLog, create_genesis, fold_check};
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::ports::Clock;
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{
    self, ExerciseBasis, GrantBasis, GrantContent, HoldingRef, Payload, Root, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Binding as ProofBinding, CanonicalAuthority, ConstraintSet,
    Consumption, DelegationTerms, EqValue, Id, Independence, ProofKind, RequirementTerm,
    ResourceRef, ResourceSelector, Structural, SubjectSelector, Window,
};
use access_kernel::record::Opened;
use access_kernel::verify::cose::{ALG, CONTENT_TYPE as CT, KID, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::thumbprint;
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
const TTL: Duration = Duration::from_secs(10);
const ROOT: Id = Id([1; 16]);
const ALICE: Id = Id([2; 16]);
const ROOT_KEY: u8 = 11;
const ALICE_KEY: u8 = 12;
const PEP: &str = "pep.example";
const NOW: u64 = 10_000;

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

fn action(namespace: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: Digest([9; 32]),
    }
}

fn selector(namespace: &str) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: namespace.to_owned(),
        prefix: Vec::new(),
        kind: None,
        attrs: BTreeMap::new(),
    })
}

fn authority(actions: Vec<ActionRef>, resource: ResourceSelector) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: actions.into_iter().collect(),
                prefix: BTreeSet::new(),
            },
            resource,
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: 1_000_000,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth: 0,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::new(),
    }
}

fn sole(p: Id) -> Value {
    Value::Map(vec![(Value::text("sole"), p.to_value())])
}

/// Genesis (L0-META-7): ROOT roots the meta-anchor and a `shop` Anchor; a Public Grant on
/// the meta-anchor lets anyone register and create Instances.
fn genesis() -> BTreeMap<String, Opened> {
    let opened = |value| Opened {
        value,
        salt: [3; 32],
    };
    let bootstrap = Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(0)),
        (Value::text("holder"), SubjectSelector::Public.to_value()),
        (
            Value::text("authority"),
            authority(
                vec![
                    action("access", "party_register"),
                    action("access", "instance_create"),
                ],
                selector("access.party"),
            )
            .to_value(),
        ),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ]);
    let shop = Value::Map(vec![
        (
            Value::text("scope"),
            Value::Map(vec![(Value::text("resource"), selector("shop").to_value())]),
        ),
        (Value::text("root"), sole(ROOT)),
    ]);
    BTreeMap::from([
        (
            "meta_anchor".to_owned(),
            opened(Value::Map(vec![(Value::text("root"), sole(ROOT))])),
        ),
        ("anchors".to_owned(), opened(Value::Array(vec![shop]))),
        ("grants".to_owned(), opened(Value::Array(vec![bootstrap]))),
        (
            "versions".to_owned(),
            opened(Value::Map(vec![
                (Value::text("core"), Value::Unsigned(1)),
                (Value::text("meta_schema"), Value::Unsigned(1)),
            ])),
        ),
    ])
}

/// The identity plane's actor-binding, fixed for the test.
#[derive(Clone)]
struct Bound(BTreeMap<[u8; 32], (Id, PublicKey)>);

impl Binding for Bound {
    fn bound(&self, kid: &[u8; 32]) -> Option<(Id, PublicKey)> {
        self.0.get(kid).cloned()
    }
}

#[derive(Clone)]
struct Counter(u8);

impl Salts for Counter {
    fn salt(&mut self) -> Result<[u8; 32], CoreError> {
        self.0 = self.0.wrapping_add(1);
        Ok([self.0; 32])
    }
}

type Core = Authority<PgLog, PgReader, Bound, Counter>;

fn binding() -> Bound {
    Bound(BTreeMap::from([
        (thumbprint(&public(ROOT_KEY)), (ROOT, public(ROOT_KEY))),
        (thumbprint(&public(ALICE_KEY)), (ALICE, public(ALICE_KEY))),
    ]))
}

async fn setup(db: &TestDb) -> (Core, Digest) {
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    (Authority::new(leader, reader, binding(), Counter(0), d), d)
}

fn sign(s: &Statement, seed: u8) -> Vec<u8> {
    let with = signing(seed);
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
    let sig = with.sign(&to_be_signed(&prot, &payload)).to_bytes();
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

fn intent(act: ActionRef, resource: (&str, &str), payload: Option<&Payload>) -> IntentEnvelope {
    IntentEnvelope {
        action: act,
        resources: vec![ResourceRef {
            namespace: resource.0.to_owned(),
            path: vec![resource.1.to_owned()],
            incarnation: 0,
        }],
        params: BTreeMap::new(),
        opaque: payload
            .map(|p| BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]))
            .unwrap_or_default(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
    }
}

fn meta_request(d: Digest, nonce: u8, basis: ExerciseBasis, payload: Payload) -> Request {
    Request {
        domain: d,
        mode: Mode::Commit,
        nonce: vec![nonce; 16],
        intent: intent(
            action("access", payload.action()),
            ("access.party", "p"),
            Some(&payload),
        ),
        payload: Some(payload),
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

fn shop_request(d: Digest, nonce: u8, mode: Mode, basis: ExerciseBasis) -> Request {
    Request {
        domain: d,
        mode,
        nonce: vec![nonce; 16],
        intent: intent(action("shop", "read"), ("shop", "item-1"), None),
        payload: None,
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

fn incoming(request: Request, seed: u8) -> Incoming {
    let digest = access_kernel::intent::intent_digest(&request.intent).unwrap();
    let statement = Statement {
        domain: request.domain,
        nonce: request.nonce.clone(),
        intent: digest,
        mode: request.mode,
        pep: PEP.to_owned(),
        capacity: request.capacity,
        basis: request.basis,
        iat: NOW,
        exercise: request.exercise,
    };
    Incoming {
        ais: Some(sign(&statement, seed)),
        request,
        pep: PEP.to_owned(),
        explain: false,
    }
}

async fn send(core: &mut Core, request: Request, seed: u8) -> Result<Response, CoreError> {
    core.exercise(&incoming(request, seed), NOW).await
}

fn allowed(r: &Response) {
    assert_eq!(r.decision.outcome, Outcome::Allow, "{r:?}");
}

/// Registers `party` with the key `seed` under the Public bootstrap Grant.
async fn onboard(core: &mut Core, d: Digest, party: Id, seed: u8, nonces: (u8, u8)) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
    };
    allowed(
        &send(
            core,
            meta_request(d, nonces.0, public_basis, register),
            seed,
        )
        .await
        .unwrap(),
    );
    let create = Payload::InstanceCreate {
        party,
        key: public(seed),
        mandate: None,
    };
    allowed(
        &send(core, meta_request(d, nonces.1, public_basis, create), seed)
            .await
            .unwrap(),
    );
}

#[tokio::test]
async fn a_grant_allows_until_it_is_revoked() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;

    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: authority(vec![action("shop", "read")], selector("shop")),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let issued = send(
        &mut core,
        meta_request(d, 5, ExerciseBasis::Anchor(shop), issue),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    let grant = meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant,
        holder: ALICE,
        since: issued.record.unwrap(),
    });

    let read = send(
        &mut core,
        shop_request(d, 6, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&read);
    assert!(!read.replayed);

    let revoke = Payload::GrantRevoke { grant };
    allowed(
        &send(
            &mut core,
            meta_request(d, 7, ExerciseBasis::Anchor(shop), revoke),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let after = send(
        &mut core,
        shop_request(d, 8, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(after.decision.outcome, Outcome::Deny);
    assert!(after.exercise.is_none());

    fold_check(&db.sequencer, d).await.unwrap();
}

#[tokio::test]
async fn a_nonce_returns_its_decision_and_binds_its_intent() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);

    let first = send(
        &mut core,
        shop_request(d, 9, Mode::Commit, ExerciseBasis::Anchor(shop)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&first);
    let again = send(
        &mut core,
        shop_request(d, 9, Mode::Commit, ExerciseBasis::Anchor(shop)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert!(again.replayed);
    assert_eq!(again.record, first.record);
    assert_eq!(again.exercise, first.exercise);

    let mut other = shop_request(d, 9, Mode::Commit, ExerciseBasis::Anchor(shop));
    other.intent.resources[0].path = vec!["item-2".to_owned()];
    assert!(matches!(
        send(&mut core, other, ROOT_KEY).await,
        Err(CoreError::Nonce)
    ));

    fold_check(&db.sequencer, d).await.unwrap();
}

#[tokio::test]
async fn check_mode_records_nothing() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let head = access_store::authority::read_head(&db.app, &DomainId::from_bytes(d.0))
        .await
        .unwrap()
        .pos;

    let checked = send(
        &mut core,
        shop_request(d, 10, Mode::Check, ExerciseBasis::Anchor(shop)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&checked);
    assert!(checked.record.is_none() && checked.exercise.is_none());
    let after = access_store::authority::read_head(&db.app, &DomainId::from_bytes(d.0))
        .await
        .unwrap()
        .pos;
    assert_eq!(after, head);
}

#[tokio::test]
async fn an_unknown_key_is_not_an_actor() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let r = send(
        &mut core,
        shop_request(d, 11, Mode::Commit, ExerciseBasis::Anchor(shop)),
        99,
    )
    .await;
    assert_eq!(r.unwrap_err().code(), "ais-mismatch");
}

#[tokio::test]
async fn an_anonymous_meta_action_is_denied() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party: ROOT,
        root: Root::Sole(ROOT),
    };
    let mut inc = incoming(meta_request(d, 12, public_basis, register), ROOT_KEY);
    inc.ais = None;
    let r = core.exercise(&inc, NOW).await.unwrap();
    assert_eq!(r.decision.outcome, Outcome::Deny);
    fold_check(&db.sequencer, d).await.unwrap();
}

/// Event-id keys of the listed domains only.
struct Listed(Vec<Digest>);

impl Keys for Listed {
    fn event_key(&self, domain: &Digest) -> Result<EventKey, CoreError> {
        if self.0.contains(domain) {
            Ok(EventKey::new(Secret::new([5; 32])))
        } else {
            Err(CoreError::Unavailable("event-key"))
        }
    }

    fn token_key(&self, _domain: &Digest) -> Result<access_crypto::token::TokenKey, CoreError> {
        Ok(access_crypto::token::TokenKey::new(Secret::new([6; 32])))
    }
}

#[derive(Clone)]
struct Fixed;

impl Clock for Fixed {
    fn now(&mut self) -> impl Future<Output = Result<u64, SequencerError>> + Send {
        std::future::ready(Ok(NOW))
    }
}

fn process(db: &TestDb, holder: &str, keys: Vec<Digest>) -> Domains<Listed, Bound, Counter, Fixed> {
    Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(keys),
        holder: holder.to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(0),
        clock: Fixed,
        deriver: db.deriver.clone(),
    })
}

fn unavailable(r: Result<Response, CoreError>) -> &'static str {
    match r {
        Err(CoreError::Unavailable(why)) => why,
        other => panic!("{other:?}"),
    }
}

// OP-141 m.18 (a), (d), OP-31: a process leads a domain from its first request until it
// releases it; an unknown domain, a domain led elsewhere and a domain without its key are
// unavailable
#[tokio::test]
async fn a_process_leads_a_domain_from_its_first_request() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    let b = process(&db, "b", vec![d]);
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let read = |nonce| {
        incoming(
            shop_request(d, nonce, Mode::Commit, ExerciseBasis::Anchor(shop)),
            ROOT_KEY,
        )
    };

    let mut unknown = read(1);
    unknown.request.domain = Digest([0x77; 32]);
    assert_eq!(unavailable(a.exercise(&unknown).await), "unknown-domain");

    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (nonce, payload) in [
        (
            2,
            Payload::PartyRegister {
                party: ROOT,
                root: Root::Sole(ROOT),
            },
        ),
        (
            3,
            Payload::InstanceCreate {
                party: ROOT,
                key: public(ROOT_KEY),
                mandate: None,
            },
        ),
    ] {
        let inc = incoming(meta_request(d, nonce, public_basis, payload), ROOT_KEY);
        allowed(&a.exercise(&inc).await.unwrap());
    }
    let first = a.exercise(&read(4)).await.unwrap();
    allowed(&first);
    // OP-141 m.22 (e): the record is named by an opaque reference
    let reference = first.basis_ref.clone().unwrap();
    assert!(reference.len() >= 48);

    // OP-141 m.22 (f): a reader is answered at or after what it has seen, never before
    let mut seen = read(40);
    seen.request.mode = Mode::Check;
    seen.request.consistency = first.consistency.clone();
    let ais = incoming(seen.request.clone(), ROOT_KEY);
    allowed(&a.exercise(&ais).await.unwrap());
    let ahead = access_crypto::token::TokenKey::new(Secret::new([6; 32]))
        .seal(&d.0, "consistency", &9_999_u64.to_be_bytes())
        .unwrap();
    let mut early = ais;
    early.request.consistency = Some(ahead);
    assert_eq!(unavailable(a.exercise(&early).await), "consistency");
    assert_eq!(unavailable(b.exercise(&read(5)).await), "lease-held");

    a.renew().await;
    a.release().await;
    let again = b.exercise(&read(4)).await.unwrap();
    assert!(again.replayed);
    assert_eq!(again.record, first.record);
    allowed(&b.exercise(&read(5)).await.unwrap());
    fold_check(&db.sequencer, d).await.unwrap();

    let e = create_genesis(&db.sequencer, TENANT, genesis(), 1_001)
        .await
        .unwrap();
    let mut keyless = read(6);
    keyless.request.domain = e;
    assert_eq!(unavailable(a.exercise(&keyless).await), "event-key");
}

// ---------------------------------------------------------------- D5a (OP-141 m.19)

fn term(kind: ProofKind, class: &str, binding: ProofBinding) -> RequirementTerm {
    RequirementTerm {
        proof_kind: kind,
        class: class.to_owned(),
        count: 1,
        binding,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    }
}

/// Genesis where acting on `shop` needs `terms`, ALICE issues `kyc` Claims under a
/// predicate-input Acceptance and holds a Grant to contribute `approve`.
fn gated(terms: &[RequirementTerm]) -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let opened = |value| Opened {
        value,
        salt: [3; 32],
    };
    let set = |v: Vec<Value>| Value::Array(v);
    let shop = Value::Map(vec![
        (
            Value::text("scope"),
            Value::Map(vec![(Value::text("resource"), selector("shop").to_value())]),
        ),
        (Value::text("root"), sole(ROOT)),
        (
            Value::text("root_terms"),
            set(terms.iter().map(Canonical::to_value).collect()),
        ),
    ]);
    g.insert("anchors".to_owned(), opened(set(vec![shop])));
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    grants.push(Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(0)),
        (
            Value::text("holder"),
            SubjectSelector::Party(ALICE).to_value(),
        ),
        (
            Value::text("authority"),
            authority(
                vec![action("access", "contribute")],
                selector("access.contribution"),
            )
            .to_value(),
        ),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ]));
    g.insert("grants".to_owned(), opened(set(grants)));
    let acceptance = Value::Map(vec![
        (Value::text("issuer"), ALICE.to_value()),
        (Value::text("use"), Value::text("predicate-input")),
        (Value::text("classes"), set(vec![Value::text("kyc")])),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            set(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
        ),
        (
            Value::text("quota"),
            Value::Map(vec![
                (Value::text("count"), Value::Unsigned(1)),
                (Value::text("window_s"), Value::Unsigned(3_600)),
            ]),
        ),
    ]);
    g.insert("acceptances".to_owned(), opened(set(vec![acceptance])));
    g
}

async fn setup_with(db: &TestDb, g: BTreeMap<String, Opened>) -> (Core, Digest) {
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    (Authority::new(leader, reader, binding(), Counter(0), d), d)
}

fn claim(d: Digest, issuer: Id, seed: u8, class: &str) -> Vec<u8> {
    claim_at(d, issuer, seed, class, NOW)
}

fn claim_at(d: Digest, issuer: Id, seed: u8, class: &str, issued_at: u64) -> Vec<u8> {
    let st = access_kernel::claim::Statement {
        domain: d,
        issuer,
        subject: ROOT,
        class: class.to_owned(),
        value: Some(EqValue::Bool(true)),
        issued_at,
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    };
    let with = signing(seed);
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (
                Value::Unsigned(CT),
                Value::text(access_kernel::claim::CONTENT_TYPE),
            ),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public(seed)).to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let payload = st.to_bytes().unwrap();
    let sig = with.sign(&to_be_signed(&prot, &payload)).to_bytes();
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

fn with_proofs(mut r: Request, proofs: Vec<ProofRef>) -> Request {
    r.proofs = proofs;
    r
}

// OP-141 m.19 (a)–(d), (h), L2-CLM-3, L2-CLM-4: an accepted Claim meets the requirement on the
// same nonce; a Claim no Acceptance covers is recorded in quarantine and meets nothing
#[tokio::test]
async fn an_accepted_claim_meets_a_requirement() {
    let db = fresh().await.unwrap();
    let kyc = term(ProofKind::Claim, "kyc", ProofBinding::None);
    let (mut core, d) = setup_with(&db, gated(&[kyc])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));

    let asked = send(&mut core, shop_request(d, 9, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);

    let untrusted = claim(d, ROOT, ROOT_KEY, "kyc");
    let again = send(
        &mut core,
        with_proofs(
            shop_request(d, 9, Mode::Commit, shop),
            vec![ProofRef::Claim(untrusted.clone())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(again.decision.outcome, Outcome::RequireAction);
    let id = access_kernel::claim::claim_id(&untrusted);
    assert!(
        state_of(&db, d, &meta::key(kind::CLAIM, &id))
            .await
            .is_none()
    );

    let good = claim(d, ALICE, ALICE_KEY, "kyc");
    let allowed_now = send(
        &mut core,
        with_proofs(
            shop_request(d, 9, Mode::Commit, shop),
            vec![ProofRef::Claim(good.clone())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&allowed_now);
    let id = access_kernel::claim::claim_id(&good);
    assert!(
        state_of(&db, d, &meta::key(kind::CLAIM, &id))
            .await
            .is_some()
    );

    // the recorded Claim is referenced by its id on a new nonce
    let by_ref = send(
        &mut core,
        with_proofs(
            shop_request(d, 10, Mode::Commit, shop),
            vec![ProofRef::ClaimRef(id)],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&by_ref);

    // L2-CLM-2: a Claim signed by a key the domain does not know is a protocol error
    let forged = claim(d, ALICE, 77, "kyc");
    let refused = send(
        &mut core,
        with_proofs(
            shop_request(d, 11, Mode::Commit, shop),
            vec![ProofRef::Claim(forged)],
        ),
        ROOT_KEY,
    )
    .await;
    assert_eq!(refused.unwrap_err().code(), "protocol");
    fold_check(&db.sequencer, d).await.unwrap();
}

async fn state_of(db: &TestDb, d: Digest, key: &[u8]) -> Option<Vec<u8>> {
    access_store::authority::state_of(&db.app, &DomainId::from_bytes(d.0), &[key.to_vec()])
        .await
        .unwrap()
        .into_iter()
        .next()
        .and_then(|r| r.value)
}

fn contribute(d: Digest, nonce: u8, target: Digest) -> Request {
    let payload = Payload::Contribute {
        target,
        class: "approve".to_owned(),
    };
    let mut r = meta_request(
        d,
        nonce,
        ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&d, kind::GRANT, 1),
            holder: ALICE,
            since: 0,
        }),
        payload,
    );
    r.intent.resources = vec![ResourceRef {
        namespace: "access.contribution".to_owned(),
        path: vec!["approve".to_owned()],
        incarnation: 0,
    }];
    let p = r.payload.clone().unwrap();
    r.intent.opaque = BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]);
    r
}

// OP-141 m.19 (e)–(h), L0-META-30: an approval is a contribution bound to the intent; it meets
// the requirement once and is consumed
#[tokio::test]
async fn a_contribution_approves_once() {
    let db = fresh().await.unwrap();
    let approve = term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    );
    let (mut core, d) = setup_with(&db, gated(&[approve])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let target = shop_request(d, 9, Mode::Commit, shop);
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();

    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);

    let given = send(&mut core, contribute(d, 20, digest), ALICE_KEY)
        .await
        .unwrap();
    allowed(&given);
    let approval = given.exercise.unwrap();

    let done = send(
        &mut core,
        with_proofs(target, vec![ProofRef::Contribution(approval)]),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);

    // consumed: the same contribution does not approve the same intent on a new nonce
    let reused = send(
        &mut core,
        with_proofs(
            shop_request(d, 10, Mode::Commit, shop),
            vec![ProofRef::Contribution(approval)],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(reused.decision.outcome, Outcome::RequireAction);

    // L0-META-30: without a Grant over the class, a contribution is denied
    let mut other = contribute(d, 21, digest);
    other.basis = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let denied = send(&mut core, other, ROOT_KEY).await.unwrap();
    assert_ne!(denied.decision.outcome, Outcome::Allow);
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-141 m.19 (i), L1-ADP-13: a continuation names the Exercise it continues
#[tokio::test]
async fn a_continuation_names_its_exercise() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let first = send(&mut core, shop_request(d, 9, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    allowed(&first);
    let exercise = first.exercise.unwrap();

    let mut cont = shop_request(d, 30, Mode::Continue, shop);
    cont.exercise = Some(exercise);
    let next = send(&mut core, cont.clone(), ROOT_KEY).await.unwrap();
    allowed(&next);
    assert_eq!(next.exercise, Some(exercise));

    let mut wrong = shop_request(d, 31, Mode::Continue, shop);
    wrong.exercise = Some(Digest([4; 32]));
    assert!(matches!(
        send(&mut core, wrong, ROOT_KEY).await,
        Err(CoreError::Protocol("exercise"))
    ));
    let mut missing = shop_request(d, 32, Mode::Continue, shop);
    missing.exercise = None;
    assert!(matches!(
        send(&mut core, missing, ROOT_KEY).await,
        Err(CoreError::Protocol("exercise"))
    ));
    fold_check(&db.sequencer, d).await.unwrap();
}

// ---------------------------------------------------------------- D5b (OP-141 m.20)

/// Genesis where ALICE is the membership issuer of `staff` and members of `staff` hold a Grant
/// to read the shop.
fn grouped() -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let opened = |value| Opened {
        value,
        salt: [3; 32],
    };
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let staff = SubjectSelector::Pred(BTreeSet::from([access_kernel::model::Conjunct {
        claim_class: "staff".to_owned(),
        value: None,
    }]));
    grants.push(Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(1)),
        (Value::text("holder"), staff.to_value()),
        (
            Value::text("authority"),
            authority(vec![action("shop", "read")], selector("shop")).to_value(),
        ),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ]));
    g.insert("grants".to_owned(), opened(Value::Array(grants)));
    let acceptance = Value::Map(vec![
        (Value::text("issuer"), ALICE.to_value()),
        (Value::text("use"), Value::text("subject-selection")),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text("staff")]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
        ),
    ]);
    g.insert(
        "acceptances".to_owned(),
        opened(Value::Array(vec![acceptance])),
    );
    g
}

// OP-141 m.20 (a)–(d): a member of a group holds the group's Grant from its episode start
#[tokio::test]
async fn a_member_holds_the_groups_grant_from_its_episode() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, grouped()).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let grant = meta::object_id(&d, kind::GRANT, 1);
    let holding = |since| {
        ExerciseBasis::Holding(HoldingRef {
            grant,
            holder: ROOT,
            since,
        })
    };

    // L0-EVAL-60: a holding the actor does not hold is no basis at all
    assert!(matches!(
        send(
            &mut core,
            shop_request(d, 8, Mode::Commit, holding(0)),
            ROOT_KEY
        )
        .await,
        Err(CoreError::Rejected(_))
    ));
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let membership = claim(d, ALICE, ALICE_KEY, "staff");
    let ingested = send(
        &mut core,
        with_proofs(
            shop_request(d, 9, Mode::Commit, shop),
            vec![ProofRef::Claim(membership)],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&ingested);
    let episode = ingested.record.unwrap() - 2;

    let member = send(
        &mut core,
        shop_request(d, 10, Mode::Commit, holding(episode)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&member);

    assert!(matches!(
        send(
            &mut core,
            shop_request(d, 11, Mode::Commit, holding(episode - 1)),
            ROOT_KEY
        )
        .await,
        Err(CoreError::Rejected(_))
    ));

    // a Claim from an issuer that is not the group's makes no member
    let outsider = claim(d, ROOT, ROOT_KEY, "staff");
    let id = access_kernel::claim::claim_id(&outsider);
    send(
        &mut core,
        with_proofs(
            shop_request(d, 12, Mode::Commit, shop),
            vec![ProofRef::Claim(outsider)],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert!(
        state_of(&db, d, &meta::key(kind::CLAIM, &id))
            .await
            .is_none()
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-141 m.21 (a): an issuer admits twice its declared quota per window; the rest wait in
// quarantine
#[tokio::test]
async fn an_issuer_quota_quarantines_the_excess() {
    let db = fresh().await.unwrap();
    let kyc = term(ProofKind::Claim, "kyc", ProofBinding::None);
    let (mut core, d) = setup_with(&db, gated(&[kyc])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let claims: Vec<Vec<u8>> = (0..3)
        .map(|i| claim_at(d, ALICE, ALICE_KEY, "kyc", NOW - i))
        .collect();
    let r = send(
        &mut core,
        with_proofs(
            shop_request(d, 9, Mode::Commit, shop),
            claims.iter().cloned().map(ProofRef::Claim).collect(),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&r);
    let stored = |i: usize| meta::key(kind::CLAIM, &access_kernel::claim::claim_id(&claims[i]));
    assert!(state_of(&db, d, &stored(0)).await.is_some());
    assert!(state_of(&db, d, &stored(1)).await.is_some());
    assert!(state_of(&db, d, &stored(2)).await.is_none());
    fold_check(&db.sequencer, d).await.unwrap();
}

// ---------------------------------------------------------------- D6 (OP-141 m.22)

fn search_request(d: Digest, nonce: u8, kind: &str) -> Request {
    Request {
        domain: d,
        mode: Mode::Check,
        nonce: vec![nonce; 16],
        intent: intent(action("access", "search"), ("access.search", kind), None),
        payload: None,
        basis: ExerciseBasis::Public(Id([0; 16])),
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

// OP-141 m.22 (g), (j), E26: the index names candidates; a root sees who can act within its
// Anchor, a Party sees what it reaches itself, and nobody sees more
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from onboarding to every search kind"
)]
async fn search_shows_what_the_reader_may_see() {
    use access_authority_core::query::{Hit, Query};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (party, seed, n) in [(ROOT, ROOT_KEY, 1), (ALICE, ALICE_KEY, 3)] {
        for (nonce, payload) in [
            (
                n,
                Payload::PartyRegister {
                    party,
                    root: Root::Sole(party),
                },
            ),
            (
                n + 1,
                Payload::InstanceCreate {
                    party,
                    key: public(seed),
                    mandate: None,
                },
            ),
        ] {
            let inc = incoming(meta_request(d, nonce, public_basis, payload), seed);
            allowed(&a.exercise(&inc).await.unwrap());
        }
    }
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let grant = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: authority(vec![action("shop", "read")], selector("shop")),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let mut issue = meta_request(d, 5, ExerciseBasis::Anchor(shop), grant);
    issue.intent.resources = vec![ResourceRef {
        namespace: "shop".to_owned(),
        path: vec![],
        incarnation: 0,
    }];
    let p = issue.payload.clone().unwrap();
    issue.intent.opaque = BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]);
    allowed(&a.exercise(&incoming(issue, ROOT_KEY)).await.unwrap());
    assert!(a.derive().await.is_empty());

    let item = ResourceRef {
        namespace: "shop".to_owned(),
        path: vec!["item-1".to_owned()],
        incarnation: 0,
    };
    let who = Query::Subject {
        action: action("shop", "read"),
        resource: item.clone(),
    };
    let (hits, next) = a
        .search(
            &incoming(search_request(d, 50, "subject"), ROOT_KEY),
            &who,
            None,
        )
        .await
        .unwrap();
    assert_eq!(hits, [Hit::Party(ALICE)]);
    assert!(next.is_none());
    let (hits, _) = a
        .search(
            &incoming(search_request(d, 51, "subject"), ALICE_KEY),
            &who,
            None,
        )
        .await
        .unwrap();
    assert_eq!(hits, []);

    let mine = Query::Resource {
        party: ALICE,
        action: action("shop", "read"),
    };
    let (hits, _) = a
        .search(
            &incoming(search_request(d, 52, "resource"), ALICE_KEY),
            &mine,
            None,
        )
        .await
        .unwrap();
    assert_eq!(hits, [Hit::Resource(selector("shop"))]);
    let theirs = Query::Action {
        party: ROOT,
        resource: item,
    };
    let (hits, _) = a
        .search(
            &incoming(search_request(d, 53, "action"), ALICE_KEY),
            &theirs,
            None,
        )
        .await
        .unwrap();
    assert_eq!(hits, []);
    let mut anonymous = incoming(search_request(d, 54, "resource"), ALICE_KEY);
    anonymous.ais = None;
    assert_eq!(a.search(&anonymous, &mine, None).await.unwrap().0, []);
    // §13.7.4, OP-141 m.23: ten searches a minute per reader
    for n in 0..7 {
        a.search(
            &incoming(search_request(d, 60 + n, "resource"), ALICE_KEY),
            &mine,
            None,
        )
        .await
        .unwrap();
    }
    assert!(matches!(
        a.search(
            &incoming(search_request(d, 70, "resource"), ALICE_KEY),
            &mine,
            None
        )
        .await,
        Err(CoreError::Limited)
    ));
    // the search intent must name the search kind
    assert!(matches!(
        a.search(
            &incoming(search_request(d, 55, "action"), ALICE_KEY),
            &mine,
            None
        )
        .await,
        Err(CoreError::Protocol("search"))
    ));
}
