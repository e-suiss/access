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

/// The Action Schema the test catalog publishes for `name` (OP-141 m.35).
fn schema_of(name: &str) -> access_kernel::schema::ActionSchema {
    access_kernel::schema::ActionSchema {
        name: name.to_owned(),
        major: 1,
        effect: access_kernel::schema::EffectClass::Reversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::new(),
        resource_types: BTreeSet::new(),
        render: None,
    }
}

fn action(namespace: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: namespace.to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: access_kernel::schema::action_digest(&schema_of(name)),
    }
}

/// The `schema-definition` Acceptance that publishes the `shop` actions (OP-141 m.35).
fn shop_schemas() -> Value {
    let spp = access_kernel::schema::Spp {
        publisher: ROOT,
        namespace: "shop".to_owned(),
        catalog_version: 1,
        actions: vec![schema_of("read")],
        retirements: BTreeSet::new(),
        core_spec_min: None,
    };
    Value::Map(vec![
        (Value::text("issuer"), ROOT.to_value()),
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
    ])
}

/// Adds Acceptances to a Genesis, keeping the set in canonical order.
fn add_acceptances(g: &mut BTreeMap<String, Opened>, extra: Vec<Value>) {
    let mut all = match g.get("acceptances").map(|o| o.value.clone()) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    all.extend(extra);
    let mut keyed: Vec<(Vec<u8>, Value)> = all
        .into_iter()
        .map(|v| {
            let b = dcbor::encode(&v, Limits::CEILING).unwrap();
            (b.clone(), dcbor::decode(&b, Limits::CEILING).unwrap())
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    g.insert(
        "acceptances".to_owned(),
        Opened {
            value: Value::Array(keyed.into_iter().map(|(_, v)| v).collect()),
            salt: [3; 32],
        },
    );
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
            "acceptances".to_owned(),
            opened(Value::Array(vec![shop_schemas()])),
        ),
        // OP-141 m.34 (d): the scenarios below run without the CT3 time-lock
        (
            "policy".to_owned(),
            opened(Value::Map(vec![(
                Value::text("ct3_delay_s"),
                Value::Unsigned(0),
            )])),
        ),
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
    gated_with(terms, 1)
}

fn gated_with(terms: &[RequirementTerm], quota: u64) -> BTreeMap<String, Opened> {
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
                (Value::text("count"), Value::Unsigned(quota)),
                (Value::text("window_s"), Value::Unsigned(3_600)),
            ]),
        ),
    ]);
    add_acceptances(&mut g, vec![acceptance]);
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
    claim_after(d, issuer, seed, class, issued_at, None)
}

fn claim_after(
    d: Digest,
    issuer: Id,
    seed: u8,
    class: &str,
    issued_at: u64,
    supersedes: Option<Id>,
) -> Vec<u8> {
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
        supersedes,
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

// TI-RT7, OP-141 m.30: a Claim with a recorded successor in its issuer line no longer asserts,
// and a fork leaves neither side asserting
#[tokio::test]
async fn a_superseded_claim_no_longer_asserts() {
    let db = fresh().await.unwrap();
    let kyc = term(ProofKind::Claim, "kyc", ProofBinding::None);
    let (mut core, d) = setup_with(&db, gated_with(&[kyc], 2)).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut nonce = 20;
    let mut prove = async |core: &mut Core, proof: ProofRef| {
        nonce += 1;
        send(
            core,
            with_proofs(shop_request(d, nonce, Mode::Commit, shop), vec![proof]),
            ROOT_KEY,
        )
        .await
        .unwrap()
        .decision
        .outcome
    };
    let first = claim(d, ALICE, ALICE_KEY, "kyc");
    let first_id = access_kernel::claim::claim_id(&first);
    assert_eq!(
        prove(&mut core, ProofRef::Claim(first)).await,
        Outcome::Allow
    );
    let next = claim_after(d, ALICE, ALICE_KEY, "kyc", NOW, Some(first_id));
    let next_id = access_kernel::claim::claim_id(&next);
    assert_eq!(
        prove(&mut core, ProofRef::Claim(next)).await,
        Outcome::Allow
    );
    assert!(
        state_of(
            &db,
            d,
            &access_kernel::claim::successor_key(&first_id, &next_id)
        )
        .await
        .is_some()
    );
    assert_eq!(
        prove(&mut core, ProofRef::ClaimRef(first_id)).await,
        Outcome::RequireAction
    );
    let fork = claim_after(d, ALICE, ALICE_KEY, "kyc", NOW - 1, Some(first_id));
    assert_eq!(
        prove(&mut core, ProofRef::Claim(fork)).await,
        Outcome::RequireAction
    );
    assert_eq!(
        prove(&mut core, ProofRef::ClaimRef(next_id)).await,
        Outcome::RequireAction
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// SEC12, OP-141 m.31: an accepted party_compromise Claim restricts the Party's Instances set up
// at or after its occurredAt; a later Claim in the issuer's line moves occurredAt
#[tokio::test]
async fn a_compromise_restricts_instances_set_up_after_it() {
    let db = fresh().await.unwrap();
    let mut g = genesis();
    add_acceptances(
        &mut g,
        vec![Value::Map(vec![
            (Value::text("issuer"), ROOT.to_value()),
            (Value::text("use"), Value::text("predicate-input")),
            (
                Value::text("classes"),
                Value::Array(vec![Value::text(access_kernel::claim::PARTY_COMPROMISE)]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
            ),
        ])],
    );
    let (mut core, d) = setup_with(&db, g).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let meta_anchor = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let compromise = |nonce, at: i64, supersedes| {
        meta_request(
            d,
            nonce,
            meta_anchor,
            Payload::ClaimIssue {
                subject: ALICE,
                class: access_kernel::claim::PARTY_COMPROMISE.to_owned(),
                value: EqValue::Int(at),
                validity: None,
                bound_intent: None,
                supersedes,
            },
        )
    };
    let restricted = |r: &Response| {
        r.decision
            .blockers
            .iter()
            .any(|b| b.subcode.as_deref() == Some("party-compromise"))
    };
    let later = send(&mut core, compromise(10, 20_000, None), ROOT_KEY)
        .await
        .unwrap();
    allowed(&later);
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let before = send(&mut core, shop_request(d, 11, Mode::Check, shop), ALICE_KEY)
        .await
        .unwrap();
    assert!(!restricted(&before));
    let first = meta::object_id(&later.exercise.unwrap(), kind::CLAIM, 0);
    allowed(
        &send(&mut core, compromise(12, 5_000, Some(first)), ROOT_KEY)
            .await
            .unwrap(),
    );
    let after = send(&mut core, shop_request(d, 13, Mode::Check, shop), ALICE_KEY)
        .await
        .unwrap();
    assert_eq!(after.decision.outcome, Outcome::Deny);
    assert!(restricted(&after));
    let root = send(&mut core, shop_request(d, 14, Mode::Check, shop), ROOT_KEY)
        .await
        .unwrap();
    assert!(!restricted(&root));
    fold_check(&db.sequencer, d).await.unwrap();
}

// L0-EVAL-4, OP-141 m.33: a Grant held while a Claim is held lapses until the Claim is
// recorded under the named Acceptance, and while-instance-alive needs a live Instance
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one Grant through both while-conditions"
)]
async fn while_conditions_are_prepared_on_the_commit_path() {
    use access_kernel::model::WhileCondition;
    let db = fresh().await.unwrap();
    let kyc = term(ProofKind::Claim, "kyc", ProofBinding::None);
    let (mut core, d) = setup_with(&db, gated(&[kyc])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let mut acceptance = None;
    for seq in 0..2 {
        let key = meta::key(
            kind::ACCEPTANCE,
            &meta::object_id(&d, kind::ACCEPTANCE, seq),
        );
        let state = state_of(&db, d, &key).await.unwrap();
        let state =
            meta::ContentState::from_value(&dcbor::decode(&state, Limits::CEILING).unwrap())
                .unwrap();
        if state.content.get("use") == Some(&Value::text("predicate-input")) {
            acceptance = Some(state);
        }
    }
    let acceptance = acceptance.unwrap();
    let held = WhileCondition::ClaimHeld {
        class: "kyc".to_owned(),
        subject: SubjectSelector::Party(ROOT),
        acceptance: access_kernel::claim::acceptance_digest(&acceptance.content),
    };
    let meta_anchor = meta::meta_anchor(&d);
    let grant_to_alice = |nonce, condition: WhileCondition| {
        let mut granted = authority(vec![action("shop", "read")], selector("shop"));
        granted.constraints.conditions = BTreeSet::from([condition]);
        meta_request(
            d,
            nonce,
            ExerciseBasis::Anchor(meta_anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta_anchor),
                holder: SubjectSelector::Party(ALICE),
                authority: granted,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
    };
    let holding = |r: &Response| {
        ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&r.exercise.unwrap(), kind::GRANT, 0),
            holder: ALICE,
            since: r.record.unwrap(),
        })
    };
    let issued = send(&mut core, grant_to_alice(10, held), ROOT_KEY)
        .await
        .unwrap();
    allowed(&issued);
    let lapsed = send(
        &mut core,
        shop_request(d, 11, Mode::Commit, holding(&issued)),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(lapsed.decision.outcome, Outcome::Deny);
    assert!(
        lapsed
            .decision
            .blockers
            .iter()
            .any(|b| b.subcode.as_deref() == Some("ended/lapsed"))
    );
    // the Claim arrives with another request and is recorded under the Acceptance
    send(
        &mut core,
        with_proofs(
            shop_request(d, 12, Mode::Commit, ExerciseBasis::Anchor(meta_anchor)),
            vec![ProofRef::Claim(claim(d, ALICE, ALICE_KEY, "kyc"))],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(
        &send(
            &mut core,
            shop_request(d, 13, Mode::Commit, holding(&issued)),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let gone = send(
        &mut core,
        grant_to_alice(14, WhileCondition::InstanceAlive(Id([9; 16]))),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&gone);
    let denied = send(
        &mut core,
        shop_request(d, 15, Mode::Commit, holding(&gone)),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(denied.decision.outcome, Outcome::Deny);
    fold_check(&db.sequencer, d).await.unwrap();
}

// SEC26, OP-141 m.34: a CT3 meta-action waits out the time-lock on its nonce, counted from the
// nonce's first decision; a narrowing one does not
#[tokio::test]
async fn a_ct3_expansion_waits_out_the_time_lock() {
    use access_kernel::combinator::{BlockerClass, Remediation};
    let db = fresh().await.unwrap();
    let mut g = genesis();
    g.remove("policy");
    let (mut core, d) = setup_with(&db, g).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let set = send(
        &mut core,
        policy_set(
            d,
            10,
            None,
            r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };"#,
            None,
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&set);
    let policy = meta::object_id(&set.exercise.unwrap(), kind::POLICY, 0);
    let retire = || {
        let mut r = meta_request(
            d,
            11,
            ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            Payload::PolicyRetire { policy },
        );
        r.intent.validity = Window {
            from: NOW,
            until: NOW + 72 * 3_600_000,
        };
        r
    };
    let waiting = send(&mut core, retire(), ROOT_KEY).await.unwrap();
    assert_eq!(waiting.decision.outcome, Outcome::RequireAction);
    let lock = NOW + 86_400_000;
    assert!(waiting.decision.blockers.iter().any(|b| {
        b.class == BlockerClass::Restricted
            && b.subcode.as_deref() == Some("time-lock")
            && b.remediation == Remediation::WaitUntil(lock)
    }));
    let early = core
        .exercise(&incoming(retire(), ROOT_KEY), lock - 1)
        .await
        .unwrap();
    assert_eq!(early.decision.outcome, Outcome::RequireAction);
    allowed(
        &core
            .exercise(&incoming(retire(), ROOT_KEY), lock)
            .await
            .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.7.3, OP-141 m.34 (b): an intent valid for longer than its tier allows is refused
#[tokio::test]
async fn an_intent_beyond_its_tier_ceiling_is_refused() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let mut r = shop_request(
        d,
        10,
        Mode::Check,
        ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1)),
    );
    r.intent.validity.until = r.intent.validity.from + 86_400_001;
    assert!(matches!(
        send(&mut core, r, ROOT_KEY).await,
        Err(CoreError::Protocol("intent-validity"))
    ));
}

// OP-141 m.35 (e): a domain action is evaluated only when an accepted SPP of its namespace
// publishes exactly that action and schema
#[tokio::test]
async fn an_action_without_an_accepted_schema_is_denied() {
    use access_kernel::combinator::BlockerClass;
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let not_accepted = |r: &Response| {
        r.decision.outcome == Outcome::Deny
            && r.decision.blockers.iter().any(|b| {
                b.class == BlockerClass::SchemaNotAccepted
                    && b.subcode.as_deref() == Some("unknown-action")
            })
    };
    allowed(
        &send(&mut core, shop_request(d, 10, Mode::Commit, shop), ROOT_KEY)
            .await
            .unwrap(),
    );
    let mut other = shop_request(d, 11, Mode::Commit, shop);
    other.intent.action = action("shop", "refund");
    assert!(not_accepted(
        &send(&mut core, other, ROOT_KEY).await.unwrap()
    ));
    let mut changed = shop_request(d, 12, Mode::Commit, shop);
    changed.intent.action.schema = Digest([9; 32]);
    assert!(not_accepted(
        &send(&mut core, changed, ROOT_KEY).await.unwrap()
    ));
}

// L1-ADP-15, OP-141 m.36: a recorded decision is explained by evaluating its request again on
// the state and counters just before it, also after the state has moved on
#[tokio::test]
async fn a_recorded_decision_is_explained_as_it_was() {
    use access_kernel::model::{BudgetDimension, BudgetTerm, BudgetWindow};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let meta_anchor = meta::meta_anchor(&d);
    let mut granted = authority(vec![action("shop", "read")], selector("shop"));
    granted.constraints.budget = BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 1,
        window: BudgetWindow::Total,
    }]);
    let issued = send(
        &mut core,
        meta_request(
            d,
            10,
            ExerciseBasis::Anchor(meta_anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta_anchor),
                holder: SubjectSelector::Party(ALICE),
                authority: granted,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    let grant = meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant,
        holder: ALICE,
        since: issued.record.unwrap(),
    });
    let first = send(
        &mut core,
        shop_request(d, 11, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&first);
    let second = send(
        &mut core,
        shop_request(d, 12, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(second.decision.outcome, Outcome::Deny);
    // the Grant is revoked afterwards; both decisions still explain as recorded
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                13,
                ExerciseBasis::Anchor(meta_anchor),
                Payload::GrantRevoke { grant },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let explain = |nonce, record| {
        let inc = incoming(shop_request(d, nonce, Mode::Commit, holding), ALICE_KEY);
        (inc, record)
    };
    let (inc, record) = explain(11, first.record.unwrap());
    let again = core.explain_recorded(&inc, record, NOW).await.unwrap();
    assert_eq!(again.decision, first.decision);
    let (inc, record) = explain(12, second.record.unwrap());
    let again = core.explain_recorded(&inc, record, NOW).await.unwrap();
    assert_eq!(again.decision, second.decision);
    // the request must be the recorded one, from its actor
    let (inc, _) = explain(11, 0);
    assert!(matches!(
        core.explain_recorded(&inc, second.record.unwrap(), NOW)
            .await,
        Err(CoreError::Protocol("explain-record"))
    ));
    let other = incoming(shop_request(d, 11, Mode::Commit, holding), ROOT_KEY);
    assert!(matches!(
        core.explain_recorded(&other, first.record.unwrap(), NOW)
            .await,
        Err(CoreError::Protocol("explain-record"))
    ));
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

    // SEC11: a contribution from an Instance that has since ended approves nothing
    let again = send(&mut core, contribute(d, 22, digest), ALICE_KEY)
        .await
        .unwrap();
    allowed(&again);
    let alice = meta::object_id(&meta::exercise_id(&d, &[4; 16]).unwrap(), kind::INSTANCE, 0);
    let end = Payload::InstanceTerminate { instance: alice };
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                23,
                ExerciseBasis::Anchor(meta::object_id(
                    &meta::exercise_id(&d, &[3; 16]).unwrap(),
                    kind::ANCHOR,
                    0,
                )),
                end,
            ),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let stale = send(
        &mut core,
        with_proofs(
            shop_request(d, 11, Mode::Commit, shop),
            vec![ProofRef::Contribution(again.exercise.unwrap())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(stale.decision.outcome, Outcome::RequireAction);

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

// §13.4 G31, L1-ADP-13: after the Grant is revoked, a continuation of an allowed Exercise is
// a new decision against the current state and is denied
#[tokio::test]
async fn a_continuation_after_revocation_is_denied() {
    use access_kernel::combinator::BlockerClass;
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let meta_anchor = meta::meta_anchor(&d);
    let issued = send(
        &mut core,
        meta_request(
            d,
            10,
            ExerciseBasis::Anchor(meta_anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(meta_anchor),
                holder: SubjectSelector::Party(ALICE),
                authority: authority(vec![action("shop", "read")], selector("shop")),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
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
    let first = send(
        &mut core,
        shop_request(d, 11, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&first);
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                12,
                ExerciseBasis::Anchor(meta_anchor),
                Payload::GrantRevoke { grant },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let mut cont = shop_request(d, 13, Mode::Continue, holding);
    cont.exercise = first.exercise;
    let next = send(&mut core, cont, ALICE_KEY).await.unwrap();
    assert_eq!(next.decision.outcome, Outcome::Deny);
    assert!(
        next.decision
            .blockers
            .iter()
            .any(|b| b.class == BlockerClass::Ended)
    );
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
    add_acceptances(&mut g, vec![acceptance]);
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
    let issued = a.exercise(&incoming(issue, ROOT_KEY)).await.unwrap();
    allowed(&issued);
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
    // §13.4 Check/List: a party the subject search lists is allowed by a check, one it does not
    // list is not
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    });
    allowed(
        &a.exercise(&incoming(
            shop_request(d, 80, Mode::Check, holding),
            ALICE_KEY,
        ))
        .await
        .unwrap(),
    );
    assert_ne!(
        a.exercise(&incoming(
            shop_request(d, 81, Mode::Check, holding),
            ROOT_KEY
        ))
        .await
        .unwrap()
        .decision
        .outcome,
        Outcome::Allow
    );
    // OP-141 m.37: the eligible approvers of a class are the subject search for `contribute`
    let meta_anchor = meta::meta_anchor(&d);
    let approve = meta_request(
        d,
        82,
        ExerciseBasis::Anchor(meta_anchor),
        Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Anchor(meta_anchor),
            holder: SubjectSelector::Party(ALICE),
            authority: authority(
                vec![action("access", "contribute")],
                selector("access.contribution"),
            ),
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        }),
    );
    allowed(&a.exercise(&incoming(approve, ROOT_KEY)).await.unwrap());
    assert!(a.derive().await.is_empty());
    let eligible = Query::Subject {
        action: action("access", "contribute"),
        resource: ResourceRef {
            namespace: "access.contribution".to_owned(),
            path: vec!["approve".to_owned()],
            incarnation: 0,
        },
    };
    let (hits, _) = a
        .search(
            &incoming(search_request(d, 83, "subject"), ROOT_KEY),
            &eligible,
            None,
        )
        .await
        .unwrap();
    assert_eq!(hits, [Hit::Party(ALICE)]);
}

// ---------------------------------------------------------------- budgets (OP-141 m.26)

// L0-EVAL-15, OP-141 m.26, m.28: a Grant's budget is drawn by each allow and exhausts, and a
// grounded release returns a draw once
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one budget through draw, exhaustion and release"
)]
async fn a_budget_is_drawn_until_it_is_exhausted() {
    use access_kernel::combinator::BlockerClass;
    use access_kernel::model::{BudgetDimension, BudgetTerm, BudgetWindow};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let mut granted = authority(vec![action("shop", "read")], selector("shop"));
    granted.constraints.budget = BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 2,
        window: BudgetWindow::Total,
    }]);
    let grant = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: granted,
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
    let issued = send(&mut core, issue, ROOT_KEY).await.unwrap();
    allowed(&issued);
    let g = meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: g,
        holder: ALICE,
        since: issued.record.unwrap(),
    });
    let mut spent = None;
    for n in [20, 21] {
        let request = shop_request(d, n, Mode::Commit, holding);
        let digest = access_kernel::intent::intent_digest(&request.intent).unwrap();
        let answer = send(&mut core, request, ALICE_KEY).await.unwrap();
        allowed(&answer);
        spent = Some((answer.exercise.unwrap(), digest));
    }
    let over = send(
        &mut core,
        shop_request(d, 22, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(over.decision.outcome, Outcome::Deny);
    assert!(
        over.decision
            .blockers
            .iter()
            .any(|b| b.class == BlockerClass::BudgetExhausted)
    );
    // check does not draw
    let checked = send(
        &mut core,
        shop_request(d, 23, Mode::Check, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(checked.decision.outcome, Outcome::Deny);
    // OP-141 m.28: a grounded release returns the draw once
    let (exercise, intent) = spent.unwrap();
    let ground = send(
        &mut core,
        meta_request(
            d,
            24,
            ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            Payload::ClaimIssue {
                subject: ALICE,
                class: meta::NON_EXECUTION.to_owned(),
                value: access_kernel::model::EqValue::Bool(true),
                validity: None,
                bound_intent: Some(intent),
                supersedes: None,
            },
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&ground);
    let claim = meta::object_id(&ground.exercise.unwrap(), kind::CLAIM, 0);
    let release = |nonce| {
        meta_request(
            d,
            nonce,
            holding,
            Payload::ConsumptionRelease {
                exercise,
                grounds: BTreeSet::from([claim]),
            },
        )
    };
    allowed(&send(&mut core, release(25), ALICE_KEY).await.unwrap());
    let again = send(&mut core, release(26), ALICE_KEY).await.unwrap();
    assert!(again.decision.blockers.iter().any(|b| {
        b.class == BlockerClass::BudgetExhausted
            && b.subcode.as_deref() == Some("release-exceeds-draw")
    }));
    allowed(
        &send(
            &mut core,
            shop_request(d, 27, Mode::Commit, holding),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let over = send(
        &mut core,
        shop_request(d, 28, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(over.decision.outcome, Outcome::Deny);
    fold_check(&db.sequencer, d).await.unwrap();
}

// ---------------------------------------------------------------- restrictions (OP-141 m.27)

fn policy_set(
    d: Digest,
    nonce: u8,
    policy: Option<Id>,
    source: &str,
    requirements: Option<Value>,
) -> Request {
    let mut content = vec![
        (Value::text("schema"), Value::text("access/restriction/v1")),
        (Value::text("source"), Value::text(source)),
        (Value::text("target"), Value::text("domain")),
    ];
    if let Some(r) = requirements {
        content.push((Value::text("requirements"), r));
    }
    let content = Value::Map(content);
    let content = dcbor::decode(
        &dcbor::encode(&content, Limits::CEILING).unwrap(),
        Limits::CEILING,
    )
    .unwrap();
    meta_request(
        d,
        nonce,
        ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        Payload::PolicySet { policy, content },
    )
}

// L0-EVAL-18, OP-141 m.27: a domain policy denies, a @require policy asks for its requirement,
// a policy that does not compile is never set, and a retired policy stops applying
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario through a policy's life"
)]
async fn restriction_policies_narrow_the_commit_path() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    allowed(
        &send(&mut core, shop_request(d, 9, Mode::Commit, shop), ROOT_KEY)
            .await
            .unwrap(),
    );

    assert!(matches!(
        send(
            &mut core,
            policy_set(d, 10, None, "forbid(", None),
            ROOT_KEY
        )
        .await,
        Err(CoreError::Protocol("policy"))
    ));
    let set = send(
        &mut core,
        policy_set(
            d,
            11,
            None,
            r#"@id("no-reads") forbid(principal, action, resource) when { context.action == "shop:read" };"#,
            None,
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&set);
    let denied = send(&mut core, shop_request(d, 12, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(denied.decision.outcome, Outcome::Deny);
    assert!(
        denied
            .decision
            .blockers
            .iter()
            .any(|b| b.class == access_kernel::combinator::BlockerClass::Restricted)
    );

    // replace it with a policy that asks for a kyc Claim
    let policy = meta::object_id(&set.exercise.unwrap(), kind::POLICY, 0);
    let kyc = term(ProofKind::Claim, "kyc", ProofBinding::None);
    let requirements = Value::Map(vec![(
        Value::text("rs-kyc"),
        Value::Array(vec![kyc.to_value()]),
    )]);
    allowed(
        &send(
            &mut core,
            policy_set(
                d,
                13,
                Some(policy),
                r#"@id("kyc") @require("rs-kyc") forbid(principal, action, resource) when { context.action == "shop:read" };"#,
                Some(requirements),
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let asked = send(&mut core, shop_request(d, 14, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    let good = claim(d, ALICE, ALICE_KEY, "kyc");
    allowed(
        &send(
            &mut core,
            with_proofs(
                shop_request(d, 14, Mode::Commit, shop),
                vec![ProofRef::Claim(good)],
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );

    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                15,
                ExerciseBasis::Anchor(meta::meta_anchor(&d)),
                Payload::PolicyRetire { policy },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    allowed(
        &send(&mut core, shop_request(d, 16, Mode::Commit, shop), ROOT_KEY)
            .await
            .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}
