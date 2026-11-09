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
use access_authority_core::app::approval::BindingFacet;
use access_authority_core::app::{Authority, Incoming, Response, Scope};
use access_authority_core::domain::{ProofRef, Request};
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::{PgLog, create_genesis, fold_check};
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::ports::Clock;
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_internal_api::context::RateContext;
use access_kernel::aas::{Act, ApprovalAct};
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{BlockerClass, Capacity, Mode, Outcome, Resolver};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{
    self, ActorKind, ExerciseBasis, GrantBasis, GrantContent, HoldingRef, Payload, Root, kind,
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
const BOB: Id = Id([3; 16]);
const BOB_KEY: u8 = 13;
const PEP: &str = "pep.example";
const NOW: u64 = 10_000;
const API: &str = "https://api.example";

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

/// The Action Schema the test catalog publishes for `name` (OP-141 m.35).
fn schema_of(name: &str) -> access_kernel::schema::ActionSchema {
    access_kernel::schema::ActionSchema {
        reversibility: None,
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

/// The SPP of the `shop` actions.
fn shop_spp() -> access_kernel::schema::Spp {
    access_kernel::schema::Spp {
        publisher: ROOT,
        namespace: "shop".to_owned(),
        catalog_version: 1,
        actions: vec![schema_of("read")],
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// The `schema-definition` Acceptance that publishes the `shop` actions (OP-141 m.35).
fn shop_schemas() -> Value {
    let spp = shop_spp();
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
        // OP-141 m.34 (d)
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
        (thumbprint(&public(BOB_KEY)), (BOB, public(BOB_KEY))),
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
    (
        Authority::new(leader, reader, binding(), Counter(0), d).with_pseudonyms(
            access_crypto::pseudonym::PseudonymKey::new(Secret::new([7; 32])),
        ),
        d,
    )
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
    let sig = with
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

fn intent(act: ActionRef, resource: (&str, &str), payload: Option<&Payload>) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
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
        requester: None,
        explain: false,
        status: None,
        context: None,
    }
}

async fn send(core: &mut Core, request: Request, seed: u8) -> Result<Response, CoreError> {
    core.exercise(&incoming(request, seed), NOW).await
}

/// Sends `request` at trusted time `now`, its AIS issued then.
async fn send_at(
    core: &mut Core,
    request: Request,
    seed: u8,
    now: u64,
) -> Result<Response, CoreError> {
    let mut inc = incoming(request, seed);
    let digest = access_kernel::intent::intent_digest(&inc.request.intent).unwrap();
    let statement = Statement {
        domain: inc.request.domain,
        nonce: inc.request.nonce.clone(),
        intent: digest,
        mode: inc.request.mode,
        pep: PEP.to_owned(),
        capacity: inc.request.capacity,
        basis: inc.request.basis,
        iat: now,
        exercise: inc.request.exercise,
    };
    inc.ais = Some(sign(&statement, seed));
    core.exercise(&inc, now).await
}

fn allowed(r: &Response) {
    assert_eq!(r.decision.outcome, Outcome::Allow, "{r:?}");
}

/// A recorded `no_covering_authority` the actor resolves (OP-152 m.5 (a)).
fn unresolved(r: &Response) {
    assert_eq!(r.decision.outcome, Outcome::Deny, "{r:?}");
    assert!(r.record.is_some(), "{r:?}");
    assert!(r.exercise.is_none());
    let [b] = r.decision.blockers.as_slice() else {
        panic!("one blocker: {r:?}");
    };
    assert_eq!(b.class, BlockerClass::NoCoveringAuthority);
    assert_eq!(b.resolver, Resolver::Actor);
    assert_eq!(b.subcode, None);
}

// OP-152 m.5 (a)
#[tokio::test]
async fn an_unresolvable_basis_is_a_recorded_denial() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);

    let not_root = send(
        &mut core,
        shop_request(d, 5, Mode::Commit, ExerciseBasis::Anchor(shop)),
        ALICE_KEY,
    )
    .await
    .unwrap();
    unresolved(&not_root);

    let missing = send(
        &mut core,
        shop_request(
            d,
            6,
            Mode::Commit,
            ExerciseBasis::Holding(HoldingRef {
                grant: Id([0xEE; 16]),
                holder: ALICE,
                since: 1,
            }),
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    unresolved(&missing);
    assert_eq!(not_root.decision, missing.decision);

    fold_check(&db.sequencer, d).await.unwrap();
}

/// A `party_register` of `Id([seed; 16])` under the bootstrap Grant, forwarded for `context`.
async fn register_for(
    core: &mut Core,
    d: Digest,
    (seed, nonce): (u8, u8),
    context: Option<&str>,
) -> Response {
    let party = Id([seed; 16]);
    let register = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
        actor_kind: ActorKind::Human,
    };
    let basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let mut inc = incoming(meta_request(d, nonce, basis, register), seed);
    inc.context = context.map(|c| RateContext::parse(c).unwrap());
    core.exercise(&inc, NOW).await.unwrap()
}

// §13.7.4, OP-152 m.5 (b)
#[tokio::test]
async fn bootstrap_grants_are_limited_per_context() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut keys = binding().0;
    for s in 40..54 {
        keys.insert(thumbprint(&public(s)), (Id([s; 16]), public(s)));
    }
    let mut core: Core = Authority::new(leader, reader, Bound(keys), Counter(0), d);
    for (i, s) in (40..50).enumerate() {
        let nonce = 100 + u8::try_from(i).unwrap();
        allowed(&register_for(&mut core, d, (s, nonce), Some("ip:aa")).await);
    }
    let over = register_for(&mut core, d, (50, 120), Some("ip:aa")).await;
    assert_eq!(over.decision.outcome, Outcome::Deny, "{over:?}");
    assert!(over.record.is_some());
    assert_eq!(
        over.decision.blockers[0].subcode.as_deref(),
        Some("policy:bootstrap-rate")
    );
    assert_eq!(over.decision.blockers[0].class, BlockerClass::Restricted);
    allowed(&register_for(&mut core, d, (51, 121), Some("ip:bb")).await);
    allowed(&register_for(&mut core, d, (52, 122), None).await);
    fold_check(&db.sequencer, d).await.unwrap();
}

/// Registers `party` with the key `seed` under the Public bootstrap Grant.
async fn onboard(core: &mut Core, d: Digest, party: Id, seed: u8, nonces: (u8, u8)) {
    onboard_as(core, d, (party, ActorKind::Human), seed, nonces).await;
}

/// Registers `party` as an actor of `actor_kind` with the key `seed`.
async fn onboard_as(
    core: &mut Core,
    d: Digest,
    (party, actor_kind): (Id, ActorKind),
    seed: u8,
    nonces: (u8, u8),
) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
        actor_kind,
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
    // INV-1, G1, G4, MUST-NEVER-1, CI-1, EI-2
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;

    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let before = send(
        &mut core,
        shop_request(d, 30, Mode::Check, ExerciseBasis::Anchor(shop)),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_ne!(before.decision.outcome, Outcome::Allow);
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
    // INV-19, MUST-NEVER-12, U31, CI-8
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
    // INV-22, G28
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
    // G14, INV-11
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
    // G15, INV-11, CI-5
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party: ROOT,
        root: Root::Sole(ROOT),
        actor_kind: ActorKind::Human,
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

    fn pseudonym_key(
        &self,
        _domain: &Digest,
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
        signer: None,
        api_base: API.to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    })
}

fn unavailable(r: Result<Response, CoreError>) -> &'static str {
    match r {
        Err(CoreError::Unavailable(why)) => why,
        other => panic!("{other:?}"),
    }
}

// OP-141 m.18 (a), (d), OP-31
#[tokio::test]
async fn a_process_leads_a_domain_from_its_first_request() {
    // TI-5, SAI-3, G48, MUST-NEVER-11
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
                actor_kind: ActorKind::Human,
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
    // OP-141 m.22 (e)
    let reference = first.basis_ref.clone().unwrap();
    assert!(reference.len() >= 48);

    // OP-141 m.22 (f)
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

// OP-141

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
        (Value::text("root_terms"), {
            let mut keyed: Vec<(Vec<u8>, Value)> = terms
                .iter()
                .map(|t| (t.to_bytes().unwrap(), t.to_value()))
                .collect();
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            set(keyed.into_iter().map(|(_, v)| v).collect())
        }),
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
    // OP-150 L6
    let authentication = Value::Map(vec![
        (Value::text("issuer"), ALICE.to_value()),
        (Value::text("use"), Value::text("predicate-input")),
        (
            Value::text("classes"),
            set(vec![Value::text("authentication")]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            set(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
        ),
        (
            Value::text("quota"),
            Value::Map(vec![
                (Value::text("count"), Value::Unsigned(100)),
                (Value::text("window_s"), Value::Unsigned(3_600)),
            ]),
        ),
    ]);
    add_acceptances(&mut g, vec![acceptance, authentication]);
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
    sign_claim(
        &access_kernel::claim::Statement {
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
        },
        seed,
    )
}

fn sign_claim(st: &access_kernel::claim::Statement, seed: u8) -> Vec<u8> {
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
    let sig = with
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

fn with_proofs(mut r: Request, proofs: Vec<ProofRef>) -> Request {
    r.proofs = proofs;
    r
}

// OP-149 m.8, L0-EVAL-30
#[tokio::test]
async fn an_agent_party_cannot_satisfy_human_presence_itself() {
    let mut present = term(ProofKind::Authentication, "presence", ProofBinding::None);
    present.assurance.insert("human_presence".to_owned(), 1);
    for (actor_kind, satisfiable) in [(ActorKind::Human, true), (ActorKind::Agent, false)] {
        let db = fresh().await.unwrap();
        let (mut core, d) = setup_with(&db, gated(&[present.clone()])).await;
        onboard_as(&mut core, d, (ROOT, actor_kind), ROOT_KEY, (1, 2)).await;
        let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
        let asked = send(&mut core, shop_request(d, 9, Mode::Commit, shop), ROOT_KEY)
            .await
            .unwrap();
        assert_eq!(asked.decision.outcome, Outcome::RequireAction);
        assert_eq!(asked.decision.unmet.len(), 1);
        assert_eq!(asked.decision.unmet[0].satisfiable_by_actor, satisfiable);
    }
}

// OP-141 m.19, (h), L2-CLM-3, L2-CLM-4
#[tokio::test]
async fn an_accepted_claim_meets_a_requirement() {
    // INV-14, G7, G8, SI-3, PI-3, EI-21, MUST-NEVER-3, MUST-NEVER-9, EI-3, EI-22
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

    // L2-CLM-2
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

/// An `authentication` Claim ALICE issues about `subject` at `auth_time` with `assurance`.
fn sign_in_claim(d: Digest, subject: Id, assurance: &[(&str, u64)], seed: u8) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(vec![seed; 32])),
            issued_at: NOW - 1_000,
            validity: Window {
                from: NOW - 1_000,
                until: NOW + 3_600_000,
            },
            assurance: assurance
                .iter()
                .map(|(k, v)| ((*k).to_owned(), *v))
                .collect(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

// E9, §13.7.3 CT0, N-45, SEC10, SEC26
#[tokio::test]
async fn an_ordinary_exercise_needs_the_tiers_authenticator_class() {
    let db = fresh().await.unwrap();
    let authentication = term(ProofKind::Claim, "authentication", ProofBinding::None);
    let (mut core, d) = setup_with(&db, gated(&[authentication])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let password = [("aal", 1), ("phishing_resistant", 0)];
    let totp = [("aal", 2), ("phishing_resistant", 0)];
    for (nonce, levels, seed) in [(9, &password[..], 0xc1), (10, &totp[..], 0xc2)] {
        let r = send(
            &mut core,
            with_proofs(
                shop_request(d, nonce, Mode::Commit, shop),
                vec![ProofRef::Claim(sign_in_claim(d, ROOT, levels, seed))],
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        assert_eq!(r.decision.outcome, Outcome::RequireAction, "{levels:?}");
        let unmet = &r.decision.unmet[0];
        assert_eq!(unmet.term.class, "authentication");
        assert_eq!(unmet.term.assurance.get("phishing_resistant"), Some(&1));
    }
    let passkey = send(
        &mut core,
        with_proofs(
            shop_request(d, 11, Mode::Commit, shop),
            vec![ProofRef::Claim(sign_in_claim(d, ROOT, &PASSKEY_UV, 0xc3))],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&passkey);
    fold_check(&db.sequencer, d).await.unwrap();
}

// TI-RT7, OP-141 m.30
#[tokio::test]
async fn a_superseded_claim_no_longer_asserts() {
    // G36
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

// SEC12, OP-141 m.31
#[tokio::test]
async fn a_compromise_restricts_instances_set_up_after_it() {
    // SI-8, SI-9, INV-23, G22
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

// L0-EVAL-4, OP-141 m.33
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

// SEC26, OP-141 m.34
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

// §13.7.3, OP-141 m.34 (b)
#[tokio::test]
async fn an_intent_beyond_its_tier_ceiling_is_refused() {
    // TI-RT3
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

// OP-141 m.35 (e)
#[tokio::test]
async fn an_action_without_an_accepted_schema_is_denied() {
    // G11, EI-16, PI-19
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

// L1-ADP-15, OP-141 m.36
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "two recorded decisions through every scope"
)]
async fn a_recorded_decision_is_explained_as_it_was() {
    // INV-22, PI-16, G27, SI-14, EI-24, TI-3
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
    let again = core
        .explain_recorded(&inc, record, Scope::Requester, NOW)
        .await
        .unwrap();
    assert_eq!(again.decision, first.decision);
    let (inc, record) = explain(12, second.record.unwrap());
    let again = core
        .explain_recorded(&inc, record, Scope::Requester, NOW)
        .await
        .unwrap();
    assert_eq!(again.decision, second.decision);
    let (inc, _) = explain(11, 0);
    assert!(matches!(
        core.explain_recorded(&inc, second.record.unwrap(), Scope::Requester, NOW)
            .await,
        Err(CoreError::Protocol("explain-record"))
    ));
    let other = incoming(shop_request(d, 11, Mode::Commit, holding), ROOT_KEY);
    assert!(matches!(
        core.explain_recorded(&other, first.record.unwrap(), Scope::Requester, NOW)
            .await,
        Err(CoreError::Protocol("explain-record"))
    ));
    // OP-141 m.38
    for scope in [Scope::Viewer, Scope::Audit] {
        let other = incoming(shop_request(d, 12, Mode::Commit, holding), ROOT_KEY);
        let seen = core
            .explain_recorded(&other, second.record.unwrap(), scope, NOW)
            .await
            .unwrap();
        assert_eq!(seen.decision, second.decision);
    }
    let alice = incoming(shop_request(d, 12, Mode::Commit, holding), ALICE_KEY);
    assert!(matches!(
        core.explain_recorded(&alice, second.record.unwrap(), Scope::Audit, NOW)
            .await,
        Err(CoreError::Protocol("explain-scope"))
    ));
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let moved = incoming(shop_request(d, 12, Mode::Commit, shop), ROOT_KEY);
    assert!(matches!(
        core.explain_recorded(&moved, second.record.unwrap(), Scope::Audit, NOW)
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

/// ALICE's Instance, opened by `onboard(.., (3, 4))`.
fn alice_instance(d: Digest) -> Id {
    meta::object_id(&meta::exercise_id(&d, &[4; 16]).unwrap(), kind::INSTANCE, 0)
}

/// The render digest of a `shop` request as the decision point computes it (§9.13.3, XI-8).
fn render_of(req: &Request) -> Digest {
    let r = access_kernel::render::of(
        Some(&schema_of(&req.intent.action.name)),
        &req.intent,
        access_kernel::render::DEFAULT_LOCALE,
    )
    .unwrap();
    access_kernel::render::digest(&r).unwrap()
}

/// The Approval Act Statement of ALICE's contribution `nonce` to `target` (§9.14.1 A step 2).
fn approval_act(
    d: Digest,
    nonce: u8,
    target: Digest,
    render: Digest,
    issued_at: u64,
    expires_at: u64,
) -> ApprovalAct {
    ApprovalAct {
        evidence: None,
        surface_class: None,
        act: Act::Contribution("approve".to_owned()),
        instance: alice_instance(d),
        party: ALICE,
        capacity: Capacity::Own,
        target,
        domain: d,
        nonce: vec![nonce; 16],
        work_gate: None,
        surface_profile: "suiss-approval-surface".to_owned(),
        surface_version: 1,
        render_digest: render,
        material_fields: ["action".to_owned(), "resource".to_owned()]
            .into_iter()
            .collect(),
        issued_at,
        expires_at,
    }
}

/// The `authentication` Claim ALICE's realm issuer (here ALICE herself) issued for the assertion
/// over H(AAS) (§9.14.1 A step 3, §10.1.5): bound to the statement, with its assurance.
fn approval_claim(
    d: Digest,
    statement: Digest,
    assurance: &[(&str, u64)],
    auth_time: u64,
) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject: ALICE,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(vec![0xaa; 32])),
            issued_at: auth_time,
            validity: Window {
                from: auth_time,
                until: auth_time.saturating_add(12 * 3_600_000),
            },
            assurance: assurance
                .iter()
                .map(|(k, v)| ((*k).to_owned(), *v))
                .collect(),
            bound_intent: Some(statement),
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

const PASSKEY_UV: [(&str, u64); 6] = [
    ("aal", 2),
    ("phishing_resistant", 1),
    ("uv", 1),
    ("human_presence", 1),
    ("hardware_bound", 0),
    ("non_custodial", 0),
];

/// ALICE's approval of `target` (its render `render`) on contribution `nonce`: the statement and
/// the Claim bound to it, with `assurance` at `auth_time`.
fn approved(
    d: Digest,
    nonce: u8,
    target: Digest,
    render: Digest,
    assurance: &[(&str, u64)],
    auth_time: u64,
) -> Request {
    approved_at(d, nonce, target, render, assurance, auth_time, NOW)
}

/// [`approved`] with the statement issued at `now`.
fn approved_at(
    d: Digest,
    nonce: u8,
    target: Digest,
    render: Digest,
    assurance: &[(&str, u64)],
    auth_time: u64,
    now: u64,
) -> Request {
    let act = approval_act(
        d,
        nonce,
        target,
        render,
        now.saturating_sub(1_000),
        now.saturating_add(60_000),
    );
    let h = access_kernel::aas::digest(&act).unwrap();
    with_proofs(
        contribute(d, nonce, target),
        vec![
            ProofRef::Aas(act.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(d, h, assurance, auth_time)),
        ],
    )
}

// OP-141 m.19, L0-META-30, §9.14.1
#[tokio::test]
async fn a_contribution_approves_once() {
    // G12, G13, SI-5, SI-17, EI-18, XI-19, INV-20, CI-14
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
    let render = render_of(&target);

    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);

    let given = send(
        &mut core,
        approved(d, 20, digest, render, &PASSKEY_UV, NOW - 5_000),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&given);
    let approval = given.exercise.unwrap();
    // SI-5, §13.7.3
    let state = state_of(&db, d, &meta::exercise_key(kind::CONTRIBUTION, &approval))
        .await
        .map(|b| {
            meta::ContributionState::from_value(&dcbor::decode(&b, Limits::CEILING).unwrap())
                .unwrap()
        })
        .unwrap();
    assert!(state.statement.is_some());
    assert_eq!(state.assurance.get("human_presence"), Some(&1));
    assert_eq!(state.auth_time, Some(NOW - 5_000));

    let done = send(
        &mut core,
        with_proofs(target, vec![ProofRef::Contribution(approval)]),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);

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

    // SEC11
    let again = send(
        &mut core,
        approved(d, 22, digest, render, &PASSKEY_UV, NOW - 5_000),
        ALICE_KEY,
    )
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
    let ended_approval = send(
        &mut core,
        with_proofs(
            shop_request(d, 11, Mode::Commit, shop),
            vec![ProofRef::Contribution(again.exercise.unwrap())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(ended_approval.decision.outcome, Outcome::RequireAction);

    // L0-META-30
    let mut other = contribute(d, 21, digest);
    other.basis = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let denied = send(&mut core, other, ROOT_KEY).await.unwrap();
    assert_ne!(denied.decision.outcome, Outcome::Allow);
    fold_check(&db.sequencer, d).await.unwrap();
}

fn protocol(r: Result<Response, CoreError>) -> &'static str {
    match r {
        Err(CoreError::Protocol(code)) => code,
        Err(e @ CoreError::AasBinding(_)) => e.reason().unwrap(),
        other => panic!("expected a protocol rejection, got {other:?}"),
    }
}

/// The facets an `aas-binding` rejection names (OP-149 m.30 (b)).
fn unbound(r: Result<Response, CoreError>) -> Vec<BindingFacet> {
    match r {
        Err(CoreError::AasBinding(facets)) => facets,
        other => panic!("expected aas-binding, got {other:?}"),
    }
}

// §9.14.1 step 4, §9.14.2, L2-AAS-3, L2-AAS-4, §13.7.3
#[tokio::test]
async fn an_approval_must_fit_the_request_it_answers() {
    // XI-7, SI-5
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
    let render = render_of(&target);
    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);

    assert_eq!(
        protocol(send(&mut core, contribute(d, 20, digest), ALICE_KEY).await),
        "aas"
    );
    let changed = approval_act(d, 20, digest, Digest([0xcc; 32]), NOW - 1_000, NOW + 60_000);
    let h = access_kernel::aas::digest(&changed).unwrap();
    let r = with_proofs(
        contribute(d, 20, digest),
        vec![
            ProofRef::Aas(changed.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(d, h, &PASSKEY_UV, NOW - 5_000)),
        ],
    );
    assert_eq!(protocol(send(&mut core, r, ALICE_KEY).await), "aas-render");
    let nowhere = Digest([0xdd; 32]);
    assert_eq!(
        protocol(
            send(
                &mut core,
                approved(d, 20, nowhere, render, &PASSKEY_UV, NOW - 5_000),
                ALICE_KEY
            )
            .await
        ),
        "aas-target"
    );
    let other = approval_act(d, 21, digest, render, NOW - 1_000, NOW + 60_000);
    let h = access_kernel::aas::digest(&other).unwrap();
    let r = with_proofs(
        contribute(d, 20, digest),
        vec![
            ProofRef::Aas(other.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(d, h, &PASSKEY_UV, NOW - 5_000)),
        ],
    );
    assert_eq!(protocol(send(&mut core, r, ALICE_KEY).await), "aas-nonce");
    // CT1
    let long = approval_act(d, 20, digest, render, NOW - 1_000, NOW + 16 * 60_000);
    let h = access_kernel::aas::digest(&long).unwrap();
    let r = with_proofs(
        contribute(d, 20, digest),
        vec![
            ProofRef::Aas(long.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(d, h, &PASSKEY_UV, NOW - 5_000)),
        ],
    );
    assert_eq!(protocol(send(&mut core, r, ALICE_KEY).await), "aas-expiry");
    // (OP-149 m.30 (b))
    let nobody = approval_act(d, 20, digest, render, NOW - 1_000, NOW + 60_000);
    let r = with_proofs(
        contribute(d, 20, digest),
        vec![ProofRef::Aas(nobody.to_bytes().unwrap())],
    );
    assert_eq!(
        unbound(send(&mut core, r, ALICE_KEY).await),
        BindingFacet::ALL
    );
    let r = with_proofs(
        contribute(d, 20, digest),
        vec![
            ProofRef::Aas(nobody.to_bytes().unwrap()),
            ProofRef::Claim(approval_claim(
                d,
                Digest([0xee; 32]),
                &PASSKEY_UV,
                NOW - 5_000,
            )),
        ],
    );
    assert_eq!(
        unbound(send(&mut core, r, ALICE_KEY).await),
        vec![BindingFacet::BoundIntent]
    );
    allowed(
        &send(
            &mut core,
            approved(d, 20, digest, render, &PASSKEY_UV, NOW - 5_000),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// TI-RT7, OP-141 m.30 (e), OP-150 L6 (f)
#[tokio::test]
async fn a_sign_in_claim_does_not_fork_the_approvals_authentication() {
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
    let render = render_of(&target);
    let asked = send(&mut core, target, ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    for (seed, at) in [(0xb1, NOW - 9_000), (0xb2, NOW - 3_000)] {
        let signed_in = sign_claim(
            &access_kernel::claim::Statement {
                domain: d,
                issuer: ALICE,
                subject: ALICE,
                class: "authentication".to_owned(),
                value: Some(EqValue::Bytes(vec![seed; 32])),
                issued_at: at,
                validity: Window {
                    from: at,
                    until: at.saturating_add(12 * 3_600_000),
                },
                assurance: PASSKEY_UV
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), *v))
                    .collect(),
                bound_intent: None,
                bound_instance: Some(alice_instance(d)),
                bound_resource: None,
                supersedes: None,
            },
            ALICE_KEY,
        );
        let sub = access_internal_api::claims::ClaimSubmission {
            domain: d,
            carrier: access_internal_api::claims::Carrier::Cose,
            claim: signed_in,
            body: None,
            evidence: None,
        };
        assert!(matches!(
            core.ingest(&sub, NOW).await.unwrap().verdict,
            access_internal_api::claims::ClaimVerdict::Admitted { .. }
        ));
    }
    allowed(
        &send(
            &mut core,
            approved(d, 20, digest, render, &PASSKEY_UV, NOW - 5_000),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.7.3, N-45
// IDP-8
// X29
#[tokio::test]
async fn a_weak_or_stale_approval_asks_for_the_tiers_authentication() {
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
    let render = render_of(&target);
    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);

    let password = [("aal", 1), ("phishing_resistant", 0), ("human_presence", 0)];
    let totp = [("aal", 2), ("phishing_resistant", 0), ("human_presence", 0)];
    let absent = [("aal", 2), ("phishing_resistant", 1), ("human_presence", 0)];
    let later = NOW + 15 * 60_000 + 1;
    let mut nonce = 20;
    for (levels, auth_time, now) in [
        (&password[..], NOW - 5_000, NOW),
        (&totp[..], NOW - 5_000, NOW),
        (&absent[..], NOW - 5_000, NOW),
        (&PASSKEY_UV[..], NOW, later),
    ] {
        let r = send_at(
            &mut core,
            approved_at(d, nonce, digest, render, levels, auth_time, now),
            ALICE_KEY,
            now,
        )
        .await
        .unwrap();
        assert_eq!(r.decision.outcome, Outcome::RequireAction, "{levels:?}");
        assert!(r.exercise.is_none());
        let unmet = &r.decision.unmet[0];
        assert_eq!(unmet.term.class, "authentication");
        assert_eq!(unmet.term.proof_kind, ProofKind::Claim);
        assert_eq!(unmet.term.freshness_ms, Some(15 * 60_000));
        assert_eq!(unmet.term.assurance.get("phishing_resistant"), Some(&1));
        assert_eq!(unmet.term.assurance.get("human_presence"), Some(&1));
        assert!(unmet.satisfiable_by_actor);
        nonce += 1;
    }
    let edge = NOW + 15 * 60_000;
    let fresh_enough = send_at(
        &mut core,
        approved_at(d, nonce, digest, render, &PASSKEY_UV, NOW, edge),
        ALICE_KEY,
        edge,
    )
    .await
    .unwrap();
    allowed(&fresh_enough);
    fold_check(&db.sequencer, d).await.unwrap();
}

// SI-5, §6.6, §13.7.3
#[tokio::test]
async fn a_contribution_carries_the_approvers_assurance() {
    let db = fresh().await.unwrap();
    let mut present = term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    );
    present.assurance.insert("human_presence".to_owned(), 1);
    let mut hardware = term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    );
    hardware.assurance.insert("hardware_bound".to_owned(), 1);
    let (mut core, d) = setup_with(&db, gated(&[present, hardware])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let target = shop_request(d, 9, Mode::Commit, shop);
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let render = render_of(&target);
    let asked = send(&mut core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    assert_eq!(asked.decision.unmet.len(), 2);

    let synced = send(
        &mut core,
        approved(d, 20, digest, render, &PASSKEY_UV, NOW - 5_000),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&synced);
    let partly = send(
        &mut core,
        with_proofs(
            target.clone(),
            vec![ProofRef::Contribution(synced.exercise.unwrap())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(partly.decision.outcome, Outcome::RequireAction);
    assert_eq!(partly.decision.unmet.len(), 1);
    assert_eq!(
        partly.decision.unmet[0]
            .term
            .assurance
            .get("hardware_bound"),
        Some(&1)
    );

    let device = [
        ("aal", 3),
        ("phishing_resistant", 1),
        ("uv", 1),
        ("human_presence", 1),
        ("hardware_bound", 1),
        ("non_custodial", 1),
    ];
    let bound = send(
        &mut core,
        approved(d, 21, digest, render, &device, NOW - 5_000),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&bound);
    let done = send(
        &mut core,
        with_proofs(
            target,
            vec![
                ProofRef::Contribution(synced.exercise.unwrap()),
                ProofRef::Contribution(bound.exercise.unwrap()),
            ],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.7.4, SEC28, OP-141 m.40
#[tokio::test]
async fn approval_requests_are_throttled_per_requester() {
    // SI-8
    let db = fresh().await.unwrap();
    let approve = term(
        ProofKind::Contribution,
        "approve",
        ProofBinding::IntentDigest,
    );
    let (mut core, d) = setup_with(&db, gated(&[approve])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    for nonce in 30..50 {
        let asked = send(
            &mut core,
            shop_request(d, nonce, Mode::Commit, shop),
            ROOT_KEY,
        )
        .await
        .unwrap();
        assert_eq!(asked.decision.outcome, Outcome::RequireAction);
    }
    let again = send(&mut core, shop_request(d, 30, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(again.decision.outcome, Outcome::RequireAction);
    let over = send(&mut core, shop_request(d, 50, Mode::Commit, shop), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(over.decision.outcome, Outcome::Deny);
    assert_eq!(
        over.decision.blockers[0].subcode.as_deref(),
        Some("policy:request-rate")
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-141 m.19 (i), L1-ADP-13
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

// §13.4 G31, L1-ADP-13
#[tokio::test]
async fn a_continuation_after_revocation_is_denied() {
    // G4, CI-9
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

// OP-141

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

// OP-141 m.20
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one membership from its first episode through a cutoff and its lifting"
)]
async fn a_member_holds_the_groups_grant_from_its_episode() {
    // INV-16, INV-31, G5, G9, SI-10, TI-RT9, U34, INV-25
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

    // OP-152 m.5 (a)
    unresolved(
        &send(
            &mut core,
            shop_request(d, 8, Mode::Commit, holding(0)),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
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

    unresolved(
        &send(
            &mut core,
            shop_request(d, 11, Mode::Commit, holding(episode - 1)),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );

    // OP-141 m.42
    let index = state_of(&db, d, &meta::key(kind::ACCEPTANCES, &ALICE))
        .await
        .unwrap();
    let Value::Array(ids) = dcbor::decode(&index, Limits::CEILING).unwrap() else {
        panic!("acceptance index");
    };
    let acceptance = Id::from_value(&ids[0]).unwrap();
    let content = |cutoff: Option<u64>| {
        let mut fields = vec![
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
        ];
        if let Some(c) = cutoff {
            fields.push((Value::text("ingest_until"), Value::Unsigned(c)));
        }
        let b = dcbor::encode(&Value::Map(fields), Limits::CEILING).unwrap();
        dcbor::decode(&b, Limits::CEILING).unwrap()
    };
    let meta_anchor = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    for (nonce, cutoff) in [(13, Some(1)), (14, None)] {
        let amend = Payload::AcceptanceAmend {
            acceptance,
            content: content(cutoff),
        };
        let r = send(
            &mut core,
            meta_request(d, nonce, meta_anchor, amend),
            ROOT_KEY,
        )
        .await
        .unwrap();
        allowed(&r);
        if cutoff.is_some() {
            assert_eq!(
                send(
                    &mut core,
                    shop_request(d, 15, Mode::Check, holding(episode)),
                    ROOT_KEY
                )
                .await
                .unwrap()
                .decision
                .outcome,
                Outcome::Deny
            );
        } else {
            assert_eq!(
                send(
                    &mut core,
                    shop_request(d, 16, Mode::Check, holding(episode)),
                    ROOT_KEY
                )
                .await
                .unwrap()
                .decision
                .outcome,
                Outcome::Deny
            );
            allowed(
                &send(
                    &mut core,
                    shop_request(d, 17, Mode::Check, holding(r.record.unwrap())),
                    ROOT_KEY,
                )
                .await
                .unwrap(),
            );
        }
    }

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

// OP-141 m.21 (a)
#[tokio::test]
async fn an_issuer_quota_quarantines_the_excess() {
    // G44
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

// OP-141

fn search_request(d: Digest, nonce: u8, kind: &str) -> Request {
    Request {
        domain: d,
        mode: Mode::Check,
        nonce: vec![nonce; 16],
        intent: intent(action("access", "read"), ("access.search", kind), None),
        payload: None,
        basis: ExerciseBasis::Public(Id([0; 16])),
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

// OP-141 m.22 (g), (j), m.41 (c), E26
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from onboarding to every search kind"
)]
async fn search_shows_what_the_reader_may_see() {
    // G27, SI-14, PI-16, SAI-43, G62
    use access_authority_core::query::{Hit, Query};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (party, seed, n) in [
        (ROOT, ROOT_KEY, 1),
        (ALICE, ALICE_KEY, 3),
        (BOB, BOB_KEY, 60),
    ] {
        for (nonce, payload) in [
            (
                n,
                Payload::PartyRegister {
                    party,
                    root: Root::Sole(party),
                    actor_kind: ActorKind::Human,
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
    // OP-141 m.39 (c)
    let mut prefixed = authority(Vec::new(), selector("shop"));
    prefixed
        .authority
        .actions
        .prefix
        .insert(("shop".to_owned(), shop_spp().catalog_digest()));
    let grant = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: prefixed,
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
    // OP-141 m.41 (c)
    assert_eq!(hits, [Hit::Party(ALICE)]);
    // SAI-43, G62
    let nowhere = Query::Subject {
        action: action("shop", "read"),
        resource: ResourceRef {
            namespace: "nowhere".to_owned(),
            path: vec!["item-1".to_owned()],
            incarnation: 0,
        },
    };
    let mut answers = Vec::new();
    for (nonce, q) in [(62, &who), (63, &nowhere)] {
        answers.push(
            a.search(
                &incoming(search_request(d, nonce, "subject"), BOB_KEY),
                q,
                None,
            )
            .await
            .unwrap(),
        );
    }
    assert_eq!(answers[0], (Vec::new(), None));
    assert_eq!(answers[0], answers[1]);

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
    // §13.7.4, OP-141 m.23
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
    // OP-141 m.23 (a), OP-151 m.12 (e) (W-5)
    let as_user = |nonce: u8, user: &str| {
        let mut inc = incoming(search_request(d, nonce, "resource"), ALICE_KEY);
        inc.ais = None;
        inc.requester = Some(user.to_owned());
        inc
    };
    for n in 0..10 {
        a.search(&as_user(100 + n, "session-1"), &mine, None)
            .await
            .unwrap();
    }
    assert!(matches!(
        a.search(&as_user(110, "session-1"), &mine, None).await,
        Err(CoreError::Limited)
    ));
    a.search(&as_user(111, "session-2"), &mine, None)
        .await
        .unwrap();
    assert!(matches!(
        a.search(
            &incoming(search_request(d, 55, "action"), ALICE_KEY),
            &mine,
            None
        )
        .await,
        Err(CoreError::Protocol("search"))
    ));
    // §13.4
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
    // OP-141 m.39 (a)
    let mut other = search_request(d, 83, "subject");
    other.intent.action = action("access", "audit");
    assert!(matches!(
        a.exercise(&incoming(other, ALICE_KEY)).await,
        Err(CoreError::Protocol("action"))
    ));
    // OP-141 m.37
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

// OP-141

// L0-EVAL-15, OP-141 m.26, m.28
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one budget through draw, exhaustion and release"
)]
async fn a_budget_is_drawn_until_it_is_exhausted() {
    // G3
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
    let checked = send(
        &mut core,
        shop_request(d, 23, Mode::Check, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(checked.decision.outcome, Outcome::Deny);
    // OP-141 m.28
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

// OP-141

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

// L0-EVAL-18, OP-141 m.27
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario through a policy's life"
)]
async fn restriction_policies_narrow_the_commit_path() {
    // G6, SI-8
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

// §6.9 INV-34, §9.7A.1, OP-141 m.41
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one generated scenario from onboarding to the comparison"
)]
async fn search_and_check_agree_over_generated_grants() {
    use access_authority_core::query::{Hit, Query};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let parties = [(ALICE, ALICE_KEY), (BOB, BOB_KEY)];
    let mut seed: u64 = 0x5eed;
    let mut next = move || {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        seed >> 33
    };
    let mut nonce = 10u8;
    let mut held = Vec::new();
    for _ in 0..8 {
        let p = usize::from(next() % 2 == 1);
        let prefix = match next() % 3 {
            0 => Vec::new(),
            1 => vec!["a".to_owned()],
            _ => vec!["b".to_owned()],
        };
        let content = GrantContent {
            basis: GrantBasis::Anchor(shop),
            holder: SubjectSelector::Party(parties[p].0),
            authority: authority(
                vec![action("shop", "read")],
                ResourceSelector::Structural(Structural {
                    namespace: "shop".to_owned(),
                    prefix,
                    kind: None,
                    attrs: BTreeMap::new(),
                }),
            ),
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        };
        let issued = send(
            &mut core,
            meta_request(
                d,
                nonce,
                ExerciseBasis::Anchor(shop),
                Payload::GrantIssue(content),
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        allowed(&issued);
        nonce += 1;
        let grant = meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0);
        let basis = ExerciseBasis::Holding(HoldingRef {
            grant,
            holder: parties[p].0,
            since: issued.record.unwrap(),
        });
        held.push((grant, p, basis));
    }
    for (grant, _, _) in &held {
        if next() % 3 == 0 {
            let revoke = Payload::GrantRevoke { grant: *grant };
            allowed(
                &send(
                    &mut core,
                    meta_request(d, nonce, ExerciseBasis::Anchor(shop), revoke),
                    ROOT_KEY,
                )
                .await
                .unwrap(),
            );
            nonce += 1;
        }
    }
    access_authority_core::adapters::derive(&db.deriver, d)
        .await
        .unwrap();
    let mut outcomes = [false; 2];
    for path in ["a", "b", "c"] {
        let who = Query::Subject {
            action: action("shop", "read"),
            resource: ResourceRef {
                namespace: "shop".to_owned(),
                path: vec![path.to_owned()],
                incarnation: 0,
            },
        };
        let found = core
            .search(
                &incoming(search_request(d, nonce, "subject"), ROOT_KEY),
                &who,
                None,
                NOW,
            )
            .await
            .unwrap();
        nonce += 1;
        let alice_sees = core
            .search(
                &incoming(search_request(d, nonce, "subject"), ALICE_KEY),
                &who,
                None,
                NOW,
            )
            .await
            .unwrap();
        nonce += 1;
        assert!(!alice_sees.hits.contains(&Hit::Party(BOB)));
        for (p, (party, key)) in parties.iter().enumerate() {
            let mut any = false;
            for (_, _, basis) in held.iter().filter(|h| h.1 == p) {
                let mut req = shop_request(d, nonce, Mode::Check, *basis);
                req.intent = intent(action("shop", "read"), ("shop", path), None);
                nonce += 1;
                any |= send(&mut core, req, *key).await.unwrap().decision.outcome == Outcome::Allow;
            }
            assert_eq!(found.hits.contains(&Hit::Party(*party)), any, "{path} {p}");
            outcomes[usize::from(any)] = true;
        }
    }
    assert_eq!(outcomes, [true, true]);
}

// INV-37, TNI-1, EI-27
#[tokio::test]
async fn the_tenant_is_not_a_decision_input() {
    let db = fresh().await.unwrap();
    let mut decisions = Vec::new();
    for (tenant, salt) in [(TENANT, 3), ([0x02; 16], 4)] {
        let mut g = genesis();
        for opened in g.values_mut() {
            opened.salt = [salt; 32];
        }
        let d = create_genesis(&db.sequencer, tenant, g, 1_000)
            .await
            .unwrap();
        let log = PgLog::new(db.sequencer.clone(), d, tenant, "t".to_owned(), TTL);
        let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
            .await
            .unwrap();
        let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
        let mut core = Authority::new(leader, reader, binding(), Counter(0), d);
        onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
        onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
        let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
        let mut both = Vec::new();
        for seed in [ROOT_KEY, ALICE_KEY] {
            let r = send(&mut core, shop_request(d, 9, Mode::Check, shop), seed)
                .await
                .unwrap();
            both.push(r.decision);
        }
        decisions.push(both);
    }
    assert_eq!(decisions[0][0].outcome, Outcome::Allow);
    assert_ne!(decisions[0][1].outcome, Outcome::Allow);
    assert_eq!(decisions[0], decisions[1]);
}

/// The binding key of every domain in the in-process signer of the signing tests.
struct SoftBinding;

impl access_authority_signer::ports::Bindings for SoftBinding {
    fn binding(
        &mut self,
        _: &Digest,
    ) -> Result<Box<dyn suiss_crypto::signer::Signer + Send>, suiss_crypto::signer::SignError> {
        static DOC: std::sync::OnceLock<suiss_crypto::secret::Secret<Vec<u8>>> =
            std::sync::OnceLock::new();
        let doc = DOC.get_or_init(|| {
            suiss_crypto::signer::SoftSigner::generate_ed25519()
                .unwrap()
                .1
        });
        Ok(Box::new(
            suiss_crypto::signer::SoftSigner::ed25519_from_pkcs8(doc)?,
        ))
    }
}

type SignerService = std::sync::Arc<
    std::sync::Mutex<
        access_authority_signer::service::Service<
            access_authority_signer::adapters::SealedFactory<suiss_crypto::envelope::SoftKek>,
            SoftBinding,
            access_authority_signer::adapters::DirVault,
        >,
    >,
>;

/// An in-process signer on a socket of its own, at the tests' fixed time, with no lead.
fn start_signer(name: &str) -> (std::path::PathBuf, SignerService) {
    use access_authority_signer::adapters::{DirVault, SealedFactory, serve};
    let dir = std::env::temp_dir().join(format!("access-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let policy = suiss_crypto::rotation::Policy {
        publish_lead_ms: 0,
        ..suiss_crypto::rotation::Policy::AUTHORITY
    };
    let service = std::sync::Arc::new(std::sync::Mutex::new(
        access_authority_signer::service::Service::start(
            SealedFactory::new(suiss_crypto::envelope::SoftKek::new("kek", [4; 32])),
            SoftBinding,
            DirVault::new(&dir),
            policy,
            NOW,
        )
        .unwrap(),
    ));
    let socket = dir.join("signer.sock");
    let _ = std::fs::remove_file(&socket);
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    tokio::spawn(serve(
        tokio::net::UnixListener::bind(&socket).unwrap(),
        std::sync::Arc::clone(&service),
        vec![uid],
        || NOW,
    ));
    (socket, service)
}

/// The domain's Domain Metadata from the signer, verified under the binding key.
async fn signer_metadata(
    socket: &std::path::Path,
    d: Digest,
) -> access_kernel::verify::key_scope::DomainMetadata {
    use access_authority_signer::ports::Bindings as _;
    use access_authority_signer::protocol::{Request, Response};
    let Response::Metadata(bytes) =
        access_authority_signer::adapters::call(socket, &Request::Metadata(d))
            .await
            .unwrap()
    else {
        panic!("metadata");
    };
    let binding_key = SoftBinding.binding(&d).unwrap().public_key();
    let mut trusted = access_kernel::verify::cose::KeySet::default();
    trusted
        .insert(
            access_kernel::verify::key_scope::thumbprint(&binding_key),
            binding_key,
        )
        .unwrap();
    trusted
        .allowed
        .insert(access_kernel::verify::cose::Algorithm::Ed25519);
    access_kernel::verify::key_scope::verify_metadata(
        &access_kernel::verify::PureBackend,
        &bytes,
        &trusted,
    )
    .unwrap()
}

/// A process leading `d` that signs through the signer at `socket`.
fn signing_process(
    db: &TestDb,
    d: Digest,
    socket: &std::path::Path,
) -> Domains<Listed, Bound, Counter, Fixed> {
    Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(vec![d]),
        holder: "a".to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(0),
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: Some(socket.to_path_buf()),
        api_base: API.to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    })
}

/// Registers ROOT through `a`, letting the signer's schedule run after each ALLOW so that its
/// first key may sign.
async fn onboard_signed(
    a: &Domains<Listed, Bound, Counter, Fixed>,
    d: Digest,
    service: &SignerService,
) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let steps = [
        Payload::PartyRegister {
            party: ROOT,
            root: Root::Sole(ROOT),
            actor_kind: ActorKind::Human,
        },
        Payload::InstanceCreate {
            party: ROOT,
            key: public(ROOT_KEY),
            mandate: None,
        },
    ];
    for (nonce, payload) in (1..).zip(steps) {
        allowed(
            &a.exercise(&incoming(
                meta_request(d, nonce, public_basis, payload),
                ROOT_KEY,
            ))
            .await
            .unwrap(),
        );
        for _ in 0..2 {
            service.lock().unwrap().tick(NOW, 1);
        }
    }
}

// L2-PAP-1 to L2-PAP-3, OP-143 m.7, m.11
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one projection from commit to an offline verifier's two decisions"
)]
async fn a_projection_carries_a_signed_pap() {
    // CI-3
    use access_kernel::validity::{ProfileClass, ProfileVariant};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("pap");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut bounds = authority(vec![action("shop", "read")], selector("shop"));
    bounds.constraints.validity = Window {
        from: NOW,
        until: NOW + 3_600_000,
    };
    let issue = Payload::ProjectionIssue {
        bounds: bounds.clone(),
        audience: BTreeSet::from(["verifier.example".to_owned()]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    let r = a
        .exercise(&incoming(meta_request(d, 9, shop, issue), ROOT_KEY))
        .await
        .unwrap();
    allowed(&r);
    let (pap_sign1, excerpt) = r.signed_pap.clone().expect("signed PAP");
    let metadata = signer_metadata(&socket, d).await;

    let present = |intent: &IntentEnvelope| {
        let p = access_kernel::pap::Presentation {
            pap: access_kernel::pap::pap_digest(&pap_sign1),
            intent: access_kernel::intent::intent_digest(intent).unwrap(),
            audience: "verifier.example".to_owned(),
            nonce: vec![5; 16],
            iat: NOW,
        };
        let prot = dcbor::encode(
            &Value::Map(vec![
                (Value::Unsigned(ALG), Value::int(-19)),
                (
                    Value::Unsigned(CT),
                    Value::text(access_kernel::pap::PRESENTATION_CONTENT_TYPE),
                ),
                (
                    Value::Unsigned(KID),
                    Value::Bytes(thumbprint(&public(ROOT_KEY)).to_vec()),
                ),
            ]),
            Limits::CEILING,
        )
        .unwrap();
        let payload = p.to_bytes().unwrap();
        let sig = signing(ROOT_KEY)
            .sign(&to_be_signed(&prot, &payload).unwrap())
            .to_bytes()
            .to_vec();
        let body = dcbor::encode(
            &Value::Array(vec![
                Value::Bytes(prot),
                Value::Map(vec![]),
                Value::Bytes(payload),
                Value::Bytes(sig),
            ]),
            Limits::CEILING,
        )
        .unwrap();
        [vec![0xd2], body].concat()
    };
    let verify = |intent: &IntentEnvelope| {
        access_kernel::pap::verify(
            &access_kernel::verify::PureBackend,
            &metadata,
            &pap_sign1,
            &excerpt,
            &present(intent),
            &access_kernel::pap::Expected {
                domain: &d,
                intent,
                audience: "verifier.example",
                nonce: &[5; 16],
                now: NOW,
                catalog: &access_kernel::algebra::Catalog::default(),
                satisfied: &BTreeSet::new(),
                remaining: &BTreeMap::new(),
                metadata_fresh: true,
                understood: &BTreeSet::new(),
                last_refresh: None,
                online: true,
                skew_ms: access_kernel::ais::SKEW_MS,
                horizon_cap_ms: 86_400_000,
            },
        )
    };
    let read = shop_request(d, 10, Mode::Commit, shop).intent;
    let pap = verify(&read).unwrap();
    assert_eq!(pap.projection_exercise, r.exercise.unwrap());
    assert_eq!(pap.bounds, bounds.authority);
    let mut write = read.clone();
    write.action = action("shop", "write");
    assert_eq!(
        verify(&write).map_err(access_kernel::pap::PapError::code),
        Err("pap-bounds")
    );
}

// §9.8, L2-RCP-1 to L2-RCP-3, TI-12, OP-143 m.5
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one signer, one domain and one receipt from commit to offline verification"
)]
async fn an_allow_carries_a_signed_receipt() {
    // TI-12
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("receipt");
    let a = Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(vec![d]),
        holder: "a".to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(0),
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: Some(socket.clone()),
        api_base: API.to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    });
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (nonce, payload) in [
        (
            1,
            Payload::PartyRegister {
                party: ROOT,
                root: Root::Sole(ROOT),
                actor_kind: ActorKind::Human,
            },
        ),
        (
            2,
            Payload::InstanceCreate {
                party: ROOT,
                key: public(ROOT_KEY),
                mandate: None,
            },
        ),
    ] {
        let first = a
            .exercise(&incoming(
                meta_request(d, nonce, public_basis, payload),
                ROOT_KEY,
            ))
            .await
            .unwrap();
        allowed(&first);
        for _ in 0..2 {
            service.lock().unwrap().tick(NOW, 1);
        }
    }
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let r = a
        .exercise(&incoming(shop_request(d, 9, Mode::Commit, shop), ROOT_KEY))
        .await
        .unwrap();
    allowed(&r);
    let (sign1, excerpt) = r.signed_receipt.clone().expect("signed receipt");
    let metadata = signer_metadata(&socket, d).await;
    let intent =
        access_kernel::intent::intent_digest(&shop_request(d, 9, Mode::Commit, shop).intent)
            .unwrap();
    let receipt = access_kernel::receipt::verify(
        &access_kernel::verify::PureBackend,
        &metadata,
        &sign1,
        &excerpt,
        &access_kernel::receipt::Expected {
            domain: &d,
            audience: PEP,
            intent: &intent,
            now: NOW,
        },
    )
    .unwrap();
    assert_eq!(receipt.exercise, r.exercise.unwrap());
    assert_eq!(Some(receipt.record), r.record);
    // TI-12
    let log = access_store::authority::read_log(
        &db.app,
        &DomainId::from_bytes(d.0),
        receipt.record,
        receipt.record,
    )
    .await
    .unwrap();
    let envelope = access_kernel::record::RecordEnvelope::from_bytes(&log[0].envelope).unwrap();
    let artifacts = envelope.fields.get("artifacts").unwrap().value.clone();
    assert_eq!(
        artifacts,
        Value::Array(vec![
            access_kernel::receipt::digest(&receipt).unwrap().to_value()
        ])
    );
}

// OP-149 m.11, m.14 (d), L2-RCP-1, INV-4, C14
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "two agents, one Mandate and two receipts from registration to the chain"
)]
async fn a_receipt_names_the_agency_chain_of_a_mandated_agent() {
    // OP-149 m.11
    // L2-RCP-1, CI-6
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                3,
                public_basis,
                Payload::PartyRegister {
                    party: ALICE,
                    root: Root::Sole(ALICE),
                    actor_kind: ActorKind::Agent,
                },
            ),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let shop_read = authority(vec![action("shop", "read")], selector("shop"));
    let created = send(
        &mut core,
        meta_request(
            d,
            4,
            public_basis,
            Payload::InstanceCreate {
                party: ALICE,
                key: public(ALICE_KEY),
                mandate: Some(meta::MandateEnvelope {
                    origins: access_kernel::combinator::Origins::default(),
                    authority: shop_read.authority.clone(),
                    constraints: shop_read.constraints.clone(),
                    requirements: BTreeSet::new(),
                    pin: None,
                }),
            },
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&created);
    let mandate = meta::object_id(&created.exercise.unwrap(), kind::MANDATE, 0);
    onboard_as(&mut core, d, (BOB, ActorKind::Agent), BOB_KEY, (5, 6)).await;

    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let mut holdings = Vec::new();
    for (nonce, holder) in [(7, ALICE), (8, BOB)] {
        let issued = send(
            &mut core,
            meta_request(
                d,
                nonce,
                ExerciseBasis::Anchor(shop),
                Payload::GrantIssue(GrantContent {
                    basis: GrantBasis::Anchor(shop),
                    holder: SubjectSelector::Party(holder),
                    authority: shop_read.clone(),
                    agency: BTreeSet::from([Capacity::For(ROOT)]),
                    named: None,
                }),
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        allowed(&issued);
        holdings.push(ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
            holder,
            since: issued.record.unwrap(),
        }));
    }
    let on_behalf = |nonce, basis| {
        let mut r = shop_request(d, nonce, Mode::Commit, basis);
        r.capacity = Capacity::For(ROOT);
        r
    };
    let receipt = |r: &Response| {
        access_kernel::receipt::Receipt::from_bytes(r.receipt.as_deref().expect("receipt")).unwrap()
    };

    let mandated = send(&mut core, on_behalf(9, holdings[0]), ALICE_KEY)
        .await
        .unwrap();
    allowed(&mandated);
    let r = receipt(&mandated);
    assert_eq!(r.capacity, Capacity::For(ROOT));
    assert_eq!(
        r.agency,
        vec![access_kernel::receipt::AgencyLink {
            mandate,
            principal: ROOT,
            agent: ALICE,
        }]
    );

    // OP-149 m.14 (d)
    let unmandated = send(&mut core, on_behalf(10, holdings[1]), BOB_KEY)
        .await
        .unwrap();
    allowed(&unmandated);
    assert_eq!(receipt(&unmandated).agency, Vec::new());

    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-143 m.12, INV-21, G3
#[tokio::test]
async fn an_offline_slice_is_drawn_in_advance() {
    use access_kernel::combinator::BlockerClass;
    use access_kernel::validity::ProfileVariant;
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let a = moving_process(&db, d, Movable::at(NOW));
    onboard_process(&a, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard_process(&a, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = grant_alice(&a, d, 5, vec![action("shop", "read")], 5).await;
    // §9.12.1
    let body = access_kernel::claim::body::Body::VerifierProfile(verifier_profile(ROBOT, true));
    admitted(
        &a.ingest(&body_claim(d, "verifier_profile", &body, NOW))
            .await
            .unwrap()
            .verdict,
    );
    let project = |count| {
        projection(
            vec![action("shop", "read")],
            &[ROBOT],
            ProfileVariant::BoundedStaleness,
            (NOW, NOW + 3_600_000),
            Some(60_000),
            Some(count),
        )
    };
    let first = a
        .exercise(&incoming(
            meta_request(d, 6, holding, project(3)),
            ALICE_KEY,
        ))
        .await
        .unwrap();
    allowed(&first);
    let pap = access_kernel::pap::Pap::from_bytes(&first.pap.unwrap()).unwrap();
    let entry = pap.validity.offline_slice.iter().next().unwrap();
    assert_eq!((entry.amount, entry.unit.as_str()), (3, "count"));
    let over = a
        .exercise(&incoming(
            meta_request(d, 7, holding, project(3)),
            ALICE_KEY,
        ))
        .await
        .unwrap();
    assert_eq!(over.decision.outcome, Outcome::Deny);
    assert!(
        over.decision
            .blockers
            .iter()
            .any(|b| b.class == BlockerClass::BudgetExhausted)
    );
    allowed(
        &a.exercise(&incoming(
            meta_request(d, 8, holding, project(2)),
            ALICE_KEY,
        ))
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §9.15.1, OP-143 m.4
#[tokio::test]
async fn domain_metadata_comes_only_from_the_signer() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    assert_eq!(process(&db, "a", vec![d]).metadata(d).await, None);
    let (socket, service) = start_signer("metadata");
    let a = signing_process(&db, d, &socket);
    assert_eq!(a.metadata(d).await, None);
    onboard_signed(&a, d, &service).await;
    let served = a.metadata(d).await.expect("signed metadata");
    let verified = signer_metadata(&socket, d).await;
    assert_eq!(verified.domain, d);
    let Ok(access_authority_signer::protocol::Response::Metadata(current)) =
        access_authority_signer::adapters::call(
            &socket,
            &access_authority_signer::protocol::Request::Metadata(d),
        )
        .await
    else {
        panic!("metadata");
    };
    assert_eq!(served, current);
    assert_eq!(a.metadata(Digest([9; 32])).await, None);
}

/// A `COSE_Sign1` by the key `seed`.
fn sign1(seed: u8, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(CT), Value::text(content_type)),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public(seed)).to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = signing(seed)
        .sign(&to_be_signed(&prot, payload).unwrap())
        .to_bytes();
    let body = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(payload.to_vec()),
            Value::Bytes(sig.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    [vec![0xd2], body].concat()
}

/// The schema of a consumption-bearing `shop` action.
fn buy_schema() -> access_kernel::schema::ActionSchema {
    access_kernel::schema::ActionSchema {
        consumption_bearing: true,
        ..schema_of("buy")
    }
}

fn buy() -> ActionRef {
    ActionRef {
        schema: access_kernel::schema::action_digest(&buy_schema()),
        ..action("shop", "buy")
    }
}

/// A Genesis whose `shop` SPP also publishes the consumption-bearing `buy`.
fn genesis_with_buy() -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let mut spp = shop_spp();
    spp.actions.push(buy_schema());
    let mut schemas = shop_schemas();
    if let Value::Map(m) = &mut schemas {
        for (k, v) in m.iter_mut() {
            if *k == Value::text("spp") {
                *v = spp.to_value();
            }
        }
    }
    g.remove("acceptances");
    add_acceptances(&mut g, vec![schemas]);
    g
}

/// A `foreign-authority` Acceptance of `domain` for `classes`, pinning `binding`.
fn foreign_acceptance(domain: Digest, binding: &PublicKey, classes: &[&str]) -> Payload {
    use access_kernel::verify::key_scope::{BindingKey, BindingScope};
    let pin = BindingKey {
        kid: thumbprint(binding),
        alg: access_kernel::verify::cose::Algorithm::Ed25519,
        key: binding.clone(),
        scope: BindingScope::Domain,
        superseded: None,
    };
    let issuer = access_kernel::foreign::ForeignIssuer {
        domain,
        binding: BTreeMap::from([(pin.kid, pin)]),
    };
    let content = Value::Map(vec![
        (
            Value::text("issuer"),
            Value::Map(vec![(Value::text("foreign"), issuer.to_value())]),
        ),
        (Value::text("use"), Value::text("foreign-authority")),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ]);
    let payload = Value::Map(vec![(Value::text("acceptance_establish"), content)]);
    let canonical = dcbor::decode(
        &dcbor::encode(&payload, Limits::CEILING).unwrap(),
        Limits::CEILING,
    )
    .unwrap();
    Payload::from_value(&canonical).unwrap()
}

/// An `Incoming` whose AIS is signed at `iat`.
fn incoming_at(request: Request, seed: u8, iat: u64) -> Incoming {
    let digest = access_kernel::intent::intent_digest(&request.intent).unwrap();
    let statement = Statement {
        domain: request.domain,
        nonce: request.nonce.clone(),
        intent: digest,
        mode: request.mode,
        pep: PEP.to_owned(),
        capacity: request.capacity,
        basis: request.basis,
        iat,
        exercise: request.exercise,
    };
    Incoming {
        ais: Some(sign(&statement, seed)),
        request,
        pep: PEP.to_owned(),
        requester: None,
        explain: false,
        status: None,
        context: None,
    }
}

/// What a holder brings from its home domain: the signed PAP, its excerpt, the home domain's
/// metadata and, when it fetched one, the home domain's status list with its key excerpt.
#[derive(Clone)]
struct Home {
    pap: Vec<u8>,
    excerpt: Vec<u8>,
    metadata: Vec<u8>,
    status: Option<(Vec<u8>, Vec<u8>)>,
}

impl Home {
    /// `request` with this PAP presented by the holder key `seed` at `iat`.
    fn present(&self, mut request: Request, seed: u8, iat: u64) -> Request {
        let p = access_kernel::pap::Presentation {
            pap: access_kernel::pap::pap_digest(&self.pap),
            intent: access_kernel::intent::intent_digest(&request.intent).unwrap(),
            audience: access_kernel::foreign::domain_text(&request.domain),
            nonce: request.nonce.clone(),
            iat,
        };
        request.proofs.push(ProofRef::ForeignPap {
            metadata: self.metadata.clone(),
            pap: self.pap.clone(),
            excerpt: self.excerpt.clone(),
            presentation: sign1(
                seed,
                access_kernel::pap::PRESENTATION_CONTENT_TYPE,
                &p.to_bytes().unwrap(),
            ),
            status: self.status.clone(),
        });
        request
    }
}

/// The home domain's newest published status list with the excerpt of the key that signed it,
/// as a holder fetches it before crossing the border (§9.15A.3).
async fn home_status(
    db: &TestDb,
    d: Digest,
    socket: &std::path::Path,
) -> Option<(Vec<u8>, Vec<u8>)> {
    use access_authority_core::status::adapters::{PgLists, SignerSocket};
    use access_authority_core::status::{Publisher, list_uri};
    Publisher::new(
        PgLists {
            app: db.app.clone(),
            sequencer: db.sequencer.clone(),
        },
        SignerSocket(socket.to_path_buf()),
    )
    .publish(d, NOW)
    .await
    .unwrap();
    let p =
        access_store::status::latest(&db.app, &DomainId::from_bytes(d.0), &list_uri(API, &d, 0))
            .await
            .unwrap()
            .unwrap();
    Some((p.token, p.excerpt.unwrap()))
}

/// In the home domain `d`, where the domain `to` declared its Verifier Profile, ROOT grants
/// Alice `shop.read` and `shop.buy` with a count budget and Alice projects them to `to` twice,
/// each with a slice of two; each PAP comes with the home domain's status list.
#[allow(
    clippy::too_many_lines,
    reason = "one home domain from registration to two signed PAPs and their status list"
)]
async fn home_pap(
    a: &Domains<Listed, Bound, Counter, Fixed>,
    db: &TestDb,
    d: Digest,
    to: Digest,
    socket: &std::path::Path,
    service: &SignerService,
) -> (Home, Home) {
    use access_kernel::model::{BudgetDimension, BudgetTerm, BudgetWindow};
    use access_kernel::validity::{ProfileClass, ProfileVariant};
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let steps = [
        Payload::PartyRegister {
            party: ALICE,
            root: Root::Sole(ALICE),
            actor_kind: ActorKind::Human,
        },
        Payload::InstanceCreate {
            party: ALICE,
            key: public(ALICE_KEY),
            mandate: None,
        },
    ];
    for (nonce, payload) in (3..).zip(steps) {
        allowed(
            &a.exercise(&incoming(
                meta_request(d, nonce, public_basis, payload),
                ALICE_KEY,
            ))
            .await
            .unwrap(),
        );
    }
    // §9.12.1, PI-12
    let audience = access_kernel::foreign::domain_text(&to);
    let body = access_kernel::claim::body::Body::VerifierProfile(verifier_profile(&audience, true));
    admitted(
        &a.ingest(&body_claim(d, "verifier_profile", &body, NOW))
            .await
            .unwrap()
            .verdict,
    );
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let mut granted = authority(vec![action("shop", "read"), buy()], selector("shop"));
    granted.constraints.budget = BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 50,
        window: BudgetWindow::Total,
    }]);
    granted.constraints.validity.until = NOW + 86_400_000;
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: granted,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let issued = a
        .exercise(&incoming(
            meta_request(d, 5, ExerciseBasis::Anchor(shop), issue),
            ROOT_KEY,
        ))
        .await
        .unwrap();
    allowed(&issued);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    });
    let mut paps = Vec::new();
    for nonce in [6, 7] {
        let mut bounds = authority(vec![action("shop", "read"), buy()], selector("shop"));
        bounds.constraints.validity = Window {
            from: NOW,
            until: NOW + 7_200_000,
        };
        // §9.15A.3
        let project = Payload::ProjectionIssue {
            bounds,
            audience: BTreeSet::from([audience.clone()]),
            class: ProfileClass::Offline,
            variant: ProfileVariant::CheckpointedOffline,
            max_staleness_ms: None,
            offline_slice: Some(meta::SliceRequest {
                count: Some(2),
                amounts: BTreeMap::new(),
            }),
        };
        let projected = a
            .exercise(&incoming(
                meta_request(d, nonce, holding, project),
                ALICE_KEY,
            ))
            .await
            .unwrap();
        allowed(&projected);
        paps.push(projected.signed_pap.unwrap());
    }
    service.lock().unwrap().tick(NOW, 1);
    let access_authority_signer::protocol::Response::Metadata(metadata) =
        access_authority_signer::adapters::call(
            socket,
            &access_authority_signer::protocol::Request::Metadata(d),
        )
        .await
        .unwrap()
    else {
        panic!("metadata");
    };
    let status = home_status(db, d, socket).await;
    let home = |(pap, excerpt): (Vec<u8>, Vec<u8>)| Home {
        pap,
        excerpt,
        metadata: metadata.clone(),
        status: status.clone(),
    };
    let twin = home(paps.pop().unwrap());
    (home(paps.pop().unwrap()), twin)
}

fn blocked(r: &Response) -> (access_kernel::combinator::BlockerClass, String) {
    assert_eq!(r.decision.outcome, Outcome::Deny, "{r:?}");
    let b = r.decision.blockers.first().unwrap();
    (b.class, b.subcode.clone().unwrap_or_default())
}

// OP-143 m.13, §9.15A.2–4, §9.12.4, PI-3, INV-17, INV-21, G52, 2337–2339, 2455, 2494
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one home domain, one target domain and each way a foreign PAP is refused"
)]
async fn a_foreign_pap_holds_a_bridging_grant() {
    // INV-17, G10, PI-3, PI-24, CI-10, EI-12
    use access_authority_signer::ports::Bindings as _;
    use access_kernel::combinator::BlockerClass;
    let db = fresh().await.unwrap();
    let a = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let b = create_genesis(&db.sequencer, TENANT, genesis_with_buy(), 2_000)
        .await
        .unwrap();
    assert_ne!(a, b);
    let (socket, service) = start_signer("foreign");
    let home_process = signing_process(&db, a, &socket);
    onboard_signed(&home_process, a, &service).await;
    let (home, twin) = home_pap(&home_process, &db, a, b, &socket, &service).await;

    let log = PgLog::new(db.sequencer.clone(), b, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, b, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(b.0));
    let mut core: Core = Authority::new(leader, reader, binding(), Counter(0), b);
    onboard(&mut core, b, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, b, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, b, BOB, BOB_KEY, (5, 6)).await;
    let meta_basis = ExerciseBasis::Anchor(meta::meta_anchor(&b));
    let shop = meta::object_id(&b, kind::ANCHOR, 1);
    let bridge = |class: &str, nonce: u8| {
        let mut ceiling = authority(
            vec![action("shop", "read"), buy()],
            ResourceSelector::Structural(Structural {
                namespace: "shop".to_owned(),
                prefix: vec!["item-1".to_owned()],
                kind: None,
                attrs: BTreeMap::new(),
            }),
        );
        ceiling.constraints.validity.until = NOW + 86_400_000;
        meta_request(
            b,
            nonce,
            ExerciseBasis::Anchor(shop),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(shop),
                holder: SubjectSelector::Foreign {
                    domain: a,
                    class: class.to_owned(),
                },
                authority: ceiling,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
    };
    let issued = send(&mut core, bridge("shop", 7), ROOT_KEY).await.unwrap();
    allowed(&issued);
    let holding = |holder| {
        ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
            holder,
            since: issued.record.unwrap(),
        })
    };
    let read = |nonce: u8, holder| shop_request(b, nonce, Mode::Commit, holding(holder));
    let refusal = async |core: &mut Core, request: Request, seed: u8| {
        blocked(&send(core, request, seed).await.unwrap())
    };
    let named = |class: BlockerClass, subcode: &str| (class, subcode.to_owned());

    assert_eq!(
        refusal(
            &mut core,
            home.present(read(20, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::SourceNotAccepted, "foreign-not-accepted"),
    );
    let unpinned = send(
        &mut core,
        meta_request(
            b,
            8,
            meta_basis,
            foreign_acceptance(a, &public(99), &["shop"]),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&unpinned);
    assert_eq!(
        refusal(
            &mut core,
            home.present(read(21, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::NoCoveringAuthority, "foreign-metadata"),
    );
    allowed(
        &send(
            &mut core,
            meta_request(
                b,
                9,
                meta_basis,
                Payload::AcceptanceRevoke {
                    acceptance: meta::object_id(&unpinned.exercise.unwrap(), kind::ACCEPTANCE, 0),
                },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    // §9.16
    let revoked = meta::object_id(&unpinned.exercise.unwrap(), kind::ACCEPTANCE, 0);
    assert!(outbox_events(&db, b).await.iter().any(|e| {
        e.kind == access_internal_api::events::Kind::AcceptanceChanged
            && e.subject == access_internal_api::events::Subject::Acceptance(revoked)
    }));

    // 2455, L26, OP-143 m.13 (a)
    let party_issuer = Value::Map(vec![(
        Value::text("acceptance_establish"),
        Value::Map(vec![
            (Value::text("issuer"), ROOT.to_value()),
            (Value::text("use"), Value::text("foreign-authority")),
            (
                Value::text("classes"),
                Value::Array(vec![Value::text("shop")]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
            ),
        ]),
    )]);
    assert!(Payload::from_value(&party_issuer).is_err());
    allowed(
        &send(
            &mut core,
            meta_request(b, 13, meta_basis, {
                let v = claim_acceptance(ALICE, &["shop"]);
                Payload::from_value(&Value::Map(vec![(Value::text("acceptance_establish"), v)]))
                    .unwrap()
            }),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        refusal(
            &mut core,
            home.present(read(30, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::SourceNotAccepted, "foreign-not-accepted"),
    );
    let binding_key = SoftBinding.binding(&a).unwrap().public_key();
    let accepted = send(
        &mut core,
        meta_request(
            b,
            10,
            meta_basis,
            foreign_acceptance(a, &binding_key, &["shop", "billing"]),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&accepted);
    // 2494, §9.12.4
    let mut blind = home.clone();
    blind.status = None;
    assert_eq!(
        refusal(
            &mut core,
            blind.present(read(31, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::ForeignStatusUnavailable, "foreign-status"),
    );
    allowed(
        &send(
            &mut core,
            home.present(read(22, ALICE), ALICE_KEY, NOW),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );

    assert_eq!(
        refusal(&mut core, read(23, ALICE), ALICE_KEY).await,
        named(BlockerClass::SourceNotAccepted, "foreign-pap-missing"),
    );
    let mut outside = read(24, ALICE);
    outside.intent.resources = vec![ResourceRef {
        namespace: "shop".to_owned(),
        path: vec!["item-2".to_owned()],
        incarnation: 0,
    }];
    let r = send(&mut core, home.present(outside, ALICE_KEY, NOW), ALICE_KEY)
        .await
        .unwrap();
    assert_eq!(r.decision.outcome, Outcome::Deny);
    assert_eq!(
        refusal(
            &mut core,
            home.present(read(25, BOB), ALICE_KEY, NOW),
            BOB_KEY
        )
        .await,
        named(BlockerClass::NoCoveringAuthority, "foreign-holder-key"),
    );
    let billing = send(&mut core, bridge("billing", 11), ROOT_KEY)
        .await
        .unwrap();
    allowed(&billing);
    let request = shop_request(
        b,
        27,
        Mode::Commit,
        ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&billing.exercise.unwrap(), kind::GRANT, 0),
            holder: ALICE,
            since: billing.record.unwrap(),
        }),
    );
    assert_eq!(
        refusal(&mut core, home.present(request, ALICE_KEY, NOW), ALICE_KEY).await,
        named(BlockerClass::NoCoveringAuthority, "foreign-class"),
    );
    // §9.15A.3, INV-21
    let mut purchase = read(26, ALICE);
    purchase.intent.action = buy();
    let bought = send(&mut core, home.present(purchase, ALICE_KEY, NOW), ALICE_KEY)
        .await
        .unwrap();
    allowed(&bought);
    assert_eq!(
        refusal(
            &mut core,
            home.present(read(32, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::NoCoveringAuthority, "pap-slice"),
    );
    // 2339, §9.15A.3
    allowed(
        &send(
            &mut core,
            twin.present(read(33, ALICE), ALICE_KEY, NOW),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let twin_pap = access_verifier::offline::peek(&twin.pap).unwrap();
    assert!(
        home_process
            .revoke_family(a, family_of(&twin_pap.projection_exercise))
            .await
            .unwrap()
    );
    allowed(
        &home_process
            .exercise(&incoming(
                shop_request(
                    a,
                    40,
                    Mode::Commit,
                    ExerciseBasis::Anchor(meta::object_id(&a, kind::ANCHOR, 1)),
                ),
                ROOT_KEY,
            ))
            .await
            .unwrap(),
    );
    let mut revoked = twin.clone();
    revoked.status = home_status(&db, a, &socket).await;
    assert_ne!(revoked.status, twin.status);
    assert_eq!(
        refusal(
            &mut core,
            revoked.present(read(34, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::NoCoveringAuthority, "foreign-revoked"),
    );
    allowed(
        &send(
            &mut core,
            twin.present(read(35, ALICE), ALICE_KEY, NOW),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );

    let later = NOW + 3_600_001;
    let stale = core
        .exercise(
            &incoming_at(
                home.present(read(28, ALICE), ALICE_KEY, later),
                ALICE_KEY,
                later,
            ),
            later,
        )
        .await
        .unwrap();
    assert_eq!(
        blocked(&stale),
        named(BlockerClass::ForeignStatusUnavailable, "foreign-stale"),
    );

    allowed(
        &send(
            &mut core,
            meta_request(
                b,
                12,
                meta_basis,
                Payload::AcceptanceRevoke {
                    acceptance: meta::object_id(&accepted.exercise.unwrap(), kind::ACCEPTANCE, 0),
                },
            ),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert_eq!(
        refusal(
            &mut core,
            home.present(read(29, ALICE), ALICE_KEY, NOW),
            ALICE_KEY
        )
        .await,
        named(BlockerClass::SourceNotAccepted, "foreign-not-accepted"),
    );
    fold_check(&db.sequencer, b).await.unwrap();
}

// P52, MD-10, OP-143 m.15 (d)
#[tokio::test]
async fn a_pap_names_parties_by_pseudonym() {
    // P52, MD-10
    use access_kernel::validity::{ProfileClass, ProfileVariant};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut bounds = authority(vec![action("shop", "read")], selector("shop"));
    bounds.authority.recipient = Some(SubjectSelector::Party(ALICE));
    bounds.constraints.validity = Window {
        from: NOW,
        until: NOW + 3_600_000,
    };
    let issue = Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from(["verifier.example".to_owned()]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    let r = send(&mut core, meta_request(d, 9, shop, issue), ROOT_KEY)
        .await
        .unwrap();
    allowed(&r);
    let pap = access_kernel::pap::Pap::from_bytes(&r.pap.unwrap()).unwrap();
    let pseudonym = access_crypto::pseudonym::PseudonymKey::new(Secret::new([7; 32]))
        .party_ref(&ALICE.0)
        .unwrap();
    assert_eq!(
        pap.bounds.recipient,
        Some(SubjectSelector::Party(Id(pseudonym)))
    );
    assert_eq!(pap.validity.bounds.recipient, pap.bounds.recipient);
    assert_ne!(pseudonym, ALICE.0);
}

/// Registers ROOT and ALICE with their keys on `a`.
async fn onboard_both(a: &Domains<Listed, Bound, Counter, Fixed>, d: Digest, alice: ActorKind) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (nonce, seed, party, actor_kind) in [
        (1, ROOT_KEY, ROOT, ActorKind::Human),
        (2, ROOT_KEY, ROOT, ActorKind::Human),
        (3, ALICE_KEY, ALICE, alice),
        (4, ALICE_KEY, ALICE, alice),
    ] {
        let payload = if nonce % 2 == 1 {
            Payload::PartyRegister {
                party,
                root: Root::Sole(party),
                actor_kind,
            }
        } else {
            Payload::InstanceCreate {
                party,
                key: public(seed),
                mandate: None,
            }
        };
        let inc = incoming(meta_request(d, nonce, public_basis, payload), seed);
        allowed(&a.exercise(&inc).await.unwrap());
    }
}

// OP-149 m.10, §9.5.2 rule 1, INV-22
#[tokio::test]
async fn an_eligibility_check_records_nothing() {
    // G28
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    onboard_both(&a, d, ActorKind::Human).await;
    let id = DomainId::from_bytes(d.0);
    let head = access_store::authority::read_head(&db.sequencer, &id)
        .await
        .unwrap();
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let inc = Incoming {
        request: shop_request(d, 50, Mode::Check, ExerciseBasis::Anchor(shop)),
        ais: None,
        pep: PEP.to_owned(),
        requester: None,
        explain: false,
        status: None,
        context: None,
    };
    let root = a.eligible(&inc, ROOT).await.unwrap();
    allowed(&root);
    assert!(root.record.is_none() && root.exercise.is_none());
    assert!(root.consistency.is_some());
    let alice = a.eligible(&inc, ALICE).await.unwrap();
    assert_ne!(alice.decision.outcome, Outcome::Allow);
    assert_eq!(
        access_store::authority::read_head(&db.sequencer, &id)
            .await
            .unwrap(),
        head
    );
    assert!(
        access_store::authority::find_nonce(&db.app, &id, &inc.request.nonce)
            .await
            .unwrap()
            .is_none()
    );
    let mut commit = inc.clone();
    commit.request.mode = Mode::Commit;
    assert_eq!(
        a.eligible(&commit, ROOT).await.unwrap_err().code(),
        "protocol"
    );
    let mut signed = inc;
    signed.ais = incoming(signed.request.clone(), ROOT_KEY).ais;
    assert_eq!(
        a.eligible(&signed, ROOT).await.unwrap_err().code(),
        "protocol"
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-151 m.20 (d), OP-152 m.5, IA-5
#[tokio::test]
async fn a_payload_less_meta_action_probe_is_answered_by_coverage() {
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    onboard_both(&a, d, ActorKind::Human).await;
    let id = DomainId::from_bytes(d.0);
    let head = access_store::authority::read_head(&db.sequencer, &id)
        .await
        .unwrap();
    let probe = |name: &str, basis: ExerciseBasis| Incoming {
        request: Request {
            domain: d,
            mode: Mode::Check,
            nonce: vec![61; 16],
            intent: intent(action("access", name), ("access.domain", "acme"), None),
            payload: None,
            basis,
            capacity: Capacity::Own,
            proofs: Vec::new(),
            exercise: None,
            consistency: None,
        },
        ais: None,
        pep: PEP.to_owned(),
        requester: None,
        context: None,
        explain: false,
        status: None,
    };
    let root = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    for name in [
        "authority_set_define",
        "grant_amend",
        "policy_set",
        "anchor_amend",
    ] {
        allowed(&a.eligible(&probe(name, root), ROOT).await.unwrap());
        let other = a.eligible(&probe(name, root), ALICE).await.unwrap();
        assert_ne!(other.decision.outcome, Outcome::Allow, "{name}");
    }
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let narrow = a.eligible(&probe("policy_set", shop), ROOT).await.unwrap();
    assert_ne!(narrow.decision.outcome, Outcome::Allow);
    assert_eq!(
        access_store::authority::read_head(&db.sequencer, &id)
            .await
            .unwrap(),
        head
    );
    let signed = incoming(probe("grant_amend", root).request, ROOT_KEY);
    assert_eq!(a.exercise(&signed).await.unwrap_err().code(), "protocol");
    let mut commit = probe("grant_amend", root);
    commit.request.mode = Mode::Commit;
    let commit = incoming(commit.request, ROOT_KEY);
    assert_eq!(a.exercise(&commit).await.unwrap_err().code(), "protocol");
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-149 m.5, OP-149 m.8, CR-24, CMP-9, SEC12
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one key through its lookups")]
async fn keys_are_looked_up_at_a_ledger_position() {
    use access_authority_core::keys::{AsOf, KeyState};
    let db = fresh().await.unwrap();
    let mut fields = genesis();
    add_acceptances(
        &mut fields,
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
    let d = create_genesis(&db.sequencer, TENANT, fields, 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    onboard_both(&a, d, ActorKind::Agent).await;
    let (root_kid, alice_kid) = (
        thumbprint(&public(ROOT_KEY)),
        thumbprint(&public(ALICE_KEY)),
    );
    let all = [root_kid, alice_kid, [0xee; 32]];

    let now = a.lookup_keys(d, &all, AsOf::Head, false).await.unwrap();
    let first = &now.lookup;
    assert_eq!(first.unknown, [[0xee; 32]]);
    let (root, alice) = (&first.keys[0], &first.keys[1]);
    assert_eq!(
        (root.kid, root.party, root.key.clone()),
        (root_kid, ROOT, public(ROOT_KEY))
    );
    assert_eq!((alice.kid, alice.party), (alice_kid, ALICE));
    // OP-149 m.8
    assert_eq!(
        (root.actor_kind, alice.actor_kind),
        (ActorKind::Human, ActorKind::Agent)
    );
    assert!(first.keys.iter().all(|k| k.state == KeyState::Active));
    assert!(alice.since.pos > root.since.pos && alice.since.pos <= first.pos);
    assert_eq!(alice.since.at, NOW);

    let early = a
        .lookup_keys(
            d,
            &[alice_kid],
            AsOf::Position(alice.since.pos.saturating_sub(1)),
            false,
        )
        .await
        .unwrap();
    assert_eq!(early.lookup.keys, Vec::new());

    let meta_anchor = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let declared = meta_request(
        d,
        10,
        meta_anchor,
        Payload::ClaimIssue {
            subject: ALICE,
            class: access_kernel::claim::PARTY_COMPROMISE.to_owned(),
            value: EqValue::Int(0),
            validity: None,
            bound_intent: None,
            supersedes: None,
        },
    );
    let claim = a.exercise(&incoming(declared, ROOT_KEY)).await.unwrap();
    allowed(&claim);
    let claim_id = meta::object_id(&claim.exercise.unwrap(), kind::CLAIM, 0);
    let after = a.lookup_keys(d, &all, AsOf::Head, false).await.unwrap();
    let alice_now = &after.lookup.keys[1];
    assert_eq!(alice_now.state, KeyState::Compromised);
    let found = alice_now.compromise.unwrap();
    assert_eq!(
        (found.from, found.claim, found.declared_at),
        (0, claim_id, NOW)
    );
    assert_eq!(after.lookup.keys[0].state, KeyState::Active);
    let then = a
        .lookup_keys(d, &all, AsOf::Position(first.pos), false)
        .await
        .unwrap();
    assert_eq!(then.lookup.keys[1].state, KeyState::Active);
    assert_eq!(then.lookup.keys[1].actor_kind, ActorKind::Agent);
    assert_eq!(then.lookup.pos, first.pos);

    let late = a
        .lookup_keys(d, &[root_kid], AsOf::Time(u64::MAX), false)
        .await
        .unwrap();
    assert_eq!(late.lookup.pos, after.lookup.pos);
    assert_eq!(
        a.lookup_keys(d, &[root_kid], AsOf::Time(10), false)
            .await
            .unwrap_err()
            .code(),
        "protocol"
    );
    assert_eq!(
        unavailable(
            a.lookup_keys(
                d,
                &[root_kid],
                AsOf::Position(after.lookup.pos.saturating_add(1)),
                false
            )
            .await
            .map(|_| unreachable_response())
        ),
        "consistency"
    );
    assert_eq!(
        unavailable(
            a.lookup_keys(d, &[root_kid], AsOf::Head, true)
                .await
                .map(|_| unreachable_response())
        ),
        "signer"
    );
    assert_eq!(
        a.lookup_keys(d, &[[1; 32]; 101], AsOf::Head, false)
            .await
            .unwrap_err()
            .code(),
        "protocol"
    );
    let head = access_store::authority::read_head(&db.app, &DomainId::from_bytes(d.0))
        .await
        .unwrap()
        .pos;
    assert_eq!(head, after.lookup.pos);
    fold_check(&db.sequencer, d).await.unwrap();
}

fn unreachable_response() -> Response {
    panic!("expected no answer")
}

async fn outbox_events(db: &TestDb, d: Digest) -> Vec<access_internal_api::events::Event> {
    access_store::authority::read_outbox(&db.app, &DomainId::from_bytes(d.0), (0, 0), 100)
        .await
        .unwrap()
        .iter()
        .map(|r| access_internal_api::events::Event::from_bytes(&r.event).unwrap())
        .collect()
}

// OP-149 m.7, §9.16, OP-130 m.9
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one domain through four meta-actions"
)]
async fn committed_meta_actions_derive_semantic_events() {
    use access_internal_api::events::{Detail, Kind, ReasonClass, Source, Subject};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    assert_eq!(outbox_events(&db, d).await.len(), 0);
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
        meta_request(d, 7, ExerciseBasis::Anchor(shop), issue),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    let grant = meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0);
    let revoke = Payload::GrantRevoke { grant };
    let denied = send(
        &mut core,
        meta_request(d, 8, ExerciseBasis::Anchor(shop), revoke.clone()),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_ne!(denied.decision.outcome, Outcome::Allow);
    assert_eq!(outbox_events(&db, d).await.len(), 0);
    let revoked = send(
        &mut core,
        meta_request(d, 9, ExerciseBasis::Anchor(shop), revoke),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&revoked);

    let self_anchor = |n: u8| {
        ExerciseBasis::Anchor(meta::object_id(
            &meta::exercise_id(&d, &[n; 16]).unwrap(),
            kind::ANCHOR,
            0,
        ))
    };
    let bob = meta::object_id(&meta::exercise_id(&d, &[6; 16]).unwrap(), kind::INSTANCE, 0);
    let ended = send(
        &mut core,
        meta_request(
            d,
            10,
            self_anchor(5),
            Payload::InstanceTerminate { instance: bob },
        ),
        BOB_KEY,
    )
    .await
    .unwrap();
    allowed(&ended);
    let departed = send(
        &mut core,
        meta_request(
            d,
            11,
            ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            Payload::PartyDepart {
                party: ALICE,
                disposition: BTreeMap::new(),
            },
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&departed);

    let events = outbox_events(&db, d).await;
    let shape: Vec<(Kind, Subject, Source)> = events
        .iter()
        .map(|e| (e.kind, e.subject, e.source))
        .collect();
    assert_eq!(
        shape,
        vec![
            (
                Kind::AuthorityRevoked,
                Subject::Grant(grant),
                Source::Exercise(revoked.exercise.unwrap())
            ),
            (
                Kind::InstanceTerminated,
                Subject::Instance(bob),
                Source::Exercise(ended.exercise.unwrap())
            ),
            (
                Kind::PartyDisabled,
                Subject::Party(ALICE),
                Source::Exercise(departed.exercise.unwrap())
            ),
        ]
    );
    assert!(events.iter().all(|e| e.domain == d && e.at == NOW));
    assert_eq!(events[1].detail, Detail::Instance { party: BOB });
    assert_eq!(
        events[2].detail,
        Detail::Disabled {
            reason: ReasonClass::Departed
        }
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-149 m.7, m.17 (d), SI-9, OP-141 m.31
#[tokio::test]
async fn a_compromise_declaration_derives_party_compromised() {
    use access_internal_api::events::{Detail, Kind, Subject};
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
    let declare = |nonce: u8, value: EqValue| {
        meta_request(
            d,
            nonce,
            ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            Payload::ClaimIssue {
                subject: ALICE,
                class: access_kernel::claim::PARTY_COMPROMISE.to_owned(),
                value,
                validity: None,
                bound_intent: None,
                supersedes: None,
            },
        )
    };
    let known = send(&mut core, declare(10, EqValue::Int(20_000)), ROOT_KEY)
        .await
        .unwrap();
    allowed(&known);
    let unknown = send(&mut core, declare(11, EqValue::Bool(true)), ROOT_KEY)
        .await
        .unwrap();
    allowed(&unknown);
    let events = outbox_events(&db, d).await;
    assert_eq!(events.len(), 2);
    let alice = meta::object_id(&meta::exercise_id(&d, &[4; 16]).unwrap(), kind::INSTANCE, 0);
    let set_up = vec![(alice, thumbprint(&public(ALICE_KEY)))];
    for (e, (occurred, from, covered)) in events
        .iter()
        .zip([(Some(20_000), 20_000, Vec::new()), (None, 0, set_up)])
    {
        assert_eq!(e.kind, Kind::PartyCompromised);
        assert_eq!(e.subject, Subject::Party(ALICE));
        let Detail::Compromised {
            keys,
            occurred_at,
            window_from,
            declared_at,
            ..
        } = &e.detail
        else {
            panic!("{e:?}");
        };
        assert_eq!(
            (*occurred_at, *window_from, *declared_at),
            (occurred, from, NOW)
        );
        assert_eq!(keys, &covered);
    }
}

/// A Genesis whose `shop` SPP also publishes `schema`.
fn genesis_with_schema(schema: access_kernel::schema::ActionSchema) -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let mut spp = shop_spp();
    spp.actions.push(schema);
    let mut schemas = shop_schemas();
    if let Value::Map(m) = &mut schemas {
        for (k, v) in m.iter_mut() {
            if *k == Value::text("spp") {
                *v = spp.to_value();
            }
        }
    }
    g.remove("acceptances");
    add_acceptances(&mut g, vec![schemas]);
    g
}

const RS: &str = "https://rs.example";
const AS_ISSUER: &str = "https://acme.id.example";

/// The irreversible `shop/ship` action: CT2 (§13.7.1).
fn ship_schema() -> access_kernel::schema::ActionSchema {
    access_kernel::schema::ActionSchema {
        effect: access_kernel::schema::EffectClass::Irreversible,
        ..schema_of("ship")
    }
}

fn ship() -> ActionRef {
    ActionRef {
        schema: access_kernel::schema::action_digest(&ship_schema()),
        ..action("shop", "ship")
    }
}

/// ROOT's `projection.issue` of `actions` for `audience`, valid for `life` ms from NOW.
fn token_order(
    d: Digest,
    nonce: u8,
    actions: Vec<ActionRef>,
    audience: &str,
    life: u64,
    authority: access_authority_core::adapters::TokenAuthority,
    family: Option<[u8; 16]>,
) -> access_authority_core::adapters::TokenOrder {
    use access_kernel::validity::{ProfileClass, ProfileVariant};
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut bounds = authority_of(actions);
    bounds.constraints.validity = Window {
        from: NOW,
        until: NOW.checked_add(life).unwrap(),
    };
    let issue = Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from([RS.to_owned()]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    access_authority_core::adapters::TokenOrder {
        incoming: incoming(meta_request(d, nonce, shop, issue), ROOT_KEY),
        issuer: AS_ISSUER.to_owned(),
        client_id: "cli_shop".to_owned(),
        audience: audience.to_owned(),
        confirmation: access_kernel::verify::projection::Confirmation::Jkt(thumbprint(&public(
            ROOT_KEY,
        ))),
        authority,
        family,
    }
}

fn authority_of(actions: Vec<ActionRef>) -> CanonicalAuthority {
    authority(actions, selector("shop"))
}

/// The domain's operational keys that sign tokens, from its metadata.
fn token_keys(
    metadata: &access_kernel::verify::key_scope::DomainMetadata,
) -> access_kernel::verify::cose::KeySet {
    let mut keys = access_kernel::verify::cose::KeySet::default();
    for k in &metadata.operational_keys {
        if k.usage
            .contains(&access_kernel::verify::key_scope::KeyUsage::Token)
        {
            keys.insert(k.kid, k.key.clone()).unwrap();
            keys.allowed.insert(k.alg);
        }
    }
    keys
}

async fn head_of(db: &TestDb, d: Digest) -> u64 {
    access_store::authority::read_head(&db.app, &DomainId::from_bytes(d.0))
        .await
        .unwrap()
        .pos
}

// §9.9, P17, PI-11, INV-38, §9.9.3, TN-14, TN-27
#[tokio::test]
async fn an_authority_token_is_a_projection_issue_decision() {
    use access_authority_core::adapters::{Projected, TokenAuthority};
    // INV-22, MD-7
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("token");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let before = head_of(&db, d).await;
    let order = token_order(
        d,
        20,
        vec![action("shop", "read")],
        RS,
        600_000,
        TokenAuthority::Bounds,
        None,
    );
    let Projected::Issued(t) = a.project(&order).await.unwrap() else {
        panic!("not issued");
    };
    assert!(head_of(&db, d).await > before);
    assert_eq!(t.expires_at, NOW.checked_add(600_000).unwrap());
    let metadata = signer_metadata(&socket, d).await;
    let cnf = access_kernel::verify::projection::Confirmation::Jkt(thumbprint(&public(ROOT_KEY)));
    let verify = |audience: &str, cnf: &access_kernel::verify::projection::Confirmation| {
        access_kernel::verify::projection::verify_access_token(
            &access_kernel::verify::PureBackend,
            &t.jws,
            &token_keys(&metadata),
            &access_kernel::verify::projection::AccessTokenRules {
                issuer: AS_ISSUER,
                audience,
                domain: &d,
                confirmation: cnf,
                now: NOW,
                skew_ms: 60_000,
            },
        )
    };
    let verified = verify(RS, &cnf).unwrap();
    let claims = &verified.claims;
    assert_eq!(
        claims
            .get("exp")
            .and_then(access_kernel::json::Json::as_int),
        Some(610)
    );
    let details = claims.get("authorization_details").unwrap();
    let access_kernel::json::Json::Array(details) = details else {
        panic!("details");
    };
    assert_eq!(details.len(), 1);
    assert_eq!(
        details[0]
            .get("kind")
            .and_then(access_kernel::json::Json::as_str),
        Some("bounds")
    );
    assert_eq!(
        details[0]
            .get("exercise")
            .and_then(access_kernel::json::Json::as_str),
        Some(access_kernel::verify::projection::digest_text(&t.exercise).as_str())
    );
    // MD-10
    assert_ne!(
        claims
            .get("sub")
            .and_then(access_kernel::json::Json::as_str),
        Some(access_kernel::json::b64url_encode(&ROOT.0).as_str())
    );
    assert!(verify("https://other.example", &cnf).is_err());
    assert!(
        verify(
            RS,
            &access_kernel::verify::projection::Confirmation::Jkt([9; 32])
        )
        .is_err()
    );
    // P50
    let f = a.family(d, t.family).await.unwrap().unwrap();
    assert_eq!(f.client_id, "cli_shop");
    assert_eq!(f.root_exercise, t.exercise.0);
    assert!(f.revoked_pos.is_none());
}

// §9.9.3, OP-150 m.3 (s)
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "every refusal of one domain, then the head unchanged"
)]
async fn an_unprojectable_token_is_refused_before_the_decision() {
    use access_authority_core::adapters::{
        BOUNDS_HORIZON_MS, INTENT_HORIZON_MS, Projected, TokenAuthority,
    };
    // AG-8, MD-7, P48
    let db = fresh().await.unwrap();
    let d = create_genesis(
        &db.sequencer,
        TENANT,
        genesis_with_schema(ship_schema()),
        1_000,
    )
    .await
    .unwrap();
    let (socket, service) = start_signer("token-refused");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let before = head_of(&db, d).await;
    let read = || vec![action("shop", "read")];
    let refused = |p: Projected| match p {
        Projected::Refused(c) => c,
        other => panic!("{other:?}"),
    };
    let cases = [
        (
            token_order(
                d,
                30,
                read(),
                "https://other.example",
                60_000,
                TokenAuthority::Bounds,
                None,
            ),
            "invalid-target",
        ),
        (
            token_order(
                d,
                31,
                read(),
                RS,
                BOUNDS_HORIZON_MS.checked_add(1).unwrap(),
                TokenAuthority::Bounds,
                None,
            ),
            "projection-horizon",
        ),
        (
            token_order(
                d,
                32,
                vec![action("access", "grant_issue")],
                RS,
                60_000,
                TokenAuthority::Bounds,
                None,
            ),
            "projection-authority",
        ),
        // §9.9.3 rule 4
        (
            token_order(
                d,
                33,
                vec![ship()],
                RS,
                60_000,
                TokenAuthority::Bounds,
                None,
            ),
            "projection-tier",
        ),
    ];
    for (order, code) in cases {
        assert_eq!(refused(a.project(&order).await.unwrap()), code);
    }
    let mut target = shop_request(d, 34, Mode::Commit, ExerciseBasis::Anchor(Id([0; 16]))).intent;
    target.action = ship();
    let long = token_order(
        d,
        35,
        vec![ship()],
        RS,
        INTENT_HORIZON_MS.checked_add(1).unwrap(),
        TokenAuthority::Intent(Box::new(target.clone())),
        None,
    );
    assert_eq!(
        refused(a.project(&long).await.unwrap()),
        "projection-horizon"
    );
    let other = token_order(
        d,
        36,
        vec![action("shop", "read")],
        RS,
        60_000,
        TokenAuthority::Intent(Box::new(target)),
        None,
    );
    assert_eq!(
        refused(a.project(&other).await.unwrap()),
        "projection-authority"
    );
    assert_eq!(head_of(&db, d).await, before);
}

// §9.9.1, P17
#[tokio::test]
async fn an_exact_intent_token_carries_its_intent() {
    use access_authority_core::adapters::{Projected, TokenAuthority};
    let db = fresh().await.unwrap();
    let d = create_genesis(
        &db.sequencer,
        TENANT,
        genesis_with_schema(ship_schema()),
        1_000,
    )
    .await
    .unwrap();
    let (socket, service) = start_signer("token-intent");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let mut target = shop_request(d, 40, Mode::Commit, ExerciseBasis::Anchor(Id([0; 16]))).intent;
    target.action = ship();
    let order = token_order(
        d,
        41,
        vec![ship()],
        RS,
        300_000,
        TokenAuthority::Intent(Box::new(target.clone())),
        None,
    );
    let Projected::Issued(t) = a.project(&order).await.unwrap() else {
        panic!("not issued");
    };
    let payload = t.jws.split('.').nth(1).unwrap();
    let claims =
        access_kernel::json::parse(&access_kernel::json::b64url_decode(payload).unwrap(), 8192)
            .unwrap();
    let access_kernel::json::Json::Array(details) = claims.get("authorization_details").unwrap()
    else {
        panic!("details");
    };
    assert_eq!(details.len(), 1);
    assert_eq!(
        details[0]
            .get("kind")
            .and_then(access_kernel::json::Json::as_str),
        Some("intent")
    );
    assert_eq!(
        details[0]
            .get("intent")
            .and_then(access_kernel::json::Json::as_str),
        Some(
            access_kernel::verify::projection::digest_text(
                &access_kernel::intent::intent_digest(&target).unwrap()
            )
            .as_str()
        )
    );
}

// §9.9.3 rule 6, L19, P50, PI-10
#[tokio::test]
async fn a_refresh_is_a_new_decision_until_its_family_is_revoked() {
    use access_authority_core::adapters::{Projected, TokenAuthority};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("token-refresh");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let read = || vec![action("shop", "read")];
    let Projected::Issued(first) = a
        .project(&token_order(
            d,
            50,
            read(),
            RS,
            60_000,
            TokenAuthority::Bounds,
            None,
        ))
        .await
        .unwrap()
    else {
        panic!("first");
    };
    let head = head_of(&db, d).await;
    let Projected::Issued(second) = a
        .project(&token_order(
            d,
            51,
            read(),
            RS,
            60_000,
            TokenAuthority::Bounds,
            Some(first.family),
        ))
        .await
        .unwrap()
    else {
        panic!("refresh");
    };
    assert_eq!(second.family, first.family);
    assert_ne!(second.exercise, first.exercise);
    assert!(second.position > head);
    assert_eq!(
        a.project(&token_order(
            d,
            51,
            read(),
            RS,
            60_000,
            TokenAuthority::Bounds,
            Some(first.family),
        ))
        .await
        .unwrap(),
        Projected::Refused("replayed")
    );
    assert!(a.revoke_family(d, first.family).await.unwrap());
    assert!(!a.revoke_family(d, first.family).await.unwrap());
    let head = head_of(&db, d).await;
    assert_eq!(
        a.project(&token_order(
            d,
            52,
            read(),
            RS,
            60_000,
            TokenAuthority::Bounds,
            Some(first.family),
        ))
        .await
        .unwrap(),
        Projected::Refused("family-revoked")
    );
    assert_eq!(head_of(&db, d).await, head);
    assert_eq!(
        a.project(&token_order(
            d,
            53,
            read(),
            RS,
            60_000,
            TokenAuthority::Bounds,
            Some([0xee; 16]),
        ))
        .await
        .unwrap(),
        Projected::Refused("family-unknown")
    );
}

// K17, §16.7.1
#[tokio::test]
async fn no_signer_no_token() {
    use access_authority_core::adapters::{Projected, TokenAuthority};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("token-down");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    a.release().await;
    let gone = std::env::temp_dir().join(format!("access-no-signer-{}", std::process::id()));
    let b = signing_process(&db, d, &gone);
    let order = token_order(
        d,
        60,
        vec![action("shop", "read")],
        RS,
        60_000,
        TokenAuthority::Bounds,
        None,
    );
    assert_eq!(
        b.project(&order).await.unwrap(),
        Projected::Refused(access_internal_api::projections::SIGNER_UNAVAILABLE)
    );
}

// §9.9.3 rule 5, MD-8, OPI-3, P50, OP-150 m.2
#[tokio::test]
async fn introspection_reflects_signature_horizon_and_family() {
    use access_authority_core::adapters::{FAMILY_CLAIM, Projected, TokenAuthority};
    // T24, OP-45
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("token-introspect");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let order = token_order(
        d,
        70,
        vec![action("shop", "read")],
        RS,
        60_000,
        TokenAuthority::Bounds,
        None,
    );
    let Projected::Issued(t) = a.project(&order).await.unwrap() else {
        panic!("not issued");
    };
    let (active, claims, as_of) = a.introspect(d, &t.jws, NOW).await.unwrap();
    assert!(active);
    assert_eq!(as_of, head_of(&db, d).await);
    let claims = access_kernel::json::parse(claims.unwrap().as_bytes(), 8192).unwrap();
    assert_eq!(
        claims
            .get(FAMILY_CLAIM)
            .and_then(access_kernel::json::Json::as_str),
        Some(access_kernel::json::b64url_encode(&t.family).as_str())
    );
    let late = NOW.checked_add(61_000).unwrap();
    assert!(!a.introspect(d, &t.jws, late).await.unwrap().0);
    let mut parts: Vec<String> = t.jws.split('.').map(str::to_owned).collect();
    parts[1] = access_kernel::json::b64url_encode(br#"{"exp":99999999999}"#);
    assert!(!a.introspect(d, &parts.join("."), NOW).await.unwrap().0);
    // P50
    assert!(a.revoke_family(d, t.family).await.unwrap());
    assert!(!a.introspect(d, &t.jws, NOW).await.unwrap().0);
}

/// ALICE's bounds token for `shop.read` over `resource`, decided on `basis`.
fn alice_order(
    d: Digest,
    nonce: u8,
    basis: ExerciseBasis,
    resource: ResourceSelector,
) -> access_authority_core::adapters::TokenOrder {
    use access_kernel::validity::{ProfileClass, ProfileVariant};
    let mut bounds = authority(vec![action("shop", "read")], resource);
    bounds.constraints.validity = Window {
        from: NOW,
        until: NOW.checked_add(600_000).unwrap(),
    };
    let issue = Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from([RS.to_owned()]),
        class: ProfileClass::Online,
        variant: ProfileVariant::OnlineStrict,
        max_staleness_ms: None,
        offline_slice: None,
    };
    access_authority_core::adapters::TokenOrder {
        incoming: incoming(meta_request(d, nonce, basis, issue), ALICE_KEY),
        issuer: AS_ISSUER.to_owned(),
        client_id: "cli_shop".to_owned(),
        audience: RS.to_owned(),
        confirmation: access_kernel::verify::projection::Confirmation::Jkt(thumbprint(&public(
            ALICE_KEY,
        ))),
        authority: access_authority_core::adapters::TokenAuthority::Bounds,
        family: None,
    }
}

// §5.3, §5.17, INV-33, S-1, OP-141 m.32, OP-148
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "a role defined, pinned by two Grants and projected three ways"
)]
async fn a_role_claim_is_a_grant_projection() {
    use access_authority_core::adapters::Projected;
    use access_kernel::meta::authority_set_digest;
    // §9.9.6, P55, PI-8
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("roles");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (nonce, payload) in [
        (
            3,
            Payload::PartyRegister {
                party: ALICE,
                root: Root::Sole(ALICE),
                actor_kind: ActorKind::Human,
            },
        ),
        (
            4,
            Payload::InstanceCreate {
                party: ALICE,
                key: public(ALICE_KEY),
                mandate: None,
            },
        ),
    ] {
        allowed(
            &a.exercise(&incoming(
                meta_request(d, nonce, public_basis, payload),
                ALICE_KEY,
            ))
            .await
            .unwrap(),
        );
    }
    let reader = authority_of(vec![action("shop", "read")]).authority;
    allowed(
        &a.exercise(&incoming(
            meta_request(
                d,
                5,
                ExerciseBasis::Anchor(meta::meta_anchor(&d)),
                Payload::AuthoritySetDefine {
                    name: "reader".to_owned(),
                    authority: reader.clone(),
                },
            ),
            ROOT_KEY,
        ))
        .await
        .unwrap(),
    );
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let grant = |named| {
        Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Anchor(shop),
            holder: SubjectSelector::Party(ALICE),
            authority: authority_of(vec![action("shop", "read")]),
            agency: BTreeSet::from([Capacity::Own]),
            named,
        })
    };
    let mut holdings = Vec::new();
    for (nonce, named) in [
        (
            6,
            Some(("reader".to_owned(), 1, authority_set_digest(&reader))),
        ),
        (7, None),
    ] {
        let issued = a
            .exercise(&incoming(
                meta_request(d, nonce, ExerciseBasis::Anchor(shop), grant(named)),
                ROOT_KEY,
            ))
            .await
            .unwrap();
        allowed(&issued);
        holdings.push(ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
            holder: ALICE,
            since: issued.record.unwrap(),
        }));
    }
    let metadata = signer_metadata(&socket, d).await;
    let cnf = access_kernel::verify::projection::Confirmation::Jkt(thumbprint(&public(ALICE_KEY)));
    let roles = |jws: &str| {
        let verified = access_kernel::verify::projection::verify_access_token(
            &access_kernel::verify::PureBackend,
            jws,
            &token_keys(&metadata),
            &access_kernel::verify::projection::AccessTokenRules {
                issuer: AS_ISSUER,
                audience: RS,
                domain: &d,
                confirmation: &cnf,
                now: NOW,
                skew_ms: 60_000,
            },
        )
        .unwrap();
        verified.claims.get("roles").cloned()
    };
    let orders = [
        alice_order(d, 20, holdings[0], selector("shop")),
        alice_order(d, 21, holdings[1], selector("shop")),
        alice_order(
            d,
            22,
            holdings[0],
            ResourceSelector::Structural(Structural {
                namespace: "shop".to_owned(),
                prefix: vec!["orders".to_owned()],
                kind: None,
                attrs: BTreeMap::new(),
            }),
        ),
    ];
    let mut seen = Vec::new();
    for order in &orders {
        let Projected::Issued(t) = a.project(order).await.unwrap() else {
            panic!("not issued");
        };
        seen.push(roles(&t.jws));
    }
    assert_eq!(
        seen,
        vec![
            Some(access_kernel::json::Json::Array(vec![
                access_kernel::json::Json::Str("reader".to_owned())
            ])),
            None,
            None,
        ]
    );
}

/// The JSON claims of a compact JWS, unverified.
fn jwt_claims(jws: &str) -> access_kernel::json::Json {
    let payload = jws.split('.').nth(1).unwrap();
    access_kernel::json::parse(&access_kernel::json::b64url_decode(payload).unwrap(), 8192).unwrap()
}

/// The latest signed list at `uri`, read without verifying, with its inflated bits.
async fn published_bits(
    db: &TestDb,
    d: Digest,
    uri: &str,
) -> (access_kernel::status::ListToken, Vec<u8>) {
    let p = access_store::status::latest(&db.app, &DomainId::from_bytes(d.0), uri)
        .await
        .unwrap()
        .unwrap();
    let payload = access_kernel::verify::cose::parse_sign1(&p.token)
        .unwrap()
        .payload
        .unwrap();
    let t = access_kernel::status::ListToken::from_bytes(&payload).unwrap();
    let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&t.lst).unwrap();
    (t, raw)
}

fn entry(uri: &str, idx: u64) -> access_kernel::status::StatusRef {
    access_kernel::status::StatusRef {
        idx,
        uri: uri.to_owned(),
    }
}

// OP-150 m.3 (a), (s), m.10 (a), (b), §11.20, T24, G43, L2-STL-3
#[tokio::test]
async fn a_token_names_its_status_list_entry() {
    use access_authority_core::adapters::{Projected, STATUS_CLAIM, TokenAuthority};
    use access_authority_core::status::adapters::{PgLists, SignerSocket};
    use access_authority_core::status::{Publisher, list_uri};
    use access_kernel::json::Json;
    use access_kernel::status::lookup;
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("token-status");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let uri = list_uri(API, &d, 0);
    let issue = |nonce, family| {
        token_order(
            d,
            nonce,
            vec![action("shop", "read")],
            RS,
            60_000,
            TokenAuthority::Bounds,
            family,
        )
    };
    let issued = async |order| match a.project(&order).await.unwrap() {
        Projected::Issued(t) => t,
        other => panic!("{other:?}"),
    };
    let first = issued(issue(80, None)).await;
    assert_eq!(first.status, Some(entry(&uri, 0)));
    let status = jwt_claims(&first.jws);
    let status = status
        .get(STATUS_CLAIM)
        .unwrap()
        .get("status_list")
        .unwrap();
    assert_eq!(status.get("idx").and_then(Json::as_int), Some(0));
    assert_eq!(status.get("uri").and_then(Json::as_str), Some(uri.as_str()));
    assert!(first.jws.len() <= access_internal_api::projections::MAX_TOKEN_BYTES);
    assert_eq!(
        a.family(d, first.family).await.unwrap().unwrap().status,
        Some((uri.clone(), 0))
    );
    let second = issued(issue(81, None)).await;
    assert_eq!(second.status, Some(entry(&uri, 1)));
    let refreshed = issued(issue(82, Some(first.family))).await;
    assert_eq!(refreshed.family, first.family);
    assert_eq!(refreshed.status, Some(entry(&uri, 0)));
    let (active, claims, _) = a.introspect(d, &refreshed.jws, NOW).await.unwrap();
    assert!(active);
    assert!(
        access_kernel::json::parse(claims.unwrap().as_bytes(), 8192)
            .unwrap()
            .get(STATUS_CLAIM)
            .is_some()
    );

    let publisher = Publisher::new(
        PgLists {
            app: db.app.clone(),
            sequencer: db.sequencer.clone(),
        },
        SignerSocket(socket.clone()),
    );
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let (t, raw) = published_bits(&db, d, &uri).await;
    assert_eq!(t.as_of, head_of(&db, d).await);
    assert!(!lookup(&t, &raw, &entry(&uri, 0)).unwrap());
    assert!(!lookup(&t, &raw, &entry(&uri, 1)).unwrap());
    // G43
    assert!(a.revoke_family(d, second.family).await.unwrap());
    assert_eq!(publisher.publish(d, NOW).await.unwrap(), Vec::new());
    let third = issued(issue(83, None)).await;
    assert_eq!(third.status, Some(entry(&uri, 2)));
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let (t, raw) = published_bits(&db, d, &uri).await;
    assert_eq!(t.as_of, head_of(&db, d).await);
    assert!(!lookup(&t, &raw, &entry(&uri, 0)).unwrap());
    assert!(lookup(&t, &raw, &entry(&uri, 1)).unwrap());
    assert!(!lookup(&t, &raw, &entry(&uri, 2)).unwrap());
}

// §9.9.3 k.6, §9.16, P50, OP-150 m.9 (d), m.10 (g)
#[tokio::test]
async fn ending_a_holder_revokes_its_families_with_one_event_each() {
    use access_authority_core::adapters::{Projected, TokenAuthority};
    use access_authority_core::status::adapters::{PgLists, SignerSocket};
    use access_authority_core::status::{Publisher, list_uri};
    use access_internal_api::events::{Kind, Source, Subject};
    use access_kernel::status::lookup;
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("token-holder-end");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    let uri = list_uri(API, &d, 0);
    let issue = |nonce, family| {
        token_order(
            d,
            nonce,
            vec![action("shop", "read")],
            RS,
            60_000,
            TokenAuthority::Bounds,
            family,
        )
    };
    let issued = async |order| match a.project(&order).await.unwrap() {
        Projected::Issued(t) => t,
        other => panic!("{other:?}"),
    };
    let first = issued(issue(90, None)).await;
    let second = issued(issue(91, None)).await;
    let before = outbox_events(&db, d).await.len();

    let instance = meta::object_id(&meta::exercise_id(&d, &[2; 16]).unwrap(), kind::INSTANCE, 0);
    let anchor = ExerciseBasis::Anchor(meta::object_id(
        &meta::exercise_id(&d, &[1; 16]).unwrap(),
        kind::ANCHOR,
        0,
    ));
    let terminate = incoming(
        meta_request(d, 92, anchor, Payload::InstanceTerminate { instance }),
        ROOT_KEY,
    );
    let ended = a.exercise(&terminate).await.unwrap();
    allowed(&ended);
    assert_eq!(ended.ended, vec![instance]);
    let pos = ended.record.unwrap();
    for t in [&first, &second] {
        assert_eq!(
            a.family(d, t.family).await.unwrap().unwrap().revoked_pos,
            Some(pos)
        );
    }
    let events = outbox_events(&db, d).await;
    let new = &events[before..];
    assert_eq!(new[0].kind, Kind::InstanceTerminated);
    assert_eq!(new[0].subject, Subject::Instance(instance));
    let invalidated: Vec<_> = new
        .iter()
        .filter(|e| e.kind == Kind::ProjectionInvalidated)
        .collect();
    assert_eq!(invalidated.len(), 2);
    assert_eq!(new.len(), 3);
    let mut subjects: Vec<Subject> = invalidated.iter().map(|e| e.subject).collect();
    subjects.sort_by_key(|s| s.bytes().to_vec());
    let mut expected = vec![
        Subject::Projection(first.exercise),
        Subject::Projection(second.exercise),
    ];
    expected.sort_by_key(|s| s.bytes().to_vec());
    assert_eq!(subjects, expected);
    assert!(
        invalidated
            .iter()
            .all(|e| e.source == Source::Exercise(ended.exercise.unwrap()) && e.at == NOW)
    );
    assert!(matches!(
        a.exercise(&terminate).await,
        Err(CoreError::Ais(_))
    ));
    assert_eq!(outbox_events(&db, d).await.len(), events.len());
    assert_eq!(
        a.project(&issue(93, Some(first.family))).await.unwrap(),
        Projected::Refused("family-revoked")
    );
    assert!(!a.introspect(d, &first.jws, NOW).await.unwrap().0);
    let publisher = Publisher::new(
        PgLists {
            app: db.app.clone(),
            sequencer: db.sequencer.clone(),
        },
        SignerSocket(socket.clone()),
    );
    assert_eq!(publisher.publish(d, NOW).await.unwrap().len(), 1);
    let (t, raw) = published_bits(&db, d, &uri).await;
    assert_eq!(t.as_of, pos);
    assert!(lookup(&t, &raw, &entry(&uri, 0)).unwrap());
    assert!(lookup(&t, &raw, &entry(&uri, 1)).unwrap());
}

// OP-150

/// The verifier a robot or edge device presents itself as (§9.12.1).
const ROBOT: &str = "robot.example";

/// A clock the test moves (OP-129 m.1).
#[derive(Clone)]
struct Movable(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl Movable {
    fn at(now: u64) -> Self {
        Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(now)))
    }

    fn set(&self, now: u64) {
        self.0.store(now, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Clock for Movable {
    fn now(&mut self) -> impl Future<Output = Result<u64, SequencerError>> + Send {
        std::future::ready(Ok(self.0.load(std::sync::atomic::Ordering::Relaxed)))
    }
}

/// A process leading `d` without a signer, on a clock the test moves.
fn moving_process(
    db: &TestDb,
    d: Digest,
    clock: Movable,
) -> Domains<Listed, Bound, Counter, Movable> {
    Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(vec![d]),
        holder: "l8".to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(0),
        clock,
        deriver: db.deriver.clone(),
        signer: None,
        api_base: API.to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    })
}

/// A `predicate-input` Acceptance of `issuer` for `classes`, for every subject, forever.
fn claim_acceptance(issuer: Id, classes: &[&str]) -> Value {
    Value::Map(vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text("predicate-input")),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(u64::MAX)]),
        ),
    ])
}

/// A Genesis whose `shop` SPP publishes `read`, the consumption-bearing `buy` and the
/// irreversible `ship`, and that accepts ROOT's Verifier Profiles and Offline Exercise Reports.
fn genesis_offline() -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let mut spp = shop_spp();
    spp.actions.push(buy_schema());
    spp.actions.push(ship_schema());
    let mut schemas = shop_schemas();
    if let Value::Map(m) = &mut schemas {
        for (k, v) in m.iter_mut() {
            if *k == Value::text("spp") {
                *v = spp.to_value();
            }
        }
    }
    g.remove("acceptances");
    add_acceptances(
        &mut g,
        vec![
            schemas,
            claim_acceptance(ROOT, &["verifier_profile", "offline_exercise_report"]),
        ],
    );
    g
}

/// The Verifier Profile of `audience` (§9.12.1): every variant but `checkpoint-continuation`,
/// a tamper-evident counter, offline reports and the secure clock class; with `hardware`, an
/// attestation too (§13.7.2).
fn verifier_profile(audience: &str, hardware: bool) -> access_kernel::claim::body::VerifierProfile {
    use access_kernel::claim::body::{VerifierId, VerifierProfile};
    use access_kernel::validity::ProfileVariant as V;
    VerifierProfile {
        verifier: VerifierId::Workload(audience.to_owned()),
        profiles: BTreeMap::from([
            (V::CheckpointedOffline, BTreeMap::new()),
            (V::BoundedStaleness, BTreeMap::new()),
            (V::RevalidateOnReconnect, BTreeMap::new()),
            (V::OnlineStrict, BTreeMap::new()),
        ]),
        versions: access_kernel::verify::key_scope::SpecVersions::default(),
        clock_source: access_verifier::caps::SECURE_CLOCK_CLASS.to_owned(),
        clock_skew_ms: 60_000,
        tamper_evident_counter: true,
        offline_report: true,
        content_position_check: false,
        status_access: BTreeSet::new(),
        refresh_interval_ms: None,
        attestation: hardware.then_some(Digest([30; 32])),
        cap_horizon: BTreeMap::new(),
        slice_max: BTreeMap::new(),
        conformance: BTreeSet::new(),
    }
}

/// ROOT's Claim of `class` with `body`, signed by ROOT's key, submitted with the body.
fn body_claim(
    d: Digest,
    class: &str,
    body: &access_kernel::claim::body::Body,
    issued_at: u64,
) -> access_internal_api::claims::ClaimSubmission {
    let v = body.to_value();
    let digest = access_kernel::claim::body::body_digest(
        access_kernel::claim::body::Class::parse(class).unwrap(),
        &v,
    )
    .unwrap();
    report_claim(
        d,
        class,
        digest,
        dcbor::encode(&v, Limits::CEILING).unwrap(),
        issued_at,
    )
}

/// ROOT's Claim of `class` whose value is `digest` and whose body is `body`.
fn report_claim(
    d: Digest,
    class: &str,
    digest: [u8; 32],
    body: Vec<u8>,
    issued_at: u64,
) -> access_internal_api::claims::ClaimSubmission {
    let st = access_kernel::claim::Statement {
        domain: d,
        issuer: ROOT,
        subject: ROOT,
        class: class.to_owned(),
        value: Some(EqValue::Bytes(digest.to_vec())),
        issued_at,
        validity: Window {
            from: 0,
            until: 1 << 50,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes: None,
    };
    access_internal_api::claims::ClaimSubmission {
        domain: d,
        carrier: access_internal_api::claims::Carrier::Cose,
        claim: sign1(
            ROOT_KEY,
            access_kernel::claim::CONTENT_TYPE,
            &st.to_bytes().unwrap(),
        ),
        body: Some(body),
        evidence: None,
    }
}

fn admitted(v: &access_internal_api::claims::ClaimVerdict) {
    assert!(
        matches!(
            v,
            access_internal_api::claims::ClaimVerdict::Admitted { .. }
        ),
        "{v:?}"
    );
}

/// Registers `party` with the key `seed` through the process `a`.
async fn onboard_process<C: Clock + Clone>(
    a: &Domains<Listed, Bound, Counter, C>,
    d: Digest,
    party: Id,
    seed: u8,
    nonces: (u8, u8),
) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let steps = [
        Payload::PartyRegister {
            party,
            root: Root::Sole(party),
            actor_kind: ActorKind::Human,
        },
        Payload::InstanceCreate {
            party,
            key: public(seed),
            mandate: None,
        },
    ];
    for (nonce, payload) in [nonces.0, nonces.1].into_iter().zip(steps) {
        allowed(
            &a.exercise(&incoming(
                meta_request(d, nonce, public_basis, payload),
                seed,
            ))
            .await
            .unwrap(),
        );
    }
}

/// ROOT grants ALICE `actions` on `shop` with a count budget of `count` for three days; the
/// holding ALICE exercises it by.
async fn grant_alice<C: Clock + Clone>(
    a: &Domains<Listed, Bound, Counter, C>,
    d: Digest,
    nonce: u8,
    actions: Vec<ActionRef>,
    count: u64,
) -> ExerciseBasis {
    use access_kernel::model::{BudgetDimension, BudgetTerm, BudgetWindow};
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let mut granted = authority(actions, selector("shop"));
    granted.constraints.budget = BTreeSet::from([BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: count,
        window: BudgetWindow::Total,
    }]);
    granted.constraints.validity.until = NOW + 72 * 3_600_000;
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: granted,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let issued = a
        .exercise(&incoming(
            meta_request(d, nonce, ExerciseBasis::Anchor(shop), issue),
            ROOT_KEY,
        ))
        .await
        .unwrap();
    allowed(&issued);
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    })
}

/// A `projection.issue` payload of `actions` to `audience` under `variant`, from `from` to
/// `horizon`.
fn projection(
    actions: Vec<ActionRef>,
    audience: &[&str],
    variant: access_kernel::validity::ProfileVariant,
    (from, horizon): (u64, u64),
    max_staleness_ms: Option<u64>,
    slice: Option<u64>,
) -> Payload {
    let mut bounds = authority(actions, selector("shop"));
    bounds.constraints.validity = Window {
        from,
        until: horizon,
    };
    Payload::ProjectionIssue {
        bounds,
        audience: audience.iter().map(|a| (*a).to_owned()).collect(),
        class: variant.class(),
        variant,
        max_staleness_ms,
        offline_slice: slice.map(|count| meta::SliceRequest {
            count: Some(count),
            amounts: BTreeMap::new(),
        }),
    }
}

/// Domain Metadata the verifier holds, witnessed at `now` (TI-RT5).
fn witnessed(
    metadata: access_kernel::verify::key_scope::DomainMetadata,
    now: u64,
) -> access_verifier::metadata::MetadataView {
    use suiss_crypto::note::{self, Verifier};
    const LOG: &str = "access.example/log";
    const WITNESS: &str = "witness.example/w1";
    let (log_key, witness_key) = (signing(40), signing(41));
    let log = Verifier::ed25519(LOG, log_key.verifying_key().to_bytes()).unwrap();
    let witness = Verifier::cosigner(WITNESS, witness_key.verifying_key().to_bytes()).unwrap();
    let signed = b"signed domain metadata";
    let body = format!(
        "{LOG}\n7\n{}\nmetadata sha-256:{}\n",
        note::base64_encode(&[7; 32]),
        access_kernel::json::b64url_encode(&access_verifier::metadata::metadata_digest(signed)),
    );
    let mut sig = log.id().to_be_bytes().to_vec();
    sig.extend(log_key.sign(body.as_bytes()).to_bytes());
    let mut checkpoint = format!("{body}\n\u{2014} {LOG} {}\n", note::base64_encode(&sig));
    let ts = now / 1_000;
    let mut sig = witness.id().to_be_bytes().to_vec();
    sig.extend(ts.to_be_bytes());
    sig.extend(
        witness_key
            .sign(&note::cosigned_message(ts, &body))
            .to_bytes(),
    );
    checkpoint = format!(
        "{checkpoint}\u{2014} {WITNESS} {}\n",
        note::base64_encode(&sig)
    );
    let mut view = access_verifier::metadata::MetadataView::new(metadata, signed);
    view.witness(&checkpoint, LOG, &log, &[witness]).unwrap();
    view
}

/// The holder's presentation of `pap` for `intent` to `audience`, signed by `seed`.
fn presentation(
    pap: &[u8],
    intent: &IntentEnvelope,
    audience: &str,
    nonce: &[u8],
    seed: u8,
    iat: u64,
) -> Vec<u8> {
    let p = access_kernel::pap::Presentation {
        pap: access_kernel::pap::pap_digest(pap),
        intent: access_kernel::intent::intent_digest(intent).unwrap(),
        audience: audience.to_owned(),
        nonce: nonce.to_vec(),
        iat,
    };
    sign1(
        seed,
        access_kernel::pap::PRESENTATION_CONTENT_TYPE,
        &p.to_bytes().unwrap(),
    )
}

/// The `access/validity/v1` digest of a PAP's contract (OP-150 m.7 (a)).
fn contract_digest(pap: &access_kernel::pap::Pap) -> Digest {
    Digest(
        suiss_crypto::digest::context_digest(
            access_authority_core::adapters::CONTRACT_LABEL,
            &pap.validity.to_bytes().unwrap(),
        )
        .0,
    )
}

fn policy_denied(r: &Response, code: &str) {
    assert_eq!(
        blocked(r),
        (
            access_kernel::combinator::BlockerClass::Restricted,
            code.to_owned()
        ),
        "{r:?}"
    );
}

/// The first 16 bytes of an `ExerciseID`: its projection family (P50).
fn family_of(exercise: &Digest) -> [u8; 16] {
    let mut f = [0; 16];
    f.copy_from_slice(&exercise.0[..16]);
    f
}

// L2-PAP-1 to L2-PAP-3, L2-RPT-1 to L2-RPT-3, §9.10, §9.12, §9.12.1, §9.12.2, §7.9.4.1, §13.7.2
// PI-12, INV-21, OP-150 m.7 (a), m.10 (a)
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one domain, one verifier device and one projection from issuance to reconciliation"
)]
async fn a_core_pap_is_accepted_and_reported_by_the_verifier_sdk() {
    use access_authority_core::app::projection::policy;
    use access_kernel::report::{LocalOutcome, Report};
    use access_kernel::validity::ProfileVariant;
    use access_verifier::counter::CounterId;
    use access_verifier::offline::{Identity, OfflineVerifier, Use, Verdict, peek};
    use access_verifier::profile::LocalProfile;
    use access_verifier::testing::{EmulatedClock, EmulatedCounter};
    use access_verifier::time::{ClockGuard, DEFAULT_TOLERANCE_MS};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let (socket, service) = start_signer("sdk-pap");
    let a = signing_process(&db, d, &socket);
    onboard_signed(&a, d, &service).await;
    onboard_process(&a, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = grant_alice(&a, d, 5, vec![action("shop", "read")], 50).await;
    let hour = 3_600_000;
    let offline = |slice| {
        projection(
            vec![action("shop", "read")],
            &[ROBOT],
            ProfileVariant::CheckpointedOffline,
            (NOW, NOW + hour),
            None,
            Some(slice),
        )
    };
    // §9.12.1
    policy_denied(
        &a.exercise(&incoming(
            meta_request(d, 6, holding, offline(2)),
            ALICE_KEY,
        ))
        .await
        .unwrap(),
        policy::VERIFIER_PROFILE,
    );
    let body = access_kernel::claim::body::Body::VerifierProfile(verifier_profile(ROBOT, true));
    admitted(
        &a.ingest(&body_claim(d, "verifier_profile", &body, NOW))
            .await
            .unwrap()
            .verdict,
    );
    // §13.7.2
    policy_denied(
        &a.exercise(&incoming(
            meta_request(d, 7, holding, offline(6)),
            ALICE_KEY,
        ))
        .await
        .unwrap(),
        policy::SLICE_SHARE,
    );
    let uri = access_authority_core::status::list_uri(API, &d, 0);
    let r = a
        .exercise(&incoming(
            meta_request(d, 8, holding, offline(2)),
            ALICE_KEY,
        ))
        .await
        .unwrap();
    allowed(&r);
    let (pap_sign1, excerpt) = r.signed_pap.clone().expect("signed PAP");
    let pap = peek(&pap_sign1).unwrap();
    let profile = LocalProfile::new(verifier_profile(ROBOT, true)).unwrap();
    assert_eq!(pap.validity.verifier_profile_ref, *profile.digest());
    assert_eq!(
        pap.validity.clock_source,
        access_verifier::caps::SECURE_CLOCK_CLASS
    );
    // OP-150 m.10 (a)
    assert_eq!(pap.validity.status, Some(entry(&uri, 2)));
    let row = a
        .family(d, family_of(&pap.projection_exercise))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (row.holder, row.client_id.as_str()),
        (pap.holder.instance.0, PEP)
    );
    assert_eq!(row.revoked_pos, None);
    let dead = a
        .family(d, family_of(&meta::exercise_id(&d, &[7; 16]).unwrap()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(dead.status, Some((uri.clone(), 1)));
    assert!(dead.revoked_pos.is_some());

    let mut device = OfflineVerifier::new(
        Identity {
            audience: ROBOT.to_owned(),
            instance: None,
            domain: d,
            profile,
            catalog: access_kernel::algebra::Catalog::default(),
            understood: BTreeSet::new(),
        },
        witnessed(signer_metadata(&socket, d).await, NOW),
        EmulatedClock::new(NOW),
        ClockGuard::new(DEFAULT_TOLERANCE_MS),
    );
    for (i, s) in pap.validity.offline_slice.iter().enumerate() {
        device
            .provision(
                pap.projection_exercise,
                s.budget_term,
                s.amount,
                EmulatedCounter::new(CounterId([u8::try_from(i).unwrap() + 1; 16])),
            )
            .unwrap();
    }
    let read = shop_request(d, 9, Mode::Commit, holding).intent;
    let nonce = [5; 16];
    let proof = presentation(&pap_sign1, &read, ROBOT, &nonce, ALICE_KEY, NOW);
    let schema = schema_of("read");
    let use_ = Use {
        pap: &pap_sign1,
        excerpt: &excerpt,
        presentation: &proof,
        intent: &read,
        nonce: &nonce,
        satisfied: &BTreeSet::new(),
        schema: Some(&schema),
        content_position: None,
    };
    let Verdict::Allow(first) = device.verify(&use_) else {
        panic!("{:?}", device.verify(&use_));
    };
    assert_eq!(first.seq, 0);
    assert_eq!(first.drawn.iter().map(|s| s.amount).sum::<u64>(), 1);
    assert!(matches!(device.verify(&use_), Verdict::Allow(_)));
    let Verdict::Deny(denied) = device.verify(&use_) else {
        panic!("slice");
    };
    assert_eq!(denied.code(), "pap-slice");

    // §9.12.2
    let cut = device.report(&pap.projection_exercise).unwrap().unwrap();
    assert_eq!(cut.report.contract, contract_digest(&pap));
    assert_eq!(cut.report.entries.len(), 3);
    admitted(
        &a.ingest(&report_claim(
            d,
            "offline_exercise_report",
            cut.value,
            cut.body.clone(),
            NOW,
        ))
        .await
        .unwrap()
        .verdict,
    );
    let rec = a.reconciliation(d, pap.projection_exercise).await.unwrap();
    assert_eq!(rec.len(), 1);
    assert!(rec[0].bound && rec[0].continuous && !rec[0].late, "{rec:?}");
    assert_eq!((rec[0].in_contract, rec[0].out_of_contract), (3, 0));
    // §9.12.2, 2546
    let intermittent = |slice| {
        projection(
            vec![action("shop", "read")],
            &[ROBOT],
            ProfileVariant::BoundedStaleness,
            (NOW, NOW + hour),
            Some(60_000),
            Some(slice),
        )
    };
    let over = a
        .exercise(&incoming(
            meta_request(d, 10, holding, intermittent(49)),
            ALICE_KEY,
        ))
        .await
        .unwrap();
    assert_eq!(
        blocked(&over).0,
        access_kernel::combinator::BlockerClass::BudgetExhausted
    );
    allowed(
        &a.exercise(&incoming(
            meta_request(d, 11, holding, intermittent(48)),
            ALICE_KEY,
        ))
        .await
        .unwrap(),
    );

    // §7.9.14, 2727
    device.clock().advance(2 * hour);
    let late = presentation(&pap_sign1, &read, ROBOT, &nonce, ALICE_KEY, NOW + 2 * hour);
    let Verdict::Deny(expired) = device.verify(&Use {
        presentation: &late,
        ..use_
    }) else {
        panic!("horizon");
    };
    assert_eq!(expired.code(), "pap-validity");
    let second = device.report(&pap.projection_exercise).unwrap().unwrap();
    assert_eq!(second.report.first_seq, 3);
    admitted(
        &a.ingest(&report_claim(
            d,
            "offline_exercise_report",
            second.value,
            second.body.clone(),
            NOW,
        ))
        .await
        .unwrap()
        .verdict,
    );
    // L2-RPT-2
    let gap = Report {
        verifier_profile: cut.report.verifier_profile,
        verifier_instance: None,
        exercise: pap.projection_exercise,
        contract: cut.report.contract,
        period: Window {
            from: NOW,
            until: NOW,
        },
        previous: Some(Digest([9; 32])),
        first_seq: 40,
        entries: Vec::new(),
        head: Digest([9; 32]),
        slice_unused: BTreeSet::new(),
        profile_version: 1,
    };
    let gap_value = access_kernel::claim::body::body_digest(
        access_kernel::claim::body::Class::OfflineExerciseReport,
        &gap.to_value(),
    )
    .unwrap();
    admitted(
        &a.ingest(&report_claim(
            d,
            "offline_exercise_report",
            gap_value,
            gap.to_bytes().unwrap(),
            NOW,
        ))
        .await
        .unwrap()
        .verdict,
    );
    let rec = a.reconciliation(d, pap.projection_exercise).await.unwrap();
    assert_eq!(rec.len(), 3);
    assert!(rec[1].bound && rec[1].continuous);
    assert_eq!((rec[1].in_contract, rec[1].out_of_contract), (0, 1));
    assert!(rec[2].bound && !rec[2].continuous);
    assert!(
        second
            .report
            .entries
            .iter()
            .all(|e| e.outcome == LocalOutcome::Deny)
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.7.2, §9.12, §9.12.1, PI-12, SEC13, 2506, 2517, 2533, 2537, 2539, 2547
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "every rule of the issuance policy against one domain"
)]
async fn the_issuance_policy_admits_only_what_the_ceilings_and_profile_allow() {
    use access_authority_core::app::projection::policy;
    use access_kernel::validity::{ProfileClass, ProfileVariant as V};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let a = moving_process(&db, d, Movable::at(NOW));
    onboard_process(&a, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard_process(&a, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = grant_alice(&a, d, 5, vec![action("shop", "read"), buy(), ship()], 50).await;
    let hour = 3_600_000;
    let read = || vec![action("shop", "read")];
    let nonce = std::cell::Cell::new(10_u8);
    let issue = async |payload: Payload| {
        let n = nonce.get();
        nonce.set(n + 1);
        a.exercise(&incoming(meta_request(d, n, holding, payload), ALICE_KEY))
            .await
            .unwrap()
    };
    let bounded = |horizon, delta| {
        projection(
            read(),
            &[ROBOT],
            V::BoundedStaleness,
            (NOW, NOW + horizon),
            delta,
            None,
        )
    };
    // §9.12.1
    policy_denied(
        &issue(bounded(hour, Some(60_000))).await,
        policy::VERIFIER_PROFILE,
    );
    let online = issue(projection(
        read(),
        &[ROBOT],
        V::OnlineStrict,
        (NOW, NOW + hour),
        None,
        None,
    ))
    .await;
    allowed(&online);
    for (audience, hardware) in [(ROBOT, true), ("plain.example", false)] {
        let body =
            access_kernel::claim::body::Body::VerifierProfile(verifier_profile(audience, hardware));
        admitted(
            &a.ingest(&body_claim(d, "verifier_profile", &body, NOW))
                .await
                .unwrap()
                .verdict,
        );
    }
    allowed(&issue(bounded(hour, Some(60_000))).await);
    // §13.7.2 CT1
    policy_denied(&issue(bounded(hour, None)).await, policy::PARAMETER);
    policy_denied(
        &issue(bounded(hour, Some(6 * 60_000))).await,
        policy::PARAMETER,
    );
    policy_denied(
        &issue(bounded(9 * hour, Some(60_000))).await,
        policy::HORIZON,
    );
    policy_denied(
        &issue(projection(
            read(),
            &[ROBOT],
            V::RevalidateOnReconnect,
            (NOW, NOW + hour),
            Some(60_000),
            None,
        ))
        .await,
        policy::PARAMETER,
    );
    let Payload::ProjectionIssue { bounds, .. } = bounded(hour, Some(60_000)) else {
        panic!("projection payload");
    };
    // OP-153 m.17 (h)
    let mismatched = Payload::ProjectionIssue {
        bounds,
        audience: BTreeSet::from([ROBOT.to_owned()]),
        class: ProfileClass::Offline,
        variant: V::BoundedStaleness,
        max_staleness_ms: Some(60_000),
        offline_slice: None,
    };
    assert!(matches!(
        a.exercise(&incoming(
            meta_request(d, 0xfe, holding, mismatched),
            ALICE_KEY
        ))
        .await,
        Err(access_authority_core::CoreError::Protocol("payload"))
    ));
    // §13.7.2
    policy_denied(
        &issue(projection(
            vec![ship()],
            &[ROBOT],
            V::BoundedStaleness,
            (NOW, NOW + hour),
            Some(60_000),
            None,
        ))
        .await,
        policy::CLASS_CAP,
    );
    policy_denied(
        &issue(projection(
            read(),
            &[ROBOT],
            V::CheckpointContinuation,
            (NOW, NOW + hour),
            None,
            None,
        ))
        .await,
        policy::PARAMETER,
    );
    let offline = |actions, audience: &[&str], slice| {
        projection(
            actions,
            audience,
            V::CheckpointedOffline,
            (NOW, NOW + hour),
            None,
            slice,
        )
    };
    policy_denied(
        &issue(offline(vec![buy()], &[ROBOT], None)).await,
        policy::SLICE_REQUIRED,
    );
    policy_denied(
        &issue(offline(read(), &["plain.example"], None)).await,
        policy::HARDWARE,
    );
    policy_denied(
        &issue(offline(read(), &[ROBOT, "plain.example"], Some(1))).await,
        policy::VERIFIER_PROFILE,
    );
    policy_denied(
        &issue(offline(read(), &[ROBOT, "nobody.example"], Some(1))).await,
        policy::VERIFIER_PROFILE,
    );
    allowed(&issue(offline(vec![buy()], &[ROBOT], Some(5))).await);
    policy_denied(
        &issue(offline(vec![buy()], &[ROBOT], Some(6))).await,
        policy::SLICE_SHARE,
    );
    let online = issue(projection(
        read(),
        &[ROBOT],
        V::OnlineStrict,
        (NOW, NOW + hour),
        None,
        None,
    ))
    .await;
    allowed(&online);
    let pap = access_kernel::pap::Pap::from_bytes(&online.pap.unwrap()).unwrap();
    assert_eq!(
        pap.validity.verifier_profile_ref,
        *access_verifier::profile::LocalProfile::new(verifier_profile(ROBOT, true))
            .unwrap()
            .digest()
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.7.4, SEC14, 2591, 2556
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "three limits against one domain and clock"
)]
async fn projection_issuance_limits_are_decisions() {
    use access_authority_core::app::projection::policy;
    use access_kernel::combinator::Remediation;
    use access_kernel::report::Report;
    use access_kernel::validity::ProfileVariant as V;
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let clock = Movable::at(NOW);
    let a = moving_process(&db, d, clock.clone());
    onboard_process(&a, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard_process(&a, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = grant_alice(&a, d, 5, vec![action("shop", "read")], 50).await;
    let hour = 3_600_000;
    for audience in [ROBOT, "lone.example"] {
        let body =
            access_kernel::claim::body::Body::VerifierProfile(verifier_profile(audience, true));
        admitted(
            &a.ingest(&body_claim(d, "verifier_profile", &body, NOW))
                .await
                .unwrap()
                .verdict,
        );
    }
    let read = || vec![action("shop", "read")];
    let offline = |audience: &str, from: u64| {
        projection(
            read(),
            &[audience],
            V::CheckpointedOffline,
            (from, from + hour),
            None,
            None,
        )
    };
    let at = async |nonce: u8, payload: Payload, now: u64| {
        let mut request = meta_request(d, nonce, holding, payload);
        request.intent.validity = Window {
            from: now,
            until: now + hour,
        };
        a.exercise(&incoming_at(request, ALICE_KEY, now))
            .await
            .unwrap()
    };
    let lone = at(10, offline("lone.example", NOW), NOW).await;
    allowed(&lone);
    allowed(&at(11, offline(ROBOT, NOW), NOW).await);
    allowed(&at(12, offline(ROBOT, NOW), NOW).await);
    policy_denied(
        &at(13, offline(ROBOT, NOW), NOW).await,
        policy::OPEN_OFFLINE,
    );
    let online = |from: u64| {
        projection(
            read(),
            &[ROBOT],
            V::OnlineStrict,
            (from, from + hour),
            None,
            None,
        )
    };
    for nonce in 14..41 {
        allowed(&at(nonce, online(NOW), NOW).await);
    }
    let over = at(41, online(NOW), NOW).await;
    policy_denied(&over, policy::RATE);
    assert_eq!(
        over.decision.blockers[0].remediation,
        Remediation::WaitUntil(NOW + hour)
    );
    let later = NOW + hour + 1;
    clock.set(later);
    allowed(&at(42, online(later), later).await);
    // SEC14
    let overdue = NOW + hour + 24 * hour + 1;
    clock.set(overdue);
    policy_denied(
        &at(
            43,
            projection(
                read(),
                &["lone.example"],
                V::OnlineStrict,
                (overdue, overdue + hour),
                None,
                None,
            ),
            overdue,
        )
        .await,
        policy::UNREPORTED,
    );
    allowed(
        &at(
            44,
            projection(
                read(),
                &["fresh.example"],
                V::OnlineStrict,
                (overdue, overdue + hour),
                None,
                None,
            ),
            overdue,
        )
        .await,
    );
    let pap = access_kernel::pap::Pap::from_bytes(&lone.pap.unwrap()).unwrap();
    let contract = contract_digest(&pap);
    let report = Report {
        verifier_profile: *access_verifier::profile::LocalProfile::new(verifier_profile(
            "lone.example",
            true,
        ))
        .unwrap()
        .digest(),
        verifier_instance: None,
        exercise: pap.projection_exercise,
        contract,
        period: Window {
            from: NOW,
            until: NOW + hour,
        },
        previous: None,
        first_seq: 0,
        entries: Vec::new(),
        head: access_kernel::report::seed(&pap.projection_exercise, &contract).unwrap(),
        slice_unused: BTreeSet::new(),
        profile_version: 1,
    };
    let value = access_kernel::claim::body::body_digest(
        access_kernel::claim::body::Class::OfflineExerciseReport,
        &report.to_value(),
    )
    .unwrap();
    admitted(
        &a.ingest(&report_claim(
            d,
            "offline_exercise_report",
            value,
            report.to_bytes().unwrap(),
            overdue,
        ))
        .await
        .unwrap()
        .verdict,
    );
    let rec = a.reconciliation(d, pap.projection_exercise).await.unwrap();
    assert_eq!(rec.len(), 1);
    assert!(rec[0].bound && rec[0].continuous && rec[0].late, "{rec:?}");
    allowed(
        &at(
            45,
            projection(
                read(),
                &["lone.example"],
                V::OnlineStrict,
                (overdue, overdue + hour),
                None,
                None,
            ),
            overdue,
        )
        .await,
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// M11 (OP-151 m.2)

/// The rows of the operational audit stream of event `event`.
async fn operational(db: &TestDb, event: &str) -> Vec<access_store::operational::OperationalRow> {
    access_store::operational::operational_rows(&db.checkpointer, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.event_type == event)
        .collect()
}

/// The export intent of `nonce` from position 0 with `disclosure`.
fn export_request(d: Digest, nonce: u8, basis: ExerciseBasis, disclosure: &str) -> Request {
    let mut intent = intent(
        action("access", "audit_export"),
        ("access.audit", "export"),
        None,
    );
    intent.params = BTreeMap::from([
        (
            "disclosure".to_owned(),
            access_kernel::intent::ParamValue::Enum(disclosure.to_owned()),
        ),
        (
            "from".to_owned(),
            access_kernel::intent::ParamValue::Count(0),
        ),
    ]);
    Request {
        domain: d,
        mode: Mode::Commit,
        nonce: vec![nonce; 16],
        intent,
        payload: None,
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

type Led = Domains<Listed, Bound, Counter, Fixed>;

/// A domain led by one process, with ROOT, ALICE and BOB onboarded, ALICE holding a `shop`
/// Grant and having used it once; returns the holding and the position of that decision.
async fn audited_domain(db: &TestDb) -> (Led, Digest, ExerciseBasis, u64) {
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let a = process(db, "a", vec![d]);
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (party, seed, (first, second)) in [
        (ROOT, ROOT_KEY, (1, 2)),
        (ALICE, ALICE_KEY, (3, 4)),
        (BOB, BOB_KEY, (7, 8)),
    ] {
        for (nonce, payload) in [
            (
                first,
                Payload::PartyRegister {
                    party,
                    root: Root::Sole(party),
                    actor_kind: ActorKind::Human,
                },
            ),
            (
                second,
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
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: authority(vec![action("shop", "read")], selector("shop")),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let issued = a
        .exercise(&incoming(
            meta_request(d, 5, ExerciseBasis::Anchor(shop), issue),
            ROOT_KEY,
        ))
        .await
        .unwrap();
    allowed(&issued);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    });
    let used = a
        .exercise(&incoming(
            shop_request(d, 20, Mode::Commit, holding),
            ALICE_KEY,
        ))
        .await
        .unwrap();
    allowed(&used);
    (a, d, holding, used.record.unwrap())
}

// U53, OP-44, PI-4, §17.6.11
#[tokio::test]
async fn u53_op_44_every_audit_read_is_one_row() {
    let db = fresh().await.unwrap();
    let (a, d, holding, record) = audited_domain(&db).await;
    let n = 3;
    for _ in 0..n {
        let inc = incoming(shop_request(d, 20, Mode::Commit, holding), ROOT_KEY);
        let r = a
            .explain_recorded(&inc, record, Scope::Audit)
            .await
            .unwrap();
        allowed(&r);
    }
    let inc = incoming(shop_request(d, 20, Mode::Commit, holding), ROOT_KEY);
    a.explain_recorded(&inc, record, Scope::Viewer)
        .await
        .unwrap();
    let reads = operational(&db, "audit.read").await;
    assert_eq!(reads.len(), n);
    assert!(reads.iter().all(|r| r.target == format!("record:{record}")
        && r.tenant == Some(TENANT)
        && r.domain == Some(d.0)
        && r.occurred_at_ms == NOW));
    // OP-41
    assert_eq!(
        reads[0].correlation,
        access_kernel::json::b64url_encode(&[20; 16])
    );
}

// §9.6, §9.6.1, §17.1.1, OP-148
#[tokio::test]
async fn audit_answers_expand_basis_ref_and_state_basis() {
    let db = fresh().await.unwrap();
    let (a, d, holding, record) = audited_domain(&db).await;
    let inc = incoming(shop_request(d, 20, Mode::Commit, holding), ROOT_KEY);
    let audit = a
        .explain_recorded(&inc, record, Scope::Audit)
        .await
        .unwrap();
    let detail = audit.explained.as_ref().unwrap().audit.as_ref().unwrap();
    assert_eq!(detail.basis.domain, d);
    assert_eq!(detail.basis.position_q_minus_1, record - 1);
    let versions = Value::Map(vec![
        (Value::text("core"), Value::Unsigned(1)),
        (Value::text("meta_schema"), Value::Unsigned(1)),
    ]);
    assert_eq!(
        detail.basis.version_vector_digest,
        suiss_crypto::digest::context_digest(
            "access/versions/v1",
            &dcbor::encode(&versions, Limits::CEILING).unwrap()
        )
    );
    assert_ne!(detail.reads.len(), 0);
    assert_eq!(detail.evaluated_at, NOW);
    let lineage = &audit.explained.as_ref().unwrap().lineage;
    assert_eq!(lineage.len(), 1);
    assert_eq!(
        lineage[0].holder,
        Some(access_authority_core::app::audit::Named::Clear(ALICE))
    );
    let viewer = a
        .explain_recorded(&inc, record, Scope::Viewer)
        .await
        .unwrap();
    assert!(viewer.explained.as_ref().unwrap().audit.is_none());
    let alice = incoming(shop_request(d, 20, Mode::Commit, holding), ALICE_KEY);
    let own = a
        .explain_recorded(&alice, record, Scope::Requester)
        .await
        .unwrap();
    assert!(own.explained.is_none());
}

// AP-14, INV-27, PI-6, PI-4, U53
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one scenario from the first export to the refused one"
)]
#[allow(
    clippy::many_single_char_names,
    reason = "the package, its root and its parts"
)]
async fn ap_14_an_export_is_an_audited_exercise_that_verifies_itself() {
    use access_authority_core::domain::export::{Coverage, Package, verify};
    let db = fresh().await.unwrap();
    let (a, d, _, _) = audited_domain(&db).await;
    let meta_anchor = meta::meta_anchor(&d);
    // OP-141
    let audit_basis = ExerciseBasis::Anchor(meta_anchor);
    let early = incoming(export_request(d, 31, audit_basis, "full"), ROOT_KEY);
    assert!(matches!(
        a.export(&early).await,
        Err(CoreError::Protocol("export-exercise"))
    ));
    let committed = a.exercise(&early).await.unwrap();
    allowed(&committed);
    let exported = a.export(&early).await.unwrap();
    let p = &exported.package;
    assert_eq!(p.export_exercise, committed.exercise.unwrap());
    assert_eq!(p.replay_coverage, Coverage::Full);
    assert_eq!(p.range.0, 0);
    let v = verify(p).unwrap();
    assert!(v.folded);
    let bytes = p.to_bytes().unwrap();
    assert_eq!(&Package::from_bytes(&bytes).unwrap(), p);
    a.export(&early).await.unwrap();
    let rows = operational(&db, "audit.export").await;
    assert_eq!(rows.len(), 2);
    assert!(rows[0].reason == "full" && rows[0].target.starts_with("records:0-"));
    let redacted = incoming(export_request(d, 32, audit_basis, "redacted"), ROOT_KEY);
    allowed(&a.exercise(&redacted).await.unwrap());
    let r = a.export(&redacted).await.unwrap().package;
    assert_eq!(r.replay_coverage, Coverage::Digest);
    assert!(
        r.records
            .iter()
            .all(|rec| rec.opened.keys().all(|k| k == "versions"))
    );
    assert_eq!(verify(&r).unwrap().size, r.range.1 + 1);
    let bob = incoming(export_request(d, 33, audit_basis, "full"), BOB_KEY);
    assert_ne!(
        a.exercise(&bob).await.map(|r| r.decision.outcome).ok(),
        Some(Outcome::Allow)
    );
    assert!(matches!(
        a.export(&bob).await,
        Err(CoreError::Protocol("export-exercise"))
    ));
    assert_eq!(operational(&db, "audit.export").await.len(), 3);
    // OP-151 m.19 (d)
    let mut dotted = export_request(d, 34, audit_basis, "full");
    dotted.intent.action = action("access", "audit.export");
    assert!(matches!(
        a.exercise(&incoming(dotted, ROOT_KEY)).await,
        Err(CoreError::Protocol("action"))
    ));
}

// OP-39, OP-44 OP-142
#[tokio::test]
async fn protocol_rejections_go_to_the_operational_stream() {
    let db = fresh().await.unwrap();
    let (a, d, holding, _) = audited_domain(&db).await;
    let id = DomainId::from_bytes(d.0);
    let head = access_store::authority::read_head(&db.sequencer, &id)
        .await
        .unwrap()
        .pos;
    let mut forged = incoming(shop_request(d, 40, Mode::Commit, holding), ALICE_KEY);
    forged.ais = incoming(shop_request(d, 41, Mode::Commit, holding), ALICE_KEY).ais;
    assert!(matches!(a.exercise(&forged).await, Err(CoreError::Ais(_))));
    let mut other = shop_request(d, 20, Mode::Commit, holding);
    other.intent.resources[0].path = vec!["item-2".to_owned()];
    assert!(a.exercise(&incoming(other, ALICE_KEY)).await.is_err());
    let rows = operational(&db, "authority.protocol.rejected").await;
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(
        rows.iter()
            .all(|r| r.actor == PEP && r.target == "evaluation")
    );
    assert!(rows.iter().all(|r| !r.reason.is_empty()));
    assert_eq!(
        access_store::authority::read_head(&db.sequencer, &id)
            .await
            .unwrap()
            .pos,
        head
    );
}

/// A subscriber that counts the explain trace events it sees.
#[derive(Default)]
struct Traces(std::sync::atomic::AtomicUsize);

impl tracing::Subscriber for Traces {
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, e: &tracing::Event<'_>) {
        if e.metadata().target() == "access::explain" {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// The domain's record envelopes, in order.
async fn records(db: &TestDb, d: Digest) -> Vec<Vec<u8>> {
    let id = DomainId::from_bytes(d.0);
    let head = access_store::authority::read_head(&db.sequencer, &id)
        .await
        .unwrap()
        .pos;
    access_store::authority::read_log(&db.sequencer, &id, 0, head)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.envelope)
        .collect()
}

// §9.7.1, §9.16.3, C30
#[tokio::test]
async fn traces_never_reach_the_record() {
    let traced_db = fresh().await.unwrap();
    let counted = std::sync::Arc::new(Traces::default());
    let traced = {
        let _on = tracing::subscriber::set_default(counted.clone());
        let (a, d, holding, record) = audited_domain(&traced_db).await;
        for scope in [Scope::Requester, Scope::Viewer, Scope::Audit] {
            let seed = if scope == Scope::Requester {
                ALICE_KEY
            } else {
                ROOT_KEY
            };
            let inc = incoming(shop_request(d, 20, Mode::Commit, holding), seed);
            a.explain_recorded(&inc, record, scope).await.unwrap();
        }
        let after = a
            .exercise(&incoming(
                shop_request(d, 21, Mode::Commit, holding),
                ALICE_KEY,
            ))
            .await
            .unwrap();
        allowed(&after);
        records(&traced_db, d).await
    };
    assert!(counted.0.load(std::sync::atomic::Ordering::Relaxed) >= 3);
    let quiet_db = fresh().await.unwrap();
    let (a, d, holding, _) = audited_domain(&quiet_db).await;
    allowed(
        &a.exercise(&incoming(
            shop_request(d, 21, Mode::Commit, holding),
            ALICE_KEY,
        ))
        .await
        .unwrap(),
    );
    assert_eq!(traced, records(&quiet_db, d).await);
}

/// The outcome of `req` signed by `seed`, `None` when it is rejected before a decision.
async fn outcome_of(a: &Led, req: Request, seed: u8) -> Option<Outcome> {
    a.exercise(&incoming(req, seed))
        .await
        .ok()
        .map(|r| r.decision.outcome)
}

/// The self-anchor the `party_register` with `nonce` opened.
fn self_anchor_of(d: Digest, nonce: u8) -> ExerciseBasis {
    ExerciseBasis::Anchor(meta::object_id(
        &meta::exercise_id(&d, &[nonce; 16]).unwrap(),
        kind::ANCHOR,
        0,
    ))
}

fn hex(id: Id) -> String {
    use std::fmt::Write as _;
    id.0.iter().fold(String::new(), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

// E6, §7.9.2.5
#[tokio::test]
async fn e6_a_self_anchor_covers_only_its_party() {
    let db = fresh().await.unwrap();
    let (a, d, _, _) = audited_domain(&db).await;
    let alice_anchor = self_anchor_of(d, 3);
    assert_ne!(
        outcome_of(
            &a,
            shop_request(d, 40, Mode::Commit, alice_anchor),
            ALICE_KEY
        )
        .await,
        Some(Outcome::Allow)
    );
    assert_ne!(
        outcome_of(
            &a,
            export_request(d, 41, alice_anchor, "redacted"),
            ALICE_KEY
        )
        .await,
        Some(Outcome::Allow)
    );
    let mut bobs = shop_request(d, 42, Mode::Commit, alice_anchor);
    bobs.intent.resources[0] = ResourceRef {
        namespace: "access.party".to_owned(),
        path: vec![hex(BOB)],
        incarnation: 0,
    };
    assert_ne!(outcome_of(&a, bobs, ALICE_KEY).await, Some(Outcome::Allow));
    let mut own = shop_request(d, 43, Mode::Commit, alice_anchor);
    own.intent.resources[0] = ResourceRef {
        namespace: "access.party".to_owned(),
        path: vec![hex(ALICE), "profile".to_owned()],
        incarnation: 0,
    };
    assert_eq!(outcome_of(&a, own, ALICE_KEY).await, Some(Outcome::Allow));
}

// E6, §7.9.2.5
#[tokio::test]
async fn e6_resource_anchor_stays_scoped_domain_anchor_covers_the_domain() {
    // EI-14
    let db = fresh().await.unwrap();
    let (a, d, _, _) = audited_domain(&db).await;
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    assert_eq!(
        outcome_of(&a, shop_request(d, 40, Mode::Commit, shop), ROOT_KEY).await,
        Some(Outcome::Allow)
    );
    let mut other = shop_request(d, 41, Mode::Commit, shop);
    other.intent.resources[0].namespace = "ledger".to_owned();
    assert_ne!(outcome_of(&a, other, ROOT_KEY).await, Some(Outcome::Allow));
    let domain = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    assert_eq!(
        outcome_of(&a, shop_request(d, 42, Mode::Commit, domain), ROOT_KEY).await,
        Some(Outcome::Allow)
    );
}

/// Issues ALICE a Grant naming `access:audit_export` on `resource` from `basis`, signed by
/// `seed`, with `edit` applied to its authority; returns its holding.
async fn audit_grant_for_alice(
    a: &Led,
    d: Digest,
    nonce: u8,
    (basis, seed): (Id, u8),
    resource: ResourceSelector,
    edit: impl FnOnce(&mut CanonicalAuthority),
) -> ExerciseBasis {
    let mut auth = authority(vec![action("access", "audit_export")], resource);
    edit(&mut auth);
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(basis),
        holder: SubjectSelector::Party(ALICE),
        authority: auth,
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let issued = a
        .exercise(&incoming(
            meta_request(d, nonce, ExerciseBasis::Anchor(basis), issue),
            seed,
        ))
        .await
        .unwrap();
    allowed(&issued);
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    })
}

/// Whether ALICE may read `record` at audit scope.
async fn alice_audits(a: &Led, d: Digest, holding: ExerciseBasis, record: u64) -> bool {
    assert!(a.derive().await.is_empty());
    let inc = incoming(shop_request(d, 20, Mode::Commit, holding), ALICE_KEY);
    match a.explain_recorded(&inc, record, Scope::Audit).await {
        Ok(_) => true,
        Err(CoreError::Protocol("explain-scope")) => false,
        Err(e) => panic!("{e:?}"),
    }
}

fn audit_selector() -> ResourceSelector {
    selector("access.audit")
}

// OP-141 m.38 (d), m.39 (b)
#[tokio::test]
async fn op_141_m38_d_a_self_issued_audit_grant_audits_nothing() {
    let db = fresh().await.unwrap();
    let (a, d, holding, record) = audited_domain(&db).await;
    let ExerciseBasis::Anchor(own) = self_anchor_of(d, 3) else {
        panic!("a self-anchor basis")
    };
    let own_subtree = ResourceSelector::Structural(Structural {
        namespace: "access.party".to_owned(),
        prefix: vec![hex(ALICE)],
        kind: None,
        attrs: BTreeMap::new(),
    });
    audit_grant_for_alice(&a, d, 50, (own, ALICE_KEY), own_subtree, |_| {}).await;
    assert!(!alice_audits(&a, d, holding, record).await);
}

// OP-141 m.38 (d)
#[tokio::test]
async fn op_141_m38_d_an_audit_grant_must_hold_now() {
    let db = fresh().await.unwrap();
    let (a, d, holding, record) = audited_domain(&db).await;
    let meta_anchor = meta::meta_anchor(&d);
    audit_grant_for_alice(&a, d, 50, (meta_anchor, ROOT_KEY), audit_selector(), |g| {
        g.constraints.validity = Window {
            from: NOW + 1_000,
            until: 1_000_000,
        };
    })
    .await;
    assert!(!alice_audits(&a, d, holding, record).await);
    audit_grant_for_alice(&a, d, 51, (meta_anchor, ROOT_KEY), audit_selector(), |g| {
        g.requirements = BTreeSet::from([term(ProofKind::Claim, "kyc", ProofBinding::None)]);
    })
    .await;
    assert!(!alice_audits(&a, d, holding, record).await);
    audit_grant_for_alice(&a, d, 52, (meta_anchor, ROOT_KEY), audit_selector(), |_| {}).await;
    assert!(alice_audits(&a, d, holding, record).await);
}

// OP-141 m.38 (d), m.39 (b), AP-14
#[tokio::test]
async fn op_141_m38_d_a_meta_anchor_audit_grant_exports() {
    let db = fresh().await.unwrap();
    let (a, d, _, _) = audited_domain(&db).await;
    let meta_anchor = meta::meta_anchor(&d);
    let grant =
        audit_grant_for_alice(&a, d, 50, (meta_anchor, ROOT_KEY), audit_selector(), |_| {}).await;
    let inc = incoming(export_request(d, 51, grant, "full"), ALICE_KEY);
    allowed(&a.exercise(&inc).await.unwrap());
    assert!(a.derive().await.is_empty());
    let exported = a.export(&inc).await.unwrap();
    assert_eq!(
        exported.package.replay_coverage,
        access_authority_core::domain::export::Coverage::Full
    );
}

// OP-141 m.39 (a), §9.13.7
#[tokio::test]
async fn op_141_m39_a_an_export_carries_only_its_typed_parameters() {
    use access_kernel::intent::ParamValue;
    let db = fresh().await.unwrap();
    let (a, d, _, _) = audited_domain(&db).await;
    let audit_basis = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    for (nonce, (name, value)) in [
        (
            60,
            (
                "amount",
                ParamValue::Amount {
                    value: i64::MAX,
                    unit: "eur".to_owned(),
                },
            ),
        ),
        (61, ("until", ParamValue::Count(1))),
        (62, ("from", ParamValue::Enum("0".to_owned()))),
        (63, ("disclosure", ParamValue::Count(1))),
    ] {
        let mut req = export_request(d, nonce, audit_basis, "redacted");
        req.intent.params.insert(name.to_owned(), value);
        assert!(matches!(
            a.exercise(&incoming(req, ROOT_KEY)).await,
            Err(CoreError::Protocol("export-params"))
        ));
    }
    let mut ranged = export_request(d, 64, audit_basis, "redacted");
    ranged
        .intent
        .params
        .insert("to".to_owned(), ParamValue::Count(1));
    allowed(&a.exercise(&incoming(ranged, ROOT_KEY)).await.unwrap());
}

/// A developer-surface search of `kind`, on the meta-anchor.
fn report_request(d: Digest, nonce: u8, kind: &str) -> Request {
    Request {
        domain: d,
        mode: Mode::Check,
        nonce: vec![nonce; 16],
        intent: intent(action("access", "read"), ("access.search", kind), None),
        payload: None,
        basis: ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

// U53, OP-44, §8.17.10
#[tokio::test]
async fn u53_op_44_every_report_served_is_one_audit_read() {
    use access_authority_core::app::impact::{Compromised, Revoked};
    use access_authority_core::query::Query;
    let db = fresh().await.unwrap();
    let (a, d, holding, _) = audited_domain(&db).await;
    assert!(a.derive().await.is_empty());
    let ExerciseBasis::Holding(h) = holding else {
        panic!("a holding basis")
    };
    let reports = [
        (
            "revocation-impact",
            Query::RevocationImpact {
                revoked: Revoked::Grant(h.grant),
                at: None,
            },
        ),
        (
            "compromise-impact",
            Query::CompromiseImpact {
                compromised: Compromised::Issuer(ALICE),
                window: Window {
                    from: 0,
                    until: NOW,
                },
            },
        ),
        (
            "schema-publications",
            Query::SchemaPublications {
                namespace: "shop".to_owned(),
            },
        ),
    ];
    let mut nonce = 70;
    for _ in 0..2 {
        for (kind, query) in &reports {
            nonce += 1;
            let inc = incoming(report_request(d, nonce, kind), ROOT_KEY);
            let (hits, _) = a.search(&inc, query, None).await.unwrap();
            assert_eq!(hits.len(), usize::from(*kind != "schema-publications"));
        }
    }
    let inc = incoming(report_request(d, 90, "revocation-impact"), ALICE_KEY);
    let (hits, _) = a.search(&inc, &reports[0].1, None).await.unwrap();
    assert_eq!(hits.len(), 0);
    let reads = operational(&db, "audit.read").await;
    assert_eq!(reads.len(), 2 * reports.len());
    assert!(
        reads.iter().all(|r| r.reason == "report"
            && r.tenant == Some(TENANT)
            && r.actor.starts_with("inst:"))
    );
    assert_eq!(
        reads
            .iter()
            .filter(|r| r.target == "report:revocation-impact")
            .count(),
        2
    );
}

// §9.10, Ek B 2517
#[tokio::test]
async fn s9_10_a_requirement_the_verifier_cannot_check_stays_online() {
    use access_kernel::combinator::BlockerClass;
    use access_kernel::validity::ProfileVariant;
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, genesis_offline(), 1_000)
        .await
        .unwrap();
    let a = moving_process(&db, d, Movable::at(NOW));
    onboard_process(&a, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard_process(&a, d, ALICE, ALICE_KEY, (3, 4)).await;
    let holding = grant_alice(&a, d, 5, vec![action("shop", "read")], 5).await;
    let with = |terms: Vec<RequirementTerm>| {
        let mut p = projection(
            vec![action("shop", "read")],
            &[ROBOT],
            ProfileVariant::OnlineStrict,
            (NOW, NOW + 60_000),
            None,
            None,
        );
        if let Payload::ProjectionIssue { bounds, .. } = &mut p {
            bounds.requirements = terms.into_iter().collect();
        }
        p
    };
    let remote = [
        term(
            ProofKind::Contribution,
            "approve",
            ProofBinding::IntentDigest,
        ),
        term(ProofKind::ForeignAuthority, "partner", ProofBinding::None),
        term(ProofKind::Claim, "kyc", ProofBinding::IntentDigest),
        term(
            ProofKind::Authentication,
            "presence",
            ProofBinding::Resource,
        ),
    ];
    for (nonce, t) in (10..).zip(remote) {
        let denied = a
            .exercise(&incoming(
                meta_request(d, nonce, holding, with(vec![t])),
                ALICE_KEY,
            ))
            .await
            .unwrap();
        assert_eq!(denied.decision.outcome, Outcome::Deny);
        assert!(
            denied
                .decision
                .blockers
                .iter()
                .any(|b| b.class == BlockerClass::Restricted
                    && b.subcode.as_deref() == Some("policy:local-requirement"))
        );
        assert!(denied.pap.is_none());
    }
    let local = vec![
        term(
            ProofKind::Authentication,
            "presence",
            ProofBinding::ActorInstance,
        ),
        term(ProofKind::Claim, "device_posture", ProofBinding::None),
    ];
    let projected = a
        .exercise(&incoming(
            meta_request(d, 20, holding, with(local.clone())),
            ALICE_KEY,
        ))
        .await
        .unwrap();
    allowed(&projected);
    let pap = access_kernel::pap::Pap::from_bytes(&projected.pap.unwrap()).unwrap();
    assert_eq!(pap.local_requirements, local.into_iter().collect());
}

/// Genesis declaring causal-bound allowances, or not.
fn causal_genesis(declared: bool) -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let mut policy = vec![(Value::text("ct3_delay_s"), Value::Unsigned(0))];
    if declared {
        policy.push((Value::text(meta::CAUSAL_BINDING), Value::Bool(true)));
    }
    g.insert(
        "policy".to_owned(),
        Opened {
            value: Value::Map(policy),
            salt: [9; 32],
        },
    );
    g
}

/// ALICE's holding of `shop:read` on the shop Anchor, issued by the root.
async fn alice_reads(core: &mut Core, d: Digest) -> ExerciseBasis {
    onboard(core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: authority(vec![action("shop", "read")], selector("shop")),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let issued = send(
        core,
        meta_request(d, 5, ExerciseBasis::Anchor(shop), issue),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    })
}

fn downstream(d: Digest, nonce: u8, mode: Mode, basis: ExerciseBasis, up: u8) -> Request {
    let mut r = shop_request(d, nonce, mode, basis);
    r.intent.context.upstream_exercise = Some(Digest([up; 32]));
    r
}

#[tokio::test]
async fn a_declared_causal_bound_allowance_backs_one_downstream_exercise() {
    // OP-152 m.7 (d), §7.9.7.4, E17, EI-17, U8
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, causal_genesis(true)).await;
    let holding = alice_reads(&mut core, d).await;
    let check = send(
        &mut core,
        downstream(d, 6, Mode::Check, holding, 0x70),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&check);
    assert_eq!(check.causal, Some(true));
    let first = send(
        &mut core,
        downstream(d, 7, Mode::Commit, holding, 0x70),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&first);
    assert_eq!(first.causal, Some(true));
    let second = send(
        &mut core,
        downstream(d, 8, Mode::Commit, holding, 0x70),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_eq!(second.decision.outcome, Outcome::Deny, "{second:?}");
    assert_eq!(
        second.decision.blockers[0].subcode.as_deref(),
        Some("policy:causal-bound")
    );
    assert!(second.record.is_some());
    let other = send(
        &mut core,
        downstream(d, 9, Mode::Commit, holding, 0x71),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&other);
    let plain = send(
        &mut core,
        shop_request(d, 10, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&plain);
    assert_eq!(plain.causal, None);
    fold_check(&db.sequencer, d).await.unwrap();
}

#[tokio::test]
async fn an_undeclared_causal_ref_is_audit_only() {
    // OP-152 m.7 (d), §9.9.2, E17
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, causal_genesis(false)).await;
    let holding = alice_reads(&mut core, d).await;
    for nonce in [6, 7] {
        let r = send(
            &mut core,
            downstream(d, nonce, Mode::Commit, holding, 0x70),
            ALICE_KEY,
        )
        .await
        .unwrap();
        allowed(&r);
        assert_eq!(r.causal, Some(false));
    }
}

/// ROOT's Instance, opened by `onboard(.., (1, 2))`.
fn root_instance(d: Digest) -> Id {
    meta::object_id(&meta::exercise_id(&d, &[2; 16]).unwrap(), kind::INSTANCE, 0)
}

/// ROOT's statement of its own authority act `req` (§9.14.1 B step 2).
fn authority_act(d: Digest, req: &Request, render: Digest, act: Act) -> ApprovalAct {
    ApprovalAct {
        evidence: None,
        surface_class: None,
        act,
        instance: root_instance(d),
        party: ROOT,
        capacity: Capacity::Own,
        target: access_kernel::intent::intent_digest(&req.intent).unwrap(),
        domain: d,
        nonce: req.nonce.clone(),
        work_gate: None,
        surface_profile: "suiss-approval-surface".to_owned(),
        surface_version: 1,
        render_digest: render,
        material_fields: ["action".to_owned(), "resource".to_owned()]
            .into_iter()
            .collect(),
        issued_at: NOW - 1_000,
        expires_at: NOW + 60_000,
    }
}

/// The realm issuer's `authentication` Claim about ROOT for the assertion over `statement`.
fn act_claim(d: Digest, statement: Digest) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject: ROOT,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(vec![0xab; 32])),
            issued_at: NOW - 5_000,
            validity: Window {
                from: NOW - 5_000,
                until: NOW + 3_600_000,
            },
            assurance: PASSKEY_UV
                .iter()
                .map(|(k, v)| ((*k).to_owned(), *v))
                .collect(),
            bound_intent: Some(statement),
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

// OP-152 m.7 (d), §9.14.1 B, §9.14.3, AP-6, P29
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one authority act through each way its statement can fail"
)]
async fn an_authority_act_meets_the_actors_own_intent_bound_authentication() {
    // SI-5, INV-20
    let db = fresh().await.unwrap();
    let authentication = term(
        ProofKind::Claim,
        "authentication",
        ProofBinding::IntentDigest,
    );
    let (mut core, d) = setup_with(&db, gated(&[authentication])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(BOB),
        authority: authority(vec![action("shop", "read")], selector("shop")),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    });
    let req = meta_request(d, 9, ExerciseBasis::Anchor(shop), issue);
    let digest = access_kernel::intent::intent_digest(&req.intent).unwrap();

    let early = authority_act(d, &req, Digest([0; 32]), Act::AuthorityAct);
    let h = access_kernel::aas::digest(&early).unwrap();
    assert_eq!(
        protocol(
            send(
                &mut core,
                with_proofs(
                    req.clone(),
                    vec![
                        ProofRef::Aas(early.to_bytes().unwrap()),
                        ProofRef::Claim(act_claim(d, h)),
                    ],
                ),
                ROOT_KEY,
            )
            .await
        ),
        "aas-target"
    );

    let asked = send(&mut core, req.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction, "{asked:?}");
    let render = Digest(
        access_store::authority::find_opening(&db.app, &DomainId::from_bytes(d.0), &digest.0)
            .await
            .unwrap()
            .unwrap()
            .render_digest,
    );

    let act = authority_act(d, &req, render, Act::AuthorityAct);
    let h = access_kernel::aas::digest(&act).unwrap();
    let claim_only = send(
        &mut core,
        with_proofs(req.clone(), vec![ProofRef::Claim(act_claim(d, h))]),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(
        claim_only.decision.outcome,
        Outcome::RequireAction,
        "an H(AAS)-bound Claim alone is bound to another digest"
    );

    let contribution = authority_act(d, &req, render, Act::Contribution("approve".to_owned()));
    let hc = access_kernel::aas::digest(&contribution).unwrap();
    assert_eq!(
        protocol(
            send(
                &mut core,
                with_proofs(
                    req.clone(),
                    vec![
                        ProofRef::Aas(contribution.to_bytes().unwrap()),
                        ProofRef::Claim(act_claim(d, hc)),
                    ],
                ),
                ROOT_KEY,
            )
            .await
        ),
        "aas-act"
    );
    let other = authority_act(d, &req, render, Act::AuthorityAct);
    let other = ApprovalAct {
        issued_at: NOW - 2_000,
        ..other
    };
    assert_eq!(
        unbound(
            send(
                &mut core,
                with_proofs(
                    req.clone(),
                    vec![
                        ProofRef::Aas(act.to_bytes().unwrap()),
                        ProofRef::Claim(act_claim(d, access_kernel::aas::digest(&other).unwrap())),
                    ],
                ),
                ROOT_KEY,
            )
            .await
        ),
        vec![BindingFacet::BoundIntent]
    );
    let on_behalf = ApprovalAct {
        capacity: Capacity::For(ALICE),
        ..authority_act(d, &req, render, Act::AuthorityAct)
    };
    let hb = access_kernel::aas::digest(&on_behalf).unwrap();
    assert_eq!(
        protocol(
            send(
                &mut core,
                with_proofs(
                    req.clone(),
                    vec![
                        ProofRef::Aas(on_behalf.to_bytes().unwrap()),
                        ProofRef::Claim(act_claim(d, hb)),
                    ],
                ),
                ROOT_KEY,
            )
            .await
        ),
        "aas-capacity"
    );

    let done = send(
        &mut core,
        with_proofs(
            req,
            vec![
                ProofRef::Aas(act.to_bytes().unwrap()),
                ProofRef::Claim(act_claim(d, h)),
            ],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);
    fold_check(&db.sequencer, d).await.unwrap();
}

/// `party`'s `contribute` of `class` to `target` (its render `render`) under the basis `basis`,
/// with its Approval Act Statement and ALICE's `authentication` Claim bound to it (SI-5).
fn contribution_of(
    d: Digest,
    (party, instance, nonce): (Id, Id, u8),
    class: &str,
    basis: ExerciseBasis,
    (target, render): (Digest, Digest),
) -> Request {
    let act = ApprovalAct {
        evidence: None,
        surface_class: None,
        act: Act::Contribution(class.to_owned()),
        instance,
        party,
        capacity: Capacity::Own,
        target,
        domain: d,
        nonce: vec![nonce; 16],
        work_gate: None,
        surface_profile: "suiss-approval-surface".to_owned(),
        surface_version: 1,
        render_digest: render,
        material_fields: ["action".to_owned(), "resource".to_owned()]
            .into_iter()
            .collect(),
        issued_at: NOW - 1_000,
        expires_at: NOW + 60_000,
    };
    let h = access_kernel::aas::digest(&act).unwrap();
    let claim = sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject: party,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(vec![0xaa; 32])),
            issued_at: NOW - 5_000,
            validity: Window {
                from: NOW - 5_000,
                until: NOW + 12 * 3_600_000,
            },
            assurance: [
                ("aal", 3),
                ("phishing_resistant", 1),
                ("uv", 1),
                ("human_presence", 1),
                ("hardware_bound", 1),
                ("non_custodial", 1),
            ]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), *v))
            .collect(),
            bound_intent: Some(h),
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    );
    let payload = Payload::Contribute {
        target,
        class: class.to_owned(),
    };
    let mut r = meta_request(d, nonce, basis, payload);
    r.intent.resources = vec![ResourceRef {
        namespace: "access.contribution".to_owned(),
        path: vec![class.to_owned()],
        incarnation: 0,
    }];
    with_proofs(
        r,
        vec![
            ProofRef::Aas(act.to_bytes().unwrap()),
            ProofRef::Claim(claim),
        ],
    )
}

/// ALICE's `authentication` Claim about `subject` bound to `intent`, of the strongest class: what
/// a CT3 Exercise asks of its actor (§13.7.3).
fn ct3_claim(d: Digest, subject: Id, intent: Digest, seed: u8) -> ProofRef {
    ProofRef::Claim(sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(vec![seed; 32])),
            issued_at: NOW - 1_000,
            validity: Window {
                from: NOW - 1_000,
                until: NOW + 3_600_000,
            },
            assurance: [
                ("aal", 3),
                ("phishing_resistant", 1),
                ("uv", 1),
                ("human_presence", 1),
                ("hardware_bound", 1),
                ("non_custodial", 1),
            ]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), *v))
            .collect(),
            bound_intent: Some(intent),
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    ))
}

/// `r` with ROOT's CT3 `authentication` Claim and `proofs`.
fn as_root(d: Digest, r: Request, seed: u8, mut proofs: Vec<ProofRef>) -> Request {
    let digest = access_kernel::intent::intent_digest(&r.intent).unwrap();
    proofs.push(ct3_claim(d, ROOT, digest, seed));
    with_proofs(r, proofs)
}

/// The self-anchor of the Party registered with nonce `n`.
fn self_anchor(d: Digest, n: u8) -> ExerciseBasis {
    ExerciseBasis::Anchor(meta::object_id(
        &meta::exercise_id(&d, &[n; 16]).unwrap(),
        kind::ANCHOR,
        0,
    ))
}

// L0-META-20, L0-META-30, TN-91, OP-153 m.17 (b), m.25 (a)
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one root change from its opening through refused and accepted contributions"
)]
async fn a_root_change_waits_for_the_new_roots_own_acceptance() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, gated(&[])).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    let created = send(
        &mut core,
        as_root(
            d,
            meta_request(
                d,
                30,
                ExerciseBasis::Anchor(meta::meta_anchor(&d)),
                Payload::AnchorCreate {
                    scope: meta::AnchorScope::Resource(ResourceSelector::Structural(Structural {
                        namespace: "shop".to_owned(),
                        prefix: vec!["handover".to_owned()],
                        kind: None,
                        attrs: BTreeMap::new(),
                    })),
                    root: Root::Sole(ROOT),
                    root_terms: BTreeSet::new(),
                },
            ),
            0xd1,
            Vec::new(),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&created);
    let handed = meta::object_id(&created.exercise.unwrap(), kind::ANCHOR, 0);
    let transfer = meta_request(
        d,
        31,
        ExerciseBasis::Anchor(handed),
        Payload::AnchorTransfer {
            anchor: handed,
            root: Root::Sole(BOB),
            disposition: BTreeMap::new(),
        },
    );
    let digest = access_kernel::intent::intent_digest(&transfer.intent).unwrap();
    let render = render_of(&transfer);
    let asked = send(
        &mut core,
        as_root(d, transfer.clone(), 0xd2, Vec::new()),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction, "{asked:?}");

    let bob = meta::object_id(&meta::exercise_id(&d, &[6; 16]).unwrap(), kind::INSTANCE, 0);
    let alice = alice_instance(d);
    let approve = send(
        &mut core,
        contribution_of(
            d,
            (BOB, bob, 40),
            "approve",
            self_anchor(d, 5),
            (digest, render),
        ),
        BOB_KEY,
    )
    .await
    .unwrap();
    assert_ne!(approve.decision.outcome, Outcome::Allow);
    let elsewhere = send(
        &mut core,
        contribution_of(
            d,
            (BOB, bob, 41),
            meta::ACCEPT_ROOT,
            self_anchor(d, 3),
            (digest, render),
        ),
        BOB_KEY,
    )
    .await
    .unwrap();
    assert_ne!(elsewhere.decision.outcome, Outcome::Allow);
    let stranger = send(
        &mut core,
        contribution_of(
            d,
            (ALICE, alice, 42),
            meta::ACCEPT_ROOT,
            self_anchor(d, 3),
            (digest, render),
        ),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&stranger);
    let mut other = transfer.clone();
    other.nonce = vec![32; 16];
    let not_bob = send(
        &mut core,
        as_root(
            d,
            other,
            0xd2,
            vec![ProofRef::Contribution(stranger.exercise.unwrap())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    // OP-111 m.8
    assert_eq!(not_bob.decision.outcome, Outcome::Deny);
    assert!(
        not_bob
            .decision
            .blockers
            .iter()
            .any(|b| b.class == BlockerClass::SourceNotAccepted),
        "{not_bob:?}"
    );

    let accepted = send(
        &mut core,
        contribution_of(
            d,
            (BOB, bob, 43),
            meta::ACCEPT_ROOT,
            self_anchor(d, 5),
            (digest, render),
        ),
        BOB_KEY,
    )
    .await
    .unwrap();
    allowed(&accepted);
    let done = send(
        &mut core,
        as_root(
            d,
            transfer,
            0xd2,
            vec![ProofRef::Contribution(accepted.exercise.unwrap())],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&done);
    let state = state_of(&db, d, &meta::key(kind::ANCHOR, &handed))
        .await
        .map(|b| {
            meta::AnchorState::from_value(&dcbor::decode(&b, Limits::CEILING).unwrap()).unwrap()
        })
        .unwrap();
    assert_eq!(state.root, Root::Sole(BOB));
    fold_check(&db.sequencer, d).await.unwrap();
}

/// Genesis where ALICE is the membership issuer of `org_member` and the members of the
/// organization `org` hold a Grant to read the shop (OP-153 m.17 (c)).
fn org_members(org: Id) -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let members = SubjectSelector::Pred(BTreeSet::from([access_kernel::model::Conjunct {
        claim_class: "org_member".to_owned(),
        value: Some(EqValue::Bytes(org.0.to_vec())),
    }]));
    grants.push(Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(1)),
        (Value::text("holder"), members.to_value()),
        (
            Value::text("authority"),
            authority(vec![action("shop", "read")], selector("shop")).to_value(),
        ),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ]));
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    let acceptance = Value::Map(vec![
        (Value::text("issuer"), ALICE.to_value()),
        (Value::text("use"), Value::text("subject-selection")),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text("org_member")]),
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

/// ALICE's `org_member` Claim that `subject` is a member of `org`.
fn org_member_claim(d: Digest, subject: Id, org: Id) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: "org_member".to_owned(),
            value: Some(EqValue::Bytes(org.0.to_vec())),
            issued_at: NOW,
            validity: Window {
                from: 0,
                until: 1_000_000,
            },
            assurance: BTreeMap::new(),
            bound_intent: None,
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

// OP-153 m.17 (c), m.25 (a), L2-CLB-2, C13
#[tokio::test]
async fn an_organizations_rule_shaped_grant_selects_only_its_own_members() {
    const ORG: Id = Id([0xa1; 16]);
    const OTHER: Id = Id([0xa2; 16]);
    let db = fresh().await.unwrap();
    let (mut core, d) = setup_with(&db, org_members(ORG)).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    let grant = meta::object_id(&d, kind::GRANT, 1);
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut episodes = Vec::new();
    for (nonce, subject, org) in [(9, ROOT, ORG), (10, BOB, OTHER)] {
        let ingested = send(
            &mut core,
            with_proofs(
                shop_request(d, nonce, Mode::Commit, shop),
                vec![ProofRef::Claim(org_member_claim(d, subject, org))],
            ),
            ROOT_KEY,
        )
        .await
        .unwrap();
        allowed(&ingested);
        episodes.push(ingested.record.unwrap() - 2);
    }
    let holding = |holder, since| {
        ExerciseBasis::Holding(HoldingRef {
            grant,
            holder,
            since,
        })
    };
    allowed(
        &send(
            &mut core,
            shop_request(d, 11, Mode::Commit, holding(ROOT, episodes[0])),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    unresolved(
        &send(
            &mut core,
            shop_request(d, 12, Mode::Commit, holding(BOB, episodes[1])),
            BOB_KEY,
        )
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// E54 (4), L0-EVAL-16a, OP-154 m.3 (b)
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "an agent, its task Mandate, a Grant and three commits"
)]
async fn an_origin_outside_the_mandate_is_denied_on_commit() {
    use access_kernel::combinator::{BlockerClass, ORIGIN_SUBCODE, Origins};
    use access_kernel::intent::ParamValue;
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                3,
                public_basis,
                Payload::PartyRegister {
                    party: ALICE,
                    root: Root::Sole(ALICE),
                    actor_kind: ActorKind::Agent,
                },
            ),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let shop_read = authority(vec![action("shop", "read")], selector("shop"));
    let shop = "https://shop.example";
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                4,
                public_basis,
                Payload::InstanceCreate {
                    party: ALICE,
                    key: public(ALICE_KEY),
                    mandate: Some(meta::MandateEnvelope {
                        origins: Origins {
                            read: BTreeSet::from([shop.to_owned()]),
                            write: BTreeSet::new(),
                        },
                        authority: shop_read.authority.clone(),
                        constraints: shop_read.constraints.clone(),
                        requirements: BTreeSet::new(),
                        pin: None,
                    }),
                },
            ),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let anchor = meta::object_id(&d, kind::ANCHOR, 1);
    let issued = send(
        &mut core,
        meta_request(
            d,
            5,
            ExerciseBasis::Anchor(anchor),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(anchor),
                holder: SubjectSelector::Party(ALICE),
                authority: shop_read,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&issued);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: ALICE,
        since: issued.record.unwrap(),
    });
    let at = |nonce, origin: &str, write| {
        let mut r = shop_request(d, nonce, Mode::Commit, holding);
        r.intent.params.insert(
            "target".to_owned(),
            ParamValue::Origin {
                origin: origin.to_owned(),
                write,
            },
        );
        r
    };
    allowed(
        &send(&mut core, at(6, shop, false), ALICE_KEY)
            .await
            .unwrap(),
    );
    for (nonce, origin, write) in [(7, "https://mail.example", false), (8, shop, true)] {
        let r = send(&mut core, at(nonce, origin, write), ALICE_KEY)
            .await
            .unwrap();
        assert_eq!(r.decision.outcome, Outcome::Deny, "{origin} {write}: {r:?}");
        assert!(r.exercise.is_none());
        assert!(
            r.decision
                .blockers
                .iter()
                .any(|b| b.class == BlockerClass::OutsideInstanceLimits
                    && b.subcode.as_deref() == Some(ORIGIN_SUBCODE)),
            "{r:?}"
        );
    }
    fold_check(&db.sequencer, d).await.unwrap();
}
