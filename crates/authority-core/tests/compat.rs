//! Compatibility mappings on a real PostgreSQL (E10, P24, PI-19, §9.13.4, SEC16, OP-157
//! m.3 (r)): a mapping the publisher declares changes no coverage until the domain pins its
//! digest, a pinned mapping that broadens never applies, a pinned non-broadening one needs an
//! approval for CT2+ Exercises during its probation, and dropping the pin ends it.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::arithmetic_side_effects,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::PgReader;
use access_authority_core::app::publishing::{self, Compatibility, Draft, Publication, Relation};
use access_authority_core::app::{Authority, Incoming, Response};
use access_authority_core::domain::Request;
use access_authority_core::ports::{Binding, Salts};
use access_authority_sequencer::adapters::{PgLog, create_genesis};
use access_authority_sequencer::app::Leader;
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{BlockerClass, Capacity, Mode, Outcome};
use access_kernel::compat::{Mapping, MappingOp, mapping_digest};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::meta::{
    self, ActorKind, ExerciseBasis, GrantBasis, GrantContent, HoldingRef, Payload, Root, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Bound as ParamBound, CanonicalAuthority, ConstraintSet,
    DelegationTerms, Id, ResourceRef, ResourceSelector, Structural, SubjectSelector, Window,
};
use access_kernel::record::Opened;
use access_kernel::schema::{ActionSchema, EffectClass, Spp};
use access_kernel::verify::cose::{ALG, CONTENT_TYPE as CT, KID, PublicKey, to_be_signed};
use access_kernel::verify::key_scope::thumbprint;
use access_store::scope::DomainId;
use access_store::testing::{TestDb, fresh};
use ed25519_dalek::Signer as _;
use suiss_crypto::dcbor::{self, Limits, Value};

const TENANT: [u8; 16] = [0x01, 0x9a, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];
const TTL: Duration = Duration::from_secs(10);
const ROOT: Id = Id([1; 16]);
const ALICE: Id = Id([2; 16]);
const ROOT_KEY: u8 = 11;
const ALICE_KEY: u8 = 12;
const PEP: &str = "pep.example";
const NOW: u64 = 1_000_000;
const DAY_MS: u64 = 86_400_000;
const UNTIL: u64 = NOW + 100 * DAY_MS;

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

/// `pay` of `major`: irreversible, so CT2 (§13.7.2); its count parameter is named `n` in
/// version 1 and `count` after.
fn pay(major: u64) -> ActionSchema {
    let param = if major == 1 { "n" } else { "count" };
    ActionSchema {
        reversibility: None,
        name: "pay".to_owned(),
        major,
        effect: EffectClass::Irreversible,
        reserved: false,
        consumption_bearing: false,
        params: BTreeMap::from([(param.to_owned(), "int".to_owned())]),
        resource_types: BTreeSet::new(),
        render: None,
    }
}

fn pay_ref(major: u64) -> ActionRef {
    ActionRef {
        namespace: "shop".to_owned(),
        name: "pay".to_owned(),
        major,
        schema: access_kernel::schema::action_digest(&pay(major)),
    }
}

fn core_action(name: &str) -> ActionRef {
    access_kernel::meta::core_action(name)
}

fn spp(version: u64) -> Spp {
    Spp {
        publisher: ROOT,
        namespace: "shop".to_owned(),
        catalog_version: version,
        actions: vec![pay(version)],
        retirements: BTreeSet::new(),
        core_spec_min: None,
    }
}

/// The `shop` `schema-definition` Acceptance of `spp`, pinning `mappings`.
fn schemas(spp: &Spp, mappings: &[Digest]) -> Value {
    let mut fields = vec![
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
    ];
    if !mappings.is_empty() {
        let mut ds: Vec<Value> = mappings.iter().map(Canonical::to_value).collect();
        ds.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
        fields.push((Value::text("mappings"), Value::Array(ds)));
    }
    let b = dcbor::encode(&Value::Map(fields), Limits::CEILING).unwrap();
    dcbor::decode(&b, Limits::CEILING).unwrap()
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
                until: UNTIL,
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
                    core_action("party_register"),
                    core_action("instance_create"),
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
            opened(Value::Array(vec![schemas(&spp(1), &[])])),
        ),
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

async fn setup(db: &TestDb) -> (Core, Digest) {
    let d = create_genesis(&db.sequencer, TENANT, genesis(), 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let binding = Bound(BTreeMap::from([
        (thumbprint(&public(ROOT_KEY)), (ROOT, public(ROOT_KEY))),
        (thumbprint(&public(ALICE_KEY)), (ALICE, public(ALICE_KEY))),
    ]));
    (Authority::new(leader, reader, binding, Counter(0), d), d)
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

fn envelope(
    act: ActionRef,
    resource: (&str, &str),
    params: BTreeMap<String, ParamValue>,
    payload: Option<&Payload>,
) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action: act,
        resources: vec![ResourceRef {
            namespace: resource.0.to_owned(),
            path: vec![resource.1.to_owned()],
            incarnation: 0,
        }],
        params,
        opaque: payload
            .map(|p| BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]))
            .unwrap_or_default(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: 0,
            until: UNTIL,
        },
    }
}

fn meta_request(d: Digest, nonce: u8, basis: ExerciseBasis, payload: Payload) -> Request {
    Request {
        domain: d,
        mode: Mode::Commit,
        nonce: vec![nonce; 16],
        intent: envelope(
            core_action(payload.action()),
            ("access.party", "p"),
            BTreeMap::new(),
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

/// `pay` of `major` on `shop/item-1` with its count parameter.
fn pay_request(d: Digest, nonce: u8, major: u64, basis: ExerciseBasis) -> Request {
    let param = if major == 1 { "n" } else { "count" };
    Request {
        domain: d,
        mode: Mode::Commit,
        nonce: vec![nonce; 16],
        intent: envelope(
            pay_ref(major),
            ("shop", "item-1"),
            BTreeMap::from([(param.to_owned(), ParamValue::Count(3))]),
            None,
        ),
        payload: None,
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

async fn send_at(
    core: &mut Core,
    mut request: Request,
    seed: u8,
    now: u64,
) -> Result<Response, CoreError> {
    request.intent.validity = Window {
        from: now,
        until: now + 60_000,
    };
    let digest = access_kernel::intent::intent_digest(&request.intent).unwrap();
    let statement = Statement {
        domain: request.domain,
        nonce: request.nonce.clone(),
        intent: digest,
        mode: request.mode,
        pep: PEP.to_owned(),
        capacity: request.capacity,
        basis: request.basis,
        iat: now,
        exercise: request.exercise,
    };
    let inc = Incoming {
        ais: Some(sign(&statement, seed)),
        request,
        pep: PEP.to_owned(),
        requester: None,
        explain: false,
        status: None,
        context: None,
    };
    core.exercise(&inc, now).await
}

fn allowed(r: &Response) {
    assert_eq!(r.decision.outcome, Outcome::Allow, "{r:?}");
}

fn denied(r: &Response, class: BlockerClass) {
    assert_eq!(r.decision.outcome, Outcome::Deny, "{r:?}");
    assert!(
        r.decision.blockers.iter().any(|b| b.class == class),
        "{r:?}"
    );
}

async fn onboard(core: &mut Core, d: Digest, party: Id, seed: u8, nonces: (u8, u8)) {
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
        actor_kind: ActorKind::Human,
    };
    allowed(
        &send_at(
            core,
            meta_request(d, nonces.0, public_basis, register),
            seed,
            NOW,
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
        &send_at(
            core,
            meta_request(d, nonces.1, public_basis, create),
            seed,
            NOW,
        )
        .await
        .unwrap(),
    );
}

/// ALICE holds `pay` of version 1 on `shop`, with at most 5 as its `n`.
async fn ready(db: &TestDb) -> (Core, Digest, ExerciseBasis) {
    let (mut core, d) = setup(db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let mut granted = authority(vec![pay_ref(1)], selector("shop"));
    granted
        .authority
        .params
        .insert("n".to_owned(), ParamBound::CountMax(5));
    let issued = send_at(
        &mut core,
        meta_request(
            d,
            5,
            ExerciseBasis::Anchor(shop),
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(shop),
                holder: SubjectSelector::Party(ALICE),
                authority: granted,
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ROOT_KEY,
        NOW,
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
    allowed(
        &send_at(&mut core, pay_request(d, 6, 1, holding), ALICE_KEY, NOW)
            .await
            .unwrap(),
    );
    (core, d, holding)
}

fn mapping(relation: access_kernel::compat::Relation) -> Mapping {
    Mapping {
        from: pay_ref(1),
        to: pay_ref(2),
        relation,
        ops: vec![MappingOp::Rename {
            from: "count".to_owned(),
            to: "n".to_owned(),
        }],
    }
}

fn v1() -> Publication {
    Publication {
        spp: spp(1),
        classes: BTreeMap::from([(
            ("pay".to_owned(), "n".to_owned()),
            publishing::ParamClass::Relevant(publishing::Affects::Count),
        )]),
        compatibility: None,
        published_ms: 0,
    }
}

/// Publishes version 2 declaring `relation` with its mapping, offered to the domain.
async fn publish_v2(db: &TestDb, d: Digest, relation: Relation) -> Mapping {
    let m = mapping(relation.kernel());
    let draft = Draft {
        namespace: "shop".to_owned(),
        catalog_version: 2,
        actions: vec![pay(2)],
        classes: BTreeMap::from([(
            ("pay".to_owned(), "count".to_owned()),
            publishing::ParamClass::Relevant(publishing::Affects::Count),
        )]),
        retirements: BTreeSet::new(),
        core_spec_min: None,
        compatibility: Some(Compatibility {
            from: 1,
            relation,
            mappings: vec![m.clone()],
        }),
    };
    let published = publishing::publish(ROOT, draft, Some(&v1()), NOW).unwrap();
    access_store::publications::keep(
        &db.app,
        &DomainId::from_bytes(d.0),
        &access_store::publications::PublicationRow {
            fingerprint: published.fingerprint.0,
            publisher: ROOT.0,
            namespace: "shop".to_owned(),
            catalog_version: 2,
            package: published.publication.to_bytes().unwrap(),
            published_ms: NOW,
        },
    )
    .await
    .unwrap();
    m
}

fn acceptance(d: Digest) -> Id {
    meta::object_id(&d, kind::ACCEPTANCE, 0)
}

/// The domain accepts version 2, pinning `mappings`, at `now`.
async fn accept_v2(
    core: &mut Core,
    d: Digest,
    nonce: u8,
    mappings: &[Digest],
    now: u64,
) -> Result<Response, CoreError> {
    send_at(
        core,
        meta_request(
            d,
            nonce,
            ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            Payload::AcceptanceAmend {
                acceptance: acceptance(d),
                content: schemas(&spp(2), mappings),
            },
        ),
        ROOT_KEY,
        now,
    )
    .await
}

// PI-19, E10, OP-157 m.3 (r), Ek B 5667
#[tokio::test]
async fn an_unpinned_mapping_or_version_changes_no_coverage() {
    let db = fresh().await.unwrap();
    let (mut core, d, holding) = ready(&db).await;
    publish_v2(&db, d, Relation::Narrowing).await;
    let v3 = send_at(&mut core, pay_request(d, 10, 3, holding), ALICE_KEY, NOW)
        .await
        .unwrap();
    denied(&v3, BlockerClass::SchemaNotAccepted);
    allowed(&accept_v2(&mut core, d, 11, &[], NOW).await.unwrap());
    let unpinned = send_at(&mut core, pay_request(d, 12, 2, holding), ALICE_KEY, NOW)
        .await
        .unwrap();
    denied(&unpinned, BlockerClass::NoCoveringAuthority);
}

// E10, PI-19, OP-157 m.3 (r), Ek B 5665
#[tokio::test]
async fn a_pinned_broadening_mapping_is_never_applied() {
    let db = fresh().await.unwrap();
    let (mut core, d, holding) = ready(&db).await;
    let m = publish_v2(&db, d, Relation::Broadening).await;
    allowed(
        &accept_v2(&mut core, d, 10, &[mapping_digest(&m).unwrap()], NOW)
            .await
            .unwrap(),
    );
    let r = send_at(
        &mut core,
        pay_request(d, 11, 2, holding),
        ALICE_KEY,
        NOW + 20 * DAY_MS,
    )
    .await
    .unwrap();
    denied(&r, BlockerClass::NoCoveringAuthority);
}

// C18, OP-157 m.3 (r), Ek B 5665
#[tokio::test]
async fn only_a_mapping_the_publisher_declared_can_be_pinned() {
    let db = fresh().await.unwrap();
    let (mut core, d, _) = ready(&db).await;
    publish_v2(&db, d, Relation::Narrowing).await;
    let undeclared = mapping_digest(&mapping(
        access_kernel::compat::Relation::RepresentationEquivalent,
    ))
    .unwrap();
    let r = accept_v2(&mut core, d, 10, &[undeclared], NOW).await;
    assert!(
        matches!(r, Err(CoreError::Protocol("mapping-unknown"))),
        "{r:?}"
    );
}

// SEC16, PI-19, OP-157 m.3 (r), Ek B 5665, 5666, 5667
#[tokio::test]
async fn a_pinned_narrowing_mapping_needs_an_approval_through_its_probation() {
    let db = fresh().await.unwrap();
    let (mut core, d, holding) = ready(&db).await;
    let m = publish_v2(&db, d, Relation::Narrowing).await;
    let digest = mapping_digest(&m).unwrap();
    allowed(&accept_v2(&mut core, d, 10, &[digest], NOW).await.unwrap());
    let day13 = send_at(
        &mut core,
        pay_request(d, 11, 2, holding),
        ALICE_KEY,
        NOW + 13 * DAY_MS,
    )
    .await
    .unwrap();
    assert_eq!(day13.decision.outcome, Outcome::RequireAction, "{day13:?}");
    let day15 = send_at(
        &mut core,
        pay_request(d, 12, 2, holding),
        ALICE_KEY,
        NOW + 15 * DAY_MS,
    )
    .await
    .unwrap();
    allowed(&day15);
    // E10
    let mut over = pay_request(d, 13, 2, holding);
    over.intent
        .params
        .insert("count".to_owned(), ParamValue::Count(9));
    let r = send_at(&mut core, over, ALICE_KEY, NOW + 15 * DAY_MS)
        .await
        .unwrap();
    denied(&r, BlockerClass::NoCoveringAuthority);
    // OP-157 m.3 (r)
    allowed(
        &accept_v2(&mut core, d, 14, &[], NOW + 15 * DAY_MS)
            .await
            .unwrap(),
    );
    let r = send_at(
        &mut core,
        pay_request(d, 15, 2, holding),
        ALICE_KEY,
        NOW + 16 * DAY_MS,
    )
    .await
    .unwrap();
    denied(&r, BlockerClass::NoCoveringAuthority);
}

// PI-19, OP-157 m.3 (r), Ek B 5667
#[tokio::test]
async fn revoking_the_acceptance_drops_the_pin() {
    let db = fresh().await.unwrap();
    let (mut core, d, holding) = ready(&db).await;
    let m = publish_v2(&db, d, Relation::Narrowing).await;
    allowed(
        &accept_v2(&mut core, d, 10, &[mapping_digest(&m).unwrap()], NOW)
            .await
            .unwrap(),
    );
    allowed(
        &send_at(
            &mut core,
            pay_request(d, 11, 2, holding),
            ALICE_KEY,
            NOW + 15 * DAY_MS,
        )
        .await
        .unwrap(),
    );
    allowed(
        &send_at(
            &mut core,
            meta_request(
                d,
                12,
                ExerciseBasis::Anchor(meta::meta_anchor(&d)),
                Payload::AcceptanceRevoke {
                    acceptance: acceptance(d),
                },
            ),
            ROOT_KEY,
            NOW + 15 * DAY_MS,
        )
        .await
        .unwrap(),
    );
    let r = send_at(
        &mut core,
        pay_request(d, 13, 2, holding),
        ALICE_KEY,
        NOW + 16 * DAY_MS,
    )
    .await
    .unwrap();
    denied(&r, BlockerClass::SchemaNotAccepted);
}
