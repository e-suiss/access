//! The developer back end on a real PostgreSQL (§8.17.10, X20, X21, C28, TN-121, INV-10,
//! INV-27, §9.7, §5.4, SEC15): schema publishing to acceptance, role change previews, the
//! decision lab and the impact queries. Every preview writes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::PgReader;
use access_authority_core::app::impact::{Compromised, Revoked};
use access_authority_core::app::lab::{ADVISORY, Sample};
use access_authority_core::app::publishing::{self, Draft, Publication, Standing};
use access_authority_core::app::roles::SetRelation;
use access_authority_core::app::{Authority, Incoming, Response};
use access_authority_core::domain::Request;
use access_authority_core::ports::{Binding, Salts};
use access_authority_core::query::{Change, Hit, Query, Report};
use access_authority_sequencer::adapters::{PgLog, create_genesis};
use access_authority_sequencer::app::Leader;
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::meta::{
    self, ActorKind, ExerciseBasis, GrantBasis, GrantContent, HoldingRef, Payload, Root, kind,
};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms, Id,
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

/// ALICE's Instance, opened by `onboard(.., (3, 4))`.
fn alice_instance(d: Digest) -> Id {
    meta::object_id(&meta::exercise_id(&d, &[4; 16]).unwrap(), kind::INSTANCE, 0)
}

fn meta_anchor(d: Digest) -> ExerciseBasis {
    ExerciseBasis::Anchor(meta::meta_anchor(&d))
}

/// Root and Alice registered, each with an Instance.
async fn ready(db: &TestDb) -> (Core, Digest) {
    let (mut core, d) = setup(db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    (core, d)
}

/// The `schema-definition` Acceptance content of `shop` pinning `spp`.
fn schemas_with(spp: &access_kernel::schema::Spp) -> Value {
    let Value::Map(fields) = shop_schemas() else {
        panic!("acceptance");
    };
    let fields = fields
        .into_iter()
        .map(|(k, v)| {
            if k == Value::text("spp") {
                (k, spp.to_value())
            } else {
                (k, v)
            }
        })
        .collect();
    let b = dcbor::encode(&Value::Map(fields), Limits::CEILING).unwrap();
    dcbor::decode(&b, Limits::CEILING).unwrap()
}

/// The id of the `shop` `schema-definition` Acceptance.
async fn shop_acceptance_id(db: &TestDb, d: Digest) -> Id {
    let rows = access_store::authority::state_of(
        &db.app,
        &DomainId::from_bytes(d.0),
        &[access_kernel::schema::schemas_key("shop")],
    )
    .await
    .unwrap();
    let Value::Array(ids) =
        dcbor::decode(rows[0].value.as_deref().unwrap(), Limits::CEILING).unwrap()
    else {
        panic!("schema index");
    };
    Id::from_value(&ids[0]).unwrap()
}

fn v1() -> Publication {
    Publication {
        spp: shop_spp(),
        classes: BTreeMap::new(),
        compatibility: None,
        published_ms: 0,
    }
}

fn v2_draft(version: u64) -> Draft {
    let mut actions = shop_spp().actions;
    actions.push(schema_of("refund"));
    Draft {
        namespace: "shop".to_owned(),
        catalog_version: version,
        actions,
        classes: BTreeMap::new(),
        retirements: BTreeSet::new(),
        core_spec_min: None,
        compatibility: None,
    }
}

async fn status_in(db: &TestDb, d: Digest, p: &Publication) -> publishing::Status {
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    publishing::status(p, Some(&v1()), vec![(d, reader)], NOW)
        .await
        .unwrap()
}

// X21, E10, E11: a published version waits in each domain that accepts its publisher until that
// domain's own `acceptance.amend` pins its exact fingerprint; the publisher has no accept path
#[tokio::test]
async fn a_publication_reaches_a_domain_only_by_its_own_acceptance() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    let published = publishing::publish(ROOT, v2_draft(2), Some(&v1()), NOW).unwrap();
    assert!(published.notes.existing_grants_unchanged);
    assert_eq!(published.notes.new_actions, ["refund"]);
    let p2 = published.publication.clone();
    access_store::publications::keep(
        &db.app,
        &DomainId::from_bytes(d.0),
        &access_store::publications::PublicationRow {
            fingerprint: published.fingerprint.0,
            publisher: ROOT.0,
            namespace: "shop".to_owned(),
            catalog_version: 2,
            package: p2.to_bytes().unwrap(),
            published_ms: NOW,
        },
    )
    .await
    .unwrap();
    let head = core.head();
    let status = status_in(&db, d, &p2).await;
    assert_eq!(status.pending_acceptance, [d]);
    assert!(status.accepted_in.is_empty());
    assert_eq!(status_in(&db, d, &v1()).await.accepted_in, [d]);
    let offers = core.publication_offers("shop", NOW).await.unwrap();
    assert_eq!(offers.len(), 1);
    assert_eq!(
        offers[0].standing,
        Standing::Pending {
            accepted_version: Some(1)
        }
    );
    assert_eq!(offers[0].diff.added, ["refund"]);
    assert_eq!(core.head(), head, "reading a publication writes nothing");

    let acceptance = shop_acceptance_id(&db, d).await;
    let amend = |spp: &access_kernel::schema::Spp| Payload::AcceptanceAmend {
        acceptance,
        content: schemas_with(spp),
    };
    // X21: Alice, without the domain's authority, cannot accept for it
    let by_alice = send(
        &mut core,
        meta_request(d, 20, meta_anchor(d), amend(&p2.spp)),
        ALICE_KEY,
    )
    .await;
    assert!(by_alice.is_err() || by_alice.unwrap().decision.outcome != Outcome::Allow);
    assert_eq!(status_in(&db, d, &p2).await.pending_acceptance, [d]);
    // E10: accepting another package is not accepting this fingerprint
    let other = publishing::publish(ROOT, v2_draft(3), Some(&v1()), NOW)
        .unwrap()
        .publication;
    allowed(
        &send(
            &mut core,
            meta_request(d, 21, meta_anchor(d), amend(&other.spp)),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    assert_eq!(status_in(&db, d, &p2).await.pending_acceptance, [d]);
    // the domain's root pins the exact fingerprint
    allowed(
        &send(
            &mut core,
            meta_request(d, 22, meta_anchor(d), amend(&p2.spp)),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let status = status_in(&db, d, &p2).await;
    assert_eq!(status.accepted_in, [d]);
    assert!(status.pending_acceptance.is_empty());
}

fn role_set(actions: &[&str], prefix: &[&str]) -> AuthoritySet {
    AuthoritySet {
        actions: ActionSet {
            exact: actions.iter().map(|a| action("shop", a)).collect(),
            prefix: BTreeSet::new(),
        },
        resource: ResourceSelector::Structural(Structural {
            namespace: "shop".to_owned(),
            prefix: prefix.iter().map(|p| (*p).to_owned()).collect(),
            kind: None,
            attrs: BTreeMap::new(),
        }),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    }
}

async fn define(core: &mut Core, d: Digest, nonce: u8, set: &AuthoritySet) {
    let define = Payload::AuthoritySetDefine {
        name: "clerk".to_owned(),
        authority: set.clone(),
    };
    allowed(
        &send(
            core,
            meta_request(d, nonce, meta_anchor(d), define),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
}

/// Alice holds `clerk` v1 on the `shop` Anchor; returns the Grant and its holding.
async fn clerk_grant(core: &mut Core, d: Digest, nonce: u8) -> (Id, ExerciseBasis) {
    let v1 = role_set(&["read"], &[]);
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let mut granted = authority(vec![action("shop", "read")], selector("shop"));
    granted.authority = v1.clone();
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(ALICE),
        authority: granted,
        agency: BTreeSet::from([Capacity::Own]),
        named: Some(("clerk".to_owned(), 1, meta::authority_set_digest(&v1))),
    });
    let issued = send(
        core,
        meta_request(d, nonce, ExerciseBasis::Anchor(shop), issue),
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
    (grant, holding)
}

// C28, X20, INV-10, TN-121: a role version pair is previewed per ability with its holders; a
// widening move carries the expansion requirements, a narrowing one none; the preview writes
// nothing and the move stays one `grant.amend` per Grant
#[tokio::test]
async fn a_role_move_is_previewed_and_never_applied() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    define(&mut core, d, 10, &role_set(&["read"], &[])).await;
    define(&mut core, d, 11, &role_set(&["read", "refund"], &[])).await;
    define(&mut core, d, 12, &role_set(&["read"], &["a"])).await;
    let (grant, _) = clerk_grant(&mut core, d, 13).await;
    access_authority_core::adapters::derive(&db.deriver, d)
        .await
        .unwrap();
    let head = core.head();

    let role = core.role("clerk", None, NOW).await.unwrap().unwrap();
    assert_eq!((role.version, role.latest), (3, 3));
    let first = core.role("clerk", Some(1), NOW).await.unwrap().unwrap();
    assert_eq!(first.authority, role_set(&["read"], &[]));

    let wider = core.change_role("clerk", 1, 2, NOW).await.unwrap().unwrap();
    assert_eq!(wider.relation, SetRelation::Widening);
    assert_eq!(wider.moves, [grant]);
    assert_eq!(wider.holders.parties, 1);
    let refund: Vec<_> = wider
        .abilities
        .iter()
        .filter(|a| a.ability.action.name == "refund")
        .collect();
    assert_eq!(refund.len(), 1);
    assert_eq!(
        (refund[0].holders_gaining, refund[0].holders_losing),
        (1, 0)
    );
    // INV-10: the widening move needs the expansion requirements
    let expansion = wider.expansion.unwrap();
    assert_eq!(expansion.joint_root_quorum, meta::CT3_QUORUM);
    assert_eq!(wider.pin.1, 2);

    let narrower = core.change_role("clerk", 1, 3, NOW).await.unwrap().unwrap();
    assert_eq!(narrower.relation, SetRelation::Narrowing);
    assert!(narrower.expansion.is_none());
    assert!(narrower.abilities.iter().all(|a| a.holders_gaining == 0));
    assert!(narrower.orphans.empty_scopes.is_empty());
    // TN-121: no Grant pins v2, so a move from it has nothing to move
    let none = core.change_role("clerk", 2, 3, NOW).await.unwrap().unwrap();
    assert!(none.moves.is_empty());
    assert!(
        core.change_role("clerk", 1, 9, NOW)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(core.head(), head, "a preview writes nothing");

    // §8.17.9.2: the admin view lists covered meta-actions one by one, reserved apart
    let admin = core
        .admin_grant(&meta::object_id(&d, kind::GRANT, 0), NOW)
        .await
        .unwrap()
        .unwrap();
    let names: Vec<&str> = admin.actions.iter().map(|l| l.action).collect();
    assert_eq!(names, ["party_register", "instance_create"]);
    assert!(admin.reserved.is_empty());
}

fn search_request(d: Digest, nonce: u8, kind: &str) -> Request {
    Request {
        domain: d,
        mode: Mode::Check,
        nonce: vec![nonce; 16],
        intent: intent(action("access", "read"), ("access.search", kind), None),
        payload: None,
        basis: meta_anchor(d),
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

// §8.17.10, X21: the developer reports are search kinds only the domain's auditors get; each
// is one page and records nothing
#[tokio::test]
async fn developer_reports_are_for_the_domains_auditors_only() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    define(&mut core, d, 10, &role_set(&["read"], &[])).await;
    define(&mut core, d, 11, &role_set(&["read", "refund"], &[])).await;
    clerk_grant(&mut core, d, 12).await;
    access_authority_core::adapters::derive(&db.deriver, d)
        .await
        .unwrap();
    let head = core.head();
    let query = Query::ChangeImpact(Change::Role {
        name: "clerk".to_owned(),
        from: 1,
        to: 2,
    });
    let by = |seed| incoming(search_request(d, 40 + seed, "change-impact"), seed);
    let root = core.search(&by(ROOT_KEY), &query, None, NOW).await.unwrap();
    assert!(matches!(
        root.hits.as_slice(),
        [Hit::Report(r)] if matches!(**r, Report::RoleChange(_))
    ));
    let alice = core
        .search(&by(ALICE_KEY), &query, None, NOW)
        .await
        .unwrap();
    assert!(alice.hits.is_empty());
    let wrong_kind = core
        .search(
            &incoming(search_request(d, 60, "subject"), ROOT_KEY),
            &query,
            None,
            NOW,
        )
        .await;
    assert!(matches!(wrong_kind, Err(CoreError::Protocol("search"))));
    assert_eq!(core.head(), head);
}

// §9.7, X21: Check is advisory and records nothing; only `check` is accepted
#[tokio::test]
async fn a_lab_check_records_nothing() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    define(&mut core, d, 9, &role_set(&["read"], &[])).await;
    let (_, holding) = clerk_grant(&mut core, d, 10).await;
    let head = core.head();
    let checked = core
        .lab_check(
            &incoming(shop_request(d, 11, Mode::Check, holding), ALICE_KEY),
            NOW,
        )
        .await
        .unwrap();
    assert_eq!(checked.response.decision.outcome, Outcome::Allow);
    assert!(checked.advisory && !checked.recorded);
    assert_eq!(checked.label, ADVISORY);
    assert_eq!(checked.response.record, None);
    assert_eq!(core.head(), head, "check leaves the position unchanged");
    assert!(matches!(
        core.lab_check(
            &incoming(shop_request(d, 12, Mode::Commit, holding), ALICE_KEY),
            NOW
        )
        .await,
        Err(CoreError::Protocol("lab-mode"))
    ));
    // §8.17.10.4 Explain: the holder views her own basis and sees its path
    let explained = core
        .lab_explain(
            &incoming(shop_request(d, 13, Mode::Check, holding), ALICE_KEY),
            NOW,
        )
        .await
        .unwrap();
    let ExerciseBasis::Holding(h) = holding else {
        panic!("holding");
    };
    assert_eq!(explained.path, [h.grant]);
    assert!(!explained.path_hidden && explained.selection.is_none());
    assert_eq!(core.head(), head);
}

// INV-27: a recorded decision replays to the same decision for an auditor; others are refused
#[tokio::test]
async fn a_recorded_decision_replays_to_a_match() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    define(&mut core, d, 9, &role_set(&["read"], &[])).await;
    let (_, holding) = clerk_grant(&mut core, d, 10).await;
    let done = send(
        &mut core,
        shop_request(d, 11, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&done);
    let record = done.record.unwrap();
    let head = core.head();
    let replay = core
        .lab_replay(
            &incoming(shop_request(d, 11, Mode::Commit, holding), ROOT_KEY),
            record,
            NOW,
        )
        .await
        .unwrap();
    assert!(replay.matches, "{replay:?}");
    assert_eq!(replay.recorded, Outcome::Allow);
    assert!(replay.differing.is_empty());
    assert!(matches!(
        core.lab_replay(
            &incoming(shop_request(d, 11, Mode::Commit, holding), ALICE_KEY),
            record,
            NOW
        )
        .await,
        Err(CoreError::Protocol("replay-scope"))
    ));
    assert_eq!(core.head(), head);
}

// §18.3, §5.8: a candidate policy is simulated over a sample and counted; nothing is set
#[tokio::test]
async fn a_policy_candidate_is_simulated_and_previewed() {
    let db = fresh().await.unwrap();
    let (core, _d) = ready(&db).await;
    let candidate = Value::Map(vec![
        (Value::text("schema"), Value::text(meta::RESTRICTION_SCHEMA)),
        (
            Value::text("source"),
            Value::text(r#"@id("all") forbid(principal, action, resource);"#),
        ),
    ]);
    let sample = Sample {
        intent: intent(action("shop", "read"), ("shop", "item-1"), None),
        actor: Some(meta::Actor {
            party: ALICE,
            instance: Id([4; 16]),
        }),
        capacity: Capacity::Own,
    };
    let head = core.head();
    let report = core
        .lab_simulate(
            ROOT,
            None,
            &candidate,
            &[sample.clone(), sample.clone()],
            NOW,
        )
        .await
        .unwrap();
    assert_eq!((report.evaluated, report.newly_denied), (1, 1));
    assert!(matches!(
        core.lab_simulate(ALICE, None, &candidate, &[sample], NOW)
            .await,
        Err(CoreError::Protocol("lab-scope"))
    ));
    // §5.8: without the control-plane solver the relation is unknown, never equivalent
    let preview = core
        .change_policy(None, &candidate, &access_authority_core::ports::NoAnalysis)
        .await
        .unwrap();
    assert_eq!(
        preview.relation,
        access_authority_core::ports::PolicyRelation::Unknown
    );
    assert_eq!(preview.refused, None);
    assert_eq!(core.head(), head);
}

// §5.4, SEC15, RR-13: revocation impact names the subtree and counts orphan index rows; the
// compromise query lists what an Instance did inside the window
#[tokio::test]
async fn revocation_and_compromise_impact_are_derived() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    define(&mut core, d, 9, &role_set(&["read"], &[])).await;
    let (grant, holding) = clerk_grant(&mut core, d, 10).await;
    let read = send(
        &mut core,
        shop_request(d, 11, Mode::Commit, holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    allowed(&read);
    access_authority_core::adapters::derive(&db.deriver, d)
        .await
        .unwrap();
    let before = core
        .revocation_impact(Revoked::Grant(grant), NOW)
        .await
        .unwrap();
    assert_eq!(before.subtree, [grant]);
    assert_eq!(before.aftermath.grants_ending, 1);
    assert_eq!((before.orphan_tuples, before.index_lag), (0, 0));
    assert!(before.exposed.is_empty());
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    allowed(
        &send(
            &mut core,
            meta_request(d, 12, shop, Payload::GrantRevoke { grant }),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    // §5.4: the index has not seen the revocation yet; its live row is an orphan tuple
    let after = core
        .revocation_impact(Revoked::Instance(alice_instance(d)), NOW)
        .await
        .unwrap();
    assert_eq!(after.orphan_tuples, 1);
    assert!(after.index_lag > 0);
    assert_eq!(after.aftermath.running_copies, 0);

    let window = Window {
        from: 0,
        until: NOW,
    };
    let by_instance = core
        .compromise_impact(Compromised::Instance(alice_instance(d)), window)
        .await
        .unwrap();
    assert!(
        by_instance
            .exercises
            .iter()
            .any(|e| e.pos == read.record.unwrap() && e.outcome == "allow"),
        "{by_instance:?}"
    );
    let by_key = core
        .compromise_impact(Compromised::Key(thumbprint(&public(ALICE_KEY))), window)
        .await
        .unwrap();
    assert_eq!(by_key.instance, Some(alice_instance(d)));
    assert_eq!(by_key.exercises, by_instance.exercises);
    let empty = core
        .compromise_impact(
            Compromised::Instance(alice_instance(d)),
            Window { from: 0, until: 0 },
        )
        .await
        .unwrap();
    assert!(empty.exercises.is_empty());
}

/// A control-plane analysis that proves every change narrowing.
struct Narrows;

impl access_authority_core::ports::PolicyAnalysis for Narrows {
    fn compare<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> access_authority_core::ports::Comparing<'a> {
        Box::pin(std::future::ready(
            access_authority_core::ports::PolicyRelation::Narrowing,
        ))
    }
}

// OP-105, §5.8: the policy change-impact report asks the analysis the core was given, not a
// fixed "unknown"
#[tokio::test]
async fn op_105_the_change_impact_report_asks_the_wired_analysis() {
    let db = fresh().await.unwrap();
    let (core, d) = ready(&db).await;
    let mut core = core.with_analysis(std::sync::Arc::new(Narrows));
    let candidate = Value::Map(vec![
        (Value::text("schema"), Value::text(meta::RESTRICTION_SCHEMA)),
        (
            Value::text("source"),
            Value::text(r#"@id("all") forbid(principal, action, resource);"#),
        ),
    ]);
    let query = Query::ChangeImpact(Change::Policy {
        policy: None,
        candidate: suiss_crypto::dcbor::encode(&candidate, suiss_crypto::dcbor::Limits::CEILING)
            .unwrap(),
    });
    let found = core
        .search(
            &incoming(search_request(d, 70, "change-impact"), ROOT_KEY),
            &query,
            None,
            NOW,
        )
        .await
        .unwrap();
    assert!(matches!(
        found.hits.as_slice(),
        [Hit::Report(r)] if matches!(
            &**r,
            Report::PolicyChange(c)
                if c.relation == access_authority_core::ports::PolicyRelation::Narrowing
        )
    ));
}
