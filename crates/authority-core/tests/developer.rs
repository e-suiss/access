//! The developer back end on a real PostgreSQL (§8.17.10, X20, X21, C28, TN-121, INV-10,
//! INV-27, §9.7, §5.4, SEC15): schema publishing to acceptance, role change previews, the
//! decision lab and the impact queries. Every preview writes nothing.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assert_is_empty,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::PgReader;
use access_authority_core::app::hub::{Basis, Entry, Holding as HubHolding};
use access_authority_core::app::impact::{Compromised, Revoked};
use access_authority_core::app::lab::{ADVISORY, Sample};
use access_authority_core::app::management::Changed;
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

// X21, E10, E11
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
    // X21
    let by_alice = send(
        &mut core,
        meta_request(d, 20, meta_anchor(d), amend(&p2.spp)),
        ALICE_KEY,
    )
    .await;
    assert!(by_alice.is_err() || by_alice.unwrap().decision.outcome != Outcome::Allow);
    assert_eq!(status_in(&db, d, &p2).await.pending_acceptance, [d]);
    // E10
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

// C28, X20, INV-10, TN-121
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
    // X20, §8.17.9.8
    let amend = Payload::from_bytes(&wider.amends[0]).unwrap();
    let Payload::GrantAmend {
        grant: amended,
        authority,
        named,
        ..
    } = amend
    else {
        panic!("{amend:?}")
    };
    assert_eq!(amended, grant);
    assert_eq!(authority.authority, role_set(&["read", "refund"], &[]));
    assert_eq!(named.map(|(n, v, _)| (n, v)), Some(("clerk".to_owned(), 2)));
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
    // INV-10
    let expansion = wider.expansion.unwrap();
    assert_eq!(expansion.joint_root_quorum, meta::CT3_QUORUM);
    assert_eq!(wider.pin.1, 2);

    let narrower = core.change_role("clerk", 1, 3, NOW).await.unwrap().unwrap();
    assert_eq!(narrower.relation, SetRelation::Narrowing);
    assert!(narrower.expansion.is_none());
    assert!(narrower.abilities.iter().all(|a| a.holders_gaining == 0));
    assert!(narrower.orphans.empty_scopes.is_empty());
    // TN-121
    let none = core.change_role("clerk", 2, 3, NOW).await.unwrap().unwrap();
    assert!(none.moves.is_empty());
    assert!(
        core.change_role("clerk", 1, 9, NOW)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(core.head(), head, "a preview writes nothing");

    // §8.17.9.2
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

// §8.17.10, X21
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

// IA-2, IA-5, §8.17.9.2, OP-152 m.7 (b), TN-20
#[tokio::test]
async fn management_reads_disclose_only_what_the_viewer_may_see() {
    let db = fresh().await.unwrap();
    let (mut core, d) = ready(&db).await;
    define(&mut core, d, 10, &role_set(&["read"], &[])).await;
    let (grant, holding) = clerk_grant(&mut core, d, 12).await;
    access_authority_core::adapters::derive(&db.deriver, d)
        .await
        .unwrap();
    let head = core.head();
    let ask = |seed: u8, nonce: u8, kind: &str| incoming(search_request(d, nonce, kind), seed);
    let rows = |found: &access_authority_core::query::Found| -> Vec<Changed> {
        found
            .hits
            .iter()
            .filter_map(|h| match h {
                Hit::Report(r) => match &**r {
                    Report::Change(c) => Some(c.changed.clone()),
                    _ => None,
                },
                _ => None,
            })
            .collect()
    };
    let changes = Query::Changes { before: None };
    let root = core
        .search(&ask(ROOT_KEY, 40, "changes"), &changes, None, NOW)
        .await
        .unwrap();
    let all = rows(&root);
    assert!(all.contains(&Changed::Role {
        name: "clerk".to_owned(),
        version: 1
    }));
    assert!(all.contains(&Changed::Object(grant)));
    let alice = core
        .search(&ask(ALICE_KEY, 41, "changes"), &changes, None, NOW)
        .await
        .unwrap();
    let mine = rows(&alice);
    assert!(mine.contains(&Changed::Object(grant)));
    assert!(mine.contains(&Changed::Object(ALICE)));
    assert!(!mine.iter().any(|c| matches!(c, Changed::Role { .. })));
    assert!(!mine.contains(&Changed::Object(ROOT)));

    let holdings = core
        .search(&ask(ALICE_KEY, 42, "holdings"), &Query::Holdings, None, NOW)
        .await
        .unwrap();
    assert!(holdings.hits.iter().any(|h| matches!(
        h,
        Hit::Report(r) if matches!(&**r, Report::Holding(x)
            if ExerciseBasis::Holding(HoldingRef { grant: x.grant, holder: x.holder, since: x.since }) == holding)
    )));

    let own = Query::AdminGrant { grant };
    let own_view = core
        .search(&ask(ALICE_KEY, 43, "admin-grant"), &own, None, NOW)
        .await
        .unwrap();
    assert_eq!(own_view.hits.len(), 1);
    let other = Query::AdminGrant {
        grant: meta::object_id(&d, kind::GRANT, 0),
    };
    let not_hers = core
        .search(&ask(ALICE_KEY, 44, "admin-grant"), &other, None, NOW)
        .await
        .unwrap();
    assert!(not_hers.hits.is_empty());
    let roles = core
        .search(&ask(ALICE_KEY, 45, "roles"), &Query::Roles, None, NOW)
        .await
        .unwrap();
    assert!(roles.hits.is_empty());
    assert_eq!(core.head(), head, "a read writes nothing");
}

// §9.7, X21
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
    // §8.17.10.4
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

// INV-27
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

// §18.3, §5.8
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
    // §5.8
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

// §5.4, SEC15, RR-13
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
    // §5.4
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

// OP-105, §5.8
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

// OP-151 m.20 (a), OP-141 m.35 (e), Ek B 3115, 3116
#[tokio::test]
async fn the_domains_accepted_tenant_actions_are_read_with_their_schema() {
    let db = fresh().await.unwrap();
    let (core, _) = ready(&db).await;
    assert_eq!(
        core.accepted_action("shop", "read", 1, NOW).await.unwrap(),
        Some(action("shop", "read"))
    );
    for (namespace, name, major) in [
        ("shop", "refund", 1),
        ("shop", "read", 2),
        ("bank", "read", 1),
    ] {
        assert_eq!(
            core.accepted_action(namespace, name, major, NOW)
                .await
                .unwrap(),
            None,
            "{namespace}/{name}/{major}"
        );
    }
}

/// BOB's authority-state acknowledgement as `pep` of the state at `basis`, applied at
/// `applied_at` (§9.12.3).
fn ack(
    d: Digest,
    pep: &str,
    basis: u64,
    applied_at: u64,
) -> access_internal_api::claims::ClaimSubmission {
    use access_kernel::claim::body::{AckEvent, AckScope, AuthorityStateAck, Body, Class};
    let body = Body::AuthorityStateAck(AuthorityStateAck {
        pep: pep.to_owned(),
        event: AckEvent::Exercise(Digest([9; 32])),
        applied_at,
        clock_evidence: None,
        basis,
        scope: BTreeSet::from([AckScope::Cache]),
    });
    let v = body.to_value();
    let digest = access_kernel::claim::body::body_digest(Class::AuthorityStateAck, &v).unwrap();
    let statement = access_kernel::claim::Statement {
        domain: d,
        issuer: BOB,
        subject: BOB,
        class: "authority_state_ack".to_owned(),
        value: Some(access_kernel::model::EqValue::Bytes(digest.to_vec())),
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
    };
    let payload = statement.to_bytes().unwrap();
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (
                Value::Unsigned(CT),
                Value::text(access_kernel::claim::CONTENT_TYPE),
            ),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public(BOB_KEY)).to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = signing(BOB_KEY)
        .sign(&to_be_signed(&prot, &payload).unwrap())
        .to_bytes();
    let cose = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(sig.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    access_internal_api::claims::ClaimSubmission {
        domain: d,
        carrier: access_internal_api::claims::Carrier::Cose,
        claim: [vec![0xd2], cose].concat(),
        body: Some(dcbor::encode(&v, Limits::CEILING).unwrap()),
        evidence: None,
    }
}

/// The domain of [`genesis`] that also accepts BOB's `authority_state_ack` and
/// `party_key_state` Claims.
async fn with_ack_issuer(db: &TestDb) -> (Core, Digest) {
    let sorted = |mut m: Vec<(Value, Value)>| {
        m.sort_by_key(|(k, _)| dcbor::encode(k, Limits::CEILING).unwrap());
        Value::Map(m)
    };
    let accepts = sorted(vec![
        (Value::text("use"), Value::text("predicate-input")),
        (Value::text("issuer"), BOB.to_value()),
        (
            Value::text("classes"),
            Value::Array(vec![
                Value::text("party_key_state"),
                Value::text("authority_state_ack"),
            ]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
        ),
    ]);
    let mut list = vec![shop_schemas(), accepts];
    list.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
    let mut g = genesis();
    g.insert(
        "acceptances".to_owned(),
        Opened {
            value: Value::Array(list),
            salt: [3; 32],
        },
    );
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

// E15, §9.12.3, §7.9.8.3, E30, INV-21
#[tokio::test]
async fn authority_state_acks_feed_the_revocation_view() {
    let db = fresh().await.unwrap();
    let (mut core, d) = with_ack_issuer(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    define(&mut core, d, 9, &role_set(&["read"], &[])).await;
    let (grant, _) = clerk_grant(&mut core, d, 10).await;

    let admitted = |v: &access_internal_api::claims::ClaimVerdict| {
        matches!(
            v,
            access_internal_api::claims::ClaimVerdict::Admitted { .. }
        )
    };
    let early = core
        .ingest(&ack(d, "pep.early", 2, NOW), NOW)
        .await
        .unwrap();
    assert!(admitted(&early.verdict), "{early:?}");
    let before = core
        .revocation_impact(Revoked::Grant(grant), NOW)
        .await
        .unwrap();
    assert!(before.acknowledged.is_empty());
    assert_eq!(before.aftermath.confirmed_applied, 0);

    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let revoked = send(
        &mut core,
        meta_request(d, 12, shop, Payload::GrantRevoke { grant }),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&revoked);
    let at = revoked.record.unwrap();
    for (pep, basis, applied) in [
        ("pep.stale", at - 1, NOW + 1),
        ("pep.applied", at, NOW + 2),
        ("pep.applied", at + 1, NOW + 5),
    ] {
        let v = core
            .ingest(&ack(d, pep, basis, applied), NOW)
            .await
            .unwrap();
        assert!(admitted(&v.verdict), "{v:?}");
    }
    let after = core
        .revocation_impact(Revoked::Grant(grant), NOW)
        .await
        .unwrap();
    let peps: Vec<(&str, u64)> = after
        .acknowledged
        .iter()
        .map(|a| (a.pep.as_str(), a.applied_at))
        .collect();
    assert_eq!(peps, [("pep.applied", NOW + 5)]);
}

/// BOB's `party_key_state` Claim about `subject`: a regime key-event as a custodian signs it
/// (U26, SI-13).
fn key_state(d: Digest, subject: Id) -> access_internal_api::claims::ClaimSubmission {
    use access_kernel::claim::body::{Body, Class, PartyKeyState};
    let body = Body::PartyKeyState(PartyKeyState {
        sequence: 1,
        keys: BTreeSet::from([Digest([4; 32])]),
        designated: BTreeMap::new(),
    });
    let v = body.to_value();
    let digest = access_kernel::claim::body::body_digest(Class::PartyKeyState, &v).unwrap();
    let statement = access_kernel::claim::Statement {
        domain: d,
        issuer: BOB,
        subject,
        class: "party_key_state".to_owned(),
        value: Some(access_kernel::model::EqValue::Bytes(digest.to_vec())),
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
    };
    let payload = statement.to_bytes().unwrap();
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (
                Value::Unsigned(CT),
                Value::text(access_kernel::claim::CONTENT_TYPE),
            ),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public(BOB_KEY)).to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = signing(BOB_KEY)
        .sign(&to_be_signed(&prot, &payload).unwrap())
        .to_bytes();
    let cose = dcbor::encode(
        &Value::Array(vec![
            Value::Bytes(prot),
            Value::Map(Vec::new()),
            Value::Bytes(payload),
            Value::Bytes(sig.to_vec()),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    access_internal_api::claims::ClaimSubmission {
        domain: d,
        carrier: access_internal_api::claims::Carrier::Cose,
        claim: [vec![0xd2], cose].concat(),
        body: Some(dcbor::encode(&v, Limits::CEILING).unwrap()),
        evidence: None,
    }
}

fn entries(found: &access_authority_core::query::Found) -> Vec<Entry> {
    found
        .hits
        .iter()
        .map(|h| match h {
            Hit::Entry(e) => (**e).clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}

fn holdings(found: &access_authority_core::query::Found) -> Vec<HubHolding> {
    entries(found)
        .into_iter()
        .filter_map(|e| match e {
            Entry::Holding(h) => Some(*h),
            _ => None,
        })
        .collect()
}

fn uses_of(
    found: &access_authority_core::query::Found,
) -> Vec<access_authority_core::app::hub::Use> {
    entries(found)
        .into_iter()
        .filter_map(|e| match e {
            Entry::Use(u) => Some(u),
            _ => None,
        })
        .collect()
}

fn changes_of(
    found: &access_authority_core::query::Found,
) -> Vec<access_authority_core::app::management::Change> {
    found
        .hits
        .iter()
        .filter_map(|h| match h {
            Hit::Report(r) => match &**r {
                Report::Change(c) => Some(c.clone()),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

/// BOB holds `shop:read` from the `shop` Anchor, to be exercised for ROOT.
async fn for_root_grant(core: &mut Core, d: Digest, nonce: u8) -> (Id, ExerciseBasis) {
    let shop = meta::object_id(&d, kind::ANCHOR, 1);
    let issue = Payload::GrantIssue(GrantContent {
        basis: GrantBasis::Anchor(shop),
        holder: SubjectSelector::Party(BOB),
        authority: authority(vec![action("shop", "read")], selector("shop")),
        agency: BTreeSet::from([Capacity::For(ROOT)]),
        named: None,
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
    (
        grant,
        ExerciseBasis::Holding(HoldingRef {
            grant,
            holder: BOB,
            since: issued.record.unwrap(),
        }),
    )
}

// §8.17.7.1, X6, XI-10, XI-9, XI-22, S6, IA-2, SI-21, U26, SI-13, XI-5
#[tokio::test]
async fn the_hub_reads_only_the_viewers_own_slice() {
    use access_authority_core::app::hub::{Group, Holder};
    use access_authority_core::app::management::{ChangeKind, Changed};
    let db = fresh().await.unwrap();
    let (mut core, d) = with_ack_issuer(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    define(&mut core, d, 9, &role_set(&["read"], &[])).await;
    let (clerk, alice_holding) = clerk_grant(&mut core, d, 10).await;
    let (for_root, bob_holding) = for_root_grant(&mut core, d, 11).await;
    allowed(
        &send(
            &mut core,
            shop_request(d, 12, Mode::Commit, alice_holding),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let mut on_behalf = shop_request(d, 13, Mode::Commit, bob_holding);
    on_behalf.capacity = Capacity::For(ROOT);
    allowed(&send(&mut core, on_behalf, BOB_KEY).await.unwrap());
    let denied = send(
        &mut core,
        shop_request(d, 14, Mode::Commit, bob_holding),
        ALICE_KEY,
    )
    .await
    .unwrap();
    assert_ne!(denied.decision.outcome, Outcome::Allow);
    let admitted = core.ingest(&key_state(d, ALICE), NOW).await.unwrap();
    assert!(
        matches!(
            admitted.verdict,
            access_internal_api::claims::ClaimVerdict::Admitted { .. }
        ),
        "{admitted:?}"
    );
    let head = core.head();

    let mut nonce = 40u8;
    let mut read = |seed: u8, query: Query| {
        nonce = nonce.wrapping_add(1);
        let kind = query.kind();
        (incoming(search_request(d, nonce, kind), seed), query)
    };

    // §8.17.7.1, XI-10
    let (inc, q) = read(ROOT_KEY, Query::Inventory { party: ROOT });
    let root = core.search(&inc, &q, None, NOW).await.unwrap();
    let rows = holdings(&root);
    let shared = rows.iter().find(|r| r.grant == clerk).unwrap();
    assert_eq!(shared.groups, [Group::SharedFromYou]);
    assert_eq!(shared.holder, Holder::Party(ALICE));
    assert_eq!(shared.capacities, [Capacity::Own]);
    let acting = rows.iter().find(|r| r.grant == for_root).unwrap();
    assert_eq!(acting.groups, [Group::ActingForYou]);
    assert_eq!(acting.capacities, [Capacity::For(ROOT)]);
    assert!(
        entries(&root)
            .iter()
            .any(|e| matches!(e, Entry::Rooted(r) if r.sole)),
        "ROOT roots the Anchors alone"
    );
    let (inc, q) = read(ALICE_KEY, Query::Inventory { party: ALICE });
    let alice = holdings(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert_eq!(alice.len(), 1, "{alice:?}");
    assert_eq!(alice[0].grant, clerk);
    assert_eq!(alice[0].groups, [Group::YourAuthority]);
    assert_eq!(alice[0].named, Some(("clerk".to_owned(), 1)));
    // XI-9, XI-22
    let (inc, q) = read(BOB_KEY, Query::Inventory { party: ALICE });
    assert!(
        core.search(&inc, &q, None, NOW)
            .await
            .unwrap()
            .hits
            .is_empty()
    );

    // S6, §8.17.12
    let (inc, q) = read(ALICE_KEY, Query::Activity { party: ALICE });
    let uses = uses_of(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert!(
        uses.iter()
            .any(|u| u.by_viewer && u.basis == Basis::Grant(clerk)),
        "{uses:?}"
    );
    assert!(
        uses.iter().all(|u| u.basis != Basis::Grant(for_root)),
        "a DENY is not a use"
    );
    let (inc, q) = read(ROOT_KEY, Query::Activity { party: ROOT });
    let uses = uses_of(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert!(
        uses.iter().any(|u| !u.by_viewer
            && u.capacity == Capacity::For(ROOT)
            && u.basis == Basis::Grant(for_root)),
        "{uses:?}"
    );

    // IA-2, SI-21, U26, SI-13
    let (inc, q) = read(ALICE_KEY, Query::Changes { before: None });
    let changes = changes_of(&core.search(&inc, &q, None, NOW).await.unwrap());
    let about: Vec<&Changed> = changes.iter().map(|c| &c.changed).collect();
    assert!(about.contains(&&Changed::Object(clerk)), "{changes:?}");
    assert!(
        !about.contains(&&Changed::Object(for_root)),
        "a Grant neither to nor for ALICE is not her change"
    );
    assert!(
        changes.iter().any(|c| c.kind == ChangeKind::KeyEvent
            && matches!(
                &c.changed,
                Changed::KeyEvent { class, issuer, subject, .. }
                    if class == "party_key_state" && *issuer == BOB && *subject == ALICE
            )),
        "{changes:?}"
    );
    let (inc, q) = read(BOB_KEY, Query::Changes { before: None });
    let changes = changes_of(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert!(
        changes
            .iter()
            .any(|c| c.changed == Changed::Object(for_root))
    );
    assert!(
        !changes.iter().any(|c| c.kind == ChangeKind::KeyEvent),
        "another Party's key events stay out"
    );

    // XI-5, §8.17.7.3
    let preview = Query::RevocationImpact {
        revoked: Revoked::Grant(clerk),
        at: None,
    };
    let (inc, q) = read(ROOT_KEY, preview.clone());
    assert_eq!(
        core.search(&inc, &q, None, NOW).await.unwrap().hits.len(),
        1
    );
    for seed in [ALICE_KEY, BOB_KEY] {
        let (inc, q) = read(seed, preview.clone());
        assert!(
            core.search(&inc, &q, None, NOW)
                .await
                .unwrap()
                .hits
                .is_empty(),
            "only those above the Grant in its lineage preview revoking it"
        );
    }
    assert_eq!(core.head(), head, "the hub reads write nothing");
}

// XI-26, MD-9, X37, SI-21, §8.16
#[tokio::test]
async fn a_support_grant_is_a_visible_delegation() {
    use access_authority_core::app::hub::{Group, Holder};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    let shop_anchor = meta::object_id(&d, kind::ANCHOR, 1);
    let shop = ExerciseBasis::Anchor(shop_anchor);
    let own = send(
        &mut core,
        meta_request(
            d,
            10,
            shop,
            Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(shop_anchor),
                holder: SubjectSelector::Party(BOB),
                authority: authority(vec![action("shop", "read")], selector("shop")),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&own);
    let own_grant = meta::object_id(&own.exercise.unwrap(), kind::GRANT, 0);
    let bob_own = ExerciseBasis::Holding(HoldingRef {
        grant: own_grant,
        holder: BOB,
        since: own.record.unwrap(),
    });
    let for_root = |nonce: u8, basis: ExerciseBasis| {
        let mut r = shop_request(d, nonce, Mode::Commit, basis);
        r.capacity = Capacity::For(ROOT);
        r
    };

    let posed = send(&mut core, for_root(11, bob_own), BOB_KEY)
        .await
        .unwrap();
    assert_ne!(
        posed.decision.outcome,
        Outcome::Allow,
        "without a Grant naming ROOT in its agency, BOB cannot act for ROOT"
    );

    let (support, bob_support) = for_root_grant(&mut core, d, 12).await;
    allowed(
        &send(&mut core, for_root(13, bob_support), BOB_KEY)
            .await
            .unwrap(),
    );

    let mut nonce = 40u8;
    let mut read = |seed: u8, query: Query| {
        nonce = nonce.wrapping_add(1);
        let kind = query.kind();
        (incoming(search_request(d, nonce, kind), seed), query)
    };
    let (inc, q) = read(ROOT_KEY, Query::Inventory { party: ROOT });
    let rows = holdings(&core.search(&inc, &q, None, NOW).await.unwrap());
    let row = rows.iter().find(|r| r.grant == support).unwrap();
    assert_eq!(row.groups, [Group::ActingForYou]);
    assert_eq!(row.holder, Holder::Party(BOB));
    assert_eq!(row.capacities, [Capacity::For(ROOT)]);
    let plain = rows.iter().find(|r| r.grant == own_grant).unwrap();
    assert!(
        !plain.groups.contains(&Group::ActingForYou),
        "a Grant that does not name ROOT does not act for ROOT"
    );
    let (inc, q) = read(ROOT_KEY, Query::Activity { party: ROOT });
    let uses = uses_of(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert!(
        uses.iter().any(|u| !u.by_viewer
            && u.capacity == Capacity::For(ROOT)
            && u.basis == Basis::Grant(support)),
        "{uses:?}"
    );
    assert!(
        uses.iter().all(|u| u.basis != Basis::Grant(own_grant)),
        "the refused attempt is not a use"
    );
    let (inc, q) = read(ROOT_KEY, Query::Changes { before: None });
    let changes = changes_of(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert!(
        changes
            .iter()
            .any(|c| c.changed == Changed::Object(support)),
        "{changes:?}"
    );

    allowed(
        &send(
            &mut core,
            meta_request(d, 14, shop, Payload::GrantRevoke { grant: support }),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let ended = send(&mut core, for_root(15, bob_support), BOB_KEY)
        .await
        .unwrap();
    assert_ne!(ended.decision.outcome, Outcome::Allow);
    let (inc, q) = read(ROOT_KEY, Query::Inventory { party: ROOT });
    let rows = holdings(&core.search(&inc, &q, None, NOW).await.unwrap());
    assert!(rows.iter().all(|r| r.grant != support));
}

/// Genesis where ALICE issues `staff` membership Claims under a `subject-selection` Acceptance;
/// members with `staff = true` hold two Grants to read the shop, the second only with a `staff`
/// statement at most `fresh_ms` old.
fn staffed(fresh_ms: u64) -> BTreeMap<String, Opened> {
    use access_kernel::model::{
        Binding as ProofBinding, Conjunct, Consumption, EqValue, Independence, ProofKind,
        RequirementTerm,
    };
    let mut g = genesis();
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let staff = SubjectSelector::Pred(BTreeSet::from([Conjunct {
        claim_class: "staff".to_owned(),
        value: Some(EqValue::Bool(true)),
    }]));
    let plain = authority(vec![action("shop", "read")], selector("shop"));
    let mut fresh = plain.clone();
    fresh.requirements.insert(RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: "staff".to_owned(),
        count: 1,
        binding: ProofBinding::None,
        freshness_ms: Some(fresh_ms),
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    });
    for a in [plain, fresh] {
        grants.push(Value::Map(vec![
            (Value::text("anchor"), Value::Unsigned(1)),
            (Value::text("holder"), staff.to_value()),
            (Value::text("authority"), a.to_value()),
            (
                Value::text("agency"),
                Value::Array(vec![meta::capacity_value(Capacity::Own)]),
            ),
        ]));
    }
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    let mut all = match g.get("acceptances").map(|o| o.value.clone()) {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    all.push(staff_acceptance(None));
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
    g
}

/// ALICE's `subject-selection` Acceptance of `staff`, with an ingest cutoff when given.
fn staff_acceptance(cutoff: Option<u64>) -> Value {
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
}

/// ALICE's `staff` Claim about ROOT, superseding `supersedes` when given.
fn staff_claim(d: Digest, member: bool, supersedes: Option<Id>) -> Vec<u8> {
    let st = access_kernel::claim::Statement {
        domain: d,
        issuer: ALICE,
        subject: ROOT,
        class: "staff".to_owned(),
        value: Some(access_kernel::model::EqValue::Bool(member)),
        issued_at: NOW,
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
    let with = signing(ALICE_KEY);
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (
                Value::Unsigned(CT),
                Value::text(access_kernel::claim::CONTENT_TYPE),
            ),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public(ALICE_KEY)).to_vec()),
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

async fn staff_inventory(core: &mut Core, d: Digest, nonce: u8, at: u64) -> Vec<HubHolding> {
    let inc = incoming(search_request(d, nonce, "inventory"), ROOT_KEY);
    let found = core
        .search(&inc, &Query::Inventory { party: ROOT }, None, at)
        .await
        .unwrap();
    holdings(&found)
}

async fn prove_staff(core: &mut Core, d: Digest, nonce: u8, claim: Vec<u8>) {
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let mut r = shop_request(d, nonce, Mode::Commit, shop);
    r.proofs = vec![access_authority_core::domain::ProofRef::Claim(claim)];
    allowed(&send(core, r, ROOT_KEY).await.unwrap());
}

fn row_of(rows: &[HubHolding], grant: Id) -> HubHolding {
    rows.iter().find(|r| r.grant == grant).cloned().unwrap()
}

// XI-15, C13, INV-31, OP-153 m.25 (d), §8.17.5.7
#[tokio::test]
async fn the_hub_tells_stale_from_ended_and_a_rejoin_from_a_restore() {
    use access_authority_core::app::hub::{Group, Selection};
    let db = fresh().await.unwrap();
    let d = create_genesis(&db.sequencer, TENANT, staffed(1_000), 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut core: Core = Authority::new(leader, reader, binding(), Counter(0), d);
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    let plain = meta::object_id(&d, kind::GRANT, 1);
    let fresh_only = meta::object_id(&d, kind::GRANT, 2);

    let rows = staff_inventory(&mut core, d, 21, NOW).await;
    let p = row_of(&rows, plain);
    assert_eq!(
        p.selection, None,
        "never selected: neither stale nor removed"
    );
    assert_eq!(p.said, None);
    assert_eq!(p.groups, [Group::SharedFromYou]);

    let joined = staff_claim(d, true, None);
    let joined_id = access_kernel::claim::claim_id(&joined);
    prove_staff(&mut core, d, 22, joined).await;
    let rows = staff_inventory(&mut core, d, 23, NOW).await;
    let p = row_of(&rows, plain);
    let Some(Selection::Current { since: first }) = p.selection else {
        panic!("{p:?}");
    };
    // XI-15, §8.17.5.7, Ek B 3704
    let said = p.said.expect("the selecting statement");
    assert_eq!(said.issuer, ALICE);
    assert_eq!(said.at, NOW);
    assert!(p.groups.contains(&Group::YourAuthority));
    assert_eq!(
        row_of(&rows, fresh_only).selection,
        Some(Selection::Current { since: first })
    );

    // C13
    let rows = staff_inventory(&mut core, d, 24, NOW + 2_000).await;
    assert_eq!(
        row_of(&rows, plain).selection,
        Some(Selection::Current { since: first })
    );
    assert_eq!(
        row_of(&rows, fresh_only).selection,
        Some(Selection::Stale { since: first })
    );

    let left = staff_claim(d, false, Some(joined_id));
    let left_id = access_kernel::claim::claim_id(&left);
    prove_staff(&mut core, d, 25, left).await;
    let rows = staff_inventory(&mut core, d, 26, NOW).await;
    let p = row_of(&rows, plain);
    let Some(Selection::Ended {
        pos: Some(removed),
        at: Some(_),
    }) = p.selection
    else {
        panic!("{p:?}");
    };
    assert!(removed > first);
    assert_eq!(p.said.map(|s| s.issuer), Some(ALICE));
    assert_eq!(row_of(&rows, fresh_only).selection, p.selection);
    assert!(p.groups.contains(&Group::YourAuthority));

    // INV-31
    prove_staff(&mut core, d, 27, staff_claim(d, true, Some(left_id))).await;
    let rows = staff_inventory(&mut core, d, 28, NOW).await;
    let p = row_of(&rows, plain);
    let Some(Selection::Current { since: again }) = p.selection else {
        panic!("{p:?}");
    };
    assert!(again > removed, "a rejoin is a new episode");
    let restored = send(
        &mut core,
        shop_request(
            d,
            29,
            Mode::Check,
            ExerciseBasis::Holding(HoldingRef {
                grant: plain,
                holder: ROOT,
                since: first,
            }),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_ne!(restored.decision.outcome, Outcome::Allow);

    let rows = staff_inventory(&mut core, d, 30, 1_000_001).await;
    let p = row_of(&rows, plain);
    assert_eq!(
        p.selection,
        Some(Selection::Ended {
            pos: None,
            at: Some(1_000_000)
        }),
        "an expired membership Claim ended the episode"
    );
    assert_eq!(
        row_of(&rows, fresh_only).selection,
        p.selection,
        "expired is ended, not stale"
    );

    // OP-141 m.42
    let state = access_store::authority::state_of(
        &db.app,
        &DomainId::from_bytes(d.0),
        &[meta::key(kind::ACCEPTANCES, &ALICE)],
    )
    .await
    .unwrap();
    let Value::Array(ids) =
        dcbor::decode(state[0].value.as_deref().unwrap(), Limits::CEILING).unwrap()
    else {
        panic!("acceptance index");
    };
    let amend = Payload::AcceptanceAmend {
        acceptance: Id::from_value(&ids[0]).unwrap(),
        content: staff_acceptance(Some(NOW + 100)),
    };
    allowed(
        &send(
            &mut core,
            meta_request(d, 31, meta_anchor(d), amend),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let rows = staff_inventory(&mut core, d, 32, NOW + 200).await;
    assert_eq!(
        row_of(&rows, plain).selection,
        Some(Selection::Ended {
            pos: None,
            at: Some(NOW + 100)
        }),
        "a cutoff ended the episode"
    );
}
