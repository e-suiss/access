//! CMP-8, §9.13: Claim Ingest end to end on a real PostgreSQL: carriers, dispositions, quota,
//! designation and resubmission.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

#[path = "ingest/compromise.rs"]
mod compromise;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use access_authority_core::CoreError;
use access_authority_core::adapters::{Domains, PgReader, Setup};
use access_authority_core::app::{Authority, Incoming, Response};
use access_authority_core::domain::Request;
use access_authority_core::ports::{Binding, Keys, Salts};
use access_authority_ingest::domain::{binding_value, context_bytes, subject_digest};
use access_authority_ingest::ports::Ledger;
use access_authority_sequencer::SequencerError;
use access_authority_sequencer::adapters::{PgLog, create_genesis};
use access_authority_sequencer::app::Leader;
use access_authority_sequencer::ports::Clock;
use access_crypto::event_id::EventKey;
use access_crypto::secret::Secret;
use access_internal_api::claims::{Carrier, ClaimSubmission, ClaimVerdict, Quarantine};
use access_kernel::ais::{CONTENT_TYPE, Statement as Ais};
use access_kernel::claim::Statement;
use access_kernel::claim::body::{
    AuthenticatorBinding, AuthenticatorKind, Body, Class, PartyKeyState,
};
use access_kernel::codec::Canonical;
use access_kernel::combinator::{Capacity, Mode, Outcome};
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{self, ActorKind, ExerciseBasis, HoldingRef, Payload, Root, kind};
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, CanonicalAuthority, ConstraintSet, DelegationTerms,
    EqValue, Id, ResourceRef, ResourceSelector, Structural, SubjectSelector, Window,
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
const BOB: Id = Id([3; 16]);
const REGIME: Id = Id([4; 16]);
const IDP: Id = Id([5; 16]);
const ROOT_KEY: u8 = 11;
const ALICE_KEY: u8 = 12;
const BOB_KEY: u8 = 13;
const REGIME_KEY: u8 = 14;
const IDP_KEY: u8 = 30;
const PEP: &str = "pep.example";
const NOW: u64 = 10_000;
const ISS: &str = "https://idp.example";

fn signing(seed: u8) -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
}

fn public(seed: u8) -> PublicKey {
    PublicKey::Ed25519(signing(seed).verifying_key().to_bytes())
}

fn action(name: &str) -> ActionRef {
    ActionRef {
        namespace: "access".to_owned(),
        name: name.to_owned(),
        major: 1,
        schema: access_kernel::schema::action_digest(&access_kernel::schema::ActionSchema {
            reversibility: None,
            name: name.to_owned(),
            major: 1,
            effect: access_kernel::schema::EffectClass::Reversible,
            reserved: false,
            consumption_bearing: false,
            params: BTreeMap::new(),
            resource_types: BTreeSet::new(),
            render: None,
        }),
    }
}

fn window() -> Value {
    Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)])
}

fn acceptance(issuer: Id, use_: &str, classes: &[&str], extra: Vec<(&str, Value)>) -> Value {
    let mut m = vec![
        (Value::text("issuer"), issuer.to_value()),
        (Value::text("use"), Value::text(use_)),
        (
            Value::text("classes"),
            Value::Array(classes.iter().map(|c| Value::text(c)).collect()),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (Value::text("validity"), window()),
    ];
    m.extend(extra.into_iter().map(|(k, v)| (Value::text(k), v)));
    m.sort_by(|a, b| {
        let ka = dcbor::encode(&a.0, Limits::CEILING).unwrap();
        let kb = dcbor::encode(&b.0, Limits::CEILING).unwrap();
        ka.cmp(&kb)
    });
    Value::Map(m)
}

fn quota(count: u64) -> (&'static str, Value) {
    (
        "quota",
        Value::Map(vec![
            (Value::text("count"), Value::Unsigned(count)),
            (Value::text("window_s"), Value::Unsigned(3_600)),
        ]),
    )
}

fn pinned() -> (&'static str, Value) {
    (
        "pinned",
        Value::Map(vec![
            (Value::text("iss"), Value::text(ISS)),
            (Value::text("aud"), Value::text("access")),
            (
                Value::text("keys"),
                Value::Array(vec![public(IDP_KEY).to_value()]),
            ),
        ]),
    )
}

/// A Grant held by `holder` on the meta-anchor for `actions` on `namespace`.
fn grant(holder: &SubjectSelector, actions: &[&str], namespace: &str) -> Value {
    Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(0)),
        (Value::text("holder"), holder.to_value()),
        (
            Value::text("authority"),
            CanonicalAuthority {
                authority: AuthoritySet {
                    actions: ActionSet {
                        exact: actions.iter().map(|a| action(a)).collect(),
                        prefix: BTreeSet::new(),
                    },
                    resource: ResourceSelector::Structural(Structural {
                        namespace: namespace.to_owned(),
                        prefix: Vec::new(),
                        kind: None,
                        attrs: BTreeMap::new(),
                    }),
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
            .to_value(),
        ),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ])
}

/// The Genesis of these tests: two Grants, then `extra`, as a sorted set.
fn genesis_with(acceptances: Vec<Value>, extra: Vec<Value>) -> BTreeMap<String, Opened> {
    let opened = |value| Opened {
        value,
        salt: [3; 32],
    };
    let mut grants = vec![
        grant(
            &SubjectSelector::Public,
            &["party_register", "instance_create"],
            "access.party",
        ),
        grant(&SubjectSelector::Party(ALICE), &["read"], "access.party"),
    ];
    if !extra.is_empty() {
        grants.extend(extra);
        grants.sort_by_key(|g| dcbor::encode(g, Limits::CEILING).unwrap());
    }
    let mut keyed: Vec<(Vec<u8>, Value)> = acceptances
        .into_iter()
        .map(|v| (dcbor::encode(&v, Limits::CEILING).unwrap(), v))
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    BTreeMap::from([
        (
            "meta_anchor".to_owned(),
            opened(Value::Map(vec![(
                Value::text("root"),
                Value::Map(vec![(Value::text("sole"), ROOT.to_value())]),
            )])),
        ),
        ("grants".to_owned(), opened(Value::Array(grants))),
        (
            "acceptances".to_owned(),
            opened(Value::Array(keyed.into_iter().map(|(_, v)| v).collect())),
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

fn binding() -> Bound {
    Bound(
        [
            (ROOT, ROOT_KEY),
            (ALICE, ALICE_KEY),
            (BOB, BOB_KEY),
            (REGIME, REGIME_KEY),
            (ALICE, 50),
            (ALICE, 51),
        ]
        .into_iter()
        .map(|(p, k)| (thumbprint(&public(k)), (p, public(k))))
        .collect(),
    )
}

async fn setup(db: &TestDb, acceptances: Vec<Value>) -> (Core, Digest) {
    setup_with(db, acceptances, Vec::new()).await
}

/// [`setup`] over [`genesis_with`].
async fn setup_with(db: &TestDb, acceptances: Vec<Value>, extra: Vec<Value>) -> (Core, Digest) {
    let d = create_genesis(
        &db.sequencer,
        TENANT,
        genesis_with(acceptances, extra),
        1_000,
    )
    .await
    .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut core = Authority::new(leader, reader, binding(), Counter(0), d);
    for (party, key, nonces) in [
        (ALICE, ALICE_KEY, (1, 2)),
        (BOB, BOB_KEY, (3, 4)),
        (REGIME, REGIME_KEY, (5, 6)),
    ] {
        onboard(&mut core, d, party, key, nonces).await;
    }
    core.release().await.unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    (Authority::new(leader, reader, binding(), Counter(9), d), d)
}

fn cose(payload: Vec<u8>, content_type: &str, seed: u8) -> Vec<u8> {
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

async fn onboard(core: &mut Core, d: Digest, party: Id, seed: u8, nonces: (u8, u8)) {
    let basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let register = Payload::PartyRegister {
        party,
        root: Root::Sole(party),
        actor_kind: ActorKind::Human,
    };
    let create = Payload::InstanceCreate {
        party,
        key: public(seed),
        mandate: None,
    };
    for (nonce, payload) in [(nonces.0, register), (nonces.1, create)] {
        let r = send(core, request(d, nonce, basis, payload), seed)
            .await
            .unwrap();
        assert_eq!(r.decision.outcome, Outcome::Allow, "{r:?}");
    }
}

fn request(d: Digest, nonce: u8, basis: ExerciseBasis, payload: Payload) -> Request {
    Request {
        domain: d,
        mode: Mode::Commit,
        nonce: vec![nonce; 16],
        intent: IntentEnvelope {
            provenance: BTreeMap::new(),
            action: action(payload.action()),
            resources: vec![ResourceRef {
                namespace: "access.party".to_owned(),
                path: vec!["p".to_owned()],
                incarnation: 0,
            }],
            params: BTreeMap::new(),
            opaque: BTreeMap::from([("payload".to_owned(), payload.digest().unwrap())]),
            recipient: None,
            purpose: None,
            context: ContextRefs::default(),
            validity: Window {
                from: 0,
                until: 1_000_000,
            },
        },
        payload: Some(payload),
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

async fn send(core: &mut Core, request: Request, seed: u8) -> Result<Response, CoreError> {
    send_at(core, request, seed, NOW).await
}

async fn send_at(
    core: &mut Core,
    request: Request,
    seed: u8,
    now: u64,
) -> Result<Response, CoreError> {
    let digest = access_kernel::intent::intent_digest(&request.intent).unwrap();
    let ais = Ais {
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
        ais: Some(cose(ais.to_bytes().unwrap(), CONTENT_TYPE, seed)),
        request,
        pep: PEP.to_owned(),
        requester: None,
        explain: false,
        status: None,
        context: None,
    };
    core.exercise(&inc, now).await
}

fn statement(d: Digest, issuer: Id, subject: Id, class: &str, value: EqValue) -> Statement {
    Statement {
        domain: d,
        issuer,
        subject,
        class: class.to_owned(),
        value: Some(value),
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
    }
}

fn submit(d: Digest, carrier: Carrier, claim: Vec<u8>, body: Option<Vec<u8>>) -> ClaimSubmission {
    ClaimSubmission {
        domain: d,
        carrier,
        claim,
        body,
        evidence: None,
    }
}

fn signed(s: &Statement, seed: u8) -> ClaimSubmission {
    submit(
        s.domain,
        Carrier::Cose,
        cose(
            s.to_bytes().unwrap(),
            access_kernel::claim::CONTENT_TYPE,
            seed,
        ),
        None,
    )
}

/// A Claim whose class has a body: its value is the body's digest and the body travels with it.
fn with_body(mut s: Statement, body: &Body, seed: u8) -> ClaimSubmission {
    let class = Class::parse(&s.class).unwrap();
    let v = body.to_value();
    s.value = Some(EqValue::Bytes(
        access_kernel::claim::body::body_digest(class, &v)
            .unwrap()
            .to_vec(),
    ));
    let mut sub = signed(&s, seed);
    sub.body = Some(dcbor::encode(&v, Limits::CEILING).unwrap());
    sub
}

fn kyc(d: Digest, issuer: Id, n: u8) -> Statement {
    statement(d, issuer, ROOT, "kyc", EqValue::Int(i64::from(n)))
}

// CMP-8, L2-CLM-3, L2-CLM-4, INV-2, PI-22, §9.13 rule 3
#[tokio::test]
async fn ingest_admits_holds_or_refuses() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![acceptance(ALICE, "predicate-input", &["kyc"], vec![])],
    )
    .await;
    let sub = signed(&kyc(d, ALICE, 1), ALICE_KEY);
    let ClaimVerdict::Admitted {
        claim,
        position,
        replayed: false,
    } = core.ingest(&sub, NOW).await.unwrap().verdict
    else {
        panic!("admitted");
    };
    assert_eq!(
        core.ingest(&sub, NOW).await.unwrap().verdict,
        ClaimVerdict::Admitted {
            claim,
            position,
            replayed: true
        }
    );
    let held = core
        .ingest(&signed(&kyc(d, BOB, 1), BOB_KEY), NOW)
        .await
        .unwrap();
    assert!(matches!(
        held.verdict,
        ClaimVerdict::Quarantined {
            reason: Quarantine::SourceNotAccepted,
            ..
        }
    ));
    assert_eq!(held.issuer, BOB);
    let forged = signed(&kyc(d, ALICE, 2), BOB_KEY);
    assert_eq!(
        core.ingest(&forged, NOW).await.unwrap().verdict,
        ClaimVerdict::Rejected {
            code: "claim-payload".to_owned()
        }
    );
    let before = core.head();
    let unknown = signed(&kyc(d, ALICE, 3), 99);
    assert_eq!(
        core.ingest(&unknown, NOW).await.unwrap().verdict,
        ClaimVerdict::Rejected {
            code: "claim-signature".to_owned()
        }
    );
    assert_eq!(core.head(), before);
}

// G44, P19, §13.7.4
#[tokio::test]
async fn the_issuer_quota_holds_only_qualifying_claims() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![acceptance(
            ALICE,
            "predicate-input",
            &["kyc", "account_status"],
            vec![quota(1)],
        )],
    )
    .await;
    for n in 1..=2 {
        let v = core
            .ingest(&signed(&kyc(d, ALICE, n), ALICE_KEY), NOW)
            .await
            .unwrap();
        assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    }
    let over = core
        .ingest(&signed(&kyc(d, ALICE, 3), ALICE_KEY), NOW)
        .await
        .unwrap();
    assert!(matches!(
        over.verdict,
        ClaimVerdict::Quarantined {
            reason: Quarantine::Quota,
            ..
        }
    ));
    assert_eq!(over.quota, Some((0, 3_600_000)));
    let suspended = statement(
        d,
        ALICE,
        ROOT,
        "account_status",
        EqValue::Text("suspended".to_owned()),
    );
    let v = core
        .ingest(&signed(&suspended, ALICE_KEY), NOW)
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
}

fn key_state(d: Digest, designated: &[Id]) -> ClaimSubmission {
    let body = Body::PartyKeyState(PartyKeyState {
        sequence: 1,
        keys: BTreeSet::from([Digest([8; 32])]),
        designated: BTreeMap::from([(
            "authenticator_binding".to_owned(),
            designated.iter().copied().collect(),
        )]),
    });
    with_body(
        statement(d, REGIME, ROOT, "party_key_state", EqValue::Bool(true)),
        &body,
        REGIME_KEY,
    )
}

fn passkey(d: Digest, issuer: Id, seed: u8) -> ClaimSubmission {
    let body = Body::AuthenticatorBinding(AuthenticatorBinding {
        kind: AuthenticatorKind::Passkey,
        material: Digest([issuer.0[0]; 32]),
        alg: Some(-7),
        attestation: None,
        aaguid: None,
        be: true,
        transports: BTreeSet::new(),
    });
    let mut sub = with_body(
        statement(
            d,
            issuer,
            ROOT,
            "authenticator_binding",
            EqValue::Bool(true),
        ),
        &body,
        seed,
    );
    sub.carrier = Carrier::Webauthn;
    sub
}

/// BOB's `controller_of` Claim about ROOT naming `controller`.
fn controller_of(d: Digest, controller: Id) -> ClaimSubmission {
    signed(
        &statement(
            d,
            BOB,
            ROOT,
            "controller_of",
            EqValue::Bytes(controller.0.to_vec()),
        ),
        BOB_KEY,
    )
}

// P21, §9.13.1 and, E18, U26, OP-152 m.7 (d)
#[tokio::test]
async fn designation_and_acceptance_must_both_hold() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![
            acceptance(ALICE, "actor-binding", &["authenticator_binding"], vec![]),
            acceptance(
                BOB,
                "actor-binding",
                &["controller_of", "authenticator_binding"],
                vec![],
            ),
            acceptance(REGIME, "actor-binding", &["party_key_state"], vec![]),
        ],
    )
    .await;
    let v = core
        .ingest(&passkey(d, ALICE, ALICE_KEY), NOW)
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    let c = core.ingest(&controller_of(d, REGIME), NOW).await.unwrap();
    assert!(matches!(c.verdict, ClaimVerdict::Admitted { .. }), "{c:?}");
    let ks = core.ingest(&key_state(d, &[BOB]), NOW).await.unwrap();
    assert!(
        matches!(ks.verdict, ClaimVerdict::Admitted { .. }),
        "{ks:?}"
    );
    let mut again = passkey(d, ALICE, ALICE_KEY);
    again.claim = passkey_variant(d, ALICE, ALICE_KEY);
    let v = core.ingest(&again, NOW).await.unwrap();
    assert!(
        matches!(
            v.verdict,
            ClaimVerdict::Quarantined {
                reason: Quarantine::SourceNotAccepted,
                ..
            }
        ),
        "{v:?}"
    );
    let v = core.ingest(&passkey(d, BOB, BOB_KEY), NOW).await.unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    let mut plain = passkey(d, BOB, BOB_KEY);
    plain.body = None;
    assert_eq!(
        core.ingest(&plain, NOW).await.unwrap().verdict,
        ClaimVerdict::Rejected {
            code: "claim-carrier".to_owned()
        }
    );
}

// OP-152 m.7 (d), §9.13.1, §10.1.5
#[tokio::test]
async fn only_the_named_controllers_key_state_designates() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![
            acceptance(ALICE, "actor-binding", &["authenticator_binding"], vec![]),
            acceptance(BOB, "actor-binding", &["controller_of"], vec![]),
            acceptance(REGIME, "actor-binding", &["party_key_state"], vec![]),
        ],
    )
    .await;
    let ks = core.ingest(&key_state(d, &[BOB]), NOW).await.unwrap();
    assert!(
        matches!(ks.verdict, ClaimVerdict::Admitted { .. }),
        "{ks:?}"
    );
    let v = core
        .ingest(&passkey(d, ALICE, ALICE_KEY), NOW)
        .await
        .unwrap();
    assert!(
        matches!(v.verdict, ClaimVerdict::Admitted { .. }),
        "no controller named: the key-state designates nobody, {v:?}"
    );
    let c = core.ingest(&controller_of(d, ALICE), NOW).await.unwrap();
    assert!(matches!(c.verdict, ClaimVerdict::Admitted { .. }), "{c:?}");
    let mut again = passkey(d, ALICE, ALICE_KEY);
    again.claim = passkey_variant(d, ALICE, ALICE_KEY);
    let v = core.ingest(&again, NOW).await.unwrap();
    assert!(
        matches!(v.verdict, ClaimVerdict::Admitted { .. }),
        "another Party's key-state is no designation, {v:?}"
    );
}

/// The same binding Claim signed at another time, so it has another `ClaimID`.
fn passkey_variant(d: Digest, issuer: Id, seed: u8) -> Vec<u8> {
    let sub = passkey(d, issuer, seed);
    let st = access_kernel::claim::verify(&sub.claim, &public(seed), &issuer, &d).unwrap();
    let st = Statement {
        issued_at: NOW - 1,
        ..st
    };
    cose(
        st.to_bytes().unwrap(),
        access_kernel::claim::CONTENT_TYPE,
        seed,
    )
}

fn id_token(sub: &str, seed: u8) -> Vec<u8> {
    let kid = b64url_encode(&thumbprint(&public(seed)));
    let header = format!(r#"{{"alg":"Ed25519","kid":"{kid}","typ":"JWT"}}"#);
    let payload = format!(
        r#"{{"iss":"{ISS}","aud":"access","sub":"{sub}","iat":10,"exp":900,"amr":["pwd"]}}"#
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = signing(seed).sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(&sig.to_bytes())).into_bytes()
}

// B7, P-ID-2, E18, INV-12, G45, IDI-9, §9.13, §10.1.1
#[tokio::test]
async fn an_external_idp_enters_through_its_pinned_acceptance() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![
            acceptance(IDP, "actor-binding", &["authentication"], vec![pinned()]),
            acceptance(ALICE, "actor-binding", &["identity_binding_person"], vec![]),
        ],
    )
    .await;
    let token = id_token("u-1", IDP_KEY);
    let ctx = Some(context_bytes(&ROOT));
    assert_eq!(
        core.ingest(&submit(d, Carrier::Oidc, token.clone(), ctx.clone()), NOW)
            .await
            .unwrap()
            .verdict,
        ClaimVerdict::Rejected {
            code: "claim-subject".to_owned()
        }
    );
    let bind = statement(
        d,
        ALICE,
        ROOT,
        "identity_binding_person",
        binding_value(&subject_digest(ISS, "u-1")).unwrap(),
    );
    let v = core.ingest(&signed(&bind, ALICE_KEY), NOW).await.unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    let v = core
        .ingest(&submit(d, Carrier::Oidc, token, ctx.clone()), NOW)
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    assert_eq!((v.issuer, v.class.as_str()), (IDP, "authentication"));
    let other = id_token("u-1", 31);
    assert_eq!(
        core.ingest(&submit(d, Carrier::Oidc, other, ctx), NOW)
            .await
            .unwrap()
            .verdict,
        ClaimVerdict::Rejected {
            code: "claim-issuer".to_owned()
        }
    );
    let elsewhere = id_token("u-2", IDP_KEY);
    assert_eq!(
        core.ingest(
            &submit(d, Carrier::Oidc, elsewhere, Some(context_bytes(&ROOT))),
            NOW
        )
        .await
        .unwrap()
        .verdict,
        ClaimVerdict::Rejected {
            code: "claim-subject".to_owned()
        }
    );
}

// §9.13.2, §9.17.4, E3, E24, PI-13, OP-155 m.3 (q), Ek B 4868
#[tokio::test]
async fn a_domain_whose_only_actor_binding_issuer_is_an_external_idp_commits_exercises() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![
            acceptance(IDP, "actor-binding", &["authentication"], vec![pinned()]),
            acceptance(BOB, "predicate-input", &["identity_binding_person"], vec![]),
        ],
    )
    .await;
    let issuers = core.assertion_issuers(ISS, NOW).await.unwrap();
    assert_eq!(issuers.len(), 1);
    assert_eq!(issuers[0].0, IDP);
    for realm in [
        "https://access.test/realms/acme",
        "https://acme.access.test",
    ] {
        assert!(
            core.assertion_issuers(realm, NOW).await.unwrap().is_empty(),
            "no Suiss realm issuer is accepted: {realm}"
        );
    }

    let bind = statement(
        d,
        BOB,
        ALICE,
        "identity_binding_person",
        binding_value(&subject_digest(ISS, "alice@external")).unwrap(),
    );
    let v = core.ingest(&signed(&bind, BOB_KEY), NOW).await.unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    let token = id_token("alice@external", IDP_KEY);
    let v = core
        .ingest(
            &submit(d, Carrier::Oidc, token, Some(context_bytes(&ALICE))),
            NOW,
        )
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    assert_eq!((v.issuer, v.class.as_str()), (IDP, "authentication"));

    let held = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&d, kind::GRANT, 1),
        holder: ALICE,
        since: 0,
    });
    let mut read = request(
        d,
        40,
        held,
        Payload::PartyRegister {
            party: ALICE,
            root: Root::Sole(ALICE),
            actor_kind: ActorKind::Human,
        },
    );
    read.payload = None;
    read.intent.action = action("read");
    read.intent.opaque = BTreeMap::new();
    let r = send(&mut core, read, ALICE_KEY).await.unwrap();
    assert_eq!(r.decision.outcome, Outcome::Allow, "{r:?}");
    assert!(r.exercise.is_some() && r.record.is_some(), "{r:?}");
    let other = id_token("alice@external", 31);
    assert_eq!(
        core.ingest(
            &submit(d, Carrier::Oidc, other, Some(context_bytes(&ALICE))),
            NOW
        )
        .await
        .unwrap()
        .verdict,
        ClaimVerdict::Rejected {
            code: "claim-issuer".to_owned()
        }
    );
}

#[derive(Clone)]
struct Listed(Digest);

impl Keys for Listed {
    fn event_key(&self, domain: &Digest) -> Result<EventKey, CoreError> {
        if *domain == self.0 {
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

// L2-CLM-3, §9.13 rule 3, G44, §16.7
#[tokio::test]
async fn the_ledger_indexes_held_claims_and_quota_notices() {
    let db = fresh().await.unwrap();
    let (core, d) = setup(
        &db,
        vec![acceptance(
            ALICE,
            "predicate-input",
            &["kyc"],
            vec![quota(1)],
        )],
    )
    .await;
    core.release().await.unwrap();
    let domains = Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(d),
        holder: "ingest".to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(40),
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: None,
        api_base: "https://api.example".to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    });
    let held = signed(&kyc(d, BOB, 1), BOB_KEY);
    let first = domains.record(held.clone(), false).await.unwrap();
    let ClaimVerdict::Quarantined { claim, .. } = first.clone() else {
        panic!("{first:?}");
    };
    assert_eq!(domains.record(held, true).await.unwrap(), first);
    let rows = access_store::claims::quarantined(&db.app, &DomainId::from_bytes(d.0), &claim.0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason, "source-not-accepted");
    let before = access_telemetry::counters::ISSUER_QUOTA.get();
    for n in 1..=4 {
        domains
            .record(signed(&kyc(d, ALICE, n), ALICE_KEY), false)
            .await
            .unwrap();
    }
    assert_eq!(access_telemetry::counters::ISSUER_QUOTA.get(), before + 1);
    domains.release().await;
}

/// `party` (acting with key `actor`) asks to add an Instance with key `new`, at `now`: its
/// outcome and the subcode of its first blocker.
async fn add_key(
    core: &mut Core,
    d: Digest,
    (party, actor): (Id, u8),
    (new, nonce): (u8, u8),
    now: u64,
) -> (Outcome, Option<String>) {
    let basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    let create = Payload::InstanceCreate {
        party,
        key: public(new),
        mandate: None,
    };
    let r = send_at(core, request(d, nonce, basis, create), actor, now)
        .await
        .unwrap();
    let subcode = r.decision.blockers.first().and_then(|b| b.subcode.clone());
    (r.decision.outcome, subcode)
}

/// ALICE, by key `seed`, reads under her Grant, at `now`: an Exercise of an existing Instance
/// that needs no approval (OP-141 m.39 (a)).
async fn act(
    core: &mut Core,
    d: Digest,
    seed: u8,
    nonce: u8,
    now: u64,
) -> (Outcome, Option<String>) {
    let basis = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&d, kind::GRANT, 1),
        holder: ALICE,
        since: 0,
    });
    let mut r = request(
        d,
        nonce,
        basis,
        Payload::InstanceTerminate { instance: ALICE },
    );
    r.intent.action = action("read");
    r.intent.opaque = BTreeMap::new();
    r.payload = None;
    let r = send_at(core, r, seed, now).await.unwrap();
    let subcode = r.decision.blockers.first().and_then(|b| b.subcode.clone());
    (r.decision.outcome, subcode)
}

fn regime_acceptance() -> Value {
    acceptance(
        REGIME,
        "predicate-input",
        &[
            "account_status",
            "party_recovered",
            "party_compromise",
            "party_terminated",
            "party_identity_break",
        ],
        vec![],
    )
}

fn status(d: Digest, party: Id, value: &str, issued_at: u64, supersedes: Option<Id>) -> Statement {
    Statement {
        issued_at,
        supersedes,
        ..statement(
            d,
            REGIME,
            party,
            "account_status",
            EqValue::Text(value.to_owned()),
        )
    }
}

// TN-49, TN-50, SEC12, X36, E5, CI-2, TI-RT7, G36
// PI-22
#[tokio::test]
async fn account_status_overlays_the_party_until_superseded() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db, vec![regime_acceptance()]).await;
    assert_eq!(
        add_key(&mut core, d, (ALICE, ALICE_KEY), (50, 20), NOW)
            .await
            .0,
        Outcome::Allow
    );
    let suspended = signed(&status(d, ALICE, "suspended", NOW, None), REGIME_KEY);
    let ClaimVerdict::Admitted { claim, .. } = core.ingest(&suspended, NOW).await.unwrap().verdict
    else {
        panic!("admitted");
    };
    assert_eq!(
        add_key(&mut core, d, (ALICE, ALICE_KEY), (51, 21), NOW).await,
        (Outcome::Deny, Some("account-status".to_owned()))
    );
    // OP-149 m.7, m.19 (f)
    let events: Vec<_> =
        access_store::authority::read_outbox(&db.app, &DomainId::from_bytes(d.0), (0, 0), 100)
            .await
            .unwrap()
            .into_iter()
            .map(|r| access_internal_api::events::Event::from_bytes(&r.event).unwrap())
            .filter(|e| e.kind == access_internal_api::events::Kind::PartyDisabled)
            .collect();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].detail,
        access_internal_api::events::Detail::Disabled {
            reason: access_internal_api::events::ReasonClass::Suspended
        }
    );
    assert_eq!(
        events[0].subject,
        access_internal_api::events::Subject::Party(ALICE)
    );
    let unordered = signed(&status(d, ALICE, "active", NOW - 1, None), REGIME_KEY);
    core.ingest(&unordered, NOW).await.unwrap();
    assert_eq!(
        add_key(&mut core, d, (ALICE, ALICE_KEY), (51, 22), NOW)
            .await
            .0,
        Outcome::Deny
    );
    let active = signed(&status(d, ALICE, "active", NOW, Some(claim)), REGIME_KEY);
    core.ingest(&active, NOW).await.unwrap();
    assert_eq!(
        add_key(&mut core, d, (ALICE, ALICE_KEY), (51, 23), NOW)
            .await
            .0,
        Outcome::Allow
    );
}

// §7.9.2.4, §10.1.5, E5
#[tokio::test]
async fn termination_and_identity_break_restrict_instances() {
    // EI-7
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db, vec![regime_acceptance()]).await;
    let terminated = statement(d, REGIME, BOB, "party_terminated", EqValue::Int(5_000));
    core.ingest(&signed(&terminated, REGIME_KEY), NOW)
        .await
        .unwrap();
    assert_eq!(
        add_key(&mut core, d, (BOB, BOB_KEY), (52, 30), NOW).await,
        (Outcome::Deny, Some("party-terminated".to_owned()))
    );
    assert_eq!(
        act(&mut core, d, ALICE_KEY, 32, NOW).await.0,
        Outcome::Allow
    );
    let broken = statement(
        d,
        REGIME,
        ALICE,
        "party_identity_break",
        EqValue::Text("key_loss".to_owned()),
    );
    core.ingest(&signed(&broken, REGIME_KEY), NOW)
        .await
        .unwrap();
    assert_eq!(
        act(&mut core, d, ALICE_KEY, 31, NOW).await,
        (Outcome::Deny, Some("party-identity-break".to_owned()))
    );
}

// SEC12, §7.9.2.3, §7.9.2.4
#[tokio::test]
async fn party_recovery_frees_only_instances_created_after_it() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(&db, vec![regime_acceptance()]).await;
    let compromise = Statement {
        issued_at: 20_000,
        ..statement(d, REGIME, ALICE, "party_compromise", EqValue::Int(20_000))
    };
    core.ingest(&signed(&compromise, REGIME_KEY), 25_000)
        .await
        .unwrap();
    assert_eq!(
        add_key(&mut core, d, (ALICE, ALICE_KEY), (50, 40), 30_000)
            .await
            .0,
        Outcome::Allow
    );
    assert_eq!(
        act(&mut core, d, 50, 41, 30_000).await,
        (Outcome::Deny, Some("party-compromise".to_owned()))
    );
    let recovered = Statement {
        issued_at: 30_000,
        ..statement(d, REGIME, ALICE, "party_recovered", EqValue::Bool(true))
    };
    let body = Body::PartyRecovered(access_kernel::claim::body::PartyRecovered {
        previous: Digest([1; 32]),
        next: Digest([2; 32]),
    });
    let v = core
        .ingest(&with_body(recovered, &body, REGIME_KEY), 30_000)
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    assert_eq!(
        add_key(&mut core, d, (ALICE, ALICE_KEY), (51, 42), 31_000)
            .await
            .0,
        Outcome::Allow
    );
    assert_eq!(act(&mut core, d, 51, 43, 31_000).await.0, Outcome::Allow);
    assert_eq!(act(&mut core, d, 50, 44, 31_000).await.0, Outcome::Deny);
}

// §9.12.3, §9.12.4, E30, P28, INV-21, PI-9
#[tokio::test]
async fn an_authority_state_ack_is_recorded_and_widens_nothing() {
    use access_kernel::claim::body::{AckEvent, AckScope, AuthorityStateAck};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![acceptance(
            BOB,
            "predicate-input",
            &["authority_state_ack"],
            vec![],
        )],
    )
    .await;
    let scope = DomainId::from_bytes(d.0);
    let before = act(&mut core, d, ALICE_KEY, 30, NOW).await;
    assert_eq!(before.0, Outcome::Allow);
    let events = access_store::authority::read_outbox(&db.app, &scope, (0, 0), 100)
        .await
        .unwrap()
        .len();
    let ack = Body::AuthorityStateAck(AuthorityStateAck {
        pep: PEP.to_owned(),
        event: AckEvent::Exercise(Digest([9; 32])),
        applied_at: NOW,
        clock_evidence: None,
        basis: 3,
        scope: BTreeSet::from([AckScope::Cache, AckScope::Token]),
    });
    let s = statement(d, BOB, ALICE, "authority_state_ack", EqValue::Int(0));
    assert!(matches!(
        core.ingest(&with_body(s, &ack, BOB_KEY), NOW)
            .await
            .unwrap()
            .verdict,
        ClaimVerdict::Admitted {
            replayed: false,
            ..
        }
    ));
    assert_eq!(
        access_store::authority::read_outbox(&db.app, &scope, (0, 0), 100)
            .await
            .unwrap()
            .len(),
        events
    );
    assert_eq!(act(&mut core, d, ALICE_KEY, 31, NOW).await, before);
}

/// An upstream ID token of `sub` issued at `iat` seconds, signed by the key `seed`.
fn id_token_at(sub: &str, iat: u64, seed: u8) -> Vec<u8> {
    let kid = b64url_encode(&thumbprint(&public(seed)));
    let header = format!(r#"{{"alg":"Ed25519","kid":"{kid}","typ":"JWT"}}"#);
    let payload = format!(
        r#"{{"iss":"{ISS}","aud":"access","sub":"{sub}","iat":{iat},"exp":900,"amr":["pwd"]}}"#
    );
    let input = format!(
        "{}.{}",
        b64url_encode(header.as_bytes()),
        b64url_encode(payload.as_bytes())
    );
    let sig = signing(seed).sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(&sig.to_bytes())).into_bytes()
}

/// A realm whose issuer is [`ISS`], with a decided drop of `kid` declaring `cutoff_at`, in a
/// tenant and governing domain of its own (OP-150 m.11 (c)).
async fn dropped_realm_key(db: &TestDb, kid: [u8; 32], cutoff_at: u64) {
    use access_store::authority::{
        CommitBatch, HeadRow, LogRecord, NonceRow, acquire_lease, commit_batch, create_domain,
    };
    use access_store::identity::TenantTx;
    use access_store::idp::{Decision, KeyChange, bind, create_settings, record_key_change};
    use access_store::tenancy::{create_realm, create_tenant, set_issuer};
    let tenant = create_tenant(&db.app, "pool-default").await.unwrap();
    let domain = DomainId::from_bytes([0x77; 32]);
    let genesis = LogRecord {
        pos: 0,
        kind: "genesis",
        recorded_at: 1,
        leaf_hash: [0x77; 32],
        envelope: vec![0xa0],
    };
    create_domain(&db.sequencer, &domain, *tenant.as_bytes(), &genesis, &[])
        .await
        .unwrap();
    let (lease, head) = acquire_lease(&db.sequencer, &domain, "t", TTL)
        .await
        .unwrap();
    let pos = head.pos.checked_add(1).unwrap();
    let next = HeadRow {
        pos,
        epoch: lease.epoch,
        leaf_hash: [0x78; 32],
        recorded_at: 2,
        frontier: vec![[0x78; 32]],
    };
    let batch = CommitBatch {
        epoch: lease.epoch,
        after: head.pos,
        records: vec![LogRecord {
            pos,
            kind: "decision",
            recorded_at: 2,
            leaf_hash: [0x78; 32],
            envelope: vec![0xa1, 1],
        }],
        head: next,
        nonces: vec![NonceRow {
            nonce: vec![0x78; 16],
            actor: vec![1],
            intent_digest: [9; 32],
            decision_pos: pos,
            outcome: String::from("allow"),
            render_digest: None,
            tier: None,
        }],
        outbox: vec![],
        proofs: vec![],
        reads: vec![],
        writes: vec![],
        draws: vec![],
        single_use: vec![],
        beside: vec![],
        effects: vec![],
    };
    commit_batch(&db.sequencer, &domain, *tenant.as_bytes(), &batch)
        .await
        .unwrap();
    let mut t = TenantTx::begin_tenant(&db.app, tenant).await.unwrap();
    let realm = create_realm(&mut t, &domain, "idp", "pool-default")
        .await
        .unwrap();
    t.enter_realm(realm).await.unwrap();
    assert!(set_issuer(&mut t, ISS).await.unwrap());
    create_settings(&mut t).await.unwrap();
    let bound = bind(
        &mut t,
        &Decision {
            domain: &domain,
            position: pos,
            nonce: &[0x78; 16],
            intent: [9; 32],
            change: [5; 32],
            action: "idp.realm.key_drop",
        },
    )
    .await
    .unwrap()
    .unwrap();
    record_key_change(
        &mut t,
        &bound,
        &KeyChange {
            action: String::from("idp.realm.key_drop"),
            kid: Some(kid),
            policy: None,
            compromised_at: None,
            declared_at: cutoff_at,
            cutoff_at: Some(cutoff_at),
        },
    )
    .await
    .unwrap();
    t.commit().await.unwrap();
}

// §13.7.7, SEC9, OP-150 m.11 (c), (j)
#[tokio::test]
async fn a_dropped_realm_key_signs_nothing_admitted_after_its_cutoff() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![
            acceptance(IDP, "actor-binding", &["authentication"], vec![pinned()]),
            acceptance(ALICE, "actor-binding", &["identity_binding_person"], vec![]),
        ],
    )
    .await;
    let bind = statement(
        d,
        ALICE,
        ROOT,
        "identity_binding_person",
        binding_value(&subject_digest(ISS, "u-1")).unwrap(),
    );
    let v = core.ingest(&signed(&bind, ALICE_KEY), NOW).await.unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
    let ctx = Some(context_bytes(&ROOT));
    let v = core
        .ingest(
            &submit(
                d,
                Carrier::Oidc,
                id_token_at("u-1", 8, IDP_KEY),
                ctx.clone(),
            ),
            NOW,
        )
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");

    dropped_realm_key(&db, thumbprint(&public(IDP_KEY)), 6_000).await;
    let v = core
        .ingest(
            &submit(
                d,
                Carrier::Oidc,
                id_token_at("u-1", 7, IDP_KEY),
                ctx.clone(),
            ),
            NOW,
        )
        .await
        .unwrap();
    assert!(
        matches!(
            v.verdict,
            ClaimVerdict::Quarantined {
                reason: Quarantine::SourceNotAccepted,
                ..
            }
        ),
        "{v:?}"
    );
    let v = core
        .ingest(
            &submit(d, Carrier::Oidc, id_token_at("u-1", 5, IDP_KEY), ctx),
            NOW,
        )
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
}

/// A `resource_lifecycle` Claim of BOB, the domain product, about `ride/vehicles/<id>`
/// (`product-seam.cddl`): its value is the body digest and the body travels with it.
fn lifecycle(
    d: Digest,
    id: &str,
    incarnation: u64,
    event: &str,
    issued_at: u64,
) -> ClaimSubmission {
    let body = Value::Map(vec![
        (Value::text("namespace"), Value::text("ride")),
        (
            Value::text("path"),
            Value::Array(vec![Value::text("vehicles"), Value::text(id)]),
        ),
        (Value::text("incarnation"), Value::Unsigned(incarnation)),
        (Value::text("event"), Value::text(event)),
    ]);
    let tagged = dcbor::encode(
        &Value::Array(vec![Value::text("resource_lifecycle"), body.clone()]),
        Limits::CEILING,
    )
    .unwrap();
    let digest =
        suiss_crypto::digest::context_digest(access_kernel::claim::body::BODY_CONTEXT, &tagged);
    let mut s = statement(
        d,
        BOB,
        BOB,
        "resource_lifecycle",
        EqValue::Bytes(digest.0.to_vec()),
    );
    s.issued_at = issued_at;
    let mut sub = signed(&s, BOB_KEY);
    sub.body = Some(dcbor::encode(&body, Limits::CEILING).unwrap());
    sub
}

fn ingest_domains(db: &TestDb, d: Digest) -> Domains<Listed, Bound, Counter, Fixed> {
    Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(d),
        holder: "ingest".to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(40),
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: None,
        api_base: "https://api.example".to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    })
}

/// A `resource-incarnation` search by the key `seed`, over the meta-anchor.
fn search_incoming(d: Digest, nonce: u8, seed: u8) -> Incoming {
    let mut r = request(
        d,
        nonce,
        ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        Payload::InstanceTerminate { instance: ROOT },
    );
    r.mode = Mode::Check;
    r.intent.action = action("read");
    r.intent.resources = vec![ResourceRef {
        namespace: "access.search".to_owned(),
        path: vec!["resource-incarnation".to_owned()],
        incarnation: 0,
    }];
    r.intent.opaque = BTreeMap::new();
    r.payload = None;
    let digest = access_kernel::intent::intent_digest(&r.intent).unwrap();
    let ais = Ais {
        domain: d,
        nonce: r.nonce.clone(),
        intent: digest,
        mode: r.mode,
        pep: PEP.to_owned(),
        capacity: r.capacity,
        basis: r.basis,
        iat: NOW,
        exercise: None,
    };
    Incoming {
        ais: Some(cose(ais.to_bytes().unwrap(), CONTENT_TYPE, seed)),
        request: r,
        pep: PEP.to_owned(),
        requester: None,
        explain: false,
        status: None,
        context: None,
    }
}

// INV-32, E14, OP-156 m.3 (k), §7.9.10.4
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one resource's lifecycle from create to reincarnation, its registry and its search"
)]
async fn a_reused_incarnation_is_refused_at_ingest() {
    let db = fresh().await.unwrap();
    let (core, d) = setup(
        &db,
        vec![acceptance(
            BOB,
            "predicate-input",
            &["resource_lifecycle"],
            vec![],
        )],
    )
    .await;
    let mut core = core;
    onboard(&mut core, d, ROOT, ROOT_KEY, (7, 8)).await;
    core.release().await.unwrap();
    let domains = ingest_domains(&db, d);
    let admitted = |v: &ClaimVerdict| matches!(v, ClaimVerdict::Admitted { .. });
    let reused = |v: &ClaimVerdict| matches!(v, ClaimVerdict::Rejected { code } if code == "incarnation-reused");
    let created = lifecycle(d, "34-abc-12", 0, "create", NOW);
    let v = domains.record(created.clone(), false).await.unwrap();
    assert!(admitted(&v), "{v:?}");
    let again = domains
        .record(lifecycle(d, "34-abc-12", 0, "create", NOW + 1), false)
        .await
        .unwrap();
    assert!(reused(&again), "{again:?}");
    let other = domains
        .record(lifecycle(d, "35-xyz-99", 0, "create", NOW + 1), false)
        .await
        .unwrap();
    assert!(admitted(&other), "{other:?}");
    let deleted = domains
        .record(lifecycle(d, "34-abc-12", 0, "delete", NOW + 2), false)
        .await
        .unwrap();
    assert!(admitted(&deleted), "{deleted:?}");
    let back = domains
        .record(lifecycle(d, "34-abc-12", 0, "reincarnate", NOW + 3), false)
        .await
        .unwrap();
    assert!(reused(&back), "{back:?}");
    let next = domains
        .record(lifecycle(d, "34-abc-12", 1, "reincarnate", NOW + 3), false)
        .await
        .unwrap();
    assert!(admitted(&next), "{next:?}");
    let replayed = domains.record(created, false).await.unwrap();
    assert!(
        matches!(replayed, ClaimVerdict::Admitted { replayed: true, .. }),
        "{replayed:?}"
    );
    let path = vec!["vehicles".to_owned(), "34-abc-12".to_owned()];
    let rows =
        access_store::resources::incarnations(&db.app, &DomainId::from_bytes(d.0), "ride", &path)
            .await
            .unwrap();
    assert_eq!(
        rows.iter()
            .map(|r| (r.incarnation, r.event.as_str()))
            .collect::<Vec<_>>(),
        [(0, "create"), (0, "delete"), (1, "reincarnate")]
    );
    assert!(rows.iter().all(|r| r.issuer == BOB.0));
    assert_eq!(
        access_store::resources::highest_incarnation(
            &db.app,
            &DomainId::from_bytes(d.0),
            "ride",
            &path
        )
        .await
        .unwrap(),
        Some(1)
    );
    let query = access_authority_core::query::Query::ResourceIncarnation {
        namespace: "ride".to_owned(),
        path: path.clone(),
    };
    let (hits, _) = domains
        .search(&search_incoming(d, 70, ROOT_KEY), &query, None)
        .await
        .unwrap();
    let [access_authority_core::query::Hit::Report(report)] = hits.as_slice() else {
        panic!("{hits:?}");
    };
    let access_authority_core::query::Report::Incarnations(found) = &**report else {
        panic!("{report:?}");
    };
    assert_eq!(found.highest, Some(1));
    assert_eq!(found.facts.len(), 3);
    let (others, _) = domains
        .search(&search_incoming(d, 71, BOB_KEY), &query, None)
        .await
        .unwrap();
    assert!(others.is_empty(), "the domain's auditors only");
    let mut broken = lifecycle(d, "36", 0, "create", NOW);
    broken.body = Some(vec![0xa0]);
    let v = domains.record(broken, false).await.unwrap();
    assert!(
        matches!(&v, ClaimVerdict::Rejected { code } if code == "claim-value"),
        "{v:?}"
    );
    domains.release().await;
}

// INV-32
#[tokio::test]
async fn an_unaccepted_lifecycle_claim_is_held_and_reserves_nothing() {
    let db = fresh().await.unwrap();
    let (core, d) = setup(
        &db,
        vec![acceptance(ALICE, "predicate-input", &["kyc"], vec![])],
    )
    .await;
    core.release().await.unwrap();
    let domains = ingest_domains(&db, d);
    let held = domains
        .record(lifecycle(d, "34-abc-12", 5, "create", NOW), false)
        .await
        .unwrap();
    assert!(matches!(held, ClaimVerdict::Quarantined { .. }), "{held:?}");
    let path = vec!["vehicles".to_owned(), "34-abc-12".to_owned()];
    assert_eq!(
        access_store::resources::highest_incarnation(
            &db.app,
            &DomainId::from_bytes(d.0),
            "ride",
            &path
        )
        .await
        .unwrap(),
        None
    );
    domains.release().await;
}

fn vehicle(incarnation: u64) -> ResourceRef {
    ResourceRef {
        namespace: "access.party".to_owned(),
        path: vec!["vehicles".to_owned(), "34-abc-12".to_owned()],
        incarnation,
    }
}

/// A Grant held by `holder` for `action` on exactly `resource`.
fn exact_grant(holder: Id, action_name: &str, resource: &ResourceRef) -> Value {
    let Value::Map(mut entries) = grant(&SubjectSelector::Party(holder), &[action_name], "ride")
    else {
        panic!()
    };
    for (k, v) in &mut entries {
        if *k == Value::text("authority") {
            let mut a = CanonicalAuthority::from_value(v).unwrap();
            a.authority.resource = ResourceSelector::Exact(resource.clone());
            *v = a.to_value();
        }
    }
    Value::Map(entries)
}

// E14, INV-32, §7.9.10.4
#[tokio::test]
async fn a_grant_on_one_incarnation_does_not_cover_the_next() {
    let db = fresh().await.unwrap();
    let exact = exact_grant(ALICE, "read", &vehicle(1));
    let mut sorted = [
        grant(
            &SubjectSelector::Public,
            &["party_register", "instance_create"],
            "access.party",
        ),
        grant(&SubjectSelector::Party(ALICE), &["read"], "access.party"),
        exact.clone(),
    ];
    sorted.sort_by_key(|g| dcbor::encode(g, Limits::CEILING).unwrap());
    let index = u64::try_from(sorted.iter().position(|g| *g == exact).unwrap()).unwrap();
    let (mut core, d) = setup_with(
        &db,
        vec![acceptance(ALICE, "predicate-input", &["kyc"], vec![])],
        vec![exact],
    )
    .await;
    let mut ask = async |incarnation: u64, nonce: u8| {
        let basis = ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&d, kind::GRANT, index),
            holder: ALICE,
            since: 0,
        });
        let mut r = request(
            d,
            nonce,
            basis,
            Payload::InstanceTerminate { instance: ALICE },
        );
        r.intent.action = action("read");
        r.intent.resources = vec![vehicle(incarnation)];
        r.intent.opaque = BTreeMap::new();
        r.payload = None;
        send(&mut core, r, ALICE_KEY)
            .await
            .unwrap()
            .decision
            .outcome
    };
    assert_eq!(ask(1, 90).await, Outcome::Allow);
    assert_eq!(ask(2, 91).await, Outcome::Deny);
    assert_eq!(ask(0, 92).await, Outcome::Deny);
}

// G44, §13.7.4, OP-157 m.3 (p), Ek B 5664
#[tokio::test]
async fn narrowing_claims_take_their_own_lane_through_the_ledger() {
    use access_authority_core::app::{Lane, lane_of};
    let db = fresh().await.unwrap();
    let (core, d) = setup(
        &db,
        vec![
            regime_acceptance(),
            acceptance(ALICE, "predicate-input", &["kyc"], vec![quota(1)]),
        ],
    )
    .await;
    core.release().await.unwrap();
    let domains = Domains::new(Setup {
        sequencer: db.sequencer.clone(),
        app: db.app.clone(),
        keys: Listed(d),
        holder: "ingest".to_owned(),
        ttl: TTL,
        binding: binding(),
        salts: Counter(40),
        clock: Fixed,
        deriver: db.deriver.clone(),
        signer: None,
        api_base: "https://api.example".to_owned(),
        analysis: std::sync::Arc::new(access_authority_core::ports::NoAnalysis),
    });
    let compromise = signed(
        &statement(d, REGIME, ALICE, "party_compromise", EqValue::Int(5_000)),
        REGIME_KEY,
    );
    let suspended = signed(&status(d, BOB, "suspended", NOW, None), REGIME_KEY);
    let active = signed(&status(d, BOB, "active", NOW, None), REGIME_KEY);
    let kyc_claim = signed(&kyc(d, ALICE, 1), ALICE_KEY);
    assert_eq!(lane_of(&compromise), Lane::Narrowing);
    assert_eq!(lane_of(&suspended), Lane::Narrowing);
    assert_eq!(lane_of(&active), Lane::General);
    assert_eq!(lane_of(&kyc_claim), Lane::General);
    for n in 1..=3 {
        domains
            .record(signed(&kyc(d, ALICE, n), ALICE_KEY), false)
            .await
            .unwrap();
    }
    assert!(matches!(
        domains.record(compromise, false).await.unwrap(),
        ClaimVerdict::Admitted { .. }
    ));
    domains.release().await;
}

/// A `checkpoint` Claim of `d` for a tree of `size` with `root`, its body travelling with it.
fn checkpoint_claim(d: Digest, size: u64, root: [u8; 32], origin: &str) -> ClaimSubmission {
    use access_authority_sequencer::checkpoint::CLAIM_CONTEXT;
    let cp = suiss_crypto::note::Checkpoint {
        origin: origin.to_owned(),
        size,
        root,
        extensions: vec![format!("issued_at {NOW}")],
    };
    let text = cp.to_body().unwrap();
    let line = format!(
        "\u{2014} {origin} {}\n",
        suiss_crypto::note::base64_encode(&[0, 0, 0, 1, 7, 7, 7])
    );
    let body = dcbor::encode(
        &Value::Map(vec![
            (Value::text("note"), Value::text(&format!("{text}\n{line}"))),
            (Value::text("excerpt"), Value::Bytes(vec![1])),
            (Value::text("trigger"), Value::text("interval")),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let digest = suiss_crypto::digest::context_digest(CLAIM_CONTEXT, &body);
    let s = statement(
        d,
        ALICE,
        ALICE,
        access_kernel::claim::CHECKPOINT,
        EqValue::Bytes(digest.0.to_vec()),
    );
    let mut sub = signed(&s, ALICE_KEY);
    sub.body = Some(body);
    sub
}

// SEC21, SEC22, OP-158 m.3 (c), m.6 (j)
#[tokio::test]
async fn an_admitted_checkpoint_claim_is_the_witness_head_the_rollback_guard_reads() {
    use access_kernel::claim::ClaimState;
    use access_kernel::fold::{Guard, GuardError, rollback_guard};
    use access_kernel::recovery::{witness_head, witness_head_key};
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![acceptance(
            ALICE,
            "predicate-input",
            &["checkpoint"],
            vec![],
        )],
    )
    .await;
    let origin = access_authority_sequencer::checkpoint::origin(&d);
    let root = suiss_crypto::digest::sha256(b"the witnessed tree");
    let sub = checkpoint_claim(d, 7, root, &origin);
    let ClaimVerdict::Admitted { claim, .. } = core.ingest(&sub, NOW).await.unwrap().verdict else {
        panic!("admitted");
    };
    let id = DomainId::from_bytes(d.0);
    let rows = access_store::authority::state_of(
        &db.app,
        &id,
        &[meta::key(kind::CLAIM, &claim), witness_head_key(&claim)],
    )
    .await
    .unwrap();
    let get = |k: &[u8]| {
        rows.iter()
            .find(|r| r.key == k)
            .and_then(|r| r.value.as_deref())
            .map(|v| dcbor::decode(v, Limits::CEILING).unwrap())
    };
    let state = ClaimState::from_value(&get(&meta::key(kind::CLAIM, &claim)).unwrap()).unwrap();
    let head = witness_head(&state, get(&witness_head_key(&claim)).as_ref(), NOW).unwrap();
    assert_eq!((head.size, head.root), (7, root));
    assert_eq!(
        rollback_guard(&[Some(head)], Some(7), (7, root), false, NOW),
        Ok(Guard::Pass)
    );
    assert_eq!(
        rollback_guard(&[Some(head)], Some(7), (5, root), false, NOW),
        Err(GuardError::Rollback)
    );

    let mut bare = checkpoint_claim(d, 8, root, &origin);
    bare.body = None;
    let mut tampered = checkpoint_claim(d, 8, root, &origin);
    if let Some(b) = tampered.body.as_mut() {
        let last = b.len() - 1;
        b[last] ^= 1;
    }
    let elsewhere = checkpoint_claim(d, 8, root, "sha-256:AAAA");
    for (sub, code) in [
        (bare, "claim-body"),
        (tampered, "claim-body-digest"),
        (elsewhere, "claim-body"),
    ] {
        assert_eq!(
            core.ingest(&sub, NOW).await.unwrap().verdict,
            ClaimVerdict::Rejected {
                code: code.to_owned()
            }
        );
    }
}
