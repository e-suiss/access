//! CMP-8, §9.13: Claim Ingest end to end on a real PostgreSQL: carriers, dispositions, quota,
//! designation and resubmission.

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

fn genesis(acceptances: Vec<Value>) -> BTreeMap<String, Opened> {
    let opened = |value| Opened {
        value,
        salt: [3; 32],
    };
    let grants = vec![
        grant(
            &SubjectSelector::Public,
            &["party_register", "instance_create"],
            "access.party",
        ),
        grant(&SubjectSelector::Party(ALICE), &["read"], "access.party"),
    ];
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
    let d = create_genesis(&db.sequencer, TENANT, genesis(acceptances), 1_000)
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
        explain: false,
        status: None,
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

// CMP-8, L2-CLM-3, L2-CLM-4, INV-2, §9.13 rule 3: an accepted Claim is admitted once and a
// resubmission answers with its record; an issuer without an Acceptance is held, a Claim that
// does not verify is refused and not recorded
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

// G44, P19, §13.7.4: past twice the declared quota a qualifying Claim is held and opens no
// episode, while a narrowing Claim of the same issuer is still admitted
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

// P21, §9.13.1 rules 2 and 4, E18, U26: an authenticator binding needs the domain's actor-binding
// Acceptance and the subject's designation of its issuer; without a key-state the Acceptance
// alone decides, and a key-state that drops the issuer holds its later Claims
#[tokio::test]
async fn designation_and_acceptance_must_both_hold() {
    let db = fresh().await.unwrap();
    let (mut core, d) = setup(
        &db,
        vec![
            acceptance(ALICE, "actor-binding", &["authenticator_binding"], vec![]),
            acceptance(BOB, "actor-binding", &["authenticator_binding"], vec![]),
            acceptance(REGIME, "actor-binding", &["party_key_state"], vec![]),
        ],
    )
    .await;
    let v = core
        .ingest(&passkey(d, ALICE, ALICE_KEY), NOW)
        .await
        .unwrap();
    assert!(matches!(v.verdict, ClaimVerdict::Admitted { .. }), "{v:?}");
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

// B7, P-ID-2, E18, INV-12, G45, IDI-9, §9.13 (pinned key set), §10.1.1: an upstream ID token
// verified under the Acceptance's pinned key set becomes an authentication Claim of the IdP, only
// for a Party an identity binding holds; another key or an unbound Party is refused
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

// L2-CLM-3, §9.13 rule 3, G44, §16.7: the domains as ledger index a held Claim by its record,
// answer a resubmission with it, and note an issuer's used-up quota once per window
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

// TN-49, TN-50, SEC12, X36, E5, CI-2, TI-RT7, G36: a narrowing account status denies the Party's
// Instances from its ingest on, as a restriction; a newer status in the issuer line lifts it,
// and one without an order keeps it (the disqualifying side wins)
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
    // OP-149 m.7, m.19 (f): the producer of party.disabled{suspended}
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

// §7.9.2.4, §10.1.5, E5: termination denies every Instance of the Party and its actor-binding
// fails closed; an identity break denies the Instances established before it
#[tokio::test]
async fn termination_and_identity_break_restrict_instances() {
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

// SEC12, §7.9.2.3, §7.9.2.4: Instances set up after a compromise are denied; after the Party
// recovers, an Instance set up later is not, and the ones before stay denied
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

// §9.12.3, §9.12.4, E30, P28, INV-21, PI-9: a PEP's authority-state acknowledgement is admitted
// and recorded as a detection signal only: it derives no event and changes no decision
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
