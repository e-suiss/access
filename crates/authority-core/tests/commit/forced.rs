//! Forced recovery on the real store (§13.6, §16.6 FR-2, FR-3, PR-1, SEC20–SEC22, U16, U24,
//! U28, OP-158 m.3 (m), m.7 (c)): the witness heads the recovering provider records, the entry
//! keys, both arms, the `domain-recovered` event and the pre-recovery nonce closure.

use std::hash::BuildHasher as _;

use access_authority_core::app::forced::{RECOVERY_KEY, WitnessHead};
use access_authority_core::ports::Reader as _;
use access_internal_api::events::{Detail, Event, Kind};
use access_kernel::recovery::{
    CheckpointRef, KeyHolding, LostSuffix, RECOVER, RecoverInput, RecoveryEntry, binding_key,
    recovered_key,
};
use access_kernel::verify::key_scope::{BindingKey, BindingScope};
use suiss_crypto::note::{Checkpoint, Verifier, base64_encode, cosigned_message};

use super::*;

fn runtime_key() -> ed25519_dalek::SigningKey {
    let bytes: Vec<u8> = (0..4_u64)
        .flat_map(|i| {
            std::collections::hash_map::RandomState::new()
                .hash_one(i)
                .to_le_bytes()
        })
        .collect();
    ed25519_dalek::SigningKey::from_bytes(&bytes.try_into().unwrap())
}

fn public_of(k: &ed25519_dalek::SigningKey) -> PublicKey {
    PublicKey::Ed25519(k.verifying_key().to_bytes())
}

fn cose(k: &ed25519_dalek::SigningKey, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let prot = dcbor::encode(
        &Value::Map(vec![
            (Value::Unsigned(ALG), Value::int(-19)),
            (Value::Unsigned(CT), Value::text(content_type)),
            (
                Value::Unsigned(KID),
                Value::Bytes(thumbprint(&public_of(k)).to_vec()),
            ),
        ]),
        Limits::CEILING,
    )
    .unwrap();
    let sig = k.sign(&to_be_signed(&prot, payload).unwrap()).to_bytes();
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

/// Sends `request` signed by `key`, its AIS issued at `iat`, at trusted time `now`.
async fn send_by(
    core: &mut Core,
    request: Request,
    key: &ed25519_dalek::SigningKey,
    (iat, now): (u64, u64),
) -> Response {
    let mut inc = incoming(request, ROOT_KEY);
    let statement = Statement {
        domain: inc.request.domain,
        nonce: inc.request.nonce.clone(),
        intent: access_kernel::intent::intent_digest(&inc.request.intent).unwrap(),
        mode: inc.request.mode,
        pep: PEP.to_owned(),
        capacity: inc.request.capacity,
        basis: inc.request.basis,
        iat,
        exercise: inc.request.exercise,
    };
    inc.ais = Some(cose(key, CONTENT_TYPE, &statement.to_bytes().unwrap()));
    core.exercise(&inc, now).await.unwrap()
}

/// `name`'s cosigned note over `size` and `root` of `d`, at `seconds`, and its vkey.
fn cosigned(
    key: &ed25519_dalek::SigningKey,
    name: &str,
    (d, size, root): (Digest, u64, [u8; 32]),
    seconds: u64,
) -> (String, String) {
    let v = Verifier::cosigner(name, key.verifying_key().to_bytes()).unwrap();
    let body = Checkpoint {
        origin: access_authority_sequencer::checkpoint::origin(&d),
        size,
        root,
        extensions: Vec::new(),
    }
    .to_body()
    .unwrap();
    let sig = key.sign(&cosigned_message(seconds, &body)).to_bytes();
    let mut raw = v.id().to_be_bytes().to_vec();
    raw.extend_from_slice(&seconds.to_be_bytes());
    raw.extend_from_slice(&sig);
    (
        format!("{body}\n\u{2014} {name} {}\n", base64_encode(&raw)),
        v.to_vkey(),
    )
}

/// The root Parties, each with one recovery key of the entry.
const ROOTS: [Id; 3] = [ROOT, ALICE, BOB];

/// The recovery keys of ROOT, ALICE and BOB, generated at run time.
struct Keys3 {
    entry: [ed25519_dalek::SigningKey; 3],
}

fn joint() -> Value {
    Value::Map(vec![(
        Value::text("joint"),
        Value::Map(vec![
            (
                Value::text("parties"),
                Value::Array(ROOTS.iter().map(Canonical::to_value).collect()),
            ),
            (Value::text("k"), Value::Unsigned(2)),
        ]),
    )])
}

/// Genesis: ROOT, ALICE and BOB jointly root the meta-anchor with a 2-of-3 recovery entry of
/// `entry`, ALICE and BOB hold the Grant to contribute and ALICE issues `authentication`
/// Claims; the index of each one's Grant.
fn recoverable(entry: &[ed25519_dalek::SigningKey; 3]) -> (BTreeMap<String, Opened>, [u64; 2]) {
    let mut g = gated(&[]);
    let kids = entry.iter().map(|k| thumbprint(&public_of(k))).collect();
    let e = RecoveryEntry::new(2, kids, 2, KeyHolding::Device, ROOTS.into_iter().collect());
    g.insert(
        "meta_anchor".to_owned(),
        Opened {
            value: Value::Map(vec![
                (Value::text("root"), joint()),
                (Value::text("recovery"), e.to_value()),
            ]),
            salt: [3; 32],
        },
    );
    g.insert(
        "binding".to_owned(),
        Opened {
            value: Value::Array(binding_of(60).values().map(Canonical::to_value).collect()),
            salt: [3; 32],
        },
    );
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let Value::Map(mut bob) = grants.get(1).unwrap().clone() else {
        panic!("a grant is a map");
    };
    for (k, v) in &mut bob {
        if *k == Value::text("holder") {
            *v = SubjectSelector::Party(BOB).to_value();
        }
    }
    grants.push(Value::Map(bob));
    grants.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
    let index = |p: Id| {
        let holder = SubjectSelector::Party(p).to_value();
        u64::try_from(
            grants
                .iter()
                .position(|v| v.get("holder") == Some(&holder))
                .unwrap(),
        )
        .unwrap()
    };
    let held = [index(ALICE), index(BOB)];
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    (g, held)
}

fn binding_of(seed: u8) -> BTreeMap<[u8; 32], BindingKey> {
    let key = public(seed);
    let b = BindingKey {
        kid: thumbprint(&key),
        alg: access_kernel::verify::cose::Algorithm::Ed25519,
        key,
        scope: BindingScope::Domain,
        superseded: None,
    };
    BTreeMap::from([(b.kid, b)])
}

/// The domain with the root Parties' Instances: their keys and their entry keys, each entry key
/// opened by its nonce `40 + i`.
async fn recoverable_core(db: &TestDb, keys: &Keys3) -> (Core, Digest, [u64; 2]) {
    let (g, grant) = recoverable(&keys.entry);
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut bound = binding();
    for (k, p) in keys.entry.iter().zip(ROOTS) {
        bound.0.insert(thumbprint(&public_of(k)), (p, public_of(k)));
    }
    let mut core: Core = Authority::new(leader, reader, bound, Counter(0), d);
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (i, (k, party)) in keys.entry.iter().zip(ROOTS).enumerate() {
        let create = Payload::InstanceCreate {
            party,
            key: public_of(k),
            mandate: None,
        };
        let nonce = 40_u8.checked_add(u8::try_from(i).unwrap()).unwrap();
        allowed(
            &send_by(
                &mut core,
                meta_request(d, nonce, public_basis, create),
                k,
                (NOW, NOW),
            )
            .await,
        );
    }
    (core, d, grant)
}

fn instance_of(d: Digest, i: u8) -> Id {
    meta::object_id(
        &meta::exercise_id(&d, &[40_u8.checked_add(i).unwrap(); 16]).unwrap(),
        kind::INSTANCE,
        0,
    )
}

/// `party`'s `recover` contribution to `target` from its Instance `instance`, on its Grant
/// `grant`.
fn recover_contribution(
    d: Digest,
    (party, grant, instance): (Id, u64, Id),
    (nonce, class): (u8, &str),
    target: Digest,
    render: Digest,
) -> Request {
    let payload = Payload::Contribute {
        target,
        class: class.to_owned(),
    };
    let mut r = meta_request(
        d,
        nonce,
        ExerciseBasis::Holding(HoldingRef {
            grant: meta::object_id(&d, kind::GRANT, grant),
            holder: party,
            since: 0,
        }),
        payload,
    );
    r.intent.resources = vec![ResourceRef {
        namespace: "access.contribution".to_owned(),
        path: vec![class.to_owned()],
        incarnation: 0,
    }];
    let p = r.payload.clone().unwrap();
    r.intent.opaque = BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]);
    let mut act = approval_act(d, nonce, target, render, NOW - 1_000, NOW + 60_000);
    act.act = Act::Contribution(class.to_owned());
    act.party = party;
    act.instance = instance;
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
    with_proofs(
        r,
        vec![
            ProofRef::Aas(act.to_bytes().unwrap()),
            ProofRef::Claim(claim),
        ],
    )
}

/// Records two witnesses' heads at `n` with `root`, the recovery's witness Claims.
async fn witnessed(core: &mut Core, d: Digest, n: u64, root: [u8; 32]) -> BTreeSet<Id> {
    let mut heads = Vec::new();
    for name in ["w1.example", "w2.example"] {
        let (note, vkey) = cosigned(&runtime_key(), name, (d, n, root), NOW / 1_000);
        heads.push(WitnessHead::verified(&d, &note, &vkey).unwrap());
    }
    core.record_witness_heads(&heads, NOW)
        .await
        .unwrap()
        .into_iter()
        .collect()
}

fn recover_request(d: Digest, nonce: u8, input: RecoverInput) -> Request {
    meta_request(
        d,
        nonce,
        ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        Payload::DomainRecover(input),
    )
}

/// One contribution: the Party, its Grant, its Instance, the Instance's key, the nonce and the
/// class.
type From<'a> = (Id, u64, Id, &'a ed25519_dalek::SigningKey, (u8, &'a str));

/// Asks with `target`, has `from` contribute and asks again with a fresh nonce.
async fn with_recover_contributions(
    core: &mut Core,
    db: &TestDb,
    d: Digest,
    (target, retry): (Request, u8),
    from: &[From<'_>],
) -> Response {
    let asked = send(core, target.clone(), ROOT_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction, "{asked:?}");
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let shown = reader.opening(&digest).await.unwrap().unwrap().render;
    let mut proofs = Vec::new();
    for (party, grant, instance, key, nonce) in from {
        let given = send_by(
            core,
            recover_contribution(d, (*party, *grant, *instance), *nonce, digest, shown),
            key,
            (NOW, NOW),
        )
        .await;
        allowed(&given);
        proofs.push(ProofRef::Contribution(given.exercise.unwrap()));
    }
    let mut again = with_proofs(target, proofs);
    again.nonce = vec![retry; 16];
    send(core, again, ROOT_KEY).await.unwrap()
}

// §13.6, FR-2, FR-3, SEC20, SEC21, SEC22, U16, L0-META-36, OP-158 m.3 (m), m.7 (c),
// Ek B 5764, 5908, 6022, 6023, 6121, 6140
#[tokio::test]
async fn a_recovery_counts_only_entry_keys_and_rebinds_on_its_witness_heads() {
    let db = fresh().await.unwrap();
    let keys = Keys3 {
        entry: [runtime_key(), runtime_key(), runtime_key()],
    };
    let (mut core, d, grant) = recoverable_core(&db, &keys).await;
    let root = suiss_crypto::digest::sha256(b"the witnessed tree at N");
    let claims = witnessed(&mut core, d, 5, root).await;
    let mut input = RecoverInput::new(5, CheckpointRef::new(5, Digest(root)), binding_of(61));
    input.witness_claims = claims;
    input.replica_head = Some(CheckpointRef::new(5, Digest(root)));
    let before = state_of(&db, d, &binding_key()).await.unwrap();

    // SEC20, U16, OP-158 m.7 (c)
    let bob_daily = meta::object_id(&meta::exercise_id(&d, &[6; 16]).unwrap(), kind::INSTANCE, 0);
    let outsider = with_recover_contributions(
        &mut core,
        &db,
        d,
        (recover_request(d, 60, input.clone()), 61),
        &[
            (
                ALICE,
                grant[0],
                instance_of(d, 1),
                &keys.entry[1],
                (62, RECOVER),
            ),
            (BOB, grant[1], bob_daily, &signing(BOB_KEY), (63, RECOVER)),
        ],
    )
    .await;
    assert_eq!(outsider.decision.outcome, Outcome::Deny, "{outsider:?}");
    assert_eq!(
        outsider.decision.blockers[0].subcode.as_deref(),
        Some(RECOVERY_KEY)
    );
    assert_eq!(state_of(&db, d, &binding_key()).await.unwrap(), before);

    // FR-3, arm (i)
    let done = with_recover_contributions(
        &mut core,
        &db,
        d,
        (recover_request(d, 64, input), 65),
        &[
            (
                ALICE,
                grant[0],
                instance_of(d, 1),
                &keys.entry[1],
                (66, RECOVER),
            ),
            (
                BOB,
                grant[1],
                instance_of(d, 2),
                &keys.entry[2],
                (67, RECOVER),
            ),
        ],
    )
    .await;
    allowed(&done);
    assert_ne!(state_of(&db, d, &binding_key()).await.unwrap(), before);
    assert!(state_of(&db, d, &recovered_key()).await.is_some());
    let old = *binding_of(60).keys().next().unwrap();
    assert!(
        state_of(&db, d, &access_kernel::recovery::superseded_key(&old))
            .await
            .is_some()
    );

    // §13.6 notification, Ek B 5883
    let outbox =
        access_store::authority::read_outbox(&db.app, &DomainId::from_bytes(d.0), (0, 0), 500)
            .await
            .unwrap();
    let recovered: Vec<Event> = outbox
        .iter()
        .filter_map(|r| Event::from_bytes(&r.event).ok())
        .filter(|e| e.kind == Kind::DomainRecovered)
        .collect();
    assert_eq!(recovered.len(), 1, "{recovered:?}");
    assert_eq!(recovered[0].detail, Detail::Domain { position: 5 });

    // U28, TI-RT3, SEC22 R1 (c), Ek B 5944, 6121
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let stale = send_by(
        &mut core,
        shop_request(d, 70, Mode::Commit, shop),
        &signing(ROOT_KEY),
        (NOW - 1, NOW + 1),
    )
    .await;
    assert_eq!(stale.decision.outcome, Outcome::Deny, "{stale:?}");
    assert_eq!(stale.decision.blockers[0].class, BlockerClass::NonceClosed);
    assert_eq!(
        stale.decision.blockers[0].subcode.as_deref(),
        Some("pre-recovery")
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.6 arm (ii), U24, SEC22, FR-0, OP-158 m.3 (m), Ek B 6023, 6024
#[tokio::test]
async fn a_domain_without_a_replica_recovers_with_its_lost_suffix_declared() {
    let db = fresh().await.unwrap();
    let keys = Keys3 {
        entry: [runtime_key(), runtime_key(), runtime_key()],
    };
    let (mut core, d, grant) = recoverable_core(&db, &keys).await;
    let root = suiss_crypto::digest::sha256(b"the witnessed tree at N");
    let claims = witnessed(&mut core, d, 7, root).await;
    let n_root = suiss_crypto::digest::sha256(b"the tree at N = 3");
    let mut undeclared =
        RecoverInput::new(3, CheckpointRef::new(3, Digest(n_root)), binding_of(61));
    undeclared.witness_claims = claims.clone();
    let refused = send(&mut core, recover_request(d, 50, undeclared), ROOT_KEY)
        .await
        .unwrap();
    assert_eq!(refused.decision.outcome, Outcome::Deny, "{refused:?}");

    let mut at_three = RecoverInput::new(3, CheckpointRef::new(3, Digest(n_root)), binding_of(61));
    at_three.witness_claims = claims;
    at_three.lost_suffix = Some(LostSuffix::new(3, 7));
    let done = with_recover_contributions(
        &mut core,
        &db,
        d,
        (recover_request(d, 51, at_three), 52),
        &[
            (
                ALICE,
                grant[0],
                instance_of(d, 1),
                &keys.entry[1],
                (53, RECOVER),
            ),
            (
                BOB,
                grant[1],
                instance_of(d, 2),
                &keys.entry[2],
                (54, RECOVER),
            ),
            (
                ALICE,
                grant[0],
                alice_instance(d),
                &signing(ALICE_KEY),
                (55, "co_root"),
            ),
        ],
    )
    .await;
    allowed(&done);
    assert!(state_of(&db, d, &recovered_key()).await.is_some());
    fold_check(&db.sequencer, d).await.unwrap();
}

// §9.13.7, §13.6, L0-EVAL-30, Ek B 6078
#[tokio::test]
async fn an_anonymous_request_cannot_recover_a_domain() {
    let db = fresh().await.unwrap();
    let keys = Keys3 {
        entry: [runtime_key(), runtime_key(), runtime_key()],
    };
    let (mut core, d, _) = recoverable_core(&db, &keys).await;
    let root = suiss_crypto::digest::sha256(b"the witnessed tree at N");
    let claims = witnessed(&mut core, d, 5, root).await;
    let mut input = RecoverInput::new(5, CheckpointRef::new(5, Digest(root)), binding_of(61));
    input.witness_claims = claims;
    input.replica_head = Some(CheckpointRef::new(5, Digest(root)));
    let before = state_of(&db, d, &binding_key()).await.unwrap();
    let mut inc = incoming(recover_request(d, 80, input), ROOT_KEY);
    inc.ais = None;
    let r = core.exercise(&inc, NOW).await.unwrap();
    assert_eq!(r.decision.outcome, Outcome::Deny, "{r:?}");
    assert_eq!(state_of(&db, d, &binding_key()).await.unwrap(), before);
    assert!(state_of(&db, d, &recovered_key()).await.is_none());
    fold_check(&db.sequencer, d).await.unwrap();
}
