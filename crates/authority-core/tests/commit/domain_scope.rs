//! Domain-scope meta-actions on the real store (§9.13.7, §9.15, §13.6, §15.4, §15.16, PI-15,
//! SEC20–SEC22, OP-158 m.3 (b), L0-META-36 to L0-META-38).

use access_kernel::recovery::{
    CheckpointRef, HandoverInput, KeyHolding, RecoverInput, RecoveryEntry, binding_key,
    recovered_key, versions_key,
};
use access_kernel::verify::key_scope::{BindingKey, BindingScope, SpecVersions};

use super::*;

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

/// The commit genesis with a provider binding and, when `recovery`, ROOT's 2-of-3 recovery entry.
fn scoped_genesis(recovery: bool) -> BTreeMap<String, Opened> {
    let mut g = genesis();
    let mut meta_anchor = vec![(Value::text("root"), sole(ROOT))];
    if recovery {
        let entry = RecoveryEntry::new(
            2,
            [[0x71; 32], [0x72; 32], [0x73; 32]].into_iter().collect(),
            2,
            KeyHolding::Device,
            BTreeSet::from([ROOT]),
        );
        meta_anchor.push((Value::text("recovery"), entry.to_value()));
    }
    g.insert(
        "meta_anchor".to_owned(),
        Opened {
            value: Value::Map(meta_anchor),
            salt: [3; 32],
        },
    );
    add_acceptances(
        &mut g,
        vec![Value::Map(vec![
            (Value::text("issuer"), ALICE.to_value()),
            (Value::text("use"), Value::text("predicate-input")),
            (
                Value::text("classes"),
                Value::Array(vec![Value::text(access_kernel::claim::CHECKPOINT)]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
            ),
        ])],
    );
    g.insert(
        "binding".to_owned(),
        Opened {
            value: Value::Array(binding_of(60).values().map(Canonical::to_value).collect()),
            salt: [3; 32],
        },
    );
    g
}

async fn core_with(db: &TestDb, g: BTreeMap<String, Opened>) -> (Core, Digest) {
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
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
    (core, d)
}

/// ALICE, the domain's witness here, saying it co-signed `head`.
fn checkpoint_claim(d: Digest, nonce: u8, head: CheckpointRef) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject: ALICE,
            class: access_kernel::claim::CHECKPOINT.to_owned(),
            value: Some(EqValue::Bytes(
                dcbor::encode(&head.to_value(), Limits::CEILING).unwrap(),
            )),
            issued_at: NOW.checked_sub(u64::from(nonce)).unwrap(),
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

fn denied(r: &Response) {
    assert_eq!(r.decision.outcome, Outcome::Deny, "{r:?}");
}

// §9.13.7, §9.15, PI-15, L0-META-36, Ek B 6117, 6132
#[tokio::test]
async fn only_the_meta_anchor_root_rebinds_the_provider() {
    let db = fresh().await.unwrap();
    let (mut core, d) = core_with(&db, scoped_genesis(false)).await;
    let meta = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let handover = Payload::DomainHandover(HandoverInput::new(
        binding_of(61),
        CheckpointRef::new(9, Digest([9; 32])),
        false,
    ));
    let genesis_binding = state_of(&db, d, &binding_key()).await.unwrap();

    denied(
        &send(
            &mut core,
            meta_request(d, 10, shop, handover.clone()),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    denied(
        &send(
            &mut core,
            meta_request(d, 11, meta, handover.clone()),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    let amend = Payload::AnchorAmend {
        anchor: meta::meta_anchor(&d),
        root: None,
        root_terms: Some(BTreeSet::new()),
    };
    allowed(
        &send(&mut core, meta_request(d, 12, meta, amend), ROOT_KEY)
            .await
            .unwrap(),
    );
    assert_eq!(
        state_of(&db, d, &binding_key()).await.unwrap(),
        genesis_binding
    );

    allowed(
        &send(&mut core, meta_request(d, 13, meta, handover), ROOT_KEY)
            .await
            .unwrap(),
    );
    let now = state_of(&db, d, &binding_key()).await.unwrap();
    assert_ne!(now, genesis_binding);
    let old = *binding_of(60).keys().next().unwrap();
    assert!(
        state_of(&db, d, &access_kernel::recovery::superseded_key(&old))
            .await
            .is_some()
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// §13.6, SEC20, SEC22, L0-META-36, Ek B 6117, 6121
#[tokio::test]
async fn a_recovery_needs_its_entry_and_passes_the_rollback_guard() {
    let db = fresh().await.unwrap();
    let (mut bare, d0) = core_with(&db, scoped_genesis(false)).await;
    let recover = |claims: BTreeSet<Id>, n: u64| {
        let mut p = RecoverInput::new(n, CheckpointRef::new(n, Digest([1; 32])), binding_of(61));
        p.witness_claims = claims;
        p.replica_head = Some(CheckpointRef::new(100, Digest([1; 32])));
        Payload::DomainRecover(p)
    };
    let unknown = BTreeSet::from([Id([0x61; 16])]);
    let without = send(
        &mut bare,
        meta_request(
            d0,
            20,
            ExerciseBasis::Anchor(meta::meta_anchor(&d0)),
            recover(unknown.clone(), 100),
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    denied(&without);

    let db = fresh().await.unwrap();
    let (mut core, d) = core_with(&db, scoped_genesis(true)).await;
    let meta = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let unwitnessed = send(
        &mut core,
        meta_request(d, 21, meta, recover(unknown, 100)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    denied(&unwitnessed);

    let mut heads = BTreeSet::new();
    for nonce in [22, 23] {
        let claim = checkpoint_claim(d, nonce, CheckpointRef::new(100, Digest([1; 32])));
        heads.insert(access_kernel::claim::claim_id(&claim));
        let carried = send(
            &mut core,
            with_proofs(
                shop_request(d, nonce, Mode::Commit, meta),
                vec![ProofRef::Claim(claim)],
            ),
            ROOT_KEY,
        )
        .await;
        assert!(carried.is_ok(), "{carried:?}");
    }
    let below = send(
        &mut core,
        meta_request(d, 24, meta, recover(heads.clone(), 90)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    denied(&below);
    assert_eq!(
        below.decision.blockers[0].subcode.as_deref(),
        Some("rollback-guard"),
        "{below:?}"
    );
    let at_head = send(
        &mut core,
        meta_request(d, 25, meta, recover(heads, 100)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(
        at_head.decision.outcome,
        Outcome::RequireAction,
        "{at_head:?}"
    );
    assert!(
        at_head
            .decision
            .unmet
            .iter()
            .any(|u| u.term.class == access_kernel::recovery::RECOVER),
        "{at_head:?}"
    );
    assert!(state_of(&db, d, &recovered_key()).await.is_none());
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-56, SI-18, CR-8, §15.4, §15.16, L0-META-37
// L0-META-38, Ek B 6118, 6119, 6131, 6141, 6142, 6143
#[tokio::test]
async fn a_raised_minimum_narrows_and_a_lowered_one_waits_a_day() {
    let db = fresh().await.unwrap();
    let (mut core, d) = core_with(&db, scoped_genesis(false)).await;
    let meta = ExerciseBasis::Anchor(meta::meta_anchor(&d));
    let v = |core| SpecVersions {
        core,
        meta_schema: 1,
        ..SpecVersions::default()
    };
    let raised = send(
        &mut core,
        meta_request(d, 30, meta, Payload::VersionActivate { versions: v(2) }),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&raised);
    let (floor, activated, at) = access_kernel::recovery::versions_state(
        &dcbor::decode(
            &state_of(&db, d, &versions_key()).await.unwrap(),
            Limits::CEILING,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(activated, v(2));
    assert_eq!(
        access_kernel::version::minimum_at(&floor, &activated, at, at),
        floor
    );
    assert_eq!(
        access_kernel::version::minimum_at(
            &floor,
            &activated,
            at,
            at + access_kernel::version::TRANSITION_MS
        ),
        v(2)
    );

    let lowered = send(
        &mut core,
        meta_request(d, 31, meta, Payload::VersionActivate { versions: v(1) }),
        ROOT_KEY,
    )
    .await
    .unwrap();
    assert_eq!(
        lowered.decision.outcome,
        Outcome::RequireAction,
        "{lowered:?}"
    );
    assert_eq!(
        lowered.decision.blockers[0].subcode.as_deref(),
        Some("time-lock")
    );

    let retire = Payload::AlgorithmRetire {
        algorithm: access_kernel::verify::cose::Algorithm::Es256,
    };
    denied(
        &send(
            &mut core,
            meta_request(d, 32, meta, retire.clone()),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );
    allowed(
        &send(&mut core, meta_request(d, 33, meta, retire), ROOT_KEY)
            .await
            .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}
