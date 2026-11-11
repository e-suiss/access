//! Exceptional authority and containment on the real store (CI-13, SI-4, SI-22, §6.6,
//! §7.9.12.1, §7.9.12.7, §17.7.3, OP-157 m.3 (i)): a court order acts only through the
//! legal-process Grant written before it, an ownership change moves nothing by itself, and a
//! Party allowed to restrict contains with one narrowing Exercise and no quorum, while lifting
//! the containment widens.

use access_authority_core::app::templates::legal::{self, Setup};
use access_authority_core::app::templates::transfer::{OWNERSHIP_CHANGED, OwnershipChanged};
use access_authority_core::restrict::patterns::{Containment, containment};

use super::*;

/// The legal-ops Party court orders are served to.
const LEGAL: Id = BOB;
const LEGAL_KEY: u8 = BOB_KEY;
/// The Security Party, a root of the domain beside ROOT that may act alone (k = 1).
const SECURITY: Id = BOB;
const SECURITY_KEY: u8 = BOB_KEY;
const ALICE_SPARE_KEY: u8 = 17;

fn wipe_schema() -> access_kernel::schema::ActionSchema {
    access_kernel::schema::ActionSchema {
        reserved: true,
        ..schema_of("wipe")
    }
}

/// `shop:wipe`, a reserved action (§13.7.1).
fn wipe() -> ActionRef {
    ActionRef {
        schema: access_kernel::schema::action_digest(&wipe_schema()),
        ..action("shop", "wipe")
    }
}

fn publish_wipe(g: &mut BTreeMap<String, Opened>) {
    let mut spp = shop_spp();
    spp.actions.push(wipe_schema());
    let Some(Value::Array(mut all)) = g.get("acceptances").map(|o| o.value.clone()) else {
        panic!("genesis has acceptances");
    };
    for a in &mut all {
        if a.get("use") == Some(&Value::text("schema-definition"))
            && let Value::Map(m) = a
        {
            for (k, v) in m.iter_mut() {
                if *k == Value::text("spp") {
                    *v = spp.to_value();
                }
            }
        }
    }
    g.remove("acceptances");
    add_acceptances(g, all);
}

/// Genesis where ALICE and CAROL hold the Grant to contribute, ALICE issues `court_order` and
/// `ownership_changed` Claims under a predicate-input Acceptance and `shop:wipe` is published.
fn legal_genesis() -> (BTreeMap<String, Opened>, [u64; 2]) {
    let mut g = gated(&[]);
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let Value::Map(mut carol) = grants.get(1).unwrap().clone() else {
        panic!("a grant is a map");
    };
    for (k, v) in &mut carol {
        if *k == Value::text("holder") {
            *v = SubjectSelector::Party(CAROL).to_value();
        }
    }
    grants.push(Value::Map(carol));
    grants.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
    let held = |party: Id| {
        let holder = SubjectSelector::Party(party).to_value();
        u64::try_from(
            grants
                .iter()
                .position(|v| v.get("holder") == Some(&holder))
                .unwrap(),
        )
        .unwrap()
    };
    let index = [held(ALICE), held(CAROL)];
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    publish_wipe(&mut g);
    add_acceptances(
        &mut g,
        vec![Value::Map(vec![
            (Value::text("issuer"), ALICE.to_value()),
            (Value::text("use"), Value::text("predicate-input")),
            (
                Value::text("classes"),
                Value::Array(vec![
                    Value::text(legal::COURT_ORDER),
                    Value::text(OWNERSHIP_CHANGED),
                ]),
            ),
            (Value::text("subject"), SubjectSelector::Public.to_value()),
            (
                Value::text("validity"),
                Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
            ),
        ])],
    );
    (g, index)
}

async fn core_of(db: &TestDb, g: BTreeMap<String, Opened>) -> (Core, Digest) {
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
        .await
        .unwrap();
    let log = PgLog::new(db.sequencer.clone(), d, TENANT, "t".to_owned(), TTL);
    let leader = Leader::acquire(log, d, EventKey::new(Secret::new([5; 32])))
        .await
        .unwrap();
    let reader = PgReader::new(db.app.clone(), DomainId::from_bytes(d.0));
    let mut bound = binding();
    bound
        .0
        .insert(thumbprint(&public(CAROL_KEY)), (CAROL, public(CAROL_KEY)));
    bound.0.insert(
        thumbprint(&public(ALICE_SPARE_KEY)),
        (ALICE, public(ALICE_SPARE_KEY)),
    );
    let mut core: Core = Authority::new(leader, reader, bound, Counter(0), d);
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ALICE, ALICE_KEY, (3, 4)).await;
    onboard(&mut core, d, BOB, BOB_KEY, (5, 6)).await;
    onboard(&mut core, d, CAROL, CAROL_KEY, (7, 8)).await;
    (core, d)
}

fn shop_anchor(d: Digest) -> Id {
    meta::object_id(&d, kind::ANCHOR, 1)
}

/// The predicate-input Acceptance that admits ALICE's `court_order` Claims.
async fn court_acceptance(db: &TestDb, d: Digest) -> Digest {
    for seq in 0..8 {
        let key = meta::key(
            kind::ACCEPTANCE,
            &meta::object_id(&d, kind::ACCEPTANCE, seq),
        );
        let Some(state) = state_of(db, d, &key).await else {
            continue;
        };
        let state =
            meta::ContentState::from_value(&dcbor::decode(&state, Limits::CEILING).unwrap())
                .unwrap();
        if state.content.get("classes").is_some_and(
            |c| matches!(c, Value::Array(a) if a.contains(&Value::text(legal::COURT_ORDER))),
        ) {
            return access_kernel::claim::acceptance_digest(&state.content);
        }
    }
    panic!("no court_order Acceptance");
}

fn legal_setup(d: Digest, acceptance: Digest) -> Setup {
    Setup {
        basis: GrantBasis::Anchor(shop_anchor(d)),
        holder: LEGAL,
        actions: BTreeSet::from([wipe()]),
        resource: selector("shop"),
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
        approvals: 2,
        approvers: None,
        acceptance,
    }
}

fn issue(d: Digest, nonce: u8, content: GrantContent) -> Request {
    meta_request(
        d,
        nonce,
        ExerciseBasis::Anchor(shop_anchor(d)),
        Payload::GrantIssue(content),
    )
}

fn wipe_request(d: Digest, nonce: u8, basis: ExerciseBasis, purpose: Option<&str>) -> Request {
    let mut r = shop_request(d, nonce, Mode::Commit, basis);
    r.intent.action = wipe();
    r.intent.purpose = purpose.map(|p| access_kernel::model::PurposeRef::Code(p.to_owned()));
    r.intent.validity = Window {
        from: NOW - 1_000,
        until: NOW + 3_600_000,
    };
    r
}

fn wipe_render(req: &Request) -> Digest {
    let r = access_kernel::render::of(
        Some(&wipe_schema()),
        &req.intent,
        access_kernel::render::DEFAULT_LOCALE,
    )
    .unwrap();
    access_kernel::render::digest(&r).unwrap()
}

/// The CT3 authenticator class (§13.7.3).
const CT3_KEY: [(&str, u64); 6] = [
    ("aal", 3),
    ("phishing_resistant", 1),
    ("uv", 1),
    ("human_presence", 1),
    ("hardware_bound", 1),
    ("non_custodial", 1),
];

fn authentication(d: Digest, subject: Id, value: Vec<u8>, bound: Digest) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(value)),
            issued_at: NOW - 1_000,
            validity: Window {
                from: NOW - 1_000,
                until: NOW + 3_600_000,
            },
            assurance: CT3_KEY.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
            bound_intent: Some(bound),
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

/// `party`'s legal-process approval of `target` on its contribute Grant `grant`, its Instance
/// opened by `instance_nonce`.
fn approval(
    d: Digest,
    (party, grant, instance_nonce): (Id, u64, u8),
    nonce: u8,
    target: Digest,
    render: Digest,
) -> Request {
    let payload = Payload::Contribute {
        target,
        class: legal::APPROVAL.to_owned(),
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
        path: vec![legal::APPROVAL.to_owned()],
        incarnation: 0,
    }];
    let p = r.payload.clone().unwrap();
    r.intent.opaque = BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]);
    let mut act = approval_act(d, nonce, target, render, NOW - 1_000, NOW + 60_000);
    act.act = Act::Contribution(legal::APPROVAL.to_owned());
    act.party = party;
    act.instance = meta::object_id(
        &meta::exercise_id(&d, &[instance_nonce; 16]).unwrap(),
        kind::INSTANCE,
        0,
    );
    let h = access_kernel::aas::digest(&act).unwrap();
    let claim = authentication(d, party, vec![0xaa; 32], h);
    with_proofs(
        r,
        vec![
            ProofRef::Aas(act.to_bytes().unwrap()),
            ProofRef::Claim(claim),
        ],
    )
}

/// A Claim of `class` by ALICE about `subject` whose value is `value`.
fn seam_claim(d: Digest, subject: Id, class: &str, value: [u8; 32]) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: class.to_owned(),
            value: Some(EqValue::Bytes(value.to_vec())),
            issued_at: NOW - 1_000,
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

/// Records `claim` by carrying it on ROOT's own check (the commit path admits carried Claims).
async fn record_claim(core: &mut Core, d: Digest, nonce: u8, claim: Vec<u8>) {
    send(
        core,
        with_proofs(
            shop_request(
                d,
                nonce,
                Mode::Commit,
                ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            ),
            vec![ProofRef::Claim(claim)],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
}

fn subcode(r: &Response, code: &str) -> bool {
    r.decision
        .blockers
        .iter()
        .any(|b| b.subcode.as_deref() == Some(code))
}

// CI-13, SI-22, §6.1, §7.9.12.7, OP-157 m.3 (i), Ek B 5540, 5668
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one court order through its Grant")]
async fn a_court_order_acts_only_through_the_legal_process_grant_and_its_approvals() {
    let db = fresh().await.unwrap();
    let (g, index) = legal_genesis();
    let (mut core, d) = core_of(&db, g).await;
    let acceptance = court_acceptance(&db, d).await;
    let content = legal_setup(d, acceptance).grant().unwrap();

    let mut bare = content.clone();
    bare.authority.constraints.conditions.clear();
    assert!(matches!(
        send(&mut core, issue(d, 10, bare), ROOT_KEY).await,
        Err(CoreError::Protocol("legal-process-grant"))
    ));
    let mut alone = content.clone();
    alone.authority.requirements = BTreeSet::from([legal::approval_term(1, None)]);
    assert!(matches!(
        send(&mut core, issue(d, 11, alone), ROOT_KEY).await,
        Err(CoreError::Protocol("legal-process-grant"))
    ));

    let issued = send(&mut core, issue(d, 12, content), ROOT_KEY)
        .await
        .unwrap();
    allowed(&issued);
    let held = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder: LEGAL,
        since: issued.record.unwrap(),
    });

    let lapsed = send(
        &mut core,
        wipe_request(d, 20, held, Some(legal::PURPOSE)),
        LEGAL_KEY,
    )
    .await
    .unwrap();
    assert_eq!(lapsed.decision.outcome, Outcome::Deny, "{lapsed:?}");
    assert!(subcode(&lapsed, "ended/lapsed"), "{lapsed:?}");

    let order = legal::body(
        &Digest([0x0c; 32]),
        "TR",
        &BTreeSet::from([String::from("shop:wipe")]),
        900_000,
    );
    record_claim(
        &mut core,
        d,
        21,
        seam_claim(d, LEGAL, legal::COURT_ORDER, legal::value_digest(&order)),
    )
    .await;

    // CI-13
    let by_claim = send(
        &mut core,
        wipe_request(
            d,
            22,
            ExerciseBasis::Anchor(shop_anchor(d)),
            Some(legal::PURPOSE),
        ),
        LEGAL_KEY,
    )
    .await
    .unwrap();
    assert_eq!(by_claim.decision.outcome, Outcome::Deny, "{by_claim:?}");
    let undeclared = send(&mut core, wipe_request(d, 23, held, None), LEGAL_KEY)
        .await
        .unwrap();
    assert_ne!(
        undeclared.decision.outcome,
        Outcome::Allow,
        "{undeclared:?}"
    );

    let target = wipe_request(d, 24, held, Some(legal::PURPOSE));
    let asked = send(&mut core, target.clone(), LEGAL_KEY).await.unwrap();
    assert_eq!(asked.decision.outcome, Outcome::RequireAction, "{asked:?}");
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let shown = wipe_render(&target);
    let mut proofs = Vec::new();
    for ((party, at, inst), key, nonce) in [
        ((ALICE, index[0], 4), ALICE_KEY, 30),
        ((CAROL, index[1], 8), CAROL_KEY, 31),
    ] {
        let given = send(
            &mut core,
            approval(d, (party, at, inst), nonce, digest, shown),
            key,
        )
        .await
        .unwrap();
        allowed(&given);
        proofs.push(ProofRef::Contribution(given.exercise.unwrap()));
    }
    let one = send(
        &mut core,
        with_proofs(
            target.clone(),
            vec![
                proofs[0].clone(),
                ProofRef::Claim(authentication(d, LEGAL, digest.0.to_vec(), digest)),
            ],
        ),
        LEGAL_KEY,
    )
    .await
    .unwrap();
    assert_eq!(one.decision.outcome, Outcome::RequireAction, "{one:?}");
    proofs.push(ProofRef::Claim(authentication(
        d,
        LEGAL,
        digest.0.to_vec(),
        digest,
    )));
    let used = send(&mut core, with_proofs(target, proofs), LEGAL_KEY)
        .await
        .unwrap();
    allowed(&used);
    fold_check(&db.sequencer, d).await.unwrap();
}

// CI-13, §7.9.9.2, OP-157 m.3 (i), Ek B 5669
#[tokio::test]
async fn an_ownership_change_moves_no_root_by_itself() {
    let db = fresh().await.unwrap();
    let (g, _) = legal_genesis();
    let (mut core, d) = core_of(&db, g).await;
    let anchor = shop_anchor(d);
    let change = OwnershipChanged {
        anchor,
        from: ROOT,
        to: CAROL,
        effective_at: NOW - 5_000,
    };
    record_claim(
        &mut core,
        d,
        20,
        seam_claim(d, CAROL, OWNERSHIP_CHANGED, change.value_digest()),
    )
    .await;
    let take = |nonce| {
        meta_request(
            d,
            nonce,
            ExerciseBasis::Anchor(anchor),
            Payload::AnchorTransfer {
                anchor,
                root: Root::Sole(CAROL),
                disposition: BTreeMap::new(),
            },
        )
    };
    let taken = send(&mut core, take(21), CAROL_KEY).await;
    assert!(
        taken.as_ref().is_err() || taken.as_ref().unwrap().decision.outcome == Outcome::Deny,
        "{taken:?}"
    );
    let still = send(
        &mut core,
        shop_request(d, 22, Mode::Check, ExerciseBasis::Anchor(anchor)),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&still);
    fold_check(&db.sequencer, d).await.unwrap();
}

/// Genesis whose meta-anchor ROOT and SECURITY root jointly, either acting alone (k = 1), and
/// where ALICE holds a Grant to read the shop, at the index returned.
fn joint_genesis() -> (BTreeMap<String, Opened>, u64) {
    let mut g = genesis();
    let joint = Value::Map(vec![(
        Value::text("joint"),
        Value::Map(vec![
            (Value::text("k"), Value::Unsigned(1)),
            (
                Value::text("parties"),
                Value::Array(vec![ROOT.to_value(), SECURITY.to_value()]),
            ),
        ]),
    )]);
    g.insert(
        "meta_anchor".to_owned(),
        Opened {
            value: Value::Map(vec![(Value::text("root"), joint)]),
            salt: [3; 32],
        },
    );
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    grants.push(Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(1)),
        (
            Value::text("holder"),
            SubjectSelector::Party(ALICE).to_value(),
        ),
        (
            Value::text("authority"),
            authority(vec![action("shop", "read")], selector("shop")).to_value(),
        ),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ]));
    grants.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
    let alice = SubjectSelector::Party(ALICE).to_value();
    let index = u64::try_from(
        grants
            .iter()
            .position(|v| v.get("holder") == Some(&alice))
            .unwrap(),
    )
    .unwrap();
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    (g, index)
}

fn contain(d: Digest, nonce: u8, c: &Containment) -> Request {
    meta_request(
        d,
        nonce,
        ExerciseBasis::Anchor(meta::meta_anchor(&d)),
        Payload::PolicySet {
            policy: None,
            content: containment(c, None).unwrap(),
            defaults: None,
        },
    )
}

fn restricted(r: &Response) -> bool {
    r.decision.outcome == Outcome::Deny
        && r.decision
            .blockers
            .iter()
            .any(|b| b.class == BlockerClass::Restricted)
}

// SI-4, RT3, RT9, §6.6, §7.9.12.1, §11.9.2, §17.7.3, OP-157 m.3 (b), (i), Ek B 5541, 5581, 5659
#[tokio::test]
#[allow(clippy::too_many_lines, reason = "one containment from start to lift")]
async fn security_contains_with_one_narrowing_exercise_and_lifting_it_widens() {
    let db = fresh().await.unwrap();
    let (g, index) = joint_genesis();
    let (mut core, d) = core_of(&db, g).await;
    allowed(
        &send(
            &mut core,
            meta_request(
                d,
                9,
                ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0)),
                Payload::InstanceCreate {
                    party: ALICE,
                    key: public(ALICE_SPARE_KEY),
                    mandate: None,
                },
            ),
            ALICE_SPARE_KEY,
        )
        .await
        .unwrap(),
    );
    let alice = ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&d, kind::GRANT, index),
        holder: ALICE,
        since: 0,
    });
    allowed(
        &send(
            &mut core,
            shop_request(d, 10, Mode::Commit, alice),
            ALICE_KEY,
        )
        .await
        .unwrap(),
    );

    // §11.9.2
    let first = meta::object_id(&meta::exercise_id(&d, &[4; 16]).unwrap(), kind::INSTANCE, 0);
    let suspended_instance = send(
        &mut core,
        contain(d, 11, &Containment::SuspendInstance { instance: first }),
        SECURITY_KEY,
    )
    .await
    .unwrap();
    allowed(&suspended_instance);
    assert_eq!(suspended_instance.decision.blockers, Vec::new());
    assert!(restricted(
        &send(
            &mut core,
            shop_request(d, 12, Mode::Commit, alice),
            ALICE_KEY
        )
        .await
        .unwrap()
    ));
    allowed(
        &send(
            &mut core,
            shop_request(d, 13, Mode::Commit, alice),
            ALICE_SPARE_KEY,
        )
        .await
        .unwrap(),
    );

    // SI-4
    let suspended = send(
        &mut core,
        contain(d, 14, &Containment::SuspendParty { party: ALICE }),
        SECURITY_KEY,
    )
    .await
    .unwrap();
    allowed(&suspended);
    assert!(restricted(
        &send(
            &mut core,
            shop_request(d, 15, Mode::Commit, alice),
            ALICE_SPARE_KEY,
        )
        .await
        .unwrap()
    ));
    let party_policy = meta::object_id(&suspended.exercise.unwrap(), kind::POLICY, 0);

    // RT9
    let lift = send(
        &mut core,
        meta_request(
            d,
            16,
            ExerciseBasis::Anchor(meta::meta_anchor(&d)),
            Payload::PolicyRetire {
                policy: party_policy,
            },
        ),
        SECURITY_KEY,
    )
    .await
    .unwrap();
    assert_eq!(lift.decision.outcome, Outcome::RequireAction, "{lift:?}");
    assert!(
        lift.decision
            .unmet
            .iter()
            .any(|u| u.term.class == "co_root" && u.missing == 1),
        "{lift:?}"
    );
    assert!(
        suspended
            .decision
            .unmet
            .iter()
            .all(|u| u.term.class != "co_root")
    );
    assert!(restricted(
        &send(
            &mut core,
            shop_request(d, 17, Mode::Commit, alice),
            ALICE_SPARE_KEY,
        )
        .await
        .unwrap()
    ));

    // §6.6
    let contained = send(
        &mut core,
        contain(
            d,
            18,
            &Containment::ContainDomainAction {
                actions: BTreeSet::from([String::from("shop:read")]),
            },
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&contained);
    assert!(restricted(
        &send(
            &mut core,
            shop_request(d, 19, Mode::Commit, ExerciseBasis::Anchor(shop_anchor(d))),
            ROOT_KEY,
        )
        .await
        .unwrap()
    ));
    let no_root = send(
        &mut core,
        contain(d, 20, &Containment::SuspendParty { party: ROOT }),
        CAROL_KEY,
    )
    .await;
    assert!(
        no_root.as_ref().is_err() || no_root.as_ref().unwrap().decision.outcome != Outcome::Allow,
        "{no_root:?}"
    );
    fold_check(&db.sequencer, d).await.unwrap();
}
