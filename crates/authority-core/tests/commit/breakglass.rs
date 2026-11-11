//! Break-glass at the authority level on the real store (G29, INV-28, TN-93, §12.3.8,
//! OP-157 m.3 (h)): only a pre-issued break-glass Grant with its approvals acts on a reserved
//! action, within its own time limit, and only a declared exemption lifts a blocking rule.

use access_authority_core::app::breakglass::{self, Setup};

use super::*;

/// Genesis where ALICE, BOB and CAROL hold the Grant to contribute and the CT3 time-lock is
/// `delay_s`.
fn three_approvers(delay_s: Option<u64>) -> (BTreeMap<String, Opened>, [u64; 3]) {
    let mut g = gated(&[]);
    match delay_s {
        Some(s) => {
            g.insert(
                "policy".to_owned(),
                Opened {
                    value: Value::Map(vec![(Value::text("ct3_delay_s"), Value::Unsigned(s))]),
                    salt: [3; 32],
                },
            );
        }
        None => {
            g.remove("policy");
        }
    }
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let alice = grants.get(1).unwrap().clone();
    for party in [BOB, CAROL] {
        let Value::Map(mut m) = alice.clone() else {
            panic!("a grant is a map");
        };
        for (k, v) in &mut m {
            if *k == Value::text("holder") {
                *v = SubjectSelector::Party(party).to_value();
            }
        }
        grants.push(Value::Map(m));
    }
    grants.sort_by_key(|v| dcbor::encode(v, Limits::CEILING).unwrap());
    with_wipe(&mut g);
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
    let index = [held(ALICE), held(BOB), held(CAROL)];
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    (g, index)
}

fn wipe_schema() -> access_kernel::schema::ActionSchema {
    access_kernel::schema::ActionSchema {
        reserved: true,
        ..schema_of("wipe")
    }
}

/// `shop:wipe`, a reserved action: CT3 (§13.7.1).
fn wipe() -> ActionRef {
    ActionRef {
        schema: access_kernel::schema::action_digest(&wipe_schema()),
        ..action("shop", "wipe")
    }
}

/// Publishes `shop:wipe` beside `shop:read` in the Genesis `g`.
fn with_wipe(g: &mut BTreeMap<String, Opened>) {
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

/// The break-glass setup of ALICE and BOB for wiping the shop.
fn wipe_setup(d: Digest) -> Setup {
    Setup {
        basis: GrantBasis::Anchor(shop_anchor(d)),
        holders: BTreeSet::from([ALICE, BOB]),
        actions: BTreeSet::from([wipe()]),
        resource: selector("shop"),
        validity: Window {
            from: 0,
            until: 1_000_000,
        },
        approvals: 2,
        approvers: None,
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

fn holding_of(issued: &Response, holder: Id) -> ExerciseBasis {
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&issued.exercise.unwrap(), kind::GRANT, 0),
        holder,
        since: issued.record.unwrap(),
    })
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

/// The render digest of a `shop:wipe` intent.
fn wipe_render(req: &Request) -> Digest {
    let r = access_kernel::render::of(
        Some(&wipe_schema()),
        &req.intent,
        access_kernel::render::DEFAULT_LOCALE,
    )
    .unwrap();
    access_kernel::render::digest(&r).unwrap()
}

/// `party`'s break-glass approval of `target` on its contribute Grant `grant`, its Instance
/// opened by `instance_nonce`.
fn breakglass_approval(
    d: Digest,
    (party, grant, instance_nonce): (Id, u64, u8),
    nonce: u8,
    target: Digest,
    render: Digest,
) -> Request {
    let payload = Payload::Contribute {
        target,
        class: breakglass::APPROVAL.to_owned(),
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
        path: vec![breakglass::APPROVAL.to_owned()],
        incarnation: 0,
    }];
    let p = r.payload.clone().unwrap();
    r.intent.opaque = BTreeMap::from([("payload".to_owned(), p.digest().unwrap())]);
    let mut act = approval_act(d, nonce, target, render, NOW - 1_000, NOW + 60_000);
    act.act = Act::Contribution(breakglass::APPROVAL.to_owned());
    act.party = party;
    act.instance = meta::object_id(
        &meta::exercise_id(&d, &[instance_nonce; 16]).unwrap(),
        kind::INSTANCE,
        0,
    );
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
            assurance: CT3_KEY.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
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

/// Asks with `target`, has ALICE and CAROL approve it and asks again with their approvals.
async fn with_approvals(
    core: &mut Core,
    d: Digest,
    index: [u64; 3],
    (target, seed): (Request, u8),
    nonces: (u8, u8),
) -> (Response, Response) {
    let asked = send(core, target.clone(), seed).await.unwrap();
    let digest = access_kernel::intent::intent_digest(&target.intent).unwrap();
    let shown = wipe_render(&target);
    let mut proofs = Vec::new();
    for ((party, at, inst), key, nonce) in [
        ((ALICE, index[0], 4), ALICE_KEY, nonces.0),
        ((CAROL, index[2], 8), CAROL_KEY, nonces.1),
    ] {
        let given = send(
            core,
            breakglass_approval(d, (party, at, inst), nonce, digest, shown),
            key,
        )
        .await
        .unwrap();
        allowed(&given);
        proofs.push(ProofRef::Contribution(given.exercise.unwrap()));
    }
    proofs.push(ProofRef::Claim(hardware_sign_in(d, BOB, digest)));
    let decided = send(core, with_proofs(target, proofs), seed).await.unwrap();
    (asked, decided)
}

/// The CT3 authenticator class: a hardware-bound, user-verified, phishing-resistant key
/// (§13.7.3), what a break-glass account signs in with (§10.2.5).
const CT3_KEY: [(&str, u64); 6] = [
    ("aal", 3),
    ("phishing_resistant", 1),
    ("uv", 1),
    ("human_presence", 1),
    ("hardware_bound", 1),
    ("non_custodial", 1),
];

/// `subject`'s fresh hardware-key authentication bound to the intent `digest`: the CT3
/// authenticator class (§13.7.3) a break-glass account signs in with (§10.2.5).
fn hardware_sign_in(d: Digest, subject: Id, digest: Digest) -> Vec<u8> {
    sign_claim(
        &access_kernel::claim::Statement {
            domain: d,
            issuer: ALICE,
            subject,
            class: "authentication".to_owned(),
            value: Some(EqValue::Bytes(digest.0.to_vec())),
            issued_at: NOW - 1_000,
            validity: Window {
                from: NOW - 1_000,
                until: NOW + 3_600_000,
            },
            assurance: CT3_KEY.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect(),
            bound_intent: Some(digest),
            bound_instance: None,
            bound_resource: None,
            supersedes: None,
        },
        ALICE_KEY,
    )
}

// G29, INV-28, TN-93, §12.3.8, §13.7.3, OP-157 m.3 (h), Ek B 5488, 5534, 5653, 5663
#[tokio::test]
async fn only_a_breakglass_grant_with_its_approvals_acts_and_within_its_own_limit() {
    let db = fresh().await.unwrap();
    let (g, index) = three_approvers(None);
    let (mut core, d) = core_of(&db, g).await;
    let grants = wipe_setup(d).grants().unwrap();
    let alice = grants
        .iter()
        .find(|c| c.holder == SubjectSelector::Party(BOB))
        .unwrap()
        .clone();
    let issued = send(&mut core, issue(d, 10, alice.clone()), ROOT_KEY)
        .await
        .unwrap();
    allowed(&issued);
    let bg = holding_of(&issued, BOB);

    // G29
    let mut bare = alice.clone();
    bare.authority.requirements.clear();
    assert!(matches!(
        send(&mut core, issue(d, 11, bare), ROOT_KEY).await,
        Err(CoreError::Protocol("breakglass-grant"))
    ));

    // INV-28
    let nothing = send(
        &mut core,
        wipe_request(
            d,
            19,
            ExerciseBasis::Anchor(shop_anchor(d)),
            Some(breakglass::PURPOSE),
        ),
        BOB_KEY,
    )
    .await
    .unwrap();
    assert_eq!(nothing.decision.outcome, Outcome::Deny, "{nothing:?}");
    let alone = send(
        &mut core,
        wipe_request(d, 20, bg, Some(breakglass::PURPOSE)),
        BOB_KEY,
    )
    .await
    .unwrap();
    assert_eq!(alone.decision.outcome, Outcome::RequireAction, "{alone:?}");
    let undeclared = send(&mut core, wipe_request(d, 21, bg, None), BOB_KEY)
        .await
        .unwrap();
    assert_ne!(
        undeclared.decision.outcome,
        Outcome::Allow,
        "{undeclared:?}"
    );

    let (_, used) = with_approvals(
        &mut core,
        d,
        index,
        (wipe_request(d, 22, bg, Some(breakglass::PURPOSE)), BOB_KEY),
        (30, 31),
    )
    .await;
    allowed(&used);

    // §13.7.3, Ek B 5663
    let mut long = wipe_request(d, 25, bg, Some(breakglass::PURPOSE));
    long.intent.validity.until = long.intent.validity.from + breakglass::USE_MAX_MS + 1;
    assert!(matches!(
        send(&mut core, long, BOB_KEY).await,
        Err(CoreError::Protocol("intent-validity"))
    ));

    // §12.3.8 (5)
    let (_, drill) = with_approvals(
        &mut core,
        d,
        index,
        (wipe_request(d, 26, bg, Some(breakglass::DRILL)), BOB_KEY),
        (32, 33),
    )
    .await;
    allowed(&drill);
    fold_check(&db.sequencer, d).await.unwrap();
}

const FREEZE: &str =
    r#"@id("freeze") forbid(principal, action, resource) when { context.action == "shop:wipe" };"#;

const EXEMPT: &str = r#"@id("freeze") @breakglass_exempt forbid(principal, action, resource) when { context.action == "shop:wipe" };"#;

// TN-93, §5.8, §12.3.8 (6), OP-157 m.3 (h), Ek B 5538
#[tokio::test]
async fn only_a_declared_exemption_lets_breakglass_past_a_blocking_rule() {
    let db = fresh().await.unwrap();
    let (g, index) = three_approvers(Some(0));
    let (mut core, d) = core_of(&db, g).await;
    let grants = wipe_setup(d).grants().unwrap();
    let alice = grants
        .iter()
        .find(|c| c.holder == SubjectSelector::Party(BOB))
        .unwrap()
        .clone();
    let issued = send(&mut core, issue(d, 10, alice.clone()), ROOT_KEY)
        .await
        .unwrap();
    allowed(&issued);
    let bg = holding_of(&issued, BOB);
    let mut ordinary = alice;
    ordinary.authority.authority.purpose = None;
    ordinary.authority.requirements.clear();
    let plain_grant = send(&mut core, issue(d, 11, ordinary), ROOT_KEY)
        .await
        .unwrap();
    allowed(&plain_grant);
    let plain = holding_of(&plain_grant, BOB);
    let set = send(&mut core, policy_set(d, 12, None, FREEZE, None), ROOT_KEY)
        .await
        .unwrap();
    allowed(&set);
    let freeze = meta::object_id(&set.exercise.unwrap(), kind::POLICY, 0);

    // §5.8
    let stopped = send(
        &mut core,
        wipe_request(d, 20, bg, Some(breakglass::PURPOSE)),
        BOB_KEY,
    )
    .await
    .unwrap();
    assert_eq!(stopped.decision.outcome, Outcome::Deny, "{stopped:?}");
    assert!(
        stopped
            .decision
            .blockers
            .iter()
            .any(|b| b.class == BlockerClass::Restricted)
    );

    allowed(
        &send(
            &mut core,
            policy_set(d, 13, Some(freeze), EXEMPT, None),
            ROOT_KEY,
        )
        .await
        .unwrap(),
    );
    let (_, through) = with_approvals(
        &mut core,
        d,
        index,
        (wipe_request(d, 21, bg, Some(breakglass::PURPOSE)), BOB_KEY),
        (32, 33),
    )
    .await;
    allowed(&through);
    let others = send(&mut core, wipe_request(d, 22, plain, None), BOB_KEY)
        .await
        .unwrap();
    assert_eq!(others.decision.outcome, Outcome::Deny, "{others:?}");

    // TN-93
    assert!(matches!(
        send(
            &mut core,
            policy_set(
                d,
                14,
                Some(freeze),
                r#"@id("freeze") @require("rs-x") @breakglass_exempt forbid(principal, action, resource);"#,
                Some(Value::Map(vec![(
                    Value::text("rs-x"),
                    Value::Array(vec![
                        term(ProofKind::Claim, "kyc", ProofBinding::None).to_value()
                    ]),
                )])),
            ),
            ROOT_KEY,
        )
        .await,
        Err(CoreError::Protocol("policy"))
    ));
    fold_check(&db.sequencer, d).await.unwrap();
}
