//! The tenant administrator rule on the real store (OP-159 m.47 (d), (e), (f), TN-109): a
//! rule-shaped Grant whose holder is `Pred{tenant_administration}` from the management
//! environment's issuer covers the console's meta-action bases and domain actions for as long
//! as that issuer's Claim about the Party is live.

use super::*;

/// The primary environment's issuer in the consuming domain.
const ISSUER: Id = ALICE;
const ISSUER_KEY: u8 = ALICE_KEY;
/// A tenant administrator's Party in the consuming domain.
const ADMIN: Id = BOB;
const ADMIN_KEY: u8 = BOB_KEY;

const CLASS: &str = "tenant_administration";

fn meta_bases() -> [(&'static str, &'static str); 5] {
    [
        ("grant_issue", "access.domain"),
        ("authority_set_define", "access.domain"),
        ("policy_set", "access.domain"),
        ("acceptance_establish", "access.domain"),
        ("read", "access.audit"),
    ]
}

fn rule() -> SubjectSelector {
    SubjectSelector::Pred(BTreeSet::from([access_kernel::model::Conjunct {
        claim_class: CLASS.to_owned(),
        value: Some(EqValue::Bool(true)),
    }]))
}

fn rule_grant(anchor: u64, authority: &CanonicalAuthority) -> Value {
    Value::Map(vec![
        (Value::text("anchor"), Value::Unsigned(anchor)),
        (Value::text("holder"), rule().to_value()),
        (Value::text("authority"), authority.to_value()),
        (
            Value::text("agency"),
            Value::Array(vec![meta::capacity_value(Capacity::Own)]),
        ),
    ])
}

/// The Genesis indices of the three rule Grants and of the control Grant to the administrator
/// by name.
#[derive(Clone, Copy)]
struct Rule {
    meta: u64,
    audit: u64,
    shop: u64,
    named: u64,
}

/// Genesis with the administrator rule: on the meta-anchor the console's meta-actions over
/// `access.domain` and the audit read, on the `shop` Anchor its domain actions; and the
/// issuer's `subject-selection` Acceptance of `tenant_administration`.
fn administered() -> (BTreeMap<String, Opened>, Rule) {
    let mut g = genesis();
    let Some(Value::Array(mut grants)) = g.get("grants").map(|o| o.value.clone()) else {
        panic!("genesis has grants");
    };
    let core = |names: &[&str], ns: &str| {
        authority(
            names.iter().map(|n| meta::core_action(n)).collect(),
            selector(ns),
        )
    };
    let rules = [
        rule_grant(
            0,
            &core(
                &[
                    "grant_issue",
                    "authority_set_define",
                    "policy_set",
                    "acceptance_establish",
                ],
                "access.domain",
            ),
        ),
        rule_grant(0, &core(&["read", "audit_export"], "access.audit")),
        rule_grant(
            1,
            &authority(vec![action("shop", "read")], selector("shop")),
        ),
        Value::Map(vec![
            (Value::text("anchor"), Value::Unsigned(0)),
            (
                Value::text("holder"),
                SubjectSelector::Party(ADMIN).to_value(),
            ),
            (
                Value::text("authority"),
                core(&["authority_set_define"], "access.domain").to_value(),
            ),
            (
                Value::text("agency"),
                Value::Array(vec![meta::capacity_value(Capacity::Own)]),
            ),
        ]),
    ];
    let bytes = |v: &Value| dcbor::encode(v, Limits::CEILING).unwrap();
    grants.extend(rules.iter().cloned());
    grants.sort_by_key(|v| bytes(v));
    let index = |r: &Value| {
        let at = grants.iter().position(|v| bytes(v) == bytes(r)).unwrap();
        u64::try_from(at).unwrap()
    };
    let rule = Rule {
        meta: index(&rules[0]),
        audit: index(&rules[1]),
        shop: index(&rules[2]),
        named: index(&rules[3]),
    };
    g.insert(
        "grants".to_owned(),
        Opened {
            value: Value::Array(grants),
            salt: [3; 32],
        },
    );
    let acceptance = Value::Map(vec![
        (Value::text("issuer"), ISSUER.to_value()),
        (Value::text("use"), Value::text("subject-selection")),
        (
            Value::text("classes"),
            Value::Array(vec![Value::text(CLASS)]),
        ),
        (Value::text("subject"), SubjectSelector::Public.to_value()),
        (
            Value::text("validity"),
            Value::Array(vec![Value::Unsigned(0), Value::Unsigned(1_000_000)]),
        ),
    ]);
    add_acceptances(&mut g, vec![acceptance]);
    (g, rule)
}

fn statement(
    d: Digest,
    value: bool,
    from: u64,
    supersedes: Option<Id>,
) -> access_kernel::claim::Statement {
    access_kernel::claim::Statement {
        domain: d,
        issuer: ISSUER,
        subject: ADMIN,
        class: CLASS.to_owned(),
        value: Some(EqValue::Bool(value)),
        issued_at: NOW,
        validity: Window {
            from,
            until: 1_000_000,
        },
        assurance: BTreeMap::new(),
        bound_intent: None,
        bound_instance: None,
        bound_resource: None,
        supersedes,
    }
}

fn check(d: Digest, nonce: u8, (name, ns): (&str, &str), basis: ExerciseBasis) -> Request {
    Request {
        domain: d,
        mode: Mode::Check,
        nonce: vec![nonce; 16],
        intent: intent(meta::core_action(name), (ns, "acme"), None),
        payload: None,
        basis,
        capacity: Capacity::Own,
        proofs: Vec::new(),
        exercise: None,
        consistency: None,
    }
}

/// The eligibility of `req` for the administrator: coverage only, no AIS (OP-151 m.20 (d)).
async fn probe(core: &mut Core, req: Request, now: u64) -> Response {
    let mut inc = incoming(req, ADMIN_KEY);
    inc.ais = None;
    core.eligible(&inc, ADMIN, now).await.unwrap()
}

/// Ingests `claim` by presenting it on a root request; returns the record of that Claim.
async fn ingest(core: &mut Core, d: Digest, nonce: u8, claim: Vec<u8>) -> u64 {
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let r = send(
        core,
        with_proofs(
            shop_request(d, nonce, Mode::Commit, shop),
            vec![ProofRef::Claim(claim)],
        ),
        ROOT_KEY,
    )
    .await
    .unwrap();
    allowed(&r);
    r.record.unwrap().checked_sub(2).unwrap()
}

fn holding(d: Digest, index: u64, since: u64) -> ExerciseBasis {
    ExerciseBasis::Holding(HoldingRef {
        grant: meta::object_id(&d, kind::GRANT, index),
        holder: ADMIN,
        since,
    })
}

fn basis_of(d: Digest, rule: Rule, (_, ns): (&str, &str), since: u64) -> ExerciseBasis {
    holding(
        d,
        if ns == "access.audit" {
            rule.audit
        } else {
            rule.meta
        },
        since,
    )
}

// OP-159 m.47 (d), (f), TN-139, INV-31, C13
#[tokio::test]
async fn a_tenant_administration_claim_selects_the_admin_rule_until_it_ends() {
    let db = fresh().await.unwrap();
    let (g, rule) = administered();
    let (mut core, d) = setup_with(&db, g).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ISSUER, ISSUER_KEY, (3, 4)).await;
    onboard(&mut core, d, ADMIN, ADMIN_KEY, (5, 6)).await;

    for (i, base) in meta_bases().into_iter().enumerate() {
        let r = probe(
            &mut core,
            check(
                d,
                10 + u8::try_from(i).unwrap(),
                base,
                basis_of(d, rule, base, 0),
            ),
            NOW,
        )
        .await;
        assert_eq!(r.decision.outcome, Outcome::Deny, "{base:?}: {r:?}");
    }

    let first = sign_claim(&statement(d, true, 0, None), ISSUER_KEY);
    let first_id = access_kernel::claim::claim_id(&first);
    let episode = ingest(&mut core, d, 20, first).await;

    for (i, base) in meta_bases().into_iter().enumerate() {
        let r = probe(
            &mut core,
            check(
                d,
                30 + u8::try_from(i).unwrap(),
                base,
                basis_of(d, rule, base, episode),
            ),
            NOW,
        )
        .await;
        allowed(&r);
    }
    allowed(
        &send(
            &mut core,
            shop_request(d, 40, Mode::Commit, holding(d, rule.shop, episode)),
            ADMIN_KEY,
        )
        .await
        .unwrap(),
    );

    // OP-159 m.47 (f)
    let end = sign_claim(&statement(d, false, 0, Some(first_id)), ISSUER_KEY);
    ingest(&mut core, d, 41, end).await;
    for (i, base) in meta_bases().into_iter().enumerate() {
        let r = probe(
            &mut core,
            check(
                d,
                50 + u8::try_from(i).unwrap(),
                base,
                basis_of(d, rule, base, episode),
            ),
            NOW,
        )
        .await;
        assert_eq!(r.decision.outcome, Outcome::Deny, "{base:?}: {r:?}");
    }
    unresolved(
        &send(
            &mut core,
            shop_request(d, 60, Mode::Commit, holding(d, rule.shop, episode)),
            ADMIN_KEY,
        )
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

// OP-159 m.47 (f), TN-109, SI-21
#[tokio::test]
async fn a_cooling_tenant_administration_claim_selects_nothing_until_it_starts() {
    const COOLING: u64 = 1_000;
    let db = fresh().await.unwrap();
    let (g, rule) = administered();
    let (mut core, d) = setup_with(&db, g).await;
    onboard(&mut core, d, ROOT, ROOT_KEY, (1, 2)).await;
    onboard(&mut core, d, ISSUER, ISSUER_KEY, (3, 4)).await;
    onboard(&mut core, d, ADMIN, ADMIN_KEY, (5, 6)).await;
    let cooling = sign_claim(&statement(d, true, NOW + COOLING, None), ISSUER_KEY);
    let episode = ingest(&mut core, d, 20, cooling).await;
    let base = meta_bases()[0];
    let early = probe(
        &mut core,
        check(d, 30, base, basis_of(d, rule, base, episode)),
        NOW,
    )
    .await;
    assert_eq!(early.decision.outcome, Outcome::Deny, "{early:?}");
    allowed(
        &probe(
            &mut core,
            check(d, 31, base, basis_of(d, rule, base, episode)),
            NOW + COOLING,
        )
        .await,
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

/// A role definition with `basis`, as the console drafts it.
fn define_role(d: Digest, nonce: u8, basis: ExerciseBasis) -> Request {
    let payload = Payload::AuthoritySetDefine {
        name: "support".to_owned(),
        authority: authority(vec![action("shop", "read")], selector("shop")).authority,
    };
    let mut r = meta_request(d, nonce, basis, payload);
    r.intent.resources = vec![ResourceRef {
        namespace: "access.domain".to_owned(),
        path: vec!["acme".to_owned()],
        incarnation: 0,
    }];
    r
}

// OP-159 m.47 (d), (e), OP-141 m.3
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "the rule and a named holder side by side on one domain"
)]
async fn the_admin_rule_covers_but_does_not_write_root_meta_actions() {
    let db = fresh().await.unwrap();
    let (g, rule) = administered();
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (party, seed, (first, second)) in [
        (ROOT, ROOT_KEY, (1, 2)),
        (ISSUER, ISSUER_KEY, (3, 4)),
        (ADMIN, ADMIN_KEY, (5, 6)),
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
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let ingested = a
        .exercise(&incoming(
            with_proofs(
                shop_request(d, 20, Mode::Commit, shop),
                vec![ProofRef::Claim(sign_claim(
                    &statement(d, true, 0, None),
                    ISSUER_KEY,
                ))],
            ),
            ROOT_KEY,
        ))
        .await
        .unwrap();
    allowed(&ingested);
    let episode = ingested.record.unwrap().checked_sub(2).unwrap();
    assert!(a.derive().await.is_empty());

    allowed(
        &a.exercise(&incoming(
            shop_request(d, 22, Mode::Commit, holding(d, rule.shop, episode)),
            ADMIN_KEY,
        ))
        .await
        .unwrap(),
    );
    let written = a
        .exercise(&incoming(
            define_role(d, 23, holding(d, rule.meta, episode)),
            ADMIN_KEY,
        ))
        .await
        .unwrap();
    assert_eq!(written.decision.outcome, Outcome::Deny, "{written:?}");

    let written = a
        .exercise(&incoming(
            define_role(d, 24, holding(d, rule.named, 0)),
            ADMIN_KEY,
        ))
        .await
        .unwrap();
    assert_eq!(written.decision.outcome, Outcome::Deny, "{written:?}");
    allowed(
        &a.exercise(&incoming(
            define_role(d, 25, ExerciseBasis::Anchor(meta::meta_anchor(&d))),
            ROOT_KEY,
        ))
        .await
        .unwrap(),
    );
    fold_check(&db.sequencer, d).await.unwrap();
}

/// The Grants `party` holds now by the holdings report, with the episode each names.
async fn held_by(a: &Led, d: Digest, nonce: u8, seed: u8) -> BTreeMap<Id, u64> {
    use access_authority_core::query::{Hit, Query, Report};
    let (hits, _) = a
        .search(
            &incoming(search_request(d, nonce, "holdings"), seed),
            &Query::Holdings,
            None,
        )
        .await
        .unwrap();
    hits.into_iter()
        .filter_map(|h| match h {
            Hit::Report(r) => match *r {
                Report::Holding(x) => Some((x.grant, x.since)),
                _ => None,
            },
            _ => None,
        })
        .collect()
}

// OP-159 m.47 (k), OP-141 m.38 (d), m.20, INV-31
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one administrator from its first episode through its end"
)]
async fn the_admin_rule_audits_and_holds_from_genesis_while_the_episode_lives() {
    let db = fresh().await.unwrap();
    let (g, rule) = administered();
    let d = create_genesis(&db.sequencer, TENANT, g, 1_000)
        .await
        .unwrap();
    let a = process(&db, "a", vec![d]);
    let public_basis = ExerciseBasis::Public(meta::object_id(&d, kind::GRANT, 0));
    for (party, seed, (first, second)) in [
        (ROOT, ROOT_KEY, (1, 2)),
        (ISSUER, ISSUER_KEY, (3, 4)),
        (ADMIN, ADMIN_KEY, (5, 6)),
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
    let shop = ExerciseBasis::Anchor(meta::object_id(&d, kind::ANCHOR, 1));
    let recorded = a
        .exercise(&incoming(shop_request(d, 19, Mode::Commit, shop), ROOT_KEY))
        .await
        .unwrap();
    allowed(&recorded);
    let record = recorded.record.unwrap();
    assert!(a.derive().await.is_empty());
    let id = |i: u64| meta::object_id(&d, kind::GRANT, i);

    // OP-159 m.47 (k) (3)
    let before = held_by(&a, d, 30, ADMIN_KEY).await;
    assert_eq!(before.get(&id(rule.named)), Some(&0), "{before:?}");
    assert!(!before.contains_key(&id(rule.audit)), "{before:?}");
    let explain = |nonce| incoming(shop_request(d, nonce, Mode::Commit, shop), ADMIN_KEY);
    let early = a.explain_recorded(&explain(19), record, Scope::Audit).await;
    assert!(
        matches!(early, Err(CoreError::Protocol("explain-scope"))),
        "{early:?}"
    );

    let first = sign_claim(&statement(d, true, 0, None), ISSUER_KEY);
    let first_id = access_kernel::claim::claim_id(&first);
    let ingested = a
        .exercise(&incoming(
            with_proofs(
                shop_request(d, 20, Mode::Commit, shop),
                vec![ProofRef::Claim(first)],
            ),
            ROOT_KEY,
        ))
        .await
        .unwrap();
    allowed(&ingested);
    let episode = ingested.record.unwrap().checked_sub(2).unwrap();
    assert!(a.derive().await.is_empty());
    let during = held_by(&a, d, 31, ADMIN_KEY).await;
    for i in [rule.meta, rule.audit, rule.shop] {
        assert_eq!(during.get(&id(i)), Some(&episode), "{during:?}");
    }
    // OP-159 m.47 (k) (1)
    let audited = a.explain_recorded(&explain(19), record, Scope::Audit).await;
    assert!(audited.is_ok(), "{audited:?}");

    let end = sign_claim(&statement(d, false, 0, Some(first_id)), ISSUER_KEY);
    allowed(
        &a.exercise(&incoming(
            with_proofs(
                shop_request(d, 21, Mode::Commit, shop),
                vec![ProofRef::Claim(end)],
            ),
            ROOT_KEY,
        ))
        .await
        .unwrap(),
    );
    assert!(a.derive().await.is_empty());
    let after = held_by(&a, d, 32, ADMIN_KEY).await;
    assert!(!after.contains_key(&id(rule.audit)), "{after:?}");
    assert_eq!(after.get(&id(rule.named)), Some(&0), "{after:?}");
    let late = a.explain_recorded(&explain(19), record, Scope::Audit).await;
    assert!(
        matches!(late, Err(CoreError::Protocol("explain-scope"))),
        "{late:?}"
    );
    fold_check(&db.sequencer, d).await.unwrap();
}
