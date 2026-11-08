use alloc::string::ToString;
use alloc::vec;

use super::*;
use crate::model::{ActionRef, ActionSet, DelegationTerms, Structural};

struct Mem(BTreeMap<Vec<u8>, Value>);

impl View for Mem {
    fn get(&self, key: &[u8]) -> Option<Value> {
        self.0.get(key).cloned()
    }
}

impl Mem {
    fn apply(&mut self, effects: &[Effect]) {
        for (k, v) in effects {
            match v {
                Some(v) => self.0.insert(k.clone(), v.clone()),
                None => self.0.remove(k),
            };
        }
    }
}

const DOMAIN: Digest = Digest([7; 32]);
const ROOT: Id = Id([1; 16]);
const ALICE: Id = Id([2; 16]);
const BOB: Id = Id([3; 16]);
const CAROL: Id = Id([4; 16]);

fn shop(prefix: &[&str]) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: "shop".to_string(),
        prefix: prefix.iter().map(ToString::to_string).collect(),
        kind: None,
        attrs: BTreeMap::new(),
    })
}

fn authority(prefix: &[&str], depth: u64, until: u64) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: AuthoritySet {
            actions: ActionSet {
                exact: [ActionRef {
                    namespace: "shop".to_string(),
                    name: "refund".to_string(),
                    major: 1,
                    schema: Digest([9; 32]),
                }]
                .into_iter()
                .collect(),
                prefix: BTreeSet::new(),
            },
            resource: shop(prefix),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        constraints: ConstraintSet {
            validity: Window { from: 0, until },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth,
            downstream_holder_class: None,
        },
        requirements: BTreeSet::new(),
    }
}

fn genesis() -> Mem {
    let mut fields = BTreeMap::new();
    fields.insert(
        "meta_anchor".to_string(),
        map([("root", Some(root_value(&Root::Sole(ROOT))))]),
    );
    fields.insert(
        "anchors".to_string(),
        set_value([map([
            (
                "scope",
                Some(scope_value(&AnchorScope::Resource(shop(&[])))),
            ),
            ("root", Some(root_value(&Root::Sole(ROOT)))),
        ])]),
    );
    fields.insert(
        "versions".to_string(),
        map([
            ("core", Some(Value::Unsigned(1))),
            ("meta_schema", Some(Value::Unsigned(1))),
        ]),
    );
    let mut m = Mem(BTreeMap::new());
    m.apply(&genesis_effects(&DOMAIN, &fields).unwrap());
    m
}

fn shop_anchor() -> Id {
    object_id(&DOMAIN, kind::ANCHOR, 1)
}

struct Run {
    state: Mem,
    pos: u64,
    now: u64,
    catalog: Catalog,
}

impl Run {
    fn new() -> Self {
        Self {
            state: genesis(),
            pos: 1,
            now: 0,
            catalog: Catalog::default(),
        }
    }

    fn act(
        &mut self,
        party: Id,
        instance: Id,
        basis: ExerciseBasis,
        payload: &Payload,
    ) -> Result<(Digest, Outcome), MetaError> {
        let exercise = exercise_id(&DOMAIN, &self.pos.to_be_bytes().repeat(2)).unwrap();
        let ctx = Context {
            domain: DOMAIN,
            exercise,
            pos: self.pos,
            now: self.now,
            actor: Actor { party, instance },
            basis,
            capacity: Capacity::Own,
            catalog: &self.catalog,
        };
        let out = apply(&ctx, payload, &self.state)?;
        self.state.apply(&out.effects);
        self.pos = self.pos.checked_add(1).unwrap();
        Ok((exercise, out))
    }

    fn grant(&self, id: &Id) -> GrantState {
        read(&self.state, kind::GRANT, id).unwrap()
    }
}

fn issue(holder: Id, basis: GrantBasis, prefix: &[&str], depth: u64) -> Payload {
    issue_named(holder, basis, prefix, depth, None)
}

fn issue_named(
    holder: Id,
    basis: GrantBasis,
    prefix: &[&str],
    depth: u64,
    named: Option<NamedPin>,
) -> Payload {
    Payload::GrantIssue(GrantContent {
        basis,
        holder: SubjectSelector::Party(holder),
        authority: authority(prefix, depth, 1_000),
        agency: BTreeSet::from([Capacity::Own]),
        named,
    })
}

fn projection(prefix: &[&str], depth: u64, until: u64) -> Payload {
    Payload::ProjectionIssue {
        bounds: authority(prefix, depth, until),
        audience: BTreeSet::from(["pep.shop.example".to_string()]),
        class: crate::validity::ProfileClass::Intermittent,
        variant: crate::validity::ProfileVariant::BoundedStaleness,
        max_staleness_ms: Some(60_000),
        offline_slice: None,
    }
}

fn sliced(prefix: &[&str], class: crate::validity::ProfileClass) -> Payload {
    let bounds = authority(prefix, 0, 3_600_000);
    let audience = BTreeSet::from(["pep.shop.example".to_string()]);
    let max_staleness_ms = Some(60_000);
    let variant = match class {
        crate::validity::ProfileClass::Online => crate::validity::ProfileVariant::OnlineStrict,
        _ => crate::validity::ProfileVariant::BoundedStaleness,
    };
    Payload::ProjectionIssue {
        bounds,
        audience,
        class,
        variant,
        max_staleness_ms,
        offline_slice: Some(SliceRequest {
            count: Some(3),
            amounts: BTreeMap::from([("eur".to_string(), 500)]),
        }),
    }
}

// C11, C15, INV-3, OP-141 m.3: the root grants, a holder delegates only within its holding
#[test]
fn root_grants_and_holders_delegate_within() {
    let mut r = Run::new();
    let a = shop_anchor();
    let (ex, out) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(a),
            &issue(ALICE, GrantBasis::Anchor(a), &["eu"], 2),
        )
        .unwrap();
    assert!(out.expansion);
    let g1 = object_id(&ex, kind::GRANT, 0);
    let since = r.grant(&g1).since;
    let h = HoldingRef {
        grant: g1,
        holder: ALICE,
        since,
    };
    let (ex2, _) = r
        .act(
            ALICE,
            ALICE,
            ExerciseBasis::Holding(h),
            &issue(BOB, GrantBasis::Holding(h), &["eu", "de"], 1),
        )
        .unwrap();
    let g2 = object_id(&ex2, kind::GRANT, 0);
    assert_eq!(r.grant(&g2).content.holder, SubjectSelector::Party(BOB));
    // wider than the parent, or not further delegable
    assert_eq!(
        r.act(
            ALICE,
            ALICE,
            ExerciseBasis::Holding(h),
            &issue(BOB, GrantBasis::Holding(h), &[], 1)
        ),
        Err(MetaError::NotWithin)
    );
    let h2 = HoldingRef {
        grant: g2,
        holder: BOB,
        since: r.grant(&g2).since,
    };
    assert_eq!(
        r.act(
            BOB,
            BOB,
            ExerciseBasis::Holding(h2),
            &issue(CAROL, GrantBasis::Holding(h2), &["eu", "de"], 1)
        ),
        Err(MetaError::NotWithin)
    );
    // someone else's holding, or a root that is not the actor
    assert_eq!(
        r.act(
            BOB,
            BOB,
            ExerciseBasis::Holding(h),
            &issue(CAROL, GrantBasis::Holding(h), &["eu"], 0)
        ),
        Err(MetaError::Basis)
    );
    assert_eq!(
        r.act(
            ALICE,
            ALICE,
            ExerciseBasis::Anchor(a),
            &issue(CAROL, GrantBasis::Anchor(a), &["eu"], 0)
        ),
        Err(MetaError::NotAuthorized)
    );
}

// C17, CI-4, OP-141 m.3: upstream holders and the root revoke; the holder renounces; nobody else
#[test]
fn revoke_and_renounce_powers() {
    let mut r = Run::new();
    let a = shop_anchor();
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(a),
            &issue(ALICE, GrantBasis::Anchor(a), &["eu"], 2),
        )
        .unwrap();
    let g1 = object_id(&ex, kind::GRANT, 0);
    let h = HoldingRef {
        grant: g1,
        holder: ALICE,
        since: r.grant(&g1).since,
    };
    let (ex2, _) = r
        .act(
            ALICE,
            ALICE,
            ExerciseBasis::Holding(h),
            &issue(BOB, GrantBasis::Holding(h), &["eu"], 1),
        )
        .unwrap();
    let g2 = object_id(&ex2, kind::GRANT, 0);
    let basis = ExerciseBasis::Anchor(a);
    assert_eq!(
        r.act(CAROL, CAROL, basis, &Payload::GrantRevoke { grant: g2 }),
        Err(MetaError::NotAuthorized)
    );
    assert_eq!(
        r.act(BOB, BOB, basis, &Payload::GrantRevoke { grant: g1 }),
        Err(MetaError::NotAuthorized)
    );
    // Alice holds the Grant above g2
    r.act(ALICE, ALICE, basis, &Payload::GrantRevoke { grant: g2 })
        .unwrap();
    assert_eq!(r.grant(&g2).ended.map(|e| e.how), Some(EndedHow::Revoked));
    // terminal: no second revoke, no renounce (INV-5)
    assert_eq!(
        r.act(ROOT, ROOT, basis, &Payload::GrantRevoke { grant: g2 }),
        Err(MetaError::Ended)
    );
    r.act(ALICE, ALICE, basis, &Payload::GrantRenounce { grant: g1 })
        .unwrap();
    assert_eq!(r.grant(&g1).ended.map(|e| e.how), Some(EndedHow::Renounced));
}

// C16: an amend keeps the GrantID, counts revisions and says whether it widens
#[test]
fn amend_narrows_or_widens_within_the_parent() {
    let mut r = Run::new();
    let a = shop_anchor();
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(a),
            &issue(ALICE, GrantBasis::Anchor(a), &["eu"], 2),
        )
        .unwrap();
    let g1 = object_id(&ex, kind::GRANT, 0);
    let amend = |prefix: &[&str]| Payload::GrantAmend {
        grant: g1,
        authority: authority(prefix, 2, 1_000),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    };
    let (_, out) = r
        .act(ROOT, ROOT, ExerciseBasis::Anchor(a), &amend(&["eu", "de"]))
        .unwrap();
    assert!(!out.expansion);
    let (_, out) = r
        .act(ROOT, ROOT, ExerciseBasis::Anchor(a), &amend(&["eu"]))
        .unwrap();
    assert!(out.expansion);
    assert_eq!(r.grant(&g1).revision, 2);
}

// INV-4: a Grant can carry only OWN and FOR(principal)
#[test]
fn agency_is_continuous() {
    let mut r = Run::new();
    let a = shop_anchor();
    let mut p = issue(ALICE, GrantBasis::Anchor(a), &["eu"], 0);
    if let Payload::GrantIssue(c) = &mut p {
        c.agency.insert(Capacity::For(BOB));
    }
    assert_eq!(
        r.act(ROOT, ROOT, ExerciseBasis::Anchor(a), &p),
        Err(MetaError::Agency)
    );
}

fn p256_key(seed: u8) -> PublicKey {
    PublicKey::P256(
        p256::ecdsa::SigningKey::from_slice(&[seed; 32])
            .unwrap()
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
    )
}

// OP-149 m.8: the actor kind is recorded at registration and decides actor_is_agent
#[test]
fn the_actor_kind_is_recorded_and_decides_agency() {
    let public = ExerciseBasis::Public(Id([9; 16]));
    for (kind_of, agent) in [
        (ActorKind::Human, false),
        (ActorKind::Agent, true),
        (ActorKind::System, false),
        (ActorKind::Machine, false),
        (ActorKind::Organization, false),
    ] {
        let mut r = Run::new();
        let register = Payload::PartyRegister {
            party: ALICE,
            root: Root::Sole(ALICE),
            actor_kind: kind_of,
        };
        assert_eq!(Payload::from_value(&register.to_value()).unwrap(), register);
        r.act(ALICE, ALICE, public, &register).unwrap();
        let p: PartyState = read(&r.state, kind::PARTY, &ALICE).unwrap();
        assert_eq!(p.actor_kind, kind_of);
        assert_eq!(actor_is_agent(&r.state, &ALICE), agent);
        assert_eq!(ActorKind::parse(kind_of.name()), Some(kind_of));
    }
    assert!(!actor_is_agent(&Run::new().state, &BOB));
    assert_eq!(ActorKind::parse("robot"), None);
}

// OP-149 m.8: a registration without an actor kind, or with an unknown one, is malformed
#[test]
fn a_registration_names_a_known_actor_kind() {
    let register = Payload::PartyRegister {
        party: ALICE,
        root: Root::Sole(ALICE),
        actor_kind: ActorKind::Human,
    };
    let Value::Map(mut outer) = register.to_value() else {
        panic!("a payload is a map");
    };
    let Value::Map(body) = &mut outer[0].1 else {
        panic!("a payload body is a map");
    };
    let kind_at = body
        .iter()
        .position(|(k, _)| *k == Value::text("actor_kind"))
        .unwrap();
    body[kind_at].1 = Value::text("robot");
    assert!(Payload::from_value(&Value::Map(outer.clone())).is_err());
    let Value::Map(body) = &mut outer[0].1 else {
        panic!("a payload body is a map");
    };
    body.remove(kind_at);
    assert!(Payload::from_value(&Value::Map(outer)).is_err());
}

// OP-149 m.6, L0-SIG-4: an Instance key is Ed25519 or P-256; an ML-DSA key is not one
#[test]
fn instance_keys_are_ed25519_or_p256() {
    let create = |key: PublicKey| Payload::InstanceCreate {
        party: ALICE,
        key,
        mandate: None,
    };
    let p = create(p256_key(3));
    assert_eq!(Payload::from_value(&p.to_value()).unwrap(), p);
    let ml = create(PublicKey::MlDsa(
        crate::verify::cose::Algorithm::MlDsa44,
        vec![0; 1312],
    ));
    assert_eq!(
        Payload::from_value(&ml.to_value()),
        Err(ModelError::Unknown)
    );
    let mut off = p256_key(3);
    if let PublicKey::P256(b) = &mut off {
        b[64] ^= 1;
    }
    assert!(Payload::from_value(&create(off).to_value()).is_err());
}

// E6, §7.9.2.3, OP-141 m.2, m.4: a Party registers itself with its self-anchor, then creates its
// own Instance; neither can be done for someone else
#[test]
fn register_then_create_own_instance() {
    let mut r = Run::new();
    let public = ExerciseBasis::Public(Id([9; 16]));
    let register = Payload::PartyRegister {
        party: ALICE,
        root: Root::Sole(ALICE),
        actor_kind: ActorKind::Human,
    };
    assert_eq!(
        r.act(BOB, BOB, public, &register),
        Err(MetaError::NotAuthorized)
    );
    r.act(ALICE, ALICE, public, &register).unwrap();
    assert_eq!(
        r.act(ALICE, ALICE, public, &register),
        Err(MetaError::Ended)
    );
    let p: PartyState = read(&r.state, kind::PARTY, &ALICE).unwrap();
    let anchor: AnchorState = read(&r.state, kind::ANCHOR, &p.anchor).unwrap();
    assert_eq!(anchor.scope, AnchorScope::Party(ALICE));

    let key = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[5; 32])
            .verifying_key()
            .to_bytes(),
    );
    let create = Payload::InstanceCreate {
        party: ALICE,
        key: key.clone(),
        mandate: None,
    };
    assert_eq!(
        r.act(ALICE, Id([0; 16]), public, &create),
        Err(MetaError::NotAuthorized)
    );
    let instance_now = object_id(
        &exercise_id(&DOMAIN, &r.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.act(ALICE, instance_now, public, &create).unwrap();
    let i: InstanceState = read(&r.state, kind::INSTANCE, &instance_now).unwrap();
    assert_eq!((i.party, i.key), (ALICE, key));

    // only the Party's own Instance terminates it without a further power
    let term = Payload::InstanceTerminate {
        instance: instance_now,
    };
    assert_eq!(
        r.act(BOB, BOB, public, &term),
        Err(MetaError::NotAuthorized)
    );
    r.act(ALICE, instance_now, public, &term).unwrap();
    let i: InstanceState = read(&r.state, kind::INSTANCE, &instance_now).unwrap();
    assert_eq!(i.ended.map(|e| e.how), Some(EndedHow::Terminated));
}

// C10: transfer and retire must dispose of exactly the live dependent Grants
#[test]
fn anchor_changes_need_a_complete_disposition() {
    let mut r = Run::new();
    let a = shop_anchor();
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(a),
            &issue(ALICE, GrantBasis::Anchor(a), &["eu"], 0),
        )
        .unwrap();
    let g1 = object_id(&ex, kind::GRANT, 0);
    let retire = |d: BTreeMap<Id, Disposition>| Payload::AnchorRetire {
        anchor: a,
        disposition: d,
    };
    let basis = ExerciseBasis::Anchor(a);
    assert_eq!(
        r.act(ROOT, ROOT, basis, &retire(BTreeMap::new())),
        Err(MetaError::Disposition)
    );
    assert_eq!(
        r.act(
            ROOT,
            ROOT,
            basis,
            &retire(BTreeMap::from([(g1, Disposition::Keep)]))
        ),
        Err(MetaError::Disposition)
    );
    r.act(
        ROOT,
        ROOT,
        basis,
        &retire(BTreeMap::from([(g1, Disposition::Revoke)])),
    )
    .unwrap();
    assert!(r.grant(&g1).ended.is_some());
    let anchor: AnchorState = read(&r.state, kind::ANCHOR, &a).unwrap();
    assert_eq!(anchor.ended.map(|e| e.how), Some(EndedHow::Retired));
    assert_eq!(
        r.act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(meta_anchor(&DOMAIN)),
            &Payload::AnchorRetire {
                anchor: meta_anchor(&DOMAIN),
                disposition: BTreeMap::new(),
            }
        ),
        Err(MetaError::Basis)
    );
}

// C9, C26: a joint root acts with k−1 further contributions; root terms are added
#[test]
fn joint_roots_require_contributions() {
    // INV-10
    let mut r = Run::new();
    let a = shop_anchor();
    let create = Payload::AnchorCreate {
        scope: AnchorScope::Resource(shop(&["eu"])),
        root: Root::Joint {
            parties: BTreeSet::from([ALICE, BOB, CAROL]),
            k: 2,
        },
        root_terms: BTreeSet::new(),
    };
    let (ex, _) = r
        .act(ROOT, ROOT, ExerciseBasis::Anchor(a), &create)
        .unwrap();
    let eu = object_id(&ex, kind::ANCHOR, 0);
    let (_, out) = r
        .act(
            BOB,
            BOB,
            ExerciseBasis::Anchor(eu),
            &issue(CAROL, GrantBasis::Anchor(eu), &["eu", "fr"], 0),
        )
        .unwrap();
    let term = out.requirements.iter().next().unwrap();
    assert_eq!((term.class.as_str(), term.count), ("co_root", 1));
    // §13.7.3, OP-141 m.43: a CT3 meta-action asks two of the other principals
    let nested = Payload::AnchorCreate {
        scope: AnchorScope::Resource(shop(&["eu", "fr"])),
        root: Root::Sole(BOB),
        root_terms: BTreeSet::new(),
    };
    let (_, out) = r.act(BOB, BOB, ExerciseBasis::Anchor(eu), &nested).unwrap();
    let term = out.requirements.iter().next().unwrap();
    assert_eq!((term.class.as_str(), term.count), ("co_root", 2));
    // a nested Anchor stays inside its covering scope
    let outside = Payload::AnchorCreate {
        scope: AnchorScope::Resource(shop(&[])),
        root: Root::Sole(ALICE),
        root_terms: BTreeSet::new(),
    };
    assert_eq!(
        r.act(ALICE, ALICE, ExerciseBasis::Anchor(eu), &outside),
        Err(MetaError::NotWithin)
    );
}

// OP-141 m.6, m.13: identifiers and the payload digest are deterministic and payloads round-trip
#[test]
fn identifiers_and_payload_round_trip() {
    let p = issue(ALICE, GrantBasis::Anchor(shop_anchor()), &["eu"], 1);
    assert_eq!(Payload::from_value(&p.to_value()).unwrap(), p);
    assert_eq!(p.action(), "grant_issue");
    assert_eq!(p.digest().unwrap(), p.digest().unwrap());
    assert_ne!(
        object_id(&DOMAIN, kind::GRANT, 0),
        object_id(&DOMAIN, kind::GRANT, 1)
    );
    assert_ne!(
        exercise_id(&DOMAIN, b"0123456789abcdef").unwrap(),
        exercise_id(&DOMAIN, b"0123456789abcdeg").unwrap()
    );
    assert!(is_meta("access", "grant_issue") && !is_meta("shop", "grant_issue"));
    assert!(Payload::from_value(&tagged("grant_explode", map([]))).is_err());
}

// L0-META-30: a contribution records who contributed to which intent, under its ExerciseID
#[test]
fn a_contribution_is_recorded_under_its_exercise() {
    let mut r = Run::new();
    let payload = Payload::Contribute {
        target: Digest([9; 32]),
        class: String::from("approve"),
    };
    assert_eq!(Payload::from_value(&payload.to_value()).unwrap(), payload);
    assert!(is_meta("access", "contribute"));
    let (exercise, out) = r
        .act(ALICE, BOB, ExerciseBasis::Public(Id([0; 16])), &payload)
        .unwrap();
    assert!(out.requirements.is_empty());
    let stored = r
        .state
        .get(&exercise_key(kind::CONTRIBUTION, &exercise))
        .unwrap();
    let c = ContributionState::from_value(&stored).unwrap();
    assert_eq!(
        (c.target, c.party, c.instance, c.consumed),
        (Digest([9; 32]), ALICE, BOB, None)
    );
}

const SPENDER: Id = Id([14; 16]);
const SPENT: Digest = Digest([15; 32]);

fn budget(grant: &Id, term: u64) -> Vec<u8> {
    dcbor::encode(
        &Value::Array(alloc::vec![
            Value::text("budget"),
            grant.to_value(),
            Value::Unsigned(term),
            Value::Unsigned(0),
        ]),
        Limits::CEILING,
    )
    .unwrap()
}

/// An Exercise of `SPENDER` that drew 1 from a count term and 100 EUR from an amount term of
/// `grant`, and two Claims bound to its intent (OP-141 m.28).
fn spent(state: &mut Mem, grant: &Id, exercise: &Digest) {
    let claim = |class: &str, value: Option<crate::model::EqValue>, intent: Digest| {
        crate::claim::ClaimState {
            statement: crate::claim::Statement {
                domain: DOMAIN,
                issuer: ROOT,
                subject: ALICE,
                class: String::from(class),
                value,
                issued_at: 0,
                validity: Window {
                    from: 0,
                    until: u64::MAX,
                },
                assurance: BTreeMap::new(),
                bound_intent: Some(intent),
                bound_instance: None,
                bound_resource: None,
                supersedes: None,
            },
            instance: None,
            since: 1,
            ended: None,
        }
        .to_value()
    };
    let mut draws = alloc::vec![
        ExerciseDraw {
            key: budget(grant, 0),
            drawn: 1,
            released: 0,
            unit: None,
        },
        ExerciseDraw {
            key: budget(grant, 1),
            drawn: 100,
            released: 0,
            unit: Some(String::from("eur")),
        },
    ];
    draws.sort_by(|a, b| a.key.cmp(&b.key));
    state.apply(&[
        (
            exercise_key(kind::EXERCISE, exercise),
            Some(
                ExerciseState {
                    intent: SPENT,
                    actor: SPENDER,
                    since: 1,
                    draws,
                    grounds: BTreeSet::new(),
                }
                .to_value(),
            ),
        ),
        (
            key(kind::CLAIM, &Id([21; 16])),
            Some(claim(
                ACTUAL_AMOUNT,
                Some(crate::model::EqValue::Int(30)),
                SPENT,
            )),
        ),
        (
            key(kind::CLAIM, &Id([22; 16])),
            Some(claim(NON_EXECUTION, None, SPENT)),
        ),
        (
            key(kind::CLAIM, &Id([23; 16])),
            Some(claim(NON_EXECUTION, None, Digest([16; 32]))),
        ),
    ]);
}

fn release_of(exercise: Digest, grounds: &[u8]) -> Payload {
    Payload::ConsumptionRelease {
        exercise,
        grounds: grounds.iter().map(|g| Id([*g; 16])).collect(),
    }
}

// OP-141 m.28: a lower actual amount returns the rest of an amount draw, a non-execution the
// rest of every draw; a ground is used once and Σrelease never exceeds the draw
#[test]
fn a_release_returns_at_most_the_draw() {
    // TI-RT8, G3, MUST-NEVER-5
    let mut r = Run::new();
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(shop_anchor()),
            &issue(ALICE, GrantBasis::Anchor(shop_anchor()), &["eu"], 0),
        )
        .unwrap();
    let g = object_id(&ex, kind::GRANT, 0);
    let spending = Digest([17; 32]);
    spent(&mut r.state, &g, &spending);
    let payload = release_of(spending, &[21]);
    assert_eq!(Payload::from_value(&payload.to_value()).unwrap(), payload);
    assert!(is_meta("access", "consumption_release"));
    let any = ExerciseBasis::Anchor(shop_anchor());
    assert_eq!(
        r.act(CAROL, CAROL, any, &payload).unwrap_err(),
        MetaError::NotAuthorized
    );
    let (_, out) = r.act(ALICE, ALICE, any, &payload).unwrap();
    assert_eq!(out.releases, alloc::vec![(budget(&g, 1), 70)]);
    assert!(out.expansion);
    assert_eq!(
        r.act(ALICE, ALICE, any, &payload).unwrap_err(),
        MetaError::ReleaseExceedsDraw
    );
    assert_eq!(
        r.act(CAROL, SPENDER, any, &release_of(spending, &[23]))
            .unwrap_err(),
        MetaError::NotWithin
    );
    let (_, out) = r
        .act(CAROL, SPENDER, any, &release_of(spending, &[22]))
        .unwrap();
    assert_eq!(
        out.releases,
        alloc::vec![(budget(&g, 0), 1), (budget(&g, 1), 30)]
    );
    let state = ExerciseState::from_value(
        &r.state
            .get(&exercise_key(kind::EXERCISE, &spending))
            .unwrap(),
    )
    .unwrap();
    assert!(state.draws.iter().all(|d| d.released == d.drawn));
    assert_eq!(state.grounds.len(), 2);
    assert_eq!(
        r.act(CAROL, SPENDER, any, &release_of(spending, &[22]))
            .unwrap_err(),
        MetaError::ReleaseExceedsDraw
    );
    assert_eq!(released_key(&budget(&g, 0)).first(), Some(&0x84));
    assert_eq!(budget_grant(&budget(&g, 0)), Some(g));
}

fn pinned_issue(prefix: &[&str], pin: NamedPin) -> Payload {
    issue_named(
        ALICE,
        GrantBasis::Anchor(shop_anchor()),
        prefix,
        0,
        Some(pin),
    )
}

// OP-141 m.32: a named AuthoritySet is versioned; a Grant pins a version by digest and stays
// within it; a new version changes no Grant until it is re-pinned
#[test]
fn a_grant_pins_a_named_authority_set_version() {
    let mut r = Run::new();
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let anchor = ExerciseBasis::Anchor(shop_anchor());
    let eu = authority(&["eu"], 0, 1_000).authority;
    let define = |a: &AuthoritySet| Payload::AuthoritySetDefine {
        name: String::from("refunds"),
        authority: a.clone(),
    };
    assert_eq!(
        Payload::from_value(&define(&eu).to_value()).unwrap(),
        define(&eu)
    );
    assert!(r.act(ALICE, ALICE, meta, &define(&eu)).is_err());
    r.act(ROOT, ROOT, meta, &define(&eu)).unwrap();
    let v1 = (String::from("refunds"), 1, authority_set_digest(&eu));
    let (ex, _) = r
        .act(ROOT, ROOT, anchor, &pinned_issue(&["eu", "de"], v1.clone()))
        .unwrap();
    let g = object_id(&ex, kind::GRANT, 0);
    assert_eq!(
        r.act(ROOT, ROOT, anchor, &pinned_issue(&[], v1.clone()))
            .unwrap_err(),
        MetaError::NotWithin
    );
    let wrong = (String::from("refunds"), 1, Digest([1; 32]));
    assert_eq!(
        r.act(ROOT, ROOT, anchor, &pinned_issue(&["eu"], wrong))
            .unwrap_err(),
        MetaError::NotWithin
    );
    let v2_missing = (String::from("refunds"), 2, authority_set_digest(&eu));
    assert_eq!(
        r.act(ROOT, ROOT, anchor, &pinned_issue(&["eu"], v2_missing))
            .unwrap_err(),
        MetaError::Unknown
    );
    let all = authority(&[], 0, 1_000).authority;
    r.act(ROOT, ROOT, meta, &define(&all)).unwrap();
    assert_eq!(r.grant(&g).content.named, Some(v1));
    let widen = |named| Payload::GrantAmend {
        grant: g,
        authority: authority(&[], 0, 1_000),
        agency: BTreeSet::from([Capacity::Own]),
        named,
    };
    assert_eq!(
        r.act(ROOT, ROOT, anchor, &widen(None)).unwrap_err(),
        MetaError::NotWithin
    );
    let v2 = (String::from("refunds"), 2, authority_set_digest(&all));
    let (_, out) = r.act(ROOT, ROOT, anchor, &widen(Some(v2.clone()))).unwrap();
    assert!(out.expansion);
    assert_eq!(r.grant(&g).content.named, Some(v2));
}

// OP-141 m.34 (d): Genesis may set the CT3 time-lock; any other policy field is malformed
#[test]
fn genesis_sets_the_ct3_time_lock() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "meta_anchor".to_string(),
        map([("root", Some(root_value(&Root::Sole(ROOT))))]),
    );
    fields.insert(
        "policy".to_string(),
        map([("ct3_delay_s", Some(Value::Unsigned(60)))]),
    );
    let effects = genesis_effects(&DOMAIN, &fields).unwrap();
    assert!(effects.contains(&(policy_default_key(CT3_DELAY), Some(Value::Unsigned(60)))));
    fields.insert(
        "policy".to_string(),
        map([("ct0_delay_s", Some(Value::Unsigned(60)))]),
    );
    assert!(genesis_effects(&DOMAIN, &fields).is_err());
}

// L0-META-5, L0-META-27: Acceptances are indexed by issuer; a domain Claim names its issuer
#[test]
fn acceptances_are_indexed_by_issuer() {
    let mut r = Run::new();
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let content = map([
        ("issuer", Some(CAROL.to_value())),
        ("use", Some(Value::text("predicate-input"))),
        (
            "classes",
            Some(Value::Array(alloc::vec![Value::text("kyc")])),
        ),
        ("subject", Some(SubjectSelector::Public.to_value())),
        (
            "validity",
            Some(Value::Array(alloc::vec![
                Value::Unsigned(0),
                Value::Unsigned(10)
            ])),
        ),
    ]);
    let (exercise, _) = r
        .act(ROOT, ROOT, meta, &Payload::AcceptanceEstablish(content))
        .unwrap();
    let index = r.state.get(&key(kind::ACCEPTANCES, &CAROL)).unwrap();
    assert_eq!(
        crate::codec::set_items(&index, true).unwrap(),
        [object_id(&exercise, kind::ACCEPTANCE, 0).to_value()]
    );
    let (exercise, _) = r
        .act(
            ROOT,
            ROOT,
            meta,
            &Payload::ClaimIssue {
                subject: ALICE,
                class: String::from("member"),
                value: crate::model::EqValue::Bool(true),
                validity: None,
                bound_intent: None,
                supersedes: None,
            },
        )
        .unwrap();
    let claim = r
        .state
        .get(&key(kind::CLAIM, &object_id(&exercise, kind::CLAIM, 0)))
        .unwrap();
    let c = crate::claim::ClaimState::from_value(&claim).unwrap();
    assert_eq!((c.statement.issuer, c.statement.subject), (ROOT, ALICE));
}

// OP-141 m.20 (e), CI-11, EI-1: a group has one membership issuer
#[test]
fn a_group_has_one_membership_issuer() {
    let mut r = Run::new();
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let selection = |issuer: Id, class: &str| {
        Payload::AcceptanceEstablish(map([
            ("issuer", Some(issuer.to_value())),
            ("use", Some(Value::text("subject-selection"))),
            (
                "classes",
                Some(Value::Array(alloc::vec![Value::text(class)])),
            ),
            ("subject", Some(SubjectSelector::Public.to_value())),
            (
                "validity",
                Some(Value::Array(alloc::vec![
                    Value::Unsigned(0),
                    Value::Unsigned(10)
                ])),
            ),
        ]))
    };
    r.act(ROOT, ROOT, meta, &selection(CAROL, "staff")).unwrap();
    r.act(ROOT, ROOT, meta, &selection(CAROL, "staff")).unwrap();
    assert_eq!(
        r.act(ROOT, ROOT, meta, &selection(BOB, "staff"))
            .unwrap_err(),
        MetaError::NotWithin
    );
    r.act(ROOT, ROOT, meta, &selection(BOB, "guests")).unwrap();
}

// OP-143 m.7, L0-META-35: a projection records itself, is CT1 and ends within a day
#[test]
fn projection_records_and_caps_the_horizon() {
    let mut r = Run::new();
    let a = shop_anchor();
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(a),
            &Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(a),
                holder: SubjectSelector::Party(ALICE),
                authority: authority(&["eu"], 0, 100_000_000),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .unwrap();
    let grant = object_id(&ex, kind::GRANT, 0);
    let holding = ExerciseBasis::Holding(HoldingRef {
        grant,
        holder: ALICE,
        since: r.grant(&grant).since,
    });
    let p = projection(&["eu"], 0, 100_000_000);
    r.now = 13_599_999;
    assert_eq!(r.act(ALICE, ALICE, holding, &p), Err(MetaError::NotWithin));
    r.now = 100_000_001;
    assert_eq!(r.act(ALICE, ALICE, holding, &p), Err(MetaError::NotWithin));
    r.now = 13_600_000;
    let (ex, out) = r.act(ALICE, ALICE, holding, &p).unwrap();
    assert!(!out.expansion);
    assert_eq!(
        crate::tier::meta_tier(&p, out.expansion),
        crate::tier::Tier::Ct1
    );
    assert_eq!(out.effects.len(), 1);
    let stored = r.state.get(&exercise_key(kind::PROJECTION, &ex)).unwrap();
    assert_eq!(stored.get("holder"), Some(&ALICE.to_value()));
    assert_eq!(stored.get("horizon"), Some(&Value::Unsigned(100_000_000)));
    assert_eq!(
        stored.get("bounds"),
        Some(&bounds_digest(&authority(&["eu"], 0, 100_000_000)).to_value())
    );
    assert_eq!(Payload::from_value(&p.to_value()), Ok(p.clone()));
    let mut bad = p.to_value();
    if let Value::Map(m) = &mut bad
        && let Some((_, Value::Map(body))) = m.first_mut()
        && let Some((_, Value::Map(profile))) =
            body.iter_mut().find(|(k, _)| k == &Value::text("profile"))
        && let Some((_, v)) = profile
            .iter_mut()
            .find(|(k, _)| k == &Value::text("variant"))
    {
        *v = Value::text("online-strict");
    }
    assert_eq!(Payload::from_value(&bad), Err(ModelError::Range));
}

struct Recorder {
    run: Run,
    cases: Vec<String>,
}

fn cbor(v: &Value) -> String {
    crate::vector_rules::hex(&dcbor::encode(v, Limits::CEILING).unwrap())
}

impl Recorder {
    /// A case whose payload is given as a value, so that one the Kernel refuses to decode is
    /// recorded too.
    fn step_raw(
        &mut self,
        id: &str,
        rules: &[&str],
        actor: (Id, Id),
        basis: ExerciseBasis,
        payload: &Value,
    ) -> Option<Digest> {
        match Payload::from_value(payload) {
            Ok(p) => self.step(id, rules, actor, basis, &p),
            Err(e) => {
                let head = self.head(id, rules, actor, basis, payload);
                self.cases.push(alloc::format!(
                    "  {head}, \"error\": \"{}\"}}",
                    MetaError::from(e).code()
                ));
                None
            }
        }
    }

    fn head(
        &self,
        id: &str,
        rules: &[&str],
        actor: (Id, Id),
        basis: ExerciseBasis,
        payload: &Value,
    ) -> String {
        use crate::vector_rules::{field, hex};
        use alloc::format;
        let state: Vec<String> = self
            .run
            .state
            .0
            .iter()
            .map(|(k, v)| format!("[\"{}\", \"{}\"]", hex(k), cbor(v)))
            .collect();
        let exercise = exercise_id(&DOMAIN, &self.run.pos.to_be_bytes().repeat(2)).unwrap();
        format!(
            "{{\"id\": \"{id}\", {}, \"state\": [{}], \"domain_id\": \"{}\", \"exercise\": \"{}\", \"pos\": {}, \"now\": {}, \"party\": \"{}\", \"instance\": \"{}\", \"basis\": \"{}\", \"capacity\": \"{}\", \"payload\": \"{}\"",
            field(rules),
            state.join(", "),
            hex(&DOMAIN.0),
            hex(&exercise.0),
            self.run.pos,
            self.run.now,
            hex(&actor.0.0),
            hex(&actor.1.0),
            cbor(&basis_value(&basis)),
            cbor(&capacity_value(Capacity::Own)),
            cbor(payload),
        )
    }

    fn step(
        &mut self,
        id: &str,
        rules: &[&str],
        actor: (Id, Id),
        basis: ExerciseBasis,
        payload: &Payload,
    ) -> Option<Digest> {
        use crate::vector_rules::hex;
        use alloc::format;
        let head = self.head(id, rules, actor, basis, &payload.to_value());
        let exercise = exercise_id(&DOMAIN, &self.run.pos.to_be_bytes().repeat(2)).unwrap();
        let (tail, ok) = match self.run.act(actor.0, actor.1, basis, payload) {
            Ok((_, out)) => {
                let effects: Vec<String> = out
                    .effects
                    .iter()
                    .map(|(k, v)| match v {
                        Some(v) => format!("[\"{}\", \"{}\"]", hex(k), cbor(v)),
                        None => format!("[\"{}\"]", hex(k)),
                    })
                    .collect();
                let req = set_value(out.requirements.iter().map(Canonical::to_value));
                (
                    format!(
                        "\"effects\": [{}], \"requirements\": \"{}\", \"expansion\": {}",
                        effects.join(", "),
                        cbor(&req),
                        out.expansion
                    ),
                    Some(exercise),
                )
            }
            Err(e) => (format!("\"error\": \"{}\"", e.code()), None),
        };
        self.cases.push(format!("  {head}, {tail}}}"));
        ok
    }
}

// L0-META-*: the scripted run, byte for byte
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one scripted run of the meta-actions"
)]
fn meta_vectors_match() {
    // INV-13, EI-8
    use crate::vector_rules::{field, golden};
    use alloc::format;
    let mut r = Recorder {
        run: Run::new(),
        cases: Vec::new(),
    };
    let a = shop_anchor();
    let anchor = ExerciseBasis::Anchor(a);
    let ex = r
        .step(
            "root-issues",
            &[
                "L0-META-3",
                "L0-META-4",
                "L0-META-5",
                "L0-META-7",
                "L0-META-10",
                "L0-META-25",
                "L0-META-28",
                "L0-META-29",
            ],
            (ROOT, ROOT),
            anchor,
            &issue(ALICE, GrantBasis::Anchor(a), &["eu"], 2),
        )
        .unwrap();
    let g1 = object_id(&ex, kind::GRANT, 0);
    r.step(
        "non-root-issues",
        &["L0-META-10"],
        (CAROL, CAROL),
        anchor,
        &issue(CAROL, GrantBasis::Anchor(a), &["eu"], 0),
    );
    r.step(
        "outside-anchor-scope",
        &["L0-META-25"],
        (ROOT, ROOT),
        anchor,
        &Payload::GrantIssue(GrantContent {
            basis: GrantBasis::Anchor(a),
            holder: SubjectSelector::Party(ALICE),
            authority: CanonicalAuthority {
                authority: AuthoritySet {
                    resource: ResourceSelector::Structural(Structural {
                        namespace: "bank".to_string(),
                        prefix: Vec::new(),
                        kind: None,
                        attrs: BTreeMap::new(),
                    }),
                    ..authority(&["eu"], 0, 10).authority
                },
                ..authority(&["eu"], 0, 10)
            },
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        }),
    );
    let h = HoldingRef {
        grant: g1,
        holder: ALICE,
        since: r.run.grant(&g1).since,
    };
    let ex2 = r
        .step(
            "holder-delegates",
            &["L0-META-13", "L0-META-25"],
            (ALICE, ALICE),
            ExerciseBasis::Holding(h),
            &issue(BOB, GrantBasis::Holding(h), &["eu", "de"], 1),
        )
        .unwrap();
    let g2 = object_id(&ex2, kind::GRANT, 0);
    r.step(
        "delegation-wider-than-parent",
        &["L0-META-25"],
        (ALICE, ALICE),
        ExerciseBasis::Holding(h),
        &issue(BOB, GrantBasis::Holding(h), &[], 1),
    );
    r.step(
        "someone-elses-holding",
        &["L0-META-13", "L0-META-25"],
        (BOB, BOB),
        ExerciseBasis::Holding(h),
        &issue(CAROL, GrantBasis::Holding(h), &["eu"], 0),
    );
    let mut agency = issue(CAROL, GrantBasis::Anchor(a), &["eu"], 0);
    if let Payload::GrantIssue(c) = &mut agency {
        c.agency.insert(Capacity::For(BOB));
    }
    r.step(
        "agency-not-continuous",
        &["L0-META-25"],
        (ROOT, ROOT),
        anchor,
        &agency,
    );
    r.step(
        "amend-narrows",
        &["L0-META-26", "L0-META-28"],
        (ROOT, ROOT),
        anchor,
        &Payload::GrantAmend {
            grant: g1,
            authority: authority(&["eu", "de"], 2, 1_000),
            agency: BTreeSet::from([Capacity::Own]),
            named: None,
        },
    );
    r.step(
        "stranger-revokes",
        &["L0-META-11", "L0-META-26"],
        (CAROL, CAROL),
        anchor,
        &Payload::GrantRevoke { grant: g2 },
    );
    r.step(
        "upstream-holder-revokes",
        &["L0-META-11", "L0-META-26"],
        (ALICE, ALICE),
        anchor,
        &Payload::GrantRevoke { grant: g2 },
    );
    r.step(
        "revoke-ended",
        &["L0-META-6"],
        (ROOT, ROOT),
        anchor,
        &Payload::GrantRevoke { grant: g2 },
    );
    r.step(
        "holder-renounces",
        &["L0-META-26"],
        (ALICE, ALICE),
        anchor,
        &Payload::GrantRenounce { grant: g1 },
    );
    let public = ExerciseBasis::Public(Id([9; 16]));
    let register = Payload::PartyRegister {
        party: BOB,
        root: Root::Sole(BOB),
        actor_kind: ActorKind::Human,
    };
    r.step(
        "register-someone-else",
        &["L0-META-22"],
        (CAROL, CAROL),
        public,
        &register,
    );
    r.step(
        "register-self",
        &["L0-META-22", "L0-META-13"],
        (BOB, BOB),
        public,
        &register,
    );
    r.step(
        "register-twice",
        &["L0-META-22"],
        (BOB, BOB),
        public,
        &register,
    );
    let key = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[5; 32])
            .verifying_key()
            .to_bytes(),
    );
    let create = Payload::InstanceCreate {
        party: BOB,
        key,
        mandate: None,
    };
    r.step(
        "instance-other-id",
        &["L0-META-23"],
        (BOB, BOB),
        public,
        &create,
    );
    let new_instance = object_id(
        &exercise_id(&DOMAIN, &r.run.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.step(
        "instance-create",
        &["L0-META-23"],
        (BOB, new_instance),
        public,
        &create,
    );
    let envelope = MandateEnvelope {
        authority: authority(&["eu"], 0, 10).authority,
        constraints: authority(&["eu"], 0, 10).constraints,
        requirements: BTreeSet::new(),
        pin: None,
    };
    r.step(
        "mandate-bind-other-party",
        &["L0-META-24"],
        (CAROL, CAROL),
        public,
        &Payload::MandateBind {
            instance: new_instance,
            envelope: envelope.clone(),
        },
    );
    r.step(
        "mandate-bind-own",
        &["L0-META-24"],
        (BOB, new_instance),
        public,
        &Payload::MandateBind {
            instance: new_instance,
            envelope,
        },
    );
    r.step(
        "terminate-not-own",
        &["L0-META-12", "L0-META-23"],
        (CAROL, CAROL),
        public,
        &Payload::InstanceTerminate {
            instance: new_instance,
        },
    );
    r.step(
        "terminate-own",
        &["L0-META-12", "L0-META-23"],
        (BOB, new_instance),
        public,
        &Payload::InstanceTerminate {
            instance: new_instance,
        },
    );
    let ex3 = r
        .step(
            "issue-for-retire",
            &["L0-META-25"],
            (ROOT, ROOT),
            anchor,
            &issue(CAROL, GrantBasis::Anchor(a), &["eu"], 0),
        )
        .unwrap();
    let g3 = object_id(&ex3, kind::GRANT, 0);
    r.step(
        "retire-no-disposition",
        &["L0-META-21"],
        (ROOT, ROOT),
        anchor,
        &Payload::AnchorRetire {
            anchor: a,
            disposition: BTreeMap::new(),
        },
    );
    r.step(
        "retire-keep",
        &["L0-META-21"],
        (ROOT, ROOT),
        anchor,
        &Payload::AnchorRetire {
            anchor: a,
            disposition: BTreeMap::from([(g3, Disposition::Keep)]),
        },
    );
    r.step(
        "retire-meta-anchor",
        &["L0-META-20"],
        (ROOT, ROOT),
        ExerciseBasis::Anchor(meta_anchor(&DOMAIN)),
        &Payload::AnchorRetire {
            anchor: meta_anchor(&DOMAIN),
            disposition: BTreeMap::new(),
        },
    );
    let joint = Payload::AnchorCreate {
        scope: AnchorScope::Resource(shop(&["eu"])),
        root: Root::Joint {
            parties: BTreeSet::from([ALICE, BOB, CAROL]),
            k: 2,
        },
        root_terms: BTreeSet::new(),
    };
    let ex4 = r
        .step(
            "nested-anchor",
            &["L0-META-20", "L0-META-28"],
            (ROOT, ROOT),
            anchor,
            &joint,
        )
        .unwrap();
    let eu = object_id(&ex4, kind::ANCHOR, 0);
    r.step(
        "joint-root-requires",
        &["L0-META-10", "L0-META-25"],
        (BOB, BOB),
        ExerciseBasis::Anchor(eu),
        &issue(CAROL, GrantBasis::Anchor(eu), &["eu", "fr"], 0),
    );
    r.step(
        "joint-root-ct3-quorum",
        &["L0-META-10", "L0-META-28"],
        (BOB, BOB),
        ExerciseBasis::Anchor(eu),
        &Payload::AnchorCreate {
            scope: AnchorScope::Resource(shop(&["eu", "fr"])),
            root: Root::Sole(BOB),
            root_terms: BTreeSet::new(),
        },
    );
    r.step(
        "nested-outside",
        &["L0-META-20"],
        (ALICE, ALICE),
        ExerciseBasis::Anchor(eu),
        &Payload::AnchorCreate {
            scope: AnchorScope::Resource(shop(&[])),
            root: Root::Sole(ALICE),
            root_terms: BTreeSet::new(),
        },
    );
    r.step(
        "retire-revoke",
        &["L0-META-20", "L0-META-21"],
        (ROOT, ROOT),
        anchor,
        &Payload::AnchorRetire {
            anchor: a,
            disposition: BTreeMap::from([(g3, Disposition::Revoke)]),
        },
    );
    r.step(
        "anchor-ended",
        &["L0-META-6", "L0-META-10"],
        (ROOT, ROOT),
        anchor,
        &issue(CAROL, GrantBasis::Anchor(a), &["eu"], 0),
    );
    r.step(
        "domain-object-needs-meta-root",
        &["L0-META-27"],
        (ALICE, ALICE),
        ExerciseBasis::Anchor(meta_anchor(&DOMAIN)),
        &Payload::PolicyRetire {
            policy: Id([8; 16]),
        },
    );
    r.step(
        "contribution-recorded",
        &["L0-META-30"],
        (ALICE, ALICE),
        ExerciseBasis::Public(Id([0; 16])),
        &Payload::Contribute {
            target: Digest([9; 32]),
            class: String::from("approve"),
        },
    );
    // L0-META-27, L0-META-28, L0-META-29, L0-META-31: the domain objects, their indexes and
    // reasons, so that F0 cross-checks them
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let acceptance = |issuer: Id, use_: &str, classes: &[&str], until: u64| {
        map([
            ("issuer", Some(issuer.to_value())),
            ("use", Some(Value::text(use_))),
            (
                "classes",
                Some(Value::Array(
                    classes.iter().map(|c| Value::text(c)).collect(),
                )),
            ),
            ("subject", Some(SubjectSelector::Public.to_value())),
            (
                "validity",
                Some(Value::Array(alloc::vec![
                    Value::Unsigned(0),
                    Value::Unsigned(until)
                ])),
            ),
        ])
    };
    let established = r
        .step(
            "acceptance-established",
            &["L0-META-27", "L0-META-28", "L0-META-29"],
            (ROOT, ROOT),
            meta,
            &Payload::AcceptanceEstablish(acceptance(
                CAROL,
                "subject-selection",
                &["staff", "guests"],
                100,
            )),
        )
        .unwrap();
    let accepted = object_id(&established, kind::ACCEPTANCE, 0);
    r.step(
        "acceptance-amend-narrows",
        &["L0-META-28"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceAmend {
            acceptance: accepted,
            content: acceptance(CAROL, "subject-selection", &["staff"], 50),
        },
    );
    r.step(
        "acceptance-amend-widens",
        &["L0-META-28"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceAmend {
            acceptance: accepted,
            content: acceptance(CAROL, "subject-selection", &["staff"], 500),
        },
    );
    r.step(
        "acceptance-amend-changes-use",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceAmend {
            acceptance: accepted,
            content: acceptance(CAROL, "predicate-input", &["staff"], 50),
        },
    );
    // OP-143 m.13 (a): a foreign-authority Acceptance names a foreign domain and its pinned
    // binding keys, joins that domain's index and keeps its pins; no other pairing decodes
    let pinned = |seed: u8| {
        let key = crate::verify::cose::PublicKey::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        );
        crate::verify::key_scope::BindingKey {
            kid: crate::verify::key_scope::thumbprint(&key),
            alg: crate::verify::cose::Algorithm::Ed25519,
            key,
            scope: crate::verify::key_scope::BindingScope::Domain,
            superseded: None,
        }
    };
    let foreign_issuer = |seed: u8| {
        let b = pinned(seed);
        Value::Map(alloc::vec![(
            Value::text(crate::foreign::INDEX),
            crate::foreign::ForeignIssuer {
                domain: Digest([0x0a; 32]),
                binding: BTreeMap::from([(b.kid, b)]),
            }
            .to_value(),
        )])
    };
    let with_issuer = |issuer: Value, use_: &str| match acceptance(CAROL, use_, &["pay"], 100) {
        Value::Map(m) => Value::Map(
            m.into_iter()
                .map(|(k, v)| {
                    if k == Value::text("issuer") {
                        (k, issuer.clone())
                    } else {
                        (k, v)
                    }
                })
                .collect(),
        ),
        other => other,
    };
    let establish =
        |content: Value| Value::Map(alloc::vec![(Value::text("acceptance_establish"), content)]);
    let foreign = r
        .step_raw(
            "foreign-acceptance-established",
            &["L0-META-5", "L0-META-27", "L0-META-28", "L0-META-29"],
            (ROOT, ROOT),
            meta,
            &establish(with_issuer(foreign_issuer(3), "foreign-authority")),
        )
        .unwrap();
    r.step_raw(
        "foreign-acceptance-amend-pins",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &Value::Map(alloc::vec![(
            Value::text("acceptance_amend"),
            map([
                (
                    "acceptance",
                    Some(object_id(&foreign, kind::ACCEPTANCE, 0).to_value()),
                ),
                (
                    "content",
                    Some(with_issuer(foreign_issuer(4), "foreign-authority")),
                ),
            ]),
        )]),
    );
    r.step_raw(
        "foreign-issuer-other-use",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &establish(with_issuer(foreign_issuer(3), "predicate-input")),
    );
    r.step_raw(
        "foreign-authority-party-issuer",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &establish(acceptance(CAROL, "foreign-authority", &["pay"], 100)),
    );
    let mut forged = pinned(3);
    forged.kid = pinned(4).kid;
    r.step_raw(
        "foreign-issuer-pin-not-thumbprint",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &establish(with_issuer(
            Value::Map(alloc::vec![(
                Value::text(crate::foreign::INDEX),
                map([
                    ("domain", Some(Digest([0x0a; 32]).to_value())),
                    (
                        "binding",
                        Some(Value::Array(alloc::vec![forged.to_value()]))
                    ),
                ]),
            )]),
            "foreign-authority",
        )),
    );
    // OP-141 m.35: a schema-definition Acceptance carries its SPP and joins its namespace's index
    let with_spp = |namespace: &str| {
        let spp = crate::schema::Spp {
            publisher: CAROL,
            namespace: namespace.to_string(),
            catalog_version: 1,
            actions: alloc::vec![crate::schema::ActionSchema {
                name: "refund".to_string(),
                major: 1,
                effect: crate::schema::EffectClass::Irreversible,
                reserved: false,
                consumption_bearing: true,
                params: BTreeMap::new(),
                resource_types: BTreeSet::new(),
                render: None,
            }],
            retirements: BTreeSet::new(),
            core_spec_min: None,
        };
        let mut m = match acceptance(CAROL, "schema-definition", &["action_schema"], 100) {
            Value::Map(m) => m,
            _ => Vec::new(),
        };
        m.push((Value::text("spp"), spp.to_value()));
        dcbor::decode(
            &dcbor::encode(&Value::Map(m), Limits::CEILING).unwrap(),
            Limits::CEILING,
        )
        .unwrap()
    };
    assert!(
        Payload::from_value(&Payload::AcceptanceEstablish(with_spp("shop")).to_value()).is_ok()
    );
    assert!(
        Payload::from_value(
            &Payload::AcceptanceEstablish(acceptance(CAROL, "schema-definition", &["a"], 1))
                .to_value()
        )
        .is_err()
    );
    let schema = r
        .step(
            "schema-acceptance-established",
            &["L0-META-27", "L0-META-34"],
            (ROOT, ROOT),
            meta,
            &Payload::AcceptanceEstablish(with_spp("shop")),
        )
        .unwrap();
    r.step(
        "schema-acceptance-namespace-change",
        &["L0-META-27", "L0-META-34"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceAmend {
            acceptance: object_id(&schema, kind::ACCEPTANCE, 0),
            content: with_spp("shop.eu"),
        },
    );
    r.step(
        "second-membership-issuer",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceEstablish(acceptance(BOB, "subject-selection", &["staff"], 100)),
    );
    let issued = r.step(
        "claim-issued",
        &["L0-META-27"],
        (ROOT, ROOT),
        meta,
        &Payload::ClaimIssue {
            subject: ALICE,
            class: String::from("staff"),
            value: crate::model::EqValue::Bool(true),
            validity: None,
            bound_intent: None,
            supersedes: None,
        },
    );
    r.step(
        "claim-issued-supersedes",
        &["L0-META-27"],
        (ROOT, ROOT),
        meta,
        &Payload::ClaimIssue {
            subject: ALICE,
            class: String::from("staff"),
            value: crate::model::EqValue::Bool(false),
            validity: None,
            bound_intent: None,
            supersedes: issued.map(|e| object_id(&e, kind::CLAIM, 0)),
        },
    );
    r.step(
        "claim-issued-bound",
        &["L0-META-27", "L0-META-32"],
        (ROOT, ROOT),
        meta,
        &Payload::ClaimIssue {
            subject: ALICE,
            class: String::from(NON_EXECUTION),
            value: crate::model::EqValue::Bool(true),
            validity: None,
            bound_intent: Some(SPENT),
            supersedes: None,
        },
    );
    r.step(
        "unknown-acceptance",
        &["L0-META-31"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceRevoke {
            acceptance: Id([9; 16]),
        },
    );
    // L0-META-5, L0-META-27: a policy joins its target's index and moves with it
    let policy = |target: Value, schema: &str| {
        map([
            ("schema", Some(Value::text(schema))),
            (
                "source",
                Some(Value::text("forbid(principal, action, resource);")),
            ),
            ("target", Some(target)),
        ])
    };
    let set_policy = r
        .step(
            "policy-set",
            &["L0-META-5", "L0-META-27", "L0-META-29"],
            (ROOT, ROOT),
            meta,
            &Payload::PolicySet {
                policy: None,
                content: policy(Value::text("domain"), RESTRICTION_SCHEMA),
            },
        )
        .unwrap();
    r.step(
        "policy-moves-target",
        &["L0-META-5", "L0-META-27"],
        (ROOT, ROOT),
        meta,
        &Payload::PolicySet {
            policy: Some(object_id(&set_policy, kind::POLICY, 0)),
            content: policy(tagged("party", ALICE.to_value()), RESTRICTION_SCHEMA),
        },
    );
    r.step(
        "policy-other-schema",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &Payload::PolicySet {
            policy: None,
            content: policy(Value::text("domain"), "cedar"),
        },
    );
    // L0-META-22, L0-META-23: rekey, recover and departure
    let key_of = |seed: u8| {
        PublicKey::Ed25519(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .to_bytes(),
        )
    };
    let second = object_id(
        &exercise_id(&DOMAIN, &r.run.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.step(
        "instance-create-again",
        &["L0-META-23"],
        (BOB, second),
        public,
        &Payload::InstanceCreate {
            party: BOB,
            key: key_of(6),
            mandate: None,
        },
    );
    r.step(
        "instance-rekey",
        &["L0-META-5", "L0-META-23"],
        (BOB, second),
        public,
        &Payload::InstanceRekey {
            instance: second,
            key: key_of(7),
        },
    );
    r.step(
        "instance-recover",
        &["L0-META-5", "L0-META-23"],
        (BOB, BOB),
        public,
        &Payload::InstanceRecover {
            instance: second,
            key: key_of(8),
        },
    );
    // OP-141 m.32: named AuthoritySets
    let eu = authority(&["eu"], 0, 1_000).authority;
    r.step(
        "authority-set-define",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &Payload::AuthoritySetDefine {
            name: String::from("refunds"),
            authority: eu.clone(),
        },
    );
    let pin = |version, digest| {
        issue_named(
            ALICE,
            GrantBasis::Anchor(meta_anchor(&DOMAIN)),
            &["eu"],
            0,
            Some((String::from("refunds"), version, digest)),
        )
    };
    let pinned_grant = r.step(
        "grant-pins-authority-set",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &pin(1, authority_set_digest(&eu)),
    );
    r.step(
        "grant-pin-wrong-digest",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &pin(1, Digest([1; 32])),
    );
    r.step(
        "grant-pin-unknown-version",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &pin(2, authority_set_digest(&eu)),
    );
    let all = authority(&[], 0, 1_000).authority;
    r.step(
        "authority-set-new-version",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &Payload::AuthoritySetDefine {
            name: String::from("refunds"),
            authority: all.clone(),
        },
    );
    let repin = |named| Payload::GrantAmend {
        grant: object_id(&pinned_grant.unwrap(), kind::GRANT, 0),
        authority: authority(&[], 0, 1_000),
        agency: BTreeSet::from([Capacity::Own]),
        named,
    };
    r.step(
        "grant-widens-past-pin",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &repin(None),
    );
    r.step(
        "grant-repins-authority-set",
        &["L0-META-33"],
        (ROOT, ROOT),
        meta,
        &repin(Some((
            String::from("refunds"),
            2,
            authority_set_digest(&all),
        ))),
    );
    // OP-141 m.28: releases
    let (ex, _) = r
        .run
        .act(
            ROOT,
            ROOT,
            meta,
            &issue(ALICE, GrantBasis::Anchor(meta_anchor(&DOMAIN)), &["eu"], 0),
        )
        .unwrap();
    let spending = Digest([17; 32]);
    spent(&mut r.run.state, &object_id(&ex, kind::GRANT, 0), &spending);
    r.step(
        "release-not-authorized",
        &["L0-META-32"],
        (CAROL, CAROL),
        meta,
        &release_of(spending, &[21]),
    );
    r.step(
        "release-actual-amount",
        &["L0-META-32"],
        (ALICE, ALICE),
        meta,
        &release_of(spending, &[21]),
    );
    r.step(
        "release-ground-reused",
        &["L0-META-31", "L0-META-32"],
        (ALICE, ALICE),
        meta,
        &release_of(spending, &[21]),
    );
    r.step(
        "release-ground-unbound",
        &["L0-META-32"],
        (CAROL, SPENDER),
        meta,
        &release_of(spending, &[23]),
    );
    r.step(
        "release-non-execution",
        &["L0-META-32"],
        (CAROL, SPENDER),
        meta,
        &release_of(spending, &[22]),
    );
    // OP-143 m.7: projections
    r.run.now = 1_000;
    let held = |r: &mut Recorder, holder: Id, depth: u64, until: u64| {
        let (ex, _) = r
            .run
            .act(
                ROOT,
                ROOT,
                meta,
                &Payload::GrantIssue(GrantContent {
                    basis: GrantBasis::Anchor(meta_anchor(&DOMAIN)),
                    holder: SubjectSelector::Party(holder),
                    authority: authority(&["eu"], depth, until),
                    agency: BTreeSet::from([Capacity::Own]),
                    named: None,
                }),
            )
            .unwrap();
        let g = object_id(&ex, kind::GRANT, 0);
        HoldingRef {
            grant: g,
            holder,
            since: r.run.grant(&g).since,
        }
    };
    let wide = held(&mut r, CAROL, 2, 200_000_000);
    let leaf = held(&mut r, CAROL, 0, 2_000_000);
    let bobs = held(&mut r, BOB, 1, 50_000_000);
    let bob_instance = object_id(
        &exercise_id(&DOMAIN, &r.run.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.run
        .act(
            BOB,
            bob_instance,
            public,
            &Payload::InstanceCreate {
                party: BOB,
                key: key_of(9),
                mandate: Some(MandateEnvelope {
                    authority: authority(&["eu", "fr"], 0, 10_000_000).authority,
                    constraints: authority(&["eu", "fr"], 0, 10_000_000).constraints,
                    requirements: BTreeSet::new(),
                    pin: None,
                }),
            },
        )
        .unwrap();
    r.step(
        "projection-from-holding",
        &["L0-META-5", "L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(wide),
        &projection(&["eu", "de"], 0, 3_600_000),
    );
    r.step(
        "projection-from-anchor-root",
        &["L0-META-10", "L0-META-35"],
        (ROOT, ROOT),
        meta,
        &projection(&["eu"], 0, 3_600_000),
    );
    r.step(
        "projection-from-leaf",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(leaf),
        &projection(&["eu"], 0, 1_500_000),
    );
    r.step(
        "projection-outside-basis",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(wide),
        &projection(&[], 0, 3_600_000),
    );
    r.step(
        "projection-window-longer",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(leaf),
        &projection(&["eu"], 0, 2_500_000),
    );
    r.step(
        "projection-horizon-beyond-day",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(wide),
        &projection(&["eu"], 0, 100_000_000),
    );
    r.step(
        "projection-delegable",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(wide),
        &projection(&["eu"], 1, 3_600_000),
    );
    r.step(
        "projection-within-mandate",
        &["L0-META-35"],
        (BOB, bob_instance),
        ExerciseBasis::Holding(bobs),
        &projection(&["eu", "fr"], 0, 5_000_000),
    );
    r.step(
        "projection-outside-mandate",
        &["L0-META-35"],
        (BOB, bob_instance),
        ExerciseBasis::Holding(bobs),
        &projection(&["eu", "de"], 0, 5_000_000),
    );
    r.step(
        "projection-grant-not-held",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(HoldingRef {
            holder: CAROL,
            ..bobs
        }),
        &projection(&["eu"], 0, 3_600_000),
    );
    r.step(
        "projection-someone-elses-holding",
        &["L0-META-13", "L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(bobs),
        &projection(&["eu"], 0, 3_600_000),
    );
    r.step(
        "projection-with-slice",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(wide),
        &sliced(&["eu", "de"], crate::validity::ProfileClass::Intermittent),
    );
    r.step(
        "projection-slice-online",
        &["L0-META-35"],
        (CAROL, CAROL),
        ExerciseBasis::Holding(wide),
        &sliced(&["eu", "de"], crate::validity::ProfileClass::Online),
    );
    r.step(
        "projection-slice-from-anchor",
        &["L0-META-35"],
        (ROOT, ROOT),
        meta,
        &sliced(&["eu"], crate::validity::ProfileClass::Intermittent),
    );
    r.step(
        "party-depart",
        &["L0-META-21", "L0-META-22"],
        (ROOT, ROOT),
        meta,
        &Payload::PartyDepart {
            party: BOB,
            disposition: BTreeMap::new(),
        },
    );
    let dave = Id([5; 16]);
    let edit = |payload: &Payload, name: &str, value: Option<Value>| -> Value {
        let Value::Map(mut outer) = payload.to_value() else {
            panic!("a payload is a map");
        };
        if let Value::Map(body) = &mut outer[0].1 {
            body.retain(|(k, _)| *k != Value::text(name));
            if let Some(v) = value {
                body.push((Value::text(name), v));
                body.sort_by_key(|(k, _)| dcbor::encode(k, Limits::CEILING).unwrap());
            }
        }
        Value::Map(outer)
    };
    let register_agent = Payload::PartyRegister {
        party: dave,
        root: Root::Sole(dave),
        actor_kind: ActorKind::Agent,
    };
    r.step_raw(
        "register-without-actor-kind",
        &["L0-META-1", "L0-META-22"],
        (dave, dave),
        public,
        &edit(&register_agent, "actor_kind", None),
    );
    r.step_raw(
        "register-unknown-actor-kind",
        &["L0-META-1", "L0-META-22"],
        (dave, dave),
        public,
        &edit(&register_agent, "actor_kind", Some(Value::text("robot"))),
    );
    r.step(
        "register-agent",
        &["L0-META-22"],
        (dave, dave),
        public,
        &register_agent,
    );
    let create_p256 = Payload::InstanceCreate {
        party: dave,
        key: p256_key(6),
        mandate: None,
    };
    let mut off_curve = p256_key(6).to_value();
    if let Value::Map(m) = &mut off_curve
        && let Value::Bytes(b) = &mut m[0].1
    {
        b[64] ^= 1;
    }
    r.step_raw(
        "instance-create-p256-off-curve",
        &["L0-META-1", "L0-META-23"],
        (dave, dave),
        public,
        &edit(&create_p256, "key", Some(off_curve)),
    );
    r.step_raw(
        "instance-create-ml-dsa",
        &["L0-META-1", "L0-META-23"],
        (dave, dave),
        public,
        &edit(
            &create_p256,
            "key",
            Some(
                PublicKey::MlDsa(crate::verify::cose::Algorithm::MlDsa44, vec![0; 1312]).to_value(),
            ),
        ),
    );
    let p256_instance = object_id(
        &exercise_id(&DOMAIN, &r.run.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.step(
        "instance-create-p256",
        &["L0-META-23"],
        (dave, p256_instance),
        public,
        &create_p256,
    );
    let json = format!(
        "{{\n \"rule\": \"OP-141\",\n \"track\": \"core\",\n \"version\": 1,\n \"operation\": \"meta.apply\",\n {},\n \"cases\": [\n{}\n ]\n}}\n",
        field(&["L0-META-1", "L0-META-2"]),
        r.cases.join(",\n")
    );
    golden(
        "meta.json",
        include_str!("../../../../conformance/vectors/core/1/meta.json"),
        &json,
    );
}
