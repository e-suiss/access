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
        self.act_in(Capacity::Own, party, instance, basis, payload)
    }

    fn act_in(
        &mut self,
        capacity: Capacity,
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
            capacity,
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

// C11, C15, INV-3, OP-141 m.3
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

// C17, CI-4, OP-141 m.3
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
    r.act(ALICE, ALICE, basis, &Payload::GrantRevoke { grant: g2 })
        .unwrap();
    assert_eq!(r.grant(&g2).ended.map(|e| e.how), Some(EndedHow::Revoked));
    // INV-5
    assert_eq!(
        r.act(ROOT, ROOT, basis, &Payload::GrantRevoke { grant: g2 }),
        Err(MetaError::Ended)
    );
    r.act(ALICE, ALICE, basis, &Payload::GrantRenounce { grant: g1 })
        .unwrap();
    assert_eq!(r.grant(&g1).ended.map(|e| e.how), Some(EndedHow::Renounced));
}

// C16
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

// INV-4
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

// OP-149 m.8
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

// OP-149 m.8
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

// OP-149 m.6, L0-SIG-4, P-256
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

// E6, §7.9.2.3, OP-141 m.2, m.4
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

// C10
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

// C9, C26
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
    // §13.7.3, OP-141 m.43
    let nested = Payload::AnchorCreate {
        scope: AnchorScope::Resource(shop(&["eu", "fr"])),
        root: Root::Sole(BOB),
        root_terms: BTreeSet::new(),
    };
    let (_, out) = r.act(BOB, BOB, ExerciseBasis::Anchor(eu), &nested).unwrap();
    let term = out.requirements.iter().next().unwrap();
    assert_eq!((term.class.as_str(), term.count), ("co_root", 2));
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

// OP-141 m.6, m.13
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

/// A Grant issue whose action name is not a Kernel identifier.
fn unreadable_issue() -> Payload {
    let mut p = issue(ALICE, GrantBasis::Anchor(shop_anchor()), &["eu"], 0);
    if let Payload::GrantIssue(c) = &mut p {
        let mut a = c.authority.authority.actions.exact.pop_first().unwrap();
        a.name = "enterprise-connection-manager".to_string();
        c.authority.authority.actions.exact.insert(a);
    }
    p
}

// L0-META-1, OP-153 m.20 (a), m.25 (a)
#[test]
fn a_payload_that_does_not_read_back_writes_nothing() {
    let mut r = Run::new();
    let p = unreadable_issue();
    assert!(Payload::from_value(&p.to_value()).is_err());
    let before = r.state.0.clone();
    assert!(matches!(
        r.act(ROOT, ROOT, ExerciseBasis::Anchor(shop_anchor()), &p),
        Err(MetaError::Malformed(_))
    ));
    assert_eq!(r.state.0, before);
}

// L0-META-30
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

/// A Claim of `class` bound to `intent` (OP-141 m.28 (d)).
fn bound_claim(class: &str, value: Option<crate::model::EqValue>, intent: Digest) -> Value {
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
}

/// An Exercise of `SPENDER` that drew 1 from a count term and 100 EUR from an amount term of
/// `grant`, and two Claims bound to its intent (OP-141 m.28).
fn spent(state: &mut Mem, grant: &Id, exercise: &Digest) {
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
            Some(bound_claim(
                ACTUAL_AMOUNT,
                Some(crate::model::EqValue::Int(30)),
                SPENT,
            )),
        ),
        (
            key(kind::CLAIM, &Id([22; 16])),
            Some(bound_claim(NON_EXECUTION, None, SPENT)),
        ),
        (
            key(kind::CLAIM, &Id([23; 16])),
            Some(bound_claim(NON_EXECUTION, None, Digest([16; 32]))),
        ),
    ]);
}

fn release_of(exercise: Digest, grounds: &[u8]) -> Payload {
    Payload::ConsumptionRelease {
        exercise,
        grounds: grounds.iter().map(|g| Id([*g; 16])).collect(),
    }
}

// OP-141 m.28
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

// OP-141 m.32
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

// OP-141 m.34 (d)
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

// OP-152 m.7 (d), §7.9.7.4, E17
#[test]
fn genesis_declares_causal_binding_only_as_true() {
    let mut fields = BTreeMap::new();
    fields.insert(
        "meta_anchor".to_string(),
        map([("root", Some(root_value(&Root::Sole(ROOT))))]),
    );
    let declared = genesis_effects(&DOMAIN, &fields).unwrap();
    assert!(
        declared
            .iter()
            .all(|(k, _)| *k != policy_default_key(CAUSAL_BINDING))
    );
    fields.insert(
        "policy".to_string(),
        map([(CAUSAL_BINDING, Some(Value::Bool(true)))]),
    );
    let effects = genesis_effects(&DOMAIN, &fields).unwrap();
    assert!(effects.contains(&(policy_default_key(CAUSAL_BINDING), Some(Value::Bool(true)))));
    for wrong in [
        Value::Bool(false),
        Value::Unsigned(1),
        Value::text("enforced"),
    ] {
        fields.insert("policy".to_string(), map([(CAUSAL_BINDING, Some(wrong))]));
        assert_eq!(
            genesis_effects(&DOMAIN, &fields).unwrap_err(),
            MetaError::Malformed(ModelError::Shape)
        );
    }
}

// L0-META-5, L0-META-27
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

// OP-141 m.20 (e), CI-11, EI-1
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

// OP-143 m.7, L0-META-35
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
        origins: crate::combinator::Origins::default(),
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
    // L0-META-27, L0-META-28, L0-META-29, L0-META-31
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
    // OP-143 m.13 (a)
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
    // OP-141 m.35
    let with_spp = |namespace: &str| {
        let spp = crate::schema::Spp {
            publisher: CAROL,
            namespace: namespace.to_string(),
            catalog_version: 1,
            actions: alloc::vec![crate::schema::ActionSchema {
                reversibility: None,
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
    // L0-META-5, L0-META-27
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
                defaults: None,
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
            defaults: None,
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
            defaults: None,
            policy: None,
            content: policy(Value::text("domain"), "cedar"),
        },
    );
    // L0-META-22, L0-META-23
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
    // OP-141 m.32
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
    // OP-141 m.28
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
    // OP-143 m.7
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
                    origins: crate::combinator::Origins::default(),
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
    let org = Id([6; 16]);
    r.step(
        "register-organization",
        &["L0-META-22"],
        (org, org),
        public,
        &Payload::PartyRegister {
            party: org,
            root: Root::Sole(org),
            actor_kind: ActorKind::Organization,
        },
    );
    let org_instance = object_id(
        &exercise_id(&DOMAIN, &r.run.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    // C6, OP-153 m.3 (b)
    r.step(
        "organization-has-no-instance",
        &["L0-META-23"],
        (org, org_instance),
        public,
        &Payload::InstanceCreate {
            party: org,
            key: p256_key(7),
            mandate: None,
        },
    );
    let forged = Id([7; 16]);
    r.run.state.apply(&[(
        super::key(kind::INSTANCE, &forged),
        Some(
            InstanceState {
                party: org,
                key: p256_key(8),
                since: 1,
                successor: None,
                ended: None,
            }
            .to_value(),
        ),
    )]);
    // C6, OP-153 m.3 (b)
    r.step(
        "organization-has-no-recovery",
        &["L0-META-23"],
        (org, forged),
        public,
        &Payload::InstanceRecover {
            instance: forged,
            key: p256_key(9),
        },
    );
    // L0-META-1, OP-153 m.20 (a)
    r.step_raw(
        "unreadable-identifier",
        &["L0-META-1", "L0-META-31"],
        (ROOT, ROOT),
        anchor,
        &unreadable_issue().to_value(),
    );
    // L0-META-20, TN-91, OP-153 m.17 (b)
    let made = r
        .step(
            "handover-anchor",
            &["L0-META-20"],
            (ROOT, ROOT),
            ExerciseBasis::Anchor(meta_anchor(&DOMAIN)),
            &Payload::AnchorCreate {
                scope: AnchorScope::Resource(shop(&["handover"])),
                root: Root::Sole(ROOT),
                root_terms: BTreeSet::new(),
            },
        )
        .unwrap();
    let handed = object_id(&made, kind::ANCHOR, 0);
    r.step(
        "transfer-asks-each-new-root",
        &["L0-META-20", "L0-META-21"],
        (ROOT, ROOT),
        ExerciseBasis::Anchor(handed),
        &Payload::AnchorTransfer {
            anchor: handed,
            root: Root::Joint {
                parties: BTreeSet::from([ROOT, BOB]),
                k: 1,
            },
            disposition: BTreeMap::new(),
        },
    );
    r.step(
        "amend-root-asks-the-new-root",
        &["L0-META-20"],
        (BOB, BOB),
        ExerciseBasis::Anchor(handed),
        &Payload::AnchorAmend {
            anchor: handed,
            root: Some(Root::Sole(CAROL)),
            root_terms: None,
        },
    );
    // L0-META-24a, E54 (4)
    let runner = Id([0x35; 16]);
    r.step(
        "register-an-agent",
        &["L0-META-22"],
        (runner, runner),
        public,
        &Payload::PartyRegister {
            party: runner,
            root: Root::Sole(runner),
            actor_kind: ActorKind::Agent,
        },
    );
    let tasked = object_id(
        &exercise_id(&DOMAIN, &r.run.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.step(
        "instance-create-for-a-task",
        &["L0-META-23"],
        (runner, tasked),
        public,
        &Payload::InstanceCreate {
            party: runner,
            key: PublicKey::Ed25519(
                ed25519_dalek::SigningKey::from_bytes(&[6; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            mandate: None,
        },
    );
    let with_origins = |write: &[&str]| MandateEnvelope {
        origins: crate::combinator::Origins {
            read: BTreeSet::from([String::from("https://shop.example")]),
            write: write.iter().map(|o| String::from(*o)).collect(),
        },
        ..self::envelope(&["eu"], BTreeSet::new(), None)
    };
    let bound = r
        .step(
            "mandate-bind-origins",
            &["L0-META-24", "L0-META-24a"],
            (runner, tasked),
            public,
            &Payload::MandateBind {
                instance: tasked,
                envelope: with_origins(&[]),
            },
        )
        .unwrap();
    let task_mandate = object_id(&bound, kind::MANDATE, 0);
    r.step(
        "mandate-rebind-widen-origins",
        &["L0-META-24a", "L0-META-28"],
        (runner, tasked),
        public,
        &Payload::MandateRebind {
            mandate: task_mandate,
            envelope: with_origins(&["https://shop.example"]),
        },
    );
    r.step(
        "mandate-rebind-narrow-origins",
        &["L0-META-24a", "L0-META-28"],
        (runner, tasked),
        public,
        &Payload::MandateRebind {
            mandate: task_mandate,
            envelope: with_origins(&[]),
        },
    );
    // SI-18, INV-36, OP-157 m.3 (b)
    let source = |extra: &str| {
        map([
            ("schema", Some(Value::text(RESTRICTION_SCHEMA))),
            (
                "source",
                Some(Value::text(&format!(
                    "forbid(principal, action, resource);{extra}"
                ))),
            ),
            ("target", Some(tagged("party", ALICE.to_value()))),
        ])
    };
    let amended = object_id(&set_policy, kind::POLICY, 0);
    r.step(
        "policy-amend-adds-forbid-narrows",
        &["L0-META-27", "L0-META-28"],
        (ROOT, ROOT),
        meta,
        &Payload::PolicySet {
            policy: Some(amended),
            content: source("\nforbid(principal, action, resource) when { context.tier > 1 };"),
            defaults: None,
        },
    );
    r.step(
        "policy-amend-drops-forbid-widens",
        &["L0-META-27", "L0-META-28"],
        (ROOT, ROOT),
        meta,
        &Payload::PolicySet {
            policy: Some(amended),
            content: source(""),
            defaults: None,
        },
    );
    // SI-18, SEC8, OP-157 m.3 (n)
    for (id, defaults) in [
        (
            "policy-defaults-raise-ct3-delay-narrows",
            PolicyDefaults {
                ct3_delay_s: Some(172_800),
                support_max_min: Some(60),
                ..PolicyDefaults::default()
            },
        ),
        (
            "policy-defaults-lower-ct3-delay-widens",
            PolicyDefaults {
                ct3_delay_s: Some(3_600),
                ..PolicyDefaults::default()
            },
        ),
        (
            "policy-defaults-add-surface-widens",
            PolicyDefaults {
                approval_surfaces: Some(BTreeSet::from([
                    String::from("suiss-approval-surface"),
                    String::from("vendor-surface"),
                ])),
                ..PolicyDefaults::default()
            },
        ),
    ] {
        r.step(
            id,
            &["L0-META-27", "L0-META-28"],
            (ROOT, ROOT),
            meta,
            &Payload::PolicySet {
                policy: Some(amended),
                content: source(""),
                defaults: Some(defaults),
            },
        );
    }
    self_anchor_steps(&mut r);
    transfer_steps(&mut r);
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

/// DAN restricting his own self-anchor (OP-157 m.11 (e), OP-158 m.3 (b), Ek B 5515).
#[allow(clippy::too_many_lines, reason = "one scripted run")]
fn self_anchor_steps(r: &mut Recorder) {
    use alloc::format;
    const DAN: Id = Id([0x51; 16]);
    let registered = r
        .step(
            "self-anchor-register",
            &["L0-META-22"],
            (DAN, DAN),
            ExerciseBasis::Public(Id([9; 16])),
            &Payload::PartyRegister {
                party: DAN,
                root: Root::Sole(DAN),
                actor_kind: ActorKind::Human,
            },
        )
        .unwrap();
    let own = object_id(&registered, kind::ANCHOR, 0);
    let basis = ExerciseBasis::Anchor(own);
    let on = |target: Value, source: &str| {
        map([
            ("schema", Some(Value::text(RESTRICTION_SCHEMA))),
            ("source", Some(Value::text(source))),
            ("target", Some(target)),
        ])
    };
    let mine = || tagged("anchor", own.to_value());
    let forbid = "forbid(principal, action, resource) when { context.breakglass };";
    let set = r
        .step(
            "self-anchor-restricts-itself",
            &["L0-META-27a", "L0-META-28"],
            (DAN, DAN),
            basis,
            &Payload::PolicySet {
                policy: None,
                content: on(mine(), forbid),
                defaults: None,
            },
        )
        .unwrap();
    let p = object_id(&set, kind::POLICY, 0);
    for (id, actor, content, policy, defaults) in [
        (
            "self-anchor-permit-refused",
            DAN,
            on(mine(), "permit(principal, action, resource);"),
            None,
            None,
        ),
        (
            "self-anchor-other-target-refused",
            DAN,
            on(tagged("party", DAN.to_value()), forbid),
            None,
            None,
        ),
        (
            "self-anchor-not-its-root",
            CAROL,
            on(mine(), forbid),
            None,
            None,
        ),
        (
            "policy-defaults-on-self-anchor-refused",
            DAN,
            on(mine(), forbid),
            None,
            Some(PolicyDefaults {
                ct3_delay_s: Some(172_800),
                ..PolicyDefaults::default()
            }),
        ),
        (
            "self-anchor-amend-drops-forbid-refused",
            DAN,
            on(mine(), ""),
            Some(p),
            None,
        ),
        (
            "self-anchor-amend-adds-forbid",
            DAN,
            on(
                mine(),
                &format!("{forbid}\nforbid(principal, action, resource);"),
            ),
            Some(p),
            None,
        ),
    ] {
        r.step(
            id,
            &["L0-META-27a", "L0-META-28"],
            (actor, actor),
            basis,
            &Payload::PolicySet {
                policy,
                content,
                defaults,
            },
        );
    }
}

/// A conditional `anchor_transfer` Grant its root wrote, used by its holder (OP-157 m.13 (b),
/// OP-158 m.3 (b), Ek B 5669).
#[allow(clippy::too_many_lines, reason = "one scripted run")]
fn transfer_steps(r: &mut Recorder) {
    let created = r
        .step(
            "transfer-anchor-create",
            &["L0-META-20"],
            (ROOT, ROOT),
            ExerciseBasis::Anchor(meta_anchor(&DOMAIN)),
            &Payload::AnchorCreate {
                scope: AnchorScope::Resource(shop(&["xfer"])),
                root: Root::Sole(ROOT),
                root_terms: BTreeSet::new(),
            },
        )
        .unwrap();
    let x = object_id(&created, kind::ANCHOR, 0);
    let condition = crate::model::WhileCondition::ClaimHeld {
        class: String::from("ownership_changed"),
        subject: SubjectSelector::Party(CAROL),
        acceptance: Digest([0x33; 32]),
    };
    let transfer_authority = |conditional: bool| {
        let mut a = authority(&["xfer"], 0, 1_000_000);
        a.authority.actions.exact = BTreeSet::from([core_action("anchor_transfer")]);
        if conditional {
            a.constraints.conditions = BTreeSet::from([condition.clone()]);
        }
        a
    };
    let mut held = Vec::new();
    for (id, conditional) in [
        ("transfer-grant-conditional", true),
        ("transfer-grant-unconditional", false),
    ] {
        let ex = r
            .step(
                id,
                &["L0-META-20a", "L0-META-25"],
                (ROOT, ROOT),
                ExerciseBasis::Anchor(x),
                &Payload::GrantIssue(GrantContent {
                    basis: GrantBasis::Anchor(x),
                    holder: SubjectSelector::Party(CAROL),
                    authority: transfer_authority(conditional),
                    agency: BTreeSet::from([Capacity::Own]),
                    named: None,
                }),
            )
            .unwrap();
        let g = object_id(&ex, kind::GRANT, 0);
        held.push((
            g,
            HoldingRef {
                grant: g,
                holder: CAROL,
                since: r.run.grant(&g).since,
            },
        ));
    }
    let [(cond, cond_h), (plain, plain_h)] = [held[0], held[1]];
    let disposition = BTreeMap::from([(cond, Disposition::Keep), (plain, Disposition::Revoke)]);
    let transfer = |anchor: Id, root: Root| Payload::AnchorTransfer {
        anchor,
        root,
        disposition: disposition.clone(),
    };
    for (id, basis, payload) in [
        (
            "transfer-unconditional-grant-refused",
            plain_h,
            transfer(x, Root::Sole(CAROL)),
        ),
        (
            "transfer-to-someone-else-refused",
            cond_h,
            transfer(x, Root::Sole(BOB)),
        ),
        (
            "transfer-other-anchor-refused",
            cond_h,
            transfer(shop_anchor(), Root::Sole(CAROL)),
        ),
        (
            "transfer-by-conditional-grant",
            cond_h,
            transfer(x, Root::Sole(CAROL)),
        ),
    ] {
        r.step(
            id,
            &["L0-META-20a", "L0-META-21"],
            (CAROL, CAROL),
            ExerciseBasis::Holding(basis),
            &payload,
        );
    }
}

fn term(count: u64) -> RequirementTerm {
    co_root(count)
}

fn envelope(
    prefix: &[&str],
    requirements: BTreeSet<RequirementTerm>,
    pin: Option<HoldingRef>,
) -> MandateEnvelope {
    let a = authority(prefix, 0, 1_000_000);
    MandateEnvelope {
        origins: crate::combinator::Origins::default(),
        authority: a.authority,
        constraints: a.constraints,
        requirements,
        pin,
    }
}

/// Root issues `holder` a Grant on the shop Anchor and returns its current holding.
fn held(r: &mut Run, holder: Id, prefix: &[&str], depth: u64) -> HoldingRef {
    let a = shop_anchor();
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(a),
            &issue(holder, GrantBasis::Anchor(a), prefix, depth),
        )
        .unwrap();
    let grant = object_id(&ex, kind::GRANT, 0);
    HoldingRef {
        grant,
        holder,
        since: r.grant(&grant).since,
    }
}

/// Registers Alice and creates her Instance with an optional first Mandate.
fn alice_instance(r: &mut Run, mandate: Option<MandateEnvelope>) -> Id {
    let public = ExerciseBasis::Public(Id([9; 16]));
    r.act(
        ALICE,
        ALICE,
        public,
        &Payload::PartyRegister {
            party: ALICE,
            root: Root::Sole(ALICE),
            actor_kind: ActorKind::Human,
        },
    )
    .unwrap();
    let instance = object_id(
        &exercise_id(&DOMAIN, &r.pos.to_be_bytes().repeat(2)).unwrap(),
        kind::INSTANCE,
        0,
    );
    r.act(
        ALICE,
        instance,
        public,
        &Payload::InstanceCreate {
            party: ALICE,
            key: p256_key(3),
            mandate,
        },
    )
    .unwrap();
    instance
}

/// The `projection` payload with other bounds.
fn projection_of(bounds: CanonicalAuthority) -> Payload {
    match projection(&["eu"], 0, 1_000) {
        Payload::ProjectionIssue {
            audience,
            class,
            variant,
            max_staleness_ms,
            offline_slice,
            ..
        } => Payload::ProjectionIssue {
            bounds,
            audience,
            class,
            variant,
            max_staleness_ms,
            offline_slice,
        },
        other => other,
    }
}

// OP-141 m.6, m.13
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one payload per meta-action of the closed list"
)]
fn every_payload_round_trips() {
    let anchor = shop_anchor();
    let g = Id([10; 16]);
    let h = Id([11; 16]);
    let pin = HoldingRef {
        grant: g,
        holder: ALICE,
        since: 3,
    };
    let terms = BTreeSet::from([term(1)]);
    let acceptance = map(acceptance(CAROL, "predicate-input", "kyc"));
    let policy = map([
        ("schema", Some(Value::text(RESTRICTION_SCHEMA))),
        ("source", Some(Value::text("deny all"))),
        ("target", Some(Value::text("domain"))),
    ]);
    let payloads = [
        Payload::AnchorCreate {
            scope: AnchorScope::Resource(shop(&["eu"])),
            root: Root::Joint {
                parties: BTreeSet::from([ALICE, BOB]),
                k: 2,
            },
            root_terms: terms.clone(),
        },
        Payload::AnchorTransfer {
            anchor,
            root: Root::Sole(BOB),
            disposition: BTreeMap::from([(g, Disposition::Keep), (h, Disposition::Revoke)]),
        },
        Payload::AnchorAmend {
            anchor,
            root: Some(Root::Sole(ALICE)),
            root_terms: Some(BTreeSet::from([term(2)])),
        },
        Payload::AnchorRetire {
            anchor,
            disposition: BTreeMap::from([(g, Disposition::Revoke), (h, Disposition::Keep)]),
        },
        Payload::PartyRegister {
            party: ALICE,
            root: Root::Sole(ALICE),
            actor_kind: ActorKind::Agent,
        },
        Payload::PartyDepart {
            party: ALICE,
            disposition: BTreeMap::from([(g, Disposition::Keep)]),
        },
        Payload::InstanceCreate {
            party: ALICE,
            key: p256_key(3),
            mandate: Some(envelope(&["eu"], terms.clone(), Some(pin))),
        },
        Payload::InstanceRekey {
            instance: h,
            key: p256_key(4),
        },
        Payload::InstanceTerminate { instance: h },
        Payload::InstanceRecover {
            instance: h,
            key: p256_key(5),
        },
        Payload::MandateBind {
            instance: h,
            envelope: envelope(&["eu"], terms.clone(), Some(pin)),
        },
        Payload::MandateRebind {
            mandate: g,
            envelope: envelope(&[], BTreeSet::new(), None),
        },
        Payload::MandateRevoke { mandate: g },
        issue(ALICE, GrantBasis::Holding(pin), &["eu"], 1),
        Payload::GrantAmend {
            grant: g,
            authority: authority(&["eu"], 1, 1_000),
            agency: BTreeSet::from([Capacity::Own, Capacity::For(BOB)]),
            named: Some((String::from("refunds"), 1, Digest([9; 32]))),
        },
        Payload::GrantRevoke { grant: g },
        Payload::GrantRenounce { grant: g },
        Payload::AcceptanceEstablish(acceptance.clone()),
        Payload::AcceptanceAmend {
            acceptance: g,
            content: acceptance,
        },
        Payload::AcceptanceRevoke { acceptance: g },
        Payload::PolicySet {
            defaults: None,
            policy: Some(h),
            content: policy,
        },
        Payload::PolicyRetire { policy: h },
        Payload::ClaimIssue {
            subject: ALICE,
            class: String::from("member"),
            value: crate::model::EqValue::Bool(true),
            validity: Some(Window { from: 0, until: 10 }),
            bound_intent: Some(Digest([8; 32])),
            supersedes: Some(g),
        },
        Payload::Contribute {
            target: Digest([9; 32]),
            class: String::from("approve"),
        },
        Payload::ConsumptionRelease {
            exercise: Digest([9; 32]),
            grounds: BTreeSet::from([g, h]),
        },
        Payload::AuthoritySetDefine {
            name: String::from("refunds"),
            authority: authority(&["eu"], 0, 1_000).authority,
        },
        sliced(&["eu"], crate::validity::ProfileClass::Intermittent),
    ];
    let payloads: Vec<Payload> = payloads.into_iter().chain(stage13_payloads()).collect();
    let mut names = BTreeSet::new();
    for p in &payloads {
        assert_eq!(Payload::from_value(&p.to_value()).as_ref(), Ok(p), "{p:?}");
        assert!(is_meta(NAMESPACE, p.action()));
        names.insert(p.action());
    }
    assert_eq!(names.len(), NAMES.len());
}

fn stage13_binding() -> BTreeMap<[u8; 32], crate::verify::key_scope::BindingKey> {
    let key = PublicKey::Ed25519(
        ed25519_dalek::SigningKey::from_bytes(&[5; 32])
            .verifying_key()
            .to_bytes(),
    );
    let b = crate::verify::key_scope::BindingKey {
        kid: crate::verify::key_scope::thumbprint(&key),
        alg: crate::verify::cose::Algorithm::Ed25519,
        key,
        scope: crate::verify::key_scope::BindingScope::Domain,
        superseded: None,
    };
    BTreeMap::from([(b.kid, b)])
}

fn stage13_payloads() -> [Payload; 4] {
    use crate::recovery::{CheckpointRef, HandoverInput, LostSuffix, RecoverInput};
    let c = CheckpointRef::new(9, Digest([6; 32]));
    let mut recover = RecoverInput::new(9, c, stage13_binding());
    recover.lost_suffix = Some(LostSuffix::new(9, 12));
    recover.witness_claims.insert(Id([7; 16]));
    [
        Payload::DomainHandover(HandoverInput::new(stage13_binding(), c, false)),
        Payload::DomainRecover(recover),
        Payload::VersionActivate {
            versions: crate::verify::key_scope::SpecVersions {
                core: 2,
                meta_schema: 1,
                ..crate::verify::key_scope::SpecVersions::default()
            },
        },
        Payload::AlgorithmRetire {
            algorithm: crate::verify::cose::Algorithm::MlDsa44,
        },
    ]
}

// OP-158 m.4 (a)
#[test]
fn stage13_meta_actions_are_refused_as_restricted_until_decided() {
    let mut r = Run::new();
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    for p in stage13_payloads() {
        assert_eq!(
            r.act(ROOT, ROOT, meta, &p).map(|_| ()),
            Err(MetaError::Restricted),
            "{}",
            p.action()
        );
    }
    assert_eq!(MetaError::Restricted.code(), "meta-restricted");
}

// C10, E6
#[test]
fn a_disposition_is_keep_or_revoke() {
    let pair =
        |word: &str| Value::Array(vec![Value::Array(vec![BOB.to_value(), Value::text(word)])]);
    assert_eq!(
        disposition(&pair("keep")),
        Ok(BTreeMap::from([(BOB, Disposition::Keep)]))
    );
    assert_eq!(
        disposition(&pair("revoke")),
        Ok(BTreeMap::from([(BOB, Disposition::Revoke)]))
    );
    for word in ["suspend", "Keep", ""] {
        assert_eq!(disposition(&pair(word)), Err(ModelError::Unknown), "{word}");
    }
}

// OP-143 m.12
#[test]
fn an_offline_slice_asks_for_something() {
    let slice = |count: Option<u64>, amounts: &[(&str, u64)]| SliceRequest {
        count,
        amounts: amounts
            .iter()
            .map(|(u, a)| ((*u).to_string(), *a))
            .collect(),
    };
    for ok in [
        slice(Some(3), &[("eur", 500)]),
        slice(Some(1), &[]),
        slice(None, &[("eur", 1)]),
    ] {
        assert_eq!(SliceRequest::from_value(&ok.to_value()), Ok(ok));
    }
    for bad in [
        slice(None, &[]),
        slice(Some(0), &[]),
        slice(Some(0), &[("eur", 1)]),
        slice(Some(2), &[("eur", 0)]),
        slice(None, &[("eur", 0)]),
    ] {
        assert_eq!(
            SliceRequest::from_value(&bad.to_value()),
            Err(ModelError::Range),
            "{bad:?}"
        );
    }
}

// C9
#[test]
fn a_joint_root_has_a_reachable_quorum() {
    let joint = |parties: &[Id], k: u64| Root::Joint {
        parties: parties.iter().copied().collect(),
        k,
    };
    for ok in [
        joint(&[ALICE, BOB], 2),
        joint(&[ALICE, BOB], 1),
        joint(&[ALICE, BOB, CAROL], 3),
        Root::Sole(ALICE),
    ] {
        assert_eq!(root(&root_value(&ok)), Ok(ok));
    }
    for bad in [
        joint(&[ALICE], 1),
        joint(&[ALICE, BOB], 0),
        joint(&[ALICE, BOB], 3),
        joint(&[ALICE, BOB, CAROL], 4),
    ] {
        assert_eq!(root(&root_value(&bad)), Err(ModelError::Range), "{bad:?}");
    }
}

// L0-META-10
#[test]
fn joint_root_requirements_count_the_other_members() {
    let anchor = |parties: &[Id], k: u64| AnchorState {
        scope: AnchorScope::Domain,
        root: Root::Joint {
            parties: parties.iter().copied().collect(),
            k,
        },
        root_terms: BTreeSet::from([term(5)]),
        since: 0,
        ended: None,
    };
    let actor = |party: Id| Actor {
        party,
        instance: party,
    };
    let three = anchor(&[ALICE, BOB, CAROL], 3);
    assert_eq!(
        root_requirements(&three, &actor(BOB)),
        Some(BTreeSet::from([term(5), co_root(2)]))
    );
    assert_eq!(root_requirements(&three, &actor(ROOT)), None);
    let any = anchor(&[ALICE, BOB], 1);
    assert_eq!(
        root_requirements(&any, &actor(ALICE)),
        Some(BTreeSet::from([term(5)]))
    );
    assert_eq!(root_requirements(&any, &actor(CAROL)), None);
}

// §7.9.2.3
#[test]
fn a_self_anchor_covers_its_party_resources() {
    let party = Id([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);
    let Some(ResourceSelector::Structural(s)) = scope_selector(&AnchorScope::Party(party)) else {
        panic!("a self-anchor covers structural resources");
    };
    assert_eq!(s.namespace, "access.party");
    assert_eq!(s.prefix, ["0123456789abcdeffedcba9876543210".to_string()]);
    assert!(scope_selector(&AnchorScope::Domain).is_none());
}

fn acceptance(issuer: Id, use_: &str, class: &str) -> Vec<(&'static str, Option<Value>)> {
    alloc::vec![
        ("issuer", Some(issuer.to_value())),
        ("use", Some(Value::text(use_))),
        ("classes", Some(set_value([Value::text(class)]))),
        ("subject", Some(SubjectSelector::Public.to_value())),
        ("validity", Some(Window { from: 0, until: 10 }.to_value())),
    ]
}

// OP-141 m.21 (a)
#[test]
fn an_acceptance_names_a_known_use_and_a_positive_quota() {
    assert!(acceptance_content(&map(acceptance(CAROL, "predicate-input", "kyc"))).is_ok());
    assert_eq!(
        acceptance_content(&map(acceptance(CAROL, "anything-goes", "kyc"))),
        Err(ModelError::Unknown)
    );
    let quota = |count: u64, window_s: u64| {
        let mut c = acceptance(CAROL, "predicate-input", "kyc");
        c.push((
            "quota",
            Some(map([
                ("count", Some(Value::Unsigned(count))),
                ("window_s", Some(Value::Unsigned(window_s))),
            ])),
        ));
        acceptance_content(&map(c))
    };
    assert!(quota(1_000, 3_600).is_ok());
    assert_eq!(quota(0, 3_600), Err(ModelError::Range));
    assert_eq!(quota(1_000, 0), Err(ModelError::Range));
}

// OP-141 m.28, L1-ADP-13
#[test]
fn an_exercise_without_draws_omits_them() {
    let base = || {
        alloc::vec![
            ("intent", Some(SPENT.to_value())),
            ("actor", Some(SPENDER.to_value())),
            ("since", Some(Value::Unsigned(1))),
        ]
    };
    let e = ExerciseState::from_value(&map(base())).unwrap();
    assert_eq!(e.to_value(), map(base()));
    let mut empty = base();
    empty.push(("draws", Some(Value::Array(Vec::new()))));
    assert_eq!(
        ExerciseState::from_value(&map(empty)),
        Err(ModelError::Shape)
    );
}

fn genesis_fields() -> BTreeMap<String, Value> {
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
    fields
}

// C4, OP-141 m.6
#[test]
fn genesis_grants_derive_from_a_genesis_anchor() {
    let grant_on = |index: u64| {
        let mut fields = genesis_fields();
        fields.insert(
            "grants".to_string(),
            set_value([map([
                ("anchor", Some(Value::Unsigned(index))),
                ("holder", Some(SubjectSelector::Party(ALICE).to_value())),
                ("authority", Some(authority(&["eu"], 0, 1_000).to_value())),
            ])]),
        );
        genesis_effects(&DOMAIN, &fields)
    };
    let mut state = Mem(BTreeMap::new());
    state.apply(&grant_on(1).unwrap());
    let g = object_id(&DOMAIN, kind::GRANT, 0);
    let stored: GrantState = read(&state, kind::GRANT, &g).unwrap();
    assert_eq!(stored.content.basis, GrantBasis::Anchor(shop_anchor()));
    assert_eq!(stored.content.holder, SubjectSelector::Party(ALICE));
    assert_eq!(
        ids(&state, kind::CHILDREN, &shop_anchor()).unwrap(),
        BTreeSet::from([g])
    );
    assert!(grant_on(0).is_ok());
    assert_eq!(
        grant_on(2).unwrap_err(),
        MetaError::Malformed(ModelError::Range)
    );
}

// L0-META-5, OP-141 m.20 (e)
#[test]
fn genesis_selection_acceptances_have_one_issuer_per_class() {
    let with = |list: Vec<Value>| {
        let mut fields = genesis_fields();
        fields.insert("acceptances".to_string(), set_value(list));
        genesis_effects(&DOMAIN, &fields)
    };
    let mut later = acceptance(CAROL, "subject-selection", "staff");
    later.retain(|(k, _)| *k != "validity");
    later.push(("validity", Some(Window { from: 0, until: 20 }.to_value())));
    let effects = with(alloc::vec![
        map(acceptance(CAROL, "subject-selection", "staff")),
        map(later),
        map(acceptance(BOB, "predicate-input", "kyc")),
    ])
    .unwrap();
    let mut state = Mem(BTreeMap::new());
    state.apply(&effects);
    let all = BTreeSet::from([
        object_id(&DOMAIN, kind::ACCEPTANCE, 0),
        object_id(&DOMAIN, kind::ACCEPTANCE, 1),
        object_id(&DOMAIN, kind::ACCEPTANCE, 2),
    ]);
    let staff = index_of(&state, &selection_key("staff")).unwrap();
    assert_eq!(staff.len(), 2);
    assert!(staff.is_subset(&all));
    assert!(index_of(&state, &selection_key("kyc")).unwrap().is_empty());
    assert_eq!(
        with(alloc::vec![
            map(acceptance(CAROL, "subject-selection", "staff")),
            map(acceptance(BOB, "subject-selection", "staff")),
        ])
        .unwrap_err(),
        MetaError::NotWithin
    );
}

// C10, OP-141 m.3
#[test]
fn anchor_transfer_and_amend_act_on_the_named_anchor() {
    let mut r = Run::new();
    let a = shop_anchor();
    let g = held(&mut r, ALICE, &["eu"], 0).grant;
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let basis = ExerciseBasis::Anchor(a);
    let transfer = Payload::AnchorTransfer {
        anchor: a,
        root: Root::Sole(BOB),
        disposition: BTreeMap::from([(g, Disposition::Keep)]),
    };
    assert_eq!(r.act(ROOT, ROOT, meta, &transfer), Err(MetaError::Basis));
    let (_, out) = r.act(ROOT, ROOT, basis, &transfer).unwrap();
    assert!(out.expansion);
    // L0-META-20, TN-91, OP-153 m.17 (b)
    assert_eq!(out.requirements, BTreeSet::from([accept_root(BOB)]));
    assert!(r.grant(&g).ended.is_none());
    let anchor: AnchorState = read(&r.state, kind::ANCHOR, &a).unwrap();
    assert_eq!(anchor.root, Root::Sole(BOB));

    let amend =
        |root: Option<Root>, terms: Option<BTreeSet<RequirementTerm>>| Payload::AnchorAmend {
            anchor: a,
            root,
            root_terms: terms,
        };
    let add = amend(None, Some(BTreeSet::from([term(1)])));
    assert_eq!(r.act(BOB, BOB, meta, &add), Err(MetaError::Basis));
    let (_, out) = r.act(BOB, BOB, basis, &add).unwrap();
    assert!(!out.expansion);
    let (_, out) = r
        .act(BOB, BOB, basis, &amend(None, Some(BTreeSet::new())))
        .unwrap();
    assert!(out.requirements.contains(&term(1)));
    assert!(out.expansion);
    let (_, out) = r
        .act(BOB, BOB, basis, &amend(Some(Root::Sole(CAROL)), None))
        .unwrap();
    assert!(out.expansion);
    assert!(out.requirements.contains(&accept_root(CAROL)));
    let anchor: AnchorState = read(&r.state, kind::ANCHOR, &a).unwrap();
    assert_eq!(anchor.root, Root::Sole(CAROL));
    let joint = Root::Joint {
        parties: BTreeSet::from([CAROL, ALICE]),
        k: 1,
    };
    let (_, out) = r
        .act(CAROL, CAROL, basis, &amend(Some(joint), None))
        .unwrap();
    assert!(out.requirements.contains(&accept_root(ALICE)));
    assert!(!out.requirements.contains(&accept_root(CAROL)));
}

// C14
#[test]
fn a_mandate_pin_names_the_actors_current_holding() {
    let mut r = Run::new();
    let instance = alice_instance(&mut r, None);
    let mine = held(&mut r, ALICE, &["eu"], 0);
    let bobs = held(&mut r, BOB, &["eu"], 0);
    let public = ExerciseBasis::Public(Id([9; 16]));
    let bind = |pin: HoldingRef| Payload::MandateBind {
        instance,
        envelope: envelope(&["eu"], BTreeSet::new(), Some(pin)),
    };
    for wrong in [
        HoldingRef {
            holder: BOB,
            ..mine
        },
        HoldingRef {
            since: mine.since.checked_add(1).unwrap(),
            ..mine
        },
        HoldingRef {
            holder: ALICE,
            ..bobs
        },
    ] {
        assert_eq!(
            r.act(ALICE, instance, public, &bind(wrong)),
            Err(MetaError::NotAuthorized),
            "{wrong:?}"
        );
    }
    let (ex, out) = r.act(ALICE, instance, public, &bind(mine)).unwrap();
    assert!(out.expansion);
    let mandate = object_id(&ex, kind::MANDATE, 0);
    let stored: MandateState = read(&r.state, kind::MANDATE, &mandate).unwrap();
    assert_eq!(stored.envelope.pin, Some(mine));

    // C14
    let rebind = |prefix: &[&str]| Payload::MandateRebind {
        mandate,
        envelope: envelope(prefix, BTreeSet::new(), None),
    };
    let (_, out) = r
        .act(ALICE, instance, public, &rebind(&["eu", "de"]))
        .unwrap();
    assert!(!out.expansion);
    let (_, out) = r.act(ALICE, instance, public, &rebind(&["eu"])).unwrap();
    assert!(out.expansion);
}

// C15, INV-3
#[test]
fn delegation_and_amend_stay_within_the_current_holding() {
    let mut r = Run::new();
    let h = held(&mut r, ALICE, &["eu"], 2);
    let stale = HoldingRef {
        since: h.since.checked_add(1).unwrap(),
        ..h
    };
    assert_eq!(
        r.act(
            ALICE,
            ALICE,
            ExerciseBasis::Holding(stale),
            &issue(BOB, GrantBasis::Holding(stale), &["eu", "de"], 1)
        ),
        Err(MetaError::NotAuthorized)
    );
    let (ex, _) = r
        .act(
            ALICE,
            ALICE,
            ExerciseBasis::Holding(h),
            &issue(BOB, GrantBasis::Holding(h), &["eu", "de"], 1),
        )
        .unwrap();
    let g2 = object_id(&ex, kind::GRANT, 0);
    let amend = |prefix: &[&str]| Payload::GrantAmend {
        grant: g2,
        authority: authority(prefix, 1, 1_000),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    };
    let any = ExerciseBasis::Holding(h);
    let (_, out) = r.act(ALICE, ALICE, any, &amend(&["eu", "fr"])).unwrap();
    assert!(out.expansion);
    assert_eq!(
        r.grant(&g2).content.authority,
        authority(&["eu", "fr"], 1, 1_000)
    );
    assert_eq!(
        r.act(ALICE, ALICE, any, &amend(&[])),
        Err(MetaError::NotWithin)
    );
}

// OP-143 m.7, L0-META-35
#[test]
fn a_holding_projection_stays_within_its_lineage() {
    let mut r = Run::new();
    let h = held(&mut r, ALICE, &["eu"], 1);
    let p = projection(&["eu"], 0, 1_000);
    let mine = ExerciseBasis::Holding(h);
    r.act(ALICE, ALICE, mine, &p).unwrap();
    assert_eq!(
        r.act_in(Capacity::For(CAROL), ALICE, ALICE, mine, &p),
        Err(MetaError::NotWithin)
    );
    let (ex, _) = r
        .act(
            ALICE,
            ALICE,
            mine,
            &issue(BOB, GrantBasis::Holding(h), &["eu"], 0),
        )
        .unwrap();
    let g2 = object_id(&ex, kind::GRANT, 0);
    let bobs = ExerciseBasis::Holding(HoldingRef {
        grant: g2,
        holder: BOB,
        since: r.grant(&g2).since,
    });
    r.act(BOB, BOB, bobs, &p).unwrap();
    r.act(
        ROOT,
        ROOT,
        ExerciseBasis::Anchor(shop_anchor()),
        &Payload::GrantRevoke { grant: h.grant },
    )
    .unwrap();
    assert_eq!(r.act(BOB, BOB, bobs, &p), Err(MetaError::NotWithin));

    let mut demanding = authority(&["eu"], 0, 1_000);
    demanding.requirements.insert(term(1));
    let (ex, _) = r
        .act(
            ROOT,
            ROOT,
            ExerciseBasis::Anchor(shop_anchor()),
            &Payload::GrantIssue(GrantContent {
                basis: GrantBasis::Anchor(shop_anchor()),
                holder: SubjectSelector::Party(CAROL),
                authority: demanding.clone(),
                agency: BTreeSet::from([Capacity::Own]),
                named: None,
            }),
        )
        .unwrap();
    let g3 = object_id(&ex, kind::GRANT, 0);
    let carols = ExerciseBasis::Holding(HoldingRef {
        grant: g3,
        holder: CAROL,
        since: r.grant(&g3).since,
    });
    assert_eq!(r.act(CAROL, CAROL, carols, &p), Err(MetaError::NotWithin));
    r.act(CAROL, CAROL, carols, &projection_of(demanding))
        .unwrap();
}

// OP-143 m.7
#[test]
fn a_root_projection_stays_within_the_anchor_scope() {
    let mut r = Run::new();
    let anchor = ExerciseBasis::Anchor(shop_anchor());
    r.act(ROOT, ROOT, anchor, &projection(&["eu"], 0, 1_000))
        .unwrap();
    let mut bounds = authority(&["eu"], 0, 1_000);
    bounds.authority.resource = ResourceSelector::Structural(Structural {
        namespace: "bank".to_string(),
        prefix: alloc::vec!["eu".to_string()],
        kind: None,
        attrs: BTreeMap::new(),
    });
    assert_eq!(
        r.act(ROOT, ROOT, anchor, &projection_of(bounds)),
        Err(MetaError::NotWithin)
    );
}

// OP-143 m.7
#[test]
fn a_projection_stays_within_the_mandate() {
    let mut r = Run::new();
    let instance = alice_instance(
        &mut r,
        Some(envelope(&["eu"], BTreeSet::from([term(1)]), None)),
    );
    let h = held(&mut r, ALICE, &["eu"], 0);
    let basis = ExerciseBasis::Holding(h);
    assert_eq!(
        r.act(ALICE, instance, basis, &projection(&["eu"], 0, 1_000)),
        Err(MetaError::NotWithin)
    );
    let mut bounds = authority(&["eu"], 0, 1_000);
    bounds.requirements.insert(term(1));
    r.act(ALICE, instance, basis, &projection_of(bounds))
        .unwrap();
}

// OP-143 m.7
#[test]
fn a_projection_horizon_may_be_now() {
    let mut r = Run::new();
    let h = held(&mut r, ALICE, &["eu"], 0);
    let basis = ExerciseBasis::Holding(h);
    r.now = 1_000;
    r.act(ALICE, ALICE, basis, &projection(&["eu"], 0, 1_000))
        .unwrap();
    r.now = 1_001;
    assert_eq!(
        r.act(ALICE, ALICE, basis, &projection(&["eu"], 0, 1_000)),
        Err(MetaError::NotWithin)
    );
}

// OP-141 m.28 (d)
#[test]
fn actual_amount_grounds_agree() {
    let mut r = Run::new();
    let g = held(&mut r, ALICE, &["eu"], 0).grant;
    let spending = Digest([17; 32]);
    spent(&mut r.state, &g, &spending);
    r.state.apply(&[
        (
            key(kind::CLAIM, &Id([24; 16])),
            Some(bound_claim(
                ACTUAL_AMOUNT,
                Some(crate::model::EqValue::Int(30)),
                SPENT,
            )),
        ),
        (
            key(kind::CLAIM, &Id([25; 16])),
            Some(bound_claim(
                ACTUAL_AMOUNT,
                Some(crate::model::EqValue::Int(40)),
                SPENT,
            )),
        ),
    ]);
    let any = ExerciseBasis::Anchor(shop_anchor());
    assert_eq!(
        r.act(ALICE, ALICE, any, &release_of(spending, &[21, 25])),
        Err(MetaError::NotWithin)
    );
    let (_, out) = r
        .act(ALICE, ALICE, any, &release_of(spending, &[21, 24]))
        .unwrap();
    assert_eq!(out.releases, alloc::vec![(budget(&g, 1), 70)]);
}

// OP-141 m.28 (g)
#[test]
fn only_budget_keys_name_a_grant() {
    let g = Id([10; 16]);
    assert_eq!(budget_grant(&budget(&g, 0)), Some(g));
    assert_eq!(budget_grant(&released_key(&budget(&g, 0))), None);
}

// OP-141 m.27 (c)
#[test]
fn policies_of_a_target_are_indexed_together() {
    let mut r = Run::new();
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let policy = |source: &str| Payload::PolicySet {
        defaults: None,
        policy: None,
        content: map([
            ("schema", Some(Value::text(RESTRICTION_SCHEMA))),
            ("source", Some(Value::text(source))),
            ("target", Some(Value::text("domain"))),
        ]),
    };
    let (first, _) = r.act(ROOT, ROOT, meta, &policy("deny a")).unwrap();
    let (second, _) = r.act(ROOT, ROOT, meta, &policy("deny b")).unwrap();
    assert_eq!(
        index_of(&r.state, &policies_key(&Value::text("domain"))).unwrap(),
        BTreeSet::from([
            object_id(&first, kind::POLICY, 0),
            object_id(&second, kind::POLICY, 0)
        ])
    );
}

// SI-18, SEC8, OP-157 m.3 (b), (n)
#[test]
fn policy_defaults_tighten_at_ct1_and_loosen_as_expansion() {
    let mut r = Run::new();
    let meta = ExerciseBasis::Anchor(meta_anchor(&DOMAIN));
    let set = |defaults: PolicyDefaults| Payload::PolicySet {
        defaults: Some(defaults),
        policy: None,
        content: map([
            ("schema", Some(Value::text(RESTRICTION_SCHEMA))),
            ("source", Some(Value::text("deny a"))),
            ("target", Some(Value::text("domain"))),
        ]),
    };
    let mut step = |d: PolicyDefaults| {
        let (_, out) = r.act(ROOT, ROOT, meta, &set(d)).unwrap();
        out.expansion
    };
    let ct3 = |n| PolicyDefaults {
        ct3_delay_s: Some(n),
        ..PolicyDefaults::default()
    };
    assert!(!step(ct3(172_800)));
    assert!(step(ct3(3_600)), "a smaller ct3_delay_s loosens");
    let surfaces = |names: &[&str]| PolicyDefaults {
        approval_surfaces: Some(names.iter().map(|n| (*n).to_string()).collect()),
        ..PolicyDefaults::default()
    };
    assert!(!step(surfaces(&["suiss-approver-sdk"])));
    assert!(step(surfaces(&["suiss-approver-sdk", "vendor-surface"])));
    let support = |n| PolicyDefaults {
        support_max_min: Some(n),
        ..PolicyDefaults::default()
    };
    assert!(!step(support(60)));
    assert!(step(support(120)));
    let review = |n| PolicyDefaults {
        breakglass_review_h: Some(n),
        ..PolicyDefaults::default()
    };
    assert!(!step(review(24)));
    assert!(step(review(48)));
    let probation = |n| PolicyDefaults {
        mapping_probation_days: Some(n),
        ..PolicyDefaults::default()
    };
    assert!(!step(probation(30)));
    assert!(step(probation(7)));
    assert_eq!(
        crate::tier::meta_tier(&set(ct3(1)), true),
        crate::tier::Tier::Ct3
    );
}

// OP-157 m.3 (n), OP-108 m.4
#[test]
fn policy_defaults_name_only_known_keys() {
    let all = PolicyDefaults {
        ct3_delay_s: Some(86_400),
        mapping_probation_days: Some(14),
        approval_surfaces: Some(BTreeSet::from([
            "suiss-approval-surface".to_string(),
            "suiss-approver-sdk".to_string(),
        ])),
        breakglass_review_h: Some(72),
        support_max_min: Some(60),
    };
    assert_eq!(PolicyDefaults::from_value(&all.to_value()), Ok(all.clone()));
    let keys: Vec<String> = match all.to_value() {
        Value::Map(m) => m
            .iter()
            .filter_map(|(k, _)| match k {
                Value::Text(t) => Some(t.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    assert_eq!(keys, POLICY_DEFAULT_KEYS.map(String::from).to_vec());
    let unknown = map([("quorum", Some(Value::Unsigned(1)))]);
    assert_eq!(
        PolicyDefaults::from_value(&unknown),
        Err(ModelError::Unknown)
    );
    assert_eq!(
        PolicyDefaults::from_value(&Value::Map(Vec::new())),
        Err(ModelError::Range)
    );
}

// OP-157 m.3 (b), (r), C18
#[test]
fn only_a_schema_definition_acceptance_pins_mappings() {
    let pins = set_value([Digest([7; 32]).to_value()]);
    let mut c = acceptance(CAROL, "predicate-input", "kyc");
    c.push(("mappings", Some(pins)));
    assert_eq!(acceptance_content(&map(c)), Err(ModelError::Shape));
}

// OP-157 m.3 (b), OP-1
#[test]
fn kernel_0_4_0_meta_payloads_decode_unchanged() {
    extern crate std;
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../conformance/vectors/core/1/meta.json"
    ))
    .unwrap();
    let mut decoded = 0;
    for case in doc["cases"].as_array().unwrap() {
        let hex = case["payload"].as_str().unwrap();
        let bytes: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect();
        if let Ok(p) = Payload::from_bytes(&bytes) {
            assert_eq!(p.to_bytes().unwrap(), bytes, "{}", case["id"]);
            // OP-157 m.3 (n)
            if let Payload::PolicySet { defaults, .. } = &p {
                let added = case["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("policy-defaults-"));
                assert_eq!(defaults.is_some(), added, "{}", case["id"]);
            }
            decoded += 1;
        }
    }
    assert!(decoded >= 50, "{decoded}");
}
