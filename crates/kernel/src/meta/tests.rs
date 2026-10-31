use alloc::string::ToString;

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
    catalog: Catalog,
}

impl Run {
    fn new() -> Self {
        Self {
            state: genesis(),
            pos: 1,
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
    Payload::GrantIssue(GrantContent {
        basis,
        holder: SubjectSelector::Party(holder),
        authority: authority(prefix, depth, 1_000),
        agency: BTreeSet::from([Capacity::Own]),
        named: None,
    })
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

// E6, §7.9.2.3, OP-141 m.2, m.4: a Party registers itself with its self-anchor, then creates its
// own Instance; neither can be done for someone else
#[test]
fn register_then_create_own_instance() {
    let mut r = Run::new();
    let public = ExerciseBasis::Public(Id([9; 16]));
    let register = Payload::PartyRegister {
        party: ALICE,
        root: Root::Sole(ALICE),
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

// OP-141 m.20 (e): a group has one membership issuer
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

struct Recorder {
    run: Run,
    cases: Vec<String>,
}

fn cbor(v: &Value) -> String {
    crate::vector_rules::hex(&dcbor::encode(v, Limits::CEILING).unwrap())
}

impl Recorder {
    fn step(
        &mut self,
        id: &str,
        rules: &[&str],
        actor: (Id, Id),
        basis: ExerciseBasis,
        payload: &Payload,
    ) -> Option<Digest> {
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
        let head = format!(
            "{{\"id\": \"{id}\", {}, \"state\": [{}], \"domain_id\": \"{}\", \"exercise\": \"{}\", \"pos\": {}, \"party\": \"{}\", \"instance\": \"{}\", \"basis\": \"{}\", \"capacity\": \"{}\", \"payload\": \"{}\"",
            field(rules),
            state.join(", "),
            hex(&DOMAIN.0),
            hex(&exercise.0),
            self.run.pos,
            hex(&actor.0.0),
            hex(&actor.1.0),
            cbor(&basis_value(&basis)),
            cbor(&capacity_value(Capacity::Own)),
            cbor(&payload.to_value()),
        );
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
    r.step(
        "second-membership-issuer",
        &["L0-META-27", "L0-META-31"],
        (ROOT, ROOT),
        meta,
        &Payload::AcceptanceEstablish(acceptance(BOB, "subject-selection", &["staff"], 100)),
    );
    r.step(
        "claim-issued",
        &["L0-META-27"],
        (ROOT, ROOT),
        meta,
        &Payload::ClaimIssue {
            subject: ALICE,
            class: String::from("staff"),
            value: crate::model::EqValue::Bool(true),
            validity: None,
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
