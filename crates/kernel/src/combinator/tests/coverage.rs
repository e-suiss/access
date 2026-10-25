//! Conformance scenarios for L0 rules without an older vector, and the rules each case cites
//! (TI-RT12).

use super::*;
use crate::intent::ParamValue;
use crate::model::{
    BudgetDimension, BudgetTerm, Conjunct, EqValue, PurposeRef, ResourceRef, ResourceSelector,
    Structural,
};
use suiss_crypto::dcbor::{Limits, Value, decode, encode};

fn bounded(bound: &Bound, value: Option<ParamValue>) -> World {
    let mut w = World::new();
    for h in w.hops_mut() {
        h.authority
            .authority
            .params
            .insert("p".to_string(), bound.clone());
    }
    if let Some(v) = value {
        w.intent.params.insert("p".to_string(), v);
    }
    w
}

fn range(min: Option<i64>, max: Option<i64>) -> Bound {
    Bound::Range {
        min,
        max,
        unit: "eur".to_string(),
    }
}

fn amount(value: i64, unit: &str) -> ParamValue {
    ParamValue::Amount {
        value,
        unit: unit.to_string(),
    }
}

fn texts(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn rref(path: &[&str], incarnation: u64) -> ResourceRef {
    ResourceRef {
        namespace: "shop".to_string(),
        path: path.iter().map(|s| (*s).to_string()).collect(),
        incarnation,
    }
}

fn structural(namespace: &str, prefix: &[&str]) -> Structural {
    Structural {
        namespace: namespace.to_string(),
        prefix: prefix.iter().map(|s| (*s).to_string()).collect(),
        kind: None,
        attrs: BTreeMap::new(),
    }
}

fn code(s: &str) -> PurposeRef {
    PurposeRef::Code(s.to_string())
}

fn with_purposes(mut w: World) -> World {
    w.catalog
        .purposes
        .insert(code("care"), [code("treatment")].into_iter().collect());
    w
}

fn pred(n: usize) -> SubjectSelector {
    SubjectSelector::Pred(
        (0..n)
            .map(|i| Conjunct {
                claim_class: format!("c{i}"),
                value: None,
            })
            .collect(),
    )
}

fn bound_scenarios() -> Vec<(&'static str, World)> {
    let enumb = || Bound::Enum(texts(&["eur", "usd"]));
    let eq = |s: &str| ParamValue::Eq(EqValue::Text(s.to_string()));
    vec![
        (
            "allow-enum-member",
            bounded(&enumb(), Some(ParamValue::Enum("eur".to_string()))),
        ),
        (
            "deny-enum-not-member",
            bounded(&enumb(), Some(ParamValue::Enum("chf".to_string()))),
        ),
        (
            "allow-eq-equal",
            bounded(&Bound::Eq(EqValue::Text("x".to_string())), Some(eq("x"))),
        ),
        (
            "deny-eq-different",
            bounded(&Bound::Eq(EqValue::Text("x".to_string())), Some(eq("y"))),
        ),
        (
            "allow-flag-equal",
            bounded(&Bound::Flag(true), Some(ParamValue::Flag(true))),
        ),
        (
            "deny-flag-different",
            bounded(&Bound::Flag(true), Some(ParamValue::Flag(false))),
        ),
        (
            "allow-range-at-max",
            bounded(&range(Some(0), Some(100)), Some(amount(100, "eur"))),
        ),
        (
            "deny-range-above-max",
            bounded(&range(Some(0), Some(100)), Some(amount(101, "eur"))),
        ),
        (
            "deny-range-unit-differs",
            bounded(&range(Some(0), Some(100)), Some(amount(50, "usd"))),
        ),
        (
            "allow-range-missing-min",
            bounded(&range(None, Some(100)), Some(amount(-5, "eur"))),
        ),
        (
            "allow-count-at-max",
            bounded(&Bound::CountMax(3), Some(ParamValue::Count(3))),
        ),
        (
            "deny-count-above-max",
            bounded(&Bound::CountMax(3), Some(ParamValue::Count(4))),
        ),
    ]
}

fn structured_bound_scenarios() -> Vec<(&'static str, World)> {
    let window = |from, until| Window { from, until };
    let resource = || Bound::Resource(ResourceSelector::Structural(structural("shop", &["a"])));
    vec![
        (
            "allow-interval-at-edges",
            bounded(
                &Bound::Interval(window(10, 20)),
                Some(ParamValue::Interval(window(10, 20))),
            ),
        ),
        (
            "deny-interval-outside",
            bounded(
                &Bound::Interval(window(10, 20)),
                Some(ParamValue::Interval(window(9, 20))),
            ),
        ),
        (
            "allow-resource-bound-prefix",
            bounded(
                &resource(),
                Some(ParamValue::Resource(rref(&["a", "b"], 0))),
            ),
        ),
        (
            "deny-resource-bound-partial-segment",
            bounded(&resource(), Some(ParamValue::Resource(rref(&["ab"], 0)))),
        ),
        (
            "allow-subject-bound-party",
            bounded(
                &Bound::Subject(SubjectSelector::Party(party(5))),
                Some(ParamValue::Subject(party(5))),
            ),
        ),
        (
            "deny-subject-bound-other-party",
            bounded(
                &Bound::Subject(SubjectSelector::Party(party(5))),
                Some(ParamValue::Subject(party(6))),
            ),
        ),
        (
            "allow-purpose-bound-declared-below",
            with_purposes(bounded(
                &Bound::Purpose([code("care")].into_iter().collect()),
                Some(ParamValue::Purpose(code("treatment"))),
            )),
        ),
        (
            "deny-purpose-bound-not-below",
            with_purposes(bounded(
                &Bound::Purpose([code("care")].into_iter().collect()),
                Some(ParamValue::Purpose(code("billing"))),
            )),
        ),
        (
            "deny-param-missing-in-intent",
            bounded(&Bound::Enum(texts(&["eur"])), None),
        ),
        (
            "deny-bound-type-mismatch",
            bounded(&range(Some(0), Some(100)), Some(ParamValue::Count(1))),
        ),
        ("allow-unbounded-param", {
            let mut w = World::new();
            w.intent
                .params
                .insert("p".to_string(), ParamValue::Count(9));
            w
        }),
    ]
}

fn dimension_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let purpose = |intent: Option<PurposeRef>| {
        let mut w = with_purposes(World::new());
        for h in w.hops_mut() {
            h.authority.authority.purpose = Some([code("care")].into_iter().collect());
        }
        w.intent.purpose = intent;
        w
    };
    out.push((
        "allow-purpose-declared-below",
        purpose(Some(code("treatment"))),
    ));
    out.push(("deny-purpose-missing-in-intent", purpose(None)));
    let resource = |sel: ResourceSelector| {
        let mut w = World::new();
        for h in w.hops_mut() {
            h.authority.authority.resource = sel.clone();
        }
        w
    };
    out.push((
        "allow-resource-exact",
        resource(ResourceSelector::Exact(rref(&["o1"], 0))),
    ));
    out.push((
        "deny-resource-exact-other-incarnation",
        resource(ResourceSelector::Exact(rref(&["o1"], 1))),
    ));
    let mut typed = structural("shop", &[]);
    typed.kind = Some("order".to_string());
    out.push((
        "deny-resource-structural-typed",
        resource(ResourceSelector::Structural(typed)),
    ));
    out.push((
        "deny-resource-other-namespace",
        resource(ResourceSelector::Structural(structural("shop2", &[]))),
    ));
    let mut w = resource(ResourceSelector::Structural(structural("shop", &["o1"])));
    w.intent.resources.push(rref(&["o2"], 0));
    out.push(("deny-one-resource-outside", w));
    let mut w = pinned_catalog(21);
    w.catalog.reserved.insert(action());
    out.push(("deny-prefix-reserved-action", w));
    let mut w = World::new();
    w.catalog.reserved.insert(action());
    out.push(("allow-exact-reserved-action", w));
    out.push(("deny-prefix-unknown-catalog", pinned_catalog(77)));
    let sub = |ns: &str| {
        let mut w = World::new();
        let a = ActionRef {
            namespace: ns.to_string(),
            ..action()
        };
        w.catalog
            .catalogs
            .insert(d(22), [a.clone()].into_iter().collect());
        w.intent.action = a;
        for h in w.hops_mut() {
            h.authority.authority.actions = ActionSet {
                exact: BTreeSet::new(),
                prefix: [("pay".to_string(), d(22))].into_iter().collect(),
            };
        }
        w
    };
    out.push(("allow-prefix-sub-namespace", sub("pay.eu")));
    out.push(("deny-prefix-namespace-without-dot", sub("payx")));
    out
}

fn input_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.hop(0).authority.constraints.validity.until = 50_000;
    out.push(("allow-hop-valid-until-edge", w));
    let mut w = World::new();
    w.hop(1).authority.constraints.validity.from = 50_000;
    out.push(("allow-hop-valid-from-edge", w));
    let mut w = World::new();
    w.intent.validity.until = 50_000;
    out.push(("allow-intent-validity-edge", w));
    let mut w = World::new();
    w.catalog
        .purposes
        .insert(code("a"), [code("b")].into_iter().collect());
    w.catalog
        .purposes
        .insert(code("b"), [code("a")].into_iter().collect());
    out.push(("reject-purpose-cycle", w));
    for (id, n) in [
        ("deny-selector-32-conditions", 32),
        ("reject-selector-33-conditions", 33),
    ] {
        let mut w = World::new();
        w.hop(0).authority.authority.recipient = Some(pred(n));
        w.intent.recipient = Some(party(5));
        out.push((id, w));
    }
    let mut w = World::new();
    let mut s = structural("shop", &[]);
    s.attrs = (0..33)
        .map(|i| (format!("k{i}"), EqValue::Int(i)))
        .collect();
    w.hop(0).authority.authority.resource = ResourceSelector::Structural(s);
    out.push(("reject-where-33-conditions", w));
    let mut w = World::new();
    w.bases = vec![basis(vec![hop(); MAX_LINEAGE])];
    out.push(("allow-basis-16-hops", w));
    let mut w = World::new();
    w.bases = vec![basis(vec![hop(); MAX_LINEAGE + 1])];
    out.push(("reject-basis-17-hops", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    w.bases = vec![basis(vec![hop()]), basis(vec![hop(); MAX_LINEAGE + 1])];
    out.push(("reject-check-17-hops-later-candidate", w));
    let mut w = World::new();
    w.restrictions.push(PolicyResult {
        policy: party(7),
        version: d(2),
        outcome: RestrictionOutcome::Deny(PolicyDeny {
            policy: party(8),
            version: d(2),
            undisclosed: false,
        }),
    });
    out.push(("reject-restriction-deny-other-policy", w));
    let mut w = World::new();
    w.restrictions.push(PolicyResult {
        policy: party(7),
        version: d(2),
        outcome: RestrictionOutcome::NoObjection,
    });
    out.push(("allow-restriction-no-objection", w));
    out
}

fn hop_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let mut w = World::new();
    w.mandate = Some(Mandate {
        authority: authority(),
        requirements: [approval(false)].into_iter().collect(),
    });
    out.push(("require-from-mandate", w));
    let mut w = World::new();
    w.bases[0].capacities.insert(Capacity::For(party(5)));
    w.capacity = Capacity::For(party(5));
    out.push(("allow-capacity-for-party", w));
    let mut w = World::new();
    w.hop(1).status = HopStatus::Lapsed;
    out.push(("deny-status-lapsed", w));
    let mut w = World::new();
    w.hop(0).budgets.push(BudgetState {
        window: BudgetWindow::Total,
        remaining: 3,
        demand: 3,
        resets_at: None,
    });
    out.push(("allow-budget-demand-equals-remaining", w));
    let mut w = World::new();
    w.mode = Mode::Check;
    w.bases = vec![basis(vec![hop()]), basis(vec![hop()])];
    w.restrictions.push(deny_policy(7, false));
    out.push(("check-restriction-applies-to-every-candidate", w));
    out
}

fn proved(term: RequirementTerm, proofs: Vec<Proof>) -> World {
    let mut w = World::new();
    w.hop(0).authority.requirements.insert(term);
    w.proofs = proofs;
    w
}

fn proof(id: u8, position: u64, party_n: u8) -> Proof {
    Proof {
        id: Id([id; 16]),
        position,
        party: party(party_n),
        ..step_up_proof()
    }
}

fn proof_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let mut p = step_up_proof();
    p.class = "other".to_string();
    out.push((
        "require-proof-class-mismatch",
        proved(approval(false), vec![p]),
    ));
    let mut p = step_up_proof();
    p.kind = ProofKind::Claim;
    out.push((
        "require-proof-kind-mismatch",
        proved(approval(false), vec![p]),
    ));
    let mut p = step_up_proof();
    p.consumed = true;
    out.push((
        "require-consumed-proof-single-use-term",
        proved(approval(false), vec![p.clone()]),
    ));
    let mut reusable = approval(false);
    reusable.consumption = Consumption::Reusable;
    out.push((
        "allow-consumed-proof-reusable-term",
        proved(reusable.clone(), vec![p]),
    ));
    let bind = |b: Binding, pb: ProofBinding| {
        let mut t = approval(false);
        t.binding = b;
        let mut p = step_up_proof();
        p.binding = pb;
        proved(t, vec![p])
    };
    out.push((
        "allow-binding-actor-instance",
        bind(
            Binding::ActorInstance,
            ProofBinding {
                actor_instance: Some(Id([1; 16])),
                ..ProofBinding::default()
            },
        ),
    ));
    out.push((
        "require-binding-actor-instance-other",
        bind(
            Binding::ActorInstance,
            ProofBinding {
                actor_instance: Some(Id([2; 16])),
                ..ProofBinding::default()
            },
        ),
    ));
    out.push((
        "allow-binding-resource",
        bind(
            Binding::Resource,
            ProofBinding {
                resource: Some(rref(&["o1"], 0)),
                ..ProofBinding::default()
            },
        ),
    ));
    out.push((
        "require-binding-resource-other",
        bind(
            Binding::Resource,
            ProofBinding {
                resource: Some(rref(&["o2"], 0)),
                ..ProofBinding::default()
            },
        ),
    ));
    out.push((
        "require-binding-intent-other",
        bind(
            Binding::IntentDigest,
            ProofBinding {
                intent_digest: Some(d(2)),
                ..ProofBinding::default()
            },
        ),
    ));
    out.push((
        "allow-binding-none",
        bind(Binding::None, ProofBinding::default()),
    ));
    for (id, freshness) in [
        ("allow-freshness-edge", 49_999),
        ("require-freshness-stale", 49_998),
    ] {
        let mut t = approval(false);
        t.freshness_ms = Some(freshness);
        out.push((id, proved(t, vec![step_up_proof()])));
    }
    let mut src = approval(false);
    src.source = Some(SubjectSelector::Party(Id([1; 16])));
    out.push(("allow-source-accepted", proved(src, vec![step_up_proof()])));
    out.extend(count_scenarios(reusable));
    out
}

fn count_scenarios(reusable: RequirementTerm) -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    let mut two = approval(false);
    two.count = 2;
    two.independence = Independence::DistinctParty;
    out.push((
        "require-count-two-one-proof",
        proved(two.clone(), vec![proof(3, 1, 1)]),
    ));
    out.push((
        "allow-count-two-distinct-parties",
        proved(two.clone(), vec![proof(3, 1, 1), proof(4, 2, 2)]),
    ));
    out.push((
        "require-count-two-same-party",
        proved(two, vec![proof(3, 1, 1), proof(4, 2, 1)]),
    ));
    out.push((
        "allow-chooses-earliest-position",
        proved(approval(false), vec![proof(3, 2, 1), proof(4, 1, 1)]),
    ));
    out.push((
        "allow-chooses-smaller-id-on-tie",
        proved(approval(false), vec![proof(4, 1, 1), proof(3, 1, 1)]),
    ));
    let mut second = reusable.clone();
    second.freshness_ms = Some(100_000);
    let mut w = proved(reusable, vec![step_up_proof()]);
    w.hop(0).authority.requirements.insert(second);
    out.push(("allow-reusable-proof-serves-two-terms", w));
    out
}

fn fuel_scenarios() -> Vec<(&'static str, World)> {
    let mut out = Vec::new();
    for (id, fuel) in [("allow-fuel-exact", 3), ("reject-fuel-short", 2)] {
        let mut w = World::new();
        w.hop(1).authority.requirements.insert(approval(true));
        w.proofs.push(step_up_proof());
        w.fuel = fuel;
        out.push((id, w));
    }
    for (id, fuel) in [
        ("check-fuel-exact-recharges-restrictions", 4),
        ("reject-check-fuel-short", 3),
    ] {
        let mut w = World::new();
        w.mode = Mode::Check;
        let mut revoked = hop();
        revoked.status = HopStatus::Revoked;
        w.bases = vec![basis(vec![revoked]), basis(vec![hop()])];
        w.restrictions.push(PolicyResult {
            policy: party(7),
            version: d(2),
            outcome: RestrictionOutcome::NoObjection,
        });
        w.fuel = fuel;
        out.push((id, w));
    }
    out
}

/// Decision scenarios added for rule coverage.
pub(super) fn scenarios() -> Vec<(&'static str, World)> {
    let mut out = bound_scenarios();
    out.extend(structured_bound_scenarios());
    out.extend(dimension_scenarios());
    out.extend(input_scenarios());
    out.extend(hop_scenarios());
    out.extend(proof_scenarios());
    out.extend(fuel_scenarios());
    out
}

fn with_field(input: &[u8], key: &str, value: Value) -> Vec<u8> {
    let Ok(Value::Map(mut entries)) = decode(input, Limits::CEILING) else {
        panic!("evaluation input is a map")
    };
    entries.retain(|(k, _)| *k != Value::text(key));
    entries.push((Value::text(key), value));
    entries.sort_by_key(|(k, _)| encode(k, Limits::CEILING).unwrap());
    encode(&Value::Map(entries), Limits::CEILING).unwrap()
}

/// Inputs no `World` can express: an unknown field and an unknown choice (L0-ENC-9).
pub(super) fn raw_inputs() -> Vec<(&'static str, Vec<u8>)> {
    use crate::codec::Canonical as _;
    let base = World::new().owned().to_bytes().unwrap();
    vec![
        (
            "reject-unknown-field",
            with_field(&base, "zzz", Value::Bool(true)),
        ),
        (
            "reject-unknown-mode",
            with_field(&base, "mode", Value::text("simulate")),
        ),
    ]
}

/// Delegation cases added for rule coverage.
pub(super) fn delegate_cases() -> Vec<(&'static str, Cve)> {
    let case = |child, parent, holder: SubjectSelector, within| Cve::Delegate {
        child,
        parent,
        holder,
        within,
    };
    let p2 = || SubjectSelector::Party(party(2));
    let mut out = Vec::new();
    out.push((
        "delegate-from-leaf-parent",
        case(leaf(), leaf(), p2(), false),
    ));
    out.push((
        "delegate-same-depth",
        case(hop().authority, hop().authority, p2(), false),
    ));
    let mut classed = hop().authority;
    classed.delegation.downstream_holder_class = Some(p2());
    let mut child = leaf();
    child.delegation.downstream_holder_class = Some(p2());
    out.push((
        "delegate-holder-within-class",
        case(child.clone(), classed.clone(), p2(), true),
    ));
    out.push((
        "delegate-holder-outside-class",
        case(
            child,
            classed.clone(),
            SubjectSelector::Party(party(3)),
            false,
        ),
    ));
    out.push((
        "delegate-child-drops-holder-class",
        case(leaf(), classed, p2(), false),
    ));
    let mut wide = leaf();
    wide.constraints.validity.until = 100_001;
    out.push((
        "delegate-validity-outside-parent",
        case(wide, hop().authority, p2(), false),
    ));
    let mut strict = hop().authority;
    strict.requirements.insert(approval(false));
    let mut kept = leaf();
    kept.requirements.insert(approval(false));
    out.push((
        "delegate-keeps-requirement",
        case(kept.clone(), strict.clone(), p2(), true),
    ));
    kept.requirements.insert(approval(true));
    out.push((
        "delegate-adds-requirement",
        case(kept, strict.clone(), p2(), true),
    ));
    out.push((
        "delegate-drops-requirement",
        case(leaf(), strict, p2(), false),
    ));
    let mut budget = leaf();
    budget.constraints.budget.insert(BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 1_000,
        window: BudgetWindow::Total,
    });
    let mut small = hop().authority;
    small.constraints.budget.insert(BudgetTerm {
        dimension: BudgetDimension::Count,
        capacity: 1,
        window: BudgetWindow::Total,
    });
    out.push((
        "delegate-budget-not-compared",
        case(budget, small, p2(), true),
    ));
    out.extend(delegate_bound_cases());
    out
}

fn delegate_bound_cases() -> Vec<(&'static str, Cve)> {
    let p2 = || SubjectSelector::Party(party(2));
    let with = |depth: u64, bound: Option<Bound>| {
        let mut c = hop().authority;
        c.delegation.depth = depth;
        if let Some(b) = bound {
            c.authority.params.insert("p".to_string(), b);
        }
        c
    };
    let case = |child, parent, within| Cve::Delegate {
        child,
        parent,
        holder: p2(),
        within,
    };
    let ab = || Some(Bound::Enum(texts(&["a", "b"])));
    let mut out = vec![(
        "delegate-drops-param-bound",
        case(with(0, None), with(1, ab()), false),
    )];
    out.push((
        "delegate-narrows-param-bound",
        case(
            with(0, Some(Bound::Enum(texts(&["a"])))),
            with(1, ab()),
            true,
        ),
    ));
    out.push((
        "delegate-range-missing-min",
        case(
            with(0, Some(range(None, Some(50)))),
            with(1, Some(range(Some(0), Some(100)))),
            false,
        ),
    ));
    out.push((
        "delegate-pred-subject-more-conjuncts",
        case(
            with(0, Some(Bound::Subject(pred(2)))),
            with(1, Some(Bound::Subject(pred(1)))),
            true,
        ),
    ));
    let mut parent = hop().authority;
    parent.authority.recipient = Some(SubjectSelector::Party(party(5)));
    out.push(("delegate-drops-recipient", case(leaf(), parent, false)));
    let mut narrow = leaf();
    narrow.authority.resource = ResourceSelector::Structural(structural("shop", &["a"]));
    out.push((
        "delegate-narrower-resource-prefix",
        case(narrow, hop().authority, true),
    ));
    let mut other = leaf();
    other.authority.resource = ResourceSelector::Structural(structural("shop2", &[]));
    out.push((
        "delegate-other-resource-namespace",
        case(other, hop().authority, false),
    ));
    let mut bottom = leaf();
    bottom.authority.actions.exact.clear();
    out.push((
        "delegate-bottom-actions",
        case(bottom, hop().authority, true),
    ));
    out
}

/// L0/L2 rules each decision case cites.
pub(super) fn decision_rules(id: &str) -> &'static [&'static str] {
    if let Some(r) = assurance_rules(id) {
        return r;
    }
    match id {
        "allow" => &[
            "L0-ALG-2",
            "L0-ALG-33",
            "L0-ALG-41",
            "L0-EVAL-10",
            "L0-EVAL-12",
            "L0-EVAL-33",
            "L0-EVAL-34",
        ],
        "deny-no-covering-authority-hop1" => &[
            "L0-ALG-1",
            "L0-ALG-6",
            "L0-ALG-52",
            "L0-EVAL-12",
            "L0-EVAL-40",
        ],
        "deny-outside-instance-limits" => &["L0-EVAL-16", "L0-EVAL-40"],
        "deny-restricted" => &["L0-ENC-16", "L0-EVAL-18", "L0-EVAL-40"],
        "deny-budget-rolling" | "deny-budget-total" => &["L0-EVAL-4", "L0-EVAL-15", "L0-EVAL-40"],
        "deny-expired" | "deny-not-yet-valid" => &["L0-ALG-55", "L0-EVAL-13", "L0-EVAL-40"],
        "deny-revoked" | "deny-status-lapsed" => &["L0-EVAL-14", "L0-EVAL-40"],
        "deny-lapsed" => &["L0-EVAL-4", "L0-EVAL-14", "L0-EVAL-40"],
        "deny-capacity-mismatch" => &["L0-EVAL-17", "L0-EVAL-40"],
        "require-step-up" => &[
            "L0-ALG-59",
            "L0-EVAL-19",
            "L0-EVAL-20",
            "L0-EVAL-29",
            "L0-EVAL-33",
        ],
        "require-human-presence-agent" | "require-human-presence-zero-agent" => &["L0-EVAL-30"],
        "allow-with-proof" => &[
            "L0-ALG-59",
            "L0-EVAL-4a",
            "L0-EVAL-22",
            "L0-EVAL-23",
            "L0-EVAL-27",
        ],
        "deny-overrides-require" => &["L0-EVAL-33"],
        "require-from-restriction" => &["L0-EVAL-18", "L0-EVAL-20"],
        "deny-source-not-accepted" => &["L0-EVAL-31", "L0-EVAL-40"],
        "check-no-basis" | "check-no-basis-only-no-covering" => &["L0-EVAL-35a"],
        "check-first-require" => &["L0-EVAL-29", "L0-EVAL-35"],
        "reject-commit-two-bases" => &["L0-EVAL-34", "L0-EVAL-60", "L0-EVAL-61"],
        "deny-four-blocker-classes" => &["L0-ENC-6", "L0-EVAL-33", "L0-EVAL-41"],
        "allow-inherited-term-counts-once" | "require-inherited-term-at-first-hop" => {
            &["L0-EVAL-21"]
        }
        "check-deny-merges-blockers-only" => &["L0-EVAL-36"],
        "reject-rolling-budget-without-reset" | "reject-check-bad-later-candidate" => {
            &["L0-EVAL-15a", "L0-EVAL-60"]
        }
        "require-future-dated-proof" => &["L0-EVAL-24"],
        "reject-duplicate-proof-id" => &["L0-EVAL-3", "L0-EVAL-60"],
        "reject-inverted-hop-window" => &["L0-ALG-11", "L0-EVAL-60"],
        "deny-schema-digest-mismatch" => &["L0-ALG-30", "L0-EVAL-11"],
        "reject-intent-expired" | "reject-intent-not-yet-valid" => &["L0-EVAL-5", "L0-EVAL-60"],
        "allow-intent-validity-edge" => &["L0-EVAL-5"],
        "deny-not-understood-hop1-commit"
        | "deny-not-understood-hop0-continue"
        | "deny-not-understood-keeps-unmet" => {
            &["L0-ALG-4", "L0-ALG-4a", "L0-EVAL-12a", "L0-GEN-8"]
        }
        "check-not-understood-then-allow" | "check-not-understood-only" => {
            &["L0-EVAL-12a", "L0-EVAL-35"]
        }
        "require-shared-single-use-proof-canonical-order" => &["L0-EVAL-21", "L0-EVAL-28"],
        "allow-public-recipient-with-recipient"
        | "allow-public-recipient-without-recipient"
        | "allow-public-subject-bound-with-value"
        | "allow-public-subject-bound-without-value" => &["L0-ALG-45", "L0-EVAL-10"],
        _ => coverage_rules(id),
    }
}

fn assurance_rules(id: &str) -> Option<&'static [&'static str]> {
    if id == "reject-assurance-auth-time-is-not-a-dimension" {
        return Some(&["L0-ALG-60a", "L0-ALG-60b", "L0-EVAL-3", "L0-EVAL-60"]);
    }
    if id.starts_with("reject-assurance-") {
        return Some(&["L0-ALG-60a", "L0-EVAL-3", "L0-EVAL-60"]);
    }
    (id.starts_with("allow-assurance-") || id.starts_with("require-assurance-"))
        .then_some(&["L0-ALG-60", "L0-EVAL-25"][..])
}

fn coverage_rules(id: &str) -> &'static [&'static str] {
    match id {
        "allow-enum-member"
        | "deny-enum-not-member"
        | "allow-eq-equal"
        | "deny-eq-different"
        | "allow-flag-equal"
        | "deny-flag-different"
        | "allow-count-at-max"
        | "deny-count-above-max" => &["L0-ALG-10", "L0-ALG-13", "L0-EVAL-10"],
        "allow-range-at-max"
        | "deny-range-above-max"
        | "deny-range-unit-differs"
        | "allow-range-missing-min" => &["L0-ALG-10", "L0-ALG-12", "L0-ALG-13", "L0-EVAL-10"],
        "allow-interval-at-edges" | "deny-interval-outside" => {
            &["L0-ALG-10", "L0-ALG-11", "L0-ALG-13"]
        }
        "allow-resource-bound-prefix" | "deny-resource-bound-partial-segment" => {
            &["L0-ALG-13", "L0-ALG-41"]
        }
        "allow-subject-bound-party" | "deny-subject-bound-other-party" => {
            &["L0-ALG-13", "L0-ALG-45"]
        }
        "allow-purpose-bound-declared-below" | "deny-purpose-bound-not-below" => {
            &["L0-ALG-13", "L0-ALG-47", "L0-ALG-48"]
        }
        "deny-bound-type-mismatch" => &["L0-ALG-3", "L0-ALG-13"],
        "allow-unbounded-param" => &["L0-ALG-2", "L0-EVAL-10"],
        "allow-purpose-declared-below" | "deny-purpose-missing-in-intent" => {
            &["L0-ALG-47", "L0-EVAL-10"]
        }
        "allow-resource-exact" | "deny-resource-exact-other-incarnation" => {
            &["L0-ALG-40", "L0-ALG-41"]
        }
        "deny-resource-structural-typed" | "deny-resource-other-namespace" => &["L0-ALG-41"],
        "deny-param-missing-in-intent" | "deny-one-resource-outside" => &["L0-EVAL-10"],
        "deny-prefix-reserved-action" | "allow-exact-reserved-action" => {
            &["L0-ALG-31", "L0-ALG-33", "L0-ALG-34"]
        }
        "deny-prefix-unknown-catalog" => &["L0-ALG-32"],
        "allow-prefix-sub-namespace" | "deny-prefix-namespace-without-dot" => &["L0-ALG-31"],
        "allow-hop-valid-until-edge" | "allow-hop-valid-from-edge" => &["L0-ALG-11", "L0-EVAL-13"],
        "reject-purpose-cycle" => &["L0-ALG-47", "L0-EVAL-3", "L0-EVAL-60"],
        "deny-selector-32-conditions"
        | "reject-selector-33-conditions"
        | "reject-where-33-conditions" => &["L0-ENC-10", "L0-ENC-13", "L0-EVAL-60"],
        "allow-basis-16-hops" => &["L0-ENC-10"],
        "reject-basis-17-hops" | "reject-check-17-hops-later-candidate" => {
            &["L0-ENC-10", "L0-ENC-12", "L0-EVAL-60"]
        }
        "reject-restriction-deny-other-policy" => &["L0-EVAL-18", "L0-EVAL-60"],
        "allow-restriction-no-objection" => &["L0-EVAL-18"],
        "require-from-mandate" => &["L0-EVAL-16", "L0-EVAL-20"],
        "allow-capacity-for-party" => &["L0-EVAL-17"],
        "allow-budget-demand-equals-remaining" => &["L0-EVAL-15"],
        "check-restriction-applies-to-every-candidate" => &["L0-EVAL-37"],
        "require-proof-class-mismatch"
        | "require-proof-kind-mismatch"
        | "allow-source-accepted" => &["L0-EVAL-22"],
        "require-consumed-proof-single-use-term" | "allow-consumed-proof-reusable-term" => {
            &["L0-EVAL-22", "L0-EVAL-28"]
        }
        "allow-binding-actor-instance"
        | "require-binding-actor-instance-other"
        | "allow-binding-resource"
        | "require-binding-resource-other"
        | "require-binding-intent-other"
        | "allow-binding-none" => &["L0-ALG-59", "L0-EVAL-23"],
        "allow-freshness-edge" | "require-freshness-stale" => &["L0-ALG-60b", "L0-EVAL-24"],
        "require-count-two-one-proof" | "require-count-two-same-party" => {
            &["L0-EVAL-26", "L0-EVAL-29"]
        }
        "allow-count-two-distinct-parties" => &["L0-EVAL-26"],
        "allow-chooses-earliest-position" | "allow-chooses-smaller-id-on-tie" => &["L0-EVAL-27"],
        "allow-reusable-proof-serves-two-terms" => &["L0-EVAL-28"],
        "allow-fuel-exact"
        | "reject-fuel-short"
        | "check-fuel-exact-recharges-restrictions"
        | "reject-check-fuel-short" => &["L0-EVAL-45", "L0-EVAL-46"],
        "reject-unknown-field" | "reject-unknown-mode" => {
            &["L0-ALG-4", "L0-ENC-9", "L0-EVAL-3", "L0-EVAL-60"]
        }
        _ => &[],
    }
}

/// L0 rules each CVE-regression or delegation case cites.
pub(super) fn cve_rules(id: &str) -> &'static [&'static str] {
    match id {
        "delegate-to-party" => &["L0-ALG-70", "L0-ALG-71", "L0-ALG-73"],
        "delegate-to-public-leaf"
        | "delegate-onward-to-public"
        | "delegate-public-holder-class" => &["L0-ALG-75"],
        "delegate-keeps-condition" | "delegate-drops-condition" => &["L0-ALG-56", "L0-ALG-72"],
        "recipient-party-same" | "recipient-pred-not-party" | "recipient-foreign-not-party" => {
            &["L0-ALG-45", "L0-EVAL-10"]
        }
        "recipient-party-other" => &["L0-ALG-45", "L0-EVAL-10", "L0-EVAL-12"],
        "exclusion-over-covering-grant" => &["L0-ALG-7", "L0-EVAL-18", "L0-EVAL-33"],
        "two-exclusions" | "two-exclusions-reordered" => &["L0-ENC-6", "L0-EVAL-18", "L0-EVAL-41"],
        "expired-invitation" => &["L0-EVAL-13"],
        "invitation-reused" => &["L0-EVAL-15"],
        "prefix-current-catalog" => &["L0-ALG-31", "L0-ALG-33"],
        "prefix-old-catalog" => &["L0-ALG-31", "L0-EVAL-12"],
        "impersonate-admin" => &["L0-EVAL-17"],
        "delegate-child-prefix-unknown-catalog" => &["L0-ALG-32"],
        "delegate-above-own-authority" => &["L0-ALG-33", "L0-ALG-50", "L0-ALG-71"],
        "delegate-from-leaf-parent" | "delegate-same-depth" => &["L0-ALG-58", "L0-ALG-73"],
        "delegate-holder-within-class"
        | "delegate-holder-outside-class"
        | "delegate-child-drops-holder-class" => &["L0-ALG-74"],
        "delegate-validity-outside-parent" => &["L0-ALG-11", "L0-ALG-72"],
        "delegate-keeps-requirement"
        | "delegate-adds-requirement"
        | "delegate-drops-requirement" => &["L0-ALG-61", "L0-ALG-76"],
        "delegate-budget-not-compared" => &["L0-ALG-57", "L0-ALG-77"],
        "delegate-drops-param-bound" | "delegate-narrows-param-bound" => {
            &["L0-ALG-10", "L0-ALG-50"]
        }
        "delegate-range-missing-min" => &["L0-ALG-12", "L0-ALG-50"],
        "delegate-pred-subject-more-conjuncts" => &["L0-ALG-45", "L0-ALG-50"],
        "delegate-drops-recipient" => &["L0-ALG-50"],
        "delegate-narrower-resource-prefix" | "delegate-other-resource-namespace" => {
            &["L0-ALG-41", "L0-ALG-50"]
        }
        "delegate-bottom-actions" => &["L0-ALG-1", "L0-ALG-33"],
        _ => &[],
    }
}
