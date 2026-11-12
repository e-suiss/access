//! Random algebra cases with the Kernel's answers, for the Lean model (OP-159 m.3 (v), CR-49 m.1).

#![cfg(not(any(target_family = "wasm", target_os = "android")))]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    missing_docs,
    reason = "test code"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

use access_kernel::algebra::{Catalog, child_within_parent, meet, normalize, subsumes};
use access_kernel::codec::Canonical;
use access_kernel::digest::Digest;
use access_kernel::model::{
    ActionRef, ActionSet, AuthoritySet, Bound, CanonicalAuthority, Conjunct, ConstraintSet,
    Consumption, DelegationTerms, EqValue, Id, Independence, ProofKind, PurposeRef,
    RequirementTerm, ResourceRef, ResourceSelector, Structural, SubjectSelector, WhileCondition,
    Window,
};
use suiss_crypto::dcbor::{Limits, Value, encode};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

fn s(x: &str) -> String {
    x.to_string()
}

fn d(label: &str) -> Digest {
    Digest(suiss_crypto::digest::sha256(label.as_bytes()))
}

fn id(n: u8) -> Id {
    Id(suiss_crypto::digest::sha256(&[n])[..16].try_into().unwrap())
}

fn action(ns: &str, name: &str) -> ActionRef {
    ActionRef {
        namespace: s(ns),
        name: s(name),
        major: 1,
        schema: d("schema"),
    }
}

const ACTIONS: [(&str, &str); 5] = [
    ("pay", "refund"),
    ("pay", "charge"),
    ("pay.admin", "close"),
    ("payroll", "run"),
    ("shop", "read"),
];

fn catalog() -> Catalog {
    let mut c = Catalog::default();
    c.catalogs.insert(
        d("catalog-1"),
        ACTIONS[..4].iter().map(|(n, a)| action(n, a)).collect(),
    );
    c.catalogs.insert(
        d("catalog-2"),
        [action("pay", "refund"), action("shop", "read")]
            .into_iter()
            .collect(),
    );
    c.reserved.insert(action("pay.admin", "close"));
    let code = |x: &str| PurposeRef::Code(s(x));
    c.purposes.insert(
        code("support"),
        [code("complaint"), code("refund-check")]
            .into_iter()
            .collect(),
    );
    c.purposes.insert(
        code("complaint"),
        [code("complaint-escalation")].into_iter().collect(),
    );
    c
}

fn catalog_value(c: &Catalog) -> Value {
    let catalogs = c
        .catalogs
        .iter()
        .map(|(digest, actions)| {
            Value::Array(vec![
                digest.to_value(),
                Value::Array(actions.iter().map(Canonical::to_value).collect()),
            ])
        })
        .collect();
    let purposes = c
        .purposes
        .iter()
        .map(|(p, below)| {
            Value::Array(vec![
                p.to_value(),
                Value::Array(below.iter().map(Canonical::to_value).collect()),
            ])
        })
        .collect();
    Value::Map(vec![
        (
            Value::text("reserved"),
            Value::Array(c.reserved.iter().map(Canonical::to_value).collect()),
        ),
        (Value::text("catalogs"), Value::Array(catalogs)),
        (Value::text("purposes"), Value::Array(purposes)),
    ])
}

fn purpose(r: &mut Rng) -> PurposeRef {
    match r.below(6) {
        0 => PurposeRef::Code(s("support")),
        1 => PurposeRef::Code(s("complaint")),
        2 => PurposeRef::Code(s("refund-check")),
        3 => PurposeRef::Code(s("complaint-escalation")),
        4 => PurposeRef::Work(d("work-3")),
        _ => PurposeRef::Aim(d("aim-1")),
    }
}

fn purposes(r: &mut Rng) -> BTreeSet<PurposeRef> {
    let mut out = BTreeSet::new();
    for _ in 0..=r.below(2) {
        out.insert(purpose(r));
    }
    out
}

fn segments(r: &mut Rng) -> Vec<String> {
    (0..r.below(3)).map(|_| s(r.pick(&["o", "eu"]))).collect()
}

fn resource(r: &mut Rng) -> ResourceSelector {
    if r.chance(40) {
        ResourceSelector::Exact(ResourceRef {
            namespace: s("shop"),
            path: segments(r),
            incarnation: r.below(2),
        })
    } else {
        let mut attrs = BTreeMap::new();
        for _ in 0..r.below(3) {
            attrs.insert(
                s(r.pick(&["t", "r"])),
                EqValue::Int(r.below(2).cast_signed()),
            );
        }
        ResourceSelector::Structural(Structural {
            namespace: s("shop"),
            prefix: segments(r),
            kind: r.chance(50).then(|| s(r.pick(&["order", "cart"]))),
            attrs,
        })
    }
}

fn subject(r: &mut Rng) -> SubjectSelector {
    match r.below(4) {
        0 => SubjectSelector::Party(id(r.below(2) as u8)),
        1 => {
            let mut c = BTreeSet::new();
            for _ in 0..=r.below(2) {
                c.insert(Conjunct {
                    claim_class: s(r.pick(&["staff", "eu"])),
                    value: r.chance(30).then(|| EqValue::Text(s("x"))),
                });
            }
            SubjectSelector::Pred(c)
        }
        2 => SubjectSelector::Foreign {
            domain: d("domain-b"),
            class: s("auditor"),
        },
        _ => SubjectSelector::Public,
    }
}

fn opt_int(r: &mut Rng) -> Option<i64> {
    r.chance(70).then(|| r.below(6).cast_signed() - 3)
}

fn bound(r: &mut Rng) -> Bound {
    match r.below(9) {
        0 => {
            let mut e = BTreeSet::new();
            for _ in 0..=r.below(2) {
                e.insert(s(r.pick(&["a", "b", "c"])));
            }
            Bound::Enum(e)
        }
        1 => Bound::Eq(match r.below(3) {
            0 => EqValue::Int(r.below(2).cast_signed()),
            1 => EqValue::Text(s(r.pick(&["x", "y"]))),
            _ => EqValue::Bool(r.chance(50)),
        }),
        2 => Bound::Flag(r.chance(50)),
        3 => Bound::Range {
            min: opt_int(r),
            max: opt_int(r),
            unit: s(r.pick(&["try", "eur"])),
        },
        4 => Bound::CountMax(r.below(4)),
        5 => {
            let (a, b) = (r.below(4), r.below(4));
            Bound::Interval(Window {
                from: a.min(b),
                until: a.max(b),
            })
        }
        6 => Bound::Resource(resource(r)),
        7 => Bound::Subject(subject(r)),
        _ => Bound::Purpose(purposes(r)),
    }
}

fn authority(r: &mut Rng) -> AuthoritySet {
    let mut exact = BTreeSet::new();
    for _ in 0..r.below(3) {
        let (n, a) = *r.pick(&ACTIONS);
        exact.insert(action(n, a));
    }
    let mut prefix = BTreeSet::new();
    if r.chance(40) {
        prefix.insert((
            s(r.pick(&["pay", "shop", "pay.admin"])),
            d(r.pick(&["catalog-1", "catalog-2", "catalog-9"])),
        ));
    }
    let mut params = BTreeMap::new();
    for _ in 0..r.below(3) {
        params.insert(s(r.pick(&["x", "y", "z"])), bound(r));
    }
    AuthoritySet {
        actions: ActionSet { exact, prefix },
        resource: resource(r),
        params,
        recipient: r.chance(40).then(|| subject(r)),
        purpose: r.chance(40).then(|| purposes(r)),
    }
}

fn widen(r: &mut Rng, mut a: AuthoritySet) -> AuthoritySet {
    if r.chance(40) {
        let (n, x) = *r.pick(&ACTIONS);
        a.actions.exact.insert(action(n, x));
    }
    if r.chance(30) {
        a.actions.prefix.insert((s("pay"), d("catalog-1")));
    }
    if r.chance(30) {
        a.resource = ResourceSelector::Structural(Structural {
            namespace: s("shop"),
            prefix: Vec::new(),
            kind: None,
            attrs: BTreeMap::new(),
        });
    }
    if r.chance(40) {
        let keys: Vec<String> = a.params.keys().cloned().collect();
        if !keys.is_empty() {
            let k = r.pick(&keys).clone();
            a.params.remove(&k);
        }
    }
    if r.chance(30) {
        a.recipient = None;
    }
    if r.chance(30) {
        a.purpose = None;
    }
    a
}

fn normal(r: &mut Rng, cat: &Catalog) -> AuthoritySet {
    loop {
        if let Some(a) = normalize(&authority(r), cat).unwrap() {
            return a;
        }
    }
}

fn condition(r: &mut Rng) -> WhileCondition {
    if r.chance(60) {
        WhileCondition::InstanceAlive(id(r.below(3) as u8))
    } else {
        WhileCondition::ClaimHeld {
            class: s("staff"),
            subject: SubjectSelector::Party(id(r.below(2) as u8)),
            acceptance: d("acceptance"),
        }
    }
}

fn term(r: &mut Rng) -> RequirementTerm {
    RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: s(r.pick(&["kyc", "step-up"])),
        count: 1,
        binding: access_kernel::model::Binding::None,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::Reusable,
        source: None,
        assurance: BTreeMap::new(),
    }
}

fn canonical(r: &mut Rng, cat: &Catalog) -> CanonicalAuthority {
    let (a, b) = (r.below(10), r.below(10));
    let mut conditions = BTreeSet::new();
    for _ in 0..r.below(3) {
        conditions.insert(condition(r));
    }
    let mut requirements = BTreeSet::new();
    for _ in 0..r.below(3) {
        requirements.insert(term(r));
    }
    CanonicalAuthority {
        authority: normal(r, cat),
        constraints: ConstraintSet {
            validity: Window {
                from: a.min(b),
                until: a.max(b),
            },
            conditions,
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms {
            depth: r.below(4),
            downstream_holder_class: r.chance(40).then(|| subject(r)),
        },
        requirements,
    }
}

fn narrow(r: &mut Rng, cat: &Catalog, p: &CanonicalAuthority) -> CanonicalAuthority {
    let mut c = p.clone();
    if r.chance(70) {
        let x = normal(r, cat);
        if let Some(m) = meet(&p.authority, &x, cat).and_then(|m| normalize(&m, cat).unwrap()) {
            c.authority = m;
        }
    } else if r.chance(50) {
        c.authority = normal(r, cat);
    }
    let w = p.constraints.validity;
    if r.chance(50) && w.from < w.until {
        c.constraints.validity.from = w.from + 1;
    }
    if r.chance(10) {
        c.constraints.validity.until = w.until + 1;
    }
    if r.chance(40) {
        c.constraints.conditions.insert(condition(r));
    }
    if r.chance(10) {
        c.constraints.conditions.clear();
    }
    if r.chance(40) {
        c.requirements.insert(term(r));
    }
    if r.chance(10) {
        c.requirements.clear();
    }
    c.delegation.depth = if r.chance(80) {
        p.delegation.depth.saturating_sub(1 + r.below(2))
    } else {
        r.below(4)
    };
    c.delegation.downstream_holder_class = if r.chance(60) {
        p.delegation.downstream_holder_class.clone()
    } else {
        r.chance(50).then(|| subject(r))
    };
    c
}

fn bytes_of(v: &Value) -> Vec<u8> {
    encode(v, Limits::CEILING).unwrap()
}

fn case(r: &mut Rng, cat: &Catalog, i: u64) -> Value {
    let mut fields = vec![(Value::text("id"), Value::Unsigned(i))];
    match r.below(4) {
        0 => {
            let a = normal(r, cat);
            let b = if r.chance(50) {
                normalize(&widen(r, a.clone()), cat)
                    .unwrap()
                    .unwrap_or_else(|| normal(r, cat))
            } else {
                normal(r, cat)
            };
            fields.push((Value::text("op"), Value::text("le")));
            fields.push((Value::text("result"), Value::Bool(subsumes(&a, &b, cat))));
            fields.push((Value::text("a"), a.to_value()));
            fields.push((Value::text("b"), b.to_value()));
        }
        1 => {
            let a = normal(r, cat);
            let b = if r.chance(50) {
                normalize(&widen(r, a.clone()), cat)
                    .unwrap()
                    .unwrap_or_else(|| normal(r, cat))
            } else {
                normal(r, cat)
            };
            fields.push((Value::text("op"), Value::text("meet")));
            if let Some(m) = meet(&a, &b, cat) {
                fields.push((Value::text("result"), m.to_value()));
            }
            fields.push((Value::text("a"), a.to_value()));
            fields.push((Value::text("b"), b.to_value()));
        }
        2 => {
            let a = authority(r);
            fields.push((Value::text("op"), Value::text("normalize")));
            match normalize(&a, cat) {
                Ok(Some(n)) => fields.push((Value::text("result"), n.to_value())),
                Ok(None) => {}
                Err(e) => panic!("generated input outside the model: {e}"),
            }
            fields.push((Value::text("a"), a.to_value()));
        }
        _ => {
            let parent = canonical(r, cat);
            let child = narrow(r, cat, &parent);
            let holder = subject(r);
            fields.push((Value::text("op"), Value::text("within")));
            fields.push((
                Value::text("result"),
                Value::Bool(child_within_parent(&child, &parent, &holder, cat)),
            ));
            fields.push((Value::text("child"), child.to_value()));
            fields.push((Value::text("parent"), parent.to_value()));
            fields.push((Value::text("holder"), holder.to_value()));
        }
    }
    Value::Map(fields)
}

// OP-159 m.3 (v), CR-49 m.1, INV-8
#[test]
#[ignore = "nightly: set ACCESS_RANDOM_VECTORS to an output directory"]
fn random_algebra_for_lean() {
    let Some(dir) = std::env::var_os("ACCESS_RANDOM_VECTORS") else {
        return;
    };
    let count: u64 = std::env::var("ACCESS_RANDOM_COUNT")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(10_000);
    let seed: u64 = std::env::var("ACCESS_RANDOM_SEED")
        .ok()
        .and_then(|c| c.parse().ok())
        .unwrap_or(1);
    let mut r = Rng(seed);
    let cat = catalog();
    let path = std::path::PathBuf::from(dir).join("lean");
    std::fs::create_dir_all(&path).unwrap();
    let file = std::fs::File::create(path.join("algebra.cbor")).unwrap();
    let mut out = std::io::BufWriter::new(file);
    let header = Value::Map(vec![
        (Value::text("rule"), Value::text("OP-159")),
        (Value::text("seed"), Value::Unsigned(seed)),
        (Value::text("count"), Value::Unsigned(count)),
        (Value::text("catalog"), catalog_value(&cat)),
    ]);
    let control = std::fs::File::create(path.join("control.cbor")).unwrap();
    let mut control = std::io::BufWriter::new(control);
    out.write_all(&bytes_of(&header)).unwrap();
    control.write_all(&bytes_of(&header)).unwrap();
    let mut inverted = 0;
    for i in 0..count {
        let v = case(&mut r, &cat, i);
        out.write_all(&bytes_of(&v)).unwrap();
        if inverted < 100
            && let Some(flipped) = invert(&v)
        {
            control.write_all(&bytes_of(&flipped)).unwrap();
            inverted += 1;
        }
    }
    out.flush().unwrap();
    control.flush().unwrap();
}

fn invert(v: &Value) -> Option<Value> {
    let Value::Map(fields) = v else { return None };
    let mut out = fields.clone();
    let result = out.iter_mut().find(|(k, _)| *k == Value::text("result"))?;
    let Value::Bool(b) = result.1 else {
        return None;
    };
    result.1 = Value::Bool(!b);
    Some(Value::Map(out))
}

// OP-159 m.3 (v)
#[test]
fn generated_algebra_cases_are_canonical_and_mixed() {
    let cat = catalog();
    let mut r = Rng(7);
    let mut ops = BTreeMap::new();
    let mut truths = 0_u32;
    for i in 0..2_000 {
        let v = case(&mut r, &cat, i);
        let bytes = bytes_of(&v);
        let back = suiss_crypto::dcbor::decode(&bytes, Limits::CEILING).unwrap();
        assert_eq!(bytes_of(&back), bytes);
        let op = v.get("op").unwrap().clone();
        if v.get("result") == Some(&Value::Bool(true)) {
            truths += 1;
        }
        *ops.entry(format!("{op:?}")).or_insert(0_u32) += 1;
    }
    assert_eq!(ops.len(), 4);
    assert!(ops.values().all(|n| *n > 300));
    assert!(truths > 200, "too few true answers: {truths}");
}
