//! The Suiss Ride and Suiss Health vectors (§7.9.10.3, OP-156 m.2 Q1): each product's decisions
//! as plain Kernel evaluations, so F0 checks them as Kernel semantics. Written to
//! `conformance/vectors/seams/1/` under `ACCESS_UPDATE_VECTORS`, else compared with it.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code; the request-path lints (OP-3) do not apply"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use access_kernel::algebra::Catalog;
use access_kernel::codec::{Canonical as _, Stored};
use access_kernel::combinator::codec::{OwnedInput, decision_value};
use access_kernel::combinator::{
    Basis, BudgetState, Capacity, Fuel, Hop, HopStatus, Mode, Outcome, evaluate,
};
use access_kernel::contribution::DISCLOSE;
use access_kernel::digest::Digest;
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue, intent_digest};
use access_kernel::model::{
    ActionSet, AuthoritySet, Binding, Bound, BudgetWindow, CanonicalAuthority, ConstraintSet,
    Consumption, DelegationTerms, Id, Independence, ProofKind, RequirementTerm, ResourceRef,
    ResourceSelector, Structural, SubjectSelector, Window,
};
use access_kernel::requirement::{Proof, ProofBinding};
use access_product_twin::Schema;
use suiss_crypto::dcbor::{Limits, encode};

const NOW: u64 = 1_000_000;
const PATIENT: Id = Id([0x50; 16]);
const ACTOR: Id = Id([0xa1; 16]);

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

fn schema(name: &str) -> Schema {
    let path = dir().join("seams/schemas").join(format!("{name}.toml"));
    Schema::parse(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut h, x| {
        let _ = write!(h, "{x:02x}");
        h
    })
}

fn structural(namespace: &str, prefix: &[&str]) -> ResourceSelector {
    ResourceSelector::Structural(Structural {
        namespace: String::from(namespace),
        prefix: prefix.iter().map(|p| String::from(*p)).collect(),
        kind: None,
        attrs: BTreeMap::new(),
    })
}

fn authority(set: AuthoritySet, requirements: BTreeSet<RequirementTerm>) -> CanonicalAuthority {
    CanonicalAuthority {
        authority: set,
        constraints: ConstraintSet {
            validity: Window {
                from: 0,
                until: 10 * NOW,
            },
            conditions: BTreeSet::new(),
            budget: BTreeSet::new(),
        },
        delegation: DelegationTerms::default(),
        requirements,
    }
}

fn intent(
    action: access_kernel::model::ActionRef,
    resource: (&str, &[&str]),
    params: BTreeMap<String, ParamValue>,
) -> IntentEnvelope {
    IntentEnvelope {
        provenance: BTreeMap::new(),
        action,
        resources: vec![ResourceRef {
            namespace: String::from(resource.0),
            path: resource.1.iter().map(|p| String::from(*p)).collect(),
            incarnation: 0,
        }],
        params,
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs::default(),
        validity: Window {
            from: NOW - 1_000,
            until: NOW + 60_000,
        },
    }
}

fn input(envelope: IntentEnvelope, hop: Hop, proofs: Vec<Proof>) -> OwnedInput {
    OwnedInput {
        mode: Mode::Commit,
        intent_digest: intent_digest(&envelope).unwrap(),
        intent: envelope,
        now: NOW,
        actor_instance: Some(ACTOR),
        actor_party: None,
        actor_is_agent: false,
        mandate: None,
        capacity: Capacity::Own,
        bases: vec![Basis {
            hops: vec![Stored::Known(hop)],
            capacities: BTreeSet::from([Capacity::Own]),
        }],
        restrictions: Vec::new(),
        proofs,
        catalog: Catalog::default(),
        mappings: Vec::new(),
    }
}

fn hop(authority: CanonicalAuthority, budgets: Vec<BudgetState>) -> Hop {
    Hop {
        authority,
        status: HopStatus::Active,
        conditions_hold: true,
        budgets,
    }
}

/// One case: its id, the rules it shows, its input and the outcome it must have.
struct Case {
    id: &'static str,
    rules: &'static [&'static str],
    input: OwnedInput,
    outcome: Outcome,
}

fn fare(kurus: i64) -> BTreeMap<String, ParamValue> {
    BTreeMap::from([(
        String::from("fare"),
        ParamValue::Amount {
            value: kurus,
            unit: String::from("try"),
        },
    )])
}

fn ride() -> Vec<Case> {
    let ride = schema("ride");
    let request = ride.action("request").unwrap();
    let accept = ride.action("accept").unwrap();
    let bounded = AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([request.clone()]),
            prefix: BTreeSet::new(),
        },
        resource: structural("ride.trip", &[]),
        params: BTreeMap::from([(
            String::from("fare"),
            Bound::Range {
                min: Some(0),
                max: Some(30_000),
                unit: String::from("try"),
            },
        )]),
        recipient: None,
        purpose: None,
    };
    let mut budgeted = authority(bounded, BTreeSet::new());
    budgeted.constraints.budget = BTreeSet::from([access_kernel::model::BudgetTerm {
        dimension: access_kernel::model::BudgetDimension::Amount(String::from("try")),
        capacity: 30_000,
        window: BudgetWindow::Total,
    }]);
    let left = |remaining: u64, demand: u64| {
        vec![BudgetState {
            window: BudgetWindow::Total,
            remaining,
            demand,
            resets_at: None,
        }]
    };
    let drivers = authority(
        AuthoritySet {
            actions: ActionSet {
                exact: BTreeSet::from([accept.clone()]),
                prefix: BTreeSet::new(),
            },
            resource: structural("ride.trip", &[]),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        BTreeSet::new(),
    );
    vec![
        Case {
            id: "ride-agent-trip-within-budget",
            rules: &["L0-EVAL-15", "L0-ALG-2"],
            input: input(
                intent(request.clone(), ("ride.trip", &["t-1"]), fare(20_000)),
                hop(budgeted.clone(), left(30_000, 20_000)),
                Vec::new(),
            ),
            outcome: Outcome::Allow,
        },
        Case {
            id: "ride-agent-trip-over-budget",
            rules: &["L0-EVAL-15"],
            input: input(
                intent(request.clone(), ("ride.trip", &["t-2"]), fare(20_000)),
                hop(budgeted.clone(), left(10_000, 20_000)),
                Vec::new(),
            ),
            outcome: Outcome::Deny,
        },
        Case {
            id: "ride-agent-trip-over-bound",
            rules: &["L0-ALG-2"],
            input: input(
                intent(request, ("ride.trip", &["t-3"]), fare(40_000)),
                hop(budgeted, left(30_000, 40_000)),
                Vec::new(),
            ),
            outcome: Outcome::Deny,
        },
        Case {
            id: "ride-selected-driver-accepts",
            rules: &["L0-ALG-2"],
            input: input(
                intent(accept, ("ride.trip", &["t-1"]), BTreeMap::new()),
                hop(drivers, Vec::new()),
                Vec::new(),
            ),
            outcome: Outcome::Allow,
        },
    ]
}

fn party_hex(id: &Id) -> String {
    hex(&id.0)
}

fn health() -> Vec<Case> {
    let health = schema("health");
    let read = health.action("read").unwrap();
    let share = health.action("share").unwrap();
    let records = party_hex(&PATIENT);
    let on_records = |action: &access_kernel::model::ActionRef| AuthoritySet {
        actions: ActionSet {
            exact: BTreeSet::from([action.clone()]),
            prefix: BTreeSet::new(),
        },
        resource: structural("access.party", &[&records]),
        params: BTreeMap::new(),
        recipient: None,
        purpose: None,
    };
    let disclose = RequirementTerm {
        proof_kind: ProofKind::Contribution,
        class: String::from(DISCLOSE),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: None,
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: Some(SubjectSelector::Party(PATIENT)),
        assurance: BTreeMap::new(),
    };
    let shared = intent(
        share,
        ("access.party", &[&records, "record-1"]),
        BTreeMap::from([(String::from("recipient"), ParamValue::Subject(ACTOR))]),
    );
    let digest: Digest = intent_digest(&shared).unwrap();
    let consent = Proof {
        id: Id([0xd1; 16]),
        kind: ProofKind::Contribution,
        class: String::from(DISCLOSE),
        position: 7,
        time: NOW - 10,
        party: PATIENT,
        instance: Id([0x51; 16]),
        issuer: PATIENT,
        binding: ProofBinding {
            actor_instance: None,
            intent_digest: Some(digest),
            resource: None,
        },
        assurance: BTreeMap::new(),
        consumed: false,
        surface: None,
    };
    let sharing = authority(
        on_records(&health.action("share").unwrap()),
        BTreeSet::from([disclose]),
    );
    vec![
        Case {
            id: "health-guardian-reads-under-the-patients-root",
            rules: &["L0-ALG-2"],
            input: input(
                intent(
                    read.clone(),
                    ("access.party", &[&records, "record-1"]),
                    BTreeMap::new(),
                ),
                hop(authority(on_records(&read), BTreeSet::new()), Vec::new()),
                Vec::new(),
            ),
            outcome: Outcome::Allow,
        },
        Case {
            id: "health-share-without-disclose",
            rules: &["L0-EVAL-10"],
            input: input(shared.clone(), hop(sharing.clone(), Vec::new()), Vec::new()),
            outcome: Outcome::RequireAction,
        },
        Case {
            id: "health-share-with-the-patients-disclose",
            rules: &["L0-EVAL-10"],
            input: input(shared, hop(sharing, Vec::new()), vec![consent]),
            outcome: Outcome::Allow,
        },
        Case {
            id: "health-other-patient-record",
            rules: &["L0-ALG-2"],
            input: input(
                intent(
                    read.clone(),
                    ("access.party", &["0000", "record-1"]),
                    BTreeMap::new(),
                ),
                hop(authority(on_records(&read), BTreeSet::new()), Vec::new()),
                Vec::new(),
            ),
            outcome: Outcome::Deny,
        },
    ]
}

const MERCHANT: Id = Id([0x4d; 16]);
const COMMERCE: Id = Id([0xc0; 16]);
const AUTHENTICATOR: Id = Id([0xa7; 16]);

fn try_amount(kurus: i64) -> BTreeMap<String, ParamValue> {
    BTreeMap::from([(
        String::from("amount"),
        ParamValue::Amount {
            value: kurus,
            unit: String::from("try"),
        },
    )])
}

fn exact(actions: &[access_kernel::model::ActionRef]) -> ActionSet {
    ActionSet {
        exact: actions.iter().cloned().collect(),
        prefix: BTreeSet::new(),
    }
}

fn left(remaining: u64, demand: u64) -> Vec<BudgetState> {
    vec![BudgetState {
        window: BudgetWindow::Total,
        remaining,
        demand,
        resets_at: None,
    }]
}

fn pay() -> Vec<Case> {
    use access_kernel::model::PurposeRef;
    let pay = schema("pay");
    let initiate = pay.action("initiate").unwrap();
    let groceries = PurposeRef::Code(String::from("groceries"));
    let mut envelope = authority(
        AuthoritySet {
            actions: exact(std::slice::from_ref(&initiate)),
            resource: structural("pay.instrument", &[]),
            params: BTreeMap::from([(
                String::from("amount"),
                Bound::Range {
                    min: Some(0),
                    max: Some(30_000),
                    unit: String::from("try"),
                },
            )]),
            recipient: Some(SubjectSelector::Party(MERCHANT)),
            purpose: Some(BTreeSet::from([groceries.clone()])),
        },
        BTreeSet::new(),
    );
    envelope.constraints.budget = BTreeSet::from([access_kernel::model::BudgetTerm {
        dimension: access_kernel::model::BudgetDimension::Amount(String::from("try")),
        capacity: 50_000,
        window: BudgetWindow::Total,
    }]);
    let payment = |kurus: i64, to: Id, purpose: &PurposeRef| {
        let mut i = intent(
            initiate.clone(),
            ("pay.instrument", &["card-1"]),
            try_amount(kurus),
        );
        i.recipient = Some(to);
        i.purpose = Some(purpose.clone());
        i
    };
    let gkd = access_kernel::model::RequirementTerm {
        proof_kind: ProofKind::Claim,
        class: String::from("authentication"),
        count: 1,
        binding: Binding::IntentDigest,
        freshness_ms: Some(300_000),
        independence: Independence::None,
        consumption: Consumption::SingleUse,
        source: Some(SubjectSelector::Party(AUTHENTICATOR)),
        assurance: BTreeMap::from([
            (String::from("aal"), 2),
            (String::from("app_controlled_factor"), 1),
            (String::from("phishing_resistant"), 1),
        ]),
    };
    let template = |mut input: OwnedInput, app: Option<u64>| {
        input.restrictions = vec![access_kernel::combinator::PolicyResult {
            policy: Id([0x9a; 16]),
            version: Digest([0x9b; 32]),
            outcome: access_kernel::restriction::RestrictionOutcome::Require(BTreeSet::from([
                gkd.clone()
            ])),
        }];
        if let Some(level) = app {
            input.proofs = vec![Proof {
                id: Id([0xa8; 16]),
                kind: ProofKind::Claim,
                class: String::from("authentication"),
                position: 9,
                time: NOW - 10,
                party: ACTOR,
                instance: Id([0xa9; 16]),
                issuer: AUTHENTICATOR,
                binding: ProofBinding {
                    actor_instance: None,
                    intent_digest: Some(input.intent_digest),
                    resource: None,
                },
                assurance: BTreeMap::from([
                    (String::from("aal"), 2),
                    (String::from("app_controlled_factor"), level),
                    (String::from("phishing_resistant"), 1),
                ]),
                consumed: false,
                surface: None,
            }];
        }
        input
    };
    let other = PurposeRef::Code(String::from("travel"));
    vec![
        Case {
            id: "pay-within-the-envelope",
            rules: &["L0-ALG-2", "L0-EVAL-15"],
            input: input(
                payment(20_000, MERCHANT, &groceries),
                hop(envelope.clone(), left(50_000, 20_000)),
                Vec::new(),
            ),
            outcome: Outcome::Allow,
        },
        Case {
            id: "pay-another-recipient",
            rules: &["L0-ALG-2"],
            input: input(
                payment(20_000, ACTOR, &groceries),
                hop(envelope.clone(), left(50_000, 20_000)),
                Vec::new(),
            ),
            outcome: Outcome::Deny,
        },
        Case {
            id: "pay-another-purpose",
            rules: &["L0-ALG-2"],
            input: input(
                payment(20_000, MERCHANT, &other),
                hop(envelope.clone(), left(50_000, 20_000)),
                Vec::new(),
            ),
            outcome: Outcome::Deny,
        },
        Case {
            id: "pay-over-the-budget",
            rules: &["L0-EVAL-15"],
            input: input(
                payment(20_000, MERCHANT, &groceries),
                hop(envelope.clone(), left(10_000, 20_000)),
                Vec::new(),
            ),
            outcome: Outcome::Deny,
        },
        Case {
            id: "pay-tr-gkd-without-the-app-factor",
            rules: &["L0-EVAL-18", "U62"],
            input: template(
                input(
                    payment(20_000, MERCHANT, &groceries),
                    hop(envelope.clone(), left(50_000, 20_000)),
                    Vec::new(),
                ),
                Some(0),
            ),
            outcome: Outcome::RequireAction,
        },
        Case {
            id: "pay-tr-gkd-with-the-app-factor",
            rules: &["L0-EVAL-18", "U62"],
            input: template(
                input(
                    payment(20_000, MERCHANT, &groceries),
                    hop(envelope, left(50_000, 20_000)),
                    Vec::new(),
                ),
                Some(1),
            ),
            outcome: Outcome::Allow,
        },
    ]
}

fn commerce() -> Vec<Case> {
    let commerce = schema("commerce");
    let refund = commerce.action("refund").unwrap();
    let order = access_kernel::model::ResourceRef {
        namespace: String::from("commerce.merchant"),
        path: vec![
            String::from("m-1"),
            String::from("orders"),
            String::from("o-1"),
        ],
        incarnation: 0,
    };
    let refunds = authority(
        AuthoritySet {
            actions: exact(std::slice::from_ref(&refund)),
            resource: structural("commerce.merchant", &["m-1", "orders"]),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        BTreeSet::from([access_kernel::model::RequirementTerm {
            proof_kind: ProofKind::Claim,
            class: String::from("order_refundable"),
            count: 1,
            binding: Binding::Resource,
            freshness_ms: Some(600_000),
            independence: Independence::None,
            consumption: Consumption::Reusable,
            source: Some(SubjectSelector::Party(COMMERCE)),
            assurance: BTreeMap::new(),
        }]),
    );
    let refundable = Proof {
        id: Id([0x0b; 16]),
        kind: ProofKind::Claim,
        class: String::from("order_refundable"),
        position: 5,
        time: NOW - 10,
        party: ACTOR,
        instance: Id([0xc1; 16]),
        issuer: COMMERCE,
        binding: ProofBinding {
            actor_instance: None,
            intent_digest: None,
            resource: Some(order),
        },
        assurance: BTreeMap::new(),
        consumed: false,
        surface: None,
    };
    let refund_o1 = || {
        intent(
            refund.clone(),
            ("commerce.merchant", &["m-1", "orders", "o-1"]),
            try_amount(10_000),
        )
    };
    vec![
        Case {
            id: "commerce-refund-without-order-refundable",
            rules: &["L0-EVAL-10"],
            input: input(refund_o1(), hop(refunds.clone(), Vec::new()), Vec::new()),
            outcome: Outcome::RequireAction,
        },
        Case {
            id: "commerce-refund-with-order-refundable",
            rules: &["L0-EVAL-10"],
            input: input(refund_o1(), hop(refunds, Vec::new()), vec![refundable]),
            outcome: Outcome::Allow,
        },
    ]
}

fn serve() -> Vec<Case> {
    let serve = schema("serve");
    let void = serve.action("void").unwrap();
    let cashier = authority(
        AuthoritySet {
            actions: exact(std::slice::from_ref(&void)),
            resource: structural("serve.store", &["store-1"]),
            params: BTreeMap::new(),
            recipient: None,
            purpose: None,
        },
        BTreeSet::new(),
    );
    let void_o1 = || {
        intent(
            void.clone(),
            ("serve.store", &["store-1", "orders", "o-1"]),
            try_amount(1_000),
        )
    };
    let mut off_shift = hop(cashier.clone(), Vec::new());
    off_shift.conditions_hold = false;
    vec![
        Case {
            id: "serve-void-on-shift",
            rules: &["L0-ALG-2"],
            input: input(void_o1(), hop(cashier, Vec::new()), Vec::new()),
            outcome: Outcome::Allow,
        },
        Case {
            id: "serve-void-after-the-shift",
            rules: &["OP-141 m.33"],
            input: input(void_o1(), off_shift, Vec::new()),
            outcome: Outcome::Deny,
        },
    ]
}

fn rules_field(rules: &[&str]) -> String {
    let list: Vec<String> = rules.iter().map(|r| format!("\"{r}\"")).collect();
    format!("\"rules\": [{}]", list.join(", "))
}

fn document(rule: &str, cases: &[Case]) -> String {
    let mut json = format!(
        "{{\n \"rule\": \"{rule}\",\n \"track\": \"seams\",\n \"version\": 1,\n \"operation\": \"combinator.evaluate\",\n \"fuel\": 10000,\n {},\n \"cases\": [\n",
        rules_field(&["L0-EVAL-1"])
    );
    let mut lines = Vec::new();
    for c in cases {
        let bytes = c.input.to_bytes().unwrap();
        let back = OwnedInput::from_bytes(&bytes).unwrap();
        let d = evaluate(&back.input(), &mut Fuel(10_000)).unwrap();
        assert_eq!(d.outcome, c.outcome, "{}: {d:?}", c.id);
        lines.push(format!(
            "  {{\"id\": \"{}\", {}, \"input\": \"{}\", \"decision\": \"{}\"}}",
            c.id,
            rules_field(c.rules),
            hex(&bytes),
            hex(&encode(&decision_value(&d), Limits::CEILING).unwrap())
        ));
    }
    json.push_str(&lines.join(",\n"));
    json.push_str("\n ]\n}\n");
    json
}

fn golden(file: &str, json: &str) {
    let path = dir().join("vectors/seams/1").join(file);
    if std::env::var_os("ACCESS_UPDATE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, json).unwrap();
        return;
    }
    assert_eq!(
        std::fs::read_to_string(&path).unwrap_or_default(),
        json,
        "{file}: run with ACCESS_UPDATE_VECTORS=1 and review the diff"
    );
}

// §7.9.10.3, CR-49
#[test]
fn ride_vectors_match() {
    golden("ride.json", &document("§7.9.10.3", &ride()));
}

// §7.9.10.3, §7.9.15, CR-49
#[test]
fn health_vectors_match() {
    golden("health.json", &document("§7.9.10.3", &health()));
}

// §7.9.9, E21, U62, OP-156 m.3 (u)
#[test]
fn pay_vectors_match() {
    golden("pay.json", &document("§7.9.9", &pay()));
}

// §7.9.10.1, OP-156 m.3 (u)
#[test]
fn commerce_vectors_match() {
    golden("commerce.json", &document("§7.9.10.1", &commerce()));
}

// §7.9.10.2, OP-156 m.3 (u)
#[test]
fn serve_vectors_match() {
    golden("serve.json", &document("§7.9.10.2", &serve()));
}

// §7.9.10.3, OP-141 m.35 (b)
#[test]
fn schema_vectors_match() {
    let mut json = format!(
        "{{\n \"rule\": \"§7.9.10.3\",\n \"track\": \"seams\",\n \"version\": 1,\n \"operation\": \"seam.schema\",\n {},\n \"cases\": [\n",
        rules_field(&["OP-141 m.35 (b)"])
    );
    let mut lines = Vec::new();
    for name in ["commerce", "health", "pay", "ride", "serve"] {
        let s = schema(name);
        let actions: Vec<String> = s
            .actions
            .iter()
            .map(|a| {
                format!(
                    "\"{}\": \"{}\"",
                    a.name,
                    hex(&s.action(&a.name).unwrap().schema.0)
                )
            })
            .collect();
        lines.push(format!(
            "  {{\"id\": \"{name}\", \"schema\": \"seams/schemas/{name}.toml\", \"namespace\": \"{}\", \"actions\": {{{}}}}}",
            s.namespace,
            actions.join(", ")
        ));
    }
    json.push_str(&lines.join(",\n"));
    json.push_str("\n ]\n}\n");
    golden("schemas.json", &json);
}
