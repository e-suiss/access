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
